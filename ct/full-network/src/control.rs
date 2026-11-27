use std::{
    collections::HashSet,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
};

use hopr_api::types::{crypto::types::OffchainPublicKey, internal::routing::PathId};
// Only the `sync` primitives of tokio are used. They need no tokio runtime, so the handle works
// under any async executor.
use tokio::sync::watch;

/// A function that values a loopback path the way the component that routes traffic does.
type PathWeightFn = dyn Fn(&[OffchainPublicKey], PathId) -> Option<f64> + Send + Sync;

/// How much a loopback path is worth probing, as judged by the component that routes traffic.
///
/// Probing follows the same weight distribution as routing, so it watches the paths routing will
/// use and keeps the same spread. The generator never computes the distribution itself: whoever
/// owns the path planner hands one in with [`EgressControl::set_path_weights`].
#[derive(Clone)]
pub struct PathWeights(Arc<PathWeightFn>);

impl PathWeights {
    /// Values every path the same.
    pub fn uniform() -> Self {
        Self(Arc::new(|_, _| Some(1.0)))
    }

    /// Builds a weigher from `f`, which returns `None` for a path it does not value.
    pub fn new(f: impl Fn(&[OffchainPublicKey], PathId) -> Option<f64> + Send + Sync + 'static) -> Self {
        Self(Arc::new(f))
    }

    /// The weight of `path`, `None` when the owner does not value it.
    ///
    /// A weight that is not a positive finite number is treated as unvalued rather than as a
    /// negative one, which a weighted draw would read as "never".
    pub fn weight_of(&self, path: &[OffchainPublicKey], path_id: PathId) -> Option<f64> {
        (self.0)(path, path_id).filter(|weight| weight.is_finite() && *weight > 0.0)
    }
}

impl Default for PathWeights {
    fn default() -> Self {
        Self::uniform()
    }
}

impl std::fmt::Debug for PathWeights {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PathWeights").finish_non_exhaustive()
    }
}

/// What the last completed loopback cycle saw evidence for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Coverage {
    /// Distinct edges that held fresh SURB evidence when the cycle was built.
    pub edges_with_evidence: usize,
    /// Cycles the generator completed since the stream was built.
    pub cycles: u64,
}

/// Counters a running stream publishes into; see [`EgressControl::coverage`].
#[derive(Debug, Default)]
pub(crate) struct CoverageCounters {
    edges_with_evidence: AtomicUsize,
    cycles: AtomicU64,
}

impl CoverageCounters {
    /// Records a completed cycle that saw `edges_with_evidence` edges carrying evidence.
    pub(crate) fn record_cycle(&self, edges_with_evidence: usize) {
        self.edges_with_evidence.store(edges_with_evidence, Ordering::Relaxed);
        self.cycles.fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> Option<Coverage> {
        match self.cycles.load(Ordering::Relaxed) {
            0 => None,
            cycles => Some(Coverage {
                edges_with_evidence: self.edges_with_evidence.load(Ordering::Relaxed),
                cycles,
            }),
        }
    }
}

/// State shared between a [`EgressControl`] and the streams it steers.
#[derive(Debug, Clone, Default)]
pub(crate) struct ControlState {
    /// Cap on the loopback best set, `None` when only `EgressConfig::best_set_size` applies.
    pub(crate) best_set_cap: Option<usize>,
    pub(crate) noise: bool,
    pub(crate) focus: Option<Arc<HashSet<OffchainPublicKey>>>,
    /// How the path owner values a loopback path.
    pub(crate) weights: PathWeights,
}

/// Cloneable handle that steers the traffic a `FullNetworkDiscovery` generates.
///
/// Changes reach already-built streams immediately; no stream needs rebuilding. Obtain a handle
/// with `FullNetworkDiscovery::control` before the prober is handed to the node.
#[derive(Debug, Clone)]
pub struct EgressControl {
    state: Arc<watch::Sender<ControlState>>,
    coverage: Arc<CoverageCounters>,
}

impl Default for EgressControl {
    fn default() -> Self {
        Self {
            state: Arc::new(watch::channel(ControlState::default()).0),
            coverage: Arc::new(CoverageCounters::default()),
        }
    }
}

impl EgressControl {
    pub(crate) fn subscribe(&self) -> watch::Receiver<ControlState> {
        self.state.subscribe()
    }

    pub(crate) fn coverage_counters(&self) -> Arc<CoverageCounters> {
        self.coverage.clone()
    }

    /// Tells every idle probe stream to re-examine the graph.
    ///
    /// The graph is read through `NetworkGraphView`, which has no change notification and gives
    /// the generator no clock, so an idle stream cannot notice on its own that a neighbour
    /// disconnected or that a recorded outcome dropped its rate. Whoever records those
    /// observations calls this after writing them, and the next pull sees the new state.
    pub fn wake_probing(&self) {
        // A watch update reaches every subscriber, including a stream between its graph read
        // and its wait. No control setting changes, but the watch version advances.
        self.state.send_modify(|_| {});
    }

    /// Caps the loopback best set to `cap` paths, `None` to keep the plain `best_set_size` cap.
    ///
    /// The cap is what one consumer window can re-measure, so the best set never exceeds it and one
    /// window of pulls can re-measure every best path. `Some(0)` is treated as `None`.
    pub fn set_best_set_cap(&self, cap: Option<usize>) {
        let cap = cap.filter(|cap| *cap > 0);
        self.state
            .send_if_modified(|s| std::mem::replace(&mut s.best_set_cap, cap) != cap);
    }

    /// Cap on the loopback best set, `None` when only `best_set_size` applies.
    pub fn best_set_cap(&self) -> Option<usize> {
        self.state.borrow().best_set_cap
    }

    /// Sets how the path owner values a loopback path. Probing then follows the routing distribution.
    pub fn set_path_weights(&self, weights: PathWeights) {
        self.state.send_modify(|s| s.weights = weights);
    }

    /// Switches cover traffic on or off. Off by default.
    ///
    /// Has no effect unless the crate is built with the `noise` feature.
    pub fn set_noise(&self, enabled: bool) {
        self.state
            .send_if_modified(|s| std::mem::replace(&mut s.noise, enabled) != enabled);
    }

    /// Whether cover traffic is switched on.
    pub fn noise(&self) -> bool {
        self.state.borrow().noise
    }

    /// Biases loopback probing towards loops around `exits`.
    ///
    /// Replaces any earlier focus. The best set is then drawn from the loops around the exits, so
    /// most loopback probes keep those measured; the rest of the network is still explored at the
    /// configured exploration share. Exits unknown to the graph produce no focused loops. An empty
    /// set clears the focus.
    pub fn set_focus(&self, exits: impl IntoIterator<Item = OffchainPublicKey>) {
        let exits: HashSet<_> = exits.into_iter().collect();
        self.state.send_modify(|s| {
            s.focus = (!exits.is_empty()).then(|| Arc::new(exits));
        });
    }

    /// Restores unfocused probing across the whole network.
    pub fn clear_focus(&self) {
        self.state.send_if_modified(|s| s.focus.take().is_some());
    }

    /// Exits loopback probing is currently focused on, if any.
    pub fn focus(&self) -> Option<Arc<HashSet<OffchainPublicKey>>> {
        self.state.borrow().focus.clone()
    }

    /// Edges the last completed loopback cycle saw fresh SURB evidence for, `None` before the first
    /// cycle completes.
    pub fn coverage(&self) -> Option<Coverage> {
        self.coverage.snapshot()
    }
}

#[cfg(test)]
mod handle {
    use hopr_api::{OffchainKeypair, types::crypto::keypairs::Keypair};

    use super::*;

    fn random_key() -> OffchainPublicKey {
        *OffchainKeypair::random().public()
    }

    #[test]
    fn control_should_start_with_noise_off_and_no_focus() {
        let control = EgressControl::default();

        assert!(!control.noise());
        assert!(control.focus().is_none());
        assert!(control.best_set_cap().is_none());
        assert!(control.coverage().is_none());
    }

    #[test]
    fn clones_should_share_one_state() {
        let control = EgressControl::default();
        let clone = control.clone();

        clone.set_noise(true);
        clone.set_best_set_cap(Some(7));

        assert!(control.noise());
        assert_eq!(control.best_set_cap(), Some(7));
    }

    #[test]
    fn a_zero_best_set_cap_should_read_as_unset() {
        let control = EgressControl::default();

        control.set_best_set_cap(Some(0));

        assert!(control.best_set_cap().is_none(), "a best set of zero paths is no cap");
    }

    #[test]
    fn coverage_should_stay_unset_until_a_cycle_completes() {
        let control = EgressControl::default();
        let counters = control.coverage_counters();

        counters.record_cycle(3);

        assert_eq!(
            control.coverage(),
            Some(Coverage {
                edges_with_evidence: 3,
                cycles: 1
            })
        );
    }

    #[test]
    fn the_default_weights_should_value_every_path_the_same() {
        let weights = PathWeights::default();

        assert_eq!(weights.weight_of(&[random_key(), random_key()], [0; 5]), Some(1.0));
    }

    #[test]
    fn a_weight_that_is_not_positive_and_finite_should_read_as_unvalued() {
        for weight in [0.0, -1.0, f64::NAN, f64::INFINITY] {
            let weights = PathWeights::new(move |_, _| Some(weight));
            assert_eq!(weights.weight_of(&[], [0; 5]), None, "{weight}");
        }

        let unknown = PathWeights::new(|_, _| None);
        assert_eq!(unknown.weight_of(&[], [0; 5]), None);
    }

    #[test]
    fn set_focus_should_replace_the_earlier_focus() {
        let control = EgressControl::default();
        let (first, second) = (random_key(), random_key());

        control.set_focus([first]);
        control.set_focus([second]);

        assert_eq!(control.focus().as_deref(), Some(&HashSet::from([second])));
    }

    #[test]
    fn set_focus_should_clear_the_focus_when_given_no_exits() {
        let control = EgressControl::default();
        control.set_focus([random_key()]);

        control.set_focus([]);

        assert!(control.focus().is_none());
    }

    #[test]
    fn clear_focus_should_restore_unfocused_probing() {
        let control = EgressControl::default();
        control.set_focus([random_key()]);

        control.clear_focus();

        assert!(control.focus().is_none());
    }

    #[test]
    fn setting_an_unchanged_value_should_not_wake_subscribers() {
        let control = EgressControl::default();
        let mut rx = control.subscribe();
        rx.mark_unchanged();

        control.set_noise(false);
        control.clear_focus();
        control.set_best_set_cap(None);

        assert!(!rx.has_changed().unwrap_or(true), "no-op setters must not wake streams");
    }
}
