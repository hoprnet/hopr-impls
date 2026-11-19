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

/// Dial that scales the rate at which the consumer pulls probes.
///
/// Probe generation no longer has an interval of its own: it yields one probe per pull and the
/// consumer decides how often to pull. The dial tells that consumer how hard to pull. `None` is off.
/// [`EgressControl::set_level`] sets it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProbingLevel {
    /// One tenth of the base rate.
    Low,
    /// Half of the base rate.
    Medium,
    /// The base rate.
    #[default]
    High,
    /// Twice the base rate. Overcharge for a short burst, such as a new session that needs path evidence fast.
    Ultra,
}

impl ProbingLevel {
    /// Dial multiplier, always positive.
    pub const fn multiplier(self) -> f64 {
        match self {
            Self::Low => 0.1,
            Self::Medium => 0.5,
            Self::High => 1.0,
            Self::Ultra => 2.0,
        }
    }
}

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
#[derive(Debug, Clone)]
pub(crate) struct ControlState {
    /// `None` switches probing off.
    pub(crate) level: Option<ProbingLevel>,
    /// Probes one cycle may spend, `None` for the whole candidate set.
    pub(crate) budget: Option<usize>,
    pub(crate) noise: bool,
    pub(crate) focus: Option<Arc<HashSet<OffchainPublicKey>>>,
    /// How the path owner values a loopback path.
    pub(crate) weights: PathWeights,
}

impl Default for ControlState {
    fn default() -> Self {
        Self {
            level: Some(ProbingLevel::default()),
            budget: None,
            noise: false,
            focus: None,
            weights: PathWeights::default(),
        }
    }
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

    /// Sets the dial. `None` stops all probing traffic.
    ///
    /// The generator emits one probe per pull while the dial is on; the multiplier tells the
    /// consumer how hard to pull. Does not affect cover traffic, see [`Self::set_noise`].
    pub fn set_level(&self, level: Option<ProbingLevel>) {
        self.state
            .send_if_modified(|s| std::mem::replace(&mut s.level, level) != level);
    }

    /// Current dial, `None` when probing is off.
    pub fn level(&self) -> Option<ProbingLevel> {
        self.state.borrow().level
    }

    /// Bounds the probes one loopback cycle spends to `budget`, `None` for the whole candidate set.
    ///
    /// A cycle is what the generator offers between two rebuilds of its candidate set, roughly one
    /// consumer window. With a budget below the candidate count a cycle covers only part of the
    /// network and the next one continues where it stopped, so consecutive windows reach different
    /// edges. `Some(0)` is treated as `None`: a cycle that may spend nothing can never complete.
    pub fn set_budget(&self, budget: Option<usize>) {
        let budget = budget.filter(|budget| *budget > 0);
        self.state
            .send_if_modified(|s| std::mem::replace(&mut s.budget, budget) != budget);
    }

    /// Probes one cycle may spend, `None` when unbounded.
    pub fn budget(&self) -> Option<usize> {
        self.state.borrow().budget
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
    fn the_dial_should_multiply_the_base_pull_rate() {
        for (level, expected) in [
            (ProbingLevel::Low, 0.1),
            (ProbingLevel::Medium, 0.5),
            (ProbingLevel::High, 1.0),
            (ProbingLevel::Ultra, 2.0),
        ] {
            assert_eq!(level.multiplier(), expected, "{level:?}");
        }
    }

    #[test]
    fn control_should_start_at_full_pace_with_noise_off_and_no_focus() {
        let control = EgressControl::default();

        assert_eq!(control.level(), Some(ProbingLevel::High));
        assert!(!control.noise());
        assert!(control.focus().is_none());
        assert!(control.budget().is_none());
        assert!(control.coverage().is_none());
    }

    #[test]
    fn clones_should_share_one_state() {
        let control = EgressControl::default();
        let clone = control.clone();

        clone.set_level(Some(ProbingLevel::Low));
        clone.set_noise(true);
        clone.set_budget(Some(7));

        assert_eq!(control.level(), Some(ProbingLevel::Low));
        assert!(control.noise());
        assert_eq!(control.budget(), Some(7));
    }

    #[test]
    fn a_zero_budget_should_read_as_unbounded() {
        let control = EgressControl::default();

        control.set_budget(Some(0));

        assert!(
            control.budget().is_none(),
            "a cycle that may spend nothing never completes"
        );
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

        control.set_level(Some(ProbingLevel::High));
        control.set_noise(false);
        control.clear_focus();
        control.set_budget(None);

        assert!(!rx.has_changed().unwrap_or(true), "no-op setters must not wake streams");
    }
}
