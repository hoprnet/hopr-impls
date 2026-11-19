use std::{collections::HashSet, sync::Arc};

use hopr_api::types::crypto::types::OffchainPublicKey;
// Only the `sync` primitives of tokio are used. They need no tokio runtime, so the handle works
// under any async executor.
use tokio::sync::watch;

/// Dial for probing traffic. Probing follows the dial only; the caller applies it to its own budget.
///
/// The dial is a positive multiplier, or off. It does not pace anything here: the caller owns the
/// interval and the per-window budget, and scales the budget by this multiplier. `None` (dial off)
/// holds the probing stream pending.
///
/// The graph counts the outcome of a loopback for `hopr_network_graph::LOOPBACK_WINDOW` (60 s by
/// default). A low dial that pulls fewer than one loopback per half-window can let the evidence of
/// a failing relay expire between rounds, so it reads as unprobed again and may be routed until the
/// next loop fails. A slow dial trades slower detection for less traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProbingLevel {
    /// One tenth of the configured budget.
    Low,
    /// Half of the configured budget.
    Medium,
    /// The configured budget.
    #[default]
    High,
    /// Twice the configured budget. Overcharge for a short burst, such as a new session that needs path evidence fast.
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

/// Network coverage the generator measured when a loopback window closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LoopbackCoverage {
    /// Distinct edges of the loopback candidate set that carried fresh SURB evidence.
    ///
    /// A best-effort figure: coverage is bounded by the budget the caller gives the generator.
    pub edges_with_evidence: usize,
    /// Loopback probes the generator offered in the window that just closed.
    pub window_draws: usize,
}

/// Coverage counters, written by the probing stream and read through [`EgressControl`].
#[derive(Debug, Default)]
struct CoverageCounters {
    edges_with_evidence: std::sync::atomic::AtomicUsize,
    window_draws: std::sync::atomic::AtomicUsize,
    windows: std::sync::atomic::AtomicUsize,
}

/// State shared between a [`EgressControl`] and the streams it steers.
#[derive(Debug, Clone)]
pub(crate) struct ControlState {
    /// `None` switches probing off.
    pub(crate) level: Option<ProbingLevel>,
    pub(crate) noise: bool,
    pub(crate) focus: Option<Arc<HashSet<OffchainPublicKey>>>,
    /// Probes the caller will pull per window. `None` closes a coverage window at a cycle wrap.
    pub(crate) budget: Option<usize>,
}

impl Default for ControlState {
    fn default() -> Self {
        Self {
            level: Some(ProbingLevel::default()),
            noise: false,
            focus: None,
            budget: None,
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
            coverage: Arc::default(),
        }
    }
}

impl EgressControl {
    pub(crate) fn subscribe(&self) -> watch::Receiver<ControlState> {
        self.state.subscribe()
    }

    /// Sets the probing dial. `None` stops all probing traffic.
    ///
    /// The dial is a multiplier the caller applies to its own budget. It does not affect cover
    /// traffic, see [`Self::set_noise`].
    pub fn set_level(&self, level: Option<ProbingLevel>) {
        self.state
            .send_if_modified(|s| std::mem::replace(&mut s.level, level) != level);
    }

    /// Current probing dial, `None` when probing is off.
    pub fn level(&self) -> Option<ProbingLevel> {
        self.state.borrow().level
    }

    /// Current dial multiplier, `0.0` when probing is off.
    pub fn dial(&self) -> f64 {
        self.level().map_or(0.0, ProbingLevel::multiplier)
    }

    /// Sets the number of probes the caller will pull per window.
    ///
    /// The generator uses it only to close a coverage window: the budget never limits what the
    /// stream yields, because the caller paces the stream. `None` closes a window at a cycle wrap.
    pub fn set_budget(&self, budget: Option<usize>) {
        self.state
            .send_if_modified(|s| std::mem::replace(&mut s.budget, budget) != budget);
    }

    /// Probes per window the caller pulls, `None` when unset.
    pub fn budget(&self) -> Option<usize> {
        self.state.borrow().budget
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
    /// Replaces any earlier focus. Loops around the exits are sought first and lead each cycle of
    /// loopback probes; loops elsewhere in the network are still probed. Exits unknown to the graph
    /// produce no focused loops. An empty set clears the focus.
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

    /// Coverage measured at the last closed loopback window, `None` before the first one.
    pub fn coverage(&self) -> Option<LoopbackCoverage> {
        use std::sync::atomic::Ordering;
        if self.coverage.windows.load(Ordering::Relaxed) == 0 {
            return None;
        }
        Some(LoopbackCoverage {
            edges_with_evidence: self.coverage.edges_with_evidence.load(Ordering::Relaxed),
            window_draws: self.coverage.window_draws.load(Ordering::Relaxed),
        })
    }

    /// Loopback windows closed so far.
    pub fn coverage_windows(&self) -> usize {
        self.coverage.windows.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Publishes the coverage of a window the generator just closed.
    pub(crate) fn publish_coverage(&self, coverage: LoopbackCoverage) {
        use std::sync::atomic::Ordering;
        self.coverage
            .edges_with_evidence
            .store(coverage.edges_with_evidence, Ordering::Relaxed);
        self.coverage
            .window_draws
            .store(coverage.window_draws, Ordering::Relaxed);
        self.coverage.windows.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod handle {
    use std::time::Duration;

    use hopr_api::{OffchainKeypair, types::crypto::keypairs::Keypair};

    use super::*;

    fn random_key() -> OffchainPublicKey {
        *OffchainKeypair::random().public()
    }

    #[test]
    fn the_dial_should_scale_a_caller_owned_budget() {
        for (level, expected) in [
            (ProbingLevel::Low, 0.1),
            (ProbingLevel::Medium, 0.5),
            (ProbingLevel::High, 1.0),
            (ProbingLevel::Ultra, 2.0),
        ] {
            assert_eq!(level.multiplier(), expected, "{level:?}");
        }
        assert_eq!(
            Duration::from_secs(30).mul_f64(ProbingLevel::Ultra.multiplier()),
            Duration::from_secs(60)
        );
    }

    #[test]
    fn control_should_start_at_full_dial_with_noise_off_and_no_focus() {
        let control = EgressControl::default();

        assert_eq!(control.level(), Some(ProbingLevel::High));
        assert_eq!(control.dial(), 1.0);
        assert_eq!(control.budget(), None);
        assert!(!control.noise());
        assert!(control.focus().is_none());
        assert_eq!(control.coverage(), None);
    }

    #[test]
    fn a_switched_off_dial_should_read_as_zero() {
        let control = EgressControl::default();
        control.set_level(None);

        assert_eq!(control.level(), None);
        assert_eq!(control.dial(), 0.0);
    }

    #[test]
    fn clones_should_share_one_state() {
        let control = EgressControl::default();
        let clone = control.clone();

        clone.set_level(Some(ProbingLevel::Low));
        clone.set_noise(true);
        clone.set_budget(Some(64));

        assert_eq!(control.level(), Some(ProbingLevel::Low));
        assert!(control.noise());
        assert_eq!(control.budget(), Some(64));
    }

    #[test]
    fn clones_should_share_the_coverage_counters() {
        let control = EgressControl::default();
        let clone = control.clone();

        clone.publish_coverage(LoopbackCoverage {
            edges_with_evidence: 7,
            window_draws: 20,
        });

        assert_eq!(control.coverage_windows(), 1);
        assert_eq!(
            control.coverage(),
            Some(LoopbackCoverage {
                edges_with_evidence: 7,
                window_draws: 20,
            })
        );
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
        control.set_budget(None);
        control.clear_focus();

        assert!(!rx.has_changed().unwrap_or(true), "no-op setters must not wake streams");
    }
}
