use std::{collections::HashSet, sync::Arc};

use hopr_api::types::crypto::types::OffchainPublicKey;
// Only the `sync` primitives of tokio are used. They need no tokio runtime, so the handle works
// under any async executor.
use tokio::sync::watch;

/// Pace of probing traffic, relative to the configured [`EgressConfig::interval`](crate::EgressConfig).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProbingLevel {
    /// One tenth of the configured pace.
    Low,
    /// Half of the configured pace.
    Medium,
    /// The configured pace.
    #[default]
    High,
}

impl ProbingLevel {
    /// Pace multiplier applied to the configured probing rate, always positive.
    pub const fn multiplier(self) -> f64 {
        match self {
            Self::Low => 0.1,
            Self::Medium => 0.5,
            Self::High => 1.0,
        }
    }

    /// Interval between probing rounds at this level.
    pub fn period(self, interval: std::time::Duration) -> std::time::Duration {
        interval.div_f64(self.multiplier())
    }
}

/// State shared between a [`EgressControl`] and the streams it steers.
#[derive(Debug, Clone)]
pub(crate) struct ControlState {
    /// `None` switches probing off.
    pub(crate) level: Option<ProbingLevel>,
    pub(crate) noise: bool,
    pub(crate) focus: Option<Arc<HashSet<OffchainPublicKey>>>,
}

impl Default for ControlState {
    fn default() -> Self {
        Self {
            level: Some(ProbingLevel::default()),
            noise: false,
            focus: None,
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
}

impl Default for EgressControl {
    fn default() -> Self {
        Self {
            state: Arc::new(watch::channel(ControlState::default()).0),
        }
    }
}

impl EgressControl {
    pub(crate) fn subscribe(&self) -> watch::Receiver<ControlState> {
        self.state.subscribe()
    }

    /// Sets the probing pace. `None` stops all probing traffic.
    ///
    /// Does not affect cover traffic, see [`Self::set_noise`].
    pub fn set_level(&self, level: Option<ProbingLevel>) {
        self.state
            .send_if_modified(|s| std::mem::replace(&mut s.level, level) != level);
    }

    /// Current probing pace, `None` when probing is off.
    pub fn level(&self) -> Option<ProbingLevel> {
        self.state.borrow().level
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
    /// Replaces any earlier focus. Loops elsewhere in the network are still probed, at a lower
    /// weight (see `EgressConfig::focus_boost`). Exits unknown to the graph produce no focused
    /// loops. An empty set clears the focus.
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
    fn level_should_stretch_the_configured_interval() {
        let interval = Duration::from_secs(30);

        for (level, expected) in [
            (ProbingLevel::Low, Duration::from_secs(300)),
            (ProbingLevel::Medium, Duration::from_secs(60)),
            (ProbingLevel::High, interval),
        ] {
            assert_eq!(level.period(interval), expected, "{level:?}");
        }
    }

    #[test]
    fn control_should_start_at_full_pace_with_noise_off_and_no_focus() {
        let control = EgressControl::default();

        assert_eq!(control.level(), Some(ProbingLevel::High));
        assert!(!control.noise());
        assert!(control.focus().is_none());
    }

    #[test]
    fn clones_should_share_one_state() {
        let control = EgressControl::default();
        let clone = control.clone();

        clone.set_level(Some(ProbingLevel::Low));
        clone.set_noise(true);

        assert_eq!(control.level(), Some(ProbingLevel::Low));
        assert!(control.noise());
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

        assert!(!rx.has_changed().unwrap_or(true), "no-op setters must not wake streams");
    }
}
