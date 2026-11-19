#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationError, ValidationErrors};

/// Configuration for the probing mechanism
#[derive(Debug, Clone, Copy, PartialEq, smart_default::SmartDefault)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(deny_unknown_fields))]
pub struct EgressConfig {
    /// The delay between individual cover-traffic rounds.
    ///
    /// Cover traffic only. Probe generation is pull driven and never reads this value; the consumer
    /// decides how often to pull. Validation rejects an interval above half of the loopback evidence
    /// window, because a failing relay's evidence would expire between cover-traffic rounds.
    #[cfg_attr(
        feature = "serde",
        serde(default = "default_probing_interval", with = "humantime_serde")
    )]
    #[default(default_probing_interval())]
    pub interval: std::time::Duration,

    /// When `true`, neighbor probes are only sent to peers that are not observed to be down.
    ///
    /// A peer whose connectivity was never observed is still probed: skipping it would suppress the
    /// probe that establishes whether it is reachable.
    #[cfg_attr(feature = "serde", serde(default = "just_true"))]
    #[default(just_true())]
    pub probe_connected_only: bool,

    /// Probes a peer needs before it counts as measured (`N`).
    ///
    /// A peer below `N` is probed on every pull until it reaches the count. From there on it is left
    /// alone while it stays connected. Must be at least
    /// [`hopr_network_graph::PROBE_SUCCESS_AVERAGING_WINDOW`]: below the success-rate averaging window
    /// the count says nothing about the rate it is meant to measure.
    #[cfg_attr(feature = "serde", serde(default = "default_stable_samples"))]
    #[default(default_stable_samples())]
    pub stable_samples: u32,

    /// Probe success rate below which a measured peer is probed again.
    ///
    /// The further below the threshold the rate sits, the earlier the peer is offered. In `(0.0, 1.0]`.
    #[cfg_attr(feature = "serde", serde(default = "default_min_success_rate"))]
    #[default(default_min_success_rate())]
    pub min_success_rate: f64,

    /// Acknowledgement rate below which a measured peer is probed again.
    ///
    /// The further below the threshold the rate sits, the earlier the peer is offered. In `(0.0, 1.0]`.
    #[cfg_attr(feature = "serde", serde(default = "default_min_ack_rate"))]
    #[default(default_min_ack_rate())]
    pub min_ack_rate: f64,

    /// Chance that a measured, healthy peer is offered again on a pull.
    ///
    /// Keeps a stale assumption about a static link from holding forever, at a small steady cost. In
    /// `[0.0, 1.0]`; `0.0` stops the re-add.
    #[cfg_attr(feature = "serde", serde(default = "default_readd_probability"))]
    #[default(default_readd_probability())]
    pub readd_probability: f64,

    /// Share of loopback probes that keep the best paths measured; the rest explores.
    ///
    /// The best set is the focused loops while a focus is set, and the paths the planner values most
    /// otherwise. In `[0.0, 1.0]`; `0.9` sends a tenth of the loopbacks to the rest of the network.
    #[cfg_attr(feature = "serde", serde(default = "default_best_path_share"))]
    #[default(default_best_path_share())]
    pub best_path_share: f64,

    /// Most paths the best set holds. At least 1.
    #[cfg_attr(feature = "serde", serde(default = "default_best_set_size"))]
    #[default(default_best_set_size())]
    pub best_set_size: usize,
}

impl EgressConfig {
    /// Validates the config, additionally ensuring `self.interval >= probe_timeout`.
    ///
    /// Pinging more frequently than the probe timeout would cause probes to overlap;
    /// this check prevents that misconfiguration.
    pub fn validate_against_probe_timeout(&self, probe_timeout: std::time::Duration) -> anyhow::Result<()> {
        self.validate_against_loopback_window(probe_timeout, hopr_network_graph::LOOPBACK_WINDOW)
    }

    /// Like [`validate_against_probe_timeout`](Self::validate_against_probe_timeout), with the interval
    /// checked against the graph's configured loopback `window` instead of the default one.
    pub fn validate_against_loopback_window(
        &self,
        probe_timeout: std::time::Duration,
        window: std::time::Duration,
    ) -> anyhow::Result<()> {
        self.validate_for_window(window)
            .map_err(|e| anyhow::anyhow!("invalid EgressConfig: {e}"))?;
        anyhow::ensure!(
            self.interval >= probe_timeout,
            "EgressConfig.interval ({:?}) must be >= probe_timeout ({:?})",
            self.interval,
            probe_timeout,
        );
        Ok(())
    }

    /// The checks of [`Validate::validate`], with the interval held against `window` instead of the
    /// default loopback window.
    fn validate_for_window(&self, window: std::time::Duration) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();

        // Below the success-rate averaging window the sample count says nothing about the rate it is
        // meant to measure, so probing would stop on noise instead of on a measurement.
        if (self.stable_samples as usize) < hopr_network_graph::PROBE_SUCCESS_AVERAGING_WINDOW {
            errors.add(
                "stable_samples",
                ValidationError::new("stable_samples_below_averaging_window").with_message(
                    format!(
                        "stable_samples must be at least {} (the probe success-rate averaging window)",
                        hopr_network_graph::PROBE_SUCCESS_AVERAGING_WINDOW
                    )
                    .into(),
                ),
            );
        }

        // The loopback evidence of one cover-traffic round must still be counted when the next one is
        // sent, with room for the probe timeout and a late round, or a failing relay reads as unprobed
        // instead of starved.
        if self.interval > window / 2 {
            errors.add(
                "interval",
                ValidationError::new("interval_exceeds_loopback_window")
                    .with_message(format!("interval must fit twice in the {window:?} loopback evidence window").into()),
            );
        }

        // Also rejects NaN, which no comparison satisfies.
        for (field, rate) in [
            ("min_success_rate", self.min_success_rate),
            ("min_ack_rate", self.min_ack_rate),
        ] {
            if !(rate > 0.0 && rate <= 1.0) {
                errors.add(
                    field,
                    ValidationError::new("rate_threshold_out_of_range")
                        .with_message(format!("{field} must be in (0.0, 1.0], got {rate}").into()),
                );
            }
        }

        if !(0.0..=1.0).contains(&self.readd_probability) {
            errors.add(
                "readd_probability",
                ValidationError::new("readd_probability_out_of_range")
                    .with_message("readd_probability must be between 0.0 and 1.0".into()),
            );
        }

        if !(0.0..=1.0).contains(&self.best_path_share) {
            errors.add(
                "best_path_share",
                ValidationError::new("best_path_share_out_of_range")
                    .with_message("best_path_share must be between 0.0 and 1.0".into()),
            );
        }

        if self.best_set_size == 0 {
            errors.add(
                "best_set_size",
                ValidationError::new("empty_best_set").with_message("best_set_size must be at least 1".into()),
            );
        }

        if errors.is_empty() { Ok(()) } else { Err(errors) }
    }
}

impl Validate for EgressConfig {
    /// Holds the interval against the default [`hopr_network_graph::LOOPBACK_WINDOW`]; use
    /// [`validate_against_loopback_window`](EgressConfig::validate_against_loopback_window) for a configured one.
    fn validate(&self) -> Result<(), ValidationErrors> {
        self.validate_for_window(hopr_network_graph::LOOPBACK_WINDOW)
    }
}

#[inline]
const fn default_stable_samples() -> u32 {
    // The floor, so the default measures the longest average an edge keeps before it stops probing.
    hopr_network_graph::PROBE_SUCCESS_AVERAGING_WINDOW as u32
}

#[inline]
const fn default_min_success_rate() -> f64 {
    0.5
}

#[inline]
const fn default_min_ack_rate() -> f64 {
    0.5
}

#[inline]
const fn default_readd_probability() -> f64 {
    0.01
}

#[inline]
const fn default_best_path_share() -> f64 {
    0.9
}

#[inline]
const fn default_best_set_size() -> usize {
    100
}

#[inline]
const fn default_probing_interval() -> std::time::Duration {
    std::time::Duration::from_secs(30)
}

#[inline]
const fn just_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_probing_interval_should_pass_validation() {
        assert!(EgressConfig::default().validate().is_ok());
    }

    #[test]
    fn an_interval_that_does_not_fit_twice_in_the_loopback_window_should_be_invalid() {
        let half = hopr_network_graph::LOOPBACK_WINDOW / 2;
        let at_limit = EgressConfig {
            interval: half,
            ..EgressConfig::default()
        };
        assert!(at_limit.validate().is_ok(), "exactly twice fits");

        let over = EgressConfig {
            interval: half + std::time::Duration::from_secs(1),
            ..EgressConfig::default()
        };
        let err = over.validate().unwrap_err();
        assert!(err.field_errors().contains_key("interval"), "{err}");
    }

    #[test]
    fn an_interval_too_large_to_double_should_be_invalid_instead_of_panicking() {
        let huge = EgressConfig {
            interval: std::time::Duration::MAX,
            ..EgressConfig::default()
        };
        let err = huge.validate().unwrap_err();
        assert!(err.field_errors().contains_key("interval"), "{err}");
    }

    #[test]
    fn an_interval_should_be_checked_against_the_configured_loopback_window() {
        let timeout = std::time::Duration::from_secs(3);
        let cfg = EgressConfig {
            interval: std::time::Duration::from_secs(60),
            ..EgressConfig::default()
        };

        assert!(
            cfg.validate_against_probe_timeout(timeout).is_err(),
            "60 s does not fit twice in the default 60 s window"
        );
        assert!(
            cfg.validate_against_loopback_window(timeout, std::time::Duration::from_secs(120))
                .is_ok(),
            "exactly twice fits"
        );
        assert!(
            cfg.validate_against_loopback_window(timeout, std::time::Duration::from_secs(119))
                .is_err(),
            "one second short of twice does not"
        );
    }

    #[test]
    fn interval_less_than_probe_timeout_is_invalid() {
        let cfg = EgressConfig::default(); // interval = 30s
        let timeout = std::time::Duration::from_secs(60);
        assert!(cfg.validate_against_probe_timeout(timeout).is_err());
    }

    #[test]
    fn interval_equal_to_probe_timeout_is_valid() {
        let cfg = EgressConfig::default(); // interval = 30s
        let timeout = std::time::Duration::from_secs(30);
        assert!(cfg.validate_against_probe_timeout(timeout).is_ok());
    }

    #[test]
    fn default_config_is_valid() {
        let cfg = EgressConfig::default();
        assert!(cfg.validate().is_ok());
        assert!(cfg.probe_connected_only, "probe_connected_only should default to true");
    }

    #[test]
    fn stable_samples_at_the_averaging_window_are_accepted_and_one_below_are_rejected() {
        let floor = hopr_network_graph::PROBE_SUCCESS_AVERAGING_WINDOW as u32;

        let at_floor = EgressConfig {
            stable_samples: floor,
            ..Default::default()
        };
        assert!(at_floor.validate().is_ok(), "the averaging window is the floor");

        let below_floor = EgressConfig {
            stable_samples: floor - 1,
            ..Default::default()
        };
        let err = below_floor.validate().unwrap_err();
        assert!(err.field_errors().contains_key("stable_samples"), "{err}");
    }

    #[test]
    fn the_default_stable_samples_should_be_accepted() {
        assert!(EgressConfig::default().stable_samples >= hopr_network_graph::PROBE_SUCCESS_AVERAGING_WINDOW as u32);
    }

    #[test]
    fn a_rate_threshold_outside_zero_exclusive_to_one_should_be_invalid() {
        for rate in [f64::NAN, 0.0, -0.1, 1.1, f64::INFINITY] {
            let success = EgressConfig {
                min_success_rate: rate,
                ..Default::default()
            };
            let err = success.validate().unwrap_err();
            assert!(err.field_errors().contains_key("min_success_rate"), "{rate}: {err}");

            let ack = EgressConfig {
                min_ack_rate: rate,
                ..Default::default()
            };
            let err = ack.validate().unwrap_err();
            assert!(err.field_errors().contains_key("min_ack_rate"), "{rate}: {err}");
        }
    }

    #[test]
    fn rate_thresholds_of_one_are_valid() {
        let cfg = EgressConfig {
            min_success_rate: 1.0,
            min_ack_rate: 1.0,
            ..Default::default()
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn readd_probability_outside_zero_to_one_should_be_invalid() {
        for probability in [f64::NAN, -0.1, 1.1] {
            let cfg = EgressConfig {
                readd_probability: probability,
                ..Default::default()
            };
            let err = cfg.validate().unwrap_err();
            assert!(err.field_errors().contains_key("readd_probability"), "{probability}");
        }
    }

    #[test]
    fn best_path_share_outside_zero_to_one_should_be_invalid() {
        for share in [f64::NAN, -0.1, 1.1] {
            let cfg = EgressConfig {
                best_path_share: share,
                ..Default::default()
            };
            let err = cfg.validate().unwrap_err();
            assert!(err.field_errors().contains_key("best_path_share"), "{share}");
        }
    }

    #[test]
    fn an_empty_best_set_should_be_invalid() {
        let cfg = EgressConfig {
            best_set_size: 0,
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.field_errors().contains_key("best_set_size"), "{err}");
    }

    #[test]
    fn zero_readd_probability_and_full_exploration_should_be_valid() {
        let cfg = EgressConfig {
            readd_probability: 0.0,
            best_path_share: 0.0,
            ..Default::default()
        };
        assert!(cfg.validate().is_ok());
    }
}
