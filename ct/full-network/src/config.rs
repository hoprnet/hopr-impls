#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationError, ValidationErrors};

/// Configuration for the probing mechanism
///
/// Probing is pull-driven: the generator yields the next probe when the consumer pulls for it and
/// keeps no timer. Pacing, the per-window budget and the dial belong to the caller. Only cover
/// traffic still runs on a clock, so [`interval`](Self::interval) paces cover traffic alone.
#[derive(Debug, Clone, Copy, PartialEq, smart_default::SmartDefault)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(deny_unknown_fields))]
pub struct EgressConfig {
    /// The delay between individual cover traffic rounds.
    ///
    /// The graph counts a loopback's outcome for `hopr_network_graph::LOOPBACK_WINDOW`. Validation
    /// rejects an interval above half of that, because a failing relay's evidence would expire
    /// between rounds and it would read as unprobed, not dead.
    ///
    /// Probing does not read this field.
    #[cfg_attr(
        feature = "serde",
        serde(default = "default_probing_interval", with = "humantime_serde")
    )]
    #[default(default_probing_interval())]
    pub interval: std::time::Duration,

    /// Probes a peer receives before its link counts as settled.
    ///
    /// Must be at least [`hopr_network_graph::MIN_STABLE_SAMPLES`], the wider of the two averaging
    /// windows an edge keeps. A lower count stops sampling while the window still holds initial
    /// values.
    #[cfg_attr(feature = "serde", serde(default = "default_stable_samples"))]
    #[default(default_stable_samples())]
    pub stable_samples: usize,

    /// Probe success rate, below which a settled peer is probed again (0.0–1.0).
    #[cfg_attr(feature = "serde", serde(default = "default_rate_threshold"))]
    #[default(default_rate_threshold())]
    pub success_rate_threshold: f64,

    /// Acknowledgement rate, below which a settled peer is probed again (0.0–1.0).
    #[cfg_attr(feature = "serde", serde(default = "default_rate_threshold"))]
    #[default(default_rate_threshold())]
    pub ack_rate_threshold: f64,

    /// Chance a settled but connected peer is probed again anyway (0.0–1.0).
    ///
    /// `0.0` never re-adds a settled peer. A small value keeps a stale answer from lasting for the
    /// whole connection.
    #[cfg_attr(feature = "serde", serde(default = "default_readd_probability"))]
    #[default(default_readd_probability())]
    pub readd_probability: f64,

    /// Share of loopback probes that keeps the best measured paths fresh (0.0–1.0).
    ///
    /// The rest explores the remaining loops. `0.9` keeps 90% on the best paths and spends 10% on
    /// the rest.
    #[cfg_attr(feature = "serde", serde(default = "default_best_path_share"))]
    #[default(default_best_path_share())]
    pub best_path_share: f64,

    /// Most loops one cycle counts as best paths.
    ///
    /// Caps the set so a large network still explores. The share decides the size below the cap.
    #[cfg_attr(feature = "serde", serde(default = "default_best_set_size"))]
    #[default(default_best_set_size())]
    pub best_set_size: usize,

    /// When `true`, neighbor probes are only sent to peers that have a
    /// `Connected(true)` edge in the graph (i.e. the background discovery
    /// process has already established a transport-level connection).
    ///
    /// When `false`, all known peers are probed regardless of connection
    /// state — useful during bootstrap or when discovery runs out-of-band.
    #[cfg_attr(feature = "serde", serde(default = "just_true"))]
    #[default(just_true())]
    pub probe_connected_only: bool,
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

        if self.stable_samples < hopr_network_graph::MIN_STABLE_SAMPLES {
            errors.add(
                "stable_samples",
                ValidationError::new("stable_samples_below_averaging_window").with_message(
                    format!(
                        "stable_samples must be at least {}",
                        hopr_network_graph::MIN_STABLE_SAMPLES
                    )
                    .into(),
                ),
            );
        }

        // Also rejects NaN, which no comparison satisfies.
        for (field, value) in [
            ("success_rate_threshold", self.success_rate_threshold),
            ("ack_rate_threshold", self.ack_rate_threshold),
            ("readd_probability", self.readd_probability),
            ("best_path_share", self.best_path_share),
        ] {
            if !(0.0..=1.0).contains(&value) {
                errors.add(field, ValidationError::new("must be between 0.0 and 1.0"));
            }
        }

        if self.best_set_size == 0 {
            errors.add("best_set_size", ValidationError::new("best_set_size_must_be_positive"));
        }

        // The loopback evidence of one round must still be counted when the next one is sent, with room for
        // the probe timeout and a late round, or a failing relay reads as unprobed instead of starved.
        if self.interval > window / 2 {
            errors.add(
                "interval",
                ValidationError::new("interval_exceeds_loopback_window")
                    .with_message(format!("interval must fit twice in the {window:?} loopback evidence window").into()),
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
const fn default_stable_samples() -> usize {
    hopr_network_graph::MIN_STABLE_SAMPLES
}

#[inline]
const fn default_rate_threshold() -> f64 {
    0.8
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
        assert_eq!(
            cfg.stable_samples,
            hopr_network_graph::MIN_STABLE_SAMPLES,
            "the default sample count must fill the wider averaging window"
        );
    }

    #[test]
    fn a_sample_count_below_the_averaging_window_should_be_invalid() {
        let cfg = EgressConfig {
            stable_samples: hopr_network_graph::MIN_STABLE_SAMPLES - 1,
            ..EgressConfig::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.field_errors().contains_key("stable_samples"), "{err}");

        let at_floor = EgressConfig {
            stable_samples: hopr_network_graph::MIN_STABLE_SAMPLES,
            ..EgressConfig::default()
        };
        assert!(at_floor.validate().is_ok(), "the floor itself must pass");
    }

    #[test]
    fn probabilities_outside_the_unit_range_should_be_invalid() {
        for (field, cfg) in [
            (
                "success_rate_threshold",
                EgressConfig {
                    success_rate_threshold: 1.1,
                    ..EgressConfig::default()
                },
            ),
            (
                "ack_rate_threshold",
                EgressConfig {
                    ack_rate_threshold: -0.1,
                    ..EgressConfig::default()
                },
            ),
            (
                "readd_probability",
                EgressConfig {
                    readd_probability: f64::NAN,
                    ..EgressConfig::default()
                },
            ),
            (
                "best_path_share",
                EgressConfig {
                    best_path_share: 2.0,
                    ..EgressConfig::default()
                },
            ),
        ] {
            let err = cfg.validate().unwrap_err();
            assert!(err.field_errors().contains_key(field), "{field}: {err}");
        }
    }

    #[test]
    fn an_empty_best_set_should_be_invalid() {
        let cfg = EgressConfig {
            best_set_size: 0,
            ..EgressConfig::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.field_errors().contains_key("best_set_size"), "{err}");
    }
}
