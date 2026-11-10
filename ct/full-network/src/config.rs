#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationError, ValidationErrors};

/// Configuration for the probing mechanism
#[derive(Debug, Clone, Copy, PartialEq, smart_default::SmartDefault)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(deny_unknown_fields))]
pub struct EgressConfig {
    /// The delay between individual probing rounds for neighbor discovery.
    ///
    /// A loopback is sent once per round, and the graph counts its outcome for
    /// `hopr_network_graph::LOOPBACK_WINDOW`. Validation rejects an interval above half of that, because a
    /// failing relay's evidence would expire between rounds and it would read as unprobed, not dead.
    #[cfg_attr(
        feature = "serde",
        serde(default = "default_probing_interval", with = "humantime_serde")
    )]
    #[default(default_probing_interval())]
    pub interval: std::time::Duration,

    /// Weight for the staleness factor in probe priority (0.0–1.0).
    ///
    /// Higher values prioritize probing edges that haven't been measured recently.
    /// Set to `0.0` to disable staleness-based probing (edges are not prioritized by age).
    /// At least one of `staleness_weight`, `quality_weight`, or `base_priority` must be positive.
    #[cfg_attr(feature = "serde", serde(default = "default_staleness_weight"))]
    #[default(default_staleness_weight())]
    pub staleness_weight: f64,

    /// Weight for the inverse quality factor in probe priority (0.0–1.0).
    ///
    /// Higher values prioritize probing edges with poor quality scores.
    /// Set to `0.0` to disable quality-based probing (edges are not prioritized by their score).
    /// At least one of `staleness_weight`, `quality_weight`, or `base_priority` must be positive.
    #[cfg_attr(feature = "serde", serde(default = "default_quality_weight"))]
    #[default(default_quality_weight())]
    pub quality_weight: f64,

    /// Minimum probe chance added for all peers regardless of measurements (0.0–1.0).
    ///
    /// Ensures that even well-measured, recently-probed peers retain some chance of re-probing.
    /// Set to `0.0` only when `staleness_weight` and/or `quality_weight` are sufficient to
    /// guarantee all peers receive probe opportunities.
    /// At least one of `staleness_weight`, `quality_weight`, or `base_priority` must be positive.
    #[cfg_attr(feature = "serde", serde(default = "default_base_priority"))]
    #[default(default_base_priority())]
    pub base_priority: f64,

    /// TTL for the cached weighted shuffle order.
    ///
    /// When expired, the graph is re-traversed and a new priority-ordered shuffle is computed.
    /// Defaults to `2 × interval`.
    #[cfg_attr(feature = "serde", serde(default = "default_shuffle_ttl", with = "humantime_serde"))]
    #[default(default_shuffle_ttl())]
    pub shuffle_ttl: std::time::Duration,

    /// When `true`, neighbor probes are only sent to peers that have a
    /// `Connected(true)` edge in the graph (i.e. the background discovery
    /// process has already established a transport-level connection).
    ///
    /// When `false`, all known peers are probed regardless of connection
    /// state — useful during bootstrap or when discovery runs out-of-band.
    #[cfg_attr(feature = "serde", serde(default = "just_true"))]
    #[default(just_true())]
    pub probe_connected_only: bool,

    /// Factor by which forward-focused loopbacks outweigh other loopbacks (>= 1.0). Return-focused
    /// loopbacks get `max(focus_boost / 2, 1.0)`.
    ///
    /// Applies only while a focus is set with `EgressControl::set_focus`. Loopbacks are emitted in
    /// a weighted shuffle, so a higher factor makes focused loops lead each round more often.
    /// `1.0` gives focused loops no advantage.
    #[cfg_attr(feature = "serde", serde(default = "default_focus_boost"))]
    #[default(default_focus_boost())]
    pub focus_boost: f64,
}

impl EgressConfig {
    /// Validates the config, additionally ensuring `self.interval >= probe_timeout`.
    ///
    /// Pinging more frequently than the probe timeout would cause probes to overlap;
    /// this check prevents that misconfiguration.
    pub fn validate_against_probe_timeout(&self, probe_timeout: std::time::Duration) -> anyhow::Result<()> {
        self.validate()
            .map_err(|e| anyhow::anyhow!("invalid EgressConfig: {e}"))?;
        anyhow::ensure!(
            self.interval >= probe_timeout,
            "EgressConfig.interval ({:?}) must be >= probe_timeout ({:?})",
            self.interval,
            probe_timeout,
        );
        Ok(())
    }
}

impl Validate for EgressConfig {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();

        if !(0.0..=1.0).contains(&self.staleness_weight) {
            errors.add(
                "staleness_weight",
                ValidationError::new("staleness_weight must be between 0.0 and 1.0"),
            );
        }
        if !(0.0..=1.0).contains(&self.quality_weight) {
            errors.add(
                "quality_weight",
                ValidationError::new("quality_weight must be between 0.0 and 1.0"),
            );
        }
        if !(0.0..=1.0).contains(&self.base_priority) {
            errors.add(
                "base_priority",
                ValidationError::new("base_priority must be between 0.0 and 1.0"),
            );
        }

        // The loopback evidence of one round must still be counted when the next one is sent, with room for
        // the probe timeout and a late round, or a failing relay reads as unprobed instead of starved.
        if self.interval > hopr_network_graph::LOOPBACK_WINDOW / 2 {
            errors.add(
                "interval",
                ValidationError::new("interval must fit twice in the 60 s loopback evidence window"),
            );
        }

        // Also rejects NaN, which no comparison satisfies.
        if !(self.focus_boost >= 1.0 && self.focus_boost.is_finite()) {
            errors.add(
                "focus_boost",
                ValidationError::new("focus_boost must be finite and at least 1.0"),
            );
        }

        if self.staleness_weight + self.quality_weight + self.base_priority <= 0.0 {
            errors.add(
                "weights",
                ValidationError::new("at least one priority weight must be positive"),
            );
        }

        if errors.is_empty() { Ok(()) } else { Err(errors) }
    }
}

#[inline]
const fn default_staleness_weight() -> f64 {
    0.4
}

#[inline]
const fn default_quality_weight() -> f64 {
    0.3
}

#[inline]
const fn default_base_priority() -> f64 {
    0.3
}

#[inline]
const fn default_focus_boost() -> f64 {
    10.0
}

#[inline]
const fn default_shuffle_ttl() -> std::time::Duration {
    std::time::Duration::from_secs(default_probing_interval().as_secs() * 2)
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
    fn all_zero_weights_are_invalid() {
        let cfg = EgressConfig {
            staleness_weight: 0.0,
            quality_weight: 0.0,
            base_priority: 0.0,
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.field_errors().contains_key("weights"));
    }

    #[test]
    fn zero_staleness_weight_alone_is_valid() {
        let cfg = EgressConfig {
            staleness_weight: 0.0,
            ..Default::default()
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn zero_quality_weight_alone_is_valid() {
        let cfg = EgressConfig {
            quality_weight: 0.0,
            ..Default::default()
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn zero_base_priority_alone_is_valid() {
        let cfg = EgressConfig {
            base_priority: 0.0,
            ..Default::default()
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn staleness_weight_above_one_is_invalid() {
        let cfg = EgressConfig {
            staleness_weight: 1.1,
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.field_errors().contains_key("staleness_weight"));
    }

    #[test]
    fn quality_weight_above_one_is_invalid() {
        let cfg = EgressConfig {
            quality_weight: 1.1,
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.field_errors().contains_key("quality_weight"));
    }

    #[test]
    fn base_priority_above_one_is_invalid() {
        let cfg = EgressConfig {
            base_priority: 1.1,
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.field_errors().contains_key("base_priority"));
    }

    #[test]
    fn focus_boost_below_one_nan_or_infinite_is_invalid() {
        for focus_boost in [0.99, 0.0, -1.0, f64::NAN, f64::INFINITY] {
            let cfg = EgressConfig {
                focus_boost,
                ..Default::default()
            };
            let err = cfg.validate().unwrap_err();
            assert!(err.field_errors().contains_key("focus_boost"), "{focus_boost}");
        }
    }

    #[test]
    fn focus_boost_of_one_is_valid() {
        let cfg = EgressConfig {
            focus_boost: 1.0,
            ..Default::default()
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn negative_staleness_weight_is_invalid() {
        let cfg = EgressConfig {
            staleness_weight: -0.1,
            quality_weight: 0.5,
            base_priority: 0.5,
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.field_errors().contains_key("staleness_weight"));
    }

    #[test]
    fn negative_quality_weight_is_invalid() {
        let cfg = EgressConfig {
            staleness_weight: 0.5,
            quality_weight: -0.1,
            base_priority: 0.5,
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.field_errors().contains_key("quality_weight"));
    }

    #[test]
    fn negative_base_priority_is_invalid() {
        let cfg = EgressConfig {
            staleness_weight: 0.5,
            quality_weight: 0.5,
            base_priority: -0.1,
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.field_errors().contains_key("base_priority"));
    }
}
