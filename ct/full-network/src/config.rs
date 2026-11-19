#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationError, ValidationErrors};

/// Configuration for the probing mechanism
///
/// Deserialization runs [`Validate::validate`], so a config taken from a file cannot hold a value
/// the probing code would have to defend against.
#[derive(Debug, Clone, Copy, PartialEq, smart_default::SmartDefault)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(try_from = "EgressConfigFields")
)]
pub struct EgressConfig {
    /// The delay between individual cover-traffic rounds.
    ///
    /// The delay between individual cover-traffic rounds.
    ///
    /// Cover traffic only, which is why this exists only with the `noise` feature: probe generation
    /// is pull driven and never reads a clock. Validation rejects an interval above half of the
    /// loopback evidence window, because a failing relay's evidence would expire between
    /// cover-traffic rounds.
    #[cfg(feature = "noise")]
    #[default(default_probing_interval())]
    pub interval: std::time::Duration,

    /// How long an idle probe stream waits before re-reading the graph on its own.
    ///
    /// A stream with nothing to offer cannot see a disconnect, a dropped rate or a new channel: the
    /// graph has no change notification and the generator reads no clock. Re-reading after this long
    /// bounds how stale an idle stream can be, and
    /// [`EgressControl::wake_probing`](crate::EgressControl::wake_probing) makes it immediate for a
    /// consumer that knows it just wrote. Must be greater than zero.
    #[default(default_recheck_interval())]
    pub recheck_interval: std::time::Duration,

    /// When `true`, neighbor probes are only sent to peers that are not observed to be down.
    ///
    /// A peer whose connectivity was never observed is still probed: skipping it would suppress the
    /// probe that establishes whether it is reachable.
    #[default(just_true())]
    pub probe_connected_only: bool,

    /// Probes a peer needs before it counts as measured (`N`).
    ///
    /// A peer below `N` is probed on every pull until it reaches the count. From there on it is left
    /// alone while it stays connected. Must be at least
    /// [`hopr_network_graph::PROBE_SUCCESS_AVERAGING_WINDOW`]: below the success-rate averaging window
    /// the count says nothing about the rate it is meant to measure.
    #[default(default_stable_samples())]
    pub stable_samples: u32,

    /// Probe success rate below which a measured peer is probed again.
    ///
    /// The further below the threshold the rate sits, the earlier the peer is offered. In
    /// `[0.0, 1.0]`; `0.0` disables the trigger.
    #[default(default_min_success_rate())]
    pub min_success_rate: f64,

    /// Acknowledgement rate below which a measured peer is probed again.
    ///
    /// The further below the threshold the rate sits, the earlier the peer is offered. In
    /// `[0.0, 1.0]`; `0.0` disables the trigger.
    #[default(default_min_ack_rate())]
    pub min_ack_rate: f64,

    /// Chance that a measured, healthy peer is offered again on a pull.
    ///
    /// Keeps a stale assumption about a static link from holding forever, at a small steady cost. In
    /// `[0.0, 1.0]`; `0.0` stops the re-add.
    #[default(default_readd_probability())]
    pub readd_probability: f64,

    /// Share of loopback probes that keep the best paths measured; the rest explores.
    ///
    /// The best set is the focused loops while a focus is set, and the paths the planner values most
    /// otherwise. In `[0.0, 1.0]`; `0.9` sends a tenth of the loopbacks to the rest of the network.
    #[default(default_best_path_share())]
    pub best_path_share: f64,

    /// Most paths the best set holds. At least 1.
    #[default(default_best_set_size())]
    pub best_set_size: usize,
}

impl EgressConfig {
    /// Validates the config, additionally ensuring the cover-traffic interval is at least
    /// `probe_timeout`.
    ///
    /// Rounds closer together than the probe timeout would overlap; this check prevents that
    /// misconfiguration. Only exists with the `noise` feature, which is the only thing that paces on
    /// the interval.
    #[cfg(feature = "noise")]
    pub fn validate_against_probe_timeout(&self, probe_timeout: std::time::Duration) -> anyhow::Result<()> {
        self.validate_against_loopback_window(probe_timeout, hopr_network_graph::LOOPBACK_WINDOW)
    }

    /// Like [`validate_against_probe_timeout`](Self::validate_against_probe_timeout), with the interval
    /// checked against the graph's configured loopback `window` instead of the default one.
    #[cfg(feature = "noise")]
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
    ///
    /// `window` only matters for the interval, which exists only with the `noise` feature.
    #[cfg_attr(not(feature = "noise"), allow(unused_variables))]
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
        #[cfg(feature = "noise")]
        if self.interval > window / 2 {
            errors.add(
                "interval",
                ValidationError::new("interval_exceeds_loopback_window")
                    .with_message(format!("interval must fit twice in the {window:?} loopback evidence window").into()),
            );
        }

        if self.recheck_interval.is_zero() {
            errors.add(
                "recheck_interval",
                ValidationError::new("zero_recheck_interval")
                    .with_message("recheck_interval must be greater than zero".into()),
            );
        }

        // Also rejects NaN, which no comparison satisfies.
        for (field, rate) in [
            ("min_success_rate", self.min_success_rate),
            ("min_ack_rate", self.min_ack_rate),
        ] {
            if !(0.0..=1.0).contains(&rate) {
                errors.add(
                    field,
                    ValidationError::new("rate_threshold_out_of_range")
                        .with_message(format!("{field} must be between 0.0 and 1.0, got {rate}").into()),
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

/// The wire form of [`EgressConfig`].
///
/// Split out so deserialization can run [`Validate::validate`] before an `EgressConfig` exists: a
/// config file is the one path that could otherwise hand probing a value outside its bounds. Every
/// field repeats [`EgressConfig`]'s default, so an omitted field deserializes to the same value.
#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct EgressConfigFields {
    #[cfg(feature = "noise")]
    #[serde(default = "default_probing_interval", with = "humantime_serde")]
    interval: std::time::Duration,
    #[serde(default = "default_recheck_interval", with = "humantime_serde")]
    recheck_interval: std::time::Duration,
    #[serde(default = "just_true")]
    probe_connected_only: bool,
    #[serde(default = "default_stable_samples")]
    stable_samples: u32,
    #[serde(default = "default_min_success_rate")]
    min_success_rate: f64,
    #[serde(default = "default_min_ack_rate")]
    min_ack_rate: f64,
    #[serde(default = "default_readd_probability")]
    readd_probability: f64,
    #[serde(default = "default_best_path_share")]
    best_path_share: f64,
    #[serde(default = "default_best_set_size")]
    best_set_size: usize,
}

#[cfg(feature = "serde")]
impl TryFrom<EgressConfigFields> for EgressConfig {
    /// The validation failures, joined, so serde reports why the config was rejected.
    type Error = String;

    fn try_from(fields: EgressConfigFields) -> Result<Self, Self::Error> {
        let cfg = EgressConfig {
            #[cfg(feature = "noise")]
            interval: fields.interval,
            recheck_interval: fields.recheck_interval,
            probe_connected_only: fields.probe_connected_only,
            stable_samples: fields.stable_samples,
            min_success_rate: fields.min_success_rate,
            min_ack_rate: fields.min_ack_rate,
            readd_probability: fields.readd_probability,
            best_path_share: fields.best_path_share,
            best_set_size: fields.best_set_size,
        };

        cfg.validate().map(|()| cfg).map_err(|errors| errors.to_string())
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
const fn default_recheck_interval() -> std::time::Duration {
    std::time::Duration::from_secs(30)
}

#[cfg(feature = "noise")]
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

    #[cfg(feature = "noise")]
    #[test]
    fn the_default_probing_interval_should_pass_validation() {
        assert!(EgressConfig::default().validate().is_ok());
    }

    #[cfg(feature = "noise")]
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

    #[cfg(feature = "noise")]
    #[test]
    fn an_interval_too_large_to_double_should_be_invalid_instead_of_panicking() {
        let huge = EgressConfig {
            interval: std::time::Duration::MAX,
            ..EgressConfig::default()
        };
        let err = huge.validate().unwrap_err();
        assert!(err.field_errors().contains_key("interval"), "{err}");
    }

    #[cfg(feature = "noise")]
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

    #[cfg(feature = "noise")]
    #[test]
    fn interval_less_than_probe_timeout_is_invalid() {
        let cfg = EgressConfig::default(); // interval = 30s
        let timeout = std::time::Duration::from_secs(60);
        assert!(cfg.validate_against_probe_timeout(timeout).is_err());
    }

    #[cfg(feature = "noise")]
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
    fn a_rate_threshold_outside_zero_to_one_should_be_invalid() {
        for rate in [f64::NAN, -0.1, 1.1, f64::INFINITY] {
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
    fn a_rate_threshold_of_zero_or_one_is_valid() {
        for rate in [0.0, 1.0] {
            let cfg = EgressConfig {
                min_success_rate: rate,
                min_ack_rate: rate,
                ..Default::default()
            };
            assert!(cfg.validate().is_ok(), "{rate}");
        }
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

    #[cfg(feature = "serde")]
    fn deserialize_floats(entries: impl IntoIterator<Item = (&'static str, f64)>) -> Result<EgressConfig, String> {
        use serde::de::value::{Error as ValueError, F64Deserializer, MapDeserializer};

        let map: Vec<(&'static str, F64Deserializer<ValueError>)> = entries
            .into_iter()
            .map(|(key, value)| (key, F64Deserializer::<ValueError>::new(value)))
            .collect();

        EgressConfig::deserialize(MapDeserializer::<_, ValueError>::new(map.into_iter()))
            .map_err(|error| error.to_string())
    }

    #[cfg(feature = "serde")]
    #[test]
    fn deserializing_a_rate_threshold_above_one_should_fail() {
        let error = deserialize_floats([("min_success_rate", 1.5)]).unwrap_err();
        assert!(error.contains("min_success_rate"), "{error}");
    }

    #[cfg(feature = "serde")]
    #[test]
    fn deserializing_a_negative_probability_should_fail() {
        let error = deserialize_floats([("readd_probability", -0.5)]).unwrap_err();
        assert!(error.contains("readd_probability"), "{error}");
    }

    #[cfg(feature = "serde")]
    #[test]
    fn deserializing_a_valid_field_should_keep_every_other_default() -> anyhow::Result<()> {
        let cfg = deserialize_floats([("best_path_share", 0.5)]).map_err(anyhow::Error::msg)?;

        assert_eq!(
            cfg,
            EgressConfig {
                best_path_share: 0.5,
                ..Default::default()
            }
        );
        Ok(())
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
