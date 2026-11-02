//! Edge health: a small, log-friendly view of an edge's [`Observations`].
//!
//! Path selection decides from the raw observations. This module only names the outcome of the
//! two checks it applies to the node's own edges (is the peer reachable, is its acknowledgement
//! rate above the floor), so a change can be logged once instead of on every observation.

use hopr_api::graph::{
    EdgeImmediateProtocolObservable,
    traits::{EdgeNetworkObservableRead, EdgeObservableRead},
};

use crate::Observations;

/// Health of a single edge, as seen by path selection.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum EdgeHealth {
    /// Not enough observed to score this edge yet.
    Unknown,
    /// The peer was last reported as not connected.
    Unreachable,
    /// The peer acknowledges too few packets, so data paths skip it.
    LowAckRate,
    /// Observed, reachable, and not below the acknowledgement floor.
    Usable,
}

impl EdgeHealth {
    /// Stable name used in log fields.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Unreachable => "unreachable",
            Self::LowAckRate => "low_ack_rate",
            Self::Usable => "usable",
        }
    }

    /// Classifies an edge from its observations and the graph's minimum acknowledgement rate.
    pub fn of(observations: &Observations, min_ack_rate: f64) -> Self {
        let immediate = observations.immediate_qos();

        if immediate.and_then(|imm| imm.is_connected()) == Some(false) {
            return Self::Unreachable;
        }

        if immediate
            .and_then(|imm| imm.ack_rate())
            .is_some_and(|rate| rate < min_ack_rate)
        {
            return Self::LowAckRate;
        }

        if observations.score().is_none() {
            Self::Unknown
        } else {
            Self::Usable
        }
    }
}

impl std::fmt::Display for EdgeHealth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use hopr_api::graph::traits::{EdgeObservableWrite, EdgeWeightType};

    use super::*;

    const MIN_ACK_RATE: f64 = 0.1;

    #[test]
    fn edge_without_observations_should_be_unknown() {
        assert_eq!(
            EdgeHealth::of(&Observations::default(), MIN_ACK_RATE),
            EdgeHealth::Unknown
        );
    }

    #[test]
    fn connection_or_balance_without_quality_evidence_should_be_unknown() {
        for observation in [
            EdgeWeightType::Connected(true),
            EdgeWeightType::Balance(Some(10.into())),
        ] {
            let mut obs = Observations::default();
            obs.record(observation);
            assert_eq!(EdgeHealth::of(&obs, MIN_ACK_RATE), EdgeHealth::Unknown);
        }
    }

    #[test]
    fn disconnected_report_should_take_precedence_over_low_ack_rate() {
        let mut obs = Observations::default();
        obs.record(EdgeWeightType::ImmediateProtocolConformance {
            num_packets: 10,
            num_acks: 0,
        });
        obs.record(EdgeWeightType::Connected(false));
        assert_eq!(EdgeHealth::of(&obs, MIN_ACK_RATE), EdgeHealth::Unreachable);
    }

    #[test]
    fn acknowledgement_floor_is_inclusive() {
        let mut obs = Observations::default();
        obs.record(EdgeWeightType::Immediate(Ok(std::time::Duration::from_millis(50))));
        obs.record(EdgeWeightType::ImmediateProtocolConformance {
            num_packets: 10,
            num_acks: 1,
        });
        assert_eq!(EdgeHealth::of(&obs, MIN_ACK_RATE), EdgeHealth::Usable);
        assert_eq!(EdgeHealth::of(&obs, MIN_ACK_RATE + 0.01), EdgeHealth::LowAckRate);
    }

    #[test]
    fn health_names_are_stable() {
        for (health, name) in [
            (EdgeHealth::Unknown, "unknown"),
            (EdgeHealth::Unreachable, "unreachable"),
            (EdgeHealth::LowAckRate, "low_ack_rate"),
            (EdgeHealth::Usable, "usable"),
        ] {
            assert_eq!(health.as_str(), name);
            assert_eq!(health.to_string(), name);
        }
    }

    #[test]
    fn edge_with_a_successful_probe_should_be_usable() {
        let mut obs = Observations::default();
        obs.record(EdgeWeightType::Immediate(Ok(std::time::Duration::from_millis(50))));
        assert_eq!(EdgeHealth::of(&obs, MIN_ACK_RATE), EdgeHealth::Usable);
    }

    #[test]
    fn edge_to_a_disconnected_peer_should_be_unreachable() {
        let mut obs = Observations::default();
        obs.record(EdgeWeightType::Immediate(Ok(std::time::Duration::from_millis(50))));
        obs.record(EdgeWeightType::Connected(false));
        assert_eq!(EdgeHealth::of(&obs, MIN_ACK_RATE), EdgeHealth::Unreachable);
    }

    #[test]
    fn edge_to_a_peer_that_does_not_acknowledge_should_have_a_low_ack_rate() {
        let mut obs = Observations::default();
        obs.record(EdgeWeightType::Immediate(Ok(std::time::Duration::from_millis(50))));
        for _ in 0..50 {
            obs.record(EdgeWeightType::ImmediateProtocolConformance {
                num_packets: 50,
                num_acks: 0,
            });
        }
        assert_eq!(EdgeHealth::of(&obs, MIN_ACK_RATE), EdgeHealth::LowAckRate);
    }
}
