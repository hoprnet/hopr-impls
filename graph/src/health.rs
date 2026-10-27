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
    /// Nothing has been observed on this edge yet.
    Unknown,
    /// The last probe found the peer not connected.
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

/// Counts of nodes and edges, and of the node's own edges by [`EdgeHealth`].
///
/// Its size does not depend on the size of the graph, so it fits in one log line.
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub struct GraphHealthSummary {
    pub nodes: usize,
    pub edges: usize,
    pub own_edges: usize,
    pub own_usable: usize,
    pub own_low_ack_rate: usize,
    pub own_unreachable: usize,
    pub own_unknown: usize,
}

impl GraphHealthSummary {
    pub(crate) fn add_own_edge(&mut self, health: EdgeHealth) {
        self.own_edges += 1;
        match health {
            EdgeHealth::Usable => self.own_usable += 1,
            EdgeHealth::LowAckRate => self.own_low_ack_rate += 1,
            EdgeHealth::Unreachable => self.own_unreachable += 1,
            EdgeHealth::Unknown => self.own_unknown += 1,
        }
    }
}

impl std::fmt::Display for GraphHealthSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "nodes={} edges={} own_edges={} own_usable={} own_low_ack_rate={} own_unreachable={} own_unknown={}",
            self.nodes,
            self.edges,
            self.own_edges,
            self.own_usable,
            self.own_low_ack_rate,
            self.own_unreachable,
            self.own_unknown
        )
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

    #[test]
    fn summary_should_count_own_edges_by_health() {
        let mut summary = GraphHealthSummary::default();
        summary.add_own_edge(EdgeHealth::Usable);
        summary.add_own_edge(EdgeHealth::Usable);
        summary.add_own_edge(EdgeHealth::Unreachable);

        assert_eq!(summary.own_edges, 3);
        assert_eq!(summary.own_usable, 2);
        assert_eq!(summary.own_unreachable, 1);
        assert_eq!(
            summary.to_string(),
            "nodes=0 edges=0 own_edges=3 own_usable=2 own_low_ack_rate=0 own_unreachable=1 own_unknown=0"
        );
    }
}
