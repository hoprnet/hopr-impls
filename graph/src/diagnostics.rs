//! Bounded graph reads for operational reporting, independent of chain inventories.
use hopr_api::OffchainPublicKey;
use serde::{Serialize, Serializer};

/// Maximum named incident edges, including both directions and transport-only edges.
#[cfg(any(feature = "serde", test))]
pub(crate) const MAX_LOCAL_GRAPH_EDGES: usize = 8;
/// Maximum named directed edges referenced by sampled paths.
#[cfg(any(feature = "serde", test))]
pub(crate) const MAX_PATH_GRAPH_EDGES: usize = 4;
/// Maximum supplied paths inspected per read (four destinations, four pairs, two legs).
#[cfg(any(feature = "serde", test))]
pub(crate) const MAX_GRAPH_PATHS: usize = 32;
/// Serialized graph detail budget, leaving room for the record envelope.
#[cfg(any(feature = "serde", test))]
pub(crate) const MAX_GRAPH_STATE_BYTES: usize = 16 * 1024;

/// Read observations without traversing or allocating the whole graph.
/// Implementations must respect the sample limits and preserve omission counts.
#[cfg(any(feature = "serde", test))]
pub(crate) trait GraphStateRead {
    /// `None` means path producers are unavailable; an empty slice means no sampled paths.
    /// Paths use the graph's canonical slots, with trailing zero padding.
    fn graph_state(&self, paths: Option<&[[u64; 5]]>) -> GraphState;
}
#[cfg(any(feature = "serde", test))]
impl<T: GraphStateRead + ?Sized> GraphStateRead for &T {
    fn graph_state(&self, paths: Option<&[[u64; 5]]>) -> GraphState {
        (**self).graph_state(paths)
    }
}
#[cfg(any(feature = "serde", test))]
impl<T: GraphStateRead + ?Sized> GraphStateRead for std::sync::Arc<T> {
    fn graph_state(&self, paths: Option<&[[u64; 5]]>) -> GraphState {
        (**self).graph_state(paths)
    }
}

/// One graph read. Counts cover the graph; detail covers incident and sampled-path edges only.
#[derive(Debug, Serialize)]
#[cfg(any(feature = "serde", test))]
pub(crate) struct GraphState {
    pub scope: &'static str,
    pub node_count: usize,
    pub edge_count: usize,
    pub local_node_present: bool,
    /// Decimal token base units, not a floating-point balance.
    pub ticket_face_value: Option<String>,
    pub edge_penalty: f64,
    pub min_ack_rate: f64,
    pub incoming_edges: usize,
    pub outgoing_edges: usize,
    pub local_edges_omitted: usize,
    pub local_edges: Vec<GraphEdge>,
    /// Null when no path counters were supplied. Only retained SURB paths are inspected.
    pub paths: Option<PathGraphState>,
    pub searches: SearchState,
}
#[cfg(any(feature = "serde", test))]
impl GraphState {
    /// Drop detail until the graph fits its reserved payload budget.
    pub(crate) fn bound_bytes(&mut self) {
        self.bound_bytes_to(MAX_GRAPH_STATE_BYTES);
    }

    fn bound_bytes_to(&mut self, limit: usize) {
        const MIN_LOCAL_EDGES: usize = 4;

        while serde_json::to_vec(self).map_or(usize::MAX, |json| json.len()) > limit {
            if self.searches.samples.len() > 1 {
                self.drop_search_sample();
            } else if self.local_edges.len() > MIN_LOCAL_EDGES {
                self.local_edges.pop();
                self.local_edges_omitted += 1;
            } else if !self.searches.samples.is_empty() {
                self.drop_search_sample();
            } else if !self.local_edges.is_empty() {
                self.local_edges.pop();
                self.local_edges_omitted += 1;
            } else if let Some(paths) = self.paths.as_mut().filter(|p| !p.edges.is_empty()) {
                paths.edges.pop();
                paths.edges_omitted += 1;
            } else {
                break;
            }
        }
    }

    fn drop_search_sample(&mut self) {
        let victim = self.searches.samples.iter().position(|s| s.returned > 0).unwrap_or(0);
        let sample = self.searches.samples.remove(victim);
        self.searches.samples_omitted = self.searches.samples_omitted.saturating_add(sample.occurrences);
    }

    #[cfg(test)]
    pub fn local_edges(&self) -> &[GraphEdge] {
        &self.local_edges
    }
}

/// Coverage of unique directed edges from the supplied SURB path sample, not all routed traffic.
#[derive(Debug, Default, Serialize)]
#[cfg(any(feature = "serde", test))]
pub(crate) struct PathGraphState {
    pub sampled_paths: usize,
    pub paths_omitted: usize,
    pub invalid_paths: usize,
    pub requested_edges: usize,
    pub missing_edges: usize,
    pub missing_node_edges: usize,
    pub ambiguous_slot_edges: usize,
    pub edges_omitted: usize,
    pub edges: Vec<GraphEdge>,
}
#[cfg(any(feature = "serde", test))]
impl PathGraphState {
    #[cfg(test)]
    pub fn edges(&self) -> &[GraphEdge] {
        &self.edges
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GraphEdgeStatus {
    Present,
    #[cfg(any(feature = "serde", test))]
    MissingEdge,
    #[cfg(any(feature = "serde", test))]
    MissingNode,
    #[cfg(any(feature = "serde", test))]
    AmbiguousSlot,
}

/// Endpoints and current observations of one directed edge. Null metrics mean unobserved.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct GraphEdge {
    pub source_slot: u64,
    pub destination_slot: u64,
    /// Missing or ambiguous slots have no trustworthy identity.
    #[serde(serialize_with = "optional_key")]
    pub source: Option<OffchainPublicKey>,
    #[serde(serialize_with = "optional_key")]
    pub destination: Option<OffchainPublicKey>,
    pub status: GraphEdgeStatus,
    pub observation: Option<GraphObservation>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct GraphObservation {
    /// Decimal token base units. Null is unknown; "0" is an observed empty channel.
    pub balance: Option<String>,
    pub is_connected: Option<bool>,
    pub ack_rate: Option<f64>,
    pub immediate_probe_rate: Option<f64>,
    pub intermediate_probe_rate: Option<f64>,
    pub immediate_latency_ms: Option<u64>,
    pub intermediate_latency_ms: Option<u64>,
    pub score: Option<f64>,
    pub health: Option<f64>,
    /// Unix milliseconds; zero means no update has been recorded.
    pub updated_at_ms: u64,
}

fn optional_key<S: Serializer>(key: &Option<OffchainPublicKey>, serializer: S) -> Result<S::Ok, S::Error> {
    match key {
        Some(key) => serializer.serialize_some(&key.to_string()),
        None => serializer.serialize_none(),
    }
}

/// Retain decision-time examples, prioritizing unsuccessful searches.
pub(crate) const MAX_SEARCH_SAMPLES: usize = 2;

/// Cumulative counters and capped latest query examples. Reading does not drain counters.
#[derive(Debug, Serialize)]
#[cfg(any(feature = "serde", test))]
pub(crate) struct SearchState {
    pub scope: &'static str,
    pub total: u64,
    pub empty: u64,
    pub contended_samples: u64,
    pub samples_unavailable: bool,
    pub samples_omitted: u64,
    pub debug_suppressed: u64,
    pub samples: Vec<SearchRecord>,
}

/// Evidence for a graph traversal, not the transport's final ranking or random draw.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct SearchRecord {
    pub selection_id: u64,
    pub search_id: u64,
    pub phase: &'static str,
    pub kind: &'static str,
    pub direction: &'static str,
    pub source: String,
    pub destination: Option<String>,
    pub length: usize,
    pub take_count: Option<usize>,
    pub value_function: &'static str,
    /// Graph configuration at query time; opaque caller value functions may use different policy.
    pub graph_ticket_face_value: Option<String>,
    pub graph_min_ack_rate: f64,
    pub graph_edge_penalty: f64,
    pub outcome: &'static str,
    pub returned: usize,
    /// A reached result cap means traversal may have stopped early; it does not count unseen paths.
    pub limit_reached: bool,
    pub cycles_skipped: u64,
    pub excluded_skipped: u64,
    pub below_minimum: u64,
    pub target_too_early: u64,
    pub depth_limited: u64,
    /// Capped visited prefix through the rejected edge, not necessarily a complete path.
    /// `rejected_prefix_truncated` marks prefixes that do not fit the five slots.
    pub rejected_prefix: Option<[u64; 5]>,
    pub rejected_prefix_nodes: Option<Vec<String>>,
    pub rejected_reason: Option<&'static str>,
    pub rejected_evaluation_id: Option<u64>,
    pub rejected_examples_omitted: u64,
    pub rejected_prefix_truncated: bool,
    pub rejected_edge: Option<GraphEdge>,
    pub returned_path: Option<[u64; 5]>,
    pub returned_path_nodes: Option<Vec<String>>,
    pub returned_paths_omitted: usize,
    pub elapsed_us: u64,
    pub recorded_at_ms: u64,
    /// Queries coalesced into this latest example; observations describe only the latest query.
    pub occurrences: u64,
}
impl SearchRecord {
    pub(crate) fn same_query(&self, other: &Self) -> bool {
        self.phase == other.phase
            && self.kind == other.kind
            && self.source == other.source
            && self.destination == other.destination
            && self.length == other.length
            && self.take_count == other.take_count
            && self.value_function == other.value_function
    }
}

#[cfg(test)]
mod coverage_tests {
    use anyhow::Context as _;
    use hopr_api::{
        graph::NetworkGraphWrite,
        types::crypto::prelude::{Keypair, OffchainKeypair},
    };

    use super::*;
    #[cfg(feature = "serde")]
    use crate::state_reporting::{MAX_SNAPSHOT_BYTES, Record, Section};

    fn graph_with_incident_edges() -> anyhow::Result<GraphState> {
        let me = *OffchainKeypair::from_secret(&[1; 32]).context("local key")?.public();
        let graph = crate::ChannelGraph::new(me);
        for index in 0u16..406 {
            let mut secret = [2; 32];
            secret[..2].copy_from_slice(&index.to_be_bytes());
            let peer = *OffchainKeypair::from_secret(&secret).context("peer key")?.public();
            graph.upsert_edge(&me, &peer, |_| {});
            graph.upsert_edge(&peer, &me, |_| {});
        }
        Ok(graph.graph_state(None))
    }

    fn full_sample(row: &GraphEdge, occurrences: u64) -> SearchRecord {
        let key = row.source.as_ref().expect("present source").to_string();
        SearchRecord {
            selection_id: u64::MAX,
            search_id: u64::MAX,
            phase: "phase2",
            kind: "simple_paths",
            direction: "forward",
            source: key.clone(),
            destination: Some(key.clone()),
            length: usize::MAX,
            take_count: Some(usize::MAX),
            value_function: "forward",
            graph_ticket_face_value: Some(hopr_api::graph::traits::Balance::MAX.to_string()),
            graph_min_ack_rate: 0.12345678901234568,
            graph_edge_penalty: 0.12345678901234568,
            outcome: "no_eligible_paths",
            returned: 0,
            limit_reached: true,
            cycles_skipped: u64::MAX,
            excluded_skipped: u64::MAX,
            below_minimum: u64::MAX,
            target_too_early: u64::MAX,
            depth_limited: u64::MAX,
            rejected_prefix: Some([u64::MAX; 5]),
            rejected_prefix_nodes: Some(vec![key.clone(); 5]),
            rejected_reason: Some("value_below_minimum"),
            rejected_evaluation_id: Some(u64::MAX),
            rejected_examples_omitted: u64::MAX,
            rejected_prefix_truncated: true,
            rejected_edge: Some(row.clone()),
            returned_path: Some([u64::MAX; 5]),
            returned_path_nodes: Some(vec![key; 5]),
            returned_paths_omitted: usize::MAX,
            elapsed_us: u64::MAX,
            recorded_at_ms: u64::MAX,
            occurrences,
        }
    }

    fn full_row(mut row: GraphEdge) -> GraphEdge {
        row.source_slot = u64::MAX;
        row.destination_slot = u64::MAX;
        row.observation = Some(GraphObservation {
            balance: Some(hopr_api::graph::traits::Balance::MAX.to_string()),
            is_connected: Some(false),
            ack_rate: Some(0.12345678901234568),
            immediate_probe_rate: Some(0.12345678901234568),
            intermediate_probe_rate: Some(0.12345678901234568),
            immediate_latency_ms: Some(u64::MAX),
            intermediate_latency_ms: Some(u64::MAX),
            score: Some(0.12345678901234568),
            health: Some(0.12345678901234568),
            updated_at_ms: u64::MAX,
        });
        row
    }

    #[test]
    fn graph_should_keep_local_rows_and_coverage_when_trimming() -> anyhow::Result<()> {
        let mut state = graph_with_incident_edges()?;
        let row = full_row(state.local_edges[0].clone());
        state.local_edges = vec![row.clone(); MAX_LOCAL_GRAPH_EDGES];
        state.searches.samples = vec![full_sample(&row, 3), full_sample(&row, 5)];
        state.bound_bytes_to(3 * 1024);

        assert!(!state.local_edges.is_empty());
        assert_eq!(state.local_edges.len() + state.local_edges_omitted, 812);
        assert_eq!(
            state.searches.samples_omitted,
            8 - state.searches.samples.iter().map(|s| s.occurrences).sum::<u64>()
        );
        assert!(serde_json::to_vec(&state).context("serialize graph state")?.len() <= 3 * 1024);
        Ok(())
    }

    #[cfg(feature = "serde")]
    #[test]
    fn graph_should_fit_all_capped_details_and_the_record_envelope() -> anyhow::Result<()> {
        let mut state = graph_with_incident_edges()?;
        let row = full_row(state.local_edges[0].clone());
        state.local_edges = vec![row.clone(); MAX_LOCAL_GRAPH_EDGES];
        state.paths = Some(PathGraphState {
            sampled_paths: MAX_GRAPH_PATHS,
            requested_edges: MAX_PATH_GRAPH_EDGES,
            edges: vec![row.clone(); MAX_PATH_GRAPH_EDGES],
            ..Default::default()
        });
        state.searches.samples = vec![full_sample(&row, 3), full_sample(&row, 5)];
        state.bound_bytes();

        assert_eq!(state.local_edges.len(), MAX_LOCAL_GRAPH_EDGES);
        assert_eq!(state.local_edges_omitted, 804);
        assert_eq!(state.searches.samples.len(), 2);
        assert_eq!(
            state.paths.as_ref().expect("path sample").edges.len(),
            MAX_PATH_GRAPH_EDGES
        );
        assert!(serde_json::to_vec(&state).context("serialize graph state")?.len() <= MAX_GRAPH_STATE_BYTES);
        let record = Record {
            schema_version: u8::MAX,
            component: "graph",
            instance: "i".repeat(120),
            sequence: u64::MAX,
            collected_at_ms: u64::MAX,
            collection_ms: u64::MAX,
            reason: "sampled_path_unavailable".to_owned(),
            analysis_required: true,
            state: Section::Ok { value: state },
        };
        assert!(record.to_json()?.len() <= MAX_SNAPSHOT_BYTES);
        Ok(())
    }

    #[test]
    fn borrowed_graph_reads_and_path_trimming_preserve_coverage_totals() -> anyhow::Result<()> {
        let key = |i| OffchainKeypair::from_secret(&[i; 32]).map(|key| *key.public());
        let me = key(1)?;
        let graph = crate::ChannelGraph::new(me);
        graph.upsert_edge(&me, &key(2)?, |_| {});
        let mut state = GraphStateRead::graph_state(&&graph, None);
        assert_eq!(state.outgoing_edges, 1);
        let row = state.local_edges[0].clone();
        state.local_edges.clear();
        state.paths = Some(PathGraphState {
            sampled_paths: 8,
            requested_edges: 8,
            edges: vec![row; 8],
            ..Default::default()
        });
        state.bound_bytes_to(3 * 1024);
        let paths = state.paths.as_ref().unwrap();
        assert!(paths.edges_omitted > 0);
        assert_eq!(paths.edges.len() + paths.edges_omitted, 8);
        assert_eq!(paths.requested_edges, 8);
        assert!(serde_json::to_vec(&state)?.len() <= MAX_GRAPH_STATE_BYTES);
        Ok(())
    }
}
