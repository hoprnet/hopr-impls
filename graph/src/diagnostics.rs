//! Bounded graph reads for operational reporting, independent of chain inventories.
use hopr_api::OffchainPublicKey;
use serde::{Serialize, Serializer};

/// Maximum named incident edges, including both directions and transport-only edges.
pub const MAX_LOCAL_GRAPH_EDGES: usize = 8;
/// Maximum named directed edges referenced by sampled paths.
pub const MAX_PATH_GRAPH_EDGES: usize = 4;
/// Maximum supplied paths inspected per read (four destinations, four pairs, two legs).
pub const MAX_GRAPH_PATHS: usize = 32;
/// Serialized graph detail budget, leaving room for the other operational sections.
pub const MAX_GRAPH_STATE_BYTES: usize = 3 * 1024;

/// Read observations without traversing or allocating the whole graph.
/// Implementations must respect the sample limits and preserve omission counts.
pub trait GraphStateRead {
    /// `None` means path producers are unavailable; an empty slice means no sampled paths.
    /// Paths use the graph's canonical slots, with trailing zero padding.
    fn graph_state(&self, paths: Option<&[[u64; 5]]>) -> GraphState;
}
impl<T: GraphStateRead + ?Sized> GraphStateRead for &T {
    fn graph_state(&self, paths: Option<&[[u64; 5]]>) -> GraphState {
        (**self).graph_state(paths)
    }
}
impl<T: GraphStateRead + ?Sized> GraphStateRead for std::sync::Arc<T> {
    fn graph_state(&self, paths: Option<&[[u64; 5]]>) -> GraphState {
        (**self).graph_state(paths)
    }
}

/// One graph read. Counts cover the graph; detail covers incident and sampled-path edges only.
#[derive(Debug, Serialize)]
pub struct GraphState {
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
impl GraphState {
    /// Drop lowest-priority rows until the graph fits its reserved payload budget.
    /// Keep both scopes represented when possible; counts continue to describe full coverage.
    pub(crate) fn bound_bytes(&mut self) {
        while serde_json::to_vec(self).map_or(usize::MAX, |json| json.len()) > MAX_GRAPH_STATE_BYTES {
            let path_len = self.paths.as_ref().map_or(0, |p| p.edges.len());
            if !self.local_edges.is_empty() && (self.local_edges.len() >= path_len || path_len <= 1) {
                self.local_edges.pop();
                self.local_edges_omitted += 1;
            } else if let Some(paths) = self.paths.as_mut().filter(|p| !p.edges.is_empty()) {
                paths.edges.pop();
                paths.edges_omitted += 1;
            } else if !self.searches.samples.is_empty() {
                let victim = self.searches.samples.iter().position(|s| s.returned > 0).unwrap_or(0);
                let sample = self.searches.samples.remove(victim);
                self.searches.samples_omitted = self.searches.samples_omitted.saturating_add(sample.occurrences);
            } else {
                break;
            }
        }
    }

    pub fn local_edges(&self) -> &[GraphEdge] {
        &self.local_edges
    }
}

/// Coverage of unique directed edges from the supplied SURB path sample, not all routed traffic.
#[derive(Debug, Default, Serialize)]
pub struct PathGraphState {
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
impl PathGraphState {
    pub fn edges(&self) -> &[GraphEdge] {
        &self.edges
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphEdgeStatus {
    Present,
    MissingEdge,
    MissingNode,
    AmbiguousSlot,
}

/// Endpoints and current observations of one directed edge. Null metrics mean unobserved.
#[derive(Clone, Debug, Serialize)]
pub struct GraphEdge {
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
pub struct GraphObservation {
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
pub const MAX_SEARCH_SAMPLES: usize = 2;

/// Cumulative counters and capped latest query examples. Reading does not drain counters.
#[derive(Debug, Serialize)]
pub struct SearchState {
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
pub struct SearchRecord {
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
        self.kind == other.kind
            && self.source == other.source
            && self.destination == other.destination
            && self.length == other.length
            && self.take_count == other.take_count
            && self.value_function == other.value_function
    }
}
