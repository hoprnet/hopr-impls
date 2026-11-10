//! Optional graph-owned dump adapter. Custom graph implementations can implement `StateDump` with their own schema.
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use hopr_state_dump::{Dump, Signal, StateDump};

use crate::diagnostics::{GraphState, GraphStateRead};

type Paths = Arc<dyn Fn() -> Vec<[u64; 5]> + Send + Sync>;

/// Independent graph reporter input. Reads and optional path sampling run off the async executor.
/// Keep one adapter per reporting stream so its new-empty-search signal has a consistent baseline.
pub struct GraphDump<G> {
    graph: Arc<G>,
    paths: Option<Paths>,
    previous_empty: AtomicU64,
}
impl<G> GraphDump<G> {
    pub fn new(graph: G) -> Self {
        Self {
            graph: Arc::new(graph),
            paths: None,
            previous_empty: AtomicU64::new(0),
        }
    }

    /// Optional bounded path sample supplied by its owner, without a dependency on routing counters.
    /// An empty sample means available but idle. The reader inspects at most `MAX_GRAPH_PATHS` entries
    /// and counts omissions; the provider must bound its own allocation and must not drain another reporter's window.
    pub fn with_paths(mut self, paths: impl Fn() -> Vec<[u64; 5]> + Send + Sync + 'static) -> Self {
        self.paths = Some(Arc::new(paths));
        self
    }
}
impl<G: GraphStateRead + Send + Sync + 'static> StateDump for GraphDump<G> {
    type State = GraphState;

    async fn state_dump(&self) -> Result<Dump<Self::State>, String> {
        let graph = self.graph.clone();
        let paths = self.paths.clone();
        let state = hopr_utils::runtime::prelude::spawn_blocking(move || {
            let paths = paths.map(|source| source());
            graph.graph_state(paths.as_deref())
        })
        .await
        .map_err(|e| e.to_string())?;
        let previous = self.previous_empty.fetch_max(state.searches.empty, Ordering::Relaxed);
        let (signal, reason) = assess(&state, state.searches.empty > previous);
        Ok(Dump { state, signal, reason })
    }
}
fn assess(state: &GraphState, new_empty_search: bool) -> (Signal, &'static str) {
    if !state.local_node_present {
        return (Signal::NeedsAnalysis, "local_node_missing");
    }
    if new_empty_search {
        return (Signal::NeedsAnalysis, "new_empty_searches");
    }
    if state.paths.as_ref().is_some_and(|p| {
        p.invalid_paths > 0 || p.missing_edges > 0 || p.missing_node_edges > 0 || p.ambiguous_slot_edges > 0
    }) {
        return (Signal::NeedsAnalysis, "sampled_path_unavailable");
    }
    let edges = || {
        state
            .local_edges
            .iter()
            .chain(state.paths.iter().flat_map(|p| p.edges.iter()))
    };
    let face = state
        .ticket_face_value
        .as_deref()
        .and_then(|v| hopr_api::graph::traits::Balance::from_dec_str(v).ok());
    if edges().filter_map(|e| e.observation.as_ref()).any(|o| {
        o.is_connected == Some(false)
            || o.ack_rate.is_some_and(|v| v < state.min_ack_rate)
            || o.immediate_probe_rate == Some(0.0)
            || o.intermediate_probe_rate == Some(0.0)
            || o.score == Some(0.0)
            || o.health.is_some_and(|v| v < 1.0)
            || o.balance
                .as_deref()
                .and_then(|v| hopr_api::graph::traits::Balance::from_dec_str(v).ok())
                .zip(face)
                .is_some_and(|(balance, face)| balance < face)
    }) {
        return (Signal::NeedsAnalysis, "sampled_edge_degraded");
    }
    if state.searches.samples_unavailable
        || edges().any(|e| {
            e.observation.as_ref().is_none_or(|o| {
                o.is_connected.is_none()
                    && o.ack_rate.is_none()
                    && o.immediate_probe_rate.is_none()
                    && o.intermediate_probe_rate.is_none()
            })
        })
    {
        return (Signal::Unknown, "graph_observations_incomplete");
    }
    (Signal::Healthy, "observed_graph_scope_ok")
}

#[cfg(all(test, feature = "petgraph"))]
mod tests {
    use std::time::Duration;

    use hopr_api::{
        graph::{
            NetworkGraphTraverse, NetworkGraphWrite,
            function::EdgeValueFn,
            traits::{EdgeObservableWrite, EdgeWeightType},
        },
        types::crypto::prelude::{Keypair, OffchainKeypair},
    };
    use hopr_state_dump::{Config, Reporter, Section};

    use super::*;
    use crate::ChannelGraph;
    fn key(i: u8) -> hopr_api::OffchainPublicKey {
        *OffchainKeypair::from_secret(&[i; 32]).unwrap().public()
    }

    #[tokio::test]
    async fn graph_owns_health_and_new_search_failures_do_not_latch_forever() {
        let graph = ChannelGraph::new(key(1));
        let adapter = GraphDump::new(graph.clone()).with_paths(Vec::new);
        assert_eq!(adapter.state_dump().await.unwrap().signal, Signal::Healthy);
        assert!(
            graph
                .simple_paths(
                    &key(1),
                    &key(2),
                    1,
                    None,
                    EdgeValueFn::forward(1.try_into().unwrap(), 0.5, 0.1, None)
                )
                .is_empty()
        );
        let failed = adapter.state_dump().await.unwrap();
        assert_eq!(failed.signal, Signal::NeedsAnalysis);
        assert_eq!(failed.reason, "new_empty_searches");
        assert!(failed.state.paths.is_some());
        let next = adapter.state_dump().await.unwrap();
        assert_eq!(
            next.signal,
            Signal::Healthy,
            "historical empty searches are not fresh failures"
        );
        assert_eq!(next.state.searches.empty, 1, "diagnostics are not drained");
        graph.upsert_edge(&key(1), &key(2), |o| o.record(EdgeWeightType::Connected(false)));
        assert_eq!(adapter.state_dump().await.unwrap().reason, "sampled_edge_degraded");
    }
    #[tokio::test]
    async fn optional_paths_and_unobserved_measurements_remain_distinct() {
        let graph = ChannelGraph::new(key(1));
        graph.upsert_edge(&key(1), &key(2), |_| {});
        let dump = GraphDump::new(graph).state_dump().await.unwrap();
        assert!(dump.state.paths.is_none());
        assert_eq!(dump.signal, Signal::Unknown);
    }
    struct Faulty {
        graph: ChannelGraph,
        panic: bool,
        executor: std::thread::ThreadId,
    }
    impl GraphStateRead for Faulty {
        fn graph_state(&self, paths: Option<&[[u64; 5]]>) -> GraphState {
            assert_ne!(std::thread::current().id(), self.executor);
            assert!(!self.panic, "injected graph read failure");
            std::thread::sleep(Duration::from_millis(50));
            self.graph.graph_state(paths)
        }
    }
    #[tokio::test]
    async fn graph_blocking_reads_have_independent_timeouts_and_join_failures() {
        for panic in [false, true] {
            let timeout = if panic {
                Duration::from_secs(5)
            } else {
                Duration::from_millis(5)
            };
            let source = GraphDump::new(Faulty {
                graph: ChannelGraph::new(key(1)),
                panic,
                executor: std::thread::current().id(),
            });
            let reporter = Reporter::new(
                "graph",
                "node",
                source,
                Config::default().with_source_timeout(timeout).unwrap(),
            );
            let record = reporter.collect().await;
            assert!(record.analysis_required);
            assert_eq!(record.signal, Signal::Unknown);
            if panic {
                assert!(matches!(record.state, Section::Error { .. }));
            } else {
                assert!(matches!(record.state, Section::Timeout));
            }
        }
    }
}
