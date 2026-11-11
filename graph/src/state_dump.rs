//! Graph-owned diagnostic collection and assessment.
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use crate::{
    diagnostics::{GraphState, GraphStateRead},
    state_reporting::Dump,
};

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
impl<G: GraphStateRead + Send + Sync + 'static> GraphDump<G> {
    async fn collect_dump(&self) -> Result<Dump<GraphState>, String> {
        let graph = self.graph.clone();
        let paths = self.paths.clone();
        let state = hopr_utils::runtime::prelude::spawn_blocking(move || {
            let paths = paths.map(|source| source());
            graph.graph_state(paths.as_deref())
        })
        .await
        .map_err(|e| e.to_string())?;
        let previous = self.previous_empty.fetch_max(state.searches.empty, Ordering::Relaxed);
        let (analysis_required, reason) = assess(&state, state.searches.empty > previous);
        Ok(Dump {
            state,
            analysis_required,
            reason,
        })
    }
}
fn assess(state: &GraphState, new_empty_search: bool) -> (bool, &'static str) {
    if !state.local_node_present {
        return (true, "local_node_missing");
    }
    if new_empty_search {
        return (true, "new_empty_searches");
    }
    if state.paths.as_ref().is_some_and(|p| {
        p.invalid_paths > 0 || p.missing_edges > 0 || p.missing_node_edges > 0 || p.ambiguous_slot_edges > 0
    }) {
        return (true, "sampled_path_unavailable");
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
        return (true, "sampled_edge_degraded");
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
        return (true, "graph_observations_incomplete");
    }
    (false, "observed_graph_scope_ok")
}

#[cfg(feature = "petgraph")]
impl crate::ChannelGraph {
    /// Configure path sampling for collection through [`hopr_api::StateDump`].
    /// The provider runs off the async executor and must bound allocation without draining counters.
    pub fn state_view(
        &self,
        paths: impl Fn() -> Vec<[u64; 5]> + Send + Sync + 'static,
    ) -> impl hopr_api::StateDump<Error = std::io::Error> {
        GraphDump::new(self.clone()).with_paths(paths)
    }

    /// Read bounded graph diagnostics as an opaque Serde object.
    /// This synchronous read briefly locks the graph. The diagnostic schema may change.
    pub fn state(
        &self,
        paths: Option<&[[u64; 5]]>,
    ) -> Result<impl serde::Serialize + serde::de::DeserializeOwned + Send, serde_json::Error> {
        serde_json::to_value(self.graph_state(paths))
    }

    /// Collect off the async executor and emit periodic diagnostics until cancelled.
    /// HOPR_STATE_DUMP_INTERVAL controls the interval; zero disables collection.
    pub async fn run_state_reporting(
        &self,
        instance: &str,
        paths: impl Fn() -> Vec<[u64; 5]> + Send + Sync + 'static,
    ) -> Result<(), String> {
        let config = crate::state_reporting::Config::from_env().map_err(|e| e.to_string())?;
        let source = GraphDump::new(self.clone()).with_paths(paths);
        crate::state_reporting::Reporter::new("graph", instance, config)
            .run(|| source.collect_dump())
            .await;
        Ok(())
    }
}

impl<G: GraphStateRead + Send + Sync + 'static> hopr_api::StateDump for GraphDump<G> {
    type Error = std::io::Error;

    async fn dump(&self) -> Result<impl serde::Serialize + serde::de::DeserializeOwned + Send + 'static, Self::Error> {
        let dump = self.collect_dump().await.map_err(std::io::Error::other)?;
        serde_json::to_value(dump).map_err(std::io::Error::other)
    }
}

impl hopr_api::StateDump for crate::ChannelGraph {
    type Error = std::io::Error;

    async fn dump(&self) -> Result<impl serde::Serialize + serde::de::DeserializeOwned + Send + 'static, Self::Error> {
        let graph = self.clone();
        let state = hopr_utils::runtime::prelude::spawn_blocking(move || graph.graph_state(None))
            .await
            .map_err(std::io::Error::other)?;
        serde_json::to_value(state).map_err(std::io::Error::other)
    }
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

    use super::*;
    use crate::{
        ChannelGraph,
        state_reporting::{Config, Reporter, Section},
    };
    fn key(i: u8) -> hopr_api::OffchainPublicKey {
        *OffchainKeypair::from_secret(&[i; 32]).unwrap().public()
    }

    #[tokio::test]
    async fn graph_owns_health_and_new_search_failures_do_not_latch_forever() {
        let graph = ChannelGraph::new(key(1));
        let adapter = GraphDump::new(graph.clone()).with_paths(Vec::new);
        assert!(!adapter.collect_dump().await.unwrap().analysis_required);
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
        let failed = adapter.collect_dump().await.unwrap();
        assert!(failed.analysis_required);
        assert_eq!(failed.reason, "new_empty_searches");
        assert!(failed.state.paths.is_some());
        let next = adapter.collect_dump().await.unwrap();
        assert!(
            !next.analysis_required,
            "historical empty searches are not fresh failures"
        );
        assert_eq!(next.state.searches.empty, 1, "diagnostics are not drained");
        graph.upsert_edge(&key(1), &key(2), |o| o.record(EdgeWeightType::Connected(false)));
        assert_eq!(adapter.collect_dump().await.unwrap().reason, "sampled_edge_degraded");
    }
    #[tokio::test]
    async fn optional_paths_and_unobserved_measurements_remain_distinct() {
        let graph = ChannelGraph::new(key(1));
        graph.upsert_edge(&key(1), &key(2), |_| {});
        let dump = GraphDump::new(graph).collect_dump().await.unwrap();
        assert!(dump.state.paths.is_none());
        assert!(dump.analysis_required);
    }
    #[test]
    fn callers_can_serialize_graph_state_without_access_to_its_model() -> anyhow::Result<()> {
        let graph = ChannelGraph::new(key(1));
        let snapshot = graph.state(None)?;
        let value = serde_json::to_value(snapshot)?;
        assert_eq!(value["node_count"], 1);
        assert!(value["paths"].is_null());
        Ok(())
    }

    #[tokio::test]
    async fn generic_callers_can_collect_graphs_and_configured_path_views() -> anyhow::Result<()> {
        async fn collect<T: hopr_api::StateDump>(source: &T) -> anyhow::Result<serde_json::Value> {
            Ok(serde_json::to_value(source.dump().await?)?)
        }
        let graph = ChannelGraph::new(key(1));
        assert_eq!(collect(&graph).await?["node_count"], 1);
        let view = graph.state_view(Vec::new);
        let snapshot = collect(&view).await?;
        assert!(snapshot["state"]["paths"].is_object());
        Ok(())
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
            let reporter = Reporter::new("graph", "node", Config::default().with_source_timeout(timeout).unwrap());
            let record = reporter.collect(source.collect_dump()).await;
            assert!(record.analysis_required);
            assert!(record.analysis_required);
            if panic {
                assert!(matches!(record.state, Section::Error { .. }));
            } else {
                assert!(matches!(record.state, Section::Timeout));
            }
        }
    }
    #[tokio::test]
    async fn missing_local_nodes_and_unavailable_sampled_paths_request_analysis() -> anyhow::Result<()> {
        let graph = ChannelGraph::new(key(10));
        graph.remove_node(&key(10));
        let report = GraphDump::new(graph).collect_dump().await.map_err(anyhow::Error::msg)?;
        assert_eq!(report.reason, "local_node_missing");
        let report = GraphDump::new(ChannelGraph::new(key(11)))
            .with_paths(|| vec![[1, 2, 0, 0, 0]])
            .collect_dump()
            .await
            .map_err(anyhow::Error::msg)?;
        assert_eq!(report.reason, "sampled_path_unavailable");
        assert!(report.analysis_required);
        for scenario in ["0", "invalid"] {
            let output = std::process::Command::new(std::env::current_exe()?)
                .args(["--exact", "state_dump::tests::public_reporting_probe"])
                .env("HOPR_COMPONENT_REPORT_TEST", scenario)
                .env("HOPR_STATE_DUMP_INTERVAL", scenario)
                .output()?;
            assert!(
                output.status.success(),
                "{} {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
        }
        Ok(())
    }

    #[tokio::test]
    async fn public_reporting_probe() -> anyhow::Result<()> {
        let Ok(scenario) = std::env::var("HOPR_COMPONENT_REPORT_TEST") else {
            return Ok(());
        };
        let graph = ChannelGraph::new(key(12));
        let result = graph.run_state_reporting("node", Vec::new).await;
        assert_eq!(result.is_err(), scenario == "invalid");
        Ok(())
    }
}
