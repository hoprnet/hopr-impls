//! Decision-time evidence. Recording never waits for a shared diagnostics lock.
use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use parking_lot::Mutex;

use crate::diagnostics::{MAX_SEARCH_SAMPLES, SearchRecord, SearchState};

#[derive(Debug)]
pub(crate) struct SearchJournal {
    started: Instant,
    total: AtomicU64,
    empty: AtomicU64,
    unavailable_samples: AtomicU64,
    next_debug_ms: AtomicU64,
    suppressed_debug: AtomicU64,
    since_debug: AtomicU64,
    samples: Mutex<Vec<SearchRecord>>,
}
impl Default for SearchJournal {
    fn default() -> Self {
        Self {
            started: Instant::now(),
            total: AtomicU64::new(0),
            empty: AtomicU64::new(0),
            unavailable_samples: AtomicU64::new(0),
            next_debug_ms: AtomicU64::new(0),
            suppressed_debug: AtomicU64::new(0),
            since_debug: AtomicU64::new(0),
            samples: Mutex::new(Vec::new()),
        }
    }
}
impl SearchJournal {
    pub(crate) fn record(&self, mut record: SearchRecord, returned: usize, elapsed: Duration) {
        record.returned = returned;
        record.elapsed_us = elapsed.as_micros().min(u64::MAX as u128) as u64;
        record.recorded_at_ms = now_ms();
        if returned > 0 {
            record.outcome = "completed";
        }
        record.limit_reached = returned > 0 && record.take_count == Some(returned);
        self.total.fetch_add(1, Ordering::Relaxed);
        if returned == 0 {
            self.empty.fetch_add(1, Ordering::Relaxed);
            let now = self.started.elapsed().as_millis().min(u64::MAX as u128 - 60001) as u64 + 1;
            let next = self.next_debug_ms.load(Ordering::Relaxed);
            if now >= next
                && self
                    .next_debug_ms
                    .compare_exchange(next, now + 60000, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
            {
                let suppressed = self.since_debug.swap(0, Ordering::Relaxed);
                tracing::debug!(event="graph_search_failure", suppressed, search=?record,
                    "graph search returned no paths; repeated failures are summarized in node_state");
            } else {
                self.suppressed_debug.fetch_add(1, Ordering::Relaxed);
                self.since_debug.fetch_add(1, Ordering::Relaxed);
            }
        }
        tracing::trace!(event="graph_search_completed", search=?record, "graph traversal completed");
        if let Some(mut samples) = self.samples.try_lock() {
            if let Some(i) = samples.iter().position(|old| old.same_query(&record)) {
                record.occurrences = samples[i].occurrences.saturating_add(1);
                samples.remove(i);
            } else if samples.len() == MAX_SEARCH_SAMPLES {
                // Prefer failures, but allow stale evidence to age out after five minutes.
                let victim = samples
                    .iter()
                    .position(|old| {
                        old.direction == record.direction
                            && (returned == 0
                                || old.returned > 0
                                || record.recorded_at_ms.saturating_sub(old.recorded_at_ms) > 300000)
                    })
                    .or_else(|| {
                        samples.iter().position(|old| {
                            old.returned > 0 || record.recorded_at_ms.saturating_sub(old.recorded_at_ms) > 300000
                        })
                    });
                if let Some(i) = victim.or_else(|| (returned == 0).then_some(0)) {
                    samples.remove(i);
                } else {
                    return;
                }
            }
            samples.push(record);
        } else {
            self.unavailable_samples.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn snapshot(&self) -> SearchState {
        let samples = self.samples.try_lock();
        let retained = samples.as_ref().map(|s| s.to_vec()).unwrap_or_default();
        let total = self.total.load(Ordering::Relaxed);
        SearchState {
            scope: "cumulative_since_graph_creation",
            total,
            empty: self.empty.load(Ordering::Relaxed),
            samples_unavailable: samples.is_none(),
            samples_omitted: total
                .saturating_sub(retained.iter().fold(0u64, |sum, s| sum.saturating_add(s.occurrences))),
            contended_samples: self.unavailable_samples.load(Ordering::Relaxed),
            debug_suppressed: self.suppressed_debug.load(Ordering::Relaxed),
            samples: retained,
        }
    }
}
pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use hopr_api::{
        OffchainPublicKey,
        graph::{
            NetworkGraphTraverse, NetworkGraphUpdate, NetworkGraphWrite,
            function::EdgeValueFn,
            traits::{EdgeObservableWrite, EdgeWeightType},
        },
        types::crypto::prelude::{Keypair, OffchainKeypair},
    };

    use crate::{
        ChannelGraph,
        diagnostics::{GraphStateRead, MAX_GRAPH_STATE_BYTES, MAX_SEARCH_SAMPLES},
    };

    fn key(i: u8) -> OffchainPublicKey {
        *OffchainKeypair::from_secret(&[i; 32]).unwrap().public()
    }
    fn route(graph: &ChannelGraph, source: OffchainPublicKey, destination: OffchainPublicKey, balance: u64) {
        graph.upsert_edge(&source, &destination, |o| {
            o.record(EdgeWeightType::Connected(true));
            o.record(EdgeWeightType::Immediate(Ok(std::time::Duration::from_millis(10))));
            o.record(EdgeWeightType::ImmediateProtocolConformance {
                num_packets: 100,
                num_acks: 100,
            });
            o.record(EdgeWeightType::Balance(Some(balance.into())));
        });
    }

    #[test]
    fn failed_forward_and_return_searches_preserve_decision_time_remote_edge_evidence() {
        let (me, relay, destination) = (key(1), key(2), key(3));
        let graph = ChannelGraph::new(me);
        graph.set_ticket_face_value(10u64.into());
        route(&graph, me, relay, 0);
        route(&graph, relay, destination, 100);
        let paths = graph.simple_paths(
            &me,
            &destination,
            2,
            Some(10),
            EdgeValueFn::forward(2.try_into().unwrap(), 0.5, 0.1, Some(10u64.into())),
        );
        assert!(paths.is_empty());
        // The current graph changes before the next INFO dump. Evidence must not be re-read.
        route(&graph, me, relay, 100);
        let state = graph.graph_state(None);
        let failed = &state.searches.samples[0];
        assert_eq!(failed.direction, "forward");
        assert_eq!(failed.outcome, "no_eligible_paths");
        assert_eq!(failed.rejected_reason, Some("value_below_minimum"));
        assert_eq!(
            failed.rejected_prefix_nodes,
            Some(vec![me.to_string(), relay.to_string()])
        );
        assert!(failed.below_minimum > 0);
        let rejected = failed.rejected_edge.as_ref().unwrap();
        assert_eq!((rejected.source, rejected.destination), (Some(me), Some(relay)));
        assert_eq!(rejected.observation.as_ref().unwrap().balance.as_deref(), Some("0"));
        assert_eq!(failed.graph_ticket_face_value.as_deref(), Some("10"));
        route(&graph, destination, relay, 0);
        route(&graph, relay, me, 100);
        assert!(
            graph
                .simple_paths(
                    &destination,
                    &me,
                    2,
                    None,
                    EdgeValueFn::returning(2.try_into().unwrap(), 0.5, 0.1, Some(10u64.into()))
                )
                .is_empty()
        );
        let state = graph.graph_state(None);
        let failed = state.searches.samples.iter().find(|s| s.direction == "return").unwrap();
        let rejected = failed.rejected_edge.as_ref().unwrap();
        assert_eq!(
            (rejected.source, rejected.destination),
            (Some(destination), Some(relay)),
            "remote return edges must be visible"
        );
        assert_eq!(rejected.observation.as_ref().unwrap().balance.as_deref(), Some("0"));
        assert!(serde_json::to_vec(&state).unwrap().len() <= MAX_GRAPH_STATE_BYTES);
    }

    #[test]
    fn successful_candidates_and_result_caps_are_distinct_from_rejected_branches() {
        let (me, relay, destination) = (key(1), key(2), key(3));
        let graph = ChannelGraph::new(me);
        route(&graph, me, relay, 100);
        route(&graph, relay, destination, 100);
        let paths = graph.simple_paths(
            &me,
            &destination,
            2,
            Some(1),
            EdgeValueFn::forward(2.try_into().unwrap(), 0.5, 0.1, Some(10u64.into())),
        );
        assert_eq!(paths.len(), 1);
        let state = graph.graph_state(None);
        let search = &state.searches.samples[0];
        assert_eq!(search.outcome, "completed");
        assert_eq!(search.returned_path, Some(paths[0].1));
        assert!(search.limit_reached);
        assert_eq!(search.below_minimum, 0);
        assert!(search.rejected_edge.is_none());
    }

    #[derive(Clone, Default)]
    struct Counts {
        debug: Arc<AtomicUsize>,
        trace: Arc<AtomicUsize>,
        spans: Arc<AtomicUsize>,
        include_trace: bool,
    }
    impl tracing::Subscriber for Counts {
        fn enabled(&self, m: &tracing::Metadata<'_>) -> bool {
            self.include_trace || *m.level() <= tracing::Level::DEBUG
        }

        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(self.spans.fetch_add(1, Ordering::Relaxed) as u64 + 1)
        }

        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

        fn event(&self, e: &tracing::Event<'_>) {
            if *e.metadata().level() == tracing::Level::DEBUG {
                self.debug.fetch_add(1, Ordering::Relaxed);
            }
            if *e.metadata().level() == tracing::Level::TRACE {
                self.trace.fetch_add(1, Ordering::Relaxed);
            }
        }

        fn enter(&self, _: &tracing::span::Id) {}

        fn exit(&self, _: &tracing::span::Id) {}
    }
    #[test]
    fn repeated_searches_are_bounded_at_debug_and_recorded_without_a_logger() {
        let me = key(1);
        let graph = ChannelGraph::new(me);
        route(&graph, me, key(2), 100);
        let logs = Counts::default();
        tracing::subscriber::with_default(logs.clone(), || {
            for _ in 0..1000 {
                assert_eq!(
                    graph
                        .simple_paths(
                            &me,
                            &key(2),
                            1,
                            None,
                            EdgeValueFn::forward(1.try_into().unwrap(), 0.5, 0.1, None)
                        )
                        .len(),
                    1
                );
                assert!(
                    graph
                        .simple_paths(
                            &me,
                            &key(3),
                            1,
                            None,
                            EdgeValueFn::forward(1.try_into().unwrap(), 0.5, 0.1, None)
                        )
                        .is_empty()
                );
            }
        });
        assert_eq!(
            logs.debug.load(Ordering::Relaxed),
            1,
            "one failure explanation per graph per minute, not per query"
        );
        assert_eq!(logs.trace.load(Ordering::Relaxed), 0);
        assert_eq!(logs.spans.load(Ordering::Relaxed), 0);
        let state = graph.graph_state(None);
        assert_eq!(state.searches.total, 2000);
        assert_eq!(state.searches.empty, 1000);
        assert_eq!(state.searches.debug_suppressed, 999);
        assert!(state.searches.samples.len() <= MAX_SEARCH_SAMPLES);
        assert!(serde_json::to_vec(&state).unwrap().len() <= MAX_GRAPH_STATE_BYTES);
    }

    #[test]
    fn query_churn_and_contention_preserve_totals_with_bounded_evidence() {
        let graph = ChannelGraph::new(key(1));
        {
            let _held = graph.searches.samples.lock();
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
        }
        for i in 2..100 {
            graph.simple_paths(
                &key(1),
                &key(i),
                1,
                None,
                EdgeValueFn::forward(1.try_into().unwrap(), 0.5, 0.1, None),
            );
        }
        let state = graph.graph_state(None);
        assert_eq!(state.searches.total, 99);
        assert_eq!(state.searches.contended_samples, 1);
        assert!(state.searches.samples.len() <= MAX_SEARCH_SAMPLES);
        assert_eq!(
            state.searches.samples_omitted + state.searches.samples.iter().map(|s| s.occurrences).sum::<u64>(),
            99
        );
        assert!(serde_json::to_vec(&state).unwrap().len() <= MAX_GRAPH_STATE_BYTES);
    }
    #[test]
    fn trace_keeps_candidate_and_branch_detail_with_query_spans() {
        if tracing::level_filters::STATIC_MAX_LEVEL < tracing::level_filters::LevelFilter::TRACE {
            return;
        }
        let graph = ChannelGraph::new(key(1));
        route(&graph, key(1), key(2), 0);
        route(&graph, key(2), key(3), 100);
        let logs = Counts {
            include_trace: true,
            ..Default::default()
        };
        tracing::subscriber::with_default(logs.clone(), || {
            graph.simple_paths(
                &key(1),
                &key(3),
                2,
                None,
                EdgeValueFn::forward(2.try_into().unwrap(), 0.5, 0.1, Some(10u64.into())),
            );
            route(&graph, key(1), key(2), 100);
            graph.simple_paths(
                &key(1),
                &key(3),
                2,
                None,
                EdgeValueFn::forward(2.try_into().unwrap(), 0.5, 0.1, Some(10u64.into())),
            );
        });
        assert!(
            logs.trace.load(Ordering::Relaxed) >= 4,
            "branch, candidate and both query completions survive at TRACE"
        );
        assert!(logs.spans.load(Ordering::Relaxed) >= 2);
        let state = graph.graph_state(None);
        let success = state.searches.samples.iter().find(|s| s.returned == 1).unwrap();
        assert_eq!(
            success.returned_path_nodes,
            Some(vec![key(1).to_string(), key(2).to_string(), key(3).to_string()])
        );
    }
    #[test]
    fn successful_query_churn_does_not_displace_recent_failure_evidence() {
        let graph = ChannelGraph::new(key(1));
        route(&graph, key(1), key(2), 100);
        graph.simple_paths(
            &key(1),
            &key(3),
            1,
            None,
            EdgeValueFn::forward(1.try_into().unwrap(), 0.5, 0.1, None),
        );
        graph.simple_paths(
            &key(4),
            &key(1),
            1,
            None,
            EdgeValueFn::returning(1.try_into().unwrap(), 0.5, 0.1, None),
        );
        for _ in 0..100 {
            graph.simple_paths(
                &key(1),
                &key(2),
                1,
                None,
                EdgeValueFn::forward(1.try_into().unwrap(), 0.5, 0.1, None),
            );
        }
        let state = graph.searches.snapshot();
        assert_eq!(state.samples.len(), 2);
        assert!(state.samples.iter().all(|s| s.returned == 0));
        assert!(state.samples.iter().any(|s| s.direction == "forward"));
        assert!(state.samples.iter().any(|s| s.direction == "return"));
    }
}
