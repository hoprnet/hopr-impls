use std::{
    hint::black_box,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use hopr_api::{
    OffchainKeypair, OffchainPublicKey,
    graph::{
        NetworkGraphTraverse, NetworkGraphWrite,
        function::EdgeValueFn,
        traits::{EdgeObservableWrite, EdgeWeightType},
    },
    types::crypto::prelude::Keypair,
};
use hopr_network_graph::ChannelGraph;

const BENCH_EDGE_PENALTY: f64 = 0.5;
/// Intentionally 0.0 for benchmarks (no ack filtering).
const BENCH_MIN_ACK_RATE: f64 = 0.0;

// ── Graph construction helpers ───────────────────────────────────────────────

/// Deterministically derives an [`OffchainPublicKey`] from a 32-bit index.
///
/// The first 4 bytes of the Ed25519 seed encode `i` in little-endian; the
/// remaining bytes are a fixed non-zero fill so that every seed is unique and
/// valid for all index values in `0..u32::MAX`.
fn key_from_index(i: u32) -> OffchainPublicKey {
    let mut secret = [0x5Au8; 32];
    secret[..4].copy_from_slice(&i.to_le_bytes());
    *OffchainKeypair::from_secret(&secret)
        .expect("deterministic secret is always valid for Ed25519")
        .public()
}

/// Builds a [`ChannelGraph`] with `node_count` nodes and a controlled edge
/// density using a ring-plus-chords topology.
///
/// Every edge is annotated with the full set of observations (connected,
/// immediate QoS, intermediate QoS, and payment-channel capacity), so it
/// satisfies any of the built-in cost functions without extra setup.
///
/// # Parameters
///
/// * `node_count` — number of nodes in the graph (including `me`).
/// * `density` — target edge-to-node ratio (e.g. `10`, `100`, `1_000`). Each node receives outgoing edges to the next
///   `min(node_count − 1, density)` nodes in the ring (wrapping around), giving `node_count × min(node_count − 1,
///   density)` total directed edges.
///
/// # Edge counts by (node_count, density)
///
/// | nodes | density | edges/node | total edges  |
/// |------:|--------:|-----------:|-------------:|
/// |    10 |      10 |          9 |           90 |
/// |    10 |     100 |          9 |           90 |
/// |    10 |   1 000 |          9 |           90 |
/// |   100 |      10 |         10 |        1 000 |
/// |   100 |     100 |         99 |        9 900 |
/// |   100 |   1 000 |         99 |        9 900 |
/// | 1 000 |      10 |         10 |       10 000 |
/// | 1 000 |     100 |        100 |      100 000 |
/// | 1 000 |   1 000 |        999 |      999 000 |
///
/// When `density ≥ node_count − 1` the graph is fully connected (no
/// self-loops), which is the theoretical maximum for a simple directed graph.
///
/// Returns the populated graph and the ordered key list (`keys[0]` is the
/// local node identity, i.e., `me`).
fn build_graph(node_count: usize, density: usize) -> (ChannelGraph, Vec<OffchainPublicKey>) {
    let edges_per_node = (node_count - 1).min(density);
    let keys: Vec<OffchainPublicKey> = (0..node_count as u32).map(key_from_index).collect();

    let graph = ChannelGraph::new(keys[0]);
    for &key in &keys[1..] {
        graph.add_node(key);
    }

    // Ring + chords: node i → (i+1)%N, (i+2)%N, …, (i+edges_per_node)%N.
    for i in 0..node_count {
        for step in 1..=edges_per_node {
            let j = (i + step) % node_count;
            graph.upsert_edge(&keys[i], &keys[j], |obs| {
                obs.record(EdgeWeightType::Connected(true));
                obs.record(EdgeWeightType::Immediate(Ok(Duration::from_millis(50))));
                obs.record(EdgeWeightType::Intermediate(Ok(Duration::from_millis(50))));
                obs.record(EdgeWeightType::Balance(Some(hopr_api::graph::traits::Balance::from(
                    1_000u64,
                ))));
            });
        }
    }

    (graph, keys)
}

fn summarize(mut times: Vec<u64>, seconds: f64) -> serde_json::Value {
    times.sort_unstable();
    let percentile = |p: usize| {
        times
            .get((times.len().saturating_sub(1) * p) / 100)
            .copied()
            .unwrap_or(0) as f64
            / 1000.0
    };
    serde_json::json!({"count":times.len(), "per_second":times.len() as f64 / seconds,
        "p50_us":percentile(50), "p99_us":percentile(99), "max_us":percentile(100)})
}

fn run(size: usize, density: usize, updates: bool) {
    let (graph, keys) = build_graph(size, density);
    let graph = Arc::new(graph);
    let select = |g: &ChannelGraph| {
        g.simple_paths(
            &keys[0],
            &keys[(2 * (size - 1).min(density) + 1).min(size - 1)],
            3,
            Some(10),
            EdgeValueFn::forward(
                std::num::NonZeroUsize::new(3).unwrap(),
                BENCH_EDGE_PENALTY,
                BENCH_MIN_ACK_RATE,
                None,
            ),
        )
    };
    let paths: Vec<_> = select(&graph).iter().map(|p| p.1).cycle().take(32).collect();
    assert_eq!(paths.len(), 32, "fixture must return paths");
    let phase = AtomicUsize::new(0);
    let progress = AtomicUsize::new(0);
    let stop_writer = AtomicBool::new(false);
    let result = thread::scope(|scope| {
        let selector = scope.spawn(|| {
            let mut timings: [Vec<u64>; 3] = Default::default();
            while phase.load(Ordering::Acquire) < 3 {
                let p = phase.load(Ordering::Acquire);
                if p >= 3 {
                    break;
                }
                let start = Instant::now();
                let candidates = black_box(select(&graph));
                assert!(!candidates.is_empty());
                let elapsed = start.elapsed().as_nanos() as u64;
                progress.fetch_add(1, Ordering::Relaxed);
                if phase.load(Ordering::Acquire) == p {
                    timings[p].push(elapsed);
                }
            }
            timings
        });
        let writer = scope.spawn(|| {
            let mut writes = 0;
            while !stop_writer.load(Ordering::Acquire) {
                if updates {
                    graph.upsert_edge(&keys[0], &keys[1], |obs| {
                        obs.record(EdgeWeightType::Connected(true));
                    });
                    writes += 1;
                }
                thread::sleep(Duration::from_millis(1));
            }
            writes
        });
        let pre = Instant::now();
        thread::sleep(Duration::from_secs(1));
        phase.store(1, Ordering::Release);
        let pre_seconds = pre.elapsed().as_secs_f64();
        let during = Instant::now();
        let mut dump_times = Vec::new();
        let mut dumps_with_progress = 0;
        let mut payload_bytes = 0;
        while during.elapsed() < Duration::from_secs(1) {
            let before = progress.load(Ordering::Relaxed);
            let start = Instant::now();
            let state = graph.state(Some(&paths)).unwrap();
            let payload = serde_json::to_vec(&state).unwrap();
            payload_bytes = payload.len();
            black_box(payload);
            dump_times.push(start.elapsed().as_nanos() as u64);
            dumps_with_progress += usize::from(progress.load(Ordering::Relaxed) > before);
            thread::sleep(Duration::from_millis(10));
        }
        phase.store(2, Ordering::Release);
        let during_seconds = during.elapsed().as_secs_f64();
        let post = Instant::now();
        thread::sleep(Duration::from_secs(1));
        phase.store(3, Ordering::Release);
        let post_seconds = post.elapsed().as_secs_f64();
        stop_writer.store(true, Ordering::Release);
        let [pre, during, post] = selector.join().unwrap();
        serde_json::json!({"nodes":size,"density":density,"updates":updates,"writes":writer.join().unwrap(),
            "pre":summarize(pre,pre_seconds),"during":summarize(during,during_seconds),"post":summarize(post,post_seconds),
            "dumps":summarize(dump_times,during_seconds),"dumps_with_search_progress":dumps_with_progress,"last_payload_bytes":payload_bytes})
    });
    println!("{result}");
}

fn main() {
    // 3-edge searches, capped at 10 candidates; dump includes 32 sampled paths.
    // Repeated dumps (~100 Hz) amplify contention compared with the 60 s default.
    // No tracing subscriber: this measures graph reads + JSON, not log-sink I/O.
    for (size, density) in [(100, 10), (1000, 1000)] {
        for updates in [false, true] {
            run(size, density, updates);
        }
    }
}
