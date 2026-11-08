//! A declarative harness for channel-graph integration tests.
//!
//! Tests describe a HOPR topology as inline JSON and assert on routes named the way the JSON names
//! them, so a failure reads as "expected me→r1→exit, got me→r2→exit" rather than as a diff of
//! public keys.
//!
//! ```ignore
//! let net = Net::from_json(r#"{
//!   "me": "me",
//!   "edges": [
//!     { "from": "me", "to": "r1", "connected": true, "latency_ms": 20, "balance": 10000, "relayed_ms": 30 },
//!     { "from": "r1", "to": "exit", "balance": 10000, "relayed_ms": 30 }
//!   ]
//! }"#)?;
//! assert_eq!(net.forward("exit", 1).names(), vec![vec!["r1"]]);
//! ```
//!
//! Every field is optional and *absence means unobserved*, which is the distinction the graph
//! exists to preserve: an edge with no `connected` has never been checked, which is not the same as
//! `"connected": false`.

#![allow(dead_code)] // Each integration test binary uses a different subset of the harness.

use std::collections::HashMap;

use hopr_api::{
    OffchainPublicKey,
    graph::{
        NetworkGraphTraverse, NetworkGraphUpdate, NetworkGraphView, NetworkGraphWrite,
        function::EdgeValueFn,
        traits::{Balance, EdgeObservableWrite, EdgeWeightType},
    },
    types::crypto::prelude::{Keypair, OffchainKeypair},
};
use hopr_network_graph::{
    ChannelGraph, DEFAULT_EDGE_PENALTY, DEFAULT_MAX_PLAUSIBLE_LOOPBACK_RTT, DEFAULT_MIN_ACK_RATE, Observations,
};

/// A whole network, as one JSON object.
#[derive(Debug, serde::Deserialize)]
pub struct Scenario {
    /// The node the graph belongs to. Every path is planned from here.
    me: String,
    /// Nodes with no edges, which would otherwise be unnameable.
    #[serde(default)]
    nodes: Vec<String>,
    #[serde(default)]
    edges: Vec<Edge>,
    /// Network-wide single-hop ticket price. Absent means the graph has not been told one.
    #[serde(default)]
    ticket_face_value: Option<u64>,
    /// Multiplier for edges with no probe observations. Absent means the RFC default.
    #[serde(default)]
    edge_penalty: Option<f64>,
    /// Acknowledgement floor below which the data path rejects an edge.
    #[serde(default)]
    min_ack_rate: Option<f64>,
}

/// One directed edge. A HOPR channel is unidirectional, so `a→b` and `b→a` are separate entries.
#[derive(Debug, serde::Deserialize)]
pub struct Edge {
    from: String,
    to: String,
    /// Transport reachability. Absent = never observed, which must not read as "down".
    #[serde(default)]
    connected: Option<bool>,
    /// Latency of a *successful* direct probe, in milliseconds. Fractions are honoured.
    #[serde(default)]
    latency_ms: Option<f64>,
    /// Failed direct probes, recorded after any success.
    #[serde(default)]
    failed_probes: u32,
    /// Latency attributed by a *successful* loopback probe.
    #[serde(default)]
    relayed_ms: Option<f64>,
    /// Failed loopback probes.
    #[serde(default)]
    failed_relays: u32,
    /// Remaining channel balance in base units. Absent = unknown; `0` = an open but drained channel.
    #[serde(default)]
    balance: Option<u64>,
    /// Packets sent to the immediate peer, for the acknowledgement rate.
    #[serde(default)]
    packets: u64,
    /// Acknowledgements received back.
    #[serde(default)]
    acks: u64,
    /// SURB round-trips minted over this edge and how many replies arrived.
    #[serde(default)]
    surbs: Option<[u64; 2]>,
}

/// A built graph plus the names needed to read results back.
pub struct Net {
    pub graph: ChannelGraph,
    me: String,
    by_name: HashMap<String, OffchainPublicKey>,
    by_key: HashMap<OffchainPublicKey, String>,
    ticket_face_value: Option<Balance>,
    edge_penalty: f64,
    min_ack_rate: f64,
}

/// Routes as names, with the value the selector assigned each.
#[derive(Debug)]
pub struct Routes(pub Vec<(Vec<String>, f64)>);

impl Routes {
    /// Just the hop names, sorted, so assertions do not depend on sampling order.
    pub fn names(&self) -> Vec<Vec<String>> {
        let mut out: Vec<Vec<String>> = self.0.iter().map(|(hops, _)| hops.clone()).collect();
        out.sort();
        out
    }

    /// The value assigned to one route, identified by its hop names.
    pub fn value_of(&self, hops: &[&str]) -> Option<f64> {
        self.0
            .iter()
            .find(|(names, _)| names.iter().map(String::as_str).eq(hops.iter().copied()))
            .map(|(_, value)| *value)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

/// The canonical relayed shape `me → r1 → exit`, with each edge's JSON supplied by the caller.
///
/// Most scenarios vary exactly one field on one edge; spelling the whole topology out each time
/// buries that difference in boilerplate.
pub fn relayed(first: &str, last: &str) -> String {
    format!(r#"{{ "me": "me", "ticket_face_value": 100, "edges": [ {first}, {last} ] }}"#)
}

/// The fully healthy `me → r1` first edge, for scenarios that vary only the last one.
pub const HEALTHY_FIRST: &str =
    r#"{ "from": "me", "to": "r1", "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30 }"#;

/// The fully healthy `r1 → exit` last edge, for scenarios that vary only the first one.
pub const HEALTHY_LAST: &str =
    r#"{ "from": "r1", "to": "exit", "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30 }"#;

/// Derives a stable key from a node name, so a scenario always builds the same graph.
///
/// Reproducibility matters beyond convenience: `PathId` slots are derived from the key, so a random
/// key would make slot assertions differ run to run.
fn key_for(name: &str) -> OffchainPublicKey {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in name.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }

    let mut secret = [0u8; 32];
    for (i, chunk) in secret.chunks_mut(8).enumerate() {
        chunk.copy_from_slice(&hash.wrapping_add(i as u64).to_be_bytes());
    }
    // Off-chain keys are ed25519, which clamps rather than rejecting, so any 32 bytes are a secret.
    *OffchainKeypair::from_secret(&secret)
        .expect("32 bytes is always a valid ed25519 secret")
        .public()
}

impl Net {
    /// Builds a graph from an inline scenario.
    pub fn from_json(json: &str) -> anyhow::Result<Self> {
        let scenario: Scenario = serde_json::from_str(json)?;
        Self::build(scenario)
    }

    fn build(scenario: Scenario) -> anyhow::Result<Self> {
        let edge_penalty = scenario.edge_penalty.unwrap_or(DEFAULT_EDGE_PENALTY);
        let min_ack_rate = scenario.min_ack_rate.unwrap_or(DEFAULT_MIN_ACK_RATE);

        let me_key = key_for(&scenario.me);
        let graph =
            ChannelGraph::with_edge_params(me_key, edge_penalty, min_ack_rate, DEFAULT_MAX_PLAUSIBLE_LOOPBACK_RTT);

        let mut by_name: HashMap<String, OffchainPublicKey> = HashMap::new();
        let mut by_key: HashMap<OffchainPublicKey, String> = HashMap::new();
        let mut register = |name: &str| {
            let key = key_for(name);
            by_name.insert(name.to_string(), key);
            by_key.insert(key, name.to_string());
            key
        };

        register(&scenario.me);
        for name in scenario
            .nodes
            .iter()
            .chain(scenario.edges.iter().flat_map(|edge| [&edge.from, &edge.to]))
        {
            graph.add_node(register(name));
        }

        if let Some(value) = scenario.ticket_face_value {
            graph.set_ticket_face_value(Balance::from(value));
        }

        for edge in &scenario.edges {
            let (src, dest) = (by_name[&edge.from], by_name[&edge.to]);
            // `upsert_edge` creates the edge, so an entry with no observations still yields a
            // topological edge that has simply never been measured.
            graph.upsert_edge(&src, &dest, |obs| apply(obs, edge));
        }

        Ok(Self {
            graph,
            me: scenario.me,
            by_name,
            by_key,
            ticket_face_value: scenario.ticket_face_value.map(Balance::from),
            edge_penalty,
            min_ack_rate,
        })
    }

    /// The public key a name refers to.
    pub fn key(&self, name: &str) -> OffchainPublicKey {
        *self
            .by_name
            .get(name)
            .unwrap_or_else(|| panic!("node {name:?} is not in the scenario"))
    }

    /// The name of a key, for readable assertions.
    pub fn name(&self, key: &OffchainPublicKey) -> String {
        self.by_key.get(key).cloned().unwrap_or_else(|| "<unknown>".into())
    }

    fn length(hops: usize) -> std::num::NonZeroUsize {
        // A path of `hops` relays traverses `hops + 1` edges, and both the traversal and the value
        // function count edges.
        std::num::NonZeroUsize::new(hops + 1).expect("hops + 1 is never zero")
    }

    fn to_routes<T>(&self, raw: Vec<(Vec<OffchainPublicKey>, T, f64)>) -> Routes {
        Routes(
            raw.into_iter()
                .map(|(nodes, _, value)| (nodes.iter().map(|key| self.name(key)).collect(), value))
                .collect(),
        )
    }

    /// Forward data paths to `dest` over exactly `hops` relays.
    ///
    /// `hops == 0` is the direct case: RFC-0004 needs no channel on a final hop, so a 0-hop path is
    /// one channel-less edge.
    pub fn forward(&self, dest: &str, hops: usize) -> Routes {
        let value_fn = EdgeValueFn::forward(
            Self::length(hops),
            self.edge_penalty,
            self.min_ack_rate,
            self.ticket_face_value,
        );
        self.to_routes(
            self.graph
                .simple_paths(&self.key(&self.me), &self.key(dest), hops + 1, None, value_fn),
        )
    }

    /// Return paths from `source` back to `me`, as the planner builds them for SURBs.
    pub fn returning(&self, source: &str, hops: usize) -> Routes {
        let value_fn = EdgeValueFn::returning(
            Self::length(hops),
            self.edge_penalty,
            self.min_ack_rate,
            self.ticket_face_value,
        );
        self.to_routes(
            self.graph
                .simple_paths(&self.key(source), &self.key(&self.me), hops + 1, None, value_fn),
        )
    }

    /// Loopback probe paths of exactly `hops` intermediate relays, closing back at `me`.
    pub fn loopback(&self, hops: usize) -> Vec<Vec<String>> {
        self.loopback_raw(hops).into_iter().map(|(names, _)| names).collect()
    }

    /// The `PathId` slots those same loops carry, for conformance assertions.
    pub fn loopback_slots(&self, hops: usize) -> Vec<[u64; 5]> {
        self.loopback_raw(hops).into_iter().map(|(_, slots)| slots).collect()
    }

    /// Loops as (names, slots), sorted so assertions do not depend on sampling order.
    fn loopback_raw(&self, hops: usize) -> Vec<(Vec<String>, [u64; 5])> {
        let mut out: Vec<(Vec<String>, [u64; 5])> = self
            .graph
            .simple_loopback_to_self(hops, None)
            .into_iter()
            .map(|(nodes, path_id)| (nodes.iter().map(|key| self.name(key)).collect(), path_id))
            .collect();
        out.sort();
        out
    }

    /// The slot a node occupies in a `PathId`.
    pub fn slot(&self, name: &str) -> Option<u64> {
        self.graph.path_slot(&self.key(name))
    }

    /// Records further observations on an existing edge, for tests that evolve a graph.
    pub fn observe(&self, from: &str, to: &str, f: impl FnOnce(&mut Observations)) {
        self.graph.upsert_edge(&self.key(from), &self.key(to), f);
    }

    /// The aggregate score the graph currently reports for an edge.
    pub fn score(&self, from: &str, to: &str) -> Option<f64> {
        use hopr_api::graph::traits::EdgeObservableRead;
        self.graph.edge(&self.key(from), &self.key(to))?.score()
    }
}

/// Translates one scenario edge into the observation stream the producers would have written.
fn apply(obs: &mut Observations, edge: &Edge) {
    if let Some(connected) = edge.connected {
        obs.record(EdgeWeightType::Connected(connected));
    }
    if let Some(ms) = edge.latency_ms {
        obs.record(EdgeWeightType::Immediate(Ok(std::time::Duration::from_secs_f64(
            ms / 1000.0,
        ))));
    }
    for _ in 0..edge.failed_probes {
        obs.record(EdgeWeightType::Immediate(Err(())));
    }
    if let Some(ms) = edge.relayed_ms {
        obs.record(EdgeWeightType::Intermediate(Ok(std::time::Duration::from_secs_f64(
            ms / 1000.0,
        ))));
    }
    for _ in 0..edge.failed_relays {
        obs.record(EdgeWeightType::Intermediate(Err(())));
    }
    // An absent balance is left unrecorded rather than recorded as `None`: the graph reports an
    // untouched channel as unknown anyway, and `Some(0)` — open but drained — stays expressible.
    if let Some(balance) = edge.balance {
        obs.record(EdgeWeightType::Balance(Some(Balance::from(balance))));
    }
    if edge.packets > 0 {
        obs.record(EdgeWeightType::ImmediateProtocolConformance {
            num_packets: edge.packets,
            num_acks: edge.acks,
        });
    }
    if let Some([expected, observed]) = edge.surbs {
        obs.record(EdgeWeightType::SurbRoundTrips { expected, observed });
    }
}
