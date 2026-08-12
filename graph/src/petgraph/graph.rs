use std::sync::Arc;

use bimap::BiHashMap;
use hopr_api::OffchainPublicKey;
use parking_lot::RwLock;
use petgraph::{graph::NodeIndex, stable_graph::StableDiGraph};

use crate::{Observations, errors::ChannelGraphError};

/// Internal mutable state of a [`ChannelGraph`], protected by a lock.
#[derive(Debug, Clone, Default)]
pub(crate) struct InnerGraph {
    pub(crate) graph: StableDiGraph<OffchainPublicKey, Observations>,
    pub(crate) indices: BiHashMap<OffchainPublicKey, NodeIndex>,
    /// Reverse of [`path_id::encode`](crate::petgraph::path_id::encode), maintained beside `indices`.
    ///
    /// Resolution runs per node pair while a telemetry report holds the write lock, so scanning
    /// every node and re-encoding its key made one report cost time proportional to the size of the
    /// network. Slots are 64 bits wide and derived from keys we do not choose, so one can in
    /// principle be claimed twice; the entry keeps every claimant rather than the first, which is
    /// what lets resolution keep failing closed on an ambiguous slot instead of guessing.
    pub(crate) slots: std::collections::HashMap<u64, Vec<NodeIndex>>,
}

impl InnerGraph {
    /// Registers a node's slot claim. Idempotent for a key already registered at that index.
    pub(crate) fn claim_slot(&mut self, key: &OffchainPublicKey, idx: NodeIndex) {
        let claimants = self.slots.entry(crate::petgraph::path_id::encode(key)).or_default();
        if !claimants.contains(&idx) {
            claimants.push(idx);
        }
    }

    /// Releases a node's slot claim, dropping the entry once nothing claims it.
    pub(crate) fn release_slot(&mut self, key: &OffchainPublicKey, idx: NodeIndex) {
        let slot = crate::petgraph::path_id::encode(key);
        if let Some(claimants) = self.slots.get_mut(&slot) {
            claimants.retain(|held| *held != idx);
            if claimants.is_empty() {
                self.slots.remove(&slot);
            }
        }
    }
}

/// A directed graph representing logical channels between nodes.
///
/// The graph is directed, with nodes representing the physical nodes in the network using
/// their [`OffchainPublicKey`] as identifier and edges representing the logical channels
/// between them. Each logical channel aggregates different weighted properties, like
/// channel capacity (calculated from the on-chain channel balance, ticket price and ticket probability)
/// and evaluated transport network properties between the nodes.
///
/// Interior mutability is provided via an internal [`RwLock`] so that all trait
/// methods (which take `&self`) can safely read and write the graph. In production
/// code, the graph is expected to be shared behind an `Arc<ChannelGraph>`.
#[derive(Debug, Clone)]
pub struct ChannelGraph {
    pub(crate) me: OffchainPublicKey,
    pub(crate) edge_penalty: f64,
    pub(crate) min_ack_rate: f64,
    pub(crate) max_plausible_loopback_rtt: std::time::Duration,
    /// Current single-hop ticket face value, pushed in whenever the price or winning probability
    /// changes. Held once for the whole graph so a change costs one write, not an edge sweep.
    pub(crate) ticket_face_value: Arc<RwLock<Option<hopr_api::graph::traits::Balance>>>,
    pub(crate) inner: Arc<RwLock<InnerGraph>>,
}

impl ChannelGraph {
    /// Creates a new channel graph with the given self identity and default edge scoring
    /// parameters (edge_penalty = 0.5, min_ack_rate = 0.1).
    ///
    /// The `me` key represents the local node which is automatically added
    /// to the graph as the first node.
    ///
    /// Production code should prefer [`with_edge_params`](Self::with_edge_params) to
    /// receive values from `PathPlannerConfig`.
    pub fn new(me: OffchainPublicKey) -> Self {
        Self::with_edge_params(me, 0.5, 0.1, std::time::Duration::from_secs(30))
    }

    /// Creates a new channel graph with custom edge scoring parameters.
    ///
    /// * `me` – offchain public key of the local node (added as the first graph node).
    /// * `edge_penalty` – penalty multiplier for edges lacking probe-based quality observations.
    /// * `min_ack_rate` – minimum acknowledgment rate for **data** path selection; deliberately not applied to loopback
    ///   probe generation.
    /// * `max_plausible_loopback_rtt` – upper bound on a loopback probe RTT considered plausible; measurements above it
    ///   are discarded during attribution.
    pub fn with_edge_params(
        me: OffchainPublicKey,
        edge_penalty: f64,
        min_ack_rate: f64,
        max_plausible_loopback_rtt: std::time::Duration,
    ) -> Self {
        let mut graph = StableDiGraph::new();
        let mut indices = BiHashMap::new();

        let idx = graph.add_node(me);
        indices.insert(me, idx);
        let mut slots: std::collections::HashMap<u64, Vec<NodeIndex>> = std::collections::HashMap::new();
        slots
            .entry(crate::petgraph::path_id::encode(&me))
            .or_default()
            .push(idx);

        Self {
            me,
            edge_penalty,
            min_ack_rate,
            max_plausible_loopback_rtt,
            ticket_face_value: Arc::new(RwLock::new(None)),
            inner: Arc::new(RwLock::new(InnerGraph { graph, indices, slots })),
        }
    }

    /// Returns the self-identity key of this graph.
    pub fn me(&self) -> &OffchainPublicKey {
        &self.me
    }

    /// Returns the configured penalty multiplier for edges lacking probe observations.
    pub fn edge_penalty(&self) -> f64 {
        self.edge_penalty
    }

    /// Returns the configured minimum acknowledgement rate for data path selection.
    ///
    /// Exposed so data-path callers apply the same threshold the graph was built with. Not applied
    /// to loopback probe generation, which must reach edges data selection rejects.
    pub fn min_ack_rate(&self) -> f64 {
        self.min_ack_rate
    }
}

impl hopr_api::graph::NetworkGraphView for ChannelGraph {
    type NodeId = OffchainPublicKey;
    type Observed = Observations;

    fn ticket_face_value(&self) -> Option<hopr_api::graph::traits::Balance> {
        *self.ticket_face_value.read()
    }

    fn node_count(&self) -> usize {
        // The key mapping, not the vertex count: a removed node stays behind as an isolated vertex
        // so its slot is never reissued (see `remove_node`), and those must not be counted.
        self.inner.read().indices.len()
    }

    fn contains_node(&self, key: &OffchainPublicKey) -> bool {
        self.inner.read().indices.contains_left(key)
    }

    fn nodes(&self) -> futures::stream::BoxStream<'static, Self::NodeId> {
        let keys: Vec<OffchainPublicKey> = {
            let inner = self.inner.read();
            inner.indices.left_values().copied().collect()
        };

        Box::pin(futures::stream::iter(keys))
    }

    fn has_edge(&self, src: &OffchainPublicKey, dest: &OffchainPublicKey) -> bool {
        let inner = self.inner.read();
        let (Some(src_idx), Some(dest_idx)) = (inner.indices.get_by_left(src), inner.indices.get_by_left(dest)) else {
            return false;
        };
        inner.graph.contains_edge(*src_idx, *dest_idx)
    }

    fn edge(&self, src: &Self::NodeId, dest: &Self::NodeId) -> Option<Self::Observed> {
        let inner = self.inner.read();
        let src_idx = inner.indices.get_by_left(src)?;
        let dest_idx = inner.indices.get_by_left(dest)?;
        let edge_idx = inner.graph.find_edge(*src_idx, *dest_idx)?;
        inner.graph.edge_weight(edge_idx).copied()
    }

    fn identity(&self) -> &OffchainPublicKey {
        &self.me
    }

    fn path_slot(&self, key: &OffchainPublicKey) -> Option<u64> {
        // The same value `find_paths` writes into a `PathId`, so ids assembled from keys and ids
        // handed out by path selection resolve identically. Key-derived rather than the node index:
        // RFC-0010 §4.3.3 reserves `0` for padding, which a zero-based index cannot honour.
        self.inner
            .read()
            .indices
            .contains_left(key)
            .then(|| crate::petgraph::path_id::encode(key))
    }
}

impl hopr_api::graph::NetworkGraphWrite for ChannelGraph {
    type Error = ChannelGraphError;
    type NodeId = OffchainPublicKey;
    type Observed = Observations;

    fn add_node(&self, key: OffchainPublicKey) {
        let mut inner = self.inner.write();
        if !inner.indices.contains_left(&key) {
            let idx = inner.graph.add_node(key);
            inner.indices.insert(key, idx);
            inner.claim_slot(&key, idx);
        }
    }

    /// Removes a node, retiring its slot rather than freeing it.
    ///
    /// A [`StableDiGraph`] keeps every other node's index where it is, but it also keeps a free
    /// list, so a genuinely removed node's index is handed to the next node added. Both halves
    /// matter here: a [`PathId`](hopr_api::types::internal::routing::PathId) names nodes by slot,
    /// and SURB telemetry resolves slots when a round-trip is minted but reports them an interval
    /// later. A slot that came to mean a different node in between would credit edges the
    /// round-trip never traversed, and would look entirely ordinary while doing it -- the legs
    /// would join and the edges would exist.
    ///
    /// So the node is emptied instead of deleted: every incident edge goes, and it is dropped from
    /// the key mapping, which is what every lookup and every traversal reads. What is left behind
    /// is an isolated, unreachable vertex whose only job is to hold its index out of circulation.
    /// A stale id that lands on it finds no edges and the report is discarded, which is the correct
    /// outcome for evidence about a node that is gone.
    fn remove_node(&self, key: &OffchainPublicKey) {
        let mut inner = self.inner.write();
        if let Some((_, idx)) = inner.indices.remove_by_left(key) {
            inner.release_slot(key, idx);
            let incident: Vec<_> = {
                use petgraph::visit::EdgeRef;

                inner
                    .graph
                    .edges_directed(idx, petgraph::Direction::Outgoing)
                    .chain(inner.graph.edges_directed(idx, petgraph::Direction::Incoming))
                    .map(|e| e.id())
                    .collect()
            };

            for edge in incident {
                inner.graph.remove_edge(edge);
            }
        }
    }

    fn add_edge(&self, src: &OffchainPublicKey, dest: &OffchainPublicKey) -> Result<(), ChannelGraphError> {
        let mut inner = self.inner.write();
        let src_idx = inner
            .indices
            .get_by_left(src)
            .copied()
            .ok_or(ChannelGraphError::PublicKeyNodeNotFound(*src))?;
        let dest_idx = inner
            .indices
            .get_by_left(dest)
            .copied()
            .ok_or(ChannelGraphError::PublicKeyNodeNotFound(*dest))?;

        if inner.graph.find_edge(src_idx, dest_idx).is_none() {
            inner.graph.add_edge(src_idx, dest_idx, Observations::default());
        }

        Ok(())
    }

    fn remove_edge(&self, src: &OffchainPublicKey, dest: &OffchainPublicKey) {
        let mut inner = self.inner.write();
        if let (Some(src_idx), Some(dest_idx)) = (
            inner.indices.get_by_left(src).copied(),
            inner.indices.get_by_left(dest).copied(),
        ) && let Some(edge_idx) = inner.graph.find_edge(src_idx, dest_idx)
        {
            inner.graph.remove_edge(edge_idx);
        }
    }

    /// Mutably updates the edge observations between two nodes.
    ///
    /// If the edge does not exist, it gets created first.
    ///
    /// If the nodes do not exist, they are added as well.
    #[tracing::instrument(level = "debug", skip(self, f))]
    fn upsert_edge<F>(&self, src: &OffchainPublicKey, dest: &OffchainPublicKey, f: F)
    where
        F: FnOnce(&mut Observations),
    {
        let mut inner = self.inner.write();

        let src_idx = if let Some(src_idx) = inner.indices.get_by_left(src) {
            *src_idx
        } else {
            // src node missing, add it
            let idx = inner.graph.add_node(*src);
            inner.indices.insert(*src, idx);
            inner.claim_slot(src, idx);
            idx
        };

        let dest_idx = if let Some(dest_idx) = inner.indices.get_by_left(dest) {
            *dest_idx
        } else {
            // dest node missing, add it
            let idx = inner.graph.add_node(*dest);
            inner.indices.insert(*dest, idx);
            inner.claim_slot(dest, idx);
            idx
        };

        let edge_idx = inner
            .graph
            .find_edge(src_idx, dest_idx)
            .unwrap_or_else(|| inner.graph.add_edge(src_idx, dest_idx, Observations::default()));

        if let Some(weight) = inner.graph.edge_weight_mut(edge_idx) {
            f(weight);
            tracing::debug!(%src, %dest, ?weight, "updated edge weight with an observation");
        }
    }
}

impl hopr_api::graph::NetworkGraphConnectivity for ChannelGraph {
    type NodeId = OffchainPublicKey;
    type Observed = Observations;

    fn connected_edges(&self) -> Vec<(OffchainPublicKey, OffchainPublicKey, Observations)> {
        let inner = self.inner.read();
        inner
            .graph
            .edge_indices()
            .filter_map(|ei| {
                let (src_idx, dst_idx) = inner.graph.edge_endpoints(ei)?;
                let src = inner.graph.node_weight(src_idx)?;
                let dst = inner.graph.node_weight(dst_idx)?;
                let obs = inner.graph.edge_weight(ei)?;
                Some((*src, *dst, *obs))
            })
            .collect()
    }

    fn reachable_edges(&self) -> Vec<(OffchainPublicKey, OffchainPublicKey, Observations)> {
        let inner = self.inner.read();
        let Some(&me_idx) = inner.indices.get_by_left(&self.me) else {
            return vec![];
        };

        let mut reachable = std::collections::HashSet::new();
        let mut bfs = petgraph::visit::Bfs::new(&inner.graph, me_idx);
        while let Some(node_idx) = bfs.next(&inner.graph) {
            reachable.insert(node_idx);
        }

        inner
            .graph
            .edge_indices()
            .filter_map(|ei| {
                let (src_idx, dst_idx) = inner.graph.edge_endpoints(ei)?;
                if !reachable.contains(&src_idx) || !reachable.contains(&dst_idx) {
                    return None;
                }
                let src = inner.graph.node_weight(src_idx)?;
                let dst = inner.graph.node_weight(dst_idx)?;
                let obs = inner.graph.edge_weight(ei)?;
                Some((*src, *dst, *obs))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use hopr_api::{
        graph::{
            EdgeLinkObservable, NetworkGraphConnectivity, NetworkGraphView, NetworkGraphWrite,
            traits::{EdgeObservableRead, EdgeObservableWrite, EdgeWeightType},
        },
        types::crypto::prelude::{Keypair, OffchainKeypair},
    };

    use super::*;

    /// Fixed test secret keys (reused from the broader codebase).
    const SECRET_0: [u8; 32] = hex!("60741b83b99e36aa0c1331578156e16b8e21166d01834abb6c64b103f885734d");
    const SECRET_1: [u8; 32] = hex!("71bf1f42ebbfcd89c3e197a3fd7cda79b92499e509b6fefa0fe44d02821d146a");
    const SECRET_2: [u8; 32] = hex!("c24bd833704dd2abdae3933fcc9962c2ac404f84132224c474147382d4db2299");
    const SECRET_3: [u8; 32] = hex!("e0bf93e9c916104da00b1850adc4608bd7e9087bbd3f805451f4556aa6b3fd6e");
    const SECRET_4: [u8; 32] = hex!("cfc66f718ec66fb822391775d749d7a0d66b690927673634816b63339bc12a3c");
    const SECRET_5: [u8; 32] = hex!("203ca4d3c5f98dd2066bb204b5930c10b15c095585c224c826b4e11f08bfa85d");
    const SECRET_7: [u8; 32] = hex!("4ab03f6f75f845ca1bf8b7104804ea5bda18bda29d1ec5fc5d4267feca5fb8e1");

    /// Creates an OffchainPublicKey from a fixed secret.
    fn pubkey_from(secret: &[u8; 32]) -> OffchainPublicKey {
        *OffchainKeypair::from_secret(secret).expect("valid secret key").public()
    }

    #[test]
    fn new_graph_contains_self_node() -> anyhow::Result<()> {
        let me = pubkey_from(&SECRET_0);
        let graph = ChannelGraph::new(me);
        assert!(graph.contains_node(&me));
        assert_eq!(graph.node_count(), 1);
        Ok(())
    }

    #[test]
    fn path_slot_should_be_none_for_a_node_the_graph_does_not_know() -> anyhow::Result<()> {
        let graph = ChannelGraph::new(pubkey_from(&SECRET_0));

        assert_eq!(None, graph.path_slot(&pubkey_from(&SECRET_1)));
        Ok(())
    }

    #[test]
    fn path_slot_should_hand_out_the_slot_a_path_id_carries() -> anyhow::Result<()> {
        // Load-bearing: SURB round-trips assemble a `PathId` out of public keys via `path_slot`,
        // while path selection builds one itself. Both must name the same value, or a reported
        // round-trip credits whichever edges the wrong numbers happen to name -- silently, since a
        // mismatched slot simply fails to resolve.
        //
        // Asserted against the encoding rather than against fixed numbers: a test pinning only one
        // side passes happily while the other moves, which is how the two came to disagree. That
        // `find_paths` writes this same encoding is pinned in `traverse.rs`; the end-to-end
        // agreement is covered by the integration suite.
        let me = pubkey_from(&SECRET_0);
        let graph = ChannelGraph::new(me);
        let known = pubkey_from(&SECRET_1);
        graph.add_node(known);

        for key in [me, known] {
            assert_eq!(
                graph.path_slot(&key),
                Some(crate::petgraph::path_id::encode(&key)),
                "path_slot must hand out the key-derived slot a PathId carries"
            );
        }
        assert_eq!(
            None,
            graph.path_slot(&pubkey_from(&SECRET_4)),
            "a node the graph does not know has no slot"
        );
        Ok(())
    }

    #[test]
    fn a_removal_should_neither_move_another_node_nor_hand_its_slot_on() -> anyhow::Result<()> {
        // The property SURB attribution rests on. Slots are resolved when a round-trip is minted
        // and reported an interval later, so a slot that came to mean a different node in between
        // would credit edges the round-trip never traversed -- and would look entirely ordinary
        // while doing it. A vacated slot must therefore stay vacant.
        let me = pubkey_from(&SECRET_0);
        let graph = ChannelGraph::new(me);
        let middle = pubkey_from(&SECRET_1);
        let last = pubkey_from(&SECRET_2);
        graph.add_node(middle);
        graph.add_node(last);
        let (me_slot, middle_slot, last_slot) =
            (graph.path_slot(&me), graph.path_slot(&middle), graph.path_slot(&last));

        graph.remove_node(&middle);

        assert_eq!(None, graph.path_slot(&middle), "the removed node resolves to nothing");
        assert_eq!(me_slot, graph.path_slot(&me), "self must not move");
        assert_eq!(
            last_slot,
            graph.path_slot(&last),
            "a surviving node must keep the slot it had"
        );

        // Nor may a newcomer inherit it, which is what would make a stale id resolve to a live node.
        let newcomer = pubkey_from(&SECRET_3);
        graph.add_node(newcomer);
        assert_ne!(
            middle_slot,
            graph.path_slot(&newcomer),
            "a freed slot must not be handed to a different node"
        );
        Ok(())
    }

    #[test]
    fn adding_a_node_increases_count() -> anyhow::Result<()> {
        let me = pubkey_from(&SECRET_0);
        let graph = ChannelGraph::new(me);
        let peer = pubkey_from(&SECRET_1);
        graph.add_node(peer);
        assert!(graph.contains_node(&peer));
        assert_eq!(graph.node_count(), 2);
        Ok(())
    }

    #[test]
    fn adding_duplicate_node_is_idempotent() -> anyhow::Result<()> {
        let me = pubkey_from(&SECRET_0);
        let graph = ChannelGraph::new(me);
        let peer = pubkey_from(&SECRET_1);
        graph.add_node(peer);
        graph.add_node(peer);
        assert_eq!(graph.node_count(), 2);
        Ok(())
    }

    #[test]
    fn removing_a_node_decreases_count() -> anyhow::Result<()> {
        let me = pubkey_from(&SECRET_0);
        let graph = ChannelGraph::new(me);
        let peer = pubkey_from(&SECRET_1);
        graph.add_node(peer);
        assert_eq!(graph.node_count(), 2);
        graph.remove_node(&peer);
        assert!(!graph.contains_node(&peer));
        assert_eq!(graph.node_count(), 1);
        Ok(())
    }

    #[test]
    fn removing_nonexistent_node_is_noop() -> anyhow::Result<()> {
        let me = pubkey_from(&SECRET_0);
        let graph = ChannelGraph::new(me);
        graph.remove_node(&pubkey_from(&SECRET_7));
        assert_eq!(graph.node_count(), 1);
        Ok(())
    }

    #[test]
    fn adding_an_edge_between_nodes() -> anyhow::Result<()> {
        let me = pubkey_from(&SECRET_0);
        let graph = ChannelGraph::new(me);
        let peer = pubkey_from(&SECRET_1);
        graph.add_node(peer);
        graph.add_edge(&me, &peer)?;
        assert!(graph.has_edge(&me, &peer));
        assert!(!graph.has_edge(&peer, &me));
        Ok(())
    }

    #[test]
    fn adding_edge_to_missing_node_errors() -> anyhow::Result<()> {
        let me = pubkey_from(&SECRET_0);
        let graph = ChannelGraph::new(me);
        assert!(graph.add_edge(&me, &pubkey_from(&SECRET_7)).is_err());
        Ok(())
    }

    #[test]
    fn removing_a_node_also_removes_its_edges() -> anyhow::Result<()> {
        let me = pubkey_from(&SECRET_0);
        let graph = ChannelGraph::new(me);
        let peer = pubkey_from(&SECRET_1);
        graph.add_node(peer);
        graph.add_edge(&me, &peer)?;
        assert!(graph.has_edge(&me, &peer));
        graph.remove_node(&peer);
        assert!(!graph.has_edge(&me, &peer));
        Ok(())
    }

    #[tokio::test]
    async fn view_nodes_returns_all_graph_nodes() -> anyhow::Result<()> {
        use futures::StreamExt;

        let me = pubkey_from(&SECRET_0);
        let graph = ChannelGraph::new(me);
        let peers: Vec<_> = [SECRET_1, SECRET_2, SECRET_3, SECRET_4, SECRET_5]
            .iter()
            .map(pubkey_from)
            .collect();
        for &peer in &peers {
            graph.add_node(peer);
        }
        let nodes: Vec<_> = graph.nodes().collect().await;
        assert_eq!(nodes.len(), 6);
        assert!(nodes.contains(&me));
        for peer in &peers {
            assert!(nodes.contains(peer));
        }
        Ok(())
    }

    #[test]
    fn view_edge_returns_observations_for_existing_edge() -> anyhow::Result<()> {
        let me = pubkey_from(&SECRET_0);
        let graph = ChannelGraph::new(me);
        let peer = pubkey_from(&SECRET_1);
        graph.add_node(peer);
        graph.add_edge(&me, &peer)?;
        assert!(graph.edge(&me, &peer).is_some());
        Ok(())
    }

    #[test]
    fn view_edge_returns_none_for_missing_edge() -> anyhow::Result<()> {
        let me = pubkey_from(&SECRET_0);
        let graph = ChannelGraph::new(me);
        let peer = pubkey_from(&SECRET_1);
        assert!(graph.edge(&me, &peer).is_none());
        Ok(())
    }

    #[test]
    fn me_returns_self_identity() {
        let me = pubkey_from(&SECRET_0);
        let graph = ChannelGraph::new(me);
        assert_eq!(*graph.me(), me);
    }

    #[test]
    fn removing_an_edge_disconnects_nodes() -> anyhow::Result<()> {
        let me = pubkey_from(&SECRET_0);
        let peer = pubkey_from(&SECRET_1);
        let graph = ChannelGraph::new(me);
        graph.add_node(peer);
        graph.add_edge(&me, &peer)?;
        assert!(graph.has_edge(&me, &peer));

        graph.remove_edge(&me, &peer);
        assert!(!graph.has_edge(&me, &peer));
        // Nodes should still exist
        assert!(graph.contains_node(&me));
        assert!(graph.contains_node(&peer));
        Ok(())
    }

    #[test]
    fn removing_nonexistent_edge_is_noop() {
        let me = pubkey_from(&SECRET_0);
        let peer = pubkey_from(&SECRET_1);
        let graph = ChannelGraph::new(me);
        graph.add_node(peer);
        // No edge exists — should not panic
        graph.remove_edge(&me, &peer);
        assert!(!graph.has_edge(&me, &peer));
    }

    #[test]
    fn removing_edge_for_unknown_nodes_is_noop() {
        let me = pubkey_from(&SECRET_0);
        let graph = ChannelGraph::new(me);
        let unknown = pubkey_from(&SECRET_7);
        // Neither node known — should not panic
        graph.remove_edge(&me, &unknown);
    }

    #[test]
    fn edge_should_not_be_present_when_nodes_not_in_graph() {
        let me = pubkey_from(&SECRET_0);
        let graph = ChannelGraph::new(me);
        let unknown = pubkey_from(&SECRET_7);
        assert!(!graph.has_edge(&me, &unknown));
        assert!(!graph.has_edge(&unknown, &me));
    }

    #[test]
    fn edge_returns_none_when_nodes_not_in_graph() {
        let me = pubkey_from(&SECRET_0);
        let graph = ChannelGraph::new(me);
        let unknown = pubkey_from(&SECRET_7);
        assert!(graph.edge(&me, &unknown).is_none());
        assert!(graph.edge(&unknown, &me).is_none());
    }

    #[test]
    fn upsert_edge_creates_edge_when_absent() {
        let me = pubkey_from(&SECRET_0);
        let peer = pubkey_from(&SECRET_1);
        let graph = ChannelGraph::new(me);
        graph.add_node(peer);

        assert!(!graph.has_edge(&me, &peer));
        graph.upsert_edge(&me, &peer, |obs| {
            obs.record(EdgeWeightType::Immediate(Ok(std::time::Duration::from_millis(50))));
        });
        assert!(graph.has_edge(&me, &peer));

        let obs = graph.edge(&me, &peer).expect("edge should exist after upsert");
        assert!(obs.immediate_qos().is_some());
    }

    #[test]
    fn upsert_edge_updates_existing_edge() -> anyhow::Result<()> {
        let me = pubkey_from(&SECRET_0);
        let peer = pubkey_from(&SECRET_1);
        let graph = ChannelGraph::new(me);
        graph.add_node(peer);
        graph.add_edge(&me, &peer)?;

        graph.upsert_edge(&me, &peer, |obs| {
            obs.record(EdgeWeightType::Immediate(Ok(std::time::Duration::from_millis(100))));
        });
        graph.upsert_edge(&me, &peer, |obs| {
            obs.record(EdgeWeightType::Immediate(Ok(std::time::Duration::from_millis(200))));
        });

        let obs = graph.edge(&me, &peer).expect("edge should exist");
        let latency = obs
            .immediate_qos()
            .expect("should have immediate QoS")
            .average_latency()
            .expect("should have latency");
        // After two updates (100ms and 200ms), average should be between 100 and 200
        assert!(latency > std::time::Duration::from_millis(100));
        assert!(latency < std::time::Duration::from_millis(200));
        Ok(())
    }

    #[test]
    fn upsert_edge_adds_missing_dest_node_and_creates_edge() {
        let me = pubkey_from(&SECRET_0);
        let unknown = pubkey_from(&SECRET_7);
        let graph = ChannelGraph::new(me);

        assert!(!graph.contains_node(&unknown));
        graph.upsert_edge(&me, &unknown, |obs| {
            obs.record(EdgeWeightType::Immediate(Ok(std::time::Duration::from_millis(50))));
        });
        assert!(graph.contains_node(&unknown), "dest node should be auto-added");
        assert!(graph.has_edge(&me, &unknown), "edge should be created");
        assert!(graph.edge(&me, &unknown).unwrap().immediate_qos().is_some());
    }

    #[test]
    fn upsert_edge_adds_missing_src_node_and_creates_edge() {
        let me = pubkey_from(&SECRET_0);
        let unknown = pubkey_from(&SECRET_7);
        let graph = ChannelGraph::new(me);

        assert!(!graph.contains_node(&unknown));
        graph.upsert_edge(&unknown, &me, |obs| {
            obs.record(EdgeWeightType::Immediate(Ok(std::time::Duration::from_millis(50))));
        });
        assert!(graph.contains_node(&unknown), "src node should be auto-added");
        assert!(graph.has_edge(&unknown, &me), "edge should be created");
        assert!(graph.edge(&unknown, &me).unwrap().immediate_qos().is_some());
    }

    #[test]
    fn upsert_edge_adds_both_missing_nodes_and_creates_edge() {
        let me = pubkey_from(&SECRET_0);
        let a = pubkey_from(&SECRET_1);
        let b = pubkey_from(&SECRET_2);
        let graph = ChannelGraph::new(me);

        assert!(!graph.contains_node(&a));
        assert!(!graph.contains_node(&b));
        graph.upsert_edge(&a, &b, |obs| {
            obs.record(EdgeWeightType::Immediate(Ok(std::time::Duration::from_millis(50))));
        });
        assert!(graph.contains_node(&a), "src node should be auto-added");
        assert!(graph.contains_node(&b), "dest node should be auto-added");
        assert!(graph.has_edge(&a, &b), "edge should be created");
        assert!(graph.edge(&a, &b).unwrap().immediate_qos().is_some());
    }

    #[test]
    fn removing_non_last_node_preserves_other_nodes() -> anyhow::Result<()> {
        let me = pubkey_from(&SECRET_0);
        let a = pubkey_from(&SECRET_1);
        let b = pubkey_from(&SECRET_2);
        let c = pubkey_from(&SECRET_3);

        let graph = ChannelGraph::new(me);
        graph.add_node(a);
        graph.add_node(b);
        graph.add_node(c);
        assert_eq!(graph.node_count(), 4);

        // Remove a node that is not the last one (triggers index swap in petgraph)
        graph.remove_node(&a);
        assert_eq!(graph.node_count(), 3);
        assert!(!graph.contains_node(&a));
        assert!(graph.contains_node(&me));
        assert!(graph.contains_node(&b));
        assert!(graph.contains_node(&c));

        // Verify edges can still be added to remaining nodes
        graph.add_edge(&me, &b)?;
        graph.add_edge(&me, &c)?;
        assert!(graph.has_edge(&me, &b));
        assert!(graph.has_edge(&me, &c));
        Ok(())
    }

    #[test]
    fn removing_multiple_nodes_preserves_consistency() -> anyhow::Result<()> {
        let me = pubkey_from(&SECRET_0);
        let a = pubkey_from(&SECRET_1);
        let b = pubkey_from(&SECRET_2);
        let c = pubkey_from(&SECRET_3);
        let d = pubkey_from(&SECRET_4);

        let graph = ChannelGraph::new(me);
        graph.add_node(a);
        graph.add_node(b);
        graph.add_node(c);
        graph.add_node(d);

        graph.add_edge(&me, &a)?;
        graph.add_edge(&a, &b)?;
        graph.add_edge(&b, &c)?;
        graph.add_edge(&c, &d)?;

        // Remove middle nodes
        graph.remove_node(&b);
        graph.remove_node(&c);

        assert_eq!(graph.node_count(), 3);
        assert!(graph.contains_node(&me));
        assert!(graph.contains_node(&a));
        assert!(graph.contains_node(&d));

        // Edges through removed nodes should be gone
        assert!(!graph.has_edge(&a, &b));
        assert!(!graph.has_edge(&b, &c));
        assert!(!graph.has_edge(&c, &d));

        // Edge not involving removed nodes should survive
        assert!(graph.has_edge(&me, &a));
        Ok(())
    }

    #[test]
    fn edges_are_directed() -> anyhow::Result<()> {
        let me = pubkey_from(&SECRET_0);
        let peer = pubkey_from(&SECRET_1);
        let graph = ChannelGraph::new(me);
        graph.add_node(peer);
        graph.add_edge(&me, &peer)?;

        assert!(graph.has_edge(&me, &peer));
        assert!(!graph.has_edge(&peer, &me));

        assert!(graph.edge(&me, &peer).is_some());
        assert!(graph.edge(&peer, &me).is_none());
        Ok(())
    }

    #[test]
    fn connected_edges_should_exclude_isolated_nodes() {
        let me = pubkey_from(&SECRET_0);
        let a = pubkey_from(&SECRET_1);
        let isolated = pubkey_from(&SECRET_2);
        let graph = ChannelGraph::new(me);
        graph.add_node(a);
        graph.add_node(isolated); // no edges
        graph.add_edge(&me, &a).unwrap();

        let edges = graph.connected_edges();
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].0, me);
        assert_eq!(edges[0].1, a);

        // isolated node must not appear
        let all_keys: std::collections::HashSet<_> = edges.iter().flat_map(|(s, d, _)| [*s, *d]).collect();
        assert!(!all_keys.contains(&isolated));
    }

    #[test]
    fn connected_edges_should_preserve_observations() {
        let me = pubkey_from(&SECRET_0);
        let peer = pubkey_from(&SECRET_1);
        let graph = ChannelGraph::new(me);
        graph.add_node(peer);
        graph.upsert_edge(&me, &peer, |obs| {
            obs.record(EdgeWeightType::Connected(true));
            obs.record(EdgeWeightType::Immediate(Ok(std::time::Duration::from_millis(42))));
        });

        let edges = graph.connected_edges();
        assert_eq!(edges.len(), 1);
        let obs = &edges[0].2;
        assert!(obs.immediate_qos().is_some());
    }

    #[test]
    fn connected_edges_should_be_empty_when_no_edges() {
        let me = pubkey_from(&SECRET_0);
        let graph = ChannelGraph::new(me);
        graph.add_node(pubkey_from(&SECRET_1));
        assert!(graph.connected_edges().is_empty());
    }

    #[test]
    fn connected_edges_should_return_all_edges_in_diamond_topology() -> anyhow::Result<()> {
        let me = pubkey_from(&SECRET_0);
        let a = pubkey_from(&SECRET_1);
        let b = pubkey_from(&SECRET_2);
        let dest = pubkey_from(&SECRET_3);
        let graph = ChannelGraph::new(me);
        for n in [a, b, dest] {
            graph.add_node(n);
        }
        graph.add_edge(&me, &a)?;
        graph.add_edge(&me, &b)?;
        graph.add_edge(&a, &dest)?;
        graph.add_edge(&b, &dest)?;

        let edges = graph.connected_edges();
        assert_eq!(edges.len(), 4);
        Ok(())
    }
}
