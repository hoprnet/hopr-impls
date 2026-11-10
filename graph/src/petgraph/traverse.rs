use std::{
    collections::{HashMap, HashSet, VecDeque},
    hash::RandomState,
    sync::Arc,
};

use hopr_api::{
    OffchainPublicKey,
    graph::{
        function::EdgeValueFn,
        traits::{EdgeNetworkObservableRead, EdgeObservableRead, ValueFn},
    },
    types::internal::routing::PathId,
};
use petgraph::graph::NodeIndex;

use crate::{ChannelGraph, algorithm::all_simple_paths_multi_where, graph::InnerGraph, petgraph::path_id};

/// Lowest number of intermediate relay hops used for loopback probing.
///
/// RFC-0010 §4.2.1.2 permits `n = 1`, but then the sole relay sees its predecessor and successor
/// are the same node, identifying the loop and its originator. Excluding it is a local privacy
/// decision, not an RFC requirement.
pub const MIN_LOOPBACK_HOPS: usize = 2;

/// Highest number of intermediate relay hops used for loopback probing.
///
/// Bounded by the packet format: RFC-0004 requires 0–3 hops.
pub const MAX_LOOPBACK_HOPS: usize = hopr_api::types::internal::routing::RoutingOptions::MAX_INTERMEDIATE_HOPS;

/// A shared cost function that computes a cumulative cost from edge observations.
pub(crate) type SharedValueFn<C> = Arc<dyn Fn(C, &crate::Observations, usize) -> C + Send + Sync>;

/// Whether a traversal walks an edge the graph has judged dead (see `Observations::is_starved`).
///
/// Routing leaves such an edge out (RFC-0010 §4.2.3, the active tier). Probing walks it: a returning loop
/// is the only way it can be seen to recover. This is a second place that acts on the verdict next to the
/// value functions in `hopr-api`, which floor a dead edge at `MEASURED_DEAD_FLOOR` instead of excluding it.
/// Both read the same verdict; if either definition of "dead" changes, the other has to follow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StarvedEdges {
    Exclude,
    Walk,
}

/// Core path-finding routine that runs `all_simple_paths_multi_where` on the
/// inner petgraph.
#[allow(clippy::too_many_arguments)]
pub(crate) fn find_paths<C>(
    inner: &InnerGraph,
    source: NodeIndex,
    destinations: &HashSet<NodeIndex>,
    length: usize,
    take_count: Option<usize>,
    initial_value: C,
    min_value: Option<C>,
    value_fn: SharedValueFn<C>,
    starved: StarvedEdges,
) -> Vec<(Vec<OffchainPublicKey>, PathId, C)>
where
    C: Clone + PartialOrd,
{
    if length == 0 {
        return Default::default();
    }

    let intermediates = length - 1;

    let paths = all_simple_paths_multi_where::<Vec<_>, _, RandomState, _, _, _>(
        &inner.graph,
        source,
        destinations,
        None,
        intermediates,
        Some(intermediates),
        initial_value,
        min_value,
        move |c, w, i| value_fn(c, w, i),
        // A starved edge is what probing must still reach, so only routing leaves it out.
        move |w| starved == StarvedEdges::Walk || !w.is_starved(),
    )
    .filter_map(|(node_indices, final_cost)| {
        // Build the PathId along the path. Slots are key-derived via `path_id::encode`, so no
        // slot can collide with the reserved padding value `0` (RFC-0010 §4.3.3). The length comes
        // from the type rather than being restated here.
        let mut path_id: PathId = Default::default();
        for (i, &node_idx) in node_indices.iter().enumerate() {
            if i >= path_id.len() {
                return None;
            }
            // Slots are key-derived, so a node removed mid-flight can never be confused with
            // whichever node petgraph moves into its index.
            path_id[i] = path_id::encode(inner.indices.get_by_right(&node_idx)?);
        }

        // Convert node indices to public keys; strip `source` (first element).
        // path_id retains all indices including source for stable caching.
        let nodes = node_indices
            .into_iter()
            .skip(1)
            .filter_map(|v| inner.indices.get_by_right(&v).copied())
            .collect::<Vec<_>>();
        // After stripping source: intermediates + destination = length nodes.
        // `simple_paths` additionally pops the destination; the others return as-is.
        (nodes.len() == length).then_some((nodes, path_id, final_cost))
    });

    if let Some(take_count) = take_count {
        paths.take(take_count).collect::<Vec<_>>()
    } else {
        paths.collect::<Vec<_>>()
    }
}

impl hopr_api::graph::NetworkGraphTraverse for ChannelGraph {
    type NodeId = OffchainPublicKey;
    type Observed = crate::Observations;

    fn simple_paths<C: ValueFn<Weight = Self::Observed>>(
        &self,
        source: &Self::NodeId,
        destination: &Self::NodeId,
        length: usize,
        take_count: Option<usize>,
        value_fn: C,
    ) -> Vec<(Vec<Self::NodeId>, PathId, C::Value)> {
        if length == 0 {
            return Default::default();
        }

        let inner = self.inner.read();
        let Some(start) = inner.indices.get_by_left(source) else {
            return Default::default();
        };
        let Some(end) = inner.indices.get_by_left(destination) else {
            return Default::default();
        };
        let end = HashSet::from_iter([*end]);

        // find_paths returns [intermediates…, destination]; pop destination since caller
        // supplies it as an explicit input argument and it must not repeat in the path body.
        find_paths(
            &inner,
            *start,
            &end,
            length,
            take_count,
            value_fn.initial_value(),
            value_fn.min_value(),
            value_fn.into_value_fn(),
            StarvedEdges::Exclude,
        )
        .into_iter()
        .map(|(mut nodes, path_id, cost)| {
            nodes.pop(); // strip destination — caller already knows it
            (nodes, path_id, cost)
        })
        .collect()
    }

    fn simple_paths_from<C: ValueFn<Weight = Self::Observed>>(
        &self,
        source: &Self::NodeId,
        length: usize,
        take_count: Option<usize>,
        value_fn: C,
    ) -> Vec<(Vec<Self::NodeId>, PathId, C::Value)> {
        if length == 0 {
            return Default::default();
        }

        let inner = self.inner.read();
        let Some(start) = inner.indices.get_by_left(source) else {
            return Default::default();
        };

        let destinations: HashSet<NodeIndex> = inner.graph.node_indices().filter(|idx| idx != start).collect();

        find_paths(
            &inner,
            *start,
            &destinations,
            length,
            take_count,
            value_fn.initial_value(),
            value_fn.min_value(),
            value_fn.into_value_fn(),
            StarvedEdges::Exclude,
        )
    }

    /// Generates loopback paths of exactly `hops` intermediate relay nodes.
    ///
    /// NOTE: `hops` counts relay nodes, **not edges** — the closed loop has `hops + 1` edges, since
    /// the closing edge is appended after path-finding.
    ///
    /// Requests outside [`MIN_LOOPBACK_HOPS`]`..=`[`MAX_LOOPBACK_HOPS`] yield no paths.
    fn simple_loopback_to_self(&self, hops: usize, take_count: Option<usize>) -> Vec<(Vec<Self::NodeId>, PathId)> {
        if (MIN_LOOPBACK_HOPS..=MAX_LOOPBACK_HOPS).contains(&hops) {
            let inner = self.inner.read();

            if let Some(me_idx) = inner.indices.get_by_left(&self.me) {
                // The candidate set holds the *last* node before the appended closing `me`, so the
                // edge that matters is `neighbor → me`, not `me → neighbor`. Since
                // `MIN_LOOPBACK_HOPS` is 2, the destination is never the first hop, and the
                // outgoing edge plays no part in the emitted loop. `resolve_loopback_edges` rejects
                // a probe whose closing edge is absent, so requiring the incoming edge here is what
                // keeps the probe attributable. A successful neighbor probe upserts both
                // directions, so this excludes nothing that has actually been reached.
                let connected_neighbors = closing_neighbors(&inner, *me_idx);

                // Deliberately more permissive than data path selection, and the one traversal that still
                // walks a starved edge: a relay judged dead is excluded from routing (RFC-0010 §4.2.3, the
                // active tier), and loops that keep crossing it are how it is seen to recover. RFC-0010 §4.2.1.4 wants
                // low-scoring edges probed *more* urgently; applying the production `min_ack_rate`
                // here would instead prune them, so they would stop being probed, never be
                // resampled, and stay excluded permanently.
                let value_fn = EdgeValueFn::forward_without_self_loopback(
                    // The closing edge back to `me` is appended after path-finding.
                    std::num::NonZeroUsize::new(hops + 1).expect("hop range is non-zero"),
                    self.edge_penalty,
                    0.0,
                    // Whatever the producer last pushed; `None` until the first price is seen.
                    hopr_api::graph::NetworkGraphView::ticket_face_value(self),
                );

                return find_paths(
                    &inner,
                    *me_idx,
                    &connected_neighbors,
                    hops,
                    take_count,
                    value_fn.initial_value(),
                    value_fn.min_value(),
                    value_fn.into_value_fn(),
                    StarvedEdges::Walk,
                )
                .into_iter()
                .filter_map(|(mut a, mut b, _c)| {
                    // find_paths already strips the leading `me` (source), so `a` is
                    // [intermediates…, connected_neighbor]. Append `me` to close the loopback;
                    // this is the only sanctioned position where `me` appears as a "destination".
                    //
                    // b is filled by find_paths BEFORE skip(1), so b[0] = me_idx and
                    // b[1..=path_node_count] = path nodes. Closing me goes at b[path_node_count + 1].
                    //
                    // The hop range above guarantees the slot exists. Without the closing marker
                    // the PathId cannot be resolved back to a loop, so drop rather than emit it.
                    let path_node_count = a.len();
                    debug_assert!(
                        path_node_count + 1 < b.len(),
                        "loopback of {path_node_count} hops has no PathId slot for the closing node"
                    );
                    if path_node_count + 1 >= b.len() {
                        tracing::warn!(
                            hops = path_node_count,
                            "loopback path has no PathId slot for the closing node, dropping"
                        );
                        return None;
                    }
                    b[path_node_count + 1] = path_id::encode(&self.me);
                    a.push(self.me);
                    Some((a, b))
                })
                .collect();
            };
        }

        vec![]
    }
}

/// Nodes that can close a loopback at `me`: those with an edge to `me` not known to be down.
///
/// The closing edge must exist; its connectivity must merely not be known to be down. Excluding an
/// unchecked neighbour would stop it being probed, which is what would keep it unchecked.
fn closing_neighbors(inner: &InnerGraph, me: NodeIndex) -> HashSet<NodeIndex> {
    inner
        .graph
        .neighbors_directed(me, petgraph::Direction::Incoming)
        .filter(|neighbor| {
            inner
                .graph
                .edges_connecting(*neighbor, me)
                .next()
                .is_some_and(|e| e.weight().immediate_qos().and_then(|imm| imm.is_connected()) != Some(false))
        })
        .collect()
}

/// Loopback probe generation steered towards chosen exits.
///
/// Lets a caller that knows which exits it will use probe the subgraph around them, instead of
/// sampling every loop in the network. An exit is the final hop of a data path, so it needs no
/// channel: neither a channel into it nor an `exit → me` closing edge is required.
pub trait FocusedLoopback {
    /// Generates loopback paths of exactly `hops` relays around `exits`, each ranked by [`FocusRelevance`].
    ///
    /// The search runs on the subgraph around the exits' forward and return paths, so loops elsewhere
    /// in the network do not appear. `take_count` bounds the result after ranking, forward loops first. The search
    /// lists at most ten times `take_count` loops before ranking, so in a neighborhood with more loops than that a
    /// focused loop may be left out even when fewer than `take_count` are returned. Closing
    /// edges follow `simple_loopback_to_self`: they must exist and not be known to be down.
    ///
    /// Requests outside [`MIN_LOOPBACK_HOPS`]`..=`[`MAX_LOOPBACK_HOPS`], unknown exits and an empty
    /// `exits` set yield nothing.
    fn focused_loopback(
        &self,
        hops: usize,
        take_count: Option<usize>,
        exits: &HashSet<OffchainPublicKey>,
    ) -> Vec<(Vec<OffchainPublicKey>, PathId, FocusRelevance)>;
}

/// Most edges a path can have: [`MAX_LOOPBACK_HOPS`] relays plus the final hop.
const MAX_PATH_EDGES: usize = MAX_LOOPBACK_HOPS + 1;

/// How far around the exits' paths a focused loop may stray, in edges.
///
/// Loops need relays beyond the paths themselves: a closing relay for a forward prefix, or an entry
/// relay before a return component. Two steps cover every loop of up to three relays.
const FOCUS_RADIUS: usize = 2;

/// Loops one focused search enumerates before ranking, per loop the caller asks for. It bounds the work only; the
/// caller's `take_count` bounds the result.
const FOCUS_SEARCH_FACTOR: usize = 10;

/// How a loop relates to the exits it was focused on, ordered by how much it is worth probing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FocusRelevance {
    /// The loop measures an edge of a return path from an exit back to `me`, at most [`MAX_LOOPBACK_HOPS`] relays long.
    Return,
    /// The loop's leading relays form a path to an exit: one of them has an edge into it.
    Forward,
}

/// Edge distances from `sources` along `direction`, up to [`MAX_PATH_EDGES`].
///
/// `avoid` is reached but not expanded, since no path passes through `me`.
fn distances(
    inner: &InnerGraph,
    sources: impl IntoIterator<Item = NodeIndex>,
    direction: petgraph::Direction,
    avoid: Option<NodeIndex>,
) -> HashMap<NodeIndex, usize> {
    let mut dist: HashMap<NodeIndex, usize> = sources.into_iter().map(|source| (source, 0)).collect();
    let mut queue: VecDeque<NodeIndex> = dist.keys().copied().collect();

    while let Some(node) = queue.pop_front() {
        let reached = dist[&node];
        if reached >= MAX_PATH_EDGES || Some(node) == avoid {
            continue;
        }
        for next in inner.graph.neighbors_directed(node, direction) {
            if let std::collections::hash_map::Entry::Vacant(slot) = dist.entry(next) {
                slot.insert(reached + 1);
                queue.push_back(next);
            }
        }
    }
    dist
}

/// What links the exits to `me`: the edges of their return paths, and the relays of forward paths.
struct FocusPaths {
    /// Edges `u → v` on some path from an exit to `me` with at most [`MAX_LOOPBACK_HOPS`] relays.
    return_edges: HashSet<(NodeIndex, NodeIndex)>,
    /// Relays on some path from `me` to an exit with at most [`MAX_LOOPBACK_HOPS`] relays.
    forward_relays: HashSet<NodeIndex>,
}

impl FocusPaths {
    fn new(inner: &InnerGraph, me: NodeIndex, exits: &HashSet<NodeIndex>) -> Self {
        use petgraph::Direction::{Incoming, Outgoing};

        let from_exits = distances(inner, exits.iter().copied(), Outgoing, Some(me));
        let to_me = distances(inner, [me], Incoming, None);
        let return_edges = from_exits
            .iter()
            .filter(|(node, _)| **node != me)
            .flat_map(|(node, reached)| {
                let to_me = &to_me;
                inner
                    .graph
                    .neighbors_directed(*node, Outgoing)
                    .filter(move |next| to_me.get(next).is_some_and(|left| reached + 1 + left <= MAX_PATH_EDGES))
                    .map(|next| (*node, next))
            })
            .collect();

        let from_me = distances(inner, [me], Outgoing, None);
        let to_exits = distances(inner, exits.iter().copied(), Incoming, Some(me));
        let forward_relays = from_me
            .iter()
            .filter(|(node, _)| **node != me)
            .filter(|(node, reached)| to_exits.get(node).is_some_and(|left| *reached + left <= MAX_PATH_EDGES))
            .map(|(node, _)| *node)
            .collect();

        Self {
            return_edges,
            forward_relays,
        }
    }

    /// The paths, plus everything within [`FOCUS_RADIUS`] of them. `me` is kept but never grown from.
    fn neighborhood(&self, inner: &InnerGraph, me: NodeIndex, exits: &HashSet<NodeIndex>) -> HashSet<NodeIndex> {
        let mut nodes: HashSet<NodeIndex> = self
            .forward_relays
            .iter()
            .chain(exits)
            .copied()
            .chain(self.return_edges.iter().flat_map(|(from, to)| [*from, *to]))
            .collect();
        nodes.insert(me);

        let mut frontier: Vec<NodeIndex> = nodes.iter().copied().filter(|node| *node != me).collect();
        for _ in 0..FOCUS_RADIUS {
            frontier = frontier
                .into_iter()
                .flat_map(|node| {
                    [petgraph::Direction::Outgoing, petgraph::Direction::Incoming]
                        .into_iter()
                        .flat_map(move |direction| inner.graph.neighbors_directed(node, direction))
                })
                .filter(|next| *next != me && nodes.insert(*next))
                .collect();
        }
        nodes
    }
}

/// Copy of `inner` holding only `keep`, with the edges between those nodes.
fn induced(inner: &InnerGraph, keep: &HashSet<NodeIndex>) -> (InnerGraph, HashMap<NodeIndex, NodeIndex>) {
    use petgraph::visit::{EdgeRef, IntoEdgeReferences};

    let mut sub = InnerGraph::default();
    let mut renamed = HashMap::new();
    for old in keep {
        if let Some(key) = inner.indices.get_by_right(old) {
            let new = sub.graph.add_node(*key);
            sub.indices.insert(*key, new);
            renamed.insert(*old, new);
        }
    }
    for edge in inner.graph.edge_references() {
        if let (Some(source), Some(target)) = (renamed.get(&edge.source()), renamed.get(&edge.target())) {
            sub.graph.add_edge(*source, *target, *edge.weight());
        }
    }
    (sub, renamed)
}

impl FocusedLoopback for ChannelGraph {
    fn focused_loopback(
        &self,
        hops: usize,
        take_count: Option<usize>,
        exits: &HashSet<OffchainPublicKey>,
    ) -> Vec<(Vec<OffchainPublicKey>, PathId, FocusRelevance)> {
        if !(MIN_LOOPBACK_HOPS..=MAX_LOOPBACK_HOPS).contains(&hops) || exits.is_empty() {
            return vec![];
        }

        let inner = self.inner.read();
        let Some(&me) = inner.indices.get_by_left(&self.me) else {
            return vec![];
        };
        let exits: HashSet<NodeIndex> = exits
            .iter()
            .filter_map(|key| inner.indices.get_by_left(key).copied())
            .filter(|idx| *idx != me)
            .collect();
        if exits.is_empty() {
            return vec![];
        }

        let paths = FocusPaths::new(&inner, me, &exits);
        let (sub, renamed) = induced(&inner, &paths.neighborhood(&inner, me, &exits));
        let Some(&sub_me) = renamed.get(&me) else {
            return vec![];
        };
        // Only the structure of a loop matters for the search, so no edge is scored or pruned.
        let unscored: SharedValueFn<()> = Arc::new(|c, _, _| c);

        let has_edge = |from: NodeIndex, to: NodeIndex| inner.graph.edges_connecting(from, to).next().is_some();
        let index_of = |key: &OffchainPublicKey| inner.indices.get_by_left(key).copied();

        let mut ranked = find_paths(
            &sub,
            sub_me,
            &closing_neighbors(&sub, sub_me),
            hops,
            // Unrelated loops inside the neighborhood come out in no useful order, so the bound applies after
            // ranking. The cap only limits the work of the search.
            take_count.map(|take| take.saturating_mul(FOCUS_SEARCH_FACTOR)),
            (),
            None,
            unscored,
            // Focused loops probe, so they walk starved edges too: a returning loop is how a relay recovers.
            StarvedEdges::Walk,
        )
        .into_iter()
        .filter_map(|(mut relays, ..)| {
            let ids: Vec<NodeIndex> = relays.iter().map(&index_of).collect::<Option<_>>()?;
            if relays.len() != hops || ids.contains(&me) {
                return None;
            }

            // A relay with an edge into an exit makes the relays up to it a path to that exit.
            let forward = ids.iter().enumerate().any(|(at, relay)| {
                exits
                    .iter()
                    .any(|exit| has_edge(*relay, *exit) && !ids[..=at].contains(exit))
            });
            let returning = ids
                .windows(2)
                .map(|pair| (pair[0], pair[1]))
                .chain(ids.last().map(|last| (*last, me)))
                .any(|edge| paths.return_edges.contains(&edge));
            let relevance = match (forward, returning) {
                (true, _) => FocusRelevance::Forward,
                (false, true) => FocusRelevance::Return,
                (false, false) => return None,
            };

            // Slots are key-derived and the closing `me` follows the last relay, as in
            // `simple_loopback_to_self`.
            let mut path_id: PathId = Default::default();
            for (slot, key) in path_id.iter_mut().zip(std::iter::once(&self.me).chain(&relays)) {
                *slot = path_id::encode(key);
            }
            *path_id.get_mut(hops + 1)? = path_id::encode(&self.me);
            relays.push(self.me);
            Some((relays, path_id, relevance))
        })
        .collect::<Vec<_>>();

        // Forward loops lead, then return loops; the sort is stable, so equals keep the search order.
        ranked.sort_by_key(|(_, _, relevance)| matches!(relevance, FocusRelevance::Return));
        if let Some(take) = take_count {
            ranked.truncate(take);
        }
        ranked
    }
}

impl<T: FocusedLoopback> FocusedLoopback for Arc<T> {
    fn focused_loopback(
        &self,
        hops: usize,
        take_count: Option<usize>,
        exits: &HashSet<OffchainPublicKey>,
    ) -> Vec<(Vec<OffchainPublicKey>, PathId, FocusRelevance)> {
        (**self).focused_loopback(hops, take_count, exits)
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Context;
    use hex_literal::hex;
    use hopr_api::{
        graph::{
            NetworkGraphTraverse, NetworkGraphWrite,
            function::EdgeValueFn,
            traits::{EdgeObservableWrite, EdgeWeightType},
        },
        types::{
            crypto::prelude::{Keypair, OffchainKeypair},
            internal::routing::PathId,
        },
    };

    use super::*;

    /// Deliberately different from the production default (0.5) so tests
    /// verify that the configured penalty is actually propagated.
    const TEST_EDGE_PENALTY: f64 = 0.73;
    /// Disabled in tests — no protocol conformance data is recorded.
    const TEST_MIN_ACK_RATE: f64 = 0.0;

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

    /// Marks an edge as connected with an immediate probe measurement, satisfying the
    /// cost function's requirement for the last edge in a path.
    fn mark_edge_connected(graph: &ChannelGraph, src: &OffchainPublicKey, dest: &OffchainPublicKey) {
        graph.upsert_edge(src, dest, |obs| {
            obs.record(EdgeWeightType::Connected(true));
            obs.record(EdgeWeightType::Immediate(Ok(std::time::Duration::from_millis(50))));
        });
    }

    /// Connectivity observed and found absent — distinct from never having looked.
    fn mark_edge_disconnected(graph: &ChannelGraph, src: &OffchainPublicKey, dest: &OffchainPublicKey) {
        graph.upsert_edge(src, dest, |obs| {
            obs.record(EdgeWeightType::Connected(false));
        });
    }

    #[test]
    fn unreachable_destination_should_return_empty() -> anyhow::Result<()> {
        let me = pubkey_from(&SECRET_0);
        let dest = pubkey_from(&SECRET_1);

        let graph = ChannelGraph::new(me);
        graph.add_node(dest);
        // No edge between me and dest

        let routes = graph.simple_paths(
            &me,
            &dest,
            1,
            None,
            EdgeValueFn::forward(
                std::num::NonZeroUsize::new(1).context("should be non-zero")?,
                TEST_EDGE_PENALTY,
                TEST_MIN_ACK_RATE,
                None,
            ),
        );

        assert!(routes.is_empty(), "should return no routes when unreachable");

        Ok(())
    }

    #[test]
    fn unknown_destination_should_return_empty() -> anyhow::Result<()> {
        let me = pubkey_from(&SECRET_0);
        let unknown = pubkey_from(&SECRET_1);

        let graph = ChannelGraph::new(me);
        let routes = graph.simple_paths(
            &me,
            &unknown,
            1,
            None,
            EdgeValueFn::forward(
                std::num::NonZeroUsize::new(1).context("should be non-zero")?,
                TEST_EDGE_PENALTY,
                TEST_MIN_ACK_RATE,
                None,
            ),
        );

        assert!(routes.is_empty());

        Ok(())
    }

    #[test]
    fn diamond_topology_should_yield_multiple_paths() -> anyhow::Result<()> {
        //   me -> a -> dest
        //   me -> b -> dest
        let me = pubkey_from(&SECRET_0);
        let a = pubkey_from(&SECRET_1);
        let b = pubkey_from(&SECRET_2);
        let dest = pubkey_from(&SECRET_3);

        let graph = ChannelGraph::new(me);
        graph.add_node(a);
        graph.add_node(b);
        graph.add_node(dest);
        graph.add_edge(&me, &a)?;
        graph.add_edge(&me, &b)?;
        graph.add_edge(&a, &dest)?;
        graph.add_edge(&b, &dest)?;
        mark_edge_loopback_ready(&graph, &me, &a);
        mark_edge_loopback_ready(&graph, &me, &b);
        mark_edge_connected(&graph, &a, &dest);
        mark_edge_connected(&graph, &b, &dest);

        let routes = graph.simple_paths(
            &me,
            &dest,
            2,
            None,
            EdgeValueFn::forward(
                std::num::NonZeroUsize::new(2).context("should be non-zero")?,
                TEST_EDGE_PENALTY,
                TEST_MIN_ACK_RATE,
                None,
            ),
        );
        assert_eq!(routes.len(), 2, "diamond topology should yield two 2-edge routes");
        Ok(())
    }

    fn diamond(me: OffchainPublicKey) -> anyhow::Result<(ChannelGraph, [OffchainPublicKey; 3])> {
        //   me -> a -> dest
        //   me -> b -> dest
        let [a, b, dest] = [&SECRET_1, &SECRET_2, &SECRET_3].map(pubkey_from);
        let graph = ChannelGraph::new(me);
        for node in [a, b, dest] {
            graph.add_node(node);
        }
        for (src, dst) in [(me, a), (me, b), (a, dest), (b, dest)] {
            graph.add_edge(&src, &dst)?;
        }
        mark_edge_loopback_ready(&graph, &me, &a);
        mark_edge_loopback_ready(&graph, &me, &b);
        mark_edge_connected(&graph, &a, &dest);
        mark_edge_connected(&graph, &b, &dest);
        Ok((graph, [a, b, dest]))
    }

    fn two_hop_forward() -> anyhow::Result<EdgeValueFn<f64, crate::Observations>> {
        Ok(EdgeValueFn::forward(
            std::num::NonZeroUsize::new(2).context("should be non-zero")?,
            TEST_EDGE_PENALTY,
            TEST_MIN_ACK_RATE,
            None,
        ))
    }

    #[test]
    fn an_unusable_relayer_should_be_pruned_without_crowding_out_healthy_paths() -> anyhow::Result<()> {
        use hopr_api::graph::NetworkGraphUpdate;

        let me = pubkey_from(&SECRET_0);
        let (graph, [a, b, dest]) = diamond(me)?;
        graph.record_node_health(&a, 0.0);

        for _ in 0..20 {
            let routes = graph.simple_paths(&me, &dest, 2, Some(1), two_hop_forward()?);
            assert_eq!(
                1,
                routes.len(),
                "the healthy path must be found whatever the search order"
            );
            assert_eq!(
                vec![b],
                routes[0].0,
                "only the path through the healthy relayer survives"
            );
        }
        Ok(())
    }

    #[test]
    fn a_degraded_relayer_should_cost_its_paths_by_its_health() -> anyhow::Result<()> {
        use hopr_api::graph::NetworkGraphUpdate;

        let me = pubkey_from(&SECRET_0);
        let (graph, [a, b, dest]) = diamond(me)?;
        graph.record_node_health(&a, 0.5);

        let routes = graph.simple_paths(&me, &dest, 2, None, two_hop_forward()?);
        let cost_via = |relayer| {
            routes
                .iter()
                .find(|(path, ..)| path == &vec![relayer])
                .map(|(.., cost)| *cost)
        };
        let (via_a, via_b) = (cost_via(a).context("path via a")?, cost_via(b).context("path via b")?);
        assert!((via_a - via_b * 0.5).abs() < 1e-12, "{via_a} vs {via_b}");

        graph.record_node_health(&a, 1.0);
        let routes = graph.simple_paths(&me, &dest, 2, None, two_hop_forward()?);
        let restored = routes
            .iter()
            .find(|(path, ..)| path == &vec![a])
            .map(|(.., cost)| *cost);
        assert_eq!(Some(via_b), restored, "full health restores the cost");
        Ok(())
    }

    #[test]
    fn mismatched_edge_count_should_return_empty() -> anyhow::Result<()> {
        // me -> dest (1 edge), but ask for 2 edges
        let me = pubkey_from(&SECRET_0);
        let dest = pubkey_from(&SECRET_1);
        let graph = ChannelGraph::new(me);
        graph.add_node(dest);
        graph.add_edge(&me, &dest)?;

        let routes = graph.simple_paths(
            &me,
            &dest,
            2,
            None,
            EdgeValueFn::forward(
                std::num::NonZeroUsize::new(2).context("should be non-zero")?,
                TEST_EDGE_PENALTY,
                TEST_MIN_ACK_RATE,
                None,
            ),
        );
        assert!(routes.is_empty(), "no 2-edge route should exist for a single edge");
        Ok(())
    }

    #[test]
    fn zero_edge_should_always_return_empty() -> anyhow::Result<()> {
        let me = pubkey_from(&SECRET_0);
        let other = pubkey_from(&SECRET_1);
        let graph = ChannelGraph::new(me);

        // length=0 returns empty before the cost fn is used; any NonZeroUsize value is fine
        let routes = graph.simple_paths(
            &me,
            &other,
            0,
            None,
            EdgeValueFn::forward(
                std::num::NonZeroUsize::new(1).context("should be non-zero")?,
                TEST_EDGE_PENALTY,
                TEST_MIN_ACK_RATE,
                None,
            ),
        );
        assert!(routes.is_empty(), "zero-edge path should find no routes");
        Ok(())
    }

    #[test]
    fn non_trivial_graph_should_find_all_simple_paths() -> anyhow::Result<()> {
        // Topology (7 nodes):
        //
        //   me(0) ──→ a(1)
        //   me(0) ──→ b(2)
        //   a(1)  ──→ c(3)   [capacity]
        //   a(1)  ──→ d(4)   [capacity]
        //   b(2)  ──→ c(3)   [capacity]
        //   b(2)  ──→ d(4)   [capacity]
        //   b(2)  ──→ e(5)   [capacity]
        //   c(3)  ──→ f(7)
        //   d(4)  ──→ f(7)
        //   e(5)  ──→ f(7)
        //
        // Valid 3-edge paths (me → ? → ? → f):
        //   1. me → a → c → f
        //   2. me → a → d → f
        //   3. me → b → c → f
        //   4. me → b → d → f
        //   5. me → b → e → f
        //
        // Blocked paths:
        //   - me → a → e → f : edge a→e missing
        //   - me → e → … → f : edge me→e missing

        let me = pubkey_from(&SECRET_0);
        let a = pubkey_from(&SECRET_1);
        let b = pubkey_from(&SECRET_2);
        let c = pubkey_from(&SECRET_3);
        let d = pubkey_from(&SECRET_4);
        let e = pubkey_from(&SECRET_5);
        let f = pubkey_from(&SECRET_7);

        let graph = ChannelGraph::new(me);
        for node in [a, b, c, d, e, f] {
            graph.add_node(node);
        }

        // Edges from me
        graph.add_edge(&me, &a)?;
        graph.add_edge(&me, &b)?;

        // Edges from a
        graph.add_edge(&a, &c)?;
        graph.add_edge(&a, &d)?;

        // Edges from b
        graph.add_edge(&b, &c)?;
        graph.add_edge(&b, &d)?;
        graph.add_edge(&b, &e)?;

        // Edges to f (last hop)
        graph.add_edge(&c, &f)?;
        graph.add_edge(&d, &f)?;
        graph.add_edge(&e, &f)?;

        // Mark first edges with full QoS (connected + intermediate capacity)
        mark_edge_loopback_ready(&graph, &me, &a);
        mark_edge_loopback_ready(&graph, &me, &b);

        // Mark middle edges with capacity (required by EdgeValueFn::forward)
        mark_edge_with_capacity(&graph, &a, &c);
        mark_edge_with_capacity(&graph, &a, &d);
        mark_edge_with_capacity(&graph, &b, &c);
        mark_edge_with_capacity(&graph, &b, &d);
        mark_edge_with_capacity(&graph, &b, &e);

        // Last edges (c→f, d→f, e→f) are lenient with EdgeValueFn::forward

        // --- 3-edge paths: should find exactly 5 ---
        let routes_3 = graph.simple_paths(
            &me,
            &f,
            3,
            None,
            EdgeValueFn::forward(
                std::num::NonZeroUsize::new(3).context("should be non-zero")?,
                TEST_EDGE_PENALTY,
                TEST_MIN_ACK_RATE,
                None,
            ),
        );
        assert_eq!(routes_3.len(), 5, "should find exactly 5 three-edge paths");

        // Verify all returned paths have positive cost.
        // simple_paths strips both src and dest, so a 3-edge path has 2 intermediates.
        for (path, _path_id, cost) in &routes_3 {
            assert!(*cost > 0.0, "path {path:?} should have positive cost, got {cost}");
            assert_eq!(
                path.len(),
                2,
                "3-edge path should contain 2 intermediates (src and dest stripped)"
            );
            assert!(!path.contains(&me), "path must not contain src");
            assert!(!path.contains(&f), "path must not contain dest");
        }

        // --- 1-edge path: no direct me→f edge ---
        let routes_1 = graph.simple_paths(
            &me,
            &f,
            1,
            None,
            EdgeValueFn::forward(
                std::num::NonZeroUsize::new(1).context("should be non-zero")?,
                TEST_EDGE_PENALTY,
                TEST_MIN_ACK_RATE,
                None,
            ),
        );
        assert!(routes_1.is_empty(), "no direct edge from me to f");

        Ok(())
    }

    #[test]
    fn three_edge_loop_should_return_empty_because_source_is_visited() -> anyhow::Result<()> {
        // Ring topology: me → a → b → me (3 edges forming a cycle)
        //
        // The underlying all_simple_paths_multi algorithm marks the source node
        // as visited before traversal begins. Because the destination equals the
        // source, the algorithm can never "reach" it — the visited-set check
        // (`visited.contains(&child)`) rejects the back-edge to source, and the
        // expansion guard (`to.iter().any(|n| !visited.contains(n))`) is always
        // false since the only target (source) is always visited.
        let me = pubkey_from(&SECRET_0);
        let a = pubkey_from(&SECRET_1);
        let b = pubkey_from(&SECRET_2);

        let graph = ChannelGraph::new(me);
        graph.add_node(a);
        graph.add_node(b);
        graph.add_edge(&me, &a)?;
        graph.add_edge(&a, &b)?;
        graph.add_edge(&b, &me)?;
        mark_edge_connected(&graph, &b, &me);

        let routes = graph.simple_paths(
            &me,
            &me,
            3,
            None,
            EdgeValueFn::forward(
                std::num::NonZeroUsize::new(3).context("should be non-zero")?,
                TEST_EDGE_PENALTY,
                TEST_MIN_ACK_RATE,
                None,
            ),
        );
        assert!(
            routes.is_empty(),
            "simple_paths cannot discover cycles (source == destination) due to visited-set semantics"
        );

        Ok(())
    }

    #[test]
    fn path_id_should_carry_key_derived_slots_for_one_edge() -> anyhow::Result<()> {
        // me = node 0, dest = node 1
        let me = pubkey_from(&SECRET_0);
        let dest = pubkey_from(&SECRET_1);

        let graph = ChannelGraph::new(me);
        graph.add_node(dest);
        graph.add_edge(&me, &dest)?;
        mark_edge_loopback_ready(&graph, &me, &dest);

        let routes = graph.simple_paths(
            &me,
            &dest,
            1,
            None,
            EdgeValueFn::forward(
                std::num::NonZeroUsize::new(1).context("should be non-zero")?,
                TEST_EDGE_PENALTY,
                TEST_MIN_ACK_RATE,
                None,
            ),
        );
        assert_eq!(routes.len(), 1);

        let (_path, path_id, _cost) = &routes[0];
        assert_eq!(path_id[0], path_id::encode(&me), "first slot should be me");
        assert_eq!(path_id[1], path_id::encode(&dest), "second slot should be dest");
        assert_eq!(path_id[2..], [0, 0, 0], "unused positions should be padding");
        assert!(
            path_id[..2].iter().all(|&slot| slot != 0),
            "occupied slots must never hold the reserved padding value"
        );

        Ok(())
    }

    #[test]
    fn path_id_should_carry_key_derived_slots_for_three_edges() -> anyhow::Result<()> {
        // me = node 0, a = node 1, b = node 2, dest = node 3
        let me = pubkey_from(&SECRET_0);
        let a = pubkey_from(&SECRET_1);
        let b = pubkey_from(&SECRET_2);
        let dest = pubkey_from(&SECRET_3);

        let graph = ChannelGraph::new(me);
        graph.add_node(a);
        graph.add_node(b);
        graph.add_node(dest);
        graph.add_edge(&me, &a)?;
        graph.add_edge(&a, &b)?;
        graph.add_edge(&b, &dest)?;
        mark_edge_loopback_ready(&graph, &me, &a);
        mark_edge_with_capacity(&graph, &a, &b);

        let routes = graph.simple_paths(
            &me,
            &dest,
            3,
            None,
            EdgeValueFn::forward(
                std::num::NonZeroUsize::new(3).context("should be non-zero")?,
                TEST_EDGE_PENALTY,
                TEST_MIN_ACK_RATE,
                None,
            ),
        );
        assert_eq!(routes.len(), 1);

        let (_path, path_id, _cost) = &routes[0];
        for (slot, key) in [me, a, b, dest].iter().enumerate() {
            assert_eq!(
                path_id[slot],
                path_id::encode(key),
                "slot {slot} should encode its node"
            );
        }
        assert_eq!(path_id[4], 0, "unused position should be padding");
        assert!(
            path_id[..4].iter().all(|&slot| slot != 0),
            "occupied slots must never hold the reserved padding value"
        );

        Ok(())
    }

    #[test]
    fn path_id_should_differ_for_distinct_paths_in_diamond() -> anyhow::Result<()> {
        //   me → a → dest
        //   me → b → dest
        // me = node 0, a = node 1, b = node 2, dest = node 3
        let me = pubkey_from(&SECRET_0);
        let a = pubkey_from(&SECRET_1);
        let b = pubkey_from(&SECRET_2);
        let dest = pubkey_from(&SECRET_3);

        let graph = ChannelGraph::new(me);
        graph.add_node(a);
        graph.add_node(b);
        graph.add_node(dest);
        graph.add_edge(&me, &a)?;
        graph.add_edge(&me, &b)?;
        graph.add_edge(&a, &dest)?;
        graph.add_edge(&b, &dest)?;
        mark_edge_loopback_ready(&graph, &me, &a);
        mark_edge_loopback_ready(&graph, &me, &b);
        mark_edge_connected(&graph, &a, &dest);
        mark_edge_connected(&graph, &b, &dest);

        let routes = graph.simple_paths(
            &me,
            &dest,
            2,
            None,
            EdgeValueFn::forward(
                std::num::NonZeroUsize::new(2).context("should be non-zero")?,
                TEST_EDGE_PENALTY,
                TEST_MIN_ACK_RATE,
                None,
            ),
        );
        assert_eq!(routes.len(), 2, "diamond should yield two 2-edge routes");

        let path_ids: Vec<PathId> = routes.iter().map(|(_, pid, _)| *pid).collect();
        assert_ne!(path_ids[0], path_ids[1], "distinct paths should have different PathIds");

        // Each path: [me(0), intermediate(1 or 2), dest(3)] then padding
        for pid in &path_ids {
            assert_eq!(pid[0], path_id::encode(&me), "first slot should be me");
            assert!(
                pid[1] == path_id::encode(&a) || pid[1] == path_id::encode(&b),
                "second slot should be a or b"
            );
            assert_eq!(pid[2], path_id::encode(&dest), "third slot should be dest");
            assert_eq!(pid[3..], [0, 0], "unused positions should be padding");
        }

        Ok(())
    }

    // ── return-path tests (EdgeValueFn::returning) ──────────────────────────

    #[test]
    fn return_path_one_edge_should_find_route() -> anyhow::Result<()> {
        // Return path: dest -> me (1 edge)
        // For length=1, path_index=0 matches the first-edge arm which requires capacity.
        let me = pubkey_from(&SECRET_0);
        let dest = pubkey_from(&SECRET_1);

        let graph = ChannelGraph::new(me);
        graph.add_node(dest);
        graph.add_edge(&dest, &me)?;
        // dest→me: for length=1 this is the last edge, requiring connectivity
        mark_edge_connected(&graph, &dest, &me);

        let routes = graph.simple_paths(
            &dest,
            &me,
            1,
            None,
            EdgeValueFn::returning(
                std::num::NonZeroUsize::new(1).context("should be non-zero")?,
                TEST_EDGE_PENALTY,
                TEST_MIN_ACK_RATE,
                None,
            ),
        );

        assert_eq!(routes.len(), 1, "should find exactly one 1-edge return route");
        Ok(())
    }

    #[test]
    fn return_path_first_edge_without_capacity_should_be_pruned() -> anyhow::Result<()> {
        // Return path: dest -> relay -> me (2 edges)
        // dest→relay has no capacity → first-edge cost goes negative
        let me = pubkey_from(&SECRET_0);
        let relay = pubkey_from(&SECRET_1);
        let dest = pubkey_from(&SECRET_2);

        let graph = ChannelGraph::new(me);
        graph.add_node(relay);
        graph.add_node(dest);
        graph.add_edge(&dest, &relay)?;
        graph.add_edge(&relay, &me)?;
        // dest→relay: no capacity (default edge)
        // relay→me: connected
        mark_edge_connected(&graph, &relay, &me);

        let routes = graph.simple_paths(
            &dest,
            &me,
            2,
            None,
            EdgeValueFn::returning(
                std::num::NonZeroUsize::new(2).context("should be non-zero")?,
                TEST_EDGE_PENALTY,
                TEST_MIN_ACK_RATE,
                None,
            ),
        );

        assert!(
            routes.is_empty(),
            "return path should be pruned when first edge lacks capacity"
        );
        Ok(())
    }

    #[test]
    fn return_path_diamond_should_yield_multiple_paths() -> anyhow::Result<()> {
        // Return paths: dest -> a -> me, dest -> b -> me
        let me = pubkey_from(&SECRET_0);
        let a = pubkey_from(&SECRET_1);
        let b = pubkey_from(&SECRET_2);
        let dest = pubkey_from(&SECRET_3);

        let graph = ChannelGraph::new(me);
        graph.add_node(a);
        graph.add_node(b);
        graph.add_node(dest);
        graph.add_edge(&dest, &a)?;
        graph.add_edge(&dest, &b)?;
        graph.add_edge(&a, &me)?;
        graph.add_edge(&b, &me)?;
        // First edges (dest→a, dest→b): need capacity
        mark_edge_with_capacity(&graph, &dest, &a);
        mark_edge_with_capacity(&graph, &dest, &b);
        // Last edges (a→me, b→me): need connectivity
        mark_edge_connected(&graph, &a, &me);
        mark_edge_connected(&graph, &b, &me);

        let routes = graph.simple_paths(
            &dest,
            &me,
            2,
            None,
            EdgeValueFn::returning(
                std::num::NonZeroUsize::new(2).context("should be non-zero")?,
                TEST_EDGE_PENALTY,
                TEST_MIN_ACK_RATE,
                None,
            ),
        );
        assert_eq!(
            routes.len(),
            2,
            "diamond topology should yield two 2-edge return routes"
        );
        Ok(())
    }

    // ── simple_loopback_to_self tests ──────────────────────────────────

    /// Marks an edge as connected AND with intermediate capacity so that it
    /// satisfies the `EdgeValueFn::forward_without_self_loopback` at edge index 0 (connected + capacity)
    /// and at any other index (capacity).
    fn mark_edge_loopback_ready(graph: &ChannelGraph, src: &OffchainPublicKey, dest: &OffchainPublicKey) {
        graph.upsert_edge(src, dest, |obs| {
            obs.record(EdgeWeightType::Connected(true));
            obs.record(EdgeWeightType::Immediate(Ok(std::time::Duration::from_millis(50))));
            obs.record(EdgeWeightType::Intermediate(Ok(std::time::Duration::from_millis(50))));
            obs.record(EdgeWeightType::Balance(Some(hopr_api::graph::traits::Balance::from(
                1000u64,
            ))));
        });
    }

    /// Marks an edge with intermediate capacity and probe data (no connected flag).
    /// Satisfies `EdgeValueFn::forward_without_self_loopback` at index > 0 but NOT at index 0.
    fn mark_edge_with_capacity(graph: &ChannelGraph, src: &OffchainPublicKey, dest: &OffchainPublicKey) {
        graph.upsert_edge(src, dest, |obs| {
            obs.record(EdgeWeightType::Intermediate(Ok(std::time::Duration::from_millis(50))));
            obs.record(EdgeWeightType::Balance(Some(hopr_api::graph::traits::Balance::from(
                1000u64,
            ))));
        });
    }

    #[test]
    fn loopback_returns_empty_without_any_peers() {
        let me = pubkey_from(&SECRET_0);
        let graph = ChannelGraph::new(me);
        assert!(
            graph.simple_loopback_to_self(2, None).is_empty(),
            "no peers means no connected neighbors"
        );
    }

    #[test]
    fn loopback_returns_empty_when_first_hop_lacks_capacity() -> anyhow::Result<()> {
        // me → a → b, b → me (connected)
        // me→a is connected but has NO intermediate capacity → edge-0 cost goes negative
        let me = pubkey_from(&SECRET_0);
        let a = pubkey_from(&SECRET_1);
        let b = pubkey_from(&SECRET_2);

        let graph = ChannelGraph::new(me);
        graph.add_node(a);
        graph.add_node(b);
        graph.add_edge(&me, &a)?;
        graph.add_edge(&a, &b)?;
        graph.add_edge(&b, &me)?;
        // me→a: connected but no capacity (only Connected + Immediate)
        mark_edge_connected(&graph, &me, &a);
        // a→b: has capacity
        mark_edge_with_capacity(&graph, &a, &b);
        // b→me: connected (makes b a loopback destination)
        mark_edge_connected(&graph, &b, &me);

        assert!(
            graph.simple_loopback_to_self(2, None).is_empty(),
            "edge me→a lacks intermediate capacity, so EdgeValueFn::forward_without_self_loopback prunes it"
        );

        Ok(())
    }

    #[test]
    fn loopback_returns_empty_when_intermediate_edge_lacks_capacity() -> anyhow::Result<()> {
        // me → a → b, b → me (connected)
        // me→a passes cost-0, but a→b has NO capacity → cost goes negative at edge-1
        let me = pubkey_from(&SECRET_0);
        let a = pubkey_from(&SECRET_1);
        let b = pubkey_from(&SECRET_2);

        let graph = ChannelGraph::new(me);
        graph.add_node(a);
        graph.add_node(b);
        graph.add_edge(&me, &a)?;
        graph.add_edge(&a, &b)?;
        graph.add_edge(&b, &me)?;
        // me→a: connected + capacity (passes edge-0)
        mark_edge_loopback_ready(&graph, &me, &a);
        // a→b: NO capacity — default edge weight
        // b→me: connected
        mark_edge_connected(&graph, &b, &me);

        assert!(
            graph.simple_loopback_to_self(2, None).is_empty(),
            "edge a→b lacks capacity, so EdgeValueFn::forward_without_self_loopback prunes the path"
        );

        Ok(())
    }

    /// Builds `me → a → b → c → me` with every edge probe-ready, so loopbacks of 2 and 3 hops
    /// both exist and the requested hop count decides which is returned.
    fn chain_graph_for_hop_counts() -> anyhow::Result<ChannelGraph> {
        let me = pubkey_from(&SECRET_0);
        let a = pubkey_from(&SECRET_1);
        let b = pubkey_from(&SECRET_2);
        let c = pubkey_from(&SECRET_3);

        let graph = ChannelGraph::new(me);
        graph.add_node(a);
        graph.add_node(b);
        graph.add_node(c);
        graph.add_edge(&me, &a)?;
        graph.add_edge(&a, &b)?;
        graph.add_edge(&b, &c)?;
        graph.add_edge(&b, &me)?;
        graph.add_edge(&c, &me)?;
        mark_edge_loopback_ready(&graph, &me, &a);
        mark_edge_with_capacity(&graph, &a, &b);
        mark_edge_with_capacity(&graph, &b, &c);
        mark_edge_connected(&graph, &b, &me);
        mark_edge_connected(&graph, &c, &me);

        Ok(graph)
    }

    #[test]
    fn loopback_parameter_is_a_hop_count_not_an_edge_count() -> anyhow::Result<()> {
        let me = pubkey_from(&SECRET_0);
        let graph = chain_graph_for_hop_counts()?;

        for hops in MIN_LOOPBACK_HOPS..=MAX_LOOPBACK_HOPS {
            let routes = graph.simple_loopback_to_self(hops, None);
            assert!(!routes.is_empty(), "{hops} hops should yield at least one loopback");

            for (path, _) in &routes {
                // The returned path is [intermediates…, closing me]: `hops` relays plus the
                // closing node. The closed loop therefore has `hops + 1` edges.
                assert_eq!(
                    path.len(),
                    hops + 1,
                    "a {hops}-hop loopback must carry {hops} relays plus the closing node"
                );
                assert_eq!(path.last(), Some(&me), "the loop must close back at me");

                let intermediates = &path[..path.len() - 1];
                assert_eq!(
                    intermediates.len(),
                    hops,
                    "intermediate relay count must equal the requested hop count"
                );
                assert!(
                    !intermediates.contains(&me),
                    "me must not appear as an intermediate relay"
                );
            }
        }

        Ok(())
    }

    #[test]
    fn loopback_multiple_paths_through_diamond() -> anyhow::Result<()> {
        // Topology:
        //   me → a → c, me → b → c, c → me (connected)
        // Two 2-edge loopback paths: me → a → c → me, me → b → c → me
        let me = pubkey_from(&SECRET_0);
        let a = pubkey_from(&SECRET_1);
        let b = pubkey_from(&SECRET_2);
        let c = pubkey_from(&SECRET_3);

        let graph = ChannelGraph::new(me);
        graph.add_node(a);
        graph.add_node(b);
        graph.add_node(c);
        graph.add_edge(&me, &a)?;
        graph.add_edge(&me, &b)?;
        graph.add_edge(&a, &c)?;
        graph.add_edge(&b, &c)?;
        graph.add_edge(&c, &me)?;
        mark_edge_loopback_ready(&graph, &me, &a);
        mark_edge_loopback_ready(&graph, &me, &b);
        mark_edge_with_capacity(&graph, &a, &c);
        mark_edge_with_capacity(&graph, &b, &c);
        mark_edge_connected(&graph, &c, &me);

        let routes = graph.simple_loopback_to_self(2, None);
        assert_eq!(routes.len(), 2, "diamond should yield two 2-edge loopback paths");

        for (path, _path_id) in &routes {
            // Leading `me` is stripped; path is [intermediate, c, me].
            assert_eq!(path.last(), Some(&me), "every path ends with me");
            assert_eq!(path[path.len() - 2], c, "penultimate node is c (loopback destination)");
        }

        // Verify distinct first intermediates (a and b)
        let intermediates: HashSet<_> = routes.iter().map(|(p, _)| p[0]).collect();
        assert!(intermediates.contains(&a), "should include path through a");
        assert!(intermediates.contains(&b), "should include path through b");

        Ok(())
    }

    #[test]
    fn loopback_to_multiple_connected_neighbors() -> anyhow::Result<()> {
        // Topology: me → a, me → b, a → me, b → me (all connected)
        // a and b are both loopback destinations: each has a closing edge back to me.
        // With length=2: me → a → b → me and me → b → a → me
        let me = pubkey_from(&SECRET_0);
        let a = pubkey_from(&SECRET_1);
        let b = pubkey_from(&SECRET_2);

        let graph = ChannelGraph::new(me);
        graph.add_node(a);
        graph.add_node(b);
        graph.add_edge(&me, &a)?;
        graph.add_edge(&me, &b)?;
        graph.add_edge(&a, &b)?;
        graph.add_edge(&b, &a)?;
        graph.add_edge(&a, &me)?;
        graph.add_edge(&b, &me)?;
        mark_edge_loopback_ready(&graph, &me, &a);
        mark_edge_loopback_ready(&graph, &me, &b);
        mark_edge_with_capacity(&graph, &a, &b);
        mark_edge_with_capacity(&graph, &b, &a);
        mark_edge_connected(&graph, &a, &me);
        mark_edge_connected(&graph, &b, &me);

        let routes = graph.simple_loopback_to_self(2, None);
        assert_eq!(
            routes.len(),
            2,
            "should find loopback paths to both loopback destinations"
        );

        // Leading `me` is stripped; path is [intermediate, connected_neighbor, me].
        for (path, _) in &routes {
            assert_eq!(path.last(), Some(&me));
        }

        // Collect the loopback destinations (penultimate node)
        let destinations: HashSet<_> = routes.iter().map(|(p, _)| p[p.len() - 2]).collect();
        assert_eq!(destinations.len(), 2, "should reach both loopback destinations");
        assert!(destinations.contains(&a));
        assert!(destinations.contains(&b));

        Ok(())
    }

    #[test]
    fn loopback_disconnected_neighbor_is_excluded() -> anyhow::Result<()> {
        // me → a → b, me → a → c
        // b → me (connected), c → me (NOT connected)
        // length=2: only me → a → b → me should be found, not me → a → c → me
        let me = pubkey_from(&SECRET_0);
        let a = pubkey_from(&SECRET_1);
        let b = pubkey_from(&SECRET_2);
        let c = pubkey_from(&SECRET_3);

        let graph = ChannelGraph::new(me);
        graph.add_node(a);
        graph.add_node(b);
        graph.add_node(c);
        graph.add_edge(&me, &a)?;
        graph.add_edge(&a, &b)?;
        graph.add_edge(&a, &c)?;
        graph.add_edge(&b, &me)?;
        graph.add_edge(&c, &me)?;
        mark_edge_loopback_ready(&graph, &me, &a);
        mark_edge_with_capacity(&graph, &a, &b);
        mark_edge_with_capacity(&graph, &a, &c);
        // b→me: connected (b IS a loopback destination)
        mark_edge_connected(&graph, &b, &me);
        // c→me: observed down, so c is not a loopback destination
        mark_edge_disconnected(&graph, &c, &me);

        let routes = graph.simple_loopback_to_self(2, None);
        assert_eq!(
            routes.len(),
            1,
            "only the path to loopback destination b should be found"
        );

        let (path, _) = &routes[0];
        assert_eq!(path[path.len() - 2], b, "destination should be b, not c");

        Ok(())
    }

    #[test]
    fn loopback_take_count_limits_results() -> anyhow::Result<()> {
        // Create 3 possible loopback paths, but take_count=1
        //   me → a → d, me → b → d, me → c → d, d → me (connected)
        let me = pubkey_from(&SECRET_0);
        let a = pubkey_from(&SECRET_1);
        let b = pubkey_from(&SECRET_2);
        let c = pubkey_from(&SECRET_3);
        let d = pubkey_from(&SECRET_4);

        let graph = ChannelGraph::new(me);
        for node in [a, b, c, d] {
            graph.add_node(node);
        }
        graph.add_edge(&me, &a)?;
        graph.add_edge(&me, &b)?;
        graph.add_edge(&me, &c)?;
        graph.add_edge(&d, &me)?;
        graph.add_edge(&a, &d)?;
        graph.add_edge(&b, &d)?;
        graph.add_edge(&c, &d)?;
        mark_edge_loopback_ready(&graph, &me, &a);
        mark_edge_loopback_ready(&graph, &me, &b);
        mark_edge_loopback_ready(&graph, &me, &c);
        mark_edge_with_capacity(&graph, &a, &d);
        mark_edge_with_capacity(&graph, &b, &d);
        mark_edge_with_capacity(&graph, &c, &d);
        mark_edge_connected(&graph, &d, &me);

        // Without limit: should find 3 paths
        let all_routes = graph.simple_loopback_to_self(2, None);
        assert_eq!(all_routes.len(), 3, "should find 3 loopback paths without limit");

        // With take_count=1: should return exactly 1
        let limited = graph.simple_loopback_to_self(2, Some(1));
        assert_eq!(limited.len(), 1, "take_count=1 should limit to 1 result");

        Ok(())
    }

    #[test]
    fn loopback_path_ids_differ_for_distinct_routes() -> anyhow::Result<()> {
        // me → a → c, me → b → c, c → me (connected)
        let me = pubkey_from(&SECRET_0);
        let a = pubkey_from(&SECRET_1);
        let b = pubkey_from(&SECRET_2);
        let c = pubkey_from(&SECRET_3);

        let graph = ChannelGraph::new(me);
        graph.add_node(a);
        graph.add_node(b);
        graph.add_node(c);
        graph.add_edge(&me, &a)?;
        graph.add_edge(&me, &b)?;
        graph.add_edge(&a, &c)?;
        graph.add_edge(&b, &c)?;
        graph.add_edge(&c, &me)?;
        mark_edge_loopback_ready(&graph, &me, &a);
        mark_edge_loopback_ready(&graph, &me, &b);
        mark_edge_with_capacity(&graph, &a, &c);
        mark_edge_with_capacity(&graph, &b, &c);
        mark_edge_connected(&graph, &c, &me);

        let routes = graph.simple_loopback_to_self(2, None);
        assert_eq!(routes.len(), 2);

        let path_ids: Vec<PathId> = routes.iter().map(|(_, pid)| *pid).collect();
        assert_ne!(
            path_ids[0], path_ids[1],
            "distinct loopback paths should have different PathIds"
        );

        Ok(())
    }

    #[test]
    fn loopback_mismatched_hops_returns_empty() -> anyhow::Result<()> {
        // Topology only supports 2-edge internal path, but we request 3
        // me → a → b, b → me (connected)
        let me = pubkey_from(&SECRET_0);
        let a = pubkey_from(&SECRET_1);
        let b = pubkey_from(&SECRET_2);

        let graph = ChannelGraph::new(me);
        graph.add_node(a);
        graph.add_node(b);
        graph.add_edge(&me, &a)?;
        graph.add_edge(&a, &b)?;
        graph.add_edge(&b, &me)?;
        mark_edge_loopback_ready(&graph, &me, &a);
        mark_edge_with_capacity(&graph, &a, &b);
        mark_edge_connected(&graph, &b, &me);

        // length=2 works
        assert_eq!(graph.simple_loopback_to_self(2, None).len(), 1);
        // length=3 has no 3-edge path to any connected neighbor
        assert!(
            graph.simple_loopback_to_self(3, None).is_empty(),
            "no 3-edge internal path exists"
        );

        Ok(())
    }
}
