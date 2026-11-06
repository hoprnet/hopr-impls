use std::collections::BTreeSet;

use hopr_api::graph::traits::{
    EdgeImmediateProtocolObservable, EdgeLinkObservable, EdgeNetworkObservableRead, EdgeObservableRead,
    EdgeProtocolObservable,
};
use petgraph::{Direction, graph::NodeIndex, visit::EdgeRef};

use super::{ChannelGraph, graph::InnerGraph, path_id};
use crate::{
    Observations,
    diagnostics::{
        GraphEdge, GraphEdgeStatus, GraphObservation, GraphState, GraphStateRead, MAX_GRAPH_PATHS,
        MAX_LOCAL_GRAPH_EDGES, MAX_PATH_GRAPH_EDGES, PathGraphState,
    },
};

impl GraphStateRead for ChannelGraph {
    fn graph_state(&self, paths: Option<&[[u64; 5]]>) -> GraphState {
        let face = *self.ticket_face_value.read();
        let inner = self.inner.read();
        let me = inner.indices.get_by_left(&self.me).copied();
        let mut state = GraphState {
            scope: "node_path_selection_and_sampled_surbs",
            node_count: inner.indices.len(),
            edge_count: inner.graph.edge_count(),
            local_node_present: me.is_some(),
            ticket_face_value: face.map(|v| v.to_string()),
            edge_penalty: self.edge_penalty,
            min_ack_rate: self.min_ack_rate,
            incoming_edges: 0,
            outgoing_edges: 0,
            local_edges_omitted: 0,
            local_edges: Vec::with_capacity(MAX_LOCAL_GRAPH_EDGES + 1),
            paths: None,
            searches: self.searches.snapshot(),
        };
        if let Some(me) = me {
            for edge in inner.graph.edges_directed(me, Direction::Outgoing) {
                state.outgoing_edges += 1;
                retain(
                    &mut state.local_edges,
                    present(&inner, edge.source(), edge.target(), edge.weight()),
                    MAX_LOCAL_GRAPH_EDGES,
                    self.min_ack_rate,
                    face,
                );
            }
            for edge in inner.graph.edges_directed(me, Direction::Incoming) {
                state.incoming_edges += 1;
                // A self-loop appears in both directional counts but only once in the sample.
                if edge.source() != me {
                    retain(
                        &mut state.local_edges,
                        present(&inner, edge.source(), edge.target(), edge.weight()),
                        MAX_LOCAL_GRAPH_EDGES,
                        self.min_ack_rate,
                        face,
                    );
                }
            }
            let self_loop = usize::from(inner.graph.contains_edge(me, me));
            state.local_edges_omitted =
                state.incoming_edges + state.outgoing_edges - self_loop - state.local_edges.len();
        }
        if let Some(paths) = paths {
            let mut summary = PathGraphState {
                sampled_paths: paths.len().min(MAX_GRAPH_PATHS),
                paths_omitted: paths.len().saturating_sub(MAX_GRAPH_PATHS),
                ..Default::default()
            };
            // At most 32 paths * 4 edges, regardless of the network's size.
            let mut pairs = BTreeSet::new();
            for path in paths.iter().take(MAX_GRAPH_PATHS) {
                let length = path.iter().position(|slot| *slot == 0).unwrap_or(path.len());
                if length < 2 || path[length..].iter().any(|slot| *slot != 0) {
                    summary.invalid_paths += 1;
                    continue;
                }
                for edge in path[..length].windows(2) {
                    pairs.insert((edge[0], edge[1]));
                }
            }
            summary.requested_edges = pairs.len();
            for (source, destination) in pairs {
                let row = path_edge(&inner, source, destination);
                match row.status {
                    GraphEdgeStatus::Present => {}
                    GraphEdgeStatus::MissingEdge => summary.missing_edges += 1,
                    GraphEdgeStatus::MissingNode => summary.missing_node_edges += 1,
                    GraphEdgeStatus::AmbiguousSlot => summary.ambiguous_slot_edges += 1,
                }
                retain(&mut summary.edges, row, MAX_PATH_GRAPH_EDGES, self.min_ack_rate, face);
            }
            summary.edges_omitted = summary.requested_edges - summary.edges.len();
            state.paths = Some(summary);
        }
        drop(inner);
        state.bound_bytes();
        state
    }
}

fn path_edge(inner: &InnerGraph, source: u64, destination: u64) -> GraphEdge {
    // Do not guess or emit one warning per stale/ambiguous path slot during a periodic read.
    let resolve = |slot| match inner.slots.get(&slot).map(Vec::as_slice) {
        Some([node]) => Ok(*node),
        Some(_) => Err(GraphEdgeStatus::AmbiguousSlot),
        None => Err(GraphEdgeStatus::MissingNode),
    };
    let src = resolve(source);
    let dst = resolve(destination);
    if let (Ok(src), Ok(dst)) = (src, dst)
        && let Some(edge) = inner.graph.find_edge(src, dst)
    {
        return present(inner, src, dst, &inner.graph[edge]);
    }
    GraphEdge {
        source_slot: source,
        destination_slot: destination,
        source: src.ok().map(|i| inner.graph[i]),
        destination: dst.ok().map(|i| inner.graph[i]),
        status: if src == Err(GraphEdgeStatus::AmbiguousSlot) || dst == Err(GraphEdgeStatus::AmbiguousSlot) {
            GraphEdgeStatus::AmbiguousSlot
        } else if src.is_err() || dst.is_err() {
            GraphEdgeStatus::MissingNode
        } else {
            GraphEdgeStatus::MissingEdge
        },
        observation: None,
    }
}

pub(crate) fn present(inner: &InnerGraph, source: NodeIndex, destination: NodeIndex, obs: &Observations) -> GraphEdge {
    let source = inner.graph[source];
    let destination = inner.graph[destination];
    let immediate = obs.immediate_qos();
    let intermediate = obs.intermediate_qos();
    let millis = |d: std::time::Duration| d.as_millis().min(u64::MAX as u128) as u64;
    GraphEdge {
        source_slot: path_id::encode(&source),
        destination_slot: path_id::encode(&destination),
        source: Some(source),
        destination: Some(destination),
        status: GraphEdgeStatus::Present,
        observation: Some(GraphObservation {
            balance: intermediate.and_then(|q| q.balance()).map(|v| v.to_string()),
            is_connected: immediate.and_then(|q| q.is_connected()),
            ack_rate: immediate.and_then(|q| q.ack_rate()),
            immediate_probe_rate: immediate.and_then(|q| q.average_probe_rate()),
            intermediate_probe_rate: intermediate.and_then(|q| q.average_probe_rate()),
            immediate_latency_ms: immediate.and_then(|q| q.average_latency()).map(millis),
            intermediate_latency_ms: intermediate.and_then(|q| q.average_latency()).map(millis),
            score: obs.score(),
            health: obs.health(),
            updated_at_ms: millis(obs.last_update()),
        }),
    }
}

fn retain(
    rows: &mut Vec<GraphEdge>,
    row: GraphEdge,
    limit: usize,
    min_ack: f64,
    face: Option<hopr_api::graph::traits::Balance>,
) {
    rows.push(row);
    rows.sort_by(|a, b| {
        priority(b, min_ack, face)
            .cmp(&priority(a, min_ack, face))
            .then_with(|| a.source_slot.cmp(&b.source_slot))
            .then_with(|| a.destination_slot.cmp(&b.destination_slot))
            .then_with(|| {
                a.source
                    .as_ref()
                    .map(AsRef::<[u8]>::as_ref)
                    .cmp(&b.source.as_ref().map(AsRef::<[u8]>::as_ref))
            })
            .then_with(|| {
                a.destination
                    .as_ref()
                    .map(AsRef::<[u8]>::as_ref)
                    .cmp(&b.destination.as_ref().map(AsRef::<[u8]>::as_ref))
            })
    });
    rows.truncate(limit);
}

fn priority(row: &GraphEdge, min_ack: f64, face: Option<hopr_api::graph::traits::Balance>) -> u8 {
    let Some(obs) = &row.observation else { return 16 };
    let below = obs.balance.as_ref().zip(face).is_some_and(|(balance, face)| {
        balance
            .parse::<hopr_api::graph::traits::Balance>()
            .is_ok_and(|b| b < face)
    });
    8 * u8::from(below)
        + 4 * u8::from(obs.is_connected == Some(false) || obs.ack_rate.is_some_and(|v| v < min_ack))
        + 2 * u8::from(
            obs.immediate_probe_rate.is_some_and(|v| v < 0.9)
                || obs.intermediate_probe_rate.is_some_and(|v| v < 0.9)
                || obs.health.is_some_and(|v| v < 1.0),
        )
        + u8::from(obs.score.is_none())
}

#[cfg(test)]
mod tests {
    use hopr_api::{
        OffchainPublicKey,
        graph::{
            NetworkGraphUpdate, NetworkGraphView, NetworkGraphWrite,
            traits::{EdgeObservableWrite, EdgeWeightType},
        },
        types::crypto::prelude::{Keypair, OffchainKeypair},
    };

    use super::*;

    fn key(i: u8) -> OffchainPublicKey {
        *OffchainKeypair::from_secret(&[i; 32]).unwrap().public()
    }

    #[test]
    fn local_snapshot_preserves_direction_measurements_and_transport_only_edges() {
        let me = key(1);
        let peer = key(2);
        let other = key(3);
        let graph = ChannelGraph::new(me);
        graph.set_ticket_face_value(10u64.into());
        graph.upsert_edge(&me, &peer, |obs| {
            obs.record(EdgeWeightType::Connected(true));
            obs.record(EdgeWeightType::Immediate(Ok(std::time::Duration::from_millis(20))));
            obs.record(EdgeWeightType::ImmediateProtocolConformance {
                num_packets: 100,
                num_acks: 98,
            });
        });
        graph.upsert_edge(&peer, &me, |obs| {
            obs.record(EdgeWeightType::Balance(Some(hopr_api::graph::traits::Balance::MAX)));
            obs.record(EdgeWeightType::Intermediate(Err(())));
        });
        graph.upsert_edge(&peer, &other, |_| {});
        let state = graph.graph_state(None);
        assert_eq!((state.node_count, state.edge_count), (3, 3));
        assert!(state.local_node_present);
        assert_eq!(
            (state.incoming_edges, state.outgoing_edges, state.local_edges_omitted),
            (1, 1, 0)
        );
        assert_eq!(state.ticket_face_value.as_deref(), Some("10"));
        assert!(state.paths.is_none());
        let outgoing = state.local_edges().iter().find(|e| e.source == Some(me)).unwrap();
        assert_eq!(outgoing.destination, Some(peer));
        let obs = outgoing.observation.as_ref().unwrap();
        assert_eq!(obs.balance, None, "transport-only edges do not invent channel balances");
        assert_eq!(obs.is_connected, Some(true));
        assert_eq!(obs.immediate_probe_rate, Some(1.0));
        assert_eq!(obs.immediate_latency_ms, Some(20));
        assert_eq!(obs.ack_rate, Some(0.98));
        assert!(obs.updated_at_ms > 0);
        let incoming = state.local_edges().iter().find(|e| e.source == Some(peer)).unwrap();
        let obs = incoming.observation.as_ref().unwrap();
        assert_eq!(
            obs.balance.as_deref(),
            Some(hopr_api::graph::traits::Balance::MAX.to_string().as_str())
        );
        assert_eq!(obs.is_connected, None);
        assert_eq!(obs.intermediate_probe_rate, Some(0.0));
        assert_eq!(obs.intermediate_latency_ms, None);
        assert_eq!(obs.score, Some(0.0));
        let json = serde_json::to_value(&state).unwrap();
        assert!(
            json["local_edges"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["observation"]["balance"] == hopr_api::graph::traits::Balance::MAX.to_string())
        );
    }

    #[test]
    fn bounded_local_sample_is_deterministic_and_prioritizes_problem_edges() {
        let graph = ChannelGraph::new(key(1));
        let reverse = ChannelGraph::new(key(1));
        for i in 2..100 {
            graph.upsert_edge(&key(1), &key(i), |_| {});
        }
        for i in (2..100).rev() {
            reverse.upsert_edge(&key(1), &key(i), |_| {});
        }
        for g in [&graph, &reverse] {
            g.upsert_edge(&key(1), &key(99), |o| o.record(EdgeWeightType::Connected(false)));
        }
        let state = graph.graph_state(Some(&[]));
        let other = reverse.graph_state(None);
        assert!(state.local_edges().len() <= MAX_LOCAL_GRAPH_EDGES);
        assert!(!state.local_edges().is_empty());
        assert_eq!(state.outgoing_edges, 98);
        assert_eq!(state.local_edges_omitted, 98 - state.local_edges().len());
        assert_eq!(state.local_edges()[0].destination, Some(key(99)));
        let destinations = |s: &GraphState| s.local_edges().iter().map(|e| e.destination).collect::<Vec<_>>();
        assert_eq!(destinations(&state), destinations(&other));
        assert_eq!(state.paths.unwrap().requested_edges, 0);
    }

    #[test]
    fn path_sample_reads_remote_edges_and_reports_stale_or_ambiguous_slots() {
        let graph = ChannelGraph::new(key(1));
        for i in 2..8 {
            graph.add_node(key(i));
        }
        graph.upsert_edge(&key(2), &key(3), |o| {
            o.record(EdgeWeightType::Balance(Some(0u64.into())))
        });
        let slot = |i| graph.path_slot(&key(i)).unwrap();
        let removed = slot(4);
        graph.remove_node(&key(4));
        let ambiguous = slot(5);
        {
            let mut inner = graph.inner.write();
            let other = *inner.indices.get_by_left(&key(6)).unwrap();
            inner.slots.get_mut(&ambiguous).unwrap().push(other);
        }
        let paths = [
            [slot(2), slot(3), 0, 0, 0],
            [slot(3), slot(2), 0, 0, 0],
            [slot(2), removed, 0, 0, 0],
            [slot(2), ambiguous, 0, 0, 0],
        ];
        let state = graph.graph_state(Some(&paths));
        assert!(state.local_edges().is_empty(), "remote edges are not incident edges");
        let paths = state.paths.unwrap();
        assert_eq!(paths.requested_edges, 4);
        assert_eq!(
            (
                paths.missing_edges,
                paths.missing_node_edges,
                paths.ambiguous_slot_edges
            ),
            (1, 1, 1)
        );
        let remote = paths
            .edges()
            .iter()
            .find(|e| e.status == GraphEdgeStatus::Present)
            .unwrap();
        assert_eq!((remote.source, remote.destination), (Some(key(2)), Some(key(3))));
        assert_eq!(remote.observation.as_ref().unwrap().balance.as_deref(), Some("0"));
        assert!(
            paths
                .edges()
                .iter()
                .find(|e| e.status == GraphEdgeStatus::AmbiguousSlot)
                .unwrap()
                .destination
                .is_none()
        );
    }

    #[test]
    fn paths_are_deduplicated_bounded_and_invalid_padding_is_explicit() {
        let graph = ChannelGraph::new(key(1));
        for i in 2..15 {
            graph.upsert_edge(&key(i), &key(i + 1), |_| {});
        }
        let slot = |i| graph.path_slot(&key(i)).unwrap();
        let mut paths: Vec<_> = (2..15).map(|i| [slot(i), slot(i + 1), 0, 0, 0]).collect();
        paths.push(paths[0]);
        paths.push([slot(2), 0, slot(3), 0, 0]);
        paths.resize(MAX_GRAPH_PATHS + 2, paths[0]);
        let state = graph.graph_state(Some(&paths)).paths.unwrap();
        assert_eq!(state.sampled_paths, MAX_GRAPH_PATHS);
        assert_eq!(state.paths_omitted, 2);
        assert_eq!(state.invalid_paths, 1);
        assert_eq!(state.requested_edges, 13);
        assert_eq!(state.edges().len(), MAX_PATH_GRAPH_EDGES);
        assert_eq!(state.edges_omitted, 13 - MAX_PATH_GRAPH_EDGES);
    }

    #[test]
    fn missing_local_node_and_self_loop_are_counted_correctly() {
        let graph = ChannelGraph::new(key(1));
        graph.upsert_edge(&key(1), &key(1), |_| {});
        let state = graph.graph_state(None);
        assert_eq!((state.incoming_edges, state.outgoing_edges), (1, 1));
        assert_eq!((state.local_edges().len(), state.local_edges_omitted), (1, 0));
        graph.remove_node(&key(1));
        let state = graph.graph_state(None);
        assert!(!state.local_node_present);
        assert_eq!((state.node_count, state.edge_count), (0, 0));
        assert!(state.local_edges().is_empty());
    }
}
