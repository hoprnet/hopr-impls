use hopr_api::graph::{MeasurableEdge, MeasurableNode, NetworkGraphWrite, traits::EdgeObservableWrite};
#[cfg(all(feature = "telemetry", not(test)))]
use hopr_api::graph::{NetworkGraphView, traits::EdgeObservableRead};
use petgraph::graph::EdgeIndex;

use crate::{ChannelGraph, Observations, graph::InnerGraph};

#[cfg(all(feature = "telemetry", not(test)))]
lazy_static::lazy_static! {
    static ref METRIC_PEERS_BY_QUALITY: hopr_api::types::telemetry::SimpleHistogram =
        hopr_api::types::telemetry::SimpleHistogram::new(
            "hopr_peers_by_quality",
            "Distribution of the quality score of the node's directly-probed neighbors",
            vec![0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0],
        )
        .unwrap();
}

/// Records the current quality score of a directly-probed neighbor into the
/// `hopr_peers_by_quality` histogram. Called after each successful or failed neighbor probe
/// so the distribution tracks quality as it evolves per probe round.
#[cfg(all(feature = "telemetry", not(test)))]
fn observe_neighbor_quality(graph: &ChannelGraph, peer: &hopr_api::OffchainPublicKey) {
    // Unobserved edges are skipped rather than recorded as a fabricated zero.
    if let Some(obs) = graph.edge(graph.me(), peer)
        && let Some(score) = obs.score()
    {
        METRIC_PEERS_BY_QUALITY.observe(score);
    }
}

/// Resolves a loopback path from serialized node-index bytes into a validated chain of edge indices.
///
/// The `path_bytes` encode a `PathId` whose slots are key-derived (see
/// [`path_id`](crate::petgraph::path_id)), not node indices.
/// The path is expected to start and end at `me` (a closed loop).
///
/// Walks consecutive node pairs, finding the connecting edge for each.
/// Stops when the loop closes back to `me` or when no edge exists
/// between a pair. Returns `None` if the path bytes have wrong length,
/// the first node is not `me`, or fewer than 2 edges can be resolved.
fn resolve_loopback_edges(
    inner: &InnerGraph,
    me: &hopr_api::OffchainPublicKey,
    path_bytes: &[u8],
) -> Option<Vec<EdgeIndex>> {
    if path_bytes.len() != size_of::<hopr_api::ct::PathId>() {
        tracing::warn!(
            path_len = path_bytes.len(),
            expected = size_of::<hopr_api::ct::PathId>(),
            "invalid loopback path byte length"
        );
        return None;
    }

    let mut path_id: hopr_api::ct::PathId = Default::default();
    for (i, chunk) in path_bytes.chunks_exact(8).enumerate() {
        path_id[i] = u64::from_le_bytes(chunk.try_into().expect("chunk is 8 bytes"));
    }

    let me_val = crate::petgraph::path_id::encode(me);

    // First node must be self
    if path_id[0] != me_val {
        tracing::warn!("loopback path does not start at self");
        return None;
    }

    // Find the closing node: the first reoccurrence of me after position 0
    let Some(end_pos) = path_id[1..].iter().position(|&v| v == me_val).map(|p| p + 1) else {
        tracing::warn!("loopback path does not close back to self");
        return None;
    };

    // The closing node must be the last one. `find_paths` zero-fills the unused tail, so anything
    // else is a payload the local producer could not have emitted. Accepting it would let
    // `[me, a, me, b, 0]` attribute a longer path's residual latency to `me → a`.
    if path_id[end_pos + 1..].iter().any(|&slot| slot != 0) {
        tracing::warn!("loopback path has non-padding slots after the closing node");
        return None;
    }

    // Walk consecutive node pairs up to and including the closing node. Every pair must resolve:
    // attribution targets `edges[len - 2]`, so a truncated chain would retarget the whole path's
    // residual latency onto a different edge. Dropping the sample beats corrupting one.
    let mut edges = Vec::with_capacity(end_pos);

    for pair in path_id[..=end_pos].windows(2) {
        let (Some(from), Some(to)) = (
            crate::petgraph::path_id::resolve(inner, pair[0]),
            crate::petgraph::path_id::resolve(inner, pair[1]),
        ) else {
            // Padding mid-path, a node removed while the probe was in flight, or a slot no node
            // claims. All three mean the sample cannot be attributed to a known edge.
            tracing::warn!("loopback path slot does not resolve to a known node, cannot attribute");
            return None;
        };
        let Some(edge) = inner.graph.find_edge(from, to) else {
            tracing::warn!(
                resolved = edges.len(),
                expected = end_pos,
                "loopback path edge missing from graph, cannot attribute"
            );
            return None;
        };
        edges.push(edge);
    }

    if edges.len() != end_pos {
        tracing::warn!(
            edge_count = edges.len(),
            expected = end_pos,
            "incomplete loopback path resolution"
        );
        return None;
    }

    if edges.len() < 2 {
        tracing::warn!(
            edge_count = edges.len(),
            "loopback path too short to attribute intermediate measurement"
        );
        return None;
    }

    Some(edges)
}

/// Resolves the edges a SURB round-trip traversed, across both of its legs.
///
/// The two legs overlap at the replier: the forward path ends where the return path begins. That
/// shared node is what makes the join unambiguous, so the trim uses real information rather than
/// guessing at where the padding starts.
///
/// Slots are key-derived (see [`path_id`](crate::petgraph::path_id)), so `0` is unambiguously
/// padding and a slot is never handed to a different node. Returns `None` when the legs do not join,
/// do not come home, or name a node or edge the graph no longer has — attributing a stale round-trip
/// would credit edges it never used.
fn resolve_round_trip_edges(
    inner: &InnerGraph,
    me: &hopr_api::OffchainPublicKey,
    paths: &hopr_api::graph::ForwardAndReturnPath,
) -> Option<Vec<EdgeIndex>> {
    let me_val = crate::petgraph::path_id::encode(me);
    let replier = paths.reply[0];

    if paths.forward[0] != me_val {
        tracing::warn!("surb round-trip forward leg does not start at self");
        return None;
    }

    // The forward leg runs up to the replier; the return leg from the replier back to us.
    let forward_end = paths.forward.iter().position(|&v| v == replier)?;
    let reply_end = paths.reply[1..].iter().position(|&v| v == me_val).map(|p| p + 1)?;

    let loop_nodes: Vec<u64> = paths.forward[..=forward_end]
        .iter()
        .chain(paths.reply[1..=reply_end].iter())
        .copied()
        .collect();

    let mut edges = Vec::with_capacity(loop_nodes.len().saturating_sub(1));
    for pair in loop_nodes.windows(2) {
        // Resolved against the nodes actually present, so a slot belonging to a node that has since
        // been removed cannot alias whichever node now occupies its old index.
        let (Some(from), Some(to)) = (
            crate::petgraph::path_id::resolve(inner, pair[0]),
            crate::petgraph::path_id::resolve(inner, pair[1]),
        ) else {
            tracing::warn!("surb round-trip slot does not resolve to a known node, cannot attribute");
            return None;
        };
        // A missing edge means the path is stale; attributing the rest would credit edges the
        // round-trip may never have used.
        let edge = inner.graph.find_edge(from, to)?;
        edges.push(edge);
    }

    (!edges.is_empty()).then_some(edges)
}

impl hopr_api::graph::NetworkGraphUpdate for ChannelGraph {
    fn set_ticket_face_value(&self, ticket_face_value: hopr_api::graph::traits::Balance) {
        *self.ticket_face_value.write() = Some(ticket_face_value);
    }

    #[tracing::instrument(level = "debug", skip(self, update))]
    fn record_edge<N, P>(&self, update: MeasurableEdge<N, P>)
    where
        N: hopr_api::graph::MeasurablePeer + Send + Clone,
        P: hopr_api::graph::MeasurablePath + Send + Clone,
    {
        use hopr_api::graph::{
            EdgeLinkObservable,
            traits::{EdgeObservableRead, EdgeWeightType},
        };

        match update {
            MeasurableEdge::Surb(telemetry) => {
                // The window buckets this report at `Instant::now()`, so a report that was produced
                // several window widths ago would be counted as current traffic and could set or
                // clear the trend on its own. `timestamp` is the interval's reporting time (unix
                // epoch millis); a report from the future (backward clock drift) or from further
                // back than the window can still hold is discarded rather than misfiled, the same
                // way the loopback branch below discards an implausible RTT.
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis();
                let Some(age_ms) = now_ms.checked_sub(telemetry.timestamp) else {
                    tracing::debug!("surb round-trip timestamp in the future, dropping the report");
                    return;
                };
                if age_ms > crate::weight::surb_window().as_millis() {
                    tracing::debug!(age_ms, "surb round-trip report older than the window, dropping it");
                    return;
                }

                let mut inner = self.inner.write();
                if !inner.indices.contains_left(&self.me) {
                    tracing::warn!("self not present in the graph; dropping surb round-trip");
                    return;
                }
                let Some(edges) = resolve_round_trip_edges(&inner, &self.me, &telemetry.paths) else {
                    return;
                };

                // Every edge on the loop, unlike the loopback handler above which attributes to a
                // single edge. That one is doing incremental latency tomography: it knows the rest
                // of the loop already and subtracts to isolate one unknown. A round-trip has no
                // unknown to isolate — it is direct evidence that the whole loop carried traffic,
                // so crediting one edge would discard most of what was observed.
                tracing::trace!(
                    edge_count = edges.len(),
                    expected = telemetry.expected,
                    observed = telemetry.observed,
                    "recording surb round-trips across the loop"
                );
                for edge in edges {
                    if let Some(weight) = inner.graph.edge_weight_mut(edge) {
                        weight.record(EdgeWeightType::SurbRoundTrips {
                            expected: telemetry.expected,
                            observed: telemetry.observed,
                        });
                    }
                }
            }
            MeasurableEdge::Probe(Ok(hopr_api::graph::EdgeTransportTelemetry::Neighbor(ref telemetry))) => {
                tracing::trace!(
                    peer = %telemetry.peer(),
                    latency_ms = telemetry.rtt().as_millis(),
                    "neighbor probe successful"
                );

                // Both directions are set for immediate connections, because the graph is directional
                // and must be directionally complete for looping traffic.
                self.upsert_edge(&self.me, telemetry.peer(), |obs| {
                    obs.record(EdgeWeightType::Connected(true));
                    obs.record(EdgeWeightType::Immediate(Ok(telemetry.rtt() / 2)));
                });
                self.upsert_edge(telemetry.peer(), &self.me, |obs| {
                    obs.record(EdgeWeightType::Connected(true));
                    obs.record(EdgeWeightType::Immediate(Ok(telemetry.rtt() / 2)));
                });

                #[cfg(all(feature = "telemetry", not(test)))]
                observe_neighbor_quality(self, telemetry.peer());
            }
            MeasurableEdge::Probe(Ok(hopr_api::graph::EdgeTransportTelemetry::Loopback(telemetry))) => {
                tracing::trace!("loopback probe successful");

                let mut inner = self.inner.write();
                let Some(_me_idx) = inner.indices.get_by_left(&self.me).copied() else {
                    tracing::debug!("failed to resolve index of myself for loopback probe attribution");
                    return;
                };
                let Some(edges) = resolve_loopback_edges(&inner, &self.me, telemetry.path()) else {
                    tracing::debug!("failed to resolve loopback path for probe attribution");
                    return;
                };

                let target_idx = edges.len() - 2;

                // Attributed duration = total RTT - the latencies of the *other* edges on the
                // loop, each taken from its intermediate QoS where available and its immediate QoS
                // otherwise. What remains is the target edge's own latency.
                //
                // `timestamp()` is the probe's creation time (unix epoch millis), so the
                // RTT is the elapsed time until now. A timestamp in the future (backward
                // clock drift) underflows and is discarded rather than recorded as a
                // zero-duration RTT. Values above the plausibility cap (clock skew, stale
                // telemetry) are likewise discarded instead of poisoning the latency EMA.
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis();
                let Some(elapsed_ms) = now_ms.checked_sub(telemetry.timestamp()) else {
                    tracing::debug!("loopback probe timestamp in the future, skipping attribution");
                    return;
                };
                let total_rtt = std::time::Duration::from_millis(elapsed_ms as u64);
                if total_rtt > self.max_plausible_loopback_rtt {
                    tracing::debug!(
                        rtt_ms = total_rtt.as_millis(),
                        "implausible loopback probe RTT, skipping attribution"
                    );
                    return;
                }
                // Everything *except* the target: the residual is meant to be the target's own
                // latency, so subtracting our current estimate of it too would yield the error in
                // that estimate rather than a new measurement — and would drive the residual to
                // zero exactly when the estimates are good.
                let mut known_latency = std::time::Duration::ZERO;

                for (i, &edge) in edges.iter().enumerate() {
                    if i == target_idx {
                        continue;
                    }
                    if let Some(weight) = inner.graph.edge_weight(edge) {
                        let lat = weight
                            .intermediate_qos()
                            .and_then(|q| q.average_latency())
                            .or_else(|| weight.immediate_qos().and_then(|q| q.average_latency()));
                        if let Some(lat) = lat {
                            known_latency += lat;
                        }
                    } else {
                        tracing::debug!("failed to find edge for loopback probe attribution");
                    }
                }

                // A saturating subtraction would turn "the known latencies already account for the
                // whole round trip" into a measured zero — and a zero latency scores in the *fastest*
                // band, so a clamp would be read as the best possible link. The residual is only a
                // measurement while it stays positive; otherwise this probe tells us nothing about
                // the target's speed and no latency is recorded for it.
                let Some(attributed_duration) = total_rtt.checked_sub(known_latency) else {
                    tracing::debug!(
                        total_rtt_ms = total_rtt.as_millis(),
                        known_ms = known_latency.as_millis(),
                        "known latencies already exceed the loopback RTT, no latency to attribute"
                    );
                    return;
                };

                tracing::trace!(
                    target_edge = edges[target_idx].index(),
                    attributed_ms = attributed_duration.as_millis(),
                    total_rtt_ms = total_rtt.as_millis(),
                    path_edges = edges.len(),
                    "loopback probe attributed to intermediate edge"
                );

                if let Some(weight) = inner.graph.edge_weight_mut(edges[target_idx]) {
                    weight.record(EdgeWeightType::Intermediate(Ok(attributed_duration)));
                } else {
                    tracing::debug!("failed to find target edge for loopback probe attribution");
                }
            }
            MeasurableEdge::Probe(Err(hopr_api::graph::NetworkGraphError::ProbeNeighborTimeout(ref peer))) => {
                tracing::trace!(
                    peer = %peer,
                    reason = "probe timeout",
                    "neighbor probe failed"
                );

                // Both directions are set for immediate connections, because the graph is directional
                // and must be directionally complete for looping traffic.
                self.upsert_edge(&self.me, peer, |obs| {
                    obs.record(EdgeWeightType::Immediate(Err(())));
                });
                self.upsert_edge(peer, &self.me, |obs| {
                    obs.record(EdgeWeightType::Immediate(Err(())));
                });

                #[cfg(all(feature = "telemetry", not(test)))]
                observe_neighbor_quality(self, peer);
            }
            MeasurableEdge::Probe(Err(hopr_api::graph::NetworkGraphError::ProbeLoopbackTimeout(telemetry))) => {
                tracing::trace!("loopback probe failed");

                let mut inner = self.inner.write();
                let Some(_me_idx) = inner.indices.get_by_left(&self.me).copied() else {
                    tracing::debug!("failed to resolve index of myself");
                    return;
                };
                let Some(edges) = resolve_loopback_edges(&inner, &self.me, telemetry.path()) else {
                    tracing::debug!("failed to resolve loopback path for probe timeout, cannot attribute");
                    return;
                };

                let target_idx = edges.len() - 2;

                tracing::trace!(
                    target_edge = edges[target_idx].index(),
                    path_edges = edges.len(),
                    "loopback probe timeout attributed to intermediate edge"
                );

                if let Some(weight) = inner.graph.edge_weight_mut(edges[target_idx]) {
                    weight.record(EdgeWeightType::Intermediate(Err(())));
                }
            }
            MeasurableEdge::Balance(update) => {
                self.upsert_edge(&update.src, &update.dest, |obs: &mut Observations| {
                    obs.record(EdgeWeightType::Balance(update.balance));
                });
            }
            MeasurableEdge::ConnectionStatus { peer, connected } => {
                tracing::trace!(
                    peer = %peer,
                    connected = connected,
                    "recording connection status update"
                );

                self.upsert_edge(&self.me, &peer, |obs| {
                    obs.record(EdgeWeightType::Connected(connected));
                });
                self.upsert_edge(&peer, &self.me, |obs| {
                    obs.record(EdgeWeightType::Connected(connected));
                });
            }
        }
    }

    #[tracing::instrument(level = "debug", skip(self, update))]
    fn record_node<N>(&self, update: N)
    where
        N: MeasurableNode + Clone + Send + Sync + 'static,
    {
        hopr_api::graph::NetworkGraphWrite::add_node(self, update.into());
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Context;
    use assertables::assert_in_delta;
    use hex_literal::hex;
    use hopr_api::{
        OffchainPublicKey,
        graph::{
            EdgeLinkObservable, EdgeTransportTelemetry, MeasurablePath, MeasurablePeer, NetworkGraphError,
            NetworkGraphUpdate, NetworkGraphView, NetworkGraphWrite,
            traits::{EdgeObservableRead, EdgeProtocolObservable},
        },
        types::crypto::prelude::{Keypair, OffchainKeypair},
    };

    use super::*;

    /// Fixed test secret keys (reused from the broader codebase).
    const SECRET_0: [u8; 32] = hex!("60741b83b99e36aa0c1331578156e16b8e21166d01834abb6c64b103f885734d");
    const SECRET_1: [u8; 32] = hex!("71bf1f42ebbfcd89c3e197a3fd7cda79b92499e509b6fefa0fe44d02821d146a");
    const SECRET_2: [u8; 32] = hex!("c24bd833704dd2abdae3933fcc9962c2ac404f84132224c474147382d4db2299");
    const SECRET_3: [u8; 32] = hex!("e0bf93e9c916104da00b1850adc4608bd7e9087bbd3f805451f4556aa6b3fd6e");

    /// Creates an OffchainPublicKey from a fixed secret.
    fn pubkey_from(secret: &[u8; 32]) -> OffchainPublicKey {
        *OffchainKeypair::from_secret(secret).expect("valid secret key").public()
    }

    #[derive(Debug, Clone)]
    struct TestNeighbor {
        peer: OffchainPublicKey,
        rtt: std::time::Duration,
    }

    impl MeasurablePeer for TestNeighbor {
        fn peer(&self) -> &OffchainPublicKey {
            &self.peer
        }

        fn rtt(&self) -> std::time::Duration {
            self.rtt
        }
    }

    #[derive(Debug, Clone)]
    struct TestPath;

    impl MeasurablePath for TestPath {
        fn id(&self) -> &[u8] {
            &[]
        }

        fn path(&self) -> &[u8] {
            &[]
        }

        fn timestamp(&self) -> u128 {
            0
        }
    }

    /// Builds the graph `me -> exit -> relay -> me` and returns the node keys plus their indices,
    /// which is the shape a 0-hop-forward / 1-hop-return session produces.
    fn round_trip_graph() -> anyhow::Result<(ChannelGraph, OffchainPublicKey, OffchainPublicKey, OffchainPublicKey)> {
        let me = pubkey_from(&SECRET_0);
        let exit = pubkey_from(&SECRET_1);
        let relay = pubkey_from(&SECRET_2);

        let graph = ChannelGraph::new(me);
        graph.add_node(exit);
        graph.add_node(relay);
        graph.add_edge(&me, &exit)?;
        graph.add_edge(&exit, &relay)?;
        graph.add_edge(&relay, &me)?;
        Ok((graph, exit, relay, me))
    }

    /// The `PathId` slot a node occupies.
    ///
    /// Key-derived, not the petgraph index: RFC-0010 §4.3.3 reserves `0` for padding and forbids it
    /// as an identifier, which a zero-based index cannot honour.
    fn slot_of(graph: &ChannelGraph, key: &OffchainPublicKey) -> u64 {
        assert!(
            graph.inner.read().indices.contains_left(key),
            "node should be in the graph"
        );
        crate::petgraph::path_id::encode(key)
    }

    fn now_ms() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    }

    fn surb(
        paths: hopr_api::graph::ForwardAndReturnPath,
        expected: u64,
        observed: u64,
    ) -> hopr_api::graph::SurbTelemetry {
        surb_stamped(paths, expected, observed, now_ms())
    }

    fn surb_stamped(
        paths: hopr_api::graph::ForwardAndReturnPath,
        expected: u64,
        observed: u64,
        timestamp: u128,
    ) -> hopr_api::graph::SurbTelemetry {
        hopr_api::graph::SurbTelemetry {
            paths,
            timestamp,
            expected,
            observed,
        }
    }

    #[tokio::test]
    async fn surb_round_trip_should_credit_every_edge_on_both_legs() -> anyhow::Result<()> {
        // The distinguishing property of this handler. A loopback probe attributes to one edge
        // because it is isolating an unknown latency by subtraction; a round-trip has no unknown to
        // isolate, so crediting a single edge would throw away most of what was observed.
        let (graph, exit, relay, me) = round_trip_graph()?;
        let (me_i, exit_i, relay_i) = (slot_of(&graph, &me), slot_of(&graph, &exit), slot_of(&graph, &relay));

        let paths = hopr_api::graph::ForwardAndReturnPath {
            forward: [me_i, exit_i, 0, 0, 0],
            reply: [exit_i, relay_i, me_i, 0, 0],
        };
        graph.record_edge::<TestNeighbor, TestPath>(hopr_api::graph::MeasurableEdge::Surb(surb(paths, 4, 3)));

        for (src, dst) in [(me, exit), (exit, relay), (relay, me)] {
            let obs = graph.edge(&src, &dst).context("edge should exist")?;
            let rate = obs
                .intermediate_qos()
                .context("surb telemetry lands in the intermediate measurement")?
                .surb_delivery_rate()
                .context("window should hold the round-trips")?;
            // Read relatively: the first report sets the edge's own peak, so a path that has only
            // ever been seen delivering at one level reads as fully healthy whatever that level
            // was. The absolute ratio is not a delivery rate -- it also measures how far the
            // balancer over-mints -- so only movement away from the peak is meaningful.
            assert_in_delta!(rate, 1.0, 1e-9);
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_round_trip_report_from_outside_the_window_should_be_dropped() -> anyhow::Result<()> {
        // The window buckets a report at `Instant::now()` regardless of when it was produced, so a
        // batch delayed past the window would be counted as current traffic and could move the
        // trend on its own. Same treatment as an implausible loopback RTT: discard, do not misfile.
        let (graph, exit, relay, me) = round_trip_graph()?;
        let (me_i, exit_i, relay_i) = (slot_of(&graph, &me), slot_of(&graph, &exit), slot_of(&graph, &relay));
        let paths = hopr_api::graph::ForwardAndReturnPath {
            forward: [me_i, exit_i, 0, 0, 0],
            reply: [exit_i, relay_i, me_i, 0, 0],
        };

        let window_ms = crate::weight::surb_window().as_millis();
        for (label, stamp) in [
            ("older than the window", now_ms() - window_ms - 1_000),
            ("from the future", now_ms() + 60_000),
        ] {
            graph.record_edge::<TestNeighbor, TestPath>(hopr_api::graph::MeasurableEdge::Surb(surb_stamped(
                paths, 4, 3, stamp,
            )));

            let obs = graph.edge(&me, &exit).context("edge should exist")?;
            assert!(
                obs.intermediate_qos().and_then(|q| q.surb_delivery_rate()).is_none(),
                "a report {label} must not be counted as current traffic"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_round_trip_reported_after_its_relay_was_removed_should_credit_nothing() -> anyhow::Result<()> {
        // Slots are resolved when a SURB is minted and reported an interval later, so a removal can
        // land in between. What must not happen is the report being applied to whatever now sits at
        // those slots: `remove_node` retires the slot instead of freeing it, so the stale id finds
        // an isolated vertex, the loop fails to resolve, and nothing is credited.
        let (graph, exit, relay, me) = round_trip_graph()?;
        let (me_i, exit_i, relay_i) = (slot_of(&graph, &me), slot_of(&graph, &exit), slot_of(&graph, &relay));
        let paths = hopr_api::graph::ForwardAndReturnPath {
            forward: [me_i, exit_i, 0, 0, 0],
            reply: [exit_i, relay_i, me_i, 0, 0],
        };

        graph.remove_node(&relay);
        // A newcomer must not inherit the retired slot, which is what would make the stale id
        // resolve to a live node.
        let newcomer = pubkey_from(&SECRET_3);
        graph.add_node(newcomer);
        graph.add_edge(&exit, &newcomer)?;
        graph.add_edge(&newcomer, &me)?;

        graph.record_edge::<TestNeighbor, TestPath>(hopr_api::graph::MeasurableEdge::Surb(surb(paths, 4, 3)));

        for (src, dst) in [(me, exit), (exit, newcomer), (newcomer, me)] {
            let obs = graph.edge(&src, &dst).context("edge should exist")?;
            assert!(
                obs.intermediate_qos().and_then(|q| q.surb_delivery_rate()).is_none(),
                "a surviving edge must not be credited with a round-trip it never carried: {src} -> {dst}"
            );
        }
        Ok(())
    }

    /// A leg that stops delivering must fall away from its own peak, which is the signal the score
    /// is built on.
    #[tokio::test]
    async fn surb_round_trip_should_fall_when_delivery_drops_off_its_peak() -> anyhow::Result<()> {
        let (graph, exit, relay, me) = round_trip_graph()?;
        let (me_i, exit_i, relay_i) = (slot_of(&graph, &me), slot_of(&graph, &exit), slot_of(&graph, &relay));
        let paths = hopr_api::graph::ForwardAndReturnPath {
            forward: [me_i, exit_i, 0, 0, 0],
            reply: [exit_i, relay_i, me_i, 0, 0],
        };

        // Healthy: everything minted comes back, establishing the peak.
        graph.record_edge::<TestNeighbor, TestPath>(hopr_api::graph::MeasurableEdge::Surb(surb(paths, 100, 100)));
        // Then the return path breaks and nothing does.
        graph.record_edge::<TestNeighbor, TestPath>(hopr_api::graph::MeasurableEdge::Surb(surb(paths, 100, 0)));

        let obs = graph.edge(&exit, &relay).context("edge should exist")?;
        let rate = obs
            .intermediate_qos()
            .context("surb telemetry lands in the intermediate measurement")?
            .surb_delivery_rate()
            .context("window should hold the round-trips")?;

        assert!(rate < 0.6, "a leg that stopped delivering still reads {rate}");
        Ok(())
    }

    #[tokio::test]
    async fn surb_round_trip_should_leave_latency_untouched() -> anyhow::Result<()> {
        // A round-trip carries no per-edge latency, so it must not invent one.
        let (graph, exit, relay, me) = round_trip_graph()?;
        let (me_i, exit_i, relay_i) = (slot_of(&graph, &me), slot_of(&graph, &exit), slot_of(&graph, &relay));

        let paths = hopr_api::graph::ForwardAndReturnPath {
            forward: [me_i, exit_i, 0, 0, 0],
            reply: [exit_i, relay_i, me_i, 0, 0],
        };
        graph.record_edge::<TestNeighbor, TestPath>(hopr_api::graph::MeasurableEdge::Surb(surb(paths, 1, 1)));

        let obs = graph.edge(&exit, &relay).context("edge should exist")?;
        assert!(
            obs.intermediate_qos()
                .context("intermediate present")?
                .average_latency()
                .is_none(),
            "latency must stay unknown"
        );
        Ok(())
    }

    #[tokio::test]
    async fn surb_round_trip_should_be_dropped_when_the_legs_do_not_join() -> anyhow::Result<()> {
        let (graph, exit, relay, me) = round_trip_graph()?;
        let (me_i, exit_i, relay_i) = (slot_of(&graph, &me), slot_of(&graph, &exit), slot_of(&graph, &relay));

        // The reply leg starts at the relay, which never appears on the forward leg — so the two
        // legs describe no single round-trip and attributing either would be a guess.
        let paths = hopr_api::graph::ForwardAndReturnPath {
            forward: [me_i, exit_i, 0, 0, 0],
            reply: [relay_i, me_i, 0, 0, 0],
        };
        graph.record_edge::<TestNeighbor, TestPath>(hopr_api::graph::MeasurableEdge::Surb(surb(paths, 4, 0)));

        let obs = graph.edge(&me, &exit).context("edge should exist")?;
        assert!(
            obs.intermediate_qos().is_none_or(|i| i.surb_delivery_rate().is_none()),
            "a non-joining round-trip must not be attributed"
        );
        Ok(())
    }

    #[tokio::test]
    async fn surb_round_trip_should_be_dropped_when_a_slot_is_stale() -> anyhow::Result<()> {
        // A PathId names keys, not positions, so a slot whose node has left the graph resolves to
        // nothing — the report is discarded rather than credited to some surviving edge.
        let (graph, exit, relay, me) = round_trip_graph()?;
        let (me_i, exit_i) = (slot_of(&graph, &me), slot_of(&graph, &exit));
        let _ = relay;

        let paths = hopr_api::graph::ForwardAndReturnPath {
            forward: [me_i, exit_i, 0, 0, 0],
            reply: [exit_i, 999, me_i, 0, 0],
        };
        graph.record_edge::<TestNeighbor, TestPath>(hopr_api::graph::MeasurableEdge::Surb(surb(paths, 4, 4)));

        let obs = graph.edge(&me, &exit).context("edge should exist")?;
        assert!(
            obs.intermediate_qos().is_none_or(|i| i.surb_delivery_rate().is_none()),
            "a stale path must not be attributed"
        );
        Ok(())
    }

    #[tokio::test]
    async fn neighbor_probe_should_update_edge_observation() -> anyhow::Result<()> {
        let me_kp = OffchainKeypair::from_secret(&SECRET_0)?;
        let me = *me_kp.public();
        let peer_kp = OffchainKeypair::from_secret(&SECRET_1)?;
        let peer_key = *peer_kp.public();

        let graph = ChannelGraph::new(me);
        graph.add_node(peer_key);
        graph.add_edge(&me, &peer_key)?;

        let rtt = std::time::Duration::from_millis(100);
        let telemetry: Result<EdgeTransportTelemetry<TestNeighbor, TestPath>, NetworkGraphError<TestPath>> =
            Ok(EdgeTransportTelemetry::Neighbor(TestNeighbor { peer: peer_key, rtt }));
        graph.record_edge(hopr_api::graph::MeasurableEdge::Probe(telemetry));

        let obs = graph.edge(&me, &peer_key).context("edge observation should exist")?;
        let immediate = obs
            .immediate_qos()
            .context("immediate QoS should be present after probe")?;
        assert_eq!(immediate.average_latency().context("latency should be set")?, rtt / 2,);
        Ok(())
    }

    #[tokio::test]
    async fn neighbor_probe_should_create_symmetric_edges() -> anyhow::Result<()> {
        let me = pubkey_from(&SECRET_0);
        let peer = pubkey_from(&SECRET_1);

        let graph = ChannelGraph::new(me);
        graph.add_node(peer);
        // No edges pre-created — upsert should create both directions

        let rtt = std::time::Duration::from_millis(100);
        let telemetry: Result<EdgeTransportTelemetry<TestNeighbor, TestPath>, NetworkGraphError<TestPath>> =
            Ok(EdgeTransportTelemetry::Neighbor(TestNeighbor { peer, rtt }));
        graph.record_edge(hopr_api::graph::MeasurableEdge::Probe(telemetry));

        // me → peer
        let obs_fwd = graph.edge(&me, &peer).context("edge me→peer should exist")?;
        let imm_fwd = obs_fwd.immediate_qos().context("me→peer should have immediate QoS")?;
        assert_eq!(
            imm_fwd.average_latency().context("me→peer latency should be set")?,
            rtt / 2
        );

        // peer → me
        let obs_rev = graph.edge(&peer, &me).context("edge peer→me should exist")?;
        let imm_rev = obs_rev.immediate_qos().context("peer→me should have immediate QoS")?;
        assert_eq!(
            imm_rev.average_latency().context("peer→me latency should be set")?,
            rtt / 2
        );

        Ok(())
    }

    #[tokio::test]
    async fn neighbor_probe_timeout_should_create_symmetric_edges() -> anyhow::Result<()> {
        let me = pubkey_from(&SECRET_0);
        let peer = pubkey_from(&SECRET_1);

        let graph = ChannelGraph::new(me);
        graph.add_node(peer);
        // No edges pre-created

        let telemetry: Result<EdgeTransportTelemetry<TestNeighbor, TestPath>, NetworkGraphError<TestPath>> =
            Err(NetworkGraphError::ProbeNeighborTimeout(Box::new(peer)));
        graph.record_edge(hopr_api::graph::MeasurableEdge::Probe(telemetry));

        // me → peer
        let obs_fwd = graph
            .edge(&me, &peer)
            .context("edge me→peer should exist after timeout")?;
        let imm_fwd = obs_fwd.immediate_qos().context("me→peer should have immediate QoS")?;
        assert!(
            imm_fwd.average_latency().is_none(),
            "failed probe should not set latency"
        );
        assert!(
            imm_fwd.average_probe_rate().expect("probed") < 1.0,
            "failed probe should lower success rate"
        );

        // peer → me
        let obs_rev = graph
            .edge(&peer, &me)
            .context("edge peer→me should exist after timeout")?;
        let imm_rev = obs_rev.immediate_qos().context("peer→me should have immediate QoS")?;
        assert!(
            imm_rev.average_latency().is_none(),
            "failed probe should not set latency on reverse"
        );
        assert!(
            imm_rev.average_probe_rate().expect("probed") < 1.0,
            "failed probe should lower success rate on reverse"
        );

        Ok(())
    }

    #[tokio::test]
    async fn probe_timeout_should_record_as_failed_probe() -> anyhow::Result<()> {
        let me_kp = OffchainKeypair::from_secret(&SECRET_0)?;
        let me = *me_kp.public();
        let peer_kp = OffchainKeypair::from_secret(&SECRET_1)?;
        let peer_key = *peer_kp.public();

        let graph = ChannelGraph::new(me);
        graph.add_node(peer_key);
        graph.add_edge(&me, &peer_key)?;

        let telemetry: Result<EdgeTransportTelemetry<TestNeighbor, TestPath>, NetworkGraphError<TestPath>> =
            Err(NetworkGraphError::ProbeNeighborTimeout(Box::new(peer_key)));
        graph.record_edge(hopr_api::graph::MeasurableEdge::Probe(telemetry));

        let obs = graph.edge(&me, &peer_key).context("edge observation should exist")?;
        let immediate = obs
            .immediate_qos()
            .context("immediate QoS should be present after failed probe")?;
        assert!(immediate.average_latency().is_none());
        assert!(immediate.average_probe_rate().expect("probed") < 1.0);
        Ok(())
    }

    #[tokio::test]
    async fn balance_update_should_set_edge_capacity() -> anyhow::Result<()> {
        let me = pubkey_from(&SECRET_0);
        let peer = pubkey_from(&SECRET_1);
        let graph = ChannelGraph::new(me);
        graph.add_node(peer);
        graph.add_edge(&me, &peer)?;

        let capacity_update = hopr_api::graph::EdgeBalanceUpdate {
            src: me,
            dest: peer,
            balance: Some(hopr_api::graph::traits::Balance::from(1000u64)),
        };
        graph
            .record_edge::<TestNeighbor, TestPath>(hopr_api::graph::MeasurableEdge::Balance(Box::new(capacity_update)));

        let obs = graph.edge(&me, &peer).context("edge should exist")?;
        let intermediate = obs
            .intermediate_qos()
            .context("intermediate QoS should be present after capacity update")?;
        assert_eq!(
            intermediate.balance(),
            Some(hopr_api::graph::traits::Balance::from(1000u64))
        );
        Ok(())
    }

    #[tokio::test]
    async fn balance_update_should_accept_none_value() -> anyhow::Result<()> {
        let me = pubkey_from(&SECRET_0);
        let peer = pubkey_from(&SECRET_1);
        let graph = ChannelGraph::new(me);
        graph.add_node(peer);
        graph.add_edge(&me, &peer)?;

        let capacity_update = hopr_api::graph::EdgeBalanceUpdate {
            src: me,
            dest: peer,
            balance: None,
        };
        graph
            .record_edge::<TestNeighbor, TestPath>(hopr_api::graph::MeasurableEdge::Balance(Box::new(capacity_update)));

        let obs = graph.edge(&me, &peer).context("edge should exist")?;
        let intermediate = obs.intermediate_qos().context("intermediate QoS should be present")?;
        assert_eq!(intermediate.balance(), None);
        Ok(())
    }

    #[tokio::test]
    async fn record_node_should_add_node_to_graph() {
        let me = pubkey_from(&SECRET_0);
        let peer = pubkey_from(&SECRET_1);
        let graph = ChannelGraph::new(me);

        assert!(!graph.contains_node(&peer));
        graph.record_node(peer);
        assert!(graph.contains_node(&peer));
    }

    #[tokio::test]
    async fn probe_should_create_edge_if_absent() -> anyhow::Result<()> {
        let me = pubkey_from(&SECRET_0);
        let peer = pubkey_from(&SECRET_1);
        let graph = ChannelGraph::new(me);
        graph.add_node(peer);
        // No explicit add_edge — record_edge should upsert

        let rtt = std::time::Duration::from_millis(80);
        let telemetry: Result<EdgeTransportTelemetry<TestNeighbor, TestPath>, NetworkGraphError<TestPath>> =
            Ok(EdgeTransportTelemetry::Neighbor(TestNeighbor { peer, rtt }));
        graph.record_edge(hopr_api::graph::MeasurableEdge::Probe(telemetry));

        assert!(graph.has_edge(&me, &peer), "probe should create edge via upsert");
        let obs = graph.edge(&me, &peer).context("edge should exist")?;
        assert!(obs.immediate_qos().is_some());
        Ok(())
    }

    #[tokio::test]
    async fn multiple_probes_should_accumulate_in_observations() -> anyhow::Result<()> {
        let me = pubkey_from(&SECRET_0);
        let peer = pubkey_from(&SECRET_1);
        let graph = ChannelGraph::new(me);
        graph.add_node(peer);
        graph.add_edge(&me, &peer)?;

        // Send several successful probes
        for _ in 0..5 {
            let telemetry: Result<EdgeTransportTelemetry<TestNeighbor, TestPath>, NetworkGraphError<TestPath>> =
                Ok(EdgeTransportTelemetry::Neighbor(TestNeighbor {
                    peer,
                    rtt: std::time::Duration::from_millis(60),
                }));
            graph.record_edge(hopr_api::graph::MeasurableEdge::Probe(telemetry));
        }

        let obs = graph.edge(&me, &peer).context("edge should exist")?;
        let qos = obs.immediate_qos().context("immediate QoS should exist")?;
        assert_eq!(
            qos.average_latency().context("latency should be set")?,
            std::time::Duration::from_millis(30), // rtt / 2 = 30ms
        );
        assert!(qos.average_probe_rate().expect("probed") > 0.9, "all probes succeeded");
        Ok(())
    }

    /// A `MeasurablePath` carrying a serialized `PathId` and a timestamp for
    /// loopback probe telemetry tests.
    #[derive(Debug, Clone)]
    struct LoopbackTestPath {
        path_bytes: Vec<u8>,
        timestamp_ms: u128,
    }

    impl LoopbackTestPath {
        /// Builds telemetry from raw slot values, for payloads a correct encoder cannot produce.
        fn from_slots(path_id: [u64; 5], timestamp_ms: u128) -> Self {
            Self {
                path_bytes: path_id.iter().flat_map(|v| v.to_le_bytes()).collect(),
                timestamp_ms,
            }
        }

        fn new(nodes: &[hopr_api::OffchainPublicKey], timestamp_ms: u128) -> Self {
            assert!(nodes.len() <= 5, "a PathId holds at most 5 slots");

            let mut path_id: hopr_api::ct::PathId = Default::default();
            for (slot, key) in path_id.iter_mut().zip(nodes) {
                *slot = crate::petgraph::path_id::encode(key);
            }

            let path_bytes = path_id.iter().flat_map(|v| v.to_le_bytes()).collect();
            Self {
                path_bytes,
                timestamp_ms,
            }
        }
    }

    impl MeasurablePath for LoopbackTestPath {
        fn id(&self) -> &[u8] {
            &[]
        }

        fn path(&self) -> &[u8] {
            &self.path_bytes
        }

        fn timestamp(&self) -> u128 {
            self.timestamp_ms
        }
    }

    /// Current unix epoch time in milliseconds, mirroring how production code derives RTT.
    fn now_unix_ms() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    }

    /// Helper to send a loopback probe with the given path and desired RTT.
    ///
    /// The telemetry timestamp is set `rtt_ms` in the past so the receiver
    /// computes an elapsed RTT of approximately `rtt_ms`.
    fn send_loopback(graph: &ChannelGraph, nodes: &[hopr_api::OffchainPublicKey], rtt_ms: u128) {
        let telemetry: Result<
            EdgeTransportTelemetry<TestNeighbor, LoopbackTestPath>,
            NetworkGraphError<LoopbackTestPath>,
        > = Ok(EdgeTransportTelemetry::Loopback(LoopbackTestPath::new(
            nodes,
            now_unix_ms() - rtt_ms,
        )));
        graph.record_edge(hopr_api::graph::MeasurableEdge::Probe(telemetry));
    }

    /// Helper to send a loopback timeout with the given path.
    fn send_loopback_timeout(graph: &ChannelGraph, nodes: &[hopr_api::OffchainPublicKey]) {
        let telemetry: Result<
            EdgeTransportTelemetry<TestNeighbor, LoopbackTestPath>,
            NetworkGraphError<LoopbackTestPath>,
        > = Err(NetworkGraphError::ProbeLoopbackTimeout(LoopbackTestPath::new(nodes, 0)));
        graph.record_edge(hopr_api::graph::MeasurableEdge::Probe(telemetry));
    }

    #[tokio::test]
    async fn loopback_three_hop_should_attribute_to_penultimate_edge() -> anyhow::Result<()> {
        // Loopback: me(0) → a(1) → b(2) → me(0)
        // PathId nodes: [me=0, a=1, b=2, me=0, 0]
        // Resolved edges: me→a, a→b, b→me (3 edges)
        // Target = edges[len-2] = edges[1] = a→b
        let me = pubkey_from(&SECRET_0);
        let a = pubkey_from(&SECRET_1);
        let b = pubkey_from(&SECRET_2);

        let graph = ChannelGraph::new(me);
        graph.add_node(a);
        graph.add_node(b);
        graph.add_edge(&me, &a)?;
        graph.add_edge(&a, &b)?;
        graph.add_edge(&b, &me)?; // return edge

        send_loopback(&graph, &[me, a, b, me], 200);

        let obs = graph.edge(&a, &b).context("edge a→b should exist")?;
        let qos = obs
            .intermediate_qos()
            .context("intermediate QoS should be present on a→b")?;
        assert_in_delta!(
            qos.average_latency().context("latency should be set")?.as_millis(),
            200,
            25
        );

        // me→a should NOT have intermediate QoS from this probe
        let obs_me_a = graph.edge(&me, &a).context("edge me→a should exist")?;
        assert!(obs_me_a.intermediate_qos().is_none());

        Ok(())
    }

    #[tokio::test]
    async fn loopback_four_hop_should_attribute_to_penultimate_edge() -> anyhow::Result<()> {
        // Loopback: me(0) → a(1) → b(2) → c(3) → me(0)
        // PathId nodes: [me=0, a=1, b=2, c=3, me=0]
        // Resolved edges: me→a, a→b, b→c, c→me (4 edges)
        // Target = edges[len-2] = edges[2] = b→c
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
        graph.add_edge(&c, &me)?; // return edge

        send_loopback(&graph, &[me, a, b, c, me], 300);

        // Edge b→c (target) should have the intermediate QoS
        let obs = graph.edge(&b, &c).context("edge b→c should exist")?;
        let qos = obs
            .intermediate_qos()
            .context("intermediate QoS should be present on b→c")?;
        assert_in_delta!(
            qos.average_latency().context("latency should be set")?.as_millis(),
            300,
            25
        ); // no preceding intermediate latencies, so full RTT is attributed

        // Earlier edges should NOT have intermediate QoS from this probe
        let obs_me_a = graph.edge(&me, &a).context("edge me→a should exist")?;
        assert!(obs_me_a.intermediate_qos().is_none());
        let obs_a_b = graph.edge(&a, &b).context("edge a→b should exist")?;
        assert!(obs_a_b.intermediate_qos().is_none());

        Ok(())
    }

    #[tokio::test]
    async fn loopback_should_subtract_known_preceding_latencies() -> anyhow::Result<()> {
        // Loopback: me(0) → a(1) → b(2) → c(3) → me(0)
        // Resolved edges: me→a, a→b, b→c, c→me (4 edges). Target = b→c (idx 2).
        // Preceding edges = [me→a, a→b]
        // Pre-set me→a = 80ms, a→b = 40ms
        // Attributed for b→c = 300 - 80 - 40 = 180ms
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
        graph.add_edge(&c, &me)?; // return edge

        // Pre-set intermediate latency on me→a and a→b
        graph.upsert_edge(&me, &a, |obs| {
            use hopr_api::graph::traits::EdgeObservableWrite;
            obs.record(hopr_api::graph::traits::EdgeWeightType::Intermediate(Ok(
                std::time::Duration::from_millis(80),
            )));
        });
        graph.upsert_edge(&a, &b, |obs| {
            use hopr_api::graph::traits::EdgeObservableWrite;
            obs.record(hopr_api::graph::traits::EdgeWeightType::Intermediate(Ok(
                std::time::Duration::from_millis(40),
            )));
        });

        send_loopback(&graph, &[me, a, b, c, me], 300);

        let obs = graph.edge(&b, &c).context("edge b→c should exist")?;
        let qos = obs
            .intermediate_qos()
            .context("intermediate QoS should be present on b→c")?;
        assert_in_delta!(
            qos.average_latency().context("latency should be set")?.as_millis(),
            180,
            25
        ); // 300ms total - 80ms (me→a) - 40ms (a→b) = 180ms attributed to b→c

        Ok(())
    }

    #[tokio::test]
    async fn loopback_should_subtract_immediate_latency_on_first_edge() -> anyhow::Result<()> {
        // Loopback: me(0) → a(1) → b(2) → me(0)
        // Resolved edges: me→a, a→b, b→me (3 edges). Target = a→b (idx 1).
        // me→a has immediate QoS = 60ms (from my neighbor probing of a), no intermediate yet.
        // Attributed for a→b = 200 - 60 = 140ms
        let me = pubkey_from(&SECRET_0);
        let a = pubkey_from(&SECRET_1);
        let b = pubkey_from(&SECRET_2);

        let graph = ChannelGraph::new(me);
        graph.add_node(a);
        graph.add_node(b);
        graph.add_edge(&me, &a)?;
        graph.add_edge(&a, &b)?;
        graph.add_edge(&b, &me)?;

        // Pre-set immediate QoS on me→a (my direct measurement to neighbor a)
        graph.upsert_edge(&me, &a, |obs| {
            use hopr_api::graph::traits::EdgeObservableWrite;
            obs.record(hopr_api::graph::traits::EdgeWeightType::Immediate(Ok(
                std::time::Duration::from_millis(60),
            )));
        });

        send_loopback(&graph, &[me, a, b, me], 200);

        let obs = graph.edge(&a, &b).context("edge a→b should exist")?;
        let qos = obs
            .intermediate_qos()
            .context("intermediate QoS should be present on a→b")?;
        assert_in_delta!(
            qos.average_latency().context("latency should be set")?.as_millis(),
            140,
            25
        ); // 200ms total - 60ms (me→a immediate) = 140ms attributed to a→b

        Ok(())
    }

    #[tokio::test]
    async fn loopback_invalid_path_length_should_be_ignored() -> anyhow::Result<()> {
        let me = pubkey_from(&SECRET_0);
        let a = pubkey_from(&SECRET_1);

        let graph = ChannelGraph::new(me);
        graph.add_node(a);
        graph.add_edge(&me, &a)?;

        // Send loopback with wrong-length path bytes (not 40 bytes)
        let telemetry: Result<
            EdgeTransportTelemetry<TestNeighbor, LoopbackTestPath>,
            NetworkGraphError<LoopbackTestPath>,
        > = Ok(EdgeTransportTelemetry::Loopback(LoopbackTestPath {
            path_bytes: vec![0u8; 16], // wrong: 16 bytes instead of 40
            timestamp_ms: 100,
        }));
        graph.record_edge(hopr_api::graph::MeasurableEdge::Probe(telemetry));

        // Edge should have no intermediate observations
        let obs = graph.edge(&me, &a).context("edge should exist")?;
        assert!(
            obs.intermediate_qos().is_none(),
            "invalid path bytes should not produce any intermediate measurement"
        );

        Ok(())
    }

    #[tokio::test]
    async fn loopback_implausible_rtt_should_be_ignored() -> anyhow::Result<()> {
        // Adversarial mitigation: an attacker who withholds a probe past the
        // plausibility cap before replaying it would otherwise poison the latency
        // EMA with an inflated measurement. Any computed RTT above the cap is discarded.
        let me = pubkey_from(&SECRET_0);
        let a = pubkey_from(&SECRET_1);
        let b = pubkey_from(&SECRET_2);

        let graph = ChannelGraph::new(me);
        graph.add_node(a);
        graph.add_node(b);
        graph.add_edge(&me, &a)?;
        graph.add_edge(&a, &b)?;
        graph.add_edge(&b, &me)?; // return edge

        // Probe withheld 90 s before replay: computed RTT far above the 30 s cap.
        send_loopback(&graph, &[me, a, b, me], 90_000);

        let obs = graph.edge(&a, &b).context("edge a→b should exist")?;
        assert!(
            obs.intermediate_qos().is_none(),
            "implausible RTT must not produce an intermediate measurement"
        );

        Ok(())
    }

    #[tokio::test]
    async fn loopback_future_timestamp_should_be_ignored() -> anyhow::Result<()> {
        // Backward clock drift can place the probe's creation timestamp in the future,
        // so `now - timestamp` underflows. Such a probe is discarded rather than
        // recorded as a zero-duration RTT, which would poison the latency EMA toward 0.
        let me = pubkey_from(&SECRET_0);
        let a = pubkey_from(&SECRET_1);
        let b = pubkey_from(&SECRET_2);

        let graph = ChannelGraph::new(me);
        graph.add_node(a);
        graph.add_node(b);
        graph.add_edge(&me, &a)?;
        graph.add_edge(&a, &b)?;
        graph.add_edge(&b, &me)?; // return edge

        let telemetry: Result<
            EdgeTransportTelemetry<TestNeighbor, LoopbackTestPath>,
            NetworkGraphError<LoopbackTestPath>,
        > = Ok(EdgeTransportTelemetry::Loopback(LoopbackTestPath::new(
            &[me, a, b, me],
            now_unix_ms() + 5_000, // timestamp 5 s in the future
        )));
        graph.record_edge(hopr_api::graph::MeasurableEdge::Probe(telemetry));

        let obs = graph.edge(&a, &b).context("edge a→b should exist")?;
        assert!(
            obs.intermediate_qos().is_none(),
            "future timestamp must not produce an intermediate measurement"
        );

        Ok(())
    }

    #[tokio::test]
    async fn loopback_single_edge_path_should_be_ignored_if_no_immediate_or_intermediate_result_exists_for_the_edge()
    -> anyhow::Result<()> {
        // A path with only 1 edge has no "edge before the last"
        // me(0) → a(1)
        // PathId nodes: [me=0, a=1, 0, 0, 0]
        // Trailing 0 = me which is already visited → stops at 1 edge
        let me = pubkey_from(&SECRET_0);
        let a = pubkey_from(&SECRET_1);

        let graph = ChannelGraph::new(me);
        graph.add_node(a);
        graph.add_edge(&me, &a)?;

        send_loopback(&graph, &[me, a, me], 100);

        let obs = graph.edge(&me, &a).context("edge should exist")?;
        assert!(
            obs.intermediate_qos().is_none(),
            "single-edge path should not produce intermediate measurement"
        );

        Ok(())
    }

    #[tokio::test]
    async fn loopback_two_edge_path_should_attribute_when_return_edge_exists() -> anyhow::Result<()> {
        // Loopback: me(0) → a(1) → me(0)
        // PathId nodes: [me=0, a=1, me=0, 0, 0]
        // Resolved edges: me→a, a→me (2 edges). Target = me→a (idx 0).
        // me→a already has immediate QoS = 50ms (from my neighbor probing).
        // No known latency on the non-target edge a→me, so attributed = full RTT.
        let me = pubkey_from(&SECRET_0);
        let a = pubkey_from(&SECRET_1);

        let graph = ChannelGraph::new(me);
        graph.add_node(a);
        graph.add_edge(&me, &a)?;
        graph.add_edge(&a, &me)?; // return edge

        // Pre-set immediate QoS on me→a (my direct neighbor measurement)
        graph.upsert_edge(&me, &a, |obs| {
            use hopr_api::graph::traits::EdgeObservableWrite;
            obs.record(hopr_api::graph::traits::EdgeWeightType::Immediate(Ok(
                std::time::Duration::from_millis(50),
            )));
        });

        send_loopback(&graph, &[me, a, me], 100);

        let obs = graph.edge(&me, &a).context("edge me→a should exist")?;
        let qos = obs
            .intermediate_qos()
            .context("intermediate QoS should be present on me→a")?;
        // The whole round trip, because the only *other* edge on the loop has no known latency.
        // The target's own prior estimate is deliberately not subtracted: doing so would measure the
        // error in that estimate rather than the edge, and would drive the residual to zero exactly
        // when the estimate was good.
        assert_in_delta!(
            qos.average_latency().context("latency should be set")?.as_millis(),
            100,
            25
        );

        // Immediate QoS should still be intact
        let imm = obs
            .immediate_qos()
            .context("immediate QoS should still be present on me→a")?;
        assert_eq!(
            imm.average_latency().context("immediate latency should be set")?,
            std::time::Duration::from_millis(50),
        );

        Ok(())
    }

    #[tokio::test]
    async fn loopback_broken_chain_should_be_ignored() -> anyhow::Result<()> {
        // Nodes exist but no edge connects a to c (only b→c exists)
        // me(0) → a(1), b(2) → c(3)
        // PathId nodes: [me=0, a=1, c=3, 0, 0]
        // Edge me→a exists, but edge a→c does NOT → chain breaks, 1 edge < 2
        let me = pubkey_from(&SECRET_0);
        let a = pubkey_from(&SECRET_1);
        let b = pubkey_from(&SECRET_2);
        let c = pubkey_from(&SECRET_3);

        let graph = ChannelGraph::new(me);
        graph.add_node(a);
        graph.add_node(b);
        graph.add_node(c);
        graph.add_edge(&me, &a)?;
        graph.add_edge(&b, &c)?; // b→c, NOT a→c

        send_loopback(&graph, &[me, a, c, me], 200);

        let obs_me_a = graph.edge(&me, &a).context("edge me→a should exist")?;
        assert!(
            obs_me_a.intermediate_qos().is_none(),
            "broken chain should not attribute any intermediate measurement"
        );

        Ok(())
    }

    #[tokio::test]
    async fn loopback_truncated_to_two_edges_should_not_attribute_to_the_first_edge() -> anyhow::Result<()> {
        // Regression guard for misattribution by truncation.
        //
        // Probed path: me(0) → a(1) → b(2) → c(3) → me(0), i.e. 4 edges, whose penultimate edge
        // is b→c. Edge b→c is absent from the graph, so resolution stops after me→a and a→b.
        //
        // A truncated chain of exactly two edges still satisfies a `len >= 2` check, and
        // `target_idx = len - 2` then points at index 0 — so the residual latency computed for
        // the *whole four-edge* path would be attributed to me→a. That corrupts the score of an
        // edge the probe says nothing about. The sample must be discarded instead.
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
        // b→c deliberately absent, so the chain truncates to exactly two resolvable edges.
        graph.add_edge(&c, &me)?;

        send_loopback(&graph, &[me, a, b, c, me], 400);

        let obs_me_a = graph.edge(&me, &a).context("edge me→a should exist")?;
        assert!(
            obs_me_a.intermediate_qos().is_none(),
            "a truncated loopback must not attribute the whole path's residual to the first edge"
        );

        let obs_a_b = graph.edge(&a, &b).context("edge a→b should exist")?;
        assert!(
            obs_a_b.intermediate_qos().is_none(),
            "a truncated loopback must not attribute to any edge"
        );

        Ok(())
    }

    #[test]
    fn a_removed_nodes_slot_must_become_unclaimable() {
        // The property that makes reuse impossible, asserted directly on the resolver: once a node is
        // gone nothing claims its slot, and resolution fails closed.
        //
        // `remove_node` retains the petgraph node, so indices are not reissued and reuse is
        // unreachable through that path. This asserts the resolver's own guarantee rather than that
        // mechanism, so the two remain independent.
        let me = pubkey_from(&SECRET_0);
        let a = pubkey_from(&SECRET_1);
        let b = pubkey_from(&SECRET_2);
        let c = pubkey_from(&SECRET_3);

        let graph = ChannelGraph::new(me);
        for node in [a, b, c] {
            graph.add_node(node);
        }

        let b_slot = crate::petgraph::path_id::encode(&b);
        let index_of = |key: &hopr_api::OffchainPublicKey| {
            let inner = graph.inner.read();
            inner.indices.get_by_left(key).copied()
        };
        let b_index = index_of(&b).expect("b is in the graph");

        graph.remove_node(&b);

        let inner = graph.inner.read();
        assert_eq!(
            crate::petgraph::path_id::resolve(&inner, b_slot),
            None,
            "the removed node's slot must resolve to nothing"
        );
        // The index b held is still a live petgraph index; the point is that no slot maps onto it.
        assert!(
            inner.indices.get_by_right(&b_index).is_none(),
            "the vacated index must be claimed by no key"
        );
        assert_eq!(
            crate::petgraph::path_id::resolve(&inner, crate::petgraph::path_id::encode(&c)),
            index_of(&c),
            "a surviving node must still resolve"
        );
    }

    #[tokio::test]
    async fn loopback_should_not_attribute_after_a_node_is_removed_mid_flight() -> anyhow::Result<()> {
        // Regression guard for identifier reuse. `remove_node` moves the last node into the vacated
        // index, so with position-derived slots an in-flight probe for `me → a → b → me` resolves on
        // return to `me → a → c → me` once `b` is gone and `c` takes its index. The topology below
        // makes that shifted chain resolve *completely*, so the residual latency would land on the
        // a→c edge — an edge the probe never traversed. Key-derived slots leave the removed node's
        // slot unclaimable, so the sample is dropped instead.
        let me = pubkey_from(&SECRET_0);
        let a = pubkey_from(&SECRET_1);
        let b = pubkey_from(&SECRET_2);
        let c = pubkey_from(&SECRET_3);

        let graph = ChannelGraph::new(me);
        for node in [a, b, c] {
            graph.add_node(node);
        }
        // The traversed path.
        graph.add_edge(&me, &a)?;
        graph.add_edge(&a, &b)?;
        graph.add_edge(&b, &me)?;
        // The chain the shifted indices would resolve to, complete end to end.
        graph.add_edge(&a, &c)?;
        graph.add_edge(&c, &me)?;

        graph.remove_node(&b);
        assert!(
            graph.has_edge(&a, &c) && graph.has_edge(&c, &me),
            "the aliasing chain must be intact for this test to be meaningful"
        );

        send_loopback(&graph, &[me, a, b, me], 200);

        let victim = graph.edge(&a, &c).context("edge a→c should exist")?;
        assert!(
            victim.intermediate_qos().is_none(),
            "the edge that inherits the removed node's index must not absorb the measurement"
        );
        let first = graph.edge(&me, &a).context("edge me→a should exist")?;
        assert!(first.intermediate_qos().is_none(), "nor may any other surviving edge");

        Ok(())
    }

    #[tokio::test]
    async fn loopback_oversized_slot_should_not_alias_a_real_node() -> anyhow::Result<()> {
        // Regression guard for narrowing. Resolving a slot arithmetically into `NodeIndex` would
        // truncate to its `u32` index type, so a slot of `2^32 + n` could alias node `n`. Slots are
        // now matched against the nodes actually present, which no oversized value can satisfy.
        let me = pubkey_from(&SECRET_0);
        let a = pubkey_from(&SECRET_1);

        let graph = ChannelGraph::new(me);
        graph.add_node(a);
        graph.add_edge(&me, &a)?;
        graph.add_edge(&a, &me)?;

        let me_slot = crate::petgraph::path_id::encode(&me);
        let a_slot = crate::petgraph::path_id::encode(&a);
        let aliasing = a_slot.wrapping_add(1u64 << 32);

        let telemetry: Result<
            EdgeTransportTelemetry<TestNeighbor, LoopbackTestPath>,
            NetworkGraphError<LoopbackTestPath>,
        > = Ok(EdgeTransportTelemetry::Loopback(LoopbackTestPath::from_slots(
            [me_slot, aliasing, me_slot, 0, 0],
            now_unix_ms() - 100,
        )));
        graph.record_edge(hopr_api::graph::MeasurableEdge::Probe(telemetry));

        let obs = graph.edge(&me, &a).context("edge me→a should exist")?;
        assert!(
            obs.intermediate_qos().is_none(),
            "a slot differing from a real one only above bit 32 must not resolve to that node"
        );

        Ok(())
    }

    #[tokio::test]
    async fn loopback_slots_after_the_closing_node_must_be_padding() -> anyhow::Result<()> {
        // `[me, a, me, b, 0]` closes at slot 2 but keeps going. Taking the first reoccurrence of
        // `me` as the end would attribute a longer path's residual latency to `me → a`.
        let me = pubkey_from(&SECRET_0);
        let a = pubkey_from(&SECRET_1);
        let b = pubkey_from(&SECRET_2);

        let graph = ChannelGraph::new(me);
        graph.add_node(a);
        graph.add_node(b);
        graph.add_edge(&me, &a)?;
        graph.add_edge(&a, &me)?;
        graph.add_edge(&me, &b)?;

        let telemetry: Result<
            EdgeTransportTelemetry<TestNeighbor, LoopbackTestPath>,
            NetworkGraphError<LoopbackTestPath>,
        > = Ok(EdgeTransportTelemetry::Loopback(LoopbackTestPath::from_slots(
            [
                crate::petgraph::path_id::encode(&me),
                crate::petgraph::path_id::encode(&a),
                crate::petgraph::path_id::encode(&me),
                crate::petgraph::path_id::encode(&b),
                0,
            ],
            now_unix_ms() - 100,
        )));
        graph.record_edge(hopr_api::graph::MeasurableEdge::Probe(telemetry));

        let obs = graph.edge(&me, &a).context("edge me→a should exist")?;
        assert!(
            obs.intermediate_qos().is_none(),
            "a payload that does not end at the closing node must be rejected, not truncated"
        );

        Ok(())
    }

    #[tokio::test]
    async fn loopback_wrong_start_node_should_be_ignored() -> anyhow::Result<()> {
        // PathId starts with a node that is not me → early reject
        let me = pubkey_from(&SECRET_0);
        let a = pubkey_from(&SECRET_1);
        let stranger = pubkey_from(&SECRET_3);

        let graph = ChannelGraph::new(me);
        graph.add_node(a);
        graph.add_edge(&me, &a)?;

        send_loopback(&graph, &[stranger, a, me], 200);

        let obs = graph.edge(&me, &a).context("edge should exist")?;
        assert!(
            obs.intermediate_qos().is_none(),
            "wrong start node should not produce any measurement"
        );

        Ok(())
    }

    #[tokio::test]
    async fn loopback_probes_should_accumulate_on_target_edge() -> anyhow::Result<()> {
        // Send multiple loopback probes for the same target edge
        // Loopback: me(0) → a(1) → b(2) → me(0). Target = a→b.
        let me = pubkey_from(&SECRET_0);
        let a = pubkey_from(&SECRET_1);
        let b = pubkey_from(&SECRET_2);

        let graph = ChannelGraph::new(me);
        graph.add_node(a);
        graph.add_node(b);
        graph.add_edge(&me, &a)?;
        graph.add_edge(&a, &b)?;
        graph.add_edge(&b, &me)?; // return edge

        // Send 5 probes all with 100ms RTT.
        // After each probe the target's intermediate QoS is subtracted from subsequent
        // attributions, so the attributed value converges rather than staying at 100ms.
        for _ in 0..5 {
            send_loopback(&graph, &[me, a, b, me], 100);
        }

        let obs = graph.edge(&a, &b).context("edge a→b should exist")?;
        let qos = obs.intermediate_qos().context("intermediate QoS should be present")?;
        assert!(
            qos.average_latency().is_some(),
            "latency should be set after multiple probes"
        );
        assert!(
            qos.average_probe_rate().expect("probed") > 0.9,
            "all probes succeeded, rate should be high"
        );

        Ok(())
    }

    // This is handled by the moving average object, but the expectation test can stay here.
    #[tokio::test]
    async fn loopback_should_not_attribute_when_other_edges_account_for_the_whole_rtt() -> anyhow::Result<()> {
        // If the other edges already account for the whole RTT there is no residual to attribute.
        // Loopback: me(0) → a(1) → b(2) → c(3) → me(0). Target = b→c.
        // Preceding = [me→a, a→b] with me→a = 500ms
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
        graph.add_edge(&c, &me)?; // return edge

        // Pre-set me→a intermediate latency to 500ms
        graph.upsert_edge(&me, &a, |obs| {
            use hopr_api::graph::traits::EdgeObservableWrite;
            obs.record(hopr_api::graph::traits::EdgeWeightType::Intermediate(Ok(
                std::time::Duration::from_millis(500),
            )));
        });

        // Total RTT = 100ms, but preceding latency is 500ms → 100 - 500 saturates to 0
        send_loopback(&graph, &[me, a, b, c, me], 100);

        // Nothing is attributed. A clamp is not a measurement: recording the saturated zero would
        // put this edge in the *fastest* latency band on the strength of knowing nothing about it.
        assert!(
            graph
                .edge(&b, &c)
                .and_then(|obs| obs.intermediate_qos().cloned())
                .is_none(),
            "a round trip already accounted for by the other edges says nothing about the target"
        );

        Ok(())
    }

    #[tokio::test]
    async fn loopback_timeout_should_record_failed_intermediate_on_target_edge() -> anyhow::Result<()> {
        // Loopback: me(0) → a(1) → b(2) → me(0)
        // PathId nodes: [me=0, a=1, b=2, me=0, 0]
        // Resolved edges: me→a, a→b, b→me. Target = edges[1] = a→b
        let me = pubkey_from(&SECRET_0);
        let a = pubkey_from(&SECRET_1);
        let b = pubkey_from(&SECRET_2);

        let graph = ChannelGraph::new(me);
        graph.add_node(a);
        graph.add_node(b);
        graph.add_edge(&me, &a)?;
        graph.add_edge(&a, &b)?;
        graph.add_edge(&b, &me)?; // return edge

        send_loopback_timeout(&graph, &[me, a, b, me]);

        let obs = graph.edge(&a, &b).context("edge a→b should exist")?;
        let qos = obs
            .intermediate_qos()
            .context("intermediate QoS should be present on a→b after timeout")?;
        assert!(qos.average_latency().is_none(), "failed probe should not set latency");
        assert!(
            qos.average_probe_rate().expect("probed") < 1.0,
            "failed probe should lower success rate"
        );

        // me→a should NOT have intermediate QoS
        let obs_me_a = graph.edge(&me, &a).context("edge me→a should exist")?;
        assert!(obs_me_a.intermediate_qos().is_none());

        Ok(())
    }

    #[tokio::test]
    async fn loopback_timeout_four_hop_should_attribute_to_penultimate_edge() -> anyhow::Result<()> {
        // Loopback: me(0) → a(1) → b(2) → c(3) → me(0)
        // Target = last resolved edge = b→c
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
        graph.add_edge(&c, &me)?;

        send_loopback_timeout(&graph, &[me, a, b, c, me]);

        // Edge b→c (target) should have a failed intermediate record
        let obs = graph.edge(&b, &c).context("edge b→c should exist")?;
        let qos = obs
            .intermediate_qos()
            .context("intermediate QoS should be present on b→c")?;
        assert!(qos.average_latency().is_none());
        assert!(qos.average_probe_rate().expect("probed") < 1.0);

        // Earlier edges should NOT have intermediate QoS
        let obs_me_a = graph.edge(&me, &a).context("edge me→a should exist")?;
        assert!(obs_me_a.intermediate_qos().is_none());
        let obs_a_b = graph.edge(&a, &b).context("edge a→b should exist")?;
        assert!(obs_a_b.intermediate_qos().is_none());

        Ok(())
    }

    #[tokio::test]
    async fn loopback_timeout_invalid_path_should_be_ignored() -> anyhow::Result<()> {
        let me = pubkey_from(&SECRET_0);
        let a = pubkey_from(&SECRET_1);

        let graph = ChannelGraph::new(me);
        graph.add_node(a);
        graph.add_edge(&me, &a)?;

        // Wrong-length path
        let telemetry: Result<
            EdgeTransportTelemetry<TestNeighbor, LoopbackTestPath>,
            NetworkGraphError<LoopbackTestPath>,
        > = Err(NetworkGraphError::ProbeLoopbackTimeout(LoopbackTestPath {
            path_bytes: vec![0u8; 8],
            timestamp_ms: 0,
        }));
        graph.record_edge(hopr_api::graph::MeasurableEdge::Probe(telemetry));

        let obs = graph.edge(&me, &a).context("edge should exist")?;
        assert!(obs.intermediate_qos().is_none());

        Ok(())
    }

    #[tokio::test]
    async fn loopback_timeout_single_edge_should_be_ignored() -> anyhow::Result<()> {
        // me(0) → a(1), PathId: [0, 1, 0, 0, 0] → 1 edge < 2
        let me = pubkey_from(&SECRET_0);
        let a = pubkey_from(&SECRET_1);

        let graph = ChannelGraph::new(me);
        graph.add_node(a);
        graph.add_edge(&me, &a)?;

        send_loopback_timeout(&graph, &[me, a, me]);

        let obs = graph.edge(&me, &a).context("edge should exist")?;
        assert!(
            obs.intermediate_qos().is_none(),
            "single-edge timeout should not produce intermediate measurement"
        );

        Ok(())
    }
}
