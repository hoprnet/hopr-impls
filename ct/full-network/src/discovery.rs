use std::collections::HashSet;

use futures::{StreamExt, future::Either, stream::BoxStream};
use hopr_api::{
    ct::{CoverTrafficGeneration, ProbeRouting, ProbingTrafficGeneration},
    graph::{
        NetworkGraphTraverse, NetworkGraphView,
        traits::{EdgeNetworkObservableRead, EdgeObservableRead},
    },
    types::{
        crypto::types::OffchainPublicKey,
        crypto_random::Randomizable,
        internal::{
            NodeId,
            protocol::HoprPseudonym,
            routing::{DestinationRouting, PathId, RoutingOptions},
        },
    },
};
use hopr_network_graph::{FocusRelevance, FocusedLoopback, MAX_LOOPBACK_HOPS, MIN_LOOPBACK_HOPS};
use hopr_utils::statistics::WeightedCollection;
use tokio::sync::watch;

use crate::{
    EgressConfig,
    control::{ControlState, EgressControl},
    priority::immediate_probe_priority,
};

pub struct FullNetworkDiscovery<U> {
    me: OffchainPublicKey,
    cfg: EgressConfig,
    graph: U,
    control: EgressControl,
}

impl<U> FullNetworkDiscovery<U> {
    pub fn new(me: OffchainPublicKey, cfg: EgressConfig, graph: U) -> Self {
        Self {
            me,
            cfg,
            graph,
            control: EgressControl::default(),
        }
    }

    /// Returns a handle that steers the streams built from this prober, including ones already built.
    ///
    /// Defaults: full-pace probing, no focus, cover traffic off.
    pub fn control(&self) -> EgressControl {
        self.control.clone()
    }
}

/// Ticks every `period(state)`, and never while it is `None`.
///
/// A change of the period restarts the wait, so a new level takes effect at once, including waking a
/// stream that was paused. Changes that leave the period alone do not disturb the running wait.
fn paced_ticks(
    rx: watch::Receiver<ControlState>,
    period: impl Fn(&ControlState) -> Option<std::time::Duration> + Copy + Send + 'static,
) -> impl futures::Stream<Item = ()> {
    futures::stream::unfold(rx, move |mut rx| async move {
        loop {
            let current = period(&rx.borrow_and_update());

            let Some(wait) = current else {
                period_changed(&mut rx, period, current).await;
                continue;
            };

            let elapsed = {
                let sleep = std::pin::pin!(futures_time::task::sleep(wait.into()));
                let changed = std::pin::pin!(period_changed(&mut rx, period, current));
                matches!(futures::future::select(sleep, changed).await, Either::Left(_))
            };

            if elapsed {
                return Some(((), rx));
            }
        }
    })
}

/// Resolves once `period` differs from `current`. Pends forever once the control handle is gone.
async fn period_changed(
    rx: &mut watch::Receiver<ControlState>,
    period: impl Fn(&ControlState) -> Option<std::time::Duration>,
    current: Option<std::time::Duration>,
) {
    loop {
        if rx.changed().await.is_err() {
            return futures::future::pending().await;
        }
        if period(&rx.borrow_and_update()) != current {
            return;
        }
    }
}

/// Strip leading and/or trailing `me` markers from a loopback path.
///
/// `simple_loopback_to_self` returns `[intermediates..., me]` — the leading source
/// is already excluded by the graph crate. This helper also strips a leading `me`
/// defensively in case the graph-crate contract changes, so the result is always
/// a plain intermediate list suitable for `IntermediatePath`.
fn strip_loopback_endpoints(mut path: Vec<OffchainPublicKey>, me: &OffchainPublicKey) -> Vec<OffchainPublicKey> {
    if path.last() == Some(me) {
        path.pop();
    }
    if path.first() == Some(me) {
        path.remove(0);
    }
    path
}

/// Build a `DestinationRouting::Forward` with a random pseudonym and an explicit intermediate path.
fn loopback_routing(me: NodeId, path: Vec<OffchainPublicKey>) -> Option<DestinationRouting> {
    let path: Vec<NodeId> = path.into_iter().map(NodeId::from).collect();
    hopr_api::network::BoundedVec::try_from(path)
        .ok()
        .map(|path| DestinationRouting::Forward {
            destination: Box::new(me),
            pseudonym: Some(HoprPseudonym::random()),
            forward_options: RoutingOptions::IntermediatePath(path),
            return_options: None,
        })
}

/// Hop counts cycled through by loopback probing, in **intermediate relay hops** — not edges.
///
/// A loopback of `h` hops traverses `h + 1` edges. Every entry must lie within
/// `MIN_LOOPBACK_HOPS..=MAX_LOOPBACK_HOPS`; outside it, candidates are built and then silently
/// discarded when the routing options are constructed.
const LOOPBACK_HOP_COUNTS: [usize; 2] = [MIN_LOOPBACK_HOPS, MAX_LOOPBACK_HOPS];

/// Stream that cycles through 2- and 3-hop loopback paths with weighted shuffle.
///
/// Shared by both cover traffic and intermediate probing — the caller wraps each
/// emitted item into the appropriate outer type.
///
/// Each tick yields every hop count's `candidates` once, in weighted-shuffle order.
fn loopback_path_stream(
    ticks: impl futures::Stream<Item = ()>,
    candidates: impl Fn(usize) -> Vec<((Vec<OffchainPublicKey>, PathId), f64)>,
) -> impl futures::Stream<Item = (Vec<OffchainPublicKey>, PathId)> {
    ticks
        .flat_map(|_| futures::stream::iter(LOOPBACK_HOP_COUNTS))
        .filter_map(move |hops| futures::future::ready(std::num::NonZeroUsize::new(hops)))
        .flat_map(move |hops| {
            let weighted = candidates(hops.get());

            tracing::debug!(hops = hops.get(), count = weighted.len(), "loopback path candidates");

            let wc = WeightedCollection::new(weighted);
            futures::stream::iter(wc.into_shuffled())
        })
}

/// Loopback candidates with `focus` applied.
///
/// Without a focus this is the plain candidate set at `base` weight. With one, loops around the
/// exits weigh more: forward loops `boost` times, return loops half of that (never below `base`).
/// Focused loops that the default sample also holds are taken out of the default set instead of
/// being listed twice.
fn focused_candidates<U>(
    graph: &U,
    hops: usize,
    focus: Option<&HashSet<OffchainPublicKey>>,
    base: f64,
    boost: f64,
) -> Vec<((Vec<OffchainPublicKey>, PathId), f64)>
where
    U: NetworkGraphTraverse<NodeId = OffchainPublicKey> + FocusedLoopback,
{
    let default = graph.simple_loopback_to_self(hops, Some(100));

    let Some(exits) = focus else {
        return default.into_iter().map(|path| (path, base)).collect();
    };

    let focused: Vec<_> = graph
        .focused_loopback(hops, Some(100), exits)
        .into_iter()
        .map(|(path, path_id, relevance)| {
            let weight = match relevance {
                FocusRelevance::Forward => base * boost,
                FocusRelevance::Return => base * (boost / 2.0).max(1.0),
            };
            ((path, path_id), weight)
        })
        .collect();
    let taken: HashSet<_> = focused.iter().map(|(path, _)| path.clone()).collect();

    let rest = default.into_iter().filter(|path| !taken.contains(path));
    focused.into_iter().chain(rest.map(|path| (path, base))).collect()
}

impl<U> CoverTrafficGeneration for FullNetworkDiscovery<U>
where
    U: NetworkGraphTraverse<NodeId = OffchainPublicKey> + Clone + Send + Sync + 'static,
{
    fn build(&self) -> BoxStream<'static, DestinationRouting> {
        cfg_if::cfg_if! {
            if #[cfg(feature = "noise")] {
                let me = self.me;
                let me_node: NodeId = me.into();
                let (interval, base) = (self.cfg.interval, self.cfg.base_priority);
                let graph = self.graph.clone();

                // Cover traffic follows the noise switch only, never the probing level.
                let ticks = paced_ticks(self.control.subscribe(), move |s| s.noise.then_some(interval));
                let candidates = move |hops| {
                    graph
                        .simple_loopback_to_self(hops, Some(100))
                        .into_iter()
                        .map(|path| (path, base))
                        .collect()
                };

                loopback_path_stream(ticks, candidates)
                    .filter_map(move |(path, _)| {
                        let intermediates = strip_loopback_endpoints(path, &me);
                        futures::future::ready(loopback_routing(me_node, intermediates))
                    })
                    .boxed()
            } else {
                Box::pin(futures::stream::empty())
            }
        }
    }
}

impl<U> ProbingTrafficGeneration for FullNetworkDiscovery<U>
where
    U: NetworkGraphView<NodeId = OffchainPublicKey, Observed = hopr_network_graph::Observations>
        + NetworkGraphTraverse<NodeId = OffchainPublicKey>
        + FocusedLoopback
        + Clone
        + Send
        + Sync
        + 'static,
{
    fn build(&self) -> BoxStream<'static, ProbeRouting> {
        let cfg = self.cfg;
        let me = self.me;
        let rx = self.control.subscribe();
        let level_period = move |s: &ControlState| s.level.map(|level| level.period(cfg.interval));

        let immediates = immediate_probe_stream(
            me,
            cfg,
            self.graph.clone(),
            paced_ticks(rx.clone(), level_period).boxed(),
        );

        let me_node: NodeId = me.into();
        let graph = self.graph.clone();
        let focus_rx = rx.clone();
        let candidates = move |hops| {
            let focus = focus_rx.borrow().focus.clone();
            focused_candidates(&graph, hops, focus.as_deref(), cfg.base_priority, cfg.focus_boost)
        };
        let intermediates =
            loopback_path_stream(paced_ticks(rx, level_period), candidates).filter_map(move |(path, path_id)| {
                let intermediates = strip_loopback_endpoints(path, &me);
                let routing = loopback_routing(me_node, intermediates).map(|r| ProbeRouting::Looping((r, path_id)));
                futures::future::ready(routing)
            });

        futures::stream::select(immediates, intermediates).boxed()
    }
}

/// Cached weighted-shuffle batch with a creation timestamp for TTL checks.
struct ShuffleCache {
    probes: Vec<ProbeRouting>,
    created_at: std::time::Instant,
}

/// Stream of neighbor probes emitted in bursts per tick.
///
/// Each tick emits the entire cached batch. The cache is recomputed when it is
/// empty (all probes drained) or when `cfg.shuffle_ttl` has expired, whichever
/// comes first. This avoids re-traversing the graph every tick while still
/// emitting all peers in each burst.
///
/// When `cfg.probe_connected_only` is `true`, only peers with a
/// `Connected(true)` edge from `me` are included. This assumes that a
/// background discovery mechanism (e.g. libp2p identify/kademlia) has
/// already established connections and recorded them in the graph.
fn immediate_probe_stream<U>(
    me: OffchainPublicKey,
    cfg: EgressConfig,
    graph: U,
    ticker: BoxStream<'static, ()>,
) -> impl futures::Stream<Item = ProbeRouting>
where
    U: NetworkGraphView<NodeId = OffchainPublicKey, Observed = hopr_network_graph::Observations>
        + Clone
        + Send
        + Sync
        + 'static,
{
    let cache: Option<ShuffleCache> = None;

    futures::stream::unfold((cache, ticker), move |(mut cache, mut ticker)| {
        let graph = graph.clone();

        async move {
            use futures::StreamExt as _;
            ticker.next().await?;

            // Reuse cached shuffle if still within TTL.
            let needs_refresh = cache
                .as_ref()
                .is_none_or(|c| c.probes.is_empty() || c.created_at.elapsed() >= cfg.shuffle_ttl);

            if needs_refresh {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default();

                let weighted: Vec<_> = graph
                    .nodes()
                    .filter(|peer| futures::future::ready(peer != &me))
                    .filter_map(|peer| {
                        let obs = graph.edge(&me, &peer);
                        if cfg.probe_connected_only {
                            // Excludes peers observed to be down, not peers never checked:
                            // skipping the latter would stop the probe that resolves them,
                            // leaving them excluded for good.
                            let known_down = obs
                                .as_ref()
                                .and_then(|o| o.immediate_qos())
                                .and_then(|imm| imm.is_connected())
                                == Some(false);
                            if known_down {
                                return futures::future::ready(None);
                            }
                        }
                        let priority = match obs {
                            Some(obs) => immediate_probe_priority(
                                // An unobserved edge scores as poorly as possible, which
                                // RFC-0010 §4.2.1.4 turns into maximum probing urgency.
                                obs.score().unwrap_or(0.0),
                                obs.last_update(),
                                now,
                                &cfg,
                            ),
                            None => immediate_probe_priority(0.0, std::time::Duration::ZERO, now, &cfg),
                        };
                        futures::future::ready(Some((peer, priority)))
                    })
                    .collect()
                    .await;

                let peer_count = weighted.len();
                let zero_hop = RoutingOptions::Hops(0.try_into().expect("0 is a valid u8"));
                let wc = WeightedCollection::new(weighted);
                let probes: Vec<_> = wc
                    .into_shuffled()
                    .into_iter()
                    .map(|peer| {
                        ProbeRouting::Neighbor(DestinationRouting::Forward {
                            destination: Box::new(peer.into()),
                            pseudonym: Some(HoprPseudonym::random()),
                            forward_options: zero_hop.clone(),
                            return_options: Some(zero_hop.clone()),
                        })
                    })
                    .collect();

                tracing::debug!(peer_count, probes = probes.len(), "computed new neighbor probe shuffle");
                cache = Some(ShuffleCache {
                    probes,
                    created_at: std::time::Instant::now(),
                });
            }

            let batch = cache.as_ref().map(|c| c.probes.clone()).unwrap_or_default();
            tracing::debug!(probes = batch.len(), "emitting neighbor probe batch");

            Some((futures::stream::iter(batch), (cache, ticker)))
        }
    })
    .flatten()
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, sync::Arc};

    use futures::{StreamExt, pin_mut};
    use hopr_api::{
        OffchainKeypair,
        ct::{ProbeRouting, ProbingTrafficGeneration},
        graph::{NetworkGraphUpdate, NetworkGraphWrite},
        types::{crypto::keypairs::Keypair, internal::NodeId},
    };
    use hopr_network_graph::ChannelGraph;
    use tokio::time::timeout;

    use super::*;
    use crate::ProbingLevel;

    const TINY_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(20);

    #[test]
    fn requested_loopback_hop_counts_must_all_be_routable() {
        // Regression guard. These values are *hop* counts, but the parameter they feed used to be
        // read as an edge count, so the set requested was {2,3,4} rather than {2,3}. A 4-hop path
        // exceeds what the HOPR packet format can route: candidates were enumerated and then
        // silently dropped when the routing options were built, wasting a third of every probe
        // round. Any value outside the routable range must fail here rather than at runtime.
        assert!(
            !LOOPBACK_HOP_COUNTS.is_empty(),
            "loopback probing requires at least one hop count"
        );

        for hops in LOOPBACK_HOP_COUNTS {
            assert!(
                (MIN_LOOPBACK_HOPS..=MAX_LOOPBACK_HOPS).contains(&hops),
                "{hops} hops is outside the routable range {MIN_LOOPBACK_HOPS}..={MAX_LOOPBACK_HOPS}"
            );
        }
    }

    fn fast_cfg() -> EgressConfig {
        EgressConfig {
            interval: std::time::Duration::from_millis(1),
            shuffle_ttl: std::time::Duration::ZERO,
            probe_connected_only: false,
            ..Default::default()
        }
    }

    fn random_key() -> OffchainPublicKey {
        *OffchainKeypair::random().public()
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    struct Node {
        pub id: OffchainPublicKey,
    }

    impl From<Node> for OffchainPublicKey {
        fn from(node: Node) -> Self {
            node.id
        }
    }

    lazy_static::lazy_static! {
        static ref RANDOM_PEERS: HashSet<Node> = (1..10).map(|_| {
            Node {
                id: OffchainPublicKey::from_privkey(&hopr_api::types::crypto_random::random_bytes::<32>()).unwrap(),
            }
        }).collect::<HashSet<_>>();
    }

    #[tokio::test]
    async fn peers_should_not_be_passed_if_none_are_present() -> anyhow::Result<()> {
        let me = random_key();
        let prober = FullNetworkDiscovery::new(me, Default::default(), Arc::new(ChannelGraph::new(me)));
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);

        assert!(timeout(TINY_TIMEOUT, stream.next()).await.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn peers_should_have_randomized_order() -> anyhow::Result<()> {
        let me = random_key();
        let graph = Arc::new(ChannelGraph::new(me));
        for node in RANDOM_PEERS.iter() {
            graph.record_node(node.clone());
        }

        let peer_count = RANDOM_PEERS.len();
        let prober = FullNetworkDiscovery::new(me, fast_cfg(), graph);
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);

        let extract_peer = |routing: ProbeRouting| -> OffchainPublicKey {
            match routing {
                ProbeRouting::Neighbor(DestinationRouting::Forward { destination, .. }) => {
                    if let NodeId::Offchain(peer_key) = destination.as_ref() {
                        *peer_key
                    } else {
                        panic!("expected offchain destination");
                    }
                }
                _ => panic!("expected Neighbor Forward routing"),
            }
        };

        // Collect two full rounds from the stream.
        let both_rounds: Vec<OffchainPublicKey> = timeout(
            TINY_TIMEOUT * 40,
            stream.take(peer_count * 2).map(extract_peer).collect::<Vec<_>>(),
        )
        .await?;

        let round_1 = &both_rounds[..peer_count];
        let round_2 = &both_rounds[peer_count..];

        // Both rounds should cover the same set of peers.
        let set_1: HashSet<_> = round_1.iter().collect();
        let set_2: HashSet<_> = round_2.iter().collect();
        assert_eq!(set_1, set_2, "both rounds should cover the same peers");

        // The two rounds should (almost certainly) differ in order.
        assert_ne!(round_1, round_2, "two rounds should differ in order (probabilistic)");
        Ok(())
    }

    #[tokio::test]
    async fn peers_should_be_generated_in_multiple_rounds() -> anyhow::Result<()> {
        let me = random_key();
        let graph = Arc::new(ChannelGraph::new(me));
        graph.record_node(RANDOM_PEERS.iter().next().unwrap().clone());

        let prober = FullNetworkDiscovery::new(me, fast_cfg(), graph);
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);

        assert!(timeout(TINY_TIMEOUT, stream.next()).await?.is_some());
        assert!(timeout(TINY_TIMEOUT, stream.next()).await?.is_some());
        Ok(())
    }

    #[cfg(not(feature = "noise"))]
    #[tokio::test]
    async fn cover_traffic_should_produce_empty_stream() -> anyhow::Result<()> {
        let me = random_key();
        let prober = FullNetworkDiscovery::new(me, fast_cfg(), Arc::new(ChannelGraph::new(me)));
        let stream = CoverTrafficGeneration::build(&prober);
        pin_mut!(stream);

        assert!(timeout(TINY_TIMEOUT, stream.next()).await?.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn only_neighbor_probes_emitted_when_no_looping_paths_exist() -> anyhow::Result<()> {
        let me = random_key();
        let graph = Arc::new(ChannelGraph::new(me));

        let a = random_key();
        let b = random_key();
        graph.record_node(a);
        graph.record_node(b);
        graph.add_edge(&me, &a)?;
        graph.add_edge(&a, &b)?;

        let prober = FullNetworkDiscovery::new(me, fast_cfg(), graph);
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);

        let items: Vec<ProbeRouting> = timeout(TINY_TIMEOUT * 50, stream.take(10).collect::<Vec<_>>()).await?;

        assert!(!items.is_empty(), "should produce neighbor probes");
        assert!(
            items.iter().all(|r| matches!(r, ProbeRouting::Neighbor(_))),
            "all probes should be Neighbor when no looping paths exist"
        );
        Ok(())
    }

    #[tokio::test]
    async fn neighbor_probes_should_cover_all_known_nodes_across_rounds() -> anyhow::Result<()> {
        let me = random_key();
        let graph = Arc::new(ChannelGraph::new(me));

        let peer_a = random_key();
        let peer_b = random_key();
        graph.record_node(peer_a);
        graph.record_node(peer_b);

        let prober = FullNetworkDiscovery::new(me, fast_cfg(), graph);
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);

        let destinations: Vec<NodeId> = timeout(
            TINY_TIMEOUT * 50,
            neighbor_destinations(stream).take(4).collect::<Vec<_>>(),
        )
        .await?;

        let unique: HashSet<NodeId> = destinations.iter().cloned().collect();
        let expected: HashSet<NodeId> = [peer_a, peer_b].into_iter().map(NodeId::from).collect();

        assert_eq!(unique, expected, "probes should cover all known graph peers");
        assert_eq!(destinations.len(), 4, "should have probes across multiple rounds");
        Ok(())
    }

    #[tokio::test]
    async fn single_tick_should_emit_all_peers_in_burst() -> anyhow::Result<()> {
        let me = random_key();
        let graph = Arc::new(ChannelGraph::new(me));

        let peer_count = RANDOM_PEERS.len();
        for node in RANDOM_PEERS.iter() {
            graph.record_node(node.clone());
        }

        let prober = FullNetworkDiscovery::new(me, fast_cfg(), graph);
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);

        // Collect exactly peer_count items — should all arrive from a single tick burst.
        let burst: Vec<ProbeRouting> = timeout(TINY_TIMEOUT * 20, stream.take(peer_count).collect::<Vec<_>>()).await?;

        assert_eq!(
            burst.len(),
            peer_count,
            "a single tick should emit all {peer_count} peers"
        );
        assert!(
            burst.iter().all(|r| matches!(r, ProbeRouting::Neighbor(_))),
            "all burst items should be Neighbor probes"
        );

        Ok(())
    }

    /// Extract `NodeId` destinations from a `ProbeRouting::Neighbor` stream.
    fn neighbor_destinations(stream: impl futures::Stream<Item = ProbeRouting>) -> impl futures::Stream<Item = NodeId> {
        stream.filter_map(|r| {
            futures::future::ready(match r {
                ProbeRouting::Neighbor(DestinationRouting::Forward { destination, .. }) => Some(*destination),
                _ => None,
            })
        })
    }

    /// Helper: mark an edge as fully connected with capacity, so it passes all cost checks.
    fn mark_edge_ready(graph: &ChannelGraph, src: &OffchainPublicKey, dst: &OffchainPublicKey) {
        use hopr_api::graph::traits::{EdgeObservableWrite, EdgeWeightType};
        graph.upsert_edge(src, dst, |obs| {
            obs.record(EdgeWeightType::Connected(true));
            obs.record(EdgeWeightType::Immediate(Ok(std::time::Duration::from_millis(50))));
            obs.record(EdgeWeightType::Balance(Some(hopr_api::graph::traits::Balance::from(
                1000u64,
            ))));
        });
    }

    #[tokio::test]
    async fn loopback_probes_should_be_emitted_for_two_edge_path() -> anyhow::Result<()> {
        // Topology: me → a → b, b → me (connected neighbor)
        // Loopback: me → a → b → me
        let me = random_key();
        let a = random_key();
        let b = random_key();
        let graph = Arc::new(ChannelGraph::new(me));
        graph.add_node(a);
        graph.add_node(b);

        // Forward edges
        graph.add_edge(&me, &a)?;
        graph.add_edge(&a, &b)?;
        mark_edge_ready(&graph, &me, &a);
        mark_edge_ready(&graph, &a, &b);

        // Return edge: b is a connected neighbor of me
        graph.add_edge(&b, &me)?;
        mark_edge_ready(&graph, &b, &me);

        // Also need me → b edge so simple_loopback_to_self finds b as a connected neighbor
        graph.add_edge(&me, &b)?;
        mark_edge_ready(&graph, &me, &b);

        let prober = FullNetworkDiscovery::new(me, fast_cfg(), graph);
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);

        // Collect enough items to get both neighbor and loopback probes
        let items: Vec<ProbeRouting> = timeout(TINY_TIMEOUT * 100, stream.take(20).collect::<Vec<_>>()).await?;

        let looping_count = items.iter().filter(|r| matches!(r, ProbeRouting::Looping(_))).count();
        let neighbor_count = items.iter().filter(|r| matches!(r, ProbeRouting::Neighbor(_))).count();

        assert!(neighbor_count > 0, "should have neighbor probes");
        assert!(
            looping_count > 0,
            "should have loopback probes (was {looping_count} out of {} total)",
            items.len()
        );

        // Verify loopback routing has IntermediatePath
        for item in &items {
            if let ProbeRouting::Looping((
                DestinationRouting::Forward {
                    destination,
                    forward_options,
                    ..
                },
                _,
            )) = item
            {
                assert_eq!(
                    destination.as_ref(),
                    &NodeId::Offchain(me),
                    "loopback destination should be me"
                );
                assert!(
                    matches!(forward_options, RoutingOptions::IntermediatePath(_)),
                    "loopback should use IntermediatePath routing"
                );
            }
        }

        Ok(())
    }

    /// `me → a → {b, c} → me`: two 2-relay loops that differ only in their last relay.
    fn two_loops() -> anyhow::Result<(
        OffchainPublicKey,
        OffchainPublicKey,
        OffchainPublicKey,
        Arc<ChannelGraph>,
    )> {
        let (me, a, b, c) = (random_key(), random_key(), random_key(), random_key());
        let graph = Arc::new(ChannelGraph::new(me));
        for node in [a, b, c] {
            graph.add_node(node);
        }
        for (src, dst) in [(me, a), (a, b), (a, c), (b, me), (c, me)] {
            graph.add_edge(&src, &dst)?;
            mark_edge_ready(&graph, &src, &dst);
        }
        Ok((me, b, c, graph))
    }

    /// First relay of a two-relay loopback probe.
    fn two_relay_loop_head(routing: &ProbeRouting) -> Option<OffchainPublicKey> {
        match routing {
            ProbeRouting::Looping((
                DestinationRouting::Forward {
                    forward_options: RoutingOptions::IntermediatePath(path),
                    ..
                },
                _,
            )) => match path.as_ref() {
                [NodeId::Offchain(head), _] => Some(*head),
                _ => None,
            },
            _ => None,
        }
    }

    /// Exit `f` with a forward loop (`a`), a return loop (`f` itself) and an unrelated loop (`c`).
    ///
    /// Each two-relay loop is named by its first relay: `me→a→x→me` (forward, as `a→f`), `me→f→y→me`
    /// (return) and `me→c→z→me`. Returns `(me, f, a, c, graph)`.
    #[allow(clippy::type_complexity)]
    fn focus_network() -> anyhow::Result<(
        OffchainPublicKey,
        OffchainPublicKey,
        OffchainPublicKey,
        OffchainPublicKey,
        Arc<ChannelGraph>,
    )> {
        let (me, a, x, f, y, c, z) = (
            random_key(),
            random_key(),
            random_key(),
            random_key(),
            random_key(),
            random_key(),
            random_key(),
        );
        let graph = Arc::new(ChannelGraph::new(me));
        for node in [a, x, f, y, c, z] {
            graph.add_node(node);
        }
        for (src, dst) in [
            (me, a),
            (a, x),
            (x, me),
            (a, f),
            (me, f),
            (f, y),
            (y, me),
            (me, c),
            (c, z),
            (z, me),
        ] {
            graph.add_edge(&src, &dst)?;
            mark_edge_ready(&graph, &src, &dst);
        }
        Ok((me, f, a, c, graph))
    }

    /// Number of items `stream` yields within `window`.
    async fn emitted_within(stream: impl futures::Stream<Item = ProbeRouting>, window: std::time::Duration) -> usize {
        pin_mut!(stream);
        let deadline = tokio::time::Instant::now() + window;
        let mut count = 0;
        while let Ok(Some(_)) = tokio::time::timeout_at(deadline, stream.next()).await {
            count += 1;
        }
        count
    }

    /// First relay of the loop that leads each round of three two-relay loops, over `rounds` rounds.
    async fn round_leaders(
        stream: &mut (impl futures::Stream<Item = ProbeRouting> + Unpin),
        rounds: usize,
    ) -> anyhow::Result<Vec<OffchainPublicKey>> {
        let loops: Vec<OffchainPublicKey> = timeout(
            TINY_TIMEOUT * 150,
            stream
                .filter_map(|r| futures::future::ready(two_relay_loop_head(&r)))
                .take(rounds * 3)
                .collect::<Vec<_>>(),
        )
        .await?;
        Ok(loops.into_iter().step_by(3).collect())
    }

    fn share(leaders: &[OffchainPublicKey], head: &OffchainPublicKey) -> f64 {
        leaders.iter().filter(|key| *key == head).count() as f64 / leaders.len() as f64
    }

    #[tokio::test]
    async fn probing_should_stay_pending_when_level_is_off_and_resume_when_raised() -> anyhow::Result<()> {
        let (me, _, _, graph) = two_loops()?;
        let prober = FullNetworkDiscovery::new(me, fast_cfg(), graph);
        let control = prober.control();
        control.set_level(None);
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);

        assert!(
            timeout(TINY_TIMEOUT * 5, stream.next()).await.is_err(),
            "no probe may be emitted while off"
        );

        control.set_level(Some(ProbingLevel::High));

        assert!(
            timeout(TINY_TIMEOUT * 50, stream.next()).await?.is_some(),
            "the running stream must resume without being rebuilt"
        );
        Ok(())
    }

    #[tokio::test]
    async fn probing_should_stop_when_level_is_lowered_to_off_on_a_running_stream() -> anyhow::Result<()> {
        let (me, _, _, graph) = two_loops()?;
        let prober = FullNetworkDiscovery::new(me, fast_cfg(), graph);
        let control = prober.control();
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);
        assert!(timeout(TINY_TIMEOUT * 50, stream.next()).await?.is_some());

        control.set_level(None);
        // Drain what the round in flight already produced.
        while timeout(TINY_TIMEOUT, stream.next()).await.is_ok() {}

        assert!(timeout(TINY_TIMEOUT * 5, stream.next()).await.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn low_level_should_emit_far_fewer_probes_than_high() -> anyhow::Result<()> {
        let window = std::time::Duration::from_millis(300);
        let mut counts = Vec::new();

        for level in [ProbingLevel::High, ProbingLevel::Low].map(Some) {
            let me = random_key();
            let graph = Arc::new(ChannelGraph::new(me));
            graph.record_node(random_key());
            let prober = FullNetworkDiscovery::new(me, fast_cfg(), graph);
            prober.control().set_level(level);
            counts.push(emitted_within(ProbingTrafficGeneration::build(&prober), window).await);
        }

        let (high, low) = (counts[0], counts[1]);
        assert!(low > 0, "low must still probe");
        assert!(low * 3 < high, "low ({low}) should be far below high ({high})");
        Ok(())
    }

    #[cfg(feature = "noise")]
    #[tokio::test]
    async fn cover_traffic_should_stay_pending_until_noise_is_switched_on() -> anyhow::Result<()> {
        let (me, _, _, graph) = two_loops()?;
        let prober = FullNetworkDiscovery::new(me, fast_cfg(), graph);
        let stream = CoverTrafficGeneration::build(&prober);
        pin_mut!(stream);

        assert!(
            timeout(TINY_TIMEOUT * 5, stream.next()).await.is_err(),
            "noise is off by default"
        );

        prober.control().set_noise(true);

        assert!(timeout(TINY_TIMEOUT * 50, stream.next()).await?.is_some());
        Ok(())
    }

    #[cfg(feature = "noise")]
    #[tokio::test]
    async fn cover_traffic_should_ignore_the_probing_level() -> anyhow::Result<()> {
        let (me, _, _, graph) = two_loops()?;
        let prober = FullNetworkDiscovery::new(me, fast_cfg(), graph);
        let control = prober.control();
        control.set_noise(true);
        control.set_level(None);
        let stream = CoverTrafficGeneration::build(&prober);
        pin_mut!(stream);

        assert!(timeout(TINY_TIMEOUT * 50, stream.next()).await?.is_some());
        Ok(())
    }

    #[tokio::test]
    async fn probing_should_not_depend_on_the_noise_switch() -> anyhow::Result<()> {
        let (me, _, _, graph) = two_loops()?;
        let prober = FullNetworkDiscovery::new(me, fast_cfg(), graph);
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);

        assert!(!prober.control().noise());
        assert!(timeout(TINY_TIMEOUT * 50, stream.next()).await?.is_some());
        Ok(())
    }

    #[tokio::test]
    async fn unfocused_probing_should_not_favour_any_loop() -> anyhow::Result<()> {
        let (me, _, _, c, graph) = focus_network()?;
        let prober = FullNetworkDiscovery::new(me, fast_cfg(), graph);
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);

        let leaders = round_leaders(&mut stream, 200).await?;

        // Three equal loops: each leads about a third of the rounds.
        let unrelated = share(&leaders, &c);
        assert!(
            (0.2..0.5).contains(&unrelated),
            "the unrelated loop led {unrelated} of rounds"
        );
        Ok(())
    }

    #[tokio::test]
    async fn focus_should_lead_rounds_with_forward_loops_then_return_loops_then_the_rest() -> anyhow::Result<()> {
        let (me, f, a, c, graph) = focus_network()?;
        let prober = FullNetworkDiscovery::new(me, fast_cfg(), graph);
        prober.control().set_focus([f]);
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);

        let leaders = round_leaders(&mut stream, 300).await?;
        let (forward, returning, unrelated) = (share(&leaders, &a), share(&leaders, &f), share(&leaders, &c));

        // Weights 3.0 (forward, boost 10), 1.5 (return, half of it) and 0.3: about 62%, 31% and 6% of rounds.
        assert!(
            forward > returning,
            "forward {forward} must lead more often than return {returning}"
        );
        assert!(
            returning > unrelated,
            "return {returning} must lead more often than the rest {unrelated}"
        );
        assert!(unrelated > 0.0, "the rest of the network must still be probed");
        assert!(unrelated < 0.2, "the unrelated loop led {unrelated} of rounds");
        Ok(())
    }

    #[tokio::test]
    async fn focus_set_on_a_running_stream_should_take_effect_and_clear_again() -> anyhow::Result<()> {
        let (me, f, _, c, graph) = focus_network()?;
        let prober = FullNetworkDiscovery::new(me, fast_cfg(), graph);
        let control = prober.control();
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);

        control.set_focus([f]);
        // Skip rounds computed before the update was seen.
        round_leaders(&mut stream, 5).await?;
        let focused = round_leaders(&mut stream, 200).await?;
        assert!(share(&focused, &c) < 0.2, "focus must demote the unrelated loop");

        control.clear_focus();
        round_leaders(&mut stream, 5).await?;
        let cleared = round_leaders(&mut stream, 200).await?;
        assert!(
            share(&cleared, &c) > 0.2,
            "clearing the focus must restore even treatment"
        );
        Ok(())
    }

    #[tokio::test]
    async fn focus_on_an_unknown_exit_should_leave_default_probing_intact() -> anyhow::Result<()> {
        let (me, _, _, c, graph) = focus_network()?;
        let prober = FullNetworkDiscovery::new(me, fast_cfg(), graph);
        prober.control().set_focus([random_key()]);
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);

        let leaders = round_leaders(&mut stream, 200).await?;

        assert_eq!(leaders.len(), 200, "default loops must keep flowing");
        assert!(
            share(&leaders, &c) > 0.2,
            "an unknown exit must not skew the default sample"
        );
        Ok(())
    }

    #[tokio::test]
    async fn probe_connected_only_should_skip_peers_observed_down() -> anyhow::Result<()> {
        // `probe_connected_only` excludes peers *observed* to be down. A peer whose connectivity
        // was never observed must still be probed: skipping it would suppress the very probe that
        // would establish whether it is reachable.
        let me = random_key();
        let graph = Arc::new(ChannelGraph::new(me));

        let connected_peer = random_key();
        let unconnected_peer = random_key();
        graph.record_node(connected_peer);
        graph.record_node(unconnected_peer);

        mark_edge_ready(&graph, &me, &connected_peer);
        graph.upsert_edge(&me, &unconnected_peer, |obs| {
            use hopr_api::graph::traits::{EdgeObservableWrite, EdgeWeightType};
            obs.record(EdgeWeightType::Connected(false));
        });

        let cfg = EgressConfig {
            probe_connected_only: true,
            ..fast_cfg()
        };
        let prober = FullNetworkDiscovery::new(me, cfg, graph);
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);

        let destinations: Vec<NodeId> = timeout(
            TINY_TIMEOUT * 50,
            neighbor_destinations(stream).take(3).collect::<Vec<_>>(),
        )
        .await?;

        let unique: HashSet<NodeId> = destinations.iter().cloned().collect();
        assert_eq!(unique.len(), 1, "only one peer should be probed");
        assert!(
            unique.contains(&NodeId::from(connected_peer)),
            "only the connected peer should be probed"
        );
        Ok(())
    }

    #[tokio::test]
    async fn probe_connected_only_disabled_should_probe_all_peers() -> anyhow::Result<()> {
        let me = random_key();
        let graph = Arc::new(ChannelGraph::new(me));

        let connected_peer = random_key();
        let unconnected_peer = random_key();
        graph.record_node(connected_peer);
        graph.record_node(unconnected_peer);

        mark_edge_ready(&graph, &me, &connected_peer);

        // Default: probe_connected_only = false
        let prober = FullNetworkDiscovery::new(me, fast_cfg(), graph);
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);

        let destinations: Vec<NodeId> = timeout(
            TINY_TIMEOUT * 50,
            neighbor_destinations(stream).take(4).collect::<Vec<_>>(),
        )
        .await?;

        let unique: HashSet<NodeId> = destinations.iter().cloned().collect();
        let expected: HashSet<NodeId> = [connected_peer, unconnected_peer]
            .into_iter()
            .map(NodeId::from)
            .collect();
        assert_eq!(
            unique, expected,
            "both peers should be probed when probe_connected_only is false"
        );
        Ok(())
    }

    #[tokio::test]
    async fn loopback_routing_should_reject_full_path_with_me() -> anyhow::Result<()> {
        // Verify that loopback_routing rejects paths that are too long for BoundedVec.
        // simple_loopback_to_self now returns [a, b, me] (no leading me); after
        // strip_loopback_endpoints this becomes [a, b], which is the correct input.
        let me = random_key();
        let a = random_key();
        let b = random_key();
        let me_node = NodeId::Offchain(me);

        // Path with too many elements: [a, b, c, me] — 4 elements exceeds BoundedVec<3>.
        let c = random_key();
        let oversized_path = vec![a, b, c, me];
        assert!(
            loopback_routing(me_node, oversized_path).is_none(),
            "path [a, b, c, me] should exceed BoundedVec<3> and return None"
        );

        // Stripped path (intermediates only): [a, b]
        let stripped_path = vec![a, b];
        assert!(
            loopback_routing(me_node, stripped_path).is_some(),
            "stripped path [a, b] should fit BoundedVec<3> and return Some"
        );

        Ok(())
    }
}
