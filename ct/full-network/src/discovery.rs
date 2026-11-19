use std::{
    collections::{HashMap, HashSet, VecDeque},
    future::Future,
    pin::Pin,
    sync::Arc,
};

#[cfg(feature = "noise")]
use futures::future::Either;
use futures::{StreamExt, stream::BoxStream};
use hopr_api::{
    ct::{CoverTrafficGeneration, ProbeRouting, ProbingTrafficGeneration},
    graph::{
        NetworkGraphTraverse, NetworkGraphView,
        traits::{EdgeImmediateProtocolObservable, EdgeLinkObservable, EdgeNetworkObservableRead, EdgeObservableRead},
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
use rand::{RngExt, seq::SliceRandom};
#[cfg(feature = "noise")]
use tokio::sync::watch;

#[cfg(feature = "noise")]
use crate::control::ControlState;
use crate::{
    EgressConfig,
    control::{EgressControl, LoopbackCoverage},
};

/// Weights for loopback paths, as the path planner would rank them.
///
/// The generator orders its loopback candidates by these weights, so probing watches the paths
/// routing will use and keeps the same spread over relays. The weights come from the hoprnet path
/// planner; this crate never computes them or copies the planner's configuration.
pub trait PathWeightProvider: Send + Sync {
    /// Weight for each loop, in the order given. Higher is better.
    ///
    /// A missing entry, a non-finite value and a value that is not positive all read as the neutral
    /// weight `1.0`, because the generator never trusts a weight to be sane.
    fn weights(&self, paths: &[(Vec<OffchainPublicKey>, PathId)]) -> Vec<f64>;
}

/// Every loop weighted equally. Used until a path planner supplies its own weights.
#[derive(Debug, Clone, Copy, Default)]
pub struct UniformPathWeights;

impl PathWeightProvider for UniformPathWeights {
    fn weights(&self, paths: &[(Vec<OffchainPublicKey>, PathId)]) -> Vec<f64> {
        vec![1.0; paths.len()]
    }
}

pub struct FullNetworkDiscovery<U> {
    me: OffchainPublicKey,
    cfg: EgressConfig,
    graph: U,
    control: EgressControl,
    path_weights: Arc<dyn PathWeightProvider>,
}

impl<U> FullNetworkDiscovery<U> {
    pub fn new(me: OffchainPublicKey, cfg: EgressConfig, graph: U) -> Self {
        Self {
            me,
            cfg,
            graph,
            control: EgressControl::default(),
            path_weights: Arc::new(UniformPathWeights),
        }
    }

    /// Sets where loopback probing reads its path weights, so it follows the distribution routing uses.
    ///
    /// Without a provider every loop weighs the same.
    pub fn with_path_weights(mut self, provider: impl PathWeightProvider + 'static) -> Self {
        self.path_weights = Arc::new(provider);
        self
    }

    /// Returns a handle that steers the streams built from this prober, including ones already built.
    ///
    /// Defaults: full dial, no focus, no budget, cover traffic off.
    pub fn control(&self) -> EgressControl {
        self.control.clone()
    }
}

/// Ticks every `period(state)`, and never while it is `None`.
///
/// A change of the period restarts the wait, so a new period takes effect at once, including waking a
/// stream that was paused. Changes that leave the period alone do not disturb the running wait.
///
/// Cover traffic only. Probing is pull-driven and keeps no timer.
#[cfg(feature = "noise")]
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
#[cfg(feature = "noise")]
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

/// Most loops one hop count contributes to a cycle.
const LOOPBACK_TAKE: usize = 100;

/// Stream that cycles through 2- and 3-hop loopback paths with weighted shuffle.
///
/// Cover traffic only. Probing orders its own loops, see [`plan_loopbacks`].
///
/// Each tick yields every hop count's `candidates` once, in weighted-shuffle order.
#[cfg(feature = "noise")]
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

/// The unfocused loopback sample, every path at `base` weight.
#[cfg(feature = "noise")]
fn default_candidates<U>(graph: &U, hops: usize, base: f64) -> Vec<((Vec<OffchainPublicKey>, PathId), f64)>
where
    U: NetworkGraphTraverse<NodeId = OffchainPublicKey>,
{
    graph
        .simple_loopback_to_self(hops, Some(LOOPBACK_TAKE))
        .into_iter()
        .map(|path| (path, base))
        .collect()
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
                let interval = self.cfg.interval;
                let graph = self.graph.clone();

                // Cover traffic follows the noise switch only, never the probing dial.
                let ticks = paced_ticks(self.control.subscribe(), move |s| s.noise.then_some(interval));
                let candidates = move |hops| default_candidates(&graph, hops, 1.0);

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

/// Generator-owned state for one peer.
#[derive(Debug, Default, Clone, Copy)]
struct PeerProbeState {
    /// Neighbour probes this generator has offered since the peer last went down.
    ///
    /// Owned here because the graph keeps only a lifetime total that never resets.
    offered: u32,
    /// Connectivity as the graph last reported it, `None` when never observed.
    connected: Option<bool>,
}

/// One loop the prober may send over.
#[derive(Debug, Clone)]
struct LoopbackCandidate {
    path: Vec<OffchainPublicKey>,
    path_id: PathId,
    /// Rank the focus gives the loop: 2 forward, 1 return, 0 elsewhere or unfocused.
    focus_rank: u8,
    /// Weight routing would give the loop, always finite and positive.
    weight: f64,
    /// Whether this loop is part of the exploration share rather than the best set.
    explores: bool,
}

impl LoopbackCandidate {
    /// The directed edges this loop traverses, from and back to `me`.
    fn edges(&self, me: OffchainPublicKey) -> Vec<(OffchainPublicKey, OffchainPublicKey)> {
        let intermediates = strip_loopback_endpoints(self.path.clone(), &me);
        let mut previous = me;
        let mut edges = Vec::with_capacity(intermediates.len() + 1);
        for next in intermediates.into_iter().chain(std::iter::once(me)) {
            edges.push((previous, next));
            previous = next;
        }
        edges
    }
}

/// Neighbour probing state.
#[derive(Debug, Default)]
struct NeighbourState {
    /// Peers in the order they will be offered, rebuilt when drained.
    queue: VecDeque<OffchainPublicKey>,
    peers: HashMap<OffchainPublicKey, PeerProbeState>,
}

/// Loopback probing state: the persistent cursor over the loop set of one cycle.
#[derive(Debug, Default)]
struct LoopbackState {
    /// The current cycle, in offering order.
    plan: Vec<LoopbackCandidate>,
    /// Position in `plan`.
    cursor: usize,
    /// Edges of the last snapshot that carried fresh SURB evidence, published at the window close.
    snapshot_evidence: usize,
    /// Loopback probes drawn since the last published window.
    drawn: usize,
}

/// A probe-priority above every measured rate deficit, so a peer that still needs samples leads.
const NEEDS_SAMPLES_ORDER: f64 = 2.0;

/// Priority of a settled peer that the random re-add picked. Below every rate deficit.
const READD_ORDER: f64 = 0.0;

/// Commands the next probe from its own state, without reading a clock.
struct ProbeGenerator<U> {
    me: OffchainPublicKey,
    cfg: EgressConfig,
    graph: U,
    path_weights: Arc<dyn PathWeightProvider>,
    control: EgressControl,
    neighbours: NeighbourState,
    loopback: LoopbackState,
    /// Which selector takes the next pull.
    neighbour_turn: bool,
}

impl<U> ProbeGenerator<U>
where
    U: NetworkGraphView<NodeId = OffchainPublicKey, Observed = hopr_network_graph::Observations>
        + NetworkGraphTraverse<NodeId = OffchainPublicKey>
        + FocusedLoopback
        + Clone
        + Send
        + Sync
        + 'static,
{
    /// The next probe. `None` when the graph offers nothing to probe right now.
    async fn next_probe(&mut self) -> Option<ProbeRouting> {
        let neighbour_turn = self.neighbour_turn;
        let probe = if neighbour_turn {
            match self.next_neighbour().await {
                Some(probe) => Some(probe),
                None => self.next_loopback(),
            }
        } else {
            match self.next_loopback() {
                Some(probe) => Some(probe),
                None => self.next_neighbour().await,
            }
        };

        if probe.is_some() {
            self.neighbour_turn = !neighbour_turn;
        }
        probe
    }

    /// Offers a peer that still needs a probe, `None` when every known peer is settled.
    async fn next_neighbour(&mut self) -> Option<ProbeRouting> {
        if self.neighbours.queue.is_empty() {
            self.refresh_neighbours().await;
        }
        let peer = self.neighbours.queue.pop_front()?;
        if let Some(state) = self.neighbours.peers.get_mut(&peer) {
            state.offered = state.offered.saturating_add(1);
        }

        let zero_hop = RoutingOptions::Hops(0.try_into().expect("0 is a valid u8"));
        Some(ProbeRouting::Neighbor(DestinationRouting::Forward {
            destination: Box::new(peer.into()),
            pseudonym: Some(HoprPseudonym::random()),
            forward_options: zero_hop.clone(),
            return_options: Some(zero_hop),
        }))
    }

    /// Rebuilds the neighbour order from the graph and the generator's own per-peer state.
    async fn refresh_neighbours(&mut self) {
        let peers: Vec<OffchainPublicKey> = self
            .graph
            .nodes()
            .filter(|peer| futures::future::ready(peer != &self.me))
            .collect()
            .await;

        let mut rng = rand::rng();
        let mut candidates: Vec<(OffchainPublicKey, f64)> = Vec::with_capacity(peers.len());

        for peer in peers {
            let observations = self.graph.edge(&self.me, &peer);
            let connected = observations
                .as_ref()
                .and_then(|observations| observations.immediate_qos())
                .and_then(|immediate| immediate.is_connected());

            let entry = self.neighbours.peers.entry(peer).or_default();
            if connected == Some(false) {
                // A disconnect forces a full reprobe: the link may have changed while it was down.
                entry.offered = 0;
            }
            entry.connected = connected;
            let state = *entry;

            if self.cfg.probe_connected_only && connected == Some(false) {
                // Excludes only peers observed to be down. Excluding peers never checked would stop
                // the probe that resolves them.
                continue;
            }

            if let Some(priority) = neighbour_order(&self.cfg, &state, observations.as_ref(), &mut rng) {
                candidates.push((peer, priority));
            }
        }

        let peer_count = candidates.len();
        // Shuffle first, then sort by priority with a stable sort: peers that need the same amount
        // of probing take turns, and a deeper deficit always leads.
        candidates.shuffle(&mut rng);
        candidates.sort_by(|(_, a), (_, b)| b.total_cmp(a));
        self.neighbours.queue = candidates.into_iter().map(|(peer, _)| peer).collect();

        tracing::debug!(peer_count, "refreshed the neighbour probe order");
    }

    /// Offers the next loop of the current cycle, `None` when the graph holds no loop.
    fn next_loopback(&mut self) -> Option<ProbeRouting> {
        if self.loopback.cursor >= self.loopback.plan.len() {
            self.start_loopback_cycle();
        }
        let candidate = self.loopback.plan.get(self.loopback.cursor)?.clone();
        self.loopback.cursor += 1;
        self.loopback.drawn += 1;
        self.close_loopback_window_if_due();

        let intermediates = strip_loopback_endpoints(candidate.path, &self.me);
        let routing = loopback_routing(self.me.into(), intermediates)?;
        Some(ProbeRouting::Looping((routing, candidate.path_id)))
    }

    /// Starts a cycle: a fresh graph snapshot, the evidence filter, the best/explore split and a
    /// random start position.
    fn start_loopback_cycle(&mut self) {
        let focus = self.control.focus();
        let snapshot = self.snapshot_loops(focus.as_deref());
        let evidence = self.count_evidenced_edges(&snapshot);
        self.loopback.snapshot_evidence = evidence;

        // Drop the loops an edge with fresh SURB evidence already measures: the budget is better
        // spent where nothing is known.
        let live: Vec<LoopbackCandidate> = snapshot
            .into_iter()
            .filter(|candidate| !self.has_fresh_evidence(candidate))
            .collect();

        let best_len = self.best_set_len(live.len());
        let mut rng = rand::rng();
        let mut plan = plan_loopbacks(live, best_len, &mut rng);

        // Each cycle starts at a random position over its loop set.
        if !plan.is_empty() {
            let start = rng.random_range(0..plan.len());
            plan.rotate_left(start);
        }

        tracing::debug!(
            loops = plan.len(),
            explores = plan.iter().filter(|candidate| candidate.explores).count(),
            evidenced_edges = evidence,
            "started a loopback cycle"
        );

        self.loopback.plan = plan;
        self.loopback.cursor = 0;
    }

    /// How many loops of a snapshot form the best set.
    fn best_set_len(&self, candidates: usize) -> usize {
        let share = self.cfg.best_path_share;
        let share = if share.is_finite() { share.clamp(0.0, 1.0) } else { 0.0 };
        ((share * candidates as f64).round() as usize)
            .min(self.cfg.best_set_size)
            .min(candidates)
    }

    /// Every loop the graph offers, with the focus rank and the routing weight of each.
    fn snapshot_loops(&self, focus: Option<&HashSet<OffchainPublicKey>>) -> Vec<LoopbackCandidate> {
        let mut loops: Vec<(Vec<OffchainPublicKey>, PathId, u8)> = Vec::new();
        let mut focused: HashSet<Vec<OffchainPublicKey>> = HashSet::new();

        if let Some(exits) = focus {
            for hops in LOOPBACK_HOP_COUNTS {
                for (path, path_id, relevance) in self.graph.focused_loopback(hops, Some(LOOPBACK_TAKE), exits) {
                    focused.insert(path.clone());
                    loops.push((path, path_id, focus_rank(relevance)));
                }
            }
        }

        for hops in LOOPBACK_HOP_COUNTS {
            for (path, path_id) in self.graph.simple_loopback_to_self(hops, Some(LOOPBACK_TAKE)) {
                if !focused.contains(&path) {
                    loops.push((path, path_id, 0));
                }
            }
        }

        let paths: Vec<(Vec<OffchainPublicKey>, PathId)> = loops
            .iter()
            .map(|(path, path_id, _)| (path.clone(), *path_id))
            .collect();
        let weights = self.path_weights.weights(&paths);

        loops
            .into_iter()
            .enumerate()
            .map(|(index, (path, path_id, focus_rank))| LoopbackCandidate {
                path,
                path_id,
                focus_rank,
                weight: weights
                    .get(index)
                    .copied()
                    .filter(|weight| weight.is_finite() && *weight > 0.0)
                    .unwrap_or(1.0),
                explores: false,
            })
            .collect()
    }

    /// Whether any edge of the loop already carries fresh SURB evidence.
    fn has_fresh_evidence(&self, candidate: &LoopbackCandidate) -> bool {
        candidate
            .edges(self.me)
            .into_iter()
            .any(|(from, to)| edge_has_fresh_evidence(&self.graph, &from, &to))
    }

    /// Distinct edges of `candidates` that carry fresh SURB evidence.
    fn count_evidenced_edges(&self, candidates: &[LoopbackCandidate]) -> usize {
        let mut evidenced = HashSet::new();
        for candidate in candidates {
            for (from, to) in candidate.edges(self.me) {
                if edge_has_fresh_evidence(&self.graph, &from, &to) {
                    evidenced.insert((from, to));
                }
            }
        }
        evidenced.len()
    }

    /// Publishes the coverage metric when the window ends: at the caller's budget, or at a cycle wrap.
    fn close_loopback_window_if_due(&mut self) {
        let window = self
            .control
            .budget()
            .filter(|budget| *budget > 0)
            .unwrap_or(self.loopback.plan.len())
            .max(1);

        if self.loopback.drawn >= window || self.loopback.cursor >= self.loopback.plan.len() {
            self.control.publish_coverage(LoopbackCoverage {
                edges_with_evidence: self.loopback.snapshot_evidence,
                window_draws: self.loopback.drawn,
            });
            self.loopback.drawn = 0;
        }
    }
}

/// How soon a peer needs a neighbour probe, or `None` when it needs none while it stays connected.
fn neighbour_order(
    cfg: &EgressConfig,
    state: &PeerProbeState,
    observations: Option<&hopr_network_graph::Observations>,
    rng: &mut impl RngExt,
) -> Option<f64> {
    let (probe_rate, ack_rate) = observations
        .map(|observations| {
            let immediate = observations.immediate_qos();
            (
                immediate.and_then(|immediate| immediate.average_probe_rate()),
                immediate.and_then(|immediate| immediate.ack_rate()),
            )
        })
        .unwrap_or((None, None));

    let stable_samples = cfg.stable_samples.clamp(1, u32::MAX as usize) as u32;
    if state.offered < stable_samples {
        // Still filling the averaging window. The fewer samples, the sooner.
        return Some(NEEDS_SAMPLES_ORDER + (stable_samples - state.offered) as f64);
    }

    // A measured rate below its threshold reopens the probe. The deeper the drop, the sooner.
    let deficit = [
        probe_rate.map(|rate| cfg.success_rate_threshold - rate),
        ack_rate.map(|rate| cfg.ack_rate_threshold - rate),
    ]
    .into_iter()
    .flatten()
    .map(|deficit| if deficit.is_nan() { 0.0 } else { deficit })
    .fold(0.0_f64, f64::max);

    if deficit > 0.0 {
        return Some(deficit);
    }

    // Settled while connected. A rare random re-add keeps an old answer from lasting forever.
    let readd = cfg.readd_probability;
    (readd.is_finite() && readd > 0.0 && rng.random_bool(readd.min(1.0))).then_some(READD_ORDER)
}

/// Whether the graph holds SURB evidence that the edge was traversed recently.
///
/// `surb_delivery_rate` is `None` once the edge leaves the evidence window, which is the signal
/// probing needs: an edge without evidence is worth a loopback.
fn edge_has_fresh_evidence<U>(graph: &U, from: &OffchainPublicKey, to: &OffchainPublicKey) -> bool
where
    U: NetworkGraphView<NodeId = OffchainPublicKey, Observed = hopr_network_graph::Observations>,
{
    graph
        .edge(from, to)
        .and_then(|observations| {
            observations
                .intermediate_qos()
                .and_then(|intermediate| intermediate.surb_delivery_rate())
        })
        .is_some()
}

const fn focus_rank(relevance: FocusRelevance) -> u8 {
    match relevance {
        FocusRelevance::Forward => 2,
        FocusRelevance::Return => 1,
    }
}

/// Orders one cycle of loopback candidates.
///
/// The best set is the first `best_len` candidates after ranking by focus and routing weight: the
/// loops routing is most likely to use. The rest explore. The two sets interleave evenly, so the
/// exploration share holds in every window instead of only in the tail of a cycle. Every candidate
/// appears exactly once, so a cycle visits each loop before repeating.
fn plan_loopbacks(
    mut candidates: Vec<LoopbackCandidate>,
    best_len: usize,
    rng: &mut impl RngExt,
) -> Vec<LoopbackCandidate> {
    // Shuffle first so equal ranks and equal weights keep a random order.
    candidates.shuffle(rng);
    candidates.sort_by(|a, b| {
        b.focus_rank
            .cmp(&a.focus_rank)
            .then_with(|| b.weight.total_cmp(&a.weight))
    });

    let best_len = best_len.min(candidates.len());
    let mut explore = candidates.split_off(best_len);

    let best: Vec<LoopbackCandidate> = WeightedCollection::new(
        candidates
            .into_iter()
            .map(|candidate| {
                let weight = candidate.weight;
                (candidate, weight)
            })
            .collect(),
    )
    .into_shuffled();
    explore.shuffle(rng);

    let explore_total = explore.len();
    let total = best.len() + explore_total;
    let mut plan = Vec::with_capacity(total);
    let (mut best, mut explore) = (best.into_iter(), explore.into_iter());
    let mut explore_placed = 0usize;

    for position in 0..total {
        // Bresenham spread: exploration draw `k` lands at position `ceil(k * total / explore_total)`,
        // so every window sees its share instead of only the tail of a cycle.
        let explore_due =
            explore_placed < explore_total && (explore_placed + 1) * total <= (position + 1) * explore_total;
        if explore_due && let Some(candidate) = explore.next() {
            explore_placed += 1;
            plan.push(LoopbackCandidate {
                explores: true,
                ..candidate
            });
            continue;
        }
        match best.next() {
            Some(candidate) => plan.push(candidate),
            None => {
                if let Some(candidate) = explore.next() {
                    plan.push(LoopbackCandidate {
                        explores: true,
                        ..candidate
                    });
                }
            }
        }
    }

    plan
}

/// A pull in flight. It owns the generator while it runs, so the generator can be borrowed mutably.
type PullFuture<U> = Pin<Box<dyn Future<Output = (Box<ProbeGenerator<U>>, Option<ProbeRouting>)> + Send + 'static>>;

/// Resolves on the next change of the control state.
type Wake = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// Stream of probes. It yields only when the caller pulls, and it holds no timer.
///
/// Nothing here paces the probes: the caller owns the interval and the per-window budget, and it
/// scales that budget by [`EgressControl::dial`]. When the graph offers no probe, the stream returns
/// [`Poll::Pending`] and retries on the next pull.
struct ProbingStream<U> {
    /// The generator, absent while a pull owns it. Boxed so the stream is always `Unpin`.
    generator: Option<Box<ProbeGenerator<U>>>,
    pulling: Option<PullFuture<U>>,
    /// Wakes the stream on the next control change, so an idle stream still reacts to the dial.
    wake: Option<Wake>,
    control: EgressControl,
}

impl<U> ProbingStream<U>
where
    U: NetworkGraphView<NodeId = OffchainPublicKey, Observed = hopr_network_graph::Observations>
        + NetworkGraphTraverse<NodeId = OffchainPublicKey>
        + FocusedLoopback
        + Clone
        + Send
        + Sync
        + 'static,
{
    /// Arms the wake unless it is already armed. Polling it is not required for the retry: the
    /// caller's next pull retries anyway.
    fn arm(&mut self) {
        if self.wake.is_none() {
            let mut rx = self.control.subscribe();
            self.wake = Some(Box::pin(async move {
                let _ = rx.changed().await;
            }));
        }
    }
}

impl<U> futures::Stream for ProbingStream<U>
where
    U: NetworkGraphView<NodeId = OffchainPublicKey, Observed = hopr_network_graph::Observations>
        + NetworkGraphTraverse<NodeId = OffchainPublicKey>
        + FocusedLoopback
        + Clone
        + Send
        + Sync
        + 'static,
{
    type Item = ProbeRouting;

    fn poll_next(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Option<Self::Item>> {
        use std::task::Poll;

        let this = self.get_mut();

        // A control change clears the armed wake; the pull below then sees the new state.
        if let Some(wake) = this.wake.as_mut()
            && wake.as_mut().poll(cx).is_ready()
        {
            this.wake = None;
        }

        loop {
            if this.control.level().is_none() {
                // Dial off: hold the pull pending until it is raised again.
                this.arm();
                return Poll::Pending;
            }

            if let Some(mut pulling) = this.pulling.take() {
                return match pulling.as_mut().poll(cx) {
                    Poll::Ready((generator, Some(probe))) => {
                        this.generator = Some(generator);
                        this.wake = None;
                        Poll::Ready(Some(probe))
                    }
                    Poll::Ready((generator, None)) => {
                        // Nothing to probe right now. The caller's next pull retries.
                        this.generator = Some(generator);
                        this.arm();
                        Poll::Pending
                    }
                    Poll::Pending => {
                        this.pulling = Some(pulling);
                        Poll::Pending
                    }
                };
            }

            let Some(mut generator) = this.generator.take() else {
                return Poll::Ready(None);
            };
            this.pulling = Some(Box::pin(async move {
                let probe = generator.next_probe().await;
                (generator, probe)
            }));
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
        Box::pin(ProbingStream {
            generator: Some(Box::new(ProbeGenerator {
                me: self.me,
                cfg: self.cfg,
                graph: self.graph.clone(),
                path_weights: self.path_weights.clone(),
                control: self.control.clone(),
                neighbours: NeighbourState::default(),
                loopback: LoopbackState::default(),
                neighbour_turn: true,
            })),
            pulling: None,
            wake: None,
            control: self.control.clone(),
        })
    }
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

    use validator::Validate;

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

    /// Extract `NodeId` destinations from a `ProbeRouting::Neighbor` stream.
    fn neighbor_destinations(stream: impl futures::Stream<Item = ProbeRouting>) -> impl futures::Stream<Item = NodeId> {
        stream.filter_map(|r| {
            futures::future::ready(match r {
                ProbeRouting::Neighbor(DestinationRouting::Forward { destination, .. }) => Some(*destination),
                _ => None,
            })
        })
    }

    fn neighbor_peer(routing: &ProbeRouting) -> Option<OffchainPublicKey> {
        match routing {
            ProbeRouting::Neighbor(DestinationRouting::Forward { destination, .. }) => match destination.as_ref() {
                NodeId::Offchain(key) => Some(*key),
                _ => None,
            },
            _ => None,
        }
    }

    /// The two relays of a two-relay loopback probe, in order.
    fn two_relay_loop(routing: &ProbeRouting) -> Option<(OffchainPublicKey, OffchainPublicKey)> {
        match routing {
            ProbeRouting::Looping((
                DestinationRouting::Forward {
                    forward_options: RoutingOptions::IntermediatePath(path),
                    ..
                },
                _,
            )) => match path.as_ref() {
                [NodeId::Offchain(head), NodeId::Offchain(tail)] => Some((*head, *tail)),
                _ => None,
            },
            _ => None,
        }
    }

    /// First relay of a two-relay loopback probe.
    fn two_relay_loop_head(routing: &ProbeRouting) -> Option<OffchainPublicKey> {
        two_relay_loop(routing).map(|(head, _)| head)
    }

    /// Second relay of a two-relay loopback probe, which tells `two_loops`' loops apart.
    fn two_relay_loop_tail(routing: &ProbeRouting) -> Option<OffchainPublicKey> {
        two_relay_loop(routing).map(|(_, tail)| tail)
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

    /// Exit `f` with a forward loop (`a`), a return loop (`f` itself) and an unrelated loop (`c`).
    ///
    /// `me→a→x→me` (forward, as `a→f`), `me→f→y→me` (return) and `me→c→z→me`.
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

    /// The generator behind `prober`, so its snapping and ordering can be inspected without a stream.
    fn generator(prober: FullNetworkDiscovery<Arc<ChannelGraph>>) -> ProbeGenerator<Arc<ChannelGraph>> {
        ProbeGenerator {
            me: prober.me,
            cfg: prober.cfg,
            graph: prober.graph,
            path_weights: prober.path_weights,
            control: prober.control,
            neighbours: NeighbourState::default(),
            loopback: LoopbackState::default(),
            neighbour_turn: true,
        }
    }

    // ---- Acceptance criterion 1: no pulls, no timer -----------------------------------------

    #[tokio::test(start_paused = true)]
    async fn a_pull_should_never_wait_on_a_clock() -> anyhow::Result<()> {
        // A peer without samples is always probeable, so the first pull has nothing to wait for.
        let me = random_key();
        let graph = Arc::new(ChannelGraph::new(me));
        graph.record_node(random_key());

        let prober = FullNetworkDiscovery::new(me, fast_cfg(), graph);
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);
        assert_eq!(
            prober.control().coverage_windows(),
            0,
            "building the stream must not run a round"
        );

        let before = tokio::time::Instant::now();
        let probe = stream.next().await.expect("a peer needs a probe");
        assert_eq!(
            tokio::time::Instant::now(),
            before,
            "the generator must not wait on a clock before yielding"
        );
        assert!(neighbor_peer(&probe).is_some());

        // A whole interval passing changes nothing: no item is buffered while nobody pulls.
        tokio::time::advance(EgressConfig::default().interval * 10).await;
        assert!(
            timeout(TINY_TIMEOUT, stream.next()).await.is_ok(),
            "the next pull yields at once, so nothing was queued by the elapsed interval"
        );
        Ok(())
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

    // ---- Acceptance criterion 2: settled peers are left alone --------------------------------

    #[tokio::test]
    async fn a_settled_peer_should_not_be_offered_again() -> anyhow::Result<()> {
        let me = random_key();
        let graph = Arc::new(ChannelGraph::new(me));
        let peer = random_key();
        graph.record_node(peer);

        let cfg = EgressConfig {
            readd_probability: 0.0,
            ..fast_cfg()
        };
        let prober = FullNetworkDiscovery::new(me, cfg, graph);
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);

        for _ in 0..cfg.stable_samples {
            let probe = timeout(TINY_TIMEOUT, stream.next())
                .await?
                .expect("the peer still needs samples");
            assert_eq!(neighbor_peer(&probe), Some(peer));
        }

        assert!(
            timeout(TINY_TIMEOUT, stream.next()).await.is_err(),
            "a settled peer with the re-add off must not be offered again"
        );
        Ok(())
    }

    // ---- Acceptance criterion 3: a disconnect restarts the samples --------------------------

    #[tokio::test]
    async fn a_reconnect_should_restart_the_samples() -> anyhow::Result<()> {
        use hopr_api::graph::traits::{EdgeObservableWrite, EdgeWeightType};

        let me = random_key();
        let graph = Arc::new(ChannelGraph::new(me));
        let peer = random_key();
        graph.add_node(peer);
        mark_edge_ready(&graph, &me, &peer);

        let cfg = EgressConfig {
            readd_probability: 0.0,
            probe_connected_only: true,
            ..fast_cfg()
        };
        let prober = FullNetworkDiscovery::new(me, cfg, graph.clone());
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);

        for _ in 0..cfg.stable_samples {
            assert!(
                timeout(TINY_TIMEOUT, stream.next()).await?.is_some(),
                "the peer needs samples"
            );
        }
        assert!(
            timeout(TINY_TIMEOUT, stream.next()).await.is_err(),
            "the peer is settled while it stays connected"
        );

        // The disconnect is observed on the next pull, which restarts the sample count.
        graph.upsert_edge(&me, &peer, |obs| obs.record(EdgeWeightType::Connected(false)));
        assert!(
            timeout(TINY_TIMEOUT, stream.next()).await.is_err(),
            "a peer observed down is not offered while probe_connected_only is set"
        );

        graph.upsert_edge(&me, &peer, |obs| obs.record(EdgeWeightType::Connected(true)));
        for _ in 0..cfg.stable_samples {
            let probe = timeout(TINY_TIMEOUT, stream.next())
                .await?
                .expect("a reconnected peer is offered until it has fresh samples");
            assert_eq!(neighbor_peer(&probe), Some(peer));
        }
        assert!(
            timeout(TINY_TIMEOUT, stream.next()).await.is_err(),
            "the sample count fills again"
        );
        Ok(())
    }

    // ---- Acceptance criterion 4: a lower rate is probed sooner ------------------------------

    #[tokio::test]
    async fn a_deeper_rate_drop_should_be_offered_first() -> anyhow::Result<()> {
        use hopr_api::graph::traits::{EdgeObservableWrite, EdgeWeightType};

        let me = random_key();
        let graph = Arc::new(ChannelGraph::new(me));
        let (healthy, poor) = (random_key(), random_key());
        graph.record_node(healthy);
        graph.record_node(poor);

        let cfg = EgressConfig {
            readd_probability: 0.0,
            ..fast_cfg()
        };
        let prober = FullNetworkDiscovery::new(me, cfg, graph.clone());
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);

        // Settle both peers: a full window each, in whatever order they come.
        for _ in 0..cfg.stable_samples * 2 {
            assert!(timeout(TINY_TIMEOUT, stream.next()).await?.is_some());
        }
        assert!(
            timeout(TINY_TIMEOUT, stream.next()).await.is_err(),
            "both peers settled"
        );

        // Two failures out of five leave `healthy` at 0.6; five leave `poor` at 0.0.
        graph.upsert_edge(&me, &healthy, |obs| {
            for measurement in [Ok(()), Ok(()), Ok(()), Err(()), Err(())] {
                obs.record(EdgeWeightType::Immediate(
                    measurement.map(|_| std::time::Duration::from_millis(50)),
                ));
            }
        });
        graph.upsert_edge(&me, &poor, |obs| {
            for _ in 0..5 {
                obs.record(EdgeWeightType::Immediate(Err(())));
            }
        });

        let first = timeout(TINY_TIMEOUT, stream.next())
            .await?
            .expect("both rates are below the threshold");
        assert_eq!(neighbor_peer(&first), Some(poor), "the deeper drop leads");
        let second = timeout(TINY_TIMEOUT, stream.next())
            .await?
            .expect("the shallower drop still needs a probe");
        assert_eq!(neighbor_peer(&second), Some(healthy), "the shallower drop follows");
        Ok(())
    }

    #[tokio::test]
    async fn a_dropped_ack_rate_should_reopen_the_probe() -> anyhow::Result<()> {
        use hopr_api::graph::traits::{EdgeObservableWrite, EdgeWeightType};

        let me = random_key();
        let graph = Arc::new(ChannelGraph::new(me));
        let peer = random_key();
        graph.record_node(peer);

        let cfg = EgressConfig {
            readd_probability: 0.0,
            ..fast_cfg()
        };
        let prober = FullNetworkDiscovery::new(me, cfg, graph.clone());
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);

        for _ in 0..cfg.stable_samples {
            assert!(timeout(TINY_TIMEOUT, stream.next()).await?.is_some());
        }
        assert!(timeout(TINY_TIMEOUT, stream.next()).await.is_err(), "settled");

        graph.upsert_edge(&me, &peer, |obs| {
            obs.record(EdgeWeightType::ImmediateProtocolConformance {
                num_packets: 10,
                num_acks: 3,
            });
        });

        assert_eq!(
            neighbor_peer(&timeout(TINY_TIMEOUT, stream.next()).await?.expect("ack rate dropped")),
            Some(peer)
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_settled_peer_should_come_back_by_the_random_readd() -> anyhow::Result<()> {
        let me = random_key();
        let graph = Arc::new(ChannelGraph::new(me));
        let peer = random_key();
        graph.record_node(peer);

        let cfg = EgressConfig {
            readd_probability: 1.0,
            ..fast_cfg()
        };
        let prober = FullNetworkDiscovery::new(me, cfg, graph);
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);

        for _ in 0..cfg.stable_samples * 2 {
            assert!(
                timeout(TINY_TIMEOUT, stream.next()).await?.is_some(),
                "a re-add chance of 1.0 always re-offers the settled peer"
            );
        }
        Ok(())
    }

    // ---- Acceptance criterion 5: SURB evidence skips the edge --------------------------------

    #[tokio::test]
    async fn fresh_surb_evidence_should_skip_the_edge() -> anyhow::Result<()> {
        use hopr_api::graph::traits::{EdgeObservableWrite, EdgeWeightType};

        // Two loops: `me→a→x→me` and `me→c→z→me`. Evidence on `a→x` retires the first.
        let (me, a, x, c, z) = (random_key(), random_key(), random_key(), random_key(), random_key());
        let graph = Arc::new(ChannelGraph::new(me));
        for node in [a, x, c, z] {
            graph.add_node(node);
        }
        for (src, dst) in [(me, a), (a, x), (x, me), (me, c), (c, z), (z, me)] {
            graph.add_edge(&src, &dst)?;
            mark_edge_ready(&graph, &src, &dst);
        }

        let prober = FullNetworkDiscovery::new(me, fast_cfg(), graph.clone());
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);

        // Without evidence both loops are offered.
        let mut heads = HashSet::new();
        for _ in 0..64 {
            if let Some(probe) = timeout(TINY_TIMEOUT, stream.next()).await?
                && let Some(head) = two_relay_loop_head(&probe)
            {
                heads.insert(head);
            }
            if heads.len() == 2 {
                break;
            }
        }
        assert_eq!(heads, HashSet::from([a, c]), "both loops are probed without evidence");

        // Fresh SURB evidence on `a→x` retires the `a` loop.
        graph.upsert_edge(&a, &x, |obs| {
            obs.record(EdgeWeightType::SurbRoundTrips {
                expected: 10,
                observed: 10,
            });
        });

        let mut heads = HashSet::new();
        for _ in 0..64 {
            if let Some(probe) = timeout(TINY_TIMEOUT, stream.next()).await?
                && let Some(head) = two_relay_loop_head(&probe)
            {
                heads.insert(head);
            }
        }
        assert!(
            !heads.contains(&a),
            "no loopback may cross an edge with fresh SURB evidence"
        );
        assert!(heads.contains(&c), "the unevidenced loop must still be probed");
        Ok(())
    }

    // ---- Acceptance criterion 6: the cursor covers the set before repeating ------------------

    #[tokio::test]
    async fn a_cycle_should_visit_every_loop_once_before_repeating() -> anyhow::Result<()> {
        let (me, b, c, graph) = two_loops()?;
        let prober = FullNetworkDiscovery::new(me, fast_cfg(), graph);
        let control = prober.control();
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);

        let mut tails = Vec::new();
        for _ in 0..400 {
            if let Some(probe) = timeout(TINY_TIMEOUT, stream.next()).await?
                && let Some(tail) = two_relay_loop_tail(&probe)
            {
                tails.push(tail);
            }
            if tails.len() == 40 {
                break;
            }
        }
        assert_eq!(tails.len(), 40, "loops must keep flowing");

        // Two loops per cycle: each appears exactly once in every pair.
        for pair in tails.chunks(2) {
            let set: HashSet<_> = pair.iter().copied().collect();
            assert_eq!(set, HashSet::from([b, c]), "each cycle visits each loop exactly once");
        }
        assert!(control.coverage_windows() > 0, "each cycle wrap closes a window");
        Ok(())
    }

    fn fake_candidates(count: usize) -> Vec<LoopbackCandidate> {
        (0..count)
            .map(|index| LoopbackCandidate {
                path: vec![],
                path_id: [index as u64; 5],
                focus_rank: 0,
                weight: 1.0,
                explores: false,
            })
            .collect()
    }

    #[test]
    fn a_window_smaller_than_the_set_should_continue_the_cursor() {
        let plan = plan_loopbacks(fake_candidates(7), 7, &mut rand::rng());
        assert_eq!(plan.len(), 7, "a cycle holds every candidate once");

        // Walking the plan in windows of 2 keeps the windows disjoint until the cycle ends.
        let mut seen = HashSet::new();
        for window in plan.chunks(2) {
            for candidate in window {
                assert!(
                    seen.insert(candidate.path_id[0]),
                    "a candidate repeated inside one cycle"
                );
            }
        }
        assert_eq!(seen.len(), 7);
    }

    // ---- Acceptance criterion 7: the exploration share holds --------------------------------

    #[test]
    fn the_exploration_share_should_hold_in_every_window() {
        // 20 loops with a 90% best share: 18 best and 2 exploring.
        let plan = plan_loopbacks(fake_candidates(20), 18, &mut rand::rng());
        assert_eq!(plan.len(), 20);
        assert_eq!(
            plan.iter().filter(|candidate| candidate.explores).count(),
            2,
            "two loops explore"
        );

        // The exploration draws are spread evenly, so every window of ten draws has one.
        for window_start in 0..10 {
            let explored = plan[window_start..window_start + 10]
                .iter()
                .filter(|candidate| candidate.explores)
                .count();
            let share = explored as f64 / 10.0;
            assert!(
                (share - 0.1).abs() <= 0.1 + f64::EPSILON,
                "window at {window_start} explored {share} of its draws"
            );
        }
    }

    // ---- Acceptance criterion 8: the coverage metric matches the evidence -------------------

    #[tokio::test]
    async fn the_coverage_metric_should_match_the_edges_with_evidence() -> anyhow::Result<()> {
        use hopr_api::graph::traits::{EdgeObservableWrite, EdgeWeightType};

        // Two loops over a known first relay: `me→a→x→me` and `me→a→y→me`.
        let (me, a, x, y) = (random_key(), random_key(), random_key(), random_key());
        let graph = Arc::new(ChannelGraph::new(me));
        for node in [a, x, y] {
            graph.add_node(node);
        }
        for (src, dst) in [(me, a), (a, x), (x, me), (a, y), (y, me)] {
            graph.add_edge(&src, &dst)?;
            mark_edge_ready(&graph, &src, &dst);
        }

        // Evidence on exactly one edge of the loop set: `a→x`.
        graph.upsert_edge(&a, &x, |obs| {
            obs.record(EdgeWeightType::SurbRoundTrips {
                expected: 10,
                observed: 10,
            });
        });

        let prober = FullNetworkDiscovery::new(me, fast_cfg(), graph);
        let control = prober.control();
        control.set_budget(Some(1));
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);

        for _ in 0..100 {
            if control.coverage().is_some() {
                break;
            }
            assert!(timeout(TINY_TIMEOUT, stream.next()).await?.is_some());
        }

        let coverage = control.coverage().expect("a loopback window closed");
        assert_eq!(coverage.window_draws, 1, "the budget closes the window after one draw");
        assert_eq!(
            coverage.edges_with_evidence, 1,
            "exactly the one edge with fresh evidence must be counted"
        );
        Ok(())
    }

    // ---- Acceptance criterion 9: the sample count floor ------------------------------------

    #[test]
    fn a_sample_count_below_the_averaging_window_should_be_rejected() {
        // Covered in full in `config.rs`; repeated here so the acceptance criterion maps to one
        // named test in this module too.
        let below = EgressConfig {
            stable_samples: hopr_network_graph::MIN_STABLE_SAMPLES - 1,
            ..EgressConfig::default()
        };
        assert!(below.validate().is_err());

        let at_floor = EgressConfig {
            stable_samples: hopr_network_graph::MIN_STABLE_SAMPLES,
            ..EgressConfig::default()
        };
        assert!(at_floor.validate().is_ok());
    }

    // ---- Focus ------------------------------------------------------------------------------

    #[test]
    fn focus_should_rank_forward_loops_above_return_loops_above_the_rest() -> anyhow::Result<()> {
        let (me, f, a, c, graph) = focus_network()?;
        let generator = generator(FullNetworkDiscovery::new(me, fast_cfg(), graph));

        let mut loops = generator.snapshot_loops(Some(&HashSet::from([f])));
        loops.sort_by(|left, right| {
            right
                .focus_rank
                .cmp(&left.focus_rank)
                .then_with(|| right.weight.total_cmp(&left.weight))
        });

        let rank_of = |head: &OffchainPublicKey| {
            loops
                .iter()
                .find(|candidate| candidate.path.first() == Some(head))
                .map(|candidate| candidate.focus_rank)
        };

        assert_eq!(rank_of(&a), Some(2), "the forward loop leads");
        assert_eq!(rank_of(&f), Some(1), "the return loop follows");
        assert_eq!(rank_of(&c), Some(0), "the rest still probes, ranked lowest");
        Ok(())
    }

    #[test]
    fn an_unknown_exit_should_leave_default_probing_intact() -> anyhow::Result<()> {
        let (me, _f, _a, c, graph) = focus_network()?;
        let generator = generator(FullNetworkDiscovery::new(me, fast_cfg(), graph));

        let loops = generator.snapshot_loops(Some(&HashSet::from([random_key()])));

        assert!(
            loops.iter().all(|candidate| candidate.focus_rank == 0),
            "an unknown exit must not rank any loop"
        );
        assert!(
            loops.iter().any(|candidate| candidate.path.first() == Some(&c)),
            "default loops must keep flowing"
        );
        Ok(())
    }

    #[test]
    fn an_empty_path_weight_provider_should_keep_every_loop() {
        let weights = UniformPathWeights;
        let paths = vec![(Vec::new(), [1u64; 5]), (Vec::new(), [2u64; 5])];
        assert_eq!(weights.weights(&paths), vec![1.0, 1.0]);
    }

    #[test]
    fn a_path_weight_provider_should_order_the_best_set() -> anyhow::Result<()> {
        struct PreferFirst;

        impl PathWeightProvider for PreferFirst {
            fn weights(&self, _paths: &[(Vec<OffchainPublicKey>, PathId)]) -> Vec<f64> {
                // A provider that fails to return one weight per path must not break the generator.
                vec![10.0]
            }
        }

        let (me, b, c, graph) = two_loops()?;
        let generator = generator(FullNetworkDiscovery::new(me, fast_cfg(), graph).with_path_weights(PreferFirst));

        let loops = generator.snapshot_loops(None);
        assert_eq!(loops.len(), 2);
        assert!(
            loops.iter().any(|candidate| candidate.weight == 10.0),
            "the provided weight is used"
        );
        assert!(
            loops.iter().any(|candidate| candidate.weight == 1.0),
            "a missing weight falls back to neutral"
        );

        let plan = plan_loopbacks(generator.snapshot_loops(None), 1, &mut rand::rng());
        let tails: HashSet<_> = plan
            .iter()
            .filter_map(|candidate| candidate.path.get(1).copied())
            .collect();
        assert_eq!(tails, HashSet::from([b, c]), "every loop is still in the cycle");
        Ok(())
    }

    // ---- Dial ------------------------------------------------------------------------------

    #[tokio::test]
    async fn probing_should_stay_pending_when_the_dial_is_off_and_resume_when_raised() -> anyhow::Result<()> {
        let (me, _, _, graph) = two_loops()?;
        let prober = FullNetworkDiscovery::new(me, fast_cfg(), graph);
        let control = prober.control();
        control.set_level(None);
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);

        assert!(
            timeout(TINY_TIMEOUT * 5, stream.next()).await.is_err(),
            "no probe may be emitted while the dial is off"
        );

        control.set_level(Some(ProbingLevel::High));

        assert!(
            timeout(TINY_TIMEOUT * 50, stream.next()).await?.is_some(),
            "the running stream must resume without being rebuilt"
        );
        Ok(())
    }

    #[tokio::test]
    async fn probing_should_stop_when_the_dial_is_turned_off_on_a_running_stream() -> anyhow::Result<()> {
        let (me, _, _, graph) = two_loops()?;
        let prober = FullNetworkDiscovery::new(me, fast_cfg(), graph);
        let control = prober.control();
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);
        assert!(timeout(TINY_TIMEOUT * 50, stream.next()).await?.is_some());

        control.set_level(None);

        assert!(
            timeout(TINY_TIMEOUT * 5, stream.next()).await.is_err(),
            "turning the dial off mid-stream must stop the probes"
        );
        Ok(())
    }

    // ---- Neighbour selection ----------------------------------------------------------------

    #[tokio::test]
    async fn peers_should_have_a_randomized_order() -> anyhow::Result<()> {
        let me = random_key();
        let graph = Arc::new(ChannelGraph::new(me));
        for node in RANDOM_PEERS.iter() {
            graph.record_node(node.clone());
        }
        let peer_count = RANDOM_PEERS.len();

        let cfg = EgressConfig {
            stable_samples: peer_count,
            ..fast_cfg()
        };
        let prober = FullNetworkDiscovery::new(me, cfg, graph);
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);

        let peers: Vec<OffchainPublicKey> = timeout(
            TINY_TIMEOUT * 40,
            neighbor_destinations(stream)
                .take(peer_count * 2)
                .filter_map(|destination| {
                    futures::future::ready(match destination {
                        NodeId::Offchain(key) => Some(key),
                        _ => None,
                    })
                })
                .collect::<Vec<_>>(),
        )
        .await?;

        let rounds: Vec<&[OffchainPublicKey]> = peers.chunks(peer_count).collect();
        assert_eq!(rounds.len(), 2);

        let set_of = |round: &[OffchainPublicKey]| -> HashSet<OffchainPublicKey> { round.iter().copied().collect() };
        assert_eq!(set_of(rounds[0]), set_of(rounds[1]), "both passes cover the same peers");
        assert_ne!(
            rounds[0], rounds[1],
            "two passes should differ in order (probabilistic)"
        );
        Ok(())
    }

    #[tokio::test]
    async fn peers_should_be_generated_over_multiple_pulls() -> anyhow::Result<()> {
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
    async fn loopback_probes_should_be_emitted_for_two_edge_path() -> anyhow::Result<()> {
        // Topology: me → a → b, b → me (connected neighbor)
        // Loopback: me → a → b → me
        let me = random_key();
        let a = random_key();
        let b = random_key();
        let graph = Arc::new(ChannelGraph::new(me));
        graph.add_node(a);
        graph.add_node(b);

        for (src, dst) in [(me, a), (a, b), (b, me), (me, b)] {
            graph.add_edge(&src, &dst)?;
            mark_edge_ready(&graph, &src, &dst);
        }

        let prober = FullNetworkDiscovery::new(me, fast_cfg(), graph);
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);

        let items: Vec<ProbeRouting> = timeout(TINY_TIMEOUT * 100, stream.take(20).collect::<Vec<_>>()).await?;

        let looping_count = items.iter().filter(|r| matches!(r, ProbeRouting::Looping(_))).count();
        let neighbor_count = items.iter().filter(|r| matches!(r, ProbeRouting::Neighbor(_))).count();

        assert!(neighbor_count > 0, "should have neighbor probes");
        assert!(
            looping_count > 0,
            "should have loopback probes (was {looping_count} out of {} total)",
            items.len()
        );

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

    #[tokio::test]
    async fn no_loopback_probes_should_be_emitted_without_outgoing_channels() -> anyhow::Result<()> {
        use hopr_api::graph::traits::{EdgeObservableWrite, EdgeWeightType};

        // `me → a → x → me` with `a → f` focused, and `me → f → y → me`. The relays fund their channels,
        // but `me` has none: its edges are only connected and pinged.
        let (me, a, x, f, y) = (random_key(), random_key(), random_key(), random_key(), random_key());
        let graph = Arc::new(ChannelGraph::new(me));
        for node in [a, x, f, y] {
            graph.add_node(node);
        }
        for (src, dst) in [(me, a), (a, x), (x, me), (a, f), (me, f), (f, y), (y, me)] {
            graph.add_edge(&src, &dst)?;
            if src == me {
                graph.upsert_edge(&src, &dst, |obs| {
                    obs.record(EdgeWeightType::Connected(true));
                    obs.record(EdgeWeightType::Immediate(Ok(std::time::Duration::from_millis(50))));
                });
            } else {
                mark_edge_ready(&graph, &src, &dst);
            }
        }
        let cfg = EgressConfig {
            stable_samples: 64,
            ..fast_cfg()
        };
        let prober = FullNetworkDiscovery::new(me, cfg, graph);
        prober.control().set_focus([f]);
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);

        let items: Vec<ProbeRouting> = timeout(TINY_TIMEOUT * 100, stream.take(60).collect::<Vec<_>>()).await?;

        assert!(!items.is_empty(), "neighbours should still be probed");
        assert!(
            items.iter().all(|r| matches!(r, ProbeRouting::Neighbor(_))),
            "a loopback without a channel on its first hop can never be delivered"
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
    async fn cover_traffic_should_ignore_the_probing_dial() -> anyhow::Result<()> {
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
}
