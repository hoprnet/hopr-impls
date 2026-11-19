use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::Arc,
};

use futures::{
    StreamExt,
    future::Either,
    stream::{BoxStream, PollNext},
};
use hopr_api::{
    ct::{CoverTrafficGeneration, ProbeRouting, ProbingTrafficGeneration},
    graph::{
        NetworkGraphTraverse, NetworkGraphView,
        traits::{EdgeImmediateProtocolObservable, EdgeLinkObservable, EdgeNetworkObservableRead, EdgeObservableRead},
    },
    types::{
        crypto::types::OffchainPublicKey,
        crypto_random::{Randomizable, random_float, random_integer},
        internal::{
            NodeId,
            protocol::HoprPseudonym,
            routing::{DestinationRouting, PathId, RoutingOptions},
        },
    },
};
use hopr_network_graph::{FocusRelevance, FocusedLoopback, MAX_LOOPBACK_HOPS, MIN_LOOPBACK_HOPS, Observations};
use hopr_utils::statistics::WeightedCollection;
use tokio::sync::{Notify, watch};

use crate::{
    EgressConfig,
    control::{ControlState, CoverageCounters, EgressControl, PathWeights},
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
/// Cover traffic only, so it is built only with the `noise` feature. A change of the period restarts the wait, so a new
/// period takes effect at once, including waking a stream that was paused. Changes that leave the period alone do not
/// disturb the running wait.
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

/// Build a zero-hop probe of a direct neighbor.
fn neighbor_routing(peer: OffchainPublicKey) -> ProbeRouting {
    let zero_hop = RoutingOptions::Hops(0.try_into().expect("0 is a valid u8"));
    ProbeRouting::Neighbor(DestinationRouting::Forward {
        destination: Box::new(peer.into()),
        pseudonym: Some(HoprPseudonym::random()),
        forward_options: zero_hop.clone(),
        return_options: Some(zero_hop),
    })
}

/// Every directed edge of the loop `me → path → me`, the closing edge included.
fn loopback_edge_pairs(
    me: OffchainPublicKey,
    path: &[OffchainPublicKey],
) -> impl Iterator<Item = (OffchainPublicKey, OffchainPublicKey)> {
    let mut nodes = Vec::with_capacity(path.len() + 2);
    nodes.push(me);
    nodes.extend_from_slice(path);
    nodes.push(me);
    // The loop always holds at least `me → x → me`, so there is always one pair to walk.
    let pairs: Vec<_> = nodes.windows(2).map(|edge| (edge[0], edge[1])).collect();

    pairs.into_iter()
}

/// Hop counts cycled through by loopback probing, in **intermediate relay hops** — not edges.
///
/// A loopback of `h` hops traverses `h + 1` edges. Every entry must lie within
/// `MIN_LOOPBACK_HOPS..=MAX_LOOPBACK_HOPS`; outside it, candidates are built and then silently
/// discarded when the routing options are constructed.
const LOOPBACK_HOP_COUNTS: [usize; 2] = [MIN_LOOPBACK_HOPS, MAX_LOOPBACK_HOPS];

/// Candidates one hop count enumeration returns, in no particular order.
const LOOPBACK_SAMPLE: usize = 100;

/// Stream that cycles through 2- and 3-hop loopback paths with weighted shuffle.
///
/// Cover traffic only: it ticks on the configured interval and yields every hop count's candidates
/// once per tick. Probing is pull driven and does not use it.
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

/// The unfocused loopback sample, every path at the same weight.
#[cfg(feature = "noise")]
fn default_candidates<U>(graph: &U, hops: usize, base: f64) -> Vec<((Vec<OffchainPublicKey>, PathId), f64)>
where
    U: NetworkGraphTraverse<NodeId = OffchainPublicKey>,
{
    graph
        .simple_loopback_to_self(hops, Some(LOOPBACK_SAMPLE))
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

/// A loopback route, and the weight the path owner gives it.
///
/// The route is the interface's own [`ProbeRouting`], built as soon as the path is weighed, so the
/// pass holds exactly the objects the stream hands out. The weight rides alongside because
/// [`ProbeRouting`] carries no valuation and the pass is ordered by it.
type WeightedRoute = (ProbeRouting, f64);

/// What was last seen of a neighbor, and how many outcomes it has recorded since its last
/// disconnect.
///
/// Outcomes, not offers: a probe the consumer dropped, or one that never came back, says nothing
/// about the link, and counting it would retire a peer nobody has measured. The graph's counter is
/// a lifetime total that never resets, so the count here is kept as the difference since the last
/// disconnect.
#[derive(Debug, Clone, Copy, Default)]
struct NeighborProbeState {
    outcomes: u32,
    /// The graph's lifetime counter when `outcomes` was last brought up to date.
    observed: u64,
    connected: Option<bool>,
}

/// Per-peer state, and the order in which the peers are offered.
///
/// Peers that still need sampling are recorded as they are measured, so a count that has reached
/// [`EgressConfig::stable_samples`] is what takes a peer out of the sample, and the sample
/// deliberately does not outlive the pass through the graph that built it.
#[derive(Debug, Default)]
struct NeighborSamples {
    states: HashMap<OffchainPublicKey, NeighborProbeState>,
    /// Peers still to offer, fresh ones first and then the degraded ones, deepest deficit first.
    sample: VecDeque<OffchainPublicKey>,
    /// Measured peers, from which the random re-add draws.
    measured: Vec<OffchainPublicKey>,
}

impl NeighborSamples {
    /// Mutable access to a peer's record.
    fn entry(&mut self, peer: OffchainPublicKey) -> &mut NeighborProbeState {
        self.states.entry(peer).or_default()
    }

    /// Takes the next peer of the current sample that still needs a probe.
    fn take_next(&mut self, needs_probe: impl Fn(&OffchainPublicKey) -> bool) -> Option<OffchainPublicKey> {
        while let Some(peer) = self.sample.pop_front() {
            // A peer may have been measured out or disconnected since the sample was built.
            if needs_probe(&peer) {
                return Some(peer);
            }
        }
        None
    }

    /// Draws a measured peer at random, with probability `probability`.
    fn readd(&mut self, probability: f64) -> Option<OffchainPublicKey> {
        if probability <= 0.0 || self.measured.is_empty() || random_float() >= probability {
            return None;
        }

        Some(self.measured[random_integer(0, Some(self.measured.len() as u64)) as usize])
    }

    /// Replaces the sample for the next pass through the graph.
    fn install(&mut self, sample: VecDeque<OffchainPublicKey>, measured: Vec<OffchainPublicKey>) {
        self.sample = sample;
        self.measured = measured;
    }
}

/// One full pass over the loopback candidates, with the cursor that carries it across pulls.
///
/// The cursor is what makes a consumer that takes fewer probes per window than there are candidates
/// continue where it stopped, instead of starting the set over each window.
#[derive(Debug, Default)]
struct LoopbackPass {
    /// The candidates in the order they will be offered, already interleaved by the exploration share.
    paths: Vec<WeightedRoute>,
    /// How much of `paths` has been offered.
    cursor: usize,
    /// Edges with fresh SURB evidence seen while `paths` was built.
    evidence: HashSet<(OffchainPublicKey, OffchainPublicKey)>,
    /// Focus `paths` was built for, so a focus change rebuilds it.
    focus: Option<HashSet<OffchainPublicKey>>,
}

impl LoopbackPass {
    /// The next candidate, advancing the cursor.
    fn next(&mut self) -> Option<ProbeRouting> {
        let (route, _) = self.paths.get(self.cursor)?.clone();
        self.cursor += 1;
        Some(route)
    }

    /// Whether the pass must be rebuilt before the next candidate is offered.
    fn is_spent(&self, focus: Option<&HashSet<OffchainPublicKey>>) -> bool {
        self.paths.is_empty() || self.cursor >= self.paths.len() || self.focus.as_ref() != focus
    }

    /// Whether a pass ran to its end, i.e. covered its whole candidate set.
    fn is_complete(&self) -> bool {
        !self.paths.is_empty() && self.cursor >= self.paths.len()
    }

    /// Installs a pass built for `focus`, with the cursor back at its start.
    fn install(
        &mut self,
        paths: Vec<WeightedRoute>,
        evidence: HashSet<(OffchainPublicKey, OffchainPublicKey)>,
        focus: Option<HashSet<OffchainPublicKey>>,
    ) {
        self.paths = paths;
        self.cursor = 0;
        self.evidence = evidence;
        self.focus = focus;
    }
}

/// Neighbor probing on its own: which direct peer needs a ping next.
///
/// Knows nothing about loopbacks, and shares no state with them. It owns its sample count, because
/// the graph's `samples` counter is a lifetime total that never resets.
struct NeighborProber<U> {
    me: OffchainPublicKey,
    cfg: EgressConfig,
    graph: U,
    samples: NeighborSamples,
}

impl<U> NeighborProber<U>
where
    U: NetworkGraphView<NodeId = OffchainPublicKey, Observed = Observations> + Send + Sync + 'static,
{
    /// The next peer to ping, `None` when every known peer is measured and the re-add did not fire.
    ///
    /// Re-examines the graph at most once per call, so a graph with nothing left to probe cannot
    /// make the search spin.
    async fn next(&mut self) -> Option<OffchainPublicKey> {
        let mut rebuilt = false;

        loop {
            // Scoped so the shared borrow of the graph ends before the rebuild below needs `&mut self`.
            let taken = {
                let (graph, me, connected_only) = (&self.graph, self.me, self.cfg.probe_connected_only);
                self.samples
                    .take_next(|peer| neighbor_needs_probe(graph, me, connected_only, peer))
            };
            if let Some(peer) = taken {
                return Some(peer);
            }

            // Every measured peer is left alone while it stays connected. Re-add one at random, so a
            // stale assumption about a static link cannot hold forever.
            if let Some(peer) = self.samples.readd(self.cfg.readd_probability) {
                return Some(peer);
            }

            if rebuilt {
                return None;
            }
            self.rebuild_sample().await;
            rebuilt = true;
        }
    }

    /// Rebuilds the sample from the graph, recording what it says about connectivity.
    async fn rebuild_sample(&mut self) {
        let mut fresh = Vec::new();
        let mut degraded = Vec::new();
        let mut measured = Vec::new();
        let mut nodes = self.graph.nodes();

        while let Some(peer) = nodes.next().await {
            if peer == self.me {
                continue;
            }

            let obs = self.graph.edge(&self.me, &peer);
            let immediate = obs.as_ref().and_then(|obs| obs.immediate_qos());
            let connected = immediate.and_then(|imm| imm.is_connected());

            let observed = immediate.map_or(0, |imm| imm.probe_samples());

            let state = self.samples.entry(peer);
            // The link that was measured is gone, so the count that described it is too. The graph's
            // lifetime counter keeps running, so it becomes the new baseline instead of zero.
            if connected == Some(false) && state.connected != Some(false) {
                (state.outcomes, state.observed) = (0, observed);
            }
            if observed > state.observed {
                state.outcomes = state
                    .outcomes
                    .saturating_add(u32::try_from(observed - state.observed).unwrap_or(u32::MAX));
                state.observed = observed;
            }
            state.connected = connected;
            let outcomes = state.outcomes;

            if self.cfg.probe_connected_only && connected == Some(false) {
                continue;
            }

            if outcomes < self.cfg.stable_samples {
                fresh.push(peer);
                continue;
            }

            let deficit = immediate.map_or(0.0, |imm| {
                let success = imm
                    .average_probe_rate()
                    .map_or(0.0, |rate| (self.cfg.min_success_rate - rate).max(0.0));
                let ack = imm
                    .ack_rate()
                    .map_or(0.0, |rate| (self.cfg.min_ack_rate - rate).max(0.0));
                success + ack
            });

            if deficit > 0.0 {
                degraded.push((peer, deficit));
            } else {
                measured.push(peer);
            }
        }

        // The further below its threshold a peer sits, the more often it is reprobed, so the deepest
        // deficit leads the sample.
        degraded.sort_by(|left, right| right.1.total_cmp(&left.1));

        let sample = uniform_shuffle(fresh)
            .into_iter()
            .chain(degraded.into_iter().map(|(peer, _)| peer))
            .collect();
        self.samples.install(sample, measured);
    }
}

/// Loopback probing on its own: which path to measure next.
///
/// Knows nothing about neighbors, and shares no state with them. It keeps the persistent cursor
/// over its candidate set and publishes what each completed pass saw.
struct LoopbackProber<U> {
    me: OffchainPublicKey,
    cfg: EgressConfig,
    graph: U,
    pass: LoopbackPass,
    coverage: Arc<CoverageCounters>,
    /// How far into the enumeration the next pass starts.
    ///
    /// The enumeration returns a stable prefix of a bounded sample, so taking the same first
    /// `LOOPBACK_SAMPLE` paths every cycle would leave the rest of the network unvisited. Each pass
    /// therefore starts `LOOPBACK_SAMPLE` paths further in and wraps once the enumeration is
    /// exhausted, so successive cycles reach different paths.
    window: usize,
}

impl<U> LoopbackProber<U>
where
    U: NetworkGraphView<NodeId = OffchainPublicKey, Observed = Observations>
        + NetworkGraphTraverse<NodeId = OffchainPublicKey>
        + FocusedLoopback
        + Send
        + Sync
        + 'static,
{
    /// The next loopback path, taken from the persistent cursor over the current pass.
    fn next(&mut self, control: &ControlState) -> Option<ProbeRouting> {
        if self.pass.is_spent(control.focus.as_deref()) {
            // A pass that ran to its end is a full cycle over the candidate set; report what it saw.
            if self.pass.is_complete() {
                tracing::debug!(
                    paths = self.pass.paths.len(),
                    edges_with_evidence = self.pass.evidence.len(),
                    "loopback cycle completed"
                );
                self.coverage.record_cycle(self.pass.evidence.len());
            }
            self.rebuild_pass(control);
        }

        self.pass.next()
    }

    /// Builds one full pass over the loopback candidates: the best paths first, the exploration
    /// share interleaved among them, and the cursor back at the start of a fresh random order.
    fn rebuild_pass(&mut self, control: &ControlState) {
        let mut all = Vec::new();
        let mut forward = Vec::new();
        let mut returning = Vec::new();
        let mut evidence = HashSet::new();

        // Ask for one window more than the pass will use, so a short answer tells us the
        // enumeration is exhausted and the window has to wrap.
        let wanted = self.window + LOOPBACK_SAMPLE;
        let mut exhausted = false;

        for hops in LOOPBACK_HOP_COUNTS {
            if let Some(exits) = control.focus.as_deref() {
                let focused = self.graph.focused_loopback(hops, Some(wanted), exits);
                exhausted |= focused.len() < wanted;
                for (path, path_id, relevance) in focused.into_iter().skip(self.window) {
                    if let Some(candidate) = self.weigh_candidate(path, path_id, &control.weights, &mut evidence) {
                        match relevance {
                            FocusRelevance::Forward => forward.push(candidate),
                            FocusRelevance::Return => returning.push(candidate),
                        }
                    }
                }
            }

            let simple = self.graph.simple_loopback_to_self(hops, Some(wanted));
            exhausted |= simple.len() < wanted;
            for (path, path_id) in simple.into_iter().skip(self.window) {
                if let Some(candidate) = self.weigh_candidate(path, path_id, &control.weights, &mut evidence) {
                    all.push(candidate);
                }
            }
        }

        self.window = if exhausted { 0 } else { self.window + LOOPBACK_SAMPLE };

        // The best set is the selection, not a weighted draw from it: it is what the path owner
        // values most. With a focus it also stays around the exits, forward loops ahead of return
        // ones, so the paths routing will take there are the ones kept measured.
        let by_weight = |mut paths: Vec<WeightedRoute>| {
            paths.sort_by(|left, right| right.1.total_cmp(&left.1));
            paths
        };
        let ranked = if control.focus.is_some() {
            let mut ranked = by_weight(forward);
            ranked.extend(by_weight(returning));
            ranked
        } else {
            by_weight(all.clone())
        };

        // A window that spends fewer probes than the set holds cannot re-measure more paths than
        // that either, so the best set never exceeds the cap the consumer set for it.
        let best_cap = self
            .cfg
            .best_set_size
            .min(control.best_set_cap.unwrap_or(usize::MAX))
            .max(1);
        let explore_share = 1.0 - self.cfg.best_path_share;
        let paths = split_pass(ranked, all, best_cap, explore_share);
        tracing::debug!(paths = paths.len(), explore_share, "rebuilt loopback probe pass");

        self.pass.install(paths, evidence, control.focus.as_deref().cloned());
    }

    /// Weighs a candidate, and skips it when any of its edges already carries fresh SURB evidence.
    ///
    /// A path whose edges are already measured by real traffic needs no probe: the probe budget is
    /// better spent where nothing is known.
    fn weigh_candidate(
        &self,
        path: Vec<OffchainPublicKey>,
        path_id: PathId,
        weights: &PathWeights,
        evidence: &mut HashSet<(OffchainPublicKey, OffchainPublicKey)>,
    ) -> Option<WeightedRoute> {
        let intermediates = strip_loopback_endpoints(path, &self.me);
        let edges: Vec<_> = loopback_edge_pairs(self.me, &intermediates).collect();
        let mut evidenced = Vec::new();

        for (src, dst) in &edges {
            if self
                .graph
                .edge(src, dst)
                .is_some_and(|obs| edge_has_fresh_evidence(&obs))
            {
                evidenced.push((*src, *dst));
            }
        }

        // Only a path every edge of which is already measured by traffic is a wasted probe: the
        // rest still measures the edges without evidence, and the graph attributes the outcome per
        // edge. A path with more of them is worth more, so its weight is scaled by that count.
        // The metric counts edges with evidence, whichever loops they sit on.
        evidence.extend(evidenced.iter().copied());

        let unmeasured = edges.len().saturating_sub(evidenced.len());
        if unmeasured == 0 {
            return None;
        }

        let weight = weights.weight_of(&intermediates, path_id).unwrap_or(0.0) * unmeasured as f64;
        let route = ProbeRouting::Looping((loopback_routing(self.me.into(), intermediates)?, path_id));

        Some((route, weight))
    }
}

/// Whether `peer` still needs a probe under `probe_connected_only`.
fn neighbor_needs_probe<U>(
    graph: &U,
    me: OffchainPublicKey,
    probe_connected_only: bool,
    peer: &OffchainPublicKey,
) -> bool
where
    U: NetworkGraphView<NodeId = OffchainPublicKey, Observed = Observations>,
{
    if peer == &me {
        return false;
    }
    match graph.edge(&me, peer) {
        Some(obs) if probe_connected_only => !(obs.immediate_qos().and_then(|imm| imm.is_connected()) == Some(false)),
        // A node the graph knows but has no edge from `me` to is still worth a ping: it is the only
        // way the edge appears.
        Some(_) | None => true,
    }
}

/// Whether the edge carries evidence from real traffic, which probing has no reason to duplicate.
fn edge_has_fresh_evidence(obs: &Observations) -> bool {
    // Both signals read the SURB window; either one is evidence that traffic crossed the edge.
    obs.intermediate_qos().is_some_and(|intermediate| {
        intermediate.surb_delivery_rate().is_some() || intermediate.traffic_rate().is_some()
    })
}

/// A uniform random permutation.
fn uniform_shuffle<T>(items: Vec<T>) -> Vec<T> {
    WeightedCollection::new(items.into_iter().map(|item| (item, 1.0)).collect()).into_shuffled()
}

/// A random permutation in which heavier items come earlier more often.
fn weighted_shuffle(items: Vec<WeightedRoute>) -> Vec<WeightedRoute> {
    WeightedCollection::new(
        items
            .into_iter()
            .map(|item| {
                let weight = item.1;
                (item, weight)
            })
            .collect(),
    )
    .into_shuffled()
}

/// The path a loopback route was selected for, `None` for a route that is not a loopback.
fn route_path_id(route: &ProbeRouting) -> Option<PathId> {
    match route {
        ProbeRouting::Looping((_, path_id)) => Some(*path_id),
        ProbeRouting::Neighbor(_) => None,
    }
}

/// Splits the candidates into the best set and the exploration set, then interleaves them.
///
/// The best set is the highest-weighted paths (`ranked` must already be sorted by weight, which is
/// what makes membership follow the owner's valuation rather than a draw). The order within each
/// set is still random, so cycles do not replay the same sequence.
fn split_pass(
    ranked: Vec<WeightedRoute>,
    all: Vec<WeightedRoute>,
    best_cap: usize,
    explore_share: f64,
) -> Vec<WeightedRoute> {
    let best = weighted_shuffle(ranked.into_iter().take(best_cap).collect());
    let best_paths: HashSet<PathId> = best.iter().filter_map(|(route, _)| route_path_id(route)).collect();
    let explore = weighted_shuffle(
        all.into_iter()
            .filter(|(route, _)| route_path_id(route).is_none_or(|id| !best_paths.contains(&id)))
            .collect(),
    );

    interleave(best, explore, explore_share)
}

/// Interleaves `explore` among `best` so that every prefix holds the exploration share.
///
/// The generator cannot see the consumer's windows, so the share is carried by the order itself:
/// at every position the exploration set takes its turn as soon as it is behind by more than
/// `explore_share`, whatever the window boundaries turn out to be.
fn interleave(best: Vec<WeightedRoute>, explore: Vec<WeightedRoute>, explore_share: f64) -> Vec<WeightedRoute> {
    let mut best = VecDeque::from(best);
    let mut explore = VecDeque::from(explore);
    let mut pass = Vec::with_capacity(best.len() + explore.len());
    let mut explored = 0usize;

    while !best.is_empty() || !explore.is_empty() {
        let position = pass.len() + 1;
        let take_explore =
            !explore.is_empty() && (best.is_empty() || (explored as f64) < explore_share * position as f64);

        let next = if take_explore {
            explored += 1;
            explore.pop_front()
        } else {
            best.pop_front()
        };

        if let Some(candidate) = next {
            pass.push(candidate);
        }
    }

    pass
}

/// Waits until the dial is on. `None` once the control handle is gone.
async fn wait_for_dial(control: &mut watch::Receiver<ControlState>) -> Option<()> {
    loop {
        if control.borrow_and_update().dial.is_some() {
            return Some(());
        }
        if control.changed().await.is_err() {
            return None;
        }
    }
}

/// Resolves once either the control or an explicit wake says to look again.
///
/// The graph offers no change notification and the generator reads no clock, so a disconnect or a
/// dropped rate is invisible to an idle stream until something calls
/// [`EgressControl::wake_probing`](crate::EgressControl::wake_probing). `false` means the control
/// handle is gone and nothing can steer probing any more.
async fn wait_for_wake(control: &mut watch::Receiver<ControlState>, wake: &Notify) -> bool {
    match futures::future::select(std::pin::pin!(control.changed()), std::pin::pin!(wake.notified())).await {
        Either::Left((Ok(()), _)) | Either::Right(((), _)) => true,
        Either::Left((Err(_), _)) => false,
    }
}

/// Stream of neighbor probes, one per pull, driven only by its own state.
///
/// Nothing is polled until the consumer pulls, and no timer runs between pulls. While the dial is
/// off, or while every peer is measured, it waits on the control handle rather than spinning.
fn neighbor_probes<U>(
    prober: NeighborProber<U>,
    control: watch::Receiver<ControlState>,
    wake: Arc<Notify>,
) -> impl futures::Stream<Item = ProbeRouting>
where
    U: NetworkGraphView<NodeId = OffchainPublicKey, Observed = Observations> + Send + Sync + 'static,
{
    futures::stream::unfold((prober, control), move |(mut prober, mut control)| {
        let wake = wake.clone();

        async move {
            loop {
                // Without a control handle nobody can steer probing, so the stream stays pending
                // rather than ending: probe generation is never meant to run out.
                if wait_for_dial(&mut control).await.is_none() {
                    return futures::future::pending().await;
                }

                if let Some(peer) = prober.next().await {
                    return Some((neighbor_routing(peer), (prober, control)));
                }

                // Nothing to offer until the peer set or the wake says to look again.
                if !wait_for_wake(&mut control, &wake).await {
                    return futures::future::pending().await;
                }
            }
        }
    })
}

/// Stream of loopback probes, one per pull, driven only by its own state.
///
/// Nothing is polled until the consumer pulls, and no timer runs between pulls. While the dial is
/// off, or while there is no candidate path, it waits on the control handle rather than spinning.
fn loopback_probes<U>(
    prober: LoopbackProber<U>,
    control: watch::Receiver<ControlState>,
    wake: Arc<Notify>,
) -> impl futures::Stream<Item = ProbeRouting>
where
    U: NetworkGraphView<NodeId = OffchainPublicKey, Observed = Observations>
        + NetworkGraphTraverse<NodeId = OffchainPublicKey>
        + FocusedLoopback
        + Send
        + Sync
        + 'static,
{
    futures::stream::unfold((prober, control), move |(mut prober, mut control)| {
        let wake = wake.clone();

        async move {
            loop {
                // Without a control handle nobody can steer probing, so the stream stays pending
                // rather than ending: probe generation is never meant to run out.
                if wait_for_dial(&mut control).await.is_none() {
                    return futures::future::pending().await;
                }

                let state = control.borrow_and_update().clone();
                if let Some(probe) = prober.next(&state) {
                    return Some((probe, (prober, control)));
                }

                // Nothing to offer until the graph or the wake says to look again.
                if !wait_for_wake(&mut control, &wake).await {
                    return futures::future::pending().await;
                }
            }
        }
    })
}

impl<U> ProbingTrafficGeneration for FullNetworkDiscovery<U>
where
    U: NetworkGraphView<NodeId = OffchainPublicKey, Observed = Observations>
        + NetworkGraphTraverse<NodeId = OffchainPublicKey>
        + FocusedLoopback
        + Clone
        + Send
        + Sync
        + 'static,
{
    /// Neighbor and loopback probing are separate streams with no shared state, merged fairly so
    /// neither can starve the other.
    fn build(&self) -> BoxStream<'static, ProbeRouting> {
        let neighbors = neighbor_probes(
            NeighborProber {
                me: self.me,
                cfg: self.cfg,
                graph: self.graph.clone(),
                samples: NeighborSamples::default(),
            },
            self.control.subscribe(),
            self.control.wake_handle(),
        );

        let loopbacks = loopback_probes(
            LoopbackProber {
                me: self.me,
                cfg: self.cfg,
                graph: self.graph.clone(),
                pass: LoopbackPass::default(),
                coverage: self.control.coverage_counters(),
                window: 0,
            },
            self.control.subscribe(),
            self.control.wake_handle(),
        );

        // Alternate which stream is polled first, so a peer that stays below its thresholds cannot
        // hold the pull order and stop loopbacks from being measured.
        futures::stream::select_with_strategy(neighbors, loopbacks, |next: &mut PollNext| next.toggle()).boxed()
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, sync::Arc, time::Duration};

    use anyhow::Context as _;
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
    use crate::{Dial, EgressConfig};

    const TINY_TIMEOUT: Duration = Duration::from_millis(20);

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
            #[cfg(feature = "noise")]
            interval: Duration::from_millis(1),
            probe_connected_only: false,
            // Keep the re-add out of the way of the ordering assertions.
            readd_probability: 0.0,
            ..Default::default()
        }
    }

    fn random_key() -> OffchainPublicKey {
        *OffchainKeypair::random().public()
    }

    /// Helper: mark an edge as fully connected with capacity, so it passes all cost checks.
    fn mark_edge_ready(graph: &ChannelGraph, src: &OffchainPublicKey, dst: &OffchainPublicKey) {
        use hopr_api::graph::traits::{EdgeObservableWrite, EdgeWeightType};
        graph.upsert_edge(src, dst, |obs| {
            obs.record(EdgeWeightType::Connected(true));
            obs.record(EdgeWeightType::Immediate(Ok(Duration::from_millis(50))));
            obs.record(EdgeWeightType::Balance(Some(hopr_api::graph::traits::Balance::from(
                1000u64,
            ))));
        });
    }

    /// Records `successes` answered probes followed by `failures` unanswered ones on an edge.
    fn record_probes(
        graph: &ChannelGraph,
        src: &OffchainPublicKey,
        dst: &OffchainPublicKey,
        successes: u32,
        failures: u32,
    ) {
        use hopr_api::graph::traits::{EdgeObservableWrite, EdgeWeightType};
        graph.upsert_edge(src, dst, |obs| {
            for _ in 0..successes {
                obs.record(EdgeWeightType::Immediate(Ok(Duration::from_millis(50))));
            }
            for _ in 0..failures {
                obs.record(EdgeWeightType::Immediate(Err(())));
            }
        });
    }

    /// Gives an edge SURB evidence: traffic crossed it and replies came back.
    fn record_surb_evidence(graph: &ChannelGraph, src: &OffchainPublicKey, dst: &OffchainPublicKey) {
        use hopr_api::graph::traits::{EdgeObservableWrite, EdgeWeightType};
        graph.upsert_edge(src, dst, |obs| {
            obs.record(EdgeWeightType::SurbRoundTrips {
                expected: 10,
                observed: 10,
            });
        });
    }

    /// `me → head → {b, c} → me`: two 2-relay loops that differ only in their last relay.
    #[allow(clippy::type_complexity)]
    fn two_loops() -> anyhow::Result<(
        OffchainPublicKey,
        OffchainPublicKey,
        OffchainPublicKey,
        OffchainPublicKey,
        Arc<ChannelGraph>,
    )> {
        let (me, head, b, c) = (random_key(), random_key(), random_key(), random_key());
        let graph = Arc::new(ChannelGraph::new(me));
        for node in [head, b, c] {
            graph.add_node(node);
        }
        for (src, dst) in [(me, head), (head, b), (head, c), (b, me), (c, me)] {
            graph.add_edge(&src, &dst)?;
            mark_edge_ready(&graph, &src, &dst);
        }
        Ok((me, head, b, c, graph))
    }

    /// Nine loops ending at distinct exits, plus one unrelated loop: `(me, exits, unrelated, graph)`.
    #[allow(clippy::type_complexity)]
    fn focus_topology() -> anyhow::Result<(
        OffchainPublicKey,
        Vec<OffchainPublicKey>,
        OffchainPublicKey,
        Arc<ChannelGraph>,
    )> {
        let me = random_key();
        let graph = Arc::new(ChannelGraph::new(me));
        let mut exits = Vec::new();

        for _ in 0..9 {
            let (head, exit) = (random_key(), random_key());
            for node in [head, exit] {
                graph.add_node(node);
            }
            for (src, dst) in [(me, head), (head, exit), (exit, me)] {
                graph.add_edge(&src, &dst)?;
                mark_edge_ready(&graph, &src, &dst);
            }
            exits.push(exit);
        }

        let (head, unrelated) = (random_key(), random_key());
        for node in [head, unrelated] {
            graph.add_node(node);
        }
        for (src, dst) in [(me, head), (head, unrelated), (unrelated, me)] {
            graph.add_edge(&src, &dst)?;
            mark_edge_ready(&graph, &src, &dst);
        }

        Ok((me, exits, unrelated, graph))
    }

    /// `count` disjoint 2-relay loops, returned with their first relay.
    fn disjoint_loops(count: usize) -> anyhow::Result<(OffchainPublicKey, Vec<OffchainPublicKey>, Arc<ChannelGraph>)> {
        let me = random_key();
        let graph = Arc::new(ChannelGraph::new(me));
        let mut heads = Vec::with_capacity(count);

        for _ in 0..count {
            let (head, last) = (random_key(), random_key());
            for node in [head, last] {
                graph.add_node(node);
            }
            for (src, dst) in [(me, head), (head, last), (last, me)] {
                graph.add_edge(&src, &dst)?;
                mark_edge_ready(&graph, &src, &dst);
            }
            heads.push(head);
        }

        Ok((me, heads, graph))
    }

    /// `count` relays, every pair connected both ways, each also connected to `me` both ways.
    fn full_mesh(count: usize) -> anyhow::Result<(OffchainPublicKey, Arc<ChannelGraph>)> {
        let me = random_key();
        let graph = Arc::new(ChannelGraph::new(me));
        let relays: Vec<_> = (0..count).map(|_| random_key()).collect();
        for relay in &relays {
            graph.add_node(*relay);
        }

        for relay in &relays {
            for (src, dst) in [(me, *relay), (*relay, me)] {
                graph.add_edge(&src, &dst)?;
                mark_edge_ready(&graph, &src, &dst);
            }
            // A measured neighbor keeps the neighbor stream from holding the pull order.
            record_probes(&graph, &me, relay, fast_cfg().stable_samples, 0);
        }
        for from in &relays {
            for to in &relays {
                if from != to {
                    graph.add_edge(from, to)?;
                    mark_edge_ready(&graph, from, to);
                }
            }
        }
        Ok((me, graph))
    }

    /// Intermediates of a loopback probe, or `None` for a neighbor probe.
    fn loopback_path(routing: &ProbeRouting) -> Option<Vec<OffchainPublicKey>> {
        match routing {
            ProbeRouting::Looping((
                DestinationRouting::Forward {
                    forward_options: RoutingOptions::IntermediatePath(path),
                    ..
                },
                _,
            )) => Some(
                path.as_ref()
                    .iter()
                    .filter_map(|node| match node {
                        NodeId::Offchain(key) => Some(*key),
                        _ => None,
                    })
                    .collect(),
            ),
            _ => None,
        }
    }

    /// Destinations of neighbor probes, in the order they were offered.
    fn neighbor_destinations(stream: impl futures::Stream<Item = ProbeRouting>) -> impl futures::Stream<Item = NodeId> {
        stream.filter_map(|r| {
            futures::future::ready(match r {
                ProbeRouting::Neighbor(DestinationRouting::Forward { destination, .. }) => Some(*destination),
                _ => None,
            })
        })
    }

    /// Pulls until `count` loopback probes have been offered, skipping neighbor probes.
    async fn loopbacks(
        stream: &mut (impl futures::Stream<Item = ProbeRouting> + Unpin),
        count: usize,
    ) -> anyhow::Result<Vec<Vec<OffchainPublicKey>>> {
        let mut found = Vec::with_capacity(count);
        while found.len() < count {
            let probe = timeout(TINY_TIMEOUT * 400, stream.next())
                .await
                .context("timed out waiting for a loopback probe")?
                .context("the probing stream ended")?;
            if let Some(path) = loopback_path(&probe) {
                found.push(path);
            }
        }
        Ok(found)
    }

    #[tokio::test]
    async fn the_stream_should_emit_nothing_without_pulls_and_hold_no_timer() -> anyhow::Result<()> {
        let (me, _, _, _, graph) = two_loops()?;

        // The default interval is 30 s. A pull-driven stream ignores it: a pull yields a probe at
        // once, and a stream nobody pulls yields nothing at all.
        let cfg = EgressConfig {
            probe_connected_only: false,
            ..Default::default()
        };
        #[cfg(feature = "noise")]
        assert_eq!(cfg.interval, Duration::from_secs(30));

        let prober = FullNetworkDiscovery::new(me, cfg, graph);
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);

        let started = std::time::Instant::now();
        let probe = timeout(TINY_TIMEOUT * 5, stream.next()).await?;
        assert!(probe.is_some(), "a pull must yield a probe at once");
        assert!(
            started.elapsed() < TINY_TIMEOUT * 5,
            "the stream must not wait out the configured interval"
        );
        Ok(())
    }

    #[tokio::test]
    async fn the_stream_should_be_lazy_and_follow_the_dial() -> anyhow::Result<()> {
        let me = random_key();
        let graph = Arc::new(ChannelGraph::new(me));
        for _ in 0..3 {
            graph.record_node(random_key());
        }

        let prober = FullNetworkDiscovery::new(me, fast_cfg(), graph);
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);

        tokio::time::pause();

        // An hour with the dial off, and no pull, produces nothing.
        prober.control().set_dial(None);
        tokio::time::advance(Duration::from_hours(1)).await;
        assert!(
            timeout(TINY_TIMEOUT, stream.next()).await.is_err(),
            "no probe comes out of a dial that is off"
        );

        // Turning it on is what makes the next pull produce exactly one probe.
        prober.control().set_dial(Some(Dial::HIGH));
        assert!(timeout(TINY_TIMEOUT * 20, stream.next()).await?.is_some());
        Ok(())
    }

    #[tokio::test]
    async fn a_dial_that_is_not_a_preset_should_still_run_probing() -> anyhow::Result<()> {
        let me = random_key();
        let graph = Arc::new(ChannelGraph::new(me));
        graph.record_node(random_key());

        let prober = FullNetworkDiscovery::new(me, fast_cfg(), graph);
        prober
            .control()
            .set_dial(Some(Dial::new(0.25).expect("0.25 is a valid dial")));
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);

        assert!(timeout(TINY_TIMEOUT * 20, stream.next()).await?.is_some());
        Ok(())
    }

    #[tokio::test]
    async fn a_measured_peer_should_not_be_offered_again() -> anyhow::Result<()> {
        let me = random_key();
        let peer = random_key();
        let graph = Arc::new(ChannelGraph::new(me));
        graph.record_node(peer);
        mark_edge_ready(&graph, &me, &peer);

        // N successful outcomes, recorded before the stream is built.
        let outcomes = fast_cfg().stable_samples;
        record_probes(&graph, &me, &peer, outcomes, 0);

        let prober = FullNetworkDiscovery::new(me, fast_cfg(), graph);
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);

        for _ in 0..100 {
            assert!(
                timeout(TINY_TIMEOUT, stream.next()).await.is_err(),
                "a measured, connected peer must not be offered again"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn offers_without_recorded_outcomes_are_not_samples() -> anyhow::Result<()> {
        let me = random_key();
        let peer = random_key();
        let graph = Arc::new(ChannelGraph::new(me));
        graph.record_node(peer);

        let prober = FullNetworkDiscovery::new(me, fast_cfg(), graph.clone());
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);

        // Offered N times and more, but nothing was ever recorded: the peer is still unmeasured.
        let offers = fast_cfg().stable_samples as usize + 2;
        let destinations: Vec<NodeId> = timeout(
            TINY_TIMEOUT * 200,
            neighbor_destinations(stream.by_ref()).take(offers).collect::<Vec<_>>(),
        )
        .await?;
        assert_eq!(
            destinations,
            vec![NodeId::from(peer); offers],
            "an offer is not a sample, so probing does not stop"
        );

        // Recording the outcomes is what measures the peer.
        record_probes(&graph, &me, &peer, fast_cfg().stable_samples, 0);
        prober.control().wake_probing();

        assert!(
            timeout(TINY_TIMEOUT * 20, neighbor_destinations(stream).next())
                .await
                .is_err(),
            "once N outcomes are recorded the peer is left alone"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_reconnect_should_restart_the_sample_count() -> anyhow::Result<()> {
        let me = random_key();
        let peer = random_key();
        let graph = Arc::new(ChannelGraph::new(me));
        graph.record_node(peer);
        mark_edge_ready(&graph, &me, &peer);

        let outcomes = fast_cfg().stable_samples;
        record_probes(&graph, &me, &peer, outcomes, 0);

        let prober = FullNetworkDiscovery::new(me, fast_cfg(), graph.clone());
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);

        assert!(
            timeout(TINY_TIMEOUT, stream.next()).await.is_err(),
            "the peer starts measured"
        );

        // The connection drops and comes back while the stream is idle.
        {
            use hopr_api::graph::traits::{EdgeObservableWrite, EdgeWeightType};
            graph.upsert_edge(&me, &peer, |obs| obs.record(EdgeWeightType::Connected(false)));
        }
        prober.control().wake_probing();

        let after_reconnect: Vec<NodeId> = timeout(
            TINY_TIMEOUT * 200,
            neighbor_destinations(stream.by_ref())
                .take(outcomes as usize)
                .collect::<Vec<_>>(),
        )
        .await?;
        assert_eq!(
            after_reconnect,
            vec![NodeId::from(peer); outcomes as usize],
            "a reconnected peer must be sampled again until it has N new outcomes"
        );

        // The reconnect is only measured once its outcomes are recorded, not by the offers.
        record_probes(&graph, &me, &peer, outcomes, 0);
        prober.control().wake_probing();

        assert!(
            timeout(TINY_TIMEOUT * 20, neighbor_destinations(stream).next())
                .await
                .is_err(),
            "probing stops again once the new outcomes are recorded"
        );
        Ok(())
    }

    #[tokio::test]
    async fn loopbacks_should_be_offered_while_a_peer_keeps_needing_probes() -> anyhow::Result<()> {
        // A peer whose probe rate stays below its threshold never leaves the neighbor sample, so the
        // neighbor stream is always ready. Merging without a fair strategy would let it hold every
        // pull, and an edge nothing else measures would stay unmeasured.
        let (me, head, _, _, graph) = two_loops()?;
        record_probes(&graph, &me, &head, 0, 6);

        let cfg = EgressConfig {
            min_success_rate: 0.9,
            ..fast_cfg()
        };
        let prober = FullNetworkDiscovery::new(me, cfg, graph);
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);

        let offered = loopbacks(&mut stream, 2).await?;

        assert_eq!(offered.len(), 2, "loopbacks must still be offered");
        Ok(())
    }

    #[tokio::test]
    async fn a_lower_rate_should_be_offered_sooner() -> anyhow::Result<()> {
        let me = random_key();
        let (deeper, shallower, at_threshold) = (random_key(), random_key(), random_key());
        let graph = Arc::new(ChannelGraph::new(me));
        for peer in [deeper, shallower, at_threshold] {
            graph.record_node(peer);
            mark_edge_ready(&graph, &me, &peer);
        }

        let cfg = EgressConfig {
            // Measured peers with a rate below this are probed again.
            min_success_rate: 0.5,
            ..fast_cfg()
        };
        let outcomes = cfg.stable_samples;

        // All three start measured at a full success rate.
        for peer in [deeper, shallower, at_threshold] {
            record_probes(&graph, &me, &peer, outcomes, 0);
        }
        // Then two drop below the threshold, one of them further, and one sits exactly on it.
        // The success rate is an EMA over five samples, so each failure moves it part way down.
        record_probes(&graph, &me, &deeper, 0, 6);
        record_probes(&graph, &me, &shallower, 0, 4);
        record_probes(&graph, &me, &at_threshold, 1, 1);

        let prober = FullNetworkDiscovery::new(me, cfg, graph);
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);

        prober.control().wake_probing();

        let first = timeout(TINY_TIMEOUT * 200, neighbor_destinations(stream.by_ref()).next())
            .await?
            .context("a degraded peer must be offered again")?;
        let second = timeout(TINY_TIMEOUT * 200, neighbor_destinations(stream).next())
            .await?
            .context("both degraded peers must be offered again")?;

        assert_eq!(
            first,
            NodeId::from(deeper),
            "the peer further below its threshold must lead the pull order"
        );
        assert_eq!(second, NodeId::from(shallower), "then the shallower one");
        Ok(())
    }

    #[tokio::test]
    async fn fresh_surb_evidence_should_skip_only_a_fully_measured_loop() -> anyhow::Result<()> {
        // `me → head → b → me`, with evidence written onto one edge only.
        let (me, head, b, _c, graph) = two_loops()?;

        // Only `me → head` has evidence: the loop still measures `head → b` and `b → me`.
        record_surb_evidence(&graph, &me, &head);
        let prober = FullNetworkDiscovery::new(me, fast_cfg(), graph.clone());
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);
        let offered = loopbacks(&mut stream, 4).await?;
        assert!(
            offered.iter().any(|path| path == &vec![head, b]),
            "a loop with an unmeasured edge must still be offered"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_loop_is_skipped_only_when_every_edge_has_evidence() -> anyhow::Result<()> {
        let (me, head, b, c, graph) = two_loops()?;

        // Every edge of the `head → b` loop carries evidence; the `head → c` loop has none.
        for (src, dst) in [(me, head), (head, b), (b, me)] {
            record_surb_evidence(&graph, &src, &dst);
        }

        let prober = FullNetworkDiscovery::new(me, fast_cfg(), graph.clone());
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);

        let offered = loopbacks(&mut stream, 6).await?;

        assert!(
            !offered.iter().any(|path| path.contains(&b)),
            "a loop whose every edge has evidence is not worth a probe"
        );
        assert!(
            offered.iter().any(|path| path.contains(&c)),
            "the unmeasured loop must still be offered"
        );
        Ok(())
    }

    #[tokio::test]
    async fn the_cursor_should_reach_paths_beyond_the_enumerated_prefix() -> anyhow::Result<()> {
        // 20 relays in a full mesh give 20 * 19 two-relay loops, while one pass holds at most
        // LOOPBACK_SAMPLE of them. The window has to walk the enumeration for the rest to be reached.
        let (me, graph) = full_mesh(20)?;
        let prober = FullNetworkDiscovery::new(me, fast_cfg(), graph);
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);

        let mut seen: HashSet<Vec<OffchainPublicKey>> = HashSet::new();
        let mut first_window = Vec::new();
        let mut second_window = Vec::new();

        for cycle in 0..10 {
            for pull in 0..200 {
                let path = loopbacks(&mut stream, 1).await?;
                let path = path[0].clone();
                if path.len() == 2 {
                    seen.insert(path.clone());
                    match cycle {
                        0 if pull < 50 => first_window.push(path),
                        1 if pull < 50 => second_window.push(path),
                        _ => {}
                    }
                }
            }
        }

        let total = 20 * 19;
        assert!(
            seen.len() * 5 >= total * 4,
            "at least 80% of the {total} two-relay loops must be reached, got {}",
            seen.len()
        );

        let overlap = first_window.iter().filter(|path| second_window.contains(path)).count();
        assert!(
            overlap < 25,
            "cycle 2 must not repeat cycle 1's first 50 loops, shared {overlap}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn the_cursor_should_cover_the_set_before_repeating() -> anyhow::Result<()> {
        let (me, heads, graph) = disjoint_loops(6)?;
        let cfg = EgressConfig {
            // Every pull explores, so the pass is one random permutation of the candidate set.
            best_path_share: 0.0,
            ..fast_cfg()
        };
        let prober = FullNetworkDiscovery::new(me, cfg, graph);
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);

        // Three windows of two pulls each, all inside the first pass.
        let mut windows = Vec::new();
        for _ in 0..3 {
            let window: HashSet<_> = loopbacks(&mut stream, 2)
                .await?
                .iter()
                .filter_map(|path| path.first().copied())
                .collect();
            assert_eq!(window.len(), 2, "a window must not repeat a candidate");
            windows.push(window);
        }

        // Consecutive windows continue where the last stopped rather than starting over.
        for (left, right) in windows.iter().zip(windows.iter().skip(1)) {
            assert!(
                left.intersection(right).next().is_none(),
                "consecutive windows must cover different edges"
            );
        }

        // A full pass visits every candidate exactly once before repeating.
        let covered: HashSet<_> = windows.into_iter().flatten().collect();
        assert_eq!(
            covered,
            heads.iter().copied().collect::<HashSet<_>>(),
            "a cycle must cover every candidate"
        );
        Ok(())
    }

    #[test]
    fn the_exploration_share_should_hold_within_a_window() {
        // Tags at or above 1_000 identify the exploration candidates.
        let candidate = |tag: usize, weight: f64| {
            let routing = DestinationRouting::Forward {
                destination: Box::new(NodeId::Offchain(random_key())),
                pseudonym: None,
                forward_options: RoutingOptions::Hops(0u8.try_into().expect("0 is a valid u8")),
                return_options: None,
            };
            (ProbeRouting::Looping((routing, [tag as u64; 5])), weight)
        };
        let best: Vec<_> = (0..900).map(|tag| candidate(tag, 1.0)).collect();
        let explore: Vec<_> = (1_000..1_100).map(|tag| candidate(tag, 1.0)).collect();

        let pass = interleave(best, explore, 0.1);

        assert_eq!(pass.len(), 1_000);
        for window in pass.chunks(20) {
            let explored = window
                .iter()
                .filter(|(route, _)| route_path_id(route).is_some_and(|id| id[0] >= 1_000))
                .count();
            assert!(
                (1..=3).contains(&explored),
                "a twenty-pull window held {explored} explorations"
            );
        }

        // Over the whole pass the share is exact, give or take one.
        let explored = pass
            .iter()
            .filter(|(route, _)| route_path_id(route).is_some_and(|id| id[0] >= 1_000))
            .count();
        assert!((99..=101).contains(&explored), "the cycle held {explored}");
    }

    #[test]
    fn the_best_set_should_follow_the_weights() {
        // Ten paths the owner values, and a hundred and ninety it barely does.
        let candidate = |tag: usize, weight: f64| {
            let routing = DestinationRouting::Forward {
                destination: Box::new(NodeId::Offchain(random_key())),
                pseudonym: None,
                forward_options: RoutingOptions::Hops(0u8.try_into().expect("0 is a valid u8")),
                return_options: None,
            };
            (ProbeRouting::Looping((routing, [tag as u64; 5])), weight)
        };
        let heavy: Vec<_> = (0..10).map(|tag| candidate(tag, 1.0)).collect();
        let light: Vec<_> = (10..200).map(|tag| candidate(tag, 0.01)).collect();

        let mut best_slots = 0;
        let mut heavy_slots = 0;

        for _ in 0..20 {
            let mut all = heavy.clone();
            all.extend(light.clone());
            all.sort_by(|left, right| right.1.total_cmp(&left.1));

            let pass = split_pass(all.clone(), all, 10, 0.0);

            for candidate in pass.iter().take(10) {
                best_slots += 1;
                if candidate.1 == 1.0 {
                    heavy_slots += 1;
                }
            }
        }

        assert!(
            heavy_slots * 10 >= best_slots * 9,
            "at least 90% of the best-set slots must be the valued paths, got {heavy_slots} of {best_slots}"
        );
    }

    #[tokio::test]
    async fn the_coverage_metric_should_count_every_edge_with_evidence() -> anyhow::Result<()> {
        // Seven disjoint loops, one evidenced edge each: seven distinct edges in the cycle.
        let (me, heads, graph) = disjoint_loops(7)?;
        for head in &heads {
            record_surb_evidence(&graph, &me, head);
        }

        let prober = FullNetworkDiscovery::new(me, fast_cfg(), graph);
        let control = prober.control();
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);

        let before = control.coverage().map_or(0, |coverage| coverage.cycles);
        let mut rounds = 0;
        while control.coverage().map_or(0, |coverage| coverage.cycles) <= before && rounds < 40 {
            loopbacks(&mut stream, 1).await?;
            rounds += 1;
        }

        let coverage = control
            .coverage()
            .context("a completed cycle must publish its coverage")?;
        assert_eq!(coverage.edges_with_evidence, 7, "one evidenced edge per loop");
        assert_eq!(coverage.cycles, before + 1, "exactly one cycle completed");
        Ok(())
    }

    #[tokio::test]
    async fn the_coverage_metric_should_match_the_edges_with_evidence() -> anyhow::Result<()> {
        let (me, head, b, _c, graph) = two_loops()?;
        record_surb_evidence(&graph, &head, &b);

        let prober = FullNetworkDiscovery::new(me, fast_cfg(), graph);
        let control = prober.control();
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);

        // One full pass, then the pass after it, which records the first one's coverage.
        let cycles_before = control.coverage().map_or(0, |coverage| coverage.cycles);
        let mut rounds = 0;
        while control.coverage().map_or(0, |coverage| coverage.cycles) == cycles_before && rounds < 20 {
            loopbacks(&mut stream, 1).await?;
            rounds += 1;
        }

        let coverage = control
            .coverage()
            .context("a completed cycle must publish its coverage")?;
        assert_eq!(
            coverage.edges_with_evidence, 1,
            "exactly one edge carried fresh evidence in the cycle"
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

    #[tokio::test]
    async fn neighbors_should_be_covered_across_passes() -> anyhow::Result<()> {
        let me = random_key();
        let graph = Arc::new(ChannelGraph::new(me));
        let (peer_a, peer_b) = (random_key(), random_key());
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
        assert_eq!(unique, expected, "every pass must cover all known peers exactly once");
        Ok(())
    }

    #[tokio::test]
    async fn only_neighbor_probes_are_emitted_when_no_looping_paths_exist() -> anyhow::Result<()> {
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
    async fn loopback_probes_should_be_emitted_for_a_two_edge_path() -> anyhow::Result<()> {
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

        let offered = loopbacks(&mut stream, 1).await?;

        assert_eq!(offered[0], vec![a, b], "the only loop is me → a → b → me");
        Ok(())
    }

    #[tokio::test]
    async fn no_loopback_probes_should_be_emitted_without_outgoing_channels() -> anyhow::Result<()> {
        use hopr_api::graph::traits::{EdgeObservableWrite, EdgeWeightType};

        // `me → a → x → me` with `a → f` focused, and `me → f → y → me`. The relays fund their
        // channels, but `me` has none: its edges are only connected and pinged.
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
                    obs.record(EdgeWeightType::Immediate(Ok(Duration::from_millis(50))));
                });
            } else {
                mark_edge_ready(&graph, &src, &dst);
            }
        }
        let prober = FullNetworkDiscovery::new(me, fast_cfg(), graph);
        prober.control().set_focus([f]);
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);

        // The two relays are sampled out and then left alone, so the stream goes quiet instead of
        // offering a loopback that could never be delivered.
        let mut items = Vec::new();
        while let Ok(Some(item)) = timeout(TINY_TIMEOUT * 10, stream.next()).await {
            items.push(item);
            if items.len() > 60 {
                break;
            }
        }

        assert!(!items.is_empty(), "neighbours should still be probed");
        assert!(
            items.iter().all(|r| matches!(r, ProbeRouting::Neighbor(_))),
            "a loopback without a channel on its first hop can never be delivered"
        );
        Ok(())
    }

    #[tokio::test]
    async fn probing_should_stay_pending_when_the_dial_is_off_and_resume_when_raised() -> anyhow::Result<()> {
        let (me, _, _, _, graph) = two_loops()?;
        let prober = FullNetworkDiscovery::new(me, fast_cfg(), graph);
        let control = prober.control();
        control.set_dial(None);
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);

        assert!(
            timeout(TINY_TIMEOUT * 5, stream.next()).await.is_err(),
            "no probe may be emitted while the dial is off"
        );

        control.set_dial(Some(Dial::HIGH));

        assert!(
            timeout(TINY_TIMEOUT * 50, stream.next()).await?.is_some(),
            "the running stream must resume without being rebuilt"
        );
        Ok(())
    }

    #[tokio::test]
    async fn probing_should_stop_when_the_dial_is_turned_off_on_a_running_stream() -> anyhow::Result<()> {
        let (me, _, _, _, graph) = two_loops()?;
        let prober = FullNetworkDiscovery::new(me, fast_cfg(), graph);
        let control = prober.control();
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);
        assert!(timeout(TINY_TIMEOUT * 50, stream.next()).await?.is_some());

        control.set_dial(None);

        assert!(timeout(TINY_TIMEOUT * 5, stream.next()).await.is_err());
        Ok(())
    }

    #[cfg(feature = "noise")]
    #[tokio::test]
    async fn cover_traffic_should_stay_pending_until_noise_is_switched_on() -> anyhow::Result<()> {
        let (me, _, _, _, graph) = two_loops()?;
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
        let (me, _, _, _, graph) = two_loops()?;
        let prober = FullNetworkDiscovery::new(me, fast_cfg(), graph);
        let control = prober.control();
        control.set_noise(true);
        control.set_dial(None);
        let stream = CoverTrafficGeneration::build(&prober);
        pin_mut!(stream);

        assert!(timeout(TINY_TIMEOUT * 50, stream.next()).await?.is_some());
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
    async fn probing_should_not_depend_on_the_noise_switch() -> anyhow::Result<()> {
        let (me, _, _, _, graph) = two_loops()?;
        let prober = FullNetworkDiscovery::new(me, fast_cfg(), graph);
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);

        assert!(!prober.control().noise());
        assert!(timeout(TINY_TIMEOUT * 50, stream.next()).await?.is_some());
        Ok(())
    }

    #[tokio::test]
    async fn a_focus_should_spend_the_best_share_on_the_exits() -> anyhow::Result<()> {
        let (me, exits, unrelated, graph) = focus_topology()?;
        let prober = FullNetworkDiscovery::new(me, fast_cfg(), graph);
        prober.control().set_focus(exits.clone());
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);

        // A pass holds nine focused loops and one unrelated loop, in the configured 90/10 split.
        let offered = loopbacks(&mut stream, exits.len() + 1).await?;

        let focused = offered
            .iter()
            .filter(|path| path.iter().any(|relay| exits.contains(relay)))
            .count();
        let explored = offered.iter().filter(|path| path.contains(&unrelated)).count();

        assert_eq!(focused, exits.len(), "every focused loop must be measured in the pass");
        assert_eq!(explored, 1, "the unrelated loop must keep its exploration share");
        Ok(())
    }

    #[tokio::test]
    async fn focus_on_an_unknown_exit_should_leave_default_probing_intact() -> anyhow::Result<()> {
        let (me, _, b, c, graph) = two_loops()?;
        let prober = FullNetworkDiscovery::new(me, fast_cfg(), graph);
        prober.control().set_focus([random_key()]);
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);

        let offered = loopbacks(&mut stream, 6).await?;
        let heads: HashSet<_> = offered.iter().filter_map(|path| path.last().copied()).collect();

        assert!(
            heads.contains(&b) && heads.contains(&c),
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

    #[test]
    fn loopback_routing_should_reject_full_path_with_me() -> anyhow::Result<()> {
        // Verify that loopback_routing rejects paths that are too long for BoundedVec.
        // simple_loopback_to_self returns [a, b, me] (no leading me); after
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
            "intermediates-only path should be routable"
        );
        Ok(())
    }
}
