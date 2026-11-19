use std::{
    collections::{HashMap, HashSet, VecDeque},
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
use tokio::sync::watch;

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

/// What the generator offers: a direct neighbor, or a loopback over a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeKind {
    Neighbor,
    Loopback,
}

/// A path the generator may probe, at the weight the path owner gives it.
#[derive(Debug, Clone)]
struct LoopbackCandidate {
    path: Vec<OffchainPublicKey>,
    path_id: PathId,
    weight: f64,
}

/// What was last seen of a neighbor, and how many probes it has had since its last disconnect.
///
/// The generator owns this count. The graph's own `samples` counter is a lifetime total that never
/// resets, so it cannot say when a peer needs sampling again.
#[derive(Debug, Clone, Copy, Default)]
struct NeighborProbeState {
    samples: u32,
    connected: Option<bool>,
}

/// The pull-driven probe generator.
///
/// Holds no timer and reads no clock. Every pull produces at most one probe, and only while the
/// dial is on; the consumer decides how often to pull. Two persistent cursors carry probing across
/// pulls: one over the neighbor sample, one over the loopback path set, so a consumer that takes
/// fewer probes per window than there are candidates continues where it stopped.
struct ProbeGenerator<U> {
    me: OffchainPublicKey,
    cfg: EgressConfig,
    graph: U,
    control: watch::Receiver<ControlState>,
    coverage: Arc<CoverageCounters>,
    neighbors: HashMap<OffchainPublicKey, NeighborProbeState>,
    /// Neighbors still to offer in this sample, fresh peers first, then the degraded ones.
    neighbor_sample: VecDeque<OffchainPublicKey>,
    /// Measured peers, from which the random re-add draws.
    measured: Vec<OffchainPublicKey>,
    /// One full pass over the loopback candidates, already interleaved by the exploration share.
    pass: Vec<LoopbackCandidate>,
    /// How much of `pass` has been offered.
    cursor: usize,
    /// Edges with fresh SURB evidence seen while `pass` was built.
    pass_evidence: HashSet<(OffchainPublicKey, OffchainPublicKey)>,
    /// Focus `pass` was built for, so a focus change rebuilds it.
    pass_focus: Option<HashSet<OffchainPublicKey>>,
    /// Whether the previous pull offered a neighbor, so the two kinds alternate.
    last_was_neighbor: bool,
}

impl<U> ProbeGenerator<U>
where
    U: NetworkGraphView<NodeId = OffchainPublicKey, Observed = Observations>
        + NetworkGraphTraverse<NodeId = OffchainPublicKey>
        + FocusedLoopback
        + Send
        + Sync
        + 'static,
{
    /// The next probe to offer, `None` when neither kind has anything to offer right now.
    ///
    /// Neighbor and loopback probes alternate while both are available, so a peer that stays below
    /// its rate thresholds cannot hold the pull order and stop loopbacks from being measured.
    async fn next_probe(&mut self, control: &ControlState) -> Option<ProbeRouting> {
        let kinds = if self.last_was_neighbor {
            [ProbeKind::Loopback, ProbeKind::Neighbor]
        } else {
            [ProbeKind::Neighbor, ProbeKind::Loopback]
        };

        for kind in kinds {
            let routing = match kind {
                ProbeKind::Neighbor => self.next_neighbor().await.map(neighbor_routing),
                ProbeKind::Loopback => self.next_loopback(control),
            };
            if let Some(routing) = routing {
                self.last_was_neighbor = kind == ProbeKind::Neighbor;
                return Some(routing);
            }
        }
        None
    }

    /// Offers the next neighbor that needs a probe, advancing its sample count.
    ///
    /// Re-examines the graph at most once per call, so a graph with nothing left to probe cannot
    /// make the search spin.
    async fn next_neighbor(&mut self) -> Option<OffchainPublicKey> {
        let mut rebuilt = false;

        loop {
            if let Some(peer) = self.take_from_sample() {
                return Some(peer);
            }

            // Every measured peer is left alone while it stays connected. Re-add one at random, so a
            // stale assumption about a static link cannot hold forever.
            if let Some(peer) = self.readd_measured() {
                return Some(peer);
            }

            if rebuilt {
                return None;
            }
            self.rebuild_neighbor_sample().await;
            rebuilt = true;
        }
    }

    /// Takes the next peer of the current sample that still needs a probe.
    fn take_from_sample(&mut self) -> Option<OffchainPublicKey> {
        while let Some(peer) = self.neighbor_sample.pop_front() {
            // A peer may have been measured out or disconnected since the sample was built.
            if self.neighbor_needs_probe(&peer) {
                self.count_sample(&peer);
                return Some(peer);
            }
        }
        None
    }

    /// Draws a measured peer at random, with the configured probability.
    fn readd_measured(&mut self) -> Option<OffchainPublicKey> {
        if self.cfg.readd_probability <= 0.0 || self.measured.is_empty() || random_float() >= self.cfg.readd_probability
        {
            return None;
        }

        let peer = self.measured[random_integer(0, Some(self.measured.len() as u64)) as usize];
        self.count_sample(&peer);
        Some(peer)
    }

    /// Counts one probe against a peer's sample.
    fn count_sample(&mut self, peer: &OffchainPublicKey) {
        let samples = self.samples_of(peer).saturating_add(1);
        self.neighbors.entry(*peer).or_default().samples = samples;
    }

    /// Rebuilds the neighbor sample, and records what the graph says about connectivity.
    async fn rebuild_neighbor_sample(&mut self) {
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

            let entry = self.neighbors.entry(peer).or_default();
            // The link that was measured is gone, so the count that described it is too.
            if connected == Some(false) && entry.connected != Some(false) {
                entry.samples = 0;
            }
            entry.connected = connected;

            if self.cfg.probe_connected_only && connected == Some(false) {
                continue;
            }

            if entry.samples < self.cfg.stable_samples {
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

        self.measured = measured;
        self.neighbor_sample = uniform_shuffle(fresh)
            .into_iter()
            .chain(degraded.into_iter().map(|(peer, _)| peer))
            .collect();
    }

    /// Whether `peer` still needs a probe under the current configuration.
    fn neighbor_needs_probe(&self, peer: &OffchainPublicKey) -> bool {
        if peer == &self.me {
            return false;
        }
        match self.graph.edge(&self.me, peer) {
            Some(obs) if self.cfg.probe_connected_only => {
                !(obs.immediate_qos().and_then(|imm| imm.is_connected()) == Some(false))
            }
            // A node the graph knows but has no edge from `me` to is still worth a ping: it is the
            // only way the edge appears.
            Some(_) | None => true,
        }
    }

    fn samples_of(&self, peer: &OffchainPublicKey) -> u32 {
        self.neighbors.get(peer).map_or(0, |state| state.samples)
    }

    /// The next loopback path, taken from the persistent cursor over the current pass.
    fn next_loopback(&mut self, control: &ControlState) -> Option<ProbeRouting> {
        let exhausted = self.cursor >= self.pass.len();
        let focus_changed = self.pass_focus.as_ref() != control.focus.as_deref();

        if self.pass.is_empty() || exhausted || focus_changed {
            // A pass that ran to its end is a full cycle over the candidate set; report what it saw.
            if !self.pass.is_empty() && exhausted {
                tracing::debug!(
                    paths = self.pass.len(),
                    edges_with_evidence = self.pass_evidence.len(),
                    "loopback cycle completed"
                );
                self.coverage.record_cycle(self.pass_evidence.len());
            }
            self.rebuild_pass(control);
        }

        let candidate = self.pass.get(self.cursor)?.clone();
        self.cursor += 1;

        let intermediates = strip_loopback_endpoints(candidate.path, &self.me);
        loopback_routing(self.me.into(), intermediates)
            .map(|routing| ProbeRouting::Looping((routing, candidate.path_id)))
    }

    /// Builds one full pass over the loopback candidates: the best paths first, the exploration
    /// share interleaved among them, and the cursor back at the start of a fresh random order.
    fn rebuild_pass(&mut self, control: &ControlState) {
        let mut all = Vec::new();
        let mut forward = Vec::new();
        let mut returning = Vec::new();
        let mut evidence = HashSet::new();

        for hops in LOOPBACK_HOP_COUNTS {
            if let Some(exits) = control.focus.as_deref() {
                for (path, path_id, relevance) in self.graph.focused_loopback(hops, Some(LOOPBACK_SAMPLE), exits) {
                    if let Some(candidate) = self.weigh_candidate(path, path_id, &control.weights, &mut evidence) {
                        match relevance {
                            FocusRelevance::Forward => forward.push(candidate),
                            FocusRelevance::Return => returning.push(candidate),
                        }
                    }
                }
            }

            for (path, path_id) in self.graph.simple_loopback_to_self(hops, Some(LOOPBACK_SAMPLE)) {
                if let Some(candidate) = self.weigh_candidate(path, path_id, &control.weights, &mut evidence) {
                    all.push(candidate);
                }
            }
        }

        // With a focus the best set is the loops around the exits, forward loops ahead of return
        // ones. Without one it is the whole set, ranked by what the path owner values.
        let ranked = if control.focus.is_some() {
            let mut ranked = weighted_shuffle(forward);
            ranked.extend(weighted_shuffle(returning));
            ranked
        } else {
            weighted_shuffle(all.clone())
        };

        // A window that spends fewer probes than the set holds cannot re-measure more paths than
        // that either, so the best set never exceeds the budget.
        let best_cap = self.cfg.best_set_size.min(control.budget.unwrap_or(usize::MAX)).max(1);
        let best: Vec<LoopbackCandidate> = ranked.into_iter().take(best_cap).collect();
        let best_paths: HashSet<&Vec<OffchainPublicKey>> = best.iter().map(|candidate| &candidate.path).collect();
        let explore: Vec<LoopbackCandidate> = all
            .into_iter()
            .filter(|candidate| !best_paths.contains(&candidate.path))
            .collect();

        let explore_share = 1.0 - self.cfg.best_path_share;
        self.pass = interleave(best, explore, explore_share);
        self.cursor = 0;
        self.pass_evidence = evidence;
        self.pass_focus = control.focus.as_deref().cloned();

        tracing::debug!(paths = self.pass.len(), explore_share, "rebuilt loopback probe pass");
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
    ) -> Option<LoopbackCandidate> {
        let intermediates = strip_loopback_endpoints(path, &self.me);
        let mut evidenced = Vec::new();

        for (src, dst) in loopback_edge_pairs(self.me, &intermediates) {
            if self
                .graph
                .edge(&src, &dst)
                .is_some_and(|obs| edge_has_fresh_evidence(&obs))
            {
                evidenced.push((src, dst));
            }
        }

        if !evidenced.is_empty() {
            evidence.extend(evidenced);
            return None;
        }

        let weight = weights.weight_of(&intermediates, path_id).unwrap_or(0.0);

        Some(LoopbackCandidate {
            path: intermediates,
            path_id,
            weight,
        })
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
fn weighted_shuffle(items: Vec<LoopbackCandidate>) -> Vec<LoopbackCandidate> {
    WeightedCollection::new(
        items
            .into_iter()
            .map(|item| {
                let weight = item.weight;
                (item, weight)
            })
            .collect(),
    )
    .into_shuffled()
}

/// Interleaves `explore` among `best` so that every prefix holds the exploration share.
///
/// The generator cannot see the consumer's windows, so the share is carried by the order itself:
/// at every position the exploration set takes its turn as soon as it is behind by more than
/// `explore_share`, whatever the window boundaries turn out to be.
fn interleave(
    best: Vec<LoopbackCandidate>,
    explore: Vec<LoopbackCandidate>,
    explore_share: f64,
) -> Vec<LoopbackCandidate> {
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
    fn build(&self) -> BoxStream<'static, ProbeRouting> {
        let generator = ProbeGenerator {
            me: self.me,
            cfg: self.cfg,
            graph: self.graph.clone(),
            control: self.control.subscribe(),
            coverage: self.control.coverage_counters(),
            neighbors: HashMap::new(),
            neighbor_sample: VecDeque::new(),
            measured: Vec::new(),
            pass: Vec::new(),
            cursor: 0,
            pass_evidence: HashSet::new(),
            pass_focus: None,
            last_was_neighbor: false,
        };

        probing_stream(generator).boxed()
    }
}

/// The lazy stream over a [`ProbeGenerator`].
///
/// Nothing is polled until the consumer pulls, and no timer runs between pulls. While the dial is
/// off, or while nothing is left to offer, the stream waits on the control handle rather than
/// spinning; it emits nothing and holds no timer either way.
fn probing_stream<U>(generator: ProbeGenerator<U>) -> impl futures::Stream<Item = ProbeRouting>
where
    U: NetworkGraphView<NodeId = OffchainPublicKey, Observed = Observations>
        + NetworkGraphTraverse<NodeId = OffchainPublicKey>
        + FocusedLoopback
        + Send
        + Sync
        + 'static,
{
    futures::stream::unfold(generator, |mut generator| async move {
        loop {
            if generator.control.borrow_and_update().level.is_none() {
                if generator.control.changed().await.is_err() {
                    return futures::future::pending().await;
                }
                continue;
            }

            let control = generator.control.borrow_and_update().clone();

            if let Some(probe) = generator.next_probe(&control).await {
                return Some((probe, generator));
            }

            // Nothing to offer until something changes: a focus, a budget, a dial, or a peer.
            if generator.control.changed().await.is_err() {
                return futures::future::pending().await;
            }
        }
    })
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
    use crate::{EgressConfig, ProbingLevel};

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
    async fn a_measured_peer_should_not_be_offered_again() -> anyhow::Result<()> {
        let me = random_key();
        let peer = random_key();
        let graph = Arc::new(ChannelGraph::new(me));
        graph.record_node(peer);

        let prober = FullNetworkDiscovery::new(me, fast_cfg(), graph);
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);

        // The peer needs `stable_samples` probes before it counts as measured.
        let expected = fast_cfg().stable_samples as usize;
        let destinations: Vec<NodeId> = timeout(
            TINY_TIMEOUT * 100,
            neighbor_destinations(stream.by_ref())
                .take(expected)
                .collect::<Vec<_>>(),
        )
        .await?;
        assert_eq!(
            destinations,
            vec![NodeId::from(peer); expected],
            "an unmeasured peer is probed until it has enough samples"
        );

        assert!(
            timeout(TINY_TIMEOUT * 10, neighbor_destinations(stream).next())
                .await
                .is_err(),
            "a measured, connected peer must not be offered again"
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

        let prober = FullNetworkDiscovery::new(me, fast_cfg(), graph.clone());
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);

        let expected = fast_cfg().stable_samples as usize;
        timeout(
            TINY_TIMEOUT * 100,
            neighbor_destinations(stream.by_ref())
                .take(expected)
                .collect::<Vec<_>>(),
        )
        .await?;

        // The connection drops and comes back: the link that was measured is not the one in place.
        {
            use hopr_api::graph::traits::{EdgeObservableWrite, EdgeWeightType};
            graph.upsert_edge(&me, &peer, |obs| obs.record(EdgeWeightType::Connected(false)));
        }

        let after_disconnect: Vec<NodeId> = timeout(
            TINY_TIMEOUT * 100,
            neighbor_destinations(stream.by_ref())
                .take(expected)
                .collect::<Vec<_>>(),
        )
        .await?;
        assert_eq!(
            after_disconnect,
            vec![NodeId::from(peer); expected],
            "a reconnected peer must be sampled again from zero"
        );

        assert!(
            timeout(TINY_TIMEOUT * 10, neighbor_destinations(stream).next())
                .await
                .is_err(),
            "probing stops again once the sample count is back"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_lower_rate_should_be_offered_sooner() -> anyhow::Result<()> {
        let me = random_key();
        let (deeper, shallower) = (random_key(), random_key());
        let graph = Arc::new(ChannelGraph::new(me));
        for peer in [deeper, shallower] {
            graph.record_node(peer);
            mark_edge_ready(&graph, &me, &peer);
        }

        let cfg = EgressConfig {
            // Both peers fall below the threshold; the deeper one falls further.
            min_success_rate: 0.9,
            ..fast_cfg()
        };
        let prober = FullNetworkDiscovery::new(me, cfg, graph.clone());
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);

        // Measure both peers out, then degrade them to different depths.
        let expected = cfg.stable_samples as usize;
        timeout(
            TINY_TIMEOUT * 100,
            neighbor_destinations(stream.by_ref())
                .take(expected * 2)
                .collect::<Vec<_>>(),
        )
        .await?;
        record_probes(&graph, &me, &deeper, 0, 6);
        record_probes(&graph, &me, &shallower, 1, 1);

        let first = timeout(TINY_TIMEOUT * 100, neighbor_destinations(stream).next())
            .await?
            .context("a degraded peer must be offered again")?;

        assert_eq!(
            first,
            NodeId::from(deeper),
            "the peer further below its threshold must lead the pull order"
        );
        Ok(())
    }

    #[tokio::test]
    async fn fresh_surb_evidence_should_skip_the_edge() -> anyhow::Result<()> {
        // `me → head → {b, c} → me`; `head → b` already carries traffic, `head → c` does not.
        let (me, head, b, c, graph) = two_loops()?;
        record_surb_evidence(&graph, &head, &b);

        let prober = FullNetworkDiscovery::new(me, fast_cfg(), graph.clone());
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);

        let offered = loopbacks(&mut stream, 8).await?;

        assert!(
            !offered.iter().any(|path| path.contains(&b)),
            "a loop over an edge with fresh evidence must not be offered"
        );
        assert!(
            offered.iter().any(|path| path.contains(&c)),
            "loops over edges without evidence must still be offered"
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
        // Tags above 1_000 identify the exploration candidates.
        let candidate = |tag: usize| LoopbackCandidate {
            path: vec![random_key()],
            path_id: [tag as u64; 5],
            weight: 1.0,
        };
        let best: Vec<_> = (0..90).map(candidate).collect();
        let explore: Vec<_> = (1_000..1_010).map(candidate).collect();

        let pass = interleave(best, explore, 0.1);

        assert_eq!(pass.len(), 100);
        for window in pass.chunks(10) {
            let explored = window.iter().filter(|candidate| candidate.path_id[0] >= 1_000).count();
            assert!(
                (0..=2).contains(&explored),
                "a ten-pull window held {explored} explorations"
            );
        }

        // Over the whole pass the share is exact.
        let explored = pass.iter().filter(|candidate| candidate.path_id[0] >= 1_000).count();
        assert_eq!(explored, 10);
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
        let (me, _, _, _, graph) = two_loops()?;
        let prober = FullNetworkDiscovery::new(me, fast_cfg(), graph);
        let control = prober.control();
        let stream = ProbingTrafficGeneration::build(&prober);
        pin_mut!(stream);
        assert!(timeout(TINY_TIMEOUT * 50, stream.next()).await?.is_some());

        control.set_level(None);

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
        control.set_level(None);
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
