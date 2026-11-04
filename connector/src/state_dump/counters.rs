//! Bounded inputs recorded at routing/SURB producers. This module knows no transport implementation.
use std::{sync::Arc, time::Instant};

use hopr_api::{OffchainPublicKey, graph::ForwardAndReturnPath, types::internal::NodeId};
use parking_lot::Mutex;
use serde::Serialize;

/// Maximum named destination/direction rows per interval.
pub const MAX_DESTINATIONS: usize = 8;
/// Retain multiple sibling pairs for each sampled SURB destination.
pub const MAX_SURB_DESTINATIONS: usize = 4;
/// Maximum retained sibling pairs per sampled destination.
pub const MAX_SURB_PAIRS: usize = 4;
/// Forward or return path, independent of channel direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Forward,
    Return,
}
/// Counts from one actual search phase, not an inference from cache hits.
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct PhaseOutcome {
    pub returned: u64,
    pub eligible: u64,
}
/// One search result supplied by the selector. Phase 2 is absent when not run.
#[derive(Clone, Copy, Debug, Default)]
pub struct SearchOutcome {
    pub phase1: PhaseOutcome,
    pub phase2: Option<PhaseOutcome>,
    pub retained: u64,
}
/// Saturating interval counts. Resolution calls, search queries and candidate counts differ.
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct PathCounts {
    pub succeeded: u64,
    pub failed: u64,
    pub searches: u64,
    pub empty_searches: u64,
    pub phase1_returned: u64,
    pub phase1_eligible: u64,
    pub phase2_runs: u64,
    pub phase2_returned: u64,
    pub phase2_eligible: u64,
}
impl PathCounts {
    fn add(&mut self, c: Self) {
        self.succeeded = self.succeeded.saturating_add(c.succeeded);
        self.failed = self.failed.saturating_add(c.failed);
        self.searches = self.searches.saturating_add(c.searches);
        self.empty_searches = self.empty_searches.saturating_add(c.empty_searches);
        self.phase1_returned = self.phase1_returned.saturating_add(c.phase1_returned);
        self.phase1_eligible = self.phase1_eligible.saturating_add(c.phase1_eligible);
        self.phase2_runs = self.phase2_runs.saturating_add(c.phase2_runs);
        self.phase2_returned = self.phase2_returned.saturating_add(c.phase2_returned);
        self.phase2_eligible = self.phase2_eligible.saturating_add(c.phase2_eligible);
    }

    fn problematic(&self) -> bool {
        self.failed > 0 || self.empty_searches > 0
    }
}
/// One named destination sample. The caller uses the same identity at selector and resolver.
#[derive(Debug, Serialize)]
pub struct Destination {
    pub direction: Direction,
    pub destination: NodeId,
    pub counts: PathCounts,
    /// Earlier observations may be in overflow when a healthy row was replaced.
    pub partial_window: bool,
}
/// SURB event counts. Returns can cross minting windows; this is not delivery probability.
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct SurbCounts {
    pub minted: u64,
    pub returned: u64,
}
impl SurbCounts {
    fn add(&mut self, c: Self) {
        self.minted = self.minted.saturating_add(c.minted);
        self.returned = self.returned.saturating_add(c.returned);
    }
}
/// One sibling forward/reply pair. Slot IDs identify paths, not a blamed relayer.
#[derive(Debug, Serialize)]
pub struct SurbPair {
    pub forward: [u64; 5],
    pub reply: [u64; 5],
    pub counts: SurbCounts,
}
/// Capped sibling group; overflow keeps counts of unsampled pairs at this destination.
#[derive(Debug, Serialize)]
pub struct SurbDestination {
    pub destination: OffchainPublicKey,
    pub(crate) pairs: Vec<SurbPair>,
    pub overflow: SurbCounts,
}
impl SurbDestination {
    pub fn pairs(&self) -> &[SurbPair] {
        &self.pairs
    }
}
/// Maximum named neighbor-probe peers per interval. Totals include unsampled peers.
pub const MAX_PROBE_PEERS: usize = 8;
/// Neighbor probe outcomes in one reporting window.
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct ProbeCounts {
    pub succeeded: u64,
    pub timed_out: u64,
}
impl ProbeCounts {
    fn record(&mut self, succeeded: bool) {
        if succeeded {
            self.succeeded = self.succeeded.saturating_add(1);
        } else {
            self.timed_out = self.timed_out.saturating_add(1);
        }
    }

    fn add(&mut self, other: Self) {
        self.succeeded = self.succeeded.saturating_add(other.succeeded);
        self.timed_out = self.timed_out.saturating_add(other.timed_out);
    }
}
/// One retained neighbor identity. Overflow preserves counts of unsampled peers.
#[derive(Debug, Serialize)]
pub struct ProbePeer {
    pub peer: NodeId,
    pub counts: ProbeCounts,
    pub partial_window: bool,
}
/// Exact aggregate probe outcomes and bounded neighbor details; independent of graph QoS averages.
#[derive(Debug, Default, Serialize)]
pub struct ProbeSnapshot {
    pub neighbor: ProbeCounts,
    pub loopback: ProbeCounts,
    pub(crate) peers: Vec<ProbePeer>,
    pub overflow: ProbeCounts,
}
impl ProbeSnapshot {
    pub fn peers(&self) -> &[ProbePeer] {
        &self.peers
    }
}
/// Typed, bounded counters consumed by one reporter. Totals include all overflow.
#[derive(Debug, Default, Serialize)]
pub struct IntervalSnapshot {
    pub window_ms: u64,
    pub totals: PathCounts,
    pub(crate) destinations: Vec<Destination>,
    pub destinations_overflow: PathCounts,
    pub surb_totals: SurbCounts,
    pub(crate) surbs: Vec<SurbDestination>,
    pub surbs_overflow: SurbCounts,
    /// None means no probe producer has been registered, rather than zero timeouts.
    pub probes: Option<ProbeSnapshot>,
}
impl IntervalSnapshot {
    pub fn destinations(&self) -> &[Destination] {
        &self.destinations
    }

    pub fn surbs(&self) -> &[SurbDestination] {
        &self.surbs
    }
}
struct Window {
    started: Instant,
    data: IntervalSnapshot,
}
impl Default for Window {
    fn default() -> Self {
        Self {
            started: Instant::now(),
            data: IntervalSnapshot::default(),
        }
    }
}
/// A shareable producer handle. Wire it only when reporting is enabled; use one consumer per node.
#[derive(Clone, Default)]
pub struct IntervalCounters(Arc<Mutex<Window>>);
impl IntervalCounters {
    /// Register a probe producer before it starts. Idle windows then report real zeros.
    /// Without registration (or any probe observation), `probes` is null/unavailable.
    pub fn enable_probes(&self) {
        self.0.lock().data.probes.get_or_insert_with(ProbeSnapshot::default);
    }

    /// Record one completed neighbor probe: true is a received reply, false an actual timeout.
    /// Failed peers displace healthy samples; evicted observations remain in overflow.
    pub fn neighbor_probe(&self, peer: NodeId, succeeded: bool) {
        let mut window = self.0.lock();
        let probes = window.data.probes.get_or_insert_with(ProbeSnapshot::default);
        probes.neighbor.record(succeeded);
        if let Some(row) = probes.peers.iter_mut().find(|row| row.peer == peer) {
            row.counts.record(succeeded);
            return;
        }
        let partial_window = probes.peers.len() == MAX_PROBE_PEERS;
        if partial_window {
            if let Some(victim) = (!succeeded)
                .then(|| probes.peers.iter().position(|r| r.counts.timed_out == 0))
                .flatten()
            {
                let evicted = probes.peers.remove(victim);
                probes.overflow.add(evicted.counts);
            } else {
                probes.overflow.record(succeeded);
                return;
            }
        }
        let mut counts = ProbeCounts::default();
        counts.record(succeeded);
        probes.peers.push(ProbePeer {
            peer,
            counts,
            partial_window,
        });
    }

    /// Record a successful loopback return or an actual loopback expiry.
    pub fn loopback_probe(&self, succeeded: bool) {
        self.0
            .lock()
            .data
            .probes
            .get_or_insert_with(ProbeSnapshot::default)
            .loopback
            .record(succeeded);
    }

    /// Record a resolver call, including cache hits; this does not fabricate a search.
    pub fn resolution(&self, direction: Direction, destination: NodeId, succeeded: bool) {
        self.record(
            direction,
            destination,
            PathCounts {
                succeeded: u64::from(succeeded),
                failed: u64::from(!succeeded),
                ..Default::default()
            },
        );
    }

    /// Record an actual selector query, including an empty result and optional phase 2.
    pub fn search(&self, direction: Direction, destination: NodeId, outcome: SearchOutcome) {
        let p2 = outcome.phase2.unwrap_or_default();
        self.record(
            direction,
            destination,
            PathCounts {
                searches: 1,
                empty_searches: u64::from(outcome.retained == 0),
                phase1_returned: outcome.phase1.returned,
                phase1_eligible: outcome.phase1.eligible,
                phase2_runs: u64::from(outcome.phase2.is_some()),
                phase2_returned: p2.returned,
                phase2_eligible: p2.eligible,
                ..Default::default()
            },
        );
    }

    fn record(&self, direction: Direction, destination: NodeId, counts: PathCounts) {
        let mut window = self.0.lock();
        let data = &mut window.data;
        data.totals.add(counts);
        let mut index = data
            .destinations
            .iter()
            .position(|r| r.direction == direction && r.destination == destination);
        if index.is_none() {
            let partial = data.destinations.len() == MAX_DESTINATIONS;
            if partial {
                let victim = counts
                    .problematic()
                    .then(|| data.destinations.iter().position(|r| !r.counts.problematic()))
                    .flatten();
                if let Some(i) = victim {
                    let row = data.destinations.remove(i);
                    data.destinations_overflow.add(row.counts);
                } else {
                    data.destinations_overflow.add(counts);
                    return;
                }
            }
            data.destinations.push(Destination {
                direction,
                destination,
                counts: PathCounts::default(),
                partial_window: partial,
            });
            index = Some(data.destinations.len() - 1);
        }
        if let Some(i) = index {
            data.destinations[i].counts.add(counts);
        }
    }

    /// Count mint or return events independently of the graph telemetry consumer.
    pub fn surb(&self, destination: OffchainPublicKey, paths: ForwardAndReturnPath, counts: SurbCounts) {
        let mut window = self.0.lock();
        let data = &mut window.data;
        data.surb_totals.add(counts);
        let mut index = data.surbs.iter().position(|r| r.destination == destination);
        if index.is_none() {
            if data.surbs.len() == MAX_SURB_DESTINATIONS {
                data.surbs_overflow.add(counts);
                return;
            }
            data.surbs.push(SurbDestination {
                destination,
                pairs: Vec::new(),
                overflow: SurbCounts::default(),
            });
            index = Some(data.surbs.len() - 1);
        }
        if let Some(i) = index {
            let group = &mut data.surbs[i];
            if let Some(row) = group
                .pairs
                .iter_mut()
                .find(|r| r.forward == paths.forward && r.reply == paths.reply)
            {
                row.counts.add(counts);
            } else if group.pairs.len() < MAX_SURB_PAIRS {
                group.pairs.push(SurbPair {
                    forward: paths.forward,
                    reply: paths.reply,
                    counts,
                });
            } else {
                group.overflow.add(counts);
            }
        }
    }

    /// Atomically take/reset only these counters. No graph, routing cache, or SURB state is touched.
    pub fn take_snapshot(&self) -> IntervalSnapshot {
        let mut guard = self.0.lock();
        let probes_enabled = guard.data.probes.is_some();
        let mut w = std::mem::take(&mut *guard);
        if probes_enabled {
            guard.data.probes = Some(ProbeSnapshot::default());
        }
        w.data.window_ms = w.started.elapsed().as_millis().min(u64::MAX as u128) as u64;
        w.data
    }
}
