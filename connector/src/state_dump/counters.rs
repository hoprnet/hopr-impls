//! Bounded inputs recorded at routing/SURB producers. This module knows no transport implementation.
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

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
    /// Observations may be in overflow after replacement or lock contention.
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
/// Events recorded while another thread held the window lock. Path resolutions and SURB mints run on
/// the packet path, so a routine success never waits for the lock: it is counted here and added to the
/// totals and the overflow when the window is taken.
#[derive(Default)]
struct Busy {
    resolutions: AtomicU64,
    minted: AtomicU64,
    returned: AtomicU64,
}

#[derive(Default)]
struct Shared {
    window: Mutex<Window>,
    busy: Busy,
}

/// A shareable producer handle. Wire it only when reporting is enabled; use one consumer per node.
#[derive(Clone, Default)]
pub struct IntervalCounters(Arc<Shared>);
impl IntervalCounters {
    /// Register a probe producer before it starts. Idle windows then report real zeros.
    /// Without registration (or any probe observation), `probes` is null/unavailable.
    pub fn enable_probes(&self) {
        self.0
            .window
            .lock()
            .data
            .probes
            .get_or_insert_with(ProbeSnapshot::default);
    }

    /// Record one completed neighbor probe: true is a received reply, false an actual timeout.
    /// Failed peers displace healthy samples; evicted observations remain in overflow.
    pub fn neighbor_probe(&self, peer: NodeId, succeeded: bool) {
        let mut window = self.0.window.lock();
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
            .window
            .lock()
            .data
            .probes
            .get_or_insert_with(ProbeSnapshot::default)
            .loopback
            .record(succeeded);
    }

    /// Record a resolver call, including cache hits; this does not fabricate a search.
    ///
    /// A success never waits for the lock: when another thread holds it, the success is only counted
    /// in the totals and the overflow. A failure always reaches its destination row.
    pub fn resolution(&self, direction: Direction, destination: NodeId, succeeded: bool) {
        let counts = PathCounts {
            succeeded: u64::from(succeeded),
            failed: u64::from(!succeeded),
            ..Default::default()
        };
        if !succeeded {
            self.record(direction, destination, counts);
        } else if let Some(mut window) = self.0.window.try_lock() {
            record_path(&mut window.data, direction, destination, counts);
        } else {
            self.0.busy.resolutions.fetch_add(1, Ordering::Relaxed);
        }
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
        record_path(&mut self.0.window.lock().data, direction, destination, counts);
    }

    /// Count mint or return events independently of the graph telemetry consumer. This never waits
    /// for the lock: when another thread holds it, the events are only counted in the totals and the
    /// overflow.
    pub fn surb(&self, destination: OffchainPublicKey, paths: ForwardAndReturnPath, counts: SurbCounts) {
        if let Some(mut window) = self.0.window.try_lock() {
            record_surb(&mut window.data, destination, paths, counts);
        } else {
            self.0.busy.minted.fetch_add(counts.minted, Ordering::Relaxed);
            self.0.busy.returned.fetch_add(counts.returned, Ordering::Relaxed);
        }
    }

    /// Atomically take/reset only these counters. No graph, routing cache, or SURB state is touched.
    pub fn take_snapshot(&self) -> IntervalSnapshot {
        let mut guard = self.0.window.lock();
        let probes_enabled = guard.data.probes.is_some();
        let mut w = std::mem::take(&mut *guard);
        if probes_enabled {
            guard.data.probes = Some(ProbeSnapshot::default());
        }
        // Taken under the lock, so an event counted after this belongs to the next window.
        let busy = PathCounts {
            succeeded: self.0.busy.resolutions.swap(0, Ordering::Relaxed),
            ..Default::default()
        };
        if busy.succeeded > 0 {
            // Busy successes have no identity, so every named destination may be affected.
            for row in &mut w.data.destinations {
                row.partial_window = true;
            }
        }
        w.data.totals.add(busy);
        w.data.destinations_overflow.add(busy);
        let busy = SurbCounts {
            minted: self.0.busy.minted.swap(0, Ordering::Relaxed),
            returned: self.0.busy.returned.swap(0, Ordering::Relaxed),
        };
        w.data.surb_totals.add(busy);
        w.data.surbs_overflow.add(busy);
        w.data.window_ms = w.started.elapsed().as_millis().min(u64::MAX as u128) as u64;
        w.data
    }
}

fn record_path(data: &mut IntervalSnapshot, direction: Direction, destination: NodeId, counts: PathCounts) {
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

fn record_surb(
    data: &mut IntervalSnapshot,
    destination: OffchainPublicKey,
    paths: ForwardAndReturnPath,
    counts: SurbCounts,
) {
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

/// Use a separate handle/reporter for each producer module. Reading drains only this handle's window.
impl hopr_state_dump::StateDump for IntervalCounters {
    type State = IntervalSnapshot;
    async fn state_dump(&self) -> Result<hopr_state_dump::Dump<Self::State>, String> {
        let state = self.take_snapshot();
        let problematic = state.totals.problematic()
            || state
                .probes
                .as_ref()
                .is_some_and(|p| p.neighbor.timed_out > 0 || p.loopback.timed_out > 0);
        Ok(hopr_state_dump::Dump {
            state,
            signal: if problematic {
                hopr_state_dump::Signal::NeedsAnalysis
            } else {
                hopr_state_dump::Signal::Healthy
            },
            reason: if problematic {
                "routing_or_probe_failures"
            } else {
                "producer_window_ok"
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use hopr_api::types::{
        crypto::prelude::{Keypair, OffchainKeypair},
        primitive::prelude::Address,
    };

    use super::*;

    #[test]
    fn a_success_never_waits_for_the_window_lock() -> anyhow::Result<()> {
        let counters = IntervalCounters::default();
        let destination = NodeId::Chain(Address::from([1; 20]));
        let surb_destination = *OffchainKeypair::from_secret(&[1; 32])?.public();
        let paths = ForwardAndReturnPath {
            forward: [1; 5],
            reply: [2; 5],
        };
        {
            // Held as if the reporter were taking the window: these calls must return at once.
            let _held = counters.0.window.lock();
            counters.resolution(Direction::Forward, destination, true);
            counters.surb(surb_destination, paths, SurbCounts { minted: 2, returned: 1 });
        }
        counters.resolution(Direction::Forward, destination, false);

        let snapshot = counters.take_snapshot();
        assert_eq!((snapshot.totals.succeeded, snapshot.totals.failed), (1, 1));
        assert_eq!(
            snapshot.destinations_overflow.succeeded, 1,
            "the busy success is counted, not lost"
        );
        assert_eq!(
            snapshot.destinations()[0].counts.failed,
            1,
            "a failure always reaches its row"
        );
        assert!(snapshot.destinations()[0].partial_window);
        assert_eq!((snapshot.surb_totals.minted, snapshot.surb_totals.returned), (2, 1));
        assert_eq!(snapshot.surbs_overflow.minted, 2);

        let next = counters.take_snapshot();
        assert!(next.destinations().is_empty());
        assert_eq!(next.totals.succeeded, 0, "busy counts belong to one window only");
        Ok(())
    }
}
