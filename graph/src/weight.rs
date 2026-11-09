use hopr_api::graph::{
    EdgeImmediateProtocolObservable, EdgeLinkObservable,
    traits::{
        EdgeNetworkObservableRead, EdgeObservableRead, EdgeObservableWrite, EdgeProtocolObservable,
        EdgeTransportMeasurement, EdgeWeightType,
    },
};
use hopr_utils::statistics::{ExponentialMovingAverage, WindowedRatio};

/// A representation of a individual neighbor link measurement
#[derive(Debug, Copy, Clone, Default, PartialEq)]
pub struct TransportLinkMeasurement {
    /// `None` until a probe has succeeded. The average cannot express "no samples yet" on its own —
    /// an untouched EMA reads `0.0`, which is also a legitimate measured latency — so absence is
    /// carried by the `Option` rather than by a parallel counter that could disagree with it.
    latency_average: Option<ExponentialMovingAverage<3>>,
    probe_success_rate: ExponentialMovingAverage<5>,
    /// Recorded probe outcomes, successful or not. The EMA cannot express "no samples yet":
    /// an all-failed stream holds exactly `0.0`, the same as its initial value.
    samples: u64,
}

impl TransportLinkMeasurement {
    /// A success that carries no timing: counts toward the rate and leaves the latency average alone.
    fn credit(&mut self) {
        self.samples = self.samples.saturating_add(1);
        self.probe_success_rate.update(1.0);
    }
}

impl EdgeLinkObservable for TransportLinkMeasurement {
    fn record(&mut self, measurement: EdgeTransportMeasurement) {
        self.samples = self.samples.saturating_add(1);
        if let Ok(latency) = measurement {
            // Sub-millisecond resolution: the intermediate latency is a `saturating_sub` residual
            // that legitimately lands at or near zero, and truncating it to whole milliseconds
            // would store `0` — read back as "never measured" and scored as such.
            self.latency_average
                .get_or_insert_default()
                .update(latency.as_secs_f64() * 1000.0);
            self.probe_success_rate.update(1.0);
        } else {
            self.probe_success_rate.update(0.0);
        }
    }

    /// `None` until a probe has succeeded. Presence, not magnitude: a measured zero is a real
    /// latency and must not read as an absent one.
    fn average_latency(&self) -> Option<std::time::Duration> {
        self.latency_average
            .map(|avg| std::time::Duration::from_secs_f64(avg.get().max(0.0) / 1000.0))
    }

    fn average_probe_rate(&self) -> Option<f64> {
        (self.samples > 0).then(|| self.probe_success_rate.get())
    }

    /// `None` until a probe has been recorded; `Some(0.0)` once measured and found unusable.
    fn score(&self) -> Option<f64> {
        self.average_probe_rate()
            .map(|rate| rate * self.average_latency().map_or(NO_LATENCY_DATA_FLOOR, latency_score))
    }
}

/// What a *measured* latency is worth. The lower the latency, the more useful the link.
///
/// Takes a `Duration` rather than an `Option` deliberately. What the absence of a latency costs is
/// the caller's decision, not this function's: a link that was probed and never answered has earned
/// [`NO_LATENCY_DATA_FLOOR`], while an edge known only from SURB round-trips has no latency to
/// report *by construction* and must not be charged for it.
const fn latency_score(latency: std::time::Duration) -> f64 {
    match latency.as_millis() {
        0..=75 => 1.0,
        76..=125 => 0.7,
        126..=200 => 0.3,
        _ => 0.15,
    }
}

/// Latency factor for a link whose probes produced no timing at all.
const NO_LATENCY_DATA_FLOOR: f64 = 0.05;

/// Observations related to a specific peer in the network.
#[derive(Debug, Copy, Clone, Default, PartialEq)]
pub struct Observations {
    last_update: std::time::Duration,
    immediate_probe: Option<TransportImmediates>,
    intermediate_probe: Option<TransportIntermediates>,
    /// Health of the edge's destination as a relayer; `None` is not judged.
    health: Option<f64>,
}

impl Observations {
    pub(crate) fn set_health(&mut self, health: Option<f64>) {
        self.health = health;
    }

    /// Credits a returned loopback to this edge without a latency; see [`TransportIntermediates::credit_loopback`].
    pub(crate) fn credit_loopback(&mut self) {
        self.last_update = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        self.intermediate_probe.get_or_insert_default().credit_loopback();
        self.restamp_starved();
    }

    /// The neighbour ping reads the verdict of the edge's loopback stream; see `relay_starved_at`.
    fn restamp_starved(&mut self) {
        let now = std::time::Instant::now();
        if let Some(immediate) = self.immediate_probe.as_mut() {
            immediate.relay_starved_at = self
                .intermediate_probe
                .is_some_and(|i| i.relay_starved_at(now))
                .then_some(now);
        }
    }
}

impl EdgeObservableWrite for Observations {
    #[tracing::instrument(level = "trace", skip(self), name = "record_observation")]
    fn record(&mut self, measurement: EdgeWeightType) {
        self.last_update = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();

        match measurement {
            EdgeWeightType::Immediate(result) => self.immediate_probe.get_or_insert_default().record(result),
            EdgeWeightType::Intermediate(result) => self.intermediate_probe.get_or_insert_default().record(result),
            EdgeWeightType::Balance(balance) => self.intermediate_probe.get_or_insert_default().balance = balance,
            EdgeWeightType::Connected(is_connected) => {
                self.immediate_probe.get_or_insert_default().is_connected = Some(is_connected)
            }
            EdgeWeightType::SurbRoundTrips { expected, observed } => {
                self.intermediate_probe
                    .get_or_insert_default()
                    .record_surb_round_trips(expected, observed);
            }
            EdgeWeightType::ImmediateProtocolConformance { num_packets, num_acks } => {
                let imm = self.immediate_probe.get_or_insert_default();
                // Decay before accumulating; see ACK_DECAY.
                imm.messages_sent = imm.messages_sent * ACK_DECAY + num_packets as f64;
                imm.acks_received = imm.acks_received * ACK_DECAY + num_acks as f64;
            }
        }

        self.restamp_starved();
    }
}

/// Fraction of the accumulated acknowledgement counts retained per conformance report.
///
/// The producer reports increments, so accumulating verbatim gives a *lifetime* ratio: a peer that
/// behaved for a month then went dark stays admissible for as long again. Decaying bounds that
/// memory. Decaying the two totals — rather than averaging per-report ratios — keeps the estimate
/// weighted by traffic volume.
const ACK_DECAY: f64 = 0.9;

/// Minimum decayed packet volume before an acknowledgement rate is reported.
///
/// Below this the ratio is just the remnant of a handful of packets. Reporting `None` lets the
/// value function apply its unobserved-edge penalty instead of acting on noise.
const MIN_ACK_SAMPLE_VOLUME: f64 = 1.0;

#[derive(Debug, Copy, Clone, Default, PartialEq)]
pub struct TransportImmediates {
    link: TransportLinkMeasurement,
    /// `None` until connectivity is actually observed: an ack-conformance report creates this
    /// stream without saying anything about reachability.
    is_connected: Option<bool>,
    /// Exponentially decayed count of packets sent to this peer.
    messages_sent: f64,
    /// Exponentially decayed count of acknowledgements received from this peer.
    acks_received: f64,
    /// When the edge's intermediate stream last showed that the relay at its end delivers nothing.
    ///
    /// The neighbour answers pings whatever it does with relayed packets, so this stream's latency says
    /// nothing about a relay that is starved. The stream cannot see the other one, so the edge stamps
    /// the verdict here on every record, and it lapses with the window it was read from.
    relay_starved_at: Option<std::time::Instant>,
}

impl TransportImmediates {
    fn relay_starved(&self) -> bool {
        self.relay_starved_at.is_some_and(|at| at.elapsed() < LOOPBACK_WINDOW)
    }
}

impl EdgeNetworkObservableRead for TransportImmediates {
    fn is_connected(&self) -> Option<bool> {
        self.is_connected
    }
}

impl EdgeImmediateProtocolObservable for TransportImmediates {
    fn ack_rate(&self) -> Option<f64> {
        (self.messages_sent >= MIN_ACK_SAMPLE_VOLUME).then(|| (self.acks_received / self.messages_sent).clamp(0.0, 1.0))
    }
}

impl EdgeLinkObservable for TransportImmediates {
    fn record(&mut self, measurement: EdgeTransportMeasurement) {
        self.link.record(measurement)
    }

    /// Withheld while the relay at the end of the edge is starved: a ping answered by a relay that drops
    /// everything it should forward is not its latency.
    fn average_latency(&self) -> Option<std::time::Duration> {
        if self.relay_starved() {
            return None;
        }
        self.link.average_latency()
    }

    fn average_probe_rate(&self) -> Option<f64> {
        self.link.average_probe_rate()
    }

    fn score(&self) -> Option<f64> {
        self.link.score()
    }
}

/// Slice width and count for the SURB round-trip window.
///
/// 24 s of history in two-second slices. Still far above any plausible round-trip, so a reply is
/// nearly always counted in a slice that is still inside the window.
///
/// Narrowed from five-second slices rather than widened to more of them: the recent window has to
/// register a collapse inside the recovery budget, and adding slices grows a `Copy` type that is
/// read per edge during path search (30 slices measured 752 B against 320). Narrowing keeps the
/// footprint identical and preserves the contrast ratio exactly -- the recent window was 1/6 of
/// the baseline at 10 s of 60 s, and is 1/6 of it at 4 s of 24 s -- while reacting 2.5x sooner.
const SURB_BUCKET_WIDTH: std::time::Duration = std::time::Duration::from_secs(2);
const SURB_BUCKETS: usize = 12;

/// Span the SURB window covers, i.e. how far back delivery evidence is still counted.
pub(crate) const fn surb_window() -> std::time::Duration {
    std::time::Duration::from_secs(SURB_BUCKET_WIDTH.as_secs() * SURB_BUCKETS as u64)
}

/// Slices read as "lately" when looking for a sudden change: 4 s against the 24 s window.
///
/// Two rather than one so a single slice that happens to straddle a lull cannot, on its own, brand
/// a working relay as gone.
const SURB_RECENT_SLICES: usize = 2;

/// How far the recent slices must fall below the full window before it counts as a collapse.
///
/// A ratio, not an absolute level, so it is unaffected by the balancer surplus that makes the
/// absolute figure meaningless. At 0.5 the last 4 s must be delivering at less than half the rate
/// the whole window did before anything is inferred -- ordinary variance stays well inside that.
const SURB_TREND_FLOOR: f64 = 0.5;

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct TransportIntermediates {
    link: TransportLinkMeasurement,
    /// Remaining channel balance in base currency units, as reported by the chain indexer.
    balance: Option<hopr_api::graph::traits::Balance>,
    /// Delivery observed from real SURB traffic rather than from probes.
    surb: WindowedRatio<SURB_BUCKETS>,
    /// Highest delivery ratio this edge has reached, and when it was last raised.
    ///
    /// The absolute ratio is not a delivery rate: `expected` counts SURBs *minted*, and the
    /// balancer mints far more than the counterparty spends, so a path carrying every reply
    /// intact still measures well below 1. Measured on a cluster, a fully healthy path reads 0.36.
    /// The surplus is a property of the balancer, not of the path, so it applies alike to every
    /// candidate and cancels the moment the ratio is read against a baseline instead of an
    /// absolute scale.
    ///
    /// One `Option` rather than a value plus a timestamp, because the timestamp means nothing
    /// without a peak to date it. Decays rather than latching: see [`Self::peak_at`].
    surb_peak: Option<SurbPeak>,
    /// Loopbacks over this edge that returned, against all of them, over the last 60 s.
    loopback: LoopbackWindow,
}

/// A delivery-ratio peak and the instant it was set, which the decay is measured from.
#[derive(Debug, Copy, Clone, PartialEq)]
struct SurbPeak {
    value: f64,
    at: std::time::Instant,
}

/// Width of one loopback bucket.
const LOOPBACK_BUCKET_WIDTH: std::time::Duration = std::time::Duration::from_secs(5);
/// Buckets in the loopback window: 60 s of evidence.
///
/// Loops are sent once per probing round, 30 s by default, and a lost one is recorded after the 3 s
/// probe timeout. The window has to span more than one round, or the evidence is gone for most of
/// the time between rounds. Two rounds is the shortest span that bridges the gap with room for a
/// late round; a longer one only delays noticing that a relay stopped returning, because the last
/// good loop stays counted until it expires.
const LOOPBACK_BUCKETS: usize = 12;

/// How far back loopback outcomes over an edge are still counted.
///
/// The probing interval must stay well inside it: a loop is sent once per round, so with a longer
/// interval the evidence expires between rounds and a failing relay reads as unprobed instead of
/// dead. The loopback generator's own configuration is checked against it.
pub const LOOPBACK_WINDOW: std::time::Duration =
    std::time::Duration::from_secs(LOOPBACK_BUCKET_WIDTH.as_secs() * LOOPBACK_BUCKETS as u64);

/// One bucket of loopback outcomes over an edge, tagged with which bucket of time it is.
#[derive(Debug, Copy, Clone, Default, PartialEq)]
struct LoopbackBucket {
    slot: u64,
    sent: u32,
    returned: u32,
}

/// Loopbacks over an edge that returned, against all of them, over the last 60 s.
///
/// Every loop that crosses the edge counts once, as returned or as failed, so the ratio is
/// returned over returned plus failed. A window rather than a moving average: a relay none of whose
/// loops returned reads as exactly zero, and anything above zero is a relay that carries traffic.
/// A single loop is evidence, since an edge may see only one per probing round.
#[derive(Debug, Copy, Clone, PartialEq)]
struct LoopbackWindow {
    epoch: std::time::Instant,
    buckets: [LoopbackBucket; LOOPBACK_BUCKETS],
}

impl LoopbackWindow {
    fn new(epoch: std::time::Instant) -> Self {
        Self {
            epoch,
            buckets: [LoopbackBucket::default(); LOOPBACK_BUCKETS],
        }
    }

    fn slot_of(&self, now: std::time::Instant) -> u64 {
        now.saturating_duration_since(self.epoch).as_secs() / LOOPBACK_BUCKET_WIDTH.as_secs()
    }

    fn record_at(&mut self, returned: bool, now: std::time::Instant) {
        let slot = self.slot_of(now);
        let bucket = &mut self.buckets[(slot % LOOPBACK_BUCKETS as u64) as usize];
        // The bucket belongs to an earlier lap of the ring: its outcomes are out of the window.
        if bucket.slot != slot {
            *bucket = LoopbackBucket {
                slot,
                ..LoopbackBucket::default()
            };
        }
        bucket.sent = bucket.sent.saturating_add(1);
        if returned {
            bucket.returned = bucket.returned.saturating_add(1);
        }
    }

    /// `None` when no loopback crossed the edge in the window.
    fn rate_at(&self, now: std::time::Instant) -> Option<f64> {
        let current = self.slot_of(now);
        let (sent, returned) = self
            .buckets
            .iter()
            .filter(|bucket| {
                bucket.sent > 0 && bucket.slot <= current && bucket.slot + LOOPBACK_BUCKETS as u64 > current
            })
            .fold((0u32, 0u32), |(sent, returned), bucket| {
                (
                    sent.saturating_add(bucket.sent),
                    returned.saturating_add(bucket.returned),
                )
            });

        (sent > 0).then(|| f64::from(returned) / f64::from(sent))
    }
}

impl Default for TransportIntermediates {
    fn default() -> Self {
        let now = std::time::Instant::now();

        Self {
            link: TransportLinkMeasurement::default(),
            balance: None,
            surb: WindowedRatio::new(SURB_BUCKET_WIDTH, now),
            surb_peak: None,
            loopback: LoopbackWindow::new(now),
        }
    }
}

impl TransportIntermediates {
    /// Whether the relay at the end of this edge delivers, or `None` without evidence.
    ///
    /// Traffic decides where any crossed the edge: it says more than probing does, and probing is
    /// only needed where none did. Without traffic the loopbacks decide. Starved means the evidence
    /// reads exactly zero, so a single returned packet or loop keeps the relay.
    pub(crate) fn delivers_at(&self, now: std::time::Instant) -> Option<bool> {
        self.traffic_rate_at(now)
            .or_else(|| self.loopback_rate_at(now))
            .map(|rate| rate > 0.0)
    }

    /// Whether the evidence says that the relay at the end of this edge delivers nothing.
    pub(crate) fn relay_starved_at(&self, now: std::time::Instant) -> bool {
        self.delivers_at(now) == Some(false)
    }

    /// [`EdgeLinkObservable::average_probe_rate`] against a caller-supplied clock.
    pub(crate) fn average_probe_rate_at(&self, now: std::time::Instant) -> Option<f64> {
        self.surb_delivery_rate_at(now)
            .or_else(|| self.link.average_probe_rate())
    }

    /// The score of an edge whose relay is not starved, against a caller-supplied clock.
    ///
    /// Split from [`EdgeLinkObservable::score`] so a caller that has just read the verdict does not
    /// read it again for every metric: it is the costliest part of a score, and scores are read per
    /// edge during path search.
    pub(crate) fn live_score_at(&self, now: std::time::Instant) -> Option<f64> {
        // `average_probe_rate` already averages the probe and SURB signals over whichever carry
        // evidence, and reports `None` when neither does.
        //
        // Latency modulates that rate only where it was measured. A round-trip proves the loop was
        // traversed but carries no per-edge latency, so an edge known solely from SURB delivery has
        // a rate and no latency. Scoring the missing latency as [`latency_score`] does — 0.05, the
        // no-data floor — would multiply real delivery evidence by a twentieth and rank the edge
        // below one nothing at all is known about, inverting the very ordering the score exists to
        // express.
        let rate = self.average_probe_rate_at(now)?;
        Some(
            self.link
                .average_latency()
                .map_or(rate, |latency| rate * latency_score(latency)),
        )
    }

    /// The share of loopbacks over this edge that returned in the last [`LOOPBACK_WINDOW`], or `None`
    /// without any. `Some(0.0)` means loops crossed it and none returned.
    pub fn loopback_rate(&self) -> Option<f64> {
        self.loopback_rate_at(std::time::Instant::now())
    }

    /// [`Self::loopback_rate`] against a caller-supplied clock.
    pub(crate) fn loopback_rate_at(&self, now: std::time::Instant) -> Option<f64> {
        self.loopback.rate_at(now)
    }

    /// How real traffic over this edge is coming back, relative to its own best, or `None` without
    /// traffic. Same as [`Self::surb_delivery_rate`].
    pub fn traffic_rate(&self) -> Option<f64> {
        self.traffic_rate_at(std::time::Instant::now())
    }

    /// [`Self::traffic_rate`] against a caller-supplied clock.
    pub(crate) fn traffic_rate_at(&self, now: std::time::Instant) -> Option<f64> {
        self.surb_delivery_rate_at(now)
    }

    /// Folds one reporting interval of SURB round-trips into the window.
    pub(crate) fn record_surb_round_trips(&mut self, expected: u64, observed: u64) {
        self.record_surb_round_trips_at(expected, observed, std::time::Instant::now())
    }

    /// [`Self::record_surb_round_trips`] against a caller-supplied clock.
    pub(crate) fn record_surb_round_trips_at(&mut self, expected: u64, observed: u64, now: std::time::Instant) {
        self.surb.record_expected(expected, now);
        self.surb.record_observed(observed, now);

        if let Some(v) = self.surb.value(now) {
            self.surb_peak = Some(SurbPeak {
                value: self.peak_at(now).unwrap_or(0.0).max(v),
                at: now,
            });
        }
    }

    /// The baseline as it stands at `now`, having decayed since it was last raised.
    ///
    /// The peak has to forget. `expected` counts SURBs *minted*, and the balancer's surplus over
    /// what the counterparty spends is not constant; when it is briefly small the absolute ratio
    /// spikes. A peak that only ever rose would latch onto that spike, and from then on every
    /// ordinary interval would be divided by a level the edge cannot reach again -- an edge
    /// delivering every reply would read well below 1 forever, and would lose to edges whose peak
    /// happened to be set under worse minting conditions. That is a comparison between each path
    /// and its luckiest interval rather than between paths.
    ///
    /// The half-life is the window itself, so the baseline forgets a lucky interval at the same
    /// rate the window forgets the traffic that produced it. A steadily delivering edge re-raises
    /// the peak to its own value on every report, so decay costs it nothing.
    fn peak_at(&self, now: std::time::Instant) -> Option<f64> {
        let peak = self.surb_peak?;
        let half_lives = now.saturating_duration_since(peak.at).as_secs_f64() / self.surb.window().as_secs_f64();

        Some(peak.value * 0.5f64.powf(half_lives))
    }

    /// How the most recent slices compare with the full window, or `None` without evidence in both.
    ///
    /// Below 1 means delivery has fallen off lately. The comparison is what makes this usable: the
    /// full window alone dilutes a fresh collapse across the whole window of healthy history, and
    /// the recent slices alone rest on too little evidence to accuse a relay by themselves.
    pub fn surb_trend(&self) -> Option<f64> {
        self.surb_trend_at(std::time::Instant::now())
    }

    /// [`Self::surb_trend`] against a caller-supplied clock.
    pub(crate) fn surb_trend_at(&self, now: std::time::Instant) -> Option<f64> {
        let full = self.surb.value(now)?;
        let recent = self.surb.recent_value(SURB_RECENT_SLICES, now)?;

        (full > 0.0).then(|| (recent / full).clamp(0.0, 1.0))
    }

    /// How this edge is delivering relative to its own best, or `None` without traffic.
    ///
    /// Relative, because the absolute ratio measures the balancer's surplus as much as the path
    /// (see the peak this is read against). Against its own peak a healthy edge reads ~1 whatever the
    /// surplus, and one that stops delivering falls toward 0 -- which is the only thing this
    /// signal is asked to say.
    pub fn surb_delivery_rate(&self) -> Option<f64> {
        self.surb_delivery_rate_at(std::time::Instant::now())
    }

    /// [`Self::surb_delivery_rate`] against a caller-supplied clock.
    pub(crate) fn surb_delivery_rate_at(&self, now: std::time::Instant) -> Option<f64> {
        let value = self.surb.value(now)?;
        let peak = self.peak_at(now)?;
        // SURBs minted over the edge and none ever returned: there is no baseline to compare with,
        // and that absence is the evidence. Reading it as "no evidence" let a relay that drops
        // everything keep a full score (hopr-impls#81). The first returned SURB lifts the peak.
        if peak <= 0.0 {
            return (value <= 0.0).then_some(0.0);
        }
        let against_peak = (value / peak).clamp(0.0, 1.0);

        // A relay that has just stopped delivering still reads well against its peak for most of
        // the window, because eleven healthy slices outvote the one bad one. Folding the trend in
        // makes that visible within a slice or two -- deliberately as a soft discount rather than a
        // gate, so a relay is displaced by better-scoring peers rather than excluded outright.
        Some(match self.surb_trend_at(now) {
            Some(trend) if trend < SURB_TREND_FLOOR => against_peak * trend,
            _ => against_peak,
        })
    }
}

impl EdgeProtocolObservable for TransportIntermediates {
    fn balance(&self) -> Option<hopr_api::graph::traits::Balance> {
        self.balance
    }
}

impl TransportIntermediates {
    /// A loop that returned over this edge. The edge was not timed on its own, so only the rates move:
    /// writing the latency it already carries back would pin a stale value, and a loop's round trip
    /// cannot be split between its edges.
    fn credit_loopback(&mut self) {
        self.loopback.record_at(true, std::time::Instant::now());
        self.link.credit();
    }
}

impl EdgeLinkObservable for TransportIntermediates {
    fn record(&mut self, measurement: EdgeTransportMeasurement) {
        self.loopback.record_at(measurement.is_ok(), std::time::Instant::now());
        self.link.record(measurement);
    }

    fn average_latency(&self) -> Option<std::time::Duration> {
        if self.relay_starved_at(std::time::Instant::now()) {
            return None;
        }
        self.link.average_latency()
    }

    /// The SURB delivery rate where traffic crossed the edge, else the probe rate.
    ///
    /// Traffic comes first: it reacts at data rates where probing runs on an interval, and it says more
    /// about the loop than a probe does, so probing is only needed where no traffic went through. Once
    /// the traffic stops, its window empties and the probes speak again.
    ///
    /// Evidence, not merely a number: an unprobed edge's probe rate reads `None`, not `0.0`, so a
    /// SURB-only edge is not scored as dead.
    fn average_probe_rate(&self) -> Option<f64> {
        self.average_probe_rate_at(std::time::Instant::now())
    }

    fn score(&self) -> Option<f64> {
        let now = std::time::Instant::now();
        if self.relay_starved_at(now) {
            return Some(0.0);
        }
        self.live_score_at(now)
    }
}

impl EdgeObservableRead for Observations {
    type ImmediateMeasurement = TransportImmediates;
    type IntermediateMeasurement = TransportIntermediates;

    #[inline]
    fn last_update(&self) -> std::time::Duration {
        self.last_update
    }

    fn immediate_qos(&self) -> Option<&Self::ImmediateMeasurement> {
        self.immediate_probe.as_ref()
    }

    fn intermediate_qos(&self) -> Option<&Self::IntermediateMeasurement> {
        self.intermediate_probe.as_ref()
    }

    fn health(&self) -> Option<f64> {
        self.health
    }

    /// Combines the two streams per RFC-0014 §4.2: average when both are present, else the single
    /// present one, else `0.0`.
    ///
    /// "Present" means *has observations*, not *allocated* — a `Balance` update creates the
    /// intermediate stream and `Connected` the immediate one without recording a probe. Treating
    /// allocation as presence averaged against a phantom zero, halving every edge only one stream
    /// can observe: every edge incident to `me`, since immediate probes touch only those and
    /// loopback attribution targets `edges[len - 2]`.
    ///
    /// An edge whose relay is starved scores `0.0` outright: the neighbour's healthy ping must not
    /// average it up to half.
    fn score(&self) -> Option<f64> {
        let now = std::time::Instant::now();
        if self.intermediate_probe.is_some_and(|i| i.relay_starved_at(now)) {
            return Some(0.0);
        }

        // Not starved, as just read, so the stream scores itself without reading the verdict again.
        let immediate = self.immediate_probe.and_then(|m| m.score());
        let intermediate = self.intermediate_probe.and_then(|m| m.live_score_at(now));

        match (immediate, intermediate) {
            (Some(immediate), Some(intermediate)) => Some((immediate + intermediate) / 2.0),
            (Some(only), None) | (None, Some(only)) => Some(only),
            (None, None) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Context;
    use assertables::{assert_gt, assert_in_delta, assert_lt};

    use super::*;

    #[test]
    fn observations_should_update_the_timestamp_on_latency_update() {
        let mut observation = Observations::default();

        assert_eq!(observation.last_update, std::time::Duration::default());

        observation.record(EdgeWeightType::Immediate(Ok(std::time::Duration::from_millis(50))));

        std::thread::sleep(std::time::Duration::from_millis(10));

        let after = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();

        assert_gt!(observation.last_update, std::time::Duration::default());
        assert_lt!(observation.last_update, after);
    }

    #[test]
    fn observations_should_store_an_average_latency_value_after_multiple_updates() -> anyhow::Result<()> {
        let big_latency = std::time::Duration::from_millis(300);
        let small_latency = std::time::Duration::from_millis(10);

        let mut observation = Observations::default();

        for _ in 0..10 {
            observation.record(EdgeWeightType::Immediate(Ok(small_latency)));
        }

        assert_eq!(
            observation
                .immediate_qos()
                .ok_or_else(|| anyhow::anyhow!("should contain a value"))?
                .average_latency()
                .context("should contain a value")?,
            small_latency
        );

        observation.record(EdgeWeightType::Immediate(Ok(big_latency)));

        assert_gt!(
            observation
                .immediate_qos()
                .ok_or_else(|| anyhow::anyhow!("should contain a value"))?
                .average_latency()
                .context("should contain a value")?,
            small_latency
        );
        assert_lt!(
            observation
                .immediate_qos()
                .ok_or_else(|| anyhow::anyhow!("should contain a value"))?
                .average_latency()
                .context("should contain a value")?,
            big_latency
        );

        Ok(())
    }

    #[test]
    fn ack_rate_should_be_none_when_no_messages_sent() -> anyhow::Result<()> {
        let mut observation = Observations::default();
        observation.record(EdgeWeightType::Connected(true));

        let imm = observation.immediate_qos().context("should have immediate QoS")?;
        assert_eq!(imm.ack_rate(), None);
        Ok(())
    }

    #[test]
    fn ack_rate_should_be_one_when_all_messages_acked() -> anyhow::Result<()> {
        let mut observation = Observations::default();
        observation.record(EdgeWeightType::ImmediateProtocolConformance {
            num_packets: 10,
            num_acks: 10,
        });

        let imm = observation.immediate_qos().context("should have immediate QoS")?;
        assert_eq!(imm.ack_rate(), Some(1.0));
        Ok(())
    }

    #[test]
    fn ack_rate_should_reflect_partial_acknowledgment() -> anyhow::Result<()> {
        let mut observation = Observations::default();
        observation.record(EdgeWeightType::ImmediateProtocolConformance {
            num_packets: 10,
            num_acks: 7,
        });

        let imm = observation.immediate_qos().context("should have immediate QoS")?;
        let rate = imm.ack_rate().context("should have ack rate")?;
        assert_in_delta!(rate, 0.7, 0.001);
        Ok(())
    }

    #[test]
    fn ack_rate_should_weight_recent_reports_above_older_ones() -> anyhow::Result<()> {
        // The producer reports increments per flush, so verbatim accumulation would give a
        // lifetime ratio. Decaying first means an equal-sized bad window pulls the rate below the
        // arithmetic mean of the two windows.
        let mut observation = Observations::default();
        observation.record(EdgeWeightType::ImmediateProtocolConformance {
            num_packets: 5,
            num_acks: 5,
        });
        observation.record(EdgeWeightType::ImmediateProtocolConformance {
            num_packets: 5,
            num_acks: 0,
        });

        let imm = observation.immediate_qos().context("should have immediate QoS")?;
        let rate = imm.ack_rate().context("should have ack rate")?;
        assert_lt!(
            rate,
            0.5,
            "the more recent all-failed window must outweigh the older all-acked one"
        );
        assert_gt!(rate, 0.4, "one bad window must not erase the history entirely");
        Ok(())
    }

    #[test]
    fn ack_rate_demotion_should_not_depend_on_how_long_the_peer_behaved() -> anyhow::Result<()> {
        // Regression guard for the lifetime-ratio bug. Accumulating the producer's per-flush
        // increments verbatim makes demotion proportional to history: a peer that acknowledged
        // reliably for twice as long stays above the admission threshold for twice as long.
        // Decaying first bounds it — the rate saturates, so the number of silent windows needed is
        // the same no matter how much good history preceded them.
        const DEFAULT_MIN_ACK_RATE: f64 = 0.1;

        /// Reports `good_windows` fully-acked flushes, then counts how many silent flushes are
        /// needed before the rate drops below the admission threshold.
        fn windows_to_demote(good_windows: usize) -> anyhow::Result<usize> {
            let mut observation = Observations::default();
            for _ in 0..good_windows {
                observation.record(EdgeWeightType::ImmediateProtocolConformance {
                    num_packets: 50,
                    num_acks: 50,
                });
            }

            let rate = |obs: &Observations| -> anyhow::Result<f64> {
                obs.immediate_qos()
                    .context("should have immediate QoS")?
                    .ack_rate()
                    .context("should have ack rate")
            };
            assert_in_delta!(rate(&observation)?, 1.0, 0.001);

            for silent in 1..500 {
                observation.record(EdgeWeightType::ImmediateProtocolConformance {
                    num_packets: 50,
                    num_acks: 0,
                });
                if rate(&observation)? < DEFAULT_MIN_ACK_RATE {
                    return Ok(silent);
                }
            }
            anyhow::bail!("a silent peer never fell below the admission threshold")
        }

        let short_history = windows_to_demote(100)?;
        let long_history = windows_to_demote(1_000)?;

        assert_eq!(
            short_history, long_history,
            "demotion must be bounded by the decay, not by how long the peer behaved well"
        );
        assert_lt!(
            short_history,
            30,
            "a silent peer must be demoted within a small number of reports, took {short_history}"
        );
        Ok(())
    }

    #[test]
    fn observations_should_store_the_averaged_success_rate_of_the_probes() {
        let small_latency = std::time::Duration::from_millis(10);

        let mut observation = Observations::default();

        for i in 0..10 {
            if i % 2 == 0 {
                observation.record(EdgeWeightType::Immediate(Err(())));
            } else {
                observation.record(EdgeWeightType::Immediate(Ok(small_latency)));
            }
        }

        assert_in_delta!(observation.score().expect("probes were recorded"), 0.5, 0.05);
    }

    #[test]
    fn score_should_ignore_a_stream_allocated_without_observations() {
        let mut observation = Observations::default();

        // Record a successful immediate probe (simulates neighbor probe success)
        observation.record(EdgeWeightType::Immediate(Ok(std::time::Duration::from_millis(50))));

        // Record on-chain capacity only. This allocates the intermediate stream without
        // recording any loopback probe outcome, which is the permanent state of every edge
        // incident to this node.
        observation.record(EdgeWeightType::Balance(Some(hopr_api::graph::traits::Balance::from(
            100u64,
        ))));

        let imm = observation.immediate_qos().expect("immediate stream should exist");
        let inter = observation
            .intermediate_qos()
            .expect("intermediate stream should exist");

        assert!(imm.has_observations(), "the immediate probe was recorded");
        assert!(
            !inter.has_observations(),
            "capacity alone must not count as a probe observation"
        );

        // Only the immediate stream is *present* in the RFC-0014 §4.2 sense, so the edge score
        // is that stream's score — not half of it.
        assert_eq!(observation.score(), imm.score());
    }

    #[test]
    fn score_should_average_only_when_both_streams_have_observations() {
        let mut observation = Observations::default();
        observation.record(EdgeWeightType::Immediate(Ok(std::time::Duration::from_millis(50))));
        observation.record(EdgeWeightType::Intermediate(Ok(std::time::Duration::from_millis(150))));

        let imm = observation.immediate_qos().expect("immediate stream should exist");
        let inter = observation
            .intermediate_qos()
            .expect("intermediate stream should exist");
        assert!(imm.has_observations() && inter.has_observations());

        let expected = (imm.score().expect("observed") + inter.score().expect("observed")) / 2.0;
        assert_in_delta!(observation.score().expect("both streams observed"), expected, 0.001);
    }

    #[test]
    fn measured_dead_stream_should_report_a_zero_score_not_an_absent_one() {
        // Never succeeded: every probe failed from the first one.
        let mut dead = Observations::default();
        for _ in 0..10 {
            dead.record(EdgeWeightType::Intermediate(Err(())));
        }

        // Worst possible partial success: one success in the EMA window, slowest latency bucket.
        let mut flaky = Observations::default();
        for _ in 0..4 {
            flaky.record(EdgeWeightType::Intermediate(Err(())));
        }
        flaky.record(EdgeWeightType::Intermediate(Ok(std::time::Duration::from_millis(500))));

        let dead_score = dead.intermediate_qos().expect("stream exists").score();
        let flaky_score = flaky.intermediate_qos().expect("stream exists").score();

        assert_eq!(
            dead_score,
            Some(0.0),
            "a measured-dead stream reports zero, distinct from the `None` of an unobserved one; the value function \
             is what starves rather than prunes it"
        );
        assert_gt!(
            flaky_score.expect("observed"),
            0.0,
            "a stream that sometimes relays must outrank one that never has"
        );
    }

    #[test]
    fn unobserved_stream_should_report_no_score_at_all() {
        // A balance update alone: the stream exists but was never probed.
        let mut observation = Observations::default();
        observation.record(EdgeWeightType::Balance(Some(hopr_api::graph::traits::Balance::from(
            100u64,
        ))));

        let inter = observation.intermediate_qos().expect("stream exists");
        assert!(!inter.has_observations());
        assert_eq!(
            inter.score(),
            None,
            "an unprobed stream reports no score, which the value function answers with the unprobed-edge penalty \
             rather than starvation"
        );
        assert_eq!(observation.score(), None, "an edge with no observations has no score");
    }

    #[test]
    fn score_should_use_intermediate_only_when_no_immediate() {
        let mut observation = Observations::default();
        // Record a successful intermediate probe (no immediate probe recorded)
        observation.record(EdgeWeightType::Intermediate(Ok(std::time::Duration::from_millis(80))));
        observation.record(EdgeWeightType::Balance(Some(hopr_api::graph::traits::Balance::from(
            500u64,
        ))));

        assert!(observation.immediate_qos().is_none());
        let inter_score = observation.intermediate_qos().unwrap().score();
        assert_gt!(
            inter_score.expect("observed"),
            0.0,
            "intermediate score should be positive"
        );
        assert_eq!(observation.score(), inter_score);
    }

    /// The window has to react inside the recovery budget, and still have a baseline to react
    /// *against*.
    ///
    /// Both halves matter. Too wide a recent window and a dead relay is not discounted until the
    /// budget is spent; too short a full window and there is nothing to compare it with, since the
    /// signal is comparative -- the absolute SURB ratio measures the balancer surplus as much as
    /// the path, and a fully healthy path reads 0.36.
    #[test]
    fn the_surb_window_geometry_should_react_inside_the_recovery_budget() {
        let recent = SURB_BUCKET_WIDTH * SURB_RECENT_SLICES as u32;
        let full = SURB_BUCKET_WIDTH * SURB_BUCKETS as u32;

        // Detection costs ~5s on its own, against a 20s test boundary. A recent window longer than
        // this leaves no budget to refill in once the discount finally lands.
        assert!(
            recent <= std::time::Duration::from_secs(5),
            "the recent window ({recent:?}) must register a collapse inside the recovery budget"
        );
        assert!(
            full >= recent * 4,
            "the baseline ({full:?}) must be materially longer than the recent window ({recent:?}), otherwise the \
             comparison has nothing to say"
        );
    }

    /// The ring is `Copy` inside a `Copy` observation, read per edge during path search.
    #[test]
    fn the_surb_window_should_stay_cheap_to_copy() {
        let size = std::mem::size_of::<WindowedRatio<SURB_BUCKETS>>();
        assert!(
            size <= 512,
            "WindowedRatio<{SURB_BUCKETS}> is {size} B; widening the ring rather than narrowing the slice makes every \
             edge read more expensive (30 buckets measured 752 B against 320)"
        );
    }

    /// A window whose slice boundaries the test crosses by moving the clock, not by sleeping.
    ///
    /// The *shape* under test is "recent slices against the whole window", which is independent of
    /// the wall-clock scale. Sleeping would bind these assertions to the scheduler instead: an
    /// overrun on a loaded runner puts a record in the wrong slice and changes the trend, so the
    /// tests would be measuring the machine rather than the window.
    fn fast_slices(epoch: std::time::Instant) -> TransportIntermediates {
        TransportIntermediates {
            link: TransportLinkMeasurement::default(),
            balance: None,
            surb: WindowedRatio::new(TEST_SLICE, epoch),
            surb_peak: None,
            loopback: LoopbackWindow::new(epoch),
        }
    }

    /// One slice of the test window; only its ratio to the ring matters, never its real duration.
    const TEST_SLICE: std::time::Duration = std::time::Duration::from_millis(20);

    /// Records `rounds` intervals, one per slice from `from`, and returns the last one's instant.
    ///
    /// Ends *on* a record: the readers take the same instant, so stopping a slice later would leave
    /// "now" in an empty slice and read `None` instead of the value just recorded.
    fn record_slices(
        m: &mut TransportIntermediates,
        from: std::time::Instant,
        rounds: usize,
        expected: u64,
        observed: u64,
    ) -> std::time::Instant {
        let mut at = from;
        for i in 0..rounds {
            if i > 0 {
                at += TEST_SLICE;
            }
            m.record_surb_round_trips_at(expected, observed, at);
        }
        at
    }

    /// Fills the window with healthy round-trips spread across several slices.
    fn deliver_healthily(m: &mut TransportIntermediates, from: std::time::Instant) -> std::time::Instant {
        record_slices(m, from, 8, 100, 100)
    }

    /// A relay that stops delivering must be discounted long before the full window notices.
    #[test]
    fn an_edge_whose_delivery_just_collapsed_should_be_discounted_against_a_steady_one() {
        let epoch = std::time::Instant::now();
        let mut collapsed = fast_slices(epoch);
        let mut steady = fast_slices(epoch);
        deliver_healthily(&mut collapsed, epoch);
        let mut now = deliver_healthily(&mut steady, epoch) + TEST_SLICE;

        // The recent slices diverge: one keeps answering, the other stops dead.
        for i in 0..2 {
            if i > 0 {
                now += TEST_SLICE;
            }
            collapsed.record_surb_round_trips_at(100, 0, now);
            steady.record_surb_round_trips_at(100, 100, now);
        }

        // Vacuity guards: the discount can only be attributed to the trend if the trend actually
        // crossed the floor for one edge and not the other.
        let collapsed_trend = collapsed.surb_trend_at(now).expect("both windows hold evidence");
        let steady_trend = steady.surb_trend_at(now).expect("both windows hold evidence");
        assert!(
            collapsed_trend < SURB_TREND_FLOOR,
            "the collapsed edge must trip the floor, trend={collapsed_trend}"
        );
        assert!(
            steady_trend >= SURB_TREND_FLOOR,
            "the steady edge must not trip the floor, trend={steady_trend}"
        );

        let collapsed_rate = collapsed.surb_delivery_rate_at(now).expect("has traffic");
        let steady_rate = steady.surb_delivery_rate_at(now).expect("has traffic");
        assert!(
            collapsed_rate < steady_rate,
            "a relay that just stopped delivering must be discounted below one that has not: \
             collapsed={collapsed_rate} steady={steady_rate}"
        );

        // The comparison above is not enough on its own: the full-window value already differs
        // between the two, so it passes with the trend removed entirely. What must be shown is that
        // the *discount* moved the number -- i.e. the rate sits below the plain peak-relative value.
        let undiscounted = (collapsed.surb.value(now).expect("has traffic")
            / collapsed.peak_at(now).expect("has a peak"))
        .clamp(0.0, 1.0);
        assert!(
            collapsed_rate < undiscounted,
            "the trend must discount below the peak-relative value, otherwise it is inert: rate={collapsed_rate} \
             undiscounted={undiscounted}"
        );
    }

    // ── Traffic as a second witness ─────────────────────────────────────

    // Probes are sparse and fail on any hop of their loop; SURBs come back at data rate and a
    // collapse shows within seconds. They are two witnesses that the edge works, kept apart so the
    // value function can let either one keep a relay (hopr-api `EdgeValueFn`).

    #[test]
    fn traffic_that_stopped_returning_should_read_zero_within_the_trend_window() {
        let epoch = std::time::Instant::now();
        let mut m = fast_slices(epoch);
        let now = deliver_healthily(&mut m, epoch);
        let now = record_slices(&mut m, now + TEST_SLICE, 2, 100, 0);

        assert_eq!(
            m.traffic_rate_at(now),
            Some(0.0),
            "SURBs minted and none returned: traffic is dead long before the next loopback round"
        );
        assert_eq!(m.loopback_rate_at(now), None, "and no loopback was involved");
    }

    #[test]
    fn traffic_that_keeps_returning_should_read_above_zero() {
        let epoch = std::time::Instant::now();
        let mut m = fast_slices(epoch);
        let now = deliver_healthily(&mut m, epoch);

        assert!(m.traffic_rate_at(now).is_some_and(|rate| rate > 0.0));
    }

    #[test]
    fn the_loopback_rate_should_not_include_traffic() {
        // Kept apart: a healthy SURB window says nothing about loops, and the other way round.
        let epoch = std::time::Instant::now();
        let mut m = fast_slices(epoch);
        let now = deliver_healthily(&mut m, epoch);
        assert_eq!(m.loopback_rate_at(now), None);

        for _ in 0..3 {
            m.loopback.record_at(false, now);
        }
        assert_eq!(m.loopback_rate_at(now), Some(0.0));
        assert!(
            m.traffic_rate_at(now).is_some_and(|rate| rate > 0.0),
            "failed probes must not change what traffic says"
        );
    }

    #[test]
    fn a_credited_loopback_should_not_write_a_latency_into_the_edge() {
        // The edge is known by its neighbour ping only. A loop that returns over it says nothing about
        // its own latency, so crediting must not copy the ping's value into the loop stream, where it
        // would be read back and written again on every loop.
        let mut observations = Observations::default();
        observations.record(EdgeWeightType::Immediate(Ok(std::time::Duration::from_millis(20))));
        for _ in 0..5 {
            observations.credit_loopback();
        }

        let intermediate = observations.intermediate_qos().expect("credited");
        assert_eq!(intermediate.average_latency(), None, "a credit carries no timing");
        assert_eq!(intermediate.loopback_rate(), Some(1.0), "but it is a success");
        assert_eq!(intermediate.average_probe_rate(), Some(1.0));
    }

    #[test]
    fn traffic_that_never_returned_should_read_dead() {
        // SURBs were minted over the edge and none came back: with no peak to have collapsed from,
        // the absence is the evidence (hopr-impls#81).
        let epoch = std::time::Instant::now();
        let mut m = fast_slices(epoch);
        let now = record_slices(&mut m, epoch, 4, 100, 0);

        assert_eq!(m.traffic_rate_at(now), Some(0.0));
    }

    #[test]
    fn the_first_returned_surb_should_lift_an_edge_that_read_dead() {
        let epoch = std::time::Instant::now();
        let mut m = fast_slices(epoch);
        let now = record_slices(&mut m, epoch, 4, 100, 0);
        assert_eq!(m.traffic_rate_at(now), Some(0.0));

        let later = record_slices(&mut m, now, 1, 100, 50);
        assert!(
            m.traffic_rate_at(later).is_some_and(|rate| rate > 0.0),
            "a returning edge must recover"
        );
    }

    #[test]
    fn an_idle_edge_should_not_read_zero_traffic() {
        // No SURBs minted lately is not SURBs that failed to return.
        let epoch = std::time::Instant::now();
        let mut m = fast_slices(epoch);
        let now = deliver_healthily(&mut m, epoch);

        let idle = now + TEST_SLICE * 4;
        assert!(
            m.traffic_rate_at(idle).is_none_or(|rate| rate > 0.0),
            "an idle edge must not be starved"
        );
    }

    #[test]
    fn the_trait_should_expose_both_witnesses_of_an_intermediate_stream() {
        use hopr_api::graph::traits::{EdgeObservableRead, EdgeObservableWrite, EdgeWeightType};

        let mut observations = Observations::default();
        observations.record(EdgeWeightType::SurbRoundTrips {
            expected: 100,
            observed: 100,
        });
        for _ in 0..2 {
            observations.record(EdgeWeightType::Intermediate(Err(())));
        }

        let intermediate = observations.intermediate_qos().expect("recorded");
        assert_eq!(intermediate.loopback_rate(), Some(0.0), "the probes failed");
        assert!(
            intermediate.traffic_rate().is_some_and(|rate| rate > 0.0),
            "while the traffic came back"
        );
    }

    // ── Later hops ──────────────────────────────────────────────────────

    /// A relay in the middle of a path that was good and whose loops have all failed since.
    ///
    /// Its moving average is still positive, so its score alone would only fall gradually, while the
    /// loopback window already reads zero. The edge has to read dead on that, for every reader.
    fn a_middle_relay_that_stopped_returning_loops() -> Observations {
        let epoch = std::time::Instant::now();
        let mut m = fast_slices(epoch);
        m.balance = Some(hopr_api::graph::traits::Balance::from(1_000u64));
        for _ in 0..5 {
            m.link.record(Ok(std::time::Duration::from_millis(30)));
        }
        for _ in 0..2 {
            m.link.record(Err(()));
            m.loopback.record_at(false, epoch);
        }

        Observations {
            intermediate_probe: Some(m),
            ..Observations::default()
        }
    }

    #[test]
    fn a_later_relay_whose_loopbacks_never_returned_should_read_dead_though_its_average_is_still_positive() {
        let observed = a_middle_relay_that_stopped_returning_loops();
        let intermediate = observed.intermediate_qos().expect("recorded");

        // Vacuity guards: the case only means something while the average and the window disagree.
        assert!(
            intermediate.link.score().is_some_and(|score| score > 0.1),
            "the moving average must still be positive"
        );
        assert_eq!(intermediate.loopback_rate(), Some(0.0), "while the window reads zero");

        assert_eq!(intermediate.score(), Some(0.0));
        assert_eq!(observed.score(), Some(0.0));
        assert_eq!(intermediate.average_latency(), None);
    }

    /// The discount must be soft and self-clearing, not a latch.
    #[test]
    fn an_edge_should_recover_its_rate_once_the_recent_slices_climb_back() {
        let epoch = std::time::Instant::now();
        let mut m = fast_slices(epoch);
        let now = deliver_healthily(&mut m, epoch);

        let now = record_slices(&mut m, now + TEST_SLICE, 2, 100, 0);
        let during = m.surb_delivery_rate_at(now).expect("has traffic");

        // Deliveries resume; the recent slices are what move first.
        let now = record_slices(&mut m, now + TEST_SLICE, 3, 100, 100);
        let after = m.surb_delivery_rate_at(now).expect("has traffic");

        assert!(
            after > during,
            "the discount must clear on its own once deliveries resume: during={during} after={after}"
        );
    }

    /// A steady edge must be untouched: the trend is a discount for change, not a standing tax.
    #[test]
    fn a_steadily_delivering_edge_should_not_be_discounted_at_all() {
        let epoch = std::time::Instant::now();
        let mut m = fast_slices(epoch);
        let now = deliver_healthily(&mut m, epoch);

        let trend = m.surb_trend_at(now).expect("window holds evidence");
        assert!(
            trend >= SURB_TREND_FLOOR,
            "steady delivery must not read as a downward trend, got {trend}"
        );
        assert_in_delta!(m.surb_delivery_rate_at(now).expect("has traffic"), 1.0, 0.001);
    }

    /// A lucky interval must not tax the edge forever, which is what a peak that only rose did.
    #[test]
    fn a_peak_set_by_one_favourable_interval_should_decay_back_to_steady_behaviour() {
        let epoch = std::time::Instant::now();
        let mut m = fast_slices(epoch);

        // One interval where the balancer happens to mint barely more than is spent: the absolute
        // ratio spikes, and with it the peak. Nothing about the path changed.
        let now = record_slices(&mut m, epoch, 1, 10, 10);
        // Then a long stretch of ordinary, perfectly healthy delivery at the usual surplus.
        let now = record_slices(&mut m, now + TEST_SLICE, 8, 100, 30);

        let penalised = m.surb_delivery_rate_at(now).expect("has traffic");
        assert!(
            penalised < 0.9,
            "the spike must still be the baseline while it is fresh, got {penalised}"
        );

        // Kept delivering at exactly the same rate, a window later. The spike has aged out of the
        // ring, and the baseline must have followed it rather than latching.
        let now = record_slices(&mut m, now + TEST_SLICE, 12, 100, 30);
        let recovered = m.surb_delivery_rate_at(now).expect("has traffic");

        assert!(
            recovered > 0.95,
            "an edge delivering steadily must not be discounted against its luckiest interval forever: was \
             {penalised}, still {recovered} a full window later"
        );
    }

    /// An unprobed edge must not be read as a dead one, and probes are not read against traffic.
    #[test]
    fn a_failing_probe_should_not_lower_the_rate_of_an_edge_with_healthy_surb_traffic() {
        let epoch = std::time::Instant::now();

        let mut surbs_only = fast_slices(epoch);
        deliver_healthily(&mut surbs_only, epoch);
        let surbs_only_rate = surbs_only
            .average_probe_rate()
            .expect("SURB traffic alone is evidence, so the rate must be present");
        assert_in_delta!(surbs_only_rate, 1.0, 0.001);

        let mut probes_failing = fast_slices(epoch);
        deliver_healthily(&mut probes_failing, epoch);
        for _ in 0..5 {
            probes_failing.record(Err(()));
        }

        assert_eq!(
            probes_failing.average_probe_rate(),
            Some(surbs_only_rate),
            "traffic that crossed the edge says more than the probes that failed"
        );
    }

    // ── Two witnesses in the score ──────────────────────────────────────

    // Traffic comes first and probing fills in where none crossed the edge, so failed probes cannot zero
    // an edge whose traffic came back, and returned probes cannot save an edge whose traffic stopped.

    /// An edge with healthy SURBs, and the clock at the last of them.
    fn with_healthy_surbs(epoch: std::time::Instant) -> (TransportIntermediates, std::time::Instant) {
        let mut m = fast_slices(epoch);
        let now = deliver_healthily(&mut m, epoch);
        (m, now)
    }

    #[test]
    fn failed_probes_should_not_zero_the_rate_of_an_edge_whose_surbs_came_back() {
        let (mut m, now) = with_healthy_surbs(std::time::Instant::now());
        for _ in 0..5 {
            m.record(Err(()));
        }

        assert_eq!(m.link.average_probe_rate(), Some(0.0), "every probe failed");
        assert!(
            m.surb_delivery_rate_at(now).is_some_and(|rate| rate > 0.9),
            "while SURBs came back"
        );
        let combined = m.average_probe_rate_at(now).expect("both witnesses have evidence");
        assert!(
            combined > 0.0,
            "traffic that came back keeps the edge above zero, got {combined}"
        );
    }

    #[test]
    fn collapsed_surbs_should_zero_the_rate_of_an_edge_whose_probes_came_back() {
        let (mut m, now) = with_healthy_surbs(std::time::Instant::now());
        let now = record_slices(&mut m, now + TEST_SLICE, 2, 100, 0);
        for _ in 0..5 {
            m.record(Ok(std::time::Duration::from_millis(30)));
        }

        assert_eq!(m.surb_delivery_rate_at(now), Some(0.0), "traffic stopped coming back");
        assert!(
            m.link.average_probe_rate().is_some_and(|rate| rate > 0.9),
            "while probes come back"
        );
        assert_eq!(
            m.average_probe_rate_at(now),
            Some(0.0),
            "probes that came back do not save an edge whose traffic stopped"
        );
    }

    #[test]
    fn an_edge_should_read_zero_only_when_both_witnesses_read_zero() {
        let (mut m, now) = with_healthy_surbs(std::time::Instant::now());
        let now = record_slices(&mut m, now + TEST_SLICE, 2, 100, 0);
        for _ in 0..5 {
            m.record(Err(()));
        }

        assert_eq!(m.surb_delivery_rate_at(now), Some(0.0), "traffic dead");
        assert_eq!(m.link.average_probe_rate(), Some(0.0), "probes dead");
        assert_eq!(m.average_probe_rate_at(now), Some(0.0), "both dead");
    }

    #[test]
    fn probes_should_not_rank_edges_that_carry_traffic() {
        let (mut both, now) = with_healthy_surbs(std::time::Instant::now());
        let (mut one, _) = with_healthy_surbs(std::time::Instant::now());
        for _ in 0..5 {
            both.record(Ok(std::time::Duration::from_millis(30)));
            one.record(Err(()));
        }

        assert_eq!(
            both.average_probe_rate_at(now),
            one.average_probe_rate_at(now),
            "the traffic rates both carry decide, whatever the probes said"
        );
    }

    /// A relay that stops returning SURBs must score below one that keeps delivering.
    ///
    /// Regression: `TransportIntermediates::average_probe_rate` correctly prefers the SURB window,
    /// but `score()` delegated to `link.score()`, which recomputes from the raw probe EMA -- so the
    /// SURB evidence reached a diagnostic accessor and nothing else. Path selection weights come
    /// from `score()`, which meant real return-path traffic could never influence a route.
    #[test]
    fn a_relay_that_stops_returning_surbs_should_score_below_one_that_keeps_delivering() {
        // Identical probe history: same latency, same probe successes. The only difference is what
        // the SURB round-trips say, so any score difference is attributable to them alone.
        let probe_history = |o: &mut Observations| {
            for _ in 0..10 {
                o.record(EdgeWeightType::Intermediate(Ok(std::time::Duration::from_millis(50))));
            }
        };

        let mut delivering = Observations::default();
        probe_history(&mut delivering);
        let mut silent = Observations::default();
        probe_history(&mut silent);

        // Both establish the same healthy peak, so the relative ratio starts equal.
        delivering.record(EdgeWeightType::SurbRoundTrips {
            expected: 1_000,
            observed: 900,
        });
        silent.record(EdgeWeightType::SurbRoundTrips {
            expected: 1_000,
            observed: 900,
        });

        // Then one keeps delivering and the other goes silent.
        delivering.record(EdgeWeightType::SurbRoundTrips {
            expected: 1_000,
            observed: 900,
        });
        silent.record(EdgeWeightType::SurbRoundTrips {
            expected: 1_000,
            observed: 0,
        });

        // Guard against a vacuous comparison: the accessor must actually separate them, otherwise
        // the score assertion below proves nothing about `score()`.
        let d_rate = delivering
            .intermediate_qos()
            .and_then(|m| m.surb_delivery_rate())
            .expect("delivering edge has SURB history");
        let s_rate = silent
            .intermediate_qos()
            .and_then(|m| m.surb_delivery_rate())
            .expect("silent edge has SURB history");
        assert_lt!(s_rate, d_rate, "the SURB window itself must separate the two edges");

        // Both edges carry SURB evidence, so both must be scored rather than reported unobserved —
        // asserting that first keeps a `None`-vs-`None` comparison from passing this vacuously.
        let (silent_score, delivering_score) = (
            silent.score().expect("a silent edge is measured, not unobserved"),
            delivering.score().expect("a delivering edge is measured"),
        );
        assert_lt!(
            silent_score,
            delivering_score,
            "a relay that stopped returning SURBs must score below one still delivering: silent={silent_score} \
             delivering={delivering_score} (surb rates {s_rate} vs {d_rate})"
        );
    }

    #[test]
    fn a_sub_millisecond_latency_must_not_read_as_unmeasured() {
        // The intermediate latency is a `saturating_sub` residual, so a value at or below a
        // millisecond is ordinary rather than exotic. Truncating it to `0` used to make
        // `average_latency` report `None`, which `latency_score` treats as the *worst* case (0.05)
        // — so the fastest edges scored twenty times below the slowest measured ones.
        let mut fast = TransportLinkMeasurement::default();
        fast.record(Ok(std::time::Duration::from_micros(400)));

        assert!(
            fast.average_latency().is_some(),
            "a measured sub-millisecond latency is a measurement, not an absence"
        );
        assert_eq!(
            fast.score(),
            Some(1.0),
            "a fast edge must earn the top latency band, not the unmeasured penalty"
        );

        // And a genuinely unmeasured link still reports absence.
        let mut failed = TransportLinkMeasurement::default();
        failed.record(Err(()));
        assert!(
            failed.average_latency().is_none(),
            "a failed probe records no latency, so there is none to report"
        );
    }

    #[test]
    fn score_should_use_immediate_only_when_no_intermediate() {
        let mut observation = Observations::default();
        observation.record(EdgeWeightType::Immediate(Ok(std::time::Duration::from_millis(50))));

        let imm_score = observation.immediate_qos().unwrap().score();
        assert!(observation.intermediate_qos().is_none());
        assert_eq!(observation.score(), imm_score);
    }
}

#[cfg(test)]
mod loopback_window_tests {
    use std::time::{Duration, Instant};

    use hopr_api::graph::traits::{EdgeObservableRead, EdgeObservableWrite, EdgeWeightType};

    use super::*;

    fn record(window: &mut LoopbackWindow, at: Instant, returned: usize, failed: usize) {
        for _ in 0..returned {
            window.record_at(true, at);
        }
        for _ in 0..failed {
            window.record_at(false, at);
        }
    }

    #[test]
    fn a_window_without_loopbacks_should_say_nothing() {
        let epoch = Instant::now();
        assert_eq!(LoopbackWindow::new(epoch).rate_at(epoch), None);
    }

    #[test]
    fn one_failed_loopback_should_read_as_zero() {
        // Loops are sent once per probing round, so an edge may see one a round. Waiting for more
        // would mean never judging it.
        let epoch = Instant::now();
        let mut window = LoopbackWindow::new(epoch);
        record(&mut window, epoch, 0, 1);
        assert_eq!(window.rate_at(epoch), Some(0.0));
    }

    #[test]
    fn a_relay_none_of_whose_loopbacks_returned_should_read_as_exactly_zero() {
        let epoch = Instant::now();
        let mut window = LoopbackWindow::new(epoch);
        record(&mut window, epoch, 0, 3);
        assert_eq!(window.rate_at(epoch), Some(0.0));
    }

    #[test]
    fn returned_and_failed_loopbacks_should_be_summed_into_the_ratio() {
        let epoch = Instant::now();
        let mut window = LoopbackWindow::new(epoch);
        record(&mut window, epoch, 5, 5);
        assert_eq!(window.rate_at(epoch), Some(0.5));
    }

    #[test]
    fn one_returning_loop_among_many_failures_should_read_above_zero() {
        // Anything above zero is a relay that carries traffic.
        let epoch = Instant::now();
        let mut window = LoopbackWindow::new(epoch);
        record(&mut window, epoch, 1, 9);
        assert_eq!(window.rate_at(epoch), Some(0.1));
    }

    #[test]
    fn outcomes_older_than_the_window_should_be_forgotten() {
        let epoch = Instant::now();
        let mut window = LoopbackWindow::new(epoch);
        record(&mut window, epoch, 0, 5);

        let later = epoch + LOOPBACK_BUCKET_WIDTH * LOOPBACK_BUCKETS as u32;
        assert_eq!(
            window.rate_at(later),
            None,
            "a full window on, the failures are out of it"
        );
    }

    #[test]
    fn a_relay_should_recover_once_its_loopbacks_return() {
        let epoch = Instant::now();
        let mut window = LoopbackWindow::new(epoch);
        record(&mut window, epoch, 0, 3);
        assert_eq!(window.rate_at(epoch), Some(0.0));

        let later = epoch + Duration::from_secs(5);
        record(&mut window, later, 3, 0);
        assert_eq!(window.rate_at(later), Some(0.5), "both are still inside the window");
    }

    #[test]
    fn a_reused_bucket_should_not_carry_the_outcomes_of_an_earlier_lap() {
        let epoch = Instant::now();
        let mut window = LoopbackWindow::new(epoch);
        record(&mut window, epoch, 0, 4);

        // Same bucket slot one full lap later: the old second must have been cleared.
        let lap = epoch + LOOPBACK_BUCKET_WIDTH * LOOPBACK_BUCKETS as u32;
        record(&mut window, lap, 3, 0);
        assert_eq!(window.rate_at(lap), Some(1.0));
    }

    // ── Cadence ─────────────────────────────────────────────────────────

    // Loops are sent once per probing round (30 s by default) and a lost one is recorded after the
    // 3 s probe timeout. The window has to bridge the gap between rounds, or the evidence is gone
    // for most of the time.

    const ROUND: Duration = Duration::from_secs(30);
    const TIMEOUT: Duration = Duration::from_secs(3);

    /// Plays a timeline second by second: the round-`n` loop over the edge has its outcome known
    /// `TIMEOUT` after the round starts, and `rate` is read after every second.
    ///
    /// Time has to move forward: a ring window is only meaningful for a clock that does.
    fn play(outcomes: &[bool], until: Duration) -> Vec<(u64, Option<f64>)> {
        let epoch = Instant::now();
        let mut window = LoopbackWindow::new(epoch);
        (0..=until.as_secs())
            .map(|second| {
                let now = epoch + Duration::from_secs(second);
                if let Some(since) = second.checked_sub(TIMEOUT.as_secs())
                    && since % ROUND.as_secs() == 0
                    && let Some(returned) = outcomes.get((since / ROUND.as_secs()) as usize)
                {
                    window.record_at(*returned, now);
                }
                (second, window.rate_at(now))
            })
            .collect()
    }

    #[test]
    fn a_dead_relay_should_stay_starved_between_probing_rounds() {
        let timeline = play(&[false; 6], ROUND * 5 + TIMEOUT);

        // From the first outcome on, every second must read zero, not only the seconds just after a round.
        for (second, rate) in timeline.into_iter().filter(|(second, _)| *second >= TIMEOUT.as_secs()) {
            assert_eq!(rate, Some(0.0), "t = {second} s: evidence gone between rounds");
        }
    }

    #[test]
    fn a_relay_that_dies_should_be_starved_within_two_rounds() {
        let timeline = play(&[true, false, false, false], ROUND * 3 + TIMEOUT);
        let at = |second: u64| timeline[second as usize].1;

        // The last good loop is still in the window one round later.
        assert!(at(ROUND.as_secs() + TIMEOUT.as_secs()).is_some_and(|rate| rate > 0.0));
        // Two rounds later it has expired, and only failures are left.
        assert_eq!(
            at((ROUND * 2).as_secs() + TIMEOUT.as_secs()),
            Some(0.0),
            "a relay that stopped returning must read zero within two rounds"
        );
    }

    #[test]
    fn a_relay_should_be_usable_as_soon_as_a_loop_returns() {
        let timeline = play(&[false, false, false, true], ROUND * 3 + TIMEOUT);
        let recovered = timeline[(ROUND * 3 + TIMEOUT).as_secs() as usize].1;
        assert!(
            recovered.is_some_and(|rate| rate > 0.0),
            "one returning loop is enough, however many failures are still in the window"
        );
    }

    #[test]
    fn one_lost_loop_should_starve_a_single_loop_edge_for_at_most_one_round() {
        let timeline = play(&[false, true], ROUND + TIMEOUT);
        let at = |second: u64| timeline[second as usize].1;

        assert_eq!(at(TIMEOUT.as_secs() + 20), Some(0.0), "starved until the next round");
        assert!(
            at(ROUND.as_secs() + TIMEOUT.as_secs()).is_some_and(|rate| rate > 0.0),
            "the next round's loop clears it"
        );
    }

    #[test]
    fn only_intermediate_outcomes_should_feed_the_loopback_rate() {
        let mut observations = Observations::default();
        for _ in 0..5 {
            observations.record(EdgeWeightType::Immediate(Err(())));
        }
        assert!(
            observations.intermediate_qos().is_none(),
            "neighbour pings are not loopbacks"
        );

        observations.record(EdgeWeightType::Intermediate(Err(())));
        assert_eq!(
            observations.intermediate_qos().and_then(|q| q.loopback_rate()),
            Some(0.0)
        );
    }

    fn neighbour(ping_ms: u64) -> Observations {
        let mut observations = Observations::default();
        observations.record(EdgeWeightType::Connected(true));
        for _ in 0..3 {
            observations.record(EdgeWeightType::Immediate(Ok(std::time::Duration::from_millis(ping_ms))));
        }
        observations
    }

    fn latency_of(observations: &Observations) -> Option<std::time::Duration> {
        observations.immediate_qos().and_then(|q| q.average_latency())
    }

    /// A relay that rejects our packets still answers pings fast. The verdict lives in the edge itself, so every
    /// reader of the graph sees a dead relay, whichever value function it applies.
    #[test]
    fn a_neighbour_whose_loopbacks_never_return_should_read_dead_in_every_metric() {
        let mut observations = neighbour(5);
        for _ in 0..5 {
            observations.record(EdgeWeightType::Intermediate(Err(())));
        }

        assert_eq!(observations.score(), Some(0.0), "not half of a healthy ping");
        assert_eq!(
            latency_of(&observations),
            None,
            "its fast ping is not a property of a working relay"
        );
        assert_eq!(observations.intermediate_qos().and_then(|q| q.score()), Some(0.0));
        assert_eq!(observations.intermediate_qos().and_then(|q| q.average_latency()), None);
    }

    #[test]
    fn a_neighbour_with_returning_loopbacks_should_keep_its_score_and_latency() {
        let mut observations = neighbour(5);
        observations.record(EdgeWeightType::Intermediate(Ok(std::time::Duration::from_millis(40))));
        for _ in 0..4 {
            observations.record(EdgeWeightType::Intermediate(Err(())));
        }

        assert!(
            observations.score().is_some_and(|score| score > 0.0),
            "one loop in five returned"
        );
        assert!(latency_of(&observations).is_some());
    }

    #[test]
    fn a_neighbour_without_loopback_evidence_should_be_left_as_it_was() {
        let observations = neighbour(5);

        assert_eq!(
            observations.score(),
            observations.immediate_qos().and_then(|q| q.score())
        );
        assert!(latency_of(&observations).is_some());
    }

    #[test]
    fn a_neighbour_should_recover_once_a_loopback_returns() {
        let mut observations = neighbour(5);
        for _ in 0..5 {
            observations.record(EdgeWeightType::Intermediate(Err(())));
        }
        assert_eq!(observations.score(), Some(0.0));

        observations.record(EdgeWeightType::Intermediate(Ok(std::time::Duration::from_millis(40))));
        assert!(observations.score().is_some_and(|score| score > 0.0));
        assert!(latency_of(&observations).is_some(), "its latency comes back with it");
    }

    /// Where traffic crosses the edge it says more than probing does, so failed probes are not read against it.
    #[test]
    fn traffic_should_take_precedence_over_failed_probes() {
        let mut with_failed_probes = neighbour(5);
        with_failed_probes.record(EdgeWeightType::SurbRoundTrips {
            expected: 10,
            observed: 10,
        });
        let mut without = with_failed_probes;
        for _ in 0..5 {
            with_failed_probes.record(EdgeWeightType::Intermediate(Err(())));
        }

        assert_eq!(
            with_failed_probes.score(),
            without.score(),
            "probes are read only without traffic"
        );
        assert!(with_failed_probes.score().is_some_and(|score| score > 0.0));
        assert!(latency_of(&with_failed_probes).is_some());
        // Keep the comparison honest: the unchanged copy really carries traffic and no probe.
        without.record(EdgeWeightType::Balance(None));
    }

    /// Traffic that stopped is a verdict by itself, whatever the probes say.
    #[test]
    fn traffic_that_stopped_should_outweigh_probes_that_returned() {
        let t0 = std::time::Instant::now();
        let mut intermediates = TransportIntermediates::default();
        intermediates.record_surb_round_trips_at(10, 10, t0);
        for _ in 0..5 {
            intermediates.record(Ok(std::time::Duration::from_millis(40)));
        }
        // The healthy history has aged out of the SURB window, and the latest interval returned nothing.
        let later = t0 + std::time::Duration::from_secs(30);
        intermediates.record_surb_round_trips_at(10, 0, later);

        assert_eq!(intermediates.traffic_rate_at(later), Some(0.0));
        assert!(intermediates.loopback_rate_at(t0).is_some_and(|rate| rate > 0.0));
        assert_eq!(
            intermediates.average_probe_rate_at(later),
            Some(0.0),
            "the probes that returned do not dilute traffic that stopped"
        );
    }
}
