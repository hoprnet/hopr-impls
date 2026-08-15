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
    latency_average: ExponentialMovingAverage<3>,
    probe_success_rate: ExponentialMovingAverage<5>,
    /// Recorded probe outcomes, successful or not. Neither EMA can express "no samples yet":
    /// an all-failed stream holds exactly `0.0`, the same as its initial value.
    samples: u64,
    /// Successful outcomes only. A failed probe records no latency, so `samples` cannot stand in.
    latency_samples: u64,
}

impl EdgeLinkObservable for TransportLinkMeasurement {
    fn record(&mut self, measurement: EdgeTransportMeasurement) {
        self.samples = self.samples.saturating_add(1);
        if let Ok(latency) = measurement {
            // Sub-millisecond resolution: the intermediate latency is a `saturating_sub` residual
            // that legitimately lands at or near zero, and truncating it to whole milliseconds
            // would store `0` — read back as "never measured" and scored as such.
            self.latency_average.update(latency.as_secs_f64() * 1000.0);
            self.latency_samples = self.latency_samples.saturating_add(1);
            self.probe_success_rate.update(1.0);
        } else {
            self.probe_success_rate.update(0.0);
        }
    }

    /// `None` until a probe has succeeded. Presence, not magnitude: a measured zero is a real
    /// latency and must not read as an absent one.
    fn average_latency(&self) -> Option<std::time::Duration> {
        (self.latency_samples > 0)
            .then(|| std::time::Duration::from_secs_f64(self.latency_average.get().max(0.0) / 1000.0))
    }

    fn average_probe_rate(&self) -> Option<f64> {
        (self.samples > 0).then(|| self.probe_success_rate.get())
    }

    /// `None` until a probe has been recorded; `Some(0.0)` once measured and found unusable.
    fn score(&self) -> Option<f64> {
        self.average_probe_rate()
            .map(|rate| rate * latency_score(self.average_latency()))
    }
}

/// Aid in calculation of the overall transport link score.
///
/// The smaller the latency over the channel, the more useful the link might
/// be for routing complext traffic.
fn latency_score(latency: Option<std::time::Duration>) -> f64 {
    if let Some(latency) = latency {
        match latency.as_millis() {
            0..=75 => 1.0,
            76..=125 => 0.7,
            126..=200 => 0.3,
            _ => 0.15,
        }
    } else {
        0.05
    }
}

/// Observations related to a specific peer in the network.
#[derive(Debug, Copy, Clone, Default, PartialEq)]
pub struct Observations {
    last_update: std::time::Duration,
    immediate_probe: Option<TransportImmediates>,
    intermediate_probe: Option<TransportIntermediates>,
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

    fn average_latency(&self) -> Option<std::time::Duration> {
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
}

/// A delivery-ratio peak and the instant it was set, which the decay is measured from.
#[derive(Debug, Copy, Clone, PartialEq)]
struct SurbPeak {
    value: f64,
    at: std::time::Instant,
}

impl Default for TransportIntermediates {
    fn default() -> Self {
        let now = std::time::Instant::now();

        Self {
            link: TransportLinkMeasurement::default(),
            balance: None,
            surb: WindowedRatio::new(SURB_BUCKET_WIDTH, now),
            surb_peak: None,
        }
    }
}

impl TransportIntermediates {
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
    /// (see [`Self::surb_peak`]). Against its own peak a healthy edge reads ~1 whatever the
    /// surplus, and one that stops delivering falls toward 0 -- which is the only thing this
    /// signal is asked to say.
    pub fn surb_delivery_rate(&self) -> Option<f64> {
        self.surb_delivery_rate_at(std::time::Instant::now())
    }

    /// [`Self::surb_delivery_rate`] against a caller-supplied clock.
    pub(crate) fn surb_delivery_rate_at(&self, now: std::time::Instant) -> Option<f64> {
        let value = self.surb.value(now)?;
        let peak = self.peak_at(now)?;
        let against_peak = (peak > 0.0).then(|| (value / peak).clamp(0.0, 1.0))?;

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

impl EdgeLinkObservable for TransportIntermediates {
    fn record(&mut self, measurement: EdgeTransportMeasurement) {
        self.link.record(measurement);
    }

    fn average_latency(&self) -> Option<std::time::Duration> {
        self.link.average_latency()
    }

    /// The more pessimistic of the two delivery signals, over whichever of them carry evidence.
    ///
    /// SURB round-trips react sooner -- probing runs on an interval, while SURBs accrue at data
    /// rates -- but sooner is not the same as instead of. The two measure different things: the
    /// probe rate reports reachability of this hop, the SURB rate peak-relative delivery of the
    /// whole loop, and a failing probe is real evidence even while SURBs keep arriving. Taking the
    /// worse of the two lets either signal condemn an edge and neither mask the other.
    ///
    /// Evidence, not merely a number: an unprobed edge's probe rate reads 0.0 exactly as a wholly
    /// failing one does (see [`Self::probed`]), so combining them unconditionally would score every
    /// SURB-only edge as dead.
    fn average_probe_rate(&self) -> Option<f64> {
        match (self.surb_delivery_rate(), self.link.average_probe_rate()) {
            (Some(surb), Some(probe)) => Some(surb.min(probe)),
            (surb, probe) => surb.or(probe),
        }
    }

    fn score(&self) -> Option<f64> {
        // `average_probe_rate` already takes the worse of the probe and SURB signals over whichever
        // carry evidence, and reports `None` when neither does.
        //
        // Latency modulates that rate only where it was measured. A round-trip proves the loop was
        // traversed but carries no per-edge latency, so an edge known solely from SURB delivery has
        // a rate and no latency. Scoring the missing latency as [`latency_score`] does — 0.05, the
        // no-data floor — would multiply real delivery evidence by a twentieth and rank the edge
        // below one nothing at all is known about, inverting the very ordering the score exists to
        // express.
        let rate = self.average_probe_rate()?;
        Some(match self.average_latency() {
            Some(latency) => rate * latency_score(Some(latency)),
            None => rate,
        })
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

    /// Combines the two streams per RFC-0014 §4.2: average when both are present, else the single
    /// present one, else `0.0`.
    ///
    /// "Present" means *has observations*, not *allocated* — a `Balance` update creates the
    /// intermediate stream and `Connected` the immediate one without recording a probe. Treating
    /// allocation as presence averaged against a phantom zero, halving every edge only one stream
    /// can observe: every edge incident to `me`, since immediate probes touch only those and
    /// loopback attribution targets `edges[len - 2]`.
    fn score(&self) -> Option<f64> {
        let immediate = self.immediate_probe.and_then(|m| m.score());
        let intermediate = self.intermediate_probe.and_then(|m| m.score());

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

    /// Neither delivery signal may hide the other; an unprobed edge must not be read as a dead one.
    #[test]
    fn a_failing_probe_should_not_be_masked_by_healthy_surb_traffic() {
        let epoch = std::time::Instant::now();

        let mut surbs_only = fast_slices(epoch);
        deliver_healthily(&mut surbs_only, epoch);
        let surbs_only_rate = surbs_only
            .average_probe_rate()
            .expect("SURB traffic alone is evidence, so the rate must be present");
        assert_in_delta!(surbs_only_rate, 1.0, 0.001);

        // Same healthy SURB window, but every probe of this hop failed. The probe rate is evidence
        // too, and taking the SURB rate alone would discard it.
        let mut probes_failing = fast_slices(epoch);
        deliver_healthily(&mut probes_failing, epoch);
        for _ in 0..5 {
            probes_failing.record(Err(()));
        }

        let failing_rate = probes_failing.average_probe_rate().expect("probed and delivering");
        assert!(
            failing_rate < surbs_only_rate,
            "a hop whose probes all fail must not score as well as one whose probes were never run: \
             failing={failing_rate} unprobed={surbs_only_rate}"
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
