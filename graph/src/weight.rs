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
}

impl EdgeLinkObservable for TransportLinkMeasurement {
    fn record(&mut self, measurement: EdgeTransportMeasurement) {
        if let Ok(latency) = measurement {
            self.latency_average.update(latency.as_millis() as f64);
            self.probe_success_rate.update(1.0);
        } else {
            self.probe_success_rate.update(0.0);
        }
    }

    fn average_latency(&self) -> Option<std::time::Duration> {
        if self.latency_average.get() <= 0.0 {
            None
        } else {
            Some(std::time::Duration::from_millis(self.latency_average.get() as u64))
        }
    }

    fn average_probe_rate(&self) -> f64 {
        self.probe_success_rate.get()
    }

    fn score(&self) -> f64 {
        self.average_probe_rate() * latency_score(self.average_latency())
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
            EdgeWeightType::Capacity(capacity) => self.intermediate_probe.get_or_insert_default().capacity = capacity,
            EdgeWeightType::Connected(is_connected) => {
                self.immediate_probe.get_or_insert_default().is_connected = is_connected
            }
            EdgeWeightType::SurbRoundTrips { expected, observed } => {
                self.intermediate_probe
                    .get_or_insert_default()
                    .record_surb_round_trips(expected, observed);
            }
            EdgeWeightType::ImmediateProtocolConformance { num_packets, num_acks } => {
                let imm = self.immediate_probe.get_or_insert_default();
                imm.messages_sent += num_packets;
                imm.acks_received += num_acks;
            }
        }
    }
}

#[derive(Debug, Copy, Clone, Default, PartialEq)]
pub struct TransportImmediates {
    link: TransportLinkMeasurement,
    is_connected: bool,
    messages_sent: u64,
    acks_received: u64,
}

impl EdgeNetworkObservableRead for TransportImmediates {
    fn is_connected(&self) -> bool {
        self.is_connected
    }
}

impl EdgeImmediateProtocolObservable for TransportImmediates {
    fn ack_rate(&self) -> Option<f64> {
        if self.messages_sent == 0 {
            None
        } else {
            Some(self.acks_received as f64 / self.messages_sent as f64)
        }
    }
}

impl EdgeLinkObservable for TransportImmediates {
    fn record(&mut self, measurement: EdgeTransportMeasurement) {
        self.link.record(measurement)
    }

    fn average_latency(&self) -> Option<std::time::Duration> {
        self.link.average_latency()
    }

    fn average_probe_rate(&self) -> f64 {
        self.link.average_probe_rate()
    }

    fn score(&self) -> f64 {
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

/// Slices read as "lately" when looking for a sudden change: 10 s against the 60 s window.
///
/// Two rather than one so a single slice that happens to straddle a lull cannot, on its own, brand
/// a working relay as gone.
const SURB_RECENT_SLICES: usize = 2;

/// How far the recent slices must fall below the full window before it counts as a collapse.
///
/// A ratio, not an absolute level, so it is unaffected by the balancer surplus that makes the
/// absolute figure meaningless. At 0.5 the last 10 s must be delivering at less than half the rate
/// the minute did before anything is inferred -- ordinary variance stays well inside that.
const SURB_TREND_FLOOR: f64 = 0.5;

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct TransportIntermediates {
    link: TransportLinkMeasurement,
    capacity: Option<u128>,
    /// Delivery observed from real SURB traffic rather than from probes.
    surb: WindowedRatio<SURB_BUCKETS>,
    /// Highest delivery ratio this edge has reached, used to read the window relatively.
    ///
    /// The absolute ratio is not a delivery rate: `expected` counts SURBs *minted*, and the
    /// balancer mints far more than the counterparty spends, so a path carrying every reply
    /// intact still measures well below 1. Measured on a cluster, a fully healthy path reads 0.36.
    /// The surplus is a property of the balancer, not of the path, so it applies alike to every
    /// candidate and cancels the moment the ratio is read against a baseline instead of an
    /// absolute scale.
    surb_peak: f64,
}

impl Default for TransportIntermediates {
    fn default() -> Self {
        Self {
            link: TransportLinkMeasurement::default(),
            capacity: None,
            surb: WindowedRatio::new(SURB_BUCKET_WIDTH, std::time::Instant::now()),
            surb_peak: 0.0,
        }
    }
}

impl TransportIntermediates {
    /// Folds one reporting interval of SURB round-trips into the window.
    pub(crate) fn record_surb_round_trips(&mut self, expected: u64, observed: u64) {
        let now = std::time::Instant::now();
        self.surb.record_expected(expected, now);
        self.surb.record_observed(observed, now);

        if let Some(v) = self.surb.value(now) {
            self.surb_peak = self.surb_peak.max(v);
        }
    }

    /// How the most recent slices compare with the full window, or `None` without evidence in both.
    ///
    /// Below 1 means delivery has fallen off lately. The comparison is what makes this usable: the
    /// full window alone dilutes a fresh collapse across a minute of healthy history, and the
    /// recent slices alone rest on too little evidence to accuse a relay by themselves.
    pub fn surb_trend(&self) -> Option<f64> {
        let now = std::time::Instant::now();
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
        let value = self.surb.value(std::time::Instant::now())?;
        let against_peak = (self.surb_peak > 0.0).then(|| (value / self.surb_peak).clamp(0.0, 1.0))?;

        // A relay that has just stopped delivering still reads well against its peak for most of a
        // minute, because eleven healthy slices outvote the one bad one. Folding the trend in makes
        // that visible within a slice or two -- deliberately as a soft discount rather than a gate,
        // so a relay is displaced by better-scoring peers rather than excluded outright.
        Some(match self.surb_trend() {
            Some(trend) if trend < SURB_TREND_FLOOR => against_peak * trend,
            _ => against_peak,
        })
    }
}

impl EdgeProtocolObservable for TransportIntermediates {
    fn capacity(&self) -> Option<u128> {
        self.capacity
    }
}

impl EdgeLinkObservable for TransportIntermediates {
    fn record(&mut self, measurement: EdgeTransportMeasurement) {
        self.link.record(measurement);
    }

    fn average_latency(&self) -> Option<std::time::Duration> {
        self.link.average_latency()
    }

    /// Real SURB traffic when the window has any, otherwise the probe rate.
    ///
    /// Round-trips are preferred not because probes are wrong but because they are scarce: probing
    /// runs on an interval, while SURBs accrue at data rates, so the window reacts to a relay that
    /// stops delivering far sooner. With no recent traffic there is nothing to prefer and the probe
    /// rate stands.
    fn average_probe_rate(&self) -> f64 {
        self.surb_delivery_rate().unwrap_or_else(|| self.link.average_probe_rate())
    }

    fn score(&self) -> f64 {
        // Latency scoring is left to the link measurement untouched: a round-trip carries no
        // per-edge latency to contribute.
        self.average_probe_rate() * latency_score(self.average_latency())
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

    /// The score combines immediate and intermediate observations:
    /// - When both are present, average their scores (immediate neighbor probes prevent an empty intermediate from
    ///   masking real measurements).
    /// - When only intermediate is present, use it directly.
    /// - When only immediate is present, use it directly.
    fn score(&self) -> f64 {
        match (&self.immediate_probe, &self.intermediate_probe) {
            (Some(imm), Some(inter)) => (imm.score() + inter.score()) / 2.0,
            (None, Some(inter)) => inter.score(),
            (Some(imm), None) => imm.score(),
            (None, None) => 0.0,
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
    fn ack_rate_should_accumulate_across_multiple_records() -> anyhow::Result<()> {
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
        assert_in_delta!(rate, 0.5, 0.001);
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

        assert_in_delta!(observation.score(), 0.5, 0.05);
    }

    #[test]
    fn score_should_average_immediate_and_intermediate_when_both_present() {
        let mut observation = Observations::default();

        // Record a successful immediate probe (simulates neighbor probe success)
        observation.record(EdgeWeightType::Immediate(Ok(std::time::Duration::from_millis(50))));

        // Record on-chain capacity only (simulates channel existing but no loopback probes)
        observation.record(EdgeWeightType::Capacity(Some(100)));

        let imm_score = observation.immediate_qos().unwrap().score();
        let inter_score = observation.intermediate_qos().unwrap().score();

        assert_gt!(imm_score, 0.0, "immediate score should be positive");
        assert_eq!(
            inter_score, 0.0,
            "intermediate score should be zero (no loopback probes)"
        );

        // The combined score should be the average, not zero
        let combined = observation.score();
        assert_gt!(combined, 0.0, "combined score must not be masked by empty intermediate");
        assert_in_delta!(combined, imm_score / 2.0, 0.001);
    }

    #[test]
    fn score_should_use_intermediate_only_when_no_immediate() {
        let mut observation = Observations::default();
        // Record a successful intermediate probe (no immediate probe recorded)
        observation.record(EdgeWeightType::Intermediate(Ok(std::time::Duration::from_millis(80))));
        observation.record(EdgeWeightType::Capacity(Some(500)));

        assert!(observation.immediate_qos().is_none());
        let inter_score = observation.intermediate_qos().unwrap().score();
        assert_gt!(inter_score, 0.0, "intermediate score should be positive");
        assert_in_delta!(observation.score(), inter_score, 0.001);
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
            "the baseline ({full:?}) must be materially longer than the recent window ({recent:?}), \
             otherwise the comparison has nothing to say"
        );
    }

    /// The ring is `Copy` inside a `Copy` observation, read per edge during path search.
    #[test]
    fn the_surb_window_should_stay_cheap_to_copy() {
        let size = std::mem::size_of::<WindowedRatio<SURB_BUCKETS>>();
        assert!(
            size <= 512,
            "WindowedRatio<{SURB_BUCKETS}> is {size} B; widening the ring rather than narrowing the \
             slice makes every edge read more expensive (30 buckets measured 752 B against 320)"
        );
    }

    /// Slices short enough that a test can cross bucket boundaries without sleeping for seconds.
    ///
    /// The production window is 12 x 5 s; the *shape* under test is "recent slices against the
    /// whole window", which is independent of the wall-clock scale.
    fn fast_slices() -> TransportIntermediates {
        TransportIntermediates {
            link: TransportLinkMeasurement::default(),
            capacity: None,
            surb: WindowedRatio::new(TEST_SLICE, std::time::Instant::now()),
            surb_peak: 0.0,
        }
    }

    /// Wide enough that ordinary scheduler jitter cannot push a record into the wrong slice.
    const TEST_SLICE: std::time::Duration = std::time::Duration::from_millis(20);

    /// Records `rounds` intervals, one per slice, **ending on a record**.
    ///
    /// Never sleeps after the last one: the reader uses `Instant::now()`, so a trailing sleep
    /// leaves "now" in an empty slice and the recent window reads `None` instead of the value
    /// just recorded.
    fn record_slices(m: &mut TransportIntermediates, rounds: usize, expected: u64, observed: u64) {
        for i in 0..rounds {
            if i > 0 {
                std::thread::sleep(TEST_SLICE);
            }
            m.record_surb_round_trips(expected, observed);
        }
    }

    /// Fills the window with healthy round-trips spread across several slices.
    fn deliver_healthily(m: &mut TransportIntermediates) {
        record_slices(m, 8, 100, 100);
    }

    /// A relay that stops delivering must be discounted long before the full window notices.
    #[test]
    fn an_edge_whose_delivery_just_collapsed_should_be_discounted_against_a_steady_one() {
        let mut collapsed = fast_slices();
        let mut steady = fast_slices();
        deliver_healthily(&mut collapsed);
        deliver_healthily(&mut steady);
        std::thread::sleep(TEST_SLICE);

        // The recent slices diverge: one keeps answering, the other stops dead.
        for i in 0..2 {
            if i > 0 {
                std::thread::sleep(TEST_SLICE);
            }
            collapsed.record_surb_round_trips(100, 0);
            steady.record_surb_round_trips(100, 100);
        }

        // Vacuity guards: the discount can only be attributed to the trend if the trend actually
        // crossed the floor for one edge and not the other.
        let collapsed_trend = collapsed.surb_trend().expect("both windows hold evidence");
        let steady_trend = steady.surb_trend().expect("both windows hold evidence");
        assert!(
            collapsed_trend < SURB_TREND_FLOOR,
            "the collapsed edge must trip the floor, trend={collapsed_trend}"
        );
        assert!(
            steady_trend >= SURB_TREND_FLOOR,
            "the steady edge must not trip the floor, trend={steady_trend}"
        );

        let collapsed_rate = collapsed.surb_delivery_rate().expect("has traffic");
        let steady_rate = steady.surb_delivery_rate().expect("has traffic");
        assert!(
            collapsed_rate < steady_rate,
            "a relay that just stopped delivering must be discounted below one that has not: \
             collapsed={collapsed_rate} steady={steady_rate}"
        );

        // The comparison above is not enough on its own: the full-window value already differs
        // between the two, so it passes with the trend removed entirely. What must be shown is that
        // the *discount* moved the number -- i.e. the rate sits below the plain peak-relative value.
        let undiscounted = (collapsed.surb.value(std::time::Instant::now()).expect("has traffic")
            / collapsed.surb_peak)
            .clamp(0.0, 1.0);
        assert!(
            collapsed_rate < undiscounted,
            "the trend must discount below the peak-relative value, otherwise it is inert: \
             rate={collapsed_rate} undiscounted={undiscounted}"
        );
    }

    /// The discount must be soft and self-clearing, not a latch.
    #[test]
    fn an_edge_should_recover_its_rate_once_the_recent_slices_climb_back() {
        let mut m = fast_slices();
        deliver_healthily(&mut m);

        std::thread::sleep(TEST_SLICE);
        record_slices(&mut m, 2, 100, 0);
        let during = m.surb_delivery_rate().expect("has traffic");

        // Deliveries resume; the recent slices are what move first.
        std::thread::sleep(TEST_SLICE);
        record_slices(&mut m, 3, 100, 100);
        let after = m.surb_delivery_rate().expect("has traffic");

        assert!(
            after > during,
            "the discount must clear on its own once deliveries resume: during={during} after={after}"
        );
    }

    /// A steady edge must be untouched: the trend is a discount for change, not a standing tax.
    #[test]
    fn a_steadily_delivering_edge_should_not_be_discounted_at_all() {
        let mut m = fast_slices();
        deliver_healthily(&mut m);

        let trend = m.surb_trend().expect("window holds evidence");
        assert!(
            trend >= SURB_TREND_FLOOR,
            "steady delivery must not read as a downward trend, got {trend}"
        );
        assert_in_delta!(m.surb_delivery_rate().expect("has traffic"), 1.0, 0.001);
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

        assert_lt!(
            silent.score(),
            delivering.score(),
            "a relay that stopped returning SURBs must score below one still delivering: silent={} \
             delivering={} (surb rates {s_rate} vs {d_rate})",
            silent.score(),
            delivering.score()
        );
    }

    #[test]
    fn score_should_use_immediate_only_when_no_intermediate() {
        let mut observation = Observations::default();
        observation.record(EdgeWeightType::Immediate(Ok(std::time::Duration::from_millis(50))));

        let imm_score = observation.immediate_qos().unwrap().score();
        assert!(observation.intermediate_qos().is_none());
        assert_in_delta!(observation.score(), imm_score, 0.001);
    }
}
