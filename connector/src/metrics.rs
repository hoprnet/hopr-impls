//! OpenTelemetry instruments for chain writes and chain state.
//!
//! Chain writes are counted and timed in the transaction sequencer, chain state gauges are
//! refreshed from the connector's connected workflow. The instruments register on the global
//! meter through `hopr_api`'s telemetry types, so a consumer that enables the `telemetry` feature
//! reads them with its existing exporter.
//!
//! Without the feature, every function here records nothing and no instrument exists.

use std::time::Instant;

#[cfg(feature = "telemetry")]
use hopr_api::types::internal::prelude::{ChannelDirection, ChannelEntry, ChannelStatus};

/// Phase of a chain write: from the dequeue to the tracking id Blokli returns.
pub(crate) const PHASE_SUBMIT: &str = "submit";
/// Phase of a chain write: from the tracking id to the final tracking outcome.
pub(crate) const PHASE_TRACK: &str = "track";

#[cfg(all(feature = "telemetry", not(test)))]
lazy_static::lazy_static! {
    static ref TX_OUTCOMES: hopr_api::types::telemetry::MultiCounter = hopr_api::types::telemetry::MultiCounter::new(
        "hopr_chain_tx_outcomes_total",
        "Chain write outcomes by operation, phase and outcome",
        &["operation", "phase", "outcome"]
    ).unwrap();
    static ref TX_DURATION: hopr_api::types::telemetry::MultiHistogram = hopr_api::types::telemetry::MultiHistogram::new(
        "hopr_chain_tx_duration_seconds",
        "Time a chain write spends in a phase, in seconds",
        vec![0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0],
        &["operation", "phase"]
    ).unwrap();
    static ref TX_QUEUE_LENGTH: hopr_api::types::telemetry::SimpleGauge = hopr_api::types::telemetry::SimpleGauge::new(
        "hopr_chain_tx_queue_length",
        "Chain writes waiting for the transaction sequencer"
    ).unwrap();
    static ref NONCE: hopr_api::types::telemetry::MultiGauge = hopr_api::types::telemetry::MultiGauge::new(
        "hopr_chain_nonce",
        "Nonce observed on a submission cycle. kind=local is the nonce signed, kind=chain_pending is the chain's pending count",
        &["kind"]
    ).unwrap();
    static ref CALLER_ABANDONED: hopr_api::types::telemetry::MultiCounter = hopr_api::types::telemetry::MultiCounter::new(
        "hopr_chain_caller_abandoned_total",
        "Chain writes whose caller stopped waiting for the result while the transaction stayed live",
        &["operation"]
    ).unwrap();
    static ref SAFE_BALANCE: hopr_api::types::telemetry::SimpleGauge = hopr_api::types::telemetry::SimpleGauge::new(
        "hopr_chain_safe_balance",
        "wxHOPR balance of the node's Safe in token base units"
    ).unwrap();
    static ref SAFE_ALLOWANCE: hopr_api::types::telemetry::SimpleGauge = hopr_api::types::telemetry::SimpleGauge::new(
        "hopr_chain_safe_allowance",
        "wxHOPR allowance granted by the node's Safe to the module, in token base units"
    ).unwrap();
    static ref CHANNELS: hopr_api::types::telemetry::MultiGauge = hopr_api::types::telemetry::MultiGauge::new(
        "hopr_chain_channels",
        "Local channels by direction and on-chain status",
        &["direction", "status"]
    ).unwrap();
    static ref USABLE_OUTGOING_CHANNELS: hopr_api::types::telemetry::SimpleGauge = hopr_api::types::telemetry::SimpleGauge::new(
        "hopr_chain_usable_outgoing_channels",
        "Peers this node has an open outgoing channel to"
    ).unwrap();
    static ref BLOKLI_INDEXED_HEAD: hopr_api::types::telemetry::SimpleGauge = hopr_api::types::telemetry::SimpleGauge::new(
        "hopr_chain_blokli_indexed_head",
        "Latest block number indexed or observed by Blokli"
    ).unwrap();
    static ref BLOKLI_INFO_AGE: hopr_api::types::telemetry::SimpleGauge = hopr_api::types::telemetry::SimpleGauge::new(
        "hopr_chain_blokli_info_age_seconds",
        "Seconds since the last successful Blokli chain info query"
    ).unwrap();
}

/// Records into an instrument, or evaluates the arguments and drops them when telemetry is off.
///
/// Test builds never touch the instruments: they share one global meter, so a test run must not
/// register production metrics.
macro_rules! instrument {
    ($instrument:ident, $method:ident $(, $arg:expr)*) => {{
        #[cfg(all(feature = "telemetry", not(test)))]
        $instrument.$method($($arg),*);
        #[cfg(not(all(feature = "telemetry", not(test))))]
        {
            let _ = ($($arg,)*);
        }
    }};
}

/// Records the outcome of one phase of a chain write.
pub(crate) fn record_tx_outcome(operation: &str, phase: &str, outcome: &str) {
    instrument!(TX_OUTCOMES, increment, &[operation, phase, outcome]);
}

/// Records how long one phase of a chain write took, in seconds.
pub(crate) fn record_tx_duration(operation: &str, phase: &str, seconds: f64) {
    instrument!(TX_DURATION, observe, &[operation, phase], seconds);
}

/// Records how many chain writes wait for the sequencer.
pub(crate) fn record_queue_length(length: u64) {
    instrument!(TX_QUEUE_LENGTH, set, length as f64);
}

/// Records a nonce observed on a submission cycle.
pub(crate) fn record_nonce(kind: &str, nonce: u64) {
    instrument!(NONCE, set, &[kind], nonce as f64);
}

/// Records a chain write whose caller stopped waiting for the result.
pub(crate) fn record_caller_abandoned(operation: &str) {
    instrument!(CALLER_ABANDONED, increment, &[operation]);
}

/// Records the node Safe's token balance in base units.
#[cfg(feature = "telemetry")]
pub(crate) fn record_safe_balance(base_units: f64) {
    instrument!(SAFE_BALANCE, set, base_units);
}

/// Records the allowance the node Safe grants in base units.
#[cfg(feature = "telemetry")]
pub(crate) fn record_safe_allowance(base_units: f64) {
    instrument!(SAFE_ALLOWANCE, set, base_units);
}

/// Records the number of local channels for one direction and status.
#[cfg(feature = "telemetry")]
pub(crate) fn record_channel_count(direction: &str, status: &str, count: u64) {
    instrument!(CHANNELS, set, &[direction, status], count as f64);
}

/// Records the number of peers with an open outgoing channel.
#[cfg(feature = "telemetry")]
pub(crate) fn record_usable_outgoing_channels(count: u64) {
    instrument!(USABLE_OUTGOING_CHANNELS, set, count as f64);
}

/// Records the latest block number Blokli indexed or observed.
#[cfg(feature = "telemetry")]
pub(crate) fn record_blokli_indexed_head(block_number: u64) {
    instrument!(BLOKLI_INDEXED_HEAD, set, block_number as f64);
}

/// Records how long ago the last successful Blokli chain info query was.
#[cfg(feature = "telemetry")]
pub(crate) fn record_blokli_info_age(seconds: f64) {
    instrument!(BLOKLI_INFO_AGE, set, seconds);
}

/// Seconds between two instants, zero when `now` is before `since`.
pub(crate) fn elapsed_seconds(since: Instant, now: Instant) -> f64 {
    now.saturating_duration_since(since).as_secs_f64()
}

/// Chain writes queued between `enqueue` and dequeue.
///
/// The queue length gauge is set from this counter, so it also covers writes whose caller left: a
/// write that nobody waits for still occupies a queue slot until the sequencer takes it. The gauge
/// is published under the lock that moves the counter, so a concurrent dequeue cannot leave the
/// previous length behind as the last published value.
#[derive(Debug, Default)]
pub(crate) struct QueueDepth(parking_lot::Mutex<u64>);

impl QueueDepth {
    /// Counts a write that entered the queue.
    pub(crate) fn enqueued(&self) {
        let mut length = self.0.lock();
        *length += 1;
        record_queue_length(*length);
    }

    /// Counts a write the sequencer took out of the queue.
    pub(crate) fn dequeued(&self) {
        let mut length = self.0.lock();
        *length = length.saturating_sub(1);
        record_queue_length(*length);
    }

    /// Number of writes waiting in the queue.
    #[cfg(test)]
    pub(crate) fn get(&self) -> u64 {
        *self.0.lock()
    }
}

/// Direction label values of [`CHANNELS`], in the order the counts are stored.
#[cfg(feature = "telemetry")]
const DIRECTIONS: [&str; 2] = ["incoming", "outgoing"];
/// Status label values of [`CHANNELS`], in the order the counts are stored.
#[cfg(feature = "telemetry")]
const STATUSES: [&str; 3] = ["open", "pending_to_close", "closed"];

#[cfg(feature = "telemetry")]
fn status_index(status: ChannelStatus) -> usize {
    match status {
        ChannelStatus::Open => 0,
        ChannelStatus::PendingToClose(_) => 1,
        ChannelStatus::Closed => 2,
    }
}

/// Local channel counts per direction and on-chain status.
///
/// Open is counted apart from pending-to-close: a draining channel still exists on chain but can no
/// longer carry traffic. An open channel without funds counts as open but not as usable, because
/// path finding drops its edge.
#[derive(Debug, Default)]
#[cfg(feature = "telemetry")]
pub(crate) struct ChannelGauges {
    counts: [[u64; STATUSES.len()]; DIRECTIONS.len()],
    usable_peers: std::collections::HashSet<hopr_api::Address>,
}

#[cfg(feature = "telemetry")]
impl ChannelGauges {
    /// Counts one local channel of the node at `me`.
    pub(crate) fn record(&mut self, channel: &ChannelEntry, me: hopr_api::Address) {
        let Some(direction) = channel.direction(&me) else {
            return;
        };
        let direction = match direction {
            ChannelDirection::Incoming => 0,
            ChannelDirection::Outgoing => 1,
        };
        let status = status_index(channel.status);
        self.counts[direction][status] += 1;
        // Only a funded, open outgoing channel can carry traffic this node initiates: path finding
        // drops the edge of a drained channel, which is what a lost usable channel looks like.
        if direction == 1 && status == 0 && !channel.balance.amount().is_zero() {
            self.usable_peers.insert(channel.destination);
        }
    }

    /// Count for one direction and status label.
    #[cfg(test)]
    pub(crate) fn count(&self, direction: &str, status: &str) -> u64 {
        let direction = DIRECTIONS
            .iter()
            .position(|d| *d == direction)
            .expect("known direction label");
        let status = STATUSES.iter().position(|s| *s == status).expect("known status label");
        self.counts[direction][status]
    }

    /// Distinct peers with an open outgoing channel.
    pub(crate) fn usable_outgoing(&self) -> u64 {
        self.usable_peers.len() as u64
    }

    /// Sets every gauge, including zero for combinations the node has no channel for.
    pub(crate) fn apply(&self) {
        for (direction, counts) in DIRECTIONS.iter().zip(self.counts.iter()) {
            for (status, count) in STATUSES.iter().zip(counts.iter()) {
                record_channel_count(direction, status, *count);
            }
        }
        record_usable_outgoing_channels(self.usable_outgoing());
    }
}

/// Age of the last successful Blokli chain info query.
///
/// Blokli reports one block number, the latest it indexed or observed, so head lag cannot be
/// measured. This tracks how long ago the connector last got an answer at all: a stalled index
/// still answers, so the age stays low and the indexed-head gauge stays put.
#[derive(Debug, Default)]
#[cfg(feature = "telemetry")]
pub(crate) struct InfoFreshness(parking_lot::Mutex<Option<Instant>>);

#[cfg(feature = "telemetry")]
impl InfoFreshness {
    /// Records a successful chain info query. The info age drops to zero.
    pub(crate) fn success(&self) {
        self.success_at(Instant::now());
    }

    fn success_at(&self, at: Instant) {
        *self.0.lock() = Some(at);
        record_blokli_info_age(0.0);
    }

    /// Records a failed chain info query. The info age grows since the last success.
    pub(crate) fn failure(&self) {
        let now = Instant::now();
        if let Some(since) = *self.0.lock() {
            record_blokli_info_age(elapsed_seconds(since, now));
        }
    }

    /// Seconds since the last successful query at `now`, `None` before the first success.
    #[cfg(test)]
    fn age_at(&self, now: Instant) -> Option<f64> {
        // Deref the guard before mapping: `MutexGuard` already projects to the inner `Option`.
        let since = *self.0.lock();
        since.map(|since| elapsed_seconds(since, now))
    }
}

/// Token base units as a gauge value.
///
/// A gauge holds an `f64`, which represents integers exactly up to 2^53. Larger amounts round to
/// the nearest representable value, a relative error under 2^-53, far below any alert threshold.
#[cfg(feature = "telemetry")]
fn base_units(amount: hopr_api::graph::traits::Balance) -> f64 {
    // Assemble the value from all four limbs. `low_u128` would drop the upper half of a large
    // amount and report it as a small one.
    let [low, low_mid, high_mid, high] = amount.0;
    high as f64 * 2f64.powi(192) + high_mid as f64 * 2f64.powi(128) + low_mid as f64 * 2f64.powi(64) + low as f64
}

/// Set while a gauge refresh runs, so a slow refresh cannot pile up behind the ticker.
#[cfg(feature = "telemetry")]
static REFRESH_IN_FLIGHT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// How long one gauge refresh may take. Shorter than the tick, so a stalled read cannot block the
/// next one.
#[cfg(feature = "telemetry")]
const GAUGE_REFRESH_BUDGET: std::time::Duration = std::time::Duration::from_secs(30);

/// Runs one gauge refresh unless another is running, and gives up after `budget`.
///
/// A stalled backend read is dropped together with the refresh, which releases the in-flight slot
/// so the next tick can start. Returns `false` when a refresh was already running.
#[cfg(feature = "telemetry")]
async fn refresh_within_budget<F>(refresh: F, budget: std::time::Duration) -> bool
where
    F: std::future::Future<Output = ()>,
{
    use futures_time::future::FutureExt;

    if REFRESH_IN_FLIGHT.swap(true, std::sync::atomic::Ordering::AcqRel) {
        return false;
    }
    let _in_flight = RefreshInFlight;
    if refresh
        .timeout(futures_time::time::Duration::from(budget))
        .await
        .is_err()
    {
        tracing::warn!(?budget, "chain gauge refresh timed out");
    }
    true
}

/// Clears [`REFRESH_IN_FLIGHT`] however the refresh ends, including an abort.
#[cfg(feature = "telemetry")]
struct RefreshInFlight;

#[cfg(feature = "telemetry")]
impl Drop for RefreshInFlight {
    fn drop(&mut self) {
        REFRESH_IN_FLIGHT.store(false, std::sync::atomic::Ordering::Release);
    }
}

/// Reads the chain state and sets the state gauges.
///
/// Every gauge is set to an absolute value. A refresh that is still running when the next tick
/// arrives makes that tick a no-op, so slow reads cannot queue up. Read failures leave the last
/// value in place: a partial channel count would look like the node lost channels.
#[cfg(feature = "telemetry")]
pub(crate) async fn refresh_chain_gauges<C, B>(
    client: std::sync::Arc<C>,
    backend: std::sync::Arc<B>,
    graph: std::sync::Arc<
        parking_lot::RwLock<
            petgraph::prelude::DiGraphMap<
                hopr_api::chain::HoprKeyIdent,
                hopr_api::types::internal::prelude::ChannelId,
                ahash::RandomState,
            >,
        >,
    >,
    me: hopr_api::Address,
    freshness: std::sync::Arc<InfoFreshness>,
) where
    C: blokli_client::api::BlokliQueryClient + blokli_client::api::BlokliSubscriptionClient + Send + Sync + 'static,
    B: crate::Backend + Send + Sync + 'static,
{
    let ran = refresh_within_budget(
        read_and_set_gauges(client, backend, graph, me, freshness),
        GAUGE_REFRESH_BUDGET,
    )
    .await;
    if !ran {
        tracing::debug!("skipping the chain gauge refresh, the previous one is still running");
    }
}

/// Reads the chain state and sets the gauges. Bounded by [`refresh_within_budget`].
#[cfg(feature = "telemetry")]
async fn read_and_set_gauges<C, B>(
    client: std::sync::Arc<C>,
    backend: std::sync::Arc<B>,
    graph: std::sync::Arc<
        parking_lot::RwLock<
            petgraph::prelude::DiGraphMap<
                hopr_api::chain::HoprKeyIdent,
                hopr_api::types::internal::prelude::ChannelId,
                ahash::RandomState,
            >,
        >,
    >,
    me: hopr_api::Address,
    freshness: std::sync::Arc<InfoFreshness>,
) where
    C: blokli_client::api::BlokliQueryClient + blokli_client::api::BlokliSubscriptionClient + Send + Sync + 'static,
    B: crate::Backend + Send + Sync + 'static,
{
    match client.query_chain_info().await {
        Ok(info) => {
            record_blokli_indexed_head(u64::try_from(info.block_number).unwrap_or_default());
            freshness.success();
        }
        Err(error) => {
            tracing::debug!(%error, "cannot read the blokli chain info for metrics");
            freshness.failure();
        }
    }

    let reader = crate::HoprBlockchainReader(client.clone());
    match node_safe(&reader, me).await {
        Some(safe) => set_safe_gauges(&reader, safe).await,
        None => tracing::debug!(%me, "node has no safe, safe gauges are not set"),
    }

    match collect_channel_gauges(&backend, &graph, me).await {
        Some(gauges) => gauges.apply(),
        None => tracing::debug!("chain gauges not refreshed, the local channel read was incomplete"),
    }
}

/// The Safe the node signs with: the one it is registered with, else the one it deployed.
#[cfg(feature = "telemetry")]
async fn node_safe<C>(reader: &crate::HoprBlockchainReader<C>, me: hopr_api::Address) -> Option<hopr_api::Address>
where
    C: blokli_client::api::BlokliQueryClient + blokli_client::api::BlokliSubscriptionClient + Send + Sync,
{
    use hopr_api::chain::{ChainReadSafeOperations, SafeSelector};

    match reader.safe_info(SafeSelector::NodeAddress(me)).await {
        Ok(Some(safe)) => Some(safe.address),
        Ok(None) => match reader.safe_info(SafeSelector::Deployer(me)).await {
            Ok(Some(safe)) => Some(safe.address),
            Ok(None) => None,
            Err(error) => {
                tracing::debug!(%error, "cannot read the safe the node deployed for metrics");
                None
            }
        },
        Err(error) => {
            // A failed lookup must not switch to another safe: the gauges would then pair one
            // safe's balance with the other's allowance.
            tracing::debug!(%error, "cannot read the safe the node is registered with for metrics");
            None
        }
    }
}

#[cfg(feature = "telemetry")]
async fn set_safe_gauges<C>(reader: &crate::HoprBlockchainReader<C>, safe: hopr_api::Address)
where
    C: blokli_client::api::BlokliQueryClient + blokli_client::api::BlokliSubscriptionClient + Send + Sync,
{
    use hopr_api::{
        chain::{ChainReadSafeOperations, ChainValues},
        types::primitive::prelude::WxHOPR,
    };

    let balance = match reader.balance::<WxHOPR, _>(safe).await {
        Ok(balance) => base_units(balance.amount()),
        Err(error) => {
            tracing::debug!(%error, "cannot read the safe balance for metrics");
            return;
        }
    };
    let allowance = match reader.safe_allowance::<WxHOPR, _>(safe).await {
        Ok(allowance) => base_units(allowance.amount()),
        Err(error) => {
            tracing::debug!(%error, "cannot read the safe allowance for metrics");
            return;
        }
    };
    // Both values come from the same Safe, so they are published together. Publishing one of them
    // alone could pair a new Safe's balance with the previous Safe's allowance.
    record_safe_balance(balance);
    record_safe_allowance(allowance);
}

/// Backend reads per blocking batch while counting channels.
#[cfg(feature = "telemetry")]
const CHANNEL_READ_BATCH: usize = 64;

#[cfg(feature = "telemetry")]
async fn collect_channel_gauges<B>(
    backend: &std::sync::Arc<B>,
    graph: &std::sync::Arc<
        parking_lot::RwLock<
            petgraph::prelude::DiGraphMap<
                hopr_api::chain::HoprKeyIdent,
                hopr_api::types::internal::prelude::ChannelId,
                ahash::RandomState,
            >,
        >,
    >,
    me: hopr_api::Address,
) -> Option<ChannelGauges>
where
    B: crate::Backend + Send + Sync + 'static,
{
    let ids = {
        let backend = backend.clone();
        let graph = graph.clone();
        hopr_utils::runtime::prelude::spawn_blocking(move || local_channel_ids(backend.as_ref(), &graph, me)).await
    };
    let ids = match ids {
        Ok(Ok(ids)) => ids,
        Ok(Err(error)) => {
            tracing::warn!(%error, "cannot enumerate the local channels for metrics");
            return None;
        }
        Err(error) => {
            tracing::warn!(%error, "channel enumeration failed for metrics");
            return None;
        }
    };

    let mut gauges = ChannelGauges::default();
    for batch in ids.chunks(CHANNEL_READ_BATCH) {
        let batch = batch.to_vec();
        let backend = backend.clone();
        let entries = hopr_utils::runtime::prelude::spawn_blocking(move || -> Result<Vec<ChannelEntry>, String> {
            batch
                .iter()
                .map(|id| {
                    backend
                        .get_channel_by_id(id)
                        .map_err(|error| format!("{id}: {error}"))?
                        .ok_or_else(|| format!("{id}: missing"))
                })
                .collect()
        })
        .await;
        let entries = match entries {
            Ok(Ok(entries)) => entries,
            Ok(Err(error)) => {
                tracing::warn!(%error, "cannot read a local channel for metrics");
                return None;
            }
            Err(error) => {
                tracing::warn!(%error, "local channel read failed for metrics");
                return None;
            }
        };
        for entry in entries.iter() {
            gauges.record(entry, me);
        }
    }
    Some(gauges)
}

/// Channel ids of both directions that involve the account at `me`.
#[cfg(feature = "telemetry")]
fn local_channel_ids<B>(
    backend: &B,
    graph: &parking_lot::RwLock<
        petgraph::prelude::DiGraphMap<
            hopr_api::chain::HoprKeyIdent,
            hopr_api::types::internal::prelude::ChannelId,
            ahash::RandomState,
        >,
    >,
    me: hopr_api::Address,
) -> Result<Vec<hopr_api::types::internal::prelude::ChannelId>, String>
where
    B: crate::Backend,
{
    let account = backend
        .get_account_by_address(&me)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "the local account is missing".to_string())?;
    let graph = graph.read();
    Ok(graph
        .edges(account.key_id)
        .chain(
            graph
                .edges_directed(account.key_id, petgraph::Direction::Incoming)
                .filter(|(src, ..)| *src != account.key_id),
        )
        .map(|(_, _, id)| *id)
        .collect())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn queue_depth_counts_writes_between_enqueue_and_dequeue() {
        let depth = QueueDepth::default();

        assert_eq!(0, depth.get());
        depth.enqueued();
        depth.enqueued();
        assert_eq!(2, depth.get());
        depth.dequeued();
        assert_eq!(1, depth.get());
        depth.dequeued();
        depth.dequeued();
        assert_eq!(0, depth.get(), "the depth never goes below zero");
    }

    #[test]
    fn elapsed_seconds_measures_phase_durations() {
        let now = Instant::now();
        let since = now - Duration::from_millis(1500);

        assert_eq!(1.5, elapsed_seconds(since, now));
        assert_eq!(0.0, elapsed_seconds(now, since), "clocks that ran backwards");
    }

    #[cfg(feature = "telemetry")]
    #[test]
    fn info_age_is_measured_from_the_last_successful_read() {
        let freshness = InfoFreshness::default();
        let now = Instant::now();

        assert_eq!(None, freshness.age_at(now), "nothing was read yet");

        freshness.success_at(now);
        assert_eq!(Some(0.0), freshness.age_at(now), "a fresh read");

        freshness.success_at(now - Duration::from_secs(5));
        assert_eq!(Some(5.0), freshness.age_at(now), "an older read");

        // A failed read leaves the last success in place, so the age keeps growing.
        freshness.failure();
        assert!(
            freshness
                .age_at(now + Duration::from_secs(5))
                .is_some_and(|age| age >= 10.0)
        );
    }

    #[cfg(feature = "telemetry")]
    #[tokio::test]
    async fn a_stalled_refresh_releases_its_slot_for_the_next_one() {
        let budget = Duration::from_millis(50);

        // A refresh that never finishes is dropped at its deadline.
        assert!(
            refresh_within_budget(std::future::pending(), budget).await,
            "the first refresh runs"
        );
        assert!(
            refresh_within_budget(async {}, budget).await,
            "a later refresh runs once the stalled one was dropped"
        );

        // While one refresh runs, the next tick is skipped.
        let stalled = refresh_within_budget(std::future::pending(), budget);
        let overlapping = refresh_within_budget(async {}, budget);
        assert_eq!((true, false), futures::join!(stalled, overlapping));
    }

    #[cfg(feature = "telemetry")]
    #[test]
    fn token_amounts_are_reported_in_base_units() {
        // 150 wxHOPR at 18 decimals, the amount the jura-prod incident overspent on one channel.
        let amount = hopr_api::graph::traits::Balance::from(150_000_000_000_000_000_000u128);

        assert_eq!(1.5e20, base_units(amount));
        assert_eq!(0.0, base_units(hopr_api::graph::traits::Balance::zero()));
        assert_eq!(
            2f64.powi(200),
            base_units(hopr_api::graph::traits::Balance::from(1u8) << 200),
            "an amount above 2^128 must not be reported as zero"
        );
    }
}
