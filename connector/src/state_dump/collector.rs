use std::{
    collections::HashSet,
    future::Future,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use futures::{Stream, StreamExt};
use futures_time::future::FutureExt;
use hopr_api::{
    OffchainPublicKey,
    chain::{ChainKeyOperations, ChainReadChannelOperations, ChainReadSafeOperations, ChainValues},
    graph::{
        EdgeLinkObservable, NetworkGraphView,
        traits::{EdgeNetworkObservableRead, EdgeObservableRead},
    },
    network::NetworkView,
    types::{
        internal::prelude::{ChannelEntry, ChannelStatus},
        primitive::prelude::{Address, WxHOPR},
    },
};

use super::{Amount, ChannelDirection, ChannelSample, Channels, IntervalCounters, IntervalSnapshot, Section, Snapshot};

/// Cap per-node channel detail independently of network size.
pub const MAX_CHANNEL_SAMPLES: usize = 4;
/// Bound the serialized snapshot payload, excluding the embedding logger's envelope.
pub const MAX_SNAPSHOT_BYTES: usize = 24 * 1024;
const LOW_PROBE_RATE: f64 = 0.9;

/// Validated reporter timing. No global environment mutation or runtime is needed.
#[derive(Clone, Debug)]
pub struct Config {
    interval: Option<Duration>,
    timeout: Duration,
}
/// Invalid timing configuration is rejected before collection starts.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct ConfigError(&'static str);
impl Default for Config {
    fn default() -> Self {
        Self {
            interval: Some(Duration::from_secs(60)),
            timeout: Duration::from_secs(5),
        }
    }
}
impl Config {
    /// Seconds between INFO records; 0 disables periodic collection.
    pub fn new(seconds: u64) -> Result<Self, ConfigError> {
        let interval = match seconds {
            0 => None,
            5..=86400 => Some(Duration::from_secs(seconds)),
            _ => return Err(ConfigError("report interval must be 0 or 5..86400 seconds")),
        };
        Ok(Self {
            interval,
            ..Self::default()
        })
    }

    /// Read HOPR_STATE_DUMP_INTERVAL, defaulting to 60 seconds when absent.
    pub fn from_env() -> Result<Self, ConfigError> {
        match std::env::var("HOPR_STATE_DUMP_INTERVAL") {
            Ok(v) => Self::new(
                v.parse()
                    .map_err(|_| ConfigError("HOPR_STATE_DUMP_INTERVAL must be integer seconds"))?,
            ),
            Err(std::env::VarError::NotPresent) => Ok(Self::default()),
            Err(_) => Err(ConfigError("HOPR_STATE_DUMP_INTERVAL is not UTF-8")),
        }
    }

    /// Deadline for each asynchronous source (default 5 seconds, maximum 5 seconds).
    /// A shorter deadline may suit a cached source or tests.
    pub fn with_source_timeout(mut self, timeout: Duration) -> Result<Self, ConfigError> {
        if timeout.is_zero() || timeout > Duration::from_secs(5) {
            return Err(ConfigError("source timeout must be positive and at most 5 seconds"));
        }
        self.timeout = timeout;
        Ok(self)
    }

    /// None means disabled; callers should avoid wiring producer counters in that case.
    pub fn interval(&self) -> Option<Duration> {
        self.interval
    }
}
/// JSON encoding failed or a caller-modified snapshot exceeded the fixed payload budget.
#[derive(Debug, thiserror::Error)]
pub enum EncodeError {
    #[error("snapshot JSON encoding failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("snapshot exceeds the {MAX_SNAPSHOT_BYTES}-byte payload budget")]
    TooLarge,
}
impl Snapshot {
    /// Encode one bounded JSON object. Amounts are decimal strings, never floating point.
    pub fn to_json(&self) -> Result<String, EncodeError> {
        let json = serde_json::to_string(self)?;
        if json.len() > MAX_SNAPSHOT_BYTES {
            return Err(EncodeError::TooLarge);
        }
        Ok(json)
    }

    /// Emit exactly one INFO event through the application's existing subscriber.
    /// JSON formatters render the state field as a string; parse it with `fromjson` when extracting.
    pub fn emit(&self) {
        match self.to_json() {
            Ok(state) => tracing::info!(parent:None,event="node_state",state=%state,"node operational state"),
            Err(error) => {
                tracing::info!(parent:None,event="node_state",node=%self.node,sequence=self.sequence,status="encoding_error",%error,"node operational state")
            }
        }
    }
}

/// Reusable collector using chain read traits and the error-preserving `StateRead` interface.
pub struct Collector<C, G, N> {
    chain: C,
    graph: G,
    network: N,
    safe_address: Address,
    config: Config,
    sequence: AtomicU64,
}
impl<C, G, N> Collector<C, G, N>
where
    C: ChainValues
        + ChainReadSafeOperations
        + ChainReadChannelOperations
        + super::StateRead
        + ChainKeyOperations
        + Sync,
    G: NetworkGraphView<NodeId = OffchainPublicKey> + Sync,
    G::Observed: EdgeObservableRead,
    N: NetworkView + Sync,
{
    /// The views supply node identities; the host supplies the Safe address.
    pub fn new(chain: C, graph: G, network: N, safe_address: Address, config: Config) -> Self {
        Self {
            chain,
            graph,
            network,
            safe_address,
            config,
            sequence: AtomicU64::new(0),
        }
    }

    /// Collect one snapshot on demand. None explicitly marks routing/SURB producers unavailable.
    /// Values are independently read, not an atomic/freshness-verified chain snapshot.
    pub async fn collect(&self, routing: Option<IntervalSnapshot>) -> Snapshot {
        let started = Instant::now();
        // Classify every local channel against the same face-value observation.
        let face = self.graph.ticket_face_value();
        let (balance, allowance, channels, announced) = futures::join!(
            section(self.config.timeout, async {
                self.chain
                    .balance::<WxHOPR, _>(self.safe_address)
                    .await
                    .map(|b| Amount(b.amount()))
                    .map_err(|e| e.to_string())
            }),
            section(self.config.timeout, async {
                self.chain
                    .safe_allowance::<WxHOPR, _>(self.safe_address)
                    .await
                    .map(|b| Amount(b.amount()))
                    .map_err(|e| e.to_string())
            }),
            self.channels(face),
            section(self.config.timeout, async { self.chain.announced_count() }),
        );
        Snapshot {
            schema_version: 1,
            node: *self.graph.identity(),
            node_address: *self.chain.me(),
            safe_address: self.safe_address,
            sequence: self.sequence.fetch_add(1, Ordering::Relaxed),
            collected_at_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis()
                .min(u64::MAX as u128) as u64,
            collection_ms: started.elapsed().as_millis().min(u64::MAX as u128) as u64,
            chain_freshness: "unverified",
            safe_balance: balance,
            safe_allowance: allowance,
            channels,
            connected_peers: self.network.connected_peers().len() as u64,
            announced_peers: announced,
            routing: routing
                .map(|value| Section::Ok { value })
                .unwrap_or(Section::Unavailable),
        }
    }

    /// Run the configured periodic reporter. The host owns spawning/cancellation and the logger.
    /// Disabled reporting returns immediately, does no reads, and does not drain supplied counters.
    pub async fn run(&self, counters: Option<IntervalCounters>) {
        if let Some(interval) = self.config.interval {
            let ticks = futures_time::stream::interval(futures_time::time::Duration::from(interval)).map(|_| ());
            self.run_on(ticks, counters).await;
        }
    }

    pub(crate) async fn run_on<S: Stream<Item = ()> + Unpin>(&self, mut ticks: S, counters: Option<IntervalCounters>) {
        if self.config.interval.is_none() {
            return;
        }
        while ticks.next().await.is_some() {
            self.collect(counters.as_ref().map(IntervalCounters::take_snapshot))
                .await
                .emit();
        }
    }

    async fn channels(&self, face: Option<hopr_api::graph::traits::Balance>) -> Section<Channels> {
        let mut summary = Channels {
            scope: "source_visible",
            funding_value: face.map(Amount),
            low_probe_threshold: LOW_PROBE_RATE,
            ..Default::default()
        };
        let mut stream = match self.chain.local_channels() {
            Ok(stream) => stream,
            Err(message) => {
                return Section::Error {
                    message: message.chars().take(120).collect(),
                };
            }
        };
        let mut peers = HashSet::new();
        // Keep progress on timeout instead of discarding already collected observations.
        let completed = async {
            while let Some(result) = stream.next().await {
                let channel = match result {
                    Ok(channel) => {
                        summary.reads.read_ok += 1;
                        channel
                    }
                    Err(error) => {
                        summary.reads.record(error);
                        continue;
                    }
                };
                let direction = if channel.source == *self.chain.me() {
                    ChannelDirection::Outgoing
                } else {
                    ChannelDirection::Incoming
                };
                let peer = if direction == ChannelDirection::Outgoing {
                    channel.destination
                } else {
                    channel.source
                };
                let key = match self.chain.chain_key_to_packet_key(&peer) {
                    Ok(key) => key,
                    Err(error) => {
                        summary.reads.record(super::ReadFailure {
                            entity: peer.to_string(),
                            kind: "identity",
                            message: error.to_string(),
                        });
                        None
                    }
                };
                let transport_connected = key.map(|k| self.network.is_connected(&k.into()));
                let observation = key.and_then(|k| self.graph.edge(self.graph.identity(), &k));
                let qos = observation.as_ref().and_then(|o| o.immediate_qos());
                let connected = qos.and_then(|q| q.is_connected());
                let probe = qos.and_then(|q| q.average_probe_rate());
                let count_peer = channel.status == ChannelStatus::Open && peers.insert(peer);
                summary.record(&channel, direction, connected, transport_connected, probe, count_peer);
            }
        }
        .timeout(futures_time::time::Duration::from(self.config.timeout))
        .await
        .is_ok();
        summary.reads.timed_out = !completed;
        summary.reads.complete = completed
            && summary.reads.missing == 0
            && summary.reads.backend_errors == 0
            && summary.reads.join_errors == 0
            && summary.reads.identity_errors == 0;
        summary.omitted = summary.problematic.saturating_sub(summary.sample.len() as u64);
        if summary.reads.complete {
            Section::Ok { value: summary }
        } else {
            Section::Partial { value: summary }
        }
    }
}
async fn section<T>(timeout: Duration, future: impl Future<Output = Result<T, String>>) -> Section<T> {
    match future.timeout(futures_time::time::Duration::from(timeout)).await {
        Ok(Ok(value)) => Section::Ok { value },
        Ok(Err(message)) => Section::Error {
            message: message.chars().take(120).collect(),
        },
        Err(_) => Section::Timeout,
    }
}
impl Channels {
    fn record(
        &mut self,
        c: &ChannelEntry,
        direction: ChannelDirection,
        connected: Option<bool>,
        transport_connected: Option<bool>,
        probe: Option<f64>,
        count_peer: bool,
    ) {
        self.total += 1;
        let counts = if direction == ChannelDirection::Outgoing {
            &mut self.outgoing
        } else {
            &mut self.incoming
        };
        let status = match c.status {
            ChannelStatus::Closed => {
                counts.closed += 1;
                "closed"
            }
            ChannelStatus::Open => {
                counts.open += 1;
                "open"
            }
            ChannelStatus::PendingToClose(_) => {
                counts.pending_to_close += 1;
                "pending_to_close"
            }
        };
        let open = c.status == ChannelStatus::Open;
        if status == "closed" {
            return;
        }
        let below = self.funding_value.map(|f| c.balance.amount() < f.0);
        if open {
            match self.funding_value {
                None => self.funding.unknown += 1,
                Some(face) => match c.balance.amount().cmp(&face.0) {
                    std::cmp::Ordering::Less => self.funding.below += 1,
                    std::cmp::Ordering::Equal => self.funding.equal += 1,
                    std::cmp::Ordering::Greater => self.funding.above += 1,
                },
            }
        }
        let poor = probe.is_some_and(|r| r < LOW_PROBE_RATE);
        if count_peer {
            self.peers.total += 1;
            match transport_connected {
                Some(true) => self.peers.transport_connected += 1,
                Some(false) => self.peers.transport_disconnected += 1,
                None => self.peers.transport_unknown += 1,
            }
            self.peers.poor_probe += u64::from(poor);
            self.peers.probe_unknown += u64::from(probe.is_none());
        }
        if !open
            || below == Some(true)
            || connected != Some(true)
            || below.is_none()
            || transport_connected != Some(true)
            || poor
            || probe.is_none()
        {
            self.problematic += 1;
            let peer = if direction == ChannelDirection::Outgoing {
                c.destination
            } else {
                c.source
            };
            self.sample.push(ChannelSample {
                counterparty: peer,
                direction,
                status,
                balance: Amount(c.balance.amount()),
                below_funding_value: below,
                is_connected: connected,
                transport_connected,
                probe_success_rate: probe,
            });
            self.sample.sort_by(|a, b| {
                priority(b)
                    .cmp(&priority(a))
                    .then_with(|| a.balance.cmp(&b.balance))
                    .then_with(|| a.counterparty.as_ref().cmp(b.counterparty.as_ref()))
                    .then_with(|| {
                        (a.direction == ChannelDirection::Outgoing).cmp(&(b.direction == ChannelDirection::Outgoing))
                    })
            });
            self.sample.truncate(MAX_CHANNEL_SAMPLES);
        }
    }
}
fn priority(row: &ChannelSample) -> u8 {
    8 * u8::from(row.status == "open" && row.below_funding_value == Some(true))
        + 4 * u8::from(row.is_connected == Some(false) || row.transport_connected == Some(false))
        + 2 * u8::from(row.probe_success_rate.is_some_and(|r| r < LOW_PROBE_RATE))
        + u8::from(row.status == "pending_to_close")
}

impl super::ReadStats {
    fn record(&mut self, mut error: super::ReadFailure) {
        match error.kind {
            "missing" => self.missing += 1,
            "join" => self.join_errors += 1,
            "identity" => self.identity_errors += 1,
            _ => self.backend_errors += 1,
        }
        if self.error_samples.len() < MAX_CHANNEL_SAMPLES {
            error.entity = error.entity.chars().take(80).collect();
            error.message = error.message.chars().take(120).collect();
            self.error_samples.push(error);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn source_errors_timeouts_and_zero_values_are_distinct() {
        let timeout = Duration::from_millis(5);
        assert!(
            matches!(section::<u64>(timeout,async {Err("x".repeat(1000))}).await,Section::Error {message} if message.len()==120)
        );
        assert!(matches!(
            section::<u64>(timeout, std::future::pending()).await,
            Section::Timeout
        ));
        assert!(matches!(
            section(timeout, async { Ok(0u64) }).await,
            Section::Ok { value: 0 }
        ));
    }
    #[test]
    fn unknown_funding_or_connection_remains_visible() -> anyhow::Result<()> {
        let channel = ChannelEntry::builder()
            .between(Address::from([1; 20]), Address::from([2; 20]))
            .amount(100)
            .status(ChannelStatus::Open)
            .build()?;
        let mut unknown = Channels::default();
        unknown.record(&channel, ChannelDirection::Outgoing, None, Some(true), Some(1.0), true);
        assert_eq!(unknown.sample().len(), 1);
        assert_eq!(unknown.sample()[0].below_funding_value, None);
        assert_eq!(unknown.sample()[0].is_connected, None);
        let mut observed = Channels {
            funding_value: Some(Amount(10u32.into())),
            ..Default::default()
        };
        observed.record(
            &channel,
            ChannelDirection::Outgoing,
            Some(true),
            Some(true),
            Some(1.0),
            true,
        );
        assert!(observed.sample().is_empty());
        Ok(())
    }
}
