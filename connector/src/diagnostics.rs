//! Chain-owned bounded diagnostics. Snapshot models and view implementations stay private.
use std::{collections::HashSet, time::Duration};

use futures::StreamExt;
use futures_time::future::FutureExt;
use hopr_api::{
    chain::{ChainReadChannelOperations, ChainReadSafeOperations, ChainValues},
    types::{
        internal::prelude::{ChannelEntry, ChannelStatus},
        primitive::prelude::{Address, WxHOPR},
    },
};
use serde::{Serialize, Serializer};

use crate::{
    connector::state_reads::{ReadFailure, StateRead},
    state_reporting::{Config, Dump, Reporter, Section, section},
};

const MAX_CHANNEL_SAMPLES: usize = 4;
const MAX_UNDERFUNDED_SAMPLES: usize = 16;

/// Optional chain dump adapter. The concrete schema remains private to this crate.
/// Funding comparisons use the explicitly supplied value; they are unknown when it is absent.
struct ChainView<C> {
    chain: C,
    safe_address: Address,
    timeout: Duration,
    funding_value: Option<hopr_api::graph::traits::Balance>,
}
impl<C> ChainView<C>
where
    C: ChainValues + ChainReadSafeOperations + ChainReadChannelOperations + StateRead + Send + Sync,
{
    fn new(chain: C, safe_address: Address, config: Config) -> Self {
        Self {
            chain,
            safe_address,
            // Leave time to return partial observations before the reporter's overall deadline.
            timeout: (config.source_timeout() / 2).max(Duration::from_nanos(1)),
            funding_value: None,
        }
    }

    /// Face value used by the host's funding policy, in decimal token base units.
    /// The host must refresh this adapter when that policy changes; absence is explicitly unknown.
    fn with_funding_value(mut self, value: hopr_api::graph::traits::Balance) -> Self {
        self.funding_value = Some(value);
        self
    }

    async fn collect(&self) -> ChainState {
        let (balance, allowance, channels, announced) = futures::join!(
            section(self.timeout, async {
                self.chain
                    .balance::<WxHOPR, _>(self.safe_address)
                    .await
                    .map(|b| Amount(b.amount()))
                    .map_err(|e| e.to_string())
            }),
            section(self.timeout, async {
                self.chain
                    .safe_allowance::<WxHOPR, _>(self.safe_address)
                    .await
                    .map(|b| Amount(b.amount()))
                    .map_err(|e| e.to_string())
            }),
            self.channels(self.funding_value),
            section(self.timeout, async { self.chain.announced_count() }),
        );
        ChainState {
            component_state: self.chain.component_state(),
            node_address: *self.chain.me(),
            safe_address: self.safe_address,
            chain_freshness: "unverified",
            safe_balance: balance,
            safe_allowance: allowance,
            channels,
            announced_peers: announced,
        }
    }

    async fn channels(&self, face: Option<hopr_api::graph::traits::Balance>) -> Section<Channels> {
        let mut summary = Channels {
            scope: "source_visible",
            funding_value: face.map(Amount),
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
                let count_peer = channel.status == ChannelStatus::Open && peers.insert(peer);
                summary.record(&channel, direction, count_peer);
            }
        }
        .timeout(futures_time::time::Duration::from(self.timeout))
        .await
        .is_ok();
        summary.reads.timed_out = !completed;
        summary.reads.complete = completed
            && summary.reads.missing == 0
            && summary.reads.backend_errors == 0
            && summary.reads.join_errors == 0
            && summary.reads.identity_errors == 0;
        summary.omitted = summary.problematic.saturating_sub(summary.sample.len() as u64);
        summary.underfunded_omitted = summary.funding.below.saturating_sub(summary.underfunded.len() as u64);
        if summary.reads.complete {
            Section::Ok { value: summary }
        } else {
            Section::Partial { value: summary }
        }
    }
}
impl Channels {
    fn record(&mut self, c: &ChannelEntry, direction: ChannelDirection, count_peer: bool) {
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
        // Only outgoing channels are this node's to fund.
        let outgoing = direction == ChannelDirection::Outgoing;
        let below = outgoing
            .then(|| self.funding_value.map(|f| c.balance.amount() < f.0))
            .flatten();
        if open && outgoing {
            match self.funding_value {
                None => self.funding.unknown += 1,
                Some(face) => match c.balance.amount().cmp(&face.0) {
                    std::cmp::Ordering::Less => self.funding.below += 1,
                    std::cmp::Ordering::Equal => self.funding.equal += 1,
                    std::cmp::Ordering::Greater => self.funding.above += 1,
                },
            }
        }
        if count_peer {
            self.peers.total += 1;
        }
        let peer = if outgoing { c.destination } else { c.source };
        let row = || ChannelSample {
            counterparty: peer,
            direction,
            status,
            balance: Amount(c.balance.amount()),
            below_funding_value: below,
        };
        if open && below == Some(true) {
            self.underfunded.push(row());
            self.underfunded.sort_by(|a, b| {
                a.balance
                    .cmp(&b.balance)
                    .then_with(|| a.counterparty.as_ref().cmp(b.counterparty.as_ref()))
            });
            self.underfunded.truncate(MAX_UNDERFUNDED_SAMPLES);
        }
        if !open || below == Some(true) || (outgoing && below.is_none()) {
            self.problematic += 1;
            self.sample.push(row());
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
    2 * u8::from(row.status == "open" && row.below_funding_value == Some(true))
        + u8::from(row.status == "pending_to_close")
}

impl ReadStats {
    fn record(&mut self, mut error: ReadFailure) {
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

impl<C> ChainView<C>
where
    C: ChainValues + ChainReadSafeOperations + ChainReadChannelOperations + StateRead + Send + Sync,
{
    async fn collect_dump(&self) -> Result<Dump<ChainState>, String> {
        let state = self.collect().await;
        let (analysis_required, reason) =
            if state.component_state == hopr_api::ComponentState::Failed {
                (true, "chain_component_failed")
            } else if state.component_state == hopr_api::ComponentState::Degraded {
                (true, "chain_component_degraded")
            } else if !state.safe_balance.is_complete()
                || !state.safe_allowance.is_complete()
                || !state.channels.is_complete()
                || !state.announced_peers.is_complete()
            {
                (true, "chain_reads_incomplete")
            } else if state.channels.value().is_some_and(|c| {
                c.funding.below > 0 || c.incoming.pending_to_close > 0 || c.outgoing.pending_to_close > 0
            }) {
                (true, "channel_funding_or_closure")
            } else {
                (false, "chain_observations_ok")
            };
        Ok(Dump {
            state,
            analysis_required,
            reason,
        })
    }
}

impl<C> hopr_api::StateDump for ChainView<C>
where
    C: ChainValues + ChainReadSafeOperations + ChainReadChannelOperations + StateRead + Send + Sync,
{
    type Error = std::io::Error;

    async fn dump(&self) -> Result<impl serde::Serialize + serde::de::DeserializeOwned + Send + 'static, Self::Error> {
        let dump = self.collect_dump().await.map_err(std::io::Error::other)?;
        serde_json::to_value(dump).map_err(std::io::Error::other)
    }
}

/// An exact amount in token base units, serialized as a decimal string.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Amount(pub(crate) hopr_api::graph::traits::Balance);
impl Amount {
    /// Exact integer value, without loss of U256 precision.
    #[cfg(test)]
    pub fn value(self) -> hopr_api::graph::traits::Balance {
        self.0
    }
}
impl From<hopr_api::graph::traits::Balance> for Amount {
    fn from(value: hopr_api::graph::traits::Balance) -> Self {
        Self(value)
    }
}
impl Serialize for Amount {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&self.0)
    }
}
/// Channel direction relative to the reporting node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ChannelDirection {
    Incoming,
    Outgoing,
}
/// Counts by on-chain channel state.
#[derive(Debug, Default, Serialize)]
struct StatusCounts {
    pub closed: u64,
    pub open: u64,
    pub pending_to_close: u64,
}
/// Open outgoing-channel funding relative to one winning-ticket face value. Incoming channels are
/// funded by their counterparty, so they are not counted.
#[derive(Debug, Default, Serialize)]
struct FundingCounts {
    pub below: u64,
    pub equal: u64,
    pub above: u64,
    pub unknown: u64,
}
/// Distinct peers with local open channels; connectivity belongs to the network/graph dumps.
#[derive(Debug, Default, Serialize)]
struct ChannelPeers {
    pub total: u64,
}
/// One retained underfunded, pending-close or funding-unknown local channel.
#[derive(Debug, Serialize)]
struct ChannelSample {
    pub counterparty: Address,
    pub direction: ChannelDirection,
    pub status: &'static str,
    pub balance: Amount,
    /// Whether an outgoing channel holds less than one winning ticket. Always `None` for incoming
    /// channels, which this node does not fund.
    pub below_funding_value: Option<bool>,
}
/// Diagnostic read progress. Counts describe observed failures, not unseen records after timeout.
#[derive(Debug, Default, Serialize)]
struct ReadStats {
    pub read_ok: u64,
    pub missing: u64,
    pub backend_errors: u64,
    pub join_errors: u64,
    pub identity_errors: u64,
    pub timed_out: bool,
    pub complete: bool,
    pub(crate) error_samples: Vec<ReadFailure>,
}
/// Counts plus a capped channel sample. No list grows with the network.
#[derive(Debug, Default, Serialize)]
struct Channels {
    /// This inventory covers entries exposed by the supplied source, not complete historical state.
    pub scope: &'static str,
    pub reads: ReadStats,
    pub total: u64,
    pub incoming: StatusCounts,
    pub outgoing: StatusCounts,
    pub funding: FundingCounts,
    pub funding_value: Option<Amount>,
    pub peers: ChannelPeers,
    pub problematic: u64,
    pub omitted: u64,
    pub(crate) sample: Vec<ChannelSample>,
    /// Open outgoing channels below the funding value that did not fit in `underfunded`.
    pub underfunded_omitted: u64,
    pub(crate) underfunded: Vec<ChannelSample>,
}
impl Channels {
    /// At most four retained problematic channels.
    #[cfg(test)]
    pub fn sample(&self) -> &[ChannelSample] {
        &self.sample
    }

    /// Open outgoing channels below the funding value, lowest balance first. At most
    /// [`MAX_UNDERFUNDED_SAMPLES`](MAX_UNDERFUNDED_SAMPLES).
    #[cfg(test)]
    pub fn underfunded(&self) -> &[ChannelSample] {
        &self.underfunded
    }
}
/// The chain component's schema; graph, transport and routing state are reported independently.
#[derive(Debug, Serialize)]
struct ChainState {
    pub component_state: hopr_api::ComponentState,
    pub node_address: Address,
    pub safe_address: Address,
    pub chain_freshness: &'static str,
    pub safe_balance: Section<Amount>,
    pub safe_allowance: Section<Amount>,
    pub channels: Section<Channels>,
    pub announced_peers: Section<u64>,
}

impl<C, B, P, R> crate::HoprBlockchainConnector<C, B, P, R>
where
    B: crate::Backend + Send + Sync + 'static,
    C: Send + Sync,
    P: Send + Sync,
    R: Send + Sync,
    Self: hopr_api::chain::ChainValues
        + hopr_api::chain::ChainReadSafeOperations
        + hopr_api::chain::ChainReadChannelOperations
        + Send
        + Sync
        + 'static,
{
    /// Configure a diagnostic view implementing the shared [`hopr_api::StateDump`] interface.
    /// The view borrows this connector; its concrete type and snapshot schema remain private.
    /// Funding comparisons use the caller's policy; `None` records unknown funding values.
    pub fn state_view(
        &self,
        safe_address: hopr_api::Address,
        funding_value: Option<hopr_api::graph::traits::Balance>,
    ) -> impl hopr_api::StateDump<Error = std::io::Error> + '_ {
        let source = ChainView::new(self, safe_address, Config::default());
        match funding_value {
            Some(value) => source.with_funding_value(value),
            None => source,
        }
    }

    /// Collect bounded chain diagnostics. The concrete schema is internal and may change.
    pub async fn state(
        &self,
        safe_address: hopr_api::Address,
        funding_value: Option<hopr_api::graph::traits::Balance>,
    ) -> Result<impl serde::Serialize + serde::de::DeserializeOwned + Send, String> {
        let mut source = ChainView::new(self, safe_address, Config::default());
        if let Some(value) = funding_value {
            source = source.with_funding_value(value);
        }
        serde_json::to_value(source.collect_dump().await?).map_err(|error| error.to_string())
    }

    /// Emit independent chain diagnostics until this future is cancelled by the host.
    /// HOPR_STATE_DUMP_INTERVAL controls the interval; zero disables collection.
    pub async fn run_state_reporting(
        &self,
        instance: &str,
        safe_address: hopr_api::Address,
        funding_value: Option<hopr_api::graph::traits::Balance>,
    ) -> Result<(), String> {
        self.run_state_reporting_with_funding_policy(instance, safe_address, move || funding_value)
            .await
    }

    /// Emit chain diagnostics using the caller's current funding policy on every interval.
    /// The policy must be a bounded, non-blocking read, such as a cached ticket face value.
    pub async fn run_state_reporting_with_funding_policy(
        &self,
        instance: &str,
        safe_address: hopr_api::Address,
        funding_policy: impl Fn() -> Option<hopr_api::graph::traits::Balance> + Send + Sync,
    ) -> Result<(), String> {
        let config = Config::from_env().map_err(|error| error.to_string())?;
        let reporter = Reporter::new("chain", instance, config.clone());
        reporter
            .run(|| async {
                let mut source = ChainView::new(self, safe_address, config.clone());
                if let Some(value) = funding_policy() {
                    source = source.with_funding_value(value);
                }
                source.collect_dump().await
            })
            .await;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
