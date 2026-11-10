//! Chain-only diagnostics. No graph or network implementation is required.
use super::{Amount, ChainState, ChannelDirection, ChannelSample, Channels, Section};
use futures::StreamExt;
use futures_time::future::FutureExt;
use hopr_api::{
    chain::{ChainReadChannelOperations, ChainReadSafeOperations, ChainValues},
    types::{
        internal::prelude::{ChannelEntry, ChannelStatus},
        primitive::prelude::{Address, WxHOPR},
    },
};
use hopr_state_dump::{Dump, Signal, StateDump, section};
use std::{collections::HashSet, sync::Arc, time::Duration};

pub const MAX_CHANNEL_SAMPLES: usize = 4;
pub const MAX_UNDERFUNDED_SAMPLES: usize = 16;

/// Optional chain dump adapter. Custom connectors may implement `StateDump` with their own schema instead.
/// Funding comparisons use the explicitly supplied value; they are unknown when it is absent.
pub struct ChainDump<C> {
    chain: Arc<C>,
    safe_address: Address,
    timeout: Duration,
    funding_value: Option<hopr_api::graph::traits::Balance>,
}
impl<C> ChainDump<C>
where
    C: ChainValues + ChainReadSafeOperations + ChainReadChannelOperations + super::StateRead + Send + Sync + 'static,
{
    pub fn new(chain: C, safe_address: Address, config: super::Config) -> Self {
        Self {
            chain: Arc::new(chain),
            safe_address,
            // Leave time to return partial observations before the reporter's overall deadline.
            timeout: (config.source_timeout() / 2).max(Duration::from_nanos(1)),
            funding_value: None,
        }
    }
    /// Face value used by the host's funding policy, in decimal token base units.
    /// The host must refresh this adapter when that policy changes; absence is explicitly unknown.
    pub fn with_funding_value(mut self, value: hopr_api::graph::traits::Balance) -> Self {
        self.funding_value = Some(value);
        self
    }
    pub async fn collect(&self) -> ChainState {
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

impl<C> StateDump for ChainDump<C>
where
    C: ChainValues + ChainReadSafeOperations + ChainReadChannelOperations + super::StateRead + Send + Sync + 'static,
{
    type State = ChainState;
    async fn state_dump(&self) -> Result<Dump<Self::State>, String> {
        let state = self.collect().await;
        let (signal, reason) =
            if !state.safe_balance.is_complete()
                || !state.safe_allowance.is_complete()
                || !state.channels.is_complete()
                || !state.announced_peers.is_complete()
            {
                (Signal::Unknown, "chain_reads_incomplete")
            } else if state.channels.value().is_some_and(|c| {
                c.funding.below > 0 || c.incoming.pending_to_close > 0 || c.outgoing.pending_to_close > 0
            }) {
                (Signal::NeedsAnalysis, "channel_funding_or_closure")
            } else if state.channels.value().is_some_and(|c| c.funding.unknown > 0) {
                (Signal::Unknown, "funding_value_unavailable")
            } else {
                (Signal::Healthy, "chain_observations_ok")
            };
        Ok(Dump { state, signal, reason })
    }
}
