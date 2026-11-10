//! Stable serializable snapshot schema. Monetary values use decimal base units.
use hopr_api::types::primitive::prelude::Address;
use serde::{Serialize, Serializer};

/// An exact amount in token base units, serialized as a decimal string.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Amount(pub(crate) hopr_api::graph::traits::Balance);
impl Amount {
    /// Exact integer value, without loss of U256 precision.
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
pub enum ChannelDirection {
    Incoming,
    Outgoing,
}
/// Counts by on-chain channel state.
#[derive(Debug, Default, Serialize)]
pub struct StatusCounts {
    pub closed: u64,
    pub open: u64,
    pub pending_to_close: u64,
}
/// Open outgoing-channel funding relative to one winning-ticket face value. Incoming channels are
/// funded by their counterparty, so they are not counted.
#[derive(Debug, Default, Serialize)]
pub struct FundingCounts {
    pub below: u64,
    pub equal: u64,
    pub above: u64,
    pub unknown: u64,
}
/// Distinct peers with local open channels; connectivity belongs to the network/graph dumps.
#[derive(Debug, Default, Serialize)]
pub struct ChannelPeers {
    pub total: u64,
}
/// One retained underfunded, pending-close or funding-unknown local channel.
#[derive(Debug, Serialize)]
pub struct ChannelSample {
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
pub struct ReadStats {
    pub read_ok: u64,
    pub missing: u64,
    pub backend_errors: u64,
    pub join_errors: u64,
    pub identity_errors: u64,
    pub timed_out: bool,
    pub complete: bool,
    pub(crate) error_samples: Vec<super::ReadFailure>,
}
impl ReadStats {
    pub fn error_samples(&self) -> &[super::ReadFailure] {
        &self.error_samples
    }
}
/// Counts plus a capped channel sample. No list grows with the network.
#[derive(Debug, Default, Serialize)]
pub struct Channels {
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
    pub fn sample(&self) -> &[ChannelSample] {
        &self.sample
    }

    /// Open outgoing channels below the funding value, lowest balance first. At most
    /// [`MAX_UNDERFUNDED_SAMPLES`](super::MAX_UNDERFUNDED_SAMPLES).
    pub fn underfunded(&self) -> &[ChannelSample] {
        &self.underfunded
    }
}
/// The chain component's schema; graph, transport and routing state are reported independently.
#[derive(Debug, Serialize)]
pub struct ChainState {
    pub node_address: Address,
    pub safe_address: Address,
    pub chain_freshness: &'static str,
    pub safe_balance: super::Section<Amount>,
    pub safe_allowance: super::Section<Amount>,
    pub channels: super::Section<Channels>,
    pub announced_peers: super::Section<u64>,
}
