//! Stable serializable snapshot schema. Monetary values use decimal base units.
use std::collections::BTreeMap;

use hopr_api::{OffchainPublicKey, types::primitive::prelude::Address};
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
/// A source read succeeds, fails, times out, or was not supplied by the embedding node.
#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Section<T> {
    /// Source value, including a genuine zero if observed.
    Ok { value: T },
    /// Usable observations with incomplete coverage; inspect read statistics.
    Partial { value: T },
    /// Source failure; the collector caps the message at 120 characters.
    Error { message: String },
    /// Collection exceeded its deadline.
    Timeout,
    /// A producer or prerequisite is unavailable; this is not a zero observation.
    Unavailable,
}
impl<T> Section<T> {
    /// The observed value, if available.
    pub fn value(&self) -> Option<&T> {
        match self {
            Self::Ok { value } | Self::Partial { value } => Some(value),
            _ => None,
        }
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
/// Open-channel funding relative to one winning-ticket face value.
#[derive(Debug, Default, Serialize)]
pub struct FundingCounts {
    pub below: u64,
    pub equal: u64,
    pub above: u64,
    pub unknown: u64,
}
/// Distinct peers with local open channels. Probe/connection unknowns are explicit.
#[derive(Debug, Default, Serialize)]
pub struct ChannelPeers {
    pub total: u64,
    pub transport_connected: u64,
    pub transport_disconnected: u64,
    pub transport_unknown: u64,
    pub poor_probe: u64,
    pub probe_unknown: u64,
}
/// One retained problematic local channel. Reachability is local-to-peer for either direction.
#[derive(Debug, Serialize)]
pub struct ChannelSample {
    pub counterparty: Address,
    pub direction: ChannelDirection,
    pub status: &'static str,
    pub balance: Amount,
    pub below_funding_value: Option<bool>,
    /// Last graph connectivity observation, as present in edge-observation logs.
    pub is_connected: Option<bool>,
    /// Current transport connection; this does not establish probe success.
    pub transport_connected: Option<bool>,
    pub probe_success_rate: Option<f64>,
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
    pub low_probe_threshold: f64,
    pub problematic: u64,
    pub omitted: u64,
    pub(crate) sample: Vec<ChannelSample>,
}
impl Channels {
    /// At most four retained problematic channels.
    pub fn sample(&self) -> &[ChannelSample] {
        &self.sample
    }
}
/// One compact node snapshot. Source reads are not an atomic chain snapshot.
#[derive(Debug, Serialize)]
pub struct Snapshot {
    pub schema_version: u8,
    pub node: OffchainPublicKey,
    pub node_address: Address,
    pub safe_address: Address,
    pub sequence: u64,
    pub collected_at_ms: u64,
    pub collection_ms: u64,
    pub chain_freshness: &'static str,
    pub safe_balance: Section<Amount>,
    pub safe_allowance: Section<Amount>,
    pub channels: Section<Channels>,
    pub connected_peers: u64,
    pub announced_peers: Section<u64>,
    pub routing: Section<super::IntervalSnapshot>,
    /// Extra named sections supplied by the embedding node, such as strategy states. Each one is
    /// capped at [`MAX_SECTION_BYTES`](super::MAX_SECTION_BYTES); a larger one is replaced by a marker.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub sections: BTreeMap<&'static str, serde_json::Value>,
}
