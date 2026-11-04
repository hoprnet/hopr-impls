//! Bounded periodic INFO state dumps for HOPR nodes.
//!
//! This module owns collection, sample limits and interval reporting. Embedding nodes provide
//! chain/graph/network views, diagnostic `StateRead` reads and optional bounded resolver/selector/SURB counters.
//! It installs no logger or runtime and changes no routing or funding decisions.
mod collector;
mod counters;
mod model;
pub use collector::{Collector, Config, ConfigError, EncodeError, MAX_CHANNEL_SAMPLES, MAX_SNAPSHOT_BYTES};
pub use counters::{
    Direction, IntervalCounters, IntervalSnapshot, MAX_DESTINATIONS, MAX_PROBE_PEERS, MAX_SURB_DESTINATIONS,
    MAX_SURB_PAIRS, PathCounts, PhaseOutcome, ProbeCounts, ProbePeer, ProbeSnapshot, SearchOutcome, SurbCounts,
};
pub use model::{
    Amount, ChannelDirection, ChannelPeers, ChannelSample, Channels, FundingCounts, ReadStats, Section, Snapshot,
    StatusCounts,
};

pub use crate::connector::state_reads::{ReadFailure, StateRead};

#[cfg(test)]
pub(crate) mod tests;
