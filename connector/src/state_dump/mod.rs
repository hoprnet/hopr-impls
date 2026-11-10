//! Optional chain diagnostics and producer counters. Each can report independently through `StateDump`.
mod collector;
mod counters;
mod model;
pub use crate::connector::state_reads::{ReadFailure, StateRead};
pub use collector::{ChainDump, MAX_CHANNEL_SAMPLES, MAX_UNDERFUNDED_SAMPLES};
pub use counters::{
    Direction, IntervalCounters, IntervalSnapshot, MAX_DESTINATIONS, MAX_PROBE_PEERS, MAX_SURB_DESTINATIONS,
    MAX_SURB_PAIRS, PathCounts, PhaseOutcome, ProbeCounts, ProbePeer, ProbeSnapshot, SearchOutcome, SurbCounts,
};
pub use hopr_state_dump::{
    Config, ConfigError, Dump, EncodeError, MAX_SNAPSHOT_BYTES, Record, Reporter, Section, Signal, StateDump,
};
pub use model::{
    Amount, ChainState, ChannelDirection, ChannelPeers, ChannelSample, Channels, FundingCounts, ReadStats, StatusCounts,
};
#[cfg(test)]
pub(crate) mod tests;
