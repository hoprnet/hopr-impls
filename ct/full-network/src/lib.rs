mod config;
mod control;
mod discovery;
mod priority;

pub use config::EgressConfig;

/// Former name of [`EgressConfig`].
#[deprecated(since = "0.9.0", note = "renamed to `EgressConfig`")]
pub type ProberConfig = EgressConfig;

pub use control::{EgressControl, ProbingLevel};
pub use discovery::FullNetworkDiscovery;
