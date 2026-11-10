//! Component-owned state and explicit analysis signals, independent of node composition.
use std::{
    future::Future,
    io::{self, Write},
    panic::AssertUnwindSafe,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use futures::{FutureExt as _, Stream, StreamExt};
use futures_time::future::FutureExt as _;
use serde::Serialize;

/// Maximum serialized record, excluding the logger envelope.
pub const MAX_SNAPSHOT_BYTES: usize = 32 * 1024;

/// Health of the observed scope, assessed by the component itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Signal {
    Healthy,
    NeedsAnalysis,
    Unknown,
}
impl Signal {
    pub fn analysis_required(self) -> bool {
        self != Self::Healthy
    }
}

/// Component-specific state and its interpretation. `reason` is a short stable code, not an error log.
#[derive(Debug)]
pub struct Dump<T> {
    pub state: T,
    pub signal: Signal,
    pub reason: &'static str,
}

/// Optional functionality implemented by a component or an adapter, separate from its operational interface.
/// Payloads have no prescribed shape. Implementations must bound work and avoid blocking the async executor.
pub trait StateDump: Send + Sync {
    type State: Serialize + Send;
    fn state_dump(&self) -> impl Future<Output = Result<Dump<Self::State>, String>> + Send;
}
impl<T: StateDump + ?Sized> StateDump for Arc<T> {
    type State = T::State;

    async fn state_dump(&self) -> Result<Dump<Self::State>, String> {
        (**self).state_dump().await
    }
}
impl<T: StateDump + ?Sized> StateDump for &T {
    type State = T::State;

    async fn state_dump(&self) -> Result<Dump<Self::State>, String> {
        (**self).state_dump().await
    }
}

/// Observation coverage. Missing or incomplete data is never represented as an observed zero.
#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Section<T> {
    Ok { value: T },
    Partial { value: T },
    Error { message: String },
    Timeout,
    Unavailable,
}
impl<T> Section<T> {
    pub fn value(&self) -> Option<&T> {
        match self {
            Self::Ok { value } | Self::Partial { value } => Some(value),
            _ => None,
        }
    }

    pub fn is_complete(&self) -> bool {
        matches!(self, Self::Ok { .. })
    }
}

/// Preserve source errors and enforce a deadline. Components can use this for independent reads.
pub async fn section<T>(timeout: Duration, future: impl Future<Output = Result<T, String>>) -> Section<T> {
    match future.timeout(futures_time::time::Duration::from(timeout)).await {
        Ok(Ok(value)) => Section::Ok { value },
        Ok(Err(message)) => Section::Error {
            message: message.chars().take(120).collect(),
        },
        Err(_) => Section::Timeout,
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    interval: Option<Duration>,
    timeout: Duration,
}
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

    pub fn with_source_timeout(mut self, timeout: Duration) -> Result<Self, ConfigError> {
        if timeout.is_zero() || timeout > Duration::from_secs(5) {
            return Err(ConfigError("source timeout must be positive and at most 5 seconds"));
        }
        self.timeout = timeout;
        Ok(self)
    }

    pub fn interval(&self) -> Option<Duration> {
        self.interval
    }

    pub fn source_timeout(&self) -> Duration {
        self.timeout
    }
}

/// Only the envelope is shared; `state` is owned by the reporting component.
#[derive(Debug, Serialize)]
pub struct Record<T> {
    pub schema_version: u8,
    pub component: &'static str,
    pub instance: String,
    pub sequence: u64,
    pub collected_at_ms: u64,
    pub collection_ms: u64,
    pub signal: Signal,
    pub reason: String,
    pub analysis_required: bool,
    pub state: Section<T>,
}
#[derive(Debug, thiserror::Error)]
pub enum EncodeError {
    #[error("state JSON encoding failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("state exceeds the {MAX_SNAPSHOT_BYTES}-byte payload budget")]
    TooLarge,
}
struct BoundedJson {
    bytes: Vec<u8>,
    exceeded: bool,
}
impl Write for BoundedJson {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.bytes.len().saturating_add(buf.len()) > MAX_SNAPSHOT_BYTES {
            self.exceeded = true;
            return Err(io::Error::other("state budget exceeded"));
        }
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl<T: Serialize> Record<T> {
    pub fn to_json(&self) -> Result<String, EncodeError> {
        let mut writer = BoundedJson {
            bytes: Vec::new(),
            exceeded: false,
        };
        let result = serde_json::to_writer(&mut writer, self);
        if writer.exceeded {
            return Err(EncodeError::TooLarge);
        }
        result?;
        Ok(String::from_utf8(writer.bytes).expect("JSON is UTF-8"))
    }

    /// Analysis fields remain structured even if the payload cannot be encoded.
    pub fn emit(&self) {
        match self.to_json() {
            Ok(state) => tracing::info!(event="component_state", component=self.component, instance=%self.instance,
                sequence=self.sequence, signal=?self.signal, reason=%self.reason,
                analysis_required=self.analysis_required, state=%state, "component operational state"),
            Err(error) => tracing::info!(event="component_state", component=self.component, instance=%self.instance,
                sequence=self.sequence, signal=?Signal::NeedsAnalysis, reason="encoding_error",
                analysis_required=true, %error, "component operational state"),
        }
    }
}

/// One independent reporter per component. The host supplies identity, runtime, and cancellation.
pub struct Reporter<T> {
    component: &'static str,
    instance: String,
    source: T,
    config: Config,
    sequence: AtomicU64,
}
impl<T: StateDump> Reporter<T> {
    pub fn new(component: &'static str, instance: impl Into<String>, source: T, config: Config) -> Self {
        Self {
            component,
            instance: instance.into().chars().take(120).collect(),
            source,
            config,
            sequence: AtomicU64::new(0),
        }
    }

    /// Always collect on demand, even when periodic reporting is disabled.
    pub async fn collect(&self) -> Record<T::State> {
        let started = Instant::now();
        let read = AssertUnwindSafe(async { self.source.state_dump().await }).catch_unwind();
        let (state, signal, reason) = match read
            .timeout(futures_time::time::Duration::from(self.config.timeout))
            .await
        {
            Ok(Ok(Ok(dump))) => (Section::Ok { value: dump.state }, dump.signal, dump.reason),
            Ok(Ok(Err(message))) => (
                Section::Error {
                    message: message.chars().take(120).collect(),
                },
                Signal::Unknown,
                "collection_error",
            ),
            Ok(Err(_)) => (
                Section::Error {
                    message: "component state collection panicked".into(),
                },
                Signal::Unknown,
                "collection_panicked",
            ),
            Err(_) => (Section::Timeout, Signal::Unknown, "collection_timeout"),
        };
        Record {
            schema_version: 1,
            component: self.component,
            instance: self.instance.clone(),
            sequence: self.sequence.fetch_add(1, Ordering::Relaxed),
            collected_at_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis()
                .min(u64::MAX as u128) as u64,
            collection_ms: started.elapsed().as_millis().min(u64::MAX as u128) as u64,
            signal,
            reason: reason.chars().take(120).collect(),
            analysis_required: signal.analysis_required(),
            state,
        }
    }

    pub async fn run(&self) {
        if let Some(interval) = self.config.interval {
            let ticks = futures_time::stream::interval(futures_time::time::Duration::from(interval)).map(|_| ());
            self.run_on(ticks).await;
        }
    }

    async fn run_on<S: Stream<Item = ()> + Unpin>(&self, mut ticks: S) {
        if self.config.interval.is_none() {
            return;
        }
        while ticks.next().await.is_some() {
            self.collect().await.emit();
        }
    }
}

#[cfg(test)]
mod tests;
