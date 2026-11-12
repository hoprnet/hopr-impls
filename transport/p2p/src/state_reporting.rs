//! Private bounded diagnostic reporting; no public snapshot types or reporting traits.
//! Kept local so each component remains independently publishable without a diagnostic dependency.
use std::{
    future::Future,
    io::{self, Write},
    panic::AssertUnwindSafe,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use futures::{FutureExt as _, Stream, StreamExt};
use futures_time::future::FutureExt as _;
use serde::Serialize;

/// Maximum serialized record, excluding the logger envelope.
pub const MAX_SNAPSHOT_BYTES: usize = 32 * 1024;

/// Private diagnostic result. Analysis is independent of operational state.
#[derive(Debug, Serialize)]
pub struct Dump<T> {
    pub state: T,
    pub analysis_required: bool,
    pub reason: &'static str,
}

/// Observation coverage. Missing or incomplete data is never represented as an observed zero.
#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Section<T> {
    Ok { value: T },
    Error { message: String },
    Timeout,
}
impl<T> Section<T> {
    #[cfg(all(test, feature = "runtime-tokio"))]
    pub fn value(&self) -> Option<&T> {
        match self {
            Self::Ok { value } => Some(value),
            _ => None,
        }
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

    #[cfg(test)]
    pub fn with_source_timeout(mut self, timeout: Duration) -> Result<Self, ConfigError> {
        if timeout.is_zero() || timeout > Duration::from_secs(5) {
            return Err(ConfigError("source timeout must be positive and at most 5 seconds"));
        }
        self.timeout = timeout;
        Ok(self)
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
        Ok(String::from_utf8(writer.bytes).expect("serde_json writes valid UTF-8"))
    }

    /// Analysis fields remain structured even if the payload cannot be encoded.
    pub fn emit(&self) {
        match self.to_json() {
            Ok(state) => tracing::info!(event="component_state", component=self.component, instance=%self.instance,
                sequence=self.sequence, reason=%self.reason,
                analysis_required=self.analysis_required, state=%state, "component operational state"),
            Err(error) => tracing::info!(event="component_state", component=self.component, instance=%self.instance,
                sequence=self.sequence, reason="encoding_error",
                analysis_required=true, %error, "component operational state"),
        }
    }
}

/// One independent reporter per component. The host supplies identity, runtime, and cancellation.
pub struct Reporter {
    component: &'static str,
    instance: String,
    config: Config,
    sequence: AtomicU64,
}
impl Reporter {
    pub fn new(component: &'static str, instance: impl Into<String>, config: Config) -> Self {
        Self {
            component,
            instance: instance.into().chars().take(120).collect(),
            config,
            sequence: AtomicU64::new(0),
        }
    }

    /// Always collect on demand, even when periodic reporting is disabled.
    pub async fn collect<T: Serialize>(&self, source: impl Future<Output = Result<Dump<T>, String>>) -> Record<T> {
        let started = Instant::now();
        let read = AssertUnwindSafe(source).catch_unwind();
        let (state, analysis_required, reason) = match read
            .timeout(futures_time::time::Duration::from(self.config.timeout))
            .await
        {
            Ok(Ok(Ok(dump))) => (Section::Ok { value: dump.state }, dump.analysis_required, dump.reason),
            Ok(Ok(Err(message))) => (
                Section::Error {
                    message: message.chars().take(120).collect(),
                },
                true,
                "collection_error",
            ),
            Ok(Err(_)) => (
                Section::Error {
                    message: "component state collection panicked".into(),
                },
                true,
                "collection_panicked",
            ),
            Err(_) => (Section::Timeout, true, "collection_timeout"),
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
            reason: reason.chars().take(120).collect(),
            analysis_required,
            state,
        }
    }

    pub async fn run<T: Serialize, Fut: Future<Output = Result<Dump<T>, String>>>(&self, source: impl Fn() -> Fut) {
        if let Some(interval) = self.config.interval {
            let ticks = futures_time::stream::interval(futures_time::time::Duration::from(interval)).map(|_| ());
            self.run_on(ticks, source).await;
        }
    }

    async fn run_on<T: Serialize, Fut: Future<Output = Result<Dump<T>, String>>, S: Stream<Item = ()> + Unpin>(
        &self,
        mut ticks: S,
        source: impl Fn() -> Fut,
    ) {
        if self.config.interval.is_none() {
            return;
        }
        while ticks.next().await.is_some() {
            self.collect(source()).await.emit();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn collection_failures_preserve_coverage_and_request_analysis() -> anyhow::Result<()> {
        let reporter = Reporter::new(
            "test",
            "node",
            Config::default().with_source_timeout(Duration::from_millis(5))?,
        );
        let timeout = reporter
            .collect(std::future::pending::<Result<Dump<()>, String>>())
            .await;
        assert!(matches!(timeout.state, Section::Timeout));
        assert!(timeout.analysis_required);
        let error = reporter.collect(async { Err::<Dump<()>, _>("x".repeat(500)) }).await;
        let Section::Error { message } = error.state else {
            anyhow::bail!("expected collection error")
        };
        assert!(message.len() <= 120);
        let panic = reporter
            .collect(async {
                panic!("injected failure");
                #[allow(unreachable_code)]
                Ok::<_, String>(Dump {
                    state: (),
                    analysis_required: false,
                    reason: "unreachable",
                })
            })
            .await;
        assert_eq!(panic.reason, "collection_panicked");
        let recovered = reporter
            .collect(async {
                Ok(Dump {
                    state: 7,
                    analysis_required: false,
                    reason: "ok",
                })
            })
            .await;
        assert!(!recovered.analysis_required);
        assert_eq!(recovered.sequence, 3);
        Ok(())
    }

    #[tokio::test]
    async fn disabled_periodic_reporting_does_not_poll_or_drain_sources() -> anyhow::Result<()> {
        let reads = AtomicU64::new(0);
        Reporter::new("test", "node", Config::new(0)?)
            .run_on(futures::stream::iter([(), ()]), || async {
                reads.fetch_add(1, Ordering::Relaxed);
                Ok(Dump {
                    state: (),
                    analysis_required: false,
                    reason: "ok",
                })
            })
            .await;
        assert_eq!(reads.load(Ordering::Relaxed), 0);
        Ok(())
    }

    #[tokio::test]
    async fn records_enforce_the_byte_budget_and_preserve_analysis_fields() {
        let reporter = Reporter::new("test", "node", Config::default());
        let record = reporter
            .collect(async {
                Ok(Dump {
                    state: "x".repeat(MAX_SNAPSHOT_BYTES),
                    analysis_required: true,
                    reason: "test",
                })
            })
            .await;
        assert!(matches!(record.to_json(), Err(EncodeError::TooLarge)));
        assert!(record.analysis_required);
    }
    #[test]
    fn interval_and_source_deadline_boundaries_are_validated() -> anyhow::Result<()> {
        assert!(Config::new(0)?.interval.is_none());
        for seconds in [5, 60, 86400] {
            assert_eq!(Config::new(seconds)?.interval, Some(Duration::from_secs(seconds)));
        }
        for seconds in [1, 4, 86401, u64::MAX] {
            assert!(
                Config::new(seconds)
                    .unwrap_err()
                    .to_string()
                    .contains("report interval")
            );
        }
        for timeout in [Duration::ZERO, Duration::from_secs(5) + Duration::from_nanos(1)] {
            assert!(
                Config::default()
                    .with_source_timeout(timeout)
                    .unwrap_err()
                    .to_string()
                    .contains("source timeout")
            );
        }
        assert_eq!(
            Config::default().with_source_timeout(Duration::from_secs(5))?.timeout,
            Duration::from_secs(5)
        );
        Ok(())
    }

    // Command::env changes only the child process; parallel tests never mutate the process environment.
    #[test]
    fn environment_configuration_is_validated_in_isolated_processes() -> anyhow::Result<()> {
        use std::{ffi::OsString, process::Command};
        let mut cases = vec![
            (None, "default"),
            (Some(OsString::from("0")), "disabled"),
            (Some(OsString::from("5")), "enabled"),
            (Some(OsString::from("4")), "range_error"),
            (Some(OsString::from("oops")), "parse_error"),
        ];
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            cases.push((Some(OsString::from_vec(vec![255])), "utf8_error"));
        }
        for (value, expected) in cases {
            let mut child = Command::new(std::env::current_exe()?);
            child
                .args(["--exact", "state_reporting::tests::environment_probe"])
                .env("HOPR_REPORTING_ENV_TEST", expected)
                .env_remove("HOPR_STATE_DUMP_INTERVAL");
            if let Some(value) = value {
                child.env("HOPR_STATE_DUMP_INTERVAL", value);
            }
            let output = child.output()?;
            assert!(
                output.status.success(),
                "{expected}: {} {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
        }
        Ok(())
    }

    #[test]
    fn environment_probe() {
        let Ok(expected) = std::env::var("HOPR_REPORTING_ENV_TEST") else {
            return;
        };
        let config = Config::from_env();
        match expected.as_str() {
            "default" => assert_eq!(config.unwrap().interval, Some(Duration::from_secs(60))),
            "disabled" => assert!(config.unwrap().interval.is_none()),
            "enabled" => assert_eq!(config.unwrap().interval, Some(Duration::from_secs(5))),
            "range_error" => assert!(config.unwrap_err().to_string().contains("report interval")),
            "parse_error" => assert!(config.unwrap_err().to_string().contains("integer seconds")),
            "utf8_error" => assert!(config.unwrap_err().to_string().contains("not UTF-8")),
            _ => panic!("unexpected environment scenario"),
        }
    }

    #[tokio::test]
    async fn periodic_reporting_collects_each_tick_and_can_be_cancelled() -> anyhow::Result<()> {
        use std::cell::RefCell;
        let reads = AtomicU64::new(0);
        let reporter = Reporter::new(
            "test",
            "node",
            Config {
                interval: Some(Duration::from_millis(1)),
                ..Config::default()
            },
        );
        let (done, completed) = futures::channel::oneshot::channel();
        let done = RefCell::new(Some(done));
        let running = reporter.run(|| {
            if reads.fetch_add(1, Ordering::Relaxed) == 1 {
                done.borrow_mut().take().unwrap().send(()).unwrap();
            }
            async {
                Ok(Dump {
                    state: 7,
                    analysis_required: false,
                    reason: "ok",
                })
            }
        });
        let result = futures::future::select(Box::pin(running), completed)
            .timeout(futures_time::time::Duration::from_secs(2))
            .await?;
        let futures::future::Either::Right((completed, running)) = result else {
            anyhow::bail!("enabled reporter unexpectedly stopped")
        };
        completed?;
        drop(running);
        assert_eq!(reads.load(Ordering::Relaxed), 2);
        assert_eq!(reporter.sequence.load(Ordering::Relaxed), 2);
        reporter
            .run_on(futures::stream::iter([(), ()]), || async {
                Ok(Dump {
                    state: 8,
                    analysis_required: true,
                    reason: "needs_analysis",
                })
            })
            .await;
        assert_eq!(reporter.sequence.load(Ordering::Relaxed), 4);
        Reporter::new("test", "node", Config::new(0)?)
            .run(|| async {
                panic!("disabled reporter must not poll its source");
                #[allow(unreachable_code)]
                Ok::<Dump<()>, String>(Dump {
                    state: (),
                    analysis_required: false,
                    reason: "unreachable",
                })
            })
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn encoding_failures_emit_analysis_without_losing_component_identity() -> anyhow::Result<()> {
        use std::{
            collections::BTreeMap,
            sync::{Arc, Mutex},
        };

        use tracing::{
            Event, Metadata, Subscriber,
            field::{Field, Visit},
            span,
        };
        #[derive(Default)]
        struct Fields(BTreeMap<String, String>);
        impl Visit for Fields {
            fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                self.0.insert(field.name().into(), format!("{value:?}"));
            }

            fn record_str(&mut self, field: &Field, value: &str) {
                self.0.insert(field.name().into(), value.into());
            }
        }
        #[derive(Clone, Default)]
        struct Logs(Arc<Mutex<Vec<Fields>>>);
        impl Subscriber for Logs {
            fn enabled(&self, _: &Metadata<'_>) -> bool {
                true
            }

            fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
                span::Id::from_u64(1)
            }

            fn record(&self, _: &span::Id, _: &span::Record<'_>) {}

            fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}

            fn enter(&self, _: &span::Id) {}

            fn exit(&self, _: &span::Id) {}

            fn event(&self, event: &Event<'_>) {
                let mut fields = Fields::default();
                event.record(&mut fields);
                self.0.lock().unwrap().push(fields);
            }
        }
        struct Unserializable;
        impl Serialize for Unserializable {
            fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom("injected serialization failure"))
            }
        }
        let reporter = Reporter::new("test", "x".repeat(200), Config::default());
        let good = reporter
            .collect(async {
                Ok(Dump {
                    state: 42,
                    analysis_required: false,
                    reason: "ok",
                })
            })
            .await;
        let bad = reporter
            .collect(async {
                Ok(Dump {
                    state: Unserializable,
                    analysis_required: false,
                    reason: "ok",
                })
            })
            .await;
        assert!(matches!(bad.to_json(), Err(EncodeError::Json(_))));
        assert!(
            bad.to_json()
                .unwrap_err()
                .to_string()
                .contains("injected serialization failure")
        );
        let large = reporter
            .collect(async {
                Ok(Dump {
                    state: "x".repeat(MAX_SNAPSHOT_BYTES),
                    analysis_required: true,
                    reason: "large",
                })
            })
            .await;
        assert_eq!(good.instance.len(), 120);
        let logs = Logs::default();
        tracing::subscriber::with_default(logs.clone(), || {
            good.emit();
            bad.emit();
            large.emit();
        });
        let events = logs.0.lock().unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].0["component"], "test");
        let state: serde_json::Value = serde_json::from_str(&events[0].0["state"])?;
        assert_eq!(state["state"]["value"], 42);
        for event in &events[1..] {
            assert_eq!(event.0["reason"], "encoding_error");
            assert_eq!(event.0["analysis_required"], "true");
            assert_eq!(event.0["component"], "test");
            assert_eq!(event.0["instance"].len(), 120);
        }
        let mut writer = BoundedJson {
            bytes: Vec::new(),
            exceeded: false,
        };
        writer.write_all(&vec![b'x'; MAX_SNAPSHOT_BYTES])?;
        writer.flush()?;
        assert!(writer.write_all(b"!").is_err());
        assert_eq!(writer.bytes.len(), MAX_SNAPSHOT_BYTES);
        assert!(writer.exceeded);
        Ok(())
    }
}
