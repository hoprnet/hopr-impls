use std::sync::{Mutex, atomic::AtomicUsize};

use serde_json::{Value, json};

use super::*;

struct Custom {
    reads: Arc<AtomicUsize>,
    signal: Signal,
}
impl StateDump for Custom {
    type State = Vec<u8>;

    async fn state_dump(&self) -> Result<Dump<Self::State>, String> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        Ok(Dump {
            state: vec![3, 7],
            signal: self.signal,
            reason: "custom_policy",
        })
    }
}
struct Replacement;
impl StateDump for Replacement {
    type State = Value;

    async fn state_dump(&self) -> Result<Dump<Self::State>, String> {
        Ok(Dump {
            state: json!({"queue": 7}),
            signal: Signal::NeedsAnalysis,
            reason: "queue_stalled",
        })
    }
}
struct Fault(&'static str);
impl StateDump for Fault {
    type State = ();

    async fn state_dump(&self) -> Result<Dump<()>, String> {
        match self.0 {
            "hang" => std::future::pending().await,
            "panic" => panic!("injected"),
            _ => Err("x".repeat(1000)),
        }
    }
}
#[tokio::test]
async fn replacement_owns_its_schema_and_analysis_policy() {
    let source = Custom {
        reads: Arc::default(),
        signal: Signal::Healthy,
    };
    let first = Reporter::new("custom", "node-a", source, Config::default())
        .collect()
        .await;
    assert!(!first.analysis_required);
    assert_eq!(first.state.value(), Some(&vec![3, 7]));
    let second = Reporter::new("custom", "node-a", Replacement, Config::default())
        .collect()
        .await;
    assert!(second.analysis_required);
    assert_eq!(second.reason, "queue_stalled");
    let value: Value = serde_json::from_str(&second.to_json().unwrap()).unwrap();
    assert_eq!(value["state"]["value"]["queue"], 7);
    assert_eq!(value["signal"], "needs_analysis");
}
#[tokio::test]
async fn failures_are_analyzable_and_cannot_hide_another_component() {
    for fault in ["hang", "panic", "error"] {
        let bad = Reporter::new(
            "bad",
            "a",
            Fault(fault),
            Config::default().with_source_timeout(Duration::from_millis(5)).unwrap(),
        );
        let good = Reporter::new("good", "a", Replacement, Config::default());
        let (failed, good) = futures::join!(bad.collect(), good.collect());
        assert_eq!(failed.signal, Signal::Unknown);
        assert!(failed.analysis_required);
        assert!(failed.state.value().is_none());
        assert!(good.state.value().is_some());
        if let Section::Error { message } = failed.state {
            assert!(message.len() <= 120);
        }
    }
}
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<(bool, String)>>>);
struct Visitor {
    analysis: bool,
    reason: String,
}
impl tracing::field::Visit for Visitor {
    fn record_bool(&mut self, f: &tracing::field::Field, value: bool) {
        if f.name() == "analysis_required" {
            self.analysis = value;
        }
    }

    fn record_str(&mut self, f: &tracing::field::Field, value: &str) {
        if f.name() == "reason" {
            self.reason = value.into();
        }
    }

    fn record_debug(&mut self, f: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if f.name() == "reason" {
            self.reason = format!("{value:?}");
        }
    }
}
impl tracing::Subscriber for Capture {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut v = Visitor {
            analysis: false,
            reason: String::new(),
        };
        event.record(&mut v);
        self.0.lock().unwrap().push((v.analysis, v.reason));
    }

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}
#[tokio::test]
async fn periodic_idle_emission_and_disabled_runs_preserve_producers() {
    let reads = Arc::new(AtomicUsize::new(0));
    let make = |config| {
        Reporter::new(
            "custom",
            "a",
            Custom {
                reads: reads.clone(),
                signal: Signal::Unknown,
            },
            config,
        )
    };
    make(Config::new(0).unwrap())
        .run_on(futures::stream::iter([(), ()]))
        .await;
    assert_eq!(reads.load(Ordering::Relaxed), 0);
    let capture = Capture::default();
    let _subscriber = tracing::subscriber::set_default(capture.clone());
    make(Config::default()).run_on(futures::stream::iter([(), ()])).await;
    assert_eq!(reads.load(Ordering::Relaxed), 2);
    assert_eq!(capture.0.lock().unwrap().len(), 2);
    assert!(capture.0.lock().unwrap().iter().all(|r| r.0));
}
#[tokio::test]
async fn oversized_payload_preserves_the_analysis_signal_in_logs() {
    let mut record = Reporter::new("custom", "a", Replacement, Config::default())
        .collect()
        .await;
    record.state = Section::Ok {
        value: json!("x".repeat(MAX_SNAPSHOT_BYTES)),
    };
    assert!(matches!(record.to_json(), Err(EncodeError::TooLarge)));
    let capture = Capture::default();
    let _subscriber = tracing::subscriber::set_default(capture.clone());
    record.emit();
    assert_eq!(&*capture.0.lock().unwrap(), &[(true, "encoding_error".into())]);
}
#[test]
fn config_validates_intervals_and_deadlines() {
    assert_eq!(Config::default().interval(), Some(Duration::from_secs(60)));
    assert!(Config::new(1).is_err());
    assert!(Config::new(86401).is_err());
    assert_eq!(Config::new(0).unwrap().interval(), None);
    assert!(Config::default().with_source_timeout(Duration::ZERO).is_err());
}
