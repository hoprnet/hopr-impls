use std::{
    collections::HashSet,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use futures::{StreamExt, stream};
use hopr_api::{
    Multiaddr, OffchainPublicKey, PeerId,
    chain::{ChainReadChannelOperations, ChannelSelector},
    graph::{
        EdgeTransportTelemetry, MeasurableEdge, MeasurablePath, MeasurablePeer, NetworkGraphUpdate, NetworkGraphWrite,
    },
    network::{Health, NetworkEvent, NetworkView},
    types::{
        crypto::prelude::{ChainKeypair, Keypair, OffchainKeypair},
        internal::{
            NodeId,
            prelude::{AccountEntry, AccountType, ChannelEntry, ChannelStatus},
        },
        primitive::prelude::*,
    },
};
use hopr_network_graph::ChannelGraph;
use serde_json::Value;

use super::*;
use crate::{create_trustful_hopr_blokli_connector, testing::BlokliTestStateBuilder};

#[derive(Clone, Default)]
pub(crate) struct Network {
    peers: HashSet<PeerId>,
    reads: Arc<AtomicUsize>,
}
impl NetworkView for Network {
    fn listening_as(&self) -> HashSet<Multiaddr> {
        HashSet::new()
    }

    fn multiaddress_of(&self, _: &PeerId) -> Option<HashSet<Multiaddr>> {
        None
    }

    fn discovered_peers(&self) -> HashSet<PeerId> {
        self.peers.clone()
    }

    fn connected_peers(&self) -> HashSet<PeerId> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.peers.clone()
    }

    fn is_connected(&self, p: &PeerId) -> bool {
        self.peers.contains(p)
    }

    fn health(&self) -> Health {
        Health::Green
    }

    fn subscribe_network_events(&self) -> impl futures::Stream<Item = NetworkEvent> + Send + 'static {
        stream::empty()
    }
}
#[derive(Clone)]
struct Neighbor(OffchainPublicKey);
impl MeasurablePeer for Neighbor {
    fn peer(&self) -> &OffchainPublicKey {
        &self.0
    }

    fn rtt(&self) -> Duration {
        Duration::from_millis(20)
    }
}
#[derive(Clone)]
struct NoPath;
impl MeasurablePath for NoPath {
    fn id(&self) -> &[u8] {
        &[]
    }

    fn path(&self) -> &[u8] {
        &[]
    }

    fn timestamp(&self) -> u128 {
        0
    }
}
fn packet(i: u8) -> anyhow::Result<OffchainPublicKey> {
    Ok(*OffchainKeypair::from_secret(&[i; 32])?.public())
}
fn destination(i: u64) -> NodeId {
    NodeId::Chain(Address::from(
        i.to_be_bytes().repeat(3)[..20].try_into().unwrap_or([0; 20]),
    ))
}

#[tokio::test]
async fn real_sources_are_collected_and_info_reporter_emits_idle_ticks() -> anyhow::Result<()> {
    let me = ChainKeypair::from_secret(&[1; 32])?;
    let peer = ChainKeypair::from_secret(&[2; 32])?;
    let me_addr = me.public().to_address();
    let peer_addr = peer.public().to_address();
    let me_packet = packet(11)?;
    let peer_packet = packet(12)?;
    let safe = Address::from([88; 20]);
    let mut accounts: Vec<_> = [(me_addr, me_packet), (peer_addr, peer_packet)]
        .into_iter()
        .enumerate()
        .map(|(i, (chain_addr, public_key))| {
            (
                AccountEntry {
                    public_key,
                    chain_addr,
                    entry_type: AccountType::Announced(vec![
                        "/ip4/34.65.237.196/tcp/9091".parse().expect("valid fixture multiaddr"),
                    ]),
                    safe_address: None,
                    key_id: ((i + 1) as u32).into(),
                },
                HoprBalance::zero(),
                XDaiBalance::zero(),
            )
        })
        .collect();
    let mut channels = vec![
        ChannelEntry::builder()
            .between(me_addr, peer_addr)
            .amount(0)
            .status(ChannelStatus::Open)
            .build()?,
        ChannelEntry::builder()
            .between(peer_addr, me_addr)
            .amount(10)
            .status(ChannelStatus::Open)
            .build()?,
    ];
    for i in 1u64..=100 {
        let address = match destination(i) {
            NodeId::Chain(a) => a,
            _ => unreachable!(),
        };
        accounts.push((
            AccountEntry {
                public_key: packet((i + 30) as u8)?,
                chain_addr: address,
                entry_type: AccountType::NotAnnounced,
                safe_address: None,
                key_id: ((i + 2) as u32).into(),
            },
            HoprBalance::zero(),
            XDaiBalance::zero(),
        ));
        channels.push(
            ChannelEntry::builder()
                .between(me_addr, address)
                .amount(100)
                .status(ChannelStatus::Open)
                .build()?,
        );
    }
    for (i, status) in [
        (
            99,
            ChannelStatus::PendingToClose(std::time::SystemTime::now() + Duration::from_secs(60)),
        ),
        (100, ChannelStatus::Closed),
    ] {
        if let NodeId::Chain(address) = destination(i) {
            channels.push(
                ChannelEntry::builder()
                    .between(address, me_addr)
                    .amount(0)
                    .status(status)
                    .build()?,
            );
        }
    }
    let client = BlokliTestStateBuilder::default()
        .with_accounts(accounts)
        .with_channels(channels)
        .with_balances::<WxHOPR>([(safe, 100u32.into())])
        .with_safe_allowances([(safe, 7u32.into())])
        .build_static_client();
    let mut chain = create_trustful_hopr_blokli_connector(
        &me,
        crate::BlockchainConnectorConfig {
            sync_tolerance: 100,
            ..Default::default()
        },
        client,
        Address::from([99; 20]),
    )
    .await?;
    chain.connect().await?;
    // Readiness counts open channels; pending/closed replay can still be arriving.
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if chain.stream_channels(ChannelSelector::default())?.count().await == 104 {
                break Ok::<(), anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await??;
    let graph = ChannelGraph::new(me_packet);
    graph.add_node(peer_packet);
    graph.set_ticket_face_value(10u32.into());
    graph.record_edge::<Neighbor, NoPath>(MeasurableEdge::Probe(Ok(EdgeTransportTelemetry::Neighbor(Neighbor(
        peer_packet,
    )))));
    // The last graph connection observation may differ from the live transport view.
    graph.record_edge::<Neighbor, NoPath>(MeasurableEdge::ConnectionStatus {
        peer: peer_packet,
        connected: false,
    });
    let poor_peer = packet(31)?;
    graph.add_node(poor_peer);
    graph.record_edge::<Neighbor, NoPath>(MeasurableEdge::Probe(Ok(EdgeTransportTelemetry::Neighbor(Neighbor(
        poor_peer,
    )))));
    for _ in 0..4 {
        graph.record_edge::<Neighbor, NoPath>(MeasurableEdge::Probe(Err(
            hopr_api::graph::NetworkGraphError::ProbeNeighborTimeout(Box::new(poor_peer)),
        )));
    }
    let network = Network {
        peers: HashSet::from([peer_packet.into()]),
        ..Default::default()
    };
    let collector = Collector::new(&chain, &graph, network.clone(), safe, Config::default());
    let counters = IntervalCounters::default();
    counters.search(
        Direction::Forward,
        NodeId::Offchain(peer_packet),
        SearchOutcome {
            phase1: PhaseOutcome {
                returned: 0,
                eligible: 0,
            },
            phase2: Some(PhaseOutcome {
                returned: 2,
                eligible: 1,
            }),
            retained: 1,
        },
    );
    counters.resolution(Direction::Forward, NodeId::Offchain(peer_packet), false);
    for (reply, returned) in [(1, 0), (2, 18)] {
        counters.surb(
            peer_packet,
            hopr_api::graph::ForwardAndReturnPath {
                forward: [1; 5],
                reply: [reply; 5],
            },
            SurbCounts { minted: 20, returned },
        );
    }
    let output = Capture::default();
    let _subscriber = tracing::subscriber::set_default(output.clone());
    fn require_send(_: impl Send) {}
    require_send(collector.collect(None));
    require_send(collector.run(None));
    collector.run_on(stream::iter([(), ()]), Some(counters)).await;
    let records = output.0.lock().clone();
    assert_eq!(records.len(), 2, "INFO must include idle intervals");
    let first = &records[0];
    let second = &records[1];
    assert_eq!(first["sequence"], 0);
    assert_eq!(second["sequence"], 1);
    assert_eq!(first["safe_balance"]["value"], "100");
    assert_eq!(first["safe_allowance"]["value"], "7");
    assert_eq!(first["channels"]["value"]["total"], 104);
    assert_eq!(first["channels"]["value"]["incoming"]["closed"], 1);
    assert_eq!(first["channels"]["value"]["incoming"]["pending_to_close"], 1);
    assert_eq!(first["channels"]["value"]["outgoing"]["open"], 101);
    assert_eq!(first["channels"]["value"]["incoming"]["open"], 1);
    assert_eq!(first["channels"]["value"]["funding"]["below"], 1);
    assert_eq!(
        first["channels"]["value"]["funding"]["equal"], 0,
        "the open incoming channel is funded by its counterparty, not counted here"
    );
    assert_eq!(first["channels"]["value"]["funding"]["above"], 100);
    assert_eq!(
        first["channels"]["value"]["underfunded"].as_array().map(Vec::len),
        Some(1)
    );
    assert_eq!(first["channels"]["value"]["underfunded"][0]["balance"], "0");
    assert_eq!(first["channels"]["value"]["underfunded_omitted"], 0);
    assert_eq!(first["channels"]["value"]["sample"].as_array().map(Vec::len), Some(4));
    assert_eq!(first["channels"]["value"]["sample"][0]["balance"], "0");
    assert_eq!(first["channels"]["value"]["sample"][0]["below_funding_value"], true);
    assert_eq!(first["channels"]["value"]["sample"][0]["is_connected"], false);
    assert_eq!(first["channels"]["value"]["sample"][0]["transport_connected"], true);
    assert_eq!(first["channels"]["value"]["sample"][0]["probe_success_rate"], 1.0);
    assert_eq!(
        first["channels"]["value"]["peers"]["total"], 101,
        "two directed channels must not double-count a peer"
    );
    assert_eq!(first["channels"]["value"]["peers"]["poor_probe"], 1);
    assert_eq!(first["channels"]["value"]["peers"]["probe_unknown"], 99);
    assert!(
        first["channels"]["value"]["sample"]
            .as_array()
            .expect("channel sample")
            .iter()
            .any(|row| row["balance"] == "100"
                && row["below_funding_value"] == false
                && row["probe_success_rate"].as_f64().is_some_and(|r| r < 0.9)),
        "funded but poorly-probed peers need INFO coverage"
    );
    assert_eq!(first["connected_peers"], 1);
    assert_eq!(first["announced_peers"]["value"], 1, "exclude the local announcement");
    assert_eq!(first["routing"]["value"]["destinations"][0]["counts"]["failed"], 1);
    assert_eq!(
        first["routing"]["value"]["destinations"][0]["counts"]["phase2_eligible"],
        1
    );
    assert_eq!(
        first["routing"]["value"]["surbs"][0]["pairs"][0]["counts"]["returned"],
        0
    );
    assert_eq!(
        first["routing"]["value"]["surbs"][0]["pairs"][1]["counts"]["returned"],
        18
    );
    assert_eq!(second["routing"]["value"]["totals"]["failed"], 0);
    assert_eq!(second["routing"]["value"]["destinations"], serde_json::json!([]));
    assert!(first.to_string().len() < MAX_SNAPSHOT_BYTES);
    drop(records);
    let missing = collector.collect(None).await;
    assert!(matches!(missing.routing, Section::Unavailable));
    // Disabled runs neither query network nor drain a supplied handle.
    let counters = IntervalCounters::default();
    counters.resolution(Direction::Forward, destination(9999), true);
    let before = network.reads.load(Ordering::Relaxed);
    let disabled = Collector::new(&chain, &graph, network.clone(), safe, Config::new(0)?);
    disabled.run(Some(counters.clone())).await;
    assert_eq!(network.reads.load(Ordering::Relaxed), before);
    assert_eq!(counters.take_snapshot().totals.succeeded, 1);
    Ok(())
}

#[derive(Clone, Default)]
struct Capture(Arc<parking_lot::Mutex<Vec<Value>>>);
struct Visitor<'a>(&'a Capture);
impl tracing::field::Visit for Visitor<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "state"
            && let Ok(v) = serde_json::from_str(&format!("{value:?}"))
        {
            self.0.0.lock().push(v);
        }
    }
}
impl tracing::Subscriber for Capture {
    fn enabled(&self, m: &tracing::Metadata<'_>) -> bool {
        *m.level() <= tracing::Level::INFO
    }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, e: &tracing::Event<'_>) {
        e.record(&mut Visitor(self));
    }

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}

#[test]
fn churn_preserves_totals_and_failure_priority_with_bounded_inputs() {
    let counters = IntervalCounters::default();
    for i in 0..10000 {
        counters.resolution(Direction::Forward, destination(i), true);
    }
    counters.search(Direction::Forward, destination(20000), SearchOutcome::default());
    counters.resolution(Direction::Forward, destination(20000), false);
    let s = counters.take_snapshot();
    assert_eq!(s.totals.succeeded, 10000);
    assert_eq!(s.totals.failed, 1);
    assert_eq!(s.destinations().len(), MAX_DESTINATIONS);
    let broken = s
        .destinations()
        .iter()
        .find(|r| r.destination == destination(20000))
        .expect("later failure retained");
    assert_eq!(broken.counts.empty_searches, 1);
    assert!(broken.partial_window);
    assert_eq!(
        s.destinations().iter().map(|r| r.counts.succeeded).sum::<u64>() + s.destinations_overflow.succeeded,
        10000
    );
    assert_eq!(counters.take_snapshot().totals.succeeded, 0);
}
#[test]
fn one_busy_destination_cannot_consume_all_sibling_groups() -> anyhow::Result<()> {
    let c = IntervalCounters::default();
    for destination in [packet(11)?, packet(12)?, packet(13)?, packet(14)?, packet(15)?] {
        for i in 0..100 {
            c.surb(
                destination,
                hopr_api::graph::ForwardAndReturnPath {
                    forward: [1; 5],
                    reply: [i; 5],
                },
                SurbCounts {
                    minted: 20,
                    returned: if i % 2 == 0 { 0 } else { 18 },
                },
            );
        }
    }
    let s = c.take_snapshot();
    assert_eq!(s.surbs().len(), MAX_SURB_DESTINATIONS);
    for group in s.surbs() {
        assert_eq!(group.pairs().len(), MAX_SURB_PAIRS);
        assert_eq!(group.pairs()[0].counts.returned, 0);
        assert_eq!(group.pairs()[1].counts.returned, 18);
    }
    let named = s
        .surbs()
        .iter()
        .map(|g| g.pairs().iter().map(|p| p.counts.minted).sum::<u64>() + g.overflow.minted)
        .sum::<u64>();
    assert_eq!(named + s.surbs_overflow.minted, s.surb_totals.minted);
    Ok(())
}
#[test]
fn config_rejects_hot_loops_and_supports_disabling() -> anyhow::Result<()> {
    assert_eq!(Config::default().interval(), Some(Duration::from_secs(60)));
    assert_eq!(Config::new(0)?.interval(), None);
    assert!(Config::new(1).is_err());
    assert!(Config::new(86401).is_err());
    assert!(Config::default().with_source_timeout(Duration::ZERO).is_err());
    Ok(())
}

#[test]
fn saturated_payload_keeps_sibling_details_and_exact_amounts_within_budget() -> anyhow::Result<()> {
    let counters = IntervalCounters::default();
    for i in 0..100 {
        counters.search(
            Direction::Forward,
            destination(i),
            SearchOutcome {
                phase1: PhaseOutcome {
                    returned: u64::MAX,
                    eligible: u64::MAX,
                },
                phase2: Some(PhaseOutcome {
                    returned: u64::MAX,
                    eligible: u64::MAX,
                }),
                retained: 0,
            },
        );
        counters.resolution(Direction::Forward, destination(i), false);
    }
    for key in [packet(11)?, packet(12)?, packet(13)?, packet(14)?] {
        for i in 0..10 {
            counters.surb(
                key,
                hopr_api::graph::ForwardAndReturnPath {
                    forward: [u64::MAX; 5],
                    reply: [i; 5],
                },
                SurbCounts {
                    minted: u64::MAX,
                    returned: if i % 2 == 0 { 0 } else { u64::MAX },
                },
            );
        }
    }
    counters.enable_probes();
    for i in 0..100 {
        counters.neighbor_probe(destination(i), false);
    }
    counters.loopback_probe(false);
    let amount = Amount::from(hopr_api::graph::traits::Balance::MAX);
    let channels = Channels {
        total: u64::MAX,
        reads: ReadStats {
            backend_errors: u64::MAX,
            error_samples: (0..MAX_CHANNEL_SAMPLES)
                .map(|_| ReadFailure {
                    entity: "e".repeat(80),
                    kind: "backend_read",
                    message: "\0".repeat(120),
                })
                .collect(),
            ..Default::default()
        },
        funding_value: Some(amount),
        sample: (0..MAX_CHANNEL_SAMPLES)
            .map(|i| ChannelSample {
                counterparty: Address::from([i as u8; 20]),
                direction: ChannelDirection::Outgoing,
                status: "pending_to_close",
                balance: amount,
                below_funding_value: Some(false),
                is_connected: Some(false),
                transport_connected: Some(false),
                probe_success_rate: Some(0.0),
            })
            .collect(),
        underfunded: (0..MAX_UNDERFUNDED_SAMPLES)
            .map(|i| ChannelSample {
                counterparty: Address::from([i as u8; 20]),
                direction: ChannelDirection::Outgoing,
                status: "open",
                balance: amount,
                below_funding_value: Some(true),
                is_connected: Some(false),
                transport_connected: Some(false),
                probe_success_rate: Some(0.0),
            })
            .collect(),
        underfunded_omitted: u64::MAX,
        ..Default::default()
    };
    let snapshot = Snapshot {
        schema_version: 1,
        node: packet(11)?,
        node_address: Address::from([255; 20]),
        safe_address: Address::from([254; 20]),
        sequence: u64::MAX,
        collected_at_ms: u64::MAX,
        collection_ms: u64::MAX,
        chain_freshness: "unverified",
        safe_balance: Section::Ok { value: amount },
        safe_allowance: Section::Ok { value: amount },
        channels: Section::Ok { value: channels },
        connected_peers: u64::MAX,
        announced_peers: Section::Error {
            message: "\0".repeat(120),
        },
        routing: Section::Ok {
            value: counters.take_snapshot(),
        },
        // Every extra section as large as one may be.
        sections: ["a", "b", "c", "d"]
            .into_iter()
            .take(MAX_SECTIONS)
            .map(|name| (name, Value::String("x".repeat(MAX_SECTION_BYTES - 2))))
            .collect(),
    };
    let json = snapshot.to_json()?;
    assert!(json.len() <= MAX_SNAPSHOT_BYTES);
    let value: Value = serde_json::from_str(&json)?;
    assert_eq!(
        value["safe_balance"]["value"],
        hopr_api::graph::traits::Balance::MAX.to_string()
    );
    assert_eq!(
        value["routing"]["value"]["surbs"].as_array().map(Vec::len),
        Some(MAX_SURB_DESTINATIONS)
    );
    assert_eq!(
        value["routing"]["value"]["surbs"][0]["pairs"].as_array().map(Vec::len),
        Some(MAX_SURB_PAIRS)
    );
    let mut excessive = snapshot;
    excessive.announced_peers = Section::Error {
        message: "x".repeat(MAX_SNAPSHOT_BYTES),
    };
    assert!(matches!(excessive.to_json(), Err(EncodeError::TooLarge)));
    Ok(())
}

#[tokio::test]
async fn failing_or_hung_sources_do_not_hide_other_collected_sections() -> anyhow::Result<()> {
    use crate::testing::{ChainOp, Fault, create_test_blokli_connector};
    let me = ChainKeypair::from_secret(&[1; 32])?;
    let safe = Address::from([88; 20]);
    let client = BlokliTestStateBuilder::default()
        .with_balances::<WxHOPR>([(safe, 100u32.into())])
        .with_safe_allowances([(safe, 7u32.into())])
        .build_static_client();
    let chain = create_test_blokli_connector(&me, client, Address::from([99; 20])).await?;
    let faults = chain.faults();
    faults.set(ChainOp::Balance, Fault::Hang);
    faults.set(ChainOp::StreamChannels, Fault::Fail);
    let collector = Collector::new(
        chain,
        ChannelGraph::new(packet(11)?),
        Network::default(),
        safe,
        Config::default().with_source_timeout(Duration::from_millis(10))?,
    );
    let snapshot = collector.collect(None).await;
    assert!(matches!(snapshot.safe_balance, Section::Timeout));
    assert!(matches!(snapshot.channels, Section::Error { .. }));
    assert_eq!(snapshot.safe_allowance.value().map(|a| a.value()), Some(7u32.into()));
    assert!(matches!(snapshot.announced_peers, Section::Ok { value: 0 }));
    faults.set(ChainOp::Balance, Fault::Fail);
    faults.set(ChainOp::StreamChannels, Fault::Hang);
    let snapshot = collector.collect(None).await;
    assert!(matches!(snapshot.safe_balance, Section::Error { .. }));
    assert!(matches!(&snapshot.channels, Section::Partial { value } if value.reads.timed_out));
    assert_eq!(snapshot.safe_allowance.value().map(|a| a.value()), Some(7u32.into()));
    Ok(())
}
#[tokio::test]
async fn extra_sections_are_read_per_record_and_capped() -> anyhow::Result<()> {
    use crate::testing::create_test_blokli_connector;
    let me = ChainKeypair::from_secret(&[1; 32])?;
    let safe = Address::from([88; 20]);
    let client = BlokliTestStateBuilder::default().build_static_client();
    let chain = create_test_blokli_connector(&me, client, Address::from([99; 20])).await?;
    let reads = Arc::new(AtomicUsize::new(0));
    let collector = Collector::new(
        chain,
        ChannelGraph::new(packet(11)?),
        Network::default(),
        safe,
        Config::default().with_source_timeout(Duration::from_millis(10))?,
    )
    .with_section("strategies", {
        let reads = reads.clone();
        move || {
            reads.fetch_add(1, Ordering::Relaxed);
            serde_json::json!([{ "name": "auto_funding", "state": "Degraded" }])
        }
    })
    .with_section("huge", || Value::String("x".repeat(MAX_SECTION_BYTES)))
    .with_section("c", || Value::Null)
    .with_section("d", || Value::Null)
    .with_section("ignored", || Value::Null);

    let first: Value = serde_json::from_str(&collector.collect(None).await.to_json()?)?;
    let second = collector.collect(None).await;
    assert_eq!(reads.load(Ordering::Relaxed), 2, "a section is read once per record");
    assert_eq!(first["sections"]["strategies"][0]["state"], "Degraded");
    assert_eq!(first["sections"]["huge"]["status"], "too_large");
    assert_eq!(second.sections.len(), MAX_SECTIONS, "a fifth section is ignored");
    assert!(!second.sections.contains_key("ignored"));
    Ok(())
}

#[test]
fn concurrent_producers_and_resets_preserve_total_events() -> anyhow::Result<()> {
    let counters = IntervalCounters::default();
    let mut threads = Vec::new();
    for _ in 0..4 {
        let handle = counters.clone();
        threads.push(std::thread::spawn(move || {
            for i in 0..1000 {
                handle.resolution(Direction::Forward, destination(i % 8), true);
            }
        }));
    }
    let mut total = 0;
    for _ in 0..20 {
        total += counters.take_snapshot().totals.succeeded;
    }
    for thread in threads {
        thread
            .join()
            .map_err(|_| anyhow::anyhow!("counter producer panicked"))?;
    }
    total += counters.take_snapshot().totals.succeeded;
    assert_eq!(total, 4000);
    Ok(())
}

// The fault-injecting test connector has no production backend. Its stream deliberately
// exposes synchronous Fail/Hang faults; the real connector's diagnostic reader is tested separately.
impl<C> StateRead for crate::testing::TestChainConnector<C>
where
    Self: ChainReadChannelOperations + Sync,
{
    fn local_channels(&self) -> Result<futures::stream::BoxStream<'_, Result<ChannelEntry, ReadFailure>>, String> {
        Ok(self
            .stream_channels(ChannelSelector::default())
            .map_err(|e| e.to_string())?
            .map(Ok)
            .boxed())
    }

    fn announced_count(&self) -> Result<u64, String> {
        Ok(0)
    }
}

#[test]
fn probe_windows_distinguish_unavailable_idle_and_bounded_failure_samples() {
    let counters = IntervalCounters::default();
    assert!(counters.take_snapshot().probes.is_none());
    counters.enable_probes();
    let idle = counters.take_snapshot().probes.expect("registered producer");
    assert_eq!(idle.neighbor.timed_out, 0);
    for i in 0..1000 {
        counters.neighbor_probe(destination(i), true);
    }
    counters.neighbor_probe(destination(1001), false);
    counters.neighbor_probe(destination(1001), false);
    counters.loopback_probe(false);
    counters.loopback_probe(true);
    let snapshot = counters.take_snapshot();
    let probes = snapshot.probes.expect("probe counts");
    assert_eq!(probes.neighbor.succeeded, 1000);
    assert_eq!(probes.neighbor.timed_out, 2);
    assert_eq!(probes.peers().len(), MAX_PROBE_PEERS);
    let failed = probes
        .peers()
        .iter()
        .find(|r| r.peer == destination(1001))
        .expect("later timeout displaces a healthy peer");
    assert_eq!(failed.counts.timed_out, 2);
    assert!(failed.partial_window);
    assert_eq!(
        probes.peers().iter().map(|r| r.counts.succeeded).sum::<u64>() + probes.overflow.succeeded,
        1000
    );
    assert_eq!(
        probes.peers().iter().map(|r| r.counts.timed_out).sum::<u64>() + probes.overflow.timed_out,
        2
    );
    assert_eq!(probes.loopback.succeeded, 1);
    assert_eq!(probes.loopback.timed_out, 1);
    let idle = counters.take_snapshot().probes.expect("registration survives reset");
    assert_eq!(idle.neighbor.succeeded, 0);
    assert_eq!(idle.neighbor.timed_out, 0);
    assert!(idle.peers().is_empty());
}

#[test]
fn concurrent_probe_producers_and_resets_preserve_counts() {
    let counters = IntervalCounters::default();
    counters.enable_probes();
    let threads: Vec<_> = (0..4)
        .map(|_| {
            let counters = counters.clone();
            std::thread::spawn(move || {
                for i in 0..1000 {
                    counters.neighbor_probe(destination(i % 8), false);
                }
            })
        })
        .collect();
    let mut timeouts = 0;
    for _ in 0..20 {
        timeouts += counters.take_snapshot().probes.expect("registered").neighbor.timed_out;
    }
    for thread in threads {
        thread.join().expect("producer finished");
    }
    timeouts += counters.take_snapshot().probes.expect("registered").neighbor.timed_out;
    assert_eq!(timeouts, 4000);
}
