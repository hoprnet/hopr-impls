use std::time::Duration;

use futures::StreamExt;
use hopr_api::{
    OffchainPublicKey,
    chain::{ChainReadChannelOperations, ChannelSelector},
    types::{
        crypto::prelude::{ChainKeypair, Keypair, OffchainKeypair},
        internal::{
            NodeId,
            prelude::{ChannelEntry, ChannelStatus},
        },
        primitive::prelude::*,
    },
};

use super::*;
use crate::testing::BlokliTestStateBuilder;
fn packet(i: u8) -> anyhow::Result<OffchainPublicKey> {
    Ok(*OffchainKeypair::from_secret(&[i; 32])?.public())
}
fn destination(i: u64) -> NodeId {
    NodeId::Chain(Address::from(
        i.to_be_bytes().repeat(3)[..20].try_into().unwrap_or([0; 20]),
    ))
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

#[tokio::test]
async fn chain_dump_is_independent_and_signals_underfunding_with_bounded_samples() -> anyhow::Result<()> {
    use crate::testing::create_test_blokli_connector;
    let key = ChainKeypair::from_secret(&[1; 32])?;
    let me = key.public().to_address();
    let safe = Address::from([88; 20]);
    let mut channels = Vec::new();
    for i in 1..=100u64 {
        let NodeId::Chain(peer) = destination(i) else {
            unreachable!()
        };
        channels.push(
            ChannelEntry::builder()
                .between(me, peer)
                .amount(i as u32 % 10)
                .status(ChannelStatus::Open)
                .build()?,
        );
    }
    // Incoming channels are funded by the counterparty.
    channels.push(
        ChannelEntry::builder()
            .between(Address::from([3; 20]), me)
            .amount(0)
            .status(ChannelStatus::Open)
            .build()?,
    );
    let mut peers: Vec<_> = channels
        .iter()
        .flat_map(|c| [c.source, c.destination])
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    peers.sort();
    let accounts = peers
        .into_iter()
        .enumerate()
        .map(|(i, chain_addr)| {
            Ok((
                hopr_api::types::internal::prelude::AccountEntry {
                    public_key: packet(i as u8 + 1)?,
                    chain_addr,
                    entry_type: hopr_api::types::internal::prelude::AccountType::NotAnnounced,
                    safe_address: None,
                    key_id: ((i + 1) as u32).into(),
                },
                HoprBalance::zero(),
                XDaiBalance::zero(),
            ))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let chain = create_test_blokli_connector(
        &key,
        BlokliTestStateBuilder::default()
            .with_accounts(accounts)
            .with_channels(channels)
            .with_balances::<WxHOPR>([(safe, hopr_api::graph::traits::Balance::MAX.into())])
            .with_safe_allowances([(safe, 7u32.into())])
            .build_static_client(),
        Address::from([99; 20]),
    )
    .await?;
    let adapter = ChainDump::new(chain, safe, Config::default()).with_funding_value(10u32.into());
    let report = adapter.state_dump().await.map_err(anyhow::Error::msg)?;
    assert_eq!(report.signal, Signal::NeedsAnalysis);
    assert_eq!(report.reason, "channel_funding_or_closure");
    let channels = report.state.channels.value().unwrap();
    assert_eq!(channels.total, 101);
    assert_eq!(channels.funding.below, 100);
    assert_eq!(channels.underfunded().len(), MAX_UNDERFUNDED_SAMPLES);
    assert_eq!(channels.underfunded_omitted, 84);
    assert_eq!(channels.sample().len(), MAX_CHANNEL_SAMPLES);
    assert!(channels.underfunded().windows(2).all(|w| w[0].balance <= w[1].balance));
    let value = serde_json::to_value(&report.state)?;
    assert_eq!(
        value["safe_balance"]["value"],
        hopr_api::graph::traits::Balance::MAX.to_string()
    );
    assert!(value.get("graph").is_none());
    assert!(value.get("routing").is_none());
    Ok(())
}

#[tokio::test]
async fn chain_failures_keep_successful_reads_and_request_analysis() -> anyhow::Result<()> {
    use crate::testing::{ChainOp, Fault, create_test_blokli_connector};
    let key = ChainKeypair::from_secret(&[1; 32])?;
    let safe = Address::from([88; 20]);
    let chain = create_test_blokli_connector(
        &key,
        BlokliTestStateBuilder::default()
            .with_balances::<WxHOPR>([(safe, 100u32.into())])
            .with_safe_allowances([(safe, 7u32.into())])
            .build_static_client(),
        Address::from([99; 20]),
    )
    .await?;
    let faults = chain.faults();
    faults.set(ChainOp::Balance, Fault::Hang);
    faults.set(ChainOp::StreamChannels, Fault::Fail);
    let config = Config::default().with_source_timeout(Duration::from_millis(40))?;
    let adapter = ChainDump::new(chain, safe, config.clone());
    let report = adapter.state_dump().await.map_err(anyhow::Error::msg)?;
    assert_eq!(report.signal, Signal::Unknown);
    assert!(report.signal.analysis_required());
    assert!(matches!(report.state.safe_balance, Section::Timeout));
    assert!(matches!(report.state.channels, Section::Error { .. }));
    assert_eq!(
        report.state.safe_allowance.value().map(|a| a.value()),
        Some(7u32.into())
    );
    faults.set(ChainOp::Balance, Fault::Fail);
    faults.set(ChainOp::StreamChannels, Fault::Hang);
    let report = adapter.state_dump().await.map_err(anyhow::Error::msg)?;
    assert!(matches!(report.state.channels, Section::Partial { ref value } if value.reads.timed_out));
    assert_eq!(report.signal, Signal::Unknown);
    let reporter = Reporter::new("chain", "node", adapter, config);
    let record = reporter.collect().await;
    assert!(
        record.state.value().is_some(),
        "the component must return partial observations before its overall deadline"
    );
    assert_eq!(
        record.state.value().unwrap().safe_allowance.value().map(|a| a.value()),
        Some(7u32.into())
    );
    assert!(record.analysis_required);

    Ok(())
}

#[tokio::test]
async fn producer_signals_failures_without_inventing_surb_loss_and_disabled_run_does_not_drain() -> anyhow::Result<()> {
    let counters = IntervalCounters::default();
    counters.resolution(Direction::Forward, destination(1), false);
    let reporter = Reporter::new("resolver", "node", counters.clone(), Config::new(0)?);
    reporter.run().await;
    let first = reporter.collect().await;
    assert!(first.analysis_required);
    assert_eq!(first.state.value().unwrap().totals.failed, 1);
    let second = reporter.collect().await;
    assert!(!second.analysis_required);
    assert_eq!(second.state.value().unwrap().totals.failed, 0);
    counters.surb(
        packet(1)?,
        hopr_api::graph::ForwardAndReturnPath {
            forward: [1; 5],
            reply: [2; 5],
        },
        SurbCounts {
            minted: 10,
            returned: 0,
        },
    );
    assert_eq!(
        counters.state_dump().await.unwrap().signal,
        Signal::Healthy,
        "returns may cross windows; minted minus returned is not a loss verdict"
    );
    counters.neighbor_probe(destination(2), false);
    assert_eq!(counters.state_dump().await.unwrap().signal, Signal::NeedsAnalysis);
    Ok(())
}
