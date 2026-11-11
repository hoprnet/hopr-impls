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
// The fault-injecting test connector has no production backend. Its stream deliberately
// exposes synchronous Fail/Hang faults; the real connector's diagnostic reader is tested separately.
impl<C> StateRead for crate::testing::TestChainConnector<C>
where
    Self: ChainReadChannelOperations + Sync,
{
    fn component_state(&self) -> hopr_api::ComponentState {
        // The stub's diagnostic faults are independent of the supplied runtime state.
        hopr_api::ComponentState::Running
    }

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
    let adapter = ChainView::new(chain, safe, Config::default()).with_funding_value(10u32.into());
    let report = adapter.collect_dump().await.map_err(anyhow::Error::msg)?;
    assert!(report.analysis_required);
    assert_eq!(report.reason, "channel_funding_or_closure");
    assert_eq!(report.state.component_state, hopr_api::ComponentState::Running);
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
    let adapter = ChainView::new(chain, safe, config.clone());
    let report = adapter.collect_dump().await.map_err(anyhow::Error::msg)?;
    assert!(report.analysis_required);
    assert_eq!(
        report.state.component_state,
        hopr_api::ComponentState::Running,
        "diagnostic failures must not change the supplied operational state"
    );
    assert_eq!(report.reason, "chain_reads_incomplete");
    assert!(matches!(report.state.safe_balance, Section::Timeout));
    assert!(matches!(report.state.channels, Section::Error { .. }));
    assert_eq!(
        report.state.safe_allowance.value().map(|a| a.value()),
        Some(7u32.into())
    );
    faults.set(ChainOp::Balance, Fault::Fail);
    faults.set(ChainOp::StreamChannels, Fault::Hang);
    let report = adapter.collect_dump().await.map_err(anyhow::Error::msg)?;
    assert!(matches!(report.state.channels, Section::Partial { ref value } if value.reads.timed_out));
    assert!(report.analysis_required);
    let reporter = Reporter::new("chain", "node", config);
    let record = reporter.collect(adapter.collect_dump()).await;
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
async fn inventory_distinguishes_channel_status_funding_and_peer_direction() -> anyhow::Result<()> {
    use crate::testing::create_test_blokli_connector;
    let key = ChainKeypair::from_secret(&[1; 32])?;
    let me = key.public().to_address();
    let peer = Address::from([2; 20]);
    let mut summary = Channels {
        funding_value: Some(Amount::from(hopr_api::graph::traits::Balance::from(5u32))),
        ..Default::default()
    };
    for (source, destination, direction) in [
        (me, peer, ChannelDirection::Outgoing),
        (peer, me, ChannelDirection::Incoming),
    ] {
        for status in [
            ChannelStatus::Closed,
            ChannelStatus::PendingToClose(std::time::SystemTime::now()),
            ChannelStatus::Open,
        ] {
            let channel = ChannelEntry::builder()
                .between(source, destination)
                .amount(5u32)
                .status(status)
                .build()?;
            summary.record(&channel, direction, status == ChannelStatus::Open);
        }
    }
    let above = ChannelEntry::builder()
        .between(me, peer)
        .amount(6u32)
        .status(ChannelStatus::Open)
        .build()?;
    summary.record(&above, ChannelDirection::Outgoing, false);
    assert_eq!(summary.total, 7);
    assert_eq!((summary.outgoing.closed, summary.incoming.closed), (1, 1));
    assert_eq!(
        (summary.outgoing.pending_to_close, summary.incoming.pending_to_close),
        (1, 1)
    );
    assert_eq!((summary.funding.equal, summary.funding.above), (1, 1));
    assert_eq!(summary.sample.len(), 2);
    assert!(summary.sample.iter().all(|row| row.status == "pending_to_close"));
    assert!(
        summary
            .sample
            .iter()
            .any(|row| row.direction == ChannelDirection::Incoming && row.below_funding_value.is_none())
    );
    assert_eq!(
        serde_json::to_value(Amount::from(hopr_api::graph::traits::Balance::MAX))?,
        hopr_api::graph::traits::Balance::MAX.to_string()
    );

    let chain = create_test_blokli_connector(
        &key,
        BlokliTestStateBuilder::default()
            .with_generated_accounts(
                &[&me, &peer],
                false,
                XDaiBalance::new_base(1),
                HoprBalance::new_base(10),
            )
            .with_balances::<WxHOPR>([(Address::from([88; 20]), HoprBalance::new_base(100))])
            .with_safe_allowances([(Address::from([88; 20]), HoprBalance::new_base(7))])
            .with_channels([above])
            .build_static_client(),
        Address::from([99; 20]),
    )
    .await?;
    let source = ChainView::new(chain, Address::from([88; 20]), Config::default());
    let unknown = source.collect_dump().await.map_err(anyhow::Error::msg)?;
    assert_eq!(unknown.reason, "funding_value_unavailable");
    assert_eq!(unknown.state.channels.value().unwrap().funding.unknown, 1);
    Ok(())
}

#[test]
fn source_read_failures_keep_categories_and_bound_named_samples() {
    let mut reads = ReadStats::default();
    for kind in ["missing", "join", "identity", "backend_read", "backend_read"] {
        reads.record(ReadFailure {
            entity: "é".repeat(100),
            kind,
            message: "é".repeat(200),
        });
    }
    assert_eq!(
        (
            reads.missing,
            reads.join_errors,
            reads.identity_errors,
            reads.backend_errors
        ),
        (1, 1, 1, 2)
    );
    assert_eq!(reads.error_samples.len(), MAX_CHANNEL_SAMPLES);
    assert!(
        reads
            .error_samples
            .iter()
            .all(|e| e.entity.chars().count() == 80 && e.message.chars().count() == 120)
    );
}

#[tokio::test]
async fn chain_public_views_keep_opaque_snapshots_and_healthy_assessment() -> anyhow::Result<()> {
    use hopr_api::StateDump;
    let me = ChainKeypair::from_secret(&crate::connector::tests::PRIVATE_KEY_1)?
        .public()
        .to_address();
    let mut connector = crate::connector::tests::create_connector(
        BlokliTestStateBuilder::default()
            .with_generated_accounts(&[&me], false, XDaiBalance::new_base(1), HoprBalance::new_base(10))
            .with_balances::<WxHOPR>([(Address::from([88; 20]), HoprBalance::new_base(100))])
            .with_safe_allowances([(Address::from([88; 20]), HoprBalance::new_base(7))])
            .build_static_client(),
    )?;
    connector.connect().await?;
    for funding in [None, Some(5u32.into())] {
        let value = serde_json::to_value(
            connector
                .state(Address::from([88; 20]), funding)
                .await
                .map_err(anyhow::Error::msg)?,
        )?;
        assert_eq!(value["reason"], "chain_observations_ok");
        assert_eq!(value["analysis_required"], false);
        let view = connector.state_view(Address::from([88; 20]), funding);
        assert_eq!(
            serde_json::to_value(view.dump().await?)?["state"]["component_state"],
            "Running"
        );
    }
    Ok(())
}

#[test]
fn chain_periodic_api_validates_configuration_and_refreshes_the_funding_policy() -> anyhow::Result<()> {
    for scenario in ["disabled", "invalid", "enabled"] {
        let output = std::process::Command::new(std::env::current_exe()?)
            .args(["--exact", "diagnostics::tests::component_reporting_probe"])
            .env("HOPR_COMPONENT_REPORT_TEST", scenario)
            .env(
                "HOPR_STATE_DUMP_INTERVAL",
                match scenario {
                    "disabled" => "0",
                    "invalid" => "bad",
                    _ => "5",
                },
            )
            .output()?;
        assert!(
            output.status.success(),
            "{scenario}: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
    }
    Ok(())
}

#[tokio::test]
async fn component_reporting_probe() -> anyhow::Result<()> {
    let Ok(scenario) = std::env::var("HOPR_COMPONENT_REPORT_TEST") else {
        return Ok(());
    };
    let mut connector =
        crate::connector::tests::create_connector(BlokliTestStateBuilder::default().build_static_client())?;
    connector.connect().await?;
    let safe = Address::from([88; 20]);
    if scenario == "enabled" {
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let policy = || {
            let call = calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            (call == 0).then(|| 5u32.into())
        };
        let running = connector.run_state_reporting_with_funding_policy("node", safe, policy);
        let result = running.timeout(futures_time::time::Duration::from_secs(11)).await;
        assert!(result.is_err(), "periodic reporting should continue until cancelled");
        assert!(
            calls.load(std::sync::atomic::Ordering::Relaxed) >= 2,
            "policy must be refreshed between intervals"
        );
    } else {
        let result = connector.run_state_reporting("node", safe, None).await;
        assert_eq!(result.is_err(), scenario == "invalid");
        if let Err(error) = result {
            assert!(error.contains("integer seconds"));
        }
    }
    Ok(())
}
