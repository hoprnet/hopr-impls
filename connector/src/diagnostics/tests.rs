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
