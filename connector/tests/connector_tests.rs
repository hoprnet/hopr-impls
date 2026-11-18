// This integration test requires the `testing` feature.
#![cfg(feature = "testing")]

use hopr_api::{
    chain::ChainValues,
    types::{
        crypto::prelude::{ChainKeypair, Keypair, OffchainKeypair},
        internal::{
            channels::ChannelStatus,
            prelude::{AccountEntry, AccountType, ChannelEntry},
        },
        primitive::{
            balance::WxHOPR,
            prelude::{Address, BytesRepresentable, HoprBalance, XDai, XDaiBalance},
        },
    },
};
use hopr_chain_connector::{
    create_trustful_hopr_blokli_connector, create_trustless_hopr_blokli_connector, testing::BlokliTestStateBuilder,
};

lazy_static::lazy_static! {
    static ref CHAIN_KEYS: Vec<ChainKeypair> = (0..3).map(|_| ChainKeypair::random()).collect();
    static ref OFFCHAIN_KEYS: Vec<OffchainKeypair> = (0..3).map(|_| OffchainKeypair::random()).collect();

    static ref ACCOUNTS: Vec<AccountEntry> = vec![
        AccountEntry {
            public_key: *OFFCHAIN_KEYS[0].public(),
            chain_addr: CHAIN_KEYS[0].public().to_address(),
            entry_type: AccountType::Announced(vec!["/ip4/34.65.237.196/udp/9091/p2p/16Uiu2HAm3rUQdpCz53tK1MVUUq9NdMAU6mFgtcXrf71Ltw6AStzk".parse().unwrap()]),
            safe_address: None,
            key_id: 1_u32.into(),
        },
        AccountEntry {
            public_key: *OFFCHAIN_KEYS[1].public(),
            chain_addr: CHAIN_KEYS[1].public().to_address(),
            entry_type: AccountType::Announced(vec!["/ip4/34.65.237.190/udp/9091/p2p/12D3KooWPGsW7vZ8VsmJ9Lws9vsKaBiACZXQ3omRm3rFUho5BpvF".parse().unwrap()]),
            safe_address: None,
            key_id: 2_u32.into(),
        },
        AccountEntry {
            public_key: *OFFCHAIN_KEYS[2].public(),
            chain_addr: CHAIN_KEYS[2].public().to_address(),
            entry_type: AccountType::NotAnnounced,
            safe_address: None,
            key_id: 3_u32.into(),
        }
    ];
    static ref CHANNELS: Vec<ChannelEntry> = vec![
        ChannelEntry::builder()
            .between(&CHAIN_KEYS[0], &CHAIN_KEYS[1])
            .amount(100)
            .ticket_index(1)
            .status(ChannelStatus::Open)
            .epoch(1)
            .build()
            .unwrap(),
        ChannelEntry::builder()
            .between(&CHAIN_KEYS[2], &CHAIN_KEYS[0])
            .amount(200)
            .ticket_index(1)
            .status(ChannelStatus::Open)
            .epoch(2)
            .build()
            .unwrap(),
        ChannelEntry::builder()
            .between(&CHAIN_KEYS[1], &CHAIN_KEYS[0])
            .amount(10)
            .ticket_index(3)
            .status(ChannelStatus::Open)
            .epoch(1)
            .build()
            .unwrap()
    ];
}

#[tokio::test]
async fn hopr_block_chain_connector_should_return_channels() -> anyhow::Result<()> {
    let mock_client = BlokliTestStateBuilder::default()
        .with_hopr_network_chain_info("anvil-localhost")
        .with_accounts(
            ACCOUNTS
                .iter()
                .cloned()
                .map(|a| (a, HoprBalance::zero(), XDaiBalance::zero())),
        )
        .with_channels(CHANNELS.iter().cloned())
        .with_balances::<WxHOPR>([
            (CHAIN_KEYS[0].public().to_address(), 1000_u32.into()),
            (CHAIN_KEYS[1].public().to_address(), 2000_u32.into()),
        ])
        .with_balances::<XDai>([
            (CHAIN_KEYS[0].public().to_address(), 1_u32.into()),
            (CHAIN_KEYS[1].public().to_address(), 2_u32.into()),
        ])
        .build_static_client();

    let me = ChainKeypair::random();

    let mut connector = create_trustful_hopr_blokli_connector(
        &me,
        Default::default(),
        mock_client,
        Address::new(&[2u8; Address::SIZE]),
    )
    .await?;

    connector.connect().await?;

    assert_eq!(HoprBalance::from(1000_u32), connector.balance(&CHAIN_KEYS[0]).await?);
    assert_eq!(XDaiBalance::from(1_u32), connector.balance(&CHAIN_KEYS[0]).await?);

    Ok(())
}

/// Every chain write must be visible in the Prometheus output: the submit outcome, the tracking
/// outcome, the phase durations and the queue length the sequencer saw.
#[cfg(feature = "telemetry")]
#[tokio::test]
async fn chain_write_metrics_are_exported() -> anyhow::Result<()> {
    use hex_literal::hex;
    use hopr_api::{chain::ChainWriteChannelOperations, types::telemetry::gather_all_metrics};

    let me = ChainKeypair::from_secret(&hex!(
        "c14b8faa0a9b8a5fa4453664996f23a7e7de606d42297d723fc4a794f375e260"
    ))?;
    let dst = ChainKeypair::from_secret(&hex!(
        "492057cf93e99b31d2a85bc5e98a9c3aa0021feec52c227cc8170e8f7d047775"
    ))?;
    let node = AccountEntry {
        public_key: *OffchainKeypair::random().public(),
        chain_addr: me.public().to_address(),
        entry_type: AccountType::NotAnnounced,
        safe_address: Some(Address::new(&[1u8; Address::SIZE])),
        key_id: 1.into(),
    };
    let peer = AccountEntry {
        public_key: *OffchainKeypair::random().public(),
        chain_addr: dst.public().to_address(),
        entry_type: AccountType::NotAnnounced,
        safe_address: Some(Address::new(&[2u8; Address::SIZE])),
        key_id: 2.into(),
    };
    let module = Address::new(&[0x11u8; Address::SIZE]);
    let mock_client = BlokliTestStateBuilder::default()
        .with_accounts([
            (node, HoprBalance::new_base(100), XDaiBalance::new_base(1)),
            (peer, HoprBalance::new_base(100), XDaiBalance::new_base(1)),
        ])
        .with_hopr_network_chain_info("piz-palu-staging")
        .build_dynamic_client(module);

    let contracts = hopr_api::types::chain::contract_addresses_for_network("piz-palu-staging")
        .expect("network contracts")
        .1;
    let mut connector =
        create_trustless_hopr_blokli_connector(&me, Default::default(), mock_client, module, contracts)?;
    connector.connect().await?;

    connector
        .open_channel(&dst.public().to_address(), 10.into())
        .await?
        .await?;

    let expected = [
        (
            "hopr_chain_tx_outcomes_total",
            &[
                r#"operation="open_channel""#,
                r#"phase="submit""#,
                r#"outcome="accepted""#,
            ][..],
        ),
        (
            "hopr_chain_tx_outcomes_total",
            &[
                r#"operation="open_channel""#,
                r#"phase="track""#,
                r#"outcome="confirmed""#,
            ],
        ),
        (
            "hopr_chain_tx_duration_seconds_count",
            &[r#"operation="open_channel""#, r#"phase="submit""#],
        ),
        (
            "hopr_chain_tx_duration_seconds_count",
            &[r#"operation="open_channel""#, r#"phase="track""#],
        ),
        ("hopr_chain_tx_queue_length", &[]),
        ("hopr_chain_nonce", &[r#"kind="local""#]),
        ("hopr_chain_nonce", &[r#"kind="chain_pending""#]),
    ];

    // The submit outcome is recorded right after the caller is notified, so poll the export the
    // same way an exporter scrapes it.
    let mut metrics = gather_all_metrics()?;
    for _ in 0..20 {
        if expected.iter().all(|(name, labels)| has_sample(&metrics, name, labels)) {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
        metrics = gather_all_metrics()?;
    }
    for (name, labels) in expected {
        assert!(
            has_sample(&metrics, name, labels),
            "no {name} sample with {labels:?} in:\n{metrics}"
        );
    }

    Ok(())
}

/// Whether the Prometheus text has a sample of `name` carrying every given label.
fn has_sample(metrics: &str, name: &str, labels: &[&str]) -> bool {
    metrics.lines().any(|line| {
        let Some(rest) = line.strip_prefix(name) else {
            return false;
        };
        // The label block is `{key="value",…}`; compare whole pairs, so a different key that
        // happens to carry the same value cannot satisfy the check.
        let pairs = rest
            .strip_prefix('{')
            .and_then(|rest| rest.split('}').next())
            .map(|block| block.split(',').map(str::trim).collect::<Vec<_>>())
            .unwrap_or_default();
        (rest.is_empty() || rest.starts_with('{') || rest.starts_with(' '))
            && labels.iter().all(|label| pairs.contains(label))
    })
}
