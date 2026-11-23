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

/// Reproduces a production defect: Blokli's `subscribe_graph` feed can silently omit one channel's
/// events (observed live as a permanent `cache miss on channel_by_parties` immediately followed by
/// `failed to find channel` in the packet-forwarding path, for a channel confirmed `Open` on-chain
/// and correctly returned by Blokli's own `query_channels`). `channel_by_id`/`channel_by_parties`
/// only ever learn of a channel through this subscription (`connector/src/connector/mod.rs::do_connect`);
/// if one entry never arrives, there is no retry or backfill (see CORE-1172), so the channel stays
/// invisible to packet forwarding forever, even though it is real, open, and funded.
mod missing_channel_from_dropped_graph_subscription {
    use blokli_client::{
        api::{
            AccountSelector, BlokliQueryClient, BlokliSubscriptionClient, BlokliTransactionClient, ChainAddress,
            ChannelSelector, ModulePredictionInput, RedeemedStatsSelector, SafeSelector, ServiceSelector,
            ServiceTypeId, TicketSelector, TransactionTrackingOutcome, TxId, TxReceipt, types,
        },
        errors::BlokliClientError,
    };
    use futures::StreamExt;
    use hopr_api::{
        chain::ChainReadChannelOperations,
        types::{
            crypto::prelude::{ChainKeypair, Keypair, OffchainKeypair},
            internal::prelude::{AccountEntry, AccountType, ChannelEntry, ChannelStatus},
            primitive::prelude::{Address, BytesRepresentable, HoprBalance, XDaiBalance},
        },
    };
    use hopr_chain_connector::{
        BlockchainConnectorConfig, create_trustful_hopr_blokli_connector, testing::BlokliTestStateBuilder,
    };

    type BlokliResult<T> = std::result::Result<T, BlokliClientError>;

    /// Wraps a Blokli client and drops one channel's entries from `subscribe_graph`'s stream, as
    /// though Blokli's lossy broadcast silently failed to deliver it. Every other call — including
    /// `query_channels` for the very same channel — passes straight through, mirroring what was
    /// found live: Blokli's own query API had the row, only its subscription feed did not.
    #[derive(Clone)]
    struct DroppingGraphSubscriptionClient<C> {
        inner: C,
        /// Hex-encoded `concrete_channel_id` (no `0x` prefix) of the channel to withhold.
        dropped_channel_id: String,
    }

    #[allow(deprecated)]
    #[async_trait::async_trait]
    impl<C: BlokliQueryClient + Send + Sync> BlokliQueryClient for DroppingGraphSubscriptionClient<C> {
        async fn count_accounts(&self, selector: AccountSelector) -> BlokliResult<u32> {
            self.inner.count_accounts(selector).await
        }

        async fn query_accounts(&self, selector: AccountSelector) -> BlokliResult<Vec<types::Account>> {
            self.inner.query_accounts(selector).await
        }

        async fn query_native_balance(&self, address: &ChainAddress) -> BlokliResult<types::NativeBalance> {
            self.inner.query_native_balance(address).await
        }

        async fn query_token_balance(
            &self,
            address: &ChainAddress,
            token: types::Token,
        ) -> BlokliResult<types::HoprBalance> {
            self.inner.query_token_balance(address, token).await
        }

        async fn query_transaction_count(&self, address: &ChainAddress) -> BlokliResult<u64> {
            self.inner.query_transaction_count(address).await
        }

        async fn query_safe_allowance(&self, address: &ChainAddress) -> BlokliResult<types::SafeHoprAllowance> {
            self.inner.query_safe_allowance(address).await
        }

        async fn query_redeemed_stats(&self, selector: RedeemedStatsSelector) -> BlokliResult<types::RedeemedStats> {
            self.inner.query_redeemed_stats(selector).await
        }

        async fn query_safe(&self, selector: SafeSelector) -> BlokliResult<Vec<types::Safe>> {
            self.inner.query_safe(selector).await
        }

        async fn query_module_address_prediction(&self, input: ModulePredictionInput) -> BlokliResult<ChainAddress> {
            self.inner.query_module_address_prediction(input).await
        }

        async fn count_channels(&self, selector: ChannelSelector) -> BlokliResult<u32> {
            self.inner.count_channels(selector).await
        }

        async fn query_channel_stats(&self, selector: ChannelSelector) -> BlokliResult<types::ChannelStats> {
            self.inner.query_channel_stats(selector).await
        }

        async fn query_channels(&self, selector: ChannelSelector) -> BlokliResult<types::ChannelsList> {
            self.inner.query_channels(selector).await
        }

        async fn query_safes_balance(&self, owner_address: Option<ChainAddress>) -> BlokliResult<types::SafesBalance> {
            self.inner.query_safes_balance(owner_address).await
        }

        async fn count_services(&self, selector: ServiceSelector) -> BlokliResult<u32> {
            self.inner.count_services(selector).await
        }

        async fn query_services(&self, selector: ServiceSelector) -> BlokliResult<Vec<types::ServiceEntry>> {
            self.inner.query_services(selector).await
        }

        async fn query_live_services(&self, selector: ServiceSelector) -> BlokliResult<Vec<types::ServiceEntry>> {
            self.inner.query_live_services(selector).await
        }

        async fn query_service_types(
            &self,
            service_type: Option<ServiceTypeId>,
        ) -> BlokliResult<Vec<types::ServiceTypeInfo>> {
            self.inner.query_service_types(service_type).await
        }

        async fn query_service_registry_config(&self) -> BlokliResult<types::ServiceRegistryConfig> {
            self.inner.query_service_registry_config().await
        }

        async fn query_transaction_status(&self, tx_id: TxId) -> BlokliResult<types::Transaction> {
            self.inner.query_transaction_status(tx_id).await
        }

        async fn query_chain_info(&self) -> BlokliResult<types::ChainInfo> {
            self.inner.query_chain_info().await
        }

        async fn query_version(&self) -> BlokliResult<String> {
            self.inner.query_version().await
        }

        async fn query_health(&self) -> BlokliResult<String> {
            self.inner.query_health().await
        }

        async fn query_compatibility(&self) -> BlokliResult<types::Compatibility> {
            self.inner.query_compatibility().await
        }
    }

    #[async_trait::async_trait]
    impl<C: BlokliTransactionClient + Send + Sync> BlokliTransactionClient for DroppingGraphSubscriptionClient<C> {
        async fn submit_transaction(&self, signed_tx: &[u8]) -> BlokliResult<TxReceipt> {
            self.inner.submit_transaction(signed_tx).await
        }

        async fn submit_and_track_transaction(&self, signed_tx: &[u8]) -> BlokliResult<TxId> {
            self.inner.submit_and_track_transaction(signed_tx).await
        }

        async fn submit_and_confirm_transaction(
            &self,
            signed_tx: &[u8],
            num_confirmations: usize,
        ) -> BlokliResult<TxReceipt> {
            self.inner
                .submit_and_confirm_transaction(signed_tx, num_confirmations)
                .await
        }

        async fn track_transaction(
            &self,
            tx_id: TxId,
            client_timeout: std::time::Duration,
        ) -> BlokliResult<TransactionTrackingOutcome> {
            self.inner.track_transaction(tx_id, client_timeout).await
        }
    }

    impl<C: BlokliSubscriptionClient + Send + Sync> BlokliSubscriptionClient for DroppingGraphSubscriptionClient<C> {
        fn subscribe_channels(
            &self,
            selector: ChannelSelector,
        ) -> BlokliResult<impl futures::Stream<Item = BlokliResult<types::Channel>> + Send> {
            self.inner.subscribe_channels(selector)
        }

        fn subscribe_accounts(
            &self,
            selector: AccountSelector,
        ) -> BlokliResult<impl futures::Stream<Item = BlokliResult<types::Account>> + Send> {
            self.inner.subscribe_accounts(selector)
        }

        /// The one override: filters the dropped channel's entries out of the real stream, exactly
        /// as a lossy broadcast would, while leaving every other channel's delivery untouched.
        fn subscribe_graph(
            &self,
        ) -> BlokliResult<impl futures::Stream<Item = BlokliResult<types::OpenedChannelsGraphEntry>> + Send> {
            let dropped = self.dropped_channel_id.clone();
            Ok(self.inner.subscribe_graph()?.filter(move |item| {
                let keep = match item {
                    Ok(entry) => entry.channel.concrete_channel_id != dropped,
                    Err(_) => true,
                };
                futures::future::ready(keep)
            }))
        }

        fn subscribe_ticket_params(
            &self,
        ) -> BlokliResult<impl futures::Stream<Item = BlokliResult<types::TicketParameters>> + Send> {
            self.inner.subscribe_ticket_params()
        }

        fn subscribe_health(
            &self,
        ) -> BlokliResult<impl futures::Stream<Item = BlokliResult<types::ReadinessState>> + Send> {
            self.inner.subscribe_health()
        }

        fn subscribe_safe_deployments(
            &self,
        ) -> BlokliResult<impl futures::Stream<Item = BlokliResult<types::Safe>> + Send> {
            self.inner.subscribe_safe_deployments()
        }

        fn subscribe_services(
            &self,
            selector: ServiceSelector,
        ) -> BlokliResult<impl futures::Stream<Item = BlokliResult<types::ServiceUpdate>> + Send> {
            self.inner.subscribe_services(selector)
        }

        fn subscribe_service_types(
            &self,
            service_type: Option<ServiceTypeId>,
        ) -> BlokliResult<impl futures::Stream<Item = BlokliResult<types::ServiceTypeUpdate>> + Send> {
            self.inner.subscribe_service_types(service_type)
        }

        fn subscribe_service_registry_config(
            &self,
        ) -> BlokliResult<impl futures::Stream<Item = BlokliResult<types::ServiceRegistryConfig>> + Send + 'static>
        {
            self.inner.subscribe_service_registry_config()
        }

        fn subscribe_track_transaction(
            &self,
            tx_id: TxId,
        ) -> BlokliResult<impl futures::Stream<Item = BlokliResult<types::Transaction>> + Send> {
            self.inner.subscribe_track_transaction(tx_id)
        }

        fn subscribe_ticket_redeemed(
            &self,
            selector: TicketSelector,
        ) -> BlokliResult<impl futures::Stream<Item = BlokliResult<types::RedeemTicketDetails>> + Send> {
            self.inner.subscribe_ticket_redeemed(selector)
        }
    }

    /// `me --[Open, 100 wxHOPR]--> dropped_peer` exists on chain and in Blokli's query API, but its
    /// `subscribe_graph` entry never arrives. A `kept_peer` channel is opened too, as a control, to
    /// show the drop is selective rather than a blanket subscription failure.
    #[tokio::test]
    async fn connector_should_still_find_an_own_channel_whose_graph_subscription_event_was_dropped()
    -> anyhow::Result<()> {
        let me = ChainKeypair::random();
        let dropped_peer = ChainKeypair::random();
        let kept_peer = ChainKeypair::random();

        let dropped_channel = ChannelEntry::builder()
            .between(&me, &dropped_peer)
            .amount(100)
            .ticket_index(0)
            .status(ChannelStatus::Open)
            .epoch(1)
            .build()?;
        let kept_channel = ChannelEntry::builder()
            .between(&me, &kept_peer)
            .amount(50)
            .ticket_index(0)
            .status(ChannelStatus::Open)
            .epoch(1)
            .build()?;

        let accounts = [&me, &dropped_peer, &kept_peer]
            .into_iter()
            .enumerate()
            .map(|(i, key)| {
                (
                    AccountEntry {
                        public_key: *OffchainKeypair::random().public(),
                        chain_addr: key.public().to_address(),
                        entry_type: AccountType::NotAnnounced,
                        safe_address: None,
                        key_id: (i as u32).into(),
                    },
                    HoprBalance::zero(),
                    XDaiBalance::zero(),
                )
            });

        let dropped_channel_id = const_hex::encode(dropped_channel.get_id());

        let mock_client = BlokliTestStateBuilder::default()
            .with_hopr_network_chain_info("anvil-localhost")
            .with_accounts(accounts)
            .with_channels([dropped_channel, kept_channel])
            .build_static_client();

        let wrapped_client = DroppingGraphSubscriptionClient {
            inner: mock_client,
            dropped_channel_id: dropped_channel_id.clone(),
        };

        // Low enough that the one surviving channel event already clears the readiness quota on its
        // own — mirroring how a large network's 90% default tolerates missing a handful of events
        // without ever noticing or retrying them.
        let cfg = BlockchainConnectorConfig {
            sync_tolerance: 50,
            ..Default::default()
        };

        let mut connector =
            create_trustful_hopr_blokli_connector(&me, cfg, wrapped_client, Address::new(&[9u8; Address::SIZE]))
                .await?;

        connector.connect().await?;

        let kept = connector.channel_by_parties(&me.public().to_address(), &kept_peer.public().to_address())?;
        assert!(
            kept.is_some(),
            "control channel must be found: the drop must be selective"
        );

        let dropped = connector.channel_by_parties(&me.public().to_address(), &dropped_peer.public().to_address())?;
        assert!(
            dropped.is_some(),
            "channel {dropped_channel_id} is Open on-chain and Blokli's own query API returns it, but its \
             subscribe_graph entry was dropped and the connector never retried or backfilled it — so packet \
             forwarding through this real, funded channel fails as 'channel not found'"
        );

        Ok(())
    }
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

/// A receipt future dropped without being polled still leaves a live write: the caller must be
/// counted, otherwise a caller-side timeout disappears from the metrics.
#[cfg(feature = "telemetry")]
#[tokio::test]
async fn a_dropped_receipt_future_counts_the_caller_as_abandoned() -> anyhow::Result<()> {
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

    let dst_address = dst.public().to_address();
    let receipt = connector.open_channel(&dst_address, 10.into()).await?;
    drop(receipt);

    let name = "hopr_chain_caller_abandoned_total";
    let labels = [r#"operation="open_channel""#];
    let mut metrics = gather_all_metrics()?;
    for _ in 0..20 {
        if has_sample(&metrics, name, &labels) {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
        metrics = gather_all_metrics()?;
    }
    assert!(
        has_sample(&metrics, name, &labels),
        "no abandonment sample in:\n{metrics}"
    );

    Ok(())
}

/// One gauge refresh must publish the Safe, channel and Blokli state the issue asks for.
#[cfg(feature = "telemetry")]
#[tokio::test]
async fn a_gauge_refresh_exports_the_chain_state() -> anyhow::Result<()> {
    use hex_literal::hex;
    use hopr_api::{
        chain::DeployedSafe,
        types::{internal::channels::ChannelStatus, primitive::prelude::WxHOPR, telemetry::gather_all_metrics},
    };

    let me = ChainKeypair::from_secret(&hex!(
        "c14b8faa0a9b8a5fa4453664996f23a7e7de606d42297d723fc4a794f375e260"
    ))?;
    let peer = ChainKeypair::from_secret(&hex!(
        "492057cf93e99b31d2a85bc5e98a9c3aa0021feec52c227cc8170e8f7d047775"
    ))?;
    let me_address = me.public().to_address();
    let safe = Address::new(&[1u8; Address::SIZE]);
    let module = Address::new(&[0x11u8; Address::SIZE]);
    let node = AccountEntry {
        public_key: *OffchainKeypair::random().public(),
        chain_addr: me_address,
        entry_type: AccountType::NotAnnounced,
        safe_address: Some(safe),
        key_id: 1.into(),
    };
    let other = AccountEntry {
        public_key: *OffchainKeypair::random().public(),
        chain_addr: peer.public().to_address(),
        entry_type: AccountType::NotAnnounced,
        safe_address: Some(Address::new(&[2u8; Address::SIZE])),
        key_id: 2.into(),
    };
    let channel = ChannelEntry::builder()
        .between(&me, &peer)
        .amount(5u32)
        .status(ChannelStatus::Open)
        .build()?;
    let mock_client = BlokliTestStateBuilder::default()
        .with_accounts([
            (node, HoprBalance::new_base(100), XDaiBalance::new_base(1)),
            (other, HoprBalance::new_base(100), XDaiBalance::new_base(1)),
        ])
        .with_channels([channel])
        .with_deployed_safes([DeployedSafe {
            address: safe,
            owners: vec![me_address],
            module,
            registered_nodes: vec![me_address],
            deployer: me_address,
        }])
        .with_balances::<WxHOPR>([(safe, 150_u32.into())])
        .with_safe_allowances([(safe, 7_u32.into())])
        .with_hopr_network_chain_info("piz-palu-staging")
        .build_dynamic_client(module);

    let contracts = hopr_api::types::chain::contract_addresses_for_network("piz-palu-staging")
        .expect("network contracts")
        .1;
    let mut connector =
        create_trustless_hopr_blokli_connector(&me, Default::default(), mock_client, module, contracts)?;
    connector.connect().await?;
    connector.refresh_chain_state_metrics().await;

    let metrics = gather_all_metrics()?;
    for (name, labels) in [
        ("hopr_chain_safe_balance", &[][..]),
        ("hopr_chain_safe_allowance", &[][..]),
        (
            "hopr_chain_channels",
            &[r#"direction="outgoing""#, r#"status="open""#][..],
        ),
        ("hopr_chain_usable_outgoing_channels", &[][..]),
        ("hopr_chain_blokli_indexed_head", &[][..]),
        ("hopr_chain_blokli_info_age_seconds", &[][..]),
    ] {
        assert!(has_sample(&metrics, name, labels), "no {name} sample in:\n{metrics}");
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
