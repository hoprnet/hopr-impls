use ahash::HashSet;
use blokli_client::api::BlokliSubscriptionClient;
use futures::StreamExt;
use futures_concurrency::stream::Merge;
use hopr_api::{
    chain::{AccountSelector, ChainEvent, ChannelSelector, ServiceRegistryConfig, StateSyncOptions},
    types::internal::channels::ChannelStatusDiscriminants,
};

use crate::{
    Backend,
    connector::{HoprBlockchainConnector, services::service_registry_config_to_events},
    errors::ConnectorError,
    utils::model_to_service_registry_config,
};

impl<B, C, P, R> hopr_api::chain::ChainEvents for HoprBlockchainConnector<C, B, P, R>
where
    B: Backend + Send + Sync + 'static,
    C: BlokliSubscriptionClient + Send + Sync + 'static,
{
    type Error = ConnectorError;

    fn subscribe_with_state_sync<I: IntoIterator<Item = StateSyncOptions>>(
        &self,
        options: I,
    ) -> Result<impl futures::Stream<Item = ChainEvent> + Send + 'static, Self::Error> {
        self.check_connection_state()?;

        let options = options.into_iter().collect::<HashSet<_>>();

        let mut state_stream = futures_concurrency::stream::StreamGroup::new();
        if options.contains(&StateSyncOptions::PublicAccounts) && !options.contains(&StateSyncOptions::AllAccounts) {
            let stream = self
                .build_account_stream(AccountSelector::default().with_public_only(true))?
                .map(ChainEvent::Announcement);
            state_stream.insert(stream.boxed());
        }

        if options.contains(&StateSyncOptions::AllAccounts) {
            let stream = self
                .build_account_stream(AccountSelector::default().with_public_only(false))?
                .map(ChainEvent::Announcement);
            state_stream.insert(stream.boxed());
        }

        if options.contains(&StateSyncOptions::OpenedChannels) {
            let stream = self
                .build_channel_stream(
                    ChannelSelector::default().with_allowed_states(&[ChannelStatusDiscriminants::Open]),
                )?
                .map(ChainEvent::ChannelOpened);
            state_stream.insert(stream.boxed());
        }

        let include_registry_config = options.contains(&StateSyncOptions::ServiceRegistryConfig);
        let live_events = self.events.1.activate_cloned().filter(move |event| {
            futures::future::ready(
                !include_registry_config
                    || !matches!(
                        event,
                        ChainEvent::ServiceTypeRegistrationFeeChanged(_) | ChainEvent::ServiceRegistryPointerChanged(_)
                    ),
            )
        });
        let state_and_live = state_stream.chain(live_events).boxed();

        if include_registry_config {
            let registry_config_stream = self
                .client
                .subscribe_service_registry_config()?
                .scan(None::<ServiceRegistryConfig>, |previous, config| {
                    let events = config
                        .map_err(ConnectorError::from)
                        .and_then(model_to_service_registry_config)
                        .map(|current| {
                            let events = service_registry_config_to_events(current, previous.as_ref());
                            *previous = Some(current);
                            events.into_iter().map(ChainEvent::from).collect::<Vec<_>>()
                        });
                    futures::future::ready(Some(events))
                })
                .filter_map(|events| async move {
                    match events {
                        Ok(events) => Some(futures::stream::iter(events)),
                        Err(error) => {
                            tracing::error!(%error, "registry configuration subscription failed");
                            None
                        }
                    }
                })
                .flatten();

            Ok((state_and_live, registry_config_stream.boxed()).merge().boxed())
        } else {
            Ok(state_and_live)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use blokli_client::{
        api::BlokliTransactionClient,
        errors::{BlokliClientError, ErrorKind},
    };
    use futures::StreamExt;
    use hex_literal::hex;
    use hopr_api::{
        chain::{
            AccountSelector, ChainEvent, ChainEvents, ChainKeyOperations, ChainReadAccountOperations,
            ChainReadChannelOperations, ChainWriteAccountOperations, ChainWriteChannelOperations, ChannelSelector,
            DeployedSafe, StateSyncOptions,
        },
        node::ComponentStatusReporter,
        types::{crypto::prelude::*, internal::prelude::*, primitive::prelude::*},
    };

    use crate::{
        connector::{
            service_fixtures::{
                METADATA, NEW_OWNER, NODE, OWNER, REGISTERED_AT, REQUIREMENT, SERVICE_TYPE, UPDATED_AT,
                UPDATED_METADATA, empty_registry, entry_model, entry_with, registry_config, state_with_registry_config,
            },
            tests::{MODULE_ADDR, PRIVATE_KEY_1, PRIVATE_KEY_2, create_connector},
        },
        testing::{BlokliTestState, BlokliTestStateBuilder},
    };

    fn service_type_mut(
        state: &mut BlokliTestState,
    ) -> Result<&mut blokli_client::api::types::ServiceTypeInfo, BlokliClientError> {
        state.service_types.get_mut(SERVICE_TYPE).ok_or_else(|| {
            ErrorKind::MockClientError(anyhow::anyhow!("service type {SERVICE_TYPE} is not registered")).into()
        })
    }

    /// Applies the registry change named by the payload of the transaction.
    ///
    /// The test client broadcasts registry changes only for what a simulated transaction leaves
    /// behind, so a test drives the registry by submitting a transaction whose payload names the
    /// change to apply.
    fn registry_mutator(command: &[u8], state: &mut BlokliTestState) -> Result<(), BlokliClientError> {
        let key = BlokliTestState::service_entry_key(SERVICE_TYPE, &NODE);
        match command {
            b"register" => {
                state.services.insert(key, entry_model(METADATA, REGISTERED_AT));
            }
            b"update" => {
                state.services.insert(key, entry_model(UPDATED_METADATA, UPDATED_AT));
            }
            b"deregister" => {
                state.services.shift_remove(&key);
            }
            b"register-type" => {
                state.service_types.insert(
                    SERVICE_TYPE.into(),
                    blokli_client::api::types::ServiceTypeInfo {
                        service_type: SERVICE_TYPE.into(),
                        owner: Some(const_hex::encode(OWNER)),
                        requirement: None,
                        registration_burn: "1 wxHOPR".into(),
                        update_burn: "0 wxHOPR".into(),
                    },
                );
            }
            b"change-owner" => service_type_mut(state)?.owner = Some(const_hex::encode(NEW_OWNER)),
            b"abandon" => service_type_mut(state)?.owner = None,
            b"set-requirement" => {
                service_type_mut(state)?.requirement = Some(const_hex::encode(REQUIREMENT));
            }
            b"set-registration-burn" => service_type_mut(state)?.registration_burn = "2 wxHOPR".into(),
            b"set-update-burn" => service_type_mut(state)?.update_burn = "500 wei wxHOPR".into(),
            other => {
                return Err(ErrorKind::MockClientError(anyhow::anyhow!(
                    "unknown registry command {}",
                    String::from_utf8_lossy(other)
                ))
                .into());
            }
        }

        Ok(())
    }

    #[tokio::test]
    async fn connector_should_stream_new_events() -> anyhow::Result<()> {
        let offchain_key_2 = OffchainKeypair::from_secret(&hex!(
            "71bf1f42ebbfcd89c3e197a3fd7cda79b92499e509b6fefa0fe44d02821d146a"
        ))?;
        let account_2 = AccountEntry {
            public_key: *offchain_key_2.public(),
            chain_addr: ChainKeypair::from_secret(&PRIVATE_KEY_2)?.public().to_address(),
            entry_type: AccountType::NotAnnounced,
            safe_address: Some([2u8; Address::SIZE].into()),
            key_id: 1.into(),
        };
        let deployer_addr = ChainKeypair::from_secret(&PRIVATE_KEY_1)?.public().to_address();

        let blokli_client = BlokliTestStateBuilder::default()
            .with_accounts([(account_2.clone(), HoprBalance::new_base(100), XDaiBalance::new_base(1))])
            .with_balances([(
                ChainKeypair::from_secret(&PRIVATE_KEY_1)?.public().to_address(),
                XDaiBalance::new_base(1),
            )])
            .with_balances([([3u8; Address::SIZE].into(), HoprBalance::new_base(100))])
            .with_safe_allowances([([3u8; Address::SIZE].into(), HoprBalance::new_base(10000))])
            .with_deployed_safes([DeployedSafe {
                address: [3u8; Address::SIZE].into(),
                owners: vec![deployer_addr],
                module: MODULE_ADDR.into(),
                registered_nodes: vec![],
                deployer: deployer_addr,
            }])
            .with_hopr_network_chain_info("piz-palu-staging")
            .build_dynamic_client(MODULE_ADDR.into())
            .with_tx_simulation_delay(Duration::from_millis(100));

        let mut connector = create_connector(blokli_client)?;
        connector.connect().await?;

        let jh = tokio::task::spawn(connector.subscribe()?.take(2).collect::<Vec<_>>());

        let offchain_key_1 = OffchainKeypair::from_secret(&hex!(
            "60741b83b99e36aa0c1331578156e16b8e21166d01834abb6c64b103f885734d"
        ))?;
        let multiaddress: Multiaddr = "/ip4/127.0.0.1/tcp/1234".parse()?;

        connector.register_safe(&[3u8; Address::SIZE].into()).await?.await?;

        connector
            .announce(std::slice::from_ref(&multiaddress), &offchain_key_1)
            .await?
            .await?;

        connector.open_channel(&account_2.chain_addr, 10.into()).await?.await?;

        let events = jh.await?;

        assert!(
            matches!(&events[0], ChainEvent::Announcement(acc) if &acc.public_key == offchain_key_1.public() && acc.entry_type == AccountType::Announced(vec![multiaddress]))
        );
        assert!(
            matches!(&events[1], ChainEvent::ChannelOpened(channel) if channel.get_id() == &generate_channel_id(&ChainKeypair::from_secret(&PRIVATE_KEY_1)?.public().to_address(), &account_2.chain_addr))
        );

        Ok(())
    }

    #[tokio::test]
    async fn connector_should_stream_existing_state() -> anyhow::Result<()> {
        let offchain_key_1 = OffchainKeypair::from_secret(&hex!(
            "60741b83b99e36aa0c1331578156e16b8e21166d01834abb6c64b103f885734d"
        ))?;
        let account_1 = AccountEntry {
            public_key: *offchain_key_1.public(),
            chain_addr: ChainKeypair::from_secret(&PRIVATE_KEY_1)?.public().to_address(),
            entry_type: AccountType::Announced(vec!["/ip4/1.2.3.4/tcp/1234".parse()?]),
            safe_address: Some([1u8; Address::SIZE].into()),
            key_id: 1.into(),
        };
        let offchain_key_2 = OffchainKeypair::from_secret(&hex!(
            "71bf1f42ebbfcd89c3e197a3fd7cda79b92499e509b6fefa0fe44d02821d146a"
        ))?;
        let account_2 = AccountEntry {
            public_key: *offchain_key_2.public(),
            chain_addr: ChainKeypair::from_secret(&PRIVATE_KEY_2)?.public().to_address(),
            entry_type: AccountType::NotAnnounced,
            safe_address: Some([2u8; Address::SIZE].into()),
            key_id: 2.into(),
        };

        let channel_1 = ChannelEntry::builder()
            .between(
                &ChainKeypair::from_secret(&PRIVATE_KEY_1)?,
                &ChainKeypair::from_secret(&PRIVATE_KEY_2)?,
            )
            .amount(10)
            .ticket_index(1)
            .status(ChannelStatus::Open)
            .epoch(1)
            .build()?;

        let channel_2 = ChannelEntry::builder()
            .between(
                &ChainKeypair::from_secret(&PRIVATE_KEY_2)?,
                &ChainKeypair::from_secret(&PRIVATE_KEY_1)?,
            )
            .amount(15)
            .ticket_index(2)
            .status(ChannelStatus::PendingToClose(
                std::time::SystemTime::UNIX_EPOCH + Duration::from_mins(10),
            ))
            .epoch(1)
            .build()?;

        let blokli_client = BlokliTestStateBuilder::default()
            .with_accounts([
                (account_1.clone(), HoprBalance::new_base(100), XDaiBalance::new_base(1)),
                (account_2.clone(), HoprBalance::new_base(100), XDaiBalance::new_base(1)),
            ])
            .with_channels([channel_1, channel_2])
            .with_hopr_network_chain_info("piz-palu-staging")
            .build_static_client();

        let mut connector = create_connector(blokli_client)?;
        connector.connect().await?;

        let accounts = connector
            .subscribe_with_state_sync([StateSyncOptions::PublicAccounts])?
            .take(1)
            .collect::<Vec<_>>()
            .await;
        assert!(matches!(&accounts[0], ChainEvent::Announcement(acc) if acc == &account_1));

        let accounts = connector
            .subscribe_with_state_sync([StateSyncOptions::AllAccounts])?
            .take(2)
            .collect::<Vec<_>>()
            .await;
        assert!(matches!(&accounts[0], ChainEvent::Announcement(acc) if acc == &account_1));
        assert!(matches!(&accounts[1], ChainEvent::Announcement(acc) if acc == &account_2));

        let channels = connector
            .subscribe_with_state_sync([StateSyncOptions::OpenedChannels])?
            .take(1)
            .collect::<Vec<_>>()
            .await;
        assert!(matches!(&channels[0], ChainEvent::ChannelOpened(ch) if ch == &channel_1));

        Ok(())
    }

    #[tokio::test]
    async fn registry_config_state_sync_starts_with_both_current_values() -> anyhow::Result<()> {
        let expected = registry_config();
        let mut connector =
            create_connector(BlokliTestStateBuilder::from(state_with_registry_config()).build_static_client())?;
        connector.connect().await?;

        let events = connector
            .subscribe_with_state_sync([StateSyncOptions::ServiceRegistryConfig])?
            .take(2)
            .collect::<Vec<_>>()
            .await;

        assert!(matches!(
            &events[0],
            ChainEvent::ServiceTypeRegistrationFeeChanged(fee) if *fee == expected.type_registration_fee
        ));
        assert!(matches!(
            &events[1],
            ChainEvent::ServiceRegistryPointerChanged(pointer) if *pointer == expected.node_safe_registry
        ));
        Ok(())
    }

    #[tokio::test]
    async fn connector_should_stream_service_registry_entry_events() -> anyhow::Result<()> {
        let blokli_client = BlokliTestStateBuilder::default().build_dynamic_client_with_mutator(registry_mutator);

        let mut connector = create_connector(blokli_client.clone())?;
        connector.connect().await?;

        // The receiver is activated by `subscribe` before the first transaction is submitted, so
        // no event can be missed here. The fixture state seeds neither accounts nor channels, so
        // the registry subscription is the only source that can produce an event: the positional
        // assertions below depend on that.
        let events = tokio::task::spawn(connector.subscribe()?.take(3).collect::<Vec<_>>());

        blokli_client.submit_transaction(b"register").await?;
        blokli_client.submit_transaction(b"update").await?;
        blokli_client.submit_transaction(b"deregister").await?;

        let events = events.await?;

        assert!(
            matches!(&events[0], ChainEvent::ServiceRegistered(entry) if entry == &entry_with(ServiceType::GVPN_EXIT, NODE, METADATA, REGISTERED_AT)?)
        );
        // The update carries the whole entry, so the registration timestamp survives it.
        assert!(
            matches!(&events[1], ChainEvent::ServiceUpdated(entry) if entry == &entry_with(ServiceType::GVPN_EXIT, NODE, UPDATED_METADATA, UPDATED_AT)?)
        );
        assert!(
            matches!(&events[2], ChainEvent::ServiceDeregistered(service_type, node) if service_type == &ServiceType::GVPN_EXIT && node == &Address::from(NODE))
        );

        Ok(())
    }

    #[tokio::test]
    async fn connector_should_stream_service_type_configuration_events() -> anyhow::Result<()> {
        // The registration below has to be the first appearance of the type, so this cannot start
        // from the default fixture state, which pre-registers it.
        let blokli_client = empty_registry().build_dynamic_client_with_mutator(registry_mutator);

        let mut connector = create_connector(blokli_client.clone())?;
        connector.connect().await?;

        // As above, the registry subscription is the only source of events in this state.
        let events = tokio::task::spawn(connector.subscribe()?.take(6).collect::<Vec<_>>());

        for command in [
            b"register-type".as_slice(),
            b"change-owner",
            b"abandon",
            b"set-requirement",
            b"set-registration-burn",
            b"set-update-burn",
        ] {
            blokli_client.submit_transaction(command).await?;
        }

        let events = events.await?;

        assert!(
            matches!(&events[0], ChainEvent::ServiceTypeRegistered(service_type, owner) if service_type == &ServiceType::GVPN_EXIT && owner == &Address::from(OWNER))
        );
        assert!(
            matches!(&events[1], ChainEvent::ServiceTypeOwnerChanged(service_type, Some(owner)) if service_type == &ServiceType::GVPN_EXIT && owner == &Address::from(NEW_OWNER))
        );
        // Abandoning a type is an owner change to nobody, and is one-way.
        assert!(
            matches!(&events[2], ChainEvent::ServiceTypeOwnerChanged(service_type, None) if service_type == &ServiceType::GVPN_EXIT)
        );
        assert!(
            matches!(&events[3], ChainEvent::ServiceTypeRequirementChanged(service_type, Some(requirement)) if service_type == &ServiceType::GVPN_EXIT && requirement == &Address::from(REQUIREMENT))
        );
        assert!(
            matches!(&events[4], ChainEvent::ServiceTypeRegistrationBurnChanged(service_type, burn) if service_type == &ServiceType::GVPN_EXIT && burn == &HoprBalance::new_base(2))
        );
        assert!(
            matches!(&events[5], ChainEvent::ServiceTypeUpdateBurnChanged(service_type, burn) if service_type == &ServiceType::GVPN_EXIT && burn == &HoprBalance::from(500_u32))
        );

        Ok(())
    }

    #[tokio::test]
    async fn service_events_should_not_disturb_accounts_channels_or_readiness() -> anyhow::Result<()> {
        let offchain_key_1 = OffchainKeypair::from_secret(&hex!(
            "60741b83b99e36aa0c1331578156e16b8e21166d01834abb6c64b103f885734d"
        ))?;
        let account_1 = AccountEntry {
            public_key: *offchain_key_1.public(),
            chain_addr: ChainKeypair::from_secret(&PRIVATE_KEY_1)?.public().to_address(),
            entry_type: AccountType::Announced(vec!["/ip4/1.2.3.4/tcp/1234".parse()?]),
            safe_address: Some([1u8; Address::SIZE].into()),
            key_id: 1.into(),
        };
        let offchain_key_2 = OffchainKeypair::from_secret(&hex!(
            "71bf1f42ebbfcd89c3e197a3fd7cda79b92499e509b6fefa0fe44d02821d146a"
        ))?;
        let account_2 = AccountEntry {
            public_key: *offchain_key_2.public(),
            chain_addr: ChainKeypair::from_secret(&PRIVATE_KEY_2)?.public().to_address(),
            entry_type: AccountType::NotAnnounced,
            safe_address: Some([2u8; Address::SIZE].into()),
            key_id: 2.into(),
        };
        let channel_1 = ChannelEntry::builder()
            .between(
                &ChainKeypair::from_secret(&PRIVATE_KEY_1)?,
                &ChainKeypair::from_secret(&PRIVATE_KEY_2)?,
            )
            .amount(10)
            .ticket_index(1)
            .status(ChannelStatus::Open)
            .epoch(1)
            .build()?;

        let blokli_client = BlokliTestStateBuilder::default()
            .with_accounts([
                (account_1.clone(), HoprBalance::new_base(100), XDaiBalance::new_base(1)),
                (account_2.clone(), HoprBalance::new_base(100), XDaiBalance::new_base(1)),
            ])
            .with_channels([channel_1])
            .with_hopr_network_chain_info("piz-palu-staging")
            .build_dynamic_client_with_mutator(registry_mutator);

        let mut connector = create_connector(blokli_client.clone())?;
        connector.connect().await?;
        assert!(connector.component_status().is_ready());

        let accounts_before = connector
            .stream_accounts(AccountSelector::default())?
            .collect::<Vec<_>>()
            .await;
        let channels_before = connector
            .stream_channels(ChannelSelector::default())?
            .collect::<Vec<_>>()
            .await;
        assert_eq!(2, accounts_before.len());
        assert_eq!(1, channels_before.len());

        // Unlike the registry-only tests above, this state has accounts and channels, so the
        // subscription merges sources that can also produce events. Select the registry event by
        // variant rather than by position, which `.merge()` does not fix.
        let events = tokio::task::spawn(
            connector
                .subscribe()?
                .filter(|event| futures::future::ready(matches!(event, ChainEvent::ServiceRegistered(_))))
                .take(1)
                .collect::<Vec<_>>(),
        );
        blokli_client.submit_transaction(b"register").await?;
        let events = events.await?;
        assert!(matches!(&events[0], ChainEvent::ServiceRegistered(_)));

        // A registry event touches neither the account and channel caches nor the connection: it
        // does not count towards the sync quota, so the connector stays ready either way.
        assert_eq!(
            accounts_before,
            connector
                .stream_accounts(AccountSelector::default())?
                .collect::<Vec<_>>()
                .await
        );
        assert_eq!(
            channels_before,
            connector
                .stream_channels(ChannelSelector::default())?
                .collect::<Vec<_>>()
                .await
        );
        assert_eq!(
            Some(account_1.public_key),
            connector.chain_key_to_packet_key(&account_1.chain_addr)?
        );
        assert_eq!(
            Some(account_2.chain_addr),
            connector.packet_key_to_chain_key(&account_2.public_key)?
        );
        assert!(connector.is_connected());
        assert!(connector.component_status().is_ready());

        Ok(())
    }
}
