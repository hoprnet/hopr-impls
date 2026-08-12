//! Read access to the on-chain service registry, and the mapping of the Blokli registry
//! subscriptions onto [`ChainEvent`] values.
//!
//! # Reads go straight to Blokli
//!
//! Unlike accounts and channels, registry entries are not indexed into the local
//! [`Backend`](crate::Backend): every read here is a Blokli query. Registry reads are
//! low-frequency and off any hot path, so the index would buy little, and keeping them out of the
//! `Backend` has two concrete benefits: the trait, which has three implementors, does not have to
//! change, and the reads work **without** [`connect`](crate::HoprBlockchainConnector::connect). The
//! latter is what lets a client that only wants to discover services - a GnosisVPN client looking
//! for exit nodes, say - skip building the whole channel graph first. The same implementation is
//! therefore available on [`HoprBlockchainReader`], and this one delegates to it.
//!
//! # No `StateSyncOptions::Services`
//!
//! [`subscribe_with_state_sync`](hopr_api::chain::ChainEvents::subscribe_with_state_sync) can
//! replay the current accounts and channels as events, but deliberately cannot replay the service
//! registry. This is a decision, not an oversight:
//!
//! - The snapshot streams are built from the in-process graph and the local `Backend`, never from Blokli, so a registry
//!   snapshot would require persisting entries in the `Backend` - the breaking change avoided above.
//! - Nothing routes on service data, so replaying the set as events buys nothing that a
//!   [`stream_services`](hopr_api::chain::ChainReadServiceOperations::stream_services) call does not already give, and
//!   that call works without connecting.
//!
//! Live registry changes are still broadcast as the ten `ChainEvent::Service*` variants, from the
//! two subscriptions merged by the connector's subscription task.

use blokli_client::api::{
    BlokliQueryClient,
    types::{ServiceTypeUpdate, ServiceTypeUpdateKind, ServiceUpdate, ServiceUpdateKind},
};
use futures::stream::BoxStream;
use hopr_api::{
    chain::{ServiceEntry, ServiceSelector, ServiceTypeConfig},
    types::{chain::chain_events::ChainEvent, internal::prelude::ServiceType, primitive::prelude::*},
};

use crate::{
    Backend, HoprBlockchainConnector, HoprBlockchainReader,
    errors::ConnectorError,
    utils::{model_to_service_entry, model_to_service_type, model_to_service_type_config, service_burn_to_hopr_balance},
};

#[async_trait::async_trait]
impl<B, C, P, R> hopr_api::chain::ChainReadServiceOperations for HoprBlockchainConnector<C, B, P, R>
where
    B: Backend + Send + Sync + 'static,
    C: BlokliQueryClient + Send + Sync + 'static,
    P: Send + Sync + 'static,
    R: Send + Sync,
{
    type Error = ConnectorError;

    // NOTE: these APIs can be called without calling `connect` first

    #[inline]
    fn stream_services<'a>(&'a self, selector: ServiceSelector) -> Result<BoxStream<'a, ServiceEntry>, Self::Error> {
        // The stream owns its own handle to the client, so it outlives this temporary reader.
        HoprBlockchainReader(self.client.clone()).service_entry_stream(selector)
    }

    #[inline]
    async fn count_services(&self, selector: ServiceSelector) -> Result<usize, Self::Error> {
        HoprBlockchainReader(self.client.clone()).count_services(selector).await
    }

    #[inline]
    async fn get_service_type_config(
        &self,
        service_type: ServiceType,
    ) -> Result<Option<ServiceTypeConfig>, Self::Error> {
        HoprBlockchainReader(self.client.clone())
            .get_service_type_config(service_type)
            .await
    }
}

/// Converts a change of a single registry entry into the [`ChainEvent`] it stands for.
pub(crate) fn service_update_to_event(update: ServiceUpdate) -> Result<ChainEvent, ConnectorError> {
    let ServiceUpdate {
        kind,
        service_type,
        node,
        entry,
    } = update;

    let entry = || {
        entry
            .ok_or(ConnectorError::TypeConversion("service update carries no entry".into()))
            .and_then(model_to_service_entry)
    };

    Ok(match kind {
        ServiceUpdateKind::Registered => ChainEvent::ServiceRegistered(entry()?),
        ServiceUpdateKind::Updated => ChainEvent::ServiceUpdated(entry()?),
        // The entry is gone, so the type and the node it belonged to are all that is left.
        ServiceUpdateKind::Deregistered => {
            ChainEvent::ServiceDeregistered(model_to_service_type(&service_type)?, Address::from_hex(&node)?)
        }
    })
}

/// Converts a change of service-type or registry-wide configuration into the [`ChainEvent`] it
/// stands for.
pub(crate) fn service_type_update_to_event(update: ServiceTypeUpdate) -> Result<ChainEvent, ConnectorError> {
    let ServiceTypeUpdate {
        kind,
        service_type,
        config,
        registry_config,
    } = update;

    // The five per-type kinds carry the type and its configuration after the change; the two
    // registry-wide kinds carry neither, and report the registry configuration instead.
    let service_type = || {
        service_type
            .as_deref()
            .ok_or(ConnectorError::TypeConversion(
                "service type update carries no service type".into(),
            ))
            .and_then(model_to_service_type)
    };
    let config = || {
        config
            .ok_or(ConnectorError::TypeConversion(
                "service type update carries no configuration".into(),
            ))
            .and_then(model_to_service_type_config)
    };
    let registry_config = || {
        registry_config.ok_or(ConnectorError::TypeConversion(
            "registry-wide update carries no registry configuration".into(),
        ))
    };

    Ok(match kind {
        ServiceTypeUpdateKind::Registered => ChainEvent::ServiceTypeRegistered(
            service_type()?,
            // Registration always sets an owner; abandoning is a later `OwnerChanged` to `None`.
            config()?.owner.ok_or(ConnectorError::TypeConversion(
                "service type registration carries no owner".into(),
            ))?,
        ),
        ServiceTypeUpdateKind::OwnerChanged => ChainEvent::ServiceTypeOwnerChanged(service_type()?, config()?.owner),
        ServiceTypeUpdateKind::RequirementChanged => {
            ChainEvent::ServiceTypeRequirementChanged(service_type()?, config()?.requirement)
        }
        ServiceTypeUpdateKind::RegistrationBurnChanged => {
            ChainEvent::ServiceTypeRegistrationBurnChanged(service_type()?, config()?.registration_burn)
        }
        ServiceTypeUpdateKind::UpdateBurnChanged => {
            ChainEvent::ServiceTypeUpdateBurnChanged(service_type()?, config()?.update_burn)
        }
        ServiceTypeUpdateKind::RegistrationFeeChanged => ChainEvent::ServiceTypeRegistrationFeeChanged(
            service_burn_to_hopr_balance(&registry_config()?.type_registration_fee)?,
        ),
        ServiceTypeUpdateKind::RegistryPointerChanged => {
            ChainEvent::ServiceRegistryPointerChanged(Address::from_hex(&registry_config()?.node_safe_registry)?)
        }
    })
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use blokli_client::api::types::{ServiceRegistryConfig, ServiceTypeInfo};
    use futures::StreamExt;
    use hopr_api::{
        chain::{
            ChainReadServiceOperations, ChainValues, DeployedSafe, ServiceEntry, ServiceMetadata, ServiceSelector,
            ServiceType, ServiceTypeConfig,
        },
        types::{
            chain::chain_events::ChainEvent,
            crypto::prelude::{ChainKeypair, Keypair},
            primitive::prelude::*,
        },
    };

    use super::{
        ServiceTypeUpdate, ServiceTypeUpdateKind, ServiceUpdate, ServiceUpdateKind, service_type_update_to_event,
        service_update_to_event,
    };
    use crate::{
        HoprBlockchainReader,
        connector::tests::{MODULE_ADDR, PRIVATE_KEY_1, create_connector},
        testing::{BlokliTestClient, BlokliTestState, BlokliTestStateBuilder, StaticState},
    };

    const NODE: [u8; Address::SIZE] = [0x11; Address::SIZE];
    const OTHER_NODE: [u8; Address::SIZE] = [0x22; Address::SIZE];
    const SAFE: [u8; Address::SIZE] = [0x33; Address::SIZE];
    const OWNER: [u8; Address::SIZE] = [0x44; Address::SIZE];
    const REQUIREMENT: [u8; Address::SIZE] = [0x55; Address::SIZE];

    const REGISTERED_AT: u64 = 1_700_000_000;

    fn entry(service_type: ServiceType, node: [u8; Address::SIZE]) -> anyhow::Result<ServiceEntry> {
        let registered_at = UNIX_EPOCH + Duration::from_secs(REGISTERED_AT);
        Ok(ServiceEntry::new(
            service_type,
            node.into(),
            SAFE.into(),
            ServiceMetadata::try_from(b"exit-node".to_vec())?,
            registered_at,
            registered_at + Duration::from_secs(60),
        )?)
    }

    fn config() -> ServiceTypeConfig {
        ServiceTypeConfig {
            owner: Some(OWNER.into()),
            requirement: Some(REQUIREMENT.into()),
            registration_burn: HoprBalance::new_base(1),
            update_burn: HoprBalance::from(500_u32),
        }
    }

    /// Binds a Safe to the given nodes, which is what makes their entries live.
    fn safe_with_nodes(nodes: &[[u8; Address::SIZE]]) -> DeployedSafe {
        DeployedSafe {
            address: SAFE.into(),
            owners: vec![OWNER.into()],
            module: [0x66; Address::SIZE].into(),
            registered_nodes: nodes.iter().map(|node| Address::from(*node)).collect(),
            deployer: OWNER.into(),
        }
    }

    /// `ChainReadServiceOperations` is a supertrait of `HoprChainApi`, so without this impl the
    /// connector silently stops being a chain API and everything downstream of it fails to
    /// compile. The assertion keeps that failure here, where it is readable.
    #[test]
    fn connector_should_satisfy_the_whole_chain_api() {
        fn assert_chain_api<T: hopr_api::chain::HoprChainApi>() {}

        assert_chain_api::<crate::connector::tests::TestConnector<BlokliTestClient<StaticState>>>();
    }

    #[tokio::test]
    async fn connector_should_stream_services_of_a_service_type() -> anyhow::Result<()> {
        let other_type: ServiceType = "gvpn:entry".parse()?;
        let blokli_client = BlokliTestStateBuilder::default()
            .with_services([
                entry(ServiceType::GVPN_EXIT, NODE)?,
                entry(ServiceType::GVPN_EXIT, OTHER_NODE)?,
                entry(other_type, NODE)?,
            ])
            .build_static_client();

        let connector = create_connector(blokli_client)?;

        // Service reads deliberately work without a prior `connect`, so that a client that only
        // wants to discover services does not have to sync the whole channel graph first.
        assert!(!connector.is_connected());

        let entries = connector
            .stream_services(ServiceSelector::default().with_service_type(ServiceType::GVPN_EXIT))?
            .collect::<Vec<_>>()
            .await;

        assert_eq!(
            vec![
                entry(ServiceType::GVPN_EXIT, NODE)?,
                entry(ServiceType::GVPN_EXIT, OTHER_NODE)?
            ],
            entries
        );

        Ok(())
    }

    #[tokio::test]
    async fn connector_should_stream_services_of_a_node() -> anyhow::Result<()> {
        let other_type: ServiceType = "gvpn:entry".parse()?;
        let blokli_client = BlokliTestStateBuilder::default()
            .with_services([
                entry(ServiceType::GVPN_EXIT, NODE)?,
                entry(other_type, NODE)?,
                entry(ServiceType::GVPN_EXIT, OTHER_NODE)?,
            ])
            .build_static_client();

        let connector = create_connector(blokli_client)?;

        let entries = connector
            .stream_services(ServiceSelector::default().with_node(NODE.into()))?
            .collect::<Vec<_>>()
            .await;

        assert_eq!(
            vec![entry(ServiceType::GVPN_EXIT, NODE)?, entry(other_type, NODE)?],
            entries
        );

        Ok(())
    }

    #[tokio::test]
    async fn connector_should_stream_the_single_service_of_a_type_and_node() -> anyhow::Result<()> {
        let blokli_client = BlokliTestStateBuilder::default()
            .with_services([
                entry(ServiceType::GVPN_EXIT, NODE)?,
                entry(ServiceType::GVPN_EXIT, OTHER_NODE)?,
            ])
            .build_static_client();

        let connector = create_connector(blokli_client)?;

        let entries = connector
            .stream_services(
                ServiceSelector::default()
                    .with_service_type(ServiceType::GVPN_EXIT)
                    .with_node(OTHER_NODE.into()),
            )?
            .collect::<Vec<_>>()
            .await;

        assert_eq!(vec![entry(ServiceType::GVPN_EXIT, OTHER_NODE)?], entries);

        Ok(())
    }

    #[tokio::test]
    async fn connector_should_reject_an_unfiltered_service_stream() -> anyhow::Result<()> {
        let blokli_client = BlokliTestStateBuilder::default()
            .with_services([entry(ServiceType::GVPN_EXIT, NODE)?])
            .build_static_client();

        let connector = create_connector(blokli_client)?;

        let error = connector
            .stream_services(ServiceSelector::default())
            .err()
            .expect("an unfiltered selector must be rejected");

        // The error must name the filters that are missing, because the server-side rejection does
        // not, and the caller cannot otherwise tell what to add.
        let message = error.to_string();
        assert!(message.contains("service type"), "{message}");
        assert!(message.contains("node"), "{message}");

        Ok(())
    }

    #[tokio::test]
    async fn connector_should_drop_services_of_nodes_without_a_safe_binding() -> anyhow::Result<()> {
        let blokli_client = BlokliTestStateBuilder::default()
            .with_services([
                entry(ServiceType::GVPN_EXIT, NODE)?,
                entry(ServiceType::GVPN_EXIT, OTHER_NODE)?,
            ])
            .with_deployed_safes([safe_with_nodes(&[NODE])])
            .build_static_client();

        let connector = create_connector(blokli_client)?;

        let live = connector
            .stream_services(
                ServiceSelector::default()
                    .with_service_type(ServiceType::GVPN_EXIT)
                    .with_live_only(true),
            )?
            .collect::<Vec<_>>()
            .await;
        assert_eq!(vec![entry(ServiceType::GVPN_EXIT, NODE)?], live);

        // The orphaned entry is still in the registry, it is only dead.
        let all = connector
            .stream_services(ServiceSelector::default().with_service_type(ServiceType::GVPN_EXIT))?
            .collect::<Vec<_>>()
            .await;
        assert_eq!(2, all.len());

        Ok(())
    }

    #[tokio::test]
    async fn connector_should_count_services() -> anyhow::Result<()> {
        let other_type: ServiceType = "gvpn:entry".parse()?;
        let blokli_client = BlokliTestStateBuilder::default()
            .with_services([
                entry(ServiceType::GVPN_EXIT, NODE)?,
                entry(ServiceType::GVPN_EXIT, OTHER_NODE)?,
                entry(other_type, NODE)?,
            ])
            .with_deployed_safes([safe_with_nodes(&[NODE])])
            .build_static_client();

        let connector = create_connector(blokli_client)?;

        // Counting is the one read that an unfiltered selector is allowed to do.
        assert_eq!(3, connector.count_services(ServiceSelector::default()).await?);
        assert_eq!(
            2,
            connector
                .count_services(ServiceSelector::default().with_service_type(ServiceType::GVPN_EXIT))
                .await?
        );
        assert_eq!(
            1,
            connector
                .count_services(
                    ServiceSelector::default()
                        .with_service_type(ServiceType::GVPN_EXIT)
                        .with_live_only(true)
                )
                .await?
        );

        Ok(())
    }

    #[tokio::test]
    async fn connector_should_reject_an_unfiltered_live_only_count() -> anyhow::Result<()> {
        let blokli_client = BlokliTestStateBuilder::default()
            .with_services([entry(ServiceType::GVPN_EXIT, NODE)?])
            .build_static_client();

        let connector = create_connector(blokli_client)?;

        // Liveness cannot be counted server-side, so a live-only count needs the entries, and
        // fetching those needs a filter.
        assert!(
            connector
                .count_services(ServiceSelector::default().with_live_only(true))
                .await
                .is_err()
        );

        Ok(())
    }

    #[tokio::test]
    async fn connector_should_read_service_type_configuration() -> anyhow::Result<()> {
        let blokli_client = BlokliTestStateBuilder::default()
            .with_service_types([(ServiceType::GVPN_EXIT, config())])
            .build_static_client();

        let connector = create_connector(blokli_client)?;

        assert_eq!(
            Some(config()),
            connector.get_service_type_config(ServiceType::GVPN_EXIT).await?
        );
        assert_eq!(None, connector.get_service_type_config("gvpn:entry".parse()?).await?);

        Ok(())
    }

    #[tokio::test]
    async fn connector_should_read_an_abandoned_and_open_service_type() -> anyhow::Result<()> {
        // Abandoning clears the owner and is one-way; an open type has no requirement contract.
        let abandoned = ServiceTypeConfig {
            owner: None,
            requirement: None,
            ..config()
        };

        let blokli_client = BlokliTestStateBuilder::default()
            .with_service_types([(ServiceType::GVPN_EXIT, abandoned)])
            .build_static_client();

        let connector = create_connector(blokli_client)?;

        assert_eq!(
            Some(abandoned),
            connector.get_service_type_config(ServiceType::GVPN_EXIT).await?
        );

        Ok(())
    }

    #[tokio::test]
    async fn connector_should_stream_services_of_a_type_rendered_as_hex() -> anyhow::Result<()> {
        // The registry does not enforce the printable-ASCII convention on type ids, and Blokli
        // renders an id that does not follow it as hexadecimal instead of as a name.
        let raw_type = ServiceType::try_from([0xffu8; ServiceType::SIZE].as_ref())?;
        assert_eq!(None, raw_type.as_ascii());

        let blokli_client = BlokliTestStateBuilder::default()
            .with_services([entry(raw_type, NODE)?])
            .build_static_client();

        let connector = create_connector(blokli_client)?;

        let entries = connector
            .stream_services(ServiceSelector::default().with_service_type(raw_type))?
            .collect::<Vec<_>>()
            .await;

        assert_eq!(vec![entry(raw_type, NODE)?], entries);

        Ok(())
    }

    /// The two registry-wide kinds cannot be produced by the test harness, which models per-type
    /// configuration only, so their mapping is pinned on the conversion itself.
    #[test]
    fn registry_wide_updates_convert_into_the_registry_events() -> anyhow::Result<()> {
        let registry_config = ServiceRegistryConfig {
            type_registration_fee: "5 wxHOPR".into(),
            node_safe_registry: const_hex::encode(REQUIREMENT),
        };

        let fee_changed = service_type_update_to_event(ServiceTypeUpdate {
            kind: ServiceTypeUpdateKind::RegistrationFeeChanged,
            service_type: None,
            config: None,
            registry_config: Some(registry_config.clone()),
        })?;
        assert!(
            matches!(fee_changed, ChainEvent::ServiceTypeRegistrationFeeChanged(fee) if fee == HoprBalance::new_base(5))
        );

        let pointer_changed = service_type_update_to_event(ServiceTypeUpdate {
            kind: ServiceTypeUpdateKind::RegistryPointerChanged,
            service_type: None,
            config: None,
            registry_config: Some(registry_config),
        })?;
        assert!(
            matches!(pointer_changed, ChainEvent::ServiceRegistryPointerChanged(registry) if registry == Address::from(REQUIREMENT))
        );

        Ok(())
    }

    #[test]
    fn incomplete_registry_updates_are_rejected() {
        // Only a deregistration is allowed to carry no entry.
        for kind in [ServiceUpdateKind::Registered, ServiceUpdateKind::Updated] {
            assert!(
                service_update_to_event(ServiceUpdate {
                    kind,
                    service_type: "gvpn:exit".into(),
                    node: const_hex::encode(NODE),
                    entry: None,
                })
                .is_err()
            );
        }

        // Registration always sets an owner, so a registration without one is malformed.
        assert!(
            service_type_update_to_event(ServiceTypeUpdate {
                kind: ServiceTypeUpdateKind::Registered,
                service_type: Some("gvpn:exit".into()),
                config: Some(ServiceTypeInfo {
                    service_type: "gvpn:exit".into(),
                    owner: None,
                    requirement: None,
                    registration_burn: "0 wxHOPR".into(),
                    update_burn: "0 wxHOPR".into(),
                }),
                registry_config: None,
            })
            .is_err()
        );

        // A per-type kind without its configuration is malformed too.
        assert!(
            service_type_update_to_event(ServiceTypeUpdate {
                kind: ServiceTypeUpdateKind::OwnerChanged,
                service_type: Some("gvpn:exit".into()),
                config: None,
                registry_config: None,
            })
            .is_err()
        );
    }

    /// Pins the coupling between the connector and the `chainInfo` payload of Blokli.
    ///
    /// `ContractAddresses` puts `#[serde(default)]` on none of its fields, so a Blokli that does
    /// not report the service registry address makes the connector unusable rather than merely
    /// serviceless. The failure must therefore name the missing field.
    #[tokio::test]
    async fn chain_info_without_the_service_registry_address_fails_naming_the_field() -> anyhow::Result<()> {
        let mut state = BlokliTestState::default();
        let mut addresses: serde_json::Value = serde_json::from_str(&state.chain_info.contract_addresses.0)?;
        assert!(addresses["service_registry"].is_string());
        addresses
            .as_object_mut()
            .expect("contract addresses are a JSON object")
            .remove("service_registry");
        state.chain_info.contract_addresses =
            blokli_client::api::types::ContractAddressMap(serde_json::to_string(&addresses)?);

        let blokli_client = BlokliTestStateBuilder::from(state).build_static_client();

        let error = HoprBlockchainReader::new(blokli_client.clone())
            .chain_info()
            .await
            .expect_err("chain info without the service registry address must fail");
        assert!(error.to_string().contains("service_registry"), "{error}");

        // The same payload is parsed a second time when the connector takes its contract addresses
        // from Blokli instead of from the caller.
        let error = crate::create_trustful_hopr_blokli_connector(
            &ChainKeypair::from_secret(&PRIVATE_KEY_1)?,
            Default::default(),
            blokli_client,
            MODULE_ADDR.into(),
        )
        .await
        .err()
        .expect("connector construction without the service registry address must fail");
        assert!(error.to_string().contains("service_registry"), "{error}");

        Ok(())
    }
}
