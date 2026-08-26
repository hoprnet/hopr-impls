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
//! # State synchronization
//!
//! Blokli's service-entry and service-type subscriptions are snapshot-first: they register their
//! live receivers at an indexer watermark, replay the complete matching state at that watermark as
//! registrations, and then continue with later changes. Both phases carry the same
//! [`ChainEvent`] variants, so nothing distinguishes a replayed registration from a new one.
//!
//! The connector suppresses the replay. It reads the registry before subscribing and drops each
//! replayed registration once, so a [`ChainEvent::ServiceRegistered`] or
//! [`ChainEvent::ServiceTypeRegistered`] delivered to a consumer always means what it says: this
//! happened after you connected. A consumer that wants the state that already exists queries it,
//! which needs no [`connect`](crate::HoprBlockchainConnector::connect). Suppression is keyed on
//! identity and applied once, so a node that deregisters and registers again is reported both
//! times.
//!
//! Registry-wide configuration uses the same state-first contract, and its first value is dropped
//! the same way. It is the one part of the registry that
//! [`StateSyncOptions::ServiceRegistryConfig`](hopr_api::chain::StateSyncOptions) will replay on
//! request, because the two values have no other way to reach a consumer that arrives late.

use blokli_client::api::{
    BlokliQueryClient, BlokliTransactionClient,
    types::{ServiceTypeUpdate, ServiceTypeUpdateKind, ServiceUpdate, ServiceUpdateKind},
};
use futures::{FutureExt, future::BoxFuture, stream::BoxStream};
use hopr_api::{
    chain::{
        ChainReadServiceOperations, ServiceEntry, ServiceMetadata, ServiceRegistryConfig, ServiceSelector,
        ServiceTypeConfig,
    },
    types::{chain::chain_events::ChainEvent, internal::prelude::ServiceType, primitive::prelude::*},
};

use crate::{
    Backend, HoprBlockchainConnector, HoprBlockchainReader,
    errors::ConnectorError,
    utils::{
        model_to_registry_address, model_to_service_entry, model_to_service_type, model_to_service_type_config,
        service_burn_to_hopr_balance,
    },
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

    #[inline]
    async fn get_service_registry_config(&self) -> Result<ServiceRegistryConfig, Self::Error> {
        HoprBlockchainReader(self.client.clone())
            .get_service_registry_config()
            .await
    }
}

#[async_trait::async_trait]
impl<B, C, P> hopr_api::chain::ChainWriteServiceOperations for HoprBlockchainConnector<C, B, P, P::TxRequest>
where
    B: Send + Sync + 'static,
    C: BlokliQueryClient + BlokliTransactionClient + Send + Sync + 'static,
    P: hopr_api::types::chain::payload::PayloadGenerator + Send + Sync + 'static,
    P::TxRequest: Send + Sync + 'static,
{
    type Error = ConnectorError;

    async fn register_service<'a>(
        &'a self,
        service_type: ServiceType,
        metadata: ServiceMetadata,
    ) -> Result<BoxFuture<'a, Result<hopr_api::chain::ChainReceipt, Self::Error>>, Self::Error> {
        self.check_connection_state()?;
        let config = HoprBlockchainReader(self.client.clone())
            .get_service_type_config(service_type)
            .await?
            .ok_or(ConnectorError::InvalidState("service type is not registered"))?;
        let tx_req = self
            .payload_generator
            .register_service(service_type, metadata, config.registration_burn)?;
        Ok(self.send_tx(tx_req, None, None).await?.boxed())
    }

    async fn update_service<'a>(
        &'a self,
        service_type: ServiceType,
        metadata: ServiceMetadata,
    ) -> Result<BoxFuture<'a, Result<hopr_api::chain::ChainReceipt, Self::Error>>, Self::Error> {
        self.check_connection_state()?;
        let config = HoprBlockchainReader(self.client.clone())
            .get_service_type_config(service_type)
            .await?
            .ok_or(ConnectorError::InvalidState("service type is not registered"))?;
        let tx_req = self
            .payload_generator
            .update_service(service_type, metadata, config.update_burn)?;
        Ok(self.send_tx(tx_req, None, None).await?.boxed())
    }

    async fn deregister_service<'a>(
        &'a self,
        service_type: ServiceType,
    ) -> Result<BoxFuture<'a, Result<hopr_api::chain::ChainReceipt, Self::Error>>, Self::Error> {
        self.check_connection_state()?;
        let tx_req = self.payload_generator.deregister_service(service_type)?;
        Ok(self.send_tx(tx_req, None, None).await?.boxed())
    }
}

/// A change of the on-chain service registry.
///
/// This is the ten registry variants of [`ChainEvent`] and nothing else. The connector's
/// subscription handler carries this rather than the whole `ChainEvent`, so a registry stream
/// cannot produce an account or channel event, and the compiler checks that every registry kind is
/// mapped. Broadcasting converts it back with [`From`].
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum ServiceEvent {
    /// A node registered under a service type.
    Registered(ServiceEntry),
    /// A node replaced the metadata of one of its entries.
    Updated(ServiceEntry),
    /// A node's entry under a service type was removed.
    Deregistered(ServiceType, Address),
    /// A service type was registered by its first owner.
    TypeRegistered(ServiceType, Address),
    /// A service type changed owner, or was abandoned when the owner is `None`.
    TypeOwnerChanged(ServiceType, Option<Address>),
    /// A service type gained, changed, or (when `None`) dropped its requirement contract.
    TypeRequirementChanged(ServiceType, Option<Address>),
    /// The amount burned when registering an entry under a service type changed.
    TypeRegistrationBurnChanged(ServiceType, HoprBalance),
    /// The amount burned when updating an entry under a service type changed.
    TypeUpdateBurnChanged(ServiceType, HoprBalance),
    /// The registry-wide amount burned when registering a new service type changed.
    TypeRegistrationFeeChanged(HoprBalance),
    /// The registry-wide node-Safe registry pointer changed.
    RegistryPointerChanged(Address),
}

impl From<ServiceEvent> for ChainEvent {
    fn from(event: ServiceEvent) -> Self {
        match event {
            ServiceEvent::Registered(entry) => ChainEvent::ServiceRegistered(entry),
            ServiceEvent::Updated(entry) => ChainEvent::ServiceUpdated(entry),
            ServiceEvent::Deregistered(service_type, node) => ChainEvent::ServiceDeregistered(service_type, node),
            ServiceEvent::TypeRegistered(service_type, owner) => ChainEvent::ServiceTypeRegistered(service_type, owner),
            ServiceEvent::TypeOwnerChanged(service_type, owner) => {
                ChainEvent::ServiceTypeOwnerChanged(service_type, owner)
            }
            ServiceEvent::TypeRequirementChanged(service_type, requirement) => {
                ChainEvent::ServiceTypeRequirementChanged(service_type, requirement)
            }
            ServiceEvent::TypeRegistrationBurnChanged(service_type, burn) => {
                ChainEvent::ServiceTypeRegistrationBurnChanged(service_type, burn)
            }
            ServiceEvent::TypeUpdateBurnChanged(service_type, burn) => {
                ChainEvent::ServiceTypeUpdateBurnChanged(service_type, burn)
            }
            ServiceEvent::TypeRegistrationFeeChanged(fee) => ChainEvent::ServiceTypeRegistrationFeeChanged(fee),
            ServiceEvent::RegistryPointerChanged(pointer) => ChainEvent::ServiceRegistryPointerChanged(pointer),
        }
    }
}

/// Converts a change of a single registry entry into the [`ServiceEvent`] it stands for.
pub(crate) fn service_update_to_event(update: ServiceUpdate) -> Result<ServiceEvent, ConnectorError> {
    let ServiceUpdate {
        kind,
        service_type,
        node,
        entry,
    } = update;

    let entry = || {
        entry
            .as_ref()
            .ok_or(ConnectorError::TypeConversion("service update carries no entry".into()))
            .and_then(model_to_service_entry)
    };

    Ok(match kind {
        ServiceUpdateKind::Registered => ServiceEvent::Registered(entry()?),
        ServiceUpdateKind::Updated => ServiceEvent::Updated(entry()?),
        // The entry is gone, so the type and the node it belonged to are all that is left.
        ServiceUpdateKind::Deregistered => ServiceEvent::Deregistered(
            model_to_service_type(&service_type)?,
            model_to_registry_address("node", &node)?,
        ),
    })
}

/// Converts a change of service-type or registry-wide configuration into the [`ServiceEvent`] it
/// stands for.
pub(crate) fn service_type_update_to_event(update: ServiceTypeUpdate) -> Result<ServiceEvent, ConnectorError> {
    let ServiceTypeUpdate {
        kind,
        service_type,
        config,
        registry_config,
    } = update;

    // A registry-wide kind keys nothing by service type. Carrying per-type data anyway means the
    // producer and this consumer disagree about the payload shape, which is worth saying out loud
    // even though the event itself is still well defined.
    if matches!(
        kind,
        ServiceTypeUpdateKind::RegistrationFeeChanged | ServiceTypeUpdateKind::RegistryPointerChanged
    ) && (service_type.is_some() || config.is_some())
    {
        tracing::warn!(
            ?kind,
            ?service_type,
            "a registry-wide service update carries per-type data"
        );
    }

    // The five per-type kinds carry the type and its configuration after the change; the two
    // registry-wide kinds carry neither, and report the registry configuration instead. Each
    // accessor borrows, so an arm may consult more than one field, and more than once.
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
            .as_ref()
            .ok_or(ConnectorError::TypeConversion(
                "service type update carries no configuration".into(),
            ))
            .and_then(model_to_service_type_config)
    };
    let registry_config = || {
        registry_config.as_ref().ok_or(ConnectorError::TypeConversion(
            "registry-wide update carries no registry configuration".into(),
        ))
    };

    Ok(match kind {
        ServiceTypeUpdateKind::Registered => ServiceEvent::TypeRegistered(
            service_type()?,
            // Registration always sets an owner; abandoning is a later `OwnerChanged` to `None`.
            config()?.owner.ok_or(ConnectorError::TypeConversion(
                "service type registration carries no owner".into(),
            ))?,
        ),
        ServiceTypeUpdateKind::OwnerChanged => ServiceEvent::TypeOwnerChanged(service_type()?, config()?.owner),
        ServiceTypeUpdateKind::RequirementChanged => {
            ServiceEvent::TypeRequirementChanged(service_type()?, config()?.requirement)
        }
        ServiceTypeUpdateKind::RegistrationBurnChanged => {
            ServiceEvent::TypeRegistrationBurnChanged(service_type()?, config()?.registration_burn)
        }
        ServiceTypeUpdateKind::UpdateBurnChanged => {
            ServiceEvent::TypeUpdateBurnChanged(service_type()?, config()?.update_burn)
        }
        ServiceTypeUpdateKind::RegistrationFeeChanged => ServiceEvent::TypeRegistrationFeeChanged(
            service_burn_to_hopr_balance(&registry_config()?.type_registration_fee)?,
        ),
        ServiceTypeUpdateKind::RegistryPointerChanged => ServiceEvent::RegistryPointerChanged(
            model_to_registry_address("node-Safe registry", &registry_config()?.node_safe_registry)?,
        ),
    })
}

/// Converts a complete registry configuration into the events required to initialize or update
/// consumers. The first value emits both fields; later values emit only fields that changed.
pub(crate) fn service_registry_config_to_events(
    current: ServiceRegistryConfig,
    previous: Option<&ServiceRegistryConfig>,
) -> Vec<ServiceEvent> {
    let mut events = Vec::with_capacity(2);
    if previous.is_none_or(|old| old.type_registration_fee != current.type_registration_fee) {
        events.push(ServiceEvent::TypeRegistrationFeeChanged(current.type_registration_fee));
    }
    if previous.is_none_or(|old| old.node_safe_registry != current.node_safe_registry) {
        events.push(ServiceEvent::RegistryPointerChanged(current.node_safe_registry));
    }
    events
}

#[cfg(test)]
mod tests {
    use blokli_client::api::{
        BlokliQueryClient,
        types::{ServiceRegistryConfig as BlokliServiceRegistryConfig, ServiceTypeInfo},
    };
    use futures::StreamExt;
    use hopr_api::{
        chain::{
            ChainReadServiceOperations, ChainValues, ServiceRegistryConfig, ServiceSelector, ServiceType,
            ServiceTypeConfig,
        },
        types::{
            crypto::prelude::{ChainKeypair, Keypair},
            primitive::prelude::*,
        },
    };

    use super::{
        ServiceEvent, ServiceTypeUpdate, ServiceTypeUpdateKind, ServiceUpdate, ServiceUpdateKind,
        service_registry_config_to_events, service_type_update_to_event, service_update_to_event,
    };
    use crate::{
        HoprBlockchainReader,
        connector::{
            service_fixtures::{
                FailingServiceQueries, METADATA, NODE, OTHER_NODE, REGISTRY_POINTER, SERVICE_TYPE, UPDATED_AT,
                empty_registry, entry, entry_model, registry_config, safe_with_nodes, state_with_registry_config,
                type_config as config,
            },
            tests::{MODULE_ADDR, PRIVATE_KEY_1, create_connector},
        },
        testing::{BlokliTestClient, BlokliTestState, BlokliTestStateBuilder, StaticState},
    };

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

    /// Blokli rejects a bare enumeration of the permissionless registry, so an unfiltered read is
    /// answered per service type. Two types with an entry each pin that the fan-out covers every
    /// type rather than issuing the `Any` query the server would refuse.
    #[tokio::test]
    async fn connector_should_enumerate_an_unfiltered_service_stream() -> anyhow::Result<()> {
        let other_type: ServiceType = "gvpn:entry".parse()?;
        let blokli_client = BlokliTestStateBuilder::default()
            .with_service_types([(other_type, config())])
            .with_services([entry(ServiceType::GVPN_EXIT, NODE)?, entry(other_type, OTHER_NODE)?])
            .build_static_client();

        let connector = create_connector(blokli_client)?;

        let entries = connector
            .stream_services(ServiceSelector::default())?
            .collect::<Vec<_>>()
            .await;
        assert_eq!(
            vec![entry(ServiceType::GVPN_EXIT, NODE)?, entry(other_type, OTHER_NODE)?],
            entries
        );

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
            .with_service_types([(other_type, config())])
            .with_services([
                entry(ServiceType::GVPN_EXIT, NODE)?,
                entry(ServiceType::GVPN_EXIT, OTHER_NODE)?,
                entry(other_type, NODE)?,
            ])
            .with_deployed_safes([safe_with_nodes(&[NODE])])
            .build_static_client();

        let connector = create_connector(blokli_client)?;

        // An unfiltered count is the one registry read Blokli answers directly, without the
        // per-type fan-out that `stream_services` needs.
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
    async fn connector_should_count_unfiltered_live_services() -> anyhow::Result<()> {
        let blokli_client = BlokliTestStateBuilder::default()
            .with_services([entry(ServiceType::GVPN_EXIT, NODE)?])
            .build_static_client();

        let connector = create_connector(blokli_client)?;

        assert_eq!(
            0,
            connector
                .count_services(ServiceSelector::default().with_live_only(true))
                .await?
        );

        Ok(())
    }

    #[tokio::test]
    async fn connector_should_read_service_type_configuration() -> anyhow::Result<()> {
        // The default fixture state pre-registers the type with a configuration of its own, which
        // this test replaces rather than adds to.
        let blokli_client = empty_registry()
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

        let blokli_client = empty_registry()
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
    async fn connector_should_read_registry_wide_configuration() -> anyhow::Result<()> {
        let connector =
            create_connector(BlokliTestStateBuilder::from(state_with_registry_config()).build_static_client())?;

        assert_eq!(registry_config(), connector.get_service_registry_config().await?);

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
        let registry_config = BlokliServiceRegistryConfig {
            type_registration_fee: "5 wxHOPR".into(),
            node_safe_registry: const_hex::encode(REGISTRY_POINTER),
        };

        let fee_changed = service_type_update_to_event(ServiceTypeUpdate {
            kind: ServiceTypeUpdateKind::RegistrationFeeChanged,
            service_type: None,
            config: None,
            registry_config: Some(registry_config.clone()),
        })?;
        assert_eq!(
            ServiceEvent::TypeRegistrationFeeChanged(HoprBalance::new_base(5)),
            fee_changed
        );

        let pointer_changed = service_type_update_to_event(ServiceTypeUpdate {
            kind: ServiceTypeUpdateKind::RegistryPointerChanged,
            service_type: None,
            config: None,
            registry_config: Some(registry_config),
        })?;
        assert_eq!(
            ServiceEvent::RegistryPointerChanged(Address::from(REGISTRY_POINTER)),
            pointer_changed
        );

        Ok(())
    }

    #[test]
    fn registry_config_snapshot_initializes_both_fields_then_emits_only_changes() {
        let initial = ServiceRegistryConfig {
            type_registration_fee: HoprBalance::new_base(5),
            node_safe_registry: REGISTRY_POINTER.into(),
        };
        let initial_events = service_registry_config_to_events(initial, None);
        assert_eq!(
            vec![
                ServiceEvent::TypeRegistrationFeeChanged(HoprBalance::new_base(5)),
                ServiceEvent::RegistryPointerChanged(REGISTRY_POINTER.into()),
            ],
            initial_events
        );

        let updated = ServiceRegistryConfig {
            type_registration_fee: HoprBalance::new_base(7),
            ..initial
        };
        let update_events = service_registry_config_to_events(updated, Some(&initial));
        assert_eq!(
            vec![ServiceEvent::TypeRegistrationFeeChanged(HoprBalance::new_base(7))],
            update_events
        );
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

    /// A failed registry query and an empty registry are different answers, and `count_services`
    /// is the read that can tell them apart, so it must not report `Ok(0)` for a failed query.
    #[tokio::test]
    async fn counting_services_surfaces_a_failed_query_instead_of_reporting_an_empty_registry() -> anyhow::Result<()> {
        let reader = HoprBlockchainReader::new(FailingServiceQueries(
            BlokliTestStateBuilder::default()
                .with_services([entry(ServiceType::GVPN_EXIT, NODE)?])
                .with_deployed_safes([safe_with_nodes(&[NODE])])
                .build_static_client(),
        ));

        // Both counts route through a different query, and both have an entry to report.
        assert!(reader.count_services(ServiceSelector::default()).await.is_err());
        assert!(
            reader
                .count_services(ServiceSelector::default().with_live_only(true))
                .await
                .is_err()
        );

        Ok(())
    }

    /// One malformed record must not hide the rest of the registry, and the log must name the
    /// field so that a missing service can be attributed.
    #[tokio::test]
    async fn a_malformed_entry_is_skipped_and_its_offending_field_is_named() -> anyhow::Result<()> {
        let malformed = blokli_client::api::types::ServiceEntry {
            node: "not-an-address".into(),
            ..entry_model(METADATA, UPDATED_AT)
        };

        // The entries are seeded as models rather than through `with_services`, which only accepts
        // a well-formed `ServiceEntry`.
        let mut state = BlokliTestState::default();
        state.services.insert(
            BlokliTestState::service_entry_key(SERVICE_TYPE, &NODE),
            entry_model(METADATA, UPDATED_AT),
        );
        state.services.insert(
            BlokliTestState::service_entry_key(SERVICE_TYPE, &OTHER_NODE),
            malformed.clone(),
        );

        let blokli_client = BlokliTestStateBuilder::from(state).build_static_client();
        // Blokli returns both, so the entry below is dropped by the conversion and not by the query.
        assert_eq!(
            2,
            blokli_client
                .query_services(blokli_client::api::ServiceSelector::ServiceType(
                    ServiceType::GVPN_EXIT.as_encoded()
                ))
                .await?
                .len()
        );

        let connector = create_connector(blokli_client)?;

        let entries = connector
            .stream_services(ServiceSelector::default().with_service_type(ServiceType::GVPN_EXIT))?
            .collect::<Vec<_>>()
            .await;
        assert_eq!(vec![entry(ServiceType::GVPN_EXIT, NODE)?], entries);

        // The conversion itself is what carries the attribution into that log.
        let error = crate::utils::model_to_service_entry(&malformed)
            .expect_err("an entry with an unparseable node must not convert");
        assert!(error.to_string().contains("node"), "{error}");

        Ok(())
    }

    /// A registry timestamp is a `Uint64`, so it can name an instant no `SystemTime` can hold.
    /// `SystemTime + Duration` panics on overflow, which would let malformed Blokli data terminate
    /// the process instead of failing the conversion.
    #[test]
    fn an_out_of_range_timestamp_fails_the_conversion_instead_of_panicking() {
        // Both fields carry the boundary value, so the failure cannot come from `ServiceEntry`
        // rejecting an update that precedes its registration.
        let model = blokli_client::api::types::ServiceEntry {
            registered_at: blokli_client::api::types::Uint64(u64::MAX.to_string()),
            updated_at: blokli_client::api::types::Uint64(u64::MAX.to_string()),
            ..entry_model(METADATA, UPDATED_AT)
        };

        let error = crate::utils::model_to_service_entry(&model)
            .expect_err("a timestamp beyond the platform's SystemTime range must not convert");
        assert!(error.to_string().contains("out of range"), "{error}");
    }
}
