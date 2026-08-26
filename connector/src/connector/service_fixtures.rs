//! Service registry fixtures shared by the registry test modules.
//!
//! Every byte pattern below has exactly one role, so an assertion moved between test modules keeps
//! its meaning.

use std::time::{Duration, UNIX_EPOCH};

use blokli_client::{
    api::{
        AccountSelector, BlokliQueryClient, ChainAddress, ChannelSelector, ModulePredictionInput,
        RedeemedStatsSelector, SafeSelector, ServiceSelector as BlokliServiceSelector, ServiceTypeId, TxId, types,
    },
    errors::{BlokliClientError, ErrorKind},
};
use hopr_api::{
    chain::{DeployedSafe, ServiceEntry, ServiceMetadata, ServiceRegistryConfig, ServiceType, ServiceTypeConfig},
    types::primitive::prelude::*,
};

use crate::testing::{BlokliTestState, BlokliTestStateBuilder};

/// The service type of every fixture, rendered the way Blokli renders it.
pub const SERVICE_TYPE: &str = "gvpn:exit";

/// Node offering the fixture service.
pub const NODE: [u8; Address::SIZE] = [0x11; Address::SIZE];
/// A second node, for the cases where a selector has to tell two entries apart.
pub const OTHER_NODE: [u8; Address::SIZE] = [0x22; Address::SIZE];
/// Safe that both fixture nodes are bound to.
pub const SAFE: [u8; Address::SIZE] = [0x33; Address::SIZE];
/// Module of [`SAFE`].
pub const SAFE_MODULE: [u8; Address::SIZE] = [0x44; Address::SIZE];
/// Owner of the fixture service type.
pub const OWNER: [u8; Address::SIZE] = [0x55; Address::SIZE];
/// Owner the fixture service type is transferred to.
pub const NEW_OWNER: [u8; Address::SIZE] = [0x66; Address::SIZE];
/// Requirement contract of the fixture service type.
pub const REQUIREMENT: [u8; Address::SIZE] = [0x77; Address::SIZE];
/// Node-Safe registry that the fixture registry-wide configuration points at.
pub const REGISTRY_POINTER: [u8; Address::SIZE] = [0x88; Address::SIZE];

/// Registration timestamp of every fixture entry, in Unix seconds.
pub const REGISTERED_AT: u64 = 1_700_000_000;
/// Timestamp of the single update a fixture entry has seen.
pub const UPDATED_AT: u64 = REGISTERED_AT + 60;

/// Metadata a fixture entry is registered with.
pub const METADATA: &[u8] = b"exit-node";
/// Metadata a fixture entry carries after its update.
pub const UPDATED_METADATA: &[u8] = b"exit-node-v2";

/// A state builder whose service registry is empty.
///
/// [`BlokliTestStateBuilder::default`] pre-registers [`SERVICE_TYPE`], which a test that registers
/// that type itself, or that pins one exact configuration for it, must not inherit.
pub fn empty_registry() -> BlokliTestStateBuilder {
    BlokliTestStateBuilder::from(BlokliTestState::default())
}

/// The registry entry of `node` under `service_type`, registered with [`METADATA`] at
/// [`REGISTERED_AT`] and updated once at [`UPDATED_AT`].
pub fn entry(service_type: ServiceType, node: [u8; Address::SIZE]) -> anyhow::Result<ServiceEntry> {
    entry_with(service_type, node, METADATA, UPDATED_AT)
}

/// The registry entry of `node` under `service_type` with an explicit `metadata` and `updated_at`.
///
/// An entry that was never updated has `updated_at` equal to [`REGISTERED_AT`].
pub fn entry_with(
    service_type: ServiceType,
    node: [u8; Address::SIZE],
    metadata: &[u8],
    updated_at: u64,
) -> anyhow::Result<ServiceEntry> {
    Ok(ServiceEntry::new(
        service_type,
        node.into(),
        SAFE.into(),
        ServiceMetadata::try_from(metadata.to_vec())?,
        UNIX_EPOCH + Duration::from_secs(REGISTERED_AT),
        UNIX_EPOCH + Duration::from_secs(updated_at),
    )?)
}

/// The Blokli model of the [`NODE`] entry under [`SERVICE_TYPE`], as the server renders it.
pub fn entry_model(metadata: &[u8], updated_at: u64) -> types::ServiceEntry {
    types::ServiceEntry {
        service_type: SERVICE_TYPE.into(),
        node: const_hex::encode(NODE),
        safe: const_hex::encode(SAFE),
        metadata: format!("0x{}", const_hex::encode(metadata)),
        registered_at: types::Uint64(REGISTERED_AT.to_string()),
        updated_at: types::Uint64(updated_at.to_string()),
    }
}

/// Configuration of the fixture service type: owned, gated by a requirement contract, and paid.
pub fn type_config() -> ServiceTypeConfig {
    ServiceTypeConfig {
        owner: Some(OWNER.into()),
        requirement: Some(REQUIREMENT.into()),
        registration_burn: HoprBalance::new_base(1),
        update_burn: HoprBalance::from(500_u32),
    }
}

/// The registry-wide configuration seeded by [`state_with_registry_config`].
///
/// Both values differ from the ones the default fixture state carries, so a test cannot pass by
/// reading the default through.
pub fn registry_config() -> ServiceRegistryConfig {
    ServiceRegistryConfig {
        type_registration_fee: HoprBalance::new_base(5),
        node_safe_registry: REGISTRY_POINTER.into(),
    }
}

/// A bare state whose registry-wide configuration is [`registry_config`].
pub fn state_with_registry_config() -> BlokliTestState {
    BlokliTestState {
        service_registry_config: types::ServiceRegistryConfig {
            type_registration_fee: registry_config().type_registration_fee.to_string(),
            node_safe_registry: const_hex::encode(REGISTRY_POINTER),
        },
        ..Default::default()
    }
}

/// Binds [`SAFE`] to the given nodes, which is what makes their entries live.
pub fn safe_with_nodes(nodes: &[[u8; Address::SIZE]]) -> DeployedSafe {
    DeployedSafe {
        address: SAFE.into(),
        owners: vec![OWNER.into()],
        module: SAFE_MODULE.into(),
        registered_nodes: nodes.iter().map(|node| Address::from(*node)).collect(),
        deployer: OWNER.into(),
    }
}

type BlokliResult<T> = std::result::Result<T, BlokliClientError>;

/// A query client that fails every service registry query and delegates the rest to `C`.
///
/// The test client models an unreachable Blokli nowhere else, and the registry read path has to
/// distinguish a failed query from an empty registry.
pub struct FailingServiceQueries<C>(pub C);

impl<C> FailingServiceQueries<C> {
    fn failure() -> BlokliClientError {
        ErrorKind::MockClientError(anyhow::anyhow!("blokli is unreachable")).into()
    }
}

#[allow(deprecated)]
#[async_trait::async_trait]
impl<C: BlokliQueryClient + Send + Sync> BlokliQueryClient for FailingServiceQueries<C> {
    async fn count_services(&self, _: BlokliServiceSelector) -> BlokliResult<u32> {
        Err(Self::failure())
    }

    async fn query_services(&self, _: BlokliServiceSelector) -> BlokliResult<Vec<types::ServiceEntry>> {
        Err(Self::failure())
    }

    async fn query_live_services(&self, _: BlokliServiceSelector) -> BlokliResult<Vec<types::ServiceEntry>> {
        Err(Self::failure())
    }

    async fn query_service_types(&self, _: Option<ServiceTypeId>) -> BlokliResult<Vec<types::ServiceTypeInfo>> {
        Err(Self::failure())
    }

    async fn query_service_registry_config(&self) -> BlokliResult<types::ServiceRegistryConfig> {
        Err(Self::failure())
    }

    async fn count_accounts(&self, selector: AccountSelector) -> BlokliResult<u32> {
        self.0.count_accounts(selector).await
    }

    async fn query_accounts(&self, selector: AccountSelector) -> BlokliResult<Vec<types::Account>> {
        self.0.query_accounts(selector).await
    }

    async fn query_native_balance(&self, address: &ChainAddress) -> BlokliResult<types::NativeBalance> {
        self.0.query_native_balance(address).await
    }

    async fn query_token_balance(
        &self,
        address: &ChainAddress,
        token: types::Token,
    ) -> BlokliResult<types::HoprBalance> {
        self.0.query_token_balance(address, token).await
    }

    async fn query_transaction_count(&self, address: &ChainAddress) -> BlokliResult<u64> {
        self.0.query_transaction_count(address).await
    }

    async fn query_safe_allowance(&self, address: &ChainAddress) -> BlokliResult<types::SafeHoprAllowance> {
        self.0.query_safe_allowance(address).await
    }

    async fn query_redeemed_stats(&self, selector: RedeemedStatsSelector) -> BlokliResult<types::RedeemedStats> {
        self.0.query_redeemed_stats(selector).await
    }

    async fn query_safe(&self, selector: SafeSelector) -> BlokliResult<Vec<types::Safe>> {
        self.0.query_safe(selector).await
    }

    async fn query_module_address_prediction(&self, input: ModulePredictionInput) -> BlokliResult<ChainAddress> {
        self.0.query_module_address_prediction(input).await
    }

    async fn count_channels(&self, selector: ChannelSelector) -> BlokliResult<u32> {
        self.0.count_channels(selector).await
    }

    async fn query_channel_stats(&self, selector: ChannelSelector) -> BlokliResult<types::ChannelStats> {
        self.0.query_channel_stats(selector).await
    }

    async fn query_channels(&self, selector: ChannelSelector) -> BlokliResult<types::ChannelsList> {
        self.0.query_channels(selector).await
    }

    async fn query_safes_balance(&self, owner_address: Option<ChainAddress>) -> BlokliResult<types::SafesBalance> {
        self.0.query_safes_balance(owner_address).await
    }

    async fn query_transaction_status(&self, tx_id: TxId) -> BlokliResult<types::Transaction> {
        self.0.query_transaction_status(tx_id).await
    }

    async fn query_chain_info(&self) -> BlokliResult<types::ChainInfo> {
        self.0.query_chain_info().await
    }

    async fn query_version(&self) -> BlokliResult<String> {
        self.0.query_version().await
    }

    async fn query_compatibility(&self) -> BlokliResult<types::Compatibility> {
        self.0.query_compatibility().await
    }

    async fn query_health(&self) -> BlokliResult<String> {
        self.0.query_health().await
    }
}
