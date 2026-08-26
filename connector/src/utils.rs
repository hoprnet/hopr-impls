use std::{
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use hopr_api::{
    chain::{ChainInfo, DeployedSafe, DomainSeparators, RedemptionStats, ServiceRegistryConfig, ServiceTypeConfig},
    types::{
        chain::{chain_events::ChainEvent, payload::GasEstimation},
        crypto::types::Hash,
        internal::prelude::*,
        primitive::prelude::*,
    },
};

use crate::errors::ConnectorError;

pub(crate) fn model_to_account_entry(
    model: blokli_client::api::types::Account,
) -> Result<AccountEntry, ConnectorError> {
    let entry_type = if !model.multi_addresses.is_empty() {
        AccountType::Announced(
            model
                .multi_addresses
                .into_iter()
                .filter_map(|addr| match Multiaddr::from_str(&addr) {
                    Ok(addr) => Some(addr),
                    Err(_) => {
                        tracing::error!(%addr, "invalid multiaddress");
                        None
                    }
                })
                .collect(),
        )
    } else {
        AccountType::NotAnnounced
    };

    Ok(AccountEntry {
        public_key: model.packet_key.parse()?,
        chain_addr: model.chain_key.parse()?,
        key_id: (model.keyid as u32).into(),
        entry_type,
        safe_address: model.safe_address.map(|addr| Address::from_hex(&addr)).transpose()?,
    })
}

pub(crate) fn model_to_graph_entry(
    model: blokli_client::api::types::OpenedChannelsGraphEntry,
) -> Result<(AccountEntry, AccountEntry, ChannelEntry), ConnectorError> {
    let src = model_to_account_entry(model.source)?;
    let dst = model_to_account_entry(model.destination)?;
    let channel = ChannelBuilder::default()
        .between(src.chain_addr, dst.chain_addr)
        .balance(model.channel.balance.0.parse()?)
        .ticket_index(
            model
                .channel
                .ticket_index
                .0
                .parse()
                .map_err(|e| ConnectorError::TypeConversion(format!("invalid ticket index: {e}")))?,
        )
        .status(match model.channel.status {
            blokli_client::api::types::ChannelStatus::Open => ChannelStatus::Open,
            blokli_client::api::types::ChannelStatus::PendingToClose => ChannelStatus::PendingToClose(
                model
                    .channel
                    .closure_time
                    .as_ref()
                    .ok_or(ConnectorError::TypeConversion("invalid closure time".into()))
                    .and_then(|t| {
                        hopr_api::chain::DateTime::from_str(&t.0)
                            .map_err(|e| ConnectorError::TypeConversion(format!("invalid closure time: {e}")))
                    })?
                    .into(),
            ),
            blokli_client::api::types::ChannelStatus::Closed => ChannelStatus::Closed,
        })
        .epoch(model.channel.epoch as u32)
        .build()?;

    Ok((src, dst, channel))
}

pub(crate) fn model_to_redeemed_stats(
    model: blokli_client::api::types::RedeemedStats,
) -> Result<RedemptionStats, ConnectorError> {
    Ok(RedemptionStats {
        redeemed_count: model
            .redemption_count
            .0
            .parse()
            .map_err(|_| ConnectorError::TypeConversion("invalid redemption count".into()))?,
        redeemed_value: model
            .redeemed_amount
            .0
            .parse()
            .map_err(|_| ConnectorError::TypeConversion("invalid redeemed amount".into()))?,
    })
}

pub(crate) fn model_to_ticket_params(
    model: blokli_client::api::types::TicketParameters,
) -> Result<(HoprBalance, WinningProbability), ConnectorError> {
    Ok((
        model.ticket_price.0.parse()?,
        WinningProbability::try_from_f64(model.min_ticket_winning_probability)?,
    ))
}

#[derive(Debug, Clone)]
pub(crate) struct ParsedChainInfo {
    pub channel_closure_grace_period: Duration,
    pub domain_separators: DomainSeparators,
    pub key_binding_fee: HoprBalance,
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
    pub info: ChainInfo,
    pub ticket_win_prob: WinningProbability,
    pub ticket_price: HoprBalance,
    pub finality: u32,
    pub expected_block_time: Duration,
}

impl From<ParsedChainInfo> for GasEstimation {
    fn from(value: ParsedChainInfo) -> Self {
        Self {
            max_fee_per_gas: value.max_fee_per_gas,
            max_priority_fee_per_gas: value.max_priority_fee_per_gas,
            ..Self::default()
        }
    }
}

pub(crate) fn model_to_chain_info(
    model: blokli_client::api::types::ChainInfo,
) -> Result<ParsedChainInfo, ConnectorError> {
    let gas_defaults = GasEstimation::default();

    Ok(ParsedChainInfo {
        channel_closure_grace_period: model
            .channel_closure_grace_period
            .0
            .parse()
            .map(Duration::from_secs)
            .map_err(|e| ConnectorError::TypeConversion(format!("invalid channel grace period: {e}")))?,
        domain_separators: DomainSeparators {
            ledger: model
                .ledger_dst
                .ok_or(ConnectorError::TypeConversion("missing ledger dst".into()))
                .and_then(|v| {
                    Hash::from_hex(&v).map_err(|e| ConnectorError::TypeConversion(format!("invalid ledger dst: {e}")))
                })?,
            safe_registry: model
                .safe_registry_dst
                .ok_or(ConnectorError::TypeConversion("missing safe registry dst".into()))
                .and_then(|v| {
                    Hash::from_hex(&v)
                        .map_err(|e| ConnectorError::TypeConversion(format!("invalid safe registry dst: {e}")))
                })?,
            channel: model
                .channel_dst
                .ok_or(ConnectorError::TypeConversion("missing channel dst".into()))
                .and_then(|v| {
                    Hash::from_hex(&v).map_err(|e| ConnectorError::TypeConversion(format!("invalid channel dst: {e}")))
                })?,
        },
        key_binding_fee: model
            .key_binding_fee
            .0
            .parse()
            .map_err(|e| ConnectorError::TypeConversion(format!("invalid key binding fee: {e}")))?,
        max_fee_per_gas: model
            .max_fee_per_gas
            .as_deref()
            .and_then(|raw| raw.parse::<u128>().ok())
            .unwrap_or(gas_defaults.max_fee_per_gas),
        max_priority_fee_per_gas: model
            .max_priority_fee_per_gas
            .as_deref()
            .and_then(|raw| raw.parse::<u128>().ok())
            .unwrap_or(gas_defaults.max_priority_fee_per_gas)
            .min(
                model
                    .max_fee_per_gas
                    .as_deref()
                    .and_then(|raw| raw.parse::<u128>().ok())
                    .unwrap_or(gas_defaults.max_fee_per_gas),
            ),
        info: ChainInfo {
            chain_id: model.chain_id as u64,
            hopr_network_name: model.network,
            contract_addresses: serde_json::from_str(&model.contract_addresses.0)
                .map_err(|e| ConnectorError::TypeConversion(format!("invalid contract addresses JSON: {e}")))?,
        },
        ticket_win_prob: WinningProbability::try_from_f64(model.min_ticket_winning_probability)
            .map_err(|e| ConnectorError::TypeConversion(format!("invalid winning probability info: {e}")))?,
        ticket_price: model
            .ticket_price
            .0
            .parse()
            .map_err(|e| ConnectorError::TypeConversion(format!("invalid ticket price: {e}")))?,
        finality: model
            .finality
            .0
            .parse::<u32>()
            .map_err(|e| ConnectorError::TypeConversion(format!("failed to parse finality: {e}")))?
            .max(1),
        expected_block_time: Duration::from_secs(
            model
                .expected_block_time
                .0
                .parse()
                .map_err(|e| ConnectorError::TypeConversion(format!("failed to parse expected block time: {e}")))?,
        )
        .max(Duration::from_secs(1)),
    })
}

pub(crate) fn model_to_deployed_safe(model: blokli_client::api::types::Safe) -> Result<DeployedSafe, ConnectorError> {
    Ok(DeployedSafe {
        address: Address::from_hex(&model.address)?,
        owners: model
            .owners
            .into_iter()
            .map(|addr| Address::from_hex(&addr))
            .collect::<Result<Vec<_>, _>>()?,
        module: Address::from_hex(&model.module_address)?,
        registered_nodes: model
            .registered_nodes
            .into_iter()
            .map(|addr| Address::from_hex(&addr))
            .collect::<Result<Vec<_>, _>>()?,
        deployer: Address::from_hex(&model.chain_key)?,
    })
}

/// Decodes a service type the way Blokli renders it: the ASCII name of the type, or `0x`-prefixed
/// hexadecimal for a type that does not follow that convention.
///
/// The two renderings cannot be confused: an ASCII name is at most [`ServiceType::SIZE`]
/// characters long, while the hexadecimal form always has two characters per byte plus the prefix.
pub(crate) fn model_to_service_type(rendered: &str) -> Result<ServiceType, ConnectorError> {
    if rendered.len() == 2 + 2 * ServiceType::SIZE && rendered.starts_with("0x") {
        ServiceType::from_hex(rendered)
    } else {
        rendered.parse()
    }
    .map_err(|e| ConnectorError::TypeConversion(format!("invalid service type {rendered}: {e}")))
}

/// Decodes the opaque metadata of a registry entry, which Blokli renders as `0x`-prefixed
/// hexadecimal.
fn model_to_service_metadata(rendered: &str) -> Result<ServiceMetadata, ConnectorError> {
    let bytes = const_hex::decode(rendered)
        .map_err(|e| ConnectorError::TypeConversion(format!("invalid service metadata: {e}")))?;

    // Rejects metadata above the cap the registry contract enforces on every write path.
    ServiceMetadata::try_from(bytes)
        .map_err(|e| ConnectorError::TypeConversion(format!("invalid service metadata: {e}")))
}

/// Converts a Unix timestamp in seconds, as the Blokli API represents registry timestamps.
fn model_to_timestamp(seconds: &blokli_client::api::types::Uint64) -> Result<SystemTime, ConnectorError> {
    seconds
        .0
        .parse::<u64>()
        .map(|seconds| UNIX_EPOCH + Duration::from_secs(seconds))
        .map_err(|e| ConnectorError::TypeConversion(format!("invalid service timestamp {}: {e}", seconds.0)))
}

/// Parses a service registry burn.
///
/// Blokli renders every balance through [`Display`](std::fmt::Display), which carries the
/// currency - `"1.5 wxHOPR"`, not `"1500000000000000000"` - so this is a plain
/// [`FromStr`] parse. Do NOT reach for a bare-decimal parser here: `HoprBalance::from_str`
/// rejects an unsuffixed number, so the two encodings cannot be confused silently.
pub(crate) fn service_burn_to_hopr_balance(amount: &str) -> Result<HoprBalance, ConnectorError> {
    HoprBalance::from_str(amount)
        .map_err(|e| ConnectorError::TypeConversion(format!("invalid service registry burn {amount}: {e}")))
}

/// Decodes an address of the service registry, naming the field it came from.
///
/// A registry entry that fails to convert is dropped by the read path with only the error
/// attached, so without the field name an operator investigating a missing service cannot tell
/// which of the four addresses was unparseable.
pub(crate) fn model_to_registry_address(field: &str, rendered: &str) -> Result<Address, ConnectorError> {
    Address::from_hex(rendered)
        .map_err(|e| ConnectorError::TypeConversion(format!("invalid service registry {field} {rendered}: {e}")))
}

pub(crate) fn model_to_service_entry(
    model: &blokli_client::api::types::ServiceEntry,
) -> Result<ServiceEntry, ConnectorError> {
    Ok(ServiceEntry::new(
        model_to_service_type(&model.service_type)?,
        model_to_registry_address("node", &model.node)?,
        model_to_registry_address("safe", &model.safe)?,
        model_to_service_metadata(&model.metadata)?,
        model_to_timestamp(&model.registered_at)?,
        model_to_timestamp(&model.updated_at)?,
    )?)
}

pub(crate) fn model_to_service_type_config(
    model: &blokli_client::api::types::ServiceTypeInfo,
) -> Result<ServiceTypeConfig, ConnectorError> {
    Ok(ServiceTypeConfig {
        owner: model
            .owner
            .as_deref()
            .map(|owner| model_to_registry_address("type owner", owner))
            .transpose()?,
        requirement: model
            .requirement
            .as_deref()
            .map(|requirement| model_to_registry_address("type requirement", requirement))
            .transpose()?,
        registration_burn: service_burn_to_hopr_balance(&model.registration_burn)?,
        update_burn: service_burn_to_hopr_balance(&model.update_burn)?,
    })
}

pub(crate) fn model_to_service_registry_config(
    model: blokli_client::api::types::ServiceRegistryConfig,
) -> Result<ServiceRegistryConfig, ConnectorError> {
    Ok(ServiceRegistryConfig {
        type_registration_fee: service_burn_to_hopr_balance(&model.type_registration_fee)?,
        node_safe_registry: model_to_registry_address("node-Safe registry", &model.node_safe_registry)?,
    })
}

pub(crate) async fn process_channel_changes_into_events(
    new_channel: ChannelEntry,
    changes: Vec<ChannelChange>,
    me: &Address,
    event_tx: &async_broadcast::Sender<ChainEvent>,
) {
    for change in changes {
        tracing::trace!(id = %new_channel.get_id(), %change, "channel updated");
        match change {
            ChannelChange::Status {
                left: ChannelStatus::Open,
                right: ChannelStatus::PendingToClose(_),
            } => {
                tracing::debug!(id = %new_channel.get_id(), "channel pending to close");
                let _ = event_tx
                    .broadcast_direct(ChainEvent::ChannelClosureInitiated(new_channel))
                    .await;
            }
            ChannelChange::Status {
                left: ChannelStatus::PendingToClose(_),
                right: ChannelStatus::Closed,
            } => {
                tracing::debug!(id = %new_channel.get_id(), "channel closed");
                let _ = event_tx.broadcast_direct(ChainEvent::ChannelClosed(new_channel)).await;
            }
            ChannelChange::Status {
                left: ChannelStatus::Closed,
                right: ChannelStatus::Open,
            } => {
                tracing::debug!(id = %new_channel.get_id(), "channel reopened");
                let _ = event_tx.broadcast_direct(ChainEvent::ChannelOpened(new_channel)).await;
            }
            ChannelChange::Balance { left, right } => {
                if left > right {
                    tracing::debug!(id = %new_channel.get_id(), "channel balance decreased");
                    let _ = event_tx
                        .broadcast_direct(ChainEvent::ChannelBalanceDecreased(new_channel, left - right))
                        .await;
                } else {
                    tracing::debug!(id = %new_channel.get_id(), "channel balance increased");
                    let _ = event_tx
                        .broadcast_direct(ChainEvent::ChannelBalanceIncreased(new_channel, right - left))
                        .await;
                }
            }
            // Ticket index can wrap (left > right) on a channel re-open,
            // but we're not interested in that here
            ChannelChange::TicketIndex { left, right } if left < right => match new_channel.direction(me) {
                Some(ChannelDirection::Incoming) => {
                    // The corresponding event is raised in the ticket redeem tracker,
                    // as the failure must be tracked there too.
                    tracing::debug!(id = %new_channel.get_id(), "ticket redemption succeeded");
                }
                Some(ChannelDirection::Outgoing) => {
                    tracing::debug!(id = %new_channel.get_id(), "counterparty has redeemed ticket on our channel");
                    let _ = event_tx
                        .broadcast_direct(ChainEvent::TicketRedeemed(new_channel, None))
                        .await;
                }
                None => {
                    tracing::debug!(id = %new_channel.get_id(), "ticket redeemed on foreign channel");
                    let _ = event_tx
                        .broadcast_direct(ChainEvent::TicketRedeemed(new_channel, None))
                        .await;
                }
            },
            _ => {}
        }
    }
}
