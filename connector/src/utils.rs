use std::{
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use hopr_api::{
    chain::{ChainInfo, DeployedSafe, DomainSeparators, RedemptionStats, ServiceRegistryConfig, ServiceTypeConfig},
    types::{
        chain::{chain_events::ChainEvent, payload::GasEstimation, prelude::ContractAddresses},
        crypto::types::{Hash, OffchainPublicKey},
        internal::prelude::*,
        primitive::prelude::*,
    },
};

use crate::errors::ConnectorError;

/// Parses Blokli's contract-address map, accepting deployments from before the
/// service registry was introduced.
///
/// HOPR 4.x chains have no service registry. Their Blokli `chainInfo` payloads
/// therefore omit `service_registry`; represent that absence with the zero
/// address, which is the documented value for a network without a deployment.
pub(crate) fn parse_contract_addresses(raw: &str) -> Result<ContractAddresses, ConnectorError> {
    let mut addresses: serde_json::Value = serde_json::from_str(raw)
        .map_err(|e| ConnectorError::TypeConversion(format!("invalid contract addresses JSON: {e}")))?;

    let object = addresses
        .as_object_mut()
        .ok_or_else(|| ConnectorError::TypeConversion("invalid contract addresses JSON: expected an object".into()))?;
    object
        .entry("service_registry")
        .or_insert_with(|| serde_json::Value::String(Address::default().to_string()));

    serde_json::from_value(addresses)
        .map_err(|e| ConnectorError::TypeConversion(format!("invalid contract addresses JSON: {e}")))
}

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

    // The compact `OffchainPublicKey` only checks its length when parsed, so that the vast
    // majority of keys - which never enter an elliptic-curve computation - do not pay for a point
    // decompression. This is the boundary where keys enter the node from the chain indexer, and
    // the one place where a key that is not on the curve is worth rejecting outright: left
    // unchecked it would be accepted into the account tables and only fail much later, when a
    // packet is built for a path that happens to include it.
    let public_key: OffchainPublicKey = model.packet_key.parse()?;
    public_key.validate()?;

    Ok(AccountEntry {
        public_key,
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
    let channel = model_to_channel_entry(&model.channel, src.chain_addr, dst.chain_addr)?;

    Ok((src, dst, channel))
}

/// Converts a channel model into a [`ChannelEntry`] between the given, already resolved, endpoints.
///
/// The model only carries the numeric key IDs of its endpoints, so the caller supplies their addresses.
pub(crate) fn model_to_channel_entry(
    model: &blokli_client::api::types::Channel,
    source: Address,
    destination: Address,
) -> Result<ChannelEntry, ConnectorError> {
    Ok(ChannelBuilder::default()
        .between(source, destination)
        .balance(model.balance.0.parse()?)
        .ticket_index(
            model
                .ticket_index
                .0
                .parse()
                .map_err(|e| ConnectorError::TypeConversion(format!("invalid ticket index: {e}")))?,
        )
        .status(match model.status {
            blokli_client::api::types::ChannelStatus::Open => ChannelStatus::Open,
            blokli_client::api::types::ChannelStatus::PendingToClose => ChannelStatus::PendingToClose(
                model
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
            // never happens, still a case to cover
            _ => return Err(ConnectorError::TypeConversion("invalid channel status".into())),
        })
        .epoch(
            u32::try_from(model.epoch)
                .map_err(|_| ConnectorError::TypeConversion(format!("invalid channel epoch {}", model.epoch)))?,
        )
        .build()?)
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
            contract_addresses: parse_contract_addresses(&model.contract_addresses.0)?,
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
    let parsed = seconds
        .0
        .parse::<u64>()
        .map_err(|e| ConnectorError::TypeConversion(format!("invalid service timestamp {}: {e}", seconds.0)))?;

    // A `Uint64` can name an instant that the platform's `SystemTime` cannot hold, and
    // `SystemTime + Duration` panics on overflow instead of failing, so malformed Blokli data
    // would terminate the process.
    UNIX_EPOCH
        .checked_add(Duration::from_secs(parsed))
        .ok_or_else(|| ConnectorError::TypeConversion(format!("service timestamp {parsed} is out of range")))
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

/// The event announcing a channel the connector has not known before, matching the channel's status.
///
/// A first-seen `Closed` channel yields no event: there is no earlier state to finalize, and `ChannelClosed`
/// is documented as the end of a closure the consumer can have seen begin.
pub(crate) fn event_for_first_seen_channel(channel: ChannelEntry) -> Option<ChainEvent> {
    match channel.status {
        ChannelStatus::Open => Some(ChainEvent::ChannelOpened(channel)),
        ChannelStatus::PendingToClose(_) => Some(ChainEvent::ChannelClosureInitiated(channel)),
        ChannelStatus::Closed => None,
    }
}

/// Counts the distinct channels seen as `Open`, the quantity the connection quota is computed from.
///
/// The graph subscription replays every channel and delivers all later updates, so counting events would
/// count a channel once per status change or replay, and count channels that are not open at all.
#[derive(Debug, Default)]
pub(crate) struct OpenChannelCounter(std::collections::HashSet<ChannelId>);

impl OpenChannelCounter {
    /// Records the channel and returns the number of distinct open channels seen so far.
    pub(crate) fn observe(&mut self, channel: &ChannelEntry) -> u32 {
        if matches!(channel.status, ChannelStatus::Open) {
            self.0.insert(*channel.get_id());
        }
        self.0.len() as u32
    }
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
            // The intermediate PendingToClose update was missed, so the channel went straight to Closed.
            ChannelChange::Status {
                left: ChannelStatus::Open,
                right: ChannelStatus::Closed,
            } => {
                tracing::debug!(id = %new_channel.get_id(), "channel closed without a pending closure");
                let _ = event_tx.broadcast_direct(ChainEvent::ChannelClosed(new_channel)).await;
            }
            ChannelChange::Status {
                left: ChannelStatus::Closed | ChannelStatus::PendingToClose(_),
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

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use hopr_api::types::crypto::prelude::{ChainKeypair, Keypair};

    use super::*;

    fn channel(status: ChannelStatus, epoch: u32) -> ChannelEntry {
        ChannelEntry::builder()
            .between(
                &ChainKeypair::from_secret(&[1u8; 32]).unwrap(),
                &ChainKeypair::from_secret(&[2u8; 32]).unwrap(),
            )
            .amount(10)
            .ticket_index(0)
            .status(status)
            .epoch(epoch)
            .build()
            .unwrap()
    }

    fn pending() -> ChannelStatus {
        ChannelStatus::PendingToClose(SystemTime::UNIX_EPOCH + Duration::from_secs(1000))
    }

    async fn events_for(new: ChannelEntry, old: ChannelEntry) -> Vec<ChainEvent> {
        let (tx, mut rx) = async_broadcast::broadcast(16);
        let me = Address::default();
        process_channel_changes_into_events(new, old.diff(&new), &me, &tx).await;
        drop(tx);
        let mut events = Vec::new();
        while let Ok(event) = rx.recv().await {
            events.push(event);
        }
        events
    }

    #[tokio::test]
    async fn open_to_closed_should_emit_channel_closed() {
        let events = events_for(channel(ChannelStatus::Closed, 1), channel(ChannelStatus::Open, 1)).await;
        assert!(matches!(events.as_slice(), [ChainEvent::ChannelClosed(c)] if c.status == ChannelStatus::Closed));
    }

    #[tokio::test]
    async fn pending_to_close_to_open_should_emit_channel_opened() {
        let events = events_for(channel(ChannelStatus::Open, 1), channel(pending(), 1)).await;
        assert!(matches!(events.as_slice(), [ChainEvent::ChannelOpened(c)] if c.status == ChannelStatus::Open));
    }

    #[tokio::test]
    async fn closed_to_open_should_still_emit_channel_opened() {
        let events = events_for(channel(ChannelStatus::Open, 2), channel(ChannelStatus::Closed, 1)).await;
        assert!(matches!(events.as_slice(), [ChainEvent::ChannelOpened(_)]));
    }

    #[tokio::test]
    async fn epoch_change_alone_should_not_emit_an_event() {
        // ChainEvent has no variant for an epoch change.
        let events = events_for(channel(ChannelStatus::Open, 2), channel(ChannelStatus::Open, 1)).await;
        assert!(events.is_empty());
    }

    #[test]
    fn first_seen_channel_event_should_match_the_status() {
        assert!(matches!(
            event_for_first_seen_channel(channel(ChannelStatus::Open, 1)),
            Some(ChainEvent::ChannelOpened(_))
        ));
        assert!(matches!(
            event_for_first_seen_channel(channel(pending(), 1)),
            Some(ChainEvent::ChannelClosureInitiated(_))
        ));
        assert!(event_for_first_seen_channel(channel(ChannelStatus::Closed, 1)).is_none());
    }

    #[test]
    fn channel_model_with_a_negative_epoch_should_be_rejected() {
        let model = |epoch: i32| blokli_client::api::types::Channel {
            balance: blokli_client::api::types::TokenValueString(HoprBalance::from(10_u32).to_string()),
            closure_time: None,
            concrete_channel_id: String::new(),
            destination: 2,
            epoch,
            source: 1,
            status: blokli_client::api::types::ChannelStatus::Open,
            ticket_index: blokli_client::api::types::Uint64("0".into()),
        };
        let (src, dst) = (Address::new(&[1u8; Address::SIZE]), Address::new(&[2u8; Address::SIZE]));

        assert!(matches!(
            model_to_channel_entry(&model(-1), src, dst),
            Err(ConnectorError::TypeConversion(_))
        ));
        assert_eq!(3, model_to_channel_entry(&model(3), src, dst).unwrap().channel_epoch);
    }

    #[test]
    fn open_channel_counter_should_count_distinct_open_channels_only() {
        let mut counter = OpenChannelCounter::default();
        let open = channel(ChannelStatus::Open, 1);

        assert_eq!(1, counter.observe(&open));
        // a replay or an update of the same channel does not count again
        assert_eq!(1, counter.observe(&open));
        assert_eq!(1, counter.observe(&channel(ChannelStatus::Open, 2)));

        let other = ChannelEntry::builder()
            .between(
                &ChainKeypair::from_secret(&[1u8; 32]).unwrap(),
                &ChainKeypair::from_secret(&[3u8; 32]).unwrap(),
            )
            .amount(1)
            .ticket_index(0)
            .status(pending())
            .epoch(1)
            .build()
            .unwrap();
        // a channel that is not open does not count
        assert_eq!(1, counter.observe(&other));
    }
}
