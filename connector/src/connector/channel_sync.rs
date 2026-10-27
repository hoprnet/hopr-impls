//! Keeps the node's own channels in line with Blokli when channel updates were missed.
//!
//! Channel updates normally arrive through the channel graph subscription. Updates sent while that subscription was
//! disconnected, or dropped by Blokli because the subscription fell behind, are lost. The snapshot Blokli replays
//! after a reconnect does not help with closures either, because it holds no closed channels. A node that misses
//! a closure keeps the channel as open, and then sends the wrong closure transaction for it.
//!
//! [`ChannelSync`] therefore reads the node's own channels from Blokli again, every
//! [`own_channels_sync_interval`](crate::BlockchainConnectorConfig::own_channels_sync_interval), and updates the
//! stored ones that moved on.
//!
//! Query reconciliation only updates channels the node has already stored. Subscription writes use the same lock
//! and caches, but may discover channels. Only the subscription caller maintains the topology index; this helper
//! never reads or writes the graph.

use std::{cmp::Ordering, time::Duration};

use blokli_client::api::{BlokliQueryClient, ChannelFilter, ChannelSelector, types::Channel};
use hopr_api::{
    chain::{ChainEvent, HoprKeyIdent},
    types::{internal::prelude::*, primitive::prelude::*},
};

use crate::{
    backend::Backend,
    errors::ConnectorError,
    utils::{model_to_channel_entry, process_channel_changes_into_events},
};

/// Default of [`own_channels_sync_interval`](crate::BlockchainConnectorConfig::own_channels_sync_interval).
pub(crate) const DEFAULT_OWN_CHANNELS_SYNC_INTERVAL: Duration = Duration::from_mins(10);

/// Shortest allowed [`own_channels_sync_interval`](crate::BlockchainConnectorConfig::own_channels_sync_interval),
/// so the node does not query Blokli in a tight loop.
pub(crate) const MIN_OWN_CHANNELS_SYNC_INTERVAL: Duration = Duration::from_mins(1);

/// Whether a channel can move from `stored` to `fresh` within one epoch.
///
/// A channel only moves forward: open, pending to close, closed. Starting the closure again keeps it pending to
/// close, with a later closure time.
fn is_later_status(stored: &ChannelStatus, fresh: &ChannelStatus) -> bool {
    match (stored, fresh) {
        (ChannelStatus::Open, ChannelStatus::PendingToClose(_) | ChannelStatus::Closed)
        | (ChannelStatus::PendingToClose(_), ChannelStatus::Closed) => true,
        (ChannelStatus::PendingToClose(stored_time), ChannelStatus::PendingToClose(fresh_time)) => {
            fresh_time > stored_time
        }
        // Listed one by one, so a new status does not compile until it is placed here.
        (ChannelStatus::Open, ChannelStatus::Open)
        | (ChannelStatus::PendingToClose(_), ChannelStatus::Open)
        | (ChannelStatus::Closed, _) => false,
    }
}

/// Whether `fresh`, read from Blokli, is a later state of the channel than `stored`.
///
/// Within an epoch a channel only moves forward: open, pending to close, closed. Its epoch only grows, when the
/// channel is opened again. A query result can be older than an update the subscription has already delivered, so
/// anything that is not a later state is ignored instead of being written over the stored one.
pub(crate) fn is_later_state(stored: &ChannelEntry, fresh: &ChannelEntry) -> bool {
    match fresh.channel_epoch.cmp(&stored.channel_epoch) {
        Ordering::Greater => true,
        Ordering::Less => false,
        Ordering::Equal => is_later_status(&stored.status, &fresh.status),
    }
}

/// A stored subscription record and the changes from its predecessor, if one existed.
pub(crate) type StoredChannelUpdate = (ChannelEntry, Option<Vec<ChannelChange>>);

/// Writes channel states read from Blokli into the connector's backend and caches.
pub(crate) struct ChannelSync<B> {
    pub(crate) backend: std::sync::Arc<B>,
    pub(crate) channel_by_id: moka::sync::Cache<ChannelId, Option<ChannelEntry>, ahash::RandomState>,
    pub(crate) channel_by_parties: moka::sync::Cache<ChannelParties, Option<ChannelEntry>, ahash::RandomState>,
    /// Shared with the channel graph subscription, so a stored channel is never replaced between reading and writing
    /// it.
    pub(crate) write_lock: std::sync::Arc<parking_lot::Mutex<()>>,
    pub(crate) event_tx: async_broadcast::Sender<ChainEvent>,
    pub(crate) me: Address,
}

impl<B> Clone for ChannelSync<B> {
    fn clone(&self) -> Self {
        Self {
            backend: self.backend.clone(),
            channel_by_id: self.channel_by_id.clone(),
            channel_by_parties: self.channel_by_parties.clone(),
            write_lock: self.write_lock.clone(),
            event_tx: self.event_tx.clone(),
            me: self.me,
        }
    }
}

impl<B> ChannelSync<B>
where
    B: Backend + Send + Sync + 'static,
{
    /// Stores a subscription update unless its epoch, status or closure deadline is older than the stored one.
    ///
    /// Unlike query reconciliation, a subscription can discover a channel and update its balance or ticket index
    /// without changing its status. Backend and cache publication share the reconciliation lock. The caller owns
    /// topology updates and event delivery; this helper never accesses the graph.
    pub(crate) async fn store_subscription(
        &self,
        channel: ChannelEntry,
    ) -> Result<Option<StoredChannelUpdate>, ConnectorError> {
        let sync = self.clone();
        hopr_utils::runtime::prelude::spawn_blocking(move || {
            let _guard = sync.write_lock.lock();
            let stored = sync
                .backend
                .get_channel_by_id(channel.get_id())
                .map_err(ConnectorError::backend)?;
            if stored.as_ref().is_some_and(|stored| is_later_state(&channel, stored)) {
                return Ok(None);
            }

            let old = sync.backend.insert_channel(channel).map_err(ConnectorError::backend)?;
            sync.channel_by_id.insert(*channel.get_id(), Some(channel));
            sync.channel_by_parties
                .insert(ChannelParties::from(&channel), Some(channel));
            Ok(Some((channel, old.map(|old| old.diff(&channel)))))
        })
        .await
        .map_err(ConnectorError::backend)?
    }

    /// Applies a query response and returns the latest stored record, including when that response was rejected.
    ///
    /// A subscription can advance the record while the query is in flight. Returning the query response or the
    /// caller's pre-query copy would then choose the wrong closure transaction.
    pub(crate) async fn refresh(&self, fresh: ChannelEntry) -> Result<Option<ChannelEntry>, ConnectorError> {
        self.apply(fresh).await?;
        let sync = self.clone();
        hopr_utils::runtime::prelude::spawn_blocking(move || {
            let _guard = sync.write_lock.lock();
            sync.backend
                .get_channel_by_id(fresh.get_id())
                .map_err(ConnectorError::backend)
        })
        .await
        .map_err(ConnectorError::backend)?
    }

    /// Replaces the stored channel with `fresh` if `fresh` is a [later state](is_later_state), and sends the chain
    /// events for the change.
    ///
    /// Returns the stored channel after the update, or `None` when nothing was changed: the channel is not stored, or
    /// `fresh` is not a later state.
    pub(crate) async fn apply(&self, fresh: ChannelEntry) -> Result<Option<ChannelEntry>, ConnectorError> {
        let sync = self.clone();
        let replaced = hopr_utils::runtime::prelude::spawn_blocking(move || {
            let _guard = sync.write_lock.lock();
            let stored = sync
                .backend
                .get_channel_by_id(fresh.get_id())
                .map_err(ConnectorError::backend)?;
            let Some(stored) = stored.filter(|stored| is_later_state(stored, &fresh)) else {
                return Ok::<_, ConnectorError>(None);
            };

            sync.backend.insert_channel(fresh).map_err(ConnectorError::backend)?;
            sync.channel_by_id.insert(*fresh.get_id(), Some(fresh));
            sync.channel_by_parties
                .insert(ChannelParties::from(&fresh), Some(fresh));
            Ok(Some(stored))
        })
        .await
        .map_err(ConnectorError::backend)??;

        let Some(stored) = replaced else {
            return Ok(None);
        };
        tracing::warn!(
            channel_id = %fresh.get_id(),
            stored_status = %stored.status,
            stored_epoch = stored.channel_epoch,
            status = %fresh.status,
            epoch = fresh.channel_epoch,
            "own channel was out of date, updated it from Blokli"
        );
        process_channel_changes_into_events(fresh, stored.diff(&fresh), &self.me, &self.event_tx).await;

        Ok(Some(fresh))
    }

    /// Turns a channel read from Blokli into a [`ChannelEntry`], looking up the addresses of its ends.
    ///
    /// Returns `None` when an end is an account the node does not know yet.
    pub(crate) async fn resolve(&self, model: Channel) -> Result<Option<ChannelEntry>, ConnectorError> {
        let source = HoprKeyIdent::from(model.source as u32);
        let destination = HoprKeyIdent::from(model.destination as u32);
        let backend = self.backend.clone();
        let accounts = hopr_utils::runtime::prelude::spawn_blocking(move || {
            Ok::<_, ConnectorError>((
                backend.get_account_by_id(&source).map_err(ConnectorError::backend)?,
                backend
                    .get_account_by_id(&destination)
                    .map_err(ConnectorError::backend)?,
            ))
        })
        .await
        .map_err(ConnectorError::backend)??;

        let (Some(source_account), Some(destination_account)) = accounts else {
            tracing::debug!(
                channel_id = model.concrete_channel_id,
                %source,
                %destination,
                "channel end is not a known account yet, skipping it"
            );
            return Ok(None);
        };

        Ok(Some(model_to_channel_entry(
            &model,
            source_account.chain_addr,
            destination_account.chain_addr,
        )?))
    }

    /// Reads all the node's own channels from Blokli, closed ones included, and updates the stored ones that moved on.
    ///
    /// Returns how many channels were updated.
    pub(crate) async fn sync_own_channels<C>(&self, client: &C) -> Result<usize, ConnectorError>
    where
        C: BlokliQueryClient + Send + Sync,
    {
        let backend = self.backend.clone();
        let me = self.me;
        let my_account = hopr_utils::runtime::prelude::spawn_blocking(move || {
            backend.get_account_by_address(&me).map_err(ConnectorError::backend)
        })
        .await
        .map_err(ConnectorError::backend)??;
        let Some(my_account) = my_account else {
            tracing::debug!("the node has no account in Blokli yet, so it has no channels to sync");
            return Ok(0);
        };
        let my_key_id = u32::from(my_account.key_id);

        let mut models = Vec::new();
        for filter in [
            ChannelFilter::SourceKeyId(my_key_id),
            ChannelFilter::DestinationKeyId(my_key_id),
        ] {
            let selector = ChannelSelector {
                filter: Some(filter),
                status: None,
                ..Default::default()
            };
            models.extend(client.query_channels(selector).await?.channels);
        }

        let checked = models.len();
        let mut updated = 0;
        for model in models {
            if let Some(fresh) = self.resolve(model).await?
                && self.apply(fresh).await?.is_some()
            {
                updated += 1;
            }
        }

        tracing::debug!(checked, updated, "synced own channels with Blokli");
        Ok(updated)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::time::{Duration, SystemTime};

    use futures::StreamExt;
    use hex_literal::hex;
    use hopr_api::{
        chain::{ChainEvents, ChainReadChannelOperations},
        types::crypto::{
            keypairs::{ChainKeypair, OffchainKeypair},
            prelude::Keypair,
        },
    };

    use super::*;
    use crate::{
        connector::tests::{MODULE_ADDR, PRIVATE_KEY_1, PRIVATE_KEY_2, create_connector},
        testing::BlokliTestStateBuilder,
    };

    pub(crate) fn channel(status: ChannelStatus, epoch: u32) -> anyhow::Result<ChannelEntry> {
        Ok(ChannelEntry::builder()
            .between(
                &ChainKeypair::from_secret(&PRIVATE_KEY_1)?,
                &ChainKeypair::from_secret(&PRIVATE_KEY_2)?,
            )
            .amount(10)
            .ticket_index(1)
            .status(status)
            .epoch(epoch)
            .build()?)
    }

    pub(crate) fn pending_since(secs: u64) -> ChannelStatus {
        ChannelStatus::PendingToClose(SystemTime::UNIX_EPOCH + Duration::from_secs(secs))
    }

    #[test]
    fn only_later_states_replace_the_stored_channel() -> anyhow::Result<()> {
        let cases = [
            (ChannelStatus::Open, 1, pending_since(10), 1, true),
            (ChannelStatus::Open, 1, ChannelStatus::Closed, 1, true),
            (pending_since(10), 1, ChannelStatus::Closed, 1, true),
            (pending_since(10), 1, pending_since(20), 1, true),
            (ChannelStatus::Closed, 1, ChannelStatus::Open, 2, true),
            (pending_since(10), 1, ChannelStatus::Open, 1, false),
            (ChannelStatus::Closed, 1, pending_since(10), 1, false),
            (pending_since(20), 1, pending_since(10), 1, false),
            (ChannelStatus::Open, 2, ChannelStatus::Closed, 1, false),
            (ChannelStatus::Open, 1, ChannelStatus::Open, 1, false),
        ];

        for (stored_status, stored_epoch, fresh_status, fresh_epoch, expected) in cases {
            let stored = channel(stored_status, stored_epoch)?;
            let fresh = channel(fresh_status, fresh_epoch)?;
            assert_eq!(
                is_later_state(&stored, &fresh),
                expected,
                "{stored_status} (epoch {stored_epoch}) -> {fresh_status} (epoch {fresh_epoch})"
            );
        }
        Ok(())
    }

    pub(crate) fn test_state(channel: ChannelEntry) -> anyhow::Result<BlokliTestStateBuilder> {
        let account_1 = AccountEntry {
            public_key: *OffchainKeypair::from_secret(&hex!(
                "60741b83b99e36aa0c1331578156e16b8e21166d01834abb6c64b103f885734d"
            ))?
            .public(),
            chain_addr: ChainKeypair::from_secret(&PRIVATE_KEY_1)?.public().to_address(),
            entry_type: AccountType::NotAnnounced,
            safe_address: Some([1u8; Address::SIZE].into()),
            key_id: 1.into(),
        };
        let account_2 = AccountEntry {
            public_key: *OffchainKeypair::from_secret(&hex!(
                "71bf1f42ebbfcd89c3e197a3fd7cda79b92499e509b6fefa0fe44d02821d146a"
            ))?
            .public(),
            chain_addr: ChainKeypair::from_secret(&PRIVATE_KEY_2)?.public().to_address(),
            entry_type: AccountType::NotAnnounced,
            safe_address: Some([2u8; Address::SIZE].into()),
            key_id: 2.into(),
        };

        Ok(BlokliTestStateBuilder::default()
            .with_accounts([
                (account_1, HoprBalance::new_base(100), XDaiBalance::new_base(1)),
                (account_2, HoprBalance::new_base(100), XDaiBalance::new_base(1)),
            ])
            .with_channels([channel])
            .with_hopr_network_chain_info("piz-palu-staging"))
    }

    #[tokio::test]
    async fn delayed_subscription_states_cannot_undo_reconciliation() -> anyhow::Result<()> {
        let cases = [
            (channel(pending_since(10), 1)?, channel(ChannelStatus::Open, 1)?),
            (channel(ChannelStatus::Closed, 1)?, channel(pending_since(10), 1)?),
            (channel(pending_since(20), 1)?, channel(pending_since(10), 1)?),
            (channel(ChannelStatus::Open, 2)?, channel(ChannelStatus::Closed, 1)?),
        ];
        for (current, delayed) in cases {
            let open = channel(ChannelStatus::Open, 1)?;
            let mut connector = create_connector(test_state(open)?.build_dynamic_client(MODULE_ADDR.into()))?;
            connector.connect().await?;
            let sync = connector.channel_sync();
            sync.apply(current).await?;

            assert!(sync.store_subscription(delayed).await?.is_none());
            assert_eq!(connector.channel_by_id(current.get_id())?, Some(current));
            assert_eq!(
                connector.channel_by_parties(&current.source, &current.destination)?,
                Some(current)
            );
            assert_eq!(sync.backend.get_channel_by_id(current.get_id())?, Some(current));
        }
        Ok(())
    }

    #[tokio::test]
    async fn subscription_updates_keep_balance_and_ticket_changes_within_one_status() -> anyhow::Result<()> {
        let open = channel(ChannelStatus::Open, 1)?;
        let mut connector = create_connector(test_state(open)?.build_dynamic_client(MODULE_ADDR.into()))?;
        connector.connect().await?;
        let updated = ChannelEntry::builder()
            .between(open.source, open.destination)
            .balance(HoprBalance::new_base(77))
            .ticket_index(2u32.into())
            .status(ChannelStatus::Open)
            .epoch(1)
            .build()?;

        let sync = connector.channel_sync();
        assert!(sync.store_subscription(updated).await?.is_some());
        assert_eq!(sync.backend.get_channel_by_id(open.get_id())?, Some(updated));
        assert_eq!(connector.channel_by_id(open.get_id())?, Some(updated));
        assert_eq!(
            connector.channel_by_parties(&open.source, &open.destination)?,
            Some(updated)
        );
        Ok(())
    }

    #[tokio::test]
    async fn subscription_can_discover_a_channel_without_query_reconciliation_adding_it() -> anyhow::Result<()> {
        let open = channel(ChannelStatus::Open, 1)?;
        let mut connector = create_connector(test_state(open)?.build_dynamic_client(MODULE_ADDR.into()))?;
        connector.connect().await?;
        let incoming = ChannelEntry::builder()
            .between(open.destination, open.source)
            .amount(10)
            .ticket_index(1)
            .status(ChannelStatus::Open)
            .epoch(1)
            .build()?;
        let sync = connector.channel_sync();
        assert_eq!(sync.refresh(incoming).await?, None);
        let update = sync.store_subscription(incoming).await?;
        assert!(matches!(update, Some((channel, None)) if channel == incoming));
        assert_eq!(connector.channel_by_id(incoming.get_id())?, Some(incoming));
        Ok(())
    }

    #[tokio::test]
    async fn a_closure_missed_by_the_subscription_is_recovered() -> anyhow::Result<()> {
        let open = channel(ChannelStatus::Open, 1)?;
        let mut connector = create_connector(test_state(open)?.build_dynamic_client(MODULE_ADDR.into()))?;
        connector.connect().await?;
        let events = connector.subscribe()?;

        // Both closure steps happen on-chain without the subscription delivering them.
        connector.client().hidden_state_update(|state| {
            if let Some(channel) = state.get_channel_by_id_mut(&(*open.get_id()).into()) {
                channel.status = blokli_client::api::types::ChannelStatus::Closed;
            }
        });

        let updated = connector.channel_sync().sync_own_channels(connector.client()).await?;

        assert_eq!(updated, 1);
        assert_eq!(
            connector.channel_by_id(open.get_id())?.map(|c| c.status),
            Some(ChannelStatus::Closed)
        );
        let event = tokio::time::timeout(Duration::from_secs(1), events.boxed().next()).await?;
        assert!(
            matches!(event, Some(ChainEvent::ChannelClosed(c)) if c.get_id() == open.get_id()),
            "expected ChannelClosed, got {event:?}"
        );

        assert_eq!(
            connector.channel_sync().sync_own_channels(connector.client()).await?,
            0,
            "nothing is left to update"
        );
        Ok(())
    }

    #[tokio::test]
    async fn an_older_state_from_blokli_does_not_replace_a_newer_stored_one() -> anyhow::Result<()> {
        let pending = channel(pending_since(10), 1)?;
        let mut connector = create_connector(test_state(pending)?.build_dynamic_client(MODULE_ADDR.into()))?;
        connector.connect().await?;

        let updated = connector.channel_sync().apply(channel(ChannelStatus::Open, 1)?).await?;

        assert_eq!(updated, None);
        assert_eq!(
            connector.channel_by_id(pending.get_id())?.map(|c| c.status),
            Some(pending.status)
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_channel_the_node_has_not_stored_is_not_added() -> anyhow::Result<()> {
        let open = channel(ChannelStatus::Open, 1)?;
        let mut connector = create_connector(test_state(open)?.build_dynamic_client(MODULE_ADDR.into()))?;
        connector.connect().await?;

        let unknown = ChannelEntry::builder()
            .between(
                &ChainKeypair::from_secret(&PRIVATE_KEY_2)?,
                &ChainKeypair::from_secret(&PRIVATE_KEY_1)?,
            )
            .amount(10)
            .ticket_index(1)
            .status(ChannelStatus::Open)
            .epoch(1)
            .build()?;

        assert_eq!(connector.channel_sync().apply(unknown).await?, None);
        assert_eq!(connector.channel_by_id(unknown.get_id())?, None);
        Ok(())
    }

    #[tokio::test]
    async fn a_node_without_an_account_has_nothing_to_sync() -> anyhow::Result<()> {
        let account_2 = AccountEntry {
            public_key: *OffchainKeypair::from_secret(&hex!(
                "71bf1f42ebbfcd89c3e197a3fd7cda79b92499e509b6fefa0fe44d02821d146a"
            ))?
            .public(),
            chain_addr: ChainKeypair::from_secret(&PRIVATE_KEY_2)?.public().to_address(),
            entry_type: AccountType::NotAnnounced,
            safe_address: Some([2u8; Address::SIZE].into()),
            key_id: 2.into(),
        };
        let blokli_client = BlokliTestStateBuilder::default()
            .with_accounts([(account_2, HoprBalance::new_base(100), XDaiBalance::new_base(1))])
            .with_hopr_network_chain_info("piz-palu-staging")
            .build_dynamic_client(MODULE_ADDR.into());
        let mut connector = create_connector(blokli_client)?;
        connector.connect().await?;

        assert_eq!(connector.channel_sync().sync_own_channels(connector.client()).await?, 0);
        Ok(())
    }

    #[tokio::test]
    async fn a_channel_to_an_unknown_account_is_skipped() -> anyhow::Result<()> {
        let open = channel(ChannelStatus::Open, 1)?;
        let mut connector = create_connector(test_state(open)?.build_dynamic_client(MODULE_ADDR.into()))?;
        connector.connect().await?;

        // A channel whose other end is an account the node has not received yet.
        let unknown_id = const_hex::encode([7u8; 32]);
        connector.client().hidden_state_update(|state| {
            state.channels.insert(
                unknown_id.clone(),
                blokli_client::api::types::Channel {
                    balance: blokli_client::api::types::TokenValueString("10 wxHOPR".into()),
                    closure_time: None,
                    concrete_channel_id: unknown_id.clone(),
                    destination: 99,
                    epoch: 1,
                    source: 1,
                    status: blokli_client::api::types::ChannelStatus::Closed,
                    ticket_index: blokli_client::api::types::Uint64("0".into()),
                },
            );
        });

        assert_eq!(connector.channel_sync().sync_own_channels(connector.client()).await?, 0);
        assert_eq!(
            connector.channel_by_id(open.get_id())?.map(|c| c.status),
            Some(ChannelStatus::Open)
        );
        Ok(())
    }
}
