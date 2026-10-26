//! Keeps the node's own channels in line with Blokli when channel updates were missed.
//!
//! Channel updates normally arrive through the channel graph subscription. Updates sent while that subscription was
//! disconnected, or dropped by Blokli because the subscription fell behind, are lost. The snapshot Blokli replays
//! after a reconnect does not help with closures either, because it holds no closed channels. A node that misses
//! a closure keeps the channel as open, and then sends the wrong closure transaction for it.
//!
//! [`ChannelSync`] therefore reads the node's own channels from Blokli again, every
//! [`OWN_CHANNELS_SYNC_INTERVAL`], and stores the ones that moved on.

use std::{cmp::Ordering, time::Duration};

use blokli_client::api::{BlokliQueryClient, ChannelFilter, ChannelSelector, types::Channel};
use hopr_api::{
    chain::{ChainEvent, HoprKeyIdent},
    types::{internal::prelude::*, primitive::prelude::*},
};
use petgraph::prelude::DiGraphMap;

use crate::{
    backend::Backend,
    errors::ConnectorError,
    utils::{model_to_channel_entry, process_channel_changes_into_events},
};

/// How often the node's own channels are read from Blokli again.
///
/// This covers updates missed while the channel graph subscription was disconnected or had ended, and updates that
/// Blokli dropped while the subscription stayed connected.
pub(crate) const OWN_CHANNELS_SYNC_INTERVAL: Duration = Duration::from_mins(10);

/// Position of a status in the life of a channel within one epoch.
fn status_rank(status: &ChannelStatus) -> u8 {
    match status {
        ChannelStatus::Open => 0,
        ChannelStatus::PendingToClose(_) => 1,
        ChannelStatus::Closed => 2,
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
        Ordering::Equal => match (stored.status, fresh.status) {
            // The closure was started again, which moves the closure time.
            (ChannelStatus::PendingToClose(stored_time), ChannelStatus::PendingToClose(fresh_time)) => {
                fresh_time > stored_time
            }
            (stored_status, fresh_status) => status_rank(&fresh_status) > status_rank(&stored_status),
        },
    }
}

/// A channel as read from Blokli, with the key ids of its ends.
#[derive(Clone, Copy, Debug)]
pub(crate) struct FreshChannel {
    pub(crate) source: HoprKeyIdent,
    pub(crate) destination: HoprKeyIdent,
    pub(crate) channel: ChannelEntry,
}

/// The state of a channel after [`ChannelSync::apply`].
#[derive(Clone, Copy, Debug)]
pub(crate) struct SyncedChannel {
    /// The latest known state: the fresh one if it was stored, otherwise the stored one.
    pub(crate) channel: ChannelEntry,
    /// Whether the fresh state replaced the stored one.
    pub(crate) updated: bool,
}

/// Writes channel states read from Blokli into the connector's backend, caches and graph.
pub(crate) struct ChannelSync<B> {
    pub(crate) backend: std::sync::Arc<B>,
    pub(crate) graph: std::sync::Arc<parking_lot::RwLock<DiGraphMap<HoprKeyIdent, ChannelId, ahash::RandomState>>>,
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
            graph: self.graph.clone(),
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
    /// Stores `fresh` if it is a [later state](is_later_state) than the stored channel, and sends the chain events for
    /// the change.
    ///
    /// A closed channel the node has never seen is not stored: it would only add a channel that does not exist any
    /// more.
    pub(crate) async fn apply(&self, fresh: FreshChannel) -> Result<SyncedChannel, ConnectorError> {
        let sync = self.clone();
        let (synced, previous) = hopr_utils::runtime::prelude::spawn_blocking(move || {
            let _guard = sync.write_lock.lock();
            let channel = fresh.channel;
            let stored = sync
                .backend
                .get_channel_by_id(channel.get_id())
                .map_err(ConnectorError::backend)?;

            let replace = match &stored {
                Some(stored) => is_later_state(stored, &channel),
                None => channel.status != ChannelStatus::Closed,
            };
            if !replace {
                let latest = stored.unwrap_or(channel);
                return Ok::<_, ConnectorError>((
                    SyncedChannel {
                        channel: latest,
                        updated: false,
                    },
                    None,
                ));
            }

            sync.graph
                .write()
                .add_edge(fresh.source, fresh.destination, *channel.get_id());
            sync.backend.insert_channel(channel).map_err(ConnectorError::backend)?;
            sync.channel_by_id.insert(*channel.get_id(), Some(channel));
            sync.channel_by_parties
                .insert(ChannelParties::from(&channel), Some(channel));

            Ok((SyncedChannel { channel, updated: true }, Some(stored)))
        })
        .await
        .map_err(ConnectorError::backend)??;

        if let Some(stored) = previous {
            let channel = synced.channel;
            match stored {
                Some(stored) => {
                    tracing::warn!(
                        channel_id = %channel.get_id(),
                        stored_status = %stored.status,
                        stored_epoch = stored.channel_epoch,
                        status = %channel.status,
                        epoch = channel.channel_epoch,
                        "own channel was out of date, updated it from Blokli"
                    );
                    process_channel_changes_into_events(channel, stored.diff(&channel), &self.me, &self.event_tx).await;
                }
                None => {
                    tracing::warn!(
                        channel_id = %channel.get_id(),
                        status = %channel.status,
                        epoch = channel.channel_epoch,
                        "own channel was missing, added it from Blokli"
                    );
                    let _ = self.event_tx.broadcast_direct(ChainEvent::ChannelOpened(channel)).await;
                }
            }
        }

        Ok(synced)
    }

    /// Turns a channel read from Blokli into a [`FreshChannel`], looking up the addresses of its ends.
    ///
    /// Returns `None` when an end is an account the node does not know yet.
    pub(crate) async fn resolve(&self, model: Channel) -> Result<Option<FreshChannel>, ConnectorError> {
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

        Ok(Some(FreshChannel {
            source,
            destination,
            channel: model_to_channel_entry(&model, source_account.chain_addr, destination_account.chain_addr)?,
        }))
    }

    /// Reads all the node's own channels from Blokli, closed ones included, and stores those that moved on.
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
                && self.apply(fresh).await?.updated
            {
                updated += 1;
            }
        }

        tracing::debug!(checked, updated, "synced own channels with Blokli");
        Ok(updated)
    }
}

#[cfg(test)]
mod tests {
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

    fn channel(status: ChannelStatus, epoch: u32) -> anyhow::Result<ChannelEntry> {
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

    fn pending_since(secs: u64) -> ChannelStatus {
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

    fn test_state(channel: ChannelEntry) -> anyhow::Result<BlokliTestStateBuilder> {
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

        let synced = connector
            .channel_sync()
            .apply(FreshChannel {
                source: 1.into(),
                destination: 2.into(),
                channel: channel(ChannelStatus::Open, 1)?,
            })
            .await?;

        assert!(!synced.updated);
        assert_eq!(synced.channel.status, pending.status);
        assert_eq!(
            connector.channel_by_id(pending.get_id())?.map(|c| c.status),
            Some(pending.status)
        );
        Ok(())
    }
}
