//! Backfill of the node's own channels from Blokli.
//!
//! The channel view is built from the graph subscription alone, so an entry that never arrives, or arrives
//! unreadable, leaves a channel unknown or stale until the next restart. The reconciliation queries the node's own
//! channels in every status and applies what differs, raising the events the missed update would have raised.
//! Channels between other peers are not reconciled.

use std::collections::HashMap;

use blokli_client::api::{
    AccountSelector, BlokliQueryClient, ChannelFilter, ChannelSelector, KeyId,
    types::{Account, Channel},
};
use hopr_api::{
    chain::{ChainEvent, HoprKeyIdent},
    types::{internal::prelude::*, primitive::prelude::*},
};
use petgraph::prelude::DiGraphMap;

use crate::{
    backend::Backend,
    errors::ConnectorError,
    utils::{
        event_for_first_seen_channel, model_to_account_entry, model_to_channel_entry,
        process_channel_changes_into_events,
    },
};

type Graph = std::sync::Arc<parking_lot::RwLock<DiGraphMap<HoprKeyIdent, ChannelId, ahash::RandomState>>>;
type ChannelByIdCache = moka::sync::Cache<ChannelId, Option<ChannelEntry>, ahash::RandomState>;
type ChannelByPartiesCache = moka::sync::Cache<ChannelParties, Option<ChannelEntry>, ahash::RandomState>;

/// What one reconciliation pass did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReconcileStats {
    /// Channel rows returned by Blokli.
    pub(crate) seen: usize,
    /// Channels that were unknown or different locally and have been updated.
    pub(crate) healed: usize,
    /// Rows that could not be converted or stored.
    pub(crate) failed: usize,
}

pub(crate) struct OwnChannelReconciler<C, B> {
    pub(crate) client: std::sync::Arc<C>,
    pub(crate) backend: std::sync::Arc<B>,
    pub(crate) graph: Graph,
    pub(crate) channel_by_id: ChannelByIdCache,
    pub(crate) channel_by_parties: ChannelByPartiesCache,
    pub(crate) event_tx: async_broadcast::Sender<ChainEvent>,
    pub(crate) me: Address,
}

impl<C, B> OwnChannelReconciler<C, B>
where
    C: BlokliQueryClient + Send + Sync + 'static,
    B: Backend + Send + Sync + 'static,
{
    /// Resolves the key ID of the node's own account, or `None` while it is not bound on chain yet.
    async fn own_key_id(&self) -> Result<Option<KeyId>, ConnectorError> {
        let backend = self.backend.clone();
        let me = self.me;
        let local = hopr_utils::runtime::prelude::spawn_blocking(move || backend.get_account_by_address(&me))
            .await
            .map_err(ConnectorError::backend)?
            .map_err(ConnectorError::backend)?;
        if let Some(account) = local {
            return Ok(Some(u32::from(account.key_id)));
        }

        Ok(self
            .client
            .query_accounts(AccountSelector::Address(self.me.into()))
            .await?
            .first()
            .map(|account| account.keyid as u32))
    }

    /// Resolves the address of an account, from the backend first and from Blokli otherwise.
    async fn resolve_address(
        &self,
        key_id: i32,
        resolved: &mut HashMap<i32, Address>,
    ) -> Result<Address, ConnectorError> {
        if let Some(address) = resolved.get(&key_id) {
            return Ok(*address);
        }

        let backend = self.backend.clone();
        let ident = HoprKeyIdent::from(key_id as u32);
        let local = hopr_utils::runtime::prelude::spawn_blocking(move || backend.get_account_by_id(&ident))
            .await
            .map_err(ConnectorError::backend)?
            .map_err(ConnectorError::backend)?;
        let address = match local {
            Some(account) => account.chain_addr,
            None => {
                let accounts: Vec<Account> = self
                    .client
                    .query_accounts(AccountSelector::KeyId(key_id as u32))
                    .await?;
                let account = accounts
                    .into_iter()
                    .next()
                    .ok_or_else(|| ConnectorError::TypeConversion(format!("unknown account key id {key_id}")))?;
                model_to_account_entry(account)?.chain_addr
            }
        };
        resolved.insert(key_id, address);
        Ok(address)
    }

    /// Runs one pass over the outgoing and incoming channels of the node.
    ///
    /// A failing query or a row that cannot be converted is logged and skipped, so one bad item never hides the rest.
    pub(crate) async fn reconcile(&self) -> Result<ReconcileStats, ConnectorError> {
        let Some(own_key_id) = self.own_key_id().await? else {
            tracing::debug!("own account is not bound on chain yet, skipping the channel reconciliation");
            return Ok(ReconcileStats::default());
        };

        let mut stats = ReconcileStats::default();
        let mut resolved = HashMap::new();
        let mut last_error = None;
        let mut applied = std::collections::HashSet::new();

        for filter in [
            ChannelFilter::SourceKeyId(own_key_id),
            ChannelFilter::DestinationKeyId(own_key_id),
        ] {
            let rows = match self
                .client
                .query_channels(ChannelSelector {
                    filter: Some(filter),
                    ..Default::default()
                })
                .await
            {
                Ok(list) => list.channels,
                Err(error) => {
                    tracing::warn!(%error, "failed to query own channels for reconciliation");
                    last_error = Some(ConnectorError::from(error));
                    continue;
                }
            };

            for row in rows {
                // A channel from the node to itself would match both queries.
                if !applied.insert(row.concrete_channel_id.clone()) {
                    continue;
                }
                stats.seen += 1;
                match self.apply(&row, &mut resolved).await {
                    Ok(true) => stats.healed += 1,
                    Ok(false) => {}
                    Err(error) => {
                        tracing::warn!(%error, id = %row.concrete_channel_id, "failed to reconcile channel");
                        stats.failed += 1;
                    }
                }
            }
        }

        match last_error {
            Some(error) if stats.seen == 0 => Err(error),
            _ => Ok(stats),
        }
    }

    /// Stores the channel when it differs from the local view and returns whether it did.
    async fn apply(&self, row: &Channel, resolved: &mut HashMap<i32, Address>) -> Result<bool, ConnectorError> {
        let source = self.resolve_address(row.source, resolved).await?;
        let destination = self.resolve_address(row.destination, resolved).await?;
        let channel = model_to_channel_entry(row, source, destination)?;

        let backend = self.backend.clone();
        let graph = self.graph.clone();
        let (src_key, dst_key) = (
            HoprKeyIdent::from(row.source as u32),
            HoprKeyIdent::from(row.destination as u32),
        );
        let old = hopr_utils::runtime::prelude::spawn_blocking(move || {
            let old = backend.get_channel_by_id(channel.get_id())?;
            if old != Some(channel) {
                backend.insert_channel(channel)?;
                graph.write().add_edge(src_key, dst_key, *channel.get_id());
            }
            Ok::<_, B::Error>(old)
        })
        .await
        .map_err(ConnectorError::backend)?
        .map_err(ConnectorError::backend)?;

        if old == Some(channel) {
            return Ok(false);
        }

        // Rather update the cached entries than invalidating them, which also replaces a cached `None`.
        self.channel_by_id.insert(*channel.get_id(), Some(channel));
        self.channel_by_parties
            .insert(ChannelParties::from(&channel), Some(channel));

        match old {
            Some(old) => {
                tracing::debug!(id = %channel.get_id(), "channel healed by reconciliation");
                process_channel_changes_into_events(channel, old.diff(&channel), &self.me, &self.event_tx).await;
            }
            None => {
                tracing::debug!(id = %channel.get_id(), "channel learned by reconciliation");
                if let Some(event) = event_for_first_seen_channel(channel) {
                    let _ = self.event_tx.broadcast_direct(event).await;
                }
            }
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use hopr_api::types::crypto::prelude::{ChainKeypair, Keypair, OffchainKeypair};

    use super::*;
    use crate::{
        InMemoryBackend,
        testing::{BlokliTestClient, BlokliTestStateBuilder, StaticState},
    };

    struct Fixture {
        reconciler: OwnChannelReconciler<BlokliTestClient<StaticState>, InMemoryBackend>,
        events: async_broadcast::Receiver<ChainEvent>,
        me: ChainKeypair,
        peer: ChainKeypair,
        other: ChainKeypair,
    }

    fn account(key: &ChainKeypair, key_id: u32) -> AccountEntry {
        AccountEntry {
            public_key: *OffchainKeypair::random().public(),
            chain_addr: key.public().to_address(),
            entry_type: AccountType::NotAnnounced,
            safe_address: None,
            key_id: key_id.into(),
        }
    }

    fn channel(src: &ChainKeypair, dst: &ChainKeypair, status: ChannelStatus) -> ChannelEntry {
        ChannelEntry::builder()
            .between(src, dst)
            .amount(10)
            .ticket_index(0)
            .status(status)
            .epoch(1)
            .build()
            .unwrap()
    }

    /// `me` is registered in Blokli unless `bound` is false. The connector never subscribes, so nothing in
    /// `blokli_channels` is delivered on the graph stream.
    fn fixture(
        blokli_channels: impl Fn(&ChainKeypair, &ChainKeypair, &ChainKeypair) -> Vec<ChannelEntry>,
        bound: bool,
    ) -> Fixture {
        let (me, peer, other) = (ChainKeypair::random(), ChainKeypair::random(), ChainKeypair::random());
        let mut accounts = vec![account(&peer, 2), account(&other, 3)];
        if bound {
            accounts.push(account(&me, 1));
        }
        let channels = if bound {
            blokli_channels(&me, &peer, &other)
        } else {
            vec![]
        };
        let client = BlokliTestStateBuilder::default()
            .with_accounts(
                accounts
                    .into_iter()
                    .map(|a| (a, HoprBalance::zero(), XDaiBalance::zero())),
            )
            .with_channels(channels)
            .build_static_client();

        let (mut tx, rx) = async_broadcast::broadcast(32);
        tx.set_overflow(true);
        fn cache<K: std::hash::Hash + Eq + Send + Sync + 'static>()
        -> moka::sync::Cache<K, Option<ChannelEntry>, ahash::RandomState> {
            moka::sync::CacheBuilder::new(100).build_with_hasher(ahash::RandomState::default())
        }
        Fixture {
            reconciler: OwnChannelReconciler {
                client: std::sync::Arc::new(client),
                backend: std::sync::Arc::new(InMemoryBackend::default()),
                graph: Default::default(),
                channel_by_id: cache(),
                channel_by_parties: cache(),
                event_tx: tx,
                me: me.public().to_address(),
            },
            events: rx,
            me,
            peer,
            other,
        }
    }

    #[tokio::test]
    async fn reconciliation_should_learn_own_channels_never_delivered_on_the_stream() -> anyhow::Result<()> {
        let mut f = fixture(
            |me, peer, other| {
                vec![
                    channel(me, peer, ChannelStatus::Open),
                    channel(peer, me, ChannelStatus::Open),
                    // not ours: must not be reconciled
                    channel(peer, other, ChannelStatus::Open),
                ]
            },
            true,
        );
        let outgoing = channel(&f.me, &f.peer, ChannelStatus::Open);
        let incoming = channel(&f.peer, &f.me, ChannelStatus::Open);
        let foreign = channel(&f.peer, &f.other, ChannelStatus::Open);

        // negatively cached before, as a failed lookup would have left it
        f.reconciler.channel_by_id.insert(*outgoing.get_id(), None);

        let stats = f.reconciler.reconcile().await?;

        assert_eq!(
            ReconcileStats {
                seen: 2,
                healed: 2,
                failed: 0
            },
            stats
        );
        assert_eq!(
            Some(outgoing),
            f.reconciler.backend.get_channel_by_id(outgoing.get_id())?
        );
        assert_eq!(
            Some(incoming),
            f.reconciler.backend.get_channel_by_id(incoming.get_id())?
        );
        assert_eq!(None, f.reconciler.backend.get_channel_by_id(foreign.get_id())?);
        assert_eq!(Some(Some(outgoing)), f.reconciler.channel_by_id.get(outgoing.get_id()));
        assert_eq!(
            Some(Some(incoming)),
            f.reconciler.channel_by_parties.get(&ChannelParties::from(&incoming))
        );
        assert_eq!(2, f.reconciler.graph.read().edge_count());

        let mut ids = vec![];
        for _ in 0..2 {
            match f.events.try_recv()? {
                ChainEvent::ChannelOpened(c) => ids.push(*c.get_id()),
                other => anyhow::bail!("unexpected event {other}"),
            }
        }
        ids.sort();
        let mut expected = vec![*outgoing.get_id(), *incoming.get_id()];
        expected.sort();
        assert_eq!(expected, ids);

        // a second pass finds nothing to heal
        assert_eq!(0, f.reconciler.reconcile().await?.healed);
        assert!(f.events.try_recv().is_err());
        Ok(())
    }

    #[tokio::test]
    async fn reconciliation_should_close_an_own_channel_stuck_open_locally() -> anyhow::Result<()> {
        let mut f = fixture(|me, peer, _| vec![channel(me, peer, ChannelStatus::Closed)], true);
        let open = channel(&f.me, &f.peer, ChannelStatus::Open);
        let closed = channel(&f.me, &f.peer, ChannelStatus::Closed);

        f.reconciler.backend.insert_channel(open)?;
        f.reconciler.channel_by_id.insert(*open.get_id(), Some(open));
        f.reconciler
            .channel_by_parties
            .insert(ChannelParties::from(&open), Some(open));

        let stats = f.reconciler.reconcile().await?;

        assert_eq!(1, stats.healed);
        assert_eq!(Some(closed), f.reconciler.backend.get_channel_by_id(open.get_id())?);
        assert_eq!(Some(Some(closed)), f.reconciler.channel_by_id.get(open.get_id()));
        assert_eq!(
            Some(Some(closed)),
            f.reconciler.channel_by_parties.get(&ChannelParties::from(&open))
        );
        assert!(matches!(f.events.try_recv()?, ChainEvent::ChannelClosed(c) if c == closed));
        Ok(())
    }

    #[tokio::test]
    async fn reconciliation_should_do_nothing_while_the_own_account_is_not_bound() -> anyhow::Result<()> {
        let mut f = fixture(|_, _, _| vec![], false);

        assert_eq!(ReconcileStats::default(), f.reconciler.reconcile().await?);
        assert!(f.events.try_recv().is_err());
        Ok(())
    }
}
