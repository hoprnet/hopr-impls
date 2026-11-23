//! Backfill of the node's own channels from Blokli.
//!
//! The channel view is built from the graph subscription alone, so an entry that never arrives, or arrives
//! unreadable, leaves a channel unknown or stale until the next restart. The reconciliation queries the node's own
//! channels in every status and applies what differs, raising the events the missed update would have raised.
//! Channels between other peers are not reconciled.
//!
//! A pass first reads everything from Blokli under a timeout, then applies the rows without any await point that
//! could be cancelled, so a timeout can never leave a channel half written.

use std::collections::HashMap;

use blokli_client::api::{
    AccountSelector, BlokliQueryClient, ChannelFilter, ChannelSelector, KeyId,
    types::{Account, Channel},
};
use futures_time::future::FutureExt as FuturesTimeExt;
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

/// Upper bound for reading everything one pass needs from Blokli.
const RECONCILE_FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

type Graph = std::sync::Arc<parking_lot::RwLock<DiGraphMap<HoprKeyIdent, ChannelId, ahash::RandomState>>>;
type ChannelByIdCache = moka::sync::Cache<ChannelId, Option<ChannelEntry>, ahash::RandomState>;
type ChannelByPartiesCache = moka::sync::Cache<ChannelParties, Option<ChannelEntry>, ahash::RandomState>;

/// Position of a status in the lifecycle of one channel epoch.
fn status_rank(status: &ChannelStatus) -> u8 {
    match status {
        ChannelStatus::Open => 0,
        ChannelStatus::PendingToClose(_) => 1,
        ChannelStatus::Closed => 2,
    }
}

/// Whether `new` is strictly newer than `old`, and so may replace it when it comes from a query.
///
/// A query can be older than what the subscription has delivered since. The epoch decides first, then the status
/// (a reopen needs a higher epoch), then the ticket index. When those are all equal there is no way to tell which
/// value is newer, so the row is not newer and the subscription stays authoritative. This leaves one known gap: a
/// channel that went from PendingToClose back to Open within the same epoch is not healed by a query.
fn is_newer(old: &ChannelEntry, new: &ChannelEntry) -> bool {
    (new.channel_epoch, status_rank(&new.status), new.ticket_index)
        > (old.channel_epoch, status_rank(&old.status), old.ticket_index)
}

/// Outcome of [`upsert_channel`].
pub(crate) enum Upsert {
    /// Nothing was written: the channel is unchanged, or the update was older than the local state.
    ///
    /// `cache_repaired` tells whether a cached entry that disagreed with the backend was overwritten.
    Skipped { cache_repaired: bool },
    /// The channel was written; holds the value it replaced.
    Written(Option<ChannelEntry>),
}

/// Writes a channel to the backend, the graph and both caches as one step.
///
/// The graph write lock is held for the whole operation, and every writer of channels goes through this function,
/// so a writer never observes or overwrites another one halfway. With `only_if_not_older`, an update that would move
/// the channel backwards, or that is not strictly newer, is skipped.
pub(crate) fn upsert_channel<B: Backend>(
    backend: &B,
    graph: &Graph,
    channel_by_id: &ChannelByIdCache,
    channel_by_parties: &ChannelByPartiesCache,
    (src, dst): (HoprKeyIdent, HoprKeyIdent),
    channel: ChannelEntry,
    only_if_not_older: bool,
) -> Result<Upsert, B::Error> {
    let mut graph = graph.write();
    if only_if_not_older {
        match backend.get_channel_by_id(channel.get_id())? {
            Some(old) if !is_newer(&old, &channel) => {
                // The backend holds the newer (or the same) value, so it is what the caches must agree with,
                // not the row. An entry that is not cached is left to be loaded from the backend on demand.
                let parties = ChannelParties::from(&old);
                let stale_by_id = channel_by_id
                    .get(old.get_id())
                    .is_some_and(|cached| cached != Some(old));
                let stale_by_parties = channel_by_parties
                    .get(&parties)
                    .is_some_and(|cached| cached != Some(old));
                if stale_by_id {
                    super::cache::put(channel_by_id, old.get_id(), old);
                }
                if stale_by_parties {
                    super::cache::put(channel_by_parties, &parties, old);
                }
                return Ok(Upsert::Skipped {
                    cache_repaired: stale_by_id || stale_by_parties,
                });
            }
            _ => {}
        }
    }
    graph.add_edge(src, dst, *channel.get_id());
    let old = backend.insert_channel(channel)?;
    // Rather update the cached entries than invalidating them, which also replaces a cached `None`.
    super::cache::put(channel_by_id, channel.get_id(), channel);
    super::cache::put(channel_by_parties, &ChannelParties::from(&channel), channel);
    Ok(Upsert::Written(old))
}

/// What applying one row did.
enum Applied {
    Healed,
    CacheRepaired,
    Unchanged,
}

/// A channel row of Blokli converted for storing.
struct Fetched {
    channel: ChannelEntry,
    keys: (HoprKeyIdent, HoprKeyIdent),
}

/// What one reconciliation pass did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReconcileStats {
    /// Channel rows returned by Blokli.
    pub(crate) seen: usize,
    /// Channels that were unknown or different locally and have been updated.
    pub(crate) healed: usize,
    /// Rows that could not be converted or stored.
    pub(crate) failed: usize,
    /// Channels whose cached entry disagreed with the backend and was overwritten, without any event.
    pub(crate) cache_repaired: usize,
    /// Direction queries that failed, so the pass did not see every channel.
    pub(crate) incomplete: usize,
}

pub(crate) struct OwnChannelReconciler<C, B> {
    pub(crate) client: std::sync::Arc<C>,
    pub(crate) backend: std::sync::Arc<B>,
    pub(crate) graph: Graph,
    pub(crate) channel_by_id: ChannelByIdCache,
    pub(crate) channel_by_parties: ChannelByPartiesCache,
    pub(crate) event_tx: async_broadcast::Sender<ChainEvent>,
    pub(crate) me: Address,
    /// Set while a pass is running, so passes never overlap.
    pub(crate) in_flight: std::sync::atomic::AtomicBool,
}

/// Clears the in-flight flag when the pass ends, however it ends.
struct InFlightGuard<'a>(&'a std::sync::atomic::AtomicBool);

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::Release);
    }
}

fn key_id(raw: i32, what: &str) -> Result<KeyId, ConnectorError> {
    u32::try_from(raw).map_err(|_| ConnectorError::TypeConversion(format!("invalid {what} key id {raw}")))
}

impl<C, B> OwnChannelReconciler<C, B>
where
    C: BlokliQueryClient + Send + Sync + 'static,
    B: Backend + Send + Sync + 'static,
{
    /// Starts a pass in the background unless one is still running.
    ///
    /// The pass runs in its own task so that slow queries never hold up the handling of the subscriptions.
    pub(crate) fn spawn_pass(self: &std::sync::Arc<Self>) {
        if self.in_flight.swap(true, std::sync::atomic::Ordering::AcqRel) {
            tracing::debug!("previous channel reconciliation is still running, skipping this one");
            return;
        }
        let this = self.clone();
        hopr_utils::runtime::prelude::spawn(async move {
            let _guard = InFlightGuard(&this.in_flight);
            match this.reconcile().await {
                Ok(stats) if stats.failed > 0 || stats.incomplete > 0 => {
                    tracing::warn!(?stats, "own channels reconciled incompletely")
                }
                Ok(stats) => tracing::debug!(?stats, "own channels reconciled"),
                Err(error) => tracing::warn!(%error, "own channel reconciliation failed"),
            }
        });
    }

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

        self.client
            .query_accounts(AccountSelector::Address(self.me.into()))
            .await?
            .first()
            .map(|account| key_id(account.keyid, "own account"))
            .transpose()
    }

    /// Resolves the address of an account, from the backend first and from Blokli otherwise.
    ///
    /// Accounts learned here are not persisted: the account subscription is the only writer of accounts, because
    /// storing one also updates the key mappings, the announced-account count and the graph nodes, and a copy
    /// written from here could skip or race those.
    async fn resolve_address(
        &self,
        raw_key_id: i32,
        resolved: &mut HashMap<i32, (Address, HoprKeyIdent)>,
    ) -> Result<(Address, HoprKeyIdent), ConnectorError> {
        if let Some(found) = resolved.get(&raw_key_id) {
            return Ok(*found);
        }

        let key = key_id(raw_key_id, "account")?;
        let ident = HoprKeyIdent::from(key);
        let backend = self.backend.clone();
        let local = hopr_utils::runtime::prelude::spawn_blocking(move || backend.get_account_by_id(&ident))
            .await
            .map_err(ConnectorError::backend)?
            .map_err(ConnectorError::backend)?;
        let address = match local {
            Some(account) => account.chain_addr,
            None => {
                let accounts: Vec<Account> = self.client.query_accounts(AccountSelector::KeyId(key)).await?;
                let account = accounts
                    .into_iter()
                    .next()
                    .ok_or_else(|| ConnectorError::TypeConversion(format!("unknown account key id {key}")))?;
                model_to_account_entry(account)?.chain_addr
            }
        };
        resolved.insert(raw_key_id, (address, ident));
        Ok((address, ident))
    }

    /// Reads the node's outgoing and incoming channels from Blokli and converts them.
    ///
    /// A failing query or a row that cannot be converted is logged and skipped, so one bad item never hides the
    /// rest. Returns the rows, the number of failed rows and the last query error.
    async fn fetch(&self) -> Result<(Vec<Fetched>, usize, usize, Option<ConnectorError>), ConnectorError> {
        let Some(own_key_id) = self.own_key_id().await? else {
            tracing::debug!("own account is not bound on chain yet, skipping the channel reconciliation");
            return Ok((vec![], 0, 0, None));
        };

        let mut fetched = Vec::new();
        let mut failed = 0;
        let mut incomplete = 0;
        let mut last_error = None;
        let mut resolved = HashMap::new();
        let mut seen_ids = std::collections::HashSet::new();

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
                    incomplete += 1;
                    last_error = Some(ConnectorError::from(error));
                    continue;
                }
            };

            for row in rows {
                // A channel from the node to itself would match both queries.
                if !seen_ids.insert(row.concrete_channel_id.clone()) {
                    continue;
                }
                match self.convert(&row, &mut resolved).await {
                    Ok(item) => fetched.push(item),
                    Err(error) => {
                        tracing::warn!(%error, id = %row.concrete_channel_id, "failed to convert channel for reconciliation");
                        failed += 1;
                    }
                }
            }
        }
        Ok((fetched, failed, incomplete, last_error))
    }

    async fn convert(
        &self,
        row: &Channel,
        resolved: &mut HashMap<i32, (Address, HoprKeyIdent)>,
    ) -> Result<Fetched, ConnectorError> {
        let (source, src_key) = self.resolve_address(row.source, resolved).await?;
        let (destination, dst_key) = self.resolve_address(row.destination, resolved).await?;
        Ok(Fetched {
            channel: model_to_channel_entry(row, source, destination)?,
            keys: (src_key, dst_key),
        })
    }

    /// Runs one pass over the outgoing and incoming channels of the node.
    ///
    /// Only reading from Blokli is subject to the timeout; applying the rows is not cancellable by it.
    pub(crate) async fn reconcile(&self) -> Result<ReconcileStats, ConnectorError> {
        let (rows, mut failed, incomplete, last_error) = self
            .fetch()
            .timeout(futures_time::time::Duration::from(RECONCILE_FETCH_TIMEOUT))
            .await
            .map_err(|_| ConnectorError::InvalidState("channel reconciliation timed out"))??;

        let mut stats = ReconcileStats {
            seen: rows.len() + failed,
            incomplete,
            ..Default::default()
        };
        for row in rows {
            match self.apply(row).await {
                Ok(Applied::Healed) => stats.healed += 1,
                Ok(Applied::CacheRepaired) => stats.cache_repaired += 1,
                Ok(Applied::Unchanged) => {}
                Err(error) => {
                    tracing::warn!(%error, "failed to apply reconciled channel");
                    failed += 1;
                }
            }
        }
        stats.failed = failed;

        match last_error {
            Some(error) if stats.seen == 0 => Err(error),
            Some(error) => {
                tracing::warn!(%error, "channel reconciliation was incomplete because a query failed");
                Ok(stats)
            }
            None => Ok(stats),
        }
    }

    /// Stores the channel unless it is unchanged or older than the local view, and returns whether it did.
    async fn apply(&self, row: Fetched) -> Result<Applied, ConnectorError> {
        let Fetched { channel, keys } = row;
        let (backend, graph) = (self.backend.clone(), self.graph.clone());
        let (by_id, by_parties) = (self.channel_by_id.clone(), self.channel_by_parties.clone());
        let upsert = hopr_utils::runtime::prelude::spawn_blocking(move || {
            upsert_channel(backend.as_ref(), &graph, &by_id, &by_parties, keys, channel, true)
        })
        .await
        .map_err(ConnectorError::backend)?
        .map_err(ConnectorError::backend)?;

        match upsert {
            Upsert::Skipped { cache_repaired: true } => {
                tracing::debug!(id = %channel.get_id(), "stale channel cache entry repaired by reconciliation");
                Ok(Applied::CacheRepaired)
            }
            Upsert::Skipped { cache_repaired: false } => Ok(Applied::Unchanged),
            Upsert::Written(Some(old)) => {
                tracing::debug!(id = %channel.get_id(), "channel healed by reconciliation");
                process_channel_changes_into_events(channel, old.diff(&channel), &self.me, &self.event_tx).await;
                Ok(Applied::Healed)
            }
            Upsert::Written(None) => {
                tracing::debug!(id = %channel.get_id(), "channel learned by reconciliation");
                if let Some(event) = event_for_first_seen_channel(channel) {
                    let _ = self.event_tx.broadcast_direct(event).await;
                }
                Ok(Applied::Healed)
            }
        }
    }
}

/// What closing the channels missing from a snapshot did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SweepStats {
    /// Known channels that are not closed and that the snapshot did not hold.
    pub(crate) missing: usize,
    /// Of those, the channels that were closed.
    pub(crate) closed: usize,
    /// Channels that could not be closed.
    pub(crate) failed: usize,
}

impl<C, B> OwnChannelReconciler<C, B>
where
    C: BlokliQueryClient + Send + Sync + 'static,
    B: Backend + Send + Sync + 'static,
{
    /// Starts closing the channels missing from a snapshot in the background.
    ///
    /// Like [`spawn_pass`](Self::spawn_pass), it runs in its own task so that it never holds up the handling of the
    /// subscriptions.
    pub(crate) fn spawn_sweep(self: &std::sync::Arc<Self>, snapshot: std::collections::HashSet<ChannelId>) {
        let this = self.clone();
        hopr_utils::runtime::prelude::spawn(async move {
            match this.close_missing(&snapshot).await {
                Ok(stats) if stats.failed > 0 => {
                    tracing::warn!(?stats, "channels missing from a snapshot closed incompletely")
                }
                Ok(stats) => tracing::debug!(?stats, "channels missing from a snapshot closed"),
                Err(error) => tracing::warn!(%error, "closing the channels missing from a snapshot failed"),
            }
        });
    }

    /// Closes every known channel that is not closed and that `snapshot` does not hold.
    ///
    /// A snapshot lists every channel that is not closed, so a channel it lacks closed while the subscription was
    /// not delivering updates. A closed channel holds no balance, so it is closed with a zero balance and keeps its
    /// epoch and ticket index. What differs is applied like a reconciliation row, with the events of the missed
    /// update.
    pub(crate) async fn close_missing(
        &self,
        snapshot: &std::collections::HashSet<ChannelId>,
    ) -> Result<SweepStats, ConnectorError> {
        let (backend, graph, snapshot) = (self.backend.clone(), self.graph.clone(), snapshot.clone());
        let missing = hopr_utils::runtime::prelude::spawn_blocking(move || {
            let edges = graph
                .read()
                .all_edges()
                .filter(|(_, _, id)| !snapshot.contains(*id))
                .map(|(src, dst, id)| ((src, dst), *id))
                .collect::<Vec<_>>();
            edges
                .into_iter()
                .filter_map(|(keys, id)| match backend.get_channel_by_id(&id) {
                    Ok(Some(channel)) if !matches!(channel.status, ChannelStatus::Closed) => Some((keys, channel)),
                    Ok(_) => None,
                    Err(error) => {
                        tracing::warn!(%error, %id, "backend error when looking up a channel missing from a snapshot");
                        None
                    }
                })
                .collect::<Vec<_>>()
        })
        .await
        .map_err(ConnectorError::backend)?;

        let mut stats = SweepStats {
            missing: missing.len(),
            ..Default::default()
        };
        for (keys, local) in missing {
            let id = *local.get_id();
            let closed = ChannelBuilder::default()
                .between(local.source, local.destination)
                .balance(HoprBalance::zero())
                .ticket_index(local.ticket_index)
                .status(ChannelStatus::Closed)
                .epoch(local.channel_epoch)
                .build();
            let result = match closed {
                Ok(channel) => self.apply(Fetched { channel, keys }).await,
                Err(error) => Err(ConnectorError::from(error)),
            };
            match result {
                Ok(Applied::Healed) => stats.closed += 1,
                Ok(_) => {}
                Err(error) => {
                    tracing::warn!(%error, %id, "failed to close a channel missing from a snapshot");
                    stats.failed += 1;
                }
            }
        }
        Ok(stats)
    }
}

#[cfg(test)]
mod tests {
    use blokli_client::{
        api::{
            ChainAddress, ModulePredictionInput, RedeemedStatsSelector, SafeSelector, ServiceSelector, ServiceTypeId,
            TxId, types,
        },
        errors::ErrorKind,
    };
    use hopr_api::types::crypto::prelude::{ChainKeypair, Keypair, OffchainKeypair};

    use super::*;
    use crate::{
        InMemoryBackend,
        testing::{BlokliTestClient, BlokliTestStateBuilder, StaticState},
    };

    type BlokliResult<T> = std::result::Result<T, blokli_client::errors::BlokliClientError>;

    /// Delegates to `C`, except that the outgoing channel query fails when asked to.
    struct FailingOutgoingQuery<C> {
        inner: C,
        fail_outgoing: bool,
    }

    #[allow(deprecated)]
    #[async_trait::async_trait]
    impl<C: BlokliQueryClient + Send + Sync> BlokliQueryClient for FailingOutgoingQuery<C> {
        async fn count_services(&self, s: ServiceSelector) -> BlokliResult<u32> {
            self.inner.count_services(s).await
        }

        async fn query_services(&self, s: ServiceSelector) -> BlokliResult<Vec<types::ServiceEntry>> {
            self.inner.query_services(s).await
        }

        async fn query_live_services(&self, s: ServiceSelector) -> BlokliResult<Vec<types::ServiceEntry>> {
            self.inner.query_live_services(s).await
        }

        async fn query_service_types(&self, s: Option<ServiceTypeId>) -> BlokliResult<Vec<types::ServiceTypeInfo>> {
            self.inner.query_service_types(s).await
        }

        async fn query_service_registry_config(&self) -> BlokliResult<types::ServiceRegistryConfig> {
            self.inner.query_service_registry_config().await
        }

        async fn count_accounts(&self, s: AccountSelector) -> BlokliResult<u32> {
            self.inner.count_accounts(s).await
        }

        async fn query_accounts(&self, s: AccountSelector) -> BlokliResult<Vec<types::Account>> {
            self.inner.query_accounts(s).await
        }

        async fn query_native_balance(&self, a: &ChainAddress) -> BlokliResult<types::NativeBalance> {
            self.inner.query_native_balance(a).await
        }

        async fn query_token_balance(&self, a: &ChainAddress, t: types::Token) -> BlokliResult<types::HoprBalance> {
            self.inner.query_token_balance(a, t).await
        }

        async fn query_transaction_count(&self, a: &ChainAddress) -> BlokliResult<u64> {
            self.inner.query_transaction_count(a).await
        }

        async fn query_safe_allowance(&self, a: &ChainAddress) -> BlokliResult<types::SafeHoprAllowance> {
            self.inner.query_safe_allowance(a).await
        }

        async fn query_redeemed_stats(&self, s: RedeemedStatsSelector) -> BlokliResult<types::RedeemedStats> {
            self.inner.query_redeemed_stats(s).await
        }

        async fn query_safe(&self, s: SafeSelector) -> BlokliResult<Vec<types::Safe>> {
            self.inner.query_safe(s).await
        }

        async fn query_module_address_prediction(&self, i: ModulePredictionInput) -> BlokliResult<ChainAddress> {
            self.inner.query_module_address_prediction(i).await
        }

        async fn count_channels(&self, s: ChannelSelector) -> BlokliResult<u32> {
            self.inner.count_channels(s).await
        }

        async fn query_channel_stats(&self, s: ChannelSelector) -> BlokliResult<types::ChannelStats> {
            self.inner.query_channel_stats(s).await
        }

        async fn query_channels(&self, s: ChannelSelector) -> BlokliResult<types::ChannelsList> {
            if self.fail_outgoing && matches!(s.filter, Some(ChannelFilter::SourceKeyId(_))) {
                return Err(ErrorKind::MockClientError(anyhow::anyhow!("blokli is unreachable")).into());
            }
            self.inner.query_channels(s).await
        }

        async fn query_safes_balance(&self, o: Option<ChainAddress>) -> BlokliResult<types::SafesBalance> {
            self.inner.query_safes_balance(o).await
        }

        async fn query_transaction_status(&self, t: TxId) -> BlokliResult<types::Transaction> {
            self.inner.query_transaction_status(t).await
        }

        async fn query_chain_info(&self) -> BlokliResult<types::ChainInfo> {
            self.inner.query_chain_info().await
        }

        async fn query_version(&self) -> BlokliResult<String> {
            self.inner.query_version().await
        }

        async fn query_compatibility(&self) -> BlokliResult<types::Compatibility> {
            self.inner.query_compatibility().await
        }

        async fn query_health(&self) -> BlokliResult<String> {
            self.inner.query_health().await
        }
    }

    struct Fixture {
        reconciler: OwnChannelReconciler<FailingOutgoingQuery<BlokliTestClient<StaticState>>, InMemoryBackend>,
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
        channel_at(src, dst, status, 1)
    }

    fn channel_at(src: &ChainKeypair, dst: &ChainKeypair, status: ChannelStatus, epoch: u32) -> ChannelEntry {
        ChannelEntry::builder()
            .between(src, dst)
            .amount(10)
            .ticket_index(0)
            .status(status)
            .epoch(epoch)
            .build()
            .unwrap()
    }

    /// `me` is registered in Blokli unless `bound` is false. The connector never subscribes, so nothing in
    /// `blokli_channels` is delivered on the graph stream.
    fn fixture(
        blokli_channels: impl Fn(&ChainKeypair, &ChainKeypair, &ChainKeypair) -> Vec<ChannelEntry>,
        bound: bool,
    ) -> Fixture {
        fixture_with(blokli_channels, bound, |_| {}, false)
    }

    fn fixture_with(
        blokli_channels: impl Fn(&ChainKeypair, &ChainKeypair, &ChainKeypair) -> Vec<ChannelEntry>,
        bound: bool,
        tweak: impl FnOnce(&mut crate::testing::BlokliTestState),
        fail_outgoing: bool,
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
        let mut state = BlokliTestStateBuilder::default()
            .with_accounts(
                accounts
                    .into_iter()
                    .map(|a| (a, HoprBalance::zero(), XDaiBalance::zero())),
            )
            .with_channels(channels)
            .build();
        tweak(&mut state);
        let client = FailingOutgoingQuery {
            inner: BlokliTestStateBuilder::from(state).build_static_client(),
            fail_outgoing,
        };

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
                in_flight: Default::default(),
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
                failed: 0,
                cache_repaired: 0,
                incomplete: 0
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

    fn seed(f: &Fixture, local: ChannelEntry) {
        f.reconciler.backend.insert_channel(local).unwrap();
        f.reconciler.channel_by_id.insert(*local.get_id(), Some(local));
        f.reconciler
            .channel_by_parties
            .insert(ChannelParties::from(&local), Some(local));
    }

    #[tokio::test]
    async fn reconciliation_should_not_move_a_channel_backwards() -> anyhow::Result<()> {
        // Blokli answers with an older epoch, and with an older status of the same epoch.
        for (local_epoch, blokli_epoch) in [(2, 1), (1, 1)] {
            let mut f = fixture(
                |me, peer, _| vec![channel_at(me, peer, ChannelStatus::Open, blokli_epoch)],
                true,
            );
            let local = channel_at(&f.me, &f.peer, ChannelStatus::Closed, local_epoch);
            seed(&f, local);

            let stats = f.reconciler.reconcile().await?;

            assert_eq!(0, stats.healed);
            assert_eq!(Some(local), f.reconciler.backend.get_channel_by_id(local.get_id())?);
            assert_eq!(Some(Some(local)), f.reconciler.channel_by_id.get(local.get_id()));
            assert!(f.events.try_recv().is_err());
        }
        Ok(())
    }

    #[tokio::test]
    async fn reconciliation_should_accept_a_reopen_with_a_higher_epoch() -> anyhow::Result<()> {
        let mut f = fixture(|me, peer, _| vec![channel_at(me, peer, ChannelStatus::Open, 2)], true);
        seed(&f, channel_at(&f.me, &f.peer, ChannelStatus::Closed, 1));

        assert_eq!(1, f.reconciler.reconcile().await?.healed);
        assert!(matches!(f.events.try_recv()?, ChainEvent::ChannelOpened(c) if c.channel_epoch == 2));
        Ok(())
    }

    #[tokio::test]
    async fn reconciliation_should_report_a_pending_to_close_channel_as_closure_initiated() -> anyhow::Result<()> {
        let closure = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1000);
        let mut f = fixture(
            |me, peer, _| vec![channel(me, peer, ChannelStatus::PendingToClose(closure))],
            true,
        );

        assert_eq!(1, f.reconciler.reconcile().await?.healed);
        assert!(matches!(f.events.try_recv()?, ChainEvent::ChannelClosureInitiated(_)));
        Ok(())
    }

    #[tokio::test]
    async fn reconciliation_should_skip_a_bad_row_and_still_apply_the_others() -> anyhow::Result<()> {
        let mut f = fixture_with(
            |me, peer, _| {
                vec![
                    channel(me, peer, ChannelStatus::Open),
                    channel(peer, me, ChannelStatus::Open),
                ]
            },
            true,
            |state| {
                let bad = state.channels.values_mut().next().expect("a channel");
                bad.ticket_index = types::Uint64("not a number".into());
            },
            false,
        );

        let stats = f.reconciler.reconcile().await?;

        assert_eq!(
            ReconcileStats {
                seen: 2,
                healed: 1,
                failed: 1,
                cache_repaired: 0,
                incomplete: 0
            },
            stats
        );
        assert!(matches!(f.events.try_recv()?, ChainEvent::ChannelOpened(_)));
        assert!(f.events.try_recv().is_err());
        Ok(())
    }

    #[tokio::test]
    async fn reconciliation_should_apply_the_other_direction_when_a_query_fails() -> anyhow::Result<()> {
        let mut f = fixture_with(
            |me, peer, _| {
                vec![
                    channel(me, peer, ChannelStatus::Open),
                    channel(peer, me, ChannelStatus::Open),
                ]
            },
            true,
            |_| {},
            true,
        );
        let incoming = channel(&f.peer, &f.me, ChannelStatus::Open);

        let stats = f.reconciler.reconcile().await?;

        assert_eq!(
            ReconcileStats {
                seen: 1,
                healed: 1,
                failed: 0,
                cache_repaired: 0,
                incomplete: 1
            },
            stats
        );
        assert_eq!(
            Some(incoming),
            f.reconciler.backend.get_channel_by_id(incoming.get_id())?
        );
        assert!(matches!(f.events.try_recv()?, ChainEvent::ChannelOpened(c) if c == incoming));
        Ok(())
    }

    #[tokio::test]
    async fn reconciliation_should_replace_a_negatively_cached_channel() -> anyhow::Result<()> {
        let f = fixture(|me, peer, _| vec![channel(me, peer, ChannelStatus::Open)], true);
        let open = channel(&f.me, &f.peer, ChannelStatus::Open);
        f.reconciler.channel_by_id.insert(*open.get_id(), None);
        f.reconciler
            .channel_by_parties
            .insert(ChannelParties::from(&open), None);

        f.reconciler.reconcile().await?;

        assert_eq!(Some(Some(open)), f.reconciler.channel_by_id.get(open.get_id()));
        assert_eq!(
            Some(Some(open)),
            f.reconciler.channel_by_parties.get(&ChannelParties::from(&open))
        );
        Ok(())
    }

    #[tokio::test]
    async fn reconciliation_should_not_overwrite_a_newer_balance_at_the_same_epoch() -> anyhow::Result<()> {
        let mut f = fixture(|me, peer, _| vec![channel(me, peer, ChannelStatus::Open)], true);
        let stream_value = ChannelEntry::builder()
            .between(&f.me, &f.peer)
            .amount(99)
            .ticket_index(0)
            .status(ChannelStatus::Open)
            .epoch(1)
            .build()?;
        seed(&f, stream_value);

        assert_eq!(0, f.reconciler.reconcile().await?.healed);
        assert_eq!(
            Some(stream_value),
            f.reconciler.backend.get_channel_by_id(stream_value.get_id())?
        );
        assert!(f.events.try_recv().is_err());
        Ok(())
    }

    /// Pins a known gap: a query cannot heal a channel that is PendingToClose locally but Open in Blokli within the
    /// same epoch, because the status would move backwards. Only the subscription can do that.
    #[tokio::test]
    async fn reconciliation_should_leave_pending_to_close_alone_for_an_open_row_of_the_same_epoch() -> anyhow::Result<()>
    {
        let closure = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1000);
        let mut f = fixture(|me, peer, _| vec![channel(me, peer, ChannelStatus::Open)], true);
        let local = channel(&f.me, &f.peer, ChannelStatus::PendingToClose(closure));
        seed(&f, local);

        assert_eq!(0, f.reconciler.reconcile().await?.healed);
        assert_eq!(Some(local), f.reconciler.backend.get_channel_by_id(local.get_id())?);
        assert!(f.events.try_recv().is_err());
        Ok(())
    }

    #[tokio::test]
    async fn reconciliation_should_repair_stale_cache_entries_without_events() -> anyhow::Result<()> {
        let mut f = fixture(|me, peer, _| vec![channel(me, peer, ChannelStatus::Open)], true);
        let open = channel(&f.me, &f.peer, ChannelStatus::Open);
        let stale = channel_at(&f.me, &f.peer, ChannelStatus::Closed, 0);
        f.reconciler.backend.insert_channel(open)?;
        let parties = ChannelParties::from(&open);

        for (by_id, by_parties) in [(Some(stale), None), (None, Some(stale))] {
            f.reconciler.channel_by_id.insert(*open.get_id(), by_id);
            f.reconciler.channel_by_parties.insert(parties, by_parties);

            let stats = f.reconciler.reconcile().await?;

            assert_eq!(1, stats.cache_repaired);
            assert_eq!(0, stats.healed);
            assert_eq!(Some(Some(open)), f.reconciler.channel_by_id.get(open.get_id()));
            assert_eq!(Some(Some(open)), f.reconciler.channel_by_parties.get(&parties));
            assert!(f.events.try_recv().is_err());

            // nothing is left to repair
            assert_eq!(0, f.reconciler.reconcile().await?.cache_repaired);
        }
        Ok(())
    }

    #[tokio::test]
    async fn reconciliation_should_repair_caches_against_the_backend_for_a_stale_row() -> anyhow::Result<()> {
        // Blokli's row is older than the backend: the caches follow the backend, not the row.
        let f = fixture(|me, peer, _| vec![channel_at(me, peer, ChannelStatus::Open, 1)], true);
        let local = channel_at(&f.me, &f.peer, ChannelStatus::Closed, 2);
        f.reconciler.backend.insert_channel(local)?;
        f.reconciler.channel_by_id.insert(*local.get_id(), None);

        let stats = f.reconciler.reconcile().await?;

        assert_eq!(1, stats.cache_repaired);
        assert_eq!(Some(Some(local)), f.reconciler.channel_by_id.get(local.get_id()));
        Ok(())
    }

    #[test]
    fn in_flight_guard_should_clear_the_flag() {
        let flag = std::sync::atomic::AtomicBool::new(true);
        drop(InFlightGuard(&flag));
        assert!(!flag.load(std::sync::atomic::Ordering::Acquire));
    }

    /// Makes the channel known locally the way the subscription would have: stored, cached and in the graph.
    fn seed_known(f: &Fixture, local: ChannelEntry, src: u32, dst: u32) {
        seed(f, local);
        f.reconciler
            .graph
            .write()
            .add_edge(HoprKeyIdent::from(src), HoprKeyIdent::from(dst), *local.get_id());
    }

    fn closed_without_balance(src: &ChainKeypair, dst: &ChainKeypair) -> ChannelEntry {
        ChannelEntry::builder()
            .between(src, dst)
            .amount(0)
            .ticket_index(0)
            .status(ChannelStatus::Closed)
            .epoch(1)
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn the_sweep_should_close_channels_missing_from_the_snapshot() -> anyhow::Result<()> {
        // Blokli is not asked: a snapshot lacking a channel is enough to know it closed, and a closed channel holds
        // no balance.
        let mut f = fixture(|_, _, _| vec![], true);
        let own = channel(&f.me, &f.peer, ChannelStatus::Open);
        // between two other nodes, and about to close
        let foreign = channel(
            &f.peer,
            &f.other,
            ChannelStatus::PendingToClose(std::time::SystemTime::UNIX_EPOCH),
        );
        seed_known(&f, own, 1, 2);
        seed_known(&f, foreign, 2, 3);

        let stats = f.reconciler.close_missing(&Default::default()).await?;

        assert_eq!(
            SweepStats {
                missing: 2,
                closed: 2,
                failed: 0
            },
            stats
        );
        for (before, closed) in [
            (own, closed_without_balance(&f.me, &f.peer)),
            (foreign, closed_without_balance(&f.peer, &f.other)),
        ] {
            assert_eq!(Some(closed), f.reconciler.backend.get_channel_by_id(before.get_id())?);
            assert_eq!(Some(Some(closed)), f.reconciler.channel_by_id.get(before.get_id()));
            assert_eq!(
                Some(Some(closed)),
                f.reconciler.channel_by_parties.get(&ChannelParties::from(&before))
            );
        }
        // each channel raises what its closure would have: the balance drops to zero and the channel closes
        let (mut closed_events, mut decreased_events) = (0, 0);
        while let Ok(event) = f.events.try_recv() {
            match event {
                ChainEvent::ChannelClosed(_) => closed_events += 1,
                ChainEvent::ChannelBalanceDecreased(..) => decreased_events += 1,
                other => anyhow::bail!("unexpected event {other}"),
            }
        }
        assert_eq!((2, 2), (closed_events, decreased_events));

        // a second sweep finds nothing: the channels are closed now
        assert_eq!(
            SweepStats::default(),
            f.reconciler.close_missing(&Default::default()).await?
        );
        assert!(f.events.try_recv().is_err());
        Ok(())
    }

    #[tokio::test]
    async fn the_sweep_should_leave_channels_the_snapshot_held_alone() -> anyhow::Result<()> {
        let mut f = fixture(|_, _, _| vec![], true);
        let open = channel(&f.me, &f.peer, ChannelStatus::Open);
        seed_known(&f, open, 1, 2);

        let snapshot = std::collections::HashSet::from([*open.get_id()]);

        assert_eq!(SweepStats::default(), f.reconciler.close_missing(&snapshot).await?);
        assert_eq!(Some(open), f.reconciler.backend.get_channel_by_id(open.get_id())?);
        assert!(f.events.try_recv().is_err());
        Ok(())
    }

    #[tokio::test]
    async fn the_sweep_should_skip_channels_that_are_closed_already() -> anyhow::Result<()> {
        let mut f = fixture(|_, _, _| vec![], true);
        let closed = channel(&f.me, &f.peer, ChannelStatus::Closed);
        seed_known(&f, closed, 1, 2);

        assert_eq!(
            SweepStats::default(),
            f.reconciler.close_missing(&Default::default()).await?
        );
        assert_eq!(Some(closed), f.reconciler.backend.get_channel_by_id(closed.get_id())?);
        assert!(f.events.try_recv().is_err());
        Ok(())
    }
}
