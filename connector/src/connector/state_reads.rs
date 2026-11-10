//! Diagnostic reads preserve errors instead of silently dropping unreadable records.
use futures::stream::BoxStream;
use hopr_api::types::internal::prelude::ChannelEntry;
use serde::Serialize;

/// A failed diagnostic read. Messages and named samples are bounded by the collector.
#[derive(Debug, Serialize)]
pub struct ReadFailure {
    pub entity: String,
    pub kind: &'static str,
    pub message: String,
}

/// Read interface for the reporter, separate from the existing best-effort chain streams.
/// Implementations must enumerate each local channel once and preserve individual failures.
pub trait StateRead: Sync {
    fn local_channels(&self) -> Result<BoxStream<'_, Result<ChannelEntry, ReadFailure>>, String>;
    /// Public remote accounts stored by the connector, excluding the local account.
    fn announced_count(&self) -> Result<u64, String>;
}
impl<T: StateRead + ?Sized> StateRead for &T {
    fn local_channels(&self) -> Result<BoxStream<'_, Result<ChannelEntry, ReadFailure>>, String> {
        (**self).local_channels()
    }

    fn announced_count(&self) -> Result<u64, String> {
        (**self).announced_count()
    }
}
impl<T: StateRead + Send + ?Sized> StateRead for std::sync::Arc<T> {
    fn local_channels(&self) -> Result<BoxStream<'_, Result<ChannelEntry, ReadFailure>>, String> {
        (**self).local_channels()
    }

    fn announced_count(&self) -> Result<u64, String> {
        (**self).announced_count()
    }
}

// Keep the batch small: cancellation can leave at most one batch of backend reads running.
const READ_BATCH: usize = 64;
impl<C, B, P, R> StateRead for crate::HoprBlockchainConnector<C, B, P, R>
where
    B: crate::Backend + Send + Sync + 'static,
    C: Send + Sync,
    P: Send + Sync,
    R: Send + Sync,
{
    fn announced_count(&self) -> Result<u64, String> {
        self.check_connection_state().map_err(|e| e.to_string())?;
        Ok(self.announced.load(std::sync::atomic::Ordering::Relaxed))
    }

    fn local_channels(&self) -> Result<BoxStream<'_, Result<ChannelEntry, ReadFailure>>, String> {
        use futures::{StreamExt, stream};
        use hopr_api::types::crypto::prelude::Keypair;
        self.check_connection_state().map_err(|e| e.to_string())?;
        let backend = self.backend.clone();
        let graph = self.graph.clone();
        let me = self.chain_key.public().to_address();
        // Resolve our graph ID off the async executor; no network-wide channel inventory.
        let ids = stream::once(async move {
            hopr_utils::runtime::prelude::spawn_blocking(move || {
                let account = backend
                    .get_account_by_address(&me)
                    .map_err(|e| ReadFailure {
                        entity: me.to_string(),
                        kind: "backend_read",
                        message: e.to_string(),
                    })?
                    .ok_or_else(|| ReadFailure {
                        entity: me.to_string(),
                        kind: "missing",
                        message: "local account missing".into(),
                    })?;
                let graph = graph.read();
                let ids: Vec<_> = graph
                    .edges(account.key_id)
                    .chain(
                        graph
                            .edges_directed(account.key_id, petgraph::Direction::Incoming)
                            .filter(|(src, ..)| *src != account.key_id),
                    )
                    .map(|(_, _, id)| *id)
                    .collect();
                Ok::<_, ReadFailure>(ids)
            })
            .await
            .unwrap_or_else(|e| {
                Err(ReadFailure {
                    entity: me.to_string(),
                    kind: "join",
                    message: e.to_string(),
                })
            })
        });
        let backend = self.backend.clone();
        Ok(ids
            .flat_map(move |ids| {
                let backend = backend.clone();
                let batches: BoxStream<'static, _> = match ids {
                    Ok(ids) => stream::iter(ids).chunks(READ_BATCH).map(Ok).boxed(),
                    Err(e) => stream::once(futures::future::ready(Err(e))).boxed(),
                };
                batches
                    .then(move |batch| {
                        let backend = backend.clone();
                        async move {
                            let ids = match batch {
                                Ok(ids) => ids,
                                Err(e) => return vec![Err(e)],
                            };
                            hopr_utils::runtime::prelude::spawn_blocking(move || {
                                ids.into_iter()
                                    .map(|id| match backend.get_channel_by_id(&id) {
                                        Ok(Some(channel)) => Ok(channel),
                                        Ok(None) => Err(ReadFailure {
                                            entity: id.to_string(),
                                            kind: "missing",
                                            message: "channel missing".into(),
                                        }),
                                        Err(e) => Err(ReadFailure {
                                            entity: id.to_string(),
                                            kind: "backend_read",
                                            message: e.to_string(),
                                        }),
                                    })
                                    .collect::<Vec<_>>()
                            })
                            .await
                            .unwrap_or_else(|e| {
                                vec![Err(ReadFailure {
                                    entity: "channel_batch".into(),
                                    kind: "join",
                                    message: e.to_string(),
                                })]
                            })
                        }
                    })
                    .flat_map(stream::iter)
            })
            .boxed())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use futures::StreamExt;
    use hopr_api::{
        chain::HoprKeyIdent,
        types::{crypto::prelude::*, internal::prelude::*, primitive::prelude::*},
    };

    use super::*;
    use crate::{
        Backend, HoprBlockchainConnector, InMemoryBackend, SafePayloadGenerator, testing::BlokliTestStateBuilder,
    };

    #[derive(Clone, Default)]
    struct BackendProbe {
        inner: InMemoryBackend,
        reads: Arc<AtomicUsize>,
        async_thread: Arc<parking_lot::Mutex<Option<std::thread::ThreadId>>>,
        identity_reads: Arc<AtomicUsize>,
        failed: Arc<parking_lot::Mutex<Option<ChannelId>>>,
    }
    impl Backend for BackendProbe {
        type Error = std::io::Error;

        fn count_announced_accounts(&self, me: &Address) -> Result<u64, Self::Error> {
            Ok(self.inner.count_announced_accounts(me).unwrap())
        }

        fn insert_account(&self, a: AccountEntry) -> Result<Option<AccountEntry>, Self::Error> {
            Ok(self.inner.insert_account(a).unwrap())
        }

        fn insert_channel(&self, c: ChannelEntry) -> Result<Option<ChannelEntry>, Self::Error> {
            Ok(self.inner.insert_channel(c).unwrap())
        }

        fn get_account_by_id(&self, id: &HoprKeyIdent) -> Result<Option<AccountEntry>, Self::Error> {
            Ok(self.inner.get_account_by_id(id).unwrap())
        }

        fn get_account_by_key(&self, k: &OffchainPublicKey) -> Result<Option<AccountEntry>, Self::Error> {
            Ok(self.inner.get_account_by_key(k).unwrap())
        }

        fn get_account_by_address(&self, a: &Address) -> Result<Option<AccountEntry>, Self::Error> {
            if let Some(async_thread) = *self.async_thread.lock() {
                assert_ne!(
                    std::thread::current().id(),
                    async_thread,
                    "backend lookup blocked the async executor"
                );
                self.identity_reads.fetch_add(1, Ordering::Relaxed);
            }
            Ok(self.inner.get_account_by_address(a).unwrap())
        }

        fn get_channel_by_id(&self, id: &ChannelId) -> Result<Option<ChannelEntry>, Self::Error> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            if self.failed.lock().as_ref() == Some(id) {
                return Err(std::io::Error::other("injected backend failure"));
            }
            Ok(self.inner.get_channel_by_id(id).unwrap())
        }
    }

    #[tokio::test]
    async fn diagnostic_reads_only_local_edges_once_and_preserves_failures() -> anyhow::Result<()> {
        let key = ChainKeypair::from_secret(&[1; 32])?;
        let me = key.public().to_address();
        let peer = Address::from([2; 20]);
        let backend = BackendProbe::default();
        let mut connector = HoprBlockchainConnector::new(
            key.clone(),
            Default::default(),
            BlokliTestStateBuilder::default().build_static_client(),
            backend.clone(),
            SafePayloadGenerator::new(
                &key,
                hopr_api::types::chain::contract_addresses_for_network("piz-palu-staging")
                    .unwrap()
                    .1,
                Address::from([99; 20]),
            ),
        );
        // Seed the production graph/backend directly to exercise reader failures without
        // subscription error handling modifying the fixture first.
        connector.connect().await?;
        backend.insert_account(AccountEntry {
            public_key: *OffchainKeypair::from_secret(&[11; 32])?.public(),
            chain_addr: me,
            key_id: 1u32.into(),
            entry_type: AccountType::NotAnnounced,
            safe_address: None,
        })?;
        let outgoing = ChannelEntry::builder()
            .between(me, peer)
            .amount(10)
            .status(ChannelStatus::Open)
            .build()?;
        let incoming = ChannelEntry::builder()
            .between(peer, me)
            .amount(10)
            .status(ChannelStatus::Open)
            .build()?;
        backend.insert_channel(outgoing)?;
        backend.insert_channel(incoming)?;
        connector
            .graph
            .write()
            .add_edge(1u32.into(), 2u32.into(), *outgoing.get_id());
        connector
            .graph
            .write()
            .add_edge(2u32.into(), 1u32.into(), *incoming.get_id());
        for i in 3u32..1003 {
            connector
                .graph
                .write()
                .add_edge(i.into(), (i + 1).into(), ChannelId::from([i as u8; 32]));
        }
        let rows: Vec<_> = connector.local_channels().map_err(anyhow::Error::msg)?.collect().await;
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(Result::is_ok));
        assert_eq!(
            backend.reads.load(Ordering::Relaxed),
            2,
            "remote channels must not be loaded"
        );
        // A third local graph edge has no corresponding backend record.
        let missing = ChannelId::from([253; 32]);
        connector.graph.write().add_edge(1u32.into(), 1005u32.into(), missing);
        *backend.failed.lock() = Some(*incoming.get_id());
        let rows: Vec<_> = connector.local_channels().map_err(anyhow::Error::msg)?.collect().await;
        assert_eq!(rows.iter().filter(|r| r.is_ok()).count(), 1);
        assert!(
            rows.iter()
                .any(|r| matches!(r, Err(e) if e.entity == incoming.get_id().to_string() && e.kind == "backend_read"))
        );
        assert!(
            rows.iter()
                .any(|r| matches!(r, Err(e) if e.entity == missing.to_string() && e.kind == "missing"))
        );
        assert_eq!(backend.reads.load(Ordering::Relaxed), 5);
        *backend.async_thread.lock() = Some(std::thread::current().id());
        let collector = crate::state_dump::ChainDump::new(connector, Address::from([99; 20]), Default::default());
        let snapshot = collector.collect().await;
        assert!(
            backend.identity_reads.load(Ordering::Relaxed) >= 1,
            "local channel enumeration reaches the backend"
        );
        let crate::state_dump::Section::Partial { value } = snapshot.channels else {
            panic!("failed reads must mark the channel inventory partial")
        };
        assert_eq!(value.total, 1);
        assert_eq!(value.reads.read_ok, 1);
        assert_eq!(value.reads.missing, 1);
        assert_eq!(value.reads.backend_errors, 1);
        assert!(!value.reads.complete);
        assert_eq!(value.reads.error_samples().len(), 2);
        Ok(())
    }
    #[test]
    fn announced_counter_handles_replay_replacement_and_reconnect() -> anyhow::Result<()> {
        check_announced_counter(InMemoryBackend::default())?;
        check_announced_counter(crate::backend::TempDbBackend::new()?)
    }

    fn check_announced_counter<B: Backend>(backend: B) -> anyhow::Result<()>
    where
        B::Error: Send + Sync + 'static,
    {
        use std::sync::atomic::{AtomicU64, Ordering};
        let me = Address::from([1; 20]);
        let mut account = AccountEntry {
            public_key: *OffchainKeypair::from_secret(&[2; 32])?.public(),
            chain_addr: Address::from([2; 20]),
            key_id: 2u32.into(),
            safe_address: None,
            entry_type: AccountType::Announced(vec!["/ip4/1.2.3.4/tcp/1234".parse()?]),
        };
        // A pre-populated backend is counted before its subscription replay.
        backend.insert_account(account.clone())?;
        let count = AtomicU64::new(backend.count_announced_accounts(&me)?);
        let update = |account: &AccountEntry| {
            let old = backend.insert_account(account.clone()).unwrap();
            super::super::accounts::update_announced(&count, account, old.as_ref(), &me);
        };
        for _ in 0..10 {
            update(&account);
        }
        assert_eq!(count.load(Ordering::Relaxed), 1);
        account.entry_type = AccountType::NotAnnounced;
        update(&account);
        assert_eq!(count.load(Ordering::Relaxed), 0);
        account.entry_type = AccountType::Announced(vec!["/ip4/1.2.3.4/tcp/1234".parse()?]);
        update(&account);
        assert_eq!(count.load(Ordering::Relaxed), 1);
        account.chain_addr = me;
        update(&account);
        assert_eq!(count.load(Ordering::Relaxed), 0, "local announcements are excluded");
        account.chain_addr = Address::from([2; 20]);
        update(&account);
        count.store(backend.count_announced_accounts(&me)?, Ordering::Relaxed);
        update(&account);
        assert_eq!(count.load(Ordering::Relaxed), 1, "reconnect replay is idempotent");
        account.key_id = 3u32.into();
        update(&account);
        assert_eq!(count.load(Ordering::Relaxed), 2, "new identities increment the count");
        Ok(())
    }
}
