//! A channel lookup that misses the cache must not overwrite a newer graph update (hoprnet/hopr-impls#110).

use std::{sync::Arc, time::Duration};

use futures::StreamExt;
use hex_literal::hex;
use hopr_api::{
    chain::{
        ChainKeyOperations, ChainReadChannelOperations, ChainWriteAccountOperations, ChainWriteChannelOperations,
        ChannelSelector, HoprKeyIdent,
    },
    types::{
        chain::{contract_addresses_for_network, prelude::*},
        crypto::prelude::*,
        internal::prelude::*,
        primitive::prelude::*,
    },
};

use crate::{
    InMemoryBackend,
    backend::Backend,
    connector::{
        HoprBlockchainConnector,
        tests::{MODULE_ADDR, PRIVATE_KEY_1, PRIVATE_KEY_2},
    },
    testing::BlokliTestStateBuilder,
};

fn accounts() -> anyhow::Result<(AccountEntry, AccountEntry)> {
    let offchain_1 = OffchainKeypair::from_secret(&hex!(
        "60741b83b99e36aa0c1331578156e16b8e21166d01834abb6c64b103f885734d"
    ))?;
    let offchain_2 = OffchainKeypair::from_secret(&hex!(
        "71bf1f42ebbfcd89c3e197a3fd7cda79b92499e509b6fefa0fe44d02821d146a"
    ))?;
    Ok((
        AccountEntry {
            public_key: *offchain_1.public(),
            chain_addr: ChainKeypair::from_secret(&PRIVATE_KEY_1)?.public().to_address(),
            entry_type: AccountType::NotAnnounced,
            safe_address: Some([1u8; Address::SIZE].into()),
            key_id: 1.into(),
        },
        AccountEntry {
            public_key: *offchain_2.public(),
            chain_addr: ChainKeypair::from_secret(&PRIVATE_KEY_2)?.public().to_address(),
            entry_type: AccountType::NotAnnounced,
            safe_address: Some([2u8; Address::SIZE].into()),
            key_id: 2.into(),
        },
    ))
}

/// Pauses the first backend read of one channel after the read and before the value is returned, so a test can
/// interleave other work exactly there.
struct Gate {
    channel_id: ChannelId,
    read_done: std::sync::mpsc::Sender<Option<ChannelEntry>>,
    release: std::sync::mpsc::Receiver<()>,
}

/// Pauses the first backend read of an account by packet key after the read.
struct KeyGate {
    read_done: std::sync::mpsc::Sender<Option<AccountEntry>>,
    release: std::sync::mpsc::Receiver<()>,
}

#[derive(Clone, Default)]
struct GatedBackend {
    inner: InMemoryBackend,
    key_gate: Arc<parking_lot::Mutex<Option<KeyGate>>>,
    gate: Arc<parking_lot::Mutex<Option<Gate>>>,
}

impl Backend for GatedBackend {
    type Error = std::convert::Infallible;

    fn count_announced_accounts(&self, me: &Address) -> Result<u64, Self::Error> {
        self.inner.count_announced_accounts(me)
    }

    fn insert_account(&self, entry: AccountEntry) -> Result<Option<AccountEntry>, Self::Error> {
        self.inner.insert_account(entry)
    }

    fn insert_channel(&self, channel: ChannelEntry) -> Result<Option<ChannelEntry>, Self::Error> {
        self.inner.insert_channel(channel)
    }

    fn get_account_by_id(&self, id: &HoprKeyIdent) -> Result<Option<AccountEntry>, Self::Error> {
        self.inner.get_account_by_id(id)
    }

    fn get_account_by_key(&self, key: &OffchainPublicKey) -> Result<Option<AccountEntry>, Self::Error> {
        let value = self.inner.get_account_by_key(key)?;
        let gate = self.key_gate.lock().take();
        if let Some(gate) = gate {
            let _ = gate.read_done.send(value.clone());
            let _ = gate.release.recv();
        }
        Ok(value)
    }

    fn get_account_by_address(&self, chain_key: &Address) -> Result<Option<AccountEntry>, Self::Error> {
        self.inner.get_account_by_address(chain_key)
    }

    fn get_channel_by_id(&self, id: &ChannelId) -> Result<Option<ChannelEntry>, Self::Error> {
        let value = self.inner.get_channel_by_id(id)?;
        let gate = {
            let mut gate = self.gate.lock();
            if gate.as_ref().is_some_and(|gate| &gate.channel_id == id) {
                gate.take()
            } else {
                None
            }
        };
        if let Some(gate) = gate {
            let _ = gate.read_done.send(value);
            let _ = gate.release.recv();
        }
        Ok(value)
    }
}

/// Polls `probe` until it returns a value or `within` has passed.
async fn eventually<T>(within: Duration, mut probe: impl FnMut() -> Option<T>) -> Option<T> {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        if let Some(value) = probe() {
            return Some(value);
        }
        if tokio::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// A `channel_by_parties` lookup that misses the cache reads the backend before the channel exists. While it is
/// paused, the channel opens and the graph subscription stores it. Once the lookup resumes, the packet path must see
/// the channel; today the lookup's stale `None` overwrites the update in the cache and is served from then on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lookup_racing_the_graph_subscription_must_not_leave_a_stale_value_in_the_cache() -> anyhow::Result<()> {
    let (account_1, account_2) = accounts()?;
    let me_kp = ChainKeypair::from_secret(&PRIVATE_KEY_1)?;
    let me = account_1.chain_addr;
    let peer = account_2.chain_addr;
    let channel_id = generate_channel_id(&me, &peer);

    let client = BlokliTestStateBuilder::default()
        .with_accounts([
            (account_1, HoprBalance::new_base(100), XDaiBalance::new_base(1)),
            (account_2, HoprBalance::new_base(100), XDaiBalance::new_base(1)),
        ])
        .with_hopr_network_chain_info("piz-palu-staging")
        .build_dynamic_client(MODULE_ADDR.into());

    let backend = GatedBackend::default();
    let mut connector = HoprBlockchainConnector::new(
        me_kp.clone(),
        Default::default(),
        client,
        backend.clone(),
        SafePayloadGenerator::new(
            &me_kp,
            contract_addresses_for_network("piz-palu-staging").unwrap().1,
            MODULE_ADDR.into(),
        ),
    );
    connector.connect().await?;
    let connector = Arc::new(connector);

    let (read_done_tx, read_done_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    *backend.gate.lock() = Some(Gate {
        channel_id,
        read_done: read_done_tx,
        release: release_rx,
    });

    // 1. A packet needs `me -> peer`: the lookup misses the cache and reads the backend, which has no channel yet.
    let lookup = {
        let connector = connector.clone();
        std::thread::spawn(move || connector.channel_by_parties(&me, &peer))
    };
    assert_eq!(read_done_rx.recv_timeout(Duration::from_secs(5))?, None);

    // 2. The channel opens, and the graph subscription stores it in the backend and then in the cache. A fix that
    //    orders cache writes per key may hold the cache write back until the paused lookup is done, so that wait is
    //    bounded rather than required.
    connector.open_channel(&peer, 10.into()).await?.await?;
    let opened = eventually(Duration::from_secs(5), || {
        backend.inner.get_channel_by_id(&channel_id).unwrap()
    })
    .await
    .expect("the graph subscription stores the opened channel");
    assert_eq!(opened.status, ChannelStatus::Open);
    let _ = eventually(Duration::from_secs(1), || {
        connector
            .channel_by_parties
            .get(&ChannelParties::new(me, peer))
            .flatten()
    })
    .await;

    // 3. The paused lookup resumes. It may return what it read, but it must not leave that in the cache.
    release_tx.send(())?;
    lookup.join().expect("lookup thread")?;

    // `stream_channels` (and hoprd's `GET /api/v4/channels`, built on it) lists the channel as open...
    let listed = connector
        .stream_channels(ChannelSelector::default().with_source(me))?
        .collect::<Vec<_>>()
        .await;
    assert_eq!(listed, vec![opened]);

    // ...so the packet path must find it too.
    let seen = eventually(Duration::from_secs(2), || {
        connector.channel_by_parties(&me, &peer).ok().flatten()
    })
    .await;
    assert_eq!(
        seen,
        Some(opened),
        "channel_by_parties serves a stale value for an open channel"
    );

    Ok(())
}

/// Same race on the key caches: a `packet_key_to_chain_key` lookup reads the backend before the account exists. While
/// it is paused, the account is announced and the subscription stores it. The lookup's stale `None` must not be left in
/// the cache.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_key_lookup_racing_the_account_subscription_must_not_leave_a_stale_value_in_the_cache() -> anyhow::Result<()>
{
    let me_kp = ChainKeypair::from_secret(&PRIVATE_KEY_1)?;
    let me = me_kp.public().to_address();
    let offchain = OffchainKeypair::from_secret(&hex!(
        "60741b83b99e36aa0c1331578156e16b8e21166d01834abb6c64b103f885734d"
    ))?;

    let client = BlokliTestStateBuilder::default()
        .with_balances([(me, XDaiBalance::new_base(1))])
        .with_hopr_network_chain_info("piz-palu-staging")
        .build_dynamic_client(MODULE_ADDR.into());

    let backend = GatedBackend::default();
    let mut connector = HoprBlockchainConnector::new(
        me_kp.clone(),
        Default::default(),
        client,
        backend.clone(),
        SafePayloadGenerator::new(
            &me_kp,
            contract_addresses_for_network("piz-palu-staging").unwrap().1,
            MODULE_ADDR.into(),
        ),
    );
    connector.connect().await?;
    let connector = Arc::new(connector);

    let (read_done_tx, read_done_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    *backend.key_gate.lock() = Some(KeyGate {
        read_done: read_done_tx,
        release: release_rx,
    });

    let public_key = *offchain.public();
    let lookup = {
        let connector = connector.clone();
        std::thread::spawn(move || connector.packet_key_to_chain_key(&public_key))
    };
    assert_eq!(read_done_rx.recv_timeout(Duration::from_secs(5))?, None);

    connector.announce(&[], &offchain).await?.await?;
    let stored = eventually(Duration::from_secs(5), || {
        backend.inner.get_account_by_key(&public_key).unwrap()
    })
    .await
    .expect("the account subscription stores the announced account");
    // A fix that orders cache writes per key may hold the cache write back until the paused lookup is done.
    let _ = eventually(Duration::from_secs(1), || {
        connector.packet_to_chain.get(&public_key).flatten()
    })
    .await;

    release_tx.send(())?;
    lookup.join().expect("lookup thread")?;

    let seen = eventually(Duration::from_secs(2), || {
        connector.packet_key_to_chain_key(&public_key).ok().flatten()
    })
    .await;
    assert_eq!(
        seen,
        Some(stored.chain_addr),
        "packet_key_to_chain_key serves a stale value for an announced account"
    );

    Ok(())
}
