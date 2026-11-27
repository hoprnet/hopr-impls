mod tempdb;

pub use hopr_api::{
    chain::HoprKeyIdent,
    types::{
        crypto::prelude::OffchainPublicKey,
        internal::{
            account::AccountEntry,
            channels::{ChannelEntry, ChannelId},
        },
        primitive::prelude::Address,
    },
};

/// Represents a cache backend for the connector.
pub trait Backend {
    type Error: std::error::Error + Send + Sync + 'static;
    /// Counts announced accounts with routing information, excluding the local account.
    /// Used once at connection startup; implementations may scan stored accounts.
    fn count_announced_accounts(&self, me: &Address) -> Result<u64, Self::Error>;
    /// Inserts an [`AccountEntry`] into the backend.
    ///
    /// Returns the old value if one was present in the backend before.
    fn insert_account(&self, entry: AccountEntry) -> Result<Option<AccountEntry>, Self::Error>;
    /// Inserts a [`ChannelEntry`] into the backend.
    ///
    /// Returns the old value if one was present in the backend before.
    fn insert_channel(&self, channel: ChannelEntry) -> Result<Option<ChannelEntry>, Self::Error>;
    /// Retrieves an [`AccountEntry`] by [`HoprKeyIdent`].
    fn get_account_by_id(&self, id: &HoprKeyIdent) -> Result<Option<AccountEntry>, Self::Error>;
    /// Retrieves an [`AccountEntry`] by [`OffchainPublicKey`].
    fn get_account_by_key(&self, key: &OffchainPublicKey) -> Result<Option<AccountEntry>, Self::Error>;
    /// Retrieves an [`AccountEntry`] by an on-chain [`Address`].
    fn get_account_by_address(&self, chain_key: &Address) -> Result<Option<AccountEntry>, Self::Error>;
    /// Retrieves a [`ChannelEntry`] by its [`ChannelId`].
    fn get_channel_by_id(&self, id: &ChannelId) -> Result<Option<ChannelEntry>, Self::Error>;
}

pub use tempdb::{TempDbBackend, TempDbError};

/// Represents a backend that stores all data in-memory.
///
/// Accounts are indexed by key id, by [`OffchainPublicKey`] and by [`Address`], and channels by
/// [`ChannelId`], so no lookup scans the stored entries. Upserts keep the indexes consistent: a changed
/// key or address leaves no stale mapping behind.
///
/// Nothing is persisted; all data is dropped with the last clone of the instance.
#[derive(Clone, Default)]
pub struct InMemoryBackend {
    inner: std::sync::Arc<parking_lot::RwLock<InMemoryState>>,
}

#[derive(Default)]
struct InMemoryState {
    accounts: std::collections::HashMap<HoprKeyIdent, AccountEntry, ahash::RandomState>,
    key_to_id: std::collections::HashMap<OffchainPublicKey, HoprKeyIdent, ahash::RandomState>,
    address_to_id: std::collections::HashMap<Address, HoprKeyIdent, ahash::RandomState>,
    channels: std::collections::HashMap<ChannelId, ChannelEntry, ahash::RandomState>,
}

impl InMemoryBackend {
    /// Creates an empty backend.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Backend for InMemoryBackend {
    type Error = std::convert::Infallible;

    fn count_announced_accounts(&self, me: &Address) -> Result<u64, Self::Error> {
        Ok(self
            .inner
            .read()
            .accounts
            .values()
            .filter(|a| a.chain_addr != *me && a.has_announced_with_routing_info())
            .count() as u64)
    }

    fn insert_account(&self, entry: AccountEntry) -> Result<Option<AccountEntry>, Self::Error> {
        let mut state = self.inner.write();
        let old = state.accounts.insert(entry.key_id, entry.clone());
        // Remove the old references so that no stale mapping remains if the key or address changed
        if let Some(old) = &old {
            state.key_to_id.remove(&old.public_key);
            state.address_to_id.remove(&old.chain_addr);
        }
        state.key_to_id.insert(entry.public_key, entry.key_id);
        state.address_to_id.insert(entry.chain_addr, entry.key_id);
        Ok(old)
    }

    fn insert_channel(&self, channel: ChannelEntry) -> Result<Option<ChannelEntry>, Self::Error> {
        Ok(self.inner.write().channels.insert(*channel.get_id(), channel))
    }

    fn get_account_by_id(&self, id: &HoprKeyIdent) -> Result<Option<AccountEntry>, Self::Error> {
        Ok(self.inner.read().accounts.get(id).cloned())
    }

    fn get_account_by_key(&self, key: &OffchainPublicKey) -> Result<Option<AccountEntry>, Self::Error> {
        let state = self.inner.read();
        Ok(state.key_to_id.get(key).and_then(|id| state.accounts.get(id)).cloned())
    }

    fn get_account_by_address(&self, chain_key: &Address) -> Result<Option<AccountEntry>, Self::Error> {
        let state = self.inner.read();
        Ok(state
            .address_to_id
            .get(chain_key)
            .and_then(|id| state.accounts.get(id))
            .cloned())
    }

    fn get_channel_by_id(&self, id: &ChannelId) -> Result<Option<ChannelEntry>, Self::Error> {
        Ok(self.inner.read().channels.get(id).copied())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use hopr_api::types::{
        crypto::keypairs::{ChainKeypair, Keypair, OffchainKeypair},
        internal::{
            account::{AccountEntry, AccountType},
            channels::{ChannelEntry, ChannelStatus, generate_channel_id},
        },
        primitive::{balance::HoprBalance, prelude::Address},
    };

    use crate::{Backend, InMemoryBackend};

    pub(crate) fn test_backend<B: Backend>(backend: B) -> anyhow::Result<()> {
        let kp = OffchainKeypair::random();
        let cp = ChainKeypair::random();

        let account = AccountEntry {
            public_key: (*kp.public()),
            chain_addr: cp.public().to_address(),
            entry_type: AccountType::Announced(vec!["/ip4/1.2.3.4/tcp/1234".parse()?]),
            safe_address: Some(Address::new(&[3u8; 20])),
            key_id: 3.into(),
        };

        let src = Address::new(&[1u8; 20]);
        let dst = Address::new(&[2u8; 20]);

        let channel = ChannelEntry::builder()
            .between(src, dst)
            .balance(HoprBalance::new_base(1000))
            .ticket_index(10u32.into())
            .status(ChannelStatus::PendingToClose(std::time::SystemTime::now()))
            .epoch(10u32)
            .build()?;

        backend.insert_account(account.clone())?;
        backend.insert_channel(channel)?;

        let a1 = backend
            .get_account_by_id(&account.key_id)?
            .ok_or(anyhow::anyhow!("account not found"))?;
        let a2 = backend
            .get_account_by_key(kp.public())?
            .ok_or(anyhow::anyhow!("account not found"))?;
        let a3 = backend
            .get_account_by_address(cp.public().as_ref())?
            .ok_or(anyhow::anyhow!("account not found"))?;

        assert_eq!(a1, account);
        assert_eq!(a2, account);
        assert_eq!(a3, account);

        let id = generate_channel_id(&src, &dst);
        let c1 = backend
            .get_channel_by_id(&id)?
            .ok_or(anyhow::anyhow!("channel not found"))?;

        assert_eq!(c1, channel);

        Ok(())
    }

    #[test]
    fn test_inmemory() -> anyhow::Result<()> {
        let backend = InMemoryBackend::default();
        test_backend(backend)
    }

    fn account(key_id: u32, kp: &OffchainKeypair, addr: Address, announced: bool) -> anyhow::Result<AccountEntry> {
        Ok(AccountEntry {
            public_key: *kp.public(),
            chain_addr: addr,
            entry_type: if announced {
                AccountType::Announced(vec!["/ip4/1.2.3.4/tcp/1234".parse()?])
            } else {
                AccountType::NotAnnounced
            },
            safe_address: None,
            key_id: key_id.into(),
        })
    }

    #[test]
    fn inmemory_should_look_up_accounts_by_id_key_and_address() -> anyhow::Result<()> {
        let backend = InMemoryBackend::new();
        let kp = OffchainKeypair::random();
        let addr = ChainKeypair::random().public().to_address();
        let acc = account(1, &kp, addr, true)?;
        backend.insert_account(acc.clone())?;

        assert_eq!(backend.get_account_by_id(&acc.key_id)?, Some(acc.clone()));
        assert_eq!(backend.get_account_by_key(kp.public())?, Some(acc.clone()));
        assert_eq!(backend.get_account_by_address(&addr)?, Some(acc));
        assert_eq!(backend.get_account_by_id(&2.into())?, None);
        assert_eq!(backend.get_account_by_key(OffchainKeypair::random().public())?, None);
        assert_eq!(backend.get_account_by_address(&Address::new(&[9u8; 20]))?, None);
        Ok(())
    }

    #[test]
    fn inmemory_upsert_should_return_the_old_value() -> anyhow::Result<()> {
        let backend = InMemoryBackend::new();
        let kp = OffchainKeypair::random();
        let addr = Address::new(&[1u8; 20]);
        let first = account(1, &kp, addr, false)?;
        let second = account(1, &kp, addr, true)?;

        assert_eq!(backend.insert_account(first.clone())?, None);
        assert_eq!(backend.insert_account(second.clone())?, Some(first));
        assert_eq!(backend.get_account_by_id(&1.into())?, Some(second));

        let channel = ChannelEntry::builder()
            .between(Address::new(&[1u8; 20]), Address::new(&[2u8; 20]))
            .balance(HoprBalance::new_base(1))
            .ticket_index(0u32.into())
            .status(ChannelStatus::Open)
            .epoch(1u32)
            .build()?;
        assert_eq!(backend.insert_channel(channel)?, None);
        assert_eq!(backend.insert_channel(channel)?, Some(channel));
        Ok(())
    }

    #[test]
    fn inmemory_upsert_should_not_leave_stale_key_or_address_mappings() -> anyhow::Result<()> {
        let backend = InMemoryBackend::new();
        let kp1 = OffchainKeypair::random();
        let kp2 = OffchainKeypair::random();
        let addr1 = Address::new(&[1u8; 20]);
        let addr2 = Address::new(&[2u8; 20]);

        backend.insert_account(account(1, &kp1, addr1, true)?)?;
        let updated = account(1, &kp2, addr2, true)?;
        backend.insert_account(updated.clone())?;

        assert_eq!(backend.get_account_by_key(kp1.public())?, None);
        assert_eq!(backend.get_account_by_address(&addr1)?, None);
        assert_eq!(backend.get_account_by_key(kp2.public())?, Some(updated.clone()));
        assert_eq!(backend.get_account_by_address(&addr2)?, Some(updated));
        Ok(())
    }

    #[test]
    fn inmemory_should_count_announced_accounts_without_the_local_one() -> anyhow::Result<()> {
        let backend = InMemoryBackend::new();
        let me = Address::new(&[1u8; 20]);
        backend.insert_account(account(1, &OffchainKeypair::random(), me, true)?)?;
        backend.insert_account(account(2, &OffchainKeypair::random(), Address::new(&[2u8; 20]), true)?)?;
        backend.insert_account(account(3, &OffchainKeypair::random(), Address::new(&[3u8; 20]), true)?)?;
        backend.insert_account(account(4, &OffchainKeypair::random(), Address::new(&[4u8; 20]), false)?)?;

        assert_eq!(backend.count_announced_accounts(&me)?, 2);
        Ok(())
    }
}
