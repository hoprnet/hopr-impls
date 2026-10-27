use blokli_client::api::{BlokliQueryClient, BlokliTransactionClient};
use futures::{FutureExt, StreamExt, future::BoxFuture, stream::BoxStream};
use hopr_api::{
    chain::{ChainReceipt, ChannelSelector},
    types::{chain::prelude::*, crypto::prelude::Keypair, internal::prelude::*, primitive::prelude::*},
};

use crate::{
    backend::Backend,
    connector::{CHANNEL_CUSTOM_TIMEMOUT_MULTIPLIER, HoprBlockchainConnector, channel_sync::ChannelSync},
    errors::ConnectorError,
    utils::model_to_channel_entry,
};

impl<B, C, P, R> HoprBlockchainConnector<C, B, P, R>
where
    B: Backend + Send + Sync + 'static,
{
    /// Writes channel states read from Blokli into this connector.
    pub(crate) fn channel_sync(&self) -> ChannelSync<B> {
        ChannelSync {
            backend: self.backend.clone(),
            channel_by_id: self.channel_by_id.clone(),
            channel_by_parties: self.channel_by_parties.clone(),
            write_lock: self.channel_write_lock.clone(),
            event_tx: self.events.0.clone(),
            me: self.chain_key.public().to_address(),
        }
    }

    pub(crate) fn build_channel_stream(
        &self,
        selector: ChannelSelector,
    ) -> Result<impl futures::Stream<Item = ChannelEntry> + Send + 'static, ConnectorError> {
        // Note: Since the graph does not contain Closed channels, they cannot
        // be selected if requested solely via the ChannelSelector.
        if selector.allowed_states == [ChannelStatusDiscriminants::Closed] {
            return Err(ConnectorError::InvalidArguments("cannot stream closed channels only"));
        }

        let mut channels = self
            .graph
            .read()
            .all_edges()
            .map(|(_, _, e)| e)
            .copied()
            .collect::<Vec<_>>();

        // Ensure the returned channels are always perfectly ordered by their id.
        channels.sort_unstable();

        let backend = self.backend.clone();
        Ok(futures::stream::iter(channels).filter_map(move |channel_id| {
            let backend = backend.clone();
            let selector = selector.clone();
            // This avoids the cache on purpose so it does not get spammed
            async move {
                match hopr_utils::runtime::prelude::spawn_blocking(move || backend.get_channel_by_id(&channel_id)).await
                {
                    Ok(Ok(value)) => value.filter(|c| selector.satisfies(c)),
                    Ok(Err(error)) => {
                        tracing::error!(%error, %channel_id, "backend error when looking up channel");
                        None
                    }
                    Err(error) => {
                        tracing::error!(%error, %channel_id, "join error when looking up channel");
                        None
                    }
                }
            }
        }))
    }
}

async fn channel_by_id_async<B: Backend + Send + Sync + 'static>(
    channel_by_id: moka::sync::Cache<ChannelId, Option<ChannelEntry>, ahash::RandomState>,
    backend: std::sync::Arc<B>,
    channel_id: ChannelId,
) -> Result<Option<ChannelEntry>, ConnectorError> {
    Ok(hopr_utils::runtime::prelude::spawn_blocking(move || {
        channel_by_id.try_get_with_by_ref(&channel_id, || {
            tracing::warn!(%channel_id, "cache miss on channel_by_id");
            backend.get_channel_by_id(&channel_id).map_err(ConnectorError::backend)
        })
    })
    .await
    .map_err(ConnectorError::backend)??)
}

#[async_trait::async_trait]
impl<B, C, P, R> hopr_api::chain::ChainReadChannelOperations for HoprBlockchainConnector<C, B, P, R>
where
    B: Backend + Send + Sync + 'static,
    C: Send + Sync,
    P: Send + Sync,
    R: Send + Sync,
{
    type Error = ConnectorError;

    fn me(&self) -> &Address {
        self.chain_key.public().as_ref()
    }

    fn channel_by_parties(&self, src: &Address, dst: &Address) -> Result<Option<ChannelEntry>, Self::Error> {
        self.check_connection_state()?;

        let src = *src;
        let dst = *dst;
        Ok(self
            .channel_by_parties
            .try_get_with(ChannelParties::new(src, dst), || {
                tracing::warn!(%src, %dst, "cache miss on channel_by_parties");
                let channel_id = generate_channel_id(&src, &dst);
                self.backend
                    .get_channel_by_id(&channel_id)
                    .map_err(ConnectorError::backend)
            })?)
    }

    fn channel_by_id(&self, channel_id: &ChannelId) -> Result<Option<ChannelEntry>, Self::Error> {
        self.check_connection_state()?;

        Ok(self.channel_by_id.try_get_with_by_ref(channel_id, || {
            tracing::warn!(%channel_id, "cache miss on channel_by_id");
            self.backend
                .get_channel_by_id(channel_id)
                .map_err(ConnectorError::backend)
        })?)
    }

    fn stream_channels(&self, selector: ChannelSelector) -> Result<BoxStream<'_, ChannelEntry>, Self::Error> {
        self.check_connection_state()?;

        Ok(self.build_channel_stream(selector)?.boxed())
    }
}

impl<B, C, P, R> HoprBlockchainConnector<C, B, P, R>
where
    B: Backend + Send + Sync + 'static,
    C: BlokliQueryClient + Send + Sync + 'static,
{
    /// Reads the current state of the `stored` channel from Blokli and stores it if it is newer.
    ///
    /// Returns the latest known state of the channel. Fails if Blokli cannot be asked, so that no transaction is sent
    /// based on a state that might be out of date.
    async fn read_channel_from_blokli(&self, stored: &ChannelEntry) -> Result<ChannelEntry, ConnectorError> {
        let channel_id = *stored.get_id();
        let model = self
            .client
            .query_channels(blokli_client::api::ChannelSelector {
                filter: Some(blokli_client::api::ChannelFilter::ChannelId(channel_id.into())),
                status: None,
                ..Default::default()
            })
            .await?
            .channels
            .into_iter()
            .next()
            .ok_or(ConnectorError::ChannelDoesNotExist(channel_id))?;

        let fresh = model_to_channel_entry(&model, stored.source, stored.destination)?;
        self.channel_sync()
            .refresh(fresh)
            .await?
            .ok_or(ConnectorError::ChannelDoesNotExist(channel_id))
    }
}

#[async_trait::async_trait]
impl<B, C, P> hopr_api::chain::ChainWriteChannelOperations for HoprBlockchainConnector<C, B, P, P::TxRequest>
where
    B: Backend + Send + Sync + 'static,
    C: BlokliQueryClient + BlokliTransactionClient + Send + Sync + 'static,
    P: PayloadGenerator + Send + Sync + 'static,
    P::TxRequest: Send + Sync + 'static,
{
    type Error = ConnectorError;

    async fn open_channel<'a>(
        &'a self,
        dst: &'a Address,
        amount: HoprBalance,
    ) -> Result<BoxFuture<'a, Result<ChainReceipt, Self::Error>>, Self::Error> {
        self.check_connection_state()?;

        let tx_req = self.payload_generator.fund_channel(*dst, amount)?;
        tracing::debug!( %dst, %amount, "opening channel");

        Ok(self
            .send_tx(tx_req, Some(CHANNEL_CUSTOM_TIMEMOUT_MULTIPLIER), None)
            .await?
            .boxed())
    }

    async fn fund_channel<'a>(
        &'a self,
        channel_id: &'a ChannelId,
        amount: HoprBalance,
    ) -> Result<BoxFuture<'a, Result<ChainReceipt, Self::Error>>, Self::Error> {
        self.check_connection_state()?;

        let channel = channel_by_id_async(self.channel_by_id.clone(), self.backend.clone(), *channel_id)
            .await?
            .ok_or_else(|| ConnectorError::ChannelDoesNotExist(*channel_id))?;

        let tx_req = self.payload_generator.fund_channel(channel.destination, amount)?;
        tracing::debug!(%channel_id, %amount, "funding channel");

        Ok(self
            .send_tx(tx_req, Some(CHANNEL_CUSTOM_TIMEMOUT_MULTIPLIER), None)
            .await?
            .boxed())
    }

    async fn close_channel<'a>(
        &'a self,
        channel_id: &'a ChannelId,
    ) -> Result<BoxFuture<'a, Result<ChainReceipt, Self::Error>>, Self::Error> {
        self.check_connection_state()?;

        use hopr_api::chain::ChainReadChannelOperations;

        let stored = channel_by_id_async(self.channel_by_id.clone(), self.backend.clone(), *channel_id)
            .await?
            .ok_or_else(|| ConnectorError::ChannelDoesNotExist(*channel_id))?;

        let direction = stored.direction(self.me()).ok_or(ConnectorError::InvalidArguments(
            "cannot close channels that is not own",
        ))?;

        // The same call starts and finishes a closure, depending on the channel status. A stored status that missed
        // an update picks the wrong step: starting a closure again on a channel already pending to close restarts
        // its notice period. So the status is read from Blokli first.
        let channel = self.read_channel_from_blokli(&stored).await?;

        let tx_req = match channel.status {
            ChannelStatus::Closed => return Err(ConnectorError::ChannelClosed(*channel_id)),
            ChannelStatus::Open => {
                if direction == ChannelDirection::Outgoing {
                    tracing::debug!(%channel_id, "initiating outgoing channel closure");
                    self.payload_generator
                        .initiate_outgoing_channel_closure(channel.destination)?
                } else {
                    tracing::debug!(%channel_id, "closing incoming channel");
                    self.payload_generator.close_incoming_channel(channel.source)?
                }
            }
            c if c.closure_time_elapsed(&std::time::SystemTime::now()) => {
                if direction == ChannelDirection::Outgoing {
                    tracing::debug!(%channel_id, "finalizing outgoing channel closure");
                    self.payload_generator
                        .finalize_outgoing_channel_closure(channel.destination)?
                } else {
                    tracing::debug!(%channel_id, "closing incoming channel");
                    self.payload_generator.close_incoming_channel(channel.source)?
                }
            }
            _ => return Err(ConnectorError::InvalidState("channel closure time has not elapsed")),
        };

        Ok(self
            .send_tx(tx_req, Some(CHANNEL_CUSTOM_TIMEMOUT_MULTIPLIER), None)
            .await?
            .boxed())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use hex_literal::hex;
    use hopr_api::{
        chain::{ChainReadChannelOperations, ChainWriteChannelOperations},
        types::crypto::keypairs::{ChainKeypair, OffchainKeypair},
    };

    use super::*;
    use crate::{
        connector::{
            channel_sync::tests::{channel, pending_since, test_state},
            tests::{MODULE_ADDR, PRIVATE_KEY_1, PRIVATE_KEY_2, create_connector},
        },
        testing::BlokliTestStateBuilder,
    };

    #[tokio::test]
    async fn a_pre_close_query_returns_the_newer_stored_pending_state() -> anyhow::Result<()> {
        let open = channel(ChannelStatus::Open, 1)?;
        let mut connector = create_connector(test_state(open)?.build_dynamic_client(MODULE_ADDR.into()))?;
        connector.connect().await?;

        // The caller captured Open before querying. The subscription advances the backend while the query's
        // snapshot still says Open. The rejected response must not be returned to transaction selection.
        let pending = channel(pending_since(10), 1)?;
        connector.channel_sync().apply(pending).await?;
        assert_eq!(
            Some(connector.read_channel_from_blokli(&open).await?.status),
            Some(pending.status)
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_pre_close_query_returns_the_newer_stored_closed_state() -> anyhow::Result<()> {
        let pending = channel(pending_since(10), 1)?;
        let mut connector = create_connector(test_state(pending)?.build_dynamic_client(MODULE_ADDR.into()))?;
        connector.connect().await?;

        connector
            .channel_sync()
            .apply(channel(ChannelStatus::Closed, 1)?)
            .await?;
        assert_eq!(
            Some(connector.read_channel_from_blokli(&pending).await?.status),
            Some(ChannelStatus::Closed)
        );
        Ok(())
    }

    #[tokio::test]
    async fn connector_should_get_and_stream_channels() -> anyhow::Result<()> {
        let offchain_key_1 = OffchainKeypair::from_secret(&hex!(
            "60741b83b99e36aa0c1331578156e16b8e21166d01834abb6c64b103f885734d"
        ))?;
        let account_1 = AccountEntry {
            public_key: *offchain_key_1.public(),
            chain_addr: ChainKeypair::from_secret(&PRIVATE_KEY_1)?.public().to_address(),
            entry_type: AccountType::NotAnnounced,
            safe_address: Some([1u8; Address::SIZE].into()),
            key_id: 1.into(),
        };
        let offchain_key_2 = OffchainKeypair::from_secret(&hex!(
            "71bf1f42ebbfcd89c3e197a3fd7cda79b92499e509b6fefa0fe44d02821d146a"
        ))?;
        let account_2 = AccountEntry {
            public_key: *offchain_key_2.public(),
            chain_addr: ChainKeypair::from_secret(&PRIVATE_KEY_2)?.public().to_address(),
            entry_type: AccountType::NotAnnounced,
            safe_address: Some([2u8; Address::SIZE].into()),
            key_id: 2.into(),
        };

        let channel_1 = ChannelEntry::builder()
            .between(
                &ChainKeypair::from_secret(&PRIVATE_KEY_1)?,
                &ChainKeypair::from_secret(&PRIVATE_KEY_2)?,
            )
            .amount(10)
            .ticket_index(1)
            .status(ChannelStatus::Open)
            .epoch(1)
            .build()?;

        let channel_2 = ChannelEntry::builder()
            .between(
                &ChainKeypair::from_secret(&PRIVATE_KEY_2)?,
                &ChainKeypair::from_secret(&PRIVATE_KEY_1)?,
            )
            .amount(15)
            .ticket_index(2)
            .status(ChannelStatus::PendingToClose(
                std::time::SystemTime::UNIX_EPOCH + Duration::from_mins(10),
            ))
            .epoch(1)
            .build()?;

        let blokli_client = BlokliTestStateBuilder::default()
            .with_accounts([
                (account_1, HoprBalance::new_base(100), XDaiBalance::new_base(1)),
                (account_2, HoprBalance::new_base(100), XDaiBalance::new_base(1)),
            ])
            .with_channels([channel_1, channel_2])
            .with_hopr_network_chain_info("piz-palu-staging")
            .build_dynamic_client(MODULE_ADDR.into());

        let mut connector = create_connector(blokli_client)?;
        connector.connect().await?;

        // `connect()`'s readiness threshold only accounts for `Open` channels, so the
        // `PendingToClose` `channel_2` is indexed by the background sync task, which can
        // lag under load (e.g. a busy CI runner). Wait for it to be indexed before
        // asserting the exact channel state.
        for _ in 0..250 {
            if connector.channel_by_id(channel_2.get_id())?.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        assert_eq!(Some(channel_1), connector.channel_by_id(channel_1.get_id())?);
        assert_eq!(
            Some(channel_1),
            connector.channel_by_parties(&channel_1.source, &channel_1.destination)?
        );
        assert_eq!(Some(channel_2), connector.channel_by_id(channel_2.get_id())?);
        assert_eq!(
            Some(channel_2),
            connector.channel_by_parties(&channel_2.source, &channel_2.destination)?
        );

        assert_eq!(
            vec![channel_1, channel_2],
            connector
                .stream_channels(ChannelSelector::default())?
                .collect::<Vec<_>>()
                .await
        );

        assert_eq!(
            vec![channel_1],
            connector
                .stream_channels(ChannelSelector::default().with_allowed_states(&[ChannelStatusDiscriminants::Open]))?
                .collect::<Vec<_>>()
                .await
        );
        assert_eq!(
            vec![channel_2],
            connector
                .stream_channels(
                    ChannelSelector::default().with_allowed_states(&[ChannelStatusDiscriminants::PendingToClose])
                )?
                .collect::<Vec<_>>()
                .await
        );
        assert_eq!(
            Vec::<ChannelEntry>::new(),
            connector
                .stream_channels(
                    ChannelSelector::default()
                        .with_allowed_states(&[ChannelStatusDiscriminants::PendingToClose])
                        .with_closure_time_range(
                            DateTime::from(std::time::SystemTime::UNIX_EPOCH + Duration::from_mins(11))..
                        )
                )?
                .collect::<Vec<_>>()
                .await
        );

        Ok(())
    }

    #[tokio::test]
    async fn connector_should_open_channel() -> anyhow::Result<()> {
        let offchain_key_1 = OffchainKeypair::from_secret(&hex!(
            "60741b83b99e36aa0c1331578156e16b8e21166d01834abb6c64b103f885734d"
        ))?;
        let account_1 = AccountEntry {
            public_key: *offchain_key_1.public(),
            chain_addr: ChainKeypair::from_secret(&PRIVATE_KEY_1)?.public().to_address(),
            entry_type: AccountType::NotAnnounced,
            safe_address: Some([1u8; Address::SIZE].into()),
            key_id: 1.into(),
        };
        let offchain_key_2 = OffchainKeypair::from_secret(&hex!(
            "71bf1f42ebbfcd89c3e197a3fd7cda79b92499e509b6fefa0fe44d02821d146a"
        ))?;
        let account_2 = AccountEntry {
            public_key: *offchain_key_2.public(),
            chain_addr: ChainKeypair::from_secret(&PRIVATE_KEY_2)?.public().to_address(),
            entry_type: AccountType::NotAnnounced,
            safe_address: Some([2u8; Address::SIZE].into()),
            key_id: 2.into(),
        };

        let blokli_client = BlokliTestStateBuilder::default()
            .with_accounts([
                (account_1.clone(), HoprBalance::new_base(100), XDaiBalance::new_base(1)),
                (account_2.clone(), HoprBalance::new_base(100), XDaiBalance::new_base(1)),
            ])
            .with_hopr_network_chain_info("piz-palu-staging")
            .build_dynamic_client(MODULE_ADDR.into());

        let mut connector = create_connector(blokli_client)?;
        connector.connect().await?;

        connector.open_channel(&account_2.chain_addr, 10.into()).await?.await?;

        insta::assert_yaml_snapshot!(*connector.client().snapshot());

        Ok(())
    }

    #[tokio::test]
    async fn connector_should_fund_channel() -> anyhow::Result<()> {
        let offchain_key_1 = OffchainKeypair::from_secret(&hex!(
            "60741b83b99e36aa0c1331578156e16b8e21166d01834abb6c64b103f885734d"
        ))?;
        let account_1 = AccountEntry {
            public_key: *offchain_key_1.public(),
            chain_addr: ChainKeypair::from_secret(&PRIVATE_KEY_1)?.public().to_address(),
            entry_type: AccountType::NotAnnounced,
            safe_address: Some([1u8; Address::SIZE].into()),
            key_id: 1.into(),
        };
        let offchain_key_2 = OffchainKeypair::from_secret(&hex!(
            "71bf1f42ebbfcd89c3e197a3fd7cda79b92499e509b6fefa0fe44d02821d146a"
        ))?;
        let account_2 = AccountEntry {
            public_key: *offchain_key_2.public(),
            chain_addr: ChainKeypair::from_secret(&PRIVATE_KEY_2)?.public().to_address(),
            entry_type: AccountType::NotAnnounced,
            safe_address: Some([2u8; Address::SIZE].into()),
            key_id: 2.into(),
        };

        let channel_1 = ChannelEntry::builder()
            .between(
                &ChainKeypair::from_secret(&PRIVATE_KEY_1)?,
                &ChainKeypair::from_secret(&PRIVATE_KEY_2)?,
            )
            .amount(10)
            .ticket_index(1)
            .status(ChannelStatus::Open)
            .epoch(1)
            .build()?;

        let blokli_client = BlokliTestStateBuilder::default()
            .with_accounts([
                (account_1, HoprBalance::new_base(100), XDaiBalance::new_base(1)),
                (account_2, HoprBalance::new_base(100), XDaiBalance::new_base(1)),
            ])
            .with_channels([channel_1])
            .with_hopr_network_chain_info("piz-palu-staging")
            .build_dynamic_client(MODULE_ADDR.into());

        let mut connector = create_connector(blokli_client)?;
        connector.connect().await?;

        connector.fund_channel(channel_1.get_id(), 5.into()).await?.await?;

        insta::assert_yaml_snapshot!(*connector.client().snapshot());

        Ok(())
    }

    #[tokio::test]
    async fn connector_should_initiate_channel_closure() -> anyhow::Result<()> {
        let offchain_key_1 = OffchainKeypair::from_secret(&hex!(
            "60741b83b99e36aa0c1331578156e16b8e21166d01834abb6c64b103f885734d"
        ))?;
        let account_1 = AccountEntry {
            public_key: *offchain_key_1.public(),
            chain_addr: ChainKeypair::from_secret(&PRIVATE_KEY_1)?.public().to_address(),
            entry_type: AccountType::NotAnnounced,
            safe_address: Some([1u8; Address::SIZE].into()),
            key_id: 1.into(),
        };
        let offchain_key_2 = OffchainKeypair::from_secret(&hex!(
            "71bf1f42ebbfcd89c3e197a3fd7cda79b92499e509b6fefa0fe44d02821d146a"
        ))?;
        let account_2 = AccountEntry {
            public_key: *offchain_key_2.public(),
            chain_addr: ChainKeypair::from_secret(&PRIVATE_KEY_2)?.public().to_address(),
            entry_type: AccountType::NotAnnounced,
            safe_address: Some([2u8; Address::SIZE].into()),
            key_id: 2.into(),
        };

        let channel_1 = ChannelEntry::builder()
            .between(
                &ChainKeypair::from_secret(&PRIVATE_KEY_1)?,
                &ChainKeypair::from_secret(&PRIVATE_KEY_2)?,
            )
            .amount(10)
            .ticket_index(1)
            .status(ChannelStatus::Open)
            .epoch(1)
            .build()?;

        let blokli_client = BlokliTestStateBuilder::default()
            .with_accounts([
                (account_1, HoprBalance::new_base(100), XDaiBalance::new_base(1)),
                (account_2, HoprBalance::new_base(100), XDaiBalance::new_base(1)),
            ])
            .with_channels([channel_1])
            .with_hopr_network_chain_info("piz-palu-staging")
            .build_dynamic_client(MODULE_ADDR.into());

        let mut connector = create_connector(blokli_client)?;
        connector.connect().await?;

        connector.close_channel(channel_1.get_id()).await?.await?;

        let mut snapshot = (*connector.client().snapshot()).clone();

        // Replace the closure time value to make the snapshot deterministic
        snapshot
            .channels
            .get_mut(&const_hex::encode(channel_1.get_id()))
            .unwrap()
            .closure_time = Some(blokli_client::api::types::DateTime("dummy".into()));

        insta::assert_yaml_snapshot!(snapshot);

        Ok(())
    }

    #[tokio::test]
    async fn connector_should_finalize_channel_closure() -> anyhow::Result<()> {
        let offchain_key_1 = OffchainKeypair::from_secret(&hex!(
            "60741b83b99e36aa0c1331578156e16b8e21166d01834abb6c64b103f885734d"
        ))?;
        let account_1 = AccountEntry {
            public_key: *offchain_key_1.public(),
            chain_addr: ChainKeypair::from_secret(&PRIVATE_KEY_1)?.public().to_address(),
            entry_type: AccountType::NotAnnounced,
            safe_address: Some([1u8; Address::SIZE].into()),
            key_id: 1.into(),
        };
        let offchain_key_2 = OffchainKeypair::from_secret(&hex!(
            "71bf1f42ebbfcd89c3e197a3fd7cda79b92499e509b6fefa0fe44d02821d146a"
        ))?;
        let account_2 = AccountEntry {
            public_key: *offchain_key_2.public(),
            chain_addr: ChainKeypair::from_secret(&PRIVATE_KEY_2)?.public().to_address(),
            entry_type: AccountType::NotAnnounced,
            safe_address: Some([2u8; Address::SIZE].into()),
            key_id: 2.into(),
        };

        let channel_1 = ChannelEntry::builder()
            .between(
                &ChainKeypair::from_secret(&PRIVATE_KEY_1)?,
                &ChainKeypair::from_secret(&PRIVATE_KEY_2)?,
            )
            .amount(10)
            .ticket_index(1)
            .status(ChannelStatus::PendingToClose(
                std::time::SystemTime::UNIX_EPOCH + Duration::from_mins(10),
            ))
            .epoch(1)
            .build()?;

        let blokli_client = BlokliTestStateBuilder::default()
            .with_accounts([
                (account_1, HoprBalance::new_base(100), XDaiBalance::new_base(1)),
                (account_2, HoprBalance::new_base(100), XDaiBalance::new_base(1)),
            ])
            .with_channels([channel_1])
            .with_hopr_network_chain_info("piz-palu-staging")
            .build_dynamic_client(MODULE_ADDR.into());

        let mut connector = create_connector(blokli_client)?;
        connector.connect().await?;

        connector.close_channel(channel_1.get_id()).await?.await?;

        insta::assert_yaml_snapshot!(*connector.client().snapshot());

        Ok(())
    }

    #[tokio::test]
    async fn connector_should_finalize_a_closure_the_subscription_missed() -> anyhow::Result<()> {
        let offchain_key_1 = OffchainKeypair::from_secret(&hex!(
            "60741b83b99e36aa0c1331578156e16b8e21166d01834abb6c64b103f885734d"
        ))?;
        let account_1 = AccountEntry {
            public_key: *offchain_key_1.public(),
            chain_addr: ChainKeypair::from_secret(&PRIVATE_KEY_1)?.public().to_address(),
            entry_type: AccountType::NotAnnounced,
            safe_address: Some([1u8; Address::SIZE].into()),
            key_id: 1.into(),
        };
        let offchain_key_2 = OffchainKeypair::from_secret(&hex!(
            "71bf1f42ebbfcd89c3e197a3fd7cda79b92499e509b6fefa0fe44d02821d146a"
        ))?;
        let account_2 = AccountEntry {
            public_key: *offchain_key_2.public(),
            chain_addr: ChainKeypair::from_secret(&PRIVATE_KEY_2)?.public().to_address(),
            entry_type: AccountType::NotAnnounced,
            safe_address: Some([2u8; Address::SIZE].into()),
            key_id: 2.into(),
        };

        let channel_1 = ChannelEntry::builder()
            .between(
                &ChainKeypair::from_secret(&PRIVATE_KEY_1)?,
                &ChainKeypair::from_secret(&PRIVATE_KEY_2)?,
            )
            .amount(10)
            .ticket_index(1)
            .status(ChannelStatus::Open)
            .epoch(1)
            .build()?;

        let blokli_client = BlokliTestStateBuilder::default()
            .with_accounts([
                (account_1, HoprBalance::new_base(100), XDaiBalance::new_base(1)),
                (account_2, HoprBalance::new_base(100), XDaiBalance::new_base(1)),
            ])
            .with_channels([channel_1])
            .with_hopr_network_chain_info("piz-palu-staging")
            .build_dynamic_client(MODULE_ADDR.into());

        let mut connector = create_connector(blokli_client)?;
        connector.connect().await?;

        // The closure was started on-chain, but the subscription did not deliver it: the node still sees the
        // channel as open.
        let notice_period_end = blokli_client::api::types::DateTime(
            hopr_api::chain::DateTime::from(std::time::SystemTime::now() - Duration::from_secs(60)).to_rfc3339(),
        );
        connector.client().hidden_state_update(|state| {
            if let Some(channel) = state.get_channel_by_id_mut(&(*channel_1.get_id()).into()) {
                channel.status = blokli_client::api::types::ChannelStatus::PendingToClose;
                channel.closure_time = Some(notice_period_end.clone());
            }
        });
        assert_eq!(
            connector.channel_by_id(channel_1.get_id())?.map(|c| c.status),
            Some(ChannelStatus::Open)
        );

        connector.close_channel(channel_1.get_id()).await?.await?;

        // Starting the closure again would have moved the closure time instead of closing the channel.
        let snapshot = connector.client().snapshot();
        let on_chain = snapshot
            .channels
            .get(&const_hex::encode(channel_1.get_id()))
            .expect("channel exists");
        assert_eq!(on_chain.status, blokli_client::api::types::ChannelStatus::Closed);
        assert_eq!(on_chain.closure_time, Some(notice_period_end));

        Ok(())
    }

    #[tokio::test]
    async fn connector_should_close_incoming_channel() -> anyhow::Result<()> {
        let offchain_key_1 = OffchainKeypair::from_secret(&hex!(
            "60741b83b99e36aa0c1331578156e16b8e21166d01834abb6c64b103f885734d"
        ))?;
        let account_1 = AccountEntry {
            public_key: *offchain_key_1.public(),
            chain_addr: ChainKeypair::from_secret(&PRIVATE_KEY_1)?.public().to_address(),
            entry_type: AccountType::NotAnnounced,
            safe_address: Some([1u8; Address::SIZE].into()),
            key_id: 1.into(),
        };
        let offchain_key_2 = OffchainKeypair::from_secret(&hex!(
            "71bf1f42ebbfcd89c3e197a3fd7cda79b92499e509b6fefa0fe44d02821d146a"
        ))?;
        let account_2 = AccountEntry {
            public_key: *offchain_key_2.public(),
            chain_addr: ChainKeypair::from_secret(&PRIVATE_KEY_2)?.public().to_address(),
            entry_type: AccountType::NotAnnounced,
            safe_address: Some([2u8; Address::SIZE].into()),
            key_id: 2.into(),
        };

        let channel_1 = ChannelEntry::builder()
            .between(
                &ChainKeypair::from_secret(&PRIVATE_KEY_2)?,
                &ChainKeypair::from_secret(&PRIVATE_KEY_1)?,
            )
            .amount(10)
            .ticket_index(1)
            .status(ChannelStatus::Open)
            .epoch(1)
            .build()?;

        let blokli_client = BlokliTestStateBuilder::default()
            .with_accounts([
                (account_1, HoprBalance::new_base(100), XDaiBalance::new_base(1)),
                (account_2, HoprBalance::new_base(100), XDaiBalance::new_base(1)),
            ])
            .with_channels([channel_1])
            .with_hopr_network_chain_info("piz-palu-staging")
            .build_dynamic_client(MODULE_ADDR.into());

        let mut connector = create_connector(blokli_client)?;
        connector.connect().await?;

        connector.close_channel(channel_1.get_id()).await?.await?;

        insta::assert_yaml_snapshot!(*connector.client().snapshot());

        Ok(())
    }

    #[tokio::test]
    async fn connector_should_not_close_non_existing_channel() -> anyhow::Result<()> {
        let blokli_client = BlokliTestStateBuilder::default()
            .with_hopr_network_chain_info("piz-palu-staging")
            .build_dynamic_client(MODULE_ADDR.into());

        let mut connector = create_connector(blokli_client)?;
        connector.connect().await?;

        let channel_id = ChannelId::from([1u8; ChannelId::SIZE]);
        let result = connector.close_channel(&channel_id).await;

        match result {
            Err(e) => {
                let err_msg = e.to_string();
                assert!(
                    err_msg.contains("does not exist"),
                    "Expected 'does not exist' error, got: {}",
                    err_msg
                );
            }
            _ => panic!("Expected error when closing non-existing channel"),
        }

        Ok(())
    }

    #[tokio::test]
    async fn connector_should_not_close_already_closed_channel() -> anyhow::Result<()> {
        let offchain_key_1 = OffchainKeypair::from_secret(&hex!(
            "60741b83b99e36aa0c1331578156e16b8e21166d01834abb6c64b103f885734d"
        ))?;
        let account_1 = AccountEntry {
            public_key: *offchain_key_1.public(),
            chain_addr: ChainKeypair::from_secret(&PRIVATE_KEY_1)?.public().to_address(),
            entry_type: AccountType::NotAnnounced,
            safe_address: Some([1u8; Address::SIZE].into()),
            key_id: 1.into(),
        };
        let offchain_key_2 = OffchainKeypair::from_secret(&hex!(
            "71bf1f42ebbfcd89c3e197a3fd7cda79b92499e509b6fefa0fe44d02821d146a"
        ))?;
        let account_2 = AccountEntry {
            public_key: *offchain_key_2.public(),
            chain_addr: ChainKeypair::from_secret(&PRIVATE_KEY_2)?.public().to_address(),
            entry_type: AccountType::NotAnnounced,
            safe_address: Some([2u8; Address::SIZE].into()),
            key_id: 2.into(),
        };

        let channel_1 = ChannelEntry::builder()
            .between(
                &ChainKeypair::from_secret(&PRIVATE_KEY_1)?,
                &ChainKeypair::from_secret(&PRIVATE_KEY_2)?,
            )
            .amount(10)
            .ticket_index(1)
            .status(ChannelStatus::Closed)
            .epoch(1)
            .build()?;

        let blokli_client = BlokliTestStateBuilder::default()
            .with_accounts([
                (account_1, HoprBalance::new_base(100), XDaiBalance::new_base(1)),
                (account_2, HoprBalance::new_base(100), XDaiBalance::new_base(1)),
            ])
            .with_channels([channel_1])
            .with_hopr_network_chain_info("piz-palu-staging")
            .build_dynamic_client(MODULE_ADDR.into());

        let mut connector = create_connector(blokli_client)?;
        connector.connect().await?;

        let result = connector.close_channel(channel_1.get_id()).await;

        match result {
            Err(e) => {
                let err_msg = e.to_string();
                assert!(
                    err_msg.contains("is closed"),
                    "Expected 'is closed' error, got: {}",
                    err_msg
                );
            }
            _ => panic!("Expected error when closing already closed channel"),
        }

        Ok(())
    }

    #[tokio::test]
    async fn connector_should_not_close_unowned_channel() -> anyhow::Result<()> {
        let offchain_key_2 = OffchainKeypair::from_secret(&hex!(
            "71bf1f42ebbfcd89c3e197a3fd7cda79b92499e509b6fefa0fe44d02821d146a"
        ))?;
        let account_2 = AccountEntry {
            public_key: *offchain_key_2.public(),
            chain_addr: ChainKeypair::from_secret(&PRIVATE_KEY_2)?.public().to_address(),
            entry_type: AccountType::NotAnnounced,
            safe_address: Some([2u8; Address::SIZE].into()),
            key_id: 2.into(),
        };
        let _offchain_key_3 = OffchainKeypair::from_secret(&hex!(
            "0000000000000000000000000000000000000000000000000000000000000003"
        ))?;
        let account_3 = AccountEntry {
            public_key: *_offchain_key_3.public(),
            chain_addr: ChainKeypair::from_secret(&hex!(
                "0000000000000000000000000000000000000000000000000000000000000003"
            ))?
            .public()
            .to_address(),
            entry_type: AccountType::NotAnnounced,
            safe_address: Some([3u8; Address::SIZE].into()),
            key_id: 3.into(),
        };

        // node is using PRIVATE_KEY_1, so it owns account_1
        // this channel is between PRIVATE_KEY_2 and PRIVATE_KEY_3
        let channel_1 = ChannelEntry::builder()
            .between(
                &ChainKeypair::from_secret(&PRIVATE_KEY_2)?,
                &ChainKeypair::from_secret(&hex!(
                    "0000000000000000000000000000000000000000000000000000000000000003"
                ))?,
            )
            .amount(10)
            .ticket_index(1)
            .status(ChannelStatus::Open)
            .epoch(1)
            .build()?;

        let blokli_client = BlokliTestStateBuilder::default()
            .with_accounts([
                (account_2, HoprBalance::new_base(100), XDaiBalance::new_base(1)),
                (account_3, HoprBalance::new_base(100), XDaiBalance::new_base(1)),
            ])
            .with_channels([channel_1])
            .with_hopr_network_chain_info("piz-palu-staging")
            .build_dynamic_client(MODULE_ADDR.into());

        let mut connector = create_connector(blokli_client)?;
        connector.connect().await?;

        let result = connector.close_channel(channel_1.get_id()).await;

        match result {
            Err(e) => {
                let err_msg = e.to_string();
                assert!(
                    err_msg.contains("cannot close channels that is not own"),
                    "Expected ownership error, got: {}",
                    err_msg
                );
            }
            _ => panic!("Expected error when closing unowned channel"),
        }

        Ok(())
    }

    #[tokio::test]
    async fn connector_should_not_fund_non_existing_channel() -> anyhow::Result<()> {
        let blokli_client = BlokliTestStateBuilder::default()
            .with_hopr_network_chain_info("piz-palu-staging")
            .build_dynamic_client(MODULE_ADDR.into());

        let mut connector = create_connector(blokli_client)?;
        connector.connect().await?;

        let channel_id = ChannelId::from([1u8; ChannelId::SIZE]);
        let result = connector.fund_channel(&channel_id, 10.into()).await;

        match result {
            Err(e) => {
                let err_msg = e.to_string();
                assert!(
                    err_msg.contains("does not exist"),
                    "Expected 'does not exist' error, got: {}",
                    err_msg
                );
            }
            _ => panic!("Expected error when funding non-existing channel"),
        }

        Ok(())
    }

    #[tokio::test]
    async fn connector_should_not_finalize_channel_closure_before_time() -> anyhow::Result<()> {
        let offchain_key_1 = OffchainKeypair::from_secret(&hex!(
            "60741b83b99e36aa0c1331578156e16b8e21166d01834abb6c64b103f885734d"
        ))?;
        let account_1 = AccountEntry {
            public_key: *offchain_key_1.public(),
            chain_addr: ChainKeypair::from_secret(&PRIVATE_KEY_1)?.public().to_address(),
            entry_type: AccountType::NotAnnounced,
            safe_address: Some([1u8; Address::SIZE].into()),
            key_id: 1.into(),
        };
        let offchain_key_2 = OffchainKeypair::from_secret(&hex!(
            "71bf1f42ebbfcd89c3e197a3fd7cda79b92499e509b6fefa0fe44d02821d146a"
        ))?;
        let account_2 = AccountEntry {
            public_key: *offchain_key_2.public(),
            chain_addr: ChainKeypair::from_secret(&PRIVATE_KEY_2)?.public().to_address(),
            entry_type: AccountType::NotAnnounced,
            safe_address: Some([2u8; Address::SIZE].into()),
            key_id: 2.into(),
        };

        let channel_1 = ChannelEntry::builder()
            .between(
                &ChainKeypair::from_secret(&PRIVATE_KEY_1)?,
                &ChainKeypair::from_secret(&PRIVATE_KEY_2)?,
            )
            .amount(10)
            .ticket_index(1)
            .status(ChannelStatus::PendingToClose(
                std::time::SystemTime::now() + Duration::from_secs(3600),
            ))
            .epoch(1)
            .build()?;

        let blokli_client = BlokliTestStateBuilder::default()
            .with_accounts([
                (account_1, HoprBalance::new_base(100), XDaiBalance::new_base(1)),
                (account_2, HoprBalance::new_base(100), XDaiBalance::new_base(1)),
            ])
            .with_channels([channel_1])
            .with_hopr_network_chain_info("piz-palu-staging")
            .build_dynamic_client(MODULE_ADDR.into());

        let mut connector = create_connector(blokli_client)?;
        connector.connect().await?;

        let result = connector.close_channel(channel_1.get_id()).await;

        match result {
            Err(e) => {
                let err_msg = e.to_string();
                assert!(
                    err_msg.contains("channel closure time has not elapsed"),
                    "Expected time elapsed error, got: {}",
                    err_msg
                );
            }
            _ => panic!("Expected error when closing channel before time elapsed"),
        }

        Ok(())
    }
}
