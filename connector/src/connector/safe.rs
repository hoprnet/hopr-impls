use std::{sync::Arc, time::Duration};

use blokli_client::api::{BlokliQueryClient, BlokliSubscriptionClient, BlokliTransactionClient};
use futures::{FutureExt, StreamExt, future::BoxFuture, stream::BoxStream};
use hopr_api::{
    chain::{ChainReceipt, ChainValues, DeployedSafe, SafeSelector},
    types::{chain::prelude::PayloadGenerator, crypto::prelude::Keypair, primitive::prelude::*},
};

use crate::{Backend, HoprBlockchainConnector, HoprBlockchainReader, errors::ConnectorError};

#[async_trait::async_trait]
impl<B, C, P, R> hopr_api::chain::ChainReadSafeOperations for HoprBlockchainConnector<C, B, P, R>
where
    B: Backend + Send + Sync + 'static,
    C: BlokliQueryClient + BlokliSubscriptionClient + Send + Sync + 'static,
    P: Send + Sync + 'static,
    R: Send + Sync,
{
    type Error = ConnectorError;

    // NOTE: these APIs can be called without calling `connect` first

    #[inline]
    async fn safe_allowance<Cy: Currency, A: Into<Address> + Send>(
        &self,
        safe_address: A,
    ) -> Result<Balance<Cy>, Self::Error> {
        HoprBlockchainReader(self.client.clone())
            .safe_allowance(safe_address)
            .await
    }

    #[inline]
    async fn safe_info(&self, selector: SafeSelector) -> Result<Option<DeployedSafe>, Self::Error> {
        HoprBlockchainReader(self.client.clone()).safe_info(selector).await
    }

    #[inline]
    async fn await_safe_deployment(
        &self,
        selector: SafeSelector,
        timeout: Duration,
    ) -> Result<DeployedSafe, Self::Error> {
        HoprBlockchainReader(self.client.clone())
            .await_safe_deployment(selector, timeout)
            .await
    }

    #[inline]
    async fn predict_module_address(
        &self,
        nonce: u64,
        owner: &Address,
        safe_address: &Address,
    ) -> Result<Address, Self::Error> {
        HoprBlockchainReader(self.client.clone())
            .predict_module_address(nonce, owner, safe_address)
            .await
    }
}

const DEPLOY_SAFE_CUSTOM_TX_TIMEOUT_MULTIPLIER: u32 = 8;

#[async_trait::async_trait]
impl<B, C, P> hopr_api::chain::ChainWriteSafeOperations for HoprBlockchainConnector<C, B, P, P::TxRequest>
where
    B: Send + Sync + 'static,
    C: BlokliQueryClient + BlokliTransactionClient + Send + Sync + 'static,
    P: PayloadGenerator + Send + Sync + 'static,
    P::TxRequest: Send + Sync + 'static,
{
    type Error = ConnectorError;

    async fn deploy_safe<'a>(
        &'a self,
        balance: HoprBalance,
    ) -> Result<BoxFuture<'a, Result<ChainReceipt, Self::Error>>, Self::Error> {
        let admin = self.chain_key.public().to_address();
        if !self
            .client
            .query_safe(blokli_client::api::SafeSelector::ChainKey(admin.into()))
            .await?
            .is_empty()
        {
            return Err(ConnectorError::InvalidState("safe already deployed for this signer"));
        }

        if self.balance(admin).await? < balance {
            return Err(ConnectorError::InvalidState("insufficient token balance at the signer"));
        }

        let tx_req = self.payload_generator.deploy_safe(
            balance,
            &[admin],
            true,
            hopr_api::types::crypto_random::random_bytes(),
        )?;
        tracing::debug!(%balance, %admin, "deploying safe");

        Ok(self
            .send_tx(tx_req, DEPLOY_SAFE_CUSTOM_TX_TIMEOUT_MULTIPLIER.into(), None)
            .await?
            .boxed())
    }

    async fn set_safe_allowance<'a>(
        &'a self,
        amount: HoprBalance,
    ) -> Result<BoxFuture<'a, Result<ChainReceipt, Self::Error>>, Self::Error> {
        self.check_connection_state()?;

        let channels = self.query_cached_chain_info().await?.info.contract_addresses.channels;
        // The payload generator of a node wraps the call in `execTransactionFromModule`,
        // so the allowance of the node's Safe is set, not the one of the node's own key.
        let tx_req = self
            .payload_generator
            .approve(Address::from(<[u8; Address::SIZE]>::from(channels)), amount)?;
        tracing::debug!(%amount, "setting safe allowance for channels");

        Ok(self.send_tx(tx_req, None, None).await?.boxed())
    }
}

/// Delay before looking up the node's Safe again, or before re-subscribing to its allowance.
pub(crate) const SAFE_ALLOWANCE_RETRY_DELAY: Duration = Duration::from_secs(30);

/// Converts a `safeHoprApproval` item from Blokli into `(owner, spender, allowance)`.
fn model_to_safe_approval(
    model: blokli_client::api::types::SafeHoprApproval,
) -> Result<(Address, Address, HoprBalance), ConnectorError> {
    Ok((
        model
            .owner
            .parse()
            .map_err(|_| ConnectorError::TypeConversion(format!("invalid approval owner: {}", model.owner)))?,
        model
            .spender
            .parse()
            .map_err(|_| ConnectorError::TypeConversion(format!("invalid approval spender: {}", model.spender)))?,
        model.allowance.0.parse().map_err(|_| {
            ConnectorError::TypeConversion(format!("invalid approval allowance: {}", model.allowance.0))
        })?,
    ))
}

/// Looks up the Safe that the node `me` is registered with.
async fn registered_safe<C: BlokliQueryClient>(client: &C, me: Address) -> Option<Address> {
    match client
        .query_safe(blokli_client::api::SafeSelector::RegisteredNode(me.into()))
        .await
    {
        Ok(safes) => safes.first().and_then(|safe| safe.address.parse().ok()),
        Err(error) => {
            tracing::warn!(%error, "failed to look up the safe of the node");
            None
        }
    }
}

enum SafeAllowanceState {
    /// The Safe of the node is not known yet, or the subscription has ended.
    Resolve,
    /// Receiving the allowance updates of the given Safe.
    Subscribed(
        Address,
        BoxStream<
            'static,
            Result<blokli_client::api::types::SafeHoprApproval, blokli_client::errors::BlokliClientError>,
        >,
    ),
}

/// Streams the wxHOPR allowance that the Safe of the node `me` grants to the `channels` contract.
///
/// Yields `(safe, allowance)` every time the allowance takes a new value, starting with the current one.
/// The stream never ends: until the node is registered with a Safe, it looks the Safe up again every
/// `retry_delay`; when Blokli ends the subscription (for example on lag or reorg), it subscribes again.
pub(crate) fn safe_allowance_updates<C>(
    client: Arc<C>,
    me: Address,
    channels: Address,
    retry_delay: Duration,
) -> impl futures::Stream<Item = (Address, HoprBalance)> + Send + 'static
where
    C: BlokliQueryClient + BlokliSubscriptionClient + Send + Sync + 'static,
{
    futures::stream::unfold(SafeAllowanceState::Resolve, move |mut state| {
        let client = client.clone();
        async move {
            loop {
                state = match state {
                    SafeAllowanceState::Resolve => match registered_safe(client.as_ref(), me).await {
                        Some(safe) => match client.subscribe_safe_hopr_approval(safe.into()) {
                            Ok(approvals) => SafeAllowanceState::Subscribed(safe, approvals.boxed()),
                            Err(error) => {
                                tracing::warn!(%safe, %error, "failed to subscribe to the safe allowance");
                                futures_time::task::sleep(retry_delay.into()).await;
                                SafeAllowanceState::Resolve
                            }
                        },
                        None => {
                            futures_time::task::sleep(retry_delay.into()).await;
                            SafeAllowanceState::Resolve
                        }
                    },
                    SafeAllowanceState::Subscribed(safe, mut approvals) => match approvals.next().await {
                        Some(approval) => {
                            match approval.map_err(ConnectorError::from).and_then(model_to_safe_approval) {
                                Ok((owner, spender, allowance)) if owner == safe && spender == channels => {
                                    return Some(((safe, allowance), SafeAllowanceState::Subscribed(safe, approvals)));
                                }
                                // Blokli only sends updates of the given Safe for the configured Channels
                                // contract; anything else means a misconfigured or incompatible Blokli.
                                Ok((owner, spender, _)) => {
                                    tracing::warn!(%safe, %owner, %spender, %channels, "ignoring unexpected safe allowance update");
                                }
                                Err(error) => tracing::warn!(%safe, %error, "safe allowance update failed"),
                            }
                            SafeAllowanceState::Subscribed(safe, approvals)
                        }
                        None => {
                            tracing::warn!(%safe, "safe allowance subscription ended, subscribing again");
                            futures_time::task::sleep(retry_delay.into()).await;
                            SafeAllowanceState::Resolve
                        }
                    },
                }
            }
        }
    })
    // Re-subscriptions start with the current allowance again: report only new values.
    .scan(None, |previous: &mut Option<HoprBalance>, (safe, allowance)| {
        let changed = previous.replace(allowance) != Some(allowance);
        futures::future::ready(Some(changed.then_some((safe, allowance))))
    })
    .filter_map(futures::future::ready)
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use hopr_api::{
        chain::{
            ChainEvent, ChainEvents, ChainReadSafeOperations, ChainWriteChannelOperations, ChainWriteSafeOperations,
        },
        types::{crypto::prelude::*, internal::prelude::*},
    };

    use super::*;
    use crate::{
        connector::tests::{MODULE_ADDR, PRIVATE_KEY_1, PRIVATE_KEY_2, create_connector},
        testing::BlokliTestStateBuilder,
    };

    const SAFE_1: [u8; Address::SIZE] = [1u8; Address::SIZE];

    /// Two accounts with Safes and an open channel from the first to the second.
    fn approval_test_state(allowance: HoprBalance) -> anyhow::Result<(BlokliTestStateBuilder, ChannelEntry)> {
        let node_1 = ChainKeypair::from_secret(&PRIVATE_KEY_1)?.public().to_address();
        let account_1 = AccountEntry {
            public_key: *OffchainKeypair::from_secret(&hex!(
                "60741b83b99e36aa0c1331578156e16b8e21166d01834abb6c64b103f885734d"
            ))?
            .public(),
            chain_addr: ChainKeypair::from_secret(&PRIVATE_KEY_1)?.public().to_address(),
            entry_type: AccountType::NotAnnounced,
            safe_address: Some(SAFE_1.into()),
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
        let channel = ChannelEntry::builder()
            .between(
                &ChainKeypair::from_secret(&PRIVATE_KEY_1)?,
                &ChainKeypair::from_secret(&PRIVATE_KEY_2)?,
            )
            .amount(10)
            .ticket_index(1)
            .status(ChannelStatus::Open)
            .epoch(1)
            .build()?;

        let builder = BlokliTestStateBuilder::default()
            .with_accounts([
                (account_1, HoprBalance::new_base(100), XDaiBalance::new_base(1)),
                (account_2, HoprBalance::new_base(100), XDaiBalance::new_base(1)),
            ])
            .with_safe_allowances([(SAFE_1.into(), allowance)])
            // The node must be registered with its Safe for the connector to find it.
            .with_deployed_safes([DeployedSafe {
                address: SAFE_1.into(),
                owners: vec![node_1],
                module: MODULE_ADDR.into(),
                registered_nodes: vec![node_1],
                deployer: node_1,
            }])
            .with_channels([channel])
            .with_hopr_network_chain_info("piz-palu-staging");

        Ok((builder, channel))
    }

    #[tokio::test]
    async fn connector_should_set_absolute_safe_allowance() -> anyhow::Result<()> {
        let (builder, _) = approval_test_state(HoprBalance::new_base(3))?;
        let mut connector = create_connector(builder.build_dynamic_client(MODULE_ADDR.into()))?;
        connector.connect().await?;

        connector.set_safe_allowance(HoprBalance::new_base(1000)).await?.await?;
        assert_eq!(
            connector.safe_allowance::<WxHOPR, _>(Address::from(SAFE_1)).await?,
            HoprBalance::new_base(1000),
            "the allowance must be set to the amount, not increased by it"
        );

        connector.set_safe_allowance(HoprBalance::new_base(10)).await?.await?;
        assert_eq!(
            connector.safe_allowance::<WxHOPR, _>(Address::from(SAFE_1)).await?,
            HoprBalance::new_base(10)
        );

        Ok(())
    }

    #[tokio::test]
    async fn connector_should_not_set_safe_allowance_when_not_connected() -> anyhow::Result<()> {
        let (builder, _) = approval_test_state(HoprBalance::new_base(3))?;
        let connector = create_connector(builder.build_dynamic_client(MODULE_ADDR.into()))?;

        assert!(connector.set_safe_allowance(HoprBalance::new_base(1000)).await.is_err());

        Ok(())
    }

    /// Waits for the next [`ChainEvent::SafeAllowanceChanged`] reporting `expected`, skipping other events.
    async fn safe_allowance_changed(
        events: &mut (impl futures::Stream<Item = ChainEvent> + Unpin),
        expected: HoprBalance,
    ) -> anyhow::Result<Address> {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match events.next().await {
                    Some(ChainEvent::SafeAllowanceChanged(safe, allowance)) if allowance == expected => break Ok(safe),
                    Some(_) => continue,
                    None => break Err(anyhow::anyhow!("event stream ended")),
                }
            }
        })
        .await?
    }

    #[tokio::test]
    async fn connector_should_report_safe_allowance_changes_as_chain_events() -> anyhow::Result<()> {
        let (builder, channel) = approval_test_state(HoprBalance::new_base(100))?;
        let mut connector = create_connector(
            builder
                .build_dynamic_client(MODULE_ADDR.into())
                .with_tx_simulation_delay(Duration::ZERO),
        )?;
        connector.connect().await?;
        let mut events = Box::pin(connector.subscribe()?);

        // Funding a channel from the Safe spends its allowance.
        connector
            .fund_channel(channel.get_id(), HoprBalance::new_base(60))
            .await?
            .await?;
        assert_eq!(
            Address::from(SAFE_1),
            safe_allowance_changed(&mut events, HoprBalance::new_base(40)).await?
        );

        connector.set_safe_allowance(HoprBalance::new_base(500)).await?.await?;
        safe_allowance_changed(&mut events, HoprBalance::new_base(500)).await?;

        // Allowance changes of other Safes are not reported.
        connector.client().update_safe_allowance(
            &[2u8; Address::SIZE],
            blokli_client::api::types::TokenValueString("7 wxHOPR".into()),
        );
        connector
            .client()
            .update_safe_allowance(&SAFE_1, blokli_client::api::types::TokenValueString("0 wxHOPR".into()));
        let next = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match events.next().await {
                    Some(ChainEvent::SafeAllowanceChanged(safe, allowance)) => break Some((safe, allowance)),
                    Some(_) => continue,
                    None => break None,
                }
            }
        })
        .await?;
        assert_eq!(next, Some((Address::from(SAFE_1), HoprBalance::zero())));

        Ok(())
    }

    #[tokio::test]
    async fn connector_should_safe_allowance() -> anyhow::Result<()> {
        let account = AccountEntry {
            public_key: *OffchainKeypair::random().public(),
            chain_addr: [1u8; Address::SIZE].into(),
            entry_type: AccountType::NotAnnounced,
            safe_address: Some([2u8; Address::SIZE].into()),
            key_id: 1.into(),
        };

        let blokli_client = BlokliTestStateBuilder::default()
            .with_accounts([(account.clone(), HoprBalance::new_base(100), XDaiBalance::new_base(1))])
            .with_safe_allowances([(account.safe_address.unwrap(), HoprBalance::new_base(10000))])
            .build_static_client();

        let connector = create_connector(blokli_client)?;

        assert_eq!(
            connector.safe_allowance(account.safe_address.unwrap()).await?,
            HoprBalance::new_base(10000)
        );

        Ok(())
    }

    #[tokio::test]
    async fn connector_should_query_existing_safe() -> anyhow::Result<()> {
        let me = ChainKeypair::from_secret(&PRIVATE_KEY_1)?.public().to_address();
        let safe_addr = [1u8; Address::SIZE].into();
        let node_addr = [2u8; Address::SIZE].into();

        let safe = DeployedSafe {
            address: safe_addr,
            owners: vec![me],
            module: MODULE_ADDR.into(),
            registered_nodes: vec![node_addr],
            deployer: me,
        };
        let blokli_client = BlokliTestStateBuilder::default()
            .with_balances([(me, XDaiBalance::new_base(10))])
            .with_deployed_safes([safe.clone()])
            .with_hopr_network_chain_info("piz-palu-staging")
            .build_dynamic_client(MODULE_ADDR.into());

        let connector = create_connector(blokli_client)?;

        assert_eq!(Some(safe.clone()), connector.safe_info(SafeSelector::Owner(me)).await?);
        assert_eq!(
            Some(safe.clone()),
            connector.safe_info(SafeSelector::Address(safe_addr)).await?
        );
        assert_eq!(
            Some(safe),
            connector.safe_info(SafeSelector::NodeAddress(node_addr)).await?
        );

        insta::assert_yaml_snapshot!(*connector.client.snapshot());

        Ok(())
    }

    #[tokio::test]
    async fn connector_should_predict_module_address() -> anyhow::Result<()> {
        let me = ChainKeypair::from_secret(&PRIVATE_KEY_1)?.public().to_address();
        let safe_addr = [1u8; Address::SIZE].into();
        let blokli_client = BlokliTestStateBuilder::default()
            .with_hopr_network_chain_info("piz-palu-staging")
            .build_dynamic_client(MODULE_ADDR.into());

        let connector = create_connector(blokli_client)?;

        assert_eq!(
            "0xff3dae517c13a59014c79c397de258c9557c04b8",
            connector.predict_module_address(0, &me, &safe_addr).await?.to_string()
        );

        Ok(())
    }
}
