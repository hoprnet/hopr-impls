use std::time::Duration;

use blokli_client::api::{BlokliQueryClient, BlokliSubscriptionClient, RedeemedStatsSelector};
use futures::{StreamExt, TryStreamExt, stream::BoxStream};
use futures_time::future::FutureExt as FuturesTimeExt;
use hopr_api::{
    chain::{
        ChainInfo, DeployedSafe, DomainSeparators, RedemptionStats, SafeSelector, ServiceRegistryConfig,
        ServiceSelector, ServiceTypeConfig,
    },
    types::{internal::prelude::*, primitive::prelude::*},
};

use crate::{
    errors::ConnectorError,
    utils::{
        model_to_chain_info, model_to_deployed_safe, model_to_redeemed_stats, model_to_service_entry,
        model_to_service_registry_config, model_to_service_type_config,
    },
};

/// A simplified version of [`HoprBlockchainConnector`](crate::HoprBlockchainConnector)
/// which only implements [HOPR Chain API](hopr_api::chain) partially, allowing for read-only operations.
///
/// This object specifically implements only the following traits:
///
/// - [`ChainValues`](hopr_api::chain::ChainValues)
/// - [`ChainReadSafeOperations`](hopr_api::chain::ChainReadSafeOperations)
/// - [`ChainReadServiceOperations`](hopr_api::chain::ChainReadServiceOperations)
///
/// The implementation is currently realized using the Blokli client and acts as a partial HOPR Chain API compatible
/// wrapper for [`blokli_client::BlokliClient`].
///
/// This object is useful for bootstrapping purposes that usually precede construction of the [full
/// connector](crate::HoprBlockchainConnector).
pub struct HoprBlockchainReader<C>(pub(crate) std::sync::Arc<C>);

impl<C> HoprBlockchainReader<C> {
    /// Creates new instance given the `client`.
    pub fn new(client: C) -> Self {
        Self(std::sync::Arc::new(client))
    }
}

impl<C> Clone for HoprBlockchainReader<C> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

/// Maps the [`ServiceSelector`] of the HOPR Chain API onto the one of the Blokli client.
///
/// An unfiltered selector becomes [`blokli_client::api::ServiceSelector::Any`]; the client walks
/// the server's stable cursor pages for registry-wide enumeration.
fn to_blokli_service_selector(selector: &ServiceSelector) -> blokli_client::api::ServiceSelector {
    match (selector.service_type, selector.node) {
        (Some(service_type), Some(node)) => blokli_client::api::ServiceSelector::ServiceTypeAndNode {
            service_type: service_type.as_encoded(),
            node: node.into(),
        },
        (Some(service_type), None) => blokli_client::api::ServiceSelector::ServiceType(service_type.as_encoded()),
        (None, Some(node)) => blokli_client::api::ServiceSelector::Node(node.into()),
        (None, None) => blokli_client::api::ServiceSelector::Any,
    }
}

/// Converts the queried entries and applies the `selector` to each of them.
///
/// A single entry that fails to convert is dropped with a log naming the offending field: one
/// malformed record must not hide the rest of the registry. A failed *query* is a different
/// matter and is never turned into an absent entry, see
/// [`HoprBlockchainReader::query_service_entries`].
fn select_service_entries(
    models: &[blokli_client::api::types::ServiceEntry],
    selector: ServiceSelector,
) -> Vec<ServiceEntry> {
    let mut entries = Vec::with_capacity(models.len());

    for model in models {
        let entry = match model_to_service_entry(model) {
            Ok(entry) => entry,
            Err(error) => {
                tracing::error!(%error, "skipping an invalid service registry entry");
                continue;
            }
        };

        // A live-only query was already checked against the exact NodeSafeRegistry pointer by
        // Blokli. For ordinary queries the liveness argument is ignored by `satisfies`.
        if selector.satisfies(&entry, selector.live_only) {
            entries.push(entry);
        }
    }

    entries
}

impl<C> HoprBlockchainReader<C>
where
    C: BlokliQueryClient + Send + Sync + 'static,
{
    /// Queries the registry entries matching the `selector` and converts them.
    ///
    /// A failed query is propagated: "the read failed" and "nothing matched" are different answers,
    /// and a discovery API that conflates them reports an unreachable Blokli as an empty registry.
    pub(crate) async fn query_service_entries(
        &self,
        selector: ServiceSelector,
    ) -> Result<Vec<ServiceEntry>, ConnectorError> {
        let query = to_blokli_service_selector(&selector);
        let models = if selector.live_only {
            self.0.query_live_services(query).await
        } else {
            self.0.query_services(query).await
        }?;

        Ok(select_service_entries(&models, selector))
    }

    /// Builds the stream of the registry entries matching the `selector`.
    ///
    /// The stream owns its handle to the client, so it outlives the reader it was built from. The
    /// [connector](crate::HoprBlockchainConnector) relies on that when it delegates here through a
    /// temporary reader.
    pub(crate) fn service_entry_stream(
        &self,
        selector: ServiceSelector,
    ) -> Result<BoxStream<'static, ServiceEntry>, ConnectorError> {
        let reader = self.clone();
        Ok(futures::stream::once(async move {
            futures::stream::iter(match reader.query_service_entries(selector).await {
                Ok(entries) => entries,
                // `stream_services` yields plain entries, so the trait leaves nowhere to report
                // this. `count_services` therefore does not count this stream.
                Err(error) => {
                    tracing::error!(%error, ?selector, "failed to query the service registry");
                    Vec::new()
                }
            })
        })
        .flatten()
        .boxed())
    }
}

#[async_trait::async_trait]
impl<C> hopr_api::chain::ChainReadServiceOperations for HoprBlockchainReader<C>
where
    C: BlokliQueryClient + Send + Sync + 'static,
{
    type Error = ConnectorError;

    fn stream_services<'a>(&'a self, selector: ServiceSelector) -> Result<BoxStream<'a, ServiceEntry>, Self::Error> {
        self.service_entry_stream(selector)
    }

    async fn count_services(&self, selector: ServiceSelector) -> Result<usize, Self::Error> {
        if selector.live_only {
            // Liveness is a property of the node-Safe registry rather than of a registry entry, so
            // Blokli cannot count it: the entries must be fetched and filtered here. This does not
            // go through `service_entry_stream`, whose item type forces it to swallow a query
            // failure - counting would then report an unreachable Blokli as `Ok(0)`.
            return Ok(self.query_service_entries(selector).await?.len());
        }

        Ok(self.0.count_services(to_blokli_service_selector(&selector)).await? as usize)
    }

    async fn get_service_type_config(
        &self,
        service_type: ServiceType,
    ) -> Result<Option<ServiceTypeConfig>, Self::Error> {
        self.0
            .query_service_types(Some(service_type.as_encoded()))
            .await?
            .first()
            .map(model_to_service_type_config)
            .transpose()
    }

    async fn get_service_registry_config(&self) -> Result<ServiceRegistryConfig, Self::Error> {
        self.0
            .query_service_registry_config()
            .await
            .map_err(ConnectorError::from)
            .and_then(model_to_service_registry_config)
    }
}

#[async_trait::async_trait]
impl<C> hopr_api::chain::ChainValues for HoprBlockchainReader<C>
where
    C: BlokliQueryClient + Send + Sync,
{
    type Error = ConnectorError;

    async fn balance<Cy: Currency, A: Into<Address> + Send>(&self, address: A) -> Result<Balance<Cy>, Self::Error> {
        let address = address.into();
        if Cy::is::<WxHOPR>() {
            Ok(self
                .0
                .query_token_balance(&address.into(), blokli_client::types::Token::WxHOPR)
                .await?
                .balance
                .0
                .parse()?)
        } else if Cy::is::<XDai>() {
            Ok(self.0.query_native_balance(&address.into()).await?.balance.0.parse()?)
        } else {
            Err(ConnectorError::InvalidState("unsupported currency"))
        }
    }

    async fn domain_separators(&self) -> Result<DomainSeparators, Self::Error> {
        let chain_info = self.0.query_chain_info().await?;
        Ok(model_to_chain_info(chain_info)?.domain_separators)
    }

    async fn minimum_incoming_ticket_win_prob(&self) -> Result<WinningProbability, Self::Error> {
        let chain_info = self.0.query_chain_info().await?;
        Ok(model_to_chain_info(chain_info)?.ticket_win_prob)
    }

    async fn minimum_ticket_price(&self) -> Result<HoprBalance, Self::Error> {
        let chain_info = self.0.query_chain_info().await?;
        Ok(model_to_chain_info(chain_info)?.ticket_price)
    }

    async fn key_binding_fee(&self) -> Result<HoprBalance, Self::Error> {
        let chain_info = self.0.query_chain_info().await?;
        Ok(model_to_chain_info(chain_info)?.key_binding_fee)
    }

    async fn channel_closure_notice_period(&self) -> Result<Duration, Self::Error> {
        let chain_info = self.0.query_chain_info().await?;
        Ok(model_to_chain_info(chain_info)?.channel_closure_grace_period)
    }

    async fn chain_info(&self) -> Result<ChainInfo, Self::Error> {
        let chain_info = self.0.query_chain_info().await?;
        Ok(model_to_chain_info(chain_info)?.info)
    }

    async fn redemption_stats<A: Into<Address> + Send>(&self, safe_addr: A) -> Result<RedemptionStats, Self::Error> {
        let safe_addr = safe_addr.into();
        model_to_redeemed_stats(
            self.0
                .query_redeemed_stats(RedeemedStatsSelector::SafeAddress(safe_addr.into()))
                .await?,
        )
    }

    async fn typical_resolution_time(&self) -> Result<Duration, Self::Error> {
        let chain_info = self.0.query_chain_info().await?;
        let info = model_to_chain_info(chain_info)?;
        Ok(info.expected_block_time * info.finality)
    }
}

#[async_trait::async_trait]
impl<C> hopr_api::chain::ChainReadSafeOperations for HoprBlockchainReader<C>
where
    C: BlokliQueryClient + BlokliSubscriptionClient + Send + Sync,
{
    type Error = ConnectorError;

    async fn safe_allowance<Cy: Currency, A: Into<Address> + Send>(
        &self,
        safe_address: A,
    ) -> Result<Balance<Cy>, Self::Error> {
        let address = safe_address.into();
        if Cy::is::<WxHOPR>() {
            Ok(self
                .0
                .query_safe_allowance(&address.into())
                .await?
                .allowance
                .0
                .parse()?)
        } else if Cy::is::<XDai>() {
            Err(ConnectorError::InvalidState("cannot query allowance on xDai"))
        } else {
            Err(ConnectorError::InvalidState("unsupported currency"))
        }
    }

    async fn safe_info(&self, selector: SafeSelector) -> Result<Option<DeployedSafe>, Self::Error> {
        let selector = match selector {
            SafeSelector::Address(safe_address) => blokli_client::api::SafeSelector::SafeAddress(safe_address.into()),
            SafeSelector::Deployer(deployer_address) => {
                blokli_client::api::SafeSelector::ChainKey(deployer_address.into())
            }
            SafeSelector::NodeAddress(node_address) => {
                blokli_client::api::SafeSelector::RegisteredNode(node_address.into())
            }
            SafeSelector::Owner(owner_address) => blokli_client::api::SafeSelector::Owner(owner_address.into()),
        };

        if let Some(safe) = self.0.query_safe(selector).await?.first() {
            Ok(Some(model_to_deployed_safe(safe.clone())?))
        } else {
            Ok(None)
        }
    }

    async fn await_safe_deployment(
        &self,
        selector: SafeSelector,
        timeout: Duration,
    ) -> Result<DeployedSafe, Self::Error> {
        if let Some(safe) = self.safe_info(selector).await? {
            return Ok(safe);
        }

        let res = self
            .0
            .subscribe_safe_deployments()?
            .map_err(ConnectorError::from)
            .and_then(|safe| futures::future::ready(model_to_deployed_safe(safe)))
            .try_skip_while(|deployed_safe| futures::future::ok(!selector.satisfies(deployed_safe)))
            .take(1)
            .try_collect::<Vec<_>>()
            .timeout(futures_time::time::Duration::from(timeout.max(Duration::from_secs(1))))
            .await
            .map_err(|_| ConnectorError::other(anyhow::anyhow!("timeout while waiting for safe deployment")))??;

        res.into_iter()
            .next()
            .ok_or(ConnectorError::InvalidState("safe deployment stream closed"))
    }

    async fn predict_module_address(
        &self,
        nonce: u64,
        owner: &Address,
        safe_address: &Address,
    ) -> Result<Address, Self::Error> {
        Ok(self
            .0
            .query_module_address_prediction(blokli_client::api::ModulePredictionInput {
                nonce,
                owner: (*owner).into(),
                safe_address: (*safe_address).into(),
            })
            .await?
            .into())
    }
}

#[cfg(test)]
mod tests {
    use hopr_api::chain::ChainValues;

    use super::*;
    use crate::testing::BlokliTestStateBuilder;

    #[tokio::test]
    async fn redeemed_stats() -> anyhow::Result<()> {
        let blokli_client = BlokliTestStateBuilder::default()
            .with_deployed_safes([DeployedSafe {
                address: [1u8; Address::SIZE].into(),
                owners: vec![[2u8; Address::SIZE].into()],
                module: [3u8; Address::SIZE].into(),
                registered_nodes: vec![],
                deployer: [2u8; Address::SIZE].into(),
            }])
            .with_hopr_network_chain_info("piz-palu-staging")
            .build_static_client();

        let reader = HoprBlockchainReader::new(blokli_client);

        let stats = reader.redemption_stats([1u8; Address::SIZE]).await?;
        assert_eq!(0, stats.redeemed_count);
        assert_eq!(HoprBalance::zero(), stats.redeemed_value);

        Ok(())
    }
}
