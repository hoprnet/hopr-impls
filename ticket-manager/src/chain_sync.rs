use std::sync::Arc;

use futures::StreamExt;
use hopr_api::chain::{ChainReadChannelOperations, ChannelSelector};

use crate::{HoprTicketFactory, HoprTicketManager, OutgoingIndexStore, TicketManagerError, TicketQueueStore};

/// Creates a [`HoprTicketFactory`] backed by the given `store` and pre-seeds it
/// from the node's current outgoing channels.
///
/// To avoid re-issuing ticket indices that were already used before a restart, the `store` must
/// be durable (e.g. a [`RedbStore`](crate::RedbStore) opened on a file kept between runs), and the
/// outgoing indices must be [saved](HoprTicketFactory::save_outgoing_indices) to it periodically and on shutdown.
///
/// Use this when building an edge (entry/exit) node that issues tickets but does not
/// relay them. For relay nodes that also manage incoming tickets, use
/// [`ticket_manager_from_chain`] instead.
pub async fn ticket_factory_from_chain<C, S>(
    connector: &C,
    store: S,
) -> Result<Arc<HoprTicketFactory<S>>, TicketManagerError>
where
    C: ChainReadChannelOperations,
    C::Error: std::fmt::Display,
    S: OutgoingIndexStore + Send + Sync + 'static,
{
    let factory = Arc::new(HoprTicketFactory::new(store));

    let me = *connector.me();
    let outgoing: Vec<_> = connector
        .stream_channels(ChannelSelector::default().with_source(me))
        .map_err(|e| TicketManagerError::Other(anyhow::anyhow!("failed to stream outgoing channels: {e}")))?
        .collect()
        .await;

    factory.sync_from_outgoing_channels(&outgoing)?;
    Ok(factory)
}

/// Creates a [`HoprTicketManager`] and its companion [`HoprTicketFactory`], both backed
/// by the given `store`, and pre-seeds them from the node's current channel state.
///
/// The same durability requirements as in [`ticket_factory_from_chain`] apply to the `store`.
/// A durable `store` also keeps the unredeemed incoming tickets across restarts.
///
/// Use this when building a full relay node that both issues and redeems tickets.
/// The factory is pre-seeded from outgoing channels and the manager from incoming channels.
/// For edge nodes that do not redeem tickets, use [`ticket_factory_from_chain`] instead.
pub async fn ticket_manager_from_chain<C, S>(
    connector: &C,
    store: S,
) -> Result<(Arc<HoprTicketManager<S, S::Queue>>, Arc<HoprTicketFactory<S>>), TicketManagerError>
where
    C: ChainReadChannelOperations,
    C::Error: std::fmt::Display,
    S: OutgoingIndexStore + TicketQueueStore + Send + Sync + 'static,
    S::Queue: Send + Sync + 'static,
{
    let (manager, factory) = HoprTicketManager::new_with_factory(store);
    let manager = Arc::new(manager);
    let factory = Arc::new(factory);

    let me = *connector.me();
    let incoming_stream = connector
        .stream_channels(ChannelSelector::default().with_destination(me))
        .map_err(|e| TicketManagerError::Other(anyhow::anyhow!("failed to stream incoming channels: {e}")))?;
    let outgoing_stream = connector
        .stream_channels(ChannelSelector::default().with_source(me))
        .map_err(|e| TicketManagerError::Other(anyhow::anyhow!("failed to stream outgoing channels: {e}")))?;

    let (incoming, outgoing): (Vec<_>, Vec<_>) = futures::join!(incoming_stream.collect(), outgoing_stream.collect());

    manager.sync_from_incoming_channels(&incoming)?;
    factory.sync_from_outgoing_channels(&outgoing)?;

    Ok((manager, factory))
}
