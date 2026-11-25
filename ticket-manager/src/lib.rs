//! Implements complete logic of ticket management in the HOPR protocol.
//!
//! The [`HoprTicketFactory`] is responsible for managing outgoing ticket indices and creating outgoing tickets.
//! It is all an entry node needs.
#![cfg_attr(
    feature = "manager",
    doc = "//! The [`HoprTicketManager`] is responsible for managing the incoming ticket queues and ticket \
           redemption.\n//! It is provided by the `manager` feature (on by default); usually both are created \
           together via\n//! [`HoprTicketManager::new_with_factory`].\n//!\n//! See the [`HoprTicketManager`] and \
           [`HoprTicketFactory`] documentation for complete details."
)]
#![cfg_attr(
    not(feature = "manager"),
    doc = "//! The `HoprTicketManager` (incoming ticket queues and redemption) is not built without the `manager` \
           feature.\n//!\n//! See the [`HoprTicketFactory`] documentation for complete details."
)]

mod backend;
mod chain_sync;
mod errors;
mod factory;
#[cfg(feature = "manager")]
mod manager;
mod traits;
mod utils;

#[cfg(feature = "redb")]
pub use crate::backend::RedbStore;
#[cfg(all(feature = "redb", feature = "manager"))]
pub use crate::backend::RedbTicketQueue;
pub use crate::{
    backend::MemoryStore, chain_sync::ticket_factory_from_chain, errors::TicketManagerError,
    factory::HoprTicketFactory, traits::OutgoingIndexStore,
};
#[cfg(feature = "manager")]
pub use crate::{
    backend::MemoryTicketQueue,
    chain_sync::ticket_manager_from_chain,
    manager::HoprTicketManager,
    traits::{TicketQueue, TicketQueueStore},
};
