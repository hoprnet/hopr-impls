//! Implements complete logic of ticket management in the HOPR protocol.
//!
//! There are two major parts in the architecture of the ticket management:
//! - [`HoprTicketManager`] is responsible for managing the incoming ticket queues and ticket redemption.
//! - [`HoprTicketFactory`] is responsible for managing outgoing ticket indices and creating outgoing tickets.
//!
//! Usually, they are created together via [`HoprTicketManager::new_with_factory`].
//!
//! The `manager` feature (on by default) provides the [`HoprTicketManager`] and the incoming ticket queues.
//! Without it, only the [`HoprTicketFactory`] and the outgoing index stores are built, which is all an
//! entry node needs.
//!
//! See the [`HoprTicketManager`] and [`HoprTicketFactory`] documentation for complete details.

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
