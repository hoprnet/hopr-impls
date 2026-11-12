//! Process-local identifiers shared by graph queries and transport selection stages.
use std::{
    cell::Cell,
    sync::atomic::{AtomicU64, Ordering},
};

use hopr_api::OffchainPublicKey;
use serde::Serialize;

static NEXT_ID: AtomicU64 = AtomicU64::new(1);
thread_local! { static CURRENT: Cell<Option<SearchContext>> = const { Cell::new(None) }; }

/// Allocate an identifier for one candidate-set computation, independently of log filters.
/// IDs are process-local; combine them with the node identity and process lifetime.
pub fn next_selection_id() -> u64 {
    NEXT_ID.fetch_add(1, Ordering::Relaxed)
}

/// One graph query within a candidate-set computation. Multiple phases share `selection_id`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct SearchContext {
    pub selection_id: u64,
    pub search_id: u64,
    pub phase: &'static str,
}
impl SearchContext {
    pub fn new(selection_id: u64, phase: &'static str) -> Self {
        Self {
            selection_id,
            search_id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            phase,
        }
    }
}

pub fn current_search_context() -> Option<SearchContext> {
    CURRENT.get()
}

/// Propagate context through a synchronous selector/graph call, restoring it on return or unwind.
/// Never keep this scope across an async suspension; pass the context explicitly across awaits.
pub fn with_search_context<T>(context: SearchContext, call: impl FnOnce() -> T) -> T {
    struct Restore(Option<SearchContext>);
    impl Drop for Restore {
        fn drop(&mut self) {
            CURRENT.set(self.0);
        }
    }
    let _restore = Restore(CURRENT.replace(Some(context)));
    call()
}

/// Canonical path slots for a transport candidate (`path` excludes source and includes destination).
/// This identifies the route, not a particular search, graph membership, rank or random draw.
/// Oversized/empty paths are explicit rather than silently truncated.
pub fn candidate_id(source: &OffchainPublicKey, path: &[OffchainPublicKey]) -> Option<[u64; 5]> {
    if path.is_empty() || path.len() >= 5 {
        return None;
    }
    let mut slots = [0; 5];
    for (i, key) in std::iter::once(source).chain(path).enumerate() {
        let bytes: [u8; 8] = key.as_ref()[..8]
            .try_into()
            .expect("public key is at least eight bytes");
        slots[i] = u64::from_be_bytes(bytes).max(1);
    }
    Some(slots)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nested_context_restores_on_return_and_unwind() {
        let outer = SearchContext::new(next_selection_id(), "phase1");
        let inner = SearchContext::new(outer.selection_id, "phase2");
        assert_ne!(outer.search_id, inner.search_id);
        with_search_context(outer, || {
            assert_eq!(current_search_context(), Some(outer));
            let _ = std::panic::catch_unwind(|| {
                with_search_context(inner, || {
                    assert_eq!(current_search_context(), Some(inner));
                    panic!("injected unwind");
                })
            });
            assert_eq!(current_search_context(), Some(outer));
        });
        assert_eq!(current_search_context(), None);
    }
    #[test]
    fn context_is_thread_local() {
        let context = SearchContext::new(next_selection_id(), "phase1");
        with_search_context(context, || {
            assert_eq!(std::thread::spawn(current_search_context).join().unwrap(), None)
        });
    }
}
