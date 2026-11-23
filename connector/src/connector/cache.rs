//! Cache access shared by the lookups and the subscription handlers.
//!
//! The lookups and the subscription handlers write the same caches. Both go through moka's
//! `entry(..).and_compute_with(..)`, which runs one computation per key at a time. A lookup that
//! misses holds the key while it reads the backend, so a handler update for the same key lands
//! after the lookup's write and is never overwritten by a stale value.
//!
//! Handlers must write the backend before the cache. `None` is never cached, so a lookup for an
//! unknown key falls back to the backend until the subscription stores the entry.

use std::hash::{BuildHasher, Hash};

use moka::{Entry, ops::compute::Op};

/// Returns the cached value or loads it with `load` while holding the key, caching only a found value.
pub(crate) fn get_or_load<K, V, S, E>(
    cache: &moka::sync::Cache<K, Option<V>, S>,
    key: &K,
    load: impl FnOnce() -> Result<Option<V>, E>,
) -> Result<Option<V>, E>
where
    K: Hash + Eq + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    S: BuildHasher + Clone + Send + Sync + 'static,
{
    if let Some(Some(value)) = cache.get(key) {
        return Ok(Some(value));
    }

    let mut loaded = None;
    cache
        .entry_by_ref(key)
        .and_compute_with(|cached: Option<Entry<K, Option<V>>>| {
            if let Some(value) = cached.and_then(|entry| entry.into_value()) {
                loaded = Some(Ok(Some(value)));
                return Op::Nop;
            }
            match load() {
                Ok(Some(value)) => {
                    loaded = Some(Ok(Some(value.clone())));
                    Op::Put(Some(value))
                }
                other => {
                    loaded = Some(other);
                    Op::Nop
                }
            }
        });
    loaded.expect("the compute closure always runs")
}

/// Stores `value` once any lookup that is loading the same key has finished.
pub(crate) fn put<K, V, S>(cache: &moka::sync::Cache<K, Option<V>, S>, key: &K, value: V)
where
    K: Hash + Eq + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    S: BuildHasher + Clone + Send + Sync + 'static,
{
    cache.entry_by_ref(key).and_compute_with(|_| Op::Put(Some(value)));
}

/// Removes the key once any lookup that is loading it has finished. A plain `invalidate` does not wait for an in-flight
/// computation (moka only locks the key on removal when a removal notifier is configured), so a lookup could write the
/// removed value back afterwards.
pub(crate) fn invalidate<K, V, S>(cache: &moka::sync::Cache<K, Option<V>, S>, key: &K)
where
    K: Hash + Eq + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    S: BuildHasher + Clone + Send + Sync + 'static,
{
    cache.entry_by_ref(key).and_compute_with(|_| Op::Remove);
}
