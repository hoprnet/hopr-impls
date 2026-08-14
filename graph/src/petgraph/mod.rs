pub mod algorithm;
pub mod graph;
pub mod traverse;
pub mod update;

pub use graph::ChannelGraph;

/// Encoding of nodes into [`PathId`](hopr_api::types::internal::routing::PathId) slots.
///
/// RFC-0010 §4.3.3 requires each slot to hold a *canonical* 64-bit node identifier, reserves `0` as
/// padding, and forbids it as an identifier. The slot is therefore derived from the node's public
/// key rather than from its position in the graph.
///
/// A `petgraph` index would satisfy neither requirement: indices are zero-based, so node 0 is
/// indistinguishable from padding.
///
/// It also decouples the slot from the graph's internal bookkeeping. `remove_node` retains the
/// petgraph node so an index is never reissued, which the node set being append-only makes cheap.
/// A key-derived slot needs no such coupling: it is stable for the lifetime of the key and is never
/// handed to a different node, whichever way removal is implemented.
pub(crate) mod path_id {
    use hopr_api::OffchainPublicKey;
    use petgraph::graph::NodeIndex;

    use crate::graph::InnerGraph;

    /// Derives the canonical slot value for a node.
    ///
    /// The leading 8 bytes of the public key, big-endian. Keys are uniformly distributed, so this is
    /// a sound truncation; `0` is mapped away from the reserved padding value.
    ///
    /// RFC-0010 §4.3.3 fixes the slot at 64 bits, so no encoding can rule out two keys sharing one.
    /// [`resolve`] refuses a slot claimed by more than one node in the graph, which covers the case
    /// while both are present; a collision where one node was removed mid-probe would misattribute a
    /// single latency sample. At 2^-64 per pair that is accepted rather than carried in per-slot
    /// tombstones, which would have to persist across restarts to be worth anything.
    pub(crate) fn encode(key: &OffchainPublicKey) -> u64 {
        let bytes = key.as_ref();
        let mut leading = [0u8; 8];
        leading.copy_from_slice(&bytes[..8]);
        match u64::from_be_bytes(leading) {
            0 => 1,
            slot => slot,
        }
    }

    /// Resolves a slot back to the node currently holding it.
    ///
    /// Returns `None` for padding, for a slot no node in the graph claims — a node removed while a
    /// probe was in flight, or a corrupted payload — and for a slot claimed by more than one key.
    /// Rejecting rather than guessing is deliberate: a wrong answer here silently attributes a
    /// measurement to an unrelated edge.
    ///
    /// Membership is checked against the graph rather than computed arithmetically, so an oversized
    /// slot cannot alias a real node by narrowing to `NodeIndex`'s `u32` index type.
    pub(crate) fn resolve(inner: &InnerGraph, slot: u64) -> Option<NodeIndex> {
        if slot == 0 {
            return None;
        }

        let mut found = None;
        for (key, idx) in inner.indices.iter() {
            if encode(key) == slot {
                if found.is_some() {
                    tracing::warn!(
                        slot,
                        "two nodes claim the same path identifier slot, refusing to resolve"
                    );
                    return None;
                }
                found = Some(*idx);
            }
        }
        found
    }

    #[cfg(test)]
    mod tests {
        use hopr_api::types::crypto::prelude::{Keypair, OffchainKeypair};

        use super::*;

        #[test]
        fn encode_should_never_produce_the_reserved_padding_value() {
            for _ in 0..32 {
                let key = *OffchainKeypair::random().public();
                assert_ne!(encode(&key), 0, "a key must not encode to the reserved padding value");
            }
        }

        #[test]
        fn encode_should_be_stable_and_key_derived() {
            let key = *OffchainKeypair::random().public();
            assert_eq!(
                encode(&key),
                encode(&key),
                "the same key must always yield the same slot"
            );

            let other = *OffchainKeypair::random().public();
            assert_ne!(encode(&key), encode(&other), "distinct keys must not share a slot");
        }
    }
}
