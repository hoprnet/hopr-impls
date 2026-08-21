# hopr-chain-connector

Implementation of HOPR Chain APIs using Blokli client

Part of the [HOPR](https://hoprnet.org/) protocol implementation.

## Curvy PIX ownership

This crate owns the HOPR-specific Curvy PIX deposit pool. Enable `pix-curvy-sdk` for the rs-sdk
adapter, durable allocation-to-note correlation, pending and committed event replay, and
withdrawal handling. The node composition layer injects this pool into `hopr-strategy`; neither
the strategy nor rs-sdk contains a second HOPR pool adapter.

The SSA BabyJubJub public key remains the note owner, and its Shamir-reconstructed private key is
the only spending authority. For private discovery, the Exit creates a separate per-SSA Curvy
viewer: public `(K,V)` is piggybacked to the Entry, while private `v` remains at the Exit. The
connector receives those values as opaque protocol metadata and is the first generic layer that
interprets them.

## License

GPL-3.0-only
