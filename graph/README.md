# hopr-network-graph

Implementation of the HOPR network graph

Part of the [HOPR](https://hoprnet.org/) protocol implementation.

## Logging

Individual observations, rejected reports, and stale-path attribution details are emitted at TRACE, including their update spans. Nodes and
edges can disappear while telemetry is in flight; those unattributable reports do not emit one DEBUG/WARN line per observation. Malformed
path structure still produces WARN diagnostics, and so does a missing local node in the SURB round-trip handler; the loopback handlers
report it at TRACE. Enable TRACE in a build that retains it for individual reports; the workspace compiles TRACE out of release builds.

The existing read API exposes balances, immediate connection/probe observations, and ticket face value for the node-level periodic snapshot.
This crate does not own the snapshot timer, Safe or channel queries, routing-resolution counters, or SURB mint/return interval counters.
Those are assembled by the node integration. No graph API, health classifier, or routing behavior changes.

## License

GPL-3.0-only
