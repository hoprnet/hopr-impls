# hopr-network-graph

Implementation of the HOPR network graph

Part of the [HOPR](https://hoprnet.org/) protocol implementation.

## Operational health

The graph logs health transitions on the local node's outgoing edges at INFO and
other edges at DEBUG. Both use `dest`, `from`, `to`, `score`, and `ack_rate`;
remote-edge events also include `src`. Health names are stable strings, and known
scores and acknowledgement rates are numeric fields. Unknown measurements are omitted.
Repeated observations without a health change remain at TRACE.

`ChannelGraph::health_summary()` is a public snapshot API for the application's
periodic state dump. This library has no runtime-owned periodic task and does not
schedule or log summaries automatically. Call it from the application's existing
dump schedule:

```rust
let summary = graph.health_summary();
tracing::info!(%summary, "graph health summary");
```

The summary counts active nodes, all edges, and the local node's outgoing edges in
each health state. Its output size is fixed; collecting it visits only outgoing
edges of the local node. Production scheduling belongs to the consuming application.

## License

GPL-3.0-only
