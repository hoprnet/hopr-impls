# hopr-network-graph

Implementation of the HOPR network graph

Part of the [HOPR](https://hoprnet.org/) protocol implementation.

## Operational health

The graph logs health transitions on the local node's outgoing edges at INFO and other edges at DEBUG. Both use `dest`, `from`, `to`,
`score`, and `ack_rate`; remote-edge events also include `src`. Health names are stable strings, and known scores and acknowledgement rates
are numeric fields. Unknown measurements are omitted. Repeated observations without a health change remain at TRACE.

## License

GPL-3.0-only
