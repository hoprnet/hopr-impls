# hopr-ct-full-network

Full implementation of the Telemetry functionality as specified in the HOPR RFCs along with optional noise (cover traffic) generation

Part of the [HOPR](https://hoprnet.org/) protocol implementation.

## Steering egress traffic at runtime

`FullNetworkDiscovery::control()` returns a cloneable `EgressControl`. Take a clone before the prober is handed to the node. Changes reach
streams that are already running.

- `set_level(Some(Low | Medium | High | Ultra))` scales the probing pace to 0.1, 0.5, 1.0 or 2.0 of `EgressConfig::interval`.
  `set_level(None)` stops probing and leaves the streams pending. Default `Some(High)`.
- `set_focus(exits)` / `clear_focus()` probe the subgraph around the exits. Loops that form a path to an exit (forward) get
  `EgressConfig::focus_boost` times the weight, default 10. Loops that cover a return path from an exit to this node get half of that. Other
  loops keep the base weight, and neighbor probes ignore focus. An exit needs no channel and no edge back to this node.
- `set_noise(bool)` switches cover traffic (`noise` feature, on by default). Default off. Independent of the level.

## Specification

- [RFC-0010: Automatic Path Discovery](https://github.com/hoprnet/rfc/blob/main/rfcs/RFC-0010-automatic-path-discovery/0010-automatic-path-discovery.md)

## License

GPL-3.0-only
