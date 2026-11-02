# hopr-ct-full-network

Full implementation of the Telemetry functionality as specified in the HOPR RFCs along with optional noise (cover traffic) generation

Part of the [HOPR](https://hoprnet.org/) protocol implementation.

## Steering probing at runtime

`FullNetworkDiscovery::control()` returns a cloneable `ProbingControl`. Take a clone before the prober
is handed to the node. Changes reach streams that are already running.

- `set_level(Off | Low | Medium | High)`: scales the probing pace to 0, 0.1, 0.5 or 1.0 of
  `ProberConfig::interval`. `Off` leaves the stream pending. Default `High`.
- `set_focus(exits)` / `clear_focus()`: loopbacks whose last relay is a focus exit lead each round
  (`ProberConfig::focus_boost`, default 10). Other loops are still probed. An exit needs an
  observed closing edge to this node, or it yields no focused loop. Neighbor probes ignore focus.
- `set_noise(bool)`: switches cover traffic (`noise` feature, on by default). Default off. Independent of the level.

## Specification

- [RFC-0010: Automatic Path Discovery](https://github.com/hoprnet/rfc/blob/main/rfcs/RFC-0010-automatic-path-discovery/0010-automatic-path-discovery.md)

## License

GPL-3.0-only
