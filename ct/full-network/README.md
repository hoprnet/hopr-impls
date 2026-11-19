# hopr-ct-full-network

Full implementation of the Telemetry functionality as specified in the HOPR RFCs along with optional noise (cover traffic) generation

Part of the [HOPR](https://hoprnet.org/) protocol implementation.

## Steering egress traffic at runtime

`FullNetworkDiscovery::control()` returns a cloneable `EgressControl`. Take a clone before the prober is handed to the node. Changes reach
streams that are already running.

- **Probing is pull driven.** The probe stream yields one probe per pull and holds no timer. The consumer owns the pacing, the per-window
  budget and the clock; this crate only decides what to probe next.
- `set_level(Some(Low | Medium | High | Ultra))` sets the dial: 0.1, 0.5, 1.0 or 2.0 of the base pull rate. `set_level(None)` stops probing
  and leaves the stream pending. Default `Some(High)`.
- `set_budget(Some(probes))` bounds the best set to what one window can re-measure. `None` is unbounded.
- `set_path_weights(PathWeights)` hands in the path planner's own evaluation, so probing follows the distribution routing uses. Without it
  every path weighs the same.
- `set_focus(exits)` / `clear_focus()` draw the best set from the loops around the exits, forward loops first. The rest of the network is
  still explored at the configured share, so a focus is not a hard restriction. An exit needs no channel and no edge back to this node.
- `set_noise(bool)` switches cover traffic (`noise` feature, on by default). Default off. Cover traffic keeps its own interval and is
  independent of the dial.
- `coverage()` reports the edges the last completed loopback cycle saw fresh SURB evidence for.

### What the generator probes

A neighbor is probed until it has `EgressConfig::stable_samples` samples, and left alone while it stays connected. A connection drop
restarts the count, and a success or acknowledgement rate below its threshold brings the peer back, the furthest below first. Loopbacks skip
any path whose edges already carry fresh SURB evidence, and reserve the exploration share for paths outside the best set.

## Specification

- [RFC-0010: Automatic Path Discovery](https://github.com/hoprnet/rfc/blob/main/rfcs/RFC-0010-automatic-path-discovery/0010-automatic-path-discovery.md)

## License

GPL-3.0-only
