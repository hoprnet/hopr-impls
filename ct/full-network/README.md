# hopr-ct-full-network

Full implementation of the Telemetry functionality as specified in the HOPR RFCs along with optional noise (cover traffic) generation

Part of the [HOPR](https://hoprnet.org/) protocol implementation.

## How probing works

Probing is a lazy, pull-driven stream of "what to probe next".

- **The caller pulls and paces.** The generator yields one probe per pull, keeps no timer, and reads no clock. The interval, the per-window
  budget and the dial belong to the caller, which scales its budget by the dial.
- **Neighbours** are probed until they have `EgressConfig::stable_samples` samples. A settled peer on a stable connection is left alone,
  except by the random re-add or a trigger. A probe success rate or ack rate below its threshold reopens the probe, and the deeper the drop
  the sooner it comes back. A disconnect restarts the count.
- **Loopbacks** walk a persistent cursor over the loop set of a cycle, starting each cycle at a random position. A loop is skipped while any
  of its edges carries fresh SURB evidence. `EgressConfig::best_path_share` of the draw keeps the best paths measured and the rest explores.
  The weights that define the best paths come from `PathWeightProvider`, which the hoprnet path planner supplies, so probing watches the
  paths routing uses.
- **When nothing is probeable** the stream stays pending and retries on the next pull, or on the next control change.

## Steering egress traffic at runtime

`FullNetworkDiscovery::control()` returns a cloneable `EgressControl`. Take a clone before the prober is handed to the node. Changes reach
streams that are already running.

- `set_level(Some(Low | Medium | High | Ultra))` sets the dial to 0.1, 0.5, 1.0 or 2.0. The dial is a multiplier the caller applies to its
  own budget; the stream does not pace itself. A dial low enough to pull fewer than one loopback per half of the 60 s loopback evidence
  window can let a failing relay's evidence expire between rounds, so it may be routed again until its next loop fails. That trade is
  accepted: a slow dial trades slower detection for less traffic. `set_level(None)` stops probing and leaves the stream pending. Default
  `Some(High)`.
- `set_budget(Some(probes))` sets how many probes the caller pulls per window. The generator uses it only to close a coverage window.
- `set_focus(exits)` / `clear_focus()` seek the best loops around the exits. Forward loops are sought first, return loops next, and loops
  elsewhere in the network are still probed at the exploration share. An exit needs no channel and no edge back to this node.
- `coverage()` reports the edges with fresh evidence at the last closed loopback window, and the draws that window took.
- `set_noise(bool)` switches cover traffic (`noise` feature, on by default). Default off. Cover traffic keeps its own timer and is
  independent of the dial.

## Specification

- [RFC-0010: Automatic Path Discovery](https://github.com/hoprnet/rfc/blob/main/rfcs/RFC-0010-automatic-path-discovery/0010-automatic-path-discovery.md)

## License

GPL-3.0-only
