# hopr-ct-full-network

Full implementation of the Telemetry functionality as specified in the HOPR RFCs along with optional noise (cover traffic) generation

Part of the [HOPR](https://hoprnet.org/) protocol implementation.

## Steering egress traffic at runtime

`FullNetworkDiscovery::control()` returns a cloneable `EgressControl`. Take a clone before the prober is handed to the node. Changes reach
streams that are already running.

- **Probing is pull driven.** The probe stream yields one probe per pull and holds no timer. The consumer owns the pacing, the per-window
  budget and the clock; this crate only decides what to probe next. The consumer also owns the on/off switch (in hoprnet that is
  `ProbeControl::set_dial`).
- `set_best_set_cap(Some(paths))` caps the best set to what one window can re-measure. `None` leaves only `EgressConfig::best_set_size`.
- `wake_probing()` tells an idle stream to re-examine the graph. The graph has no change notification and the generator reads no clock, so
  whoever records a disconnect or a probe outcome should call it; otherwise a stream with nothing to offer stays parked.
- `set_path_weights(PathWeights)` hands in the path planner's own evaluation, so probing follows the distribution routing uses. Without it
  every path weighs the same.
- `set_focus(exits)` / `clear_focus()` draw the best set from the loops around the exits, forward loops first. The rest of the network is
  still explored at the configured share, so a focus is not a hard restriction. An exit needs no channel and no edge back to this node.
- `set_noise(bool)` switches cover traffic (`noise` feature, on by default). Default off. Cover traffic keeps its own interval.
- `coverage()` reports the edges the last completed loopback cycle saw fresh SURB evidence for.

### What the generator probes

A neighbor is probed until it has `EgressConfig::stable_samples` recorded outcomes, and left alone while it stays connected, apart from a
small random re-add (`EgressConfig::readd_probability`). An offer the consumer drops is not a sample. A connection drop restarts the count,
and a success or acknowledgement rate below its threshold brings the peer back, the furthest below first.

Loopbacks skip a path only when every one of its edges already carries fresh SURB evidence, and prefer paths with more unmeasured edges. The
best set is the paths the planner values most, and the exploration share spends the rest of the cycle outside it. Successive cycles start
further into the enumeration, so a candidate set larger than one window is still covered.

`EgressConfig::interval` paces cover traffic only; probe generation reads no clock.

## Specification

- [RFC-0010: Automatic Path Discovery](https://github.com/hoprnet/rfc/blob/main/rfcs/RFC-0010-automatic-path-discovery/0010-automatic-path-discovery.md)

## License

GPL-3.0-only
