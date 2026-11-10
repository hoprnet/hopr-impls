# hopr-chain-connector

Implementation of HOPR Chain APIs using Blokli client. Part of the [HOPR](https://hoprnet.org/) protocol implementation.

## Optional diagnostics

Enable `serde` for diagnostics through `hopr_api::StateDump`. Configure the Safe address and funding policy with
`connector.state_view(safe_address, funding_value)`, then poll the returned opaque view through `state_dump().await`. Generic callers use
the same trait for chain, graph, transport, and producer diagnostics. Concrete view and snapshot types remain private to this crate; their
schema may change. The legacy `state-dump` feature also enables `serde`.

```rust,ignore
use hopr_api::StateDump;
let view = connector.state_view(safe_address, funding_value);
let snapshot = view.state_dump().await?;
let json = serde_json::to_string(&snapshot)?;
```

`connector.state(safe_address, funding_value).await` remains an inherent convenience method. There is no standalone diagnostic crate.

Collection reads Safe balance and allowance, announced accounts, and locally adjacent channels independently. Read errors, timeouts, partial
coverage, missing funding values and observed zeros remain distinct. Amounts use decimal base units. Channel details retain up to four
problematic channels and sixteen underfunded outgoing channels, with omission counts. Incoming channels are funded by their counterparties.
The supplied funding value must reflect the caller's current policy.

For periodic INFO telemetry, run `connector.run_state_reporting(instance, safe_address, funding_value)` in the host runtime. The host owns
cancellation and its tracing subscriber. Each component reports independently with its own deadline and sequence. Records carry
`event=component_state`, component identity, reason and `analysis_required`; they are capped at 32 KiB. Collection issues request diagnostic
analysis and do not assign operational `ComponentState::Failed`.

`HOPR_STATE_DUMP_INTERVAL` defaults to 60 seconds, accepts 5 through 86400 seconds, and disables collection at zero. Disabled reporting
performs no reads or counter resets. Chain subreads have a 2.5-second timeout, leaving time to retain partial observations within the
overall 5-second deadline. Local channel reads run in blocking batches of at most 64; memory scales with local adjacency rather than remote
topology. Reconnects reseed the announced-account counter.

## Operational state

`connector.component_state()` returns the shared `hopr_api::ComponentState`, even without enabling diagnostics. It reads the existing atomic
chain lifecycle: required live subscriptions operating normally are `Running`; startup, incomplete synchronization and subscription retries
are `Degraded`; a terminal subscription or connection failure is `Failed`. The existing `component_status()` retains the detailed status and
reason. No second atomic state is maintained.

Chain snapshots include the same `component_state`. Operational degradation and failure request analysis independently of snapshot
completeness, funding and channel observations. A diagnostic timeout does not change the runtime state; an operationally `Running` connector
may still return a partial diagnostic snapshot. Cached reads and metadata may remain available after live processing fails.

## Ownership

The connector owns chain snapshots only. Its private `diagnostics` module keeps collection and serialization models together; the backend
reader preserves individual channel read failures.

Routing, SURB, search-phase and probe counters live beside their event producers in `hopr_transport::TransportDiagnostics` (the `hoprnet`
repository). That handle consumes transport events, supplies a bounded non-draining path view to graph diagnostics, and implements the same
`hopr_api::StateDump` interface. The connector has no dependency on those counters.

For a changing funding policy, use `run_state_reporting_with_funding_policy(instance, safe_address, policy)`. The bounded, non-blocking
policy callback is read once per collection, so a cached ticket face-value update appears in the next chain snapshot.

## License

GPL-3.0-only
