# hopr-chain-connector

Implementation of HOPR Chain APIs using Blokli client. Part of the [HOPR](https://hoprnet.org/) protocol implementation.

## Optional diagnostics

Enable `serde` for diagnostics through `hopr_api::StateDump`. Configure the Safe address and funding policy with
`connector.state_view(safe_address, funding_value)`, then poll the returned opaque view through `dump().await`. Generic callers use the same
trait for chain, graph, transport, and producer diagnostics. Concrete view and snapshot types remain private to this crate; their schema may
change. The legacy `state-dump` feature also enables `serde`.

```rust,ignore
use hopr_api::StateDump;
let view = connector.state_view(safe_address, funding_value);
let snapshot = view.dump().await?;
let json = serde_json::to_string(&snapshot)?;
```

`connector.state(safe_address, funding_value).await` remains an inherent convenience method. There is no standalone diagnostic crate.

Collection reads Safe balance and allowance, announced accounts, and locally adjacent channels independently. Read errors, timeouts, partial
coverage, missing funding values and observed zeros remain distinct. Amounts use decimal base units. Channel details retain up to four
problematic channels and sixteen underfunded outgoing channels, with omission counts. Incoming channels are funded by their counterparties.
The supplied funding value must reflect the caller's current policy. Passing `None` skips funding assessment: open outgoing channels remain
counted as `funding.unknown`, but this alone does not request analysis. Read failures, pending closures and operational degradation still
request analysis.

For periodic INFO telemetry, run `connector.run_state_reporting(instance, safe_address, funding_value)` in the host runtime. The host owns
cancellation and its tracing subscriber. Each component reports independently with its own deadline and sequence. Records carry
`event=component_state`, component identity, reason and `analysis_required`; they are capped at 32 KiB. Collection issues request diagnostic
analysis and do not assign operational `ComponentState::Failed`.

`HOPR_STATE_DUMP_INTERVAL` defaults to 60 seconds, accepts 5 through 86400 seconds, and disables collection at zero. Disabled reporting
performs no reads or counter resets. Chain subreads have a 2.5-second timeout, leaving time to retain partial observations within the
overall 5-second deadline. Local channel reads run in blocking batches of at most 64; memory scales with local adjacency rather than remote
topology. Reconnects reseed the announced-account counter.

## Chain metrics

Enable `telemetry` to export Prometheus metrics for chain writes and chain state. The feature adds `hopr-api/types-telemetry` and
`lazy_static`; without it, no instrument exists and the recording calls compile to nothing.

- `hopr_chain_tx_outcomes_total{operation,phase,outcome}` counts every write per API operation, such as `open_channel`, in the `submit` and
  `track` phase. A tracking timeout is `tracking_timeout`, never `reverted`: the transaction can still confirm.
- `hopr_chain_tx_duration_seconds{operation,phase}` times the submit phase (dequeue to tracking id) and the track phase (tracking id to
  final outcome).
- `hopr_chain_tx_queue_length`, `hopr_chain_nonce{kind="local"|"chain_pending"}` and `hopr_chain_caller_abandoned_total{operation}` expose
  queueing, nonce state and writes whose caller stopped waiting while the transaction stayed live.
- `hopr_chain_safe_balance`, `hopr_chain_safe_allowance`, `hopr_chain_channels{direction,status}`, `hopr_chain_usable_outgoing_channels`,
  `hopr_chain_blokli_indexed_head` and `hopr_chain_blokli_info_age_seconds` are refreshed every 60 seconds from the connected workflow,
  independently of `HOPR_STATE_DUMP_INTERVAL`. Amounts use wxHOPR base units. `open` is counted apart from `pending_to_close`.

Blokli reports one block number, the latest it indexed or observed, so head lag is not measurable from the connector.
`hopr_chain_blokli_info_age_seconds` is the freshness signal instead.

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

## Backend migration for 0.32.0

`Backend` implementors must now provide `count_announced_accounts(&self, me: &Address) -> Result<u64, Self::Error>`. Count accounts that
have announced routing information, excluding `me`. This is a required method and a breaking change for custom backends; it seeds the
announced-peer count at connection startup and reconnect. Returning a default zero would silently undercount pre-existing peers. Both
bundled backends implement the count.

## License

GPL-3.0-only
