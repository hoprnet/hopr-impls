# hopr-chain-connector

Implementation of HOPR Chain APIs using Blokli client. Part of the [HOPR](https://hoprnet.org/) protocol implementation.

## Optional chain state dump

Enable `features = ["state-dump"]` to use `state_dump::ChainDump`. This adapter implements the shared `hopr_state_dump::StateDump` trait
with the connector's own `ChainState`. It needs a chain source and Safe address; it has no dependency on a graph or transport
implementation. Custom connectors may implement `StateDump` with a completely different serializable payload.

```rust,ignore
use hopr_chain_connector::state_dump::{ChainDump, Config, Reporter};
let config = Config::from_env()?;
let source = ChainDump::new(chain.clone(), safe_address, config.clone());
let reporter = Reporter::new("chain", node_id.to_string(), source, config);
// Spawn reporter.run() in the host runtime; the host owns cancellation and the tracing subscriber.
```

`ChainDump::collect()` reads Safe balance/allowance, publicly announced remote accounts, and source-visible local channels independently.
Amounts are decimal base-unit strings. Channels retain direction/status totals, up to four problematic channels, and up to sixteen
underfunded outgoing channels sorted by balance. Incoming channels are funded by their counterparty. Omission counts preserve coverage.

Use `with_funding_value(face_value)` to compare balances against the face value used by the host's funding policy. The adapter must be
refreshed when that policy changes. Without it, outgoing funding is explicitly unknown; it is not inferred from another component.
Connectivity and probe quality belong to the graph and transport dumps, not the chain's channel schema.

`state_dump()` interprets the collected state: incomplete reads signal `Unknown`; underfunding or pending closures signal `NeedsAnalysis`;
unknown funding signals `Unknown`; otherwise the observed scope signals `Healthy`. Unknown observations request analysis as well. Read
failures, timeouts, partial coverage and observed zero remain distinct. A timeout preserves channels already read. Individual reads use half
the configured component deadline, reserving time to return partial observations to the reporter. Error samples retain a capped
entity/message. Reads are not atomic: `chain_freshness=unverified` and `channels.scope=source_visible` do not claim a verified full-chain
inventory. Closed channels absent from the source are not reconstructed.

The diagnostic `StateRead` interface preserves errors before the legacy best-effort streams discard them. The built-in reader enumerates
only locally adjacent channel IDs, loads records in batches of at most 64 in blocking tasks, and maintains an announced-account counter.
Memory for channel IDs and peer deduplication scales with local channels, not remote topology. Reconnects reseed the announced counter.
Custom backends provide `count_announced_accounts`.

## Independent producer counters

`IntervalCounters` also implements `StateDump`, with its own `IntervalSnapshot` payload. Give each resolver, selector, SURB or probe module
its own handle and `Reporter`, using the producer's component name. A clone shares a window; a new handle creates an independent window. No
graph or chain source is required. Hosts may replace these counters with their own `StateDump` implementation.

Record `resolution(direction, destination, succeeded)`, `search(direction, destination, actual_phase_outcomes)`, and
`surb(destination, forward_reply_paths, counts)` at the corresponding producer. Register probes using `enable_probes()`; record matched
replies or actual expiries with `neighbor_probe` and `loopback_probe`. Late or unknown pongs must not count twice. Missing probe producers
remain `None`; registered idle producers report zero. Successful resolution/SURB recording never waits for a busy lock; overflow preserves
totals and marks affected windows partial. Failure samples displace healthy destination/peer samples.

Dumping drains only that handle's interval. Resolution failures, empty searches and probe timeouts signal `NeedsAnalysis`; idle windows
signal `Healthy`. SURB returns may cross minting windows, so `minted - returned` is not treated as a loss probability or failure signal.
Destination samples, sibling paths, peer samples and overflow counts remain bounded.

All reporters emit separate INFO `event=component_state` records with component identity, signal, reason and `analysis_required` fields. See
`hopr-state-dump` for interval configuration, deadlines, the 32 KiB record budget, and log extraction. Disabled reporters perform no reads
or counter resets. The former `Collector::new(chain, graph, network, ...)`, fixed node `Snapshot`, and `with_section` API are replaced by
independent reporters. Add custom strategy or node functionality by implementing `StateDump`, rather than inserting a fixed node section.

## License

GPL-3.0-only
