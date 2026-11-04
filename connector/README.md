# hopr-chain-connector

Implementation of HOPR Chain APIs using Blokli client

Part of the [HOPR](https://hoprnet.org/) protocol implementation.

## Compact operational state dump

Enable the `state-dump` feature to get the `state_dump` module. It provides the reusable part of
[issue #46](https://github.com/hoprnet/hopr-impls/issues/46), using chain, graph and network read traits plus the connector's
error-preserving `StateRead` diagnostic interface. The embedding node supplies the views, connects the routing, SURB and probe producers,
and starts the reporter.

- Read `state_dump::Config::from_env()`: `HOPR_STATE_DUMP_INTERVAL` defaults to 60 seconds; `0` disables reporting; enabled intervals are
  5–86400 seconds. `Config::new(seconds)` avoids environment access.
- Create one `IntervalCounters` handle when enabled. Successful resolutions and SURB counts never wait for its lock: when it is busy, they
  are added to the totals and overflow only. Clone it into the resolver (`resolution`), selector (`search`, with actual phase outcomes) and
  SURB producer (`surb`, with destination and sibling forward/reply paths). Use the same destination identity at the resolver and selector.
  For probes, call `enable_probes()` before starting the producer, then `neighbor_probe(peer, succeeded)` on a matched reply or actual
  expiry, and `loopback_probe(succeeded)` on a loopback return or expiry. These counters do not drain graph telemetry or alter routing
  state. Late/unknown pongs must not be counted again as successful probes.
- Construct `Collector::new(chain, graph, network, safe_address, config)` and run `collector.run(Some(counters))` using the node's runtime
  and existing tracing subscriber. The host owns spawning and cancellation. Pass `None` while producers are unavailable; their section is
  explicitly unavailable rather than reporting zero. Disabled reporting performs no reads or counter resets.

Each interval, including idle intervals, emits one INFO event with `event=node_state` and a JSON `state` field containing:

- Exact Safe balance and allowance in decimal token base units.
- Source-visible local channel totals by direction/status, a funding histogram of open outgoing channels, up to sixteen underfunded outgoing
  channels (lowest balance first, the rest counted in `underfunded_omitted`) and up to four problematic channels, including counterparty,
  balance, below-face-value flag, graph `is_connected`, transport connectivity and probe success rate. Incoming channels are funded by their
  counterparty, so they are not counted as underfunded.
- Connected, publicly announced and distinct open-channel peer counts (excluding the local announcement).
- Resolution/search totals and up to eight destination/direction samples with phase-1/phase-2 counts. Failures and empty searches displace
  healthy samples; overflow preserves aggregate counts and replacement samples mark `partial_window`.
- Minted/returned SURB totals and up to four destinations with four sibling path pairs each, plus overflow counts. Returns may cross minting
  windows, so these counts are not delivery probabilities.
- Neighbor and loopback probe success/timeout counts, with up to eight named neighbor peers, prioritizing timed-out peers over healthy
  samples. Named rows and overflow sum to the aggregate neighbor counts. `partial_window` marks replacement samples. `routing.value.probes`
  is null until a producer registers or records an outcome; registration survives interval resets, so subsequent idle intervals report zero.
  This preserves timeout frequency independently of sampled graph probe success rates.
- Up to four extra named sections from the embedding node (`Collector::with_section`), for example strategy states. Each is read once per
  record and capped at 2 KiB; a larger one is replaced by `{"status":"too_large"}`. The `sections` key is omitted when there are none.

Problem-channel sampling prioritizes underfunded open channels, then disconnection and poor probes. The 0.9 probe threshold only affects
sampling. Unknown observations and pending closures also qualify; omitted counts expose incomplete named coverage.

The payload is capped at 32 KiB, independently of peer/channel count. Each asynchronous source has a five-second deadline; failures,
timeouts, unavailable inputs and real zeros remain distinct. Sources are read independently: `chain_freshness=unverified` and
`channels.scope=source_visible` do not imply an atomic snapshot or complete historical closed-channel inventory. The connector enumerates
only graph edges adjacent to the local account, once per dump, and reads records in batches of at most 64 per blocking task. Temporary
channel IDs and peer deduplication use memory proportional to local channels/peers, rather than all network channels. It does not scan
remote channels. An atomic counter tracks public remote accounts, using the backend’s previous account value to handle repeated updates.
Connection startup seeds it with one backend scan; periodic reads allocate no identity set and perform no account scan. Reconnects reseed
the counter before subscription replay. Custom `Backend` implementations must provide `count_announced_accounts`. These observations remain
source-visible, not a verified full-chain inventory. Funding-strategy pass outcomes remain external to this module.

`channels.status=partial` means collected observations remain useful but coverage is incomplete. `channels.value.reads` reports successful
channel reads, missing records, backend errors, join failures, identity-lookup errors, timeout and completion. Up to four error samples
retain the failing entity and a capped message; larger error sets retain counts. A timeout keeps observations already consumed; counts
describe observed failures, not how many unread entries might also fail. The diagnostic reader returns errors before the legacy best-effort
streams would discard them, without changing those streams’ behavior.

Sampled channels identify their full counterparty and direction. SURB path pairs use compact numeric forward/reply slot arrays; mapping
those slots to peer identities requires the corresponding graph view.

With a tracing JSON subscriber, extract the structured payload using:

```sh
jq 'select(.fields.event == "node_state") | (.fields.state? // empty) | fromjson' node.jsonl
```

Encoding errors emit an INFO event with `status=encoding_error` instead of a `state` payload. Logger envelopes are outside the payload
budget. Node startup and producer wiring belong to the embedding hoprnet application. End-to-end record emission and representative runtime
and log-volume validation remain necessary before the state dump can be considered complete.

## License

GPL-3.0-only
