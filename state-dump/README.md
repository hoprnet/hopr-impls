# hopr-state-dump

Optional operational reporting for independently replaceable components. Implement `StateDump` on a component or an adapter: its
associated `State` can be any serializable type. The implementation owns its schema and decides whether the observations need analysis.
It must bound its reads and allocation, yield during asynchronous work, and move blocking reads off the executor.

`Dump` pairs that state with a `Signal` and a short machine-readable reason. `Healthy` means the component found no issue in the observed
scope; `NeedsAnalysis` flags observed trouble; `Unknown` means health could not be established. Unknown is never interpreted as healthy.
The reporter also requests analysis when collection fails, panics, times out, or cannot be encoded within 32 KiB.

Create one `Reporter::new(component_name, instance_id, source, config)` per component. `collect()` works on demand, independently of timer
configuration. The host owns spawning/cancellation of `run()` and its tracing subscriber. Reporters have separate deadlines and sequences;
one component need not finish before another reports. No logger or runtime is installed, and no fixed node topology is assumed.

`Config::from_env()` reads `HOPR_STATE_DUMP_INTERVAL` (60 seconds by default, 0 disables periodic reads, 5–86400 enables them).
`with_source_timeout` sets a positive deadline up to 5 seconds. Disabled `run()` does not call the producer or drain counters.

Every tick, including idle ticks, emits INFO with `event=component_state`, `component`, `instance`, `sequence`, `signal`, `reason`, and
`analysis_required`. The JSON `state` field contains a versioned envelope and the component's own payload. These fields also survive an
encoding failure, allowing log processors to select records for analysis without understanding the payload schema.

```sh
jq 'select(.fields.event == "component_state" and .fields.analysis_required == true)' node.jsonl
jq 'select(.fields.event == "component_state") | (.fields.state? // empty) | fromjson' node.jsonl
```

Custom graph, chain, transport, strategy or storage implementations use the same trait with their own schemas and reason codes. They do
not implement another component's snapshot type. Register optional producers only when present; an absent producer is not an idle one.
