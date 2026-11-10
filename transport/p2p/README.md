## Optional transport state dump

Enable `state-dump` to implement `hopr_state_dump::StateDump` on `HoprNetwork`. The transport owns its `NetworkState` schema: local peer ID,
connected/discovered peer counts and its own health classification. It reports counts without allocating a peer list. No chain or graph
implementation is required, and a custom transport can implement the same trait with its own schema.

Use `Reporter::new("transport", node_id.to_string(), network.clone(), config)` and spawn its `run()` in the host runtime, independently of
other reporters. `Health::Red` or `Orange` signals `NeedsAnalysis`; `Unknown` remains unknown and requests analysis; `Yellow` and `Green`
signal `Healthy` according to this transport's connectivity policy. Connection counts and health are independently observed, not atomic. The
shared reporter emits INFO `event=component_state`, including component, instance, signal, reason and `analysis_required` even on
collection/encoding errors. Probe outcomes and graph QoS are separate observations; transport connectivity does not imply probe success.
