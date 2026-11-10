## Optional transport diagnostics

Enable `serde` to implement `hopr_api::StateDump` on `HoprNetwork`. Poll `state_dump().await` through that trait to obtain an opaque
Serde-compatible object, including through `Arc` handles. `network.state().await` remains an inherent convenience method. Snapshot
structures stay private to this crate and their schema may change. The legacy `state-dump` feature enables `serde` too; there is no
standalone diagnostic crate.

The snapshot includes local peer identity, connected/discovered peer counts and the transport's existing connectivity classification. It
allocates no peer list. Probe outcomes and graph QoS remain separate observations; transport connectivity does not imply probe success.
Counts and connectivity are independently observed.

Run `network.run_state_reporting(instance)` in the host runtime for periodic INFO `event=component_state` records. The host owns
cancellation and its tracing subscriber. Each reporter has an independent sequence and 5-second collection deadline; records have a 32 KiB
budget and preserve reason and `analysis_required` even on collection or encoding failures. Missing observations request analysis without
assigning an operational failure state.

`HOPR_STATE_DUMP_INTERVAL` defaults to 60 seconds, accepts 5 through 86400 seconds, and disables collection at zero. No reads occur while
disabled.
