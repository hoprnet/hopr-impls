# hopr-network-graph

Implementation of the HOPR network graph

Part of the [HOPR](https://hoprnet.org/) protocol implementation.

## Traversal diagnostics

`simple_paths`, `simple_paths_from`, and `simple_loopback_to_self` create DEBUG spans named `graph.simple_paths`, `graph.simple_paths_from`,
and `graph.simple_loopback_to_self` under the caller's active span. The spans carry the source, destination (when specified), requested edge
length or loopback relay hops, and `take_count`. Each call emits one DEBUG completion event with `returned_count`, `elapsed_us` (including
lock wait), and `reason`: `completed`, `invalid_length`, `invalid_hops`, `zero_limit`, `source_missing`, `destination_missing`, or
`no_eligible_paths`. `no_eligible_paths` reports the search outcome; it does not identify why individual branches were rejected.

Counts describe returned candidates, not all possible paths. A result limit does not imply that the best paths were found or that the search
was exhaustive. At TRACE, each returned traversal candidate includes its `path_id` and nodes after the source, including the destination.
Loopback candidates show the forward leg before the closing source is appended. Values remain generic and are logged by the transport
selector where concrete metrics are known.

Per-observation updates and their spans remain at TRACE. Relayer health is recorded through the existing health update API; health reporting
belongs to transport/SURB telemetry. Final route validation, weighting, and selection also belong to the transport selector/planner. These
graph diagnostics add no INFO events or health classification.

TRACE is compiled out of release builds by the workspace's current `release_max_level_debug` tracing feature. Candidate details therefore
require a build that retains TRACE; DEBUG summaries remain available in release builds.

## License

GPL-3.0-only
