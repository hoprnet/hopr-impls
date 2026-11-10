# hopr-network-graph

Implementation of the HOPR network graph

Part of the [HOPR](https://hoprnet.org/) protocol implementation.

## Logging

Individual observations, rejected reports, and stale-path attribution details are emitted at TRACE, including their update spans. Nodes and
edges can disappear while telemetry is in flight; those unattributable reports do not emit one DEBUG/WARN line per observation. Malformed
path structure still produces WARN diagnostics, and so does a missing local node in the SURB round-trip handler; the loopback handlers
report it at TRACE. Enable TRACE in a build that retains it for individual reports; the workspace compiles TRACE out of release builds.

## Bounded graph diagnostics

Enable `serde` to implement `hopr_api::StateDump` on `ChannelGraph`. The asynchronous `state_dump().await` collects off the executor and
returns an opaque Serde-compatible object. For sampled paths, `graph.state_view(bounded_paths)` returns an opaque configured view
implementing the same trait. Concrete snapshot types and the graph read seam are private; the diagnostic schema may change. The legacy
`state-dump` feature enables `serde` too. There is no standalone diagnostic crate.

`graph.state(paths)` remains a synchronous inherent convenience method.

The on-demand method is synchronous and briefly locks the graph. For periodic reporting, run
`graph.run_state_reporting(instance, bounded_paths)` in the host runtime. The path provider runs with collection in a blocking task, must
bound its allocation, and must supply a non-draining view. The host owns cancellation and its tracing subscriber. Each reporting stream
keeps its own empty-search baseline; cumulative search diagnostics are never drained.

Missing local nodes, new empty searches, missing sampled path elements, degraded sampled observations and incomplete observations request
analysis. This diagnostic assessment does not assign operational `ComponentState::Failed`.

The snapshot includes graph-wide node/edge counts, whether the local node exists, ticket face value, edge penalty and minimum ack rate. It
counts both incoming and outgoing local edges and samples up to eight incident edges, including healthy and transport-only edges. Each named
directed edge carries full endpoint public keys and canonical path slots, exact decimal balance, connectivity, acknowledgement rate,
immediate/intermediate probe rates and latencies, score, relayer health and last-update time. Unobserved values are null; an observed zero
balance or zero probe success rate remains distinct. Unknown streams are not treated as failed streams.

When supplied with paths, the reader inspects at most 32 forward/reply slot arrays and samples up to four unique directed edges from them,
including remote edges. `paths` is null when the path source is unavailable and reports zero counts for an available idle source. Missing
edges, missing nodes, ambiguous slots and invalid padding are explicit. These observations cover the supplied path sample, not all routes. A
host supplies paths using the `run_state_reporting` callback. Path sampling runs in the same blocking task; the provider must bound
allocation and supply a non-draining view. This avoids coupling the graph to a particular routing/SURB counter implementation.

Samples prioritize missing path components, underfunding, disconnection/low acknowledgement rates, and poor probes/health, with
deterministic endpoint ordering for ties. Both samples share a 3 KiB JSON budget, so fewer rows may fit than the count caps.
`local_edges_omitted` and `paths.edges_omitted` include both count-limit and byte-budget omissions; aggregate counts survive trimming.
Self-loops count once in the sample and once in each direction.

The implementation reads local adjacency and indexed path slots under one graph read lock. It does not enumerate remote topology or compute
routes, and temporary memory is bounded independently of network size. Serialization for the byte budget happens after releasing the lock.
The private reporter applies a 5-second deadline and a 32 KiB record budget, emitting `event=component_state` with `component=graph`, reason
and `analysis_required`. Graph observations are not atomic with any other component. `HOPR_STATE_DUMP_INTERVAL` defaults to 60 seconds,
accepts 5 through 86400, and disables reads at zero.

## License

GPL-3.0-only

## Path-selection explanations by log level

- **INFO:** the graph component record includes `state.value.searches`: cumulative search/empty counts, bounded latest query examples,
  sample omission/contention counts and suppressed DEBUG count. The graph does not start another timer or install a subscriber.
- **DEBUG:** an unsuccessful traversal emits one bounded `graph_search_failure` explanation at most once per minute per shared graph,
  retaining the caller's context. Further failures remain counted in the INFO snapshot. Successful traversals emit no DEBUG event or span.
- **TRACE:** query spans, individual branch decisions, returned candidate paths and query completions remain available. Routine edge
  observations remain TRACE. TRACE requires a build that retains the static level.

Search examples identify forward, return, loopback or other queries relative to this node, their endpoints, requested length/result cap,
value-function type, returned count, whether the cap was reached, and counts of cycles, excluded nodes, value pruning, too-short target
visits and depth-limited branches. Counts describe the explored traversal, not every hypothetical complete path. A reached cap does not
claim that additional eligible paths exist or that the best paths were found.

A rejected example includes the visited prefix and actual edge observations captured at the pruning decision. The authoritative reason
`value_below_minimum` means the caller's supplied value function failed its threshold. Graph configuration at query time is included as
`graph_*` fields; opaque custom value functions may use different parameters, so diagnostics do not invent a more specific balance/ack
rejection reason. A graph update before the dump does not rewrite the decision-time evidence. Returned path examples include ordered
identities and canonical slots; candidates returned to the transport are not necessarily selected by its ranking or weighted draw.

At most two query examples are retained; repeated queries coalesce into their latest evidence and occurrence count. Recording never waits
for the diagnostic lock; contention preserves totals and increments an explicit lost-sample count. Forward/return coverage is preferred when
replacing samples. Examples share the existing 3 KiB graph budget with current edge samples; older/successful query examples and edge detail
may be omitted to fit. The cumulative search counters are not reset by snapshot reads and are not interval counters.

## Cross-stage identifiers

`correlation::SearchContext` gives each candidate-set computation a `selection_id` and each phase/query a `search_id`. A selector propagates
it with `with_search_context` around the synchronous graph call. The context is restored on return or unwind and never spans an async
suspension. Without a supplied context, the graph allocates IDs itself. IDs are allocated independently of log filters, are process-local,
and must be interpreted with the node identity and process lifetime.

Snapshots retain the IDs and phase. Query, candidate and branch TRACE records carry them explicitly. `graph.edge_value` spans add an
`edge_evaluation_id`, source/destination and edge index around the actual value-function call. A retained value-pruning example also records
that evaluation ID, allowing policy events emitted inside the value function to be matched to the exact attempted edge/prefix.
`correlation::candidate_id` uses the same canonical path slots as the graph, so transport validation, weighting, caching and draws can refer
to the same route without another graph lookup. It does not establish graph membership or guarantee collision-free identity.

The companion `hopr-api` patch emits specific TRACE gate reasons and the values checked by its built-in value functions; the graph itself
continues to report the factual `value_below_minimum` result for arbitrary opaque caller functions. No reason is inferred from a later graph
read. The companion transport patch carries selection IDs with cached candidate sets and records stage/reason fields for filtering,
validation, retention, weighting, cache refresh and the final weighted/exploratory draw. No extra routine DEBUG events are introduced.
