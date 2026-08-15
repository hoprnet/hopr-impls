//! Path selection across every hop count HOPR supports, forward and returning.
//!
//! Sections follow the protocol rather than the code: what a 0-hop path is allowed to require, what
//! a relayed path must require, and where the two differ. Citations are to the RFC summary.

mod common;

use common::Net;
use hopr_api::types::internal::routing::RoutingOptions;

/// A linear network `me → r1 → r2 → r3 → exit`, every edge funded and probed.
///
/// One topology serves every hop count, so a test that asserts "3 hops" is asserting the selector
/// picked a length rather than that only one length was available.
const LINE: &str = r#"{
  "me": "me",
  "ticket_face_value": 100,
  "edges": [
    { "from": "me", "to": "r1",   "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30, "packets": 10, "acks": 10 },
    { "from": "r1", "to": "r2",   "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30, "packets": 10, "acks": 10 },
    { "from": "r2", "to": "r3",   "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30, "packets": 10, "acks": 10 },
    { "from": "r3", "to": "exit", "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30, "packets": 10, "acks": 10 },
    { "from": "me", "to": "r2",   "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30, "packets": 10, "acks": 10 },
    { "from": "me", "to": "r3",   "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30, "packets": 10, "acks": 10 },
    { "from": "me", "to": "exit", "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30, "packets": 10, "acks": 10 },
    { "from": "r1", "to": "exit", "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30, "packets": 10, "acks": 10 },
    { "from": "r2", "to": "exit", "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30, "packets": 10, "acks": 10 }
  ]
}"#;

// ── Forward paths, 0 through n hops ──────────────────────────────────────

#[test]
fn zero_hop_should_route_directly_with_no_relay() -> anyhow::Result<()> {
    let net = Net::from_json(LINE)?;
    let routes = net.forward("exit", 0);

    // The path body is empty: `me` is the source and `exit` the destination, so there is nothing
    // between them to name.
    assert_eq!(routes.names(), vec![Vec::<String>::new()], "a 0-hop path has no relays");
    Ok(())
}

#[test]
fn zero_hop_needs_no_channel_on_its_only_edge() -> anyhow::Result<()> {
    // RFC-0004 / summary §6.1: the final hop of a path needs no payment channel, and for a 0-hop
    // path the only edge *is* the final hop. Connectivity alone must suffice.
    let net = Net::from_json(
        r#"{
      "me": "me",
      "edges": [ { "from": "me", "to": "exit", "connected": true, "latency_ms": 20 } ]
    }"#,
    )?;

    assert_eq!(
        net.forward("exit", 0).len(),
        1,
        "a channel-less direct edge must still be routable"
    );
    Ok(())
}

#[test]
fn one_hop_should_route_through_a_single_relay() -> anyhow::Result<()> {
    let net = Net::from_json(LINE)?;
    let routes = net.forward("exit", 1);

    assert_eq!(
        routes.names(),
        vec![vec!["r1"], vec!["r2"], vec!["r3"]],
        "every funded relay with a channel onward is a candidate"
    );
    Ok(())
}

#[test]
fn two_hop_should_route_through_two_relays() -> anyhow::Result<()> {
    let net = Net::from_json(LINE)?;
    let routes = net.forward("exit", 2);

    assert!(
        routes.names().contains(&vec!["r1".to_string(), "r2".to_string()]),
        "me→r1→r2→exit is available, got {:?}",
        routes.names()
    );
    assert!(
        routes.0.iter().all(|(hops, _)| hops.len() == 2),
        "a 2-hop request must yield exactly two relays per path"
    );
    Ok(())
}

#[test]
fn three_hop_should_route_through_the_maximum_relays() -> anyhow::Result<()> {
    let net = Net::from_json(LINE)?;
    let routes = net.forward("exit", 3);

    assert_eq!(
        routes.names(),
        vec![vec!["r1", "r2", "r3"]],
        "only one 3-relay chain exists in this topology"
    );
    Ok(())
}

#[test]
fn beyond_the_routable_hop_limit_should_yield_nothing() -> anyhow::Result<()> {
    // The packet format carries at most `MAX_INTERMEDIATE_HOPS` relays; asking for more must yield
    // nothing rather than paths that are built and then discarded downstream.
    let net = Net::from_json(LINE)?;

    assert!(
        net.forward("exit", RoutingOptions::MAX_INTERMEDIATE_HOPS + 1)
            .is_empty(),
        "a request above the packet format's limit must produce no candidates"
    );
    Ok(())
}

#[test]
fn a_path_must_never_repeat_a_node() -> anyhow::Result<()> {
    // Simple paths only: a repeated relay would both waste a hop and let one node correlate the
    // packet with itself.
    let net = Net::from_json(LINE)?;

    for hops in 0..=RoutingOptions::MAX_INTERMEDIATE_HOPS {
        for (path, _) in net.forward("exit", hops).0 {
            let mut unique = path.clone();
            unique.sort();
            unique.dedup();
            assert_eq!(unique.len(), path.len(), "path {path:?} repeats a node");
            assert!(
                !path.contains(&"me".to_string()),
                "path {path:?} routes back through me"
            );
            assert!(
                !path.contains(&"exit".to_string()),
                "path {path:?} names the destination as a relay"
            );
        }
    }
    Ok(())
}

// ── First edge: connectivity and funding ─────────────────────────────────

#[test]
fn a_relayed_path_requires_a_funded_first_edge() -> anyhow::Result<()> {
    // Unlike the 0-hop case, the first edge of a relayed path is not final: the relay issues a
    // ticket on it, so it needs a channel with enough balance for the hops that remain.
    let net = Net::from_json(
        r#"{
      "me": "me",
      "ticket_face_value": 100,
      "edges": [
        { "from": "me", "to": "r1",   "connected": true, "latency_ms": 20, "relayed_ms": 30 },
        { "from": "r1", "to": "exit", "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30 }
      ]
    }"#,
    )?;

    assert!(
        net.forward("exit", 1).is_empty(),
        "an unfunded first edge cannot carry a relayed path"
    );
    Ok(())
}

#[test]
fn a_relayed_path_requires_a_reachable_first_edge() -> anyhow::Result<()> {
    let net = Net::from_json(
        r#"{
      "me": "me",
      "ticket_face_value": 100,
      "edges": [
        { "from": "me", "to": "r1",   "connected": false, "balance": 100000, "relayed_ms": 30 },
        { "from": "r1", "to": "exit", "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30 }
      ]
    }"#,
    )?;

    assert!(
        net.forward("exit", 1).is_empty(),
        "a first hop observed to be unreachable cannot start a path"
    );
    Ok(())
}

#[test]
fn an_unchecked_first_edge_stays_selectable() -> anyhow::Result<()> {
    // The counterpart to the test above. "Never checked" is not "down": excluding it would stop the
    // edge carrying traffic, and the acknowledgement evidence that traffic produces.
    //
    // The immediate stream here exists because packets were acknowledged over it, not because it
    // was probed — which is precisely how connectivity comes to be unknown on a live edge.
    let net = Net::from_json(
        r#"{
      "me": "me",
      "ticket_face_value": 100,
      "edges": [
        { "from": "me", "to": "r1",   "balance": 100000, "packets": 10, "acks": 10 },
        { "from": "r1", "to": "exit", "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30 }
      ]
    }"#,
    )?;

    assert_eq!(
        net.forward("exit", 1).len(),
        1,
        "an unchecked but funded and acknowledging first hop must remain a candidate"
    );
    Ok(())
}

#[test]
fn a_wholly_unobserved_first_edge_is_not_a_data_path_candidate() -> anyhow::Result<()> {
    // An edge known only from the chain — an open channel, never touched by transport — has no
    // immediate stream at all and is not selectable. That is not a starvation trap: the neighbour
    // prober walks every node in the graph rather than only nodes on selected paths, so such an
    // edge is measured regardless of whether data paths pick it (summary §6.2).
    let net = Net::from_json(
        r#"{
      "me": "me",
      "ticket_face_value": 100,
      "edges": [
        { "from": "me", "to": "r1",   "balance": 100000 },
        { "from": "r1", "to": "exit", "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30 }
      ]
    }"#,
    )?;

    assert!(
        net.forward("exit", 1).is_empty(),
        "a first hop with no transport observation whatsoever cannot start a path"
    );
    Ok(())
}

// ── Last edge ────────────────────────────────────────────────────────────

#[test]
fn the_last_edge_of_a_relayed_path_needs_no_channel() -> anyhow::Result<()> {
    // Same rule as the 0-hop case, one position along: `r1 → exit` is final, so the absence of a
    // balance there must not disqualify the path.
    let net = Net::from_json(
        r#"{
      "me": "me",
      "ticket_face_value": 100,
      "edges": [
        { "from": "me", "to": "r1",   "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30 },
        { "from": "r1", "to": "exit", "connected": true, "latency_ms": 20, "relayed_ms": 30 }
      ]
    }"#,
    )?;

    assert_eq!(
        net.forward("exit", 1).len(),
        1,
        "an unfunded final hop is expected, not disqualifying"
    );
    Ok(())
}

// ── Return paths ─────────────────────────────────────────────────────────

#[test]
fn a_return_path_must_come_home_over_a_reachable_edge() -> anyhow::Result<()> {
    // The return path ends at `me`, so its last edge is one we receive on and must be reachable —
    // the mirror of the forward case, where the last edge merely has to exist.
    let net = Net::from_json(
        r#"{
      "me": "me",
      "ticket_face_value": 100,
      "edges": [
        { "from": "exit", "to": "r1", "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30 },
        { "from": "r1",   "to": "me", "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30 }
      ]
    }"#,
    )?;

    assert_eq!(
        net.returning("exit", 1).names(),
        vec![vec!["r1"]],
        "a reachable closing edge makes the return path usable"
    );
    Ok(())
}

#[test]
fn a_return_path_over_an_unreachable_closing_edge_is_rejected() -> anyhow::Result<()> {
    let net = Net::from_json(
        r#"{
      "me": "me",
      "ticket_face_value": 100,
      "edges": [
        { "from": "exit", "to": "r1", "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30 },
        { "from": "r1",   "to": "me", "connected": false, "balance": 100000, "relayed_ms": 30 }
      ]
    }"#,
    )?;

    assert!(
        net.returning("exit", 1).is_empty(),
        "a reply cannot arrive over an edge observed to be down"
    );
    Ok(())
}

#[test]
fn channels_are_directional_so_a_forward_path_does_not_imply_a_return_one() -> anyhow::Result<()> {
    // Summary §3.1: `a→b` and `b→a` are separate channels. A network wired only outbound must
    // support forward paths and no return paths at all.
    let net = Net::from_json(
        r#"{
      "me": "me",
      "ticket_face_value": 100,
      "edges": [
        { "from": "me", "to": "r1",   "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30 },
        { "from": "r1", "to": "exit", "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30 }
      ]
    }"#,
    )?;

    assert_eq!(net.forward("exit", 1).len(), 1, "the outbound direction is wired");
    assert!(
        net.returning("exit", 1).is_empty(),
        "the reverse direction has no channels, so no return path exists"
    );
    Ok(())
}
