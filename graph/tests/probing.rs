//! Loopback probe generation and the `PathId` conformance it depends on.
//!
//! A loopback probe leaves `me` and comes back to `me` over 2–3 relays (summary §6.2). Unlike a data
//! path it is deliberately permissive: RFC-0010 §4.2.3 wants poorly-scoring edges probed *more*
//! urgently, so probe generation must reach edges the data path has starved.

mod common;

use common::Net;
use hopr_network_graph::{MAX_LOOPBACK_HOPS, MIN_LOOPBACK_HOPS};

/// A ring big enough for both permitted loop lengths, with the closing edges every loop needs.
const RING: &str = r#"{
  "me": "me",
  "ticket_face_value": 100,
  "edges": [
    { "from": "me", "to": "a",  "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30 },
    { "from": "a",  "to": "b",  "balance": 100000, "relayed_ms": 30 },
    { "from": "b",  "to": "c",  "balance": 100000, "relayed_ms": 30 },
    { "from": "b",  "to": "me", "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30 },
    { "from": "c",  "to": "me", "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30 }
  ]
}"#;

// ── Permitted loop lengths ───────────────────────────────────────────────

#[test]
fn a_two_hop_loop_should_close_back_at_me() -> anyhow::Result<()> {
    let net = Net::from_json(RING)?;

    // The emitted path keeps the closing `me` and drops the leading one, so a 2-relay loop reads as
    // three nodes.
    assert_eq!(
        net.loopback(2),
        vec![vec!["a", "b", "me"]],
        "me→a→b→me is the only 2-relay loop that closes"
    );
    Ok(())
}

#[test]
fn a_three_hop_loop_should_close_back_at_me() -> anyhow::Result<()> {
    let net = Net::from_json(RING)?;

    assert_eq!(
        net.loopback(3),
        vec![vec!["a", "b", "c", "me"]],
        "me→a→b→c→me is the only 3-relay loop that closes"
    );
    Ok(())
}

#[test]
fn loop_lengths_outside_the_permitted_range_yield_nothing() -> anyhow::Result<()> {
    let net = Net::from_json(RING)?;

    for hops in [0, 1, MAX_LOOPBACK_HOPS + 1] {
        assert!(
            net.loopback(hops).is_empty(),
            "{hops} relays is outside {MIN_LOOPBACK_HOPS}..={MAX_LOOPBACK_HOPS} and must yield nothing"
        );
    }
    Ok(())
}

#[test]
fn a_single_relay_loop_is_excluded_for_privacy() -> anyhow::Result<()> {
    // RFC-0010 §4.2.1.2 permits one relay, but that relay would see its predecessor and successor
    // are the same node, identifying both the loop and its originator. A local decision, so it is
    // asserted here rather than inferred from the range check above.
    let net = Net::from_json(
        r#"{
      "me": "me",
      "edges": [
        { "from": "me", "to": "a",  "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30 },
        { "from": "a",  "to": "me", "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30 }
      ]
    }"#,
    )?;

    assert!(
        net.loopback(1).is_empty(),
        "a one-relay loop identifies its originator to that relay"
    );
    Ok(())
}

// ── The closing edge ─────────────────────────────────────────────────────

#[test]
fn a_loop_requires_the_closing_edge_back_to_me() -> anyhow::Result<()> {
    // The emitted path ends at `me`, so `last → me` is what the probe returns over. Without it the
    // probe could be sent but never attributed, wasting the round trip.
    let net = Net::from_json(
        r#"{
      "me": "me",
      "edges": [
        { "from": "me", "to": "a", "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30 },
        { "from": "a",  "to": "b", "balance": 100000, "relayed_ms": 30 },
        { "from": "me", "to": "b", "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30 }
      ]
    }"#,
    )?;

    assert!(
        net.loopback(2).is_empty(),
        "an outbound edge to the last relay does not let the loop close"
    );

    // The closing edge is the only thing missing: adding it to the same topology makes the loop
    // available, so the exclusion above is attributable to it and not to some other gap.
    net.observe("b", "me", |obs| {
        use hopr_api::graph::traits::{EdgeObservableWrite, EdgeWeightType};
        obs.record(EdgeWeightType::Connected(true));
        obs.record(EdgeWeightType::Immediate(Ok(std::time::Duration::from_millis(20))));
    });
    assert_eq!(
        net.loopback(2),
        vec![vec!["a", "b", "me"]],
        "with the closing edge present the same topology yields the loop"
    );
    Ok(())
}

#[test]
fn a_closing_edge_observed_down_excludes_the_loop() -> anyhow::Result<()> {
    let net = Net::from_json(
        r#"{
      "me": "me",
      "edges": [
        { "from": "me", "to": "a",  "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30 },
        { "from": "a",  "to": "b",  "balance": 100000, "relayed_ms": 30 },
        { "from": "b",  "to": "me", "connected": false, "balance": 100000, "relayed_ms": 30 }
      ]
    }"#,
    )?;

    assert!(
        net.loopback(2).is_empty(),
        "a reply cannot arrive over a closing edge known to be down"
    );
    Ok(())
}

#[test]
fn an_unchecked_closing_edge_still_permits_the_loop() -> anyhow::Result<()> {
    // Probing is how an unchecked edge becomes checked, so refusing to probe it is self-sealing.
    let net = Net::from_json(
        r#"{
      "me": "me",
      "edges": [
        { "from": "me", "to": "a",  "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30 },
        { "from": "a",  "to": "b",  "balance": 100000, "relayed_ms": 30 },
        { "from": "b",  "to": "me", "balance": 100000 }
      ]
    }"#,
    )?;

    assert_eq!(
        net.loopback(2),
        vec![vec!["a", "b", "me"]],
        "an unchecked closing edge must not exclude the loop that would check it"
    );
    Ok(())
}

// ── Probe generation is more permissive than data selection ──────────────

#[test]
fn probe_generation_must_reach_an_edge_the_data_path_rejects() -> anyhow::Result<()> {
    // RFC-0010 §4.2.1.4: a low-scoring edge is probed *more* urgently. Applying the data path's
    // acknowledgement floor here would prune it, so it would stop being probed, its rate would
    // never be resampled, and the exclusion would become permanent.
    let net = Net::from_json(
        r#"{
      "me": "me",
      "min_ack_rate": 0.5,
      "ticket_face_value": 100,
      "edges": [
        { "from": "me", "to": "a",  "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30, "packets": 10, "acks": 0 },
        { "from": "a",  "to": "b",  "balance": 100000, "relayed_ms": 30 },
        { "from": "b",  "to": "me", "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30 },
        { "from": "a",  "to": "exit", "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30 }
      ]
    }"#,
    )?;

    assert!(
        net.forward("exit", 1).is_empty(),
        "the data path rejects a first hop acknowledging nothing"
    );
    assert_eq!(
        net.loopback(2),
        vec![vec!["a", "b", "me"]],
        "probe generation must still reach it, or it can never recover"
    );
    Ok(())
}

#[test]
fn probe_generation_must_reach_a_measured_dead_edge() -> anyhow::Result<()> {
    // A relay whose every loopback failed is the case the whole scoring change exists for. It must
    // be starved of data traffic yet remain probeable.
    let net = Net::from_json(
        r#"{
      "me": "me",
      "ticket_face_value": 100,
      "edges": [
        { "from": "me", "to": "a",  "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30 },
        { "from": "a",  "to": "b",  "balance": 100000, "failed_relays": 20 },
        { "from": "b",  "to": "me", "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30 }
      ]
    }"#,
    )?;

    assert_eq!(
        net.loopback(2),
        vec![vec!["a", "b", "me"]],
        "a measured-dead edge must stay in the probe candidate set so it can recover"
    );
    Ok(())
}

// ── PathId conformance ───────────────────────────────────────────────────

#[test]
fn path_id_slots_are_key_derived_and_never_the_padding_value() -> anyhow::Result<()> {
    // RFC-0010 §4.3.3 reserves `0` for padding and forbids it as a node identifier.
    let net = Net::from_json(RING)?;

    for name in ["me", "a", "b", "c"] {
        let slot = net.slot(name).unwrap_or_else(|| panic!("{name} should have a slot"));
        assert_ne!(slot, 0, "{name} must not encode to the reserved padding value");
    }
    Ok(())
}

#[test]
fn a_two_hop_loop_carries_the_closing_slot_and_pads_the_rest() -> anyhow::Result<()> {
    let net = Net::from_json(RING)?;

    let me = net.slot("me").expect("me is in the graph");
    let a = net.slot("a").expect("a is in the graph");
    let b = net.slot("b").expect("b is in the graph");

    assert_eq!(
        net.loopback_slots(2),
        vec![[me, a, b, me, 0]],
        "the loop is recorded as me→a→b→me with the unused slot left as padding"
    );
    Ok(())
}

#[test]
fn a_three_hop_loop_fills_every_slot() -> anyhow::Result<()> {
    // At the maximum length the closing slot is the last one, so no padding remains — the case that
    // would break a reader trimming on "first zero".
    let net = Net::from_json(RING)?;

    let me = net.slot("me").expect("me is in the graph");
    let a = net.slot("a").expect("a is in the graph");
    let b = net.slot("b").expect("b is in the graph");
    let c = net.slot("c").expect("c is in the graph");

    assert_eq!(net.loopback_slots(3), vec![[me, a, b, c, me]], "no padding remains");
    Ok(())
}

#[test]
fn a_node_with_no_edges_still_has_a_slot() -> anyhow::Result<()> {
    let net = Net::from_json(r#"{ "me": "me", "nodes": ["known"], "edges": [] }"#)?;

    assert!(net.slot("known").is_some(), "a known node has a slot");
    Ok(())
}
