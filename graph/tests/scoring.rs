//! How an edge earns, loses, or never acquires a score, and what selection does with each.
//!
//! The distinction the graph exists to preserve: *never measured* is not *measured and useless*.
//! An unmeasured edge is penalised so it stays discoverable; a measured-dead one is starved
//! (summary §6.2, §6.3).

mod common;

use common::Net;

/// Two relays reaching the same exit, so their values can be compared directly.
fn two_relays(a: &str, b: &str) -> String {
    format!(
        r#"{{
      "me": "me",
      "ticket_face_value": 100,
      "edges": [
        {a},
        {b},
        {{ "from": "ra", "to": "exit", "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30 }},
        {{ "from": "rb", "to": "exit", "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30 }}
      ]
    }}"#
    )
}

// ── Channel funding ──────────────────────────────────────────────────────

#[test]
fn an_unknown_balance_is_not_evidence_of_sufficiency() -> anyhow::Result<()> {
    // `None` means the graph has not been told the balance, which cannot justify spending it.
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
        "an unknown balance cannot fund a hop"
    );
    Ok(())
}

#[test]
fn a_drained_channel_is_rejected_rather_than_scored() -> anyhow::Result<()> {
    // `Some(0)` is an open channel with nothing left to spend. It differs from `None` only in that
    // we know it: both are unusable, and neither may be scored as if it were funded.
    let net = Net::from_json(
        r#"{
      "me": "me",
      "ticket_face_value": 100,
      "edges": [
        { "from": "me", "to": "r1",   "connected": true, "latency_ms": 20, "balance": 0, "relayed_ms": 30 },
        { "from": "r1", "to": "exit", "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30 }
      ]
    }"#,
    )?;

    assert!(
        net.forward("exit", 1).is_empty(),
        "a drained channel funds nothing, however healthy the link"
    );
    Ok(())
}

/// A path `me -> r1 -> {r2 ->} exit` whose first edge holds `first_balance`, at face value 1000.
fn funded_path(first_balance: u64) -> anyhow::Result<Net> {
    Net::from_json(&format!(
        r#"{{
      "me": "me",
      "ticket_face_value": 1000,
      "edges": [
        {{ "from": "me", "to": "r1",   "connected": true, "latency_ms": 20, "balance": {first_balance}, "relayed_ms": 30 }},
        {{ "from": "r1", "to": "r2",   "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30 }},
        {{ "from": "r1", "to": "exit", "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30 }},
        {{ "from": "r2", "to": "exit", "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30 }}
      ]
    }}"#
    ))
}

#[test]
fn funding_must_cover_every_remaining_hop() -> anyhow::Result<()> {
    // A first edge funds the whole downstream path, not just the next hop, so the same balance can
    // be enough for a short path and not for a long one.
    let net = funded_path(1500)?;

    assert_eq!(
        net.forward("exit", 1).len(),
        1,
        "one remaining hop is within the first edge's balance"
    );
    assert!(
        net.forward("exit", 2).is_empty(),
        "two remaining hops are not, so the longer path must be rejected"
    );
    Ok(())
}

#[test]
fn funding_needs_exactly_remaining_hops_times_face_value() -> anyhow::Result<()> {
    // The check is the bare `remaining_hops * face_value`, with no safety margin on top: a channel
    // funded to exactly that amount is usable, and one wei less is not.
    assert_eq!(
        funded_path(2000)?.forward("exit", 2).len(),
        1,
        "a balance equal to two tickets funds two remaining hops"
    );
    assert!(
        funded_path(1999)?.forward("exit", 2).is_empty(),
        "a balance one below two tickets cannot fund two remaining hops"
    );
    Ok(())
}

#[test]
fn a_zero_face_value_waives_the_amount_but_not_the_channel() -> anyhow::Result<()> {
    // A network-wide face value of zero prices relaying at nothing, so any balance funds any hop.
    // The relayer still issues a ticket, so a channel must exist — the amount is waived, not the
    // requirement.
    let funded = Net::from_json(
        r#"{
      "me": "me",
      "ticket_face_value": 0,
      "edges": [
        { "from": "me", "to": "r1",   "connected": true, "latency_ms": 20, "balance": 0, "relayed_ms": 30 },
        { "from": "r1", "to": "exit", "connected": true, "latency_ms": 20, "relayed_ms": 30 }
      ]
    }"#,
    )?;
    assert_eq!(
        funded.forward("exit", 1).len(),
        1,
        "at a zero face value even a drained channel funds the hop"
    );

    let channel_less = Net::from_json(
        r#"{
      "me": "me",
      "ticket_face_value": 0,
      "edges": [
        { "from": "me", "to": "r1",   "connected": true, "latency_ms": 20, "relayed_ms": 30 },
        { "from": "r1", "to": "exit", "connected": true, "latency_ms": 20, "relayed_ms": 30 }
      ]
    }"#,
    )?;
    assert!(
        channel_less.forward("exit", 1).is_empty(),
        "no channel at all still fails, since the relayer must have one to issue against"
    );
    Ok(())
}

// ── Presence versus measurement ──────────────────────────────────────────

#[test]
fn a_measured_dead_relay_is_starved_but_not_pruned() -> anyhow::Result<()> {
    // RFC-0010 §4.2.3 requires unreliable edges to be "progressively starved rather than suddenly
    // eliminated", with their score "continuously updated by the ongoing probe stream". A pruned
    // edge receives no probes, so starvation must never reach zero candidates.
    // Dead on every stream, which is what "measured dead" means. A relay that answers pings but
    // relays nothing is the separate masking case below.
    let net = Net::from_json(&two_relays(
        r#"{ "from": "me", "to": "ra", "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30, "packets": 10, "acks": 10 }"#,
        r#"{ "from": "me", "to": "rb", "connected": true, "failed_probes": 20, "balance": 100000, "failed_relays": 20, "packets": 10, "acks": 10 }"#,
    ))?;

    let routes = net.forward("exit", 1);
    let healthy = routes.value_of(&["ra"]).expect("ra should be a candidate");
    let dead = routes.value_of(&["rb"]).expect("rb must remain a candidate");

    assert!(
        dead > 0.0,
        "a non-positive value prunes the edge from selection, so it could never recover"
    );
    let share = dead / (dead + healthy);
    assert!(
        share < 0.05,
        "a measured-dead relay must draw a negligible share of the sampling weight, got {share}"
    );
    Ok(())
}

#[test]
fn a_healthy_direct_link_must_not_mask_a_dead_relay() -> anyhow::Result<()> {
    // The defect the whole stack exists for: a node that answers pings perfectly but relays nothing
    // must not score as if only the ping mattered.
    let net = Net::from_json(&two_relays(
        r#"{ "from": "me", "to": "ra", "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30 }"#,
        r#"{ "from": "me", "to": "rb", "connected": true, "latency_ms": 20, "balance": 100000, "failed_relays": 20 }"#,
    ))?;

    let pristine = net.score("me", "ra").expect("ra is measured");
    let masked = net.score("me", "rb").expect("rb is measured on both streams");

    assert!(
        masked < pristine,
        "an excellent ping must not lift a relay that forwards nothing: {masked} vs {pristine}"
    );
    Ok(())
}

#[test]
fn an_acknowledgement_rate_below_the_floor_rejects_the_hop() -> anyhow::Result<()> {
    // The immediate peer is the one node that can be held to account for dropping our packets.
    let net = Net::from_json(
        r#"{
      "me": "me",
      "ticket_face_value": 100,
      "min_ack_rate": 0.5,
      "edges": [
        { "from": "me", "to": "r1",   "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30, "packets": 10, "acks": 1 },
        { "from": "r1", "to": "exit", "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30 }
      ]
    }"#,
    )?;

    assert!(
        net.forward("exit", 1).is_empty(),
        "a peer acknowledging a tenth of our packets is below a half"
    );
    Ok(())
}

// ── Latency scoring ──────────────────────────────────────────────────────

#[test]
fn latency_bands_should_order_relays_by_speed() -> anyhow::Result<()> {
    let net = Net::from_json(&two_relays(
        r#"{ "from": "me", "to": "ra", "connected": true, "latency_ms": 50, "balance": 100000, "relayed_ms": 50 }"#,
        r#"{ "from": "me", "to": "rb", "connected": true, "latency_ms": 150, "balance": 100000, "relayed_ms": 150 }"#,
    ))?;

    let routes = net.forward("exit", 1);
    let fast = routes.value_of(&["ra"]).expect("ra should be a candidate");
    let slow = routes.value_of(&["rb"]).expect("rb should be a candidate");

    assert!(fast > slow, "50 ms must outrank 150 ms: {fast} vs {slow}");
    Ok(())
}

// ── SURB round-trips as evidence ─────────────────────────────────────────

#[test]
fn surb_delivery_alone_should_score_an_otherwise_unprobed_relay() -> anyhow::Result<()> {
    // A round-trip costs no extra packets and accrues at data rates, so an edge carrying real
    // traffic is measured even if no loopback probe has reached it yet.
    let net = Net::from_json(&two_relays(
        r#"{ "from": "me", "to": "ra", "connected": true, "latency_ms": 20, "balance": 100000, "surbs": [100, 100], "packets": 10, "acks": 10 }"#,
        r#"{ "from": "me", "to": "rb", "connected": true, "latency_ms": 20, "balance": 100000, "packets": 10, "acks": 10 }"#,
    ))?;

    let delivering = net
        .score("me", "ra")
        .expect("SURB traffic is evidence, so the edge is measured rather than unobserved");
    let untouched = net.score("me", "rb").expect("rb is measured on its immediate stream");

    // Regression guard. A round-trip proves the loop was traversed but carries no per-edge latency,
    // so this edge has a delivery rate and no latency. Scoring the absent latency at the no-data
    // floor would multiply real evidence by a twentieth and rank the delivering edge *below* the
    // one nothing is known about — the inversion this asserts against.
    assert!(
        delivering >= untouched,
        "delivery evidence must never lower a score: {delivering} vs {untouched}"
    );
    Ok(())
}

#[test]
fn the_configured_edge_penalty_should_govern_unmeasured_edges() -> anyhow::Result<()> {
    // The penalty is what keeps an unmeasured edge discoverable, so how hard it bites is a
    // deployment decision. Asserted as a comparison between two configurations: pinning one number
    // would only restate the constant.
    let scenario = |penalty: f64| {
        format!(
            r#"{{
      "me": "me",
      "ticket_face_value": 100,
      "edge_penalty": {penalty},
      "edges": [
        {{ "from": "me", "to": "r1",   "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30, "packets": 10, "acks": 10 }},
        {{ "from": "r1", "to": "exit", "connected": true }}
      ]
    }}"#
        )
    };

    let harsh = Net::from_json(&scenario(0.1))?;
    let lenient = Net::from_json(&scenario(0.9))?;

    let harsh_value = harsh.forward("exit", 1).value_of(&["r1"]).expect("r1 is a candidate");
    let lenient_value = lenient.forward("exit", 1).value_of(&["r1"]).expect("r1 is a candidate");

    assert!(
        lenient_value > harsh_value,
        "a laxer penalty must leave an unmeasured edge more selectable: {lenient_value} vs {harsh_value}"
    );
    assert!(
        harsh_value > 0.0,
        "even the harshest penalty must leave the edge discoverable, got {harsh_value}"
    );
    Ok(())
}

// ── Relayer health ───────────────────────────────────────────────────────

fn record_health(net: &Net, name: &str, health: f64) {
    use hopr_api::graph::NetworkGraphUpdate;
    net.graph.record_nodes_health(&[(net.key(name), health)]);
}

fn healthy_relays() -> anyhow::Result<Net> {
    Net::from_json(&two_relays(
        r#"{ "from": "me", "to": "ra", "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30 }"#,
        r#"{ "from": "me", "to": "rb", "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30 }"#,
    ))
}

#[test]
fn a_dead_relayer_is_pruned_from_forward_paths() -> anyhow::Result<()> {
    let net = healthy_relays()?;
    assert_eq!(net.forward("exit", 1).len(), 2, "precondition: both relays usable");

    record_health(&net, "rb", 0.0);

    assert_eq!(net.forward("exit", 1).names(), vec![vec!["ra"]]);
    Ok(())
}

#[test]
fn a_degraded_relayer_draws_its_health_share_of_the_value() -> anyhow::Result<()> {
    let net = healthy_relays()?;
    let before = net.forward("exit", 1).value_of(&["rb"]).expect("rb is a candidate");

    record_health(&net, "rb", 0.25);

    let routes = net.forward("exit", 1);
    let after = routes.value_of(&["rb"]).expect("a degraded relay stays a candidate");
    assert!((after - before * 0.25).abs() < 1e-9, "{after} vs {before} * 0.25");
    assert_eq!(routes.value_of(&["ra"]), Some(before), "the other relay is untouched");
    Ok(())
}

#[test]
fn a_recovered_relayer_regains_its_full_value() -> anyhow::Result<()> {
    let net = healthy_relays()?;
    let before = net.forward("exit", 1).value_of(&["rb"]);

    record_health(&net, "rb", 0.0);
    record_health(&net, "rb", 1.0);

    assert_eq!(net.forward("exit", 1).value_of(&["rb"]), before);
    Ok(())
}

#[test]
fn the_destination_stays_reachable_whatever_its_health_as_a_relayer() -> anyhow::Result<()> {
    let net = healthy_relays()?;
    let before = net.forward("exit", 1);

    record_health(&net, "exit", 0.0);

    let after = net.forward("exit", 1);
    for relay in ["ra", "rb"] {
        assert_eq!(after.value_of(&[relay]), before.value_of(&[relay]), "via {relay}");
    }
    Ok(())
}

#[test]
fn a_dead_relayer_is_pruned_from_return_paths() -> anyhow::Result<()> {
    let net = Net::from_json(
        r#"{
      "me": "me",
      "ticket_face_value": 100,
      "edges": [
        { "from": "exit", "to": "ra", "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30 },
        { "from": "exit", "to": "rb", "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30 },
        { "from": "ra",   "to": "me", "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30 },
        { "from": "rb",   "to": "me", "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30 }
      ]
    }"#,
    )?;
    assert_eq!(net.returning("exit", 1).len(), 2, "precondition: both relays usable");

    record_health(&net, "rb", 0.0);

    assert_eq!(net.returning("exit", 1).names(), vec![vec!["ra"]]);
    Ok(())
}
