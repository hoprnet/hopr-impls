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

#[test]
fn funding_must_cover_every_remaining_hop() -> anyhow::Result<()> {
    // A first edge funds the whole downstream path, not just the next hop, so the same balance can
    // be enough for a short path and not for a long one.
    let net = Net::from_json(
        r#"{
      "me": "me",
      "ticket_face_value": 1000,
      "edges": [
        { "from": "me", "to": "r1",   "connected": true, "latency_ms": 20, "balance": 2500, "relayed_ms": 30 },
        { "from": "r1", "to": "r2",   "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30 },
        { "from": "r1", "to": "exit", "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30 },
        { "from": "r2", "to": "exit", "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30 }
      ]
    }"#,
    )?;

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
fn the_streams_average_only_when_both_carry_evidence() -> anyhow::Result<()> {
    // RFC-0014 §4.2: the immediate and intermediate streams combine as their mean when both are
    // present, and otherwise the single present one stands alone. So one healthy stream and two
    // healthy streams both read 1.0 — an edge is not penalised for evidence it has yet to acquire.
    let net = Net::from_json(&two_relays(
        r#"{ "from": "me", "to": "ra", "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30, "packets": 10, "acks": 10 }"#,
        r#"{ "from": "me", "to": "rb", "connected": true, "latency_ms": 20, "balance": 100000, "packets": 10, "acks": 10 }"#,
    ))?;

    assert_eq!(
        net.score("me", "ra"),
        Some(1.0),
        "two healthy streams average to a healthy score"
    );
    assert_eq!(
        net.score("me", "rb"),
        Some(1.0),
        "one healthy stream stands alone rather than being averaged against an absent one"
    );

    // The averaging is nonetheless real: a dead second stream halves the score, which is what stops
    // a healthy ping from carrying a relay that forwards nothing.
    let masked = Net::from_json(&two_relays(
        r#"{ "from": "me", "to": "ra", "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30, "packets": 10, "acks": 10 }"#,
        r#"{ "from": "me", "to": "rb", "connected": true, "latency_ms": 20, "balance": 100000, "failed_relays": 20, "packets": 10, "acks": 10 }"#,
    ))?;
    assert_eq!(
        masked.score("me", "rb"),
        Some(0.5),
        "a dead intermediate stream pulls the mean down by half"
    );
    Ok(())
}

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
fn a_sub_millisecond_link_must_score_as_the_fastest_band() -> anyhow::Result<()> {
    // The residual a loopback attributes is a difference of two similar quantities and lands at or
    // below a millisecond routinely. Truncated to zero it would read as "never measured", which
    // scores worse than the slowest measured link.
    let net = Net::from_json(&two_relays(
        r#"{ "from": "me", "to": "ra", "connected": true, "latency_ms": 0.4, "balance": 100000, "relayed_ms": 0.4 }"#,
        r#"{ "from": "me", "to": "rb", "connected": true, "latency_ms": 300, "balance": 100000, "relayed_ms": 300 }"#,
    ))?;

    let fast = net.score("me", "ra").expect("ra is measured");
    let slow = net.score("me", "rb").expect("rb is measured");

    assert!(
        fast > slow,
        "a sub-millisecond link must outrank a 300 ms one, got {fast} vs {slow}"
    );
    Ok(())
}

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
fn a_failing_probe_must_not_be_masked_by_healthy_surb_traffic() -> anyhow::Result<()> {
    // The two signals measure different things — reachability of this hop, and delivery of the
    // whole loop — so the worse of the two governs and neither can hide the other.
    let net = Net::from_json(&two_relays(
        r#"{ "from": "me", "to": "ra", "connected": true, "latency_ms": 20, "balance": 100000, "surbs": [100, 100] }"#,
        r#"{ "from": "me", "to": "rb", "connected": true, "latency_ms": 20, "balance": 100000, "surbs": [100, 100], "failed_relays": 10 }"#,
    ))?;

    let delivering = net.score("me", "ra").expect("ra is measured");
    let failing = net.score("me", "rb").expect("rb is measured");

    assert!(
        failing < delivering,
        "failing probes must pull the score down despite healthy SURB delivery: {failing} vs {delivering}"
    );
    Ok(())
}
