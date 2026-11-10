//! A relay that rejects our packets still answers pings and signs an ack for every packet, so its
//! ping score and ack rate read healthy. Loopbacks are the only evidence that it delivers nothing.
//!
//! Every scenario feeds real loop paths, taken from the graph's own loopback generator, through
//! `record_edge` as timeouts or returns, then reads routes back for each hop count.

mod common;

use common::Net;
use hopr_api::{
    OffchainPublicKey,
    graph::{
        EdgeTransportTelemetry, MeasurableEdge, MeasurablePath, MeasurablePeer, NetworkGraphError, NetworkGraphUpdate,
        traits::{EdgeObservableWrite, EdgeWeightType},
    },
};

/// `me` can start through `good` or `bad`, which look identical to pings and acks: connected, same
/// latency, healthy ack rate, funded channels. Return edges let loopbacks close at `me`.
const TOPOLOGY: &str = r#"{
  "me": "me",
  "ticket_face_value": 100,
  "edges": [
    { "from": "me",   "to": "good", "connected": true, "latency_ms": 20, "balance": 100000, "packets": 10, "acks": 10 },
    { "from": "me",   "to": "bad",  "connected": true, "latency_ms": 20, "balance": 100000, "packets": 10, "acks": 10 },
    { "from": "me",   "to": "exit", "connected": true, "latency_ms": 20, "balance": 100000, "packets": 10, "acks": 10 },
    { "from": "good", "to": "exit", "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30 },
    { "from": "bad",  "to": "exit", "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30 },
    { "from": "good", "to": "m1",   "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30 },
    { "from": "bad",  "to": "m1",   "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30 },
    { "from": "m1",   "to": "exit", "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30 },
    { "from": "m1",   "to": "m2",   "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30 },
    { "from": "m2",   "to": "exit", "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30 },
    { "from": "good", "to": "me",   "connected": true, "latency_ms": 20 },
    { "from": "bad",  "to": "me",   "connected": true, "latency_ms": 20 },
    { "from": "m1",   "to": "me",   "connected": true, "latency_ms": 20 },
    { "from": "m2",   "to": "me",   "connected": true, "latency_ms": 20 }
  ]
}"#;

const LOOPS_PER_SHAPE: usize = 6;
const LOOP_RTT_MS: u128 = 40;

#[derive(Clone)]
struct Neighbor;

impl MeasurablePeer for Neighbor {
    fn peer(&self) -> &OffchainPublicKey {
        unreachable!("loopback telemetry carries no neighbor")
    }

    fn rtt(&self) -> std::time::Duration {
        unreachable!("loopback telemetry carries no neighbor")
    }
}

#[derive(Clone)]
struct Loop {
    path: Vec<u8>,
    timestamp_ms: u128,
}

impl MeasurablePath for Loop {
    fn id(&self) -> &[u8] {
        &[]
    }

    fn path(&self) -> &[u8] {
        &self.path
    }

    fn timestamp(&self) -> u128 {
        self.timestamp_ms
    }
}

fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn the_loop(slots: [u64; 5], timestamp_ms: u128) -> Loop {
    Loop {
        path: slots.iter().flat_map(|slot| slot.to_le_bytes()).collect(),
        timestamp_ms,
    }
}

/// Every loop through `bad` times out and every loop through `good` returns, over both loop shapes
/// probing generates.
fn probe_everything(net: &Net) {
    probe_with_dead(net, &["bad"]);
}

/// Every loop through any `dead` relay times out and every other loop returns, over both loop
/// shapes probing generates.
fn probe_with_dead(net: &Net, dead: &[&str]) {
    for loop_hops in [2, 3] {
        let names = net.loopback(loop_hops);
        let slots = net.loopback_slots(loop_hops);
        assert!(!names.is_empty(), "the topology must offer {loop_hops}-hop loops");

        for (names, slots) in names.iter().zip(slots) {
            let through_bad = names.iter().any(|name| dead.contains(&name.as_str()));
            for _ in 0..LOOPS_PER_SHAPE {
                let telemetry = if through_bad {
                    Err(NetworkGraphError::ProbeLoopbackTimeout(the_loop(slots, 0)))
                } else {
                    Ok(EdgeTransportTelemetry::<Neighbor, Loop>::Loopback(the_loop(
                        slots,
                        now_ms() - LOOP_RTT_MS,
                    )))
                };
                net.graph.record_edge(MeasurableEdge::Probe(telemetry));
            }
        }
    }
}

fn route(relays: &[&str]) -> Vec<String> {
    relays.iter().map(|name| name.to_string()).collect()
}

#[test]
fn relay_whose_loopbacks_never_return_should_be_starved_as_a_first_hop_for_one_to_three_hops() -> anyhow::Result<()> {
    let one_hop = (1, route(&["good"]), route(&["bad"]));
    let two_hops = (2, route(&["good", "m1"]), route(&["bad", "m1"]));
    let three_hops = (3, route(&["good", "m1", "m2"]), route(&["bad", "m1", "m2"]));

    for (hops, good, bad) in [one_hop, two_hops, three_hops] {
        let net = Net::from_json(TOPOLOGY)?;

        let before = net.forward("exit", hops).names();
        assert!(
            before.contains(&good) && before.contains(&bad),
            "{hops} hop(s): both relays must be routable before any loop is seen, got {before:?}"
        );

        probe_everything(&net);

        // Starved, not pruned (RFC-0010 4.2.3): still a candidate, with a negligible sampling share.
        let routes = net.forward("exit", hops);
        let good_value = routes
            .value_of(&good.iter().map(String::as_str).collect::<Vec<_>>())
            .ok_or_else(|| anyhow::anyhow!("{hops} hop(s): the relay whose loops return must stay routable"))?;
        let bad_value = routes
            .value_of(&bad.iter().map(String::as_str).collect::<Vec<_>>())
            .ok_or_else(|| anyhow::anyhow!("{hops} hop(s): a starved relay must stay a candidate"))?;

        assert!(bad_value > 0.0, "{hops} hop(s): a non-positive value prunes the edge");
        let share = bad_value / (bad_value + good_value);
        assert!(
            share < 1e-8,
            "{hops} hop(s): a relay whose loops never return must draw a negligible share, got {share}"
        );
    }
    Ok(())
}

#[test]
fn relay_whose_loopbacks_never_return_should_stay_probe_able() -> anyhow::Result<()> {
    // Rejected for routing is not rejected for probing: an edge that is never probed again can
    // never show it recovered (RFC-0010 4.2.3).
    let net = Net::from_json(TOPOLOGY)?;
    probe_everything(&net);

    let loops_through_bad = [2, 3]
        .into_iter()
        .flat_map(|hops| net.loopback(hops))
        .filter(|names| names.iter().any(|name| name == "bad"))
        .count();
    assert!(
        loops_through_bad > 0,
        "loops through the bad relay must still be generated"
    );
    Ok(())
}

#[test]
fn direct_route_should_ignore_loopback_evidence() -> anyhow::Result<()> {
    // Zero hops: the destination relays nothing for us, so loops that fail elsewhere say nothing
    // about it.
    let net = Net::from_json(TOPOLOGY)?;
    probe_everything(&net);

    assert_eq!(
        net.forward("exit", 0).names(),
        vec![Vec::<String>::new()],
        "a direct route must survive loopback evidence against other relays"
    );
    Ok(())
}

// ── A failing relay deeper in the path ───────────────────────────────────

/// Two candidates at each of three positions. Every `b` and `c` is a relay that pings and acks
/// identically, so which one is dead is visible only through the loops that pass it.
///
/// `me → a1|a2 → bg|bb → cg|cb → exit`, with every relay able to close a loop at `me`.
const LAYERED: &str = r#"{
  "me": "me",
  "ticket_face_value": 100,
  "edges": [
    { "from": "me",  "to": "a1",   "connected": true, "latency_ms": 20, "balance": 100000, "packets": 10, "acks": 10 },
    { "from": "me",  "to": "a2",   "connected": true, "latency_ms": 20, "balance": 100000, "packets": 10, "acks": 10 },
    { "from": "me",  "to": "exit", "connected": true, "latency_ms": 20, "balance": 100000, "packets": 10, "acks": 10 },
    { "from": "a1",  "to": "bg",   "connected": true, "latency_ms": 20, "balance": 100000 },
    { "from": "a1",  "to": "bb",   "connected": true, "latency_ms": 20, "balance": 100000 },
    { "from": "a2",  "to": "bg",   "connected": true, "latency_ms": 20, "balance": 100000 },
    { "from": "a2",  "to": "bb",   "connected": true, "latency_ms": 20, "balance": 100000 },
    { "from": "bg",  "to": "cg",   "connected": true, "latency_ms": 20, "balance": 100000 },
    { "from": "bg",  "to": "cb",   "connected": true, "latency_ms": 20, "balance": 100000 },
    { "from": "bb",  "to": "cg",   "connected": true, "latency_ms": 20, "balance": 100000 },
    { "from": "bb",  "to": "cb",   "connected": true, "latency_ms": 20, "balance": 100000 },
    { "from": "a1",  "to": "exit", "connected": true, "latency_ms": 20, "balance": 100000 },
    { "from": "a2",  "to": "exit", "connected": true, "latency_ms": 20, "balance": 100000 },
    { "from": "bg",  "to": "exit", "connected": true, "latency_ms": 20, "balance": 100000 },
    { "from": "bb",  "to": "exit", "connected": true, "latency_ms": 20, "balance": 100000 },
    { "from": "cg",  "to": "exit", "connected": true, "latency_ms": 20, "balance": 100000 },
    { "from": "cb",  "to": "exit", "connected": true, "latency_ms": 20, "balance": 100000 },
    { "from": "a1",  "to": "me",   "connected": true, "latency_ms": 20 },
    { "from": "a2",  "to": "me",   "connected": true, "latency_ms": 20 },
    { "from": "bg",  "to": "me",   "connected": true, "latency_ms": 20 },
    { "from": "bb",  "to": "me",   "connected": true, "latency_ms": 20 },
    { "from": "cg",  "to": "me",   "connected": true, "latency_ms": 20 },
    { "from": "cb",  "to": "me",   "connected": true, "latency_ms": 20 }
  ]
}"#;

/// The value of every route over `hops` relays, split by whether it passes the `dead` relay.
fn split_by(net: &Net, hops: usize, dead: &str) -> (Vec<f64>, Vec<f64>) {
    let routes = net.forward("exit", hops);
    let (through, around): (Vec<_>, Vec<_>) = routes
        .0
        .iter()
        .partition(|(relays, _)| relays.iter().any(|name| name == dead));
    (
        through.into_iter().map(|(_, value)| *value).collect(),
        around.into_iter().map(|(_, value)| *value).collect(),
    )
}

#[test]
fn relay_that_is_dead_beyond_the_first_hop_should_be_starved_for_two_and_three_hops() -> anyhow::Result<()> {
    // Position 2 is `bb` (second hop of a 2- or 3-hop route), position 3 is `cb` (third hop of a
    // 3-hop route). Both look healthy to every ping and ack.
    for (dead, hops) in [("bb", 2), ("bb", 3), ("cb", 3)] {
        let net = Net::from_json(LAYERED)?;

        let (through, around) = split_by(&net, hops, dead);
        assert!(
            !through.is_empty() && !around.is_empty(),
            "{dead}, {hops} hop(s): routes through and around the relay must both exist before any loop is seen"
        );

        probe_with_dead(&net, &[dead]);

        let (through, around) = split_by(&net, hops, dead);
        let best_around = around.iter().copied().fold(0.0, f64::max);
        assert!(
            best_around > 0.0,
            "{dead}, {hops} hop(s): honest routes must stay routable"
        );
        for value in through {
            assert!(
                value > 0.0,
                "{dead}, {hops} hop(s): a starved route must stay a candidate"
            );
            let share = value / (value + best_around);
            assert!(
                share < 1e-6,
                "{dead}, {hops} hop(s): a route through a dead relay must draw a negligible share, got {share}"
            );
        }
    }
    Ok(())
}

/// `LAYERED` with `bb` not a neighbour of `me`: it has no edge back, so it can never be the last
/// relay of a loop. Most relays two or three hops away are in this position.
fn layered_with_far_dead_relay() -> String {
    let without_return: Vec<&str> = LAYERED
        .lines()
        .filter(|line| !line.contains(r#""from": "bb",  "to": "me""#))
        .collect();
    assert_eq!(
        without_return.len() + 1,
        LAYERED.lines().count(),
        "exactly one line removed"
    );
    without_return.join("\n")
}

#[test]
fn dead_relay_that_is_not_my_neighbour_should_be_starved_for_two_and_three_hops() -> anyhow::Result<()> {
    // `bb` is only ever a middle relay of a loop, so no outcome is attributed to the edge into it
    // unless every edge of the loop is credited.
    for hops in [2, 3] {
        let net = Net::from_json(&layered_with_far_dead_relay())?;

        let (through, around) = split_by(&net, hops, "bb");
        assert!(
            !through.is_empty() && !around.is_empty(),
            "{hops} hop(s): routes through and around bb must both exist before any loop is seen"
        );

        probe_with_dead(&net, &["bb"]);

        let (through, around) = split_by(&net, hops, "bb");
        let best_around = around.iter().copied().fold(0.0, f64::max);
        assert!(best_around > 0.0, "{hops} hop(s): honest routes must stay routable");
        for value in through {
            assert!(value > 0.0, "{hops} hop(s): a starved route must stay a candidate");
            let share = value / (value + best_around);
            assert!(
                share < 1e-6,
                "{hops} hop(s): a route through a dead non-neighbour relay must draw a negligible share, got {share}"
            );
        }
    }
    Ok(())
}

// ── Return paths ─────────────────────────────────────────────────────────

#[test]
fn return_path_through_a_dead_relay_should_be_starved() -> anyhow::Result<()> {
    // `a1 → X → me` lies on the loopback cycle `me → a1 → X → me`, so loops that never return
    // judge `X` on a return path as they do on a forward one.
    let net = Net::from_json(LAYERED)?;

    let before = net.returning("a1", 1);
    assert!(
        before.value_of(&["bb"]).is_some() && before.value_of(&["bg"]).is_some(),
        "both relays must be routable back before any loop is seen"
    );

    probe_with_dead(&net, &["bb"]);

    let after = net.returning("a1", 1);
    let honest = after
        .value_of(&["bg"])
        .ok_or_else(|| anyhow::anyhow!("the honest relay must stay routable back"))?;
    let dead = after
        .value_of(&["bb"])
        .ok_or_else(|| anyhow::anyhow!("a starved relay must stay a candidate"))?;

    assert!(dead > 0.0, "a non-positive value prunes the edge");
    let share = dead / (dead + honest);
    assert!(
        share < 1e-6,
        "a return path through a dead relay must draw a negligible share, got {share}"
    );
    Ok(())
}

// ── Probes and traffic as two witnesses ──────────────────────────────────

#[test]
fn probes_that_failed_should_not_starve_a_relay_whose_traffic_went_through() -> anyhow::Result<()> {
    // Probes are sparse and fail on any hop of their loop. SURBs that came back over the same edge
    // prove the relay works, so the failed probes do not outweigh them.
    let net = Net::from_json(TOPOLOGY)?;
    probe_everything(&net);
    net.observe("me", "bad", |obs| {
        obs.record(EdgeWeightType::SurbRoundTrips {
            expected: 100,
            observed: 100,
        });
    });

    let routes = net.forward("exit", 1);
    let bad = routes
        .value_of(&["bad"])
        .ok_or_else(|| anyhow::anyhow!("bad must stay routable"))?;
    let good = routes
        .value_of(&["good"])
        .ok_or_else(|| anyhow::anyhow!("good must stay routable"))?;
    assert!(
        bad / (bad + good) > 0.2,
        "traffic that came back must keep the relay at a real share, got {bad} against {good}"
    );
    Ok(())
}

#[test]
fn a_middle_relay_whose_probes_failed_but_whose_traffic_came_back_should_not_be_starved() -> anyhow::Result<()> {
    // `a1 → bb` is a middle edge of a 2-hop route, and every loop through `bb` timed out. SURBs
    // came back over it, so the edge works and its score must not be floored.
    let net = Net::from_json(LAYERED)?;
    probe_with_dead(&net, &["bb"]);
    net.observe("a1", "bb", |obs| {
        obs.record(EdgeWeightType::SurbRoundTrips {
            expected: 100,
            observed: 100,
        });
    });

    let routes = net.forward("exit", 2);
    let kept = routes
        .value_of(&["a1", "bb"])
        .ok_or_else(|| anyhow::anyhow!("a1 → bb must stay routable"))?;
    let honest = routes
        .value_of(&["a1", "bg"])
        .ok_or_else(|| anyhow::anyhow!("a1 → bg must stay routable"))?;
    assert!(
        kept / (kept + honest) > 0.2,
        "traffic that came back must keep the middle relay at a real share, got {kept} against {honest}"
    );
    Ok(())
}

#[test]
fn a_return_path_through_a_relay_whose_probes_failed_but_whose_traffic_came_back_should_not_be_starved()
-> anyhow::Result<()> {
    let net = Net::from_json(LAYERED)?;
    probe_with_dead(&net, &["bb"]);
    net.observe("a1", "bb", |obs| {
        obs.record(EdgeWeightType::SurbRoundTrips {
            expected: 100,
            observed: 100,
        });
    });

    let routes = net.returning("a1", 1);
    let kept = routes
        .value_of(&["bb"])
        .ok_or_else(|| anyhow::anyhow!("a1 → bb → me must stay routable"))?;
    let honest = routes
        .value_of(&["bg"])
        .ok_or_else(|| anyhow::anyhow!("a1 → bg → me must stay routable"))?;
    assert!(
        kept / (kept + honest) > 0.2,
        "traffic that came back must keep the return relay at a real share, got {kept} against {honest}"
    );
    Ok(())
}

// ── Every position, both directions ──────────────────────────────────────

/// Three layers of two relays, each layer connected to the next and to the one before it, every relay
/// connected to `me` and `exit` both ways, plus the direct route. Each edge pings and is funded. Loops
/// (`me → a → b [→ c] → me`) exist for both loop shapes, and a path of 1 to 3 relays exists in both
/// directions with the relay of any layer in any position.
///
/// Every edge but those into `dead` has carried a loop before, so the dead relay reads dead only on the
/// edges into it, as a relay whose other edges still show healthy evidence does. A relay failing on every
/// edge would be starved by the node health the graph derives, with no help from the edge itself.
fn layered_both_ways(dead: &str) -> String {
    let edge = |from: &str, to: &str| {
        let counted = if from == "me" || to == "me" {
            r#", "packets": 10, "acks": 10"#
        } else {
            ""
        };
        let carried = if to == dead { "" } else { r#", "relayed_ms": 30"# };
        format!(
            r#"{{ "from": "{from}", "to": "{to}", "connected": true, "latency_ms": 20, "balance": 100000{counted}{carried} }}"#
        )
    };
    let relay = |layer: usize, dead: bool| format!("{}{layer}", if dead { "d" } else { "g" });
    let mut edges = vec![edge("me", "exit"), edge("exit", "me")];
    for layer in 1..=3 {
        for dead in [false, true] {
            let name = relay(layer, dead);
            edges.extend([
                edge("me", &name),
                edge(&name, "me"),
                edge(&name, "exit"),
                edge("exit", &name),
            ]);
            if layer < 3 {
                for next in [false, true] {
                    edges.push(edge(&name, &relay(layer + 1, next)));
                    edges.push(edge(&relay(layer + 1, next), &name));
                }
            }
        }
    }
    format!(
        r#"{{ "me": "me", "ticket_face_value": 100, "edges": [{}] }}"#,
        edges.join(",\n")
    )
}

/// The share of the best route through `dead` against the best route around it, or `None` without a
/// route through it.
fn share_of(routes: &common::Routes, dead: &str) -> Option<f64> {
    let best = |through: bool| {
        routes
            .0
            .iter()
            .filter(|(names, _)| names.iter().any(|name| name == dead) == through)
            .map(|(_, value)| *value)
            .fold(None, |best: Option<f64>, value| {
                Some(best.map_or(value, |b| b.max(value)))
            })
    };
    let (through, around) = (best(true)?, best(false)?);
    Some(through / (through + around))
}

#[test]
fn a_dead_relay_should_be_starved_at_every_position_for_zero_to_three_hops_in_both_directions() -> anyhow::Result<()> {
    let mut failures = Vec::new();
    let mut judged = 0;

    for layer in 1..=3 {
        let dead = format!("d{layer}");
        let net = Net::from_json(&layered_both_ways(&dead))?;
        let direct = (
            net.forward("exit", 0).value_of(&[]),
            net.returning("exit", 0).value_of(&[]),
        );
        assert!(
            direct.0.is_some() && direct.1.is_some(),
            "the direct route must exist in both directions"
        );
        for hops in 1..=3 {
            for (direction, routes) in [
                ("forward", net.forward("exit", hops)),
                ("return", net.returning("exit", hops)),
            ] {
                assert!(
                    share_of(&routes, &dead).is_some_and(|share| share > 0.1),
                    "{direction}, {hops} hop(s): before any loop is seen the relay must draw a real share"
                );
            }
        }

        probe_with_dead(&net, &[dead.as_str()]);

        for hops in 1..=3 {
            for (direction, routes) in [
                ("forward", net.forward("exit", hops)),
                ("return", net.returning("exit", hops)),
            ] {
                let Some(share) = share_of(&routes, &dead) else {
                    failures.push(format!(
                        "{direction}, {hops} hop(s), layer {layer}: the dead relay vanished from the routes"
                    ));
                    continue;
                };
                judged += 1;
                if share >= 1e-6 {
                    failures.push(format!(
                        "{direction}, {hops} hop(s), dead relay in layer {layer}: share {share}"
                    ));
                }
            }
        }
        // 0 hops has no relay to judge: a dead relay elsewhere may blame the direct edge for loops it
        // crossed, which dilutes it a little, but never starves it.
        let after = (
            net.forward("exit", 0).value_of(&[]),
            net.returning("exit", 0).value_of(&[]),
        );
        if after.0.is_none_or(|value| value < 0.1) || after.1.is_none_or(|value| value < 0.1) {
            failures.push(format!(
                "0 hops, dead relay in layer {layer}: direct routes starved, {direct:?} became {after:?}"
            ));
        }
    }

    assert!(
        judged == 18,
        "every direction, hop count and layer must be judged, got {judged}"
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    Ok(())
}

// ── Evidence on the edge into the destination (hopr-impls#81) ────────────

/// `TOPOLOGY` with SURB round trips on the edge from each relay into the exit.
fn with_surbs_into_exit(good: [u64; 2], bad: [u64; 2]) -> String {
    let mut marked = 0;
    let lines: Vec<String> = TOPOLOGY
        .lines()
        .map(|line| {
            let surbs = [("good", good), ("bad", bad)]
                .into_iter()
                .find(|(relay, _)| line.contains(&format!(r#""from": "{relay}""#)) && line.contains(r#""to": "exit""#));
            match surbs {
                Some((_, [expected, observed])) => {
                    marked += 1;
                    line.replace(" }", &format!(r#", "surbs": [{expected}, {observed}] }}"#))
                }
                None => line.to_string(),
            }
        })
        .collect();
    assert_eq!(marked, 2, "both edges into the exit must carry SURBs");
    lines.join("\n")
}

#[test]
fn a_relay_whose_surbs_into_the_exit_never_return_should_be_starved() -> anyhow::Result<()> {
    // Ten SURBs minted over the edge, none came back, while the other relay returns all of them.
    let net = Net::from_json(&with_surbs_into_exit([10, 10], [10, 0]))?;

    let routes = net.forward("exit", 1);
    let share = share_of(&routes, "bad").ok_or_else(|| anyhow::anyhow!("a starved relay must stay a candidate"))?;

    assert!(
        share < 1e-6,
        "a relay none of whose SURBs return must draw a negligible share, got {share}"
    );
    Ok(())
}

#[test]
fn a_relay_whose_surbs_into_the_exit_never_return_should_be_starved_for_one_to_three_hops() -> anyhow::Result<()> {
    for hops in 1..=3usize {
        let dead = format!("d{hops}");
        // No edge here has a failed loop: only the SURBs over the edge from `dead` into the exit
        // never come back, as for a relay that forwards but drops what is addressed to the exit.
        let topology: String = layered_both_ways("none")
            .lines()
            .map(|line| {
                let into_exit = line.contains(r#""to": "exit""#)
                    && !line.contains(r#""from": "me""#)
                    && !line.contains(r#""from": "exit""#);
                if !into_exit {
                    return line.to_string();
                }
                let observed = if line.contains(&format!(r#""from": "{dead}""#)) {
                    0
                } else {
                    10
                };
                line.replace(" }", &format!(r#", "surbs": [10, {observed}] }}"#))
            })
            .collect::<Vec<_>>()
            .join("\n");
        let net = Net::from_json(&topology)?;

        // Routes that end in `dead`, against the best route that does not: `dead` also sits earlier on
        // other routes, over edges that are healthy.
        let routes = net.forward("exit", hops);
        let best = |ends_in_dead: bool| {
            routes
                .0
                .iter()
                .filter(|(names, _)| (names.last() == Some(&dead)) == ends_in_dead)
                .map(|(_, value)| *value)
                .fold(None, |best: Option<f64>, value| {
                    Some(best.map_or(value, |b| b.max(value)))
                })
        };
        let (through, around) = best(true)
            .zip(best(false))
            .ok_or_else(|| anyhow::anyhow!("{hops} hop(s): a starved relay must stay a candidate"))?;
        let share = through / (through + around);

        assert!(
            share < 1e-6,
            "{hops} hop(s): a relay whose SURBs into the exit never return must draw a negligible share, got {share}"
        );
    }
    Ok(())
}
