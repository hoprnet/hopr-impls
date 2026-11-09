//! A failed SURB round trip blames every edge on its loop, healthy ones included. When the forward
//! relay is dead, every round trip fails whatever relay the reply takes home, so the healthy relay's
//! return edges read as dead too and routing has no path left. Reproduces the empty routes seen in
//! the `dead-last-hop` integration scenario.

mod common;

use common::Net;
use hopr_api::{
    OffchainPublicKey,
    graph::{
        EdgeTransportTelemetry, ForwardAndReturnPath, MeasurableEdge, MeasurablePath, MeasurablePeer,
        NetworkGraphError, NetworkGraphUpdate, SurbTelemetry,
    },
};

/// `me`, three relays and an exit, fully meshed and funded. `bad1` and `bad2` lose their link to the
/// exit (see `cut`), `good` does not.
fn topology() -> String {
    let names = ["good", "bad1", "bad2"];
    let edge = |from: &str, to: &str| {
        let counted = if from == "me" || to == "me" {
            r#", "packets": 10, "acks": 10"#
        } else {
            ""
        };
        format!(
            r#"{{ "from": "{from}", "to": "{to}", "connected": true, "latency_ms": 20, "balance": 100000{counted} }}"#
        )
    };
    let mut edges = vec![edge("me", "exit"), edge("exit", "me")];
    for a in names {
        edges.extend([edge("me", a), edge(a, "me"), edge(a, "exit"), edge("exit", a)]);
        for b in names {
            if a != b {
                edges.push(edge(a, b));
            }
        }
    }
    format!(
        r#"{{ "me": "me", "ticket_face_value": 100, "edges": [{}] }}"#,
        edges.join(",\n")
    )
}

/// Whether the link between two nodes is cut: a relay with no way to reach the exit.
fn cut(a: &str, b: &str) -> bool {
    (a.starts_with("bad") && b == "exit") || (b.starts_with("bad") && a == "exit")
}

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

/// Every loop that crosses a cut link times out and every other loop returns, over both loop shapes.
fn probe(net: &Net) {
    for loop_hops in [2, 3] {
        let names = net.loopback(loop_hops);
        let slots = net.loopback_slots(loop_hops);
        for (names, slots) in names.iter().zip(slots) {
            let mut walk = vec!["me".to_string()];
            walk.extend(names.iter().cloned());
            walk.push("me".to_string());
            let crosses_cut = walk.windows(2).any(|pair| cut(&pair[0], &pair[1]));
            for _ in 0..6 {
                let telemetry = if crosses_cut {
                    Err(NetworkGraphError::ProbeLoopbackTimeout(the_loop(slots, 0)))
                } else {
                    Ok(EdgeTransportTelemetry::<Neighbor, Loop>::Loopback(the_loop(
                        slots,
                        now_ms() - 40,
                    )))
                };
                net.graph.record_edge(MeasurableEdge::Probe(telemetry));
            }
        }
    }
}

/// `expected` SURBs over `me -> forward -> exit` that return over `exit -> reply -> me`, of which
/// `observed` came back.
fn round_trips(net: &Net, forward: &str, reply: &str, expected: u64, observed: u64) {
    let slot = |name: &str| net.slot(name).expect("node has a slot");
    net.graph
        .record_edge::<Neighbor, Loop>(MeasurableEdge::Surb(SurbTelemetry {
            paths: ForwardAndReturnPath {
                forward: [slot("me"), slot(forward), slot("exit"), 0, 0],
                reply: [slot("exit"), slot(reply), slot("me"), 0, 0],
            },
            timestamp: now_ms(),
            expected,
            observed,
        }));
}

fn routable(net: &Net, direction: &str, relay: &str) -> bool {
    let routes = match direction {
        "forward" => net.forward("exit", 1),
        _ => net.returning("exit", 1),
    };
    routes.value_of(&[relay]).is_some_and(|value| value > 0.0)
}

#[test]
fn a_dead_forward_relay_should_not_make_the_healthy_relay_unroutable_on_the_way_home() -> anyhow::Result<()> {
    let net = Net::from_json(&topology())?;
    probe(&net);

    // The session's forward relay is `bad1`, so every round trip fails whichever relay the reply takes.
    for reply in ["good", "bad1", "bad2"] {
        round_trips(&net, "bad1", reply, 10, 0);
    }

    assert!(
        routable(&net, "forward", "good"),
        "the healthy relay must stay routable forward, got {:?}",
        net.forward("exit", 1).names()
    );
    assert!(
        routable(&net, "return", "good"),
        "the healthy relay must stay routable on the way home, got {:?}",
        net.returning("exit", 1).names()
    );
    for dead in ["bad1", "bad2"] {
        assert!(!routable(&net, "forward", dead), "{dead} must not be routable forward");
        assert!(
            !routable(&net, "return", dead),
            "{dead} must not be routable on the way home"
        );
    }
    Ok(())
}

#[test]
fn a_session_over_every_relay_pair_should_leave_only_the_healthy_relay_routable() -> anyhow::Result<()> {
    // Control: when every forward and reply combination has been tried, only (good, good) delivers.
    let net = Net::from_json(&topology())?;
    probe(&net);
    for forward in ["good", "bad1", "bad2"] {
        for reply in ["good", "bad1", "bad2"] {
            let delivers = forward == "good" && reply == "good";
            round_trips(&net, forward, reply, 10, if delivers { 10 } else { 0 });
        }
    }

    for direction in ["forward", "return"] {
        assert!(
            routable(&net, direction, "good"),
            "{direction}: the healthy relay must stay routable"
        );
        for dead in ["bad1", "bad2"] {
            assert!(
                !routable(&net, direction, dead),
                "{direction}: {dead} must not be routable"
            );
        }
    }
    Ok(())
}
