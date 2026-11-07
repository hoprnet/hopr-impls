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
    for loop_hops in [2, 3] {
        let names = net.loopback(loop_hops);
        let slots = net.loopback_slots(loop_hops);
        assert!(!names.is_empty(), "the topology must offer {loop_hops}-hop loops");

        for (names, slots) in names.iter().zip(slots) {
            let through_bad = names.iter().any(|name| name == "bad");
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
    assert!(loops_through_bad > 0, "loops through the bad relay must still be generated");
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
