//! Loopback probing focused on chosen exits.
//!
//! An exit is the final hop of a data path, so it needs no channel and may have no edge back to `me`.
//! Focus builds a subgraph around the exits and ranks the loops in it:
//!
//! - **Forward**: the loop's leading relays form a path to an exit, i.e. some relay has an edge into the exit. The
//!   edges `me → … → relay` are the ones a session towards the exit would use.
//! - **Return**: the loop touches an edge of a return path from the exit back to `me` (at most 3 relays). The edges
//!   measured are components of the path a reply would take.
//!
//! A loop that is both ranks as forward. Everything outside the neighborhood of those paths is ignored.

mod common;

use FocusRelevance::{Forward, Return};
use common::Net;
use hopr_api::graph::traits::{EdgeObservableWrite, EdgeWeightType};
use hopr_network_graph::{FocusRelevance, MAX_LOOPBACK_HOPS};

/// Builds a network from `(from, to)` edges. Every edge is connected, channelled and measured, so that only
/// the topology decides which loops exist.
fn net(edges: &[(&str, &str)], nodes: &[&str]) -> anyhow::Result<Net> {
    let edges: Vec<String> = edges
        .iter()
        .map(|(from, to)| {
            format!(
                r#"{{ "from": "{from}", "to": "{to}", "connected": true, "latency_ms": 20, "balance": 100000, "relayed_ms": 30 }}"#
            )
        })
        .collect();
    let nodes: Vec<String> = nodes.iter().map(|n| format!(r#""{n}""#)).collect();
    Net::from_json(&format!(
        r#"{{ "me": "me", "ticket_face_value": 100, "nodes": [{}], "edges": [{}] }}"#,
        nodes.join(","),
        edges.join(",")
    ))
}

fn loops(names: &[&[&str]], relevance: FocusRelevance) -> Vec<(Vec<String>, FocusRelevance)> {
    let mut out: Vec<_> = names
        .iter()
        .map(|path| (path.iter().map(|n| n.to_string()).collect(), relevance))
        .collect();
    out.sort();
    out
}

// ── Forward: leading relays form a path to the exit ──────────────────────

#[test]
fn a_loop_whose_first_relay_leads_to_the_exit_should_rank_forward() -> anyhow::Result<()> {
    // me→a→x→me. `a→f` makes `me→a` a one-relay path towards f; x only closes the loop.
    let net = net(
        &[
            ("me", "a"),
            ("a", "x"),
            ("x", "me"),
            ("a", "f"),
            ("me", "c"),
            ("c", "z"),
            ("z", "me"),
        ],
        &[],
    )?;

    assert_eq!(
        net.focused(2, &["f"]),
        loops(&[&["a", "x", "me"]], Forward),
        "the unrelated loop me→c→z→me must not be probed"
    );
    Ok(())
}

#[test]
fn a_two_relay_loop_should_rank_forward_when_its_last_relay_leads_to_the_exit() -> anyhow::Result<()> {
    // me→a→b→me, with `b→f`: the whole loop is a two-relay forward path me→a→b→f.
    let net = net(&[("me", "a"), ("a", "b"), ("b", "me"), ("b", "f")], &[])?;

    assert_eq!(net.focused(2, &["f"]), loops(&[&["a", "b", "me"]], Forward));
    Ok(())
}

#[test]
fn a_three_relay_loop_should_rank_forward_on_a_one_relay_prefix() -> anyhow::Result<()> {
    // me→a→b→x→me, with `a→f`. b and x lie two steps from the exit and are still in the neighborhood.
    let net = net(&[("me", "a"), ("a", "b"), ("b", "x"), ("x", "me"), ("a", "f")], &[])?;

    assert_eq!(net.focused(3, &["f"]), loops(&[&["a", "b", "x", "me"]], Forward));
    Ok(())
}

#[test]
fn the_exit_may_close_the_loop_itself_when_it_has_a_closing_edge() -> anyhow::Result<()> {
    let net = net(&[("me", "a"), ("a", "f"), ("f", "me")], &[])?;

    assert_eq!(
        net.focused(2, &["f"]),
        loops(&[&["a", "f", "me"]], Forward),
        "me→a→f→me measures the whole forward path me→a→f"
    );
    Ok(())
}

// ── Return: loops that measure a path back from the exit ─────────────────

#[test]
fn a_loop_that_starts_at_the_exit_should_rank_return() -> anyhow::Result<()> {
    // me→f→y→me measures f→y and y→me, the first two edges of the way back from f.
    let net = net(&[("me", "f"), ("f", "y"), ("y", "me")], &[])?;

    assert_eq!(net.focused(2, &["f"]), loops(&[&["f", "y", "me"]], Return));
    Ok(())
}

#[test]
fn a_three_relay_loop_from_the_exit_should_measure_two_return_hops() -> anyhow::Result<()> {
    let net = net(&[("me", "f"), ("f", "y"), ("y", "z"), ("z", "me")], &[])?;

    assert_eq!(net.focused(3, &["f"]), loops(&[&["f", "y", "z", "me"]], Return));
    assert!(net.focused(2, &["f"]).is_empty(), "no two-relay loop exists");
    Ok(())
}

#[test]
fn a_loop_over_a_component_of_a_return_path_should_rank_return() -> anyhow::Result<()> {
    // The exit has no edge from me. y→me is the last hop of the way back f→y→me, and me→c→y→me measures it.
    let net = net(
        &[
            ("f", "y"),
            ("y", "me"),
            ("me", "c"),
            ("c", "y"),
            ("me", "d"),
            ("d", "z"),
            ("z", "me"),
        ],
        &[],
    )?;

    assert_eq!(
        net.focused(2, &["f"]),
        loops(&[&["c", "y", "me"]], Return),
        "me→d→z→me touches no return path of f"
    );
    Ok(())
}

#[test]
fn return_paths_should_reach_at_most_three_relays_from_the_exit() -> anyhow::Result<()> {
    // s3→me closes a three-relay way back; t4→me would close a four-relay one, which no reply can use.
    let net = net(
        &[
            ("f", "s1"),
            ("s1", "s2"),
            ("s2", "s3"),
            ("s3", "me"),
            ("f", "t1"),
            ("t1", "t2"),
            ("t2", "t3"),
            ("t3", "t4"),
            ("t4", "me"),
            ("me", "c"),
            ("c", "s3"),
            ("c", "t4"),
        ],
        &[],
    )?;

    assert_eq!(net.focused(2, &["f"]), loops(&[&["c", "s3", "me"]], Return));
    Ok(())
}

// ── Ranking ──────────────────────────────────────────────────────────────

#[test]
fn a_loop_that_is_both_forward_and_return_should_rank_forward() -> anyhow::Result<()> {
    // me→a→b→me: `a→f` makes me→a a forward path, and f→a→b→me is a return path the loop covers.
    let net = net(&[("me", "a"), ("a", "b"), ("b", "me"), ("a", "f"), ("f", "a")], &[])?;

    assert_eq!(net.focused(2, &["f"]), loops(&[&["a", "b", "me"]], Forward));
    Ok(())
}

#[test]
fn forward_should_outrank_return() {
    assert!(
        Forward > Return,
        "forward loops carry the full boost, return loops half of it"
    );
}

#[test]
fn a_mixed_network_should_yield_each_loop_once_with_its_own_rank() -> anyhow::Result<()> {
    let net = net(
        &[
            ("me", "a"),
            ("a", "x"),
            ("x", "me"),
            ("a", "f"),
            ("me", "f"),
            ("f", "y"),
            ("y", "me"),
            ("me", "c"),
            ("c", "z"),
            ("z", "me"),
        ],
        &[],
    )?;

    let found = net.focused(2, &["f"]);
    let mut expected = loops(&[&["a", "x", "me"]], Forward);
    expected.extend(loops(&[&["f", "y", "me"]], Return));
    expected.sort();

    assert_eq!(found, expected);
    Ok(())
}

// ── Several exits ────────────────────────────────────────────────────────

#[test]
fn every_exit_of_the_focus_group_should_be_probed() -> anyhow::Result<()> {
    let net = net(
        &[
            ("me", "a"),
            ("a", "x"),
            ("x", "me"),
            ("a", "f1"),
            ("me", "b"),
            ("b", "w"),
            ("w", "me"),
            ("b", "f2"),
        ],
        &[],
    )?;

    assert_eq!(
        net.focused(2, &["f1", "f2"]),
        loops(&[&["a", "x", "me"], &["b", "w", "me"]], Forward)
    );
    assert_eq!(
        net.focused(2, &["f1"]),
        loops(&[&["a", "x", "me"]], Forward),
        "a smaller group drops the loops that only served the other exit"
    );
    Ok(())
}

// ── Subgraph bound ───────────────────────────────────────────────────────

#[test]
fn unrelated_loops_should_not_crowd_the_focused_ones_out_of_a_bounded_search() -> anyhow::Result<()> {
    let mut edges: Vec<(String, String)> = [("me", "a"), ("a", "x"), ("x", "me"), ("a", "f")]
        .into_iter()
        .map(|(from, to)| (from.to_string(), to.to_string()))
        .collect();
    for i in 0..200 {
        edges.push(("me".to_string(), format!("c{i}")));
        edges.push((format!("c{i}"), format!("z{i}")));
        edges.push((format!("z{i}"), "me".to_string()));
    }
    let refs: Vec<(&str, &str)> = edges.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
    let net = net(&refs, &[])?;

    let found = net.focused_with(2, Some(5), &["f"]);

    assert_eq!(
        found.into_iter().map(|(p, _, r)| (p, r)).collect::<Vec<_>>(),
        loops(&[&["a", "x", "me"]], Forward),
        "a search bounded to 5 paths must spend them inside the focus subgraph"
    );
    Ok(())
}

#[test]
fn unrelated_loops_inside_the_neighborhood_should_not_crowd_the_focused_ones_out_of_a_bounded_search()
-> anyhow::Result<()> {
    // `a→p{i}` puts every `p{i}` within the focus radius of the path relay `a`, so the loops `me→p{i}→q{i}→me`
    // are in the searched subgraph. None of them leads to the exit or touches a return path. The search lists up to
    // ten times the bound, so 40 loops fit under the 50 it enumerates.
    let mut edges: Vec<(String, String)> = [("me", "a"), ("a", "x"), ("x", "me"), ("a", "f")]
        .into_iter()
        .map(|(from, to)| (from.to_string(), to.to_string()))
        .collect();
    for i in 0..40 {
        edges.push(("a".to_string(), format!("p{i}")));
        edges.push(("me".to_string(), format!("p{i}")));
        edges.push((format!("p{i}"), format!("q{i}")));
        edges.push((format!("q{i}"), "me".to_string()));
    }
    let refs: Vec<(&str, &str)> = edges.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
    let net = net(&refs, &[])?;

    let found = net.focused_with(2, Some(5), &["f"]);

    assert!(
        found.iter().any(|(p, _, r)| *r == Forward && p == &["a", "x", "me"]),
        "a search bounded to 5 loops must still return the forward loop, got {found:?}"
    );
    assert!(
        found.len() <= 5,
        "the result must stay within the bound, got {}",
        found.len()
    );
    Ok(())
}

// ── Nothing to focus on ──────────────────────────────────────────────────

#[test]
fn an_exit_the_graph_does_not_know_should_yield_nothing() -> anyhow::Result<()> {
    let net = net(&[("me", "a"), ("a", "x"), ("x", "me")], &["f"])?;

    assert!(net.focused(2, &["f"]).is_empty(), "f is known but connected to nothing");
    Ok(())
}

#[test]
fn an_empty_focus_group_or_me_alone_should_yield_nothing() -> anyhow::Result<()> {
    let net = net(&[("me", "a"), ("a", "x"), ("x", "me"), ("a", "f")], &[])?;

    assert!(net.focused(2, &[]).is_empty());
    assert!(net.focused(2, &["me"]).is_empty(), "me is never an exit");
    Ok(())
}

#[test]
fn hop_counts_outside_the_permitted_range_should_yield_nothing() -> anyhow::Result<()> {
    let net = net(&[("me", "a"), ("a", "x"), ("x", "me"), ("a", "f")], &[])?;

    for hops in [0, 1, MAX_LOOPBACK_HOPS + 1] {
        assert!(net.focused(hops, &["f"]).is_empty(), "{hops} relays is out of range");
    }
    Ok(())
}

// ── Loop validity ────────────────────────────────────────────────────────

#[test]
fn a_closing_edge_observed_down_should_exclude_the_loop() -> anyhow::Result<()> {
    let net = net(&[("me", "a"), ("a", "x"), ("x", "me"), ("a", "f")], &[])?;
    net.observe("x", "me", |obs| {
        obs.record(EdgeWeightType::Connected(false));
    });

    assert!(
        net.focused(2, &["f"]).is_empty(),
        "x can no longer close the loop, as for default loopbacks"
    );
    Ok(())
}

#[test]
fn a_loop_should_never_pass_through_me_or_repeat_a_relay() -> anyhow::Result<()> {
    let net = net(
        &[
            ("me", "a"),
            ("a", "b"),
            ("b", "a"),
            ("b", "me"),
            ("a", "me"),
            ("a", "f"),
            ("b", "f"),
        ],
        &[],
    )?;

    for hops in [2, 3] {
        for (path, _) in net.focused(hops, &["f"]) {
            let relays = &path[..path.len() - 1];
            assert_eq!(path.last().map(String::as_str), Some("me"), "{path:?} closes at me");
            assert!(!relays.contains(&"me".to_string()), "{path:?} passes through me");
            let unique: std::collections::HashSet<_> = relays.iter().collect();
            assert_eq!(unique.len(), relays.len(), "{path:?} repeats a relay");
        }
    }
    Ok(())
}

#[test]
fn focused_loops_should_carry_path_ids_that_close_at_me() -> anyhow::Result<()> {
    let net = net(&[("me", "f"), ("f", "y"), ("y", "me")], &[])?;
    let (me, f, y) = (net.slot("me"), net.slot("f"), net.slot("y"));

    let found = net.focused_with(2, None, &["f"]);

    assert_eq!(found.len(), 1);
    assert_eq!(
        Some(found[0].1),
        me.zip(f).zip(y).map(|((me, f), y)| [me, f, y, me, 0]),
        "slots read me, f, y, the closing me, then padding"
    );
    Ok(())
}

#[cfg(feature = "serde")]
#[test]
fn focused_probing_preserves_search_diagnostics_after_ranking() -> anyhow::Result<()> {
    use anyhow::Context;

    let net = net(&[("me", "a"), ("a", "b"), ("b", "me"), ("b", "f")], &[])?;
    assert_eq!(net.focused(2, &["f"]), loops(&[&["a", "b", "me"]], Forward));

    let dump = serde_json::to_value(net.graph.state(None)?)?;
    let sample = dump["searches"]["samples"]
        .as_array()
        .context("search samples")?
        .iter()
        .find(|sample| sample["kind"] == "focused_loopback")
        .context("focused probing must retain a diagnostic search record")?;
    assert_eq!(sample["direction"], "loopback");
    assert_eq!(sample["outcome"], "completed");
    assert_eq!(sample["returned"], 1);
    assert!(sample["returned_path"].is_array());
    Ok(())
}
