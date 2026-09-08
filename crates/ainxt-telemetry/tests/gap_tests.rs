// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Gap-closure test for the transport-daemon telemetry cost-attribution rollup (gap V:
//! FinOps chargeback / cost anomaly). Written to FAIL before `CostRollup`/`InMemoryTelemetry::
//! rollup` existed and PASS after. Integer money throughout (no float drift in a cost ledger).

use ainxt_telemetry::{CostRollup, InMemoryTelemetry, TelemetrySink, TurnMetrics, TurnOutcome};
use ainxt_types::DataClass;

fn turn(
    actor: &str,
    provider: &str,
    inp: u64,
    out: u64,
    cost: u64,
    outcome: TurnOutcome,
) -> TurnMetrics {
    TurnMetrics {
        session: "s".into(),
        turn: "t".into(),
        actor: actor.into(),
        provider: provider.into(),
        data_class: DataClass::Public,
        input_tokens: inp,
        output_tokens: out,
        cost_micros: cost,
        latency_ms: 10,
        redactions: 0,
        tool_calls: 0,
        outcome,
    }
}

#[test]
fn gap_ainxt_telemetry_cost_rollup_by_actor_and_provider() {
    let mem = InMemoryTelemetry::new();
    mem.record_turn(&turn(
        "alice",
        "cloud",
        1000,
        500,
        10_500,
        TurnOutcome::Completed,
    ));
    mem.record_turn(&turn("alice", "local", 2000, 0, 0, TurnOutcome::Completed));
    mem.record_turn(&turn(
        "bob",
        "cloud",
        500,
        200,
        5_000,
        TurnOutcome::GuardrailsBlocked,
    ));
    mem.record_turn(&turn("bob", "cloud", 100, 0, 0, TurnOutcome::Cancelled));

    let r = mem.rollup();

    // Grand totals (integer-exact).
    assert_eq!(r.total.turns, 4);
    assert_eq!(r.total.input_tokens, 3600);
    assert_eq!(r.total.output_tokens, 700);
    assert_eq!(r.total.cost_micros, 15_500);
    assert_eq!(r.total.completed, 2);
    assert_eq!(r.total.not_completed, 2);

    // Per-actor chargeback.
    let alice = r.actor("alice");
    assert_eq!(alice.turns, 2);
    assert_eq!(alice.cost_micros, 10_500);
    assert_eq!(alice.input_tokens, 3000);
    assert_eq!(alice.completed, 2);
    assert_eq!(alice.not_completed, 0);

    let bob = r.actor("bob");
    assert_eq!(bob.turns, 2);
    assert_eq!(bob.cost_micros, 5_000);
    assert_eq!(
        bob.not_completed, 2,
        "blocked + cancelled both count as not-completed"
    );

    // An actor with no turns → zero bucket, never a panic.
    assert_eq!(r.actor("nobody").turns, 0);
    assert_eq!(r.actor("nobody").cost_micros, 0);

    // Per-provider FinOps.
    assert_eq!(r.provider("cloud").cost_micros, 15_500);
    assert_eq!(r.provider("cloud").turns, 3);
    assert_eq!(r.provider("local").cost_micros, 0);

    // Deterministic "top spenders" ordering: alice (10_500) before bob (5_000).
    let ranked = r.actors_by_cost();
    assert_eq!(ranked[0].0, "alice");
    assert_eq!(ranked[1].0, "bob");

    // Rollup of an empty set is all-zero, not a panic.
    assert_eq!(CostRollup::from_turns(&[]).total.cost_micros, 0);
}
