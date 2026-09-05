// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Telemetry: integer-money cost attribution, the sinks, and config parsing.

use ainxt_telemetry::{
    InMemoryTelemetry, ModelPrice, NullTelemetry, PriceTable, TelemetryConfig, TelemetrySink,
    TelemetrySinkKind, TurnMetrics, TurnOutcome,
};
use ainxt_types::DataClass;

fn sample(actor: &str, provider: &str, cost: u64) -> TurnMetrics {
    TurnMetrics {
        session: "s".into(),
        turn: "t".into(),
        actor: actor.into(),
        provider: provider.into(),
        data_class: DataClass::Public,
        input_tokens: 1000,
        output_tokens: 500,
        cost_micros: cost,
        latency_ms: 10,
        redactions: 0,
        tool_calls: 0,
        outcome: TurnOutcome::Completed,
    }
}

#[test]
fn cost_is_exact_integer_money() {
    let mut t = PriceTable::new();
    // $3 per 1M input, $15 per 1M output (in micros: $1 = 1_000_000).
    t.set(
        "cloud",
        ModelPrice {
            input_micros_per_million: 3_000_000,
            output_micros_per_million: 15_000_000,
        },
    );
    // 1000 input @ $3/M = $0.003 = 3000 micros; 500 output @ $15/M = $0.0075 = 7500 micros.
    assert_eq!(t.cost_micros("cloud", 1000, 500), 3000 + 7500);
    // An unpriced provider costs 0 (unknown), never panics.
    assert_eq!(t.cost_micros("mystery", 1000, 500), 0);
    // No floating-point drift at large volumes.
    assert_eq!(t.cost_micros("cloud", 1_000_000, 0), 3_000_000);
}

#[test]
fn null_sink_is_a_noop_and_memory_sink_collects() {
    let null = NullTelemetry;
    null.record_turn(&sample("u", "p", 0)); // no panic, nothing to observe

    let mem = InMemoryTelemetry::new();
    assert!(mem.is_empty());
    mem.record_turn(&sample("alice", "cloud", 100));
    mem.record_turn(&sample("bob", "local", 0));
    assert_eq!(mem.len(), 2);
    let turns = mem.turns();
    assert_eq!(turns[0].actor, "alice");
    assert_eq!(turns[0].cost_micros, 100);
    assert_eq!(turns[1].provider, "local");
}

#[test]
fn config_defaults_to_null_and_parses_pricing() {
    let d = TelemetryConfig::default();
    assert_eq!(d.sink, TelemetrySinkKind::Null);
    assert!(d.price_table().is_empty());

    let cfg: TelemetryConfig = serde_json::from_str(
        r#"{"sink":"memory","pricing":{"cloud":{"input_micros_per_million":3000000,"output_micros_per_million":15000000}}}"#,
    )
    .unwrap();
    assert_eq!(cfg.sink, TelemetrySinkKind::Memory);
    assert_eq!(cfg.price_table().cost_micros("cloud", 1000, 0), 3000);
}
