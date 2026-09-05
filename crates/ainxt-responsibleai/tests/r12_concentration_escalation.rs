// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R12 gap (low): "§3.5 concentration-risk board-delegate finding is a query metric, not a wired
//! threshold→escalation."
//!
//! Before: `concentration(tag, traffic)` returned a bare fraction — a human had to read it and decide.
//! After: `concentration_findings(traffic, threshold)` is the wired control — it fires a typed
//! [`ConcentrationFinding`] escalation for every tag whose dependency share exceeds the board-set
//! threshold, worst-first. Fail-before / pass-after is shown within the test: the same traffic that
//! `concentration()` merely reports a number for now produces (or does not produce) an escalation
//! depending on whether it breaches the threshold.

use std::collections::BTreeMap;

use ainxt_responsibleai::outsourcing::{
    ExitRehearsal, OutsourcingArrangement, OutsourcingRegister, SubProcessor,
};
use ainxt_types::DataClass;

fn arr(id: &str, tag: &str) -> OutsourcingArrangement {
    OutsourcingArrangement::new(
        id,
        "Provider Ltd, IN",
        DataClass::Confidential,
        "in",
        vec![SubProcessor {
            name: "sub-a".into(),
            jurisdiction: "in".into(),
        }],
        "program.exit.p",
        tag,
        ExitRehearsal::At { tick: 1 },
    )
}

#[test]
fn r12_concentration_over_threshold_fires_a_board_delegate_escalation() {
    let mut reg = OutsourcingRegister::new(10_000);
    // Two routes on the SAME dependency category (chat-inference) + one diversified (embeddings).
    reg.upsert(arr("cloud.a", "chat-inference"));
    reg.upsert(arr("cloud.b", "chat-inference"));
    reg.upsert(arr("cloud.c", "embeddings"));

    let mut traffic = BTreeMap::new();
    traffic.insert("cloud.a".to_string(), 60);
    traffic.insert("cloud.b".to_string(), 30); // chat-inference total = 90%
    traffic.insert("cloud.c".to_string(), 10); // embeddings = 10%

    // FAIL-BEFORE (the metric-only world): `concentration` just reports a number; nothing fires.
    let frac = reg.concentration("chat-inference", &traffic);
    assert!((frac - 0.9).abs() < 1e-9, "metric only: {frac}");

    // PASS-AFTER: at a 0.5 board threshold, the over-relied tag fires an escalation; the diversified
    // one does not.
    let findings = reg.concentration_findings(&traffic, 0.5);
    assert_eq!(findings.len(), 1, "exactly one tag breaches: {findings:?}");
    assert_eq!(findings[0].tag, "chat-inference");
    assert!((findings[0].fraction - 0.9).abs() < 1e-9);
    assert!((findings[0].threshold - 0.5).abs() < 1e-9);

    // Below-threshold: raising the ceiling above the measured share silences the escalation (the
    // control is genuinely threshold-driven, not always-on).
    assert!(reg.concentration_findings(&traffic, 0.95).is_empty());

    // Exactly-at-threshold is acceptable (strict `>`): 0.9 threshold does not fire on a 0.9 share.
    assert!(reg.concentration_findings(&traffic, 0.9).is_empty());
}

#[test]
fn r12_concentration_findings_are_worst_first_and_deterministic() {
    let mut reg = OutsourcingRegister::new(10_000);
    reg.upsert(arr("a", "high-dep")); // 70%
    reg.upsert(arr("b", "mid-dep")); // 20%
    reg.upsert(arr("c", "low-dep")); // 10%
    let mut traffic = BTreeMap::new();
    traffic.insert("a".to_string(), 70);
    traffic.insert("b".to_string(), 20);
    traffic.insert("c".to_string(), 10);

    // At a 0.05 threshold all three breach; findings come worst-first.
    let findings = reg.concentration_findings(&traffic, 0.05);
    assert_eq!(findings.len(), 3);
    assert_eq!(findings[0].tag, "high-dep");
    assert_eq!(findings[1].tag, "mid-dep");
    assert_eq!(findings[2].tag, "low-dep");
    assert!(findings[0].fraction >= findings[1].fraction);
    assert!(findings[1].fraction >= findings[2].fraction);

    // The per-tag view exposes every tag (including below-threshold), tag-ordered.
    let by_tag = reg.concentration_by_tag(&traffic);
    assert_eq!(by_tag.len(), 3);
    assert_eq!(by_tag[0].0, "high-dep"); // BTreeSet tag order
}

#[test]
fn r12_empty_traffic_raises_no_escalation() {
    let mut reg = OutsourcingRegister::new(10_000);
    reg.upsert(arr("a", "chat-inference"));
    let empty = BTreeMap::new();
    assert!(reg.concentration_findings(&empty, 0.0).is_empty());
}
