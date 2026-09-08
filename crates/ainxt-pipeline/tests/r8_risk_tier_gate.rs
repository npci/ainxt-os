// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R8 — **deterministic pre-stage-1 risk classification drives the Commit Gate**, plus the
//! trivial auto-approve floor and the classification-surfacing route-ready entrypoint.
//!
//! Three things this proves, end-to-end, against the real public surface a served daemon assembles:
//!
//! 1. **Classification runs BEFORE stage 1 and is authoritative over the wire-declared tier.** A
//!    caller that under-declares a *settlement-path* edit as `Local` no longer gets it auto-committed:
//!    the graph-derived classifier forces Tier 3, and the edit is handed to a human with the sink
//!    untouched. (Fail-before: prior to R8 the pipeline trusted `config.tier`, so a `Local`-declared
//!    settlement edit reached `Committed`. This test asserts it does NOT.)
//!
//! 2. **The trivial auto-approve floor is tier-driven.** With the *same* declared floor and the
//!    *same* Confidence Score, a doc/comment-only edit (classified `Trivial`) auto-completes with NO
//!    spot-audit, while a body-logic edit (classified `Local`) at the identical score completes
//!    *with* a spot-audit — the difference comes entirely from the deterministic classification.
//!
//! 3. **The route-ready `classify_and_run_turn_for` entrypoint** is RBAC-gated (fail-closed, checked
//!    before classification runs), surfaces the [`EditRiskAssessment`] + typed [`EditResponse`] on
//!    the wire, and round-trips serde — so `ainxt-server` can mount it verbatim (`needs_hot_wiring`).
//!
//! Fails-before / passes-after: `classify_and_run_turn_for`, `ClassifiedEditResponse`,
//! `EditRiskAssessment`, `classify_edit`, and `GatePolicy::trivial_auto_approve_floor` did not exist
//! before R8, so this test would not compile against the prior crate.

use ainxt_pipeline::journal::Journal;
use ainxt_pipeline::sast::BuiltinScanner;
use ainxt_pipeline::stages::ScriptedTools;
use ainxt_pipeline::{
    classify_edit, run_edit_turn, Coder, EditEngine, EditRefused, EditRequest, EditResponse,
    Observation, RiskTier, SelfHealConfig, CAP_EDIT_APPLY,
};
use ainxt_semantic::ladder::Rung;
use ainxt_semantic::workspace::MemorySink;
use ainxt_types::Principal;
use std::sync::Arc;

/// A no-op coder — no healing is needed in any of these cases (clean edits + a hard human gate).
struct NoOpCoder;
impl Coder for NoOpCoder {
    fn fix(&self, _r: u8, files: &[(String, String)], _o: &Observation) -> Vec<(String, String)> {
        files.to_vec()
    }
}

fn engine() -> EditEngine {
    EditEngine::new(
        Arc::new(NoOpCoder),
        Arc::new(ScriptedTools::default()),
        Arc::new(BuiltinScanner),
    )
}

/// A config with a declared floor + a chosen blast-radius coverage (so we can land the Confidence
/// Score in the review band deterministically). Everything else is the default.
fn cfg(tier: RiskTier, coverage: f64) -> SelfHealConfig {
    SelfHealConfig {
        tier,
        blast_radius_test_coverage: coverage,
        rung: Rung::Ast,
        max_rounds: 2,
        ..Default::default()
    }
}

#[test]
fn r8_under_declared_settlement_edit_is_forced_to_tier3_before_any_stage() {
    // The caller LIES: a settlement-path logic change declared as the cheap `Local` tier. Before R8
    // this auto-committed; now the pre-stage-1 classifier forces Tier 3 and the sink stays clean.
    let turn = ainxt_pipeline::EditTurn {
        edit_id: "r8-settle".into(),
        original_files: vec![(
            "settlement/post.rs".into(),
            "fn post() -> i32 {\n    1\n}\n".into(),
        )],
        applied_files: vec![(
            "settlement/post.rs".into(),
            "fn post() -> i32 {\n    2\n}\n".into(),
        )],
        config: cfg(RiskTier::Local, 1.0),
    };
    let mut sink = MemorySink::new();
    let mut j = Journal::new("r8-settle");
    let out = run_edit_turn(
        turn,
        &NoOpCoder,
        &ScriptedTools::default(),
        &BuiltinScanner,
        &mut sink,
        &mut j,
    );
    assert!(
        !out.committed(),
        "an under-declared settlement edit must not auto-commit"
    );
    // The applied edit was NEVER written — the sink still holds the pre-edit baseline.
    assert_eq!(
        sink.files["settlement/post.rs"],
        "fn post() -> i32 {\n    1\n}\n"
    );
    assert_eq!(j.verify(), Ok(()));

    // And the classifier itself is unambiguous about WHY (graph fact, not a caller claim).
    let a = classify_edit(
        &[(
            "settlement/post.rs".into(),
            "fn post() -> i32 {\n    1\n}\n".into(),
        )],
        &[(
            "settlement/post.rs".into(),
            "fn post() -> i32 {\n    2\n}\n".into(),
        )],
        ainxt_pipeline::Language::Rust,
        RiskTier::Local,
        Rung::Ast,
        false,
    );
    assert!(a.critical_path);
    assert_eq!(a.tier, RiskTier::HighRisk);
    assert!(a.tier.forces_hitl());
}

#[test]
fn r8_trivial_auto_approve_floor_is_classification_driven() {
    // BOTH edits declare the same floor (Trivial) and land at the SAME Confidence Score (coverage
    // 0.5 → -15 → 85, in the 70..90 review band). The ONLY difference is what the deterministic
    // classifier decides the diff-class is.
    let eng = engine();

    // (a) A doc/comment-only edit → classified Trivial → auto-approve floor → NO spot-audit.
    let doc_turn = ainxt_pipeline::EditTurn {
        edit_id: "r8-doc".into(),
        original_files: vec![("util.rs".into(), "fn helper() -> i32 {\n    7\n}\n".into())],
        applied_files: vec![(
            "util.rs".into(),
            "// returns the answer\nfn helper() -> i32 {\n    7\n}\n".into(),
        )],
        config: cfg(RiskTier::Trivial, 0.5),
    };
    let mut sink = MemorySink::new();
    let mut j = Journal::new("r8-doc");
    let doc_out = eng.run_turn(doc_turn, &mut sink, &mut j);
    match doc_out {
        ainxt_pipeline::TurnOutcome::Committed { approval, .. } => {
            assert_eq!(approval.confidence(), 85, "coverage 0.5 → score 85");
            assert!(
                !approval.spot_audit(),
                "a trivial doc edit auto-approves without a spot-audit (the floor)"
            );
        }
        other => panic!("expected a trivial doc edit to commit, got {other:?}"),
    }

    // (b) A body-logic edit at the identical score → classified Local → completes WITH a spot-audit.
    let logic_turn = ainxt_pipeline::EditTurn {
        edit_id: "r8-logic".into(),
        original_files: vec![("util.rs".into(), "fn helper() -> i32 {\n    7\n}\n".into())],
        applied_files: vec![("util.rs".into(), "fn helper() -> i32 {\n    8\n}\n".into())],
        config: cfg(RiskTier::Trivial, 0.5),
    };
    let mut sink2 = MemorySink::new();
    let mut j2 = Journal::new("r8-logic");
    let logic_out = eng.run_turn(logic_turn, &mut sink2, &mut j2);
    match logic_out {
        ainxt_pipeline::TurnOutcome::Committed { approval, .. } => {
            assert_eq!(approval.confidence(), 85);
            assert!(
                approval.spot_audit(),
                "a non-trivial edit at the same score must still be spot-audited"
            );
        }
        other => panic!("expected the logic edit to commit-with-spot-audit, got {other:?}"),
    }
}

#[test]
fn r8_classified_route_entrypoint_rbac_surface_and_serde() {
    let eng = engine();

    // Unauthorized: refused BEFORE classification/pipeline runs — no write, no assessment leaked.
    let stranger = Principal::user("intern", &[]);
    let req = EditRequest {
        edit_id: "r8-unauth".into(),
        original_files: vec![(
            "settlement/x.rs".into(),
            "fn f() -> i32 {\n    1\n}\n".into(),
        )],
        applied_files: vec![(
            "settlement/x.rs".into(),
            "fn f() -> i32 {\n    2\n}\n".into(),
        )],
        config: cfg(RiskTier::Local, 1.0),
    };
    let mut sink = MemorySink::new();
    let mut j = Journal::new("r8-unauth");
    assert_eq!(
        eng.classify_and_run_turn_for(&stranger, req, &mut sink, &mut j),
        Err(EditRefused::NotAuthorized)
    );
    assert!(sink
        .files
        .get("settlement/x.rs")
        .is_none_or(|c| !c.contains('2')));

    // Authorized: the response carries BOTH the server-computed assessment (tier + rationale) and
    // the typed outcome. The under-declared settlement edit is Tier 3 → HandedToHuman, no write.
    let dev = Principal::user("dev", &[CAP_EDIT_APPLY]);
    let req2 = EditRequest {
        edit_id: "r8-classified".into(),
        original_files: vec![(
            "settlement/x.rs".into(),
            "fn f() -> i32 {\n    1\n}\n".into(),
        )],
        applied_files: vec![(
            "settlement/x.rs".into(),
            "fn f() -> i32 {\n    2\n}\n".into(),
        )],
        config: cfg(RiskTier::Local, 1.0),
    };
    let mut sink2 = MemorySink::new();
    let mut j2 = Journal::new("r8-classified");
    let resp = eng
        .classify_and_run_turn_for(&dev, req2, &mut sink2, &mut j2)
        .expect("authorized");
    assert_eq!(resp.assessment.tier, RiskTier::HighRisk);
    assert!(resp.assessment.critical_path);
    assert!(!resp.assessment.rationale.is_empty());
    assert!(
        !resp.response.committed(),
        "Tier-3 settlement edit is handed to a human"
    );
    assert!(matches!(resp.response, EditResponse::HandedToHuman { .. }));
    assert_eq!(
        sink2.files["settlement/x.rs"],
        "fn f() -> i32 {\n    1\n}\n"
    );

    // The whole classified response round-trips serde, so a transport can render it verbatim.
    let wire = serde_json::to_string(&resp).expect("serialize");
    let back: ainxt_pipeline::ClassifiedEditResponse =
        serde_json::from_str(&wire).expect("deserialize");
    assert_eq!(back, resp);
    assert!(wire.contains("\"tier\":\"high_risk\""));
}
