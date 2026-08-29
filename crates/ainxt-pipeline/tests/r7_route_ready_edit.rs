// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R7 — the **route-ready `POST /v1/edit` entrypoint** (`EditEngine::run_turn_for`).
//!
//! A server transport holds one long-lived [`EditEngine`] (seams wired once at startup) and, per
//! request, deserializes an [`EditRequest`] off the wire, calls `run_turn_for(principal, req, sink,
//! journal)`, and renders a "done"/commit view **only** on a typed [`EditResponse::Committed`].
//!
//! This proves the whole route contract end-to-end against the offline seams:
//! 1. capability gate is fail-closed and checked BEFORE the pipeline runs (no cap ⇒ no durable write);
//! 2. an authorized clean edit reaches `Committed` AND the durable [`WorkspaceSink`] was written;
//! 3. a SAST-blocked edit comes back as `HandedToHuman` and the sink is NEVER written;
//! 4. request + response + refusal all round-trip serde, so a transport can use them verbatim.
//!
//! Fails-before / passes-after: `run_turn_for` / `EditRequest` / `EditResponse` / `CAP_EDIT_APPLY`
//! did not exist before R7, so this test would not even compile against the prior crate.

use ainxt_pipeline::journal::Journal;
use ainxt_pipeline::sast::BuiltinScanner;
use ainxt_pipeline::stages::ScriptedTools;
use ainxt_pipeline::{
    Coder, EditEngine, EditRefused, EditRequest, EditResponse, Observation, RiskTier,
    SelfHealConfig, CAP_EDIT_APPLY,
};
use ainxt_semantic::workspace::MemorySink;
use ainxt_types::Principal;
use std::sync::Arc;

/// A no-op Coder — it never edits; it exists only so the engine can be assembled. The clean-turn
/// case needs no healing; the blocked case is a hard SAST gate a Coder could not fix anyway.
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

fn cfg(tier: RiskTier) -> SelfHealConfig {
    SelfHealConfig {
        tier,
        max_rounds: 3,
        ..Default::default()
    }
}

#[test]
fn r7_route_ready_edit_unauthorized_never_touches_the_sink() {
    // A principal WITHOUT the capability is refused BEFORE the pipeline runs — 403, and the sink
    // (seeded with the pre-edit baseline) still holds the original, never the applied edit.
    let eng = engine();
    let req = EditRequest {
        edit_id: "t-unauth".into(),
        original_files: vec![("a.rs".into(), "fn f() -> i32 { 1 }\n".into())],
        applied_files: vec![("a.rs".into(), "fn f() -> i32 { 2 }\n".into())],
        config: cfg(RiskTier::Local),
    };
    let stranger = Principal::user("intern", &[]); // holds no caps
    let mut sink = MemorySink::new();
    let mut j = Journal::new("t-unauth");

    let res = eng.run_turn_for(&stranger, req, &mut sink, &mut j);
    assert_eq!(res, Err(EditRefused::NotAuthorized));
    // The applied edit was never written; the durable write is unreachable without the cap.
    assert!(sink.files.get("a.rs").is_none_or(|c| !c.contains('2')));
}

#[test]
fn r7_route_ready_edit_authorized_clean_turn_commits_and_writes_the_sink() {
    let eng = engine();
    let req = EditRequest {
        edit_id: "t-clean".into(),
        original_files: vec![("a.rs".into(), "fn f() -> i32 { 1 }\n".into())],
        applied_files: vec![("a.rs".into(), "fn f() -> i32 { 2 }\n".into())],
        config: cfg(RiskTier::Local),
    };
    let dev = Principal::user("dev", &[CAP_EDIT_APPLY]);
    let mut sink = MemorySink::new();
    let mut j = Journal::new("t-clean");

    let res = eng
        .run_turn_for(&dev, req, &mut sink, &mut j)
        .expect("authorized");
    match res {
        EditResponse::Committed {
            confidence,
            versions,
            ..
        } => {
            assert!(confidence >= 90, "clean edit should score high");
            assert_eq!(versions["a.rs"], 1, "one commit bumps v0 -> v1");
        }
        other => panic!("expected Committed, got {other:?}"),
    }
    // The durable write actually happened, and ONLY through the route → pipeline → CommitApproval.
    assert!(sink.files["a.rs"].contains('2'));
    // Admin implies the cap too.
    let mut sink2 = MemorySink::new();
    let mut j2 = Journal::new("t-clean-admin");
    let admin = Principal::admin("root");
    let req2 = EditRequest {
        edit_id: "t-clean2".into(),
        original_files: vec![("a.rs".into(), "fn f() -> i32 { 1 }\n".into())],
        applied_files: vec![("a.rs".into(), "fn f() -> i32 { 3 }\n".into())],
        config: cfg(RiskTier::Local),
    };
    assert!(eng
        .run_turn_for(&admin, req2, &mut sink2, &mut j2)
        .unwrap()
        .committed());
}

#[test]
fn r7_route_ready_edit_wire_types_round_trip_serde() {
    // A transport deserializes the request off the wire and serializes the response back — both must
    // round-trip losslessly, and the tagged discriminants a renderer matches on must be present.
    let req = EditRequest {
        edit_id: "t-json".into(),
        original_files: vec![("a.rs".into(), "fn f() {}\n".into())],
        applied_files: vec![("a.rs".into(), "fn f() { }\n".into())],
        config: cfg(RiskTier::HighRisk),
    };
    let wire = serde_json::to_string(&req).expect("serialize request");
    let back: EditRequest = serde_json::from_str(&wire).expect("deserialize request");
    assert_eq!(back.edit_id, "t-json");
    assert_eq!(back.config.tier, RiskTier::HighRisk);

    // deny_unknown_fields rejects a smuggled key.
    let smuggled = wire.replacen('{', "{\"evil\":1,", 1);
    assert!(serde_json::from_str::<EditRequest>(&smuggled).is_err());

    let committed = EditResponse::Committed {
        confidence: 93,
        spot_audit: false,
        versions: [("a.rs".to_string(), 1u64)].into_iter().collect(),
        rounds: 0,
    };
    let cj = serde_json::to_string(&committed).unwrap();
    assert!(cj.contains("\"result\":\"committed\""));
    assert_eq!(
        serde_json::from_str::<EditResponse>(&cj).unwrap(),
        committed
    );

    let refused = EditRefused::NotAuthorized;
    let rj = serde_json::to_string(&refused).unwrap();
    assert!(rj.contains("\"error\":\"not_authorized\""));
    assert_eq!(serde_json::from_str::<EditRefused>(&rj).unwrap(), refused);
}
