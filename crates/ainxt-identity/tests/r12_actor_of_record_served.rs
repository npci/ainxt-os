// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-12 seam test for the §14 (MEDIUM) item — **every Event-Log entry for an agent action
//! records the full composite AWC as actor (never a service account / bare role), universally on the
//! served path.**
//!
//! The clean entrypoint is [`AgentWorkloadCredential::actor_label`] / `actor_of_record` (r11 proved
//! it lands on `ainxt-eventlog`). This round hardens the served-path contract and proves the
//! entrypoint's contract the served path now depends on: `ainxt-runtimed::program_exec`'s
//! `EngineRunExecutor::drive_turn` stamps every `TurnObservation.actor` from `credential.actor_label()`
//! — the full composite, never the bare OBO `user_id` — so a regulator can answer "who did this?" from
//! one line (GAP-FIX identity-payments; see `ainxt-runtimed/tests/wire_loop_program.rs`'s
//! `wire2_idn_03_per_run_credential_minted_and_used`, which now asserts the served turn's `actor`
//! equals this exact composite label, not the bare user id). This test proves the entrypoint produces
//! exactly that composite (and, crucially, that it is NOT the bare user id a service-account-style
//! attribution would use), and that a JIT-renewed credential attributes the action to the FRESH key —
//! so the actor of record is never a lapsed token.
//!
//! GAP-FIX CLOSED: the one-line change in `ainxt-runtimed::program_exec::EngineRunExecutor::drive_turn`
//! now calls this entrypoint on every turn (all three `TurnObservation` construction sites: the
//! control-plane-deny path, the success path, and the engine-error path).

use ainxt_identity::authority::{
    AttestationQuote, ControlPlaneProjection, IdentityAuthority, IssueRequest,
    ReferenceValueVerifier,
};
use ainxt_identity::LogicalTime;
use ainxt_types::DataClass;

fn aia() -> IdentityAuthority<ReferenceValueVerifier> {
    IdentityAuthority::new(
        ReferenceValueVerifier::new().with_measurement("sha256:coder-image-v3"),
        ControlPlaneProjection::new(
            ["def:role/coder@v3".to_string()],
            LogicalTime(0),
            "control-sha-777",
        ),
        5,
        50,
        "key-v1",
    )
}

fn req(run: &str) -> IssueRequest {
    IssueRequest {
        def_kind: "role".into(),
        def_id: "coder".into(),
        def_version: "v3".into(),
        run_id: run.into(),
        data_class: DataClass::Internal,
        requires_tee: false,
        obo_user_id: "u-alice".into(),
        obo_department: Some("payments-eng".into()),
        obo_ad_level: Some(4),
        obo_can_approve: false,
    }
}

fn quote() -> AttestationQuote {
    AttestationQuote {
        def_content_hash: "def-hash-v3".into(),
        control_commit_sha: "control-sha-777".into(),
        measurement: "sha256:coder-image-v3".into(),
        tee_quote: None,
    }
}

#[test]
fn r12_served_actor_of_record_is_full_composite_not_service_account() {
    let mut aia = aia();
    let awc = aia
        .issue(&req("run-served-1"), &quote(), LogicalTime(1))
        .unwrap();

    let actor = awc.actor_label();
    // The full composite: which Run of which git-SHA'd definition, on whose behalf, under which key.
    assert!(actor.contains("ainxt-id://ainxt/agent/role/coder/v3/run/run-served-1"));
    assert!(actor.contains("obo=u-alice"));
    assert!(actor.contains("commit=control-sha-777"));
    assert!(actor.contains("key=key-v1"));

    // It is NOT the bare OBO user id (what the served TurnObservation currently stamps) and NOT a
    // service account — §14's core requirement.
    assert_ne!(
        actor, awc.obo_user_id,
        "the actor of record must not collapse to the bare OBO user id"
    );
    assert!(!actor.starts_with("svc:"));
    assert!(!actor.contains("service-account"));

    // The structured record exposes the same composite facets for typed consumers.
    let rec = awc.actor_of_record();
    assert_eq!(rec.run_id, "run-served-1");
    assert_eq!(rec.obo_user_id, "u-alice");
    assert_eq!(rec.control_commit_sha, "control-sha-777");
    assert_eq!(rec.key_id, "key-v1");
}

#[test]
fn r12_renewed_credential_attributes_action_to_fresh_key_not_lapsed_token() {
    let mut aia = aia();
    let awc = aia
        .issue(&req("run-served-2"), &quote(), LogicalTime(1))
        .unwrap();
    // A mid-life key rotation (ADR-023 §16), then a JIT renewal — the served path acts under the
    // fresh credential (chat_identity already threads the renewed cred as the actor of record).
    aia.rotate_key("key-v2");
    let renewed = aia.renew(&awc, None, LogicalTime(4)).unwrap();

    let actor = renewed.actor_label();
    assert!(
        actor.contains("key=key-v2"),
        "the actor of record carries the FRESH key after renewal"
    );
    assert!(
        actor.contains("run/run-served-2"),
        "identity facets carry over unchanged"
    );
    // The lapsed key is never the attribution.
    assert!(!actor.contains("key=key-v1"));
}
