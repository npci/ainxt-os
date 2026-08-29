// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-11 closure of IDN-06 (medium) — ADR-022 §14: the **composite actor of record on the
//! execution Event Log**. The design mandates that every agent action is attributed in
//! `ainxt-eventlog` to the *full composite* AWC — `def@sha | run | OBO human | key` — never a bare
//! service account. This is a cross-crate integration proof: a real attested AWC is minted by the
//! [`IdentityAuthority`], its [`actor_label`](ainxt_identity::authority::AgentWorkloadCredential::actor_label)
//! is stamped as the `actor` on a hash-chained Event-Log record, and we assert the persisted actor
//! carries the whole composite and that the record is tamper-evident.
//!
//! Fail-before/pass-after: it exercises the `actor_label` / `actor_of_record` entrypoints together
//! with `ainxt-eventlog` (a dev-dependency added this round).

use ainxt_eventlog::{EventLog, JsonlEventLog};
use ainxt_identity::authority::{
    AttestationQuote, ControlPlaneProjection, IdentityAuthority, IssueRequest,
    ReferenceValueVerifier,
};
use ainxt_identity::LogicalTime;
use ainxt_types::DataClass;

fn unique_dir(tag: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("ainxt_r11_{tag}_{}_{nanos}", std::process::id()))
}

fn attested_aia() -> IdentityAuthority<ReferenceValueVerifier> {
    let verifier = ReferenceValueVerifier::new().with_measurement("sha256:coder-image-v3");
    // The definition must be valid in the fail-closed control-plane projection.
    let projection = ControlPlaneProjection::new(
        ["def:role/coder@v3".to_string()],
        LogicalTime::new(0),
        "control-sha-777",
    );
    IdentityAuthority::new(verifier, projection, 5, 50, "key-v1")
}

#[test]
fn r11_composite_actor_of_record_on_eventlog() {
    let mut aia = attested_aia();
    let req = IssueRequest {
        def_kind: "role".into(),
        def_id: "coder".into(),
        def_version: "v3".into(),
        run_id: "run-abc".into(),
        data_class: DataClass::Internal,
        requires_tee: false,
        obo_user_id: "u-alice".into(),
        obo_department: Some("payments-eng".into()),
        obo_ad_level: Some(4),
        obo_can_approve: false,
    };
    let quote = AttestationQuote {
        def_content_hash: "def-hash-v3".into(),
        control_commit_sha: "control-sha-777".into(),
        measurement: "sha256:coder-image-v3".into(),
        tee_quote: None,
    };

    let awc = aia.issue(&req, &quote, LogicalTime::new(1)).unwrap();

    // The composite actor of record (§14) — a projection of immutable, content-addressed facets.
    let record = awc.actor_of_record();
    assert_eq!(record.run_id, "run-abc");
    assert_eq!(record.obo_user_id, "u-alice");
    assert_eq!(record.control_commit_sha, "control-sha-777");
    assert_eq!(record.key_id, "key-v1");

    // Stamp the composite as the Event-Log `actor` for an agent action (this is what the runtime
    // writes — never a service account).
    let actor = awc.actor_label();
    let dir = unique_dir("actor");
    let log = JsonlEventLog::open(&dir).unwrap();
    let appended = log
        .append("sess-1", &actor, "tool_call", "queried settlement report")
        .unwrap();

    // The persisted actor is the FULL composite, not a bare role / service account.
    let rows = log.records("sess-1");
    assert_eq!(rows.len(), 1);
    let logged_actor = &rows[0].actor;
    assert_eq!(logged_actor, &appended.actor);
    assert!(logged_actor.contains("ainxt-id://ainxt/agent/role/coder/v3/run/run-abc"));
    assert!(logged_actor.contains("obo=u-alice"));
    assert!(logged_actor.contains("commit=control-sha-777"));
    assert!(logged_actor.contains("key=key-v1"));
    // A regulator can answer "who did this?" from ONE line — it is not a shared service identity.
    assert!(!logged_actor.starts_with("svc:"));
    assert!(!logged_actor.contains("service-account"));

    // The record is tamper-evident: the hash chain verifies.
    assert_eq!(log.verify("sess-1").unwrap(), 1);

    let _ = std::fs::remove_dir_all(&dir);
}
