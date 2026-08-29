// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-8 gap closure — the Separation-of-Duties **verify-gate entrypoint** the live program
//! verifier calls (ADR-022 §18). Producer ≠ approver, keyed on the per-Run workload identity, driven
//! through `SodVerifyGate` with the SAME real [`AgentWorkloadCredential`]s the composition mints via
//! the Agent Identity Authority — not hand-built `WorkloadRef`s.
//!
//! # The gap
//!
//! The SoD decision (`SodPolicy`) and signed-handoff verification were built + unit-tested, but there
//! was no single credential-facing entrypoint the live program-verification wire could call with the
//! two `AgentWorkloadCredential`s it already holds (the producing Run and the approving/verifier Run).
//! `SodVerifyGate::authorize_approval` is that entrypoint. These tests prove, end-to-end from a real
//! attested credential mint, that:
//!
//!   * a Run **cannot approve its own work** — self-approval is refused (`SodError::SelfApproval`),
//!     even when the identical role/definition is the approver, because SoD keys on `run_id`;
//!   * a **distinct** verifier Run (of any permitted role) is granted and yields an audit-ready
//!     `ApprovalDecision` binding producer, approver, and the artifact digest;
//!   * the git-controlled approver-role allow-list is honored on top of the always-on identity rule.
//!
//! Everything is deterministic — the identity crate reads no clock / rng / I/O; logical time is a
//! caller-supplied parameter — so the refusal is an exhaustively-testable property.

use ainxt_identity::authority::{
    AgentWorkloadCredential, AttestationQuote, ControlPlaneProjection, IdentityAuthority,
    IssueRequest, ReferenceValueVerifier,
};
use ainxt_identity::sod::{SodError, SodPolicy, SodVerifyGate, WorkloadRef};
use ainxt_identity::LogicalTime;
use ainxt_types::DataClass;

/// A real AIA whose OFFLINE verifier accepts measurement `m-ok` and lists both the coder and judge
/// definitions valid; short TTL, freshness never lapses here.
fn aia() -> IdentityAuthority<ReferenceValueVerifier> {
    let verifier = ReferenceValueVerifier::new().with_measurement("m-ok");
    let projection = ControlPlaneProjection::new(
        [
            "def:role/coder@v3".to_string(),
            "def:role/judge@v2".to_string(),
            "def:role/linter@v1".to_string(),
        ],
        LogicalTime(0),
        "commit-shared",
    );
    IdentityAuthority::new(verifier, projection, 100, 1_000_000, "key-v1")
}

fn quote() -> AttestationQuote {
    AttestationQuote {
        def_content_hash: "h".into(),
        control_commit_sha: "commit-shared".into(),
        measurement: "m-ok".into(),
        tee_quote: None,
    }
}

/// Mint a real per-Run credential for `(role, version, run_id)` on-behalf-of `user`.
fn mint(
    aia: &mut IdentityAuthority<ReferenceValueVerifier>,
    role: &str,
    version: &str,
    run_id: &str,
    user: &str,
) -> AgentWorkloadCredential {
    let req = IssueRequest {
        def_kind: "role".into(),
        def_id: role.into(),
        def_version: version.into(),
        run_id: run_id.into(),
        data_class: DataClass::Internal,
        requires_tee: false,
        obo_user_id: user.into(),
        obo_department: Some("payments-eng".into()),
        obo_ad_level: Some(4),
        obo_can_approve: false,
    };
    aia.issue(&req, &quote(), LogicalTime(1))
        .expect("clean attestation -> issued")
}

// R8 — the core rule: a Run cannot approve its OWN work through the live verify-gate entrypoint.
#[test]
fn r8_sod_gate_refuses_self_approval() {
    let mut aia = aia();
    let gate = SodVerifyGate::identity_only();

    // ONE Run produces the artifact and then tries to approve it itself (the same credential is both
    // producer and approver — a compromised/mis-wired verifier that is the producing Run).
    let producer = mint(&mut aia, "coder", "v3", "run-coder-1", "u-alice");

    let err = gate
        .authorize_approval(&producer, &producer, "mr-42", "digest-abc")
        .expect_err("a Run approving its own work must be refused");

    assert_eq!(
        err,
        SodError::SelfApproval {
            producer: WorkloadRef::new("def:role/coder@v3", "run-coder-1"),
            approver: WorkloadRef::new("def:role/coder@v3", "run-coder-1"),
        }
    );
}

// R8 — the same role/model running as a DISTINCT Run is still refused if it IS the producer, but a
// genuinely distinct Run of the same role may approve: SoD keys on run_id, not on the definition.
#[test]
fn r8_sod_gate_keys_on_run_not_role() {
    let mut aia = aia();
    let gate = SodVerifyGate::identity_only();

    let producer = mint(&mut aia, "coder", "v3", "run-coder-A", "u-alice");
    // A DIFFERENT Run of the identical coder definition — a distinct peer reviewer.
    let peer = mint(&mut aia, "coder", "v3", "run-coder-B", "u-bob");

    // Producer approving itself -> refused.
    assert!(matches!(
        gate.authorize_approval(&producer, &producer, "mr-1", "d1"),
        Err(SodError::SelfApproval { .. })
    ));

    // A distinct Run of the same role -> granted, with an audit-ready decision.
    let decision = gate
        .authorize_approval(&producer, &peer, "mr-1", "d1")
        .expect("a distinct Run may approve a peer's work");
    assert_eq!(decision.artifact_id, "mr-1");
    assert_eq!(decision.producer.run_id, "run-coder-A");
    assert_eq!(decision.approver.run_id, "run-coder-B");
    assert_eq!(decision.content_digest, "d1");
}

// R8 — a distinct judge Run is granted; the git-controlled approver-role allow-list is enforced ON
// TOP of the always-on identity rule (a distinct-but-wrong role is refused).
#[test]
fn r8_sod_gate_grants_distinct_judge_and_enforces_role_allow_list() {
    let mut aia = aia();
    // Only the judge role may approve.
    let gate = SodVerifyGate::new(SodPolicy::with_permitted_approvers(["def:role/judge@v2"]));

    let producer = mint(&mut aia, "coder", "v3", "run-coder-1", "u-alice");
    let judge = mint(&mut aia, "judge", "v2", "run-judge-1", "u-carol");
    let linter = mint(&mut aia, "linter", "v1", "run-linter-1", "u-dave");

    // A distinct judge Run -> granted.
    let decision = gate
        .authorize_approval(&producer, &judge, "mr-42", "digest-abc")
        .expect("a distinct judge Run is a permitted approver");
    assert_eq!(decision.approver.def_ref, "def:role/judge@v2");
    assert_eq!(decision.approver.run_id, "run-judge-1");

    // A distinct linter Run (passes the identity rule) is still refused by the role allow-list.
    let err = gate
        .authorize_approval(&producer, &linter, "mr-42", "digest-abc")
        .expect_err("an out-of-policy approver role must be refused");
    assert!(matches!(err, SodError::ApproverRoleNotPermitted { .. }));

    // And even the permitted judge role cannot self-approve if it IS the producer.
    let judge_producer = mint(&mut aia, "judge", "v2", "run-judge-solo", "u-carol");
    assert!(matches!(
        gate.authorize_approval(&judge_producer, &judge_producer, "mr-9", "d9"),
        Err(SodError::SelfApproval { .. })
    ));
}
