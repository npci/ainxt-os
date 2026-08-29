// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-6 gap closure — the clean `issue_jit` entrypoint the composition drives to mint a Run's
//! FIRST short-TTL credential, JIT at Run start, gated on the SHARED control plane and issued only
//! after attestation-before-issuance against external reference values (ADR-022 §13 + §15 + §17/§19).
//!
//! # The gap
//!
//! Before this, [`ControlPlane`] drove renewal ([`ControlPlane::renew_if_due`], §15) and in-flight
//! admission ([`ControlPlane::admit`], §17/§19) — but the *initial* mint went straight to
//! [`IdentityAuthority::issue`], which re-checks revocation / kill-switch against the AIA's **own**
//! registries. In the composition model the live deny-state lives on the ONE shared
//! [`ControlPlane`] the runtime holds at its composition root, and the AIA is a stateless minting
//! service whose local registries are empty. So an en-masse kill-switch (§19) or a revoked OBO human
//! (§17) pulled on the shared plane correctly stopped every *renewal* — yet a brand-new Run could
//! still slip through `issue` and obtain a credential.
//!
//! These tests demonstrate the gap directly: with a workforce kill-switch engaged on the shared
//! plane, the raw `IdentityAuthority::issue` path STILL SUCCEEDS (the escape hatch `issue_jit`
//! closes), while `ControlPlane::issue_jit` DENIES — the same control action that drains running
//! Runs now also refuses new ones. Offline attestation is a real [`ReferenceValueVerifier`]; there
//! is no clock, rng, or I/O — every assertion is deterministic.

use ainxt_identity::authority::{
    AttestationError, AttestationQuote, ControlPlaneProjection, IdentityAuthority, IssueError,
    IssueRequest, KillScope, ReferenceValueVerifier,
};
use ainxt_identity::control::{ControlPlane, Renewal, RunLease};
use ainxt_identity::LogicalTime;
use ainxt_types::DataClass;

/// A real AIA whose OFFLINE verifier accepts measurement `m-ok` (and TEE quote `tee-ok`), whose
/// projection lists `def:role/coder@v3` valid, short TTL = 10 ticks, freshness never lapses here.
fn aia() -> IdentityAuthority<ReferenceValueVerifier> {
    let verifier = ReferenceValueVerifier::new()
        .with_measurement("m-ok")
        .with_tee_quote("tee-ok");
    let projection = ControlPlaneProjection::new(
        ["def:role/coder@v3".to_string()],
        LogicalTime(0),
        "commit-shared",
    );
    IdentityAuthority::new(verifier, projection, 10, 1_000_000, "key-v1")
}

fn req(run_id: &str, user: &str) -> IssueRequest {
    IssueRequest {
        def_kind: "role".into(),
        def_id: "coder".into(),
        def_version: "v3".into(),
        run_id: run_id.into(),
        data_class: DataClass::Internal,
        requires_tee: false,
        obo_user_id: user.into(),
        obo_department: Some("payments-eng".into()),
        obo_ad_level: Some(4),
        obo_can_approve: false,
    }
}

fn quote() -> AttestationQuote {
    AttestationQuote {
        def_content_hash: "h-coder".into(),
        control_commit_sha: "commit-shared".into(),
        measurement: "m-ok".into(),
        tee_quote: None,
    }
}

// R6: the happy path — `issue_jit` mints a genuine attested, short-TTL, per-Run credential when the
// shared plane is clean, and the credential carries the attested facts (not self-assertion).
#[test]
fn r6_issue_jit_mints_attested_short_ttl_credential() {
    let mut aia = aia();
    let cp = ControlPlane::new();

    let awc = cp
        .issue_jit(
            &mut aia,
            &req("run-1", "u-alice"),
            &quote(),
            LogicalTime(10),
        )
        .expect("clean shared plane + valid attestation -> issued");

    assert_eq!(awc.uri(), "ainxt-id://ainxt/agent/role/coder/v3/run/run-1");
    assert_eq!(awc.attestation_ref, "m-ok", "attested, not self-asserted");
    assert_eq!(awc.control_commit_sha, "commit-shared");
    assert_eq!(awc.key_id, "key-v1");
    // Short TTL: issued t=10, expires t=20 (inclusive), no standing credential.
    assert_eq!(awc.issued_at, LogicalTime(10));
    assert_eq!(awc.expires_at, LogicalTime(20));
    assert!(awc.is_valid_at(LogicalTime(20)));
    assert!(awc.is_expired_at(LogicalTime(21)));
}

// R6: attestation-before-issuance — a measurement absent from the offline reference-value allow-list
// mints NOTHING (§13), through the composition entrypoint.
#[test]
fn r6_issue_jit_refuses_unattested_measurement() {
    let mut aia = aia();
    let cp = ControlPlane::new();

    let tampered = AttestationQuote {
        measurement: "m-tampered".into(),
        ..quote()
    };
    let err = cp
        .issue_jit(
            &mut aia,
            &req("run-1", "u-alice"),
            &tampered,
            LogicalTime(1),
        )
        .unwrap_err();
    assert_eq!(
        err,
        IssueError::AttestationFailed(AttestationError::UnknownMeasurement("m-tampered".into()))
    );
    // A refused issuance minted nothing: the run_id is still free once the measurement is fixed.
    assert!(cp
        .issue_jit(&mut aia, &req("run-1", "u-alice"), &quote(), LogicalTime(1))
        .is_ok());
}

// R6 — THE GAP, fail-before/pass-after: a workforce kill-switch pulled on the SHARED plane stops a
// brand-new Run from being minted through `issue_jit`, whereas the raw AIA path (which consults only
// the empty local registries) STILL succeeds. `issue_jit` makes the en-masse halt total.
#[test]
fn r6_shared_kill_switch_stops_new_issuance_but_raw_aia_would_not() {
    let mut aia = aia();
    let mut cp = ControlPlane::new();

    // A senior approver pulls the workforce big-red-button on the shared plane (§19, authority-gated).
    cp.pull_kill_switch(KillScope::Workforce, "u-exec", 2, true, LogicalTime(1))
        .expect("senior approver may pull the workforce kill-switch");

    // Through the composition entrypoint: DENIED — a fresh Run cannot obtain a credential.
    let err = cp
        .issue_jit(
            &mut aia,
            &req("run-new", "u-alice"),
            &quote(),
            LogicalTime(2),
        )
        .unwrap_err();
    assert_eq!(err, IssueError::KillSwitchActive);

    // The gap it closes: the raw AIA mint path, consulting only its own (empty) local kill-switch,
    // would happily issue the very same Run — the escape hatch the composition must never use.
    let leaked = aia
        .issue(&req("run-new-raw", "u-alice"), &quote(), LogicalTime(2))
        .expect(
            "raw AIA has no shared deny-state -> would leak a credential during a workforce halt",
        );
    assert!(leaked.is_valid_at(LogicalTime(2)));

    // Releasing the halt lets `issue_jit` mint again — the control is a live lever, not a one-way trip.
    cp.release_kill_switch(&KillScope::Workforce);
    assert!(cp
        .issue_jit(
            &mut aia,
            &req("run-after-release", "u-alice"),
            &quote(),
            LogicalTime(3)
        )
        .is_ok());
}

// R6: a scoped kill-switch and a revoked OBO human are both honored at issuance with the exact §19
// facet-matching the dispatch/renewal path uses — precise, not just the big red button.
#[test]
fn r6_scoped_kill_switch_and_user_revocation_gate_issuance() {
    let mut aia = aia();
    let mut cp = ControlPlane::new();

    // Halt only regulated-payment Runs (data-class scope).
    cp.pull_kill_switch(
        KillScope::DataClass(DataClass::RegulatedPayment),
        "u-exec",
        1,
        true,
        LogicalTime(1),
    )
    .unwrap();

    // An internal-class Run is unaffected.
    assert!(cp
        .issue_jit(
            &mut aia,
            &req("run-internal", "u-alice"),
            &quote(),
            LogicalTime(2)
        )
        .is_ok());

    // A regulated-payment Run is halted at issuance.
    let mut reg = req("run-reg", "u-alice");
    reg.data_class = DataClass::RegulatedPayment;
    assert_eq!(
        cp.issue_jit(&mut aia, &reg, &quote(), LogicalTime(2))
            .unwrap_err(),
        IssueError::KillSwitchActive
    );

    // A revoked OBO human is denied a NEW credential too (§17), naming the user.
    cp.revoke_user("u-mallory");
    assert_eq!(
        cp.issue_jit(
            &mut aia,
            &req("run-m", "u-mallory"),
            &quote(),
            LogicalTime(2)
        )
        .unwrap_err(),
        IssueError::Revoked("user u-mallory".into())
    );
}

// R6: end-to-end lifecycle through the composition — issue_jit -> the Run lives -> the §15 short-TTL
// renew-and-re-attest driver rolls it forward at its renew-ahead boundary, all on the shared plane.
#[test]
fn r6_issue_jit_then_renew_drives_the_full_short_ttl_lifecycle() {
    let mut aia = aia();
    let cp = ControlPlane::new();
    let lease = RunLease::new(3); // renew when within 3 ticks of expiry

    // JIT mint at Run start: issued t=1, TTL 10 -> expires t=11.
    let awc = cp
        .issue_jit(
            &mut aia,
            &req("run-long", "u-alice"),
            &quote(),
            LogicalTime(1),
        )
        .unwrap();
    assert_eq!(awc.expires_at, LogicalTime(11));

    // Mid-life: the driver does nothing (still comfortably valid).
    assert_eq!(
        cp.renew_if_due(&aia, &awc, &lease, None, LogicalTime(5))
            .unwrap(),
        Renewal::StillValid
    );

    // Within the renew-ahead margin (t=9): renew-and-re-attest mints a fresh short-TTL credential,
    // carrying the identity facets forward — a long Run is a chain of re-authorized identities.
    let renewal = cp
        .renew_if_due(&aia, &awc, &lease, None, LogicalTime(9))
        .unwrap();
    assert!(renewal.was_renewed());
    let fresh = renewal.credential().unwrap();
    assert_eq!(fresh.issued_at, LogicalTime(9));
    assert_eq!(
        fresh.expires_at,
        LogicalTime(19),
        "fresh short TTL past now"
    );
    assert_eq!(fresh.run_id, awc.run_id, "same Run, re-authorized identity");
    assert_eq!(fresh.uri(), awc.uri());
}
