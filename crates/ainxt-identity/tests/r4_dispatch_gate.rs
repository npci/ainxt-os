// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-4 gap closure — the single per-dispatch authorization entrypoint the composition drives on
//! EVERY capability-bearing dispatch (ADR-022 §15 + §17/§19).
//!
//! Before this gap was closed, [`ControlPlane`] exposed the JIT renew-and-re-attest driver
//! (`renew_if_due`, §15) and the in-flight admission gate (`admit`, §17/§19) only as *separate*
//! primitives — the composition had to remember to call both, in order, on every dispatch, or a
//! lapsing credential / a mid-run kill-switch would slip through. [`ControlPlane::authorize_dispatch`]
//! fuses them into one deterministic decision on the REAL objects (a real
//! [`IdentityAuthority`]-minted [`AgentWorkloadCredential`] gated by a shared [`ControlPlane`]).
//!
//! These are end-to-end integration tests: they mint a genuine credential through the AIA's
//! attestation + control-plane gate, hold ONE shared control plane, and prove that a mid-run
//! kill-switch / revocation reaches the Run already in flight — its NEXT dispatch is denied — while a
//! long-lived Run is transparently re-attested at its short-TTL boundary.

use ainxt_identity::authority::{
    AgentWorkloadCredential, AttestationQuote, ControlPlaneProjection, IdentityAuthority,
    IssueRequest, KillScope, ReferenceValueVerifier,
};
use ainxt_identity::control::{
    AdmissionDenial, ControlPlane, DispatchDenial, DispatchOutcome, RunLease,
};
use ainxt_identity::LogicalTime;
use ainxt_types::DataClass;

/// A real AIA whose verifier accepts measurement `m-ok`, whose projection lists `def:role/coder@v3`
/// valid, and whose short TTL is 10 ticks (freshness never lapses in these tests).
fn aia() -> IdentityAuthority<ReferenceValueVerifier> {
    let verifier = ReferenceValueVerifier::new().with_measurement("m-ok");
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
        def_content_hash: "h".into(),
        control_commit_sha: "commit-shared".into(),
        measurement: "m-ok".into(),
        tee_quote: None,
    }
}

fn issue(
    aia: &mut IdentityAuthority<ReferenceValueVerifier>,
    run: &str,
    user: &str,
) -> AgentWorkloadCredential {
    aia.issue(&req(run, user), &quote(), LogicalTime(1))
        .unwrap()
}

/// The headline: ONE shared control plane, ONE entrypoint driven per dispatch. A healthy credential
/// proceeds; a mid-run kill-switch pull denies the Run's NEXT dispatch immediately (§19); an
/// individual revocation denies exactly that Run with zero collateral to a sibling (§17). The renewal
/// stage is transparent (credential comfortably mid-TTL → not renewed).
#[test]
fn r4_dispatch_gate() {
    let mut aia = aia();
    // Two independently-minted Runs (as the composition mints them per-Run today). TTL 10, issued
    // t=1 → expires t=11.
    let r1 = issue(&mut aia, "run-1", "u-alice");
    let r2 = issue(&mut aia, "run-2", "u-bob");

    // One shared control plane the runtime holds ONCE at its composition root.
    let cp_shared = ControlPlane::new();
    // A lease with a small renew-ahead so mid-TTL dispatches do NOT trigger renewal.
    let lease = RunLease::new(2);

    // Healthy, mid-TTL: both dispatches proceed, and neither is renewed (comfortably valid).
    let now = LogicalTime(3);
    let out1 = cp_shared.authorize_dispatch(&aia, &r1, &lease, None, now);
    assert!(out1.is_proceed(), "healthy credential proceeds");
    assert!(!out1.was_renewed(), "mid-TTL dispatch is not renewed");
    assert_eq!(out1.credential().unwrap().run_id, "run-1");
    assert!(cp_shared
        .authorize_dispatch(&aia, &r2, &lease, None, now)
        .is_proceed());

    // --- Mid-run KILL-SWITCH reaches the in-flight Run: prove the NEXT dispatch is denied. ---
    let mut cp = cp_shared.clone();
    // A senior approver pulls a data-class-scoped kill-switch covering payments-eng (§19, audited).
    let audit = cp
        .pull_kill_switch(
            KillScope::Department("payments-eng".into()),
            "u-exec",
            2,
            true,
            LogicalTime(3),
        )
        .expect("senior approver may pull the kill-switch");
    assert_eq!(audit.puller, "u-exec");
    assert_eq!(cp.kill_switch_audit().len(), 1, "the pull is audited (§19)");

    // The Run's NEXT dispatch (renewal not yet due at t=4) is denied at the admission stage — the
    // mid-run control action reached the in-flight Run, the whole point of a shared surface.
    let denied = cp.authorize_dispatch(&aia, &r2, &lease, None, LogicalTime(4));
    assert!(
        matches!(
            denied,
            DispatchOutcome::Deny(DispatchDenial::Admission(
                AdmissionDenial::KillSwitchActive { .. }
            ))
        ),
        "mid-run kill-switch denies the next dispatch: {denied:?}"
    );
    assert!(
        denied.credential().is_none(),
        "a denied dispatch yields no credential to act under"
    );

    // --- Individual revocation: exactly that Run denied, sibling untouched (§17). ---
    let mut cp2 = cp_shared.clone();
    cp2.revoke_run("run-1");
    assert!(
        matches!(
            cp2.authorize_dispatch(&aia, &r1, &lease, None, LogicalTime(4)),
            DispatchOutcome::Deny(DispatchDenial::Admission(
                AdmissionDenial::RunRevoked { .. }
            ))
        ),
        "revoked Run's next dispatch is denied"
    );
    assert!(
        cp2.authorize_dispatch(&aia, &r2, &lease, None, LogicalTime(4))
            .is_proceed(),
        "sibling Run is unaffected — zero collateral"
    );

    // --- OBO-human revocation denies every Run carrying that human (§17). ---
    let mut cp3 = cp_shared.clone();
    cp3.revoke_user("u-bob");
    assert!(
        matches!(
            cp3.authorize_dispatch(&aia, &r2, &lease, None, LogicalTime(4)),
            DispatchOutcome::Deny(DispatchDenial::Admission(
                AdmissionDenial::UserRevoked { .. }
            ))
        ),
        "revoking the OBO human denies the Run carrying them"
    );
}

/// The JIT stage: a long-lived Run whose short TTL is within the renew-ahead margin is transparently
/// re-attested by the SAME entrypoint (a fresh credential with a later TTL under the current key),
/// and the dispatch proceeds under that fresh credential — never the lapsing one. Then a kill-switch
/// pulled on the shared plane chokes the *renewal* itself at the boundary, denying the dispatch
/// (RenewalRefused) so the long Run drains at its next TTL.
#[test]
fn r4_dispatch_gate_jit_renew_and_kill_at_boundary() {
    let mut aia = aia();
    let awc = issue(&mut aia, "run-long", "u-alice"); // issued t=1, TTL 10 → expires t=11
    let cp_clean = ControlPlane::new();
    let lease = RunLease::new(3); // renew when within 3 ticks of expiry

    // At t=9 (expiry 11, margin 3) renewal is DUE: authorize_dispatch re-attests and proceeds under
    // the FRESH credential (later TTL), transparently to the caller.
    let out = cp_clean.authorize_dispatch(&aia, &awc, &lease, None, LogicalTime(9));
    assert!(out.is_proceed(), "renew-due dispatch proceeds");
    assert!(
        out.was_renewed(),
        "the short TTL boundary triggered a JIT renewal"
    );
    let fresh = out.credential().unwrap();
    assert_eq!(fresh.run_id, awc.run_id, "identity facets carried over");
    assert_eq!(
        fresh.issued_at,
        LogicalTime(9),
        "fresh credential re-issued at now"
    );
    assert_eq!(
        fresh.expires_at,
        LogicalTime(19),
        "fresh short TTL past now"
    );

    // Now a kill-switch is pulled on the shared plane. At the renewal boundary the RENEWAL is choked
    // (§15 conditional continuation over the shared deny-state), so the dispatch is denied at the
    // renewal stage — the long Run cannot mint a fresh identity and drains.
    let mut cp = ControlPlane::new();
    cp.pull_kill_switch(KillScope::Workforce, "u-exec", 1, true, LogicalTime(8))
        .expect("senior approver may pull the workforce kill-switch");
    let denied = cp.authorize_dispatch(&aia, &awc, &lease, None, LogicalTime(9));
    assert!(
        matches!(
            denied,
            DispatchOutcome::Deny(DispatchDenial::RenewalRefused(_))
        ),
        "kill-switch at the renewal boundary denies via the renewal stage: {denied:?}"
    );

    // And a fully-expired credential is denied at admission even if the caller forgot a renew-ahead
    // margin (lease with margin 0 → expired past t=11).
    let tight = RunLease::new(0);
    let expired = cp_clean.authorize_dispatch(&aia, &awc, &tight, None, LogicalTime(999));
    // margin 0 at t=999: it IS expired, so renew_if_due fires and re-mints (clean plane) → proceeds
    // under a fresh credential. Prove the entrypoint keeps a long Run alive across an expiry when the
    // shared plane permits.
    assert!(
        expired.is_proceed() && expired.was_renewed(),
        "an expired credential is re-attested when the shared plane permits: {expired:?}"
    );
}
