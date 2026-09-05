// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-11 all-severities closure for the payment-boundary half of
//! `docs/architecture/AGENT_IDENTITY_AND_PAYMENT_BOUNDARY.md` (ADR-016). Each test exercises a
//! *cross-cut* of the crate's public surface (not the in-module unit tests) and is fail-before /
//! pass-after: every entrypoint it calls was added in this round, so the file would not compile
//! against the prior crate.
//!
//! Gaps closed here:
//! * IDN-07 (medium) — Layer-4 git-native `payment_boundary` front-matter authoring *enforcement*
//!   (the single `enforce` decision a CI check / pre-receive hook calls).
//! * IDN-09 (medium) — Layer-6 tripwire *graduated response* (abort + quarantine + revoke identity
//!   + raise incident), not a bare deny-and-log.
//! * IDN-10 (low) — §4.4/§4.5 settlement-perimeter + signature list as a *git-controlled policy*
//!   artifact (dual-council governed edit + one-way ratchet + build-boundary round-trip).
//! * IDN-04 (low) — §6 PAM as the *fourth dispatch gate on top of OBO* (additive, never a
//!   substitute; a failed OBO layer denies without burning a PAM use).

use ainxt_payments::boundary::{
    EgressGuard, InitiationReason, OutboundCall, PayloadSignal, PaymentBoundary, PolicyEditError,
    PolicyGovernance, SettlementPolicy, TripwireAction, UpiOperation,
};
use ainxt_payments::front_matter::{
    self, AuthoringContext, FrontMatterError, PaymentBoundaryClass,
};
use ainxt_payments::mandate::{
    authorize_adjacent_dispatch, AdjacentDispatchDenied, MandateRegistry, OboOutcome, PamError,
    PamRequest, PaymentAdjacentMandate,
};

// ---------------------------------------------------------------------------
// IDN-07 — Layer-4 authoring enforcement: parse + authorize in one hook call.
// ---------------------------------------------------------------------------
#[test]
fn r11_frontmatter_authoring_enforcement() {
    let full = AuthoringContext {
        payments_council_approved: true,
        commit_signed: true,
        author_can_approve: true,
        author_ad_level: 3,
    };

    // `payment-initiating` can never merge — rejected BEFORE any authority is consulted, even with
    // a fully-authorized commit.
    assert!(matches!(
        front_matter::enforce("payment-initiating", &full),
        Err(FrontMatterError::ReservedValue(_))
    ));

    // A fully-governed `payment-adjacent` change merges and yields the accepted class.
    assert_eq!(
        front_matter::enforce("payment-adjacent", &full).unwrap(),
        PaymentBoundaryClass::PaymentAdjacent
    );

    // The same value fails the *authoring* gate when the council/authority is missing — proving
    // enforce chains parse -> authorize (not just parse).
    let junior = AuthoringContext {
        author_ad_level: 5,
        ..full.clone()
    };
    assert_eq!(
        front_matter::enforce("payment-adjacent", &junior).unwrap_err(),
        FrontMatterError::InsufficientAuthorAuthority {
            ad_level: 5,
            max: 3
        }
    );

    // `none` merges with no extra authority (the unimpeded common case).
    let bare = AuthoringContext {
        payments_council_approved: false,
        commit_signed: false,
        author_can_approve: false,
        author_ad_level: 6,
    };
    assert_eq!(
        front_matter::enforce("", &bare).unwrap(),
        PaymentBoundaryClass::None
    );
}

// ---------------------------------------------------------------------------
// IDN-09 — Layer-6 graduated tripwire response on a mis-declared payment call.
// ---------------------------------------------------------------------------
#[test]
fn r11_tripwire_graduated_response() {
    let guard = EgressGuard::default();
    let allow = guard.new_allow_list();

    // A capability declared SideEffecting but its *actual* call is a UPI collect (value movement)
    // to a settlement endpoint — the scenario-2 mis-declaration.
    let call = OutboundCall {
        destination: "https://upi-settlement.example.internal/collect".into(),
        resource_key: "settlement-account:9001".into(),
        payload: PayloadSignal::Upi(UpiOperation::Collect),
    };

    // A benign allow-list miss is NOT escalated to a graduated response.
    let benign = OutboundCall::read("https://internal.tools/health", "svc:health");
    match guard.screen_with_response(&benign, &allow, "turn-1", "cap-x", "ainxt-id://run/1") {
        Err(Ok(_not_allow_listed)) => {}
        other => panic!("expected a plain allow-list denial, got {other:?}"),
    }

    // The payment-initiation attempt yields the full ordered graduated response.
    let resp = match guard.screen_with_response(
        &call,
        &allow,
        "turn-42",
        "cap-settle",
        "ainxt-id://ainxt/agent/role/coder/v3/run/r-9",
    ) {
        Err(Err(resp)) => resp,
        other => panic!("expected a graduated tripwire response, got {other:?}"),
    };

    // Exactly four escalation directives, in order: abort -> quarantine -> revoke -> incident.
    assert_eq!(resp.actions.len(), 4);
    assert!(matches!(resp.actions[0], TripwireAction::AbortTurn { .. }));
    assert!(matches!(
        resp.actions[1],
        TripwireAction::QuarantineCapability { .. }
    ));
    assert!(matches!(
        resp.actions[2],
        TripwireAction::RevokeActingIdentity { .. }
    ));
    match &resp.actions[3] {
        TripwireAction::RaiseIncident { reasons, .. } => {
            // The incident carries WHY it tripped — perimeter + resource-key + UPI value op.
            assert!(reasons.contains(&InitiationReason::SettlementPerimeterDestination));
            assert!(reasons.contains(&InitiationReason::SettlementResourceKey));
            assert!(reasons.contains(&InitiationReason::UpiValueOperation));
        }
        other => panic!("expected RaiseIncident last, got {other:?}"),
    }
    assert_eq!(resp.quarantined_capability(), Some("cap-settle"));
    assert_eq!(
        resp.revoked_identity(),
        Some("ainxt-id://ainxt/agent/role/coder/v3/run/r-9")
    );
}

// ---------------------------------------------------------------------------
// IDN-10 — settlement perimeter + signature list as a git-controlled policy.
// ---------------------------------------------------------------------------
#[test]
fn r11_settlement_policy_git_controlled() {
    // The baseline policy is a serialisable artifact; round-trips through JSON (loaded from git).
    let base = SettlementPolicy::default_baseline("sha-aaa");
    let json = serde_json::to_string(&base).unwrap();
    let reloaded: SettlementPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(reloaded, base);

    // The policy *builds* the enforcement boundary; that boundary screens exactly like payment_default().
    let from_policy = base.build_boundary();
    let native = PaymentBoundary::payment_default();
    let upi = OutboundCall {
        destination: "https://upi-settlement.example.internal/collect".into(),
        resource_key: "settlement-account:1".into(),
        payload: PayloadSignal::Upi(UpiOperation::Collect),
    };
    assert!(from_policy.classify(&upi).is_initiating());
    assert!(native.classify(&upi).is_initiating());

    let full_gov = PolicyGovernance {
        payments_council_approved: true,
        security_council_approved: true,
        commit_signed: true,
        author_can_approve: true,
        author_ad_level: 3,
    };

    // A governed edit that ADDS a new rail (reserve-only) is authorized and bumps the version.
    let mut next = base.clone();
    next.perimeter_patterns.insert("newrail-settlement.".into());
    next.control_commit_sha = "sha-bbb".into();
    let applied = base.authorize_edit(&next, &full_gov).unwrap();
    assert_eq!(applied.version, base.version + 1);
    assert_eq!(applied.control_commit_sha, "sha-bbb");
    assert!(applied
        .build_boundary()
        .perimeter()
        .contains("https://newrail-settlement.bank/x"));

    // Removing a reserved pattern is refused (one-way ratchet, §4.4) even with full governance.
    let mut shrink = base.clone();
    let dropped = base.perimeter_patterns.iter().next().unwrap().clone();
    shrink.perimeter_patterns.remove(&dropped);
    assert!(matches!(
        base.authorize_edit(&shrink, &full_gov),
        Err(PolicyEditError::PerimeterRemovalForbidden { .. })
    ));

    // Missing the SECURITY council is refused (this is the dual-council artifact).
    let no_sec = PolicyGovernance {
        security_council_approved: false,
        ..full_gov.clone()
    };
    assert_eq!(
        base.authorize_edit(&next, &no_sec).unwrap_err(),
        PolicyEditError::MissingSecurityCouncilApproval
    );
    // Missing the payments council is refused too.
    let no_pay = PolicyGovernance {
        payments_council_approved: false,
        ..full_gov.clone()
    };
    assert_eq!(
        base.authorize_edit(&next, &no_pay).unwrap_err(),
        PolicyEditError::MissingPaymentsCouncilApproval
    );
    // Too-junior editor is refused.
    let junior = PolicyGovernance {
        author_ad_level: 4,
        ..full_gov.clone()
    };
    assert!(matches!(
        base.authorize_edit(&next, &junior),
        Err(PolicyEditError::InsufficientAuthorAuthority {
            ad_level: 4,
            max: 3
        })
    ));
}

// ---------------------------------------------------------------------------
// IDN-04 — PAM as the FOURTH dispatch gate, on top of OBO, never a substitute.
// ---------------------------------------------------------------------------
#[test]
fn r11_pam_fourth_gate_on_top_of_obo() {
    let request = PamRequest::single_use(
        "settlement:simulate",
        "netting-batch:B-42",
        "run-analyst-1",
        100,
    );
    let pam = PaymentAdjacentMandate::issue("m1", &request, "u-exec", 2, true, 1).unwrap();
    let mut reg = MandateRegistry::new();

    let pass = OboOutcome {
        identity_ok: true,
        delegation_ok: true,
        authz_ok: true,
    };
    let authz_fail = OboOutcome {
        authz_ok: false,
        ..pass
    };

    // A failed OBO layer denies — and CRUCIALLY does not consume the single-use PAM (no self-DoS).
    match authorize_adjacent_dispatch(
        &mut reg,
        authz_fail,
        &pam,
        "settlement:simulate",
        "netting-batch:B-42",
        "run-analyst-1",
        5,
    ) {
        Err(AdjacentDispatchDenied::Obo(o)) => assert!(!o.authz_ok),
        other => panic!("expected OBO denial, got {other:?}"),
    }
    assert_eq!(
        reg.uses_consumed("m1"),
        0,
        "a failed OBO must not burn the PAM"
    );

    // OBO passes but the PAM is out of scope -> the fourth gate denies (PAM cannot rescue nothing,
    // and equally OBO cannot rescue a bad PAM).
    match authorize_adjacent_dispatch(
        &mut reg,
        pass,
        &pam,
        "settlement:release", // wrong verb
        "netting-batch:B-42",
        "run-analyst-1",
        5,
    ) {
        Err(AdjacentDispatchDenied::Pam(PamError::WrongAction { .. })) => {}
        other => panic!("expected PAM WrongAction, got {other:?}"),
    }
    assert_eq!(reg.uses_consumed("m1"), 0);

    // All four gates satisfied -> authorized, exactly once.
    assert!(authorize_adjacent_dispatch(
        &mut reg,
        pass,
        &pam,
        "settlement:simulate",
        "netting-batch:B-42",
        "run-analyst-1",
        5,
    )
    .is_ok());
    assert_eq!(reg.uses_consumed("m1"), 1);

    // The single-use PAM is now spent — even a perfect OBO cannot replay it.
    assert!(matches!(
        authorize_adjacent_dispatch(
            &mut reg,
            pass,
            &pam,
            "settlement:simulate",
            "netting-batch:B-42",
            "run-analyst-1",
            6,
        ),
        Err(AdjacentDispatchDenied::Pam(PamError::Exhausted { .. }))
    ));
}
