// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Integration wiring test for IDN-07: the control-plane CI / pre-receive gate must parse each
//! definition's `payment_boundary` front-matter and REJECT the reserved `payment-initiating` value
//! so it can never merge (ADR-026 §5), then run the pre-receive PII/secret gate.
//!
//! This constructs the REAL assembled objects — `ainxt_governance::publish` → `PullRequest`, the
//! real `PaymentBoundaryClass::parse` / `authorize_authoring` policy core (re-exported from
//! `ainxt-payments`), and the real `MarkerPrereceiveGate` — and drives them through the wired
//! `gate_control_plane_push` entrypoint. Before the wire this call-site did not exist, so nothing
//! parsed the front-matter on the governance path; this test could not compile.

use ainxt_governance::{
    gate_control_plane_push, publish, AuthoringContext, CiGateError, FrontMatterError,
    MarkerPrereceiveGate, PaymentBoundaryClass, PublishRequest,
};

fn full_authoring() -> AuthoringContext {
    AuthoringContext {
        payments_council_approved: true,
        commit_signed: true,
        author_can_approve: true,
        author_ad_level: 3,
    }
}

fn pr_with(content: &str) -> ainxt_governance::PullRequest {
    publish(PublishRequest {
        definition_id: "harness.settlement".into(),
        branch: "publish/harness.settlement".into(),
        path: "harnesses/settlement.yml".into(),
        content: content.into(),
    })
}

#[test]
fn wire_idn_07() {
    let authoring = full_authoring();

    // 1. The reserved `payment-initiating` value is REJECTED on the CI gate — it can never merge.
    let reserved = pr_with("id: settlement\npayment_boundary: payment-initiating\n");
    match gate_control_plane_push(&reserved, &MarkerPrereceiveGate, &authoring) {
        Err(CiGateError::FrontMatter {
            error: FrontMatterError::ReservedValue(v),
            ..
        }) => assert_eq!(v, "payment-initiating"),
        other => panic!("payment-initiating must be rejected, got {other:?}"),
    }

    // Case/space-insensitive so it cannot be smuggled past the gate.
    let smuggled = pr_with("payment_boundary:   Payment-Initiating   \n");
    assert!(matches!(
        gate_control_plane_push(&smuggled, &MarkerPrereceiveGate, &authoring),
        Err(CiGateError::FrontMatter {
            error: FrontMatterError::ReservedValue(_),
            ..
        })
    ));

    // 2. A benign `payment_boundary: none` definition passes and reports its class.
    let clean = pr_with("id: rca\npayment_boundary: none\ndescription: safe\n");
    let classes = gate_control_plane_push(&clean, &MarkerPrereceiveGate, &authoring)
        .expect("a `none` definition must pass the gate");
    assert_eq!(classes[0].1, PaymentBoundaryClass::None);

    // Missing front-matter defaults to the safe `None` class (not a silent failure).
    let missing = pr_with("id: rca\ndescription: no boundary field\n");
    let classes = gate_control_plane_push(&missing, &MarkerPrereceiveGate, &authoring)
        .expect("absent front-matter defaults to None");
    assert_eq!(classes[0].1, PaymentBoundaryClass::None);

    // 3. A `payment-adjacent` definition is authorized only with council + signed senior commit.
    let adjacent = pr_with("payment_boundary: payment-adjacent\n");
    assert_eq!(
        gate_control_plane_push(&adjacent, &MarkerPrereceiveGate, &full_authoring())
            .expect("fully-authorized adjacent authoring passes")[0]
            .1,
        PaymentBoundaryClass::PaymentAdjacent
    );

    let no_council = AuthoringContext {
        payments_council_approved: false,
        ..full_authoring()
    };
    assert!(matches!(
        gate_control_plane_push(&adjacent, &MarkerPrereceiveGate, &no_council),
        Err(CiGateError::FrontMatter {
            error: FrontMatterError::MissingPaymentsCouncilApproval,
            ..
        })
    ));

    let junior = AuthoringContext {
        author_ad_level: 5,
        ..full_authoring()
    };
    assert!(matches!(
        gate_control_plane_push(&adjacent, &MarkerPrereceiveGate, &junior),
        Err(CiGateError::FrontMatter {
            error: FrontMatterError::InsufficientAuthorAuthority { .. },
            ..
        })
    ));

    // 4. The pre-receive PII/secret gate still runs after front-matter passes (blocks, never redacts).
    let leaky = pr_with("payment_boundary: none\ntoken PAN=4111111111111111\n");
    assert!(matches!(
        gate_control_plane_push(&leaky, &MarkerPrereceiveGate, &authoring),
        Err(CiGateError::Prereceive { .. })
    ));
}

/// GAP-FIX payments-governance: `gate_control_plane_push` used to iterate `pr.files` with a per-file
/// `?`-early-return, so on a push carrying MULTIPLE bad definitions it silently reported only the
/// FIRST offender — an author would fix that one, resubmit, and only then learn about the second,
/// one reject-fix-resubmit cycle per bad file. It now delegates to
/// `ainxt_payments::front_matter::evaluate_changeset`, documented as "the single call the git
/// pre-receive hook and CI job both make" specifically so a whole push names EVERY offender in one
/// pass. This proves the specific case the old inline version could not express: two bad files in one
/// push are BOTH named (one as the primary error, the other in `also_blocked`), and the one clean file
/// in the same push is named in neither.
#[test]
fn wire_batch_push_reports_every_offending_file_not_just_the_first() {
    let pr = ainxt_governance::PullRequest {
        branch: "publish/batch".into(),
        target: "main".into(),
        title: "batch publish".into(),
        body: String::new(),
        files: vec![
            (
                "roles/a.yml".into(),
                "payment_boundary: payment-initiating\n".into(),
            ),
            (
                "roles/b.yml".into(),
                "payment_boundary: payment-initiating\n".into(),
            ),
            ("roles/c.yml".into(), "payment_boundary: none\n".into()),
        ],
    };
    match gate_control_plane_push(&pr, &MarkerPrereceiveGate, &full_authoring()) {
        Err(CiGateError::FrontMatter {
            path,
            error: FrontMatterError::ReservedValue(_),
            also_blocked,
        }) => {
            assert_eq!(
                path, "roles/a.yml",
                "the first offender is still the primary error"
            );
            assert_eq!(
                also_blocked.len(),
                1,
                "the SECOND offender must ride along, not be silently dropped"
            );
            assert_eq!(also_blocked[0].path, "roles/b.yml");
            assert!(matches!(
                also_blocked[0].error,
                FrontMatterError::ReservedValue(_)
            ));
            // The clean file (c.yml) is named in neither slot.
            assert_ne!(path, "roles/c.yml");
            assert!(also_blocked.iter().all(|b| b.path != "roles/c.yml"));
        }
        other => panic!("expected BOTH offending files named, got {other:?}"),
    }
}
