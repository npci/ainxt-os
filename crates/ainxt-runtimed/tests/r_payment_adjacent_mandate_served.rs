// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX regulated-fi-responsible-lifecycle (ADR-016 §6) — the Payment-Adjacent Mandate (PAM)
//! fourth dispatch gate (`ainxt_payments::mandate::authorize_adjacent_dispatch`) was fully implemented
//! and unit-tested but had zero callers anywhere in the served path: `AssembledFull` never held a
//! `MandateRegistry`, so a deployment had no served entrypoint to check a PAM at dispatch. Proves
//! `AssembledFull::authorize_payment_adjacent_dispatch` drives the SAME fourth-gate behavior — never a
//! substitute for OBO, single-use burned exactly once, a failed OBO layer never burns the PAM.

use ainxt_payments::mandate::{
    AdjacentDispatchDenied, OboOutcome, PamError, PamRequest, PaymentAdjacentMandate,
};
use ainxt_runtimed::{assemble_chat, assemble_full, load_layered};

fn full() -> ainxt_runtimed::AssembledFull {
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let loaded = load_layered(&[("base", "version = 1")]).unwrap();
    let assembled = assemble_chat(&loaded).unwrap();
    assemble_full(&loaded, assembled).unwrap()
}

#[test]
fn r_pam_fourth_gate_reachable_from_the_served_composition_root() {
    let f = full();
    let request = PamRequest::single_use(
        "settlement:simulate",
        "netting-batch:B-42",
        "run-analyst-1",
        100,
    );
    let pam = PaymentAdjacentMandate::issue("m1", &request, "u-exec", 2, true, 1).unwrap();

    let pass = OboOutcome {
        identity_ok: true,
        delegation_ok: true,
        authz_ok: true,
    };
    let authz_fail = OboOutcome {
        authz_ok: false,
        ..pass
    };

    // A failed OBO layer denies and does NOT burn the single-use PAM (no self-DoS).
    match f.authorize_payment_adjacent_dispatch(
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

    // OBO passes but the PAM is out of scope (wrong verb) — the fourth gate still denies.
    match f.authorize_payment_adjacent_dispatch(
        pass,
        &pam,
        "settlement:release",
        "netting-batch:B-42",
        "run-analyst-1",
        5,
    ) {
        Err(AdjacentDispatchDenied::Pam(PamError::WrongAction { .. })) => {}
        other => panic!("expected PAM WrongAction, got {other:?}"),
    }

    // All four gates satisfied on the SAME served registry — authorized, exactly once.
    assert!(f
        .authorize_payment_adjacent_dispatch(
            pass,
            &pam,
            "settlement:simulate",
            "netting-batch:B-42",
            "run-analyst-1",
            5,
        )
        .is_ok());

    // The single-use PAM is now spent on the served registry — even a perfect OBO cannot replay it.
    assert!(matches!(
        f.authorize_payment_adjacent_dispatch(
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
