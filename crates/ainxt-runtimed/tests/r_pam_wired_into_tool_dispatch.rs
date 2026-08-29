// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX identity-payments (ADR-016 §6) — the Payment-Adjacent Mandate (PAM) fourth dispatch gate
//! is now REACHABLE from the served tool-dispatch path, not merely built-and-tested inside
//! `ainxt-payments`.
//!
//! Before this fix: `ainxt_payments::mandate::{authorize_adjacent_dispatch, MandateRegistry}` and
//! `AssembledFull::authorize_payment_adjacent_dispatch` (the served entrypoint on the composition
//! root) existed and were unit-tested, but NOTHING on the served tool/connector dispatch path ever
//! called them — a capability declared payment-adjacent had no enforcement at all on the actual
//! `ToolRuntime::dispatch`/`dispatch_obo`/`dispatch_obo_audited` family every OTHER dispatch gate
//! (the apex `EffectClass::PaymentInitiating` type check, the registration refusal, the §1.7 egress
//! deny-list) is already enforced through.
//!
//! This test drives the REAL, unmodified functions: [`ainxt_tools::Tool::payment_adjacent_action`],
//! [`ainxt_tools::ToolRuntime::with_mandate_registry`], [`ainxt_tools::ToolRuntime::execute_dispatch_core`]
//! (via the public `dispatch`/`dispatch_obo`/`dispatch_obo_with_pam`/`dispatch_obo_audited_with_pam`
//! entrypoints — the EXACT choke point the apex payment-boundary check and the §1.7 egress deny-list
//! already run through), and [`ainxt_runtimed::build_unified_capability_registry_shared`] (the exact
//! function `ainxt-runtimed`'s composition root calls to build the served Capability registry). The
//! one thing this test supplies that the shipped daemon does not YET ship is a payment-adjacent
//! CAPABILITY itself (the daemon currently registers zero — `query_ledger`/`federated_query`/
//! `structured_query` are all ordinary reads) — exactly the same "wired, real, and fail-closed but
//! currently guarding an empty/deployment-supplied set" posture this file already uses for
//! `egress_allowlist`/`hooks` (see `ToolRuntime::with_egress_allowlist`'s own doc comment).
//!
//! A second test proves the composition-root SHARING contract directly through the REAL, completely
//! unmodified `assemble`/`assemble_full` functions (no test-fixture capability needed at all): the
//! `Assembled::mandate_registry` a caller clones out BEFORE `assemble_full` consumes it is the
//! IDENTICAL `Arc` `AssembledFull::authorize_payment_adjacent_dispatch` mutates — never a second,
//! disjoint registry minted independently inside `assemble_full`.

use std::sync::{Arc, Mutex};

use ainxt_payments::mandate::{
    AdjacentDispatchDenied, MandateRegistry, OboOutcome, PamError, PamRequest,
    PaymentAdjacentMandate,
};
use ainxt_runtimed::{assemble, assemble_full, load_layered};
use ainxt_tools::obo::{Grant, MapAbac, OboContext, ThreeLayerPolicy};
use ainxt_tools::{DispatchResult, EffectClass, Tool, ToolError};
use ainxt_types::DataClass;

/// A test-fixture payment-adjacent capability — "simulate a settlement against a sandbox" (ADR-016
/// §6's own example, and the exact verb/resource `ainxt-payments::mandate`'s own unit tests use).
/// `Idempotent` (a repeatable projection, no exactly-once ledger needed) — deliberately NOT
/// `PaymentInitiating` (this capability cannot move value; the PAM gate is a SEPARATE, additional
/// check on top of the ordinary effect-class dispatch path, exactly as ADR-016 §6 mandates).
struct SettlementSimulateTestTool;
impl Tool for SettlementSimulateTestTool {
    fn name(&self) -> &str {
        "settlement.simulate"
    }
    fn effect_class(&self) -> EffectClass {
        EffectClass::Idempotent
    }
    fn resource(&self, _args: &str) -> Option<String> {
        Some("netting-batch:B-42".to_string())
    }
    fn payment_adjacent_action(&self, _args: &str) -> Option<(String, String)> {
        Some((
            "settlement:simulate".to_string(),
            "netting-batch:B-42".to_string(),
        ))
    }
    fn execute(&self, args: &str) -> Result<String, ToolError> {
        Ok(format!("simulated-settlement-projection:{args}"))
    }
}

fn full_grant_ctx() -> OboContext {
    OboContext::new(
        "u-analyst",
        vec![Grant::new("settlement.simulate", "*", "execute")],
        ["settlement.simulate".to_string()],
        DataClass::RegulatedPayment,
    )
}

fn no_grant_ctx() -> OboContext {
    OboContext::new("u-analyst", vec![], [], DataClass::Internal)
}

fn policy() -> ThreeLayerPolicy<MapAbac> {
    ThreeLayerPolicy::new(MapAbac::new().with("netting-batch:B-42", DataClass::RegulatedPayment))
}

fn build_registry_with_pam_capability(
) -> (Arc<ainxt_tools::ToolRuntime>, Arc<Mutex<MandateRegistry>>) {
    let mut report = Vec::new();
    // The EXACT function `ainxt-runtimed`'s composition root calls to build the served Capability
    // registry (`build_engine_ext`/`build_chat_engine_with_authz` both call this verbatim).
    let (mut registry, _ledger, _reconciler) =
        ainxt_runtimed::build_unified_capability_registry_shared(&mut report);
    registry
        .try_register_governed(Box::new(SettlementSimulateTestTool))
        .expect("an Idempotent capability registers cleanly");
    // The EXACT two lines `build_engine_ext`/`build_chat_engine_with_authz` now run (GAP-FIX
    // identity-payments) before wrapping the registry in the shared `Arc`.
    let mandate_registry = Arc::new(Mutex::new(MandateRegistry::new()));
    let registry = registry.with_mandate_registry(mandate_registry.clone());
    (Arc::new(registry), mandate_registry)
}

#[test]
fn plain_dispatch_and_dispatch_obo_fail_closed_for_a_payment_adjacent_capability_with_no_pam_seam()
{
    let (tools, _mandate_registry) = build_registry_with_pam_capability();

    // The unattributed, no-OBO entrypoint: fails closed regardless of OBO — the fourth gate is
    // checked inside `execute_dispatch_core`, the SAME choke point every dispatch path reaches.
    let plain = tools.dispatch("settlement.simulate", "{}");
    assert!(
        matches!(plain, DispatchResult::Blocked(ref m) if m.contains("PaymentAdjacentMandate")),
        "dispatch() must fail closed for a payment-adjacent capability with no PAM seam: {plain:?}"
    );

    // The three-layer-OBO entrypoint WITHOUT the PAM-aware variant: OBO alone is never sufficient —
    // "a fourth gate... never a substitute for the first three" cuts both directions.
    let obo_only = tools.dispatch_obo(
        &full_grant_ctx(),
        &policy(),
        "settlement.simulate",
        "{}",
        "execute",
    );
    assert!(
        matches!(obo_only, DispatchResult::Blocked(ref m) if m.contains("dispatch_obo_with_pam")),
        "dispatch_obo() (no PAM parameter at all) must still fail closed: {obo_only:?}"
    );
}

#[test]
fn dispatch_obo_with_pam_requires_a_presented_mandate_even_on_the_pam_aware_entrypoint() {
    let (tools, mandate_registry) = build_registry_with_pam_capability();
    let missing_pam = tools.dispatch_obo_with_pam(
        &full_grant_ctx(),
        &policy(),
        "settlement.simulate",
        "{}",
        "execute",
        None,
        "run-analyst-1",
        5,
    );
    assert!(
        matches!(missing_pam, DispatchResult::Blocked(ref m) if m.contains("requires a presented")),
        "the PAM-aware entrypoint with pam=None must still refuse: {missing_pam:?}"
    );
    assert_eq!(mandate_registry.lock().unwrap().uses_consumed("m1"), 0);
}

#[test]
fn a_valid_pam_authorizes_exactly_once_then_is_exhausted() {
    let (tools, mandate_registry) = build_registry_with_pam_capability();
    let pam = PaymentAdjacentMandate::issue(
        "m1",
        &PamRequest::single_use(
            "settlement:simulate",
            "netting-batch:B-42",
            "run-analyst-1",
            100,
        ),
        "u-exec",
        2,
        true,
        1,
    )
    .expect("a senior approving human may sign a PAM");

    let first = tools.dispatch_obo_with_pam(
        &full_grant_ctx(),
        &policy(),
        "settlement.simulate",
        "{}",
        "execute",
        Some(&pam),
        "run-analyst-1",
        5,
    );
    assert!(
        matches!(first, DispatchResult::Ok(_)),
        "OBO pass + a valid, in-scope, unexhausted PAM must authorize dispatch: {first:?}"
    );
    assert_eq!(
        mandate_registry.lock().unwrap().uses_consumed("m1"),
        1,
        "the fourth gate must consume the use on the SAME registry `with_mandate_registry` installed"
    );

    // A single-use PAM cannot fire twice (no replay) — the audited entrypoint too.
    let second = tools.dispatch_obo_audited_with_pam(
        &full_grant_ctx(),
        &policy(),
        &ainxt_tools::obo::NoOboAudit,
        "settlement.simulate",
        "{}",
        "execute",
        Some(&pam),
        "run-analyst-1",
        6,
    );
    assert!(
        matches!(
            second,
            DispatchResult::Blocked(ref m) if m.contains("exhausted")
        ),
        "a single-use PAM must not authorize a second dispatch: {second:?}"
    );
}

#[test]
fn an_obo_denial_short_circuits_before_the_pam_is_even_consulted_no_self_dos() {
    let (tools, mandate_registry) = build_registry_with_pam_capability();
    let pam = PaymentAdjacentMandate::issue(
        "m-no-self-dos",
        &PamRequest::single_use(
            "settlement:simulate",
            "netting-batch:B-42",
            "run-analyst-1",
            100,
        ),
        "u-exec",
        2,
        true,
        1,
    )
    .unwrap();

    // No grant at all ⇒ the three-layer OBO gate denies BEFORE the PAM is ever touched.
    let denied = tools.dispatch_obo_with_pam(
        &no_grant_ctx(),
        &policy(),
        "settlement.simulate",
        "{}",
        "execute",
        Some(&pam),
        "run-analyst-1",
        5,
    );
    assert!(
        matches!(denied, DispatchResult::Blocked(_)),
        "an OBO denial must still refuse even with a perfectly valid PAM presented: {denied:?}"
    );
    assert_eq!(
        mandate_registry
            .lock()
            .unwrap()
            .uses_consumed("m-no-self-dos"),
        0,
        "a failed OBO gate must NEVER burn a single-use PAM's use-count (no self-DoS)"
    );

    // The SAME pam, now through a passing OBO context, authorizes normally — proving the prior
    // denial truly never touched the registry.
    let ok = tools.dispatch_obo_with_pam(
        &full_grant_ctx(),
        &policy(),
        "settlement.simulate",
        "{}",
        "execute",
        Some(&pam),
        "run-analyst-1",
        5,
    );
    assert!(
        matches!(ok, DispatchResult::Ok(_)),
        "the untouched PAM must still be usable: {ok:?}"
    );
}

/// Direct unit-level proof of the ordering + composed-gate semantics at the `ainxt-payments` level
/// (mirrors the crate's OWN doc contract) — included here to pin the exact `AdjacentDispatchDenied`
/// shape the dispatch-path `DispatchResult::Blocked(..)` messages above are derived from.
#[test]
fn authorize_adjacent_dispatch_denial_shapes_match_what_the_dispatch_path_surfaces() {
    let mut reg = MandateRegistry::new();
    let pam = PaymentAdjacentMandate::issue(
        "m2",
        &PamRequest::single_use("settlement:simulate", "netting-batch:B-42", "run-1", 100),
        "u-exec",
        1,
        true,
        1,
    )
    .unwrap();
    let obo_fail = OboOutcome {
        identity_ok: false,
        delegation_ok: true,
        authz_ok: true,
    };
    assert!(matches!(
        ainxt_payments::mandate::authorize_adjacent_dispatch(
            &mut reg,
            obo_fail,
            &pam,
            "settlement:simulate",
            "netting-batch:B-42",
            "run-1",
            5
        ),
        Err(AdjacentDispatchDenied::Obo(_))
    ));
    let obo_pass = OboOutcome {
        identity_ok: true,
        delegation_ok: true,
        authz_ok: true,
    };
    assert!(matches!(
        ainxt_payments::mandate::authorize_adjacent_dispatch(
            &mut reg,
            obo_pass,
            &pam,
            "settlement:simulate",
            "wrong-batch",
            "run-1",
            5
        ),
        Err(AdjacentDispatchDenied::Pam(PamError::WrongResource { .. }))
    ));
}

/// GAP-FIX identity-payments — the COMPOSITION-ROOT sharing contract, proven through the REAL,
/// completely unmodified [`assemble`]/[`assemble_full`] functions (no test-fixture capability
/// needed): `Assembled::mandate_registry`, cloned out BEFORE `assemble_full` consumes `Assembled`, is
/// the IDENTICAL `Arc<Mutex<MandateRegistry>>` `AssembledFull::authorize_payment_adjacent_dispatch`
/// mutates — never a second, disjoint registry `assemble_full` mints for itself independently.
#[test]
fn assembled_and_assembled_full_share_the_identical_mandate_registry() {
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let loaded = load_layered(&[("x", "version = 1")]).unwrap();
    let assembled = assemble(&loaded).expect("bare engine surface assembles");
    // Cloned out BEFORE `assemble_full` consumes `assembled` by value.
    let mandate_registry_handle = assembled.mandate_registry.clone();
    let full =
        assemble_full(&loaded, assembled).expect("assemble_full assembles the served surface");

    let pam = PaymentAdjacentMandate::issue(
        "m-shared",
        &PamRequest::single_use(
            "settlement:simulate",
            "netting-batch:B-42",
            "run-shared-1",
            100,
        ),
        "u-exec",
        1,
        true,
        1,
    )
    .unwrap();
    let obo = OboOutcome {
        identity_ok: true,
        delegation_ok: true,
        authz_ok: true,
    };
    full.authorize_payment_adjacent_dispatch(
        obo,
        &pam,
        "settlement:simulate",
        "netting-batch:B-42",
        "run-shared-1",
        5,
    )
    .expect("a valid OBO+PAM authorizes through the served entrypoint");

    // The use is visible on the INDEPENDENTLY-HELD handle cloned before `assemble_full` ran — proof
    // this is the SAME Arc, not a second registry `assemble_full` built for itself.
    assert_eq!(
        mandate_registry_handle
            .lock()
            .unwrap()
            .uses_consumed("m-shared"),
        1,
        "AssembledFull::authorize_payment_adjacent_dispatch must mutate the EXACT SAME registry \
         Assembled::mandate_registry already exposed, never a second, disjoint one"
    );
}
