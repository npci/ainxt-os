// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX identity-payments (ADR-016 §3.3/§4 Layer 3, `docs/architecture/
//! AGENT_IDENTITY_AND_PAYMENT_BOUNDARY.md` §3.3) — the OBO grant vocabulary must have **no word** for
//! `PaymentInitiating`: even a fully-privileged human's OBO context must not be able to carry the
//! authority to dispatch a payment-initiating capability, because the authority is not representable
//! in the grant schema at all.
//!
//! Before this fix, `Grant` was a bare `{capability, resource_pattern, action}` string tuple with NO
//! effect-class awareness, and `ThreeLayerPolicy::authorize` checked only the three declared layers
//! (grant / issued-scope / resource ABAC) — so a wildcard grant `Grant::new("*", "*", "*")` would
//! technically "cover" a payment-initiating capability name. The only thing stopping an actual dispatch
//! was Layer 2 (`ToolRuntime::register` refusing to admit a `PaymentInitiating`-classed tool) — which
//! means Layer 3 was NOT an independent structural denial, contrary to the design's "five independent
//! structural denials, each individually sufficient" requirement (§3): if a payment-signature
//! capability ever reached the policy engine through a path that does not go through
//! `ToolRuntime::register` (a different admission surface, a future registry bug), the grant
//! vocabulary itself had nothing that would refuse it.
//!
//! This test proves the fix operates entirely at the **policy** layer, independent of tool
//! registration: no `Tool` matching the payment-initiation signature is ever registered on the
//! `ToolRuntime` in this test (proving Layer 2 is not what is being exercised) — the denial must come
//! from `ThreeLayerPolicy::authorize` itself, even against a maximally-privileged `OboContext`.

use ainxt_tools::obo::{Grant, MapAbac, OboContext, OboDenial, OboPolicy, ThreeLayerPolicy};
use ainxt_types::DataClass;

fn maximally_privileged_ctx(capability: &str) -> OboContext {
    OboContext::new(
        "root-admin",
        // A wildcard grant covering ANY capability, ANY resource, ANY action.
        vec![Grant::new("*", "*", "*")],
        // A full issued scope covering the exact capability name.
        [capability.to_string()],
        // The highest data-class clearance.
        DataClass::RegulatedPayment,
    )
}

#[test]
fn gap_idn_layer3_payment_signature_capability_denied_despite_wildcard_grant() {
    let policy = ThreeLayerPolicy::new(MapAbac::new().with_default(DataClass::Internal));

    for capability in [
        "connector.rails.initiate_payment",
        "connector.rails.wire_transfer",
        "connector.rails.fund_transfer",
        "connector.rails.credit_transfer",
        "connector.rails.disburse",
        "connector.rails.remittance",
        "connector.rails.settlement_instruction",
        "connector.rails.move_money",
    ] {
        let ctx = maximally_privileged_ctx(capability);
        let verdict = policy.authorize(&ctx, capability, Some("any-resource"), "execute");
        assert_eq!(
            verdict,
            Err(OboDenial::PaymentInitiatingNotRepresentable(capability.to_string())),
            "capability '{capability}' must be denied by the grant vocabulary itself, regardless of \
             a wildcard grant / full issued scope / max clearance"
        );
    }
}

#[test]
fn gap_idn_layer3_denial_precedes_all_three_declared_layers() {
    // Even a context with EMPTY grants/scope/clearance still gets the SAME payment-signature denial
    // (not a "NoGrant"/"OutOfIssuedScope" denial) — proving the check runs strictly before, and
    // independent of, layers 1-3, so the specific reason a regulator sees is always "unrepresentable",
    // not "insufficiently privileged" (which would wrongly imply a bigger grant could fix it).
    let policy = ThreeLayerPolicy::new(MapAbac::new());
    let empty_ctx = OboContext::new("nobody", vec![], Vec::<String>::new(), DataClass::Public);

    let verdict = policy.authorize(&empty_ctx, "wire_transfer.execute", None, "execute");
    assert_eq!(
        verdict,
        Err(OboDenial::PaymentInitiatingNotRepresentable(
            "wire_transfer.execute".to_string()
        ))
    );
}

#[test]
fn gap_idn_layer3_non_payment_capability_still_uses_the_normal_three_layers() {
    // Sanity: an ordinary capability name is NOT swept up by the new check — it falls through to the
    // normal layer-1 grant check and is denied for the ordinary (expected) reason.
    let policy = ThreeLayerPolicy::new(MapAbac::new());
    let empty_ctx = OboContext::new("nobody", vec![], Vec::<String>::new(), DataClass::Public);

    let verdict = policy.authorize(
        &empty_ctx,
        "connector.postgres.query",
        Some("table"),
        "read",
    );
    assert_eq!(
        verdict,
        Err(OboDenial::NoGrant {
            capability: "connector.postgres.query".to_string(),
            resource: Some("table".to_string()),
            action: "read".to_string(),
        })
    );
}
