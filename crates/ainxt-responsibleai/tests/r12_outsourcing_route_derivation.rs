// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R12 gap (medium): "Outsourcing register gates only providers that self-declare an outsourcing_route
//! id; the router guard is Option (default None off-daemon)."
//!
//! The self-declaration reliance is fail-OPEN: a cloud provider whose adapter forgot to return
//! `Some(route_id)` from `outsourcing_route()` slips past the register as if it were in-house. The
//! register-side closure is [`derive_route_id`] — a deterministic `outsourcing.cloud.<id>` derivation the
//! served assembly applies to EVERY cloud-kind provider so external-ness is by construction, not by an
//! adapter's memory. This test proves (a) the canonical derivation and (b) that a derived-but-unregistered
//! cloud route is fail-closed EXCLUDED, while a registered one is admitted.
//!
//! `needs_hot_wiring`: the two remaining call-sites are in RESERVED crates — `ainxt-runtimed::build_provider`
//! must stamp `derive_route_id(id)` onto every cloud provider, and the `ainxt-runtime` `ModelRouter`'s
//! `Option<OutsourcingGuard>` must default to a fail-closed empty register (not `None`) off-daemon.

use ainxt_responsibleai::outsourcing::{
    derive_route_id, Eligibility, ExitRehearsal, OutsourcingArrangement, OutsourcingRegister,
    SubProcessor, OUTSOURCING_ROUTE_PREFIX,
};
use ainxt_types::DataClass;

#[test]
fn r12_derived_route_id_is_canonical_and_unregistered_is_fail_closed() {
    // (a) Canonical derivation: cloud provider id → register route id.
    assert_eq!(
        derive_route_id("anthropic-sonnet"),
        "outsourcing.cloud.anthropic-sonnet"
    );
    assert!(derive_route_id("openai-gpt").starts_with(OUTSOURCING_ROUTE_PREFIX));

    let reg = OutsourcingRegister::new(1_000);
    // (b) A cloud provider marked external via the derived id, but with NO board-approved arrangement,
    // is EXCLUDED (fail-closed) — even a public-class request cannot route it.
    let route = derive_route_id("anthropic-sonnet");
    assert_eq!(
        reg.eligibility(&route, DataClass::Public, "in", 500),
        Eligibility::NoRegisterEntry
    );
}

#[test]
fn r12_registered_derived_route_admits_within_policy() {
    let mut reg = OutsourcingRegister::new(1_000);
    let route = derive_route_id("inhouse-cloud-mirror");
    reg.upsert(OutsourcingArrangement::new(
        &route,
        "Provider Ltd, IN",
        DataClass::Confidential,
        "in",
        vec![SubProcessor {
            name: "sub-a".into(),
            jurisdiction: "in".into(),
        }],
        "program.exit.p",
        "chat-inference",
        ExitRehearsal::At { tick: 900 },
    ));
    // Now the same derived id is registered + within ceiling + in-residency → eligible.
    assert!(reg
        .eligibility(&route, DataClass::Confidential, "in", 950)
        .is_eligible());
    // But a class above the ceiling is still excluded (the register remains the non-overridable gate).
    assert!(!reg
        .eligibility(&route, DataClass::RegulatedPayment, "in", 950)
        .is_eligible());
}
