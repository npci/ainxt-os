// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R13 HIGH (regulated-fi): "§3.2 'no ungoverned outsourcing can ever route' is fail-OPEN against
//! provider self-declaration."
//!
//! The Model Router's FI-03 outsourcing guard used to decide externality from the provider adapter's own
//! [`Provider::outsourcing_route`] — a provider that returned `None` was taken at its word as in-house
//! and NEVER register-gated. That is fail-OPEN: a genuinely EXTERNAL cloud provider whose adapter forgot
//! to declare a route id (or is malicious) slips past the RBI outsourcing register as though it were
//! on-prem, and ungoverned context egresses to an unapproved third party.
//!
//! R13 closes it by making externality AUTHORITATIVE-by-construction (fail-CLOSED): the shipped daemon
//! installs [`ModelRouter::with_outsourcing_register_authoritative`], where every provider is treated as
//! an external/outsourced route (register route id = [`derive_route_id`]`(id)`) UNLESS its id is in the
//! explicit, signed on-prem exemption set. A provider's own say-so is ignored.
//!
//! This test proves the invariant fail-before / pass-after in one place: the SAME rogue provider that
//! self-declares in-house (`outsourcing_route() == None`) is ADMITTED under the legacy self-declared
//! guard (the bug) and REFUSED under the authoritative guard (the fix) — and only becomes admissible once
//! a board-approved arrangement is registered under its derived id.
//!
//! The served call-site is `ainxt-runtimed::build_router`, which now installs the authoritative guard
//! with `in_house = {"offline"} ∪ {Local-kind provider ids}` so the air-gapped `offline` route still
//! serves (no empty-pool 503) while every cloud route stays fail-closed until governed.

use ainxt_protocol::Event;
use ainxt_responsibleai::outsourcing::{
    derive_route_id, ExitRehearsal, OutsourcingArrangement, OutsourcingRegister, SubProcessor,
};
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::{ModelRouter, RouteError, RouterClock};
use ainxt_types::DataClass;
use std::sync::Arc;

/// A genuinely EXTERNAL cloud provider whose adapter self-declares in-house — the fail-open exploit
/// vector: it returns `None` from `outsourcing_route()`, so a self-declaration-trusting guard treats it
/// as on-prem and never register-gates it.
struct RogueCloud;
impl Provider for RogueCloud {
    fn id(&self) -> &str {
        "rogue-cloud"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    // NOTE: no `outsourcing_route()` override — it returns the default `None` ("I am in-house").
    fn stream(&self, _p: &str) -> tokio::sync::mpsc::Receiver<Event> {
        let (_tx, rx) = tokio::sync::mpsc::channel(1);
        rx
    }
}

/// A genuinely on-prem provider (the air-gapped local route). It also self-declares `None`, but it is a
/// real in-house route and appears on the signed exemption list.
struct Offline;
impl Provider for Offline {
    fn id(&self) -> &str {
        "offline"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, _p: &str) -> tokio::sync::mpsc::Receiver<Event> {
        let (_tx, rx) = tokio::sync::mpsc::channel(1);
        rx
    }
}

fn fixed_clock(now: u64) -> RouterClock {
    Arc::new(move || now)
}

/// A board-approved arrangement for the rogue route, registered under its DERIVED id, within policy for
/// a regulated request (ceiling covers the class, in-residency, exit plan fresh).
fn approved_arrangement_for(provider_id: &str, now: u64) -> OutsourcingArrangement {
    OutsourcingArrangement::new(
        &derive_route_id(provider_id),
        "Rogue Cloud Ltd, IN",
        DataClass::RegulatedPayment,
        "in",
        vec![SubProcessor {
            name: "sub-a".into(),
            jurisdiction: "in".into(),
        }],
        "program.exit.rogue",
        "chat-inference",
        ExitRehearsal::At { tick: now },
    )
}

#[test]
fn r13_self_declared_guard_is_fail_open_authoritative_guard_is_fail_closed() {
    let residency = "in";
    let now = 1_000;

    // ---- FAIL-BEFORE: the legacy self-declared guard admits the rogue cloud route ----
    // The guard trusts `outsourcing_route() == None` ⇒ "in-house" ⇒ never gated. The register is empty
    // (the fail-closed *default*), yet the rogue route routes regulated-payment traffic anyway.
    let mut legacy = ModelRouter::new();
    legacy.register(Box::new(RogueCloud));
    let legacy = legacy.with_outsourcing_register(
        OutsourcingRegister::new(10_000),
        residency,
        fixed_clock(now),
    );
    let picked = legacy
        .select(DataClass::RegulatedPayment, None)
        .expect("fail-open: the self-declared guard wrongly admits an ungoverned cloud route");
    assert_eq!(
        picked.id(),
        "rogue-cloud",
        "demonstrates the fail-OPEN: a cloud provider that self-declares in-house escapes the register"
    );

    // ---- PASS-AFTER: the authoritative guard refuses the same rogue route ----
    // Externality is now by construction. `in_house = {"offline"}` is the ONLY exemption; the rogue route
    // is not on it, so it is treated as external, its derived id has NO register entry ⇒ excluded BEFORE
    // ranking. `offline` (exempt) still serves.
    let mut strict = ModelRouter::new();
    strict.register(Box::new(RogueCloud));
    strict.register(Box::new(Offline));
    let strict = strict.with_outsourcing_register_authoritative(
        OutsourcingRegister::new(10_000),
        residency,
        fixed_clock(now),
        ["offline".to_string()],
    );

    // The rogue route can never be selected — not by default, and not even when explicitly forced
    // (the eligibility gate is non-overridable).
    let served = strict
        .select(DataClass::RegulatedPayment, None)
        .expect("the exempt on-prem route still serves — no empty-pool 503");
    assert_eq!(
        served.id(),
        "offline",
        "authoritative guard: only the signed on-prem exemption serves; the cloud route is fail-closed"
    );
    match strict.select(DataClass::RegulatedPayment, Some("rogue-cloud")) {
        Err(RouteError::ForcedNotEligible(id, _)) => assert_eq!(id, "rogue-cloud"),
        Err(other) => panic!("expected ForcedNotEligible, got {other:?}"),
        Ok(p) => panic!(
            "forcing an unregistered/self-declared cloud route must be refused, got provider {}",
            p.id()
        ),
    }

    // A route with ONLY the rogue cloud provider and no signed exemption for it ⇒ no eligible route at
    // all (fail-closed all the way to NoEligible — it never silently routes).
    let mut rogue_only = ModelRouter::new();
    rogue_only.register(Box::new(RogueCloud));
    let rogue_only = rogue_only.with_outsourcing_register_authoritative(
        OutsourcingRegister::new(10_000),
        residency,
        fixed_clock(now),
        ["offline".to_string()],
    );
    assert!(
        matches!(
            rogue_only.select(DataClass::RegulatedPayment, None),
            Err(RouteError::NoEligible(DataClass::RegulatedPayment))
        ),
        "an unregistered cloud route as the only candidate must yield NO route, never an ungoverned one"
    );
}

#[test]
fn r13_authoritative_guard_admits_the_rogue_route_once_board_approved_and_registered() {
    let residency = "in";
    let now = 5_000;

    // Register a board-approved arrangement under the rogue provider's DERIVED id, within policy.
    let mut register = OutsourcingRegister::new(10_000);
    register.upsert(approved_arrangement_for("rogue-cloud", 4_900));

    let mut router = ModelRouter::new();
    router.register(Box::new(RogueCloud));
    let router = router.with_outsourcing_register_authoritative(
        register,
        residency,
        fixed_clock(now),
        ["offline".to_string()],
    );

    // Now the SAME rogue route is admissible — because a governed arrangement exists, not because it
    // self-declared anything.
    let picked = router
        .select(DataClass::RegulatedPayment, None)
        .expect("a board-approved, registered arrangement makes the route eligible");
    assert_eq!(picked.id(), "rogue-cloud");

    // The register stays the NON-overridable ceiling: the SAME registered arrangement (residency "in")
    // is still refused for a deployment whose residency is "us-east-1" — localisation is enforced even
    // for a governed route. This proves the authoritative guard did not weaken any register check.
    let mut foreign = OutsourcingRegister::new(10_000);
    foreign.upsert(approved_arrangement_for("rogue-cloud", 4_900));
    let mut router2 = ModelRouter::new();
    router2.register(Box::new(RogueCloud));
    let router2 = router2.with_outsourcing_register_authoritative(
        foreign,
        "us-east-1",
        fixed_clock(now),
        ["offline".to_string()],
    );
    assert!(
        matches!(
            router2.select(DataClass::RegulatedPayment, None),
            Err(RouteError::NoEligible(DataClass::RegulatedPayment))
        ),
        "a registered in-residency route must still be refused for a foreign-residency deployment"
    );
}
