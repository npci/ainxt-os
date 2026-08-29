// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R11 — two regulated-FI gap closures on the statutory incident register, fail-before / pass-after:
//!
//! 1. `r11_evidentiary_hashchain_is_governed_by_crypto_agility` (ADR-023) — the register's evidentiary
//!    hash-chain resolves its digest primitive through the crypto-agility **policy** (the single source
//!    of truth for "what may I use"), not a hard-coded sha2 call. A policy that deprecates SHA-256 at a
//!    sunset and prefers SHA-512 after it seals earlier links with sha-256 and later links with sha-512;
//!    the whole chain still `verify()`s because each link is re-checked with the primitive that sealed
//!    it (an event sealed under a since-deprecated algorithm still verifies). A policy that forbids
//!    every hash primitive fails closed at construction — a register that cannot seal tamper-evidently
//!    never comes into being.
//!    Fail-before: `IncidentRegister` had no `hash_policy`; the chain was a hard-coded `Sha256` and
//!    there was no `with_hash_policy` / `hash_alg` of record — this file would not compile.
//!
//! 2. `r11_triage_role_proposes_policy_arms` (§2.2 agentic incident taxonomy) — a triage Role (model)
//!    *proposes* a classification and the **policy arms**: a proposal can only ESCALATE coverage above
//!    the source's fail-safe floor, never lower it, so a confused/hijacked model cannot disarm a clock.
//!    The proposal is recorded verbatim on the evidentiary chain whether or not it was adopted.
//!    Fail-before: `TriageProposal` / `open_from_triage` did not exist.

use ainxt_cryptoagility::{Algorithm, AlgorithmRegistry, Purpose};
use ainxt_incident::{
    ArmingPolicy, CandidateSource, IncidentCandidate, IncidentClass, IncidentEventKind,
    IncidentRegister, StatutoryClockKind, TamperError, TriageProposal,
};
use ainxt_types::DataClass;

// ============================================================================
// (1) ADR-023 — the evidentiary hash-chain is governed by the crypto-agility policy
// ============================================================================

#[test]
fn r11_evidentiary_hashchain_is_governed_by_crypto_agility() {
    // A crypto-agility policy that migrates the hash primitive at a sunset: SHA-256 is deprecated
    // (usable up to and including tick 100), SHA-512 approved as the successor. The register's
    // evidentiary chain must SEAL each link with whatever the policy resolves AT THAT LINK'S TICK.
    let mut policy = AlgorithmRegistry::new();
    policy.register(
        Purpose::Hashing,
        Algorithm::deprecated("sha-256", 100, false),
    );
    policy.register(Purpose::Hashing, Algorithm::approved("sha-512", false));

    let mut reg =
        IncidentRegister::with_hash_policy(ArmingPolicy::india_regulatory_default(), policy)
            .expect("a policy with a usable hash primitive constructs");

    // Inspection: the governing label flips at the sunset boundary — policy is the source of truth.
    assert_eq!(reg.hash_alg_at(100).unwrap(), "sha-256");
    assert_eq!(reg.hash_alg_at(101).unwrap(), "sha-512");

    // Open an incident whose events are sealed at tick 50 (→ sha-256) …
    let id = reg.open_from(
        IncidentCandidate::from_compliance_egress(50, "sha-live", DataClass::Pii, 2),
        50,
    );
    // … then advance the register far past the sunset so later links seal at tick 200 (→ sha-512).
    let _ = reg.tick(200);
    // A meta-incident / paging at tick 200 appends events under the successor primitive.
    reg.record_filing(
        &id,
        StatutoryClockKind::DpdpDataPrincipal,
        ainxt_incident::Filing {
            template_version: "dpdp-v1".into(),
            submitted_tick: 200,
            ack_ref: "ack-1".into(),
        },
    )
    .ok();

    // Both primitives actually sealed links: the chain is genuinely governed, not hard-coded.
    let algs: std::collections::BTreeSet<&str> =
        reg.events().iter().map(|e| e.hash_alg.as_str()).collect();
    assert!(
        algs.contains("sha-256"),
        "early links sealed under sha-256: {algs:?}"
    );
    assert!(
        algs.contains("sha-512"),
        "post-sunset links sealed under sha-512: {algs:?}"
    );

    // The WHOLE chain still verifies: each link is re-checked with the primitive that sealed it — an
    // event sealed under the since-deprecated sha-256 still verifies against sha-256, not the live pick.
    assert!(
        reg.verify().is_ok(),
        "the crypto-agility-governed chain verifies end-to-end"
    );

    // Fail-closed at construction: a policy that FORBIDS every hash primitive cannot build a register
    // (a register that cannot seal tamper-evidently must never exist).
    let mut forbidden = AlgorithmRegistry::new();
    forbidden.register(Purpose::Hashing, Algorithm::forbidden("md5", false));
    assert!(
        IncidentRegister::with_hash_policy(ArmingPolicy::india_regulatory_default(), forbidden)
            .is_err(),
        "an all-forbidden hash policy must fail closed at construction"
    );

    // And a policy resolving to a primitive with no implementation here also fails closed (never a
    // silent fallback to a hard-coded primitive).
    let mut unimpl = AlgorithmRegistry::new();
    unimpl.register(Purpose::Hashing, Algorithm::approved("blake3", true));
    assert!(
        IncidentRegister::with_hash_policy(ArmingPolicy::india_regulatory_default(), unimpl)
            .is_err()
    );
}

#[test]
fn r11_default_register_chain_is_sha256_and_labelled() {
    // Back-compat: a register built with `new()` uses the default SHA-256 policy, labels every link
    // `sha-256`, and verifies — the pre-ADR-023 behaviour, now recorded as policy of record.
    let mut reg = IncidentRegister::new(ArmingPolicy::india_regulatory_default());
    let _ = reg.open_from(
        IncidentCandidate::from_serving_ops(10, "sha", "route-x"),
        10,
    );
    assert!(reg.events().iter().all(|e| e.hash_alg == "sha-256"));
    assert!(reg.verify().is_ok());

    // A tampered `hash_alg` label (recompute impossible with the recorded primitive) is caught as a
    // fail-closed CryptoUnavailable break — an auditor cannot dress up an unsealable link.
    // (Constructed by round-tripping through serde and corrupting the label.)
    let json = serde_json::to_string(&reg)
        .unwrap()
        .replace("sha-256", "rot13");
    let corrupt: IncidentRegister = serde_json::from_str(&json).unwrap();
    assert!(matches!(
        corrupt.verify(),
        Err(TamperError::CryptoUnavailable { .. }) | Err(TamperError::HashMismatch { .. })
    ));
}

// ============================================================================
// (2) §2.2 — a triage Role proposes; the policy arms (escalate-only floor)
// ============================================================================

#[test]
fn r11_triage_role_proposes_policy_arms() {
    // A serving-ops candidate's fail-safe floor is OutsourcedServiceDisruption (rank 2). A triage model
    // that proposes a LESS-protective class (QualityDegradationRegulatedRoute, rank 1) must NOT lower
    // the armed class — the policy floors at the fail-safe class.
    let mut reg = IncidentRegister::new(ArmingPolicy::india_regulatory_default());
    let cand = IncidentCandidate::from_serving_ops(100, "sha", "route-x");
    let downplay = TriageProposal::new(
        "triage-role/v1",
        IncidentClass::QualityDegradationRegulatedRoute,
        95,
    )
    .with_rationale("looks like mere latency");
    let id = reg.open_from_triage(cand, downplay, 100);

    let inc = reg.incident(&id).unwrap();
    assert_eq!(
        inc.class,
        IncidentClass::OutsourcedServiceDisruption,
        "a below-floor proposal cannot disarm — policy floors at the fail-safe class"
    );

    // The proposal is recorded verbatim on the evidentiary chain (un-hideable), with BOTH what the
    // model proposed and what the policy armed.
    let proposed_evt = reg.events().iter().find_map(|e| match &e.event {
        IncidentEventKind::TriageProposed {
            proposed_class,
            armed_class,
            model,
            ..
        } => Some((*proposed_class, *armed_class, model.clone())),
        _ => None,
    });
    assert_eq!(
        proposed_evt,
        Some((
            IncidentClass::QualityDegradationRegulatedRoute,
            IncidentClass::OutsourcedServiceDisruption,
            "triage-role/v1".to_string()
        ))
    );

    // A triage model that proposes a MORE-protective class DOES escalate: a compliance-egress candidate
    // (floor PersonalDataBreach, rank 4) escalated to AgentSettlementAction (rank 5) arms the harder
    // class — the model can raise coverage, and the policy arms the escalated class's clocks.
    let cand2 = IncidentCandidate::new(CandidateSource::ComplianceGateEgress, 200, "sha")
        .with_data_class(DataClass::RegulatedPayment);
    let escalate = TriageProposal::new("triage-role/v1", IncidentClass::AgentSettlementAction, 80);
    let id2 = reg.open_from_triage(cand2, escalate, 200);
    assert_eq!(
        reg.incident(&id2).unwrap().class,
        IncidentClass::AgentSettlementAction,
        "an above-floor proposal escalates the armed class"
    );

    // The whole chain remains tamper-evident after the triage-armed opens.
    assert!(reg.verify().is_ok());
}
