// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-12 Serving-Ops gap-3 (LOW) — the ADR-021 §8.3 attestation quote-refresh loop: declared
//! regulated nodes are (re-)attested on a cadence instead of staying unattested forever.
//!
//! The audit found the daemon declared a regulated node pool but had no loop that fetched + verified
//! fresh TEE quotes for it — a quote had to be hand-submitted, so declared nodes never became
//! regulated-eligible and the §8.2 fence drained the whole fleet. This closes the pure scheduling +
//! fence-driving half ([`refresh_regulated_nodes`]); the live-TEE quote acquisition is the
//! [`QuoteSource`] infra seam (offline reference: [`StaticQuoteSource`]).
//!
//! Fail-before: `needs_refresh`/`refresh_regulated_nodes`/`QuoteSource`/`StaticQuoteSource` did not
//! exist — this file would not compile. Pass-after: one refresh tick attests every declared node that
//! can produce a quote, a proactive tick re-attests a node whose quote is about to expire, a
//! quarantined node is never auto-refreshed, and a node the TEE cannot quote stays fail-closed.

use ainxt_serving::attestation::{
    refresh_regulated_nodes, AllowListVerifier, AttestationConfig, AttestationGate,
    AttestationQuote, Measurements, ReferenceValues, RefreshOutcome, StaticQuoteSource, TrustTier,
};
use ainxt_serving::gate::NodeCandidate;
use ainxt_types::DataClass;

/// Regulated admission over a candidate set, via the AttestationGate directly (no ServingGate here):
/// true iff at least one routable candidate is currently attestation-admitted for `dc`.
fn any_admitted(gate: &AttestationGate, cands: &[NodeCandidate], dc: DataClass, now: u64) -> bool {
    cands
        .iter()
        .any(|c| c.routable && gate.evaluate(&c.node_id, dc, now, true).is_admitted())
}

fn refs() -> ReferenceValues {
    ReferenceValues::new()
        .allow_firmware("fw-1")
        .allow_driver("drv-1")
        .allow_binary("bin-1")
}

fn good_quote(node: &str) -> AttestationQuote {
    AttestationQuote {
        node_id: node.into(),
        tier: TrustTier::CcEnclave,
        measurements: Measurements {
            firmware_hash: "fw-1".into(),
            driver_version: "drv-1".into(),
            binary_hash: "bin-1".into(),
        },
        signature: "sig-ok".into(),
    }
}

#[test]
fn r12_refresh_loop_attests_declared_nodes_and_respects_quarantine() {
    let mut gate = AttestationGate::new(AttestationConfig {
        quote_ttl: 100,
        grace_ttl: 10,
    });
    let verifier = AllowListVerifier::new().accept("sig-ok");
    let refs = refs();
    // The declared pool the daemon advertises (all UNattested at boot — the bug: they stay that way).
    let declared: Vec<String> = ["gpu-a", "gpu-b", "gpu-quarantined"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let candidates: Vec<NodeCandidate> = declared
        .iter()
        .map(|n| NodeCandidate::new(n.clone(), true))
        .collect();

    // Pre-state: a regulated turn fails closed on the whole (unattested) pool.
    assert!(
        !any_admitted(&gate, &candidates, DataClass::RegulatedPayment, 0),
        "unattested pool: regulated turn fails closed"
    );

    // gpu-quarantined is under manual-review quarantine (a firmware fault earlier) — never auto-refreshed.
    let bad = AttestationQuote {
        signature: "sig-ok".into(),
        measurements: Measurements {
            firmware_hash: "fw-EVIL".into(),
            driver_version: "drv-1".into(),
            binary_hash: "bin-1".into(),
        },
        ..good_quote("gpu-quarantined")
    };
    let _ = gate.submit_quote(&bad, 0, &verifier, &refs); // firmware not allow-listed → quarantines it
    assert!(gate.is_quarantined("gpu-quarantined"));

    // The live TEE can quote gpu-a and gpu-b (the offline source); gpu-quarantined would too, but must
    // be skipped by policy.
    let source = StaticQuoteSource::new()
        .with_quote(good_quote("gpu-a"))
        .with_quote(good_quote("gpu-b"))
        .with_quote(good_quote("gpu-quarantined"));

    // (1) One refresh tick attests gpu-a + gpu-b, skips the quarantined node.
    let report = refresh_regulated_nodes(&mut gate, &declared, 1, 20, &source, &verifier, &refs);
    assert_eq!(
        report.refreshed_count(),
        2,
        "both quotable, non-quarantined nodes attested: {report:?}"
    );
    assert!(report.outcomes.contains(&RefreshOutcome::Refreshed {
        node_id: "gpu-a".into()
    }));
    assert!(report.outcomes.contains(&RefreshOutcome::Quarantined {
        node_id: "gpu-quarantined".into()
    }));

    // Now a regulated turn is admitted onto an attested node — the fence is no longer draining the fleet.
    assert!(
        any_admitted(&gate, &candidates, DataClass::RegulatedPayment, 1),
        "after refresh: a regulated turn lands on an attested node"
    );
    // The quarantined node is still denied for regulated traffic (auto-refresh never cleared it).
    assert!(gate.is_quarantined("gpu-quarantined"));
}

#[test]
fn r12_refresh_is_proactive_and_idempotent_within_the_lead_window() {
    let mut gate = AttestationGate::new(AttestationConfig {
        quote_ttl: 100,
        grace_ttl: 10,
    });
    let verifier = AllowListVerifier::new().accept("sig-ok");
    let refs = refs();
    let declared = vec!["gpu-a".to_string()];
    let source = StaticQuoteSource::new().with_quote(good_quote("gpu-a"));

    // Attest at t=0 (quote fresh until t=100).
    assert_eq!(
        refresh_regulated_nodes(&mut gate, &declared, 0, 20, &source, &verifier, &refs)
            .refreshed_count(),
        1
    );

    // (2) Well inside freshness (t=50, lead=20 → expires at 100, 50 ticks out) → nothing to do.
    let r = refresh_regulated_nodes(&mut gate, &declared, 50, 20, &source, &verifier, &refs);
    assert_eq!(r.refreshed_count(), 0);
    assert!(r.outcomes.contains(&RefreshOutcome::StillFresh {
        node_id: "gpu-a".into()
    }));

    // (3) PROACTIVE: at t=85 the quote expires in 15 ticks (<= lead 20) → re-attested BEFORE it lapses,
    //     so the fence never flickers to fail-closed on an expiry it could have prevented.
    let r = refresh_regulated_nodes(&mut gate, &declared, 85, 20, &source, &verifier, &refs);
    assert_eq!(
        r.refreshed_count(),
        1,
        "expiring-soon node is proactively re-attested: {r:?}"
    );
    // Fresh again from t=85 → now good until 185.
    assert_eq!(gate.ttl_remaining("gpu-a", 85), Some(100));
}

#[test]
fn r12_node_without_a_tee_quote_stays_fail_closed() {
    let mut gate = AttestationGate::new(AttestationConfig {
        quote_ttl: 100,
        grace_ttl: 10,
    });
    let verifier = AllowListVerifier::new().accept("sig-ok");
    let refs = refs();
    let declared = vec!["gpu-no-tee".to_string()];
    // The source has NO quote for this node (its TEE is unavailable this tick).
    let source = StaticQuoteSource::new();
    let r = refresh_regulated_nodes(&mut gate, &declared, 0, 20, &source, &verifier, &refs);
    assert_eq!(r.refreshed_count(), 0);
    assert!(r.outcomes.contains(&RefreshOutcome::NoQuoteAvailable {
        node_id: "gpu-no-tee".into()
    }));
    // Still unattested → a regulated turn on it fails closed (never fail-open on a missing quote).
    let cands = vec![NodeCandidate::new("gpu-no-tee", true)];
    assert!(!any_admitted(&gate, &cands, DataClass::RegulatedPayment, 0));
}
