// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-13 Serving-Ops (HIGH) — the ADR-021 §8.3 attestation quote-refresh LOOP is now a stateful,
//! periodic driver, not a hand-called single tick.
//!
//! The audit found: the daemon declared a regulated node pool but no loop ever re-fetched + verified
//! fresh TEE quotes for it, so a quote had to be submitted by hand — declared nodes stayed UNattested
//! and the §8.2 fence drained regulated traffic off the whole fleet forever. Round-12 delivered the
//! pure single-tick [`refresh_regulated_nodes`]; this round wraps it in an [`AttestationRefresher`]
//! that owns the declared pool + a cadence, so periodic re-fetch + expiry-driven re-admit is a real,
//! drivable loop. The live-TEE quote acquisition remains the [`QuoteSource`] infra seam (offline
//! reference: [`StaticQuoteSource`]).
//!
//! Fail-before: `AttestationRefresher` / `RefreshConfig` did not exist — this file would not compile.
//! Pass-after: (1) the driver RE-ADMITS a regulated turn once the TEE produces a fresh quote for a
//! previously-unattested/expired node; (2) it FAILS CLOSED when a quote has expired and the TEE cannot
//! produce a fresh one (never a stale-quote fallback); (3) the sweep is genuinely PERIODIC (a tick
//! before the next due point is a no-op) and expiry-driven (proactively renews within the lead window).

use ainxt_serving::attestation::{
    AllowListVerifier, AttestationConfig, AttestationGate, AttestationQuote, AttestationRefresher,
    Measurements, ReferenceValues, RefreshConfig, RefreshOutcome, StaticQuoteSource, TrustTier,
};
use ainxt_types::DataClass;

const SIG: &str = "sig-ok";

fn refs() -> ReferenceValues {
    ReferenceValues::new()
        .allow_firmware("fw-1")
        .allow_driver("drv-1")
        .allow_binary("bin-1")
}

fn verifier() -> AllowListVerifier {
    AllowListVerifier::new().accept(SIG)
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
        signature: SIG.into(),
    }
}

/// (1) RE-ADMIT ON A FRESH QUOTE — the whole point of the loop the audit found missing.
#[test]
fn r13_refresher_re_admits_a_declared_node_once_the_tee_can_quote_it() {
    let cfg = AttestationConfig {
        quote_ttl: 100,
        grace_ttl: 10,
    };
    let mut gate = AttestationGate::new(cfg);
    let declared = vec!["gpu-a".to_string()];
    // interval 30, lead 40 (> interval so a quote never lapses between sweeps).
    let mut refresher = AttestationRefresher::new(
        declared,
        RefreshConfig {
            interval: 30,
            lead: 40,
        },
    );
    let refs = refs();
    let verifier = verifier();

    // Pre-state: declared but UNattested — a regulated turn fails closed on the whole pool.
    assert!(
        !gate
            .evaluate("gpu-a", DataClass::RegulatedPayment, 0, true)
            .is_admitted(),
        "declared-but-unattested node must fail closed for regulated traffic"
    );

    // The live TEE can now produce a quote for gpu-a (offline reference source).
    let source = StaticQuoteSource::new().with_quote(good_quote("gpu-a"));

    // First driver tick at t=0 is due → it sweeps and RE-ADMITS gpu-a.
    let report = refresher
        .tick(&mut gate, 0, &source, &verifier, &refs)
        .expect("first tick is due");
    assert_eq!(
        report.refreshed_count(),
        1,
        "the fresh quote attests gpu-a: {report:?}"
    );
    assert!(report.outcomes.contains(&RefreshOutcome::Refreshed {
        node_id: "gpu-a".into()
    }));
    assert!(
        gate.evaluate("gpu-a", DataClass::RegulatedPayment, 0, true)
            .is_admitted(),
        "after the refresh sweep, a regulated turn lands on the now-attested node"
    );
    assert_eq!(refresher.sweeps_run(), 1);
}

/// (2) FAIL CLOSED ON AN EXPIRED QUOTE — when the TEE cannot renew, the node drops out fail-closed;
///     the driver never fabricates or falls back to a stale quote.
#[test]
fn r13_refresher_fails_closed_when_an_expired_quote_cannot_be_renewed() {
    let cfg = AttestationConfig {
        quote_ttl: 100,
        grace_ttl: 0,
    };
    let mut gate = AttestationGate::new(cfg);
    let declared = vec!["gpu-a".to_string()];
    let mut refresher = AttestationRefresher::new(
        declared,
        RefreshConfig {
            interval: 30,
            lead: 40,
        },
    );
    let refs = refs();
    let verifier = verifier();

    // Boot: the TEE quotes gpu-a at t=0 → attested, fresh until t=100.
    let live = StaticQuoteSource::new().with_quote(good_quote("gpu-a"));
    refresher
        .tick(&mut gate, 0, &live, &verifier, &refs)
        .expect("boot tick attests gpu-a");
    assert!(gate
        .evaluate("gpu-a", DataClass::RegulatedPayment, 0, true)
        .is_admitted());

    // Time passes and the TEE goes DARK — a subsequent sweep finds no quote to fetch.
    let dark = StaticQuoteSource::new();
    // Force the next sweep to be due (interval 30 → next due at 30) and land at t=150, past expiry.
    let report = refresher
        .tick(&mut gate, 150, &dark, &verifier, &refs)
        .expect("sweep is due at 150");
    assert_eq!(
        report.refreshed_count(),
        0,
        "no fresh quote → nothing re-attested: {report:?}"
    );
    assert!(report.outcomes.contains(&RefreshOutcome::NoQuoteAvailable {
        node_id: "gpu-a".into()
    }));

    // The expired node is FAIL-CLOSED for regulated traffic — the driver never fell back to the stale
    // quote it held from boot.
    assert!(
        !gate
            .evaluate("gpu-a", DataClass::RegulatedPayment, 150, true)
            .is_admitted(),
        "an expired quote that cannot be renewed must fail closed, never fall back to stale trust"
    );

    // And once the TEE recovers, the very next due sweep RE-ADMITS it again (the loop self-heals).
    let recovered = StaticQuoteSource::new().with_quote(good_quote("gpu-a"));
    let report = refresher
        .tick(&mut gate, 200, &recovered, &verifier, &refs)
        .expect("due at 200");
    assert_eq!(
        report.refreshed_count(),
        1,
        "recovered TEE re-attests: {report:?}"
    );
    assert!(gate
        .evaluate("gpu-a", DataClass::RegulatedPayment, 200, true)
        .is_admitted());
}

/// (3) The sweep is genuinely PERIODIC and expiry-driven — not a per-request hot path.
#[test]
fn r13_refresh_sweep_is_periodic_and_expiry_driven() {
    let cfg = AttestationConfig {
        quote_ttl: 100,
        grace_ttl: 0,
    };
    let mut gate = AttestationGate::new(cfg);
    let declared = vec!["gpu-a".to_string()];
    let mut refresher = AttestationRefresher::new(
        declared,
        RefreshConfig {
            interval: 30,
            lead: 40,
        },
    );
    let refs = refs();
    let verifier = verifier();
    let source = StaticQuoteSource::new().with_quote(good_quote("gpu-a"));

    // t=0: due → sweeps, attests (fresh until 100). Next due at 30.
    assert!(refresher
        .tick(&mut gate, 0, &source, &verifier, &refs)
        .is_some());
    assert!(refresher.is_due(30));

    // t=10: NOT due (before the next cadence point) → a no-op tick, sweep count unchanged.
    assert!(
        refresher
            .tick(&mut gate, 10, &source, &verifier, &refs)
            .is_none(),
        "a tick before the next due point does no work (periodic, not per-request)"
    );
    assert_eq!(refresher.sweeps_run(), 1);

    // t=30: due but the quote is still fresh (expires at 100, 70 ticks out > lead 40) → StillFresh.
    let r = refresher
        .tick(&mut gate, 30, &source, &verifier, &refs)
        .expect("due at 30");
    assert_eq!(r.refreshed_count(), 0);
    assert!(r.outcomes.contains(&RefreshOutcome::StillFresh {
        node_id: "gpu-a".into()
    }));

    // t=90: due (next due was 60) and now WITHIN the lead window (expires in 10 <= lead 40) →
    // PROACTIVELY re-attested BEFORE it can lapse, so the fence never flickers to fail-closed.
    let r = refresher
        .tick(&mut gate, 90, &source, &verifier, &refs)
        .expect("due at 90");
    assert_eq!(
        r.refreshed_count(),
        1,
        "expiring-soon node re-attested proactively: {r:?}"
    );
    assert_eq!(
        gate.ttl_remaining("gpu-a", 90),
        Some(100),
        "freshness pushed out to 190"
    );
    assert!(gate
        .evaluate("gpu-a", DataClass::RegulatedPayment, 90, true)
        .is_admitted());
}
