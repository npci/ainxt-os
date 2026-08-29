// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-7: the **federated privacy-preserving cross-member-bank tier**
//! (`STRUCTURED_FEDERATED_RETRIEVAL.md` §6) — exercised END TO END offline through the public
//! [`FederatedBroker`] over the [`BankTenant`] seam.
//!
//! INFRA-GATED. The tier's LIVE property — real member-bank tenants, each in its own
//! schema/namespace with no cross-tenant read credential (§6.1) — is a physical infrastructure
//! guarantee enforced at the connection layer, not in code, and needs real tenants to prove. What
//! is code-closable and proven here (offline, deterministic — no live tenant): the whole
//! broker-side algorithm — closed-vocabulary whitelist gate, per-tenant dispatch, the
//! tenant-isolation assertion (a tenant may only speak for itself), the ε privacy-budget ledger,
//! and the k-anonymity floor — all run through the real objects with an in-memory [`BankTenant`]
//! that mirrors an isolated tenant boundary. So the seam + logic are real; only the physical
//! multi-tenant deployment is deferred → reported infra_gated.

use ainxt_retrieval::federation::{
    aggregate, noise_partial, BankPartial, BankTenant, DpParams, EpsilonLedger, FederatedBroker,
    FederationError, FederationRegistry, KAnonConfig, NoisedPartial,
};

/// An in-boundary tenant that noises its own partials locally and speaks only for its own bank id —
/// the offline analogue of a bank's isolated schema/connection.
struct OfflineTenant {
    id: String,
    locals: Vec<BankPartial>,
    reachable: bool,
}

impl BankTenant for OfflineTenant {
    fn bank_id(&self) -> &str {
        &self.id
    }
    fn local_partials(&self, _metric_id: &str, _window: &str) -> Option<Vec<NoisedPartial>> {
        if !self.reachable {
            return None; // unreachable/refused → contributes nothing (never counted as zero)
        }
        Some(
            self.locals
                .iter()
                .enumerate()
                .map(|(i, p)| {
                    noise_partial(
                        p,
                        DpParams {
                            epsilon: 5.0,
                            sensitivity: 1.0,
                        },
                        i as u64 + 1,
                    )
                })
                .collect(),
        )
    }
}

fn partial(bank: &str, bucket: &str, v: f64, n: u64) -> BankPartial {
    BankPartial {
        bank_id: bank.into(),
        bucket: bucket.into(),
        true_value: v,
        underlying_count: n,
    }
}

#[test]
fn r7_federated_broker_end_to_end_offline() {
    let reg = FederationRegistry::new().allow("mule_velocity");
    let broker = FederatedBroker::new(
        &reg,
        KAnonConfig {
            min_banks: 3,
            min_underlying: 100,
        },
        DpParams {
            epsilon: 5.0,
            sensitivity: 1.0,
        },
    );
    let t1 = OfflineTenant {
        id: "b1".into(),
        locals: vec![partial("b1", "high", 50.0, 400)],
        reachable: true,
    };
    let t2 = OfflineTenant {
        id: "b2".into(),
        locals: vec![partial("b2", "high", 60.0, 500)],
        reachable: true,
    };
    let t3 = OfflineTenant {
        id: "b3".into(),
        locals: vec![partial("b3", "high", 70.0, 600)],
        reachable: true,
    };
    let mut ledger = EpsilonLedger::new();

    let report = broker
        .dispatch(
            "mule_velocity",
            "2026-07",
            0.5,
            1.0,
            &mut ledger,
            &[&t1, &t2, &t3],
            false,
        )
        .expect("dispatch ok");

    // Aggregate-only result over the k-anon floor (3 banks contributed).
    assert_eq!(report.result.buckets.len(), 1);
    assert_eq!(report.result.buckets[0].contributing_banks, 3);
    assert!(
        report.result.per_bank.is_none(),
        "no per-bank disclosure by default"
    );
    assert_eq!(report.contributed, vec!["b1", "b2", "b3"]);
    // The ε ledger was debited and reports the remaining budget.
    assert!((report.epsilon_remaining - 0.5).abs() < 1e-9);
}

#[test]
fn r7_federation_fail_closed_gates_offline() {
    let reg = FederationRegistry::new().allow("mule_velocity");
    let broker = FederatedBroker::new(
        &reg,
        KAnonConfig {
            min_banks: 1,
            min_underlying: 0,
        },
        DpParams {
            epsilon: 1.0,
            sensitivity: 1.0,
        },
    );
    let t = OfflineTenant {
        id: "b1".into(),
        locals: vec![partial("b1", "x", 1.0, 10)],
        reachable: true,
    };
    let mut ledger = EpsilonLedger::new();

    // A metric not on the git-reviewed federated whitelist is refused before any bank is contacted.
    let err = broker
        .dispatch("account_balance", "w", 0.1, 1.0, &mut ledger, &[&t], false)
        .unwrap_err();
    assert!(matches!(err, FederationError::NotFederated { .. }));
    assert_eq!(
        ledger.spent("account_balance", "w"),
        0.0,
        "ledger untouched on a refused metric"
    );

    // Exhaust the ε budget, then the next query is refused (never silently re-noised weaker).
    broker
        .dispatch("mule_velocity", "w", 1.0, 1.0, &mut ledger, &[&t], false)
        .unwrap();
    let refused = broker
        .dispatch("mule_velocity", "w", 0.5, 1.0, &mut ledger, &[&t], false)
        .unwrap_err();
    assert!(matches!(refused, FederationError::BudgetExhausted(_)));
}

#[test]
fn r7_k_anonymity_suppresses_small_cells_offline() {
    // A bucket contributed to by fewer than min_banks is suppressed, never returned as a
    // distinguishable small cell (it merges into "other").
    let noised: Vec<NoisedPartial> = [
        partial("b1", "high", 50.0, 400),
        partial("b2", "high", 60.0, 500),
        partial("b3", "high", 70.0, 600),
        partial("b1", "rare", 5.0, 3), // only one bank + tiny underlying → suppressed
    ]
    .iter()
    .map(|p| {
        noise_partial(
            p,
            DpParams {
                epsilon: 5.0,
                sensitivity: 1.0,
            },
            1,
        )
    })
    .collect();

    let res = aggregate(
        &noised,
        &KAnonConfig {
            min_banks: 3,
            min_underlying: 100,
        },
        false,
    );
    assert!(
        res.buckets.iter().all(|b| b.bucket != "rare"),
        "the small cell must not survive"
    );
    assert!(res.suppressed_buckets.contains(&"rare".to_string()));
}
