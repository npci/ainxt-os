// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-16 HIGHs for the Federated tier (`STRUCTURED_FEDERATED_RETRIEVAL.md` §6).
//!
//! **§6.4 — per-bank disclosure is a git-reviewed consent record, not a caller boolean.** The
//! broker previously threaded a bare `disclose_per_bank: bool` straight into the aggregator, so any
//! caller could name every contributing bank in the output. Now the bool is only a *request*: the
//! breakdown is emitted iff EVERY contributing bank has a standing, un-revoked, per-metric-class
//! opt-in in the loaded consent control plane. Absence, revocation or a wrong metric class all
//! withhold it — and the withholding is recorded on the report for audit, while the aggregate
//! still ships (never a hard failure).
//!
//! **§6.3 — the ε ledger survives a restart.** The ledger was `BTreeMap` state with no persistence
//! seam, so restarting the process reset every privacy budget and restored the averaging-out attack
//! the ledger exists to bound. There is now a write-ahead durability seam (persist the debit BEFORE
//! the in-memory ledger advances; refuse the query if the persist fails) with a replay path.
//! INFRA-GATED: only the durable store itself (Postgres) is deferred; the discipline is enforced and
//! proven here against the offline journal.

use ainxt_retrieval::federation::{
    BankTenant, DisclosureConsent, DisclosureConsentRegistry, DpParams, EpsilonLedger,
    EpsilonSpendError, FederatedBroker, FederationRegistry, InMemoryEpsilonJournal, KAnonConfig,
    NoisedPartial,
};

struct Bank {
    id: &'static str,
    buckets: Vec<(&'static str, f64, u64)>,
}

impl BankTenant for Bank {
    fn bank_id(&self) -> &str {
        self.id
    }
    fn local_partials(&self, _metric_id: &str, _window: &str) -> Option<Vec<NoisedPartial>> {
        Some(
            self.buckets
                .iter()
                .map(|(b, v, n)| NoisedPartial {
                    bank_id: self.id.to_string(),
                    bucket: b.to_string(),
                    value: *v,
                    underlying_count: *n,
                })
                .collect(),
        )
    }
}

fn banks() -> Vec<Bank> {
    vec![
        Bank {
            id: "bank_a",
            buckets: vec![("mule_velocity", 10.0, 900)],
        },
        Bank {
            id: "bank_b",
            buckets: vec![("mule_velocity", 12.0, 800)],
        },
        Bank {
            id: "bank_c",
            buckets: vec![("mule_velocity", 9.0, 700)],
        },
    ]
}

fn registry() -> FederationRegistry {
    FederationRegistry::new().allow("mule_velocity")
}

fn k() -> KAnonConfig {
    KAnonConfig {
        min_banks: 3,
        min_underlying: 100,
    }
}

fn dp() -> DpParams {
    DpParams {
        epsilon: 1.0,
        sensitivity: 1.0,
    }
}

#[test]
fn r16_per_bank_disclosure_requires_every_banks_consent() {
    let reg = registry();
    let bs = banks();
    let tenants: Vec<&dyn BankTenant> = bs.iter().map(|b| b as &dyn BankTenant).collect();

    // (a) The caller ASKS for a per-bank breakdown with NO consent control plane loaded. Before
    // this round the bool alone was sufficient and every bank was named. Now: withheld.
    let broker = FederatedBroker::new(&reg, k(), dp());
    let mut ledger = EpsilonLedger::new();
    let r = broker
        .dispatch(
            "mule_velocity",
            "2026-07",
            0.1,
            10.0,
            &mut ledger,
            &tenants,
            true,
        )
        .unwrap();
    assert!(
        r.result.per_bank.is_none(),
        "no consent control plane loaded ⇒ no bank may be named"
    );
    assert_eq!(
        r.disclosure_withheld_for,
        vec!["bank_a", "bank_b", "bank_c"]
    );
    assert!(
        !r.result.buckets.is_empty(),
        "the AGGREGATE still ships — never a hard failure"
    );

    // (b) Two of three banks consent — §6.4 is all-or-nothing, so the breakdown is still withheld,
    // and the report names exactly the bank that has not opted in.
    let partial = DisclosureConsentRegistry::load(vec![
        DisclosureConsent::new("bank_a").allow_class("mule_velocity"),
        DisclosureConsent::new("bank_b").allow_class("mule_velocity"),
    ])
    .unwrap();
    let broker = FederatedBroker::new(&reg, k(), dp()).with_consent(&partial);
    let mut ledger = EpsilonLedger::new();
    let r = broker
        .dispatch(
            "mule_velocity",
            "2026-07",
            0.1,
            10.0,
            &mut ledger,
            &tenants,
            true,
        )
        .unwrap();
    assert!(r.result.per_bank.is_none());
    assert_eq!(r.disclosure_withheld_for, vec!["bank_c"]);

    // (c) A REVOKED consent withdraws disclosure, and a consent for a DIFFERENT metric class does
    // not carry over — both are checked, not just presence of a record.
    let revoked = DisclosureConsentRegistry::load(vec![
        DisclosureConsent::new("bank_a").allow_class("mule_velocity"),
        DisclosureConsent::new("bank_b")
            .allow_class("mule_velocity")
            .revoked(),
        DisclosureConsent::new("bank_c").allow_class("settlement_failures"),
    ])
    .unwrap();
    let broker = FederatedBroker::new(&reg, k(), dp()).with_consent(&revoked);
    let mut ledger = EpsilonLedger::new();
    let r = broker
        .dispatch(
            "mule_velocity",
            "2026-07",
            0.1,
            10.0,
            &mut ledger,
            &tenants,
            true,
        )
        .unwrap();
    assert!(r.result.per_bank.is_none());
    assert_eq!(r.disclosure_withheld_for, vec!["bank_b", "bank_c"]);

    // (d) Every bank consents for this metric class → the breakdown is disclosed.
    let full = DisclosureConsentRegistry::load(vec![
        DisclosureConsent::new("bank_a").allow_class("mule_velocity"),
        DisclosureConsent::new("bank_b").allow_class("mule_velocity"),
        DisclosureConsent::new("bank_c").allow_class("mule_velocity"),
    ])
    .unwrap();
    let broker = FederatedBroker::new(&reg, k(), dp()).with_consent(&full);
    let mut ledger = EpsilonLedger::new();
    let r = broker
        .dispatch(
            "mule_velocity",
            "2026-07",
            0.1,
            10.0,
            &mut ledger,
            &tenants,
            true,
        )
        .unwrap();
    assert!(r.disclosure_withheld_for.is_empty());
    assert_eq!(
        r.result.per_bank.as_ref().map(|rows| rows.len()),
        Some(3),
        "with every bank's standing opt-in the breakdown is disclosed"
    );

    // (e) Not asking still means not disclosed (aggregate-only default is unchanged).
    let mut ledger = EpsilonLedger::new();
    let r = broker
        .dispatch(
            "mule_velocity",
            "2026-07",
            0.1,
            10.0,
            &mut ledger,
            &tenants,
            false,
        )
        .unwrap();
    assert!(r.result.per_bank.is_none());
    assert!(r.disclosure_withheld_for.is_empty());
}

#[test]
fn r16_disclosure_consent_control_plane_loads_from_reviewed_files() {
    // The git-reviewed shape: one file per bank, the record's own bank_id must match its file.
    let a = serde_json::to_string(&DisclosureConsent::new("bank_a").allow_class("mule_velocity"))
        .unwrap();
    let ok = DisclosureConsentRegistry::load_from_files(&[("bank_a", a.as_str())]).unwrap();
    assert!(ok.permits("bank_a", "mule_velocity"));
    assert!(!ok.permits("bank_a", "settlement_failures"));
    assert!(!ok.permits("bank_z", "mule_velocity"), "absence is refusal");

    // A record smuggled into another bank's file fails the whole load.
    assert!(DisclosureConsentRegistry::load_from_files(&[("bank_b", a.as_str())]).is_err());
}

#[test]
fn r16_epsilon_ledger_survives_a_restart() {
    let mut journal = InMemoryEpsilonJournal::new();
    let mut ledger = EpsilonLedger::new();

    // Spend 0.6 of a 1.0 budget across two queries, write-ahead-durably.
    assert!(ledger
        .try_spend_durable(&mut journal, "mule_velocity", "2026-07", 0.4, 1.0)
        .is_ok());
    assert!(ledger
        .try_spend_durable(&mut journal, "mule_velocity", "2026-07", 0.2, 1.0)
        .is_ok());
    assert!((ledger.spent("mule_velocity", "2026-07") - 0.6).abs() < 1e-12);

    // *** RESTART *** — the process dies and a fresh ledger is built. Before this round the budget
    // reset to zero here, so an attacker could re-spend the full ε again and average out the noise.
    let restarted = EpsilonLedger::load_from(&journal);
    assert!(
        (restarted.spent("mule_velocity", "2026-07") - 0.6).abs() < 1e-12,
        "the durable journal must carry the spend across the restart"
    );

    // The remaining budget is genuinely only 0.4: a 0.5 spend after the restart is refused.
    let mut restarted = restarted;
    let err = restarted
        .try_spend_durable(&mut journal, "mule_velocity", "2026-07", 0.5, 1.0)
        .unwrap_err();
    assert!(matches!(err, EpsilonSpendError::Exhausted(_)));
    assert_eq!(journal.len(), 2, "a refused spend appends nothing");

    // A different (metric, window) has its own independent budget.
    assert!(restarted
        .try_spend_durable(&mut journal, "mule_velocity", "2026-08", 0.9, 1.0)
        .is_ok());
}

#[test]
fn r16_epsilon_debit_that_cannot_be_persisted_is_refused() {
    let mut journal = InMemoryEpsilonJournal::new();
    let mut ledger = EpsilonLedger::new();
    journal.fail_next_append = true;

    let err = ledger
        .try_spend_durable(&mut journal, "mule_velocity", "2026-07", 0.4, 1.0)
        .unwrap_err();
    assert!(matches!(err, EpsilonSpendError::NotDurable { .. }));
    // Write-ahead: because the persist failed, the in-memory ledger did NOT advance — the budget is
    // never spent in a way a restart would forget, and it is never spent twice either.
    assert_eq!(ledger.spent("mule_velocity", "2026-07"), 0.0);
    assert!(journal.is_empty());

    // The store recovers; the same debit now commits exactly once.
    assert!(ledger
        .try_spend_durable(&mut journal, "mule_velocity", "2026-07", 0.4, 1.0)
        .is_ok());
    assert_eq!(journal.len(), 1);
    assert_eq!(
        EpsilonLedger::load_from(&journal).spent("mule_velocity", "2026-07"),
        0.4
    );
}
