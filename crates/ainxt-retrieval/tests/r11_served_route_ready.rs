// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-11: the structured **metric catalog** (ADR-026 closed vocabulary) and the **federated DP**
//! broker are route-ready — exercised here in the exact shape a served handler would call, proving
//! the entrypoints are clean and complete.
//!
//! UPDATE (context-fabric gap-closing pass): both mounts this file originally called out as
//! `needs_hot_wiring` are now live on the served composition root's unified capability registry
//! (`ainxt_runtimed::build_unified_capability_registry_shared`, wired via `governed.rs`) — the
//! `federated_query` capability dispatches through the SAME [`FederatedBroker`] this file exercises
//! offline, and the `structured_query` capability dispatches through the SAME [`MetricCatalog`]
//! compile boundary via `governed::StructuredQueryTool` (see
//! `ainxt-runtimed/tests/r_structured_query_capability_served.rs` for the served-registry proof).
//! This file is kept as-is: it still usefully proves the crate-level objects are correct and
//! route-ready in isolation, independent of the composition root's wiring.

use std::collections::BTreeSet;

use ainxt_retrieval::federation::{
    BankTenant, DpParams, EpsilonLedger, FederatedBroker, FederationError, FederationRegistry,
    KAnonConfig, NoisedPartial,
};
use ainxt_retrieval::structured::{CatalogError, MetricCatalog, MetricDef};
use ainxt_types::DataClass;

// ---- gap 5: metric catalog is the closed vocabulary a query_ledger handler would compile against --

fn catalog() -> MetricCatalog {
    let m = MetricDef::new(
        "failed_settlements",
        "v_settlement_facts",
        DataClass::Confidential,
    )
    .dimension("day", DataClass::Internal)
    .dimension("bank", DataClass::Confidential);
    let deprecated = MetricDef::new("legacy_volume", "v_legacy", DataClass::Internal)
        .dimension("day", DataClass::Internal)
        .deprecated(true);
    MetricCatalog::load(vec![m, deprecated], &BTreeSet::new()).expect("catalog loads")
}

#[test]
fn r11_metric_catalog_route_ready_closed_vocabulary() {
    let cat = catalog();

    // A registered metric + declared dimension compiles to a validated plan (what the handler emits
    // instead of free-form SQL) — carrying the data-class ceiling for the Model Router.
    let plan = cat
        .plan("failed_settlements", &["day"])
        .expect("registered metric plans");
    assert_eq!(plan.source_view, "v_settlement_facts");
    assert_eq!(plan.group_by, vec!["day".to_string()]);
    assert_eq!(plan.data_class_ceiling, DataClass::Confidential);

    // An UNKNOWN metric does not exist to the compiler — fail-closed (never free-form SQL).
    assert!(matches!(
        cat.plan("drop_table_users", &[]),
        Err(CatalogError::UnknownMetric { .. })
    ));
    // An UNKNOWN dimension on a real metric is rejected — the model can only name catalog dimensions.
    assert!(matches!(
        cat.plan("failed_settlements", &["ssn"]),
        Err(CatalogError::UnknownDimension { .. })
    ));
    // A DEPRECATED metric is refused — schema/vocabulary lifecycle is governed.
    assert!(matches!(
        cat.plan("legacy_volume", &[]),
        Err(CatalogError::DeprecatedMetric { .. })
    ));
}

// ---- gap 6: federated DP broker is route-ready for a /v1/federated handler ----------------------

struct Bank {
    id: String,
    partials: Option<Vec<NoisedPartial>>,
}
impl BankTenant for Bank {
    fn bank_id(&self) -> &str {
        &self.id
    }
    fn local_partials(&self, _metric_id: &str, _window: &str) -> Option<Vec<NoisedPartial>> {
        self.partials.clone()
    }
}

fn np(bank: &str, bucket: &str, value: f64, underlying: u64) -> NoisedPartial {
    NoisedPartial {
        bank_id: bank.into(),
        bucket: bucket.into(),
        value,
        underlying_count: underlying,
    }
}

#[test]
fn r11_federated_broker_route_ready_dispatch_kanon_and_budget() {
    let reg = FederationRegistry::new().allow("mule_velocity");
    let broker = FederatedBroker::new(
        &reg,
        KAnonConfig {
            min_banks: 3,
            min_underlying: 100,
        },
        DpParams {
            epsilon: 1.0,
            sensitivity: 1.0,
        },
    );
    let banks: Vec<Bank> = vec![
        Bank {
            id: "b1".into(),
            partials: Some(vec![np("b1", "high", 50.0, 400)]),
        },
        Bank {
            id: "b2".into(),
            partials: Some(vec![np("b2", "high", 60.0, 500)]),
        },
        Bank {
            id: "b3".into(),
            partials: Some(vec![np("b3", "high", 70.0, 600)]),
        },
    ];
    let refs: Vec<&dyn BankTenant> = banks.iter().map(|b| b as &dyn BankTenant).collect();
    let mut ledger = EpsilonLedger::new();

    // A served /v1/federated handler would call exactly this: whitelist gate → ε-budget debit →
    // per-tenant dispatch (isolation-enforced) → k-anon aggregate.
    let report = broker
        .dispatch(
            "mule_velocity",
            "2026-07",
            0.5,
            1.0,
            &mut ledger,
            &refs,
            false,
        )
        .expect("dispatch ok");
    assert_eq!(report.result.buckets.len(), 1);
    assert_eq!(report.result.buckets[0].contributing_banks, 3);
    assert!(
        report.result.per_bank.is_none(),
        "aggregate-only by default"
    );
    assert!((report.epsilon_remaining - 0.5).abs() < 1e-9);

    // A non-whitelisted metric is refused before any bank is contacted (fail-closed).
    let err = broker
        .dispatch(
            "account_balance",
            "w",
            0.1,
            1.0,
            &mut EpsilonLedger::new(),
            &refs,
            false,
        )
        .unwrap_err();
    assert!(matches!(err, FederationError::NotFederated { .. }));
}
