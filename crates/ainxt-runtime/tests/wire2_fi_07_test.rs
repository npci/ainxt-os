// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Wiring test for gap FI-07: the SR-11-7 model-risk record + quality circuit-breaker are consulted
//! by the router so a tripped or un-certified route is NOT selected ("monitored, not certified-once"
//! enforced live).
//!
//! Drives the REAL assembled `Engine`. It proves, on the live path:
//!   1. A route whose live scoreboard is below the bar trips the circuit-breaker and is excluded.
//!   2. A healthy, promotable route is selected and serves.
//!   3. A route WITHOUT a model-risk record is not quality-gated (in-house default).
//!   4. Exclusion happens before ranking/failover: given a degraded + a healthy route, the healthy
//!      one serves and the degraded one is never contacted.
//!   5. The gate is non-overridable: forcing a tripped route is still refused.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use ainxt_protocol::{Event, Request};
use ainxt_responsibleai::{
    DueDiligenceConfig, ModelProvenance, ModelRiskRecord, MonitoringScoreboard,
    QualityCircuitBreaker, RiskClass, ValidationStatus,
};
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::{ModelRouter, RouteError, RouterClock};
use ainxt_runtime::{engine_with_defaults, TurnError};
use ainxt_types::{DataClass, Principal};
use tokio::sync::mpsc;

struct TrackProvider {
    id: &'static str,
    called: Arc<AtomicBool>,
}
impl Provider for TrackProvider {
    fn id(&self) -> &str {
        self.id
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, _prompt: &str) -> mpsc::Receiver<Event> {
        self.called.store(true, Ordering::SeqCst);
        let (tx, rx) = mpsc::channel(8);
        tokio::spawn(async move {
            let _ = tx.send(Event::TextDelta("served".into())).await;
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

const NOW: u64 = 100;

fn clock() -> RouterClock {
    Arc::new(|| NOW)
}

/// A model-risk record with a chosen live monitoring score. Independently validated, Limited risk
/// (no challenger required), in-house, fresh scoreboard at `NOW`.
fn record(model_id: &str, score: f64) -> ModelRiskRecord {
    ModelRiskRecord {
        model_id: model_id.to_string(),
        provenance: ModelProvenance::InHouse,
        permitted_data_class: DataClass::Internal,
        intended_use: "chat".to_string(),
        risk_class: RiskClass::Limited,
        validation: ValidationStatus::IndependentlyValidated { at_tick: 1 },
        challenger: None,
        monitoring: Some(MonitoringScoreboard::new(score, 500, NOW)),
        limitations: vec![],
    }
}

fn records(pairs: &[(&str, f64)]) -> BTreeMap<String, ModelRiskRecord> {
    pairs
        .iter()
        .map(|(id, s)| (id.to_string(), record(id, *s)))
        .collect()
}

async fn run(
    eng: &ainxt_runtime::Engine,
    req: &Request,
) -> Result<ainxt_runtime::TurnSummary, TurnError> {
    let (tx, mut rx) = mpsc::channel::<Event>(64);
    let p = Principal::user("u", &["chat.send"]);
    let fut = eng.run_turn(&p, req, tx);
    let drain = async move { while rx.recv().await.is_some() {} };
    let (res, ()) = tokio::join!(fut, drain);
    res
}

fn breaker() -> QualityCircuitBreaker {
    QualityCircuitBreaker::new(0.8)
}

#[tokio::test]
async fn wire2_fi_07() {
    let req = Request::chat("s", "t", "hi", DataClass::Internal);

    // --- 1. A degraded route (score 0.5 < bar 0.8) trips the breaker → excluded → NoEligible. ---
    {
        let called = Arc::new(AtomicBool::new(false));
        let mut router = ModelRouter::new();
        router.register(Box::new(TrackProvider {
            id: "degraded",
            called: called.clone(),
        }));
        let router = router.with_quality_guard(
            records(&[("degraded", 0.5)]),
            breaker(),
            DueDiligenceConfig::default(),
            clock(),
        );
        let eng = engine_with_defaults(router);
        let res = run(&eng, &req).await;
        assert!(
            matches!(res, Err(TurnError::Routing(RouteError::NoEligible(_)))),
            "a tripped route must be excluded, got {res:?}"
        );
        assert!(
            !called.load(Ordering::SeqCst),
            "a tripped route must never be contacted"
        );
    }

    // --- 2. A healthy route (score 0.95) is promotable + breaker closed → serves. ---
    {
        let called = Arc::new(AtomicBool::new(false));
        let mut router = ModelRouter::new();
        router.register(Box::new(TrackProvider {
            id: "healthy",
            called: called.clone(),
        }));
        let router = router.with_quality_guard(
            records(&[("healthy", 0.95)]),
            breaker(),
            DueDiligenceConfig::default(),
            clock(),
        );
        let eng = engine_with_defaults(router);
        let res = run(&eng, &req).await;
        assert!(res.is_ok(), "a healthy route must serve, got {res:?}");
        assert!(called.load(Ordering::SeqCst));
    }

    // --- 3. A route with NO model-risk record is not quality-gated → serves (in-house default). ---
    {
        let called = Arc::new(AtomicBool::new(false));
        let mut router = ModelRouter::new();
        router.register(Box::new(TrackProvider {
            id: "unlisted",
            called: called.clone(),
        }));
        let router = router.with_quality_guard(
            records(&[("some-other-route", 0.95)]),
            breaker(),
            DueDiligenceConfig::default(),
            clock(),
        );
        let eng = engine_with_defaults(router);
        let res = run(&eng, &req).await;
        assert!(
            res.is_ok(),
            "a route without a record is not gated, got {res:?}"
        );
        assert!(called.load(Ordering::SeqCst));
    }

    // --- 4. Degraded (registered first) + healthy: the healthy route serves, degraded is skipped. ---
    {
        let deg = Arc::new(AtomicBool::new(false));
        let ok = Arc::new(AtomicBool::new(false));
        let mut router = ModelRouter::new();
        router.register(Box::new(TrackProvider {
            id: "degraded",
            called: deg.clone(),
        }));
        router.register(Box::new(TrackProvider {
            id: "healthy",
            called: ok.clone(),
        }));
        let router = router.with_quality_guard(
            records(&[("degraded", 0.5), ("healthy", 0.95)]),
            breaker(),
            DueDiligenceConfig::default(),
            clock(),
        );
        let eng = engine_with_defaults(router);
        let res = run(&eng, &req).await;
        assert!(res.is_ok(), "the healthy route must serve, got {res:?}");
        assert!(
            ok.load(Ordering::SeqCst),
            "the healthy route must be contacted"
        );
        assert!(
            !deg.load(Ordering::SeqCst),
            "the tripped route must be excluded before ranking, never contacted"
        );
    }

    // --- 5. Non-overridable: forcing the tripped route is still refused. ---
    {
        let called = Arc::new(AtomicBool::new(false));
        let mut router = ModelRouter::new();
        router.register(Box::new(TrackProvider {
            id: "degraded",
            called: called.clone(),
        }));
        let router = router.with_quality_guard(
            records(&[("degraded", 0.5)]),
            breaker(),
            DueDiligenceConfig::default(),
            clock(),
        );
        let eng = engine_with_defaults(router);
        let mut forced = req.clone();
        forced.forced_provider = Some("degraded".to_string());
        let res = run(&eng, &forced).await;
        assert!(
            matches!(
                res,
                Err(TurnError::Routing(RouteError::ForcedNotEligible(_, _)))
            ),
            "a forced tripped route must be refused (non-overridable), got {res:?}"
        );
        assert!(!called.load(Ordering::SeqCst));
    }
}
