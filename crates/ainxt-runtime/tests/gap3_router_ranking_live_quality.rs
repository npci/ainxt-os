// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-AUDIT tooling-mcp-plugins-routing — "Model-router ranking not fed a signal".
//!
//! `ModelRouter::select_chain_graded` (§4.1 step 4 / §4.3) is real, tested in isolation
//! (`r12_router_graded.rs`), and even reaches ONE real call site in `Engine::run_turn`'s pinned-tier
//! path — but that call site hardcoded a permanently-EMPTY metrics map. Every eligible candidate
//! therefore scored as the neutral (0,0,0) default and the "ranking" collapsed to a pure alphabetical
//! tie-break (`a.id().cmp(&b.id())`), regardless of how good or bad any candidate's live quality
//! actually was. Meanwhile the FI-07 `MonitoringScoreboard`/`QualityCircuitBreaker` machinery already
//! reads a live per-model score — just only for a binary admit/exclude decision, never for ranking.
//!
//! Fail-before: with two ELIGIBLE (both above the breaker bar) providers "alpha" (lower live quality)
//! and "zulu" (higher live quality), the empty-metrics bug always picked "alpha" — alphabetically
//! first, quality-blind. Pass-after: `ModelRouter::live_quality_metrics()` feeds the same live
//! scoreboard into ranking, so "zulu" (the genuinely higher-quality route) is selected instead —
//! proving the signal now actually reaches ranking, not just admission.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use ainxt_protocol::{Event, Request};
use ainxt_responsibleai::{
    DueDiligenceConfig, ModelProvenance, ModelRiskRecord, MonitoringScoreboard,
    QualityCircuitBreaker, RiskClass, ValidationStatus,
};
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::{ModelRouter, RouterClock};
use ainxt_runtime::{engine_with_defaults, TurnError};
use ainxt_types::{DataClass, Principal, Tier};
use tokio::sync::mpsc;

const NOW: u64 = 100;

fn clock() -> RouterClock {
    Arc::new(|| NOW)
}

/// A model-risk record carrying a chosen live monitoring score, both above the 0.8 breaker bar so
/// BOTH providers in the test are admissible — this test is entirely about ranking among eligible
/// survivors, not about the (already-proven, `wire2_fi_07_test.rs`) exclusion gate.
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

fn records(pairs: &[(&str, f64)]) -> BTreeMap<String, ModelRiskRecord> {
    pairs
        .iter()
        .map(|(id, s)| (id.to_string(), record(id, *s)))
        .collect()
}

fn breaker() -> QualityCircuitBreaker {
    QualityCircuitBreaker::new(0.8)
}

#[tokio::test]
async fn pinned_tier_ranking_prefers_the_live_higher_quality_route() {
    // Pin a tier so the run hits `select_chain_graded` (the buggy call site) rather than the
    // unpinned soft-preference path. Both providers are un-tiered (serve any tier), so the hard
    // tier filter excludes neither — this isolates the ranking step itself.
    let req = Request::chat("s", "t", "hi", DataClass::Internal).with_pinned_tier(Tier::Simple);

    let alpha_called = Arc::new(AtomicBool::new(false));
    let zulu_called = Arc::new(AtomicBool::new(false));

    let mut router = ModelRouter::new();
    // Registration order is alphabetically-favorable to "alpha" (the LOWER-quality route) — a pass
    // only succeeds if live-quality ranking, not registration/alphabetical order, drives selection.
    router.register(Box::new(TrackProvider {
        id: "alpha",
        called: alpha_called.clone(),
    }));
    router.register(Box::new(TrackProvider {
        id: "zulu",
        called: zulu_called.clone(),
    }));
    // Both comfortably above the 0.8 breaker bar (both eligible); "zulu" is the genuinely
    // higher-live-quality route.
    let router = router.with_quality_guard(
        records(&[("alpha", 0.85), ("zulu", 0.99)]),
        breaker(),
        DueDiligenceConfig::default(),
        clock(),
    );

    let eng = engine_with_defaults(router);
    let res = run(&eng, &req).await;

    assert!(
        res.is_ok(),
        "a healthy eligible route must serve, got {res:?}"
    );
    assert!(
        zulu_called.load(Ordering::SeqCst),
        "the higher-live-quality route ('zulu', score 0.99) must be selected first"
    );
    assert!(
        !alpha_called.load(Ordering::SeqCst),
        "the lower-live-quality route ('alpha', score 0.85) must NOT be tried first — before the \
         fix, the empty-metrics bug always picked it because it sorts first alphabetically"
    );
}

#[tokio::test]
async fn live_quality_metrics_scales_and_keys_correctly() {
    // Unit-level check on the pure function itself (no engine involved): confirms the 0.0..=1.0 ->
    // 0..=100 scaling and that a provider absent from the quality guard's records contributes no
    // entry (so it falls back to the ranker's neutral default rather than a bogus zero-vs-missing
    // distinction mattering).
    let mut router = ModelRouter::new();
    router.register(Box::new(TrackProvider {
        id: "scored",
        called: Arc::new(AtomicBool::new(false)),
    }));
    router.register(Box::new(TrackProvider {
        id: "unscored",
        called: Arc::new(AtomicBool::new(false)),
    }));
    let router = router.with_quality_guard(
        records(&[("scored", 0.5)]),
        breaker(),
        DueDiligenceConfig::default(),
        clock(),
    );

    let metrics = router.live_quality_metrics();
    assert_eq!(
        metrics.get("scored").map(|m| m.quality_score),
        Some(50),
        "0.5 latest_score must scale to 50 on the 0..=100 RouteMetrics::quality_score axis"
    );
    assert!(
        !metrics.contains_key("unscored"),
        "a provider with no model-risk record contributes no metrics entry"
    );
}
