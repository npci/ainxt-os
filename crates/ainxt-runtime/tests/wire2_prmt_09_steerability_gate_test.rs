// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Wiring test for gap closure `PROMPT_ENGINEERING.md` §9: `ainxt_prompt::steerability::is_eligible`
//! had zero callers. `ModelRouter::with_steerability_gate` folds a caller-certified steerability
//! eligible-id set into the SAME non-overridable admission chain FI-03/FI-07 already run through
//! (`route_admissible`) — so a model family whose steerability score is below the Role's bar is
//! excluded from `select`/`select_chain`/`eligible_ids` exactly like a data-class or governance
//! exclusion, never merely advisory.
//!
//! Mirrors `wire2_fi_07_test.rs`'s structure/assertions for the analogous FI-07 gate.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use ainxt_protocol::{Event, Request};
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::{ModelRouter, RouteError};
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

#[tokio::test]
async fn wire2_prmt_09_no_gate_installed_preserves_pre_wire_behavior() {
    // With no `with_steerability_gate` call, a provider serves exactly as before this gap closure.
    let req = Request::chat("s", "t", "hi", DataClass::Internal);
    let called = Arc::new(AtomicBool::new(false));
    let mut router = ModelRouter::new();
    router.register(Box::new(TrackProvider {
        id: "qwen",
        called: called.clone(),
    }));
    let eng = engine_with_defaults(router);
    let res = run(&eng, &req).await;
    assert!(
        res.is_ok(),
        "no gate installed must not exclude anything, got {res:?}"
    );
    assert!(called.load(Ordering::SeqCst));
}

#[tokio::test]
async fn wire2_prmt_09_a_family_below_the_steerability_bar_is_excluded() {
    // "qwen" is NOT in the caller-certified eligible set (its steerability score is below the Role's
    // bar) → excluded before ranking/failover, never contacted.
    let req = Request::chat("s", "t", "hi", DataClass::Internal);
    let called = Arc::new(AtomicBool::new(false));
    let mut router = ModelRouter::new();
    router.register(Box::new(TrackProvider {
        id: "qwen",
        called: called.clone(),
    }));
    let router = router.with_steerability_gate(["claude".to_string()]);
    let eng = engine_with_defaults(router);
    let res = run(&eng, &req).await;
    assert!(
        matches!(res, Err(TurnError::Routing(RouteError::NoEligible(_)))),
        "a family below the steerability bar must be excluded, got {res:?}"
    );
    assert!(
        !called.load(Ordering::SeqCst),
        "an excluded family must never be contacted"
    );
}

#[tokio::test]
async fn wire2_prmt_09_a_family_at_or_above_the_bar_serves() {
    let req = Request::chat("s", "t", "hi", DataClass::Internal);
    let called = Arc::new(AtomicBool::new(false));
    let mut router = ModelRouter::new();
    router.register(Box::new(TrackProvider {
        id: "claude",
        called: called.clone(),
    }));
    let router = router.with_steerability_gate(["claude".to_string()]);
    let eng = engine_with_defaults(router);
    let res = run(&eng, &req).await;
    assert!(
        res.is_ok(),
        "a certified-eligible family must serve, got {res:?}"
    );
    assert!(called.load(Ordering::SeqCst));
}

#[tokio::test]
async fn wire2_prmt_09_exclusion_runs_before_ranking_the_certified_family_serves() {
    // A below-bar family registered FIRST must not be tried even though it would otherwise rank first.
    let req = Request::chat("s", "t", "hi", DataClass::Internal);
    let weak = Arc::new(AtomicBool::new(false));
    let strong = Arc::new(AtomicBool::new(false));
    let mut router = ModelRouter::new();
    router.register(Box::new(TrackProvider {
        id: "weak-self-hosted",
        called: weak.clone(),
    }));
    router.register(Box::new(TrackProvider {
        id: "claude",
        called: strong.clone(),
    }));
    let router = router.with_steerability_gate(["claude".to_string()]);
    let eng = engine_with_defaults(router);
    let res = run(&eng, &req).await;
    assert!(res.is_ok(), "the certified family must serve, got {res:?}");
    assert!(
        strong.load(Ordering::SeqCst),
        "the certified family must be contacted"
    );
    assert!(
        !weak.load(Ordering::SeqCst),
        "the below-bar family must never be contacted"
    );
}

#[tokio::test]
async fn wire2_prmt_09_non_overridable_forcing_an_excluded_family_is_still_refused() {
    let mut req = Request::chat("s", "t", "hi", DataClass::Internal);
    req.forced_provider = Some("qwen".to_string());
    let called = Arc::new(AtomicBool::new(false));
    let mut router = ModelRouter::new();
    router.register(Box::new(TrackProvider {
        id: "qwen",
        called: called.clone(),
    }));
    let router = router.with_steerability_gate(["claude".to_string()]);
    let eng = engine_with_defaults(router);
    let res = run(&eng, &req).await;
    assert!(
        matches!(
            res,
            Err(TurnError::Routing(RouteError::ForcedNotEligible(_, _)))
        ),
        "forcing a below-bar family must still be refused (non-overridable), got {res:?}"
    );
    assert!(!called.load(Ordering::SeqCst));
}

/// Proves the gate is genuinely fed by `ainxt_prompt::steerability::is_eligible` — not a
/// router-internal reinvention of the eligibility rule. Builds a real `SteerabilityScore` per family,
/// derives the eligible-id set via `is_eligible`, and installs exactly that on the router.
#[tokio::test]
async fn wire2_prmt_09_eligible_set_is_derived_from_the_real_steerability_engine() {
    use ainxt_prompt::steerability::{grade_case, is_eligible, score, Constraint};

    let constraints = vec![Constraint::ExactBullets { n: 2 }];
    // "claude" passes its steerability case (2 bullets as required) → is_eligible(0.9) == true.
    let claude_score = score(
        "claude",
        "role.support@7",
        vec![grade_case("c1", "- a\n- b", &constraints)],
    );
    // "qwen" fails its steerability case (3 bullets, not 2) → is_eligible(0.9) == false.
    let qwen_score = score(
        "qwen",
        "role.support@7",
        vec![grade_case("c1", "- a\n- b\n- c", &constraints)],
    );
    let bar = 0.9;
    assert!(is_eligible(&claude_score, bar));
    assert!(!is_eligible(&qwen_score, bar));

    let eligible_ids: Vec<String> = [("claude", &claude_score), ("qwen", &qwen_score)]
        .into_iter()
        .filter(|(_, s)| is_eligible(s, bar))
        .map(|(id, _)| id.to_string())
        .collect();
    assert_eq!(eligible_ids, vec!["claude".to_string()]);

    let req = Request::chat("s", "t", "hi", DataClass::Internal);
    let qwen_called = Arc::new(AtomicBool::new(false));
    let claude_called = Arc::new(AtomicBool::new(false));
    let mut router = ModelRouter::new();
    router.register(Box::new(TrackProvider {
        id: "qwen",
        called: qwen_called.clone(),
    }));
    router.register(Box::new(TrackProvider {
        id: "claude",
        called: claude_called.clone(),
    }));
    let router = router.with_steerability_gate(eligible_ids);
    let eng = engine_with_defaults(router);
    let res = run(&eng, &req).await;
    assert!(res.is_ok());
    assert!(claude_called.load(Ordering::SeqCst));
    assert!(!qwen_called.load(Ordering::SeqCst));
}
