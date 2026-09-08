// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R12 (Prompt Engineering, §8) — CONTINUOUS quality-drift detection is a WIRED control loop, not just
//! a monitor. `DriftController` is the single per-turn entrypoint the served path calls: it samples
//! (cost-bounded), scores the sampled turn with the injected judge, observes it into the rolling
//! window, and returns a rollback recommendation exactly once on confirmed degradation.
//!
//! FAIL-BEFORE: `ainxt_prompt::drift::DriftController` did not exist (won't compile). PASS-AFTER: green.
//! Offline + deterministic; live traffic + live judge model are the injected seams.

use ainxt_eval::{EvalCriteria, QualityJudge, QualityScore};
use ainxt_prompt::drift::{
    Baseline, DriftAction, DriftController, DriftKey, DriftMonitor, DriftPolicy, SamplingPolicy,
};

struct FixedJudge(u8);
impl QualityJudge for FixedJudge {
    fn score(&self, _i: &str, _o: &str, _c: &EvalCriteria) -> QualityScore {
        QualityScore {
            score: self.0,
            rationale: String::new(),
        }
    }
}

fn key() -> DriftKey {
    DriftKey::new("prompt.chat", "qwen", "1.0.0")
}

fn criteria() -> EvalCriteria {
    EvalCriteria {
        rubric: "chat quality".into(),
        threshold: 60,
    }
}

#[test]
fn r12_controller_samples_scores_and_recommends_rollback_on_sustained_drift() {
    let mut ctrl = DriftController::new(
        SamplingPolicy::new(100), // sample every turn for a deterministic test
        DriftMonitor::new(DriftPolicy::default()),
        criteria(),
    );
    ctrl.set_baseline(key(), Baseline::new(90.0));

    let judge = FixedJudge(60); // the served model silently got ~30 pts worse
    let mut event = None;
    for i in 0..80 {
        if let Some(e) = ctrl.on_live_turn(&key(), &format!("turn-{i}"), "in", "out", &judge) {
            event = Some(e);
            break;
        }
    }
    let e = event.expect("a sustained degradation on a served stream must recommend rollback");
    assert_eq!(e.action, DriftAction::OpenTicketAndRollback);
    assert!(e.window_mean < e.baseline_mean);
}

#[test]
fn r12_controller_skips_unsampled_turns_no_judge_no_alert() {
    let mut ctrl = DriftController::new(
        SamplingPolicy::new(0), // 0% → never scores (bounded cost)
        DriftMonitor::new(DriftPolicy::default()),
        criteria(),
    );
    ctrl.set_baseline(key(), Baseline::new(90.0));
    let judge = FixedJudge(5); // catastrophic — but no turn is ever sampled
    for i in 0..200 {
        assert!(ctrl
            .on_live_turn(&key(), &format!("t{i}"), "in", "out", &judge)
            .is_none());
    }
    assert!(
        ctrl.window_mean(&key()).is_none(),
        "no sampled turn was ever scored"
    );
}
