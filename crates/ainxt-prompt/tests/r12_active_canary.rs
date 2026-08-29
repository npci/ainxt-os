// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R12 (Prompt Engineering, §3 / §8, gap AS) — ACTIVE progressive delivery: a live canary is watched
//! against the last-known-good PRODUCTION and either promoted or auto-rolled-back, where rollback is an
//! INSTANT pointer flip (immutable content-addressed bodies). This proves the `CanaryController` ties
//! the online metrics to the deployment's promote/rollback pointer-flip primitives in one step.
//!
//! FAIL-BEFORE: `ainxt_prompt::canary::CanaryController` did not exist (won't compile). PASS-AFTER:
//! green. Offline + deterministic; live metric computation is the injected seam.

use ainxt_prompt::canary::{ArmMetrics, CanaryController, CanaryDecision, CanaryPolicy};
use ainxt_prompt::registry::Semver;
use ainxt_prompt::served::default_served_chat_prompts;

fn selection(served: &ainxt_prompt::served::ServedChatPrompts) -> Vec<(&str, Semver)> {
    served
        .layer_ids
        .iter()
        .map(|s| (s.as_str(), Semver::new(1, 0, 0)))
        .collect()
}

#[test]
fn r12_regressed_canary_auto_rolls_back_by_pointer_flip() {
    let mut served = default_served_chat_prompts();
    let sel = selection(&served);
    let canary_release = served
        .registry
        .pin_release("chat-prompts-v1-canary", &sel)
        .unwrap();
    let prod_tag_before = served.deployment.prod.tag.clone();
    served.deployment.start_canary(canary_release, 10);
    assert!(served.deployment.canary.is_some());

    let ctrl = CanaryController::new(CanaryPolicy::default());
    // Canary quality regresses −10 pts vs prod → rollback.
    let decision = ctrl.evaluate_and_apply(
        &mut served.deployment,
        &ArmMetrics::new(88.0, 500, 0.02),
        &ArmMetrics::new(78.0, 200, 0.02),
    );
    assert_eq!(decision, CanaryDecision::Rollback);
    assert!(
        served.deployment.canary.is_none(),
        "canary collapsed on rollback"
    );
    assert_eq!(
        served.deployment.prod.tag, prod_tag_before,
        "prod pointer is unchanged — rollback keeps the last-known-good"
    );
}

#[test]
fn r12_healthy_canary_is_promoted_by_pointer_flip() {
    let mut served = default_served_chat_prompts();
    let sel = selection(&served);
    let canary_release = served
        .registry
        .pin_release("chat-prompts-v2", &sel)
        .unwrap();
    served.deployment.start_canary(canary_release, 10);

    let ctrl = CanaryController::new(CanaryPolicy::default());
    let decision = ctrl.evaluate_and_apply(
        &mut served.deployment,
        &ArmMetrics::new(88.0, 500, 0.02),
        &ArmMetrics::new(90.0, 200, 0.01),
    );
    assert_eq!(decision, CanaryDecision::Promote);
    assert_eq!(
        served.deployment.prod.tag, "chat-prompts-v2",
        "prod fast-forwarded onto canary"
    );
    assert!(served.deployment.canary.is_none());
}

#[test]
fn r12_thin_canary_evidence_holds_no_flip() {
    let mut served = default_served_chat_prompts();
    let sel = selection(&served);
    let canary_release = served
        .registry
        .pin_release("chat-prompts-v3", &sel)
        .unwrap();
    served.deployment.start_canary(canary_release, 10);

    let ctrl = CanaryController::new(CanaryPolicy::default());
    // Terrible canary, but only 5 samples → HOLD (never act on thin evidence).
    let decision = ctrl.evaluate_and_apply(
        &mut served.deployment,
        &ArmMetrics::new(88.0, 500, 0.02),
        &ArmMetrics::new(40.0, 5, 0.5),
    );
    assert_eq!(decision, CanaryDecision::Hold);
    assert!(
        served.deployment.canary.is_some(),
        "still soaking — no flip"
    );
}
