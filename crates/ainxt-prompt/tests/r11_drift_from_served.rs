// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R11 (Prompt Engineering, §8 / PRMT-08) — CONTINUOUS quality-drift detection wired to the SHIPPED
//! deployment. The deploy-time canary gate is point-in-time; this proves the served deployment seeds a
//! per-family drift baseline, and that a sustained degradation on a served `(role, family, version)`
//! stream fires a rollback recommendation while a healthy stream does not.
//!
//! FAIL-BEFORE: `ServedChatPrompts::install_drift_baselines` / `drift_key` did not exist. PASS-AFTER:
//! green. Offline + deterministic (scores are the seam; no live traffic needed for the test).

use ainxt_prompt::drift::{DriftAction, DriftMonitor, DriftPolicy};
use ainxt_prompt::served::default_served_chat_prompts;

#[test]
fn r11_served_deployment_seeds_drift_baselines_for_every_family() {
    let served = default_served_chat_prompts();
    let baselines = served.drift_baselines();
    assert_eq!(
        baselines.len(),
        served.families.len(),
        "one drift stream per served family"
    );
    // Each key names the served family under the chat Role at the pinned artifact version.
    for fam in &served.families {
        let key = served.drift_key(fam);
        assert!(baselines.iter().any(|(k, _)| k == &key));
    }
}

#[test]
fn r11_sustained_degradation_on_a_served_stream_recommends_rollback() {
    let served = default_served_chat_prompts();
    let mut mon = DriftMonitor::new(DriftPolicy::default());
    served.install_drift_baselines(&mut mon);

    let degraded = served.drift_key(&served.families[0]);
    // Baseline is ~88; feed a stream ~68 (a real ~20-point regression) until the monitor confirms.
    let mut event = None;
    for i in 0..80 {
        let s = if i % 2 == 0 { 66 } else { 70 };
        if let Some(e) = mon.observe_score(&degraded, s) {
            event = Some(e);
            break;
        }
    }
    let e = event.expect("a sustained ~20-point drop on a served stream must be flagged as drift");
    assert_eq!(e.action, DriftAction::OpenTicketAndRollback);
    assert!(e.window_mean < e.baseline_mean);

    // A DIFFERENT served family held at baseline never alerts (drift is per-stream, not global).
    if served.families.len() > 1 {
        let healthy = served.drift_key(&served.families[1]);
        for i in 0..80 {
            let s = if i % 2 == 0 { 88 } else { 90 };
            assert!(
                mon.observe_score(&healthy, s).is_none(),
                "a healthy served stream must not alert"
            );
        }
    }
}
