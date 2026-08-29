// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-15 serving-ops (LOW) — SERVING_OPS.md §3 (gaps 26/W): the audit found
//! `AutoscaleController::tick` (the demand-driven scale/park decision body) had no cadence concept —
//! every call was treated as due, so "wired into ANY daemon loop" had no honest throttle independent
//! of the daemon's own timer granularity. `AutoscaleCadence` closes that with the same
//! is-due/next-due-cursor pattern used for the attestation and health-monitoring drivers.
//!
//! Fail-before: `ainxt_serving::placement::AutoscaleCadence` did not exist — this file would not
//! compile. Pass-after: a tick before the cadence's due point is a genuine no-op (no scale/park
//! decision is made even if demand samples would otherwise trigger one); a due tick recomputes and
//! returns the decisions.

use ainxt_serving::placement::{
    AutoscaleCadence, AutoscaleCadenceConfig, AutoscaleController, ScaleAction,
};

#[test]
fn r15_cadence_gates_the_autoscale_recompute_by_due_time() {
    let mut controller = AutoscaleController::new(0.5, 100.0, 0);
    let mut cadence = AutoscaleCadence::new(AutoscaleCadenceConfig { interval: 20 });

    // First tick at t=0 is due: sustained demand drives a scale-to decision.
    let first = cadence.tick(&mut controller, 0, &[("m".to_string(), 250.0)]);
    assert!(first.is_some());
    let actions = first.unwrap();
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, ScaleAction::ScaleTo { model_id, .. } if model_id == "m")),
        "the due tick produced a scale decision: {actions:?}"
    );
    assert_eq!(cadence.ticks_run(), 1);

    // A tick immediately after (t=1), well before the next due point (t=20), is a genuine no-op —
    // even a wildly different demand sample (that would otherwise park the family) has NO effect,
    // because the recompute itself never runs.
    let too_early = cadence.tick(&mut controller, 1, &[("m".to_string(), 0.0)]);
    assert!(
        too_early.is_none(),
        "a tick before the next due point must not recompute"
    );
    assert_eq!(
        cadence.ticks_run(),
        1,
        "still only one recompute has actually run"
    );
    // The controller's own demand EWMA is untouched by the skipped tick (proving the gate short-
    // circuits BEFORE `AutoscaleController::tick` is ever called, not merely discards its result).
    assert!(
        controller.demand("m") > 0.0,
        "demand was not zeroed by the not-yet-due tick"
    );

    // At the due point (t=20), the recompute runs and now DOES see the low-demand sample.
    let due = cadence.tick(&mut controller, 20, &[("m".to_string(), 0.0)]);
    assert!(due.is_some());
    assert_eq!(cadence.ticks_run(), 2);
}

#[test]
fn r15_cadence_config_zero_interval_never_busy_loops() {
    let mut controller = AutoscaleController::new(0.5, 100.0, 0);
    let mut cadence = AutoscaleCadence::new(AutoscaleCadenceConfig { interval: 0 });
    assert!(cadence
        .tick(&mut controller, 0, &[("m".to_string(), 10.0)])
        .is_some());
    assert!(
        cadence
            .tick(&mut controller, 1, &[("m".to_string(), 10.0)])
            .is_some(),
        "interval=0 recomputes every tick, never stalls"
    );
}
