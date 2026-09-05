// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-12 gap-closing integration test (eval-tester-scenarios, MEDIUM):
//! **"Merge-blocking CI wiring of the DoD/eval gate."**
//!
//! `ci::merge_status_check` composed the eval gate with additional required checks, but treated an
//! empty/short `additional` list as an implicit pass: `merge_status_check(ship, &[])` returned
//! `Success` on the QUALITY gate alone. The DoD is BOTH gates green (`AINXT_OS.md` §130) — a PR whose
//! Scenario-Matrix (safety/correctness) job never reported (crashed / skipped / unconfigured) would
//! then merge on the eval gate only. `ci::merge_status_check_required` closes that hole: a named
//! required gate that is ABSENT is fail-closed, exactly like a present-but-failed one.
//!
//! Fail-before: `merge_status_check_required` / `SCENARIO_MATRIX_CHECK` did not exist. Pass-after: the
//! composite required check is `Success` only when the eval gate ships AND the Scenario-Matrix gate is
//! present-and-green; a missing OR failing matrix gate blocks the merge.
//!
//! (Posting the resulting `StatusCheck` to the live GitLab commit-status API + registering it as a
//! branch-protection required check is a CI-pipeline / network concern — infra-gated. This proves the
//! decision that drives it.)

use ainxt_eval::audit::VerdictRecord;
use ainxt_eval::ci::{
    merge_status_check, merge_status_check_required, CheckState, CiGateOutcome, RequiredCheck,
    EXIT_BLOCK, EXIT_SHIP, SCENARIO_MATRIX_CHECK,
};
use ainxt_eval::pipeline::{ReleaseDecision, ReleaseGateReport};

fn outcome(mergeable: bool) -> CiGateOutcome {
    CiGateOutcome {
        merge_blocked: !mergeable,
        exit_code: if mergeable { EXIT_SHIP } else { EXIT_BLOCK },
        summary: if mergeable {
            "SHIP: release gate passed".into()
        } else {
            "BLOCK: statistical regression".into()
        },
        report: ReleaseGateReport {
            decision: if mergeable {
                ReleaseDecision::Ship
            } else {
                ReleaseDecision::Block(vec!["statistical regression".into()])
            },
            statistical: None,
            warnings: Vec::new(),
            verdict: VerdictRecord {
                eval_set_id: "s1".into(),
                eval_set_version: "v1".into(),
                judge_version: "j1".into(),
                candidate_sha: "sha".into(),
                params_hash: "ph".into(),
                seed: 1,
                dimension: "correctness".into(),
                outcome: if mergeable {
                    "pass".into()
                } else {
                    "block".into()
                },
                effect: 0.0,
                epoch: 1,
            },
            judge_version: "j1".into(),
            scored: 3,
        },
    }
}

#[test]
fn r12_merge_blocking_dod_gate() {
    let required = [SCENARIO_MATRIX_CHECK];
    let matrix_green = RequiredCheck::new(SCENARIO_MATRIX_CHECK, true, "1000 scenarios green");
    let matrix_red =
        RequiredCheck::new(SCENARIO_MATRIX_CHECK, false, "3 injection scenarios failed");

    // 1. Eval ships AND the matrix gate is present-and-green → the ONE required check is Success.
    let ok = merge_status_check_required(
        &outcome(true),
        std::slice::from_ref(&matrix_green),
        &required,
    );
    assert_eq!(
        ok.state,
        CheckState::Success,
        "both DoD gates green → mergeable: {ok:?}"
    );
    assert!(ok.allows_merge());

    // 2. THE HOLE THIS CLOSES: eval ships but the matrix gate is ABSENT → fail-closed (not a pass).
    let missing = merge_status_check_required(&outcome(true), &[], &required);
    assert_eq!(
        missing.state,
        CheckState::Failure,
        "a missing required gate must block: {missing:?}"
    );
    assert!(missing.description.contains(SCENARIO_MATRIX_CHECK));
    // The lax composer would have PASSED this same input — proving the strict version is stronger.
    assert_eq!(
        merge_status_check(&outcome(true), &[]).state,
        CheckState::Success,
        "the lax composer passes eval-only (the exact gap the strict one closes)"
    );

    // 3. Eval ships but the matrix gate FAILED → blocked.
    let matrix_failed = merge_status_check_required(&outcome(true), &[matrix_red], &required);
    assert_eq!(matrix_failed.state, CheckState::Failure);

    // 4. The matrix passes but the EVAL gate blocked → still blocked (both directions).
    let eval_blocked = merge_status_check_required(&outcome(false), &[matrix_green], &required);
    assert_eq!(eval_blocked.state, CheckState::Failure);
    assert!(eval_blocked.description.contains("eval-gate"));
    assert!(!eval_blocked.allows_merge());
}
