// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! The dogfood-runner / CI **enforcer** that actually invokes the composed release gate
//! (EVAL_PLATFORM.md §11 + §"CI wiring").
//!
//! [`crate::ci::run_release_gate_ci`] is the callable merge-check surface, but it takes a fully
//! assembled [`ReleaseGateRequest`] — the encrypted sealed corpus, the Event Log, the in-house Judge,
//! and the *dogfooded* baseline/candidate systems already wired together. Nothing outside this crate's
//! own tests assembled that request, so in practice the keystone gate was never enforced: there was no
//! non-test entrypoint a required status check / dogfood job could call.
//!
//! This module is that enforcer. It splits the two responsibilities cleanly:
//!
//! * [`ReleaseGateProvider`] — the **seam** a dogfood runner / CI job implements to assemble the
//!   release inputs. It uses a visitor (`FnMut` callback) so the provider owns every borrowed input
//!   (the loaded corpus, the systems, the calibration slices) for exactly the duration of the gate
//!   call, without leaking self-referential lifetimes across the trait boundary. A provider that
//!   cannot assemble the inputs (sealed store unavailable, the dogfood run itself failed, the candidate
//!   build is missing) returns `Err` — and the enforcer maps that to a **fail-closed** merge block, so
//!   a gate that could not run can never be mistaken for a gate that passed.
//!
//! * [`run_merge_check`] — the single non-test entrypoint. It drives the provider through the real
//!   [`crate::ci::run_release_gate_ci`] (so every instrument runs and the reproduce-from-SHA verdict is
//!   written to the Event Log before the decision returns) and returns a [`MergeCheck`] that a CI
//!   binary consumes: a merge-block boolean, a process exit code, and a stable summary line.
//!
//! The durable backends behind [`ReleaseGateProvider`] (the encrypted corpus store, the tamper-evident
//! Event Log, the in-house Judge, the runner that produces the systems) live in the reserved
//! daemon/serving crates, and the *process* wiring that reports [`MergeCheck::process_exit_code`] to
//! branch protection is a CI pipeline / thin `cargo xtask eval-gate` binary — both out-of-crate
//! (infra-gated). This module composes and runs the actual gate in-process, never a stand-in, and is
//! exercised end-to-end against a deterministic provider in the integration tests.

use crate::audit::EventSink;
use crate::ci::{run_release_gate_ci, CiGateOutcome, EXIT_INDETERMINATE};
use crate::pipeline::ReleaseGateRequest;

/// The seam a dogfood runner / CI job implements to assemble the release-gate inputs and run the gate.
///
/// Implementors load the sealed corpus, stand up the in-house Judge, run the *dogfooded* baseline and
/// candidate systems, and gather the calibration / contamination / rotation / vault evidence — then
/// build a [`ReleaseGateRequest`] and hand it (plus the Event-Log sink) to `run`. Because a
/// `ReleaseGateRequest` borrows all of those, the visitor shape lets the provider keep them alive on
/// its own stack for the call and drop them after, with no `'static` requirement and no arena.
pub trait ReleaseGateProvider {
    /// Assemble the release inputs and invoke `run` exactly once with a borrowed request + a mutable
    /// Event-Log sink. Return `Ok(())` once the gate has been run; return `Err(reason)` if the inputs
    /// could not be assembled at all (store down / dogfood run failed / candidate build missing) — the
    /// enforcer treats that as fail-closed, never a pass.
    fn with_release_inputs(
        &self,
        run: &mut dyn FnMut(&ReleaseGateRequest<'_>, &mut dyn EventSink),
    ) -> Result<(), String>;
}

/// The outcome of a merge-check run: either the composed gate ran (carrying its full CI outcome), or
/// the provider could not assemble the inputs and the merge is blocked fail-closed. Transient
/// control-flow value (one per merge-check), never bulk-allocated — boxing the large arm would only
/// add an allocation on the CI path.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub enum MergeCheck {
    /// The composed release gate ran; carries the [`CiGateOutcome`] (decision + exit code + report).
    Ran(CiGateOutcome),
    /// The release inputs could not be assembled (or the provider returned `Ok` without running the
    /// gate) — fail-closed: the merge is blocked and the exit code is `EXIT_INDETERMINATE`.
    FailClosed { summary: String },
}

impl MergeCheck {
    /// True when the change must NOT merge. A `FailClosed` always blocks; a `Ran` blocks per its gate.
    pub fn merge_blocked(&self) -> bool {
        match self {
            MergeCheck::Ran(o) => o.merge_blocked,
            MergeCheck::FailClosed { .. } => true,
        }
    }

    /// The change may merge iff the gate ran and explicitly shipped.
    pub fn is_mergeable(&self) -> bool {
        !self.merge_blocked()
    }

    /// Process exit code — the gate's own code when it ran, else `EXIT_INDETERMINATE` (fail-closed).
    pub fn exit_code(&self) -> i32 {
        match self {
            MergeCheck::Ran(o) => o.exit_code,
            MergeCheck::FailClosed { .. } => EXIT_INDETERMINATE,
        }
    }

    /// The exit code as a [`std::process::ExitCode`], so a CI binary can `return check.process_exit_code()`.
    pub fn process_exit_code(&self) -> std::process::ExitCode {
        std::process::ExitCode::from(self.exit_code() as u8)
    }

    /// A single stable human+machine summary line for the CI log.
    pub fn summary(&self) -> &str {
        match self {
            MergeCheck::Ran(o) => &o.summary,
            MergeCheck::FailClosed { summary } => summary,
        }
    }

    /// The full CI outcome, present only when the gate actually ran.
    pub fn outcome(&self) -> Option<&CiGateOutcome> {
        match self {
            MergeCheck::Ran(o) => Some(o),
            MergeCheck::FailClosed { .. } => None,
        }
    }
}

/// Run the offline release gate as a **CI merge-check / dogfood** run driven by a [`ReleaseGateProvider`].
///
/// This is the single non-test entrypoint a required status check / dogfood job calls. It asks the
/// provider to assemble the release inputs, runs the real composed gate ([`run_release_gate_ci`] →
/// `run_release_gate`) over them, and returns the merge decision:
///
/// * provider assembled inputs and the gate ran → [`MergeCheck::Ran`] with the gate's outcome;
/// * provider returned `Err` (inputs unavailable) → [`MergeCheck::FailClosed`] (merge blocked);
/// * provider returned `Ok` but never invoked the gate → [`MergeCheck::FailClosed`] (a provider bug is
///   still fail-closed, never a silent pass).
pub fn run_merge_check(provider: &dyn ReleaseGateProvider) -> MergeCheck {
    let mut captured: Option<CiGateOutcome> = None;
    let result = provider.with_release_inputs(&mut |req, sink| {
        captured = Some(run_release_gate_ci(req, sink));
    });
    match result {
        Ok(()) => match captured {
            Some(outcome) => MergeCheck::Ran(outcome),
            None => MergeCheck::FailClosed {
                summary: "FAIL-CLOSED (merge blocked): provider returned Ok but never ran the gate"
                    .to_string(),
            },
        },
        Err(reason) => MergeCheck::FailClosed {
            summary: format!("FAIL-CLOSED (merge blocked): release inputs unavailable — {reason}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::VerdictRecord;
    use crate::pipeline::ReleaseDecision;

    /// A provider that cannot assemble the inputs (e.g. the sealed corpus store is unreachable).
    struct BrokenProvider;
    impl ReleaseGateProvider for BrokenProvider {
        fn with_release_inputs(
            &self,
            _run: &mut dyn FnMut(&ReleaseGateRequest<'_>, &mut dyn EventSink),
        ) -> Result<(), String> {
            Err("sealed corpus store unreachable".into())
        }
    }

    /// A provider that returns Ok but forgets to run the gate (a provider bug) — must fail closed.
    struct SilentProvider;
    impl ReleaseGateProvider for SilentProvider {
        fn with_release_inputs(
            &self,
            _run: &mut dyn FnMut(&ReleaseGateRequest<'_>, &mut dyn EventSink),
        ) -> Result<(), String> {
            Ok(())
        }
    }

    #[test]
    fn unavailable_inputs_fail_closed() {
        let check = run_merge_check(&BrokenProvider);
        assert!(check.merge_blocked() && !check.is_mergeable());
        assert_eq!(check.exit_code(), EXIT_INDETERMINATE);
        assert!(check.summary().contains("unavailable"));
        assert!(check.outcome().is_none());
    }

    #[test]
    fn provider_that_never_runs_the_gate_fails_closed() {
        let check = run_merge_check(&SilentProvider);
        assert!(check.merge_blocked());
        assert_eq!(check.exit_code(), EXIT_INDETERMINATE);
    }

    #[test]
    fn fail_closed_outcome_maps_to_a_process_exit_code() {
        let check = run_merge_check(&BrokenProvider);
        // 2 (EXIT_INDETERMINATE) is representable — the mapping does not panic.
        let _code = check.process_exit_code();
        assert_eq!(check.exit_code() as u8, EXIT_INDETERMINATE as u8);
    }

    // A tiny "decision only" sanity check so the enum stays wired to the CI shape.
    #[test]
    fn ran_variant_reflects_the_ci_outcome() {
        let outcome = CiGateOutcome {
            merge_blocked: false,
            exit_code: crate::ci::EXIT_SHIP,
            summary: "SHIP".into(),
            report: crate::pipeline::ReleaseGateReport {
                decision: ReleaseDecision::Ship,
                statistical: None,
                warnings: Vec::new(),
                verdict: VerdictRecord {
                    eval_set_id: "s".into(),
                    eval_set_version: "v1".into(),
                    judge_version: "j".into(),
                    candidate_sha: "sha".into(),
                    params_hash: "ph".into(),
                    seed: 1,
                    dimension: "correctness".into(),
                    outcome: "pass".into(),
                    effect: 0.0,
                    epoch: 1,
                },
                judge_version: "j".into(),
                scored: 0,
            },
        };
        let check = MergeCheck::Ran(outcome);
        assert!(check.is_mergeable());
        assert_eq!(check.exit_code(), crate::ci::EXIT_SHIP);
        assert!(check.outcome().is_some());
    }
}
