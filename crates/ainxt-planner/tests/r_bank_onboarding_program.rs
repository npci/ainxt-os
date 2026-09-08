// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-AUDIT data-surfaces-artifacts — "Bank-onboarding program has no substrate":
//! `STRUCTURED_FEDERATED_RETRIEVAL.md` §6.5 named "onboarding a new bank" as an instance of the
//! generic Long-Horizon Program Supervisor (ADR-027), but no code anywhere built the actual Program —
//! no node topology, no data model, nothing the generic engine (`ainxt_planner::program`/`driver`)
//! could actually run. `ainxt_planner::bank_onboarding::bank_onboarding_program` is that substrate.
//!
//! This test proves it end-to-end through the REAL generic engine (`drive_program_verified` — the
//! SAME entrypoint every code-migration Program drives through, never a bespoke onboarding runner):
//! the three documented modules (KYC data-class registration → federated-broker credential issuance →
//! member-bank connectivity check) commit IN DEPENDENCY ORDER and the program reaches `Completed`.
//!
//! FAIL-BEFORE: `ainxt_planner::bank_onboarding` did not exist, so this file would not compile.

use ainxt_planner::bank_onboarding::{
    bank_onboarding_program, connectivity_node_id, credential_node_id, kyc_node_id,
};
use ainxt_planner::driver::{
    drive_program_verified, DriverModuleContext, ModuleAttempt, ModuleExecutor, ModuleJudge,
    StopSignal,
};
use ainxt_planner::program::{ProgramId, ProgramOutcome};
use ainxt_planner::supervisor::ProgramVerifier;
use ainxt_planner::verify::{AdversarialVerdict, DeterministicVerdict, GateOutcome, JudgeVerdict};

/// Produces a clean, deterministically-green artifact for every module — same fake shape as
/// `ainxt-planner`'s own r11 long-horizon test suite, reused here rather than reinvented.
struct GreenExecutor {
    calls: u32,
}
impl ModuleExecutor for GreenExecutor {
    fn execute(&mut self, ctx: &DriverModuleContext, _stop: &StopSignal) -> ModuleAttempt {
        self.calls += 1;
        ModuleAttempt::Ran {
            det: DeterministicVerdict::green(),
            adv: AdversarialVerdict::green(10),
            commit_shas: vec![format!("sha-{}", ctx.node)],
            ledger_key: format!("k-{}", ctx.node),
            by_model: "producer-model".into(),
        }
    }
}

struct GreenJudge;
impl ModuleJudge for GreenJudge {
    fn judge(&mut self, _c: &DriverModuleContext, _a: &ModuleAttempt) -> JudgeVerdict {
        JudgeVerdict::pass(92, 80, "producer-model", "judge-model")
    }
}

struct GreenVerifier;
impl ProgramVerifier for GreenVerifier {
    fn verify_edge(
        &mut self,
        _c: &ainxt_planner::program::NodeId,
        _n: &ainxt_planner::program::NodeId,
    ) -> GateOutcome {
        GateOutcome::Complete
    }
    fn regression_sweep(&mut self, _c: &[ainxt_planner::program::NodeId]) -> GateOutcome {
        GateOutcome::Complete
    }
    fn program_judge(&mut self) -> JudgeVerdict {
        JudgeVerdict::pass(95, 80, "producer-model", "judge-model")
    }
}

#[test]
fn r_bank_onboarding_program_commits_kyc_then_credential_then_connectivity_and_completes() {
    let mut exec = GreenExecutor { calls: 0 };
    let mut judge = GreenJudge;
    let mut verifier = GreenVerifier;
    let stop = StopSignal::new();

    let report = drive_program_verified(
        ProgramId::new("bank-onboard-newbank"),
        "Onboard newbank into the federated retrieval network",
        bank_onboarding_program("newbank"),
        &mut exec,
        &mut judge,
        &mut verifier,
        &stop,
        3,
    )
    .expect("a clean, dependency-respecting three-node program must drive to completion");

    assert_eq!(
        report.outcome,
        ProgramOutcome::Completed,
        "the real generic engine must complete the onboarding program end-to-end"
    );
    assert_eq!(
        report.committed,
        vec![
            kyc_node_id("newbank"),
            credential_node_id("newbank"),
            connectivity_node_id("newbank"),
        ],
        "the sequential driver must commit the three modules IN DEPENDENCY ORDER — KYC \
         classification before credential issuance before the connectivity probe — never any other \
         order, proving the topology's deps are real, not decorative"
    );
    assert!(
        report.program.state().committed_nodes_are_all_proven(),
        "every committed onboarding module carries a durable Complete three-way proof"
    );
    assert_eq!(
        exec.calls, 3,
        "all three modules actually drove a turn through the real executor seam"
    );
}
