// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! The callable **CI / dogfood entrypoint** for the composed release gate (EVAL_PLATFORM.md §11 +
//! §"CI wiring": *"the offline gate is a required, merge-blocking status check on the PR"*).
//!
//! [`crate::pipeline::run_release_gate`] is the composition of every rigorous instrument in this crate
//! (meta-gate, sealed corpus, Judge governance, contamination, the statistically-valid
//! [`crate::stats::statistical_gate`], the overfit tripwire, the Regression Vault, and the
//! reproduce-from-SHA verdict written to the Event Log). Before this module it was invoked *only from
//! its own unit tests* — there was no non-test surface a CI check / dogfood runner could call, so the
//! keystone gate was, in practice, bypassed.
//!
//! [`run_release_gate_ci`] is that surface. It runs the real composed gate through its trait seams and
//! turns the [`crate::pipeline::ReleaseDecision`] into the two things a merge-check actually needs:
//!
//! * a **merge-block decision** ([`CiGateOutcome::merge_blocked`]) that is **fail-closed** — both a
//!   `Block` *and* an `Indeterminate` (cancelled / over-budget / corpus unavailable) block the merge;
//!   only an explicit `Ship` is mergeable, and
//! * a **process exit code** ([`CiGateOutcome::exit_code`] / [`CiGateOutcome::process_exit_code`]) so a
//!   `cargo xtask eval-gate` / dogfood job can `std::process::exit` on it and drive branch protection.
//!
//! The durable backends behind the seams — the encrypted [`crate::integrity::SealedCorpusStore`], the
//! tamper-evident [`crate::audit::EventSink`] (Event Log / WORM), the in-house-only Judge, and the
//! dogfooded runner that produces the baseline/candidate [`crate::EvalSystem`]s — are supplied by the
//! parent (they live in the reserved daemon/serving crates). This entrypoint is the clean, real seam
//! those backends plug into; it composes and runs the actual instruments, never a stand-in.

use crate::audit::EventSink;
use crate::pipeline::{run_release_gate, ReleaseDecision, ReleaseGateReport, ReleaseGateRequest};

/// The exit code a `Ship` decision maps to (mergeable).
pub const EXIT_SHIP: i32 = 0;
/// The exit code a `Block` decision maps to (a real, statistically-valid regression / integrity fail).
pub const EXIT_BLOCK: i32 = 1;
/// The exit code an `Indeterminate` decision maps to (fail-closed: cancelled / over-budget / corpus
/// unavailable — never treated as a pass).
pub const EXIT_INDETERMINATE: i32 = 2;

/// The CI-facing outcome of a release-gate run: the merge decision + an exit code + a log line, with
/// the full [`ReleaseGateReport`] retained for the audit trail.
#[derive(Debug, Clone, PartialEq)]
pub struct CiGateOutcome {
    /// True when the change must NOT merge (block or indeterminate). Fail-closed.
    pub merge_blocked: bool,
    /// Process exit code ([`EXIT_SHIP`] / [`EXIT_BLOCK`] / [`EXIT_INDETERMINATE`]).
    pub exit_code: i32,
    /// A single, stable human+machine summary line for the CI log.
    pub summary: String,
    /// The full composed report (decision, per-cell statistics, warnings, reproduce-from-SHA verdict).
    pub report: ReleaseGateReport,
}

impl CiGateOutcome {
    /// The change may merge iff the composed gate explicitly shipped.
    pub fn is_mergeable(&self) -> bool {
        !self.merge_blocked
    }

    /// The exit code as a [`std::process::ExitCode`], so a CI binary can `return outcome.process_exit_code()`.
    pub fn process_exit_code(&self) -> std::process::ExitCode {
        // Exit codes are 0/1/2 — always in u8 range.
        std::process::ExitCode::from(self.exit_code as u8)
    }
}

/// Run the composed, statistically-valid, fail-closed release gate as a **CI merge-check / dogfood**
/// run and return the merge decision. This is the single entrypoint a required status check calls.
///
/// It delegates the actual gating to [`run_release_gate`] (so every instrument — including the
/// statistical gate rather than the naive aggregate one — runs, and the reproduce-from-SHA verdict is
/// written to `sink` **before** the decision is returned) and then maps the decision to CI semantics:
///
/// | decision        | `merge_blocked` | `exit_code`           |
/// |-----------------|-----------------|-----------------------|
/// | `Ship`          | `false`         | [`EXIT_SHIP`] (0)     |
/// | `Block`         | `true`          | [`EXIT_BLOCK`] (1)    |
/// | `Indeterminate` | `true`          | [`EXIT_INDETERMINATE`] (2) |
///
/// An `Indeterminate` run (cancelled, over budget, corpus unavailable) blocks the merge — a CI gate
/// that let an un-run eval merge would defeat the point.
pub fn run_release_gate_ci(
    req: &ReleaseGateRequest<'_>,
    sink: &mut dyn EventSink,
) -> CiGateOutcome {
    let report = run_release_gate(req, sink);
    let (merge_blocked, exit_code, summary) = match &report.decision {
        ReleaseDecision::Ship => (
            false,
            EXIT_SHIP,
            format!(
                "SHIP: release gate passed — {} case(s) scored under judge '{}'{}",
                report.scored,
                report.judge_version,
                warn_suffix(&report),
            ),
        ),
        ReleaseDecision::Block(reasons) => (
            true,
            EXIT_BLOCK,
            format!(
                "BLOCK: {} blocking reason(s) — {}{}",
                reasons.len(),
                reasons.join("; "),
                warn_suffix(&report),
            ),
        ),
        ReleaseDecision::Indeterminate(why) => (
            true,
            EXIT_INDETERMINATE,
            format!("INDETERMINATE (fail-closed, merge blocked): {why}"),
        ),
    };
    CiGateOutcome {
        merge_blocked,
        exit_code,
        summary,
        report,
    }
}

/// Append any non-blocking operational warnings (e.g. rotation-due) to the CI log line.
fn warn_suffix(report: &ReleaseGateReport) -> String {
    if report.warnings.is_empty() {
        String::new()
    } else {
        format!(" [warnings: {}]", report.warnings.join("; "))
    }
}

// =================================================================================================
// Merge-blocking status-check wiring (EVAL_PLATFORM.md §11 + SCENARIO_MATRIX.md §5)
//
// A CI exit code drives a job's pass/fail, but branch protection keys off a NAMED status check. The
// Definition of Done is BOTH gates green (`AINXT_OS.md` §130: "nothing ships until it passes both
// gates") — the Eval Gate (this crate, the *quality* half) AND the Scenario Matrix (the
// *safety/correctness* half). This section is the composite required-check a PR's branch-protection
// rule reads: it is Success only when the eval gate shipped AND every additional required check
// (the matrix slice, shadow-parity, …) passed — fail-closed, both directions.
// =================================================================================================

/// The state of a named CI status check (the GitLab/GitHub commit-status vocabulary).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckState {
    /// The check has not resolved yet (a run in flight / not started). Branch protection treats a
    /// non-`Success` required check as blocking — so `Pending` blocks a merge, fail-closed.
    Pending,
    /// The check passed — this contributes a mergeable signal.
    Success,
    /// The check failed — merge is blocked.
    Failure,
}

impl CheckState {
    /// A merge is allowed only on an explicit `Success` (fail-closed on `Pending`/`Failure`).
    pub fn allows_merge(&self) -> bool {
        matches!(self, CheckState::Success)
    }
}

/// One named status check as branch protection sees it (`context`/`name` + `state` + a description).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusCheck {
    /// The stable check name a branch-protection rule requires (e.g. `ainxt/release-gate`).
    pub name: String,
    pub state: CheckState,
    pub description: String,
}

impl StatusCheck {
    pub fn allows_merge(&self) -> bool {
        self.state.allows_merge()
    }
}

/// An additional required gate composed alongside the eval gate — most importantly the
/// **Scenario Matrix** (safety/correctness) slice, but also shadow-parity or any other required
/// merge check. A missing/pending result must be reported with `passed = false` (fail-closed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequiredCheck {
    pub name: String,
    pub passed: bool,
    pub summary: String,
}

impl RequiredCheck {
    pub fn new(name: &str, passed: bool, summary: &str) -> Self {
        RequiredCheck {
            name: name.to_string(),
            passed,
            summary: summary.to_string(),
        }
    }
}

/// The canonical name of the composite merge-blocking status check a branch-protection rule requires.
pub const RELEASE_GATE_CHECK: &str = "ainxt/release-gate";

/// Compose the eval-gate CI outcome with the other required checks (the Scenario Matrix, shadow
/// parity, …) into the ONE named status check branch protection blocks on. `Success` iff the eval
/// gate is mergeable AND every additional required check passed; otherwise `Failure`, naming the
/// first failing gate. This is the structural enforcement (ADR-010 D1 / SCENARIO_MATRIX §5) — a PR
/// that regresses either half cannot merge, by rule, not by reviewer goodwill.
pub fn merge_status_check(outcome: &CiGateOutcome, additional: &[RequiredCheck]) -> StatusCheck {
    let mut failures: Vec<String> = Vec::new();
    if !outcome.is_mergeable() {
        failures.push(format!("eval-gate: {}", outcome.summary));
    }
    for c in additional {
        if !c.passed {
            failures.push(format!("{}: {}", c.name, c.summary));
        }
    }
    if failures.is_empty() {
        StatusCheck {
            name: RELEASE_GATE_CHECK.to_string(),
            state: CheckState::Success,
            description: format!(
                "both DoD gates green (eval + {} required check(s))",
                additional.len()
            ),
        }
    } else {
        StatusCheck {
            name: RELEASE_GATE_CHECK.to_string(),
            state: CheckState::Failure,
            description: format!("merge blocked: {}", failures.join(" | ")),
        }
    }
}

/// The canonical name of the Scenario Matrix (safety/correctness) required check — the second DoD gate
/// (`AINXT_OS.md` §130: "nothing ships until it passes BOTH gates").
pub const SCENARIO_MATRIX_CHECK: &str = "ainxt/scenario-matrix";

/// The **strict** composite required-check: like [`merge_status_check`], but a named required gate that
/// is *entirely absent* from `additional` is treated as a hard failure (fail-closed), not an implicit
/// pass. This closes the DoD hole where `merge_status_check(outcome, &[])` returns `Success` on the
/// eval gate alone — a PR whose Scenario-Matrix job never reported (crashed / was skipped / never
/// configured) would then merge on the quality gate only, defeating "BOTH gates green by rule".
///
/// A required gate blocks the merge if it is missing, `passed = false`, or the eval gate is not
/// mergeable. `required` is the set of check names that MUST be present-and-green (typically
/// `[SCENARIO_MATRIX_CHECK]`). The returned [`StatusCheck`] is `Success` only when the eval gate
/// shipped AND every required check is present and passed AND no *other* supplied check failed.
pub fn merge_status_check_required(
    outcome: &CiGateOutcome,
    additional: &[RequiredCheck],
    required: &[&str],
) -> StatusCheck {
    compose_required_status(
        outcome.is_mergeable(),
        &outcome.summary,
        additional,
        required,
    )
}

/// The shared composition behind [`merge_status_check_required`] (and the CI wiring's
/// [`run_ci_merge_check`]), written over the *eval decision as a mergeable bool + summary* rather than a
/// concrete [`CiGateOutcome`] — so a gate that was itself fail-closed *without* producing an outcome
/// (the [`crate::dogfood::MergeCheck::FailClosed`] arm: provider couldn't assemble inputs) composes
/// through the exact same, identical-output path. `Success` iff the eval gate is mergeable AND every
/// supplied check passed AND every `required` name is present; else `Failure`, naming the first
/// failing/missing gate. Fail-closed in every direction.
fn compose_required_status(
    eval_mergeable: bool,
    eval_summary: &str,
    additional: &[RequiredCheck],
    required: &[&str],
) -> StatusCheck {
    let mut failures: Vec<String> = Vec::new();
    if !eval_mergeable {
        failures.push(format!("eval-gate: {eval_summary}"));
    }
    // Every explicitly-supplied check must pass.
    for c in additional {
        if !c.passed {
            failures.push(format!("{}: {}", c.name, c.summary));
        }
    }
    // Every REQUIRED check must additionally be *present* — a missing report is fail-closed, never an
    // implicit pass. (A present-but-failed required check is already captured by the loop above.)
    for req in required {
        if !additional.iter().any(|c| &c.name == req) {
            failures.push(format!(
                "{req}: required DoD gate did not report (fail-closed — a missing gate never passes)"
            ));
        }
    }
    if failures.is_empty() {
        StatusCheck {
            name: RELEASE_GATE_CHECK.to_string(),
            state: CheckState::Success,
            description: format!(
                "all DoD gates green (eval + {} required gate(s) present & passed)",
                required.len()
            ),
        }
    } else {
        StatusCheck {
            name: RELEASE_GATE_CHECK.to_string(),
            state: CheckState::Failure,
            description: format!("merge blocked: {}", failures.join(" | ")),
        }
    }
}

// =================================================================================================
// The CI-system merge-check entrypoint + the SCM commit-status publisher seam (ADR-010 D1 keystone;
// EVAL_PLATFORM.md §11 "the offline gate is a required, merge-blocking status check on the PR").
//
// Everything above *computes* the merge decision. It was never handed to a CI system: nothing posted
// the composite status back to the SCM's commit-status API so a branch-protection rule could block on
// it. This section closes that. `run_ci_merge_check` is the ONE entrypoint a CI job invokes end-to-
// end: it runs the real composed gate (through the dogfood provider), composes it with the other
// required DoD gates into the single named status check, PUBLISHES that check to the SCM commit-status
// seam, and returns the pass/block status + a process exit code the job exits on.
//
// The live GitLab commit-status API call (network + a project token + the pipeline that registers the
// check as a branch-protection requirement) is the infra half — a `CommitStatusPublisher` seam with a
// deterministic offline recorder here, and the real GitLab HTTP client supplied by the reserved
// server/daemon crates. This is honest: the *decision that drives the block* is proven offline
// end-to-end; only the wire call to a live CI system is gated.
// =================================================================================================

use crate::dogfood::{run_merge_check, MergeCheck, ReleaseGateProvider};

/// The commit-status payload posted to the SCM (GitLab commit-status API `POST
/// /projects/:id/statuses/:sha`, or the GitHub equivalent). It is the composite [`StatusCheck`] plus
/// the concrete commit ref it attaches to, so branch protection can require this `name` on the PR head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitStatus {
    /// The stable check `context`/`name` a branch-protection rule requires ([`RELEASE_GATE_CHECK`]).
    pub name: String,
    pub state: CheckState,
    pub description: String,
    /// The commit SHA (or ref) the status attaches to — the PR head under evaluation.
    pub target_ref: String,
}

impl CommitStatus {
    /// The GitLab/GitHub commit-status *state* vocabulary the API expects. `Success` → `success`,
    /// `Failure` → `failed`, `Pending` → `pending` (a not-yet-resolved required check is blocking).
    pub fn scm_state(&self) -> &'static str {
        match self.state {
            CheckState::Success => "success",
            CheckState::Failure => "failed",
            CheckState::Pending => "pending",
        }
    }
}

/// The seam a CI backend implements to publish the composite merge-check status to the SCM's
/// commit-status API. The live GitLab implementation (HTTP + project token, routed via the platform's
/// forward proxy) lives in the reserved server/daemon crates and is **infra-gated**; the offline
/// [`RecordingStatusPublisher`] here proves the wiring deterministically.
///
/// `publish` returns `Err` on a transport failure. A publish failure never turns a block into a pass —
/// it means the required check simply never flips to `Success`, which branch protection treats as
/// blocking (fail-closed at the CI layer).
pub trait CommitStatusPublisher {
    fn publish(&mut self, status: &CommitStatus) -> Result<(), String>;
}

/// An offline, deterministic [`CommitStatusPublisher`] that records every posted status instead of
/// making a network call. Used by the offline block-on-regression test and by dev/dry-run CI; the real
/// GitLab client is supplied by the parent (infra-gated).
#[derive(Debug, Default)]
pub struct RecordingStatusPublisher {
    pub published: Vec<CommitStatus>,
}

impl RecordingStatusPublisher {
    pub fn new() -> Self {
        RecordingStatusPublisher {
            published: Vec::new(),
        }
    }
    /// The most recently published status (the one branch protection would read).
    pub fn last(&self) -> Option<&CommitStatus> {
        self.published.last()
    }
}

impl CommitStatusPublisher for RecordingStatusPublisher {
    fn publish(&mut self, status: &CommitStatus) -> Result<(), String> {
        self.published.push(status.clone());
        Ok(())
    }
}

/// The result a CI job consumes from [`run_ci_merge_check`]: the published composite status, the
/// pass/block decision, a process exit code, whether the SCM publish succeeded, and the underlying
/// merge-check for the audit trail.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub struct CiMergeCheck {
    /// The single named status check posted to the SCM (what branch protection blocks on).
    pub status: StatusCheck,
    /// True when the change must NOT merge (eval regressed OR a required DoD gate missing/failed OR the
    /// gate could not run). Fail-closed.
    pub merge_blocked: bool,
    /// Process exit code the CI job exits on ([`EXIT_SHIP`]/[`EXIT_BLOCK`]/[`EXIT_INDETERMINATE`]).
    pub exit_code: i32,
    /// The SCM commit-status publish result. `Err` means the status could not be posted — the merge
    /// stays blocked (the required check never turns green).
    pub published: Result<(), String>,
    /// The underlying release-gate merge-check (its [`CiGateOutcome`] when the gate ran).
    pub check: MergeCheck,
}

impl CiMergeCheck {
    /// The change may merge iff the composite status is `Success` AND it was published.
    pub fn is_mergeable(&self) -> bool {
        !self.merge_blocked && self.published.is_ok()
    }
    /// The exit code as a [`std::process::ExitCode`], so the CI binary can `return ...`.
    pub fn process_exit_code(&self) -> std::process::ExitCode {
        std::process::ExitCode::from(self.exit_code as u8)
    }
}

/// **The CI-system merge-check entrypoint** (ADR-010 D1 keystone). This is the single call a CI job
/// makes; it wires the eval gate to a merge-blocking status check end-to-end:
///
/// 1. runs the REAL composed release gate through `provider` ([`run_merge_check`] → the whole
///    statistically-valid, fail-closed pipeline, writing the reproduce-from-SHA verdict to the Event
///    Log);
/// 2. composes that decision with the other required DoD gates (`additional` results + the `required`
///    names that MUST be present — typically `[SCENARIO_MATRIX_CHECK]`) into the one named
///    [`StatusCheck`] (fail-closed on a missing/failed gate, and fail-closed when the gate itself could
///    not run);
/// 3. **publishes** that status to the SCM commit-status API via `publisher` (the GitLab wire call is
///    infra-gated; offline this records deterministically), attaching it to `target_ref`;
/// 4. returns a [`CiMergeCheck`] with the pass/block status + a process exit code the job exits on.
///
/// The exit code is `EXIT_SHIP` (0) only when the composite is `Success`; otherwise it is the gate's
/// own non-zero code (a real statistical regression → [`EXIT_BLOCK`]; a gate that could not run →
/// [`EXIT_INDETERMINATE`]), or [`EXIT_BLOCK`] when the eval gate shipped but a *different* required DoD
/// gate blocked the merge.
pub fn run_ci_merge_check(
    provider: &dyn ReleaseGateProvider,
    additional: &[RequiredCheck],
    required: &[&str],
    target_ref: &str,
    publisher: &mut dyn CommitStatusPublisher,
) -> CiMergeCheck {
    let check = run_merge_check(provider);
    let status =
        compose_required_status(check.is_mergeable(), check.summary(), additional, required);
    let merge_blocked = !status.allows_merge();
    let exit_code = if status.allows_merge() {
        EXIT_SHIP
    } else {
        // Prefer the gate's own non-zero code (BLOCK vs INDETERMINATE); if the eval gate itself
        // shipped (code 0) but a *different* required DoD gate blocked, surface EXIT_BLOCK.
        let gate_code = check.exit_code();
        if gate_code != EXIT_SHIP {
            gate_code
        } else {
            EXIT_BLOCK
        }
    };
    let commit = CommitStatus {
        name: status.name.clone(),
        state: status.state,
        description: status.description.clone(),
        target_ref: target_ref.to_string(),
    };
    let published = publisher.publish(&commit);
    CiMergeCheck {
        status,
        merge_blocked,
        exit_code,
        published,
        check,
    }
}

// =================================================================================================
// Branch-protection RULE enforcement (round-15 gap, eval-tester-scenarios MEDIUM: "Merge-blocking CI
// status check / branch-protection ENFORCEMENT").
//
// Everything above computes a merge decision and PUBLISHES it as a named commit status
// ([`run_ci_merge_check`]). That closes "the gate is not wired as a CI status check" — but a posted
// `failed` commit status only blocks anything if the branch's protection RULE was actually configured
// to require that named check. Absent that configuration, a `Failure` status is cosmetic: GitLab (or
// GitHub) still offers the "Merge" button. Nothing before this round ever read or wrote that rule, so
// a project whose branch protection was never (or was mis-) configured would silently ship on quality
// gate alone, defeating the "BOTH gates green, by rule, not by reviewer goodwill" invariant
// (`AINXT_OS.md` §130 / `ci::merge_status_check_required`'s own doc).
//
// The live GitLab call (`PUT /projects/:id/protected_branches`, network + a maintainer/admin token) is
// the infra half — a [`BranchProtectionEnforcer`] seam with a deterministic offline recorder here; the
// real GitLab HTTP client is supplied by the reserved server/daemon crates.
// =================================================================================================

/// The branch-protection rule as GitLab/GitHub branch protection sees it: which named status checks
/// are REQUIRED before a merge is even offered.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProtectionRule {
    pub branch: String,
    pub required_checks: Vec<String>,
}

impl ProtectionRule {
    /// Whether this rule already requires every name in `required` (order-independent).
    pub fn covers(&self, required: &[&str]) -> bool {
        required
            .iter()
            .all(|name| self.required_checks.iter().any(|c| c == name))
    }
}

/// The seam a CI/governance job implements to READ and ENFORCE a branch's protection rule. The live
/// GitLab implementation lives in the reserved server/daemon crates and is infra-gated (network + a
/// maintainer/admin project token); the offline [`RecordingBranchProtectionEnforcer`] here proves the
/// enforcement logic — idempotent, additive, never silently absent — deterministically.
pub trait BranchProtectionEnforcer {
    /// The rule currently configured for `branch` (`None` if the branch has no rule yet — which is
    /// itself a finding: an unprotected branch enforces nothing).
    fn current_rule(&self, branch: &str) -> Option<ProtectionRule>;
    /// Idempotently ensure `branch`'s rule requires every name in `required` — adding any missing name;
    /// NEVER removing an existing requirement (this only strengthens a rule). Returns the resulting
    /// rule, or `Err` on a transport failure (the caller must then fail closed, never assume the rule
    /// took effect).
    fn ensure_required(
        &mut self,
        branch: &str,
        required: &[&str],
    ) -> Result<ProtectionRule, String>;
}

/// An offline, deterministic [`BranchProtectionEnforcer`]: an in-memory `branch -> rule` map. Used by
/// the offline enforcement test and by dev/dry-run tooling; the real GitLab client is supplied by the
/// parent (infra-gated).
#[derive(Debug, Clone, Default)]
pub struct RecordingBranchProtectionEnforcer {
    rules: std::collections::BTreeMap<String, ProtectionRule>,
}

impl RecordingBranchProtectionEnforcer {
    pub fn new() -> Self {
        Self::default()
    }
    /// Seed a pre-existing rule, as if read back from a live GitLab project (e.g. one with NO required
    /// checks yet, or one that already requires an unrelated check) — lets a test start from a
    /// realistic "branch protection exists but doesn't cover our gate" state.
    pub fn seed(&mut self, rule: ProtectionRule) {
        self.rules.insert(rule.branch.clone(), rule);
    }
}

impl BranchProtectionEnforcer for RecordingBranchProtectionEnforcer {
    fn current_rule(&self, branch: &str) -> Option<ProtectionRule> {
        self.rules.get(branch).cloned()
    }

    fn ensure_required(
        &mut self,
        branch: &str,
        required: &[&str],
    ) -> Result<ProtectionRule, String> {
        let rule = self
            .rules
            .entry(branch.to_string())
            .or_insert_with(|| ProtectionRule {
                branch: branch.to_string(),
                required_checks: Vec::new(),
            });
        for name in required {
            if !rule.required_checks.iter().any(|c| c == name) {
                rule.required_checks.push((*name).to_string());
            }
        }
        Ok(rule.clone())
    }
}

/// Fail-closed verification that `branch`'s protection rule ALREADY requires every name in `required`.
/// This is the check a governance job runs BEFORE trusting that a merge-blocking status actually
/// blocks anything — a `Failure` [`StatusCheck`] posted to a branch whose rule doesn't require that
/// name is cosmetic, not enforced. Returns every missing requirement (empty = fully covered).
pub fn branch_protection_covers(
    enforcer: &dyn BranchProtectionEnforcer,
    branch: &str,
    required: &[&str],
) -> Vec<String> {
    let configured = enforcer
        .current_rule(branch)
        .map(|r| r.required_checks)
        .unwrap_or_default();
    required
        .iter()
        .filter(|name| !configured.iter().any(|c| c == *name))
        .map(|name| format!("branch '{branch}' protection rule does not require '{name}'"))
        .collect()
}

/// [`run_ci_merge_check`]'s outcome, plus whether the branch's protection rule was confirmed (or
/// established) to actually require [`RELEASE_GATE_CHECK`] and every name in `required` — the
/// enforcement half this round closes.
#[derive(Debug, Clone, PartialEq)]
pub struct CiMergeCheckEnforced {
    /// The published status-check decision ([`run_ci_merge_check`]'s result).
    pub inner: CiMergeCheck,
    /// The branch's protection rule as confirmed after enforcement — `Err` when the enforcer's write
    /// failed (fail-closed: the rule is NOT assumed to have taken effect).
    pub protection: Result<ProtectionRule, String>,
}

impl CiMergeCheckEnforced {
    /// The change may merge iff the underlying check is mergeable AND the branch's protection rule was
    /// confirmed to actually require every gate name — a `Success` status posted to an unprotected (or
    /// under-configured) branch is never treated as mergeable.
    pub fn is_mergeable(&self) -> bool {
        self.inner.is_mergeable()
            && matches!(&self.protection, Ok(rule) if rule.covers(&[RELEASE_GATE_CHECK]))
    }
}

/// **The full merge-blocking wiring**: [`run_ci_merge_check`] (compute + publish the status) PLUS
/// branch-protection enforcement (make the SCM's rule actually require that status before any merge is
/// offered). This is the entrypoint a governance/bootstrap job calls once (and safely re-calls —
/// idempotent) to close the ADR-010 D1 loop end-to-end:
///
/// 1. **Enforce first**: [`BranchProtectionEnforcer::ensure_required`] on `branch` for
///    [`RELEASE_GATE_CHECK`] plus every name in `required` — idempotent and additive. A transport
///    failure here is fail-closed: the merge check still runs and publishes (so the audit trail is
///    complete), but [`CiMergeCheckEnforced::is_mergeable`] is `false` regardless of the gate's own
///    verdict, because an un-enforceable rule means a `Success` status would not actually block a bad
///    merge.
/// 2. **Verify**: re-read the rule via [`branch_protection_covers`] rather than trusting the write
///    call's return value blindly — closes the gap where an enforcer claims success but the rule was
///    not actually persisted.
/// 3. Delegate to [`run_ci_merge_check`] for the compute-and-publish half, unchanged.
pub fn run_ci_merge_check_enforced(
    provider: &dyn ReleaseGateProvider,
    additional: &[RequiredCheck],
    required: &[&str],
    target_ref: &str,
    branch: &str,
    publisher: &mut dyn CommitStatusPublisher,
    enforcer: &mut dyn BranchProtectionEnforcer,
) -> CiMergeCheckEnforced {
    // The rule must cover the composite gate itself PLUS every other required DoD gate name — the same
    // set `merge_status_check_required`/`compose_required_status` treat as mandatory.
    let mut must_cover: Vec<&str> = vec![RELEASE_GATE_CHECK];
    must_cover.extend(required.iter().copied());

    let protection = enforcer.ensure_required(branch, &must_cover).and_then(|_| {
        let missing = branch_protection_covers(enforcer, branch, &must_cover);
        if missing.is_empty() {
            enforcer
                .current_rule(branch)
                .ok_or_else(|| format!("branch '{branch}' has no rule after enforcement"))
        } else {
            Err(format!(
                "branch '{branch}' protection rule still missing required checks after \
                     enforcement: {}",
                missing.join("; ")
            ))
        }
    });

    let inner = run_ci_merge_check(provider, additional, required, target_ref, publisher);
    CiMergeCheckEnforced { inner, protection }
}
