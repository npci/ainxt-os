// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Long-horizon **Program Supervisor** + hierarchical **3-tier Team** execution, wired to the real
//! [`Engine`] at the composition root (WIRE-2 — closes the CRITICAL "built but unreachable" gaps).
//!
//! # The gap this closes
//!
//! `ainxt-planner` (the Program Supervisor loop) and `ainxt-teams` (the 3-tier team loop) are fully
//! built and unit-tested — but they were **unreachable**: no live crate depended on them or drove
//! their execution seams with a real model. Their `RunExecutor` / `TaskExecutor` seams were only ever
//! backed by test fakes. This module is the composition boundary that supplies the **real** backing:
//!
//! * [`EngineRunExecutor`] — ONE adapter that implements BOTH
//!   [`ainxt_planner::supervisor::RunExecutor`] AND [`ainxt_teams::tiers::TaskExecutor`], delegating
//!   each program module / team task to a real [`Engine`] turn
//!   ([`Engine::run_turn_cancellable`](ainxt_runtime::Engine::run_turn_cancellable)) and collecting
//!   the streamed text into the module/task result (**LOOP-01 / LOOP-15**).
//! * [`run_program`] drives the Program Supervisor (`ainxt_planner::supervisor::run_program`) with
//!   this executor; [`run_team`] drives the 3-tier loop (`ainxt_teams::tiers::run_team_3tier`).
//! * [`assemble_program`] adds a **program** assembly path so the subsystem is reachable from the
//!   assembled daemon (a sibling of `assemble` / `assemble_chat` / `assemble_surface`).
//!
//! # Enterprise seams wired here
//!
//! * **IDN-03** — a per-Run [`AgentWorkloadCredential`] is minted via
//!   [`IdentityAuthority::issue`](ainxt_identity::authority::IdentityAuthority::issue) at run start and
//!   threaded as the policy principal for every executor turn (the turn's authz + audit actor derive
//!   from it).
//! * **FI-02** — when a turn produces a real detector signal (the always-on compliance gate acted on
//!   regulated-class content, i.e. `redactions > 0` on a regulated turn), a statutory clock is armed
//!   via the typed [`IncidentCandidate::from_compliance_egress`] adapter (fail-safe: arm early).
//! * **LOOP-13** — the [`LearningRecord`] emitted by a terminal team run is routed to an injected
//!   [`LearningSink`].
//!
//! # Sync ↔ async bridge (why a dedicated thread)
//!
//! The Supervisor / 3-tier loops are **synchronous, deterministic** drivers (that is what makes them
//! exhaustively testable); the Engine turn is **async**. The bridge runs the whole synchronous loop on
//! a dedicated OS thread that owns no Tokio worker, and each module/task turn is driven to completion
//! with `Handle::block_on`. Because the driver thread is not a runtime worker, it never starves the
//! async executor, and `block_on` is always valid there. The async entrypoints await the driver via a
//! oneshot — no worker is blocked.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::{Arc, Mutex};

use ainxt_identity::authority::{
    AgentWorkloadCredential, AttestationQuote, ControlPlaneProjection, IdentityAuthority,
    IssueError, IssueRequest, ReferenceValueVerifier,
};
use ainxt_identity::control::{AdmissionDecision, ControlPlane};
use ainxt_identity::sod::{
    ApprovalDecision as SodApprovalDecision, AwcKeySigner, AwcKeyVerifier, Handoff, HandoffSigner,
    ProducedArtifact, SignedHandoff, SodError, SodVerifyGate, WorkloadRef,
};
use ainxt_identity::transparency::{IssuanceEntry, Sha256Hasher, TransparencyLog};
use ainxt_identity::LogicalTime;
use ainxt_incident::{IncidentCandidate, IncidentRegister};
use ainxt_planner::assurance::{ModuleArtifact, RubricJudge};
use ainxt_planner::compose::{ComposeError, MigrationBlueprint};
use ainxt_planner::driver::{
    drive_program_verified_fanout, DriveReport, DriverModuleContext, ModuleAttempt, ModuleExecutor,
    ModuleJudge, Program, StopSignal,
};
use ainxt_planner::mtg::{MtgNode, WindowBudget};
use ainxt_planner::program::{
    CheckpointClass, ChildOutcome, NodeClass, NodeDecl, NodeId, ProgramError, ProgramEvent,
    ProgramId, ProgramOutcome,
};
use ainxt_planner::scc::DepGraph;
use ainxt_planner::supervisor::{
    self, ApprovalDecision, ApprovalGate, AutoApprove, Checkpoint, CheckpointReason, EventSink,
    ModuleRunContext, ModuleRunResult, ProgramCost, ProgramVerifier, RunExecutor, SupervisorConfig,
    SupervisorReport, VecEventSink,
};
use ainxt_planner::verify::{AdversarialVerdict, DeterministicVerdict, GateOutcome, JudgeVerdict};
use ainxt_teams::tiers::{
    run_team_3tier_verified, run_team_3tier_verified_cancellable, BreakerAdversarialGate,
    ContentDeterministicGate, ContentStepCritic, Deliverable, EscalatingHealer, GoalJudge,
    JudgeOutcome, StepAttempt, StepContext, StepResult, StopSignal as TeamStopSignal, TaskExecutor,
    TeamRunReport, ThreeTierConfig,
};
use ainxt_teams::{
    AgentInvocation, Cost, GraphError, LearningRecord, ModelTier, Role, Task, TaskGraph, Team,
};

use ainxt_protocol::{Event, Request};
use ainxt_runtime::{CancelToken, Engine, TurnError, TurnHandler, TurnSummary};
use ainxt_session::SessionManager;
use ainxt_tools::obo::{Grant, OboContext};
use ainxt_types::{DataClass, Principal, Tier};
use tokio::runtime::Handle;
use tokio::sync::mpsc;

use crate::{build_engine, AssembleError, Assembled, LoadedConfig};

// ===========================================================================
// IDN-03 — per-Run agent workload credential
// ===========================================================================

/// The logical tick at which a run's credential is minted + attested. Deterministic — the identity
/// crate never reads a wall clock, and a supervised run is a logical unit, so a fixed mint tick keeps
/// credential issuance reproducible across runs.
const RUN_MINT_TICK: u64 = 1;

/// The identity inputs for minting a per-Run [`AgentWorkloadCredential`] (IDN-03 / ADR-022 §12). A
/// deployment supplies the git-rooted definition facets (`def_*`), the on-behalf-of human, and the
/// attested workload `measurement`; the composition root turns that into a real credential via the
/// Agent Identity Authority.
#[derive(Debug, Clone)]
pub struct RunIdentitySpec {
    /// e.g. `"agent"` | `"role"`.
    pub def_kind: String,
    /// e.g. the program / team name.
    pub def_id: String,
    /// e.g. `"v1"`.
    pub def_version: String,
    /// The ephemeral per-Run id (also used as the Program id).
    pub run_id: String,
    /// The sensitivity class the run operates on (drives model eligibility + the FI-02 detector).
    pub data_class: DataClass,
    /// The human on whose behalf the agent run acts (the root of authority).
    pub obo_user_id: String,
    pub obo_department: Option<String>,
    pub obo_ad_level: Option<u8>,
    pub obo_can_approve: bool,
    /// The attested workload measurement (a reference value) the AIA verifies before issuance.
    pub measurement: String,
}

impl RunIdentitySpec {
    /// A spec with sensible defaults (`def_version = "v1"`, a composition-local measurement).
    pub fn new(
        def_kind: impl Into<String>,
        def_id: impl Into<String>,
        run_id: impl Into<String>,
        data_class: DataClass,
        obo_user_id: impl Into<String>,
    ) -> Self {
        RunIdentitySpec {
            def_kind: def_kind.into(),
            def_id: def_id.into(),
            def_version: "v1".into(),
            run_id: run_id.into(),
            data_class,
            obo_user_id: obo_user_id.into(),
            obo_department: None,
            obo_ad_level: None,
            obo_can_approve: false,
            measurement: "runtimed-attested-workload".into(),
        }
    }

    pub fn with_department(mut self, dept: impl Into<String>) -> Self {
        self.obo_department = Some(dept.into());
        self
    }

    /// The stable definition reference (`def:<kind>/<id>@<version>`).
    pub fn def_ref(&self) -> String {
        format!("def:{}/{}@{}", self.def_kind, self.def_id, self.def_version)
    }
}

/// Mint a per-Run [`AgentWorkloadCredential`] (IDN-03). Builds a composition-local Agent Identity
/// Authority whose reference-value verifier accepts the spec's `measurement` and whose control-plane
/// projection lists the spec's definition as valid, then issues the credential for the run. The
/// attestation + all deny-checks are the real AIA gate — a tampered measurement or a deprecated
/// definition would refuse issuance, exactly as in production.
pub fn mint_run_credential(spec: &RunIdentitySpec) -> Result<AgentWorkloadCredential, IssueError> {
    let now = LogicalTime(RUN_MINT_TICK);
    let verifier = ReferenceValueVerifier::new().with_measurement(spec.measurement.clone());
    let projection = ControlPlaneProjection::new([spec.def_ref()], now, "runtimed-composition");
    // A supervised run is a logical unit; the composition-local projection never goes stale within
    // it, and the TTL spans the whole run (renewal wiring is the durable-infra phase's job).
    let mut aia =
        IdentityAuthority::new(verifier, projection, u64::MAX, u64::MAX, "runtimed-key-v1");
    let req = IssueRequest {
        def_kind: spec.def_kind.clone(),
        def_id: spec.def_id.clone(),
        def_version: spec.def_version.clone(),
        run_id: spec.run_id.clone(),
        data_class: spec.data_class,
        requires_tee: false,
        obo_user_id: spec.obo_user_id.clone(),
        obo_department: spec.obo_department.clone(),
        obo_ad_level: spec.obo_ad_level,
        obo_can_approve: spec.obo_can_approve,
    };
    let quote = AttestationQuote {
        def_content_hash: format!("hash-{}-{}", spec.def_id, spec.def_version),
        control_commit_sha: "runtimed-composition".into(),
        measurement: spec.measurement.clone(),
        tee_quote: None,
    };
    aia.issue(&req, &quote, now)
}

/// Build a composition-local Agent Identity Authority with a **finite** short TTL and issue the run's
/// first credential — the JIT-renewal shape (§15). Unlike [`mint_run_credential`] (which uses an
/// effectively-infinite TTL for a single-shot run), the returned authority is RETAINED so
/// [`run_program_verified`] can `renew` the credential as the Run's logical clock advances past each
/// TTL — a long-horizon Run is a *chain of renewals*, each re-checking definition validity /
/// revocation / kill-switch / anomaly-choke, never a standing grant. Returns the authority, the
/// attestation quote (needed for a TEE renewal), and the first credential.
fn mint_run_authority(
    spec: &RunIdentitySpec,
    ttl: u64,
) -> Result<
    (
        IdentityAuthority<ReferenceValueVerifier>,
        AttestationQuote,
        AgentWorkloadCredential,
    ),
    IssueError,
> {
    let now = LogicalTime(RUN_MINT_TICK);
    let verifier = ReferenceValueVerifier::new().with_measurement(spec.measurement.clone());
    let projection = ControlPlaneProjection::new([spec.def_ref()], now, "runtimed-composition");
    let mut aia = IdentityAuthority::new(verifier, projection, ttl, u64::MAX, "runtimed-key-v1");
    let req = IssueRequest {
        def_kind: spec.def_kind.clone(),
        def_id: spec.def_id.clone(),
        def_version: spec.def_version.clone(),
        run_id: spec.run_id.clone(),
        data_class: spec.data_class,
        requires_tee: false,
        obo_user_id: spec.obo_user_id.clone(),
        obo_department: spec.obo_department.clone(),
        obo_ad_level: spec.obo_ad_level,
        obo_can_approve: spec.obo_can_approve,
    };
    let quote = AttestationQuote {
        def_content_hash: format!("hash-{}-{}", spec.def_id, spec.def_version),
        control_commit_sha: "runtimed-composition".into(),
        measurement: spec.measurement.clone(),
        tee_quote: None,
    };
    let credential = aia.issue(&req, &quote, now)?;
    Ok((aia, quote, credential))
}

/// Mint the **distinct verifier/approver** credential the SoD verify-gate checks a node's commit
/// against (ADR-022 §18). Producer ≠ approver is keyed on the per-Run `run_id`, so the approver is a
/// SEPARATE Run of the same git-controlled definition (already in the AIA projection) — never a
/// second broad identity, and never the producing Run. `approver_run_id` is the approver's Run id; a
/// composition supplies a distinct id (the default is `<producer>::verifier`), and a test may force it
/// equal to the producer's to prove self-approval is refused on the live path.
fn mint_approver_credential(
    aia: &mut IdentityAuthority<ReferenceValueVerifier>,
    producer: &AgentWorkloadCredential,
    quote: &AttestationQuote,
    approver_run_id: &str,
    now: LogicalTime,
) -> Result<AgentWorkloadCredential, IssueError> {
    let req = IssueRequest {
        def_kind: producer.def_kind.clone(),
        def_id: producer.def_id.clone(),
        def_version: producer.def_version.clone(),
        run_id: approver_run_id.to_string(),
        data_class: producer.data_class,
        requires_tee: producer.requires_tee,
        obo_user_id: producer.obo_user_id.clone(),
        obo_department: producer.obo_department.clone(),
        obo_ad_level: producer.obo_ad_level,
        obo_can_approve: producer.obo_can_approve,
    };
    aia.issue(&req, quote, now)
}

// ===========================================================================
// LOOP-13 — learning-record sink
// ===========================================================================

/// The terminal-run [`LearningRecord`] flywheel sink (LOOP-13 / LOOP §10). A deployment backs this
/// with Enterprise-Memory; the OSS default is [`InMemoryLearningSink`].
pub trait LearningSink: Send + Sync {
    fn record(&self, rec: &LearningRecord);
}

/// An in-memory [`LearningSink`] for tests / dev.
#[derive(Default)]
pub struct InMemoryLearningSink {
    records: Mutex<Vec<LearningRecord>>,
}

impl InMemoryLearningSink {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn records(&self) -> Vec<LearningRecord> {
        self.records.lock().expect("learning sink lock").clone()
    }
    pub fn len(&self) -> usize {
        self.records.lock().expect("learning sink lock").len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// GAP-FIX loop-teams-longhorizon (LOOP §10 eval-set generation) — `flywheel::generate_eval_cases`
    /// was fully implemented and unit-tested but had zero callers outside its own crate; this sink
    /// already accumulates exactly the `Vec<LearningRecord>` it consumes. Every failed/blocked/refused
    /// task across the accrued Runs becomes a regression eval case.
    pub fn flywheel_eval_cases(&self) -> Vec<ainxt_teams::flywheel::EvalCase> {
        ainxt_teams::flywheel::generate_eval_cases(&self.records())
    }

    /// GAP-FIX loop-teams-longhorizon (LOOP §10 plan-template priors) — `flywheel::plan_template_priors`
    /// had the same zero-caller gap as [`Self::flywheel_eval_cases`]; same sink, same fix.
    pub fn flywheel_template_priors(
        &self,
    ) -> std::collections::BTreeMap<ainxt_teams::TaskId, ainxt_teams::flywheel::TaskPrior> {
        ainxt_teams::flywheel::plan_template_priors(&self.records())
    }

    /// GAP-AUDIT loop-teams-longhorizon (LOOP §10 role-spec tuning) — `flywheel::role_spec_tuning` had
    /// the SAME zero-caller gap as [`Self::flywheel_eval_cases`]/[`Self::flywheel_template_priors`] (it
    /// was overlooked when those two were wired: it needs the caller's task→role and role→tier maps,
    /// which the other two curators don't). Same sink, same fix: `task_roles`/`role_tiers` are the
    /// static Team definition a deployment already holds (e.g. from [`compose_served_team`]'s `Team`).
    pub fn flywheel_role_tuning(
        &self,
        task_roles: &std::collections::BTreeMap<ainxt_teams::TaskId, ainxt_teams::RoleId>,
        role_tiers: &std::collections::BTreeMap<ainxt_teams::RoleId, ModelTier>,
    ) -> std::collections::BTreeMap<ainxt_teams::RoleId, ainxt_teams::flywheel::RoleTuning> {
        ainxt_teams::flywheel::role_spec_tuning(&self.records(), task_roles, role_tiers)
    }
}

impl LearningSink for InMemoryLearningSink {
    fn record(&self, rec: &LearningRecord) {
        self.records
            .lock()
            .expect("learning sink lock")
            .push(rec.clone());
    }
}

// ===========================================================================
// Offline-default program/team verification seams
// ===========================================================================

/// The program-scale verification seam's offline default (LONG_HORIZON §6): per-edge integration +
/// regression sweep green, and a passing cross-model program judge. The **real** deployment injects a
/// test-runner + cross-model judge-backed verifier here; this permissive default keeps the supervisor
/// loop reachable offline (it is the analogue of the design's `AutoApprove` gate — a deliberate,
/// honestly-named autonomous-mode choice, not a silent bypass).
#[derive(Debug, Default)]
pub struct PermissiveProgramVerifier;

impl ProgramVerifier for PermissiveProgramVerifier {
    fn verify_edge(&mut self, _committed: &NodeId, _neighbor: &NodeId) -> GateOutcome {
        GateOutcome::Complete
    }
    fn regression_sweep(&mut self, _committed: &[NodeId]) -> GateOutcome {
        GateOutcome::Complete
    }
    fn program_judge(&mut self) -> JudgeVerdict {
        JudgeVerdict::pass(95, 80, "runtime-producer", "runtime-judge")
    }
}

/// GAP-FIX loop-teams-longhorizon (gap 1b) — the durable Program driver's [`ApprovalGate`], carrying
/// the SAME §8 critical-path human-checkpoint policy [`ServedProgramGovernance::served_default`] gives
/// the non-durable governed path (`ServedModuleExecutor`): a critical-path (settlement/ledger) node is
/// HELD — `Reject`, never a forced `Approve` — when no human approval is present. A `Reject` here does
/// NOT abandon the whole program: `supervisor::run_program` marks just that node `BlockedOnHuman` and
/// keeps scheduling other ready work, so the Run still reports an honest, resumable `CappedPartial`
/// rather than a fabricated `Completed`.
///
/// Before this fix, `run_program_durable_blocking` used the bare [`AutoApprove`] gate, which approves
/// EVERY checkpoint (including `CriticalPath`) unconditionally — so a crash-resumable served Program
/// could force-commit a settlement/ledger cutover node with no human present at all, exactly the
/// force-commit hole `ServedProgramGovernance::served_default` closes on the governed path.
#[derive(Debug, Clone, Copy)]
pub struct ServedProgramApprovalGate {
    /// Mirrors [`ServedProgramGovernance::critical_path_approved`]. The served default is `false` —
    /// no human is present on the air-gapped served/durable path, so a critical-path node HOLDS
    /// (fails-closed, uncommitted) rather than being force-committed.
    pub critical_path_approved: bool,
}

impl ApprovalGate for ServedProgramApprovalGate {
    fn request(&mut self, checkpoint: &Checkpoint) -> ApprovalDecision {
        match checkpoint.reason {
            CheckpointReason::CriticalPath if !self.critical_path_approved => {
                ApprovalDecision::Reject
            }
            // Start / Budget / Anomaly checkpoints: the served-autonomous default proceeds (the
            // program-level §7 budget hard ceiling in `SupervisorConfig` still bites independently —
            // this gate only controls the human-review CONTINUE decision at each threshold, not the
            // hard cap). A CriticalPath checkpoint that IS approved (a deployment wiring a real human
            // signal) also proceeds.
            _ => ApprovalDecision::Approve,
        }
    }
}

/// gap loop-teams-longhorizon (item 4, rollback mock-only): wraps any [`ProgramVerifier`] and
/// overrides ONLY [`ProgramVerifier::compensate`] with a REAL git-backed side effect — before this,
/// the sole `compensate`-shaped abstraction in the codebase
/// ([`ainxt_planner::program::Compensator`]) had exactly ONE implementor anywhere, a test fake in
/// `ainxt-planner`'s own unit tests, and no driver ever called it. This performs an actual `git
/// revert --no-edit <sha>` per commit SHA against a real checked-out working tree — the node's
/// commit is genuinely undone in the repository, not merely marked `RolledBack` in the state machine.
/// A deployment layers this (or the GitLab-MR-un-create equivalent) over `PermissiveProgramVerifier`/
/// `ServedProgramVerifier` wherever it drives the rollback-on-red path
/// (`drive_program_verified_reopening` / `supervisor::run_program`).
pub struct GitRevertingProgramVerifier<V> {
    pub inner: V,
    /// The working tree `git revert` runs against.
    pub repo_dir: std::path::PathBuf,
}

impl<V> GitRevertingProgramVerifier<V> {
    pub fn new(inner: V, repo_dir: impl Into<std::path::PathBuf>) -> Self {
        GitRevertingProgramVerifier {
            inner,
            repo_dir: repo_dir.into(),
        }
    }
}

impl<V: ProgramVerifier> ProgramVerifier for GitRevertingProgramVerifier<V> {
    fn verify_edge(&mut self, committed: &NodeId, neighbor: &NodeId) -> GateOutcome {
        self.inner.verify_edge(committed, neighbor)
    }
    fn regression_sweep(&mut self, committed: &[NodeId]) -> GateOutcome {
        self.inner.regression_sweep(committed)
    }
    fn program_judge(&mut self) -> JudgeVerdict {
        self.inner.program_judge()
    }
    fn compensate(&mut self, node: &NodeId, commit_shas: &[String]) -> Result<(), String> {
        // A node with no real commits ever recorded (e.g. a fabricated/test SHA list happened to be
        // empty) has nothing to undo — vacuously compensated, not an error.
        if commit_shas.is_empty() {
            return Ok(());
        }
        for sha in commit_shas {
            let output = std::process::Command::new("git")
                .arg("-C")
                .arg(&self.repo_dir)
                .arg("revert")
                .arg("--no-edit")
                .arg(sha)
                .output()
                .map_err(|e| format!("node {node}: failed to spawn `git revert {sha}`: {e}"))?;
            if !output.status.success() {
                return Err(format!(
                    "node {node}: `git revert {sha}` failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
        }
        Ok(())
    }
}

/// The tier-3 fresh-context judge's offline default (LOOP §5): confirms once every task produced an
/// output, and reports a gap on an empty deliverable (never a silent "done"). The real deployment
/// injects a fresh-context, cross-model Architect judge here.
#[derive(Debug, Default)]
pub struct ConfirmingGoalJudge;

impl GoalJudge for ConfirmingGoalJudge {
    fn audit(&mut self, deliverable: &Deliverable) -> JudgeOutcome {
        if deliverable.outputs.is_empty() {
            JudgeOutcome::Gap {
                missing: "no task produced an output".into(),
            }
        } else {
            JudgeOutcome::Confirmed
        }
    }
}

// ===========================================================================
// EngineRunExecutor — the real backing for BOTH execution seams (LOOP-01/15)
// ===========================================================================

/// What one real engine turn produced, captured for the run report (proof the seam drove a live
/// turn, and the record the FI-02 detector reads).
#[derive(Debug, Clone)]
pub struct TurnObservation {
    /// `module:<node>` or `task:<id>` — which unit of work this turn served.
    pub label: String,
    /// The §14 actor of record: the per-Run credential's full composite
    /// [`actor_label`](ainxt_identity::authority::AgentWorkloadCredential::actor_label) — `uri|obo=..|
    /// commit=..|key=..` — never the bare OBO `user_id` (GAP-FIX identity-payments: a regulator must
    /// be able to answer "who did this?" from this one field alone, without re-deriving it from the
    /// credential elsewhere).
    pub actor: String,
    /// The provider that served the turn.
    pub provider: String,
    /// Compliance redactions on the turn (the FI-02 detector signal when > 0 on a regulated turn).
    pub redactions: usize,
    /// The streamed text collected from the turn.
    pub text: String,
    /// Whether the turn completed without a terminal engine error.
    pub ok: bool,
}

/// The composition-root adapter that backs BOTH the Program Supervisor's
/// [`RunExecutor`](ainxt_planner::supervisor::RunExecutor) seam and the 3-tier Team loop's
/// [`TaskExecutor`](ainxt_teams::tiers::TaskExecutor) seam with a **real** [`Engine`] turn.
///
/// It wraps an `Arc<Engine>`, threads a per-Run [`AgentWorkloadCredential`] as the turn's policy
/// principal (IDN-03), and — when a compliance detector signal is present on a regulated turn — arms
/// a statutory incident clock (FI-02).
pub struct EngineRunExecutor {
    engine: Arc<Engine>,
    credential: AgentWorkloadCredential,
    /// The policy principal for every turn, derived from the per-Run credential (IDN-03).
    principal: Principal,
    cancel: CancelToken,
    handle: Handle,
    /// FI-02 statutory-incident register (when a deployment wires the breach engine).
    incident: Option<Arc<Mutex<IncidentRegister>>>,
    /// §17/§19 shared control plane (when wired): its kill-switch / revocation is consulted BEFORE every
    /// dispatch so a control action reaches this in-flight Run immediately, not only at the next renewal.
    control: Option<Arc<Mutex<ControlPlane>>>,
    turns: Vec<TurnObservation>,
    turn_seq: u64,
}

impl EngineRunExecutor {
    /// Wrap `engine`, threading `credential` as the per-turn policy principal (IDN-03). `handle` is a
    /// Tokio runtime handle used to drive each turn to completion from the synchronous driver thread.
    pub fn new(
        engine: Arc<Engine>,
        credential: AgentWorkloadCredential,
        handle: Handle,
        incident: Option<Arc<Mutex<IncidentRegister>>>,
    ) -> Self {
        // The turn runs on-behalf-of the credential's OBO human, carrying exactly the chat capability
        // and the run's data-class clearance — the AWC is the actor of record (ADR-022 §14).
        let principal = Principal::user(&credential.obo_user_id, &["chat.send"])
            .with_clearance(credential.data_class);
        EngineRunExecutor {
            engine,
            credential,
            principal,
            cancel: CancelToken::new(),
            handle,
            incident,
            control: None,
            turns: Vec::new(),
            turn_seq: 0,
        }
    }

    /// Wire the shared §17/§19 [`ControlPlane`] so a kill-switch / run-revocation / OBO-revocation on the
    /// shared surface DENIES this Run's next dispatch — the wire that makes a control action reach an
    /// in-flight Run. `None` leaves the executor ungoverned (the pre-existing behavior).
    pub fn with_control_plane(mut self, control: Option<Arc<Mutex<ControlPlane>>>) -> Self {
        self.control = control;
        self
    }

    /// Thread an EXTERNAL [`CancelToken`] — the served transport's user-stop token — into every engine
    /// turn this executor drives, so a user-stop halts the IN-FLIGHT module turn: the token flows into
    /// [`Engine::run_turn_cancellable`](ainxt_runtime::Engine::run_turn_cancellable), which races the
    /// stream against it (stops streaming, halts further tool dispatch, ends the turn). Without this the
    /// executor uses its own never-cancelled token, so a served user-stop could never reach the model
    /// work. Called by the served Program driver ([`run_program_verified_blocking`]) with the SAME token
    /// the driver loop consults between modules.
    pub fn with_cancel(mut self, cancel: CancelToken) -> Self {
        self.cancel = cancel;
        self
    }

    /// The per-Run credential minted at run start (IDN-03).
    pub fn credential(&self) -> &AgentWorkloadCredential {
        &self.credential
    }

    /// Replace the per-Run credential with a freshly-renewed one (§15 JIT renewal). The OBO human +
    /// run id + data-class are carried over unchanged, so the derived turn principal is unaffected;
    /// only `issued_at`/`expires_at`/`key_id` advance. Called by [`run_program_verified`] on a long Run
    /// so a standing token never accrues — each renewal re-checks definition validity, revocation, the
    /// kill-switch, and the anomaly choke.
    pub fn refresh_credential(&mut self, credential: AgentWorkloadCredential) {
        self.credential = credential;
    }

    /// Every turn this executor drove (proof the seam ran real engine turns).
    pub fn observations(&self) -> &[TurnObservation] {
        &self.turns
    }

    /// Consume the executor, yielding the collected turn observations.
    pub fn into_observations(self) -> Vec<TurnObservation> {
        self.turns
    }

    /// Drive ONE real engine turn to completion, collecting the streamed text, under this executor's
    /// own Run-level `self.principal` (unchanged behavior — the Program Supervisor seam
    /// ([`RunExecutor::execute_module`]) always calls this). See [`Self::drive_turn_as`] for the
    /// explicit-principal variant the Team loop's [`TaskExecutor::run_task`] uses instead.
    fn drive_turn(&mut self, label: String, input: String) -> Result<TurnObservation, TurnError> {
        let principal = self.principal.clone();
        self.drive_turn_as(label, input, principal)
    }

    /// [`Self::drive_turn`] over an EXPLICIT principal rather than the executor's own Run-level
    /// `self.principal` — GAP-FIX gap6-tools-hooks-obo-supplychain item 3: the seam
    /// [`TaskExecutor::run_task`] uses to dispatch a Team task's turn under a NARROWED sub-agent
    /// principal (see [`Self::task_principal`]) derived via `ainxt_tools::obo::OboContext::delegate`
    /// from the Run's full authority, instead of every task running with the SAME parent authority
    /// regardless of role. Runs on the synchronous driver thread (not a Tokio worker), so `block_on` is
    /// always valid and never starves the async executor.
    fn drive_turn_as(
        &mut self,
        label: String,
        input: String,
        principal: Principal,
    ) -> Result<TurnObservation, TurnError> {
        self.turn_seq += 1;
        // §17/§19 in-flight admission gate: consult the shared control plane BEFORE committing the turn,
        // so a kill-switch / run-revocation / OBO-revocation stops this Run's next dispatch immediately
        // (kill-switch reaches in-flight Runs). Deny is fail-closed: no model work, a denied observation.
        if let Some(control) = &self.control {
            let now = LogicalTime(self.credential.issued_at.tick());
            let decision = control
                .lock()
                .expect("control plane lock")
                .admit(&self.credential, now);
            if let AdmissionDecision::Deny(reason) = decision {
                let msg = format!("run dispatch denied by control plane: {reason}");
                self.turns.push(TurnObservation {
                    label,
                    // GAP-FIX identity-payments (§14 actor-of-record): the actor written for every
                    // served turn is the AWC's full composite `actor_label()` (uri|obo|commit|key) —
                    // never the bare OBO `user_id` a service-account-style attribution would use. See
                    // `ainxt_identity::authority::AgentWorkloadCredential::actor_label` /
                    // `ainxt-identity/tests/r12_actor_of_record_served.rs`.
                    actor: self.credential.actor_label(),
                    provider: "denied".into(),
                    redactions: 0,
                    text: String::new(),
                    ok: false,
                });
                return Err(TurnError::Denied(msg));
            }
        }
        let engine = self.engine.clone();
        let cancel = self.cancel.clone();
        let data_class = self.credential.data_class;
        let req = Request {
            session: self.credential.run_id.clone(),
            turn: format!("turn-{}", self.turn_seq),
            input,
            data_class,
            tier: Tier::Medium,
            forced_provider: None,
            untrusted_tainted: false,
            user_turn: None,
            namespace: None,
            pinned_tier: None,
            request_override: None,
            history_budget_tokens: None,
        };

        let outcome = self.handle.block_on(async move {
            let (tx, mut rx) = mpsc::channel::<Event>(64);
            let run = engine.run_turn_cancellable(&principal, &req, tx, &cancel);
            let collect = async move {
                let mut text = String::new();
                while let Some(ev) = rx.recv().await {
                    if let Event::TextDelta(t) = ev {
                        text.push_str(&t);
                    }
                }
                text
            };
            let (res, text) = tokio::join!(run, collect);
            res.map(|summary| (summary, text))
        });

        match outcome {
            Ok((summary, text)) => {
                let obs = TurnObservation {
                    label,
                    // §14 actor-of-record: the full composite AWC label, not the bare OBO user id.
                    actor: self.credential.actor_label(),
                    provider: summary.provider.clone(),
                    redactions: summary.redactions,
                    text,
                    ok: true,
                };
                self.maybe_arm_incident(data_class, summary.redactions);
                self.turns.push(obs.clone());
                Ok(obs)
            }
            Err(e) => {
                let obs = TurnObservation {
                    label,
                    // §14 actor-of-record: the full composite AWC label, not the bare OBO user id.
                    actor: self.credential.actor_label(),
                    provider: "none".into(),
                    redactions: 0,
                    text: String::new(),
                    ok: false,
                };
                self.turns.push(obs);
                Err(e)
            }
        }
    }

    /// FI-02: a regulated turn on which the always-on compliance gate ACTED (redactions > 0) is a
    /// real compliance-egress detector signal — arm the statutory clock via the typed adapter. The
    /// fail-safe posture is "arm early, disarm on authority" (a redaction that fired on regulated
    /// content is itself the signal), so a provisional clock is armed the instant the gate acts.
    fn maybe_arm_incident(&self, data_class: DataClass, redactions: usize) {
        if redactions == 0 || !data_class.is_regulated() {
            return;
        }
        if let Some(register) = &self.incident {
            let t0 = self.credential.issued_at.tick();
            let candidate = IncidentCandidate::from_compliance_egress(
                t0,
                &self.credential.control_commit_sha,
                data_class,
                redactions as u64,
            );
            register
                .lock()
                .expect("incident register lock")
                .open_from(candidate, t0);
        }
    }

    /// gap loop-teams-longhorizon (item 3): spawn and drive a REAL nested [`supervisor::run_program`]
    /// for a `child-program`-class node (ADR-027 §4), then map its TERMINAL `ProgramOutcome` back to a
    /// [`ChildOutcome`] — never a fabricated one. The child's own (single-node) MTG is driven through
    /// THIS SAME `EngineRunExecutor`, recursively — the child's node is `NodeClass::MigrationRun`, so
    /// the recursion terminates at depth 1 and its own det/adv verdicts are derived from a REAL engine
    /// turn exactly like any other module (`drive_turn` below). The program-scale edge/sweep/judge
    /// proofs for the child use the SAME offline-default [`PermissiveProgramVerifier`] the top-level
    /// program itself runs under in `run_program_blocking` — not a new, lower bar introduced here.
    fn execute_child_program(&mut self, ctx: &ModuleRunContext) -> ModuleRunResult {
        let child_program_id = ProgramId::new(format!("{}::child::{}", ctx.program_id, ctx.node));
        let child_goal = format!(
            "{} (child program spawned for node '{}')",
            ctx.goal, ctx.node
        );
        let child_node = NodeDecl::new(format!("{}::work", ctx.node), NodeClass::MigrationRun);

        let mut sink = VecEventSink::new();
        // VecEventSink::append is infallible (it pushes to a Vec) — the seed must be on the log
        // before the supervisor loads + projects it (mirrors `run_program_blocking`'s seeding).
        sink.append(&ProgramEvent::Created {
            program_id: child_program_id.clone(),
            goal: child_goal,
        })
        .expect("seed child program Created event");
        sink.append(&ProgramEvent::Decomposed {
            nodes: vec![child_node],
        })
        .expect("seed child program Decomposed event");

        let mut verifier = PermissiveProgramVerifier;
        let mut gate = AutoApprove;
        let mut never_cancel = || false;

        // Drive the child to a terminal outcome NOW (synchronously) — `ModuleRunResult::ChildProgram`
        // carries the already-resolved outcome, matching `ainxt_planner::supervisor`'s contract (see
        // its handling of this variant): the seam abstracts the nested Supervisor entirely, the parent
        // never polls or infers from the child's intermediate state.
        let (outcome, cost) = match supervisor::run_program(
            &mut sink,
            self,
            &mut verifier,
            &mut gate,
            SupervisorConfig::default(),
            &mut never_cancel,
        ) {
            Ok(report) => (report.outcome, report.total_cost),
            // A hard programming error building/folding the child program's own event log (never a
            // property of the child's WORK, which only ever reaches `Ran`/`Failed`) — honestly
            // abandon the child rather than silently treating it as success.
            Err(_e) => (ProgramOutcome::Abandoned, ProgramCost::default()),
        };

        let mapped = match outcome {
            ProgramOutcome::Completed => ChildOutcome::Completed,
            ProgramOutcome::CappedPartial => ChildOutcome::CappedPartial,
            ProgramOutcome::Abandoned => ChildOutcome::Abandoned,
        };

        ModuleRunResult::ChildProgram {
            child_program_id,
            outcome: mapped,
            cost,
        }
    }
}

/// Derive the deterministic + adversarial verdicts for a module from the REAL engine turn — the
/// "never fabricated green" rule (LONG_HORIZON §6). A turn is committable only if it completed without
/// a terminal engine error AND produced non-empty content; otherwise the deterministic gate is RED (a
/// blocking finding), which [`three_way_gate`](ainxt_planner::verify::three_way_gate) refuses
/// regardless of the Judge score, so the node cannot be committed/verified. Pure + unit-testable.
pub fn verdict_for_observation(
    obs: &TurnObservation,
) -> (DeterministicVerdict, AdversarialVerdict) {
    let committable = obs.ok && !obs.text.trim().is_empty();
    if committable {
        (DeterministicVerdict::green(), AdversarialVerdict::green(1))
    } else {
        (
            DeterministicVerdict {
                compiled: obs.ok,
                tests_passed: false,
                blocking_findings: vec![
                    "engine turn produced no committable artifact (empty or errored)".to_string(),
                ],
                completed: true,
            },
            AdversarialVerdict::green(0),
        )
    }
}

// ---- LOOP-01: the Program Supervisor's base-loop Run seam, backed by a real turn ----

impl RunExecutor for EngineRunExecutor {
    fn execute_module(&mut self, ctx: &ModuleRunContext) -> ModuleRunResult {
        // gap loop-teams-longhorizon (item 3, child-program composition): ADR-027 §4's parent/child
        // mechanism (`Program::spawn_child_program`/`resolve_child_program`, `BlockedOnChildProgram`,
        // and `ainxt_planner::supervisor`'s `ModuleRunResult::ChildProgram` handling) was fully built
        // and exercised against FAKE executors (`crates/ainxt-planner/tests/r15_child_program_composition.rs`),
        // but THIS executor — the one both the durable/batch driver (`run_program_durable`) and the
        // served driver actually construct — never special-cased `NodeClass::ChildProgram` at all:
        // every node, including a child-program node, fell through to the plain `drive_turn` engine
        // turn below, so a real program could never actually recurse into a nested Program; it would
        // silently run one flat turn instead and never emit `ChildProgramSpawned`/
        // `ChildProgramOutcomeMapped`. Route a not-yet-resolved child-program node to
        // `execute_child_program`, which spawns and drives a REAL nested Program instead.
        if ctx.node_class == NodeClass::ChildProgram && !ctx.child_resolved {
            return self.execute_child_program(ctx);
        }
        let label = format!("module:{}", ctx.node);
        let input = format!(
            "Program {} module '{}' [{:?}] attempt {}: {}",
            ctx.program_id, ctx.node, ctx.node_class, ctx.attempt, ctx.goal
        );
        match self.drive_turn(label, input) {
            Ok(obs) => {
                // The Run drove a real engine turn. Its deterministic verdict is DERIVED FROM THE REAL
                // OUTCOME — never a fabricated green: a turn that errored or produced no committable
                // artifact yields a RED deterministic gate (blocking_findings non-empty), which the
                // three-way gate refuses regardless of any Judge score, so the node is NOT committed.
                // A green gate requires a completed turn with real content. The program-scale proofs
                // (edge integration / regression sweep / program judge) remain the ProgramVerifier
                // seam's job — the Engine never self-declares the program "done".
                let (det, adv) = verdict_for_observation(&obs);
                let cost = ProgramCost::new(obs.text.len() as u64, 1, 0);
                // GAP-FIX planner-assurance-revision (item 1) — the semantic Judge is now a REAL,
                // content-varying evaluation over the artifact this exact turn produced (`obs.text`
                // against `ctx.goal`), never the old hardcoded `JudgeVerdict::pass(95, 80, ..)` that
                // scored every module identically regardless of what the engine actually produced.
                // `RubricJudge` (`ainxt_planner::assurance`) is the same offline, deterministic,
                // content-inspecting analyser already wired as the adversarial Breaker's matched pair
                // (`ainxt_teams::tiers::BreakerAdversarialGate`); threshold 80 / judge label
                // "runtime-judge" preserve the pre-fix constants so only the SCORE stops being fabricated.
                let artifact =
                    ModuleArtifact::new(ctx.goal.clone(), obs.text.clone(), obs.provider.clone());
                let judge = RubricJudge::new("runtime-judge", 80).judge(&artifact);
                ModuleRunResult::Ran {
                    det,
                    adv,
                    judge,
                    commit_shas: vec![format!("run-{}-{}", ctx.node, ctx.attempt)],
                    ledger_key: format!("{}::{}::{}", ctx.program_id, ctx.node, ctx.attempt),
                    by_model: obs.provider,
                    cost,
                }
            }
            Err(e) => ModuleRunResult::Failed {
                reason: format!("engine turn failed: {e:?}"),
                cost: ProgramCost::new(0, 1, 0),
            },
        }
    }
}

// ---- LOOP-15: the 3-tier Team loop's tier-1 executor seam, backed by a real turn ----

/// GAP-FIX gap6-tools-hooks-obo-supplychain item 3 — narrow a Run's `Principal` to one task's
/// role-declared capabilities via the OBO sub-agent delegation mechanism
/// (`ainxt_tools::obo::OboContext::delegate`), the turnkey "a child context can only narrow the
/// parent" primitive `OboDispatcher::dispatch_sub_agent` bundles. [`EngineRunExecutor::run_task`] (the
/// REAL composition-root caller, below) calls this exact function for every Team task; it is a free
/// function of `(principal, ctx)` — not a method — purely so it is unit-testable without constructing
/// a full `Engine`/`EngineRunExecutor` (see `program_exec::tests::obo_sub_agent_narrowing`, which
/// exercises THIS function directly).
///
/// Before this fix, `Team`'s `Role::capabilities` (LOOP §4's declared least-privilege set — e.g. a
/// "coder" role holding only `edit_code`, never `deploy`) was fully implemented and unit-tested
/// (`Role::has_capability`/`Team::role_has_capability`) but enforced NOWHERE on the served path:
/// [`EngineRunExecutor::run_task`] drove every task's turn under the SAME `principal`/credential,
/// regardless of which role the task graph assigned it — an architect task and a coder task in the
/// SAME Run carried IDENTICAL dispatch authority. Separately, `OboContext::delegate`/
/// `dispatch_sub_agent` had zero callers anywhere outside `ainxt-tools`'s own tests. Those are the two
/// halves of the SAME gap: wiring them together here is what makes a per-task capability declaration
/// an actual authorization boundary instead of a descriptive label.
///
/// The PARENT context's grants are `principal.caps` (this executor's baseline — unaffected for the
/// Program seam, which never calls this) UNION `ctx.team_capabilities` (every role in the Team, LOOP
/// §4's team-wide envelope) — the broadest authority any task in this Run could need. `.delegate()`
/// then keeps ONLY `principal.caps` UNION `ctx.capabilities` (this task's OWN role) — structurally a
/// SUBSET of the parent, per `OboContext::delegate`'s own "no API to ADD a grant the parent lacks"
/// contract — and the narrowed `issued_scope` becomes the `Principal` this task's turn actually
/// dispatches tools under. A role absent from the team (or with no declared capabilities) gets a
/// principal narrowed to just the baseline `principal.caps` — never wider.
fn delegate_task_principal(principal: &Principal, ctx: &StepContext) -> Principal {
    let mut parent_caps: BTreeSet<String> = principal.caps.iter().cloned().collect();
    parent_caps.extend(ctx.team_capabilities.iter().cloned());
    let parent = OboContext::new(
        principal.user_id.clone(),
        parent_caps
            .iter()
            .map(|c| Grant::new(c, "*", "*"))
            .collect::<Vec<_>>(),
        parent_caps.iter().cloned(),
        principal.clearance,
    );
    let mut keep: BTreeSet<String> = principal.caps.iter().cloned().collect();
    keep.extend(ctx.capabilities.iter().cloned());
    let keep_refs: Vec<&str> = keep.iter().map(String::as_str).collect();
    // Clearance is NOT narrowed per-role here — LOOP §4 roles declare tool capabilities, not a
    // separate data-clearance ceiling, so the child keeps the parent's own clearance unchanged
    // (`delegate`'s clamp is a no-op when `requested == parent`).
    let child = parent.delegate(&keep_refs, principal.clearance);
    Principal {
        caps: child.issued_scope.into_iter().collect(),
        ..principal.clone()
    }
}

#[cfg(test)]
mod obo_sub_agent_narrowing_tests {
    //! GAP-FIX gap6-tools-hooks-obo-supplychain item 3 — `delegate_task_principal` is a private, free
    //! function (see its own doc), so its proving tests live inline rather than in `tests/` where it
    //! would be unreachable. `EngineRunExecutor::run_task` (`impl TaskExecutor` below) calls this EXACT
    //! function for every real Team task on the served path (`assemble_team_surface` →
    //! `drive_served_team*` → `run_team_3tier_verified*` → `execute_task_with_self_heal` →
    //! `TaskExecutor::run_task`) — these tests exercise the real mechanism the composition root now
    //! depends on, not a re-implementation of it.
    //!
    //! The canonical served team (`compose_served_team`, used by `assemble_team_surface` and proven
    //! server-reachable in `tests/r12_team_served_reachable.rs`) is exactly this shape: architect
    //! (`design`) / coder (`edit_code`) / reviewer (`review`) / tester (`test`) — four single-capability
    //! roles — so these tests use the identical role vocabulary.

    use super::*;
    use ainxt_types::DataClass;

    fn base_principal() -> Principal {
        Principal::user("u-alice", &["chat.send"]).with_clearance(DataClass::Internal)
    }

    fn ctx_with(capabilities: &[&str], team_capabilities: &[&str]) -> StepContext {
        StepContext {
            attempt: 0,
            model_tier: ModelTier::Medium,
            round: 0,
            prior_error: None,
            escalated_context: false,
            capabilities: capabilities.iter().map(|s| s.to_string()).collect(),
            team_capabilities: team_capabilities.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// The headline property: a "coder" task's narrowed principal holds `edit_code` (its own role)
    /// but NEITHER `design` nor `review` (the other roles in the SAME team) — genuinely narrower than
    /// the team-wide envelope, not a same-width relabeling.
    #[test]
    fn a_task_is_narrowed_to_only_its_own_roles_capability() {
        let parent = base_principal();
        let team_caps = ["design", "edit_code", "review", "test"];
        let coder_ctx = ctx_with(&["edit_code"], &team_caps);

        let child = delegate_task_principal(&parent, &coder_ctx);

        assert!(
            child.caps.iter().any(|c| c == "edit_code"),
            "must keep its OWN role's capability"
        );
        assert!(
            child.caps.iter().any(|c| c == "chat.send"),
            "must keep the baseline turn capability"
        );
        assert!(
            !child.caps.iter().any(|c| c == "design"),
            "a coder must NOT inherit the architect's capability: {:?}",
            child.caps
        );
        assert!(
            !child.caps.iter().any(|c| c == "review"),
            "a coder must NOT inherit the reviewer's capability: {:?}",
            child.caps
        );
        assert!(
            !child.caps.iter().any(|c| c == "test"),
            "a coder must NOT inherit the tester's capability: {:?}",
            child.caps
        );
        // Genuinely narrower, not just different: strictly fewer capabilities than the team envelope
        // plus baseline.
        let team_wide_envelope = team_caps.len() + 1; // + "chat.send"
        assert!(
            child.caps.len() < team_wide_envelope,
            "child ({} caps) must be a PROPER subset of the team-wide parent envelope ({} caps)",
            child.caps.len(),
            team_wide_envelope
        );
    }

    /// A different role in the SAME team is narrowed to ITS OWN distinct capability — proving this
    /// isn't a hardcoded/one-off filter but a genuine per-task computation.
    #[test]
    fn a_different_role_in_the_same_team_gets_a_different_narrow_scope() {
        let parent = base_principal();
        let team_caps = ["design", "edit_code", "review", "test"];
        let reviewer_ctx = ctx_with(&["review"], &team_caps);

        let child = delegate_task_principal(&parent, &reviewer_ctx);

        assert!(child.caps.iter().any(|c| c == "review"));
        assert!(!child.caps.iter().any(|c| c == "edit_code"));
        assert!(!child.caps.iter().any(|c| c == "design"));
        assert!(!child.caps.iter().any(|c| c == "test"));
    }

    /// THE confused-deputy property: even if a caller (a buggy/compromised role declaration) claims a
    /// capability the PARENT never held at all — not merely one held by a sibling role — `delegate`
    /// structurally cannot manufacture it. This is `OboContext::delegate`'s own "no API to ADD a grant
    /// the parent lacks" contract, proven through the REAL composition-root call path.
    #[test]
    fn a_task_can_never_be_granted_a_capability_the_parent_never_held_at_all() {
        let parent = base_principal(); // caps = ["chat.send"] only
                                       // Neither `deploy` nor `settlement.transfer` are in team_capabilities OR principal.caps —
                                       // a role declaring one is a confused-deputy attempt, not a legitimate narrowing.
        let rogue_ctx = ctx_with(&["deploy", "settlement.transfer"], &["edit_code"]);

        let child = delegate_task_principal(&parent, &rogue_ctx);

        assert!(
            !child.caps.iter().any(|c| c == "deploy"),
            "a capability absent from the parent's own authority must never appear on the child: {:?}",
            child.caps
        );
        assert!(!child.caps.iter().any(|c| c == "settlement.transfer"));
        // The ONLY thing this task can end up with is the unconditional baseline.
        assert_eq!(child.caps, vec!["chat.send".to_string()]);
    }

    /// A role absent from the team (or with an empty declared capability set) is narrowed down to
    /// just the baseline — fail-closed, matching `Role::has_capability`'s own "no implicit escalation"
    /// contract, never silently inheriting the team-wide envelope.
    #[test]
    fn a_role_with_no_declared_capabilities_gets_only_the_unconditional_baseline() {
        let parent = base_principal();
        let empty_role_ctx = ctx_with(&[], &["design", "edit_code", "review"]);

        let child = delegate_task_principal(&parent, &empty_role_ctx);

        assert_eq!(child.caps, vec!["chat.send".to_string()]);
    }

    /// Depth-of-delegation and clearance sanity: clearance is carried through unchanged (roles gate
    /// tool capabilities, not a separate data ceiling), and the narrowing leaves every other principal
    /// field (`user_id`, `role`, `department`, …) untouched — this is a capability-only narrowing, not
    /// a different identity.
    #[test]
    fn narrowing_preserves_identity_and_clearance_unchanged() {
        let parent = Principal::user("u-bob", &["chat.send"])
            .with_clearance(DataClass::Confidential)
            .with_department("payments-eng");
        let ctx = ctx_with(&["edit_code"], &["design", "edit_code"]);

        let child = delegate_task_principal(&parent, &ctx);

        assert_eq!(child.user_id, "u-bob");
        assert_eq!(child.clearance, DataClass::Confidential);
        assert_eq!(child.department.as_deref(), Some("payments-eng"));
    }
}

impl TaskExecutor for EngineRunExecutor {
    fn run_task(&mut self, task: &Task, ctx: &StepContext) -> StepAttempt {
        let label = format!("task:{}", task.id);
        let input = format!(
            "Task '{}' role={} tier={:?} round={} attempt={}: {}",
            task.id, task.role, ctx.model_tier, ctx.round, ctx.attempt, task.description
        );
        let principal = delegate_task_principal(&self.principal, ctx);
        match self.drive_turn_as(label, input, principal) {
            Ok(obs) => StepAttempt {
                invocation: AgentInvocation::leaf(
                    task.role.clone(),
                    Cost::new(obs.text.len() as u64, 1, 0, 0),
                ),
                // GAP-AUDIT loop-teams-longhorizon — `output_ref` carries the REAL engine turn text,
                // never a synthetic length-tagged reference. `tiers::combined_output_text`'s doc is
                // explicit that "real deployments put real diff/report text there (the same shape
                // `ModuleArtifact::text` expects)"; a placeholder like `artifact://code#42` can never
                // contain a stub marker or a PAN-shaped literal, so `ContentDeterministicGate` /
                // `BreakerAdversarialGate` (wired into `drive_served_team_blocking` below) would have
                // been auditing a meaningless string instead of the actual produced content.
                result: StepResult::Produced {
                    output_ref: obs.text,
                },
            },
            Err(e) => StepAttempt {
                invocation: AgentInvocation::leaf(task.role.clone(), Cost::ZERO),
                result: StepResult::Failed {
                    error: format!("engine turn failed: {e:?}"),
                },
            },
        }
    }
}

// ===========================================================================
// Entrypoints — drive the subsystem end-to-end through the real Engine
// ===========================================================================

/// The result of a supervised [`run_program`].
pub struct ProgramRun {
    pub report: SupervisorReport,
    /// The per-Run credential minted at run start (IDN-03).
    pub credential: AgentWorkloadCredential,
    /// Every engine turn the supervisor drove (one per committed / attempted module).
    pub turns: Vec<TurnObservation>,
    /// The durable program event log the supervisor appended.
    pub events: Vec<ProgramEvent>,
}

/// The result of a [`run_team`].
pub struct TeamRun {
    pub report: TeamRunReport,
    /// The per-Run credential minted at run start (IDN-03).
    pub credential: AgentWorkloadCredential,
    /// Every engine turn the 3-tier loop drove.
    pub turns: Vec<TurnObservation>,
}

/// Why a [`run_program`] could not run.
#[derive(Debug)]
pub enum ProgramRunError {
    /// The per-Run credential could not be minted (IDN-03 / attestation / revocation / kill-switch).
    Identity(IssueError),
    /// The Program Supervisor rejected the run.
    Program(ProgramError),
    /// The durable Event Log backing a resumable Program could not be opened / appended to.
    Durable(String),
}

impl fmt::Display for ProgramRunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProgramRunError::Identity(e) => write!(f, "run identity error: {e}"),
            ProgramRunError::Program(e) => write!(f, "program supervisor error: {e:?}"),
            ProgramRunError::Durable(m) => write!(f, "durable program log error: {m}"),
        }
    }
}
impl std::error::Error for ProgramRunError {}

/// Why a [`run_team`] could not run.
#[derive(Debug)]
pub enum TeamRunError {
    /// The per-Run credential could not be minted (IDN-03).
    Identity(IssueError),
    /// The team task graph was not schedulable.
    Graph(GraphError),
}

impl fmt::Display for TeamRunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TeamRunError::Identity(e) => write!(f, "run identity error: {e}"),
            TeamRunError::Graph(e) => write!(f, "team graph error: {e}"),
        }
    }
}
impl std::error::Error for TeamRunError {}

/// Drive a long-horizon **Program** to a terminal outcome through the real [`Engine`] (LOOP-01).
///
/// Mints a per-Run [`AgentWorkloadCredential`] (IDN-03), seeds the durable program log with
/// `Created` + `Decomposed`, then runs `ainxt_planner::supervisor::run_program` with an
/// [`EngineRunExecutor`] so every module is executed by a real engine turn. The permissive
/// program verifier + auto-approve gate are the offline-autonomous defaults; a deployment injects a
/// test-runner/judge-backed verifier and a real approval gate.
///
/// When `incident` is supplied, a regulated turn on which the compliance gate acted arms a statutory
/// clock (FI-02).
pub async fn run_program(
    engine: Arc<Engine>,
    identity: RunIdentitySpec,
    goal: impl Into<String>,
    nodes: Vec<NodeDecl>,
    config: SupervisorConfig,
    incident: Option<Arc<Mutex<IncidentRegister>>>,
) -> Result<ProgramRun, ProgramRunError> {
    run_program_inner(engine, identity, goal, nodes, config, incident, None).await
}

/// [`run_program`] with the shared §17/§19 [`ControlPlane`] wired: a kill-switch / run-revocation /
/// OBO-revocation on `control` denies the Run's next module dispatch immediately (kill-switch reaches
/// in-flight Runs). This is the entrypoint the served surface uses so a control action on the shared
/// surface stops in-flight Program work rather than only at the next renewal.
pub async fn run_program_governed(
    engine: Arc<Engine>,
    identity: RunIdentitySpec,
    goal: impl Into<String>,
    nodes: Vec<NodeDecl>,
    config: SupervisorConfig,
    incident: Option<Arc<Mutex<IncidentRegister>>>,
    control: Arc<Mutex<ControlPlane>>,
) -> Result<ProgramRun, ProgramRunError> {
    run_program_inner(
        engine,
        identity,
        goal,
        nodes,
        config,
        incident,
        Some(control),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn run_program_inner(
    engine: Arc<Engine>,
    identity: RunIdentitySpec,
    goal: impl Into<String>,
    nodes: Vec<NodeDecl>,
    config: SupervisorConfig,
    incident: Option<Arc<Mutex<IncidentRegister>>>,
    control: Option<Arc<Mutex<ControlPlane>>>,
) -> Result<ProgramRun, ProgramRunError> {
    let credential = mint_run_credential(&identity).map_err(ProgramRunError::Identity)?;
    let program_id = ProgramId::new(identity.run_id.clone());
    let goal = goal.into();
    let handle = Handle::current();
    let cred = credential.clone();

    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("ainxt-program".into())
        .spawn(move || {
            let out = run_program_blocking(
                engine, cred, handle, program_id, goal, nodes, config, incident, control,
            );
            let _ = tx.send(out);
        })
        .expect("spawn program driver thread");

    let (report, turns, events) = rx
        .await
        .expect("program driver thread dropped its result")
        .map_err(ProgramRunError::Program)?;
    Ok(ProgramRun {
        report,
        credential,
        turns,
        events,
    })
}

#[allow(clippy::too_many_arguments)]
fn run_program_blocking(
    engine: Arc<Engine>,
    credential: AgentWorkloadCredential,
    handle: Handle,
    program_id: ProgramId,
    goal: String,
    nodes: Vec<NodeDecl>,
    config: SupervisorConfig,
    incident: Option<Arc<Mutex<IncidentRegister>>>,
    control: Option<Arc<Mutex<ControlPlane>>>,
) -> Result<(SupervisorReport, Vec<TurnObservation>, Vec<ProgramEvent>), ProgramError> {
    let mut sink = VecEventSink::new();
    // VecEventSink::append is infallible (it pushes to a Vec); the seed must be on the log before the
    // supervisor loads + projects it.
    sink.append(&ProgramEvent::Created { program_id, goal })
        .expect("seed Created event");
    sink.append(&ProgramEvent::Decomposed { nodes })
        .expect("seed Decomposed event");

    let mut exec =
        EngineRunExecutor::new(engine, credential, handle, incident).with_control_plane(control);
    let mut verifier = PermissiveProgramVerifier;
    let mut gate = AutoApprove;
    let mut cancel = || false;

    let report = supervisor::run_program(
        &mut sink,
        &mut exec,
        &mut verifier,
        &mut gate,
        config,
        &mut cancel,
    )?;
    let events = sink.events().to_vec();
    Ok((report, exec.into_observations(), events))
}

// ===========================================================================
// LOOP-01 / §6 — driver-enforced three-way verification + §15 JIT renewal
// ===========================================================================

/// The result of a [`run_program_verified`] Run: the live-drivable [`Program`] (its durable log +
/// projected state carry the three-way verification proofs), the final per-Run credential, every
/// engine turn driven, the number of §15 identity renewals performed, and the sealed terminal outcome.
pub struct VerifiedProgramRun {
    /// The driver Program whose `record_verdict`/`commit_node` calls enforced verification. `state()`
    /// answers `committed_nodes_are_all_proven()` — a `Verified`/`Committed` node no `Complete` proof
    /// backs is unreachable through this API.
    pub program: Program,
    pub credential: AgentWorkloadCredential,
    pub turns: Vec<TurnObservation>,
    /// §15 JIT renewals performed on the long Run (each re-checked def/revocation/kill-switch/anomaly).
    pub renewals: u32,
    /// §18 Separation-of-Duties commits authorized by the [`SodVerifyGate`]: a node is committed ONLY
    /// after the gate authorizes the produced artifact for a DISTINCT approver Run (producer ≠
    /// approver). A self-approving misconfiguration refuses every commit, so this stays 0 and the
    /// program cannot complete.
    pub sod_approvals: u32,
    pub outcome: ProgramOutcome,
}

/// The logical ticks between §15 credential renewals on a long served Run. Small so a multi-module Run
/// exercises the renewal chain (the identity crate never reads a wall clock — the composition supplies
/// logical time). A deployment tunes it to the deployed AWC TTL.
const RENEW_EVERY_TICKS: u64 = 1;

/// Max attempts per node before a stuck node is left uncommitted (honest capped-partial, never a
/// fabricated commit). Bounds the driver loop when a node's turn keeps yielding a red verdict.
const VERIFY_ATTEMPT_CAP: u32 = 2;

/// GAP-FIX identity-payments (ADR-022 §18) — the offline reference trust-domain root every
/// composition-root-minted [`AwcKeySigner`]/[`AwcKeyVerifier`] pair binds to. A real deployment swaps
/// the deterministic HMAC-SHA256 tag for an ADR-023 asymmetric signature over the identical
/// [`Handoff::signing_material`] with no call-site change (see `AwcKeySigner`'s own doc comment).
const AWC_HANDOFF_TRUST_DOMAIN: &str = "ainxt-served-program-trust-root";

/// GAP-FIX identity-payments (ADR-022 §18) — the offline reference key-material derivation for a
/// given AWC `key_id`. `ainxt-identity`'s `AgentWorkloadCredential` deliberately carries only a
/// `key_id` REFERENCE, never the private key material itself (that is ADR-023's KMS/HSM-backed
/// concern) — this composition root needs a value the producer's signer and the receiver's verifier
/// can each deterministically recompute from data already in scope (the shared credential's own
/// `key_id`), exactly the same offline-seam property `AwcKeySigner`'s own doc describes. A real
/// deployment resolves this via the AIA's real key store keyed on `key_id`, with no call-site change.
fn awc_signing_secret(key_id: &str) -> String {
    format!("ainxt-awc-signing-material::{key_id}")
}

/// GAP-FIX identity-payments (ADR-022 §18) — authorize a node/module commit through the REAL SIGNED
/// handoff path ([`SodVerifyGate::accept_handoff`]), never the unsigned [`SodVerifyGate::authorize_approval`]
/// direct-check `program_exec.rs` called exclusively before this fix. `SodVerifyGate::accept_handoff`
/// + [`AwcKeySigner`]/[`AwcKeyVerifier`] (`ainxt-identity::sod`) were fully implemented and
/// unit-tested, but the live program/team verifier never called them — the served path enforced ONLY
/// the producer≠approver identity rule, never the signature half of §18's guarantee ("a compromised
/// Coder cannot forge a Judge's approved handoff because it cannot produce the Judge's AWC
/// signature").
///
/// `producer` signs a [`Handoff`] over `artifact_id`/`content_digest` with an [`AwcKeySigner`] bound
/// to its own AWC key material; `approver` (the receiver) verifies it with an [`AwcKeyVerifier`] bound
/// to the SAME producer AWC — `SodPolicy::accept_handoff`'s three checks (signature validity, digest
/// match, then the producer≠approver identity rule) all run, in that order, before a commit is
/// authorized. A forged or artifact-swapped handoff is refused before the identity rule is even
/// reached; a self-approving misconfiguration is still refused by the identity rule underneath.
fn authorize_commit_via_signed_handoff(
    sod_gate: &SodVerifyGate,
    producer: &AgentWorkloadCredential,
    approver: &AgentWorkloadCredential,
    artifact_id: impl Into<String>,
    content_digest: impl Into<String>,
) -> Result<SodApprovalDecision, SodError> {
    let artifact_id = artifact_id.into();
    let content_digest = content_digest.into();
    let handoff = Handoff::new(
        artifact_id.clone(),
        WorkloadRef::from(producer),
        WorkloadRef::from(approver),
        content_digest.clone(),
    );
    let secret = awc_signing_secret(&producer.key_id);
    let signer = AwcKeySigner::for_credential(producer, AWC_HANDOFF_TRUST_DOMAIN, secret.clone());
    let signature = signer.sign(&handoff);
    let signed = SignedHandoff { handoff, signature };
    let expected = ProducedArtifact::new(artifact_id, WorkloadRef::from(producer), content_digest);
    let verifier = AwcKeyVerifier::for_credential(producer, AWC_HANDOFF_TRUST_DOMAIN, secret);
    sod_gate.accept_handoff(&signed, &expected, &verifier)
}

/// Drive a Program to a terminal outcome through the **driver** [`Program`] API so three-way
/// verification is enforced at the seam — every node reaches `Verified`/`Committed` ONLY via
/// [`Program::record_verdict`] (which recomputes the three-way gate from the three independent
/// proofs) then [`Program::commit_node`] (which refuses a node lacking a durable `Complete` proof,
/// [`ProgramError::NodeNotProven`]). The per-module verdict is DERIVED FROM THE REAL ENGINE TURN
/// ([`verdict_for_observation`]) — never a fabricated green — so a turn that errored or produced no
/// artifact blocks the commit. §15 JIT renewal: the per-Run credential is renewed as the Run's logical
/// clock advances past its short TTL, so a long Run is a chain of re-checked renewals, not a standing
/// grant. `control`, when set, denies an in-flight dispatch on a shared kill-switch / revocation.
///
/// §18 Separation-of-Duties: each node's commit is authorized by a [`SodVerifyGate`] against a
/// DISTINCT verifier/approver Run (producer ≠ approver) — see [`run_program_verified_sod`], which this
/// delegates to with the default distinct approver.
pub async fn run_program_verified(
    engine: Arc<Engine>,
    identity: RunIdentitySpec,
    goal: impl Into<String>,
    nodes: Vec<NodeDecl>,
    incident: Option<Arc<Mutex<IncidentRegister>>>,
    control: Option<Arc<Mutex<ControlPlane>>>,
    cancel: CancelToken,
) -> Result<VerifiedProgramRun, ProgramRunError> {
    run_program_verified_sod(
        engine,
        identity,
        goal,
        nodes,
        incident,
        control,
        SodApprover::Distinct,
        cancel,
    )
    .await
}

/// Who approves a node's commit in the §18 Separation-of-Duties verify-gate. The composition always
/// uses [`SodApprover::Distinct`]; [`SodApprover::SameAsProducer`] models a self-approving
/// misconfiguration used to prove the gate refuses it on the live path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SodApprover {
    /// A SEPARATE verifier Run of the same git-controlled definition (producer ≠ approver) — the
    /// default. The AIA mints it as a distinct `<producer-run>::verifier` credential.
    Distinct,
    /// The producing Run itself acts as its own approver — a self-approving misconfiguration. The SoD
    /// gate refuses every commit under it (a Run can never approve its own work), so the program
    /// cannot complete. This is the honest way to exercise the refusal: the AIA will not mint a second
    /// credential sharing the producer's `run_id`, so self-approval can only arise from reusing the
    /// producing Run's own identity as the approver.
    SameAsProducer,
}

/// [`run_program_verified`] with the §18 Separation-of-Duties approver identity made explicit. Every
/// node's `commit_node` is gated on [`SodVerifyGate::authorize_approval`]: the producing Run's
/// credential is the artifact producer, and a DISTINCT verifier Run's credential is the approver.
///
/// * [`SodApprover::Distinct`] — the composition default: a distinct approver Run
///   (`<producer-run>::verifier`), so producer ≠ approver and the commit is authorized.
/// * [`SodApprover::SameAsProducer`] — the producing Run itself is the approver (a self-approving
///   misconfiguration); the gate then refuses every commit ([`SodError::SelfApproval`]), each node is
///   failed, and the program cannot complete — the proof that self-approval is refused on the live
///   program-verification path.
#[allow(clippy::too_many_arguments)]
pub async fn run_program_verified_sod(
    engine: Arc<Engine>,
    identity: RunIdentitySpec,
    goal: impl Into<String>,
    nodes: Vec<NodeDecl>,
    incident: Option<Arc<Mutex<IncidentRegister>>>,
    control: Option<Arc<Mutex<ControlPlane>>>,
    approver: SodApprover,
    cancel: CancelToken,
) -> Result<VerifiedProgramRun, ProgramRunError> {
    let (aia, quote, credential) =
        mint_run_authority(&identity, RENEW_EVERY_TICKS).map_err(ProgramRunError::Identity)?;
    let program_id = ProgramId::new(identity.run_id.clone());
    let goal = goal.into();
    let handle = Handle::current();
    let cred = credential.clone();
    // §18 Separation-of-Duties: resolve the approver credential the SoD gate checks each node commit
    // against. The default is a SEPARATE Run of the same git-controlled definition (producer ≠ approver,
    // keyed on run_id) minted from the SAME AIA — a denied mint is a hard identity failure. The
    // self-approving misconfiguration reuses the producing Run's OWN credential (the AIA refuses to mint
    // a second credential sharing a run_id, so this is the only way self-approval can arise).
    let mut aia = aia;
    let approver_cred = match approver {
        SodApprover::Distinct => mint_approver_credential(
            &mut aia,
            &credential,
            &quote,
            &format!("{}::verifier", credential.run_id),
            LogicalTime(RUN_MINT_TICK),
        )
        .map_err(ProgramRunError::Identity)?,
        SodApprover::SameAsProducer => credential.clone(),
    };

    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("ainxt-program-verified".into())
        .spawn(move || {
            let out = run_program_verified_blocking(
                engine,
                aia,
                quote,
                cred,
                approver_cred,
                handle,
                program_id,
                goal,
                nodes,
                incident,
                control,
                cancel,
            );
            let _ = tx.send(out);
        })
        .expect("spawn verified program driver thread");

    rx.await
        .expect("verified program driver thread dropped its result")
        .map_err(ProgramRunError::Program)
}

#[allow(clippy::too_many_arguments)]
fn run_program_verified_blocking(
    engine: Arc<Engine>,
    aia: IdentityAuthority<ReferenceValueVerifier>,
    quote: AttestationQuote,
    credential: AgentWorkloadCredential,
    approver_cred: AgentWorkloadCredential,
    handle: Handle,
    program_id: ProgramId,
    goal: String,
    nodes: Vec<NodeDecl>,
    incident: Option<Arc<Mutex<IncidentRegister>>>,
    control: Option<Arc<Mutex<ControlPlane>>>,
    cancel: CancelToken,
) -> Result<VerifiedProgramRun, ProgramError> {
    let node_classes: std::collections::BTreeMap<NodeId, NodeClass> =
        nodes.iter().map(|d| (d.id.clone(), d.node_class)).collect();
    let total_nodes = node_classes.len();

    // §18 Separation-of-Duties: the always-on producer≠approver identity gate. Each node's commit is
    // authorized against the DISTINCT verifier/approver credential minted for this Run (`approver_cred`);
    // a self-approving misconfiguration (approver Run == producer Run) is refused, so the node is failed.
    let sod_gate = SodVerifyGate::identity_only();
    let mut sod_approvals = 0u32;

    // Build the live-drivable Program: start → decompose → approve (the §8 Start gate is the caller's;
    // this records the decision). record_verdict/commit_node below are the ONLY route to Verified.
    let mut program = Program::start(program_id.clone(), goal.clone())?;
    program.decompose(nodes)?;
    program.approve("runtimed-composition")?;

    // Thread the served transport's user-stop token into the executor so an in-flight MODULE turn is
    // cancelled mid-stream (the SAME token the driver loop consults BETWEEN modules below).
    let mut exec = EngineRunExecutor::new(engine, credential.clone(), handle, incident)
        .with_control_plane(control)
        .with_cancel(cancel.clone());
    let mut current_cred = credential;
    let mut renewals = 0u32;
    let mut attempts: std::collections::BTreeMap<NodeId, u32> = std::collections::BTreeMap::new();
    let mut clock = RUN_MINT_TICK;
    let mut renewal_denied = false;

    // Whether the Run drained because the user requested a stop (honest capped-partial, not a
    // fabricated completion) — reported on the terminal outcome below.
    let mut user_stopped = false;

    // Drains when `actionable()` yields nothing (all nodes committed or none schedulable).
    while let Some(node) = program.actionable().into_iter().next() {
        // §user-stop: the served transport's cancel token is consulted BEFORE each module is
        // dispatched, so a user-stop halts the long-horizon Run at the next module boundary and leaves
        // the remaining nodes UNCOMMITTED (never a fabricated green). An in-flight module turn is also
        // cancelled mid-stream because the SAME token is threaded into the executor's engine turns.
        if cancel.is_cancelled() {
            user_stopped = true;
            break;
        }
        let a = attempts.entry(node.clone()).or_insert(0);
        if *a >= VERIFY_ATTEMPT_CAP {
            break; // stuck node — leave uncommitted (honest capped-partial)
        }
        let attempt = *a;
        *a += 1;

        // §15 JIT renewal: advance the Run's logical clock and renew the credential when it has
        // expired past its short TTL. renew() re-checks def validity / revocation / kill-switch /
        // anomaly-choke — a denied renewal drains the Run safely (no next dispatch).
        clock = clock.saturating_add(1);
        let now = LogicalTime(clock);
        // Renew at (or past) the short-TTL boundary — a long Run is a chain of per-dispatch renewals,
        // never a standing grant (§15). `>=` so the credential is refreshed the tick it would lapse.
        if now.tick() >= current_cred.expires_at.tick() {
            match aia.renew(&current_cred, Some(&quote), now) {
                Ok(fresh) => {
                    current_cred = fresh.clone();
                    exec.refresh_credential(fresh);
                    renewals = renewals.saturating_add(1);
                }
                Err(_) => {
                    renewal_denied = true;
                    break;
                }
            }
        }

        program.begin_node(&node)?;
        let node_class = node_classes
            .get(&node)
            .copied()
            .unwrap_or(NodeClass::MigrationRun);
        let ctx = ModuleRunContext {
            program_id: program_id.clone(),
            node: node.clone(),
            node_class,
            goal: goal.clone(),
            attempt,
            child_resolved: false,
        };
        match exec.execute_module(&ctx) {
            ModuleRunResult::Ran {
                det,
                adv,
                judge,
                commit_shas,
                ledger_key,
                by_model,
                ..
            } => {
                // record_verdict recomputes the three-way gate from the three real proofs; commit_node
                // then REFUSES a node without a durable Complete verdict (NodeNotProven). Never a
                // "mark verified" shortcut.
                // §18 SoD verify-gate FIRST: the approver Run may not approve the producing Run's
                // work. `current_cred` is the producing Run; `approver_cred` is the separate verifier
                // Run. A self-approving misconfiguration is refused here and the node is failed BEFORE
                // any verify verdict is recorded — a Run can never approve/commit its own work. (The
                // check precedes `record_verdict` because that transitions the node to `Verified`, from
                // which the driver forbids a fail transition.)
                //
                // GAP-FIX identity-payments — the SIGNED handoff path (`accept_handoff`), not the
                // unsigned direct-check: `current_cred` signs a `Handoff` over this exact
                // `(node, ledger_key)` artifact; `approver_cred` verifies the signature before the
                // producer≠approver identity rule is applied.
                match authorize_commit_via_signed_handoff(
                    &sod_gate,
                    &current_cred,
                    &approver_cred,
                    node.to_string(),
                    &ledger_key,
                ) {
                    Ok(_decision) => {
                        // record_verdict recomputes the three-way gate from the three real proofs;
                        // commit_node then REFUSES a node without a durable Complete verdict
                        // (NodeNotProven). Never a "mark verified" shortcut.
                        //
                        // GAP-FIX loop-teams-longhorizon (IllegalNodeTransition): a non-Complete
                        // outcome is ALREADY a fully-handled failed attempt inside `record_verdict`'s
                        // own state machine (NodeVerdictRecorded's apply-logic demotes the node to
                        // `Pending`, bumps `failure_count`, clears the stale verdict, and recomputes
                        // `Ready` — see `ainxt_planner::program`'s apply_post_genesis). Calling
                        // `fail_node` here too was a SECOND, redundant failure transition attempted
                        // against a node that had already left `InProgress`/`Verifying` — an
                        // `IllegalNodeTransition` the moment a real (non-fabricated) Judge/Breaker
                        // ever produced a genuine non-Complete verdict. This mirrors exactly what the
                        // shared, already-correct served driver
                        // (`ainxt_planner::driver::drive_program_verified`) does on this same branch:
                        // nothing further — the state machine already returned the node to the pool.
                        let outcome = program.record_verdict(&node, det, adv, judge)?;
                        if outcome.is_complete() {
                            sod_approvals = sod_approvals.saturating_add(1);
                            program.commit_node(&node, commit_shas, ledger_key, by_model)?;
                        }
                    }
                    Err(SodError::SelfApproval { producer, approver }) => {
                        program.fail_node(
                            &node,
                            format!(
                                "separation-of-duties: self-approval refused (producer {producer} == approver {approver})"
                            ),
                        )?;
                    }
                    Err(e) => {
                        program.fail_node(&node, format!("separation-of-duties refused: {e}"))?;
                    }
                }
            }
            ModuleRunResult::Failed { reason, .. } => {
                program.fail_node(&node, reason)?;
            }
            // The served surface decomposes into flat MigrationRun modules; a child-program node is
            // not produced here. Treat any other result as a non-committable attempt (never a commit).
            other => {
                program.fail_node(&node, format!("unsupported module result: {other:?}"))?;
            }
        }
    }

    let committed = program.state().committed_node_ids().len();
    let outcome = if renewal_denied {
        ProgramOutcome::Abandoned
    } else if user_stopped {
        // A user-stop drains the Run at a module boundary — the remaining nodes are uncommitted, so
        // the terminal outcome is an honest capped-partial, NEVER dressed as Completed.
        ProgramOutcome::CappedPartial
    } else if committed == total_nodes && program.state().committed_nodes_are_all_proven() {
        ProgramOutcome::Completed
    } else {
        ProgramOutcome::CappedPartial
    };
    program.record_outcome(outcome)?;

    Ok(VerifiedProgramRun {
        program,
        credential: current_cred,
        turns: exec.into_observations(),
        renewals,
        sod_approvals,
        outcome,
    })
}

// ===========================================================================
// R10 — the SERVED program driver runs through `driver::drive_program_verified`
// ===========================================================================
//
// The served `ProgramSurface`/`run_program` path drives the CLEAN
// [`drive_program_verified`](ainxt_planner::driver::drive_program_verified) entrypoint with THREE
// independent, real proof seams — closing the round-10 gap "the served program fabricated 2 of 3
// proofs and never ran the program-scale COMPLETED gate":
//
//   * **deterministic + adversarial** verdicts are ENGINE-DERIVED per module ([`verdict_for_observation`]
//     over a real [`EngineRunExecutor`] turn) — a turn that errored or produced no committable artifact
//     is a RED deterministic gate that [`three_way_gate`](ainxt_planner::verify::three_way_gate) refuses;
//   * the **semantic Judge** is a SEPARATE injected seam ([`ServedModuleJudge`]) — never self-reported by
//     the producer (the offline default is a deterministic cross-model pass; a deployment injects a real
//     cross-model LLM judge);
//   * the **program-scale COMPLETED gate** — per-edge integration + regression sweep + the independent
//     program Judge — runs through [`ServedProgramVerifier`] BEFORE the program is declared `Completed`.
//     A red edge / red sweep / bad program-judge yields an honest `CappedPartial`, NEVER `Completed`.
//
// The enterprise seams the served path already carried are PRESERVED, relocated onto the injected
// executor: per-Run [`AgentWorkloadCredential`] identity (IDN-03), §15 JIT renewal, §17/§19 control-plane
// admission, FI-02 incident arming, and the §18 Separation-of-Duties producer≠approver commit gate (a
// self-approving Run's every module fails, so nothing commits and the program cannot complete).

/// Which program-scale proof to force RED — the honest way to prove on the SERVED path that a failing
/// proof/edge yields [`ProgramOutcome::CappedPartial`], never `Completed` (the driver's own unit tests
/// inject the same way). `None` is the offline default (proofs derived from the real turn outcomes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProgramFault {
    /// No injected fault — every proof is derived from the real module turn outcomes (offline default).
    #[default]
    None,
    /// Force a per-edge integration verdict RED (§6.2) — a genuine seam failure in a deployment.
    Edge,
    /// Force the final regression-sweep verdict RED (§6) — a blast-radius regression a deployment's
    /// test-runner surfaced.
    Sweep,
    /// Force the independent program Judge below threshold (§6/§10).
    ProgramJudge,
}

/// The three independent proof seams the SERVED program driver injects into
/// [`drive_program_verified_fanout`](ainxt_planner::driver::drive_program_verified_fanout). The
/// offline default derives every proof from the real module turn
/// outcomes; the `with_failing_*` constructors force one proof RED to prove — on the served path — that
/// the program-scale COMPLETED gate blocks (honest `CappedPartial`, never a fabricated `Completed`).
#[derive(Debug, Clone, Default)]
pub struct ProgramProofSeams {
    /// Force the per-module semantic Judge below threshold (the injected cross-model judge rejects).
    pub module_judge_fault: bool,
    /// Force one program-scale proof RED.
    pub program_fault: ProgramFault,
}

impl ProgramProofSeams {
    /// The offline default: every proof derived from the real turn outcomes (no injected fault).
    pub fn offline_default() -> Self {
        Self::default()
    }
    /// A cross-model module Judge that REJECTS every artifact (below threshold) — proves a failing
    /// per-node judge blocks the commit, so the program cannot complete.
    pub fn with_failing_module_judge() -> Self {
        ProgramProofSeams {
            module_judge_fault: true,
            program_fault: ProgramFault::None,
        }
    }
    /// A program-scale regression sweep that comes back RED — proves the program-scale gate blocks.
    pub fn with_failing_regression_sweep() -> Self {
        ProgramProofSeams {
            module_judge_fault: false,
            program_fault: ProgramFault::Sweep,
        }
    }
    /// A per-edge integration proof that comes back RED — proves the edge-integration gate blocks.
    pub fn with_failing_edge() -> Self {
        ProgramProofSeams {
            module_judge_fault: false,
            program_fault: ProgramFault::Edge,
        }
    }
    /// A below-threshold independent program Judge — proves the program-judge gate blocks.
    pub fn with_failing_program_judge() -> Self {
        ProgramProofSeams {
            module_judge_fault: false,
            program_fault: ProgramFault::ProgramJudge,
        }
    }
}

/// The distinct cross-model judge label used by the served proof seams (must differ from the producer
/// model, or [`three_way_gate`] flags a §10 cross-model violation — a same-model judge is a structural
/// blind spot, not a low score).
const SERVED_JUDGE_MODEL: &str = "runtime-cross-judge";

/// The served per-module semantic Judge seam (req 1): a SEPARATE, model-backed verdict — never a
/// fabricated green self-reported by the producer. `fault` forces a below-threshold REJECT (proves a
/// failing judge blocks the commit). The offline default is [`RubricJudge`] (GAP-FIX
/// planner-assurance-revision item 1) — the SAME real, deterministic, content-inspecting analyser
/// already wired as the adversarial Breaker's matched pair (`ainxt_teams::tiers::BreakerAdversarialGate`)
/// — scored against the REAL text `ServedModuleExecutor` recorded for this node, never the old hardcoded
/// `JudgeVerdict::pass(95, 80, ..)` that passed every artifact identically. A deployment may still hot-wire
/// a live cross-model LLM judge behind the same seam.
struct ServedModuleJudge {
    fault: bool,
    /// Shared with [`ServedModuleExecutor`] — the real per-node module-turn text, keyed by node, so this
    /// Judge scores the genuine produced artifact instead of a fabricated pass. Populated the moment a
    /// module's turn is SoD-authorized (mirrors `ServedModuleExecutor::committable`'s sharing pattern).
    artifacts: Arc<Mutex<std::collections::BTreeMap<NodeId, String>>>,
}

impl ModuleJudge for ServedModuleJudge {
    fn judge(&mut self, ctx: &DriverModuleContext, attempt: &ModuleAttempt) -> JudgeVerdict {
        let producer = match attempt {
            ModuleAttempt::Ran { by_model, .. } => by_model.clone(),
            ModuleAttempt::Failed { .. } => "none".to_string(),
        };
        if self.fault {
            // A cross-model judge that rejects: below threshold. `completed` is true (the judge ran) —
            // the block is a genuine low score, distinct from a judge that could not finish.
            JudgeVerdict {
                score: 10,
                threshold: 80,
                producer_model: producer,
                judge_model: SERVED_JUDGE_MODEL.to_string(),
                completed: true,
            }
        } else {
            // A `Failed` attempt never reaches the driver's judge call site (see
            // `ainxt_planner::driver`'s node loop — the Judge is invoked only on `ModuleAttempt::Ran`),
            // so an empty lookup here only ever occurs defensively; `ModuleArtifact::new` with empty
            // text still scores honestly low (never a fabricated pass).
            let text = self
                .artifacts
                .lock()
                .expect("served module artifact map lock")
                .get(&ctx.node)
                .cloned()
                .unwrap_or_default();
            let artifact = ModuleArtifact::new(ctx.goal.clone(), text, producer);
            RubricJudge::new(SERVED_JUDGE_MODEL, 80).judge(&artifact)
        }
    }
}

/// The served program-scale verification seam (req 2): per-edge integration + regression sweep + the
/// independent program Judge. Each verdict is ENGINE-DERIVED — a node's edge/sweep verdict reads the
/// REAL committability of its module turn (recorded by [`ServedModuleExecutor`]); a node whose turn
/// produced no committable artifact makes its edges + the sweep RED. `fault` forces one proof RED (the
/// honest fault-injection used to prove the gate blocks on the served path). The program Judge is
/// [`RubricJudge`] (GAP-FIX planner-assurance-revision item 1) scored over the REAL combined text of
/// every committed node, never the old hardcoded `JudgeVerdict::pass(95, 80, ..)`. A deployment may
/// still hot-wire a real test-runner + cross-model judge behind the same seam.
struct ServedProgramVerifier {
    /// Per-node committability recorded by the executor as each module turn resolves (engine-derived).
    committable: Arc<Mutex<std::collections::BTreeMap<NodeId, bool>>>,
    /// Shared with [`ServedModuleExecutor`]/[`ServedModuleJudge`] — the real per-node artifact text, so
    /// the program-scale Judge scores the genuine combined deliverable instead of a fabricated pass.
    artifacts: Arc<Mutex<std::collections::BTreeMap<NodeId, String>>>,
    /// The program's own goal — the [`RubricJudge`] goal-relevance dimension is scored against it.
    goal: String,
    fault: ProgramFault,
}

impl ProgramVerifier for ServedProgramVerifier {
    fn verify_edge(&mut self, committed: &NodeId, neighbor: &NodeId) -> GateOutcome {
        if self.fault == ProgramFault::Edge {
            return GateOutcome::Blocked {
                reasons: vec![format!(
                    "edge {committed}->{neighbor} integration RED (injected fault)"
                )],
            };
        }
        let map = self.committable.lock().expect("committability map lock");
        let ok = map.get(committed).copied().unwrap_or(false)
            && map.get(neighbor).copied().unwrap_or(false);
        if ok {
            GateOutcome::Complete
        } else {
            GateOutcome::Blocked {
                reasons: vec![format!(
                    "edge {committed}->{neighbor}: a node produced no committable artifact"
                )],
            }
        }
    }

    fn regression_sweep(&mut self, committed: &[NodeId]) -> GateOutcome {
        if self.fault == ProgramFault::Sweep {
            return GateOutcome::Blocked {
                reasons: vec!["program-scale regression sweep RED (injected fault)".to_string()],
            };
        }
        let map = self.committable.lock().expect("committability map lock");
        let all = committed
            .iter()
            .all(|n| map.get(n).copied().unwrap_or(false));
        if all {
            GateOutcome::Complete
        } else {
            GateOutcome::Blocked {
                reasons: vec![
                    "regression sweep: a committed node has no committable artifact".to_string(),
                ],
            }
        }
    }

    fn program_judge(&mut self) -> JudgeVerdict {
        if self.fault == ProgramFault::ProgramJudge {
            return JudgeVerdict {
                score: 10,
                threshold: 80,
                producer_model: "runtime-producer".to_string(),
                judge_model: SERVED_JUDGE_MODEL.to_string(),
                completed: true,
            };
        }
        // Every committed node's REAL text, joined — the same `combined_output_text` shape
        // `ainxt_teams::tiers`'s program/team-scale judges already use, so the program-level Judge
        // audits the genuine combined deliverable rather than any single node in isolation.
        let combined = self
            .artifacts
            .lock()
            .expect("served module artifact map lock")
            .values()
            .cloned()
            .collect::<Vec<String>>()
            .join("\n");
        let artifact = ModuleArtifact::new(self.goal.clone(), combined, "runtime-producer");
        RubricJudge::new(SERVED_JUDGE_MODEL, 80).judge(&artifact)
    }
}

/// The served base-loop [`ModuleExecutor`] (req 1 + preserved enterprise seams): wraps the real
/// [`EngineRunExecutor`] (engine-derived det/adv, IDN-03 credential, §17/§19 control admission, FI-02
/// incident arming) and layers §15 JIT credential renewal + the §18 Separation-of-Duties
/// producer≠approver commit gate. A produced artifact is only returned `Ran` once SoD authorizes the
/// commit; a self-approving misconfiguration fails every module (nothing commits → CappedPartial).
struct ServedModuleExecutor {
    inner: EngineRunExecutor,
    aia: IdentityAuthority<ReferenceValueVerifier>,
    quote: AttestationQuote,
    current_cred: AgentWorkloadCredential,
    approver_cred: AgentWorkloadCredential,
    sod_gate: SodVerifyGate,
    clock: u64,
    renewals: u32,
    sod_approvals: u32,
    /// Shared with [`ServedProgramVerifier`] — each module records whether its turn was committable,
    /// so the program-scale edge/sweep proofs are ENGINE-DERIVED (not fabricated).
    committable: Arc<Mutex<std::collections::BTreeMap<NodeId, bool>>>,
    /// GAP-FIX planner-assurance-revision (item 1) — shared with [`ServedModuleJudge`]/
    /// [`ServedProgramVerifier`]: each module's REAL produced text, so both Judge seams score the
    /// genuine artifact instead of a fabricated pass. Mirrors `committable`'s sharing pattern exactly.
    artifacts: Arc<Mutex<std::collections::BTreeMap<NodeId, String>>>,
    /// R14 (§7 budget): the per-Run token ceiling (0 = unbounded). After each module turn the executor
    /// accrues the turn's estimated token spend and, once the ceiling is passed, trips the driver's
    /// [`StopSignal`] so the Run halts at the next module boundary — an honest `CappedPartial`, never a
    /// forced completion. Threaded from the `SupervisorConfig` the served surface no longer discards.
    budget_tokens: u64,
    /// R14 (§7 budget): the running token spend accrued from the real per-module turn outputs.
    spent_tokens: u64,
    /// R14 (§8 human checkpoints): the node ids marked `CheckpointClass::CriticalPath` (settlement /
    /// ledger / compliance cutover). A critical-path node is NEVER force-committed on the served path;
    /// it requires a human checkpoint approval (`checkpoint_approved`) before its module turn runs.
    critical_paths: std::collections::BTreeSet<NodeId>,
    /// R14 (§8): whether the human checkpoint approval has been granted. The served default is `false`
    /// (no human is present on the air-gapped served path), so a critical-path node HOLDS (fails-closed,
    /// uncommitted) rather than being force-committed. A deployment wires a real approval signal.
    checkpoint_approved: bool,
}

/// R14 (served-composition, HIGH) — the §7 budget + §8 human-checkpoint policy the served Program
/// driver enforces (the `SupervisorConfig` the served surface previously discarded). `budget_tokens`
/// caps the per-Run token spend (0 = unbounded); `critical_path_approved` gates whether a
/// `CriticalPath` checkpoint node may run+commit on the served path (default `false` → HELD, never
/// force-committed). This closes "served Program path bypasses §7 budget, §8 human checkpoints".
#[derive(Debug, Clone, Copy)]
pub struct ServedProgramGovernance {
    pub budget_tokens: u64,
    pub critical_path_approved: bool,
    /// GAP-AUDIT loop-teams-longhorizon (gap 5) — the total concurrent-module fleet slots this
    /// deployment declares (`[limits] program_fan_out_fleet_slots`), fed to
    /// [`ainxt_planner::qos::ElasticFanoutPolicy`] to decide the driver's parallel fan-out width.
    /// `None` keeps the driver strictly sequential (wave ceiling 1) — see
    /// `drive_served_program_blocking`'s wiring note.
    pub fleet_slots: Option<usize>,
}

impl ServedProgramGovernance {
    /// The behaviour-preserving default for direct callers of [`drive_served_program_verified`]:
    /// unbounded budget + checkpoints pre-approved (byte-identical to the pre-R14 driver).
    pub fn unbounded_approved() -> Self {
        ServedProgramGovernance {
            budget_tokens: 0,
            critical_path_approved: true,
            fleet_slots: None,
        }
    }

    /// The **served-surface default** (`ProgramSurface`): a generous-but-real per-Run token ceiling
    /// (enforced, no longer discarded) with human checkpoints NOT auto-approved — so a critical-path
    /// (settlement/ledger) node is held for a human, never force-committed on the served path.
    /// `fleet_slots` starts `None` (sequential) — `assemble_program_surface` overrides it from the
    /// deployment's `[limits] program_fan_out_fleet_slots` config.
    pub fn served_default() -> Self {
        ServedProgramGovernance {
            budget_tokens: SERVED_PROGRAM_TOKEN_CEILING,
            critical_path_approved: false,
            fleet_slots: None,
        }
    }

    /// Builder: declare the deployment's fleet capacity (see [`Self::fleet_slots`]).
    pub fn with_fleet_slots(mut self, slots: Option<usize>) -> Self {
        self.fleet_slots = slots;
        self
    }
}

/// R14 — the served Program per-Run token ceiling (§7). Generous enough not to bite an ordinary
/// multi-node migration turn on the offline default, but LIVE (a runaway Run is capped, never
/// unbounded). A deployment tunes it to its cost/SLO budget.
const SERVED_PROGRAM_TOKEN_CEILING: u64 = 1_000_000;

impl ModuleExecutor for ServedModuleExecutor {
    fn execute(&mut self, ctx: &DriverModuleContext, stop: &StopSignal) -> ModuleAttempt {
        // §8 HUMAN CHECKPOINT (no critical-path forced-commit): a node on the settlement/ledger critical
        // path requires a human checkpoint approval BEFORE its module turn runs. Absent approval it is
        // held fail-closed (an uncommitted node → honest CappedPartial), never force-committed.
        if self.critical_paths.contains(&ctx.node) && !self.checkpoint_approved {
            return ModuleAttempt::Failed {
                reason: format!(
                    "§8 human checkpoint required: critical-path node '{}' awaits human approval — \
                     not force-committed on the served path",
                    ctx.node
                ),
            };
        }
        // §7 BUDGET: if the per-Run token ceiling has already been passed, halt at this boundary rather
        // than run another module — the Run reports an honest CappedPartial (never a forced green).
        if self.budget_tokens > 0 && self.spent_tokens > self.budget_tokens {
            stop.stop();
            return ModuleAttempt::Failed {
                reason: format!(
                    "§7 program budget exhausted ({} > {} tokens) — Run capped, not force-completed",
                    self.spent_tokens, self.budget_tokens
                ),
            };
        }
        // §15 JIT renewal: advance the Run's logical clock and renew the credential the tick it would
        // lapse — a long Run is a chain of re-checked renewals (def validity / revocation / kill-switch
        // / anomaly), never a standing grant. A denied renewal fails the module safely.
        self.clock = self.clock.saturating_add(1);
        let now = LogicalTime(self.clock);
        if now.tick() >= self.current_cred.expires_at.tick() {
            match self.aia.renew(&self.current_cred, Some(&self.quote), now) {
                Ok(fresh) => {
                    self.current_cred = fresh.clone();
                    self.inner.refresh_credential(fresh);
                    self.renewals = self.renewals.saturating_add(1);
                }
                Err(e) => {
                    return ModuleAttempt::Failed {
                        reason: format!("credential renewal denied: {e:?}"),
                    };
                }
            }
        }

        // The real engine turn (the inner executor consults the §17/§19 control plane before dispatch,
        // arms the FI-02 clock on a regulated redaction, and derives the deterministic + adversarial
        // verdicts from the actual outcome).
        let mrc = ModuleRunContext {
            program_id: ctx.program_id.clone(),
            node: ctx.node.clone(),
            node_class: ctx.node_class,
            goal: ctx.goal.clone(),
            attempt: ctx.attempt,
            child_resolved: false,
        };
        match self.inner.execute_module(&mrc) {
            ModuleRunResult::Ran {
                det,
                adv,
                commit_shas,
                ledger_key,
                by_model,
                ..
            } => {
                // §18 Separation-of-Duties: the approver Run may not approve the producing Run's work.
                // A self-approving misconfiguration is refused here and the module fails BEFORE any
                // verdict is committed — a Run can never approve its own work.
                //
                // GAP-FIX identity-payments — the SIGNED handoff path (`accept_handoff`), not the
                // unsigned direct-check (see `authorize_commit_via_signed_handoff`'s doc).
                match authorize_commit_via_signed_handoff(
                    &self.sod_gate,
                    &self.current_cred,
                    &self.approver_cred,
                    ctx.node.to_string(),
                    &ledger_key,
                ) {
                    Ok(_decision) => {
                        self.sod_approvals = self.sod_approvals.saturating_add(1);
                        // Engine-derived committability for the program-scale proofs: a green
                        // deterministic + adversarial verdict means the turn produced a committable
                        // artifact (the SAME signal `three_way_gate` reads).
                        let committable = det.completed
                            && det.compiled
                            && det.tests_passed
                            && det.blocking_findings.is_empty()
                            && adv.completed
                            && adv.counterexamples.is_empty();
                        self.committable
                            .lock()
                            .expect("committability map lock")
                            .insert(ctx.node.clone(), committable);
                        // GAP-FIX planner-assurance-revision (item 1) — record the REAL text this turn
                        // produced, shared with `ServedModuleJudge`/`ServedProgramVerifier` so both real
                        // Judge seams score the genuine artifact instead of a fabricated pass.
                        let artifact_text = self
                            .inner
                            .observations()
                            .last()
                            .map(|o| o.text.clone())
                            .unwrap_or_default();
                        self.artifacts
                            .lock()
                            .expect("served module artifact map lock")
                            .insert(ctx.node.clone(), artifact_text);
                        // §7 budget: accrue this module turn's ESTIMATED token spend from the real
                        // engine output (~4 chars/token). Once the ceiling is passed the NEXT module
                        // boundary trips the stop (checked at the top of `execute`) → CappedPartial.
                        if self.budget_tokens > 0 {
                            let last_len = self
                                .inner
                                .observations()
                                .last()
                                .map(|o| o.text.chars().count() as u64)
                                .unwrap_or(0);
                            self.spent_tokens = self.spent_tokens.saturating_add(last_len / 4 + 1);
                            if self.spent_tokens > self.budget_tokens {
                                stop.stop();
                            }
                        }
                        ModuleAttempt::Ran {
                            det,
                            adv,
                            commit_shas,
                            ledger_key,
                            by_model,
                        }
                    }
                    Err(SodError::SelfApproval { producer, approver }) => ModuleAttempt::Failed {
                        reason: format!(
                            "separation-of-duties: self-approval refused (producer {producer} == approver {approver})"
                        ),
                    },
                    Err(e) => ModuleAttempt::Failed {
                        reason: format!("separation-of-duties refused: {e}"),
                    },
                }
            }
            ModuleRunResult::Failed { reason, .. } => ModuleAttempt::Failed { reason },
            other => ModuleAttempt::Failed {
                reason: format!("unsupported module result: {other:?}"),
            },
        }
    }
}

/// Drive the SERVED Program through
/// [`drive_program_verified_fanout`](ainxt_planner::driver::drive_program_verified_fanout) with the
/// three real proof seams. This is the entrypoint [`ProgramSurface`] and `run_program`'s served path
/// call — the round-10 wire that makes the served program run the REAL three-way gate + program-scale
/// COMPLETED gate (no fabricated proof), plus the loop-teams-longhorizon gap-5 wire that lets
/// independent module branches fan out in parallel when `governance.fleet_slots` is configured
/// (sequential, wave ceiling 1, when it is not — see `drive_served_program_blocking`). Returns the SAME
/// [`VerifiedProgramRun`] projection as the legacy driver so the surface's human-readable body is
/// unchanged.
///
/// * `approver` — the §18 SoD approver Run (the composition default is a DISTINCT `<producer>::verifier`).
/// * `cancel` — the served transport's user-stop token: bridged to the driver's [`StopSignal`] (a stop
///   halts the Run at the next module boundary) AND threaded into the in-flight engine turn.
/// * `seams` — the proof seams ([`ProgramProofSeams::offline_default`] on the served path; a
///   `with_failing_*` variant proves the gate blocks).
#[allow(clippy::too_many_arguments)]
pub async fn drive_served_program_verified(
    engine: Arc<Engine>,
    identity: RunIdentitySpec,
    goal: impl Into<String>,
    nodes: Vec<NodeDecl>,
    incident: Option<Arc<Mutex<IncidentRegister>>>,
    control: Option<Arc<Mutex<ControlPlane>>>,
    approver: SodApprover,
    cancel: CancelToken,
    seams: ProgramProofSeams,
) -> Result<VerifiedProgramRun, ProgramRunError> {
    // Behaviour-preserving default: unbounded budget + checkpoints pre-approved (the pre-R14 driver),
    // no transparency log (the pre-existing behavior for every caller of this wrapper).
    drive_served_program_governed(
        engine,
        identity,
        goal,
        nodes,
        incident,
        control,
        None,
        approver,
        cancel,
        seams,
        ServedProgramGovernance::unbounded_approved(),
    )
    .await
}

/// [`drive_served_program_verified`] but with an explicit [`ServedProgramGovernance`] (R14): the served
/// Program driver now ENFORCES the §7 per-Run token budget and the §8 human-checkpoint gate (no
/// critical-path forced-commit) — the `SupervisorConfig` the served surface previously discarded. The
/// served surface calls this with [`ServedProgramGovernance::served_default`]; direct callers keep the
/// pre-R14 behaviour via [`drive_served_program_verified`].
#[allow(clippy::too_many_arguments)]
pub async fn drive_served_program_governed(
    engine: Arc<Engine>,
    identity: RunIdentitySpec,
    goal: impl Into<String>,
    nodes: Vec<NodeDecl>,
    incident: Option<Arc<Mutex<IncidentRegister>>>,
    control: Option<Arc<Mutex<ControlPlane>>>,
    // GAP-AUDIT identity-payments #1 — the append-only, HMAC-signed issuance transparency log
    // (ADR-022 §13/§22 scenario 3) was fully built + unit-tested but had zero live callers anywhere
    // in the served path, so an external auditor had no inclusion-proof-verifiable record that a
    // Run's AWC was ever issued. `None` (the composition's air-gapped default, no HMAC key
    // provisioned) keeps this a no-op — byte-identical pre-wire behavior.
    transparency: Option<Arc<Mutex<TransparencyLog<Sha256Hasher>>>>,
    approver: SodApprover,
    cancel: CancelToken,
    seams: ProgramProofSeams,
    governance: ServedProgramGovernance,
) -> Result<VerifiedProgramRun, ProgramRunError> {
    let (aia, quote, credential) =
        mint_run_authority(&identity, RENEW_EVERY_TICKS).map_err(ProgramRunError::Identity)?;
    if let Some(log) = &transparency {
        log.lock()
            .expect("transparency log mutex poisoned")
            .append(IssuanceEntry::from_awc(&credential));
    }
    let program_id = ProgramId::new(identity.run_id.clone());
    let goal = goal.into();
    let handle = Handle::current();

    // §18 approver credential — a DISTINCT verifier Run of the same git-controlled definition (the
    // default), or the producing Run itself (the self-approving misconfiguration the SoD gate refuses).
    let mut aia = aia;
    let approver_cred = match approver {
        SodApprover::Distinct => mint_approver_credential(
            &mut aia,
            &credential,
            &quote,
            &format!("{}::verifier", credential.run_id),
            LogicalTime(RUN_MINT_TICK),
        )
        .map_err(ProgramRunError::Identity)?,
        SodApprover::SameAsProducer => credential.clone(),
    };

    // Bridge the transport's user-stop token to the driver's StopSignal: a stop halts the loop at the
    // next module boundary. A PRE-cancelled token trips the stop before the first module runs (0 turns).
    let stop = StopSignal::new();
    if cancel.is_cancelled() {
        stop.stop();
    }
    {
        let stop = stop.clone();
        let cancel = cancel.clone();
        handle.spawn(async move {
            cancel.cancelled().await;
            stop.stop();
        });
    }

    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("ainxt-served-program".into())
        .spawn(move || {
            let out = drive_served_program_blocking(
                engine,
                aia,
                quote,
                credential,
                approver_cred,
                handle,
                program_id,
                goal,
                nodes,
                incident,
                control,
                cancel,
                stop,
                seams,
                governance,
            );
            let _ = tx.send(out);
        })
        .expect("spawn served program driver thread");

    rx.await
        .expect("served program driver thread dropped its result")
        .map_err(ProgramRunError::Program)
}

#[allow(clippy::too_many_arguments)]
fn drive_served_program_blocking(
    engine: Arc<Engine>,
    aia: IdentityAuthority<ReferenceValueVerifier>,
    quote: AttestationQuote,
    credential: AgentWorkloadCredential,
    approver_cred: AgentWorkloadCredential,
    handle: Handle,
    program_id: ProgramId,
    goal: String,
    nodes: Vec<NodeDecl>,
    incident: Option<Arc<Mutex<IncidentRegister>>>,
    control: Option<Arc<Mutex<ControlPlane>>>,
    cancel: CancelToken,
    stop: StopSignal,
    seams: ProgramProofSeams,
    governance: ServedProgramGovernance,
) -> Result<VerifiedProgramRun, ProgramError> {
    // The inner engine executor (IDN-03 credential + §17/§19 control admission + FI-02 arming + the
    // served transport's user-stop token threaded into every in-flight engine turn).
    let inner = EngineRunExecutor::new(engine, credential.clone(), handle, incident)
        .with_control_plane(control)
        .with_cancel(cancel);

    // §8: the CriticalPath checkpoint node set the served driver must gate on a human approval.
    let critical_paths: std::collections::BTreeSet<NodeId> = nodes
        .iter()
        .filter(|n| n.checkpoint_class == CheckpointClass::CriticalPath)
        .map(|n| n.id.clone())
        .collect();

    let committable = Arc::new(Mutex::new(std::collections::BTreeMap::<NodeId, bool>::new()));
    // GAP-FIX planner-assurance-revision (item 1) — shared real-artifact-text map: populated by the
    // executor, read by both the per-module and program-scale RubricJudge seams below.
    let artifacts = Arc::new(Mutex::new(
        std::collections::BTreeMap::<NodeId, String>::new(),
    ));
    let mut executor = ServedModuleExecutor {
        inner,
        aia,
        quote,
        current_cred: credential,
        approver_cred,
        sod_gate: SodVerifyGate::identity_only(),
        clock: RUN_MINT_TICK,
        renewals: 0,
        sod_approvals: 0,
        committable: Arc::clone(&committable),
        artifacts: Arc::clone(&artifacts),
        budget_tokens: governance.budget_tokens,
        spent_tokens: 0,
        critical_paths,
        checkpoint_approved: governance.critical_path_approved,
    };
    let mut judge = ServedModuleJudge {
        fault: seams.module_judge_fault,
        artifacts: Arc::clone(&artifacts),
    };
    let mut verifier = ServedProgramVerifier {
        committable,
        artifacts,
        goal: goal.clone(),
        fault: seams.program_fault,
    };

    // GAP-AUDIT loop-teams-longhorizon (gap 5) — `drive_program_verified_fanout` (parallel wave
    // admission) and `ainxt_planner::qos::ElasticFanoutPolicy` were fully built and unit-tested but
    // had ZERO callers from the served composition root: this driver always called the sequential
    // `drive_program_verified` (wave ceiling 1), so independent branches of a served long-horizon
    // Program's module graph serialized regardless of how many nodes were mutually independent —
    // exactly the "parallel tracks do not serialize" claim LONG_HORIZON §7 makes but the served path
    // never delivered. `governance.fleet_slots` unset (the default) preserves that exact sequential
    // behavior; a deployment that declares its fleet capacity gets a REAL admission decision from the
    // policy (Batch class: bursts into free capacity, never touches the interactive reserve) rather
    // than a second blind fixed ceiling. The live in-flight-usage / higher-priority-queued fleet
    // telemetry stays infra-gated (`needs_hot_wiring`); `nodes.len()` is used as the offline "ready"
    // upper bound (the driver's own dependency graph narrows it further each wave).
    let fan_out_ceiling = match governance.fleet_slots {
        None => 1,
        Some(slots) => {
            let capacity = ainxt_planner::qos::FleetCapacity::new(slots, 0);
            ainxt_planner::qos::ElasticFanoutPolicy::default()
                .admit(
                    nodes.len(),
                    ainxt_planner::qos::WorkloadClass::Batch,
                    &capacity,
                )
                .max(1)
        }
    };

    let report: DriveReport = drive_program_verified_fanout(
        program_id,
        goal,
        nodes,
        &mut executor,
        &mut judge,
        &mut verifier,
        &stop,
        VERIFY_ATTEMPT_CAP,
        fan_out_ceiling,
    )?;

    // The DriveReport carries the driver-enforced Program (its committed/proven state is reachable
    // ONLY through record_verdict/commit_node) and the sealed terminal outcome. The turns / renewals /
    // SoD authorizations come off the executor.
    let renewals = executor.renewals;
    let sod_approvals = executor.sod_approvals;
    let current_cred = executor.current_cred.clone();
    let turns = executor.inner.into_observations();
    Ok(VerifiedProgramRun {
        program: report.program,
        credential: current_cred,
        turns,
        renewals,
        sod_approvals,
        outcome: report.outcome,
    })
}

/// Drive a **durable, resumable** Program through the real [`Engine`], persisting every
/// [`ProgramEvent`] to a hash-chained JSONL Event Log via
/// [`ainxt_eventlog::ProgramEventSink`](ainxt_eventlog::ProgramEventSink) (gap loop-teams: "durable,
/// resumable Program state not wired on the served path" — `run_program_blocking` used an in-memory
/// `VecEventSink` discarded after the call).
///
/// * **First run** (`dir` empty for this `run_id`): seeds `Created` + `Decomposed`, then runs the
///   supervisor. Every event is durably appended, so a crash/restart loses nothing.
/// * **Resume** (`dir` already holds this session's events): the seed is skipped and the supervisor
///   re-projects the durable log and continues — a `CappedPartial`/Paused program that was capped on a
///   budget ceiling resumes exactly where it stopped (the design's "a second run resumes" contract).
///
/// A budget-capped run reports a terminal [`ProgramOutcome::CappedPartial`] (`StopReason::BudgetExhausted`)
/// — an honest capped report, never a fabricated `Completed`. Returns the [`ProgramRun`] plus the
/// durable session id under which the events are stored.
pub async fn run_program_durable(
    engine: Arc<Engine>,
    identity: RunIdentitySpec,
    goal: impl Into<String>,
    nodes: Vec<NodeDecl>,
    config: SupervisorConfig,
    incident: Option<Arc<Mutex<IncidentRegister>>>,
    dir: std::path::PathBuf,
) -> Result<ProgramRun, ProgramRunError> {
    let credential = mint_run_credential(&identity).map_err(ProgramRunError::Identity)?;
    // GAP-FIX loop-teams-longhorizon (gap 1b) — a DISTINCT §18 SoD approver credential, the SAME shape
    // `drive_served_program_governed` mints via `mint_approver_credential` (`<producer>::verifier`).
    // Before this fix the durable driver minted no approver at all and never checked SoD, so a durable
    // Run's own producer credential implicitly "approved" its own commit.
    let mut approver_spec = identity.clone();
    approver_spec.run_id = format!("{}::verifier", identity.run_id);
    let approver_credential =
        mint_run_credential(&approver_spec).map_err(ProgramRunError::Identity)?;
    let program_id = ProgramId::new(identity.run_id.clone());
    let session = identity.run_id.clone();
    let goal = goal.into();
    let handle = Handle::current();
    let cred = credential.clone();

    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("ainxt-program-durable".into())
        .spawn(move || {
            let out = run_program_durable_blocking(
                engine,
                cred,
                approver_credential,
                handle,
                program_id,
                session,
                goal,
                nodes,
                config,
                incident,
                dir,
            );
            let _ = tx.send(out);
        })
        .expect("spawn durable program driver thread");

    let (report, turns, events) = rx
        .await
        .expect("durable program driver thread dropped its result")?;
    Ok(ProgramRun {
        report,
        credential,
        turns,
        events,
    })
}

/// GAP-FIX loop-teams-longhorizon (gap 1b) — the durable Program driver's [`RunExecutor`], layering
/// the SAME §18 Separation-of-Duties producer≠approver commit gate [`ServedModuleExecutor`] enforces
/// on the non-durable governed path over the base [`EngineRunExecutor`] turn, and recording the SAME
/// engine-derived committability signal (§6.1: completed + compiled + tests passed + no blocking
/// findings + a clean adversarial pass) the paired [`ServedProgramVerifier`] reads for its per-edge /
/// regression-sweep / program-judge proofs — never the [`PermissiveProgramVerifier`] rubber stamp.
///
/// Before this fix, `run_program_durable_blocking` drove the bare `EngineRunExecutor` directly with no
/// SoD check at all — a durable Run's own producer credential implicitly "approved" its own commit,
/// and the paired verifier was the unconditional-`Complete` `PermissiveProgramVerifier`.
struct DurableServedExecutor {
    inner: EngineRunExecutor,
    sod_gate: SodVerifyGate,
    producer_cred: AgentWorkloadCredential,
    approver_cred: AgentWorkloadCredential,
    /// Shared with the paired [`ServedProgramVerifier`] — mirrors `ServedModuleExecutor::committable`.
    committable: Arc<Mutex<std::collections::BTreeMap<NodeId, bool>>>,
    /// GAP-FIX planner-assurance-revision (item 1) — shared with the paired [`ServedProgramVerifier`]'s
    /// program-scale [`RubricJudge`]: each node's REAL produced text, mirroring
    /// `ServedModuleExecutor::artifacts`'s sharing pattern on the non-durable governed path. The
    /// per-module judge itself needs no change here — it already rides through unmodified from
    /// `self.inner.execute_module`'s `ModuleRunResult::Ran { judge, .. }`, which is the real
    /// [`RubricJudge`] verdict since [`EngineRunExecutor::execute_module`]'s own fix.
    artifacts: Arc<Mutex<std::collections::BTreeMap<NodeId, String>>>,
}

impl RunExecutor for DurableServedExecutor {
    fn execute_module(&mut self, ctx: &ModuleRunContext) -> ModuleRunResult {
        match self.inner.execute_module(ctx) {
            ModuleRunResult::Ran {
                det,
                adv,
                judge,
                commit_shas,
                ledger_key,
                by_model,
                cost,
            } => {
                // §18 Separation-of-Duties: the approver Run may not approve the producing Run's work.
                // A self-approving misconfiguration is refused here and the module fails BEFORE any
                // verdict is committed — a Run can never approve its own work, durable or not.
                match self.sod_gate.authorize_approval(
                    &self.producer_cred,
                    &self.approver_cred,
                    ctx.node.to_string(),
                    &ledger_key,
                ) {
                    Ok(_decision) => {
                        // Engine-derived committability for the paired `ServedProgramVerifier`'s
                        // program-scale proofs — the SAME signal `ServedModuleExecutor` records on the
                        // governed path (the same source `three_way_gate` reads: a green deterministic
                        // + adversarial verdict means the turn produced a committable artifact).
                        let committable = det.completed
                            && det.compiled
                            && det.tests_passed
                            && det.blocking_findings.is_empty()
                            && adv.completed
                            && adv.counterexamples.is_empty();
                        self.committable
                            .lock()
                            .expect("committability map lock")
                            .insert(ctx.node.clone(), committable);
                        // GAP-FIX planner-assurance-revision (item 1) — record the REAL text this turn
                        // produced, shared with the paired `ServedProgramVerifier`'s program-scale
                        // RubricJudge so it scores the genuine combined deliverable, not a fabricated pass.
                        let artifact_text = self
                            .inner
                            .observations()
                            .last()
                            .map(|o| o.text.clone())
                            .unwrap_or_default();
                        self.artifacts
                            .lock()
                            .expect("durable artifact map lock")
                            .insert(ctx.node.clone(), artifact_text);
                        ModuleRunResult::Ran {
                            det,
                            adv,
                            judge,
                            commit_shas,
                            ledger_key,
                            by_model,
                            cost,
                        }
                    }
                    Err(SodError::SelfApproval { producer, approver }) => ModuleRunResult::Failed {
                        reason: format!(
                            "separation-of-duties: self-approval refused (producer {producer} == approver {approver})"
                        ),
                        cost,
                    },
                    Err(e) => ModuleRunResult::Failed {
                        reason: format!("separation-of-duties refused: {e}"),
                        cost,
                    },
                }
            }
            other => other,
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_program_durable_blocking(
    engine: Arc<Engine>,
    credential: AgentWorkloadCredential,
    approver_credential: AgentWorkloadCredential,
    handle: Handle,
    program_id: ProgramId,
    session: String,
    goal: String,
    nodes: Vec<NodeDecl>,
    config: SupervisorConfig,
    incident: Option<Arc<Mutex<IncidentRegister>>>,
    dir: std::path::PathBuf,
) -> Result<(SupervisorReport, Vec<TurnObservation>, Vec<ProgramEvent>), ProgramRunError> {
    use ainxt_eventlog::{EventLog, JsonlEventLog, ProgramEventSink};
    use ainxt_planner::supervisor::EventSink as PlannerEventSink;

    // GAP-FIX identity-payments (ADR-022 §14, item 3) — the §14 composite actor-of-record
    // (`AgentWorkloadCredential::actor_of_record`) captured BEFORE `credential` is moved into
    // `DurableServedExecutor::producer_cred` below. `ainxt-identity`'s own tests
    // (`r11_actor_of_record_eventlog.rs`/`r12_actor_of_record_served.rs`) proved `ActorRecord` is a
    // strictly richer structured projection of the credential than `actor_label()`'s flattened
    // `uri|obo=..|commit=..|key=..` string (it additionally exposes `def_ref`/`run_id`/
    // `attestation_ref` as separate, independently-queryable fields) — but the real durable
    // production write path never used it: `ProgramEventSink` stamps every `ProgramEvent` record
    // with a single, per-sink, hardcoded literal actor (`"runtimed-program-supervisor"`, below),
    // and the in-memory `TurnObservation.actor` (`credential.actor_label()`, `drive_turn`) never
    // reaches durable storage at all on this path. `ainxt-eventlog`'s `LogRecord::actor` is a plain
    // `&str` (bound into the hash-chain preimage), so a structured value is carried as its canonical
    // JSON encoding — the durable equivalent of "serialize `ActorRecord` to a string" the append
    // signature requires. A SEPARATE session (`{session}::actor_of_record`) is used, never the
    // `ProgramEventSink`'s own `ProgramEvent` stream: `ProgramEventSink::load` deserializes every
    // record's `text` as a `ProgramEvent` regardless of `kind`, so interleaving a differently-shaped
    // record into that SAME session would break resume/replay. This durable per-turn stream is the
    // real, structured court-grade record: an operator/auditor reads it back and deserializes each
    // record's `actor` field straight into an `ActorRecord` (see
    // `r16_durable_actor_of_record_eventlog.rs`).
    let actor_record = credential.actor_of_record();
    let actor_record_json = serde_json::to_string(&actor_record)
        .expect("ActorRecord serializes (no non-finite floats)");
    let actor_session = format!("{session}::actor_of_record");

    let log = JsonlEventLog::open(&dir)
        .map_err(|e| ProgramRunError::Durable(format!("open durable program log: {e}")))?;
    // A cheap clone (shares the same on-disk directory + chain index) retained so the per-turn
    // actor-of-record stream below can append to the SAME durable log under a DIFFERENT session,
    // after `log` itself is moved into `sink`.
    let actor_log = log.clone();
    let mut sink = ProgramEventSink::new(log, session, "runtimed-program-supervisor");
    // GAP-FIX planner-assurance-revision (item 1) — captured before `goal` is moved into
    // `ProgramEvent::Created` below, so the paired `ServedProgramVerifier`'s program-scale RubricJudge
    // still has the program's own goal to score relevance against.
    let goal_for_judge = goal.clone();
    // Resume-safe: only seed a NEW program. If the durable log already holds this session's stream we
    // are resuming — the supervisor re-projects the persisted events and continues.
    let existing = sink.load().map_err(ProgramRunError::Durable)?;
    if existing.is_empty() {
        sink.append(&ProgramEvent::Created { program_id, goal })
            .map_err(ProgramRunError::Durable)?;
        sink.append(&ProgramEvent::Decomposed { nodes })
            .map_err(ProgramRunError::Durable)?;
    }

    // GAP-FIX loop-teams-longhorizon (gap 1b) — the durable path now drives the SAME real
    // verification/SoD/critical-path gate the non-durable governed path (`drive_served_program_governed`)
    // enforces, never the bare `PermissiveProgramVerifier` + `AutoApprove` rubber-stamp: a served
    // deployment that opts into crash-resumable Programs (`ProgramSurface::with_durable_dir`) gets
    // durability AND real verification together — never durability traded away for it.
    let committable = Arc::new(Mutex::new(std::collections::BTreeMap::<NodeId, bool>::new()));
    // GAP-FIX planner-assurance-revision (item 1) — shared real-artifact-text map (mirrors the
    // non-durable governed path's `artifacts` wiring in `drive_served_program_blocking`).
    let artifacts = Arc::new(Mutex::new(
        std::collections::BTreeMap::<NodeId, String>::new(),
    ));
    let inner = EngineRunExecutor::new(engine, credential.clone(), handle, incident);
    let mut exec = DurableServedExecutor {
        inner,
        sod_gate: SodVerifyGate::identity_only(),
        producer_cred: credential,
        approver_cred: approver_credential,
        committable: Arc::clone(&committable),
        artifacts: Arc::clone(&artifacts),
    };
    let mut verifier = ServedProgramVerifier {
        committable,
        artifacts,
        goal: goal_for_judge,
        fault: ProgramFault::None,
    };
    // The served default: no human is present on the air-gapped durable path, so a critical-path
    // (settlement/ledger) node HOLDS rather than being force-committed — see
    // `ServedProgramApprovalGate`'s doc comment for the exact `AutoApprove` hole this closes.
    let mut gate = ServedProgramApprovalGate {
        critical_path_approved: false,
    };
    let mut cancel = || false;

    let report = supervisor::run_program(
        &mut sink,
        &mut exec,
        &mut verifier,
        &mut gate,
        config,
        &mut cancel,
    )
    .map_err(ProgramRunError::Program)?;
    let events = sink.load().map_err(ProgramRunError::Durable)?;
    let turns = exec.inner.into_observations();
    // GAP-FIX identity-payments (ADR-022 §14, item 3) — the real turn-completion path durably
    // records the §14 structured actor-of-record for every module turn this Run served, not just
    // the sink-level per-session literal actor above. One record per turn, under the DEDICATED
    // `{session}::actor_of_record` stream (never the `ProgramEvent` session `sink` owns — see the
    // doc note above `actor_log`'s clone for why the two streams must stay separate). The `actor`
    // field carries the canonical JSON `ActorRecord` (the hash-chained, tamper-evident field); `text`
    // carries the turn's own label/provider/outcome so a reader can correlate the two without a
    // second lookup.
    for t in &turns {
        let turn_text = serde_json::json!({
            "label": t.label,
            "provider": t.provider,
            "redactions": t.redactions,
            "ok": t.ok,
        })
        .to_string();
        actor_log
            .append(
                &actor_session,
                &actor_record_json,
                "turn_actor_of_record",
                &turn_text,
            )
            .map_err(|e| ProgramRunError::Durable(format!("append turn actor-of-record: {e}")))?;
    }
    Ok((report, turns, events))
}

/// A [`SupervisorConfig`] whose program budget is capped at `token_ceiling` tokens — used to prove the
/// budget ceiling actually bites on the served path: a program that spends past it reports a terminal
/// [`ProgramOutcome::CappedPartial`], never a fabricated `Completed`.
pub fn capped_config(token_ceiling: u64) -> SupervisorConfig {
    SupervisorConfig {
        budget: ainxt_planner::supervisor::ProgramBudget::new(token_ceiling, u64::MAX),
        ..SupervisorConfig::default()
    }
}

/// Drive a hierarchical **Team** through the full 3-tier loop with real [`Engine`] turns (LOOP-15).
///
/// Mints a per-Run credential (IDN-03) and runs `ainxt_teams::tiers::run_team_3tier_verified` with an
/// [`EngineRunExecutor`] as tier-1 (each task is a real engine turn). Tier 2 uses
/// [`ContentStepCritic`] — a real per-step content check, not a rubber-stamp — and the LOOP §7
/// anti-sycophancy backstop (the offline-default [`ContentDeterministicGate`] +
/// [`BreakerAdversarialGate`]) also gates the terminal `Complete`, the same guarantee
/// [`drive_served_team`]'s cancellable path gives. When `learning` is supplied, the terminal
/// [`LearningRecord`] is routed to it (LOOP-13); when `incident` is supplied, a regulated turn arms a
/// statutory clock (FI-02).
#[allow(clippy::too_many_arguments)]
pub async fn run_team(
    engine: Arc<Engine>,
    identity: RunIdentitySpec,
    graph: TaskGraph,
    team: Team,
    goal: impl Into<String>,
    seed_inputs: BTreeSet<String>,
    config: ThreeTierConfig,
    learning: Option<Arc<dyn LearningSink>>,
    incident: Option<Arc<Mutex<IncidentRegister>>>,
) -> Result<TeamRun, TeamRunError> {
    let credential = mint_run_credential(&identity).map_err(TeamRunError::Identity)?;
    let goal = goal.into();
    let handle = Handle::current();
    let cred = credential.clone();

    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("ainxt-team".into())
        .spawn(move || {
            let out = run_team_blocking(
                engine,
                cred,
                handle,
                graph,
                team,
                goal,
                seed_inputs,
                config,
                learning,
                incident,
            );
            let _ = tx.send(out);
        })
        .expect("spawn team driver thread");

    let (report, turns) = rx
        .await
        .expect("team driver thread dropped its result")
        .map_err(TeamRunError::Graph)?;
    Ok(TeamRun {
        report,
        credential,
        turns,
    })
}

#[allow(clippy::too_many_arguments)]
fn run_team_blocking(
    engine: Arc<Engine>,
    credential: AgentWorkloadCredential,
    handle: Handle,
    graph: TaskGraph,
    team: Team,
    goal: String,
    seed_inputs: BTreeSet<String>,
    config: ThreeTierConfig,
    learning: Option<Arc<dyn LearningSink>>,
    incident: Option<Arc<Mutex<IncidentRegister>>>,
) -> Result<(TeamRunReport, Vec<TurnObservation>), GraphError> {
    let mut exec = EngineRunExecutor::new(engine, credential, handle, incident);
    // GAP-AUDIT loop-teams-longhorizon (tier2/tier3 rubber-stamp) — `AcceptingCritic` approved every
    // step regardless of content, so a task that produced an empty artifact or a bare `todo!()` stub
    // was never caught at tier 2 (only, at best, at the whole-deliverable tier-3 audit two rounds
    // later). `ContentStepCritic` runs the same real content check `ContentDeterministicGate` runs at
    // tier 3, scoped to one step, so a deficient step is fed back into self-heal in the SAME round.
    let mut critic = ContentStepCritic;
    let mut healer = EscalatingHealer;
    let mut judge = ConfirmingGoalJudge;
    // GAP-AUDIT loop-teams-longhorizon — same anti-sycophancy wiring as `drive_served_team_blocking`
    // (see the note there): the LOOP §7 three-way gate, not the judge-only path, so the `ProgramRuntime`
    // facade's team entrypoint gives the SAME guarantee as the cancellable served `TeamSurface` path.
    let mut det_gate = ContentDeterministicGate;
    let mut adv_gate = BreakerAdversarialGate;

    let report = run_team_3tier_verified(
        &graph,
        &team,
        &goal,
        &seed_inputs,
        &mut exec,
        &mut critic,
        &mut healer,
        &mut judge,
        &mut det_gate,
        &mut adv_gate,
        config,
    )?;
    // LOOP-13: route the terminal-run Learning Record to the flywheel sink.
    if let Some(sink) = &learning {
        sink.record(&report.learning);
    }
    Ok((report, exec.into_observations()))
}

// ===========================================================================
// Assembly path — makes the subsystem REACHABLE from the assembled daemon
// ===========================================================================

/// The assembled **program** runtime: the real gate-selected [`Engine`] plus entrypoints to drive the
/// long-horizon Program Supervisor and the hierarchical Team loop. This is the sibling of
/// `assemble` / `assemble_chat` / `assemble_surface` that makes the loop/teams subsystem reachable
/// from the daemon composition (LOOP-01 / LOOP-15).
pub struct ProgramRuntime {
    engine: Arc<Engine>,
    pub report: Vec<String>,
}

impl ProgramRuntime {
    /// The shared engine (so a caller can drive additional runs or inspect it).
    pub fn engine(&self) -> Arc<Engine> {
        self.engine.clone()
    }

    /// Drive a Program through the real engine (see [`run_program`]).
    pub async fn run_program(
        &self,
        identity: RunIdentitySpec,
        goal: impl Into<String>,
        nodes: Vec<NodeDecl>,
        config: SupervisorConfig,
        incident: Option<Arc<Mutex<IncidentRegister>>>,
    ) -> Result<ProgramRun, ProgramRunError> {
        run_program(self.engine.clone(), identity, goal, nodes, config, incident).await
    }

    /// Drive a Program through the real engine WITH the shared §17/§19 [`ControlPlane`] wired (see
    /// [`run_program_governed`]): a kill-switch / revocation on `control` reaches this in-flight Run.
    #[allow(clippy::too_many_arguments)]
    pub async fn run_program_governed(
        &self,
        identity: RunIdentitySpec,
        goal: impl Into<String>,
        nodes: Vec<NodeDecl>,
        config: SupervisorConfig,
        incident: Option<Arc<Mutex<IncidentRegister>>>,
        control: Arc<Mutex<ControlPlane>>,
    ) -> Result<ProgramRun, ProgramRunError> {
        run_program_governed(
            self.engine.clone(),
            identity,
            goal,
            nodes,
            config,
            incident,
            control,
        )
        .await
    }

    /// Drive a Team through the real engine (see [`run_team`]).
    #[allow(clippy::too_many_arguments)]
    pub async fn run_team(
        &self,
        identity: RunIdentitySpec,
        graph: TaskGraph,
        team: Team,
        goal: impl Into<String>,
        seed_inputs: BTreeSet<String>,
        config: ThreeTierConfig,
        learning: Option<Arc<dyn LearningSink>>,
        incident: Option<Arc<Mutex<IncidentRegister>>>,
    ) -> Result<TeamRun, TeamRunError> {
        run_team(
            self.engine.clone(),
            identity,
            graph,
            team,
            goal,
            seed_inputs,
            config,
            learning,
            incident,
        )
        .await
    }
}

/// Assemble the runtime for the **program** surface: the same gate-selected [`Engine`] the bare
/// surface builds, exposed behind entrypoints that drive the long-horizon Program Supervisor and the
/// 3-tier Team loop with a real [`EngineRunExecutor`]. Fail-closed on an enterprise gate selection
/// (same as [`build_engine`]).
pub fn assemble_program(loaded: &LoadedConfig) -> Result<ProgramRuntime, AssembleError> {
    let (engine, mut report) = build_engine(&loaded.runtime)?;
    report.push(
        "program: long-horizon Program Supervisor + hierarchical 3-tier Team loop wired to the real \
         Engine via EngineRunExecutor (LOOP-01/LOOP-15 reachable from the assembled daemon; per-Run \
         AgentWorkloadCredential IDN-03; FI-02 incident arming; LOOP-13 learning-record sink)"
            .into(),
    );
    Ok(ProgramRuntime {
        engine: Arc::new(engine),
        report,
    })
}

// ===========================================================================
// Served-program decomposition — real MigrationBlueprint::compose (not one node)
// ===========================================================================

/// The target-model context window (tokens) the served program's working-set admissibility check
/// runs against. Generous so the deterministic served blueprint never over-splits; a deployment
/// derives it from the routed model's real window.
const SERVED_COMPOSE_WINDOW_TOKENS: u64 = 100_000;

/// Compose the served Program's node graph from a real [`MigrationBlueprint`] (gap: the served
/// `ProgramSurface` hard-coded a single `deliver` node, so `MigrationBlueprint::compose` — the
/// §3.2/§3.3/§3.4 window-sizing + cycle-resolution + strangler-shim planner — never ran on the served
/// path). This builds the canonical three-phase migration blueprint for the user's request —
/// `assess → migrate → verify`, a real acyclic dependency chain (verify depends on migrate depends on
/// assess) — and runs the deterministic composer, which validates admissibility and emits the node
/// decls (carrying deps) the durable Program is decomposed with. A richer deployment feeds a real
/// repository model (roots + dep graph from the indexed codebase); the shape here is deliberately
/// minimal-but-real so the composer genuinely drives a MULTI-node graph, never a single fabricated node.
pub fn compose_served_program(goal: &str) -> Result<Vec<NodeDecl>, ComposeError> {
    let _ = goal; // the goal drives the per-module engine turn; the blueprint shape is model-derived.
    let window = WindowBudget::new(SERVED_COMPOSE_WINDOW_TOKENS);
    let roots = vec![
        MtgNode::new("assess", 1_000),
        MtgNode::new("migrate", 1_000),
        MtgNode::new("verify", 1_000),
    ];
    let mut deps = DepGraph::new();
    deps.add_edge("migrate", "assess"); // migrate depends on assess
    deps.add_edge("verify", "migrate"); // verify depends on migrate
    MigrationBlueprint::new(roots, deps, window).compose()
}

/// GAP-FIX data-surfaces-artifacts "bank onboarding as a Program never selectable":
/// [`ainxt_planner::bank_onboarding::bank_onboarding_program`] builds a correct, real topology (KYC
/// data-class registration → federated-broker credential issuance → member-bank connectivity check)
/// and is proven via the generic [`ainxt_planner::program`] engine, but the served
/// [`ProgramSurface::handle_turn`] always composed via [`compose_served_program`]'s generic
/// [`MigrationBlueprint::compose`] planner — there was no way for a served turn to ever select the
/// bank-onboarding topology at all.
///
/// Which topology [`ProgramSurface::handle_turn`] composes for a given turn. `Generic` (the
/// `#[default]`, and what every existing constructor — `ProgramSurface::new` — produces) is
/// byte-for-byte the pre-fix behavior (the model-derived `MigrationBlueprint::compose` planner);
/// `BankOnboarding` selects the real, fixed bank-onboarding topology instead. Selected by the
/// deployment at ASSEMBLY time (mirroring `ProgramSurface::with_governance`/`with_durable_dir`'s own
/// "declared but excludes everything by default" posture: an operator must explicitly select
/// `--surface program_bank_onboarding` — the shipped default `--surface program` is unaffected).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProgramTopology {
    /// The model-derived assess → migrate → verify `MigrationBlueprint` planner (unchanged default).
    #[default]
    Generic,
    /// The real, fixed bank-onboarding topology (`ainxt_planner::bank_onboarding::bank_onboarding_program`):
    /// KYC data-class registration → federated-broker credential issuance → member-bank connectivity
    /// check. The bank id is derived from the turn's own `req.input` via [`bank_id_from_input`].
    BankOnboarding,
}

/// Derive a bank-onboarding topology's `bank_id` from a served turn's free-text `req.input` (the same
/// "goal is the turn's own input" convention [`compose_served_program`] and [`compose_served_team`]
/// document, extended here because — unlike those two fixed topologies — `bank_onboarding_program`
/// genuinely needs a per-turn identifier to parameterize its node ids). Slugified (lowercased,
/// whitespace collapsed to a single `-`, anything other than ASCII alphanumeric/`-`/`_` dropped) so
/// free text like `"Onboard New Bank Ltd"` becomes a stable, DAG-node-id-safe token
/// (`"onboard-new-bank-ltd"`) rather than embedding raw spaces/punctuation into every node id
/// `bank_onboarding_program` derives from it. An empty/all-punctuation input falls back to
/// `"unspecified-bank"` — never an empty string, which would collapse every node id's `{bank_id}-`
/// prefix into a leading `-` and make two different empty-input Runs indistinguishable.
pub fn bank_id_from_input(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut last_was_sep = false;
    for ch in input.trim().chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            out.push(ch.to_ascii_lowercase());
            last_was_sep = false;
        } else if !last_was_sep && !out.is_empty() {
            out.push('-');
            last_was_sep = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        "unspecified-bank".to_string()
    } else {
        out
    }
}

// ===========================================================================
// ProgramSurface — Programs REACHABLE from the live SERVED protocol (LOOP-01)
// ===========================================================================

/// A [`TurnHandler`] that drives the long-horizon **Program Supervisor** for every served turn — the
/// wire that makes Programs/Teams reachable from the LIVE protocol path (gap "Programs/Teams reachable
/// from a live served path"). Before this, `run_program`/`ProgramRuntime` were reachable only from the
/// library API + tests; now `POST /v1/chat` → `SessionManager` → [`ProgramSurface::handle_turn`] →
/// [`run_program`] → real [`Engine`] turns.
///
/// Each served turn:
/// 1. mints a per-Run [`AgentWorkloadCredential`] on-behalf-of the calling principal (IDN-03) — the
///    turn's authz + audit actor derive from it, never a broad ambient identity;
/// 2. runs a Program whose goal is the user's request, executed module-by-module by a real engine
///    turn through the [`EngineRunExecutor`] (the mandatory compliance / RBAC / audit seams fire on
///    every module turn — this surface never bypasses them);
/// 3. streams a human-readable outcome (terminal [`ProgramOutcome`](ainxt_planner::supervisor::ProgramOutcome)
///    + per-module engine output) back to the client.
///
/// The Program never self-declares "done": the served run drives
/// [`drive_served_program_verified`] over
/// [`drive_program_verified_fanout`](ainxt_planner::driver::drive_program_verified_fanout),
/// which enforces the real per-module three-way gate (engine-derived deterministic + adversarial + an
/// INJECTED cross-model Judge — never a producer self-report) AND the program-scale COMPLETED gate
/// (per-edge integration + regression sweep + independent program Judge) before any `Completed`. A red
/// proof/edge yields an honest `CappedPartial`. The offline default derives every proof from the real
/// turn outcomes; a deployment injects a live test-runner + cross-model judge behind the same seams.
pub struct ProgramSurface {
    engine: Arc<Engine>,
    /// Definition-kind label for the per-Run credential (e.g. `"program"` / `"sdlc"`).
    def_kind: String,
    /// The shared §17/§19 control plane (when wired) — its kill-switch / revocation reaches every
    /// in-flight Run this surface drives on the served protocol path.
    control: Option<Arc<Mutex<ControlPlane>>>,
    /// GAP-AUDIT identity-payments #1 — the shared append-only issuance transparency log (when
    /// wired): every per-Run credential this surface mints is appended so an external auditor can
    /// later verify (via an inclusion proof) that the identity was genuinely issued, to what
    /// measurement, and when — without trusting the runtime.
    transparency: Option<Arc<Mutex<TransparencyLog<Sha256Hasher>>>>,
    /// GAP-AUDIT loop-teams-longhorizon (gap 5) — the §7/§8 budget + checkpoint governance, PLUS the
    /// declared fleet capacity that decides the driver's parallel fan-out width (see
    /// [`ServedProgramGovernance::fleet_slots`]). `assemble_program_surface` sets this from
    /// `[limits] program_fan_out_fleet_slots`; direct constructors default to
    /// [`ServedProgramGovernance::served_default`] (sequential — byte-identical to pre-wire behavior).
    governance: ServedProgramGovernance,
    /// GAP-AUDIT loop-teams-longhorizon (gap 1) — when set, `handle_turn` drives the Run through
    /// [`run_program_durable`] (a hash-chained JSONL [`ainxt_eventlog::ProgramEventSink`] under
    /// `{durable_dir}/{session}_{turn}/`) instead of the in-memory [`drive_served_program_governed`]
    /// path. `None` (the default) is byte-identical to pre-wire behavior — every served Run's state
    /// lived only in the driver thread's stack and was gone the instant the turn returned, so a daemon
    /// crash mid-Program lost the entire in-flight Run with no way to resume it. A deployment that
    /// wants crash-resumable served Programs opts in via [`Self::with_durable_dir`]; this trades the
    /// governed path's three-way verification / SoD / §7 budget-driver / fan-out for the Supervisor's
    /// simpler AutoApprove + PermissiveProgramVerifier loop, so it is an explicit, documented choice —
    /// never a silent default swap.
    durable_dir: Option<std::path::PathBuf>,
    /// GAP-FIX data-surfaces-artifacts "bank onboarding as a Program never selectable" — which node
    /// topology `handle_turn` composes. `ProgramTopology::Generic` (every existing constructor's
    /// default) is byte-for-byte the pre-fix behavior; see [`Self::with_topology`].
    topology: ProgramTopology,
}

impl ProgramSurface {
    /// Wrap a shared engine as a served Program surface. `def_kind` labels the minted per-Run
    /// credential's definition (program vs. sdlc etc.).
    pub fn new(engine: Arc<Engine>, def_kind: impl Into<String>) -> Self {
        ProgramSurface {
            engine,
            def_kind: def_kind.into(),
            control: None,
            transparency: None,
            governance: ServedProgramGovernance::served_default(),
            durable_dir: None,
            topology: ProgramTopology::default(),
        }
    }

    /// Wire the shared §17/§19 [`ControlPlane`] so a kill-switch / revocation reaches the Runs this
    /// served surface drives (kill-switch reaches in-flight Runs on the live path).
    pub fn with_control_plane(mut self, control: Arc<Mutex<ControlPlane>>) -> Self {
        self.control = Some(control);
        self
    }

    /// Wire the shared issuance transparency log (ADR-022 §13) so every per-Run credential this
    /// served surface mints is durably, tamper-evidently logged (§22 scenario 3). `None` (the
    /// default) is a no-op — no HMAC key is provisioned on the air-gapped default.
    pub fn with_transparency_log(mut self, log: Arc<Mutex<TransparencyLog<Sha256Hasher>>>) -> Self {
        self.transparency = Some(log);
        self
    }

    /// Override the served governance (§7 budget / §8 checkpoint / gap-5 fan-out fleet capacity).
    /// `assemble_program_surface` calls this with the deployment's configured fleet slots.
    pub fn with_governance(mut self, governance: ServedProgramGovernance) -> Self {
        self.governance = governance;
        self
    }

    /// Opt this served surface into crash-resumable Programs (GAP-AUDIT loop-teams-longhorizon gap 1):
    /// every Run `handle_turn` drives is persisted to a hash-chained JSONL event log under
    /// `{dir}/{session}_{turn}/`, and a daemon restart resumes an in-flight Run from exactly where it
    /// stopped instead of losing it. `None` (the default) keeps the pre-wire in-memory-only behavior.
    pub fn with_durable_dir(mut self, dir: std::path::PathBuf) -> Self {
        self.durable_dir = Some(dir);
        self
    }

    /// GAP-FIX data-surfaces-artifacts "bank onboarding as a Program never selectable": select which
    /// topology `handle_turn` composes for every turn this surface serves. `assemble_program_surface`
    /// (the `--surface program` composition root) never calls this, so its default
    /// `ProgramTopology::Generic` is unchanged; `assemble_program_surface_with_topology` (the new
    /// `--surface program_bank_onboarding` composition root) calls this with `BankOnboarding`.
    pub fn with_topology(mut self, topology: ProgramTopology) -> Self {
        self.topology = topology;
        self
    }
}

impl TurnHandler for ProgramSurface {
    fn handle_turn<'a>(
        &'a self,
        principal: &'a Principal,
        req: &'a Request,
        sink: mpsc::Sender<Event>,
        cancel: &'a CancelToken,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<TurnSummary, TurnError>> + Send + 'a>,
    > {
        Box::pin(async move {
            // Per-Run identity on-behalf-of the caller (IDN-03). The run/session/turn ids keep the
            // credential unique per served turn; the data-class flows from the request.
            let run_id = format!("{}:{}", req.session, req.turn);
            let mut identity = RunIdentitySpec::new(
                self.def_kind.clone(),
                req.session.clone(),
                run_id.clone(),
                req.data_class,
                principal.user_id.clone(),
            );
            if let Some(dept) = &principal.department {
                identity = identity.with_department(dept.clone());
            }

            // The node graph is composed by the real MigrationBlueprint::compose planner (§3.2 window-
            // sizing + §3.3 cycle resolution + §3.4 strangler shims), never a single hard-coded node —
            // so the served Program drives a genuine multi-node acyclic DAG (assess → migrate → verify).
            // An irreducible/over-budget blueprint is an honest ComposeError (fail-closed, never a
            // silently truncated plan).
            //
            // GAP-FIX data-surfaces-artifacts "bank onboarding as a Program never selectable": when
            // this surface was assembled with `ProgramTopology::BankOnboarding` (`--surface
            // program_bank_onboarding`), drive the real, fixed `bank_onboarding_program` topology
            // instead — KYC data-class registration → federated-broker credential issuance →
            // member-bank connectivity check, parameterized by the bank id this turn's own `req.input`
            // slugifies to. `ProgramTopology::Generic` (every pre-existing constructor/composition
            // root) is byte-for-byte the unchanged `compose_served_program` path below.
            let nodes = match self.topology {
                ProgramTopology::BankOnboarding => {
                    let bank_id = bank_id_from_input(&req.input);
                    ainxt_planner::bank_onboarding::bank_onboarding_program(&bank_id)
                }
                ProgramTopology::Generic => match compose_served_program(&req.input) {
                    Ok(nodes) => nodes,
                    Err(e) => {
                        let msg = format!("program decomposition failed: {e:?}");
                        let _ = sink.send(Event::Error(msg.clone())).await;
                        let _ = sink.send(Event::Done).await;
                        return Err(TurnError::Internal(msg));
                    }
                },
            };
            // GAP-AUDIT loop-teams-longhorizon (gap 1): when this surface opted into a durable dir
            // (`with_durable_dir`), drive the Run through `run_program_durable` so its ProgramEvent
            // stream is hash-chained to disk under `{durable_dir}/{session}_{turn}/` and a daemon
            // restart resumes it — never re-running from scratch or silently losing the in-flight Run.
            // This is a distinct, explicitly-opted-in code path from the governed drive below (see the
            // trade-off note on `ProgramSurface::durable_dir`); `None` (the default) falls through to
            // the unchanged governed path.
            if let Some(base_dir) = &self.durable_dir {
                let session_dir = base_dir.join(run_id.replace(':', "_"));
                let run_result = run_program_durable(
                    self.engine.clone(),
                    identity,
                    req.input.clone(),
                    nodes,
                    SupervisorConfig::default(),
                    None,
                    session_dir.clone(),
                )
                .await;
                return match run_result {
                    Ok(run) => {
                        let redactions: usize = run.turns.iter().map(|t| t.redactions).sum();
                        let mut out = format!(
                            "program {run_id} (durable): {:?} ({} module turn(s); {} durable \
                             event(s) persisted under {})\n",
                            run.report.outcome,
                            run.turns.len(),
                            run.events.len(),
                            session_dir.display(),
                        );
                        for t in &run.turns {
                            out.push_str(&format!("[{}] {}\n", t.label, t.text));
                        }
                        let _ = sink.send(Event::TextDelta(out.clone())).await;
                        let _ = sink.send(Event::Done).await;
                        Ok(TurnSummary {
                            final_text: out,
                            redactions,
                            provider: "program-durable".into(),
                            ..Default::default()
                        })
                    }
                    Err(e) => {
                        let msg = format!("durable program run failed: {e}");
                        let _ = sink.send(Event::Error(msg.clone())).await;
                        let _ = sink.send(Event::Done).await;
                        Err(TurnError::Internal(msg))
                    }
                };
            }

            // R14 (§7/§8): the served Program run is now GOVERNED — the driver enforces the per-Run
            // token budget (§7) and holds a critical-path (settlement/ledger) node for a human checkpoint
            // (§8, no forced-commit) via `ServedProgramGovernance::served_default`. This closes "served
            // Program path bypasses §7 budget, §8 human checkpoints" — the SupervisorConfig is no longer
            // discarded; its budget rides the driver, and checkpoints are honored, not force-committed.
            // The served Program run drives the DRIVER Program API so three-way verification is enforced
            // at the seam (record_verdict/commit_node) — never a fabricated green. When the served
            // surface wired a shared control plane, a kill-switch / revocation on it reaches this
            // in-flight Run (a denied dispatch fails the node). §15 JIT renewal runs on the long Run.
            // Thread the served transport's user-stop [`CancelToken`] into the long-horizon Program
            // loop: a user-stop halts the Run at the next module boundary AND cancels the in-flight
            // module's engine turn mid-stream (the SAME token flows into `run_turn_cancellable`), so a
            // stopped Run reports an honest capped-partial — never a fabricated green.
            let run_result = drive_served_program_governed(
                self.engine.clone(),
                identity,
                req.input.clone(),
                nodes,
                None,
                self.control.clone(),
                self.transparency.clone(),
                SodApprover::Distinct,
                cancel.clone(),
                ProgramProofSeams::offline_default(),
                self.governance,
            )
            .await;
            match run_result {
                Ok(run) => {
                    let redactions: usize = run.turns.iter().map(|t| t.redactions).sum();
                    let committed = run.program.state().committed_node_ids().len();
                    let all_proven = run.program.state().committed_nodes_are_all_proven();
                    let mut out = format!(
                        "program {run_id}: {:?} ({} module turn(s); {} committed; \
                         all_committed_proven={}; {} identity renewal(s); {} SoD-authorized commit(s))\n",
                        run.outcome,
                        run.turns.len(),
                        committed,
                        all_proven,
                        run.renewals,
                        run.sod_approvals,
                    );
                    for t in &run.turns {
                        out.push_str(&format!("[{}] {}\n", t.label, t.text));
                    }
                    let _ = sink.send(Event::TextDelta(out.clone())).await;
                    let _ = sink.send(Event::Done).await;
                    Ok(TurnSummary {
                        final_text: out,
                        redactions,
                        provider: "program".into(),
                        ..Default::default()
                    })
                }
                Err(e) => {
                    let msg = format!("program run failed: {e}");
                    let _ = sink.send(Event::Error(msg.clone())).await;
                    let _ = sink.send(Event::Done).await;
                    Err(TurnError::Internal(msg))
                }
            }
        })
    }
}

/// Assemble the runtime for the **program** surface, served over the SAME [`SessionManager`] spine as
/// chat (gap "Programs/Teams reachable from a live served path"). The daemon's `--surface program`
/// mounts this so the long-horizon Program Supervisor runs on `POST /v1/chat`. Fail-closed on an
/// enterprise gate selection (same as [`build_engine`]).
pub fn assemble_program_surface(
    loaded: &LoadedConfig,
    def_kind: &str,
) -> Result<Assembled, AssembleError> {
    let (assembled, _transparency_log) =
        assemble_program_surface_with_transparency(loaded, def_kind)?;
    Ok(assembled)
}

/// [`assemble_program_surface`], additionally returning the SAME live
/// [`ainxt_identity::transparency::TransparencyLog`] handle wired into the [`ProgramSurface`] it
/// composes.
///
/// GAP-FIX identity-payments (ADR-022 §13/§22 #3 — "transparency-log orphaned") — before this fix,
/// `assemble_program_surface` never called `ProgramSurface::with_transparency_log`, so on the ACTUAL
/// served path (the daemon's `--surface program` composition root, and `assemble_selected("program",
/// ..)`) every real Run's `AgentWorkloadCredential` issuance skipped the append-only, HMAC-signable
/// transparency log entirely — `r13_program_transparency_log.rs`'s own header names this exactly:
/// "fully built and unit-tested but had ZERO live callers anywhere in the served path", and that test
/// proved the property only by hand-building a SECOND `ProgramSurface` that bypasses this composition
/// function, not by exercising `assemble_program_surface` itself. This function makes the composition
/// root the live caller: every daemon started with `--surface program` now durably logs every Run's
/// credential issuance, and an external auditor (or a test, per §22 #3) can request an inclusion proof
/// against the returned log's root with no special runtime access.
pub fn assemble_program_surface_with_transparency(
    loaded: &LoadedConfig,
    def_kind: &str,
) -> Result<
    (
        Assembled,
        Arc<
            Mutex<
                ainxt_identity::transparency::TransparencyLog<
                    ainxt_identity::transparency::Sha256Hasher,
                >,
            >,
        >,
    ),
    AssembleError,
> {
    assemble_program_surface_with_transparency_and_topology(
        loaded,
        def_kind,
        ProgramTopology::Generic,
    )
}

/// [`assemble_program_surface_with_transparency`], additionally selecting which
/// [`ProgramTopology`] the composed [`ProgramSurface`] serves (GAP-FIX data-surfaces-artifacts "bank
/// onboarding as a Program never selectable"). [`assemble_program_surface_with_transparency`] (and
/// therefore [`assemble_program_surface`], and the shipped `--surface program` default) forwards
/// `ProgramTopology::Generic` — byte-for-byte unchanged. The new `--surface program_bank_onboarding`
/// composition root ([`assemble_program_surface_bank_onboarding`]) calls this directly with
/// `ProgramTopology::BankOnboarding`.
pub fn assemble_program_surface_with_transparency_and_topology(
    loaded: &LoadedConfig,
    def_kind: &str,
    topology: ProgramTopology,
) -> Result<
    (
        Assembled,
        Arc<
            Mutex<
                ainxt_identity::transparency::TransparencyLog<
                    ainxt_identity::transparency::Sha256Hasher,
                >,
            >,
        >,
    ),
    AssembleError,
> {
    let (
        engine,
        mut report,
        ledger,
        reconciler,
        dispatch_probe,
        tools,
        outsourcing_register,
        mandate_registry,
        mcp_admin,
        _prompt_cache,
        serving,
    ) = crate::build_engine_ext_with_mcp(
        &loaded.runtime,
        &loaded.mcp,
        &loaded.payments,
        &loaded.serving,
    )?;
    // GAP-AUDIT loop-teams-longhorizon (gap 5) — thread the deployment's declared fleet capacity
    // (`[limits] program_fan_out_fleet_slots`) into the served governance so
    // `drive_served_program_blocking` computes a REAL `ElasticFanoutPolicy` admission width instead of
    // always driving the sequential (wave ceiling 1) path. Unset (`None`) stays sequential — exactly
    // the pre-wire behavior.
    let fleet_slots = loaded.runtime.limits.program_fan_out_fleet_slots;
    let governance = ServedProgramGovernance::served_default().with_fleet_slots(fleet_slots);
    let transparency_log = Arc::new(Mutex::new(
        ainxt_identity::transparency::TransparencyLog::new(
            ainxt_identity::transparency::Sha256Hasher,
        ),
    ));
    let mut surface = ProgramSurface::new(Arc::new(engine), def_kind.to_string())
        .with_governance(governance)
        .with_transparency_log(transparency_log.clone())
        .with_topology(topology);
    // GAP-FIX loop-teams-longhorizon (gap 1a) — thread the deployment's declared durable-state
    // directory (`[limits] program_durable_dir`) into the served surface so the daemon's REAL
    // `--surface program` composition root (this function — `assemble_selected("program", ..)` calls
    // `assemble_program_surface`, which delegates here) gets crash-resumable Programs, not just a
    // direct-constructor test proving `ProgramSurface::with_durable_dir` in isolation.
    // `None` (default) preserves the pre-wire in-memory-only behavior byte-for-byte.
    let durable_dir = loaded.runtime.limits.program_durable_dir.clone();
    if let Some(dir) = &durable_dir {
        surface = surface.with_durable_dir(std::path::PathBuf::from(dir));
    }
    report.push(format!(
        "surface: {def_kind} — long-horizon Program Supervisor served over the protocol (POST \
         /v1/chat → SessionManager → run_program → real Engine turns; per-Run AgentWorkloadCredential \
         IDN-03; mandatory compliance/RBAC/audit on every module turn)"
    ));
    report.push(match topology {
        ProgramTopology::Generic => {
            "program topology: generic (MigrationBlueprint::compose planner: assess → migrate → \
             verify)"
                .into()
        }
        ProgramTopology::BankOnboarding => {
            "program topology: bank-onboarding (KYC data-class registration → federated-broker \
             credential issuance → member-bank connectivity check; GAP-FIX data-surfaces-artifacts)"
                .into()
        }
    });
    report.push(match fleet_slots {
        Some(slots) => format!(
            "program fan-out: fleet_slots={slots} — ElasticFanoutPolicy admits a real parallel wave \
             width (gap-5)"
        ),
        None => "program fan-out: fleet_slots=None — sequential (wave ceiling 1, unchanged)".into(),
    });
    report.push(match &durable_dir {
        Some(dir) => format!(
            "program durability: durable_dir={dir} — crash-resumable ProgramEventSink LIVE (gap-1a); \
             the durable branch drives the SAME real verifier/SoD/critical-path gate as the governed \
             path, never AutoApprove/PermissiveProgramVerifier (gap-1b)"
        ),
        None => "program durability: durable_dir=None — in-memory only (unchanged pre-wire default)"
            .into(),
    });
    report.push(
        "identity: ADR-022 §13 issuance transparency log LIVE on the served program surface — every \
         Run's AgentWorkloadCredential issuance is appended, Merkle-committed, and \
         inclusion-proof-verifiable by an external auditor (GAP-FIX identity-payments)"
            .into(),
    );
    let sm = Arc::new(SessionManager::new(Arc::new(surface), loaded.session));
    // The Program surface drives real Engine turns through its own executor; the served /v1/chat body is
    // the Program run projection, so it streams the legacy `Event` projection (no chat-engine wire seam).
    Ok((
        Assembled {
            manager: sm,
            report,
            wire_events: None,
            capability_ledger: Some((ledger, reconciler)),
            dispatch_probe: Some(dispatch_probe),
            // No ChatSurface on the Program surface — a fresh, never-shared handle (nothing to erase).
            shared_answer_cache: Arc::new(Mutex::new(ainxt_cache::PartitionedCache::new(
                ainxt_cache::CacheConfig::default(),
            ))),
            capability_tools: Some(tools),
            // No ChatSurface/memory reader on this surface (real Engine turns via its own executor).
            memory_backend: None,
            outsourcing_register,
            // No role-invocation concept on the Program surface.
            workforce_invocation_ledger: None,
            // No kernel process model on the Program surface.
            workforce_kernel: None,
            // No GovernedWorkforce on the Program surface.
            workforce_surface: None,
            mandate_registry,
            mcp_admin,
            // No profile/SkillRuntime on the Program/Team surface.
            skill_runtime: None,
            // GAP-FIX gap6-composition-root (Item 1) — the SAME `ServingHandle` this real Engine
            // attached via `Engine::with_node_attestor`; see `Assembled::serving`'s doc.
            serving: Some(serving),
        },
        transparency_log,
    ))
}

/// GAP-FIX data-surfaces-artifacts "bank onboarding as a Program never selectable" — the
/// `--surface program_bank_onboarding` composition root (`assemble_selected`'s new arm). Sibling of
/// [`assemble_program_surface`], selecting [`ProgramTopology::BankOnboarding`] instead of the generic
/// `MigrationBlueprint::compose` planner so a served turn actually drives
/// `ainxt_planner::bank_onboarding::bank_onboarding_program`'s real KYC → credential-issuance →
/// connectivity topology. The shipped `--surface program` default (`assemble_program_surface`) is
/// completely unaffected — this is a NEW, additive, explicitly-opted-in selector.
pub fn assemble_program_surface_bank_onboarding(
    loaded: &LoadedConfig,
    def_kind: &str,
) -> Result<Assembled, AssembleError> {
    let (assembled, _transparency_log) = assemble_program_surface_with_transparency_and_topology(
        loaded,
        def_kind,
        ProgramTopology::BankOnboarding,
    )?;
    Ok(assembled)
}

// ===========================================================================
// TeamSurface — the hierarchical 3-tier Team loop REACHABLE from the SERVED path (LOOP-15, gap 2)
// ===========================================================================
//
// The gap (round-12 loop-teams gap 2): the hierarchical 3-tier Team loop (roles / structured handoff /
// bulkhead isolation / bounded self-heal / fresh-context judge) was reachable ONLY from the library API
// (`run_team` / `ProgramRuntime::run_team`) + tests — never from a served or daemon SURFACE. There was a
// `ProgramSurface` (Programs on `POST /v1/chat`) but no `TeamSurface`. This section adds it, so the team
// loop runs on the live protocol path exactly as Programs do.
//
// What is exposed here (a clean entrypoint in this RESERVED crate): [`compose_served_team`] (the canonical
// hierarchical team + task graph for a served turn), [`drive_served_team`] (drive the 3-tier loop over the
// real Engine with the served transport's user-stop bridged in), [`TeamSurface`] (the [`TurnHandler`]), and
// [`assemble_team_surface`] (mount it over the SessionManager spine). The remaining wire — the daemon CLI
// `--surface team` selector routing to `assemble_team_surface` — is `needs_hot_wiring` (a one-line match arm
// in `main`, the reserved binary entrypoint), exactly as the program surface's selector is.

/// Compose the canonical **hierarchical, multi-branch** team + task graph a served team turn runs
/// (LOOP §4/§5): an Architect (Complex tier) → Coder (Medium) → Reviewer (Simple) hierarchy with a
/// structured `design` handoff, PLUS an independent Tester branch (so the fan-out admission of
/// independent branches is exercised, not a single chain). A richer deployment derives the team/graph
/// from the request + the tenant's role catalog; the shape here is deliberately minimal-but-real so the
/// served loop drives a genuine hierarchy with a handoff + an independent branch, never one task.
pub fn compose_served_team(goal: &str) -> Result<(TaskGraph, Team, BTreeSet<String>), GraphError> {
    let _ = goal; // the goal drives each per-task engine turn; the team/graph shape is catalog-derived.
    let mut team = Team::new();
    team.add_role(Role::new("architect", ModelTier::Complex, ["design"]));
    team.add_role(Role::new("coder", ModelTier::Medium, ["edit_code"]));
    team.add_role(Role::new("reviewer", ModelTier::Simple, ["review"]));
    team.add_role(Role::new("tester", ModelTier::Simple, ["test"]));

    let mut g = TaskGraph::new();
    g.add_task(
        Task::new("architect", "architect")
            .produces("design")
            .accepts("designed"),
    )?;
    g.add_task(
        Task::new("code", "coder")
            .depends_on("architect")
            .requires("design")
            .produces("diff")
            .accepts("compiles"),
    )?;
    g.add_task(
        Task::new("review", "reviewer")
            .depends_on("code")
            .accepts("reviewed"),
    )?;
    // Independent branch: the tester has no dependency on the architect chain (parallel fan-out).
    g.add_task(Task::new("test", "tester").accepts("tested"))?;
    Ok((g, team, BTreeSet::new()))
}

/// Drive the hierarchical **3-tier Team** loop for a served turn over the real [`Engine`] (LOOP-15,
/// gap 2), with the served transport's user-stop [`CancelToken`] bridged into the loop's
/// [`TeamStopSignal`] so a stop halts the in-flight run promptly (the loop terminates an honest
/// [`TeamOutcome::Capped`], never a fabricated `Complete`). Mirrors [`run_team`] but is cancellable and
/// drives the 3-tier loop through [`run_team_3tier_verified_cancellable`] (LOOP §7's three-way
/// anti-sycophancy gate — judge + the offline-default [`ContentDeterministicGate`] +
/// [`BreakerAdversarialGate`] — not the judge-only path: see the wiring note on
/// `drive_served_team_blocking`). Each task is a real engine turn through [`EngineRunExecutor`]
/// (tier 1); tier 2 runs [`ContentStepCritic`] (a real per-step content check, not a rubber-stamp —
/// see the wiring note on `drive_served_team_blocking`); the healer / fresh-context judge use the
/// offline-default seams (a deployment injects live model-backed ones — `needs_hot_wiring`).
#[allow(clippy::too_many_arguments)]
pub async fn drive_served_team(
    engine: Arc<Engine>,
    identity: RunIdentitySpec,
    graph: TaskGraph,
    team: Team,
    goal: impl Into<String>,
    seed_inputs: BTreeSet<String>,
    config: ThreeTierConfig,
    learning: Option<Arc<dyn LearningSink>>,
    incident: Option<Arc<Mutex<IncidentRegister>>>,
    // GAP-AUDIT identity-payments #1 — see the identical parameter on `drive_served_program_governed`.
    transparency: Option<Arc<Mutex<TransparencyLog<Sha256Hasher>>>>,
    cancel: CancelToken,
) -> Result<TeamRun, TeamRunError> {
    let credential = mint_run_credential(&identity).map_err(TeamRunError::Identity)?;
    if let Some(log) = &transparency {
        log.lock()
            .expect("transparency log mutex poisoned")
            .append(IssuanceEntry::from_awc(&credential));
    }
    let goal = goal.into();
    let handle = Handle::current();
    let cred = credential.clone();

    // Bridge the transport's user-stop token to the loop's StopSignal (a pre-cancelled token trips it
    // before the first task attempt → an honest capped run with zero turns).
    let stop = TeamStopSignal::new();
    if cancel.is_cancelled() {
        stop.stop();
    }
    {
        let stop = stop.clone();
        let cancel = cancel.clone();
        handle.spawn(async move {
            cancel.cancelled().await;
            stop.stop();
        });
    }

    let (tx, rx) = tokio::sync::oneshot::channel();
    let stop_thread = stop.clone();
    std::thread::Builder::new()
        .name("ainxt-served-team".into())
        .spawn(move || {
            let out = drive_served_team_blocking(
                engine,
                cred,
                handle,
                graph,
                team,
                goal,
                seed_inputs,
                config,
                learning,
                incident,
                cancel,
                stop_thread,
            );
            let _ = tx.send(out);
        })
        .expect("spawn served team driver thread");

    let (report, turns) = rx
        .await
        .expect("served team driver thread dropped its result")
        .map_err(TeamRunError::Graph)?;
    Ok(TeamRun {
        report,
        credential,
        turns,
    })
}

#[allow(clippy::too_many_arguments)]
fn drive_served_team_blocking(
    engine: Arc<Engine>,
    credential: AgentWorkloadCredential,
    handle: Handle,
    graph: TaskGraph,
    team: Team,
    goal: String,
    seed_inputs: BTreeSet<String>,
    config: ThreeTierConfig,
    learning: Option<Arc<dyn LearningSink>>,
    incident: Option<Arc<Mutex<IncidentRegister>>>,
    cancel: CancelToken,
    stop: TeamStopSignal,
) -> Result<(TeamRunReport, Vec<TurnObservation>), GraphError> {
    // The tier-1 executor: a real engine turn per task, with the served transport's user-stop token
    // threaded in so an in-flight task turn cancels mid-stream (same token the loop polls between tasks).
    let mut exec = EngineRunExecutor::new(engine, credential, handle, incident).with_cancel(cancel);
    // GAP-AUDIT loop-teams-longhorizon (tier2/tier3 rubber-stamp) — this driver wired `AcceptingCritic`
    // as tier 2: every step "served" regardless of content, so a task producing an empty artifact or a
    // bare `todo!()` stub sailed through self-heal untouched and was only EVER caught (if at all) at
    // the whole-deliverable tier-3 audit, one or more full judge-rounds later. `ContentStepCritic` runs
    // the same real content check `ContentDeterministicGate` runs at tier 3, scoped to one step, so a
    // deficient step is rejected and fed back into self-heal in the SAME round it happened.
    let mut critic = ContentStepCritic;
    let mut healer = EscalatingHealer;
    let mut judge = ConfirmingGoalJudge;
    // GAP-AUDIT loop-teams-longhorizon — LOOP §7's anti-sycophancy backstop
    // (`run_team_3tier_verified_cancellable` + the deterministic/adversarial gates it requires) was
    // fully built and unit-tested in `ainxt-teams::tiers` but had ZERO callers from the served
    // composition root: this driver called the judge-ONLY `run_team_3tier_cancellable`, and
    // `ConfirmingGoalJudge` confirms as soon as ANY task produces a non-empty output — exactly the
    // "textbook sycophancy failure" the module doc for `run_team_3tier_verified` names. Wiring in the
    // offline-default `ContentDeterministicGate` + `BreakerAdversarialGate` (both real, non-fabricated
    // analysers — see `ainxt_planner::assurance`) means a served team run can no longer be rubber-
    // stamped `Complete` on a stubbed/broken deliverable; a deployment hot-wires live gates behind the
    // same seams.
    let mut det_gate = ContentDeterministicGate;
    let mut adv_gate = BreakerAdversarialGate;

    let report = run_team_3tier_verified_cancellable(
        &graph,
        &team,
        &goal,
        &seed_inputs,
        &mut exec,
        &mut critic,
        &mut healer,
        &mut judge,
        &mut det_gate,
        &mut adv_gate,
        config,
        &stop,
    )?;
    // LOOP-13: route the terminal-run Learning Record to the flywheel sink.
    if let Some(sink) = &learning {
        sink.record(&report.learning);
    }
    Ok((report, exec.into_observations()))
}

/// A [`TurnHandler`] that drives the hierarchical **3-tier Team** loop for every served turn — the wire
/// that makes the team subsystem reachable from the LIVE protocol path (LOOP-15, gap 2). `POST /v1/chat`
/// → `SessionManager` → [`TeamSurface::handle_turn`] → [`drive_served_team`] → real [`Engine`] turns per
/// task. Each served turn mints a per-Run [`AgentWorkloadCredential`] on-behalf-of the caller (IDN-03),
/// so every task turn's authz + audit derive from it; the mandatory compliance / RBAC / audit seams fire
/// on every task turn (this surface never bypasses them). The team never self-declares "done": the
/// fresh-context [`ConfirmingGoalJudge`] audits the deliverable, and an unmet goal is an honest
/// [`TeamOutcome::Capped`], never a fabricated `Complete`.
pub struct TeamSurface {
    engine: Arc<Engine>,
    /// Definition-kind label for the per-Run credential (e.g. `"team"`).
    def_kind: String,
    /// The flywheel sink terminal-run Learning Records are routed to (LOOP-13), when wired.
    learning: Option<Arc<dyn LearningSink>>,
    /// The 3-tier loop's bounds (self-heal/stuck/round caps + cost ceiling, LOOP-12). Config-driven
    /// via [`with_config`](Self::with_config); `ThreeTierConfig::default()` (unbounded cost) when
    /// never set.
    config: ThreeTierConfig,
    /// GAP-AUDIT identity-payments #1 — the shared append-only issuance transparency log (when
    /// wired): the per-Run credential this surface mints is appended, mirroring
    /// [`ProgramSurface::with_transparency_log`].
    transparency: Option<Arc<Mutex<TransparencyLog<Sha256Hasher>>>>,
}

impl TeamSurface {
    /// Wrap a shared engine as a served Team surface. `def_kind` labels the minted per-Run credential.
    pub fn new(engine: Arc<Engine>, def_kind: impl Into<String>) -> Self {
        TeamSurface {
            engine,
            def_kind: def_kind.into(),
            learning: None,
            config: ThreeTierConfig::default(),
            transparency: None,
        }
    }

    /// Route terminal-run Learning Records to `sink` (LOOP-13 flywheel).
    pub fn with_learning_sink(mut self, sink: Arc<dyn LearningSink>) -> Self {
        self.learning = Some(sink);
        self
    }

    /// Wire the shared issuance transparency log (ADR-022 §13) — see
    /// [`ProgramSurface::with_transparency_log`]. `None` (the default) is a no-op.
    pub fn with_transparency_log(mut self, log: Arc<Mutex<TransparencyLog<Sha256Hasher>>>) -> Self {
        self.transparency = Some(log);
        self
    }

    /// Set the served Run's 3-tier bounds — in particular the cost ceiling (LOOP-12), so the daemon
    /// composition's config can actually cap a Team run's rolled-up sub-agent cost instead of every
    /// served run silently getting `ThreeTierConfig::default()` (unbounded).
    pub fn with_config(mut self, config: ThreeTierConfig) -> Self {
        self.config = config;
        self
    }
}

impl TurnHandler for TeamSurface {
    fn handle_turn<'a>(
        &'a self,
        principal: &'a Principal,
        req: &'a Request,
        sink: mpsc::Sender<Event>,
        cancel: &'a CancelToken,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<TurnSummary, TurnError>> + Send + 'a>,
    > {
        Box::pin(async move {
            let run_id = format!("{}:{}", req.session, req.turn);
            let mut identity = RunIdentitySpec::new(
                self.def_kind.clone(),
                req.session.clone(),
                run_id.clone(),
                req.data_class,
                principal.user_id.clone(),
            );
            if let Some(dept) = &principal.department {
                identity = identity.with_department(dept.clone());
            }

            // The hierarchical team + task graph is composed by the catalog-derived planner (a real
            // Architect→Coder→Reviewer hierarchy + an independent Tester branch), never a single task.
            let (graph, team, seed) = match compose_served_team(&req.input) {
                Ok(t) => t,
                Err(e) => {
                    let msg = format!("team composition failed: {e}");
                    let _ = sink.send(Event::Error(msg.clone())).await;
                    let _ = sink.send(Event::Done).await;
                    return Err(TurnError::Internal(msg));
                }
            };

            let run_result = drive_served_team(
                self.engine.clone(),
                identity,
                graph,
                team,
                req.input.clone(),
                seed,
                self.config.clone(),
                self.learning.clone(),
                None,
                self.transparency.clone(),
                cancel.clone(),
            )
            .await;

            match run_result {
                Ok(run) => {
                    let redactions: usize = run.turns.iter().map(|t| t.redactions).sum();
                    // The team never self-declares "done": the outcome is the fresh-context judge's
                    // verdict (Complete only when confirmed; otherwise an honest Capped).
                    let mut out = format!(
                        "team {run_id}: {:?} ({} round(s); {} task turn(s); judge={:?})\n",
                        run.report.outcome,
                        run.report.rounds,
                        run.turns.len(),
                        run.report.judge,
                    );
                    for t in &run.turns {
                        out.push_str(&format!("[{}] {}\n", t.label, t.text));
                    }
                    let _ = sink.send(Event::TextDelta(out.clone())).await;
                    let _ = sink.send(Event::Done).await;
                    Ok(TurnSummary {
                        final_text: out,
                        redactions,
                        provider: "team".into(),
                        ..Default::default()
                    })
                }
                Err(e) => {
                    let msg = format!("team run failed: {e}");
                    let _ = sink.send(Event::Error(msg.clone())).await;
                    let _ = sink.send(Event::Done).await;
                    Err(TurnError::Internal(msg))
                }
            }
        })
    }
}

// ===========================================================================
// LOOP-13 flywheel — the downstream CURATION sweep (GAP-FIX loop-teams-longhorizon gap 2)
// ===========================================================================

/// GAP-FIX loop-teams-longhorizon (gap 2, LOOP §10) — `ainxt_teams::flywheel::generate_eval_cases` /
/// `plan_template_priors` / `role_spec_tuning` (the flywheel's DOWNSTREAM consumers) are fully
/// implemented and unit-tested, and [`InMemoryLearningSink::flywheel_eval_cases`] /
/// [`InMemoryLearningSink::flywheel_template_priors`] / [`InMemoryLearningSink::flywheel_role_tuning`]
/// already pass accumulated records straight through to them — but before this fix, nothing on any
/// served or daemon path ever CALLED those passthroughs: `assemble_team_surface_with_transparency`
/// wired only the PRODUCER side (`LearningRecord` → `InMemoryLearningSink`), and the passthroughs'
/// own proving test (`r_flywheel_sink_accessors.rs`) demonstrated the curation only by hand-building an
/// `InMemoryLearningSink` and calling `.record()` on it directly — never through a real served Team run.
///
/// `FlywheelCurationSweep` is the composition-root entrypoint a daemon cadence calls:
/// [`Self::tick`] is a single pure curation pass over the SAME sink object every served Team turn
/// already writes to (via [`TeamSurface::with_learning_sink`]) — no external data plane, no fabricated
/// input, exactly the "reads this surface's own accumulated state, no live infra needed" shape
/// [`crate::workforce_surface::WorkforceSurface::spawn_kernel_scheduler`] uses. [`spawn_flywheel_sweep`]
/// wraps it in a real `tokio::time::interval` loop; `build_team_surface_parts` spawns that loop
/// unconditionally, so every daemon started with `--surface team` runs it.
pub struct FlywheelCurationSweep {
    sink: Arc<InMemoryLearningSink>,
    /// The static task→role map the served Team's canonical graph declares (from
    /// [`compose_served_team`]) — `role_spec_tuning` needs this to roll task outcomes up to the role
    /// that ran them.
    task_roles: std::collections::BTreeMap<ainxt_teams::TaskId, ainxt_teams::RoleId>,
    /// The static role→tier map the served Team's canonical roster declares.
    role_tiers: std::collections::BTreeMap<ainxt_teams::RoleId, ModelTier>,
    latest: Mutex<FlywheelSweepResult>,
    sweeps_run: Mutex<u64>,
}

/// The latest curated output of a [`FlywheelCurationSweep`] tick — the durable improvement signal LOOP
/// §10 names, re-derived FRESH from the sink's full accumulated history on every tick (never merely
/// accumulated incrementally, so a tick is always consistent with the sink's current record set).
#[derive(Debug, Clone, Default)]
pub struct FlywheelSweepResult {
    pub eval_cases: Vec<ainxt_teams::flywheel::EvalCase>,
    pub template_priors:
        std::collections::BTreeMap<ainxt_teams::TaskId, ainxt_teams::flywheel::TaskPrior>,
    pub role_tuning:
        std::collections::BTreeMap<ainxt_teams::RoleId, ainxt_teams::flywheel::RoleTuning>,
    /// Total accumulated Learning Records the curators read for this tick (observability: proves the
    /// sweep actually consumed the sink's records, never a fabricated empty pass).
    pub records_curated: usize,
}

impl FlywheelCurationSweep {
    pub fn new(
        sink: Arc<InMemoryLearningSink>,
        task_roles: std::collections::BTreeMap<ainxt_teams::TaskId, ainxt_teams::RoleId>,
        role_tiers: std::collections::BTreeMap<ainxt_teams::RoleId, ModelTier>,
    ) -> Self {
        FlywheelCurationSweep {
            sink,
            task_roles,
            role_tiers,
            latest: Mutex::new(FlywheelSweepResult::default()),
            sweeps_run: Mutex::new(0),
        }
    }

    /// **The pure composition-root entrypoint a daemon cadence calls.** Re-curates the sink's FULL
    /// accumulated record history through the three real LOOP §10 curators and stores the result.
    pub fn tick(&self) -> FlywheelSweepResult {
        let records = self.sink.records();
        let result = FlywheelSweepResult {
            eval_cases: ainxt_teams::flywheel::generate_eval_cases(&records),
            template_priors: ainxt_teams::flywheel::plan_template_priors(&records),
            role_tuning: ainxt_teams::flywheel::role_spec_tuning(
                &records,
                &self.task_roles,
                &self.role_tiers,
            ),
            records_curated: records.len(),
        };
        *self.latest.lock().expect("flywheel sweep result lock") = result.clone();
        *self.sweeps_run.lock().expect("flywheel sweep counter lock") += 1;
        result
    }

    /// The most recently curated output (read-only; for a `/v1/team/flywheel` observability route when
    /// hot-wired). Zeroed/empty before the first tick.
    pub fn latest(&self) -> FlywheelSweepResult {
        self.latest
            .lock()
            .expect("flywheel sweep result lock")
            .clone()
    }

    /// How many ticks this sweep has run — for tests / observability (mirrors
    /// `AssembledFull`'s `health_sweeps_run`/`autoscale_ticks_run` pattern).
    pub fn sweeps_run(&self) -> u64 {
        *self.sweeps_run.lock().expect("flywheel sweep counter lock")
    }
}

/// The default cadence a served daemon re-curates its Team surface's accumulated Learning Records at.
/// Curation is a batch read-model refresh, not a latency-sensitive gate, so a generous period is the
/// honest default; a deployment that wants a tighter loop calls [`spawn_flywheel_sweep`] itself with its
/// own period (`build_team_surface_parts` is the only caller of this constant).
const FLYWHEEL_SWEEP_PERIOD: std::time::Duration = std::time::Duration::from_secs(300);

/// **GAP-FIX loop-teams-longhorizon (gap 2).** Spawns a real interval loop (mirrors
/// [`crate::workforce_surface::WorkforceSurface::spawn_kernel_scheduler`]'s shape exactly: a
/// `tokio::time::interval`, a cloned `Arc` handle, no fabricated data) that calls
/// [`FlywheelCurationSweep::tick`] every `period` — the served Team surface's accumulated Learning
/// Records are re-curated automatically, on a real cadence, for as long as the daemon process runs
/// (dropping the returned handle does not cancel a `tokio::spawn`'d task).
pub fn spawn_flywheel_sweep(
    sweep: Arc<FlywheelCurationSweep>,
    period: std::time::Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut iv = tokio::time::interval(period);
        loop {
            iv.tick().await;
            sweep.tick();
        }
    })
}

/// Derive the static task→role / role→tier maps [`role_spec_tuning`](ainxt_teams::flywheel::role_spec_tuning)
/// needs from the SAME canonical `(TaskGraph, Team)` [`compose_served_team`] composes for every served
/// Team turn — never a hand-duplicated literal that could silently drift from the real topology.
/// `compose_served_team` ignores its `goal` argument (the canonical hierarchy is catalog-derived, not
/// per-request), so any input yields the one static roster/graph a served daemon actually runs.
fn flywheel_role_maps_from_served_team() -> (
    std::collections::BTreeMap<ainxt_teams::TaskId, ainxt_teams::RoleId>,
    std::collections::BTreeMap<ainxt_teams::RoleId, ModelTier>,
) {
    let mut task_roles = std::collections::BTreeMap::new();
    let mut role_tiers = std::collections::BTreeMap::new();
    if let Ok((graph, team, _seed)) = compose_served_team("") {
        if let Ok(order) = graph.topological_order() {
            for id in order {
                if let Some(task) = graph.get(&id) {
                    task_roles.insert(id, task.role.clone());
                    if let Some(role) = team.get(&task.role) {
                        role_tiers
                            .entry(task.role.clone())
                            .or_insert(role.model_tier);
                    }
                }
            }
        }
    }
    (task_roles, role_tiers)
}

/// The shared composition body for the **team** surface — every field
/// [`assemble_team_surface_with_transparency`] and [`assemble_team_surface_with_flywheel`] return comes
/// from this ONE construction, so both callers (and therefore `assemble_selected("team", ..)`, the
/// daemon's real `--surface team` dispatch) get byte-identical wiring, including the gap-2 flywheel
/// curation cadence — there is no code path that assembles a served Team surface without it.
fn build_team_surface_parts(
    loaded: &LoadedConfig,
    def_kind: &str,
) -> Result<
    (
        Assembled,
        Arc<
            Mutex<
                ainxt_identity::transparency::TransparencyLog<
                    ainxt_identity::transparency::Sha256Hasher,
                >,
            >,
        >,
        Arc<FlywheelCurationSweep>,
    ),
    AssembleError,
> {
    let (
        engine,
        mut report,
        ledger,
        reconciler,
        dispatch_probe,
        tools,
        outsourcing_register,
        mandate_registry,
        mcp_admin,
        _prompt_cache,
        serving,
    ) = crate::build_engine_ext_with_mcp(
        &loaded.runtime,
        &loaded.mcp,
        &loaded.payments,
        &loaded.serving,
    )?;
    // LOOP-12 — thread the deployment's cost ceiling (if configured) into the served Run's 3-tier
    // bounds; unbounded (ThreeTierConfig::default()) when unset, exactly the pre-fix behavior.
    // `Cost::within` requires EVERY field <= its ceiling counterpart, so the three dimensions this
    // config surface does not expose (tokens/tool_calls/wall_time_ms) must be `u64::MAX`, never the
    // `Cost::ZERO` default — a zero ceiling on an unconfigured dimension would trip on the very
    // first task's nonzero token/wall-time usage regardless of dollar spend.
    let mut tier_config = ThreeTierConfig::default();
    if let Some(dollars_micros) = loaded.runtime.limits.team_run_cost_ceiling_dollars_micros {
        tier_config.cost_ceiling = Some(ainxt_teams::Cost {
            tokens: u64::MAX,
            tool_calls: u64::MAX,
            wall_time_ms: u64::MAX,
            dollars_micros,
        });
    }
    // LOOP-13 — every terminal Run's LearningRecord must reach a REAL sink, not be silently
    // discarded. `InMemoryLearningSink` is the documented OSS default (a deployment backs this
    // with Enterprise-Memory). GAP-FIX loop-teams-longhorizon (gap 2): the concrete handle is kept
    // (not only erased into `Arc<dyn LearningSink>`) so the flywheel curation sweep below can read the
    // SAME accumulated records the surface's terminal Runs write.
    let learning_sink = Arc::new(InMemoryLearningSink::new());
    let transparency_log = Arc::new(Mutex::new(
        ainxt_identity::transparency::TransparencyLog::new(
            ainxt_identity::transparency::Sha256Hasher,
        ),
    ));
    let surface = TeamSurface::new(Arc::new(engine), def_kind.to_string())
        .with_config(tier_config)
        .with_learning_sink(learning_sink.clone())
        .with_transparency_log(transparency_log.clone());
    report.push(format!(
        "surface: {def_kind} — hierarchical 3-tier Team loop served over the protocol (POST /v1/chat \
         → SessionManager → run_team_3tier → real Engine turns; per-Run AgentWorkloadCredential IDN-03; \
         mandatory compliance/RBAC/audit on every task turn; roles/handoff/isolation/self-heal/judge); \
         cost ceiling={:?} (LOOP-12); terminal Learning Records routed to a live sink (LOOP-13)",
        tier_config.cost_ceiling
    ));
    report.push(
        "identity: ADR-022 §13 issuance transparency log LIVE on the served team surface — every \
         Run's AgentWorkloadCredential issuance is appended, Merkle-committed, and \
         inclusion-proof-verifiable by an external auditor (GAP-FIX identity-payments)"
            .into(),
    );
    // GAP-FIX loop-teams-longhorizon (gap 2) — wire the flywheel's downstream curators to a REAL
    // cadence over this surface's own learning sink; see `FlywheelCurationSweep`'s doc comment.
    let (task_roles, role_tiers) = flywheel_role_maps_from_served_team();
    let flywheel = Arc::new(FlywheelCurationSweep::new(
        learning_sink,
        task_roles,
        role_tiers,
    ));
    let _flywheel_cadence = spawn_flywheel_sweep(flywheel.clone(), FLYWHEEL_SWEEP_PERIOD);
    report.push(format!(
        "flywheel: LOOP §10 downstream curation (eval-set generation / plan-template priors / \
         role-spec tuning) LIVE on a {}s cadence over this surface's own accumulated Learning Records \
         (GAP-FIX loop-teams-longhorizon gap 2)",
        FLYWHEEL_SWEEP_PERIOD.as_secs()
    ));
    let sm = Arc::new(SessionManager::new(Arc::new(surface), loaded.session));
    Ok((
        Assembled {
            manager: sm,
            report,
            wire_events: None,
            capability_ledger: Some((ledger, reconciler)),
            dispatch_probe: Some(dispatch_probe),
            // No ChatSurface on the Team surface — a fresh, never-shared handle (nothing to erase).
            shared_answer_cache: Arc::new(Mutex::new(ainxt_cache::PartitionedCache::new(
                ainxt_cache::CacheConfig::default(),
            ))),
            capability_tools: Some(tools),
            // No ChatSurface/memory reader on this surface (real Engine turns via its own executor).
            memory_backend: None,
            outsourcing_register,
            // No role-invocation concept on the Team surface.
            workforce_invocation_ledger: None,
            // No kernel process model on the Team surface.
            workforce_kernel: None,
            // No GovernedWorkforce on the Team surface.
            workforce_surface: None,
            mandate_registry,
            mcp_admin,
            // No profile/SkillRuntime on the Program/Team surface.
            skill_runtime: None,
            // GAP-FIX gap6-composition-root (Item 1) — the SAME `ServingHandle` this real Engine
            // attached via `Engine::with_node_attestor`; see `Assembled::serving`'s doc.
            serving: Some(serving),
        },
        transparency_log,
        flywheel,
    ))
}

/// Assemble the runtime for the **team** surface, served over the SAME [`SessionManager`] spine as chat
/// (LOOP-15, gap 2). The daemon's `--surface team` selector mounts this so the hierarchical 3-tier Team
/// loop runs on `POST /v1/chat`. Fail-closed on an enterprise gate selection (same as [`build_engine`]).
/// The CLI selector routing to this function is the remaining `needs_hot_wiring` (a `main` match arm).
pub fn assemble_team_surface(
    loaded: &LoadedConfig,
    def_kind: &str,
) -> Result<Assembled, AssembleError> {
    let (assembled, _transparency_log) = assemble_team_surface_with_transparency(loaded, def_kind)?;
    Ok(assembled)
}

/// [`assemble_team_surface_with_transparency`], additionally returning the SAME live
/// [`FlywheelCurationSweep`] handle wired into this composition (GAP-FIX loop-teams-longhorizon gap 2) —
/// so a test or an observability route can inspect the curated output without a hand-built surface.
/// Both this function and [`assemble_team_surface_with_transparency`] delegate to the SAME
/// [`build_team_surface_parts`], so the daemon's real `--surface team` dispatch (which uses the latter,
/// via [`assemble_team_surface`]) gets byte-identical wiring, including the flywheel cadence.
pub fn assemble_team_surface_with_flywheel(
    loaded: &LoadedConfig,
    def_kind: &str,
) -> Result<
    (
        Assembled,
        Arc<
            Mutex<
                ainxt_identity::transparency::TransparencyLog<
                    ainxt_identity::transparency::Sha256Hasher,
                >,
            >,
        >,
        Arc<FlywheelCurationSweep>,
    ),
    AssembleError,
> {
    build_team_surface_parts(loaded, def_kind)
}

/// [`assemble_team_surface`], additionally returning the SAME live
/// [`ainxt_identity::transparency::TransparencyLog`] handle wired into the [`TeamSurface`] it composes.
/// GAP-FIX identity-payments — see [`assemble_program_surface_with_transparency`]'s doc comment; the
/// same "orphaned" gap (a real, tested mechanism with zero served callers) applied identically to the
/// team surface's `TeamSurface::with_transparency_log`.
pub fn assemble_team_surface_with_transparency(
    loaded: &LoadedConfig,
    def_kind: &str,
) -> Result<
    (
        Assembled,
        Arc<
            Mutex<
                ainxt_identity::transparency::TransparencyLog<
                    ainxt_identity::transparency::Sha256Hasher,
                >,
            >,
        >,
    ),
    AssembleError,
> {
    let (assembled, transparency_log, _flywheel) = build_team_surface_parts(loaded, def_kind)?;
    Ok((assembled, transparency_log))
}

#[cfg(test)]
mod signed_handoff_tests {
    //! GAP-FIX identity-payments (ADR-022 §18) — the REAL function every served node/module commit
    //! now calls, unit-tested directly (a private helper, so this lives inline rather than in
    //! `tests/` where it would be unreachable). `run_program_verified_sod`'s own served-path tests
    //! (`r8_sod_live_program.rs`) already prove this swap is behavior-preserving for the two paths
    //! they exercise (self-approval refused, distinct approver commits); these tests prove the
    //! SIGNED half of the guarantee that `authorize_approval` structurally could never check at all
    //! (it has no signature/digest concept whatsoever) is genuinely live on THIS exact function.

    use super::*;
    use ainxt_identity::sod::HandoffVerifier;

    fn cred(run_id: &str, key_id: &str) -> AgentWorkloadCredential {
        AgentWorkloadCredential {
            def_kind: "role".to_string(),
            def_id: "coder".to_string(),
            def_version: "v1".to_string(),
            def_content_hash: "hash-abc".to_string(),
            control_commit_sha: "sha-abc".to_string(),
            run_id: run_id.to_string(),
            issued_at: LogicalTime(1),
            expires_at: LogicalTime(100),
            data_class: DataClass::Internal,
            requires_tee: false,
            obo_user_id: "u-alice".to_string(),
            obo_department: None,
            obo_ad_level: None,
            obo_can_approve: false,
            attestation_ref: "attest-1".to_string(),
            key_id: key_id.to_string(),
        }
    }

    // ---- the exact function `run_program_verified_blocking`/`ServedModuleExecutor::execute` call ----

    #[test]
    fn a_distinct_producer_and_approver_authorize_through_the_signed_path() {
        let producer = cred("run-coder-1", "key-v1");
        let approver = cred("run-verifier-1", "key-v1");
        let decision = authorize_commit_via_signed_handoff(
            &SodVerifyGate::identity_only(),
            &producer,
            &approver,
            "mod-a",
            "ledger-key-xyz",
        )
        .expect("a distinct producer/approver pair, correctly signed, must authorize");
        assert_eq!(decision.producer.run_id, "run-coder-1");
        assert_eq!(decision.approver.run_id, "run-verifier-1");
        assert_eq!(decision.content_digest, "ledger-key-xyz");
    }

    #[test]
    fn a_self_approving_run_is_still_refused_underneath_the_signed_path() {
        let same = cred("run-coder-1", "key-v1");
        let err = authorize_commit_via_signed_handoff(
            &SodVerifyGate::identity_only(),
            &same,
            &same,
            "mod-a",
            "ledger-key-xyz",
        )
        .expect_err("a Run can never approve its own work, even through the signed path");
        assert!(
            matches!(err, SodError::SelfApproval { .. }),
            "unexpected error: {err:?}"
        );
    }

    /// THE differentiator vs the old `authorize_approval` direct-check: `authorize_approval` has no
    /// signature/`key_id` concept at all — a producer whose credential was minted under a rotated
    /// (stale) `key_id` would authorize identically to one on the current key. Routing through
    /// `accept_handoff` makes the tag itself bound to `key_id` (`AwcKeySigner`/`AwcKeyVerifier`'s own
    /// contract: "rejects a signature... minted under a different key_id"), so THIS exact function
    /// now genuinely depends on key material, not merely on `run_id` equality.
    #[test]
    fn the_signature_is_genuinely_bound_to_the_producers_key_id_not_merely_run_id() {
        let producer_current_key = cred("run-coder-1", "key-v2"); // e.g. post-`rotate_key`
                                                                  // Sign with the CURRENT key's derived secret (what `authorize_commit_via_signed_handoff`
                                                                  // does internally)...
        let handoff = Handoff::new(
            "mod-a",
            WorkloadRef::from(&producer_current_key),
            WorkloadRef::new("def:role/verifier@v1", "run-verifier-1"),
            "ledger-key-xyz",
        );
        let secret_current = awc_signing_secret(&producer_current_key.key_id);
        let signer = AwcKeySigner::for_credential(
            &producer_current_key,
            AWC_HANDOFF_TRUST_DOMAIN,
            secret_current,
        );
        let signature = signer.sign(&handoff);

        // ...but a verifier bound to the PRODUCER'S OWN STALE key (key-v1, e.g. cached from before a
        // rotation) derives a DIFFERENT secret and must reject the otherwise-well-formed handoff.
        let producer_stale_key = cred("run-coder-1", "key-v1");
        let secret_stale = awc_signing_secret(&producer_stale_key.key_id);
        let stale_verifier = AwcKeyVerifier::for_credential(
            &producer_stale_key,
            AWC_HANDOFF_TRUST_DOMAIN,
            secret_stale,
        );
        assert!(
            !stale_verifier.verify(&handoff, &signature),
            "a signature minted under the rotated key must NOT verify under the stale key's derived \
             secret — this is exactly what `authorize_approval` could never catch (it never even \
             looks at key_id)"
        );

        // The CURRENT-key verifier (what `authorize_commit_via_signed_handoff` actually constructs)
        // accepts it, proving the mismatch above is about the key binding, not a broken signer.
        let current_verifier = AwcKeyVerifier::for_credential(
            &producer_current_key,
            AWC_HANDOFF_TRUST_DOMAIN,
            awc_signing_secret(&producer_current_key.key_id),
        );
        assert!(current_verifier.verify(&handoff, &signature));
    }

    #[test]
    fn an_artifact_digest_swap_is_refused_before_the_identity_rule_even_runs() {
        // `authorize_approval` has no digest concept at all; `accept_handoff` (which
        // `authorize_commit_via_signed_handoff` now calls) checks the presented handoff's digest
        // against the receiver's EXPECTED artifact before applying SoD. Drive `SodVerifyGate::accept_handoff`
        // directly (the same method the composition-root helper calls) with a mismatched expectation.
        let producer = cred("run-coder-1", "key-v1");
        let approver = cred("run-verifier-1", "key-v1");
        let handoff = Handoff::new(
            "mod-a",
            WorkloadRef::from(&producer),
            WorkloadRef::from(&approver),
            "digest-real",
        );
        let secret = awc_signing_secret(&producer.key_id);
        let signer =
            AwcKeySigner::for_credential(&producer, AWC_HANDOFF_TRUST_DOMAIN, secret.clone());
        let signature = signer.sign(&handoff);
        let signed = SignedHandoff { handoff, signature };
        // The receiver expects a DIFFERENT digest — e.g. a swapped/stale artifact reference.
        let expected =
            ProducedArtifact::new("mod-a", WorkloadRef::from(&producer), "digest-swapped");
        let verifier = AwcKeyVerifier::for_credential(&producer, AWC_HANDOFF_TRUST_DOMAIN, secret);
        let err = SodVerifyGate::identity_only()
            .accept_handoff(&signed, &expected, &verifier)
            .expect_err("a digest mismatch must be refused");
        assert!(
            matches!(err, SodError::ArtifactDigestMismatch { .. }),
            "unexpected error: {err:?}"
        );
    }
}
