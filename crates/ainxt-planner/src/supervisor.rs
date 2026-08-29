// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! The **Program Supervisor** execution loop — the orchestrator that actually *runs* a Program.
//!
//! Design: `docs/architecture/LONG_HORIZON_PROGRAMS.md` (ADR-027) §1, §5, §6, §7, §8, §9.
//!
//! [`crate::program`] is the pure, event-sourced *state machine*: it folds events into a
//! [`ProgramState`] and offers pure planners (rollback, quarantine, partial report). What was
//! missing — the gap this module closes (`gap_tracker` LOOP-02) — is the **driver**: the loop that
//! schedules READY nodes, spawns one base-loop Run per module, appends the resulting events,
//! drives per-module → per-edge → sweep verification, enforces the program budget, and gates on
//! staged human checkpoints. That driver lives here.
//!
//! # The injectable seams (why this crate never depends on `ainxt-runtime`)
//!
//! The Supervisor spawns "one ordinary base-loop Run per module" (§5) — but a Run is executed by the
//! runtime Engine, which lives in a reserved crate. So the Engine is injected behind the
//! [`RunExecutor`] trait: the Supervisor decides *what* runs and *when*, calls `execute_module`, and
//! folds the typed result. The three-way verification gate's non-deterministic proofs (the Breaker,
//! the cross-model Judge, the regression suite) are injected behind [`ProgramVerifier`]; human
//! checkpoints behind [`ApprovalGate`]; durable persistence behind [`EventSink`]. Everything the
//! Supervisor itself *decides* is pure and deterministic, so the whole loop is testable end-to-end
//! against fakes (see the tests) — the parent wires the real Engine/Event-Log/Approval-Gate.
//!
//! # What the loop guarantees (each is a test that fails if the logic is gutted)
//!
//! * **It schedules and drives to completion** — READY nodes are executed in deterministic order, one
//!   module at a time, each spawning a Run via the seam; a happy program reaches `Completed` only
//!   through the program `COMPLETED` gate (§6), never on a self-report.
//! * **Budget governance** (§7) — per-Run costs roll up into the program aggregate; crossing 25/50/75%
//!   forces a `CheckpointReview` human gate; crossing 100% is a **hard pause** (`CappedPartial`), never
//!   silent continuation.
//! * **Staged human checkpoints** (§8) — Start, Critical-path (forced human commit regardless of
//!   score), and Budget gates all route through the [`ApprovalGate`] seam; a rejected critical-path
//!   node is `BlockedOnHuman`, never auto-committed.
//! * **Per-module → per-edge → sweep verification** (§6) — a committed node's edges to already-committed
//!   neighbors are integration-verified and a regression sweep runs; a red edge/sweep **re-opens** the
//!   introducing node (rollback), and the program never reaches `Completed` with any red.
//! * **Failure isolation + poison route-around** (§9) — a program-level stuck detector quarantines a
//!   node that fails past the cap and gates its dependents, while independent branches keep running so
//!   the program ships what it can (a deployable `CappedPartial`).
//! * **Durable + resumable** (§4) — every emitted event is appended to the [`EventSink`]; a fresh
//!   projection of the sink equals the live state, and a second `run_program` on the same sink resumes
//!   from exactly where the first stopped (crash/cancel recovery), never re-committing a done node.
//! * **Cancellation** (§8) — a cooperative cancel signal pauses the program between modules; in-flight
//!   commits are never orphaned and the partial is deployable.

use crate::program::{
    build_quarantine_events, project, ChildOutcome, NodeClass, NodeId, NodeState, PoisonPolicy,
    ProgramError, ProgramEvent, ProgramId, ProgramOutcome, ProgramPhase, ProgramState,
};
use crate::verify::{
    program_completed, three_way_gate, AdversarialVerdict, DeterministicVerdict, EdgeVerification,
    GateOutcome, JudgeVerdict, ProgramCompletionInput,
};
use std::collections::{BTreeMap, BTreeSet};

// ---------------------------------------------------------------------------
// Cost & budget (§7)
// ---------------------------------------------------------------------------

/// Rolled-up program cost (§7). Integer micro-dollars keep the aggregate exact and reproducible.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProgramCost {
    pub tokens: u64,
    pub tool_calls: u64,
    pub dollars_micros: u64,
}

impl ProgramCost {
    pub fn new(tokens: u64, tool_calls: u64, dollars_micros: u64) -> Self {
        ProgramCost {
            tokens,
            tool_calls,
            dollars_micros,
        }
    }
    /// Overflow-safe roll-up — the aggregate can never wrap and defeat the budget ceiling.
    pub fn saturating_add(self, o: ProgramCost) -> ProgramCost {
        ProgramCost {
            tokens: self.tokens.saturating_add(o.tokens),
            tool_calls: self.tool_calls.saturating_add(o.tool_calls),
            dollars_micros: self.dollars_micros.saturating_add(o.dollars_micros),
        }
    }
}

/// The program budget — a hard ceiling **above** the per-Run budget (§7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgramBudget {
    pub token_ceiling: u64,
    pub dollar_ceiling_micros: u64,
}

impl ProgramBudget {
    pub fn new(token_ceiling: u64, dollar_ceiling_micros: u64) -> Self {
        ProgramBudget {
            token_ceiling,
            dollar_ceiling_micros,
        }
    }

    /// An effectively-unbounded budget (for programs that gate on other constraints).
    pub fn unbounded() -> Self {
        ProgramBudget {
            token_ceiling: u64::MAX,
            dollar_ceiling_micros: u64::MAX,
        }
    }

    /// Percent (0..=100+, saturating) of the *tighter* of the two ceilings consumed so far. Integer
    /// arithmetic — no float drift. A zeroed ceiling is treated as already-full (100).
    pub fn percent_used(&self, spent: ProgramCost) -> u32 {
        let tok = pct(spent.tokens, self.token_ceiling);
        let usd = pct(spent.dollars_micros, self.dollar_ceiling_micros);
        tok.max(usd)
    }

    /// True once the aggregate has crossed 100% of either ceiling (§7 hard pause).
    pub fn is_exhausted(&self, spent: ProgramCost) -> bool {
        spent.tokens > self.token_ceiling || spent.dollars_micros > self.dollar_ceiling_micros
    }
}

fn pct(used: u64, ceiling: u64) -> u32 {
    if ceiling == 0 {
        return 100;
    }
    let p = (used as u128).saturating_mul(100) / (ceiling as u128);
    p.min(1000) as u32
}

/// The staged budget-threshold gates that force a `CheckpointReview` (§7).
pub const BUDGET_THRESHOLDS: [u32; 3] = [25, 50, 75];

// ---------------------------------------------------------------------------
// Seams
// ---------------------------------------------------------------------------

/// Context handed to the [`RunExecutor`] for one module Run (§5 interface-not-implementation). The
/// Supervisor never assembles code context itself; it hands the Engine exactly what identifies the
/// module + its scheduling state, and the Engine's Context Optimizer does the rest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleRunContext {
    pub program_id: ProgramId,
    pub node: NodeId,
    pub node_class: NodeClass,
    pub goal: String,
    /// 0-based attempt counter for this node (drives self-heal escalation on the Engine side).
    pub attempt: u32,
    /// For a `child-program` node: whether its nested Program has already resolved `Completed`, so
    /// the Engine now runs the node's own (post-child) work rather than re-spawning the child.
    pub child_resolved: bool,
}

/// What the injected base-loop Run reports for one module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModuleRunResult {
    /// The Run produced edits and the three per-module verification verdicts (§6.1). The Supervisor
    /// combines them through the same [`three_way_gate`] the design mandates — the Engine never
    /// self-declares "done".
    Ran {
        det: DeterministicVerdict,
        adv: AdversarialVerdict,
        judge: JudgeVerdict,
        commit_shas: Vec<String>,
        /// Side-Effect Ledger key = f(program, node, edit-hash) — the §4 idempotency key.
        ledger_key: String,
        by_model: String,
        cost: ProgramCost,
    },
    /// The Run failed to produce a usable result (crash / timeout / per-Run cap). Bulkhead-isolated.
    Failed { reason: String, cost: ProgramCost },
    /// A `child-program` node's nested Program ran to a terminal outcome (§4). The seam abstracts the
    /// nested Supervisor; the parent maps the outcome deterministically.
    ChildProgram {
        child_program_id: ProgramId,
        outcome: ChildOutcome,
        cost: ProgramCost,
    },
}

/// The base-loop Run seam (§5): the parent injects the real Engine here. The Supervisor decides
/// *what* module runs and *when*; `execute_module` runs one bounded Run scoped to that module.
pub trait RunExecutor {
    fn execute_module(&mut self, ctx: &ModuleRunContext) -> ModuleRunResult;
}

/// The program-scale verification seam (§6.2/§6.3): per-edge integration + regression sweep +
/// the independent program-level Judge. These are the non-deterministic proofs the Supervisor
/// cannot compute itself; a fake makes the whole loop testable offline.
pub trait ProgramVerifier {
    /// Integration verdict for the seam between a just-committed node and an already-committed
    /// neighbor (§6.2).
    fn verify_edge(&mut self, committed: &NodeId, neighbor: &NodeId) -> GateOutcome;
    /// The program-wide regression sweep over all committed work (§6.3).
    fn regression_sweep(&mut self, committed: &[NodeId]) -> GateOutcome;
    /// The independent, cross-model program-level Judge (§6(d)).
    fn program_judge(&mut self) -> JudgeVerdict;

    /// gap loop-teams-longhorizon (item 4, rollback mock-only): the REAL side effect of a §9
    /// single-module rollback — revert `commit_shas` and run the node's saga compensation (e.g.
    /// un-create its MR, `TOOLING §1.3`). Before this method existed, [`crate::program::Compensator`]
    /// / [`crate::program::execute_rollback`] were the ONLY rollback-side-effect abstraction in the
    /// codebase, had exactly ONE implementor anywhere (a `HalfBrokenComp` test fake in
    /// `program.rs`'s own unit tests), and neither `driver::verified_loop` nor `supervisor::run_program`
    /// ever called them: both drivers only emitted the `RolledBack` STATE transition, so a "rolled
    /// back" node's actual git commit was never reverted and its MR never un-created — the durable
    /// state machine believed the world had been undone while the real world was untouched.
    ///
    /// Default is a no-op success — existing [`ProgramVerifier`] implementors (tests, fakes) are
    /// unaffected; a deployment that wants a REAL rollback side effect overrides this with a live
    /// compensator (e.g. a real `git revert` + MR-close call). Returning `Err` reports an honest
    /// `non_compensable` step (§9 `FAILED_PARTIAL` — surfaced, never silently swallowed); the caller
    /// still completes the STATE-level rollback so the node remains schedulable, but records which
    /// commit could not actually be undone.
    fn compensate(&mut self, node: &NodeId, commit_shas: &[String]) -> Result<(), String> {
        let _ = (node, commit_shas);
        Ok(())
    }
}

/// A staged human checkpoint (§8), routed through the existing Approval Gate seam.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    pub reason: CheckpointReason,
    pub node: Option<NodeId>,
    pub detail: String,
}

/// The §8 checkpoint classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointReason {
    /// Approve the MTG + strategy + budget before any code.
    Start,
    /// A budget threshold was crossed (§7).
    Budget(u32),
    /// A node touching a settlement/ledger/compliance-tagged module (§8 critical-path).
    CriticalPath,
    /// An auto-raised anomaly gate (a poison quarantine, an estimate blowout).
    Anomaly,
}

/// The human's decision at a checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalDecision {
    Approve,
    /// Do not proceed with *this* node/gate, but keep the program running elsewhere.
    Reject,
    /// Stop the whole program (→ `ABANDONED`).
    Abandon,
}

/// The human-checkpoint seam (§8) — the existing Approval Gate, injected.
pub trait ApprovalGate {
    fn request(&mut self, checkpoint: &Checkpoint) -> ApprovalDecision;
}

/// An [`ApprovalGate`] that approves everything — for fully-autonomous programs / tests with no
/// human in the loop. Named honestly so its use is a deliberate choice.
pub struct AutoApprove;
impl ApprovalGate for AutoApprove {
    fn request(&mut self, _c: &Checkpoint) -> ApprovalDecision {
        ApprovalDecision::Approve
    }
}

/// The durable-persistence seam (§4). The parent backs this with the hash-chained runtime Event Log;
/// the Supervisor appends every emitted event so program state survives restarts and a resume is a
/// projection of the log.
pub trait EventSink {
    /// Append one event, returning its new offset. An error aborts the Supervisor (never a silent
    /// lost write — durability is load-bearing).
    fn append(&mut self, ev: &ProgramEvent) -> Result<u64, String>;
    /// Load the full event stream (for projection / resume).
    fn load(&self) -> Result<Vec<ProgramEvent>, String>;
}

/// An in-memory [`EventSink`] — the deterministic backing used by tests and by callers that persist
/// out-of-band. Real durability is the `ainxt-eventlog` wiring (reported as `needs_wiring`).
#[derive(Debug, Clone, Default)]
pub struct VecEventSink {
    events: Vec<ProgramEvent>,
}

impl VecEventSink {
    pub fn new() -> Self {
        VecEventSink::default()
    }
    pub fn events(&self) -> &[ProgramEvent] {
        &self.events
    }
    pub fn len(&self) -> usize {
        self.events.len()
    }
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

impl EventSink for VecEventSink {
    fn append(&mut self, ev: &ProgramEvent) -> Result<u64, String> {
        self.events.push(ev.clone());
        Ok(self.events.len() as u64)
    }
    fn load(&self) -> Result<Vec<ProgramEvent>, String> {
        Ok(self.events.clone())
    }
}

// ---------------------------------------------------------------------------
// Config & report
// ---------------------------------------------------------------------------

/// Deterministic caps for the Supervisor loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SupervisorConfig {
    pub budget: ProgramBudget,
    /// Program-level poison cap (§9): attempts (of any failure kind) before a node is quarantined.
    pub poison: PoisonPolicy,
    /// A hard bound on total scheduling iterations — a last-resort guard so a pathological seam can
    /// never spin forever (defense-in-depth beyond the poison cap).
    pub max_iterations: usize,
}

impl Default for SupervisorConfig {
    fn default() -> Self {
        SupervisorConfig {
            budget: ProgramBudget::unbounded(),
            poison: PoisonPolicy::default(),
            max_iterations: 100_000,
        }
    }
}

/// Why the Supervisor stopped, for the honest report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    /// Nothing left to schedule; the program terminal gate decided the outcome.
    Drained,
    /// The budget hard ceiling was crossed (§7).
    BudgetExhausted,
    /// A cancel signal fired between modules (§8).
    Cancelled,
    /// A human chose `Abandon` at a checkpoint (§8).
    Abandoned,
    /// The iteration guard tripped (should never happen with a finite poison cap).
    IterationGuard,
}

/// The outcome of a Supervisor run.
#[derive(Debug, Clone)]
pub struct SupervisorReport {
    pub program_id: ProgramId,
    /// The terminal program outcome recorded on the log.
    pub outcome: ProgramOutcome,
    /// The program `COMPLETED` gate verdict (§6) — `Complete` iff every clause is green.
    pub gate: GateOutcome,
    pub stop_reason: StopReason,
    pub total_cost: ProgramCost,
    pub final_state: ProgramState,
    /// The §8 deployable partial-completion report.
    pub partial: crate::program::PartialCompletionReport,
}

// ---------------------------------------------------------------------------
// The driver
// ---------------------------------------------------------------------------

/// Run a Program to a terminal outcome, driving the seams (§1/§5/§6/§7/§8/§9).
///
/// `sink` **is** the durable log: the seed events (`Created` + `Decomposed`, and optionally
/// `Approved`) must already be appended to it. The Supervisor loads + projects it, runs the loop
/// appending every new event, and returns the terminal report. Calling `run_program` again on the
/// same `sink` **resumes** from exactly where a previous call stopped (crash/cancel recovery) — no
/// node is re-committed (§4 idempotent resume).
///
/// `cancel` is polled once **before** each module; the first `true` pauses the program between
/// modules (§8 cooperative cancellation) and produces a deployable partial.
#[allow(clippy::too_many_arguments)]
pub fn run_program(
    sink: &mut dyn EventSink,
    executor: &mut dyn RunExecutor,
    verifier: &mut dyn ProgramVerifier,
    gate: &mut dyn ApprovalGate,
    config: SupervisorConfig,
    cancel: &mut dyn FnMut() -> bool,
) -> Result<SupervisorReport, ProgramError> {
    let seed = sink.load().map_err(|_| ProgramError::NotCreated)?;
    let mut state = project(&seed)?;
    let program_id = state.program_id.clone();

    // A durable emit: append to the log first, then advance the projection. A failed append is
    // surfaced immediately (fail-fast) so the projection can never diverge from the durable log —
    // the log is load-bearing and a lost write is never swallowed.
    macro_rules! emit {
        ($ev:expr) => {{
            let ev = $ev;
            sink.append(&ev).map_err(sink_error)?;
            state.apply_event(&ev)?;
        }};
    }

    // Per-node attempt counter — the program-level stuck detector (§9), independent of the durable
    // failure_count so edge/sweep re-opens are also bounded.
    let mut attempts: BTreeMap<NodeId, u32> = BTreeMap::new();
    // Latest integration verdict per edge (overwrites stale reds after a re-commit).
    let mut edges: BTreeMap<(NodeId, NodeId), GateOutcome> = BTreeMap::new();
    // Child-program nodes whose nested Program has resolved `Completed`.
    let mut child_resolved: BTreeSet<NodeId> = BTreeSet::new();
    let mut budget_gates_fired: BTreeSet<u32> = BTreeSet::new();
    let mut total_cost = ProgramCost::default();

    let cap = config.poison.max_failures;
    let mut stop = StopReason::Drained;

    // Start checkpoint (§8): approve the MTG before any code.
    if state.phase == ProgramPhase::Decomposed {
        match gate.request(&Checkpoint {
            reason: CheckpointReason::Start,
            node: None,
            detail: "approve MTG + strategy + budget before any code".into(),
        }) {
            ApprovalDecision::Approve => emit!(ProgramEvent::Approved {
                approver: "approval-gate".into(),
            }),
            ApprovalDecision::Reject | ApprovalDecision::Abandon => {
                emit!(ProgramEvent::Outcome {
                    outcome: ProgramOutcome::Abandoned,
                });
                return finish(program_id, state, StopReason::Abandoned, total_cost);
            }
        }
    }

    // Resume: a program paused by a prior cancel / budget-hold comes back to Running (§7).
    if state.phase == ProgramPhase::Paused {
        emit!(ProgramEvent::Resumed);
    }

    let mut iterations = 0usize;
    loop {
        iterations += 1;
        if iterations > config.max_iterations {
            stop = StopReason::IterationGuard;
            break;
        }

        if cancel() {
            emit!(ProgramEvent::Paused);
            stop = StopReason::Cancelled;
            break;
        }

        let ready = state.schedulable_nodes();
        let Some(node) = ready.into_iter().next() else {
            break; // drained
        };
        let node_class = state.nodes[&node].node_class;
        let checkpoint_class = state.nodes[&node].checkpoint_class;

        // §9 program-level stuck detector: quarantine a node that failed past the cap, route around.
        if attempts.get(&node).copied().unwrap_or(0) >= cap {
            // Anomaly checkpoint with the evidence trail (§8) — advisory; we quarantine regardless.
            let _ = gate.request(&Checkpoint {
                reason: CheckpointReason::Anomaly,
                node: Some(node.clone()),
                detail: format!("poison node quarantined after {cap} failed attempts"),
            });
            for ev in build_quarantine_events(&state, &node) {
                emit!(ev);
            }
            continue;
        }

        // Critical-path checkpoint (§8): forced human commit regardless of score.
        if checkpoint_class == crate::program::CheckpointClass::CriticalPath {
            match gate.request(&Checkpoint {
                reason: CheckpointReason::CriticalPath,
                node: Some(node.clone()),
                detail: "critical-path module: human approval required regardless of score".into(),
            }) {
                ApprovalDecision::Approve => {}
                ApprovalDecision::Reject => {
                    emit!(ProgramEvent::NodeStateChanged {
                        node: node.clone(),
                        to: NodeState::BlockedOnHuman,
                        cause: "critical-path checkpoint rejected".into(),
                    });
                    continue;
                }
                ApprovalDecision::Abandon => {
                    emit!(ProgramEvent::Outcome {
                        outcome: ProgramOutcome::Abandoned,
                    });
                    stop = StopReason::Abandoned;
                    break;
                }
            }
        }

        // Budget threshold gate (§7): fire once per crossed 25/50/75% band, before spending more.
        let used_pct = config.budget.percent_used(total_cost);
        for th in BUDGET_THRESHOLDS {
            if used_pct >= th && !budget_gates_fired.contains(&th) {
                budget_gates_fired.insert(th);
                emit!(ProgramEvent::CheckpointReviewOpened {
                    reason: format!("budget threshold {th}% crossed"),
                });
                match gate.request(&Checkpoint {
                    reason: CheckpointReason::Budget(th),
                    node: None,
                    detail: format!("{used_pct}% of program budget consumed; continue?"),
                }) {
                    ApprovalDecision::Approve => emit!(ProgramEvent::Resumed),
                    ApprovalDecision::Reject => {
                        emit!(ProgramEvent::Paused);
                        stop = StopReason::BudgetExhausted;
                        break;
                    }
                    ApprovalDecision::Abandon => {
                        emit!(ProgramEvent::Outcome {
                            outcome: ProgramOutcome::Abandoned,
                        });
                        stop = StopReason::Abandoned;
                        break;
                    }
                }
            }
        }
        if matches!(stop, StopReason::BudgetExhausted | StopReason::Abandoned) {
            break;
        }

        // Budget hard ceiling (§7): crossing 100% is a hard pause, never silent continuation.
        if config.budget.is_exhausted(total_cost) {
            emit!(ProgramEvent::Paused);
            stop = StopReason::BudgetExhausted;
            break;
        }

        // Execute: Ready → InProgress, then spawn the base-loop Run via the seam.
        let attempt = attempts.get(&node).copied().unwrap_or(0);
        emit!(ProgramEvent::NodeStateChanged {
            node: node.clone(),
            to: NodeState::InProgress,
            cause: "supervisor: scheduled module Run".into(),
        });

        let ctx = ModuleRunContext {
            program_id: program_id.clone(),
            node: node.clone(),
            node_class,
            goal: state.goal.clone(),
            attempt,
            child_resolved: child_resolved.contains(&node),
        };

        match executor.execute_module(&ctx) {
            ModuleRunResult::Ran {
                det,
                adv,
                judge,
                commit_shas,
                ledger_key,
                by_model,
                cost,
            } => {
                total_cost = total_cost.saturating_add(cost);
                let outcome = three_way_gate(&det, &adv, &judge);
                if outcome.is_complete() {
                    emit!(ProgramEvent::NodeStateChanged {
                        node: node.clone(),
                        to: NodeState::Verifying,
                        cause: "per-module gate green".into(),
                    });
                    emit!(ProgramEvent::NodeStateChanged {
                        node: node.clone(),
                        to: NodeState::Verified,
                        cause: "three-way gate complete".into(),
                    });
                    emit!(ProgramEvent::NodeCommitted {
                        node: node.clone(),
                        commit_shas,
                        ledger_key,
                        by_model,
                    });

                    // §6.2 per-edge integration against already-committed neighbors.
                    let committed: BTreeSet<NodeId> =
                        state.committed_node_ids().into_iter().collect();
                    let mut neighbors: BTreeSet<NodeId> = BTreeSet::new();
                    for d in &state.nodes[&node].deps {
                        if committed.contains(d) {
                            neighbors.insert(d.clone());
                        }
                    }
                    for d in state.direct_dependents(&node) {
                        if committed.contains(&d) {
                            neighbors.insert(d);
                        }
                    }
                    let mut red = false;
                    for nb in &neighbors {
                        let eo = verifier.verify_edge(&node, nb);
                        if !eo.is_complete() {
                            red = true;
                        }
                        edges.insert((node.clone(), nb.clone()), eo);
                    }

                    // §6.3 regression sweep over all committed work.
                    let committed_ids: Vec<NodeId> = committed.iter().cloned().collect();
                    let sweep = verifier.regression_sweep(&committed_ids);
                    if !sweep.is_complete() {
                        red = true;
                    }

                    if red {
                        // Re-open the introducing node (rollback); bounded by the poison cap.
                        *attempts.entry(node.clone()).or_insert(0) += 1;
                        // gap loop-teams-longhorizon (item 4, rollback mock-only): run the REAL
                        // compensation side effect (git revert / MR un-create) BEFORE the durable
                        // state transition — previously this branch only ever emitted `RolledBack`
                        // (a state change), and no driver anywhere called `ProgramVerifier::compensate`
                        // or `crate::program::Compensator`, so a "rolled back" node's actual commit was
                        // never reverted in the real world. A non-compensable step is surfaced as an
                        // Anomaly checkpoint (§9 `FAILED_PARTIAL` — honest, never silently dropped);
                        // the state-level rollback still proceeds so the node remains schedulable.
                        let shas: Vec<String> = state
                            .nodes
                            .get(&node)
                            .map(|n| n.commit_shas.clone())
                            .unwrap_or_default();
                        if let Err(reason) = verifier.compensate(&node, &shas) {
                            let _ = gate.request(&Checkpoint {
                                reason: CheckpointReason::Anomaly,
                                node: Some(node.clone()),
                                detail: format!(
                                    "rollback compensation could not complete (FAILED_PARTIAL): {reason}"
                                ),
                            });
                        }
                        emit!(ProgramEvent::RolledBack { node: node.clone() });
                    } else {
                        emit!(ProgramEvent::Checkpoint {
                            offset: state.event_offset,
                        });
                    }
                } else {
                    // Per-module gate failed: attempt failed, node re-opens (bounded).
                    *attempts.entry(node.clone()).or_insert(0) += 1;
                    emit!(ProgramEvent::NodeAttemptFailed {
                        node: node.clone(),
                        reason: format!("per-module gate: {outcome}"),
                    });
                }
            }

            ModuleRunResult::Failed { reason, cost } => {
                total_cost = total_cost.saturating_add(cost);
                *attempts.entry(node.clone()).or_insert(0) += 1;
                emit!(ProgramEvent::NodeAttemptFailed {
                    node: node.clone(),
                    reason,
                });
            }

            ModuleRunResult::ChildProgram {
                child_program_id,
                outcome,
                cost,
            } => {
                total_cost = total_cost.saturating_add(cost);
                emit!(ProgramEvent::ChildProgramSpawned {
                    node: node.clone(),
                    child_program_id,
                });
                emit!(ProgramEvent::ChildProgramOutcomeMapped {
                    node: node.clone(),
                    outcome,
                });
                if outcome == ChildOutcome::Completed {
                    // §4: Completed re-opens the parent node (Ready) to resume its own work.
                    child_resolved.insert(node.clone());
                }
                // CappedPartial/Abandoned → BlockedOnHuman (not schedulable), loop moves on.
            }
        }
    }

    // Terminal decision (§6/§8). Only a *drained* program is written to a terminal `Outcome`:
    //   - Drained  → the program COMPLETED gate decides `Completed` vs `CappedPartial` (terminal).
    //   - Abandoned → the terminal `Outcome(Abandoned)` was already emitted at the checkpoint.
    //   - Cancelled / BudgetExhausted / IterationGuard → the program stays **Paused** (resumable,
    //     §7/§8) — a deliberately *non-terminal* honest partial the caller can resume later.
    if state.phase.is_terminal() {
        return finish(program_id, state, stop, total_cost);
    }

    let gate_outcome = program_completed_from_state(&state, &edges, verifier);
    if matches!(stop, StopReason::Drained) {
        let outcome = if gate_outcome.is_complete() {
            ProgramOutcome::Completed
        } else {
            ProgramOutcome::CappedPartial
        };
        match sink.append(&ProgramEvent::Outcome { outcome }) {
            Ok(_) => state.apply_event(&ProgramEvent::Outcome { outcome })?,
            Err(e) => return Err(sink_error(e)),
        }
        return Ok(SupervisorReport {
            program_id,
            outcome,
            gate: gate_outcome,
            stop_reason: stop,
            total_cost,
            partial: crate::program::partial_report(&state),
            final_state: state,
        });
    }

    // Paused (resumable) exit: report an honest CappedPartial without sealing the log.
    Ok(SupervisorReport {
        program_id,
        outcome: ProgramOutcome::CappedPartial,
        gate: GateOutcome::Capped {
            reason: format!("{stop:?}"),
        },
        stop_reason: stop,
        total_cost,
        partial: crate::program::partial_report(&state),
        final_state: state,
    })
}

/// Build the §6 program `COMPLETED` gate input from the final durable state + collected edge verdicts,
/// then evaluate it. Leaf outcomes are derived from the **final committed state** (not the transient
/// per-module verdict), so a node that committed then rolled back correctly reads as not-complete.
fn program_completed_from_state(
    state: &ProgramState,
    edges: &BTreeMap<(NodeId, NodeId), GateOutcome>,
    verifier: &mut dyn ProgramVerifier,
) -> GateOutcome {
    let all_leaves: BTreeSet<NodeId> = state.order.iter().cloned().collect();
    let mut leaf_outcomes: BTreeMap<NodeId, GateOutcome> = BTreeMap::new();
    for id in &state.order {
        let oc = match state.nodes.get(id).map(|n| n.state) {
            Some(NodeState::Committed) => GateOutcome::Complete,
            other => GateOutcome::Blocked {
                reasons: vec![format!("node state {other:?}")],
            },
        };
        leaf_outcomes.insert(id.clone(), oc);
    }
    let edge_outcomes: Vec<EdgeVerification> = edges
        .iter()
        .map(|((f, t), o)| EdgeVerification::new(f.clone(), t.clone(), o.clone()))
        .collect();
    let committed: Vec<NodeId> = state.committed_node_ids();
    let final_sweep = verifier.regression_sweep(&committed);
    let program_judge = verifier.program_judge();
    let input = ProgramCompletionInput {
        all_leaves: &all_leaves,
        leaf_outcomes: &leaf_outcomes,
        edge_outcomes: &edge_outcomes,
        final_sweep_green: final_sweep.is_complete(),
        program_judge: &program_judge,
    };
    program_completed(&input)
}

fn finish(
    program_id: ProgramId,
    state: ProgramState,
    stop: StopReason,
    total_cost: ProgramCost,
) -> Result<SupervisorReport, ProgramError> {
    let outcome = match state.phase {
        ProgramPhase::Completed => ProgramOutcome::Completed,
        ProgramPhase::Abandoned => ProgramOutcome::Abandoned,
        _ => ProgramOutcome::CappedPartial,
    };
    let gate = if outcome == ProgramOutcome::Completed {
        GateOutcome::Complete
    } else {
        GateOutcome::Capped {
            reason: format!("{stop:?}"),
        }
    };
    Ok(SupervisorReport {
        program_id,
        outcome,
        gate,
        stop_reason: stop,
        total_cost,
        partial: crate::program::partial_report(&state),
        final_state: state,
    })
}

fn sink_error(e: String) -> ProgramError {
    // The durable log is load-bearing; a lost append is surfaced, never swallowed. We map it onto
    // the closest structural error so the caller sees an aborted, non-diverged run.
    ProgramError::WrongPhase {
        event: format!("event-sink append failed: {e}"),
        phase: ProgramPhase::Running,
    }
}

// ===========================================================================
// Tests — the Supervisor is driven end-to-end over fakes.
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::{CheckpointClass, NodeDecl};

    fn nid(s: &str) -> NodeId {
        NodeId::new(s)
    }

    fn seed(sink: &mut VecEventSink, nodes: Vec<NodeDecl>) {
        sink.append(&ProgramEvent::Created {
            program_id: ProgramId::new("prog"),
            goal: "migrate the switch".into(),
        })
        .unwrap();
        sink.append(&ProgramEvent::Decomposed { nodes }).unwrap();
    }

    fn chain() -> Vec<NodeDecl> {
        vec![
            NodeDecl::new("a", NodeClass::MigrationRun),
            NodeDecl::new("b", NodeClass::MigrationRun).depends_on("a"),
            NodeDecl::new("c", NodeClass::MigrationRun).depends_on("b"),
        ]
    }

    /// A verifier whose edges + sweep are always green and whose program Judge passes cross-model.
    struct GreenVerifier;
    impl ProgramVerifier for GreenVerifier {
        fn verify_edge(&mut self, _c: &NodeId, _n: &NodeId) -> GateOutcome {
            GateOutcome::Complete
        }
        fn regression_sweep(&mut self, _c: &[NodeId]) -> GateOutcome {
            GateOutcome::Complete
        }
        fn program_judge(&mut self) -> JudgeVerdict {
            JudgeVerdict::pass(95, 80, "qwen", "glm")
        }
    }

    /// An executor that commits every module cleanly, cross-model, at a fixed per-module cost.
    struct HappyExecutor {
        cost: ProgramCost,
    }
    impl RunExecutor for HappyExecutor {
        fn execute_module(&mut self, ctx: &ModuleRunContext) -> ModuleRunResult {
            ModuleRunResult::Ran {
                det: DeterministicVerdict::green(),
                adv: AdversarialVerdict::green(20),
                judge: JudgeVerdict::pass(90, 80, "qwen", "glm"),
                commit_shas: vec![format!("sha-{}", ctx.node)],
                ledger_key: format!("k-{}-{}", ctx.node, ctx.attempt),
                by_model: "qwen".into(),
                cost: self.cost,
            }
        }
    }

    fn no_cancel() -> impl FnMut() -> bool {
        || false
    }

    // ---- LOOP-02: the loop schedules, runs, verifies, and completes -------

    #[test]
    fn gap_loop_02_supervisor_runs_a_program_to_completion() {
        let mut sink = VecEventSink::new();
        seed(&mut sink, chain());
        let mut exec = HappyExecutor {
            cost: ProgramCost::new(100, 1, 1_000),
        };
        let mut ver = GreenVerifier;
        let mut gate = AutoApprove;

        let report = run_program(
            &mut sink,
            &mut exec,
            &mut ver,
            &mut gate,
            SupervisorConfig::default(),
            &mut no_cancel(),
        )
        .unwrap();

        assert_eq!(report.outcome, ProgramOutcome::Completed);
        assert!(report.gate.is_complete());
        assert_eq!(report.stop_reason, StopReason::Drained);
        // Every node committed, in dependency order.
        assert_eq!(
            report.final_state.committed_node_ids(),
            vec![nid("a"), nid("b"), nid("c")]
        );
        assert!(report.final_state.committed_is_dependency_closed());
        // Cost rolled up across the three module Runs (§7).
        assert_eq!(report.total_cost, ProgramCost::new(300, 3, 3_000));
        // The Approved event was emitted by the Start gate, phase is terminal Completed.
        assert_eq!(report.final_state.phase, ProgramPhase::Completed);
    }

    // ---- LOOP-06: durable persistence + resume ---------------------------

    #[test]
    fn gap_loop_06_projecting_the_sink_equals_live_state_and_resume_is_noop() {
        let mut sink = VecEventSink::new();
        seed(&mut sink, chain());
        let mut exec = HappyExecutor {
            cost: ProgramCost::new(10, 0, 0),
        };
        let report = run_program(
            &mut sink,
            &mut exec,
            &mut GreenVerifier,
            &mut AutoApprove,
            SupervisorConfig::default(),
            &mut no_cancel(),
        )
        .unwrap();

        // A fresh projection of the durable log equals the live state (durable == authoritative).
        let replayed = project(&sink.load().unwrap()).unwrap();
        assert_eq!(replayed, report.final_state);
        assert_eq!(replayed.head_hash, report.final_state.head_hash);

        // Resume: re-running on the same (terminal) sink is a no-op — no double commit, same state.
        let before = sink.len();
        let report2 = run_program(
            &mut sink,
            &mut exec,
            &mut GreenVerifier,
            &mut AutoApprove,
            SupervisorConfig::default(),
            &mut no_cancel(),
        )
        .unwrap();
        assert_eq!(report2.outcome, ProgramOutcome::Completed);
        assert_eq!(
            sink.len(),
            before,
            "a terminal program appends nothing on resume"
        );
    }

    #[test]
    fn gap_loop_06_a_cancelled_program_resumes_from_its_checkpoint() {
        // Cancel after the first module, then resume on the SAME sink and finish.
        let mut sink = VecEventSink::new();
        seed(&mut sink, chain());
        let mut exec = HappyExecutor {
            cost: ProgramCost::new(1, 0, 0),
        };
        let mut fired = 0u32;
        let mut cancel_after_one = move || {
            fired += 1;
            fired > 1 // false on the first poll, true afterwards
        };
        let r1 = run_program(
            &mut sink,
            &mut exec,
            &mut GreenVerifier,
            &mut AutoApprove,
            SupervisorConfig::default(),
            &mut cancel_after_one,
        )
        .unwrap();
        assert_eq!(r1.stop_reason, StopReason::Cancelled);
        assert_eq!(r1.outcome, ProgramOutcome::CappedPartial);
        // Exactly one module committed before the cancel.
        assert_eq!(r1.final_state.committed_node_ids(), vec![nid("a")]);
        // The cancelled run left a Paused (non-terminal) program on the log; but partial reports the
        // committed subset honestly and it is deployable.
        assert!(r1.partial.committed.contains(&nid("a")));

        // Resume from the persisted log and drive to completion.
        // (The Paused state is non-terminal, so a fresh run continues scheduling.)
        let r2 = run_program(
            &mut sink,
            &mut exec,
            &mut GreenVerifier,
            &mut AutoApprove,
            SupervisorConfig::default(),
            &mut no_cancel(),
        )
        .unwrap();
        assert_eq!(r2.outcome, ProgramOutcome::Completed);
        assert_eq!(
            r2.final_state.committed_node_ids(),
            vec![nid("a"), nid("b"), nid("c")]
        );
        // `a` was NOT re-committed (idempotent resume): its ledger key appears once.
        let a_commits = sink
            .events()
            .iter()
            .filter(|e| matches!(e, ProgramEvent::NodeCommitted { node, .. } if node == &nid("a")))
            .count();
        assert_eq!(a_commits, 1);
    }

    // ---- LOOP-07: budget governance + staged checkpoints -----------------

    #[test]
    fn gap_loop_07_crossing_the_hard_budget_ceiling_pauses_the_program() {
        // 3 nodes at 100 tokens; ceiling 150 -> after 2 commits (200) the hard ceiling is crossed.
        let mut sink = VecEventSink::new();
        seed(&mut sink, chain());
        let mut exec = HappyExecutor {
            cost: ProgramCost::new(100, 0, 0),
        };
        let cfg = SupervisorConfig {
            budget: ProgramBudget::new(150, u64::MAX),
            ..SupervisorConfig::default()
        };
        let report = run_program(
            &mut sink,
            &mut exec,
            &mut GreenVerifier,
            &mut AutoApprove,
            cfg,
            &mut no_cancel(),
        )
        .unwrap();

        assert_eq!(report.stop_reason, StopReason::BudgetExhausted);
        assert_eq!(report.outcome, ProgramOutcome::CappedPartial);
        // The program did NOT complete every node — it hard-paused.
        assert!(report.final_state.committed_node_ids().len() < 3);
        // The committed subset is still deployable (§8).
        assert!(report.partial.committed_deployable);
    }

    #[test]
    fn gap_loop_07_a_budget_threshold_forces_a_checkpoint_review_gate() {
        // Ceiling 400; each node 100 -> 25% after node 1, 50% after node 2, 75% after node 3.
        // Record which budget gates the human saw.
        struct RecordingGate {
            seen: Vec<CheckpointReason>,
        }
        impl ApprovalGate for RecordingGate {
            fn request(&mut self, c: &Checkpoint) -> ApprovalDecision {
                self.seen.push(c.reason);
                ApprovalDecision::Approve
            }
        }
        let mut sink = VecEventSink::new();
        seed(&mut sink, chain());
        let mut exec = HappyExecutor {
            cost: ProgramCost::new(100, 0, 0),
        };
        let cfg = SupervisorConfig {
            budget: ProgramBudget::new(400, u64::MAX),
            ..SupervisorConfig::default()
        };
        let mut gate = RecordingGate { seen: Vec::new() };
        let report = run_program(
            &mut sink,
            &mut exec,
            &mut GreenVerifier,
            &mut gate,
            cfg,
            &mut no_cancel(),
        )
        .unwrap();
        assert_eq!(report.outcome, ProgramOutcome::Completed);
        // The Start gate + at least the 25% and 50% budget gates were requested.
        assert!(gate.seen.contains(&CheckpointReason::Start));
        assert!(gate
            .seen
            .iter()
            .any(|r| matches!(r, CheckpointReason::Budget(25))));
        assert!(gate
            .seen
            .iter()
            .any(|r| matches!(r, CheckpointReason::Budget(50))));
        // A CheckpointReviewOpened event is on the durable log.
        assert!(sink
            .events()
            .iter()
            .any(|e| matches!(e, ProgramEvent::CheckpointReviewOpened { .. })));
    }

    #[test]
    fn gap_loop_07_critical_path_node_rejected_by_human_is_blocked() {
        // b is critical-path; the human rejects it. a commits; b is BlockedOnHuman; c (dep of b)
        // never schedules. Program is a CappedPartial, not Completed.
        struct RejectCritical;
        impl ApprovalGate for RejectCritical {
            fn request(&mut self, c: &Checkpoint) -> ApprovalDecision {
                if c.reason == CheckpointReason::CriticalPath {
                    ApprovalDecision::Reject
                } else {
                    ApprovalDecision::Approve
                }
            }
        }
        let mut sink = VecEventSink::new();
        seed(
            &mut sink,
            vec![
                NodeDecl::new("a", NodeClass::MigrationRun),
                NodeDecl::new("b", NodeClass::MigrationRun)
                    .depends_on("a")
                    .checkpoint(CheckpointClass::CriticalPath),
                NodeDecl::new("c", NodeClass::MigrationRun).depends_on("b"),
            ],
        );
        let mut exec = HappyExecutor {
            cost: ProgramCost::new(1, 0, 0),
        };
        let report = run_program(
            &mut sink,
            &mut exec,
            &mut GreenVerifier,
            &mut RejectCritical,
            SupervisorConfig::default(),
            &mut no_cancel(),
        )
        .unwrap();

        assert_eq!(report.outcome, ProgramOutcome::CappedPartial);
        assert_eq!(
            report.final_state.nodes[&nid("a")].state,
            NodeState::Committed
        );
        assert_eq!(
            report.final_state.nodes[&nid("b")].state,
            NodeState::BlockedOnHuman
        );
        assert_ne!(
            report.final_state.nodes[&nid("c")].state,
            NodeState::Committed
        );
    }

    // ---- LOOP-14 / §9: verification re-opens; poison route-around --------

    #[test]
    fn gap_loop_14_red_integration_edge_reopens_introducer_and_blocks_completion() {
        // b's edge integration is always red -> b commits, edge fails, b rolls back, retries until
        // the poison cap, then quarantines. a stays committed; program is CappedPartial.
        struct RedEdgeVerifier;
        impl ProgramVerifier for RedEdgeVerifier {
            fn verify_edge(&mut self, committed: &NodeId, _n: &NodeId) -> GateOutcome {
                if committed == &nid("b") {
                    GateOutcome::Blocked {
                        reasons: vec!["contract broken with a".into()],
                    }
                } else {
                    GateOutcome::Complete
                }
            }
            fn regression_sweep(&mut self, _c: &[NodeId]) -> GateOutcome {
                GateOutcome::Complete
            }
            fn program_judge(&mut self) -> JudgeVerdict {
                JudgeVerdict::pass(95, 80, "qwen", "glm")
            }
        }
        let mut sink = VecEventSink::new();
        seed(
            &mut sink,
            vec![
                NodeDecl::new("a", NodeClass::MigrationRun),
                NodeDecl::new("b", NodeClass::MigrationRun).depends_on("a"),
            ],
        );
        let mut exec = HappyExecutor {
            cost: ProgramCost::new(1, 0, 0),
        };
        let cfg = SupervisorConfig {
            poison: PoisonPolicy { max_failures: 2 },
            ..SupervisorConfig::default()
        };
        let report = run_program(
            &mut sink,
            &mut exec,
            &mut RedEdgeVerifier,
            &mut AutoApprove,
            cfg,
            &mut no_cancel(),
        )
        .unwrap();

        assert_ne!(report.outcome, ProgramOutcome::Completed);
        assert_eq!(
            report.final_state.nodes[&nid("a")].state,
            NodeState::Committed
        );
        assert_eq!(
            report.final_state.nodes[&nid("b")].state,
            NodeState::FailedIsolated
        );
        assert!(report.partial.failed_isolated.contains(&nid("b")));
        // b was rolled back at least once before quarantine.
        assert!(sink
            .events()
            .iter()
            .any(|e| matches!(e, ProgramEvent::RolledBack { node } if node == &nid("b"))));
    }

    #[test]
    fn gap_loop_14_poison_module_quarantined_and_program_routes_around() {
        // b always fails its Run; independent d succeeds. b quarantines; d commits.
        struct PoisonExecutor;
        impl RunExecutor for PoisonExecutor {
            fn execute_module(&mut self, ctx: &ModuleRunContext) -> ModuleRunResult {
                if ctx.node == nid("b") {
                    ModuleRunResult::Failed {
                        reason: "cannot migrate this module".into(),
                        cost: ProgramCost::new(5, 0, 0),
                    }
                } else {
                    ModuleRunResult::Ran {
                        det: DeterministicVerdict::green(),
                        adv: AdversarialVerdict::green(10),
                        judge: JudgeVerdict::pass(90, 80, "qwen", "glm"),
                        commit_shas: vec![format!("sha-{}", ctx.node)],
                        ledger_key: format!("k-{}", ctx.node),
                        by_model: "qwen".into(),
                        cost: ProgramCost::new(5, 0, 0),
                    }
                }
            }
        }
        let mut sink = VecEventSink::new();
        seed(
            &mut sink,
            vec![
                NodeDecl::new("a", NodeClass::MigrationRun),
                NodeDecl::new("b", NodeClass::MigrationRun).depends_on("a"),
                NodeDecl::new("d", NodeClass::MigrationRun), // independent branch
            ],
        );
        let cfg = SupervisorConfig {
            poison: PoisonPolicy { max_failures: 3 },
            ..SupervisorConfig::default()
        };
        let report = run_program(
            &mut sink,
            &mut PoisonExecutor,
            &mut GreenVerifier,
            &mut AutoApprove,
            cfg,
            &mut no_cancel(),
        )
        .unwrap();

        assert_eq!(report.outcome, ProgramOutcome::CappedPartial);
        assert_eq!(
            report.final_state.nodes[&nid("b")].state,
            NodeState::FailedIsolated
        );
        // The independent branch d completed despite b being poison (route-around, §9).
        assert_eq!(
            report.final_state.nodes[&nid("d")].state,
            NodeState::Committed
        );
        assert!(report.partial.committed.contains(&nid("a")));
        assert!(report.partial.committed.contains(&nid("d")));
        assert!(report.partial.failed_isolated.contains(&nid("b")));
    }

    // ---- §4 child-program composition through the loop -------------------

    #[test]
    fn gap_loop_02_child_program_node_resolves_then_parent_runs_own_work() {
        // p is a child-program node with a dependent q. The nested program Completes, then p runs
        // its own work and commits, unblocking q.
        struct ChildExecutor;
        impl RunExecutor for ChildExecutor {
            fn execute_module(&mut self, ctx: &ModuleRunContext) -> ModuleRunResult {
                if ctx.node_class == NodeClass::ChildProgram && !ctx.child_resolved {
                    ModuleRunResult::ChildProgram {
                        child_program_id: ProgramId::new("child-1"),
                        outcome: ChildOutcome::Completed,
                        cost: ProgramCost::new(50, 0, 0),
                    }
                } else {
                    ModuleRunResult::Ran {
                        det: DeterministicVerdict::green(),
                        adv: AdversarialVerdict::green(10),
                        judge: JudgeVerdict::pass(90, 80, "qwen", "glm"),
                        commit_shas: vec![format!("sha-{}", ctx.node)],
                        ledger_key: format!("k-{}", ctx.node),
                        by_model: "qwen".into(),
                        cost: ProgramCost::new(10, 0, 0),
                    }
                }
            }
        }
        let mut sink = VecEventSink::new();
        seed(
            &mut sink,
            vec![
                NodeDecl::new("p", NodeClass::ChildProgram),
                NodeDecl::new("q", NodeClass::MigrationRun).depends_on("p"),
            ],
        );
        let report = run_program(
            &mut sink,
            &mut ChildExecutor,
            &mut GreenVerifier,
            &mut AutoApprove,
            SupervisorConfig::default(),
            &mut no_cancel(),
        )
        .unwrap();

        assert_eq!(report.outcome, ProgramOutcome::Completed);
        assert_eq!(
            report.final_state.committed_node_ids(),
            vec![nid("p"), nid("q")]
        );
        // The spawn + deterministic outcome mapping are on the durable log.
        assert!(sink
            .events()
            .iter()
            .any(|e| matches!(e, ProgramEvent::ChildProgramSpawned { .. })));
    }
}
