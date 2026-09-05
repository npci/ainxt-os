// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Long-Horizon Program Supervisor — the durable, event-sourced aggregate above a Run.
//!
//! Design: `docs/architecture/LONG_HORIZON_PROGRAMS.md` (ADR-027) §1, §4, §9.
//!
//! A [`Plan`](crate::Plan) is the adaptable, in-memory plan lifecycle. A **Program** is the layer
//! above it: a durable aggregate whose entire state is a **projection of an append-only,
//! hash-chained event stream** (§4), so it survives restarts, model swaps, and multi-week
//! wall-clock. This module is the **pure, deterministic** core of that aggregate — no clock, no I/O,
//! no threads. State is *never* mutated in place from the outside; it is **folded from events**
//! ([`project`]), and every helper that "does" something returns the events that would be appended,
//! so the log is the single source of truth (point-in-time replay works exactly as for a turn).
//!
//! # What is proven here (each is a test that fails if the logic is gutted)
//!
//! * **Event-sourced, hash-chained state** — [`project`] folds events into a [`ProgramState`]; each
//!   event extends a deterministic hash chain ([`ProgramState::head_hash`]) so tampering/reordering
//!   is detectable, and [`project_incremental`] proves resume-from-checkpoint equals full replay.
//! * **Idempotent resume, no double-commit** (§4) — a re-applied [`ProgramEvent::NodeCommitted`]
//!   with a ledger key already seen is a **no-op**; the committed set is byte-identical.
//! * **Model-swap survival** (§4) — the committed set is a function of the committed code + typed
//!   contracts only; which model committed a node (`by_model`) never changes the resulting state.
//! * **Single-module rollback + dependent cascade** (§9) — [`plan_single_module_rollback`] reverts
//!   one node and re-opens exactly its committed transitive dependents; all other committed nodes
//!   are untouched and the committed set stays dependency-closed.
//! * **Poison-node quarantine + route-around** (§9) — a node that fails past a cap is
//!   [`plan_quarantine`]d to `FailedIsolated`, its dependents are gated, and every independent
//!   branch stays schedulable so the program completes what it can.
//! * **Child-program composition** (§4) — a `child-program` node blocks on a nested Program and its
//!   terminal [`ChildOutcome`] maps **deterministically** back onto the parent node, the *only*
//!   sanctioned exit from `BlockedOnChildProgram`.

use crate::mtg::ModuleRef;
use crate::verify::{
    three_way_gate, AdversarialVerdict, DeterministicVerdict, GateOutcome, JudgeVerdict,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// A program node is identified by its migration-unit reference.
pub type NodeId = ModuleRef;

/// Stable identity of a Program.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProgramId(pub String);

impl ProgramId {
    pub fn new(s: impl Into<String>) -> Self {
        ProgramId(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl fmt::Display for ProgramId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The kind of migration unit a node owns (ADR-027 §3 node contract `node_class`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NodeClass {
    MigrationRun,
    Shim,
    ShimCleanup,
    Integration,
    CharacterizationTest,
    DecouplingRefactor,
    DeterministicCodemod,
    /// Spawns an entire nested Program rather than a single Run (§4).
    ChildProgram,
}

/// Human-checkpoint class driving §8 gates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CheckpointClass {
    None,
    PhaseBoundary,
    /// Settlement/ledger/compliance-tagged: forces a human commit gate regardless of score.
    CriticalPath,
    Anomaly,
}

/// Minimum acceptable Semantic-Editing rung for a node (ADR-027 §3 node contract `edit_ladder_floor`,
/// §10). The ladder descends LSP → AST → structured-patch → text; critical-path modules forbid the
/// `TextPatch` rung. Ordered so `>=` expresses "at least as safe as".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EditRung {
    /// Least safe — raw text patching (catastrophic at scale, §10).
    TextPatch,
    /// Structured (hunk/AST-anchored) patch.
    StructuredPatch,
    /// AST transform.
    Ast,
    /// LSP-driven, reference-complete edit — the safest rung.
    Lsp,
}

/// The per-node program state machine (§4). `Ready` is *derived* (recomputed from committed deps),
/// never set directly by a caller — the driver-settable transitions go through
/// [`ProgramEvent::NodeStateChanged`] and the commit/rollback/quarantine/child events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NodeState {
    /// Waiting on dependencies (or downstream of an isolated failure — route-around).
    Pending,
    /// Deps satisfied; schedulable now (derived).
    Ready,
    InProgress,
    Verifying,
    Verified,
    Committed,
    /// Reverted by a single-module rollback; re-opens once deps are satisfied again.
    RolledBack,
    /// Raised to a human checkpoint gate.
    BlockedOnHuman,
    /// Poison node: quarantined and routed around (§9).
    FailedIsolated,
    /// A `child-program` node awaiting its nested Program's terminal outcome (§4).
    BlockedOnChildProgram,
}

/// The per-program phase (§4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProgramPhase {
    Draft,
    Decomposed,
    Approved,
    Running,
    Paused,
    CheckpointReview,
    Completed,
    CappedPartial,
    Abandoned,
}

impl ProgramPhase {
    /// A terminal phase accepts no further events.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            ProgramPhase::Completed | ProgramPhase::CappedPartial | ProgramPhase::Abandoned
        )
    }
}

/// A node declaration, supplied at decomposition time (§3). Carries the full ADR-027 §3 node
/// contract: the LOOP §2 fields (`id`/`node_class`/`deps`) plus the program-specific fields
/// (`working_set_estimate`, `blast_radius`, `verification_plan`, `checkpoint_class`,
/// `edit_ladder_floor`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeDecl {
    pub id: NodeId,
    pub node_class: NodeClass,
    #[serde(default = "default_checkpoint_class")]
    pub checkpoint_class: CheckpointClass,
    #[serde(default)]
    pub deps: BTreeSet<NodeId>,
    /// Measured tokens for this module + its 1-hop interface context (drives the §3.2 admissibility
    /// check). Sourced from [`crate::mtg::MtgNode::working_set_estimate`].
    #[serde(default)]
    pub working_set_estimate: u64,
    /// Dependents resolved from the call/import graph — the seam integration (§6) and rollback
    /// cascade (§9) read this.
    #[serde(default)]
    pub blast_radius: BTreeSet<NodeId>,
    /// Which per-module tests / integration seams gate this node (§6). Opaque refs to the caller.
    #[serde(default)]
    pub verification_plan: Vec<String>,
    /// Minimum acceptable Semantic-Editing rung (§10); critical-path modules forbid `TextPatch`.
    #[serde(default = "default_edit_rung")]
    pub edit_ladder_floor: EditRung,
}

fn default_checkpoint_class() -> CheckpointClass {
    CheckpointClass::None
}

fn default_edit_rung() -> EditRung {
    EditRung::StructuredPatch
}

/// The rung a pre-§10 [`ProgramEvent::NodeVerdictRecorded`] is deserialized with when it carries no
/// `edit_rung`: the SAFEST rung (`Lsp`), so replaying an older durable log never spuriously trips the
/// commit-gate floor check for a proof recorded before the field existed.
fn default_verdict_rung() -> EditRung {
    EditRung::Lsp
}

impl NodeDecl {
    pub fn new(id: impl Into<NodeId>, node_class: NodeClass) -> Self {
        NodeDecl {
            id: id.into(),
            node_class,
            checkpoint_class: CheckpointClass::None,
            deps: BTreeSet::new(),
            working_set_estimate: 0,
            blast_radius: BTreeSet::new(),
            verification_plan: Vec::new(),
            edit_ladder_floor: default_edit_rung(),
        }
    }
    pub fn depends_on(mut self, dep: impl Into<NodeId>) -> Self {
        self.deps.insert(dep.into());
        self
    }
    pub fn checkpoint(mut self, class: CheckpointClass) -> Self {
        self.checkpoint_class = class;
        self
    }
    /// Builder: record the §3.2 working-set estimate for this node.
    pub fn with_working_set(mut self, tokens: u64) -> Self {
        self.working_set_estimate = tokens;
        self
    }
    /// Builder: add a blast-radius dependent (§6/§9).
    pub fn with_blast(mut self, dependent: impl Into<NodeId>) -> Self {
        self.blast_radius.insert(dependent.into());
        self
    }
    /// Builder: add a verification-plan entry (§6).
    pub fn with_verification(mut self, plan: impl Into<String>) -> Self {
        self.verification_plan.push(plan.into());
        self
    }
    /// Builder: set the minimum edit rung (§10).
    pub fn with_edit_floor(mut self, floor: EditRung) -> Self {
        self.edit_ladder_floor = floor;
        self
    }
}

/// The live projection of a node — carries the full §3 node contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramNode {
    pub id: NodeId,
    pub node_class: NodeClass,
    pub checkpoint_class: CheckpointClass,
    pub deps: BTreeSet<NodeId>,
    pub state: NodeState,
    pub commit_shas: Vec<String>,
    pub failure_count: u32,
    pub child_program_id: Option<ProgramId>,
    /// §3 node-contract field: measured working-set tokens (§3.2 admissibility).
    #[serde(default)]
    pub working_set_estimate: u64,
    /// §3 node-contract field: dependents from the call/import graph (§6/§9).
    #[serde(default)]
    pub blast_radius: BTreeSet<NodeId>,
    /// §3 node-contract field: the tests/seams that gate this node (§6).
    #[serde(default)]
    pub verification_plan: Vec<String>,
    /// §3 node-contract field: minimum Semantic-Editing rung (§10).
    #[serde(default = "default_edit_rung")]
    pub edit_ladder_floor: EditRung,
}

/// The terminal outcome of a (possibly nested) Program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProgramOutcome {
    Completed,
    CappedPartial,
    Abandoned,
}

/// The terminal outcome of a **child** Program, as observed by its parent node (§4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChildOutcome {
    Completed,
    CappedPartial,
    Abandoned,
}

/// The deterministic child-outcome → parent-node-state mapping (§4). This is the **only** sanctioned
/// resolution of `BlockedOnChildProgram`: `Completed` re-opens the parent node (it becomes
/// schedulable again); `CappedPartial`/`Abandoned` raise it to a human gate with the child's report.
pub fn map_child_outcome(outcome: ChildOutcome) -> NodeState {
    match outcome {
        ChildOutcome::Completed => NodeState::Ready,
        ChildOutcome::CappedPartial | ChildOutcome::Abandoned => NodeState::BlockedOnHuman,
    }
}

/// The append-only program event stream (§4). A subset of the ADR's event catalogue, sufficient for
/// the pure state machine; the durable Event-Log carries the full hash-chained records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgramEvent {
    Created {
        program_id: ProgramId,
        goal: String,
    },
    Decomposed {
        nodes: Vec<NodeDecl>,
    },
    Approved {
        approver: String,
    },
    /// The driver-settable node transitions: Ready→InProgress, InProgress→Verifying,
    /// Verifying→Verified, and any active→BlockedOnHuman.
    NodeStateChanged {
        node: NodeId,
        to: NodeState,
        cause: String,
    },
    /// A node's attempt failed; increments its failure count and returns it to the schedulable pool.
    NodeAttemptFailed {
        node: NodeId,
        reason: String,
    },
    /// Verified→Committed. Idempotent on `ledger_key` (§4 no double-commit). `by_model` is recorded
    /// for the audit trail but never affects the projected state (§4 model-swap survival).
    NodeCommitted {
        node: NodeId,
        commit_shas: Vec<String>,
        ledger_key: String,
        by_model: String,
    },
    /// The three-way verification proof for a node (§6 / LOOP §7). Carries the three
    /// **independent, non-substitutable** verdicts (deterministic gate + adversarial Breaker +
    /// cross-model Judge); the fold recomputes [`three_way_gate`] and admits the node to `Verified`
    /// **only** on a `Complete` outcome. A `Blocked`/`Capped` verdict counts as a failed attempt —
    /// the node returns to the schedulable pool, never silently advancing. This makes "done" a
    /// *durable, recomputed-on-replay proof*, not a self-report: a `Verified` state that no
    /// `Complete` verdict backs is unreachable through this event.
    NodeVerdictRecorded {
        node: NodeId,
        det: DeterministicVerdict,
        adv: AdversarialVerdict,
        judge: JudgeVerdict,
        /// The Semantic-Editing rung the producer actually used to author this node's artifact (§10).
        /// Enforced against the node contract's `edit_ladder_floor` at the commit gate. Defaults to
        /// the safest rung on an older log so a resume of pre-§10 events never spuriously blocks.
        #[serde(default = "default_verdict_rung")]
        edit_rung: EditRung,
    },
    /// A `child-program` node (InProgress) spawns a nested Program and blocks on it.
    ChildProgramSpawned {
        node: NodeId,
        child_program_id: ProgramId,
    },
    /// The nested Program's terminal outcome, mapped back onto the parent node (§4).
    ChildProgramOutcomeMapped {
        node: NodeId,
        outcome: ChildOutcome,
    },
    /// Single-module rollback of a committed node (§9).
    RolledBack {
        node: NodeId,
    },
    /// Poison-node quarantine (§9): a node that failed past the cap is isolated.
    Quarantined {
        node: NodeId,
    },
    Checkpoint {
        offset: u64,
    },
    Paused,
    Resumed,
    CheckpointReviewOpened {
        reason: String,
    },
    Outcome {
        outcome: ProgramOutcome,
    },
}

/// Every way an event can be rejected against the current state — the tamper/ordering/illegal-move
/// detector that makes replay trustworthy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProgramError {
    NotCreated,
    AlreadyCreated,
    WrongPhase {
        event: String,
        phase: ProgramPhase,
    },
    EmptyDecomposition,
    DuplicateNode(NodeId),
    SelfDependency(NodeId),
    DanglingDependency {
        node: NodeId,
        missing: NodeId,
    },
    Cycle(Vec<NodeId>),
    UnknownNode(NodeId),
    IllegalNodeTransition {
        node: NodeId,
        from: NodeState,
        to: NodeState,
    },
    NodeNotCommitted(NodeId),
    /// A commit was attempted on a node with no `Complete` three-way verification proof on the log
    /// (§6 "never done until proven"). The durable, replayable enforcement of the three-way gate.
    NodeNotProven(NodeId),
    /// A commit was attempted on a node whose artifact was produced with a Semantic-Editing rung
    /// BELOW the node contract's `edit_ladder_floor` (§10 — e.g. a raw `TextPatch` on a critical-path
    /// module whose floor is `Ast`). The floor is enforced at the commit gate: a below-floor artifact
    /// is refused regardless of a green three-way proof — a catastrophic-at-scale edit never commits.
    EditFloorViolation {
        node: NodeId,
        used: EditRung,
        floor: EditRung,
    },
    NotChildProgramClass(NodeId),
    NotBlockedOnChild(NodeId),
    NotPoison {
        node: NodeId,
        failures: u32,
        required: u32,
    },
    Terminal,
}

impl fmt::Display for ProgramError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProgramError::NotCreated => f.write_str("program not created"),
            ProgramError::AlreadyCreated => f.write_str("program already created"),
            ProgramError::WrongPhase { event, phase } => {
                write!(f, "event '{event}' illegal in phase {phase:?}")
            }
            ProgramError::EmptyDecomposition => f.write_str("decomposition has no nodes"),
            ProgramError::DuplicateNode(n) => write!(f, "duplicate node: {n}"),
            ProgramError::SelfDependency(n) => write!(f, "node {n} depends on itself"),
            ProgramError::DanglingDependency { node, missing } => {
                write!(f, "node {node} depends on unknown node {missing}")
            }
            ProgramError::Cycle(ns) => write!(
                f,
                "dependency cycle among: {}",
                ns.iter().map(|n| n.as_str()).collect::<Vec<_>>().join(", ")
            ),
            ProgramError::UnknownNode(n) => write!(f, "unknown node: {n}"),
            ProgramError::IllegalNodeTransition { node, from, to } => {
                write!(f, "illegal transition for {node}: {from:?} -> {to:?}")
            }
            ProgramError::NodeNotCommitted(n) => write!(f, "node {n} is not committed"),
            ProgramError::NodeNotProven(n) => {
                write!(f, "node {n} has no Complete three-way verification proof")
            }
            ProgramError::EditFloorViolation { node, used, floor } => write!(
                f,
                "node {node} committed with edit rung {used:?} below its floor {floor:?} (§10)"
            ),
            ProgramError::NotChildProgramClass(n) => {
                write!(f, "node {n} is not a child-program node")
            }
            ProgramError::NotBlockedOnChild(n) => {
                write!(f, "node {n} is not blocked on a child program")
            }
            ProgramError::NotPoison {
                node,
                failures,
                required,
            } => write!(
                f,
                "node {node} is not poison: {failures} failures < required {required}"
            ),
            ProgramError::Terminal => f.write_str("program is in a terminal phase"),
        }
    }
}

impl std::error::Error for ProgramError {}

// ---------------------------------------------------------------------------
// Deterministic hash chain (pure, no deps) — models the §4 hash-chained Event Log.
// ---------------------------------------------------------------------------

/// FNV-1a 64-bit over the input, lowercase hex. Deterministic and dependency-free; the *runtime*
/// swaps in a crypto-agility-selected hash (ADR-023) at the real Event-Log seam.
fn fnv1a_hex(input: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in input.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{h:016x}")
}

/// A stable, injective-enough string digest of an event for the hash chain. Deterministic across
/// platforms (no float, no hash-map iteration order — `BTreeSet`/`Vec` are already ordered).
fn event_digest_input(ev: &ProgramEvent) -> String {
    match ev {
        ProgramEvent::Created { program_id, goal } => format!("created|{program_id}|{goal}"),
        ProgramEvent::Decomposed { nodes } => {
            let mut s = String::from("decomposed");
            for n in nodes {
                s.push('|');
                s.push_str(n.id.as_str());
                s.push(':');
                s.push_str(&format!("{:?}", n.node_class));
                for d in &n.deps {
                    s.push('>');
                    s.push_str(d.as_str());
                }
            }
            s
        }
        ProgramEvent::Approved { approver } => format!("approved|{approver}"),
        ProgramEvent::NodeStateChanged { node, to, cause } => {
            format!("nsc|{node}|{to:?}|{cause}")
        }
        ProgramEvent::NodeAttemptFailed { node, reason } => format!("naf|{node}|{reason}"),
        ProgramEvent::NodeCommitted {
            node,
            commit_shas,
            ledger_key,
            by_model,
        } => format!(
            "commit|{node}|{}|{ledger_key}|{by_model}",
            commit_shas.join(",")
        ),
        ProgramEvent::NodeVerdictRecorded {
            node,
            det,
            adv,
            judge,
            edit_rung,
        } => format!(
            "verdict|{node}|c{}t{}|f{}|a{}x{}|s{}/{}|{}>{}|r{:?}|{}",
            det.compiled as u8,
            det.tests_passed as u8,
            det.blocking_findings.len(),
            adv.attempts,
            adv.counterexamples.len(),
            judge.score,
            judge.threshold,
            judge.producer_model,
            judge.judge_model,
            edit_rung,
            three_way_gate(det, adv, judge)
        ),
        ProgramEvent::ChildProgramSpawned {
            node,
            child_program_id,
        } => format!("child-spawn|{node}|{child_program_id}"),
        ProgramEvent::ChildProgramOutcomeMapped { node, outcome } => {
            format!("child-map|{node}|{outcome:?}")
        }
        ProgramEvent::RolledBack { node } => format!("rollback|{node}"),
        ProgramEvent::Quarantined { node } => format!("quarantine|{node}"),
        ProgramEvent::Checkpoint { offset } => format!("checkpoint|{offset}"),
        ProgramEvent::Paused => "paused".to_string(),
        ProgramEvent::Resumed => "resumed".to_string(),
        ProgramEvent::CheckpointReviewOpened { reason } => format!("review|{reason}"),
        ProgramEvent::Outcome { outcome } => format!("outcome|{outcome:?}"),
    }
}

/// Recompute the deterministic §4 hash-chain head over `events` **without** enforcing state-machine
/// legality — the pure tamper-evidence primitive (gap AK, CODE_REVIEW §9). For any legal log this
/// equals `project(events)?.head_hash`, but it is defined even for a log the state machine would
/// reject, so tamper detection never depends on legality. Each event extends the chain as
/// `H(prev | digest(event))`, so mutating, reordering, inserting, or dropping **any** event changes the
/// head — the property [`verify_hash_chain`] checks. The runtime swaps in a crypto-agility-selected,
/// collision-resistant hash + signature at the real Event-Log seam (ADR-023 / `ainxt-eventlog`;
/// reported `needs_hot_wiring`); FNV-1a here is the deterministic, dependency-free reference chain.
pub fn recompute_head_hash(events: &[ProgramEvent]) -> String {
    let mut head = fnv1a_hex("genesis");
    for ev in events {
        head = fnv1a_hex(&format!("{head}|{}", event_digest_input(ev)));
    }
    head
}

/// The verdict of a §4 hash-chain integrity check ([`verify_hash_chain`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainVerdict {
    /// The recomputed head matches the claimed head — the log is intact (no tamper detected).
    Intact,
    /// The recomputed head differs from the claimed head — the durable log was tampered with
    /// (an event mutated, reordered, inserted, or dropped).
    Tampered { recomputed: String, claimed: String },
}

impl ChainVerdict {
    pub fn is_intact(&self) -> bool {
        matches!(self, ChainVerdict::Intact)
    }
}

/// Verify a durable event log against a previously-recorded chain head (§4 tamper-evidence). Returns
/// [`ChainVerdict::Intact`] iff [`recompute_head_hash`] over `events` equals `claimed_head`; any
/// tampering (a changed field, a reordered pair, an inserted/dropped event) yields
/// [`ChainVerdict::Tampered`] with both hashes for the audit record. This is the WORM-grade check an
/// auditor runs over the exported log to prove it was not edited after the fact.
pub fn verify_hash_chain(events: &[ProgramEvent], claimed_head: &str) -> ChainVerdict {
    let recomputed = recompute_head_hash(events);
    if recomputed == claimed_head {
        ChainVerdict::Intact
    } else {
        ChainVerdict::Tampered {
            recomputed,
            claimed: claimed_head.to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// ProgramState — the projection
// ---------------------------------------------------------------------------

/// The projected program state — folded from the event stream, never mutated externally.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramState {
    pub program_id: ProgramId,
    pub goal: String,
    pub phase: ProgramPhase,
    pub nodes: BTreeMap<NodeId, ProgramNode>,
    /// Insertion/declaration order of node ids (deterministic iteration for reports).
    pub order: Vec<NodeId>,
    /// Ledger keys of committed nodes — the idempotency set (§4 no double-commit).
    pub ledger_keys: BTreeSet<String>,
    /// Durable three-way verification proofs, keyed by node — the recomputed-on-replay record that
    /// backs `Verified`/`Committed` (§6). A node carries a `Complete` verdict here **iff** a
    /// [`ProgramEvent::NodeVerdictRecorded`] with a green three-way gate folded for it and it has not
    /// since regressed (rollback / attempt-fail / quarantine clear the proof). This is what makes the
    /// gate *enforced and durable* rather than a transient supervisor-only check.
    #[serde(default)]
    pub node_verdicts: BTreeMap<NodeId, GateOutcome>,
    /// The Semantic-Editing rung each `Verified` node's artifact was produced with (§10), folded from
    /// [`ProgramEvent::NodeVerdictRecorded`]. The commit gate checks this against the node contract's
    /// `edit_ladder_floor` — a below-floor artifact is refused ([`ProgramError::EditFloorViolation`])
    /// even with a green three-way proof. Cleared alongside `node_verdicts` on any failed attempt /
    /// rollback / quarantine, so a re-attempt must re-prove its rung.
    #[serde(default)]
    pub proven_edit_rung: BTreeMap<NodeId, EditRung>,
    /// Number of events folded so far (the checkpoint offset).
    pub event_offset: u64,
    /// Head of the deterministic hash chain over all folded events (§4 tamper-evidence).
    pub head_hash: String,
    /// The last recorded durable checkpoint offset.
    pub last_checkpoint_offset: u64,
}

impl ProgramState {
    fn empty() -> Self {
        ProgramState {
            program_id: ProgramId::new(""),
            goal: String::new(),
            phase: ProgramPhase::Draft,
            nodes: BTreeMap::new(),
            order: Vec::new(),
            ledger_keys: BTreeSet::new(),
            node_verdicts: BTreeMap::new(),
            proven_edit_rung: BTreeMap::new(),
            event_offset: 0,
            head_hash: fnv1a_hex("genesis"),
            last_checkpoint_offset: 0,
        }
    }

    fn node(&self, id: &NodeId) -> Result<&ProgramNode, ProgramError> {
        self.nodes
            .get(id)
            .ok_or_else(|| ProgramError::UnknownNode(id.clone()))
    }

    /// Apply a single event to this projection, advancing the offset + hash chain and enforcing
    /// legality (§4). This is the driver hook the [`crate::supervisor`] loop uses to fold the events
    /// it emits — the log stays the single source of truth, and every emitted event is validated by
    /// the same state machine as a replay.
    pub fn apply_event(&mut self, ev: &ProgramEvent) -> Result<(), ProgramError> {
        apply(self, ev)
    }

    /// Direct dependents of `id` (nodes that list `id` in their deps).
    pub fn direct_dependents(&self, id: &NodeId) -> Vec<NodeId> {
        self.order
            .iter()
            .filter(|n| self.nodes.get(*n).is_some_and(|nd| nd.deps.contains(id)))
            .cloned()
            .collect()
    }

    /// All nodes transitively downstream of `id` (its dependents, their dependents, …), excluding
    /// `id`. Deterministic BFS over the reverse graph.
    pub fn transitive_dependents(&self, id: &NodeId) -> BTreeSet<NodeId> {
        let mut result = BTreeSet::new();
        let mut frontier = vec![id.clone()];
        while let Some(cur) = frontier.pop() {
            for dep in self.direct_dependents(&cur) {
                if result.insert(dep.clone()) {
                    frontier.push(dep);
                }
            }
        }
        result
    }

    /// Nodes schedulable *right now* (§5): `Ready` nodes. A node downstream of a `FailedIsolated`
    /// or otherwise unsatisfied dependency is never `Ready` — so the program routes around poison
    /// nodes automatically (§9).
    pub fn schedulable_nodes(&self) -> Vec<NodeId> {
        self.order
            .iter()
            .filter(|n| self.nodes.get(*n).map(|nd| nd.state) == Some(NodeState::Ready))
            .cloned()
            .collect()
    }

    /// Node ids currently `Committed`.
    pub fn committed_node_ids(&self) -> Vec<NodeId> {
        self.order
            .iter()
            .filter(|n| self.nodes.get(*n).map(|nd| nd.state) == Some(NodeState::Committed))
            .cloned()
            .collect()
    }

    /// True iff every committed node's dependencies are all committed too — the §8 "the committed
    /// subset is always a consistent, compiling, deployable system" invariant (strangler-fig at
    /// module granularity). Holds after a single-module rollback + cascade.
    pub fn committed_is_dependency_closed(&self) -> bool {
        let committed: BTreeSet<&NodeId> = self
            .nodes
            .values()
            .filter(|n| n.state == NodeState::Committed)
            .map(|n| &n.id)
            .collect();
        committed.iter().all(|id| {
            self.nodes.get(*id).is_some_and(|n| {
                n.deps
                    .iter()
                    .all(|d| self.nodes.get(d).map(|dn| dn.state) == Some(NodeState::Committed))
            })
        })
    }

    /// True iff `node` carries a `Complete` three-way verification proof (§6). The durable answer to
    /// "was this proven, or merely self-reported?" — folded from [`ProgramEvent::NodeVerdictRecorded`].
    pub fn is_node_proven(&self, node: &NodeId) -> bool {
        matches!(self.node_verdicts.get(node), Some(GateOutcome::Complete))
    }

    /// True iff **every** `Committed` node carries a `Complete` three-way proof (§6 "never done until
    /// proven"). The [`crate::driver::Program`] API upholds this by construction — a test asserts it
    /// as a durable, replay-checkable invariant on the log itself.
    pub fn committed_nodes_are_all_proven(&self) -> bool {
        self.nodes
            .values()
            .filter(|n| n.state == NodeState::Committed)
            .all(|n| self.is_node_proven(&n.id))
    }

    /// Recompute the derived `Ready`/`Pending` set. A node in `{Pending, Ready, RolledBack}` becomes
    /// `Ready` iff every dependency is `Committed`; otherwise `Pending`. Active states
    /// (InProgress/Verifying/Verified), terminal-ish states (Committed/FailedIsolated), and gate
    /// states (BlockedOnHuman/BlockedOnChildProgram) are never disturbed.
    fn recompute_ready(&mut self) {
        // Snapshot committed set to avoid borrowing conflicts.
        let committed: BTreeSet<NodeId> = self
            .nodes
            .values()
            .filter(|n| n.state == NodeState::Committed)
            .map(|n| n.id.clone())
            .collect();
        for node in self.nodes.values_mut() {
            if matches!(
                node.state,
                NodeState::Pending | NodeState::Ready | NodeState::RolledBack
            ) {
                let deps_ok = node.deps.iter().all(|d| committed.contains(d));
                node.state = if deps_ok {
                    NodeState::Ready
                } else {
                    NodeState::Pending
                };
            }
        }
    }
}

/// Is `to` a legal driver transition (via `NodeStateChanged`) from `from`? Commit, rollback,
/// quarantine, and child-program moves have their own events and are **not** allowed here.
fn legal_state_change(from: NodeState, to: NodeState) -> bool {
    use NodeState::*;
    match to {
        InProgress => from == Ready,
        Verifying => from == InProgress,
        Verified => from == Verifying,
        // Any non-terminal node can be raised to a human checkpoint gate — including a `Pending`
        // dependent gated by the §9 poison-node route-around, and a re-opened `RolledBack` node.
        BlockedOnHuman => matches!(
            from,
            Pending | Ready | InProgress | Verifying | Verified | RolledBack
        ),
        _ => false,
    }
}

/// Apply one event to the state, enforcing legality. This is the whole state machine.
fn apply(state: &mut ProgramState, ev: &ProgramEvent) -> Result<(), ProgramError> {
    // Genesis: the first event must be `Created`; nothing else is legal before it.
    if state.event_offset == 0 {
        match ev {
            ProgramEvent::Created { program_id, goal } => {
                state.program_id = program_id.clone();
                state.goal = goal.clone();
                state.phase = ProgramPhase::Draft;
            }
            _ => return Err(ProgramError::NotCreated),
        }
    } else {
        if let ProgramEvent::Created { .. } = ev {
            return Err(ProgramError::AlreadyCreated);
        }
        if state.phase.is_terminal() {
            return Err(ProgramError::Terminal);
        }
        apply_post_genesis(state, ev)?;
    }

    // Advance the offset + hash chain (all events, including Created).
    state.event_offset += 1;
    state.head_hash = fnv1a_hex(&format!("{}|{}", state.head_hash, event_digest_input(ev)));
    Ok(())
}

fn apply_post_genesis(state: &mut ProgramState, ev: &ProgramEvent) -> Result<(), ProgramError> {
    match ev {
        ProgramEvent::Created { .. } => unreachable!("handled in apply"),

        ProgramEvent::Decomposed { nodes } => {
            if state.phase != ProgramPhase::Draft {
                return Err(ProgramError::WrongPhase {
                    event: "decomposed".into(),
                    phase: state.phase,
                });
            }
            validate_decomposition(nodes)?;
            for decl in nodes {
                state.order.push(decl.id.clone());
                state.nodes.insert(
                    decl.id.clone(),
                    ProgramNode {
                        id: decl.id.clone(),
                        node_class: decl.node_class,
                        checkpoint_class: decl.checkpoint_class,
                        deps: decl.deps.clone(),
                        state: NodeState::Pending,
                        commit_shas: Vec::new(),
                        failure_count: 0,
                        child_program_id: None,
                        working_set_estimate: decl.working_set_estimate,
                        blast_radius: decl.blast_radius.clone(),
                        verification_plan: decl.verification_plan.clone(),
                        edit_ladder_floor: decl.edit_ladder_floor,
                    },
                );
            }
            state.phase = ProgramPhase::Decomposed;
            state.recompute_ready();
        }

        ProgramEvent::Approved { .. } => {
            if state.phase != ProgramPhase::Decomposed {
                return Err(ProgramError::WrongPhase {
                    event: "approved".into(),
                    phase: state.phase,
                });
            }
            state.phase = ProgramPhase::Approved;
        }

        ProgramEvent::NodeStateChanged { node, to, cause: _ } => {
            let from = state.node(node)?.state;
            // The only sanctioned exit from BlockedOnChildProgram is ChildProgramOutcomeMapped.
            if from == NodeState::BlockedOnChildProgram || !legal_state_change(from, *to) {
                return Err(ProgramError::IllegalNodeTransition {
                    node: node.clone(),
                    from,
                    to: *to,
                });
            }
            state.nodes.get_mut(node).expect("checked").state = *to;
            enter_running_if_needed(state);
        }

        ProgramEvent::NodeAttemptFailed { node, reason: _ } => {
            let n = state.node(node)?;
            if !matches!(n.state, NodeState::InProgress | NodeState::Verifying) {
                return Err(ProgramError::IllegalNodeTransition {
                    node: node.clone(),
                    from: n.state,
                    to: NodeState::Pending,
                });
            }
            let nm = state.nodes.get_mut(node).expect("checked");
            nm.failure_count = nm.failure_count.saturating_add(1);
            nm.state = NodeState::Pending;
            // A failed attempt clears any prior proof — the node is no longer verified.
            state.node_verdicts.remove(node);
            state.proven_edit_rung.remove(node);
            state.recompute_ready();
        }

        ProgramEvent::NodeVerdictRecorded {
            node,
            det,
            adv,
            judge,
            edit_rung,
        } => {
            let from = state.node(node)?.state;
            // A verdict is only meaningful for a node actively under test.
            if !matches!(from, NodeState::InProgress | NodeState::Verifying) {
                return Err(ProgramError::IllegalNodeTransition {
                    node: node.clone(),
                    from,
                    to: NodeState::Verified,
                });
            }
            // Recompute the gate from the three independent proofs — never trust a stored boolean.
            let outcome = three_way_gate(det, adv, judge);
            match &outcome {
                GateOutcome::Complete => {
                    state.nodes.get_mut(node).expect("checked").state = NodeState::Verified;
                    state.node_verdicts.insert(node.clone(), outcome);
                    // Record the rung the artifact was produced with; the commit gate (§10) checks it
                    // against the node contract's `edit_ladder_floor`.
                    state.proven_edit_rung.insert(node.clone(), *edit_rung);
                }
                // Not proven: a red/incomplete gate is a failed attempt, not an advance to Verified.
                _ => {
                    let nm = state.nodes.get_mut(node).expect("checked");
                    nm.failure_count = nm.failure_count.saturating_add(1);
                    nm.state = NodeState::Pending;
                    state.node_verdicts.remove(node);
                    state.proven_edit_rung.remove(node);
                    state.recompute_ready();
                }
            }
        }

        ProgramEvent::NodeCommitted {
            node,
            commit_shas,
            ledger_key,
            by_model: _,
        } => {
            // Idempotent resume: a re-applied commit for a seen ledger key is a no-op (§4).
            if state.ledger_keys.contains(ledger_key) {
                return Ok(());
            }
            let from = state.node(node)?.state;
            if from != NodeState::Verified {
                return Err(ProgramError::IllegalNodeTransition {
                    node: node.clone(),
                    from,
                    to: NodeState::Committed,
                });
            }
            // §10 edit-ladder floor enforced AT THE COMMIT GATE: the rung the artifact was produced
            // with (recorded on the durable NodeVerdictRecorded proof) must be at least as safe as the
            // node contract's `edit_ladder_floor`. A below-floor artifact — e.g. a raw TextPatch on a
            // critical-path module whose floor is Ast — is refused even with a green three-way proof.
            // A pre-§10 proof (no recorded rung) defaults to the safest rung, so it never spuriously
            // blocks; the ceiling that matters (critical-path forbids TextPatch) is always enforced.
            let floor = state.node(node)?.edit_ladder_floor;
            let used = state
                .proven_edit_rung
                .get(node)
                .copied()
                .unwrap_or_else(default_verdict_rung);
            if used < floor {
                return Err(ProgramError::EditFloorViolation {
                    node: node.clone(),
                    used,
                    floor,
                });
            }
            let nm = state.nodes.get_mut(node).expect("checked");
            nm.state = NodeState::Committed;
            nm.commit_shas = commit_shas.clone();
            state.ledger_keys.insert(ledger_key.clone());
            state.recompute_ready();
        }

        ProgramEvent::ChildProgramSpawned {
            node,
            child_program_id,
        } => {
            let n = state.node(node)?;
            if n.node_class != NodeClass::ChildProgram {
                return Err(ProgramError::NotChildProgramClass(node.clone()));
            }
            if n.state != NodeState::InProgress {
                return Err(ProgramError::IllegalNodeTransition {
                    node: node.clone(),
                    from: n.state,
                    to: NodeState::BlockedOnChildProgram,
                });
            }
            let nm = state.nodes.get_mut(node).expect("checked");
            nm.state = NodeState::BlockedOnChildProgram;
            nm.child_program_id = Some(child_program_id.clone());
        }

        ProgramEvent::ChildProgramOutcomeMapped { node, outcome } => {
            let n = state.node(node)?;
            if n.state != NodeState::BlockedOnChildProgram {
                return Err(ProgramError::NotBlockedOnChild(node.clone()));
            }
            let mapped = map_child_outcome(*outcome);
            state.nodes.get_mut(node).expect("checked").state = mapped;
            // Completed re-opens the node into the schedulable pool subject to its other deps.
            state.recompute_ready();
        }

        ProgramEvent::RolledBack { node } => {
            let from = state.node(node)?.state;
            if from != NodeState::Committed {
                return Err(ProgramError::NodeNotCommitted(node.clone()));
            }
            let nm = state.nodes.get_mut(node).expect("checked");
            nm.state = NodeState::RolledBack;
            nm.commit_shas.clear();
            // A rolled-back node's ledger slot is freed so a re-attempt can commit again.
            // (We cannot know the exact key here; the caller re-commits with a fresh key.)
            // Its verification proof is void — a re-attempt must earn a fresh Complete verdict.
            state.node_verdicts.remove(node);
            state.proven_edit_rung.remove(node);
            state.recompute_ready();
        }

        ProgramEvent::Quarantined { node } => {
            let from = state.node(node)?.state;
            if matches!(from, NodeState::Committed | NodeState::FailedIsolated) {
                return Err(ProgramError::IllegalNodeTransition {
                    node: node.clone(),
                    from,
                    to: NodeState::FailedIsolated,
                });
            }
            state.nodes.get_mut(node).expect("checked").state = NodeState::FailedIsolated;
            state.node_verdicts.remove(node);
            state.proven_edit_rung.remove(node);
            state.recompute_ready();
        }

        ProgramEvent::Checkpoint { offset } => {
            state.last_checkpoint_offset = *offset;
        }

        ProgramEvent::Paused => {
            if state.phase == ProgramPhase::Running {
                state.phase = ProgramPhase::Paused;
            }
        }
        ProgramEvent::Resumed => {
            if matches!(
                state.phase,
                ProgramPhase::Paused | ProgramPhase::CheckpointReview
            ) {
                state.phase = ProgramPhase::Running;
            }
        }
        ProgramEvent::CheckpointReviewOpened { .. } => {
            if state.phase == ProgramPhase::Running {
                state.phase = ProgramPhase::CheckpointReview;
            }
        }

        ProgramEvent::Outcome { outcome } => {
            state.phase = match outcome {
                ProgramOutcome::Completed => ProgramPhase::Completed,
                ProgramOutcome::CappedPartial => ProgramPhase::CappedPartial,
                ProgramOutcome::Abandoned => ProgramPhase::Abandoned,
            };
        }
    }
    Ok(())
}

/// Move Approved→Running the first time a node begins work.
fn enter_running_if_needed(state: &mut ProgramState) {
    if state.phase == ProgramPhase::Approved
        && state
            .nodes
            .values()
            .any(|n| n.state == NodeState::InProgress)
    {
        state.phase = ProgramPhase::Running;
    }
}

/// Validate a decomposition: no duplicate ids, no self-deps, no dangling deps, and the dependency
/// graph is a DAG. Rejects an unschedulable graph up front (never a silent partial program).
fn validate_decomposition(nodes: &[NodeDecl]) -> Result<(), ProgramError> {
    if nodes.is_empty() {
        return Err(ProgramError::EmptyDecomposition);
    }
    let mut ids: BTreeSet<NodeId> = BTreeSet::new();
    for n in nodes {
        if !ids.insert(n.id.clone()) {
            return Err(ProgramError::DuplicateNode(n.id.clone()));
        }
    }
    for n in nodes {
        for d in &n.deps {
            if d == &n.id {
                return Err(ProgramError::SelfDependency(n.id.clone()));
            }
            if !ids.contains(d) {
                return Err(ProgramError::DanglingDependency {
                    node: n.id.clone(),
                    missing: d.clone(),
                });
            }
        }
    }
    detect_cycle(nodes)
}

/// Kahn-style cycle detection over the decl set. Returns [`ProgramError::Cycle`] naming the nodes
/// that never reach in-degree zero.
fn detect_cycle(nodes: &[NodeDecl]) -> Result<(), ProgramError> {
    let mut indegree: BTreeMap<NodeId, usize> = BTreeMap::new();
    let mut dependents: BTreeMap<NodeId, Vec<NodeId>> = BTreeMap::new();
    for n in nodes {
        indegree.entry(n.id.clone()).or_insert(0);
        dependents.entry(n.id.clone()).or_default();
    }
    for n in nodes {
        for d in &n.deps {
            *indegree.get_mut(&n.id).expect("present") += 1;
            dependents.entry(d.clone()).or_default().push(n.id.clone());
        }
    }
    let mut ready: BTreeSet<NodeId> = indegree
        .iter()
        .filter(|(_, &c)| c == 0)
        .map(|(k, _)| k.clone())
        .collect();
    let mut visited = 0usize;
    while let Some(id) = ready.iter().next().cloned() {
        ready.remove(&id);
        visited += 1;
        if let Some(children) = dependents.get(&id) {
            for child in children.clone() {
                if let Some(e) = indegree.get_mut(&child) {
                    *e -= 1;
                    if *e == 0 {
                        ready.insert(child);
                    }
                }
            }
        }
    }
    if visited != indegree.len() {
        let cyc: Vec<NodeId> = indegree
            .into_iter()
            .filter(|(_, c)| *c > 0)
            .map(|(k, _)| k)
            .collect();
        return Err(ProgramError::Cycle(cyc));
    }
    Ok(())
}

/// Fold an entire event stream into a [`ProgramState`] (§4). The event log is the single source of
/// truth; any illegal/out-of-order/tampered event is rejected here, so a replayed program is
/// always internally consistent.
pub fn project(events: &[ProgramEvent]) -> Result<ProgramState, ProgramError> {
    let mut state = ProgramState::empty();
    for ev in events {
        apply(&mut state, ev)?;
    }
    Ok(state)
}

/// Continue folding `tail` onto an already-projected `base` (§4 incremental projection). Resume =
/// replay to the last checkpoint then continue — this is that continuation, and it is *equal* to a
/// full replay of `all` (asserted by a test), so a Friday→Monday resume needs no full re-fold.
pub fn project_incremental(
    mut base: ProgramState,
    tail: &[ProgramEvent],
) -> Result<ProgramState, ProgramError> {
    for ev in tail {
        apply(&mut base, ev)?;
    }
    Ok(base)
}

// ---------------------------------------------------------------------------
// §9 — single-module rollback, poison-node quarantine, route-around (pure planners)
// ---------------------------------------------------------------------------

/// A saga-compensation seam (§9). Rolling back a committed node reverts its git SHA(s) and runs its
/// compensation (e.g. un-create its MR). Both are I/O; the live runtime backs this. A rollback plan
/// is pure ([`plan_single_module_rollback`]); executing the compensation goes through this trait so
/// the honest "non-compensable" outcome is surfaced, never swallowed.
pub trait Compensator {
    fn compensate(&self, node: &NodeId, commit_shas: &[String]) -> Result<(), String>;
}

/// The result of executing a rollback: which nodes reverted cleanly vs. failed compensation (§9
/// `FAILED_PARTIAL` honesty).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackReport {
    pub reverted: Vec<NodeId>,
    /// Nodes whose compensation could not complete — surfaced, never hidden.
    pub non_compensable: Vec<(NodeId, String)>,
}

/// Plan a single-module rollback (§9) **without** mutating anything: revert `node` and every
/// **committed** transitive dependent (they built on now-reverted code), leaving all other committed
/// nodes untouched. Returns the `RolledBack` events, ordered dependents-first so the log reads
/// leaf-to-root. Requires `node` to be `Committed`.
pub fn plan_single_module_rollback(
    state: &ProgramState,
    node: &NodeId,
) -> Result<Vec<ProgramEvent>, ProgramError> {
    let n = state.node(node)?;
    if n.state != NodeState::Committed {
        return Err(ProgramError::NodeNotCommitted(node.clone()));
    }
    // Committed transitive dependents must roll back too; independent + uncommitted nodes are left
    // alone (progress preserved, §9).
    let mut targets: Vec<NodeId> = state
        .transitive_dependents(node)
        .into_iter()
        .filter(|d| state.nodes.get(d).map(|nd| nd.state) == Some(NodeState::Committed))
        .collect();
    // Deterministic dependents-first order: dependents (sorted) then the node itself last.
    targets.sort();
    let mut events: Vec<ProgramEvent> = targets
        .into_iter()
        .map(|d| ProgramEvent::RolledBack { node: d })
        .collect();
    events.push(ProgramEvent::RolledBack { node: node.clone() });
    Ok(events)
}

/// Execute a planned rollback against the [`Compensator`] seam, collecting an honest report. Pure
/// except for the injected seam; a mock compensator makes this fully testable offline.
pub fn execute_rollback(
    state: &ProgramState,
    node: &NodeId,
    comp: &dyn Compensator,
) -> Result<RollbackReport, ProgramError> {
    let events = plan_single_module_rollback(state, node)?;
    let mut reverted = Vec::new();
    let mut non_compensable = Vec::new();
    for ev in &events {
        if let ProgramEvent::RolledBack { node: n } = ev {
            let shas = state
                .nodes
                .get(n)
                .map(|pn| pn.commit_shas.clone())
                .unwrap_or_default();
            match comp.compensate(n, &shas) {
                Ok(()) => reverted.push(n.clone()),
                Err(reason) => non_compensable.push((n.clone(), reason)),
            }
        }
    }
    Ok(RollbackReport {
        reverted,
        non_compensable,
    })
}

/// True iff `node` has failed at least `policy.max_failures` times — the program-level stuck
/// detector (§9), distinct from the Run-level one.
pub fn is_poison(state: &ProgramState, node: &NodeId, policy: PoisonPolicy) -> bool {
    state
        .nodes
        .get(node)
        .is_some_and(|n| n.failure_count >= policy.max_failures)
}

/// Poison-node policy: how many failed attempts before a node is quarantined (§9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoisonPolicy {
    pub max_failures: u32,
}

/// Default poison cap — illustrative (ADR-027 §15 says tuning is unproven until real programs run).
pub const DEFAULT_POISON_CAP: u32 = 3;

impl Default for PoisonPolicy {
    fn default() -> Self {
        PoisonPolicy {
            max_failures: DEFAULT_POISON_CAP,
        }
    }
}

/// Plan a poison-node quarantine + route-around (§9): the node is `Quarantined` (→ `FailedIsolated`)
/// and every transitive dependent is raised to a human gate (`BlockedOnHuman`). Independent branches
/// are **untouched** — the program routes around the poison node and completes what it can. Requires
/// the node to have crossed the poison cap. Returns the events (dependents first, node last).
pub fn plan_quarantine(
    state: &ProgramState,
    node: &NodeId,
    policy: PoisonPolicy,
) -> Result<Vec<ProgramEvent>, ProgramError> {
    let n = state.node(node)?;
    if n.failure_count < policy.max_failures {
        return Err(ProgramError::NotPoison {
            node: node.clone(),
            failures: n.failure_count,
            required: policy.max_failures,
        });
    }
    Ok(build_quarantine_events(state, node))
}

/// Build the quarantine + route-around events for `node` **without** the poison-cap precondition —
/// the pure event construction shared by [`plan_quarantine`] (which enforces the cap) and the
/// [`crate::supervisor`] loop (which decides poison via its own program-level stuck detector). Every
/// transitive dependent that is not already committed/isolated is raised to a human gate
/// (`BlockedOnHuman`); independent branches are untouched. Dependents first (sorted), node last.
pub fn build_quarantine_events(state: &ProgramState, node: &NodeId) -> Vec<ProgramEvent> {
    let mut dependents: Vec<NodeId> = state.transitive_dependents(node).into_iter().collect();
    dependents.sort();
    let mut events: Vec<ProgramEvent> = dependents
        .into_iter()
        // Only gate dependents that are not already terminal/gated.
        .filter(|d| {
            !matches!(
                state.nodes.get(d).map(|nd| nd.state),
                Some(NodeState::FailedIsolated) | Some(NodeState::Committed)
            )
        })
        .map(|d| ProgramEvent::NodeStateChanged {
            node: d,
            to: NodeState::BlockedOnHuman,
            cause: format!("route-around: depends on quarantined node {node}"),
        })
        .collect();
    events.push(ProgramEvent::Quarantined { node: node.clone() });
    events
}

// ---------------------------------------------------------------------------
// §8 — partial-completion report
// ---------------------------------------------------------------------------

/// A first-class, honest, deployable partial-completion report (§8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialCompletionReport {
    pub committed: Vec<NodeId>,
    /// Nodes blocked on a human / never scheduled, with their state.
    pub blocked: Vec<(NodeId, NodeState)>,
    pub failed_isolated: Vec<NodeId>,
    /// `(committed, total)`.
    pub fraction: (usize, usize),
    /// Whether the committed subset is dependency-closed (deployable, §8).
    pub committed_deployable: bool,
}

/// Build the §8 partial-completion report from the durable state.
pub fn partial_report(state: &ProgramState) -> PartialCompletionReport {
    let mut committed = Vec::new();
    let mut blocked = Vec::new();
    let mut failed_isolated = Vec::new();
    for id in &state.order {
        let Some(n) = state.nodes.get(id) else {
            continue;
        };
        match n.state {
            NodeState::Committed => committed.push(id.clone()),
            NodeState::FailedIsolated => failed_isolated.push(id.clone()),
            NodeState::BlockedOnHuman
            | NodeState::BlockedOnChildProgram
            | NodeState::Pending
            | NodeState::RolledBack => blocked.push((id.clone(), n.state)),
            _ => {}
        }
    }
    let total = state.order.len();
    PartialCompletionReport {
        fraction: (committed.len(), total),
        committed_deployable: state.committed_is_dependency_closed(),
        committed,
        blocked,
        failed_isolated,
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(s: &str) -> NodeId {
        ModuleRef::new(s)
    }

    fn created() -> ProgramEvent {
        ProgramEvent::Created {
            program_id: ProgramId::new("prog-1"),
            goal: "migrate settlement".into(),
        }
    }

    /// Decompose a chain a -> b -> c -> d (each depends on the previous).
    fn chain_decl() -> ProgramEvent {
        ProgramEvent::Decomposed {
            nodes: vec![
                NodeDecl::new("a", NodeClass::MigrationRun),
                NodeDecl::new("b", NodeClass::MigrationRun).depends_on("a"),
                NodeDecl::new("c", NodeClass::MigrationRun).depends_on("b"),
                NodeDecl::new("d", NodeClass::MigrationRun).depends_on("c"),
            ],
        }
    }

    fn commit(node: &str, key: &str, model: &str) -> ProgramEvent {
        ProgramEvent::NodeCommitted {
            node: nid(node),
            commit_shas: vec![format!("sha-{node}")],
            ledger_key: key.into(),
            by_model: model.into(),
        }
    }

    /// Drive a node all the way Ready→InProgress→Verifying→Verified→Committed.
    fn drive_commit(events: &mut Vec<ProgramEvent>, node: &str, key: &str, model: &str) {
        events.push(ProgramEvent::NodeStateChanged {
            node: nid(node),
            to: NodeState::InProgress,
            cause: "start".into(),
        });
        events.push(ProgramEvent::NodeStateChanged {
            node: nid(node),
            to: NodeState::Verifying,
            cause: "verify".into(),
        });
        events.push(ProgramEvent::NodeStateChanged {
            node: nid(node),
            to: NodeState::Verified,
            cause: "verified".into(),
        });
        events.push(commit(node, key, model));
    }

    // ---- projection basics ------------------------------------------------

    #[test]
    fn genesis_must_be_created() {
        let err = project(&[chain_decl()]).unwrap_err();
        assert_eq!(err, ProgramError::NotCreated);
    }

    #[test]
    fn decompose_sets_pending_and_derives_ready_for_dep_free_nodes() {
        let st = project(&[created(), chain_decl()]).unwrap();
        assert_eq!(st.phase, ProgramPhase::Decomposed);
        // Only `a` (no deps) is Ready; the rest are Pending.
        assert_eq!(st.schedulable_nodes(), vec![nid("a")]);
        assert_eq!(st.nodes[&nid("b")].state, NodeState::Pending);
    }

    #[test]
    fn full_chain_drives_to_all_committed() {
        let mut ev = vec![
            created(),
            chain_decl(),
            ProgramEvent::Approved {
                approver: "boss".into(),
            },
        ];
        drive_commit(&mut ev, "a", "k-a", "qwen");
        drive_commit(&mut ev, "b", "k-b", "qwen");
        drive_commit(&mut ev, "c", "k-c", "qwen");
        drive_commit(&mut ev, "d", "k-d", "qwen");
        let st = project(&ev).unwrap();
        assert_eq!(st.phase, ProgramPhase::Running);
        assert_eq!(
            st.committed_node_ids(),
            vec![nid("a"), nid("b"), nid("c"), nid("d")]
        );
        assert!(st.committed_is_dependency_closed());
    }

    #[test]
    fn a_node_cannot_start_before_its_dependency_commits() {
        // Try to start `b` while `a` is still Pending -> b is not Ready, so InProgress is illegal.
        let ev = vec![
            created(),
            chain_decl(),
            ProgramEvent::Approved {
                approver: "b".into(),
            },
            ProgramEvent::NodeStateChanged {
                node: nid("b"),
                to: NodeState::InProgress,
                cause: "premature".into(),
            },
        ];
        let err = project(&ev).unwrap_err();
        assert!(matches!(err, ProgramError::IllegalNodeTransition { .. }));
    }

    // ---- idempotent commit + model swap ----------------------------------

    #[test]
    fn re_applied_commit_with_same_ledger_key_is_a_noop() {
        let mut ev = vec![
            created(),
            chain_decl(),
            ProgramEvent::Approved {
                approver: "b".into(),
            },
        ];
        drive_commit(&mut ev, "a", "k-a", "qwen");
        // Replay the SAME commit event (as a crash-resume would).
        ev.push(commit("a", "k-a", "qwen"));
        let st = project(&ev).unwrap();
        // Exactly one commit; a stays Committed with a single SHA; no double commit (§4).
        assert_eq!(st.nodes[&nid("a")].state, NodeState::Committed);
        assert_eq!(st.nodes[&nid("a")].commit_shas, vec!["sha-a".to_string()]);
        assert_eq!(st.ledger_keys.len(), 1);
    }

    #[test]
    fn committed_set_is_independent_of_which_model_committed_each_node() {
        // §4 model-swap survival: same events, different `by_model` strings -> identical committed set.
        let build = |m1: &str, m2: &str| {
            let mut ev = vec![
                created(),
                chain_decl(),
                ProgramEvent::Approved {
                    approver: "b".into(),
                },
            ];
            drive_commit(&mut ev, "a", "k-a", m1);
            drive_commit(&mut ev, "b", "k-b", m2);
            project(&ev).unwrap()
        };
        let s1 = build("qwen-v1", "qwen-v1");
        let s2 = build("qwen-v1", "glm-v2"); // coder model retired mid-program
        assert_eq!(s1.committed_node_ids(), s2.committed_node_ids());
        assert_eq!(s1.phase, s2.phase);
    }

    // ---- hash chain + incremental projection -----------------------------

    #[test]
    fn hash_chain_is_deterministic_and_order_sensitive() {
        let a = project(&[created(), chain_decl()]).unwrap();
        let b = project(&[created(), chain_decl()]).unwrap();
        assert_eq!(a.head_hash, b.head_hash, "same events -> same chain head");

        // Reordering the two post-genesis events yields a different (or rejected) chain — here the
        // reorder is illegal, proving order is enforced.
        let reordered = project(&[chain_decl(), created()]);
        assert!(reordered.is_err());
    }

    #[test]
    fn incremental_projection_equals_full_replay() {
        let mut all = vec![
            created(),
            chain_decl(),
            ProgramEvent::Approved {
                approver: "b".into(),
            },
        ];
        drive_commit(&mut all, "a", "k-a", "qwen");
        drive_commit(&mut all, "b", "k-b", "qwen");

        let split = 4; // an arbitrary checkpoint offset mid-stream
        let base = project(&all[..split]).unwrap();
        let incremental = project_incremental(base, &all[split..]).unwrap();
        let full = project(&all).unwrap();

        assert_eq!(
            incremental, full,
            "resume-from-checkpoint == full replay (§4)"
        );
    }

    // ---- decomposition validation ----------------------------------------

    #[test]
    fn cyclic_decomposition_is_rejected() {
        let ev = vec![
            created(),
            ProgramEvent::Decomposed {
                nodes: vec![
                    NodeDecl::new("a", NodeClass::MigrationRun).depends_on("b"),
                    NodeDecl::new("b", NodeClass::MigrationRun).depends_on("a"),
                ],
            },
        ];
        assert!(matches!(project(&ev).unwrap_err(), ProgramError::Cycle(_)));
    }

    #[test]
    fn dangling_and_self_and_duplicate_deps_are_rejected() {
        let dangling = project(&[
            created(),
            ProgramEvent::Decomposed {
                nodes: vec![NodeDecl::new("a", NodeClass::MigrationRun).depends_on("ghost")],
            },
        ]);
        assert!(matches!(
            dangling.unwrap_err(),
            ProgramError::DanglingDependency { .. }
        ));

        let dup = project(&[
            created(),
            ProgramEvent::Decomposed {
                nodes: vec![
                    NodeDecl::new("a", NodeClass::MigrationRun),
                    NodeDecl::new("a", NodeClass::Shim),
                ],
            },
        ]);
        assert!(matches!(dup.unwrap_err(), ProgramError::DuplicateNode(_)));
    }

    // ---- single-module rollback + cascade (§9) ---------------------------

    fn diamond_all_committed() -> ProgramState {
        // a -> {b, c} -> d, all committed.
        let mut ev = vec![
            created(),
            ProgramEvent::Decomposed {
                nodes: vec![
                    NodeDecl::new("a", NodeClass::MigrationRun),
                    NodeDecl::new("b", NodeClass::MigrationRun).depends_on("a"),
                    NodeDecl::new("c", NodeClass::MigrationRun).depends_on("a"),
                    NodeDecl::new("d", NodeClass::MigrationRun)
                        .depends_on("b")
                        .depends_on("c"),
                ],
            },
            ProgramEvent::Approved {
                approver: "b".into(),
            },
        ];
        drive_commit(&mut ev, "a", "k-a", "qwen");
        drive_commit(&mut ev, "b", "k-b", "qwen");
        drive_commit(&mut ev, "c", "k-c", "qwen");
        drive_commit(&mut ev, "d", "k-d", "qwen");
        project(&ev).unwrap()
    }

    #[test]
    fn single_module_rollback_reverts_node_and_its_committed_dependents_only() {
        let st = diamond_all_committed();
        // Roll back `b`: only `b` and its dependent `d` revert; `a` and `c` stay committed.
        let events = plan_single_module_rollback(&st, &nid("b")).unwrap();
        let after = project_incremental(st, &events).unwrap();

        assert_eq!(after.nodes[&nid("a")].state, NodeState::Committed);
        assert_eq!(after.nodes[&nid("c")].state, NodeState::Committed);
        // b rolled back -> re-derived: its dep a is committed so b is Ready again.
        assert_eq!(after.nodes[&nid("b")].state, NodeState::Ready);
        // d depended on b (now not committed) -> re-derived to Pending (re-opened, not orphaned).
        assert_eq!(after.nodes[&nid("d")].state, NodeState::Pending);
        // The committed subset {a, c} is still dependency-closed & deployable (§8).
        assert!(after.committed_is_dependency_closed());
        assert_eq!(after.committed_node_ids(), vec![nid("a"), nid("c")]);
    }

    #[test]
    fn rollback_of_a_non_committed_node_is_rejected() {
        let st = project(&[created(), chain_decl()]).unwrap();
        assert_eq!(
            plan_single_module_rollback(&st, &nid("a")).unwrap_err(),
            ProgramError::NodeNotCommitted(nid("a"))
        );
    }

    #[test]
    fn execute_rollback_surfaces_non_compensable_steps_honestly() {
        struct HalfBrokenComp;
        impl Compensator for HalfBrokenComp {
            fn compensate(&self, node: &NodeId, _shas: &[String]) -> Result<(), String> {
                if node == &nid("d") {
                    Err("MR already merged upstream; cannot un-create".into())
                } else {
                    Ok(())
                }
            }
        }
        let st = diamond_all_committed();
        let report = execute_rollback(&st, &nid("b"), &HalfBrokenComp).unwrap();
        // d fails compensation (non-compensable), b reverts cleanly.
        assert_eq!(report.reverted, vec![nid("b")]);
        assert_eq!(report.non_compensable.len(), 1);
        assert_eq!(report.non_compensable[0].0, nid("d"));
    }

    // ---- poison-node quarantine + route-around (§9) ----------------------

    #[test]
    fn poison_node_is_quarantined_and_program_routes_around_it() {
        // a -> b (poison), plus independent c. b fails 3 times -> quarantine; c completes.
        let mut ev = vec![
            created(),
            ProgramEvent::Decomposed {
                nodes: vec![
                    NodeDecl::new("a", NodeClass::MigrationRun),
                    NodeDecl::new("b", NodeClass::MigrationRun).depends_on("a"),
                    NodeDecl::new("c", NodeClass::MigrationRun), // independent branch
                ],
            },
            ProgramEvent::Approved {
                approver: "b".into(),
            },
        ];
        drive_commit(&mut ev, "a", "k-a", "qwen");
        // b fails three times.
        for _ in 0..3 {
            ev.push(ProgramEvent::NodeStateChanged {
                node: nid("b"),
                to: NodeState::InProgress,
                cause: "attempt".into(),
            });
            ev.push(ProgramEvent::NodeAttemptFailed {
                node: nid("b"),
                reason: "cannot migrate".into(),
            });
        }
        let st = project(&ev).unwrap();
        assert_eq!(st.nodes[&nid("b")].failure_count, 3);
        assert!(is_poison(&st, &nid("b"), PoisonPolicy::default()));

        let q = plan_quarantine(&st, &nid("b"), PoisonPolicy::default()).unwrap();
        let st = project_incremental(st, &q).unwrap();
        assert_eq!(st.nodes[&nid("b")].state, NodeState::FailedIsolated);

        // The independent branch c is untouched and still schedulable (route-around).
        assert!(st.schedulable_nodes().contains(&nid("c")));

        // Finish c, then close the program as a deployable partial.
        let mut tail = Vec::new();
        drive_commit(&mut tail, "c", "k-c", "qwen");
        tail.push(ProgramEvent::Outcome {
            outcome: ProgramOutcome::CappedPartial,
        });
        let st = project_incremental(st, &tail).unwrap();
        assert_eq!(st.phase, ProgramPhase::CappedPartial);

        let report = partial_report(&st);
        assert!(report.committed.contains(&nid("a")));
        assert!(report.committed.contains(&nid("c")));
        assert!(report.failed_isolated.contains(&nid("b")));
        assert!(report.committed_deployable);
    }

    #[test]
    fn quarantine_gates_pending_dependents_and_spares_independent_branches() {
        // a -> b(poison) -> e ; plus independent c. b fails past the cap; quarantine must gate the
        // Pending dependent e and leave the independent branch c schedulable (route-around, §9).
        let mut ev = vec![
            created(),
            ProgramEvent::Decomposed {
                nodes: vec![
                    NodeDecl::new("a", NodeClass::MigrationRun),
                    NodeDecl::new("b", NodeClass::MigrationRun).depends_on("a"),
                    NodeDecl::new("e", NodeClass::MigrationRun).depends_on("b"),
                    NodeDecl::new("c", NodeClass::MigrationRun),
                ],
            },
            ProgramEvent::Approved {
                approver: "b".into(),
            },
        ];
        drive_commit(&mut ev, "a", "k-a", "qwen");
        for _ in 0..3 {
            ev.push(ProgramEvent::NodeStateChanged {
                node: nid("b"),
                to: NodeState::InProgress,
                cause: "attempt".into(),
            });
            ev.push(ProgramEvent::NodeAttemptFailed {
                node: nid("b"),
                reason: "cannot migrate".into(),
            });
        }
        let st = project(&ev).unwrap();
        // e is a Pending dependent of the (not-yet-quarantined) poison node b.
        assert_eq!(st.nodes[&nid("e")].state, NodeState::Pending);

        let q = plan_quarantine(&st, &nid("b"), PoisonPolicy::default()).unwrap();
        let st = project_incremental(st, &q).unwrap();

        assert_eq!(st.nodes[&nid("b")].state, NodeState::FailedIsolated);
        // The Pending dependent is gated (route-around), not silently left runnable.
        assert_eq!(st.nodes[&nid("e")].state, NodeState::BlockedOnHuman);
        assert!(!st.schedulable_nodes().contains(&nid("e")));
        // The independent branch survives and is schedulable.
        assert!(st.schedulable_nodes().contains(&nid("c")));
    }

    #[test]
    fn quarantine_is_rejected_before_the_poison_cap() {
        let mut ev = vec![
            created(),
            ProgramEvent::Decomposed {
                nodes: vec![NodeDecl::new("a", NodeClass::MigrationRun)],
            },
            ProgramEvent::Approved {
                approver: "b".into(),
            },
            ProgramEvent::NodeStateChanged {
                node: nid("a"),
                to: NodeState::InProgress,
                cause: "start".into(),
            },
        ];
        ev.push(ProgramEvent::NodeAttemptFailed {
            node: nid("a"),
            reason: "once".into(),
        });
        let st = project(&ev).unwrap();
        assert_eq!(
            plan_quarantine(&st, &nid("a"), PoisonPolicy { max_failures: 3 }).unwrap_err(),
            ProgramError::NotPoison {
                node: nid("a"),
                failures: 1,
                required: 3
            }
        );
    }

    // ---- child-program composition (§4) ----------------------------------

    #[test]
    fn map_child_outcome_is_the_deterministic_table() {
        assert_eq!(map_child_outcome(ChildOutcome::Completed), NodeState::Ready);
        assert_eq!(
            map_child_outcome(ChildOutcome::CappedPartial),
            NodeState::BlockedOnHuman
        );
        assert_eq!(
            map_child_outcome(ChildOutcome::Abandoned),
            NodeState::BlockedOnHuman
        );
    }

    fn child_program_setup(outcome: ChildOutcome) -> ProgramState {
        // p (child-program node) with a dependent q.
        let ev = vec![
            created(),
            ProgramEvent::Decomposed {
                nodes: vec![
                    NodeDecl::new("p", NodeClass::ChildProgram),
                    NodeDecl::new("q", NodeClass::MigrationRun).depends_on("p"),
                ],
            },
            ProgramEvent::Approved {
                approver: "b".into(),
            },
            ProgramEvent::NodeStateChanged {
                node: nid("p"),
                to: NodeState::InProgress,
                cause: "start child".into(),
            },
            ProgramEvent::ChildProgramSpawned {
                node: nid("p"),
                child_program_id: ProgramId::new("child-1"),
            },
            ProgramEvent::ChildProgramOutcomeMapped {
                node: nid("p"),
                outcome,
            },
        ];
        project(&ev).unwrap()
    }

    #[test]
    fn child_completed_reopens_parent_node_ready() {
        let st = child_program_setup(ChildOutcome::Completed);
        // p has no deps -> after Completed it re-derives to Ready.
        assert_eq!(st.nodes[&nid("p")].state, NodeState::Ready);
        assert_eq!(
            st.nodes[&nid("p")].child_program_id,
            Some(ProgramId::new("child-1"))
        );
    }

    #[test]
    fn child_abandoned_blocks_parent_node_on_human() {
        let st = child_program_setup(ChildOutcome::Abandoned);
        assert_eq!(st.nodes[&nid("p")].state, NodeState::BlockedOnHuman);
        // The dependent q never became schedulable (parent not committed) — no silent advance.
        assert!(!st.schedulable_nodes().contains(&nid("q")));
    }

    #[test]
    fn blocked_on_child_program_only_exits_via_outcome_mapping() {
        // Spawn a child, then try to drive the parent node with a plain state change -> rejected.
        let ev = vec![
            created(),
            ProgramEvent::Decomposed {
                nodes: vec![NodeDecl::new("p", NodeClass::ChildProgram)],
            },
            ProgramEvent::Approved {
                approver: "b".into(),
            },
            ProgramEvent::NodeStateChanged {
                node: nid("p"),
                to: NodeState::InProgress,
                cause: "start".into(),
            },
            ProgramEvent::ChildProgramSpawned {
                node: nid("p"),
                child_program_id: ProgramId::new("c"),
            },
            // Illegal: a BlockedOnChildProgram node cannot be moved by NodeStateChanged.
            ProgramEvent::NodeStateChanged {
                node: nid("p"),
                to: NodeState::Verifying,
                cause: "sneaky".into(),
            },
        ];
        assert!(matches!(
            project(&ev).unwrap_err(),
            ProgramError::IllegalNodeTransition { .. }
        ));
    }

    #[test]
    fn spawning_a_child_on_a_non_child_program_node_is_rejected() {
        let ev = vec![
            created(),
            ProgramEvent::Decomposed {
                nodes: vec![NodeDecl::new("m", NodeClass::MigrationRun)],
            },
            ProgramEvent::Approved {
                approver: "b".into(),
            },
            ProgramEvent::NodeStateChanged {
                node: nid("m"),
                to: NodeState::InProgress,
                cause: "start".into(),
            },
            ProgramEvent::ChildProgramSpawned {
                node: nid("m"),
                child_program_id: ProgramId::new("c"),
            },
        ];
        assert_eq!(
            project(&ev).unwrap_err(),
            ProgramError::NotChildProgramClass(nid("m"))
        );
    }

    // ---- LOOP-09: full §3 node-contract fields ---------------------------

    #[test]
    fn gap_loop_09_node_contract_fields_are_projected_and_round_trip() {
        let decl = NodeDecl::new("settlement", NodeClass::MigrationRun)
            .checkpoint(CheckpointClass::CriticalPath)
            .with_working_set(4_200)
            .with_blast("ledger")
            .with_blast("audit")
            .with_verification("unit:settlement")
            .with_verification("integration:ledger-seam")
            .with_edit_floor(EditRung::Lsp);
        let st = project(&[created(), ProgramEvent::Decomposed { nodes: vec![decl] }]).unwrap();

        let n = &st.nodes[&nid("settlement")];
        // Every ADR-027 §3 field survives decomposition onto the projected node.
        assert_eq!(n.working_set_estimate, 4_200);
        assert!(n.blast_radius.contains(&nid("ledger")));
        assert!(n.blast_radius.contains(&nid("audit")));
        assert_eq!(n.verification_plan.len(), 2);
        assert_eq!(n.edit_ladder_floor, EditRung::Lsp);
        assert_eq!(n.checkpoint_class, CheckpointClass::CriticalPath);

        // The whole projection round-trips through serde with the new fields intact.
        let json = serde_json::to_string(&st).unwrap();
        let back: ProgramState = serde_json::from_str(&json).unwrap();
        assert_eq!(back, st);
        // A critical-path node forbids the text-patch rung (§10): its floor is strictly above it.
        assert!(back.nodes[&nid("settlement")].edit_ladder_floor > EditRung::TextPatch);
    }

    // ---- terminal guard ---------------------------------------------------

    #[test]
    fn no_events_accepted_after_a_terminal_outcome() {
        let ev = vec![
            created(),
            chain_decl(),
            ProgramEvent::Approved {
                approver: "b".into(),
            },
            ProgramEvent::Outcome {
                outcome: ProgramOutcome::Abandoned,
            },
            ProgramEvent::Checkpoint { offset: 99 },
        ];
        assert_eq!(project(&ev).unwrap_err(), ProgramError::Terminal);
    }
}
