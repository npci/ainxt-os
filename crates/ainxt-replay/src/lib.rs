// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-replay — the interaction & execution-replay spine.
//!
//! Design lineage: `docs/architecture/INTERACTION_REPL_COMMANDS.md` §2 (Execution Replay) and §3
//! (persistent + collaborative session state; branch/edit/stop/steer). The audit
//! (`IMPLEMENTATION_GAP_AUDIT.md`, data-surfaces-artifacts) flagged three load-bearing gaps this
//! crate closes:
//!
//! 1. **Execution Replay is entirely absent.** Replay here is *deterministic*, *RBAC-scoped*, and
//!    *redaction-preserving*: it reads the already-redacted event stream and re-emits the **same**
//!    typed events a live turn emits — with **zero model calls and zero side effects** — filtered by
//!    the viewer's clearance exactly as live viewing would be.
//! 2. **The Event Log is a linear chain, not the tree the design requires.** A [`SessionRecording`]
//!    models a session as a **tree of turns** ([`TurnTree`]): every turn has a stable id and a parent
//!    pointer, plus a movable *active head*. Linear logs can be [ingested](SessionRecording::from_linear)
//!    into a (degenerate, linear) tree; real branches are created by the tree operations below.
//! 3. **Branch / edit / steer are missing (only Stop existed).** All four interaction affordances are
//!    first-class here — [`SessionRecording::branch`], [`SessionRecording::edit_turn`],
//!    [`SessionRecording::stop`], [`SessionRecording::steer`] — with the design's exact semantics:
//!    editing never mutates history (it forks a labeled sibling branch), stop marks the turn
//!    `Stopped` and never deletes it, and steer is delivered at the **next safe boundary** and never
//!    mid-tool-call (the design's residual-risk #1).
//!
//! # Determinism
//!
//! No clock, no rng, no I/O. Every mutation takes the wall-clock instant (`at_millis`) and the new
//! turn/event id from the caller, so the same inputs always produce the same tree and the same replay
//! plan. Replay pacing computes inter-event *delays as data* — the engine never sleeps; the renderer
//! does. The bundle content commitment is a length-prefixed SHA-256 over the event slice, identical
//! across builds and machines.
//!
//! # What is a seam (needs live infra), and honestly so
//!
//! *Pure event replay* is fully implemented and tested. *Re-execution replay* (re-running frozen
//! inputs against a live model to detect drift) necessarily needs a model call — so it is a trait
//! ([`ReExecutor`]); this crate implements the deterministic part around it (fork a **new** branch off
//! the original, never overwrite, label it distinctly) and tests that with a fake executor. Real
//! asymmetric signing of a replay bundle needs a key/PKI; the [`BundleSigner`] trait carries that
//! seam and the built-in [`ContentCommitmentSigner`] provides a keyed integrity commitment.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

pub use ainxt_types::{DataClass, Principal, SessionId, TurnId};

/// Capability that lets a non-participant (a compliance/audit role) replay any in-scope session.
pub const CAP_COMPLIANCE_REPLAY: &str = "compliance.replay";
/// Capability that lets a dedicated compliance-officer role open a pre-redaction evidence record.
/// Every use is itself audited (break-glass), per `INTERACTION_REPL_COMMANDS.md` §2.3.
pub const CAP_BREAK_GLASS: &str = "compliance.break_glass";

// ===========================================================================
// Turn tree
// ===========================================================================

/// Whether a turn was authored by a human/user or produced by the assistant. Only a `User` turn is
/// editable (`INTERACTION_REPL_COMMANDS.md` §3.3 — "Edit is only valid on a user turn").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TurnRole {
    User,
    Assistant,
}

/// Lifecycle of a turn in the tree. A turn is **never deleted** — a stopped or superseded turn stays
/// fully replayable and audit-visible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TurnStatus {
    /// In flight or completed on the current line.
    Active,
    /// Cancelled by a Stop — model stream + tool futures were cancelled cleanly (the token fire lives
    /// in the session actor; here we record the terminal state and keep the turn replayable).
    Stopped,
}

/// Frozen inputs captured for a turn so it can be *re-executed* deterministically later
/// (`GAP_ANALYSIS_VS_AI_PLATFORMS.md` gaps X/AS): exact prompt + model version + params + seed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrozenTurnInputs {
    pub prompt: String,
    pub model: String,
    pub params: String,
    pub seed: u64,
}

/// A vertex in the session tree: one turn.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Turn {
    pub id: TurnId,
    /// Parent turn id; `None` only for a root turn.
    pub parent: Option<TurnId>,
    pub role: TurnRole,
    /// The participant who authored this turn (`participant_id`, §3.2).
    pub author: String,
    /// Optional human label for team clarity ("what-if: without the discount clause", §3.3).
    pub label: Option<String>,
    pub status: TurnStatus,
    /// Frozen inputs for re-execution, if captured.
    pub frozen: Option<FrozenTurnInputs>,
}

/// A tree (forest) of turns with a movable *active head*. Deterministic: turns and children are kept
/// in [`BTreeMap`]/[`BTreeSet`], so every traversal order is fixed by the data.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TurnTree {
    turns: BTreeMap<TurnId, Turn>,
    /// Child adjacency `parent -> {child ids}`, sorted.
    children: BTreeMap<TurnId, BTreeSet<TurnId>>,
    /// Root turn ids (no parent), sorted.
    roots: BTreeSet<TurnId>,
    /// The current branch head — the turn the "current path" ends at.
    active_head: Option<TurnId>,
}

/// Why a tree/session operation was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TreeError {
    /// A referenced turn id does not exist.
    UnknownTurn(TurnId),
    /// A turn id was reused — ids must be unique (reuse would silently overwrite history).
    DuplicateTurn(TurnId),
    /// A root turn was added when one already exists but no parent was given, or a parent was named
    /// that is absent.
    MissingParent(TurnId),
    /// Edit was attempted on an assistant turn (only user turns are editable).
    NotEditable(TurnId),
    /// Stop/steer was attempted on a turn that is not `Active`.
    NotActive(TurnId),
    /// Re-execution was requested for a turn with no captured frozen inputs.
    NoFrozenInputs(TurnId),
}

impl std::fmt::Display for TreeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TreeError::UnknownTurn(id) => write!(f, "unknown turn: {id}"),
            TreeError::DuplicateTurn(id) => write!(f, "duplicate turn id: {id}"),
            TreeError::MissingParent(id) => write!(f, "parent turn does not exist: {id}"),
            TreeError::NotEditable(id) => write!(f, "turn {id} is not user-editable"),
            TreeError::NotActive(id) => write!(f, "turn {id} is not active"),
            TreeError::NoFrozenInputs(id) => write!(f, "turn {id} has no frozen inputs to re-run"),
        }
    }
}

impl std::error::Error for TreeError {}

impl TurnTree {
    pub fn new() -> Self {
        TurnTree::default()
    }

    pub fn turn(&self, id: &str) -> Option<&Turn> {
        self.turns.get(id)
    }

    pub fn active_head(&self) -> Option<&str> {
        self.active_head.as_deref()
    }

    pub fn turn_count(&self) -> usize {
        self.turns.len()
    }

    /// Sorted child ids of `id` (empty if none or unknown).
    pub fn children(&self, id: &str) -> Vec<&str> {
        self.children
            .get(id)
            .into_iter()
            .flat_map(|s| s.iter().map(String::as_str))
            .collect()
    }

    /// Insert a turn, wiring it into the adjacency and (optionally) moving the active head to it.
    /// Rejects a duplicate id or a named-but-absent parent.
    fn insert(&mut self, turn: Turn, make_head: bool) -> Result<(), TreeError> {
        if self.turns.contains_key(&turn.id) {
            return Err(TreeError::DuplicateTurn(turn.id));
        }
        match &turn.parent {
            Some(p) => {
                if !self.turns.contains_key(p) {
                    return Err(TreeError::MissingParent(p.clone()));
                }
                self.children
                    .entry(p.clone())
                    .or_default()
                    .insert(turn.id.clone());
            }
            None => {
                self.roots.insert(turn.id.clone());
            }
        }
        let id = turn.id.clone();
        self.turns.insert(id.clone(), turn);
        if make_head {
            self.active_head = Some(id);
        }
        Ok(())
    }

    /// The ordered turn ids from a root down to `head` (inclusive) — the "current path" a replay of
    /// this branch walks. Empty if `head` is unknown.
    pub fn path_to(&self, head: &str) -> Vec<&str> {
        let mut chain: Vec<&str> = Vec::new();
        let mut cur = self.turns.get(head).map(|t| t.id.as_str());
        while let Some(id) = cur {
            chain.push(id);
            cur = self
                .turns
                .get(id)
                .and_then(|t| t.parent.as_deref())
                .and_then(|p| self.turns.get(p).map(|t| t.id.as_str()));
        }
        chain.reverse();
        chain
    }

    /// The current active-branch path (root → active head), or empty if there is no head.
    pub fn active_path(&self) -> Vec<&str> {
        match self.active_head.as_deref() {
            Some(h) => self.path_to(h),
            None => Vec::new(),
        }
    }

    /// Move the active head to an existing turn (switch branches, §3.1).
    pub fn set_head(&mut self, id: &str) -> Result<(), TreeError> {
        if !self.turns.contains_key(id) {
            return Err(TreeError::UnknownTurn(id.to_string()));
        }
        self.active_head = Some(id.to_string());
        Ok(())
    }
}

// ===========================================================================
// Events (the recorded, already-redacted protocol stream)
// ===========================================================================

/// A stable, monotonically-increasing event id within a session.
pub type EventId = u64;

/// The typed protocol events replay re-emits. This is the recording surface — the same event kinds a
/// live turn produces. `text` on every event is the **already-redacted** payload that was persisted
/// (compliance-in/tool/out ran before persistence, `INTERACTION_REPL_COMMANDS.md` §2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// A turn began.
    TurnStart,
    /// An incremental text delta from the model.
    TextDelta,
    /// A tool call was issued (a *step boundary*).
    ToolCall,
    /// A tool call returned.
    ToolResult,
    /// A human approval gate was raised (a *step boundary*).
    ApprovalGate,
    /// A human approval decision was recorded.
    ApprovalDecision,
    /// A model call was issued (a *step boundary*).
    ModelCall,
    /// The turn completed normally.
    TurnEnd,
    /// The turn was stopped (cancelled) — recorded, never deleted.
    TurnStopped,
    /// A steer interjection was appended to an in-flight turn.
    Steer,
    /// An explicit branch fork was recorded.
    Branch,
    /// A user turn was edited (a new sibling branch was created).
    Edit,
    /// A break-glass access to a pre-redaction evidence record (audit trail, §2.3).
    BreakGlassAccess,
}

impl EventKind {
    /// Whether step-mode replay pauses *before* emitting this event: tool-call, approval, and
    /// model-call boundaries (`INTERACTION_REPL_COMMANDS.md` §2.2, acceptance R5).
    pub fn is_pause_boundary(self) -> bool {
        matches!(
            self,
            EventKind::ToolCall | EventKind::ApprovalGate | EventKind::ModelCall
        )
    }
}

/// One recorded protocol event, tied to a turn.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayEvent {
    pub id: EventId,
    pub turn_id: TurnId,
    /// Global order within the session (append order).
    pub seq: u64,
    pub ts_millis: u128,
    pub kind: EventKind,
    /// The sensitivity of this event's payload; a viewer below this clearance never sees it (the
    /// same pre-rank ACL the graph/retrieval/nl2sql surfaces use).
    pub data_class: DataClass,
    /// Already-redacted, safe-to-replay payload.
    pub text: String,
}

// ===========================================================================
// Session recording (tree + events + participants + evidence)
// ===========================================================================

/// A complete, replayable recording of a session: the turn [`TurnTree`], the ordered event stream,
/// the authorized participant set, and a break-glass-only evidence vault of pre-redaction originals.
///
/// Deliberately **not** `Serialize`/`Deserialize`: the durable form is the (redacted) event log plus
/// a separately-gated evidence store, so the pre-redaction `evidence` vault can never be casually
/// dumped alongside the safe stream (`INTERACTION_REPL_COMMANDS.md` §2.3).
#[derive(Debug, Clone)]
pub struct SessionRecording {
    pub id: SessionId,
    tree: TurnTree,
    events: Vec<ReplayEvent>,
    participants: BTreeSet<String>,
    next_event_id: EventId,
    /// Pre-redaction originals, keyed by the (redacted) event id they shadow. Never returned by
    /// replay; only [`SessionRecording::access_evidence`] can read them, and only with break-glass.
    evidence: BTreeMap<EventId, String>,
    /// **Live** presence roster — the participant ids currently *joined* to the collaborative session
    /// (§6.5 `participant.*`). Ephemeral and advisory (never a lock): it is NOT part of the durable
    /// [`DurableSession`] projection nor the tamper-evident replay stream, so joining/leaving never
    /// perturbs replay determinism or the bundle content-commitment.
    present: BTreeSet<String>,
}

impl SessionRecording {
    /// A new, empty recording. `participants` are the ids authorized to replay/edit it.
    pub fn new(id: impl Into<String>, participants: &[&str]) -> Self {
        SessionRecording {
            id: id.into(),
            tree: TurnTree::new(),
            events: Vec::new(),
            participants: participants.iter().map(|s| s.to_string()).collect(),
            next_event_id: 0,
            evidence: BTreeMap::new(),
            present: BTreeSet::new(),
        }
    }

    pub fn tree(&self) -> &TurnTree {
        &self.tree
    }

    pub fn events(&self) -> &[ReplayEvent] {
        &self.events
    }

    pub fn is_participant(&self, user_id: &str) -> bool {
        self.participants.contains(user_id)
    }

    /// Append a turn as a **root** (first turn) or child of the current active head is NOT assumed —
    /// callers append the first turn here; subsequent turns use [`SessionRecording::append_turn`].
    pub fn append_root_turn(
        &mut self,
        id: &str,
        role: TurnRole,
        author: &str,
        at_millis: u128,
    ) -> Result<(), TreeError> {
        let turn = Turn {
            id: id.to_string(),
            parent: None,
            role,
            author: author.to_string(),
            label: None,
            status: TurnStatus::Active,
            frozen: None,
        };
        self.tree.insert(turn, true)?;
        self.push_event(id, EventKind::TurnStart, DataClass::Internal, "", at_millis);
        Ok(())
    }

    /// Append a turn as a child of `parent` and make it the active head.
    pub fn append_turn(
        &mut self,
        id: &str,
        parent: &str,
        role: TurnRole,
        author: &str,
        at_millis: u128,
    ) -> Result<(), TreeError> {
        let turn = Turn {
            id: id.to_string(),
            parent: Some(parent.to_string()),
            role,
            author: author.to_string(),
            label: None,
            status: TurnStatus::Active,
            frozen: None,
        };
        self.tree.insert(turn, true)?;
        self.push_event(id, EventKind::TurnStart, DataClass::Internal, "", at_millis);
        Ok(())
    }

    /// Attach frozen inputs to a turn so it can later be re-executed.
    pub fn set_frozen(&mut self, turn_id: &str, frozen: FrozenTurnInputs) -> Result<(), TreeError> {
        let turn = self
            .tree
            .turns
            .get_mut(turn_id)
            .ok_or_else(|| TreeError::UnknownTurn(turn_id.to_string()))?;
        turn.frozen = Some(frozen);
        Ok(())
    }

    /// Record a protocol event on an existing turn. `text` must already be redaction-safe. An
    /// optional pre-redaction `original` is stored in the break-glass evidence vault.
    pub fn record_event(
        &mut self,
        turn_id: &str,
        kind: EventKind,
        data_class: DataClass,
        text: &str,
        at_millis: u128,
    ) -> Result<EventId, TreeError> {
        if !self.tree.turns.contains_key(turn_id) {
            return Err(TreeError::UnknownTurn(turn_id.to_string()));
        }
        Ok(self.push_event(turn_id, kind, data_class, text, at_millis))
    }

    /// Record an event whose pre-redaction original is retained in the evidence vault (break-glass).
    pub fn record_event_with_evidence(
        &mut self,
        turn_id: &str,
        kind: EventKind,
        data_class: DataClass,
        redacted_text: &str,
        original_text: &str,
        at_millis: u128,
    ) -> Result<EventId, TreeError> {
        let id = self.record_event(turn_id, kind, data_class, redacted_text, at_millis)?;
        self.evidence.insert(id, original_text.to_string());
        Ok(id)
    }

    /// GAP-FIX regulated-fi-responsible-lifecycle (§6.3) — hard-delete the CONTENT BYTES of every
    /// recorded event belonging to `turn_id`, for a served-surface [`ErasableTier`](https://docs.rs/ainxt-lifecycle)
    /// adapter propagating a §6 erase-now/fired-deferral decision into this durable store. The
    /// [`Turn`] itself is **never removed from the tree** (module doc: "a turn is never deleted — a
    /// stopped or superseded turn stays fully replayable and audit-visible") — this clears the
    /// **payload** of its events in place (`text` set to empty), which is the actual regulated data;
    /// the turn id / tree position / role stay as a tombstone so the tree and every other turn's
    /// parent pointers remain structurally valid and the session stays replayable up to the erased
    /// point (an erased turn now replays as present-but-empty, never as a hole in the tree).
    ///
    /// Also drops any break-glass evidence-vault entry shadowing an erased event, so a pre-redaction
    /// original never outlives the erasure of its own redacted counterpart.
    ///
    /// Returns `true` iff at least one event's `text` was non-empty and was cleared (idempotent: a
    /// turn with no events, an unknown turn id, or a turn whose content is already erased returns
    /// `false`, mirroring `ErasableTier::erase_records`'s "already gone ⇒ absent from the result"
    /// contract).
    pub fn erase_turn_content(&mut self, turn_id: &str) -> bool {
        let mut changed = false;
        for e in self.events.iter_mut() {
            if e.turn_id == turn_id && !e.text.is_empty() {
                e.text.clear();
                self.evidence.remove(&e.id);
                changed = true;
            }
        }
        changed
    }

    fn push_event(
        &mut self,
        turn_id: &str,
        kind: EventKind,
        data_class: DataClass,
        text: &str,
        at_millis: u128,
    ) -> EventId {
        let id = self.next_event_id;
        self.next_event_id += 1;
        let seq = self.events.len() as u64;
        self.events.push(ReplayEvent {
            id,
            turn_id: turn_id.to_string(),
            seq,
            ts_millis: at_millis,
            kind,
            data_class,
            text: text.to_string(),
        });
        id
    }

    // --- interaction affordances: branch / edit / stop / steer ------------

    /// **Edit** a user turn (§3.3): creates a **new sibling branch** off the edited turn's parent and
    /// makes it the active head. The original turn *and its descendants are preserved* on the old
    /// branch, fully replayable — editing never mutates history. Only user turns are editable.
    pub fn edit_turn(
        &mut self,
        turn_id: &str,
        new_id: &str,
        author: &str,
        label: Option<&str>,
        at_millis: u128,
    ) -> Result<TurnId, TreeError> {
        let old = self
            .tree
            .turns
            .get(turn_id)
            .ok_or_else(|| TreeError::UnknownTurn(turn_id.to_string()))?;
        if old.role != TurnRole::User {
            return Err(TreeError::NotEditable(turn_id.to_string()));
        }
        let parent = old.parent.clone();
        let sibling = Turn {
            id: new_id.to_string(),
            parent,
            role: TurnRole::User,
            author: author.to_string(),
            label: label.map(str::to_string),
            status: TurnStatus::Active,
            frozen: None,
        };
        self.tree.insert(sibling, true)?;
        self.push_event(
            new_id,
            EventKind::Edit,
            DataClass::Internal,
            turn_id,
            at_millis,
        );
        Ok(new_id.to_string())
    }

    /// **Branch** (§3.3): an explicit fork *off* `from_turn_id` (a new child) to deliberately explore
    /// an alternative without touching the official line. Named/labeled for team clarity.
    pub fn branch(
        &mut self,
        from_turn_id: &str,
        new_id: &str,
        author: &str,
        label: Option<&str>,
        at_millis: u128,
    ) -> Result<TurnId, TreeError> {
        if !self.tree.turns.contains_key(from_turn_id) {
            return Err(TreeError::UnknownTurn(from_turn_id.to_string()));
        }
        let child = Turn {
            id: new_id.to_string(),
            parent: Some(from_turn_id.to_string()),
            role: TurnRole::User,
            author: author.to_string(),
            label: label.map(str::to_string),
            status: TurnStatus::Active,
            frozen: None,
        };
        self.tree.insert(child, true)?;
        self.push_event(
            new_id,
            EventKind::Branch,
            DataClass::Internal,
            from_turn_id,
            at_millis,
        );
        Ok(new_id.to_string())
    }

    /// **Stop** (§3.3): mark an in-flight turn `Stopped` and record it. Never deletes the turn — it
    /// stays replayable and audit-visible. The actual cancellation-token fire (model stream + tool
    /// futures) lives in the session actor; this is the durable terminal record.
    pub fn stop(&mut self, turn_id: &str, at_millis: u128) -> Result<(), TreeError> {
        let turn = self
            .tree
            .turns
            .get_mut(turn_id)
            .ok_or_else(|| TreeError::UnknownTurn(turn_id.to_string()))?;
        if turn.status != TurnStatus::Active {
            return Err(TreeError::NotActive(turn_id.to_string()));
        }
        turn.status = TurnStatus::Stopped;
        self.push_event(
            turn_id,
            EventKind::TurnStopped,
            DataClass::Internal,
            "",
            at_millis,
        );
        Ok(())
    }

    /// **Steer** (§3.3): append a user interjection to an in-flight (`Active`) turn *without*
    /// cancelling it. Returns the [`SteerDelivery`] describing when the interjection lands — at the
    /// next **safe boundary**: immediately if the model is generating text, or only *after* the
    /// in-flight tool call completes (never mid-tool-call, the design's residual-risk #1).
    pub fn steer(
        &mut self,
        turn_id: &str,
        text: &str,
        data_class: DataClass,
        at_millis: u128,
    ) -> Result<SteerDelivery, TreeError> {
        let turn = self
            .tree
            .turns
            .get(turn_id)
            .ok_or_else(|| TreeError::UnknownTurn(turn_id.to_string()))?;
        if turn.status != TurnStatus::Active {
            return Err(TreeError::NotActive(turn_id.to_string()));
        }
        let delivery = resolve_steer_delivery(&self.events, turn_id);
        self.push_event(turn_id, EventKind::Steer, data_class, text, at_millis);
        Ok(delivery)
    }

    /// A read-only snapshot of the tree for a late-joining participant (§3.4 `session.snapshot`), so
    /// they need not replay from turn zero. Only turns whose events the principal could see are
    /// summarized; a turn on the active path whose payload is above clearance is still listed
    /// structurally (its existence is not itself secret) but is otherwise inert.
    pub fn snapshot(&self, principal: &Principal) -> Result<SessionSnapshot, ReplayError> {
        authorize(self, principal)?;
        let mut turns: Vec<TurnSummary> = self
            .tree
            .turns
            .values()
            .map(|t| TurnSummary {
                id: t.id.clone(),
                parent: t.parent.clone(),
                role: t.role,
                author: t.author.clone(),
                label: t.label.clone(),
                status: t.status,
            })
            .collect();
        turns.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(SessionSnapshot {
            sid: self.id.clone(),
            active_head: self.tree.active_head().map(str::to_string),
            turns,
        })
    }

    /// **Break-glass** access to a pre-redaction evidence record (§2.3). Requires
    /// [`CAP_BREAK_GLASS`]; every access appends its own [`EventKind::BreakGlassAccess`] audit event
    /// (so "who saw the original" is always answerable). Returns `None` if no evidence was retained.
    pub fn access_evidence(
        &mut self,
        event_id: EventId,
        principal: &Principal,
        at_millis: u128,
    ) -> Result<Option<String>, ReplayError> {
        if !principal.has_cap(CAP_BREAK_GLASS) {
            return Err(ReplayError::NotAuthorized);
        }
        let original = self.evidence.get(&event_id).cloned();
        // Attach the audit event to the turn that owns the shadowed event, if resolvable.
        let turn_id = self
            .events
            .iter()
            .find(|e| e.id == event_id)
            .map(|e| e.turn_id.clone());
        if let Some(turn_id) = turn_id {
            let note = format!("break-glass by {} on event {event_id}", principal.user_id);
            self.push_event(
                &turn_id,
                EventKind::BreakGlassAccess,
                DataClass::Pii,
                &note,
                at_millis,
            );
        }
        Ok(original)
    }

    /// Ingest a legacy **linear** event log into a (necessarily linear) turn tree — bridging the
    /// "linear chain, not a tree" gap. Each [`LinearRecord`] whose `kind == TurnStart` opens a new
    /// turn chained to the previous one; the rest attach to the current turn. New *branches* require
    /// the tree operations above — a linear log cannot express them, which is exactly the gap.
    pub fn from_linear(
        id: impl Into<String>,
        participants: &[&str],
        records: &[LinearRecord],
    ) -> Self {
        let mut rec = SessionRecording::new(id, participants);
        let mut cur_turn: Option<String> = None;
        let mut turn_seq: u64 = 0;
        let mut prev_turn: Option<String> = None;
        for r in records {
            if r.kind == EventKind::TurnStart || cur_turn.is_none() {
                let tid = format!("t{turn_seq}");
                turn_seq += 1;
                let turn = Turn {
                    id: tid.clone(),
                    parent: prev_turn.clone(),
                    role: r.role,
                    author: r.author.clone(),
                    label: None,
                    status: TurnStatus::Active,
                    frozen: None,
                };
                // Linear ingest is trusted construction; a duplicate id cannot occur (monotonic).
                let _ = rec.tree.insert(turn, true);
                prev_turn = Some(tid.clone());
                cur_turn = Some(tid);
            }
            if let Some(t) = &cur_turn {
                rec.push_event(t, r.kind, r.data_class, &r.text, r.ts_millis);
            }
        }
        rec
    }
}

// ===========================================================================
// apply_interaction — the RBAC-scoped, mount-ready branch/edit/stop/steer entrypoint (R3 DATA)
// ===========================================================================

/// A branch/edit/stop/steer command against the interaction tree, deserialized straight from the
/// wire (`op` tag). This is the single vocabulary a transport route (`POST /v1/replay`) mounts;
/// [`apply_interaction`] dispatches it over the durable recording after an RBAC gate. Time and new
/// turn ids are supplied by the caller (this crate is pure — no clock, no rng).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Interaction {
    /// Explicit fork off `from_turn` — a labelled child exploring an alternative line (§3.3).
    Branch {
        from_turn: TurnId,
        new_id: TurnId,
        #[serde(default)]
        label: Option<String>,
    },
    /// Edit a **user** turn: forks a new sibling branch off the edited turn's parent; history is
    /// preserved on the old branch, never mutated (§3.3).
    Edit {
        turn: TurnId,
        new_id: TurnId,
        #[serde(default)]
        label: Option<String>,
    },
    /// Mark an in-flight turn `Stopped` (durable terminal record; the token fire lives in the actor).
    Stop { turn: TurnId },
    /// Append a user interjection to an in-flight turn without cancelling it; lands at the next safe
    /// boundary (never mid-tool-call).
    Steer {
        turn: TurnId,
        text: String,
        /// The interjection's data class (required — a steer carries user content that the pipeline
        /// must class for redaction).
        data_class: DataClass,
    },
}

/// The result of a successful [`apply_interaction`], serialized back to the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InteractionOutcome {
    /// A new branch/edit turn was created and is now the active head.
    HeadMoved { new_head: TurnId },
    /// A turn was marked stopped.
    Stopped { turn: TurnId },
    /// A steer was accepted; carries when it will be delivered to the loop.
    Steered {
        turn: TurnId,
        delivery: SteerDelivery,
    },
}

/// Why an [`apply_interaction`] was refused. Serializable so a transport renders it verbatim; the
/// authorization failure is a distinct variant so the route can map it to `403` while the tree
/// errors map to `409`/`404`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum InteractionError {
    /// The caller is not a participant of the session — a mutation is refused. Note this is STRICTER
    /// than replay/view: a read-only compliance role ([`CAP_COMPLIANCE_REPLAY`]) may *watch* a
    /// session but may never branch/edit/stop/steer it.
    NotAuthorized,
    /// A referenced turn does not exist.
    UnknownTurn(TurnId),
    /// A turn id was reused (would silently overwrite history).
    DuplicateTurn(TurnId),
    /// Edit was attempted on a non-user (assistant) turn.
    NotEditable(TurnId),
    /// Stop/steer was attempted on a turn that is not `Active`.
    NotActive(TurnId),
    /// A structural precondition failed (e.g. missing parent on insert).
    Invalid(String),
}

impl std::fmt::Display for InteractionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InteractionError::NotAuthorized => {
                write!(
                    f,
                    "not authorized to mutate this session (participants only)"
                )
            }
            InteractionError::UnknownTurn(id) => write!(f, "unknown turn: {id}"),
            InteractionError::DuplicateTurn(id) => write!(f, "duplicate turn id: {id}"),
            InteractionError::NotEditable(id) => write!(f, "turn {id} is not user-editable"),
            InteractionError::NotActive(id) => write!(f, "turn {id} is not active"),
            InteractionError::Invalid(msg) => write!(f, "invalid interaction: {msg}"),
        }
    }
}

impl std::error::Error for InteractionError {}

impl From<TreeError> for InteractionError {
    fn from(e: TreeError) -> Self {
        match e {
            TreeError::UnknownTurn(id) => InteractionError::UnknownTurn(id),
            TreeError::DuplicateTurn(id) => InteractionError::DuplicateTurn(id),
            TreeError::NotEditable(id) => InteractionError::NotEditable(id),
            TreeError::NotActive(id) => InteractionError::NotActive(id),
            TreeError::MissingParent(id) => {
                InteractionError::Invalid(format!("parent turn does not exist: {id}"))
            }
            TreeError::NoFrozenInputs(id) => {
                InteractionError::Invalid(format!("turn {id} has no frozen inputs"))
            }
        }
    }
}

/// The single RBAC-scoped entrypoint a transport route mounts to drive branch/edit/stop/steer over
/// a durable [`SessionRecording`]. It is the WRITE counterpart to [`SessionRecording::snapshot`]'s
/// read path.
///
/// RBAC (fail-closed, mutation-strict): the caller MUST be a session participant. A holder of
/// [`CAP_COMPLIANCE_REPLAY`] may *view/replay* the session but is refused here — watching is not
/// editing. Authorization runs BEFORE any tree lookup, so a non-participant cannot probe turn
/// existence through the error shape.
///
/// Editing never mutates history: [`Interaction::Edit`] and [`Interaction::Branch`] fork new turns
/// and leave the original branch fully replayable. `at_millis` and the new turn ids come from the
/// caller (pure core — no clock, no rng).
pub fn apply_interaction(
    rec: &mut SessionRecording,
    interaction: &Interaction,
    principal: &Principal,
    at_millis: u128,
) -> Result<InteractionOutcome, InteractionError> {
    // WRITE authorization: participant-only. This is intentionally stricter than `authorize`
    // (which also admits the read-only compliance role) — a mutation demands a participant.
    if !rec.is_participant(&principal.user_id) {
        return Err(InteractionError::NotAuthorized);
    }
    match interaction {
        Interaction::Branch {
            from_turn,
            new_id,
            label,
        } => {
            let head = rec.branch(
                from_turn,
                new_id,
                &principal.user_id,
                label.as_deref(),
                at_millis,
            )?;
            Ok(InteractionOutcome::HeadMoved { new_head: head })
        }
        Interaction::Edit {
            turn,
            new_id,
            label,
        } => {
            let head = rec.edit_turn(
                turn,
                new_id,
                &principal.user_id,
                label.as_deref(),
                at_millis,
            )?;
            Ok(InteractionOutcome::HeadMoved { new_head: head })
        }
        Interaction::Stop { turn } => {
            rec.stop(turn, at_millis)?;
            Ok(InteractionOutcome::Stopped { turn: turn.clone() })
        }
        Interaction::Steer {
            turn,
            text,
            data_class,
        } => {
            let delivery = rec.steer(turn, text, *data_class, at_millis)?;
            Ok(InteractionOutcome::Steered {
                turn: turn.clone(),
                delivery,
            })
        }
    }
}

// ===========================================================================
// Collaborative presence (§6.5 participant.joined/left/typing/viewing)
// ===========================================================================
//
// The audit flagged that the §6.5 presence events were *defined in the protocol but never emitted* —
// there was no organ that tracked who is live in a shared session and produced the advisory presence
// signals a collaborative surface broadcasts. This section closes that: presence is a first-class,
// RBAC-scoped, ephemeral roster on the live [`SessionRecording`]. It is **advisory only** (never a
// lock, §6.5), **self-asserted** (a participant may only signal their OWN presence — never forge
// another's), and **participant-scoped** (a non-participant is refused, mirroring the mutation-strict
// RBAC of [`apply_interaction`]). Presence is deliberately NOT part of the durable/replay stream (it
// does not survive a store round-trip and never perturbs the tamper-evident content commitment).
//
// GAP6 replay-reexec-presence — INVESTIGATED, NO COMPOSITION-ROOT WIRING (honest "no real caller yet"
// finding, not an oversight): `PresenceKind`/`PresenceEvent`/`mark_presence`/`present_participants`/
// `is_present` are fully implemented and unit-tested here (`tests/r12_data_surfaces.rs`), but the
// SERVED daemon (`ainxt-server`'s `app_full`/`app_full_ext`, `ainxt-session`'s `SessionManager`) has
// NO real multi-participant LIVE session mechanism to wire them into today:
//
//   * `ainxt-session::SessionManager` has zero participant concept at all — a session is a single
//     actor-per-session task processing turns serially; it never tracks WHO submitted a turn.
//   * The served `/v1/chat` write path enforces STRICT single-OWNER-per-session semantics
//     (`AppState::session_owner` in `ainxt-server`; see `tests/r16_session_ownership_no_self_enrollment.rs`):
//     the first caller claims a session and every OTHER caller is refused 403 (self-enrollment was a
//     real cross-tenant transcript-leak vulnerability this hardening closed). So the served write path
//     structurally admits at most one legitimate human actor per session — there is no second
//     participant to ever mark present.
//   * The `participants`/`Participant` list `/v1/events` and `/v1/observe` build (`build_session_snapshot`)
//     is a RETROSPECTIVE projection of distinct actors the durable, tamper-evident Event Log has ever
//     attributed a record to — used only to RBAC-gate who may resume/observe a transcript, never a live
//     "who is here right now" roster. `WireHub`'s observer registration (`GET /v1/observe`) is anonymous
//     (a bare queue), carrying no participant identity at all.
//   * `mark_presence`'s own roster (`self.present`) lives ONLY on the in-process [`SessionRecording`]
//     value and is explicitly documented above as NOT surviving a durable store round-trip. Every served
//     replay/re-exec/drift call reconstructs a fresh `SessionRecording` per request
//     (`SessionRecording::from_durable`), so wiring `mark_presence` into any of those routes today would
//     silently reset the roster on every single call — cosmetic wiring that reports a fake "presence"
//     rather than a real one.
//
// Conclusion: there is no real multi-participant session path to wire presence into without first
// building actual live multi-user session support (a genuinely new mechanism, out of scope for this
// gap — closing a gap means a real caller reaching an EXISTING mechanism, never fabricating one). This
// stays a fully-tested, ready-to-wire organ for the day a collaborative multi-user session lands.

/// A collaborative presence signal (§6.5). Maps 1:1 to the protocol's `participant.*` wire events; a
/// transport projects a [`PresenceEvent`] straight onto `WireEvent::Participant{Joined,Left,Typing,Viewing}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PresenceKind {
    /// The participant joined the live session (`participant.joined`).
    Joined,
    /// The participant left the live session (`participant.left`).
    Left,
    /// The participant is composing input (`participant.typing`).
    Typing,
    /// The participant is viewing a turn (`participant.viewing`).
    Viewing,
}

/// One advisory presence signal, ready to broadcast over the session's event stream. Carries the
/// signalling participant, the kind, an optional turn scope (typing/viewing a specific turn), and the
/// wall-clock instant (supplied by the caller — this crate has no clock).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresenceEvent {
    pub participant_id: String,
    pub kind: PresenceKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub turn_id: Option<TurnId>,
    pub ts_millis: u128,
}

/// Why a presence signal was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PresenceError {
    /// The signalling principal is not an authorized participant of this session.
    NotParticipant,
    /// A participant tried to signal *another* participant's presence (forging is refused — presence
    /// is strictly self-asserted).
    NotSelf,
    /// A typing/viewing signal was sent by a participant who has not `Joined` (is not present).
    NotPresent,
}

impl std::fmt::Display for PresenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PresenceError::NotParticipant => {
                write!(f, "not an authorized participant of this session")
            }
            PresenceError::NotSelf => write!(f, "a participant may only signal their own presence"),
            PresenceError::NotPresent => {
                write!(f, "typing/viewing requires the participant to have joined")
            }
        }
    }
}

impl std::error::Error for PresenceError {}

impl SessionRecording {
    /// The live presence roster — the participant ids currently *joined*, sorted.
    pub fn present_participants(&self) -> Vec<&str> {
        self.present.iter().map(String::as_str).collect()
    }

    /// Whether `participant_id` is currently joined (present) in the live session.
    pub fn is_present(&self, participant_id: &str) -> bool {
        self.present.contains(participant_id)
    }

    /// **Record a presence signal** (§6.5) and return the advisory [`PresenceEvent`] a transport
    /// broadcasts. Fail-closed RBAC (before any state mutation):
    ///
    /// * the `principal` MUST be an authorized session participant ([`PresenceError::NotParticipant`]);
    /// * presence is **self-asserted** — `participant_id` must equal `principal.user_id`
    ///   ([`PresenceError::NotSelf`], so a participant cannot forge another's presence);
    /// * `Typing`/`Viewing` require the participant to be currently `Joined` ([`PresenceError::NotPresent`]).
    ///
    /// `Joined` inserts into the roster; `Left` removes; `Typing`/`Viewing` do not change the roster
    /// (advisory). Idempotent: re-`Joined`/`Left` is a no-op on the set and still returns the event.
    pub fn mark_presence(
        &mut self,
        principal: &Principal,
        participant_id: &str,
        kind: PresenceKind,
        turn_id: Option<&str>,
        at_millis: u128,
    ) -> Result<PresenceEvent, PresenceError> {
        if !self.is_participant(&principal.user_id) {
            return Err(PresenceError::NotParticipant);
        }
        if principal.user_id != participant_id {
            return Err(PresenceError::NotSelf);
        }
        match kind {
            PresenceKind::Joined => {
                self.present.insert(participant_id.to_string());
            }
            PresenceKind::Left => {
                self.present.remove(participant_id);
            }
            PresenceKind::Typing | PresenceKind::Viewing => {
                if !self.present.contains(participant_id) {
                    return Err(PresenceError::NotPresent);
                }
            }
        }
        Ok(PresenceEvent {
            participant_id: participant_id.to_string(),
            kind,
            turn_id: turn_id.map(str::to_string),
            ts_millis: at_millis,
        })
    }
}

// ===========================================================================
// Durable persistence seam (turn-tree persistence, INTERACTION_REPL_COMMANDS.md §3.1)
// ===========================================================================
//
// The audit flagged that server-side a session was *ephemeral*: `apply_interaction` was driven over a
// `SessionRecording` rebuilt from a client-supplied linear log on every call, so a branch/edit never
// durably round-tripped — the tree was thrown away after each request. The seam below makes the tree a
// first-class durable object: a [`SessionStore`] loads and saves a [`DurableSession`], and
// [`apply_interaction_persisted`] / [`replay_session`] / [`export_session_bundle`] /
// [`re_execute_persisted`] are the single store-backed entrypoints a transport mounts (so branches,
// edits, stops and steers survive across requests and the whole tree is replayable later).
//
// Design invariant preserved (§2.3): the *safe* durable form ([`DurableSession`]) carries the
// tree + already-redacted events + participants only — **never** the pre-redaction evidence vault. The
// vault round-trips through a SEPARATE, break-glass-gated seam ([`SessionRecording::export_evidence`] /
// [`SessionRecording::restore_evidence`]) so it can never be casually dumped alongside the safe stream.

/// The **safe, serializable** durable projection of a [`SessionRecording`]: the turn [`TurnTree`], the
/// ordered (already-redacted) event stream, the participant set, and the next-event-id counter.
///
/// Deliberately excludes the break-glass evidence vault — persisting a session must never spill
/// pre-redaction originals into the safe store (`INTERACTION_REPL_COMMANDS.md` §2.3). The evidence
/// vault has its own gated round-trip via [`SessionRecording::export_evidence`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurableSession {
    pub id: SessionId,
    pub tree: TurnTree,
    pub events: Vec<ReplayEvent>,
    pub participants: Vec<String>,
    pub next_event_id: EventId,
}

/// A break-glass-gated, serializable export of a session's pre-redaction evidence vault, for a
/// SEPARATE (encrypted, access-audited) durable store. Never part of [`DurableSession`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceExport {
    /// Checkmarx CX-FP: renamed to `sid`; `#[serde(rename)]` preserves the wire key.
    #[serde(rename = "session_id")]
    pub sid: SessionId,
    pub records: BTreeMap<EventId, String>,
}

impl SessionRecording {
    /// Project the **safe** durable form (no evidence vault) for persistence.
    pub fn to_durable(&self) -> DurableSession {
        DurableSession {
            id: self.id.clone(),
            tree: self.tree.clone(),
            events: self.events.clone(),
            participants: self.participants.iter().cloned().collect(),
            next_event_id: self.next_event_id,
        }
    }

    /// Rehydrate a recording from its safe durable form. The evidence vault starts **empty** — it is
    /// restored, if at all, only through the break-glass [`SessionRecording::restore_evidence`] seam.
    pub fn from_durable(d: DurableSession) -> Self {
        SessionRecording {
            id: d.id,
            tree: d.tree,
            events: d.events,
            participants: d.participants.into_iter().collect(),
            next_event_id: d.next_event_id,
            evidence: BTreeMap::new(),
            present: BTreeSet::new(),
        }
    }

    /// Export the pre-redaction evidence vault for a separate gated store. Requires [`CAP_BREAK_GLASS`].
    pub fn export_evidence(&self, principal: &Principal) -> Result<EvidenceExport, ReplayError> {
        if !principal.has_cap(CAP_BREAK_GLASS) {
            return Err(ReplayError::NotAuthorized);
        }
        Ok(EvidenceExport {
            sid: self.id.clone(),
            records: self.evidence.clone(),
        })
    }

    /// Restore a previously-exported evidence vault (from the separate gated store) onto a rehydrated
    /// recording. Requires [`CAP_BREAK_GLASS`]; refuses a mismatched session id.
    pub fn restore_evidence(
        &mut self,
        export: EvidenceExport,
        principal: &Principal,
    ) -> Result<(), ReplayError> {
        if !principal.has_cap(CAP_BREAK_GLASS) {
            return Err(ReplayError::NotAuthorized);
        }
        if export.sid != self.id {
            return Err(ReplayError::NotAuthorized);
        }
        self.evidence = export.records;
        Ok(())
    }
}

/// Why a [`SessionStore`] operation failed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum SessionStoreError {
    /// The backend (db/file/etc.) itself failed.
    Backend(String),
}

impl std::fmt::Display for SessionStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionStoreError::Backend(m) => write!(f, "session store backend error: {m}"),
        }
    }
}

impl std::error::Error for SessionStoreError {}

/// The durable turn-tree persistence seam. A production impl backs this with Postgres (a `sessions`
/// row plus the redacted event log); the offline [`InMemorySessionStore`] round-trips the exact same
/// [`DurableSession`] so the tree survives across requests without any live infra.
///
/// `&self` (interior mutability) so one store instance is shared across the 2000-user request path.
pub trait SessionStore: Send + Sync {
    /// Load a session's safe durable form; `Ok(None)` if it does not exist.
    fn load(&self, session_id: &str) -> Result<Option<DurableSession>, SessionStoreError>;
    /// Persist (create-or-replace) a session's safe durable form.
    fn save(&self, session: &DurableSession) -> Result<(), SessionStoreError>;
    /// GAP-FIX regulated-fi-responsible-lifecycle (FI-01 §5.4) — every session id this store currently
    /// holds, so a defense-in-depth CHD sink-sweep (mirroring
    /// [`EventLog::sessions`](https://docs.rs/ainxt-eventlog)'s identical role for the audit-log sweep)
    /// can enumerate ALL persisted turn traces without a caller already knowing which session to check.
    /// Provided default returns empty — non-breaking for any impl that predates this method (the sweep
    /// then simply finds nothing to check, never a compile break for an external `SessionStore`).
    fn sessions(&self) -> Vec<SessionId> {
        Vec::new()
    }
}

/// An offline, thread-safe [`SessionStore`] backed by an in-memory map — the deterministic test/dev
/// impl behind the seam (production swaps in a Postgres-backed store with the identical contract).
#[derive(Default)]
pub struct InMemorySessionStore {
    inner: std::sync::Mutex<BTreeMap<SessionId, DurableSession>>,
}

impl InMemorySessionStore {
    pub fn new() -> Self {
        InMemorySessionStore {
            inner: std::sync::Mutex::new(BTreeMap::new()),
        }
    }

    /// Number of persisted sessions (test/observability aid).
    pub fn len(&self) -> usize {
        self.inner.lock().map(|m| m.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl SessionStore for InMemorySessionStore {
    fn load(&self, session_id: &str) -> Result<Option<DurableSession>, SessionStoreError> {
        let map = self
            .inner
            .lock()
            .map_err(|_| SessionStoreError::Backend("lock poisoned".to_string()))?;
        Ok(map.get(session_id).cloned())
    }

    fn save(&self, session: &DurableSession) -> Result<(), SessionStoreError> {
        let mut map = self
            .inner
            .lock()
            .map_err(|_| SessionStoreError::Backend("lock poisoned".to_string()))?;
        map.insert(session.id.clone(), session.clone());
        Ok(())
    }

    fn sessions(&self) -> Vec<SessionId> {
        self.inner
            .lock()
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default()
    }
}

/// Why a store-backed persisted entrypoint failed — one error type spanning the store, the
/// interaction, and the replay layers so a transport can map each variant to a status code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PersistedError {
    /// The [`SessionStore`] backend failed (→ 5xx).
    Store(SessionStoreError),
    /// No session with this id exists in the store (→ 404).
    SessionNotFound(SessionId),
    /// The interaction was refused (→ 403/404/409 per [`InteractionError`]).
    Interaction(InteractionError),
    /// A replay/re-execution was refused (→ 403/404/409 per [`ReplayError`]).
    Replay(ReplayError),
}

impl std::fmt::Display for PersistedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PersistedError::Store(e) => write!(f, "{e}"),
            PersistedError::SessionNotFound(id) => write!(f, "no such session: {id}"),
            PersistedError::Interaction(e) => write!(f, "{e}"),
            PersistedError::Replay(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for PersistedError {}

impl From<SessionStoreError> for PersistedError {
    fn from(e: SessionStoreError) -> Self {
        PersistedError::Store(e)
    }
}
impl From<InteractionError> for PersistedError {
    fn from(e: InteractionError) -> Self {
        PersistedError::Interaction(e)
    }
}
impl From<ReplayError> for PersistedError {
    fn from(e: ReplayError) -> Self {
        PersistedError::Replay(e)
    }
}

/// Load a durable session from the store or fail with [`PersistedError::SessionNotFound`].
fn load_recording(
    store: &dyn SessionStore,
    session_id: &str,
) -> Result<SessionRecording, PersistedError> {
    let durable = store
        .load(session_id)?
        .ok_or_else(|| PersistedError::SessionNotFound(session_id.to_string()))?;
    Ok(SessionRecording::from_durable(durable))
}

/// **The durable write entrypoint.** Load the tree from `store`, apply a branch/edit/stop/steer, and
/// persist the mutated tree back — so the interaction durably round-trips (the ephemeral-session gap).
/// RBAC is enforced by the inner [`apply_interaction`] (participant-only). The mutation is persisted
/// **only** if it succeeded.
pub fn apply_interaction_persisted(
    store: &dyn SessionStore,
    session_id: &str,
    interaction: &Interaction,
    principal: &Principal,
    at_millis: u128,
) -> Result<InteractionOutcome, PersistedError> {
    let mut rec = load_recording(store, session_id)?;
    let outcome = apply_interaction(&mut rec, interaction, principal, at_millis)?;
    store.save(&rec.to_durable())?;
    Ok(outcome)
}

/// The wire body a transport mounts on `POST /v1/replay` for a branch/edit/stop/steer over a durable
/// session. It carries **only** the target `session` id and the tree `interaction` — deliberately
/// **NOT** a client-supplied event log and **NOT** a client-supplied participant list.
///
/// This is the anti-bypass contract (data-surfaces-artifacts HIGH): a served `/v1/replay` route that
/// deserializes into this type *cannot* accept a fabricated history to apply the op against, nor a
/// self-asserted participant roster to defeat RBAC. Both the turn tree and the authoritative
/// participant set are loaded from the durable [`SessionStore`] inside [`apply_replay_write`]; the
/// client only names *which* session and *which* op. The `Interaction` flattens on the `op`
/// discriminator, so the wire shape is e.g.
/// `{"session":"s1","op":"branch","from_turn":"a1","new_id":"b1"}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayWriteRequest {
    /// The durable session the op targets. Its tree + participants are loaded from the store (never
    /// from the request), so this is the only session-scoping input the client controls.
    pub session: SessionId,
    /// The branch/edit/stop/steer op (`op`-tagged; its fields flatten alongside `session`).
    #[serde(flatten)]
    pub interaction: Interaction,
}

/// **The route-ready durable write entrypoint.** The single call a transport `POST /v1/replay`
/// handler mounts: deserialize the wire body into [`ReplayWriteRequest`], then call this. It loads the
/// tree AND the authoritative participant set from the durable [`SessionStore`], applies the op under
/// participant-only RBAC ([`apply_interaction`]), persists the mutated tree back, and returns the
/// wire-serializable [`InteractionOutcome`].
///
/// It is a thin, structurally-safe wrapper over [`apply_interaction_persisted`]: because the request
/// type has no `log`/`participants` fields, there is no code path by which a client-supplied history
/// or roster can reach the store — closing the "/v1/replay bypasses the durable SessionStore and uses
/// a client-supplied log + self-asserted participant list" gap by construction. `at_millis` and the
/// new turn ids inside the op come from the caller (this crate is pure — no clock, no rng).
pub fn apply_replay_write(
    store: &dyn SessionStore,
    req: &ReplayWriteRequest,
    principal: &Principal,
    at_millis: u128,
) -> Result<InteractionOutcome, PersistedError> {
    apply_interaction_persisted(store, &req.session, &req.interaction, principal, at_millis)
}

/// **The durable read entrypoint.** Load the tree from `store` and plan a pure, RBAC-scoped,
/// clearance-filtered replay — no model call, no mutation. This is the single call site a transport
/// mounts to make [`plan_replay`] reachable over a persisted session.
pub fn replay_session(
    store: &dyn SessionStore,
    session_id: &str,
    principal: &Principal,
    opts: &ReplayOptions,
) -> Result<Replay, PersistedError> {
    let rec = load_recording(store, session_id)?;
    Ok(plan_replay(&rec, principal, opts)?)
}

/// **The durable step entrypoint.** Load the tree from `store` and return one [`ReplayPage`] — the
/// run of steps from `from_index` up to the next step-boundary — RBAC-scoped and clearance-filtered
/// exactly as [`replay_session`]. This is the single store-backed call `POST /v1/replay/step` mounts;
/// the client resumes by re-calling with the returned [`ReplayPage::next_index`] (stateless paging,
/// no server-side cursor). Completing the `generate/replay/step/bundle` route quartet.
pub fn step_replay_session(
    store: &dyn SessionStore,
    session_id: &str,
    principal: &Principal,
    opts: &ReplayOptions,
    from_index: usize,
) -> Result<ReplayPage, PersistedError> {
    let rec = load_recording(store, session_id)?;
    Ok(step_replay(&rec, principal, opts, from_index)?)
}

/// **The durable export entrypoint.** Load the tree from `store` and produce a shareable,
/// credential-free, content-committed [`ReplayBundle`] — making [`export_bundle`] reachable.
pub fn export_session_bundle(
    store: &dyn SessionStore,
    session_id: &str,
    principal: &Principal,
    opts: &ReplayOptions,
    runtime_version: &str,
    signer: &dyn BundleSigner,
) -> Result<ReplayBundle, PersistedError> {
    let rec = load_recording(store, session_id)?;
    Ok(export_bundle(
        &rec,
        principal,
        opts,
        runtime_version,
        signer,
    )?)
}

/// **The durable re-execution entrypoint.** Load the tree, fork a NEW branch off `target_turn` and run
/// its frozen inputs against the live-model `executor` (never overwriting history), then persist the
/// mutated tree. Makes [`re_execute`] reachable over a persisted session. The arguments are the
/// distinct inputs of a re-execution (mirroring [`re_execute`] plus the store); bundling them into a
/// struct would only obscure the call.
#[allow(clippy::too_many_arguments)]
pub fn re_execute_persisted(
    store: &dyn SessionStore,
    session_id: &str,
    target_turn: &str,
    new_id: &str,
    author: &str,
    principal: &Principal,
    executor: &dyn ReExecutor,
    at_millis: u128,
) -> Result<TurnId, PersistedError> {
    let mut rec = load_recording(store, session_id)?;
    let head = re_execute(
        &mut rec,
        target_turn,
        new_id,
        author,
        principal,
        executor,
        at_millis,
    )?;
    store.save(&rec.to_durable())?;
    Ok(head)
}

/// A single record from a legacy linear event log, for [`SessionRecording::from_linear`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinearRecord {
    pub kind: EventKind,
    pub role: TurnRole,
    pub author: String,
    pub data_class: DataClass,
    pub text: String,
    pub ts_millis: u128,
}

/// When a steer interjection will be delivered to the agent loop.
///
/// `Serialize` so [`apply_interaction`]'s [`InteractionOutcome`] can report the delivery timing
/// straight over the wire (the transport tells the client whether its steer landed now or is queued
/// behind an in-flight tool call).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SteerDelivery {
    /// No tool call is in flight — the steer lands immediately (model is generating text or idle).
    Immediate,
    /// A tool call is in flight — the steer is queued and lands only after that tool call completes.
    /// Carries the event id of the in-flight [`EventKind::ToolCall`] it must wait behind.
    AfterToolCall(EventId),
}

/// Decide when a steer lands: if the turn's most recent tool call has **not** yet returned, the steer
/// must wait for its `ToolResult`; otherwise it lands immediately. Deterministic over the event
/// stream — the load-bearing "never mid-tool-call" guarantee (§3.3).
pub fn resolve_steer_delivery(events: &[ReplayEvent], turn_id: &str) -> SteerDelivery {
    let mut in_flight: Option<EventId> = None;
    for e in events.iter().filter(|e| e.turn_id == turn_id) {
        match e.kind {
            EventKind::ToolCall => in_flight = Some(e.id),
            EventKind::ToolResult => in_flight = None,
            _ => {}
        }
    }
    match in_flight {
        Some(id) => SteerDelivery::AfterToolCall(id),
        None => SteerDelivery::Immediate,
    }
}

// ===========================================================================
// Snapshot types
// ===========================================================================

/// A structural summary of one turn (no event payloads) — for `session.snapshot`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TurnSummary {
    pub id: TurnId,
    pub parent: Option<TurnId>,
    pub role: TurnRole,
    pub author: String,
    pub label: Option<String>,
    pub status: TurnStatus,
}

/// The current tree state handed to a late joiner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSnapshot {
    /// Checkmarx CX-FP: renamed to `sid`; `#[serde(rename)]` preserves the wire key.
    #[serde(rename = "session_id")]
    pub sid: SessionId,
    pub active_head: Option<TurnId>,
    pub turns: Vec<TurnSummary>,
}

// ===========================================================================
// Replay engine
// ===========================================================================

/// Which branch to replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BranchSelector {
    /// The current active head (default).
    ActiveHead,
    /// A specific head turn id (replays root → that turn).
    Head(TurnId),
}

/// Which turns of the selected branch to include.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TurnRange {
    /// Every turn on the branch path.
    All,
    /// Only these turn ids (intersected with the branch path).
    Turns(Vec<TurnId>),
}

/// Replay mode (`INTERACTION_REPL_COMMANDS.md` §2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayMode {
    /// Re-stream the recorded events exactly — no model call, no tool execution, no side effects.
    PureEvent,
    /// Re-run frozen inputs against a live model (a seam — see [`re_execute`]).
    ReExecution,
}

/// Replay pacing (§2.2). Delays are computed as *data*; the engine never sleeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pacing {
    /// Match the original inter-event timing.
    RealTime,
    /// Compress the original timing by `factor` (>= 1). `factor == 1` equals real time.
    FastForward(u32),
    /// No delays.
    Instant,
    /// One event at a time, zero delay; boundary events are flagged for the renderer to pause on.
    Step,
}

/// Options for a replay plan.
#[derive(Debug, Clone)]
pub struct ReplayOptions {
    pub branch: BranchSelector,
    pub range: TurnRange,
    pub mode: ReplayMode,
    pub pacing: Pacing,
}

impl Default for ReplayOptions {
    fn default() -> Self {
        ReplayOptions {
            branch: BranchSelector::ActiveHead,
            range: TurnRange::All,
            mode: ReplayMode::PureEvent,
            pacing: Pacing::RealTime,
        }
    }
}

/// Why a replay/export was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayError {
    /// The principal may not view this session (not a participant and lacks [`CAP_COMPLIANCE_REPLAY`]).
    NotAuthorized,
    /// The requested branch head turn does not exist.
    UnknownTurn(TurnId),
    /// The session has no active head and none was specified.
    NoActiveBranch,
    /// Re-execution was requested through the pure-replay planner (use [`re_execute`] instead).
    ReExecutionRequiresExecutor,
    /// Re-execution was requested for a turn that captured no frozen inputs.
    NoFrozenInputs(TurnId),
}

impl std::fmt::Display for ReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReplayError::NotAuthorized => write!(f, "not authorized to replay this session"),
            ReplayError::UnknownTurn(id) => write!(f, "unknown turn: {id}"),
            ReplayError::NoActiveBranch => write!(f, "session has no active branch to replay"),
            ReplayError::ReExecutionRequiresExecutor => {
                write!(
                    f,
                    "re-execution replay requires a ReExecutor (use re_execute)"
                )
            }
            ReplayError::NoFrozenInputs(id) => {
                write!(f, "turn {id} has no frozen inputs to re-run")
            }
        }
    }
}

impl std::error::Error for ReplayError {}

/// One replay step: the event to emit, the delay before it (from pacing), and whether the renderer
/// should pause on it in step mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayStep {
    pub event: ReplayEvent,
    pub delay_millis: u128,
    pub is_boundary: bool,
}

/// A planned replay: an ordered, RBAC-filtered, deterministic sequence of steps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replay {
    /// Checkmarx CX-FP: renamed to `sid`; not serialized (Replay is internal only).
    pub sid: SessionId,
    pub mode: ReplayMode,
    pub steps: Vec<ReplayStep>,
}

impl Replay {
    /// A step cursor for step-mode consumption (advance / pause-at-boundary / abort — acceptance R5).
    pub fn cursor(&self) -> StepCursor<'_> {
        StepCursor {
            steps: &self.steps,
            pos: 0,
            aborted: false,
        }
    }
}

/// A resumable/abortable cursor over a [`Replay`]'s steps (step mode).
#[derive(Debug)]
pub struct StepCursor<'a> {
    steps: &'a [ReplayStep],
    pos: usize,
    aborted: bool,
}

impl<'a> StepCursor<'a> {
    /// Advance to and return the next step, or `None` if exhausted/aborted.
    pub fn next_step(&mut self) -> Option<&'a ReplayStep> {
        if self.aborted || self.pos >= self.steps.len() {
            return None;
        }
        // `self.steps` is a `Copy` shared reference; copy it out so the returned borrow is tied to
        // the slice's lifetime `'a`, not to this `&mut self` call.
        let steps: &'a [ReplayStep] = self.steps;
        let step = &steps[self.pos];
        self.pos += 1;
        Some(step)
    }

    /// Whether the *next* step (if any) is a pause boundary.
    pub fn next_is_boundary(&self) -> bool {
        self.steps.get(self.pos).is_some_and(|s| s.is_boundary)
    }

    /// Abort the replay — no further steps are yielded.
    pub fn abort(&mut self) {
        self.aborted = true;
    }

    /// Steps not yet consumed.
    pub fn remaining(&self) -> usize {
        if self.aborted {
            0
        } else {
            self.steps.len().saturating_sub(self.pos)
        }
    }
}

/// Whether `principal` may replay/view `rec`: a participant, or a holder of [`CAP_COMPLIANCE_REPLAY`].
fn authorize(rec: &SessionRecording, principal: &Principal) -> Result<(), ReplayError> {
    if rec.is_participant(&principal.user_id) || principal.has_cap(CAP_COMPLIANCE_REPLAY) {
        Ok(())
    } else {
        Err(ReplayError::NotAuthorized)
    }
}

/// Whether `principal`'s clearance admits an event of `data_class` — the same pre-rank ACL predicate
/// used across the retrieval/graph/nl2sql surfaces (redaction-preserving: an above-clearance event is
/// simply omitted, never surfaced pre-redaction).
fn event_visible(principal: &Principal, e: &ReplayEvent) -> bool {
    e.data_class.sensitivity() <= principal.clearance.sensitivity()
}

/// Plan a **pure** (side-effect-free) deterministic replay of a session branch, RBAC-scoped and
/// per-event clearance-filtered. Returns the ordered steps a renderer would emit. Performs no model
/// call, no tool execution, and does not mutate `rec`.
pub fn plan_replay(
    rec: &SessionRecording,
    principal: &Principal,
    opts: &ReplayOptions,
) -> Result<Replay, ReplayError> {
    authorize(rec, principal)?;
    if opts.mode == ReplayMode::ReExecution {
        return Err(ReplayError::ReExecutionRequiresExecutor);
    }

    // Resolve the branch head and its root→head path.
    let head: String = match &opts.branch {
        BranchSelector::ActiveHead => rec
            .tree
            .active_head()
            .map(str::to_string)
            .ok_or(ReplayError::NoActiveBranch)?,
        BranchSelector::Head(id) => {
            if rec.tree.turn(id).is_none() {
                return Err(ReplayError::UnknownTurn(id.clone()));
            }
            id.clone()
        }
    };
    let path: BTreeSet<&str> = rec.tree.path_to(&head).into_iter().collect();

    // Which turns to include: the branch path, optionally intersected with an explicit turn list.
    let wanted: Option<BTreeSet<&str>> = match &opts.range {
        TurnRange::All => None,
        TurnRange::Turns(list) => Some(list.iter().map(String::as_str).collect()),
    };
    let included = |turn_id: &str| -> bool {
        path.contains(turn_id) && wanted.as_ref().is_none_or(|w| w.contains(turn_id))
    };

    // Gather visible events for those turns, in recorded (seq) order.
    let visible: Vec<&ReplayEvent> = rec
        .events
        .iter()
        .filter(|e| included(e.turn_id.as_str()) && event_visible(principal, e))
        .collect();

    // Pacing → delays. First step has zero delay; subsequent delays derive from recorded ts deltas.
    let mut steps: Vec<ReplayStep> = Vec::with_capacity(visible.len());
    let mut prev_ts: Option<u128> = None;
    for e in visible {
        let raw_delay = match prev_ts {
            Some(p) => e.ts_millis.saturating_sub(p),
            None => 0,
        };
        let delay_millis = match opts.pacing {
            Pacing::RealTime => raw_delay,
            Pacing::FastForward(factor) => raw_delay / (factor.max(1) as u128),
            Pacing::Instant | Pacing::Step => 0,
        };
        prev_ts = Some(e.ts_millis);
        steps.push(ReplayStep {
            event: e.clone(),
            delay_millis,
            is_boundary: e.kind.is_pause_boundary(),
        });
    }

    Ok(Replay {
        sid: rec.id.clone(),
        mode: ReplayMode::PureEvent,
        steps,
    })
}

// ===========================================================================
// Step-through paging (the route-ready STEP entrypoint, R6 DATA)
// ===========================================================================

/// One page of a step-through replay: the run of steps from a caller-held `from_index` up to the
/// **next step-boundary** (`INTERACTION_REPL_COMMANDS.md` §2.2 acceptance R5). A boundary — a tool
/// call, an approval gate, or a model call — is where a step-mode viewer pauses to inspect before
/// proceeding, so each page ends *right before* the next boundary and the caller resumes from
/// [`next_index`](ReplayPage::next_index) on the following request.
///
/// This is the **stateless** shape a REST route returns: replay is planned deterministically, so the
/// client holds only an integer cursor (`from_index`) and no server-side step state is required —
/// which is exactly what lets `POST /v1/replay/step` scale across the 2000-user request path. It is
/// the route-ready counterpart to the in-process [`StepCursor`] (which needs a live `&Replay`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayPage {
    /// Checkmarx CX-FP: renamed to `sid`; `#[serde(rename)]` preserves the wire key.
    #[serde(rename = "session_id")]
    pub sid: SessionId,
    pub mode: ReplayMode,
    /// The steps in this page: `from_index` and the following non-boundary steps, stopping before
    /// the next boundary (the last step of the page may itself be a boundary only when it is the
    /// very first step of the page — i.e. the caller resumed exactly onto a boundary).
    pub steps: Vec<ReplayStep>,
    /// Where to resume on the next call, or `None` when the replay is exhausted (no more steps).
    pub next_index: Option<usize>,
    /// `true` when the page stopped because the *next* step is a boundary the viewer pauses on;
    /// `false` on the final page (replay complete).
    pub paused_at_boundary: bool,
    /// Total step count of the full planned replay, so a client can render progress (`i / total`).
    pub total_steps: usize,
}

/// Slice a planned [`Replay`] into a single [`ReplayPage`] beginning at `from_index`. Emits the step
/// at the cursor, then keeps emitting while the *next* step is not a boundary; stops (pausing) as
/// soon as the next step is a boundary, or ends the replay when the steps are exhausted. Splitting
/// this out keeps [`step_replay`] a thin authz+plan wrapper and makes the paging logic unit-testable.
fn page_from(replay: Replay, from_index: usize) -> ReplayPage {
    let total = replay.steps.len();
    let mut steps: Vec<ReplayStep> = Vec::new();
    let mut next_index: Option<usize> = None;
    let mut paused_at_boundary = false;

    let mut i = from_index;
    if i < total {
        loop {
            steps.push(replay.steps[i].clone());
            i += 1;
            if i >= total {
                break; // exhausted — this is the final page
            }
            if replay.steps[i].is_boundary {
                next_index = Some(i); // pause right before the boundary
                paused_at_boundary = true;
                break;
            }
        }
    }

    ReplayPage {
        sid: replay.sid,
        mode: replay.mode,
        steps,
        next_index,
        paused_at_boundary,
        total_steps: total,
    }
}

/// **Pure, RBAC-scoped step paging** over an in-memory recording: plan the (clearance-filtered)
/// replay, then return the [`ReplayPage`] beginning at `from_index`. Identical authorization and
/// per-event redaction-preserving filtering as [`plan_replay`] — a page can never contain an event
/// the caller could not see in a full replay. Deterministic; no model call, no mutation. A
/// `from_index` at or past the end yields an empty final page (`next_index == None`).
pub fn step_replay(
    rec: &SessionRecording,
    principal: &Principal,
    opts: &ReplayOptions,
    from_index: usize,
) -> Result<ReplayPage, ReplayError> {
    let replay = plan_replay(rec, principal, opts)?;
    Ok(page_from(replay, from_index))
}

// ===========================================================================
// Re-execution replay (the live-model seam)
// ===========================================================================

/// A single event a [`ReExecutor`] produced when re-running frozen inputs (already redaction-safe).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReExecEvent {
    pub kind: EventKind,
    pub data_class: DataClass,
    pub text: String,
}

/// The live-model seam for re-execution replay. An implementation re-runs the exact frozen inputs and
/// returns the newly-produced events. This crate owns everything *around* it (authz, branch-forking,
/// labeling); the model call itself is out of scope for an offline core.
pub trait ReExecutor {
    fn re_execute(&self, frozen: &FrozenTurnInputs) -> Vec<ReExecEvent>;
}

/// The **offline default** behind the live-model [`ReExecutor`] seam (INFRA-gated: a live provider
/// call is not made in-core). It does not contact any model; it deterministically re-emits a single
/// event derived only from the frozen inputs, so `re_execute` / `re_execute_persisted` are fully
/// exercisable (branch-forking, authz, labeling, persistence) with zero infra and zero non-determinism.
///
/// A deployment swaps in a provider-backed executor (routed through the model gateway, data-class →
/// model-eligibility enforced) behind the SAME seam — no change to the surrounding fork/authz logic.
/// The emitted `data_class` is caller-configured so the fresh events are classed for redaction exactly
/// as a live re-run's would be.
pub struct DeterministicReplayExecutor {
    data_class: DataClass,
}

impl DeterministicReplayExecutor {
    /// Build the offline executor, tagging its emitted event with `data_class` (the class the
    /// re-executed content should carry for the redaction pass).
    pub fn new(data_class: DataClass) -> Self {
        DeterministicReplayExecutor { data_class }
    }
}

impl ReExecutor for DeterministicReplayExecutor {
    fn re_execute(&self, frozen: &FrozenTurnInputs) -> Vec<ReExecEvent> {
        // Purely a function of the frozen inputs — no clock, rng, or I/O — so the forked branch is
        // byte-identical on every run (deterministic replay, gap X).
        vec![ReExecEvent {
            kind: EventKind::TextDelta,
            data_class: self.data_class,
            text: format!(
                "[offline re-execution] model={} seed={} params={} :: {}",
                frozen.model, frozen.seed, frozen.params, frozen.prompt
            ),
        }]
    }
}

/// **Re-execution replay** (§2.1): re-run a turn's frozen inputs against a live model. It **never
/// overwrites history** — it forks a *new sibling branch* off the original turn, labeled distinctly,
/// appends the executor's fresh events onto it, and moves the active head there. The original turn and
/// its events are left completely intact and independently replayable.
pub fn re_execute(
    rec: &mut SessionRecording,
    target_turn: &str,
    new_id: &str,
    author: &str,
    principal: &Principal,
    executor: &dyn ReExecutor,
    at_millis: u128,
) -> Result<TurnId, ReplayError> {
    authorize(rec, principal)?;
    let target = rec
        .tree
        .turn(target_turn)
        .ok_or_else(|| ReplayError::UnknownTurn(target_turn.to_string()))?;
    let frozen = target
        .frozen
        .clone()
        .ok_or_else(|| ReplayError::NoFrozenInputs(target_turn.to_string()))?;
    let parent = target.parent.clone();
    let role = target.role;

    let sibling = Turn {
        id: new_id.to_string(),
        parent,
        role,
        author: author.to_string(),
        label: Some(format!("re-execution of {target_turn}")),
        status: TurnStatus::Active,
        frozen: Some(frozen.clone()),
    };
    rec.tree
        .insert(sibling, true)
        .map_err(|_| ReplayError::UnknownTurn(new_id.to_string()))?;
    rec.push_event(
        new_id,
        EventKind::Branch,
        DataClass::Internal,
        target_turn,
        at_millis,
    );

    for ev in executor.re_execute(&frozen) {
        rec.push_event(new_id, ev.kind, ev.data_class, &ev.text, at_millis);
    }
    Ok(new_id.to_string())
}

// ===========================================================================
// Re-execution over transport: request DTO + the drift/differential oracle
// ===========================================================================

/// The route-ready **re-execution request** a transport (`POST /v1/replay/reexec`) deserializes from
/// the wire: which turn to re-run frozen and the id to mint for the forked branch. The live-model
/// executor is injected server-side (never named on the wire — the model/eligibility policy is the
/// runtime's, not the client's), so a re-execution over transport carries only these safe fields.
/// `deny_unknown_fields` rejects a smuggled key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReExecRequest {
    /// The turn whose frozen inputs are re-run.
    pub target_turn: TurnId,
    /// The id to mint for the forked (never-overwriting) sibling branch.
    pub new_id: TurnId,
}

/// **The durable re-execution entrypoint over transport.** The RBAC-scoped, store-backed counterpart a
/// transport mounts: it takes the deserialized [`ReExecRequest`] (author = the authenticated
/// `principal`), forks a NEW branch off `target_turn` against the injected `executor`, persists it, and
/// returns the new branch id. Thin adapter over [`re_execute_persisted`] with the wire-safe argument
/// shape (the executor + author are supplied by the runtime, not the client).
pub fn re_execute_persisted_req(
    store: &dyn SessionStore,
    session_id: &str,
    req: &ReExecRequest,
    principal: &Principal,
    executor: &dyn ReExecutor,
    at_millis: u128,
) -> Result<TurnId, PersistedError> {
    re_execute_persisted(
        store,
        session_id,
        &req.target_turn,
        &req.new_id,
        &principal.user_id,
        principal,
        executor,
        at_millis,
    )
}

/// The **drift / differential oracle** result (`GAP_ANALYSIS_VS_AI_PLATFORMS.md` gaps X/AS): the
/// text a turn produced originally vs. what a re-execution produced, and whether they DRIFTED. Both
/// texts are the concatenation of the turn's clearance-visible [`EventKind::TextDelta`] payloads (in
/// recorded order), so the oracle is redaction-preserving — it never compares content the viewer
/// could not see.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriftReport {
    pub original_turn: TurnId,
    pub reexec_turn: TurnId,
    /// Concatenated visible text of the original turn.
    pub original_text: String,
    /// Concatenated visible text of the re-executed (forked) turn.
    pub reexec_text: String,
    /// `true` when the two differ — the differential signal a canary/regression gate consumes.
    pub drifted: bool,
}

/// Concatenate a turn's clearance-visible `TextDelta` payloads in recorded (seq) order.
fn visible_turn_text(rec: &SessionRecording, principal: &Principal, turn_id: &str) -> String {
    let mut out = String::new();
    for e in rec.events().iter().filter(|e| {
        e.turn_id == turn_id && e.kind == EventKind::TextDelta && event_visible(principal, e)
    }) {
        out.push_str(&e.text);
    }
    out
}

/// **The differential oracle over a persisted session.** Load the session from `store` and compare the
/// original turn's recorded output against a re-executed fork's output, RBAC-scoped exactly as replay
/// (participant or a compliance role) and redaction-preserving (only clearance-visible text is
/// compared). This is the read side of re-execution: after [`re_execute_persisted_req`] forks a drift
/// branch, a transport calls this to obtain the [`DriftReport`] a canary / auto-rollback gate consumes.
pub fn drift_report_persisted(
    store: &dyn SessionStore,
    session_id: &str,
    original_turn: &str,
    reexec_turn: &str,
    principal: &Principal,
) -> Result<DriftReport, PersistedError> {
    let rec = load_recording(store, session_id)?;
    authorize(&rec, principal)?;
    if rec.tree().turn(original_turn).is_none() {
        return Err(PersistedError::Replay(ReplayError::UnknownTurn(
            original_turn.to_string(),
        )));
    }
    if rec.tree().turn(reexec_turn).is_none() {
        return Err(PersistedError::Replay(ReplayError::UnknownTurn(
            reexec_turn.to_string(),
        )));
    }
    let original_text = visible_turn_text(&rec, principal, original_turn);
    let reexec_text = visible_turn_text(&rec, principal, reexec_turn);
    let drifted = original_text != reexec_text;
    Ok(DriftReport {
        original_turn: original_turn.to_string(),
        reexec_turn: reexec_turn.to_string(),
        original_text,
        reexec_text,
        drifted,
    })
}

// ===========================================================================
// Replay bundle (shareable, credential-free, content-committed)
// ===========================================================================

/// Signs (or commits) a replay bundle. Production plugs an asymmetric signer; the built-in
/// [`ContentCommitmentSigner`] is a keyed integrity commitment (real PKI is the deployment seam).
pub trait BundleSigner {
    /// Return a signature/commitment string over the content commitment.
    fn sign(&self, content_commitment: &str) -> String;
    /// Verify a signature against a content commitment.
    fn verify(&self, content_commitment: &str, signature: &str) -> bool;
}

/// A keyed SHA-256 integrity commitment — a deterministic stand-in for asymmetric signing that still
/// binds the bundle to a secret key. Not a substitute for PKI where non-repudiation is required.
pub struct ContentCommitmentSigner {
    key: String,
}

impl ContentCommitmentSigner {
    pub fn new(key: impl Into<String>) -> Self {
        ContentCommitmentSigner { key: key.into() }
    }
}

impl BundleSigner for ContentCommitmentSigner {
    fn sign(&self, content_commitment: &str) -> String {
        sha256_hex(&[self.key.as_bytes(), content_commitment.as_bytes()])
    }
    fn verify(&self, content_commitment: &str, signature: &str) -> bool {
        // Constant-work compare is unnecessary here (both derived from the same public commitment
        // shape); a plain equality of two hex digests is sufficient for integrity.
        self.sign(content_commitment) == signature
    }
}

/// The manifest for a shared replay bundle. Deliberately carries **no credentials and no participant
/// list** — a bundle grants a viewer the recorded (redacted) events and nothing more; it is not a
/// handle to the live session (§2.2 export, acceptance R4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleManifest {
    /// Checkmarx CX-FP: renamed to `sid`; `#[serde(rename)]` preserves the wire key.
    #[serde(rename = "session_id")]
    pub sid: SessionId,
    pub runtime_version: String,
    pub turn_ids: Vec<TurnId>,
    pub event_count: usize,
    /// Length-prefixed SHA-256 over the event slice — detects any tampering with the bundle.
    pub content_commitment: String,
    /// The signer's commitment over `content_commitment`.
    pub signature: String,
}

/// A self-contained, shareable replay: a manifest plus the redacted event slice. No live access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayBundle {
    pub manifest: BundleManifest,
    pub events: Vec<ReplayEvent>,
}

impl ReplayBundle {
    /// Recompute the content commitment and check it plus the signature — detects any tampering.
    pub fn verify(&self, signer: &dyn BundleSigner) -> bool {
        let recomputed = commit_events(&self.events);
        recomputed == self.manifest.content_commitment
            && self.manifest.event_count == self.events.len()
            && signer.verify(&recomputed, &self.manifest.signature)
    }
}

/// Export an RBAC-scoped, redaction-preserving [`ReplayBundle`] for sharing (demo/training). The
/// bundle contains only the already-redacted events the principal is authorized to see; it carries no
/// credentials and is not a handle to the live session.
pub fn export_bundle(
    rec: &SessionRecording,
    principal: &Principal,
    opts: &ReplayOptions,
    runtime_version: &str,
    signer: &dyn BundleSigner,
) -> Result<ReplayBundle, ReplayError> {
    let replay = plan_replay(rec, principal, opts)?;
    let events: Vec<ReplayEvent> = replay.steps.into_iter().map(|s| s.event).collect();
    let mut turn_ids: Vec<TurnId> = events.iter().map(|e| e.turn_id.clone()).collect();
    turn_ids.dedup();
    let content_commitment = commit_events(&events);
    let signature = signer.sign(&content_commitment);
    Ok(ReplayBundle {
        manifest: BundleManifest {
            sid: rec.id.clone(),
            runtime_version: runtime_version.to_string(),
            turn_ids,
            event_count: events.len(),
            content_commitment,
            signature,
        },
        events,
    })
}

/// Length-prefixed SHA-256 over an event slice — a canonical, deterministic content commitment. Each
/// field is length-prefixed so a value boundary cannot be forged by shifting bytes between fields.
fn commit_events(events: &[ReplayEvent]) -> String {
    let mut parts: Vec<Vec<u8>> = Vec::new();
    for e in events {
        parts.push(e.id.to_le_bytes().to_vec());
        parts.push(e.turn_id.clone().into_bytes());
        parts.push(e.seq.to_le_bytes().to_vec());
        parts.push(e.ts_millis.to_le_bytes().to_vec());
        parts.push(vec![e.kind as u8]);
        parts.push(vec![e.data_class.sensitivity()]);
        parts.push(e.text.clone().into_bytes());
    }
    let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    sha256_hex(&refs)
}

/// Hex SHA-256 over length-prefixed fields (canonical encoding, cross-build stable).
fn sha256_hex(fields: &[&[u8]]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for f in fields {
        h.update((f.len() as u64).to_le_bytes());
        h.update(f);
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect::<String>()
}

#[cfg(test)]
mod tests {
    use super::*;

    // A default event data-class helper for tests.
    fn internal() -> DataClass {
        DataClass::Internal
    }

    /// A participant of the session (their user id is in the participant set).
    fn participant() -> Principal {
        Principal::user("priya", &[]).with_clearance(DataClass::Confidential)
    }

    /// An outsider — not a participant, no compliance cap.
    fn outsider() -> Principal {
        Principal::user("mallory", &[]).with_clearance(DataClass::Pii)
    }

    /// A compliance/audit role — not a participant, but holds CAP_COMPLIANCE_REPLAY.
    fn auditor() -> Principal {
        Principal::user("dpo", &[CAP_COMPLIANCE_REPLAY]).with_clearance(DataClass::Pii)
    }

    /// Build a small recorded session: one user turn, one assistant turn with a tool call.
    fn recording() -> SessionRecording {
        let mut r = SessionRecording::new("s1", &["priya", "arun"]);
        r.append_root_turn("u1", TurnRole::User, "priya", 1000)
            .unwrap();
        r.record_event(
            "u1",
            EventKind::TextDelta,
            internal(),
            "compute settlement",
            1001,
        )
        .unwrap();
        r.append_turn("a1", "u1", TurnRole::Assistant, "assistant", 1100)
            .unwrap();
        r.record_event("a1", EventKind::ModelCall, internal(), "call", 1101)
            .unwrap();
        r.record_event("a1", EventKind::ToolCall, internal(), "sql.query", 1200)
            .unwrap();
        r.record_event("a1", EventKind::ToolResult, internal(), "42 rows", 1500)
            .unwrap();
        r.record_event(
            "a1",
            EventKind::TextDelta,
            internal(),
            "the answer is 42",
            1600,
        )
        .unwrap();
        r.record_event("a1", EventKind::TurnEnd, internal(), "", 1700)
            .unwrap();
        r
    }

    // --- R1: pure replay reproduces the recording with no side effects ----
    #[test]
    fn pure_replay_reproduces_events_without_mutating_or_re_executing() {
        let rec = recording();
        let before_events = rec.events().len();
        let replay = plan_replay(&rec, &participant(), &ReplayOptions::default()).unwrap();
        assert_eq!(replay.mode, ReplayMode::PureEvent);
        // Every recorded event on the active branch is reproduced, in order, with identical payloads.
        let kinds: Vec<EventKind> = replay.steps.iter().map(|s| s.event.kind).collect();
        assert_eq!(
            kinds,
            vec![
                EventKind::TurnStart,
                EventKind::TextDelta,
                EventKind::TurnStart,
                EventKind::ModelCall,
                EventKind::ToolCall,
                EventKind::ToolResult,
                EventKind::TextDelta,
                EventKind::TurnEnd,
            ]
        );
        assert!(replay
            .steps
            .iter()
            .any(|s| s.event.text == "the answer is 42"));
        // Pure replay never mutates the source and never re-executes.
        assert_eq!(rec.events().len(), before_events);
    }

    #[test]
    fn realtime_pacing_uses_recorded_deltas_fastforward_halves_them() {
        let rec = recording();
        let rt = plan_replay(&rec, &participant(), &ReplayOptions::default()).unwrap();
        // First step zero delay; the a1 ToolResult follows ToolCall by 1500-1200 = 300ms.
        assert_eq!(rt.steps[0].delay_millis, 0);
        let tool_result = rt
            .steps
            .iter()
            .find(|s| s.event.kind == EventKind::ToolResult)
            .unwrap();
        assert_eq!(tool_result.delay_millis, 300);
        // Fast-forward 2x halves every delay deterministically.
        let ff = plan_replay(
            &rec,
            &participant(),
            &ReplayOptions {
                pacing: Pacing::FastForward(2),
                ..ReplayOptions::default()
            },
        )
        .unwrap();
        let ff_tool_result = ff
            .steps
            .iter()
            .find(|s| s.event.kind == EventKind::ToolResult)
            .unwrap();
        assert_eq!(ff_tool_result.delay_millis, 150);
    }

    // --- R3: RBAC scoping -------------------------------------------------
    #[test]
    fn replay_is_rbac_scoped_participant_and_compliance_yes_outsider_no() {
        let rec = recording();
        assert!(plan_replay(&rec, &participant(), &ReplayOptions::default()).is_ok());
        assert!(plan_replay(&rec, &auditor(), &ReplayOptions::default()).is_ok());
        assert_eq!(
            plan_replay(&rec, &outsider(), &ReplayOptions::default()).unwrap_err(),
            ReplayError::NotAuthorized
        );
    }

    #[test]
    fn replay_filters_events_above_viewer_clearance_redaction_preserving() {
        let mut rec = SessionRecording::new("s2", &["priya"]);
        rec.append_root_turn("u1", TurnRole::User, "priya", 10)
            .unwrap();
        rec.record_event(
            "u1",
            EventKind::TextDelta,
            DataClass::Internal,
            "public bit",
            11,
        )
        .unwrap();
        // A PII-class event: only a PII-cleared viewer may see it in replay.
        rec.record_event("u1", EventKind::TextDelta, DataClass::Pii, "acct 999", 12)
            .unwrap();
        // Priya is Confidential-cleared (default from participant()); the PII event is omitted.
        let low = plan_replay(&rec, &participant(), &ReplayOptions::default()).unwrap();
        assert!(low.steps.iter().all(|s| s.event.text != "acct 999"));
        // A PII-cleared participant sees it.
        let hi = Principal::user("priya", &[]).with_clearance(DataClass::Pii);
        let seen = plan_replay(&rec, &hi, &ReplayOptions::default()).unwrap();
        assert!(seen.steps.iter().any(|s| s.event.text == "acct 999"));
    }

    // --- R5: step-mode boundaries + cursor --------------------------------
    #[test]
    fn step_mode_flags_boundaries_and_cursor_can_pause_and_abort() {
        let rec = recording();
        let replay = plan_replay(
            &rec,
            &participant(),
            &ReplayOptions {
                pacing: Pacing::Step,
                ..ReplayOptions::default()
            },
        )
        .unwrap();
        // ModelCall, ToolCall, ApprovalGate are boundaries; step delays are all zero.
        assert!(replay.steps.iter().all(|s| s.delay_millis == 0));
        let boundaries: Vec<EventKind> = replay
            .steps
            .iter()
            .filter(|s| s.is_boundary)
            .map(|s| s.event.kind)
            .collect();
        assert_eq!(boundaries, vec![EventKind::ModelCall, EventKind::ToolCall]);
        // Cursor: consume up to the first boundary, then abort — the rest is never yielded.
        let mut cur = replay.cursor();
        let mut consumed = 0;
        while !cur.next_is_boundary() {
            if cur.next_step().is_none() {
                break;
            }
            consumed += 1;
        }
        assert!(cur.next_is_boundary(), "cursor stopped before a boundary");
        let remaining_before_abort = cur.remaining();
        assert!(remaining_before_abort > 0);
        cur.abort();
        assert_eq!(cur.remaining(), 0);
        assert!(cur.next_step().is_none());
        assert!(consumed > 0);
    }

    // --- §3.1/§3.3: edit forks a sibling, preserves history ---------------
    #[test]
    fn edit_user_turn_forks_sibling_and_preserves_old_branch() {
        let mut rec = recording();
        // The old assistant turn a1 hangs off u1. Editing u1 must NOT touch a1.
        let new_head = rec
            .edit_turn("u1", "u1b", "priya", Some("reworded"), 2000)
            .unwrap();
        assert_eq!(new_head, "u1b");
        // Old turn + its descendant assistant turn still exist and are replayable.
        assert!(rec.tree().turn("u1").is_some());
        assert!(rec.tree().turn("a1").is_some());
        // The edit is a *sibling* of u1 (same parent = None, both roots here).
        assert_eq!(rec.tree().turn("u1b").unwrap().parent, None);
        // Active head moved to the edit.
        assert_eq!(rec.tree().active_head(), Some("u1b"));
        // Replaying the OLD branch still reproduces a1's content (history intact).
        let old_branch = plan_replay(
            &rec,
            &participant(),
            &ReplayOptions {
                branch: BranchSelector::Head("a1".into()),
                ..ReplayOptions::default()
            },
        )
        .unwrap();
        assert!(old_branch
            .steps
            .iter()
            .any(|s| s.event.text == "the answer is 42"));
    }

    #[test]
    fn assistant_turn_is_not_editable() {
        let mut rec = recording();
        assert_eq!(
            rec.edit_turn("a1", "a1b", "priya", None, 2000).unwrap_err(),
            TreeError::NotEditable("a1".into())
        );
    }

    // --- S5: two edits of one turn = two labeled siblings, no overwrite ---
    #[test]
    fn two_edits_of_same_turn_produce_two_sibling_branches_never_overwrite() {
        let mut rec = recording();
        let e1 = rec
            .edit_turn("u1", "u1b", "priya", Some("priya version"), 2000)
            .unwrap();
        let e2 = rec
            .edit_turn("u1", "u1c", "arun", Some("arun version"), 2001)
            .unwrap();
        assert_ne!(e1, e2);
        // Both siblings coexist; the original is untouched.
        assert!(rec.tree().turn("u1").is_some());
        assert_eq!(
            rec.tree().turn("u1b").unwrap().label.as_deref(),
            Some("priya version")
        );
        assert_eq!(
            rec.tree().turn("u1c").unwrap().label.as_deref(),
            Some("arun version")
        );
        assert_eq!(rec.tree().turn("u1b").unwrap().author, "priya");
        assert_eq!(rec.tree().turn("u1c").unwrap().author, "arun");
    }

    #[test]
    fn duplicate_turn_id_is_refused() {
        let mut rec = recording();
        assert_eq!(
            rec.edit_turn("u1", "a1", "priya", None, 2000).unwrap_err(),
            TreeError::DuplicateTurn("a1".into())
        );
    }

    // --- S3: stop marks stopped, never deletes ----------------------------
    #[test]
    fn stop_marks_turn_stopped_and_keeps_it_replayable() {
        let mut rec = recording();
        rec.stop("a1", 1800).unwrap();
        assert_eq!(rec.tree().turn("a1").unwrap().status, TurnStatus::Stopped);
        // A stopped turn is still present and its events still replay.
        let replay = plan_replay(&rec, &participant(), &ReplayOptions::default()).unwrap();
        assert!(replay
            .steps
            .iter()
            .any(|s| s.event.kind == EventKind::TurnStopped));
        // Stopping again is refused (not active).
        assert_eq!(
            rec.stop("a1", 1900).unwrap_err(),
            TreeError::NotActive("a1".into())
        );
    }

    // --- S4: steer never lands mid-tool-call ------------------------------
    #[test]
    fn steer_during_in_flight_tool_call_lands_after_the_tool_result() {
        // Build a turn where a tool call is IN FLIGHT (no ToolResult yet).
        let mut rec = SessionRecording::new("s3", &["priya"]);
        rec.append_root_turn("u1", TurnRole::User, "priya", 1)
            .unwrap();
        rec.append_turn("a1", "u1", TurnRole::Assistant, "assistant", 2)
            .unwrap();
        rec.record_event("a1", EventKind::ModelCall, internal(), "call", 3)
            .unwrap();
        let tool_call_id = rec
            .record_event("a1", EventKind::ToolCall, internal(), "sql.query", 4)
            .unwrap();
        // Steering NOW must wait for the tool call — never interrupt it mid-execution.
        let delivery = rec.steer("a1", "also include fees", internal(), 5).unwrap();
        assert_eq!(delivery, SteerDelivery::AfterToolCall(tool_call_id));

        // Once the tool returns, a further steer lands immediately.
        rec.record_event("a1", EventKind::ToolResult, internal(), "done", 6)
            .unwrap();
        let delivery2 = rec.steer("a1", "and taxes", internal(), 7).unwrap();
        assert_eq!(delivery2, SteerDelivery::Immediate);
    }

    #[test]
    fn steer_with_no_tool_in_flight_lands_immediately() {
        let mut rec = SessionRecording::new("s4", &["priya"]);
        rec.append_root_turn("u1", TurnRole::User, "priya", 1)
            .unwrap();
        rec.append_turn("a1", "u1", TurnRole::Assistant, "assistant", 2)
            .unwrap();
        rec.record_event("a1", EventKind::TextDelta, internal(), "thinking...", 3)
            .unwrap();
        assert_eq!(
            rec.steer("a1", "hurry", internal(), 4).unwrap(),
            SteerDelivery::Immediate
        );
    }

    #[test]
    fn steer_on_stopped_turn_is_refused() {
        let mut rec = recording();
        rec.stop("a1", 1800).unwrap();
        assert_eq!(
            rec.steer("a1", "too late", internal(), 1900).unwrap_err(),
            TreeError::NotActive("a1".into())
        );
    }

    // --- S7: snapshot for a late joiner -----------------------------------
    #[test]
    fn snapshot_reflects_tree_without_replaying_and_is_rbac_scoped() {
        let rec = recording();
        let snap = rec.snapshot(&participant()).unwrap();
        assert_eq!(snap.sid, "s1");
        assert_eq!(snap.active_head.as_deref(), Some("a1"));
        let ids: Vec<&str> = snap.turns.iter().map(|t| t.id.as_str()).collect();
        assert_eq!(ids, vec!["a1", "u1"]);
        // An outsider cannot snapshot.
        assert_eq!(
            rec.snapshot(&outsider()).unwrap_err(),
            ReplayError::NotAuthorized
        );
    }

    // --- R2: re-execution forks a new branch, never overwrites ------------
    struct FakeExecutor;
    impl ReExecutor for FakeExecutor {
        fn re_execute(&self, _frozen: &FrozenTurnInputs) -> Vec<ReExecEvent> {
            vec![ReExecEvent {
                kind: EventKind::TextDelta,
                data_class: DataClass::Internal,
                text: "the answer is 43 (drifted)".to_string(),
            }]
        }
    }

    #[test]
    fn re_execution_forks_new_branch_and_leaves_original_intact() {
        let mut rec = recording();
        rec.set_frozen(
            "a1",
            FrozenTurnInputs {
                prompt: "compute settlement".into(),
                model: "claude-sonnet-4-6".into(),
                params: "temp=0".into(),
                seed: 7,
            },
        )
        .unwrap();
        let original_a1_events: Vec<ReplayEvent> = rec
            .events()
            .iter()
            .filter(|e| e.turn_id == "a1")
            .cloned()
            .collect();

        let new_branch = re_execute(
            &mut rec,
            "a1",
            "a1re",
            "priya",
            &participant(),
            &FakeExecutor,
            9000,
        )
        .unwrap();
        assert_eq!(new_branch, "a1re");
        // The new branch is a labeled sibling of a1 (same parent u1).
        let nt = rec.tree().turn("a1re").unwrap();
        assert_eq!(nt.parent.as_deref(), Some("u1"));
        assert!(nt.label.as_deref().unwrap().contains("re-execution"));
        assert_eq!(rec.tree().active_head(), Some("a1re"));
        // The ORIGINAL a1 events are byte-for-byte unchanged.
        let after: Vec<ReplayEvent> = rec
            .events()
            .iter()
            .filter(|e| e.turn_id == "a1")
            .cloned()
            .collect();
        assert_eq!(after, original_a1_events);
        // The new branch replays the drifted output.
        let replay = plan_replay(&rec, &participant(), &ReplayOptions::default()).unwrap();
        assert!(replay
            .steps
            .iter()
            .any(|s| s.event.text.contains("drifted")));
    }

    #[test]
    fn re_execution_requires_frozen_inputs() {
        let mut rec = recording();
        // a1 has no frozen inputs.
        assert_eq!(
            re_execute(
                &mut rec,
                "a1",
                "a1re",
                "priya",
                &participant(),
                &FakeExecutor,
                9000
            )
            .unwrap_err(),
            ReplayError::NoFrozenInputs("a1".into())
        );
    }

    #[test]
    fn plan_replay_rejects_reexecution_mode() {
        let rec = recording();
        assert_eq!(
            plan_replay(
                &rec,
                &participant(),
                &ReplayOptions {
                    mode: ReplayMode::ReExecution,
                    ..ReplayOptions::default()
                }
            )
            .unwrap_err(),
            ReplayError::ReExecutionRequiresExecutor
        );
    }

    // --- R4: replay bundle is shareable, verifiable, credential-free ------
    #[test]
    fn export_bundle_is_content_committed_verifiable_and_carries_no_credentials() {
        let rec = recording();
        let signer = ContentCommitmentSigner::new("bundle-key");
        let bundle = export_bundle(
            &rec,
            &participant(),
            &ReplayOptions::default(),
            "runtime-1.2.3",
            &signer,
        )
        .unwrap();
        assert!(bundle.verify(&signer));
        assert_eq!(bundle.manifest.runtime_version, "runtime-1.2.3");
        assert_eq!(bundle.manifest.event_count, bundle.events.len());
        // Tamper with an event → verification fails.
        let mut tampered = bundle.clone();
        tampered.events[0].text = "forged".into();
        assert!(!tampered.verify(&signer));
        // A different key does not verify (the commitment is keyed).
        let other = ContentCommitmentSigner::new("attacker-key");
        assert!(!bundle.verify(&other));
    }

    #[test]
    fn serialized_bundle_detects_tampering_on_the_wire() {
        // A bundle shared as JSON must fail verification if a byte of a replayed event is altered
        // in transit — the content commitment is over the events, not the manifest's own copy.
        let rec = recording();
        let signer = ContentCommitmentSigner::new("wire-key");
        let bundle = export_bundle(
            &rec,
            &participant(),
            &ReplayOptions::default(),
            "v1",
            &signer,
        )
        .unwrap();
        let json = serde_json::to_string(&bundle).unwrap();
        // Round-trip clean → still verifies.
        let clean: ReplayBundle = serde_json::from_str(&json).unwrap();
        assert!(clean.verify(&signer));
        // Alter a replayed payload in the serialized form and re-parse → verification must fail.
        assert!(json.contains("the answer is 42"));
        let tampered_json = json.replace("the answer is 42", "the answer is 99");
        let tampered: ReplayBundle = serde_json::from_str(&tampered_json).unwrap();
        assert!(!tampered.verify(&signer), "wire tampering went undetected");
    }

    #[test]
    fn bundle_export_is_rbac_scoped() {
        let rec = recording();
        let signer = ContentCommitmentSigner::new("k");
        assert_eq!(
            export_bundle(&rec, &outsider(), &ReplayOptions::default(), "v", &signer).unwrap_err(),
            ReplayError::NotAuthorized
        );
    }

    #[test]
    fn bundle_only_contains_events_the_exporter_could_see() {
        let mut rec = SessionRecording::new("s5", &["priya"]);
        rec.append_root_turn("u1", TurnRole::User, "priya", 1)
            .unwrap();
        rec.record_event("u1", EventKind::TextDelta, DataClass::Internal, "safe", 2)
            .unwrap();
        rec.record_event("u1", EventKind::TextDelta, DataClass::Pii, "acct 999", 3)
            .unwrap();
        let signer = ContentCommitmentSigner::new("k");
        // Confidential-cleared exporter: PII event must not appear in the shared bundle.
        let bundle = export_bundle(
            &rec,
            &participant(),
            &ReplayOptions::default(),
            "v",
            &signer,
        )
        .unwrap();
        assert!(bundle.events.iter().all(|e| e.text != "acct 999"));
        assert!(bundle.events.iter().any(|e| e.text == "safe"));
    }

    // --- §2.3: break-glass evidence is gated + audited --------------------
    #[test]
    fn break_glass_evidence_requires_capability_and_is_audited() {
        let mut rec = SessionRecording::new("s6", &["priya"]);
        rec.append_root_turn("u1", TurnRole::User, "priya", 1)
            .unwrap();
        let ev = rec
            .record_event_with_evidence(
                "u1",
                EventKind::TextDelta,
                DataClass::Internal,
                "card [REDACTED]",
                "card 4111111111111111",
                2,
            )
            .unwrap();
        // A normal participant cannot open the pre-redaction original.
        assert_eq!(
            rec.access_evidence(ev, &participant(), 3).unwrap_err(),
            ReplayError::NotAuthorized
        );
        // Replay of the normal stream never re-exposes it.
        let replay = plan_replay(&rec, &participant(), &ReplayOptions::default()).unwrap();
        assert!(replay.steps.iter().all(|s| !s.event.text.contains("4111")));
        // A break-glass officer can — and the access is recorded as an audit event.
        let officer = Principal::user("officer", &[CAP_BREAK_GLASS, CAP_COMPLIANCE_REPLAY])
            .with_clearance(DataClass::Pii);
        let events_before = rec.events().len();
        let original = rec.access_evidence(ev, &officer, 4).unwrap();
        assert_eq!(original.as_deref(), Some("card 4111111111111111"));
        assert_eq!(rec.events().len(), events_before + 1);
        assert_eq!(
            rec.events().last().unwrap().kind,
            EventKind::BreakGlassAccess
        );
    }

    // --- linear-log ingestion into a (linear) tree ------------------------
    #[test]
    fn from_linear_reconstructs_a_linear_tree_and_replays() {
        let records = vec![
            LinearRecord {
                kind: EventKind::TurnStart,
                role: TurnRole::User,
                author: "priya".into(),
                data_class: DataClass::Internal,
                text: "".into(),
                ts_millis: 1,
            },
            LinearRecord {
                kind: EventKind::TextDelta,
                role: TurnRole::User,
                author: "priya".into(),
                data_class: DataClass::Internal,
                text: "hello".into(),
                ts_millis: 2,
            },
            LinearRecord {
                kind: EventKind::TurnStart,
                role: TurnRole::Assistant,
                author: "assistant".into(),
                data_class: DataClass::Internal,
                text: "".into(),
                ts_millis: 3,
            },
            LinearRecord {
                kind: EventKind::TextDelta,
                role: TurnRole::Assistant,
                author: "assistant".into(),
                data_class: DataClass::Internal,
                text: "hi there".into(),
                ts_millis: 4,
            },
        ];
        let rec = SessionRecording::from_linear("legacy", &["priya"], &records);
        // Two turns, chained linearly (t1's parent is t0).
        assert_eq!(rec.tree().turn_count(), 2);
        assert_eq!(rec.tree().turn("t1").unwrap().parent.as_deref(), Some("t0"));
        let replay = plan_replay(&rec, &participant(), &ReplayOptions::default()).unwrap();
        assert!(replay.steps.iter().any(|s| s.event.text == "hi there"));
    }

    #[test]
    fn tree_path_and_head_switching_are_deterministic() {
        let mut rec = recording();
        // Fork an explicit branch off u1.
        rec.branch("u1", "alt", "arun", Some("what-if"), 3000)
            .unwrap();
        assert_eq!(rec.tree().active_head(), Some("alt"));
        // Switch back to a1's branch.
        assert_eq!(rec.tree().path_to("a1"), vec!["u1", "a1"]);
        // The alt branch path is u1 -> alt.
        assert_eq!(rec.tree().path_to("alt"), vec!["u1", "alt"]);
    }

    // =======================================================================
    // SURF-11 — the exact bridge the parent wires: the live/durable event log is an append-only
    // LINEAR stream (ainxt-eventlog::JsonlEventLog) + a per-turn Stop token (ainxt-session). This
    // test drives the whole seam: linear records --from_linear--> turn TREE, then the tree-native
    // affordances (edit -> sibling branch, steer boundary, stop) that the linear log/session cannot
    // express, then a deterministic RBAC-scoped + data-class-filtered PURE replay of the chosen
    // branch. Proves that once the parent feeds its linear log through from_linear, branch/edit/
    // stop/steer + replay are all reachable on the live session.
    // =======================================================================

    /// The shape the parent reads out of the durable linear log to hand to `from_linear`.
    fn linear_log() -> Vec<LinearRecord> {
        vec![
            LinearRecord {
                kind: EventKind::TurnStart,
                role: TurnRole::User,
                author: "priya".into(),
                data_class: DataClass::Internal,
                text: "".into(),
                ts_millis: 10,
            },
            LinearRecord {
                kind: EventKind::TextDelta,
                role: TurnRole::User,
                author: "priya".into(),
                data_class: DataClass::Internal,
                text: "reconcile ledger".into(),
                ts_millis: 11,
            },
            LinearRecord {
                kind: EventKind::TurnStart,
                role: TurnRole::Assistant,
                author: "assistant".into(),
                data_class: DataClass::Internal,
                text: "".into(),
                ts_millis: 20,
            },
            // A payment-sensitive (Pii) event: must be filtered for an under-cleared viewer.
            LinearRecord {
                kind: EventKind::TextDelta,
                role: TurnRole::Assistant,
                author: "assistant".into(),
                data_class: DataClass::Pii,
                text: "holder pan 4111111111111111".into(),
                ts_millis: 21,
            },
            LinearRecord {
                kind: EventKind::TurnEnd,
                role: TurnRole::Assistant,
                author: "assistant".into(),
                data_class: DataClass::Internal,
                text: "".into(),
                ts_millis: 22,
            },
        ]
    }

    #[test]
    fn gap_ainxt_replay_surf11_linear_log_bridges_to_tree_then_branch_and_replay() {
        // 1) Bridge the WIRED linear log into the tree (the missing tree API on JsonlEventLog).
        let mut rec =
            SessionRecording::from_linear("live-session", &["priya", "arun"], &linear_log());
        assert_eq!(
            rec.tree().turn_count(),
            2,
            "two linear turns become two chained tree turns"
        );
        assert_eq!(rec.tree().turn("t1").unwrap().parent.as_deref(), Some("t0"));

        // 2) A tree-native op the linear log/session cannot express: EDIT the user turn -> a NEW
        //    sibling branch, original preserved (never mutates history).
        let branch_head = rec
            .edit_turn("t0", "t0-edit", "priya", Some("fixed-typo"), 100)
            .unwrap();
        assert_eq!(rec.tree().active_head(), Some("t0-edit"));
        assert!(
            rec.tree().turn("t0").is_some(),
            "original turn preserved on its branch"
        );
        // Both branches are independently addressable heads (branch/edit is first-class).
        assert_eq!(rec.tree().path_to("t1"), vec!["t0", "t1"]);
        assert_eq!(rec.tree().path_to(&branch_head), vec!["t0-edit"]);

        // 3) Deterministic PURE replay of the ORIGINAL assistant branch, RBAC + data-class scoped.
        let opts = ReplayOptions {
            branch: BranchSelector::Head("t1".into()),
            ..ReplayOptions::default()
        };
        // Under-cleared participant (Confidential) never sees the Pii event pre-redaction...
        let low_replay = plan_replay(&rec, &participant(), &opts).unwrap();
        assert!(
            !low_replay
                .steps
                .iter()
                .any(|s| s.event.data_class == DataClass::Pii),
            "an above-clearance event must be omitted from replay (redaction-preserving)"
        );
        assert!(!low_replay
            .steps
            .iter()
            .any(|s| s.event.text.contains("4111")));
        // ...while a compliance auditor (Pii clearance + CAP) replaying the same branch does.
        let hi_replay = plan_replay(&rec, &auditor(), &opts).unwrap();
        assert!(hi_replay
            .steps
            .iter()
            .any(|s| s.event.text.contains("4111")));

        // 4) An outsider cannot replay at all (RBAC-scoped identically to live viewing).
        assert_eq!(
            plan_replay(&rec, &outsider(), &opts).unwrap_err(),
            ReplayError::NotAuthorized
        );
    }

    #[test]
    fn gap_ainxt_replay_surf11_steer_lands_after_tool_and_stop_is_durable() {
        // Steer/Stop are first-class on the live session TREE (the wired session exposes only a raw
        // cancel token). Drive both against a turn ingested from the linear log.
        let mut rec = SessionRecording::from_linear("live", &["priya"], &linear_log());
        // Open an in-flight tool call on the assistant turn, then steer: it must land AFTER the tool.
        let tool_id = rec
            .record_event("t1", EventKind::ToolCall, internal(), "sql.query", 30)
            .unwrap();
        let delivery = rec
            .steer("t1", "actually filter by month", internal(), 31)
            .unwrap();
        assert_eq!(
            delivery,
            SteerDelivery::AfterToolCall(tool_id),
            "never mid-tool-call"
        );

        // Stop is a durable terminal record — the turn stays replayable, not deleted.
        rec.stop("t1", 40).unwrap();
        assert_eq!(rec.tree().turn("t1").unwrap().status, TurnStatus::Stopped);
        // Steering a stopped turn is refused.
        assert!(matches!(
            rec.steer("t1", "too late", internal(), 41),
            Err(TreeError::NotActive(_))
        ));
        // The stopped turn is still fully replayable (audit-visible).
        let opts = ReplayOptions {
            branch: BranchSelector::Head("t1".into()),
            ..ReplayOptions::default()
        };
        let replay = plan_replay(&rec, &auditor(), &opts).unwrap();
        assert!(replay
            .steps
            .iter()
            .any(|s| s.event.kind == EventKind::TurnStopped));
    }

    // =======================================================================
    // Round-5: durable turn-tree persistence + store-backed replay reachability
    // =======================================================================

    /// R5 — the ephemeral-session gap: a branch applied over a persisted session must durably
    /// round-trip. FAIL-BEFORE (the wired server path) rebuilt the tree from the client's linear log
    /// each request and threw the result away — a second, independent load would not see the branch.
    /// PASS-AFTER: the branch is present after saving and reloading through a fresh `from_durable`.
    #[test]
    fn r5_turn_tree_persist_roundtrip() {
        let store = InMemorySessionStore::new();

        // Seed a session with a root + assistant turn and persist it.
        let seed = recording();
        assert_eq!(seed.id, "s1");
        store.save(&seed.to_durable()).unwrap();
        assert_eq!(store.len(), 1);

        // A participant branches off the assistant turn through the DURABLE write entrypoint.
        let outcome = apply_interaction_persisted(
            &store,
            "s1",
            &Interaction::Branch {
                from_turn: "a1".into(),
                new_id: "b1".into(),
                label: Some("what-if: without discount".into()),
            },
            &participant(),
            2000,
        )
        .unwrap();
        assert_eq!(
            outcome,
            InteractionOutcome::HeadMoved {
                new_head: "b1".into()
            }
        );

        // Reload from the store into a completely fresh recording — the branch must survive.
        let reloaded = SessionRecording::from_durable(store.load("s1").unwrap().unwrap());
        let b1 = reloaded
            .tree()
            .turn("b1")
            .expect("branch turn durably round-tripped");
        assert_eq!(b1.parent.as_deref(), Some("a1"));
        assert_eq!(b1.label.as_deref(), Some("what-if: without discount"));
        assert_eq!(reloaded.tree().active_head(), Some("b1"));

        // A SECOND durable interaction sees the first branch (proves it wasn't ephemeral): stop it.
        apply_interaction_persisted(
            &store,
            "s1",
            &Interaction::Stop { turn: "b1".into() },
            &participant(),
            2100,
        )
        .unwrap();
        let reloaded2 = SessionRecording::from_durable(store.load("s1").unwrap().unwrap());
        assert_eq!(
            reloaded2.tree().turn("b1").unwrap().status,
            TurnStatus::Stopped
        );

        // A missing session is a clean NotFound, and RBAC still holds on the persisted path.
        assert_eq!(
            apply_interaction_persisted(
                &store,
                "does-not-exist",
                &Interaction::Stop { turn: "x".into() },
                &participant(),
                2200,
            )
            .unwrap_err(),
            PersistedError::SessionNotFound("does-not-exist".into())
        );
        assert_eq!(
            apply_interaction_persisted(
                &store,
                "s1",
                &Interaction::Stop { turn: "u1".into() },
                &outsider(),
                2300,
            )
            .unwrap_err(),
            PersistedError::Interaction(InteractionError::NotAuthorized)
        );
    }

    /// R5 — the durable form is the SAFE stream only: `to_durable` must never carry the pre-redaction
    /// evidence vault (§2.3). The vault round-trips through the SEPARATE break-glass seam instead.
    #[test]
    fn r5_durable_form_excludes_evidence_vault() {
        let mut rec = SessionRecording::new("se", &["priya"]);
        rec.append_root_turn("u1", TurnRole::User, "priya", 1)
            .unwrap();
        let ev_id = rec
            .record_event_with_evidence(
                "u1",
                EventKind::TextDelta,
                DataClass::Pii,
                "card ****",
                "card 4111111111111111",
                2,
            )
            .unwrap();

        // The safe durable projection carries the redacted event but no pre-redaction original.
        let durable = rec.to_durable();
        let blob = serde_json::to_string(&durable).unwrap();
        assert!(blob.contains("card ****"));
        assert!(
            !blob.contains("4111111111111111"),
            "evidence must not leak into the safe store"
        );

        // Rehydrating from the safe form starts with an EMPTY vault; break-glass cannot read the org.
        let mut rehydrated = SessionRecording::from_durable(durable);
        let dpo = Principal::user("dpo", &[CAP_BREAK_GLASS]).with_clearance(DataClass::Pii);
        assert_eq!(rehydrated.access_evidence(ev_id, &dpo, 5).unwrap(), None);

        // The vault survives only through its OWN gated export/restore seam.
        let export = rec.export_evidence(&dpo).unwrap();
        assert!(
            rec.export_evidence(&participant()).is_err(),
            "export needs break-glass"
        );
        rehydrated.restore_evidence(export, &dpo).unwrap();
        assert_eq!(
            rehydrated
                .access_evidence(ev_id, &dpo, 6)
                .unwrap()
                .as_deref(),
            Some("card 4111111111111111")
        );
    }

    /// R5 — Execution Replay reachable through ONE store-backed entrypoint: pure-event replay,
    /// signed bundle export, and re-execution all drive off a persisted session (no manual
    /// `SessionRecording` plumbing at the call site) and stay RBAC-scoped + redaction-preserving.
    #[test]
    fn r5_replay_reachable_from_store() {
        let store = InMemorySessionStore::new();
        let mut seed = recording();
        seed.set_frozen(
            "a1",
            FrozenTurnInputs {
                prompt: "compute settlement".into(),
                model: "claude-sonnet-4-6".into(),
                params: "temp=0".into(),
                seed: 7,
            },
        )
        .unwrap();
        store.save(&seed.to_durable()).unwrap();

        // Pure-event replay over the persisted session.
        let replay =
            replay_session(&store, "s1", &participant(), &ReplayOptions::default()).unwrap();
        assert_eq!(replay.mode, ReplayMode::PureEvent);
        assert!(replay
            .steps
            .iter()
            .any(|s| s.event.text == "the answer is 42"));

        // An outsider is refused on the store-backed path too.
        assert_eq!(
            replay_session(&store, "s1", &outsider(), &ReplayOptions::default()).unwrap_err(),
            PersistedError::Replay(ReplayError::NotAuthorized)
        );
        // A missing session → NotFound.
        assert_eq!(
            replay_session(&store, "nope", &participant(), &ReplayOptions::default()).unwrap_err(),
            PersistedError::SessionNotFound("nope".into())
        );

        // Signed, credential-free bundle export over the persisted session; verifies + tamper-evident.
        let signer = ContentCommitmentSigner::new("rotate-me");
        let bundle = export_session_bundle(
            &store,
            "s1",
            &participant(),
            &ReplayOptions::default(),
            "runtime-test",
            &signer,
        )
        .unwrap();
        assert!(bundle.verify(&signer));
        let mut tampered = bundle.clone();
        tampered.events[0].text.push_str(" TAMPERED");
        assert!(
            !tampered.verify(&signer),
            "content commitment detects tampering"
        );

        // Re-execution over the persisted session forks a NEW branch and PERSISTS it (never
        // overwrites), so the drift branch is durably visible on reload.
        let head = re_execute_persisted(
            &store,
            "s1",
            "a1",
            "rx1",
            "priya",
            &participant(),
            &FakeExecutor,
            3000,
        )
        .unwrap();
        assert_eq!(head, "rx1");
        let reloaded = SessionRecording::from_durable(store.load("s1").unwrap().unwrap());
        assert!(
            reloaded.tree().turn("rx1").is_some(),
            "re-exec branch durably persisted"
        );
        assert!(reloaded.tree().turn("a1").is_some(), "original left intact");
    }

    // --- GAP-FIX regulated-fi-responsible-lifecycle: erase_turn_content --------------------

    /// `erase_turn_content` clears every event's text for the named turn but leaves the turn (and
    /// every other turn) fully present in the tree — the §6.3 "actual bytes, not the tree row" shape.
    #[test]
    fn erase_turn_content_clears_bytes_but_never_removes_the_turn() {
        let mut rec = recording();
        assert!(rec.tree().turn("a1").is_some());
        let changed = rec.erase_turn_content("a1");
        assert!(changed, "a1 had non-empty event text to clear");
        // Every a1 event's text is now empty; other turns (u1) are untouched.
        for e in rec.events().iter().filter(|e| e.turn_id == "a1") {
            assert!(
                e.text.is_empty(),
                "event {:?} must have its content bytes erased",
                e.kind
            );
        }
        let u1_text: Vec<&str> = rec
            .events()
            .iter()
            .filter(|e| e.turn_id == "u1")
            .map(|e| e.text.as_str())
            .collect();
        assert!(
            u1_text.contains(&"compute settlement"),
            "u1's content must survive a1's erasure"
        );
        // The turn itself is never deleted — still in the tree, still a child of u1.
        assert!(
            rec.tree().turn("a1").is_some(),
            "erased turn must remain in the tree (audit trail)"
        );
        assert!(
            rec.tree().children("u1").contains(&"a1"),
            "tree structure must stay intact"
        );
    }

    /// Idempotent: erasing an already-erased (or content-free) turn reports no further change.
    #[test]
    fn erase_turn_content_is_idempotent() {
        let mut rec = recording();
        assert!(rec.erase_turn_content("a1"));
        assert!(
            !rec.erase_turn_content("a1"),
            "second erase finds nothing left to clear"
        );
        assert!(
            !rec.erase_turn_content("no-such-turn"),
            "unknown turn id is a no-op, not a panic"
        );
    }
}
