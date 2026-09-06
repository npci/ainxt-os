// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-pipeline — the **Code-Review Pipeline** (Phase 3, Code + SDLC profiles).
//!
//! The one gate every code edit passes through (`docs/architecture/CODE_REVIEW_PIPELINE.md`). An
//! agent may never say "done" about a code change except through a typed [`PipelineOutcome`]: the
//! commit affordance ([`outcome::CommitApproval`]) has no constructor other than
//! [`PipelineOutcome::commit_approval`], which yields `Some` only for `Complete` — so a renderer has
//! no code path to a success signal without a real `Complete` in hand.
//!
//! What this crate implements, deterministically and offline (real compilers / LSP / LLM judges are
//! trait seams elsewhere — `ainxt-judge`, `ainxt-semantic`):
//! - [`stage`] — the twelve stages and honest `Skipped(reason)` verdicts (a skip is never a pass).
//! - [`sast`] — a deterministic scanner whose **critical/high findings hard-block** regardless of the
//!   Confidence Score (Luhn-checked PAN-in-log, hard-coded secrets, private-key/AWS-key literals,
//!   high-entropy literals), with a [`sast::SastScanner`] seam for Semgrep/`cargo audit`/bandit/gosec.
//! - [`risk`] — deterministic Tier 0–3 classification with escalate-only re-classification and the
//!   Tier-3 "force a human even at score 100" rule.
//! - [`confidence`] — the fully-broken-down Confidence Score, with the two anti-sycophancy invariants
//!   (the Judge is not a term; a skip is a penalty) enforced numerically.
//! - [`gate`] — the Commit Gate policy: hard gates before scoring, Tier-3 HITL, review-band spot-audit.
//! - [`journal`] — a SHA-256 hash-chained per-edit Event-Log for tamper-evident regulator replay.
//! - [`pipeline`] — the orchestrator that composes all of the above into one [`PipelineOutcome`] and
//!   the self-heal re-entry planner ([`pipeline::StageCache`], §6 content-hash stage caching).
//!
//! Clean-room throughout: own terminology, own layout, no vendor identifiers.

pub mod breaker;
pub mod capability;
pub mod cargo_tools;
pub mod classify;
pub mod confidence;
pub mod edit_turn;
pub mod gate;
pub mod journal;
pub mod ladder_driver;
pub mod outcome;
pub mod perf;
pub mod pipeline;
pub mod review;
pub mod risk;
pub mod sast;
pub mod selfheal;
pub mod semantic_turn;
pub mod stage;
pub mod stages;
pub mod surface;
pub mod wire_seal;

pub use breaker::{
    run_if_tier3, BreakerFinding, BreakerKind, BreakerReport, DifferentialOracle, ScriptedBreaker,
};
pub use capability::{capability, Capability, Language, StageKind};
pub use classify::{classify_edit, is_critical_path, EditRiskAssessment, CRITICAL_PATH_FRAGMENTS};
pub use edit_turn::{
    run_edit_turn, run_edit_turn_full, run_edit_turn_with_perf, ClassifiedEditResponse,
    CommitReceipt, EditEngine, EditRefused, EditRequest, EditResponse, EditTurn, ReviewRefused,
    SemanticEditRequest, SemanticEditResponse, TurnOutcome, CAP_EDIT_APPLY,
};
pub use journal::{
    FsJournalStore, HmacSigner, InMemoryJournalStore, Journal, JournalRecord, JournalSigner,
    JournalStore, PipelineEvent, SignedSeal,
};
pub use ladder_driver::{guarded_full_file_apply, run_replace_ladder, GuardedApply, WiredReplace};
pub use outcome::{CommitApproval, PipelineOutcome};
pub use perf::{
    analyze_perf, ast_complexity, complexity_delta, BenchSample, BenchSuite, BenchmarkHarness,
    ComplexityDelta, NoAdvisor, NoBench, PerfAdvisor, PerfBudget, PerfConfig, PerfFinding,
    PerfReport, ScriptedBench,
};
pub use pipeline::{content_hash, run_pipeline, PipelineInputs, StageCache};
pub use review::{
    analyze_semantic_gate, architecture_violation_count, repo_layer_contract,
    test_coverage_overlap, SemanticGateConfig, SemanticGateReport, ARCH_MANIFEST_PATH,
};
pub use risk::{classify, DiffClass, RiskInputs, RiskTier};
pub use selfheal::{
    run_selfheal, run_selfheal_full, run_selfheal_reclassified, Coder, IdentityCoder, Observation,
    ReclassifySeams, ReviewSeams, SelfHealConfig, SelfHealOutcome, SemanticGateSeams,
};
pub use semantic_turn::{
    run_semantic_turn, run_semantic_turn_full, run_semantic_turn_with_lsp, AgentOp, PlanError,
    SemanticTurn, SemanticTurnOutcome,
};
pub use stage::{Stage, StageReport, StageVerdict};
pub use stages::{
    flaky_aware, run_deterministic_stages, AstVerifyTools, ScriptedTools, StageCheckHook,
    StageContext, StageTools, ToolResult,
};
pub use surface::{review_config, run_edit, run_review, ReviewOutcome, ReviewRequest};
pub use wire_seal::{
    derive_rung, seal_wire_config, DeploymentEditPolicy, RungDerivation, WireSealReport,
};
