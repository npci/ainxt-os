// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! The pipeline **orchestrator** — it composes risk → stages → SAST hard-block → Confidence Score →
//! Commit Gate into the single typed [`PipelineOutcome`], journaling every step to the hash-chained
//! [`Journal`], and the **self-heal re-entry planner** ([`StageCache`]) that implements §6's "re-enter
//! at the earliest invalidated stage, not stage 1" with content-hash stage caching.
//!
//! The orchestrator does not itself shell out to compilers/LLMs — those are the stage seams whose
//! results the caller feeds in (already deterministic-first per §4's ordering). What lives here is
//! the *policy composition* and the *invariants*: a Phase-A failure or a SAST critical/high can never
//! reach a `Complete`, and a Tier-3 critical-path edit is handed to a human even at a perfect score.

use crate::confidence::{compute, ConfidenceInputs};
use crate::gate::{decide, GateContext, GateDecision, GatePolicy};
use crate::journal::{Journal, PipelineEvent};
use crate::outcome::PipelineOutcome;
use crate::risk::RiskTier;
use crate::sast::SastFinding;
use crate::stage::{Stage, StageReport, StageVerdict};
use ainxt_semantic::ladder::Rung;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// The inputs to one pipeline pass. Phase-A stage results are supplied already-run (deterministic
/// first, cheapest-most-likely-to-fail first — §3 ordering is the caller's responsibility).
pub struct PipelineInputs<'a> {
    pub edit_id: String,
    pub tier: RiskTier,
    pub rung: Rung,
    pub blast_fan_out: usize,
    /// The Phase-A + optional later stage reports already produced this pass.
    pub stage_reports: Vec<StageReport>,
    pub sast: &'a [SastFinding],
    pub confidence: ConfidenceInputs<'a>,
    pub architecture_violations: u32,
    /// Whether the Judge ran and approved. `None` = did not run.
    pub judge_approved: Option<bool>,
    /// Whether `judge_approved` came from a genuine context-isolated independent panel (§5). See
    /// [`crate::gate::GateContext::judge_independent`] — required `true` for a Tier-2+ commit.
    pub judge_independent: bool,
    pub policy: GatePolicy,
}

/// The first unresolved Phase-A failure in the report set, if any.
fn phase_a_failure(reports: &[StageReport]) -> Option<(Stage, String)> {
    reports.iter().find_map(|r| match &r.verdict {
        StageVerdict::Fail { detail } if r.stage.is_phase_a() => Some((r.stage, detail.clone())),
        _ => None,
    })
}

fn count_skipped(reports: &[StageReport]) -> u32 {
    reports.iter().filter(|r| r.verdict.is_skipped()).count() as u32
}

/// Run one pipeline pass, producing the typed outcome and journaling every event. Deterministic:
/// journal ticks are a monotonic counter within the pass (no wall clock).
#[must_use]
pub fn run_pipeline(mut inp: PipelineInputs, journal: &mut Journal) -> PipelineOutcome {
    let mut tick = journal.len() as u64 + 1;
    let mut next = || {
        let t = tick;
        tick += 1;
        t
    };

    journal.append(
        next(),
        PipelineEvent::PipelineStarted {
            edit_id: inp.edit_id.clone(),
            risk_tier: format!("{:?}", inp.tier),
            blast_radius: inp.blast_fan_out,
            edit_engine_rung: inp.rung.as_str().to_string(),
        },
    );
    for r in &inp.stage_reports {
        journal.append(
            next(),
            PipelineEvent::StageResult {
                stage: r.stage,
                verdict: r.verdict.clone(),
                deterministic: r.deterministic,
            },
        );
    }

    // Reflect actual skips into the Confidence inputs so a skip is never free (defensive: keep the
    // larger of what the caller passed and what the reports show).
    let observed_skips = count_skipped(&inp.stage_reports);
    if observed_skips > inp.confidence.skipped_stages {
        inp.confidence.skipped_stages = observed_skips;
    }

    if let Some(approved) = inp.judge_approved {
        journal.append(
            next(),
            PipelineEvent::JudgeVerdict {
                approved,
                judge_model: "seam".to_string(),
                context_isolation_confirmed: inp.judge_independent,
            },
        );
    }

    let score = compute(&inp.confidence);
    journal.append(
        next(),
        PipelineEvent::StageResult {
            stage: Stage::Confidence,
            verdict: StageVerdict::Advisory {
                detail: format!("score={} :: {}", score.score, score.breakdown.join("; ")),
            },
            deterministic: true,
        },
    );

    let ctx = GateContext {
        tier: inp.tier,
        phase_a_failure: phase_a_failure(&inp.stage_reports),
        sast: inp.sast,
        architecture_violations: inp.architecture_violations,
        judge_approved: inp.judge_approved,
        judge_independent: inp.judge_independent,
    };
    let decision = decide(&ctx, &score, inp.policy);

    // Build the full report (stage reports + the Confidence stage line).
    let mut report = inp.stage_reports.clone();
    report.push(StageReport {
        stage: Stage::Confidence,
        verdict: StageVerdict::Advisory {
            detail: score.breakdown.join("; "),
        },
        deterministic: true,
    });

    let outcome = match decision {
        GateDecision::Blocked {
            stage,
            deterministic_failure,
        } => PipelineOutcome::Blocked {
            stage,
            deterministic_failure,
        },
        GateDecision::Complete { score, spot_audit } => PipelineOutcome::Complete {
            confidence: score,
            spot_audit,
            report,
        },
        GateDecision::RequiresHitl { score, judge_ran } => PipelineOutcome::Capped {
            blocking_stage: Stage::CommitGate,
            reason: format!(
                "Tier 3 critical-path: human approval required regardless of score {score} \
                 (autonomy forced to assisted; judge_ran={judge_ran})"
            ),
            rounds_exhausted: 0,
            gap_report: report,
        },
        GateDecision::Capped {
            blocking_stage,
            reason,
            score,
        } => PipelineOutcome::Capped {
            blocking_stage,
            reason: format!("{reason} (score {score})"),
            rounds_exhausted: 0,
            gap_report: report,
        },
    };

    let (label, conf) = match &outcome {
        PipelineOutcome::Complete { confidence, .. } => ("complete", *confidence),
        PipelineOutcome::Capped { .. } => ("capped", score.score),
        PipelineOutcome::Blocked { .. } => ("blocked", 0),
    };
    journal.append(
        next(),
        PipelineEvent::PipelineOutcome {
            outcome: label.to_string(),
            confidence_score: conf,
        },
    );

    outcome
}

// ============================ Self-heal re-entry (content-hash cache) ============================

/// Content-hash of a file set (`SEMANTIC_EDITING.md`/§3's SHA256 stage-caching discipline).
#[must_use]
pub fn content_hash(files: &BTreeMap<String, String>) -> String {
    let mut h = Sha256::new();
    for (p, c) in files {
        h.update(p.as_bytes());
        h.update(b"\x1f");
        h.update(c.as_bytes());
        h.update(b"\x1e");
    }
    let d = h.finalize();
    let mut s = String::with_capacity(64);
    for b in d {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// The stages that ALWAYS re-run for any touched file, however "small" the fix (§6): never trust a
/// small change to skip the basics.
fn always_reruns(stage: Stage) -> bool {
    matches!(
        stage,
        Stage::Compile | Stage::Test | Stage::Lint | Stage::TypeCheck
    )
}

/// Caches which `(stage, input-content-hash)` pairs have already been computed this pipeline run, so a
/// self-heal fix confined to file X does not re-run Architecture/Perf/SAST on unrelated files whose
/// hash didn't change — while compile/tests/lint/type-check always re-run for touched files.
#[derive(Debug, Clone, Default)]
pub struct StageCache {
    seen: BTreeSet<(Stage, String)>,
}

impl StageCache {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether `stage` must run given its input file set's `input_hash`.
    #[must_use]
    pub fn should_run(&self, stage: Stage, input_hash: &str) -> bool {
        always_reruns(stage) || !self.seen.contains(&(stage, input_hash.to_string()))
    }

    /// Record that `stage` ran against `input_hash`.
    pub fn record(&mut self, stage: Stage, input_hash: &str) {
        self.seen.insert((stage, input_hash.to_string()));
    }

    /// Plan the earliest-invalidated re-entry: given the stages selected for the tier and the current
    /// input hash, the subset that must re-run. Preserves stage order.
    #[must_use]
    pub fn stages_to_rerun(&self, tier_stages: &[Stage], input_hash: &str) -> Vec<Stage> {
        tier_stages
            .iter()
            .copied()
            .filter(|s| self.should_run(*s, input_hash))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::risk::RiskTier;
    use crate::sast::{SastFinding, Severity};

    fn base_inputs<'a>(sast: &'a [SastFinding], reports: Vec<StageReport>) -> PipelineInputs<'a> {
        PipelineInputs {
            edit_id: "e1".into(),
            tier: RiskTier::Local,
            rung: Rung::Ast,
            blast_fan_out: 0,
            stage_reports: reports,
            sast,
            confidence: ConfidenceInputs {
                sast,
                perf_regression_penalty: 0,
                architecture_violations: 0,
                blast_radius_test_coverage: 1.0,
                review_findings: &[],
                skipped_stages: 0,
                rung: Rung::Ast,
            },
            architecture_violations: 0,
            judge_approved: None,
            judge_independent: false,
            policy: GatePolicy::default(),
        }
    }

    #[test]
    fn clean_local_edit_completes_and_journal_verifies() {
        let reports = vec![
            StageReport::pass(Stage::Compile, true),
            StageReport::pass(Stage::Test, true),
            StageReport::pass(Stage::Lint, true),
        ];
        let mut j = Journal::new("e1");
        let out = run_pipeline(base_inputs(&[], reports), &mut j);
        assert!(out.is_complete());
        assert!(out.commit_approval().is_some());
        // Every step was journaled and the chain is intact for regulator replay.
        assert_eq!(j.verify(), Ok(()));
        assert!(j.len() >= 5);
    }

    #[test]
    fn sast_critical_blocks_the_pipeline_regardless_of_everything_else() {
        let findings = vec![SastFinding {
            rule: "pan-in-log".into(),
            severity: Severity::Critical,
            file: "pay.rs".into(),
            line: 4,
            evidence: "************1111".into(),
        }];
        let reports = vec![StageReport::pass(Stage::Compile, true)];
        let mut j = Journal::new("e1");
        let out = run_pipeline(base_inputs(&findings, reports), &mut j);
        match out {
            PipelineOutcome::Blocked {
                stage,
                deterministic_failure,
            } => {
                assert_eq!(stage, Stage::Sast);
                assert!(deterministic_failure.contains("pan-in-log"));
            }
            other => panic!("expected Blocked, got {other:?}"),
        }
        assert_eq!(j.verify(), Ok(()));
    }

    #[test]
    fn phase_a_compile_failure_blocks() {
        let reports = vec![StageReport::fail(
            Stage::Compile,
            true,
            "E0433: unresolved import",
        )];
        let mut j = Journal::new("e1");
        let out = run_pipeline(base_inputs(&[], reports), &mut j);
        assert!(matches!(
            out,
            PipelineOutcome::Blocked {
                stage: Stage::Compile,
                ..
            }
        ));
    }

    #[test]
    fn tier3_critical_path_hands_to_human_even_at_perfect_score() {
        let reports = vec![
            StageReport::pass(Stage::Compile, true),
            StageReport::pass(Stage::Test, true),
        ];
        let mut inp = base_inputs(&[], reports);
        inp.tier = RiskTier::HighRisk;
        inp.judge_approved = Some(true);
        let mut j = Journal::new("e1");
        let out = run_pipeline(inp, &mut j);
        // Not Complete (no auto-commit): a Capped human hand-off, per §8 Tier-3.
        match out {
            PipelineOutcome::Capped { reason, .. } => assert!(reason.contains("human approval")),
            other => panic!("expected Capped/HITL, got {other:?}"),
        }
    }

    #[test]
    fn uncovered_blast_radius_caps_below_threshold() {
        let reports = vec![StageReport::pass(Stage::Compile, true)];
        let mut inp = base_inputs(&[], reports);
        // 100% uncovered → -30 regression risk from 100 → 70; that's exactly the review band, so it
        // completes-with-spot-audit. Push harder: also a skipped stage → 65 → capped.
        inp.confidence.blast_radius_test_coverage = 0.0;
        inp.confidence.skipped_stages = 1;
        let mut j = Journal::new("e1");
        let out = run_pipeline(inp, &mut j);
        assert!(matches!(out, PipelineOutcome::Capped { .. }));
    }

    #[test]
    fn a_skip_in_reports_is_folded_into_the_score() {
        let reports = vec![
            StageReport::pass(Stage::Compile, true),
            StageReport::skipped(Stage::TypeCheck, "no typechecker"),
            StageReport::skipped(Stage::Sast, "no sast engine"),
        ];
        let mut j = Journal::new("e1");
        let out = run_pipeline(base_inputs(&[], reports), &mut j);
        // Two skips = -10 → 90 → still auto-completes, but the skip penalty is visible in the report.
        if let PipelineOutcome::Complete {
            confidence, report, ..
        } = out
        {
            assert_eq!(confidence, 90);
            assert!(report.iter().any(|r| r.verdict.is_skipped()));
        } else {
            panic!("expected Complete with skip penalty");
        }
    }

    // ---- re-entry / stage cache ----

    #[test]
    fn content_hash_is_stable_and_sensitive() {
        let a: BTreeMap<String, String> = [("x.rs".to_string(), "fn a() {}".to_string())]
            .into_iter()
            .collect();
        let b: BTreeMap<String, String> = [("x.rs".to_string(), "fn a() { 1 }".to_string())]
            .into_iter()
            .collect();
        assert_eq!(content_hash(&a), content_hash(&a));
        assert_ne!(content_hash(&a), content_hash(&b));
    }

    #[test]
    fn basics_always_rerun_but_expensive_stages_cache() {
        let mut cache = StageCache::new();
        let h = "hash-of-file-set";
        let tier2 = [
            Stage::Compile,
            Stage::Test,
            Stage::Lint,
            Stage::TypeCheck,
            Stage::Sast,
            Stage::Architecture,
        ];
        // First pass: everything runs.
        let first = cache.stages_to_rerun(&tier2, h);
        assert_eq!(first.len(), tier2.len());
        for s in first {
            cache.record(s, h);
        }
        // Second pass, SAME file hash: compile/test/lint/typecheck re-run; SAST/architecture cached.
        let second = cache.stages_to_rerun(&tier2, h);
        assert_eq!(
            second,
            vec![Stage::Compile, Stage::Test, Stage::Lint, Stage::TypeCheck]
        );
        assert!(!second.contains(&Stage::Sast));
        assert!(!second.contains(&Stage::Architecture));
    }

    #[test]
    fn a_changed_file_set_reinvalidates_expensive_stages() {
        let mut cache = StageCache::new();
        cache.record(Stage::Architecture, "hash-A");
        // Same hash → cached (skip).
        assert!(!cache.should_run(Stage::Architecture, "hash-A"));
        // Different hash (a fix changed the file set) → must re-run.
        assert!(cache.should_run(Stage::Architecture, "hash-B"));
    }
}
