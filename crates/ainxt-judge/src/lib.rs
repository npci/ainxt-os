// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-judge — the SDLC judge loop (Phase 3).
//!
//! SDLC work is generate-then-check, and the check must be trustworthy. This crate is a bounded
//! loop with three guarantees:
//!
//! 1. **Deterministic verify gates the judges.** A candidate that fails a deterministic check
//!    (compile/test/lint via the [`Verifier`] seam) never reaches the panel — you don't ask an LLM
//!    judge whether code that doesn't compile is good.
//! 2. **Judges are independent.** Each [`Judge`] scores the candidate on its own, never seeing the
//!    other judges' verdicts (structural: the panel hands each only the candidate + criteria).
//!    Consensus is a strict majority — a single lenient judge can't wave a change through.
//! 3. **`capped` is honest.** If the loop exhausts its iteration budget without consensus, it
//!    returns `capped = true` and `succeeded = false` with the best attempt so far. It never dresses
//!    "ran out of tries" up as success — the failure mode that silently ships bad changes.
//!
//! HITL commit gating is not here: it is the P1 Approval seam, driven by the SDLC profile's
//! `act-with-approval` autonomy — a side-effecting commit (open MR, push) clears the approval gate.
//!
//! Pure and deterministic (generator/verifier/judges are seams), so the loop's control flow — and
//! especially the honest-`capped` invariant — is exhaustively testable. Clean-room throughout.

use serde::{Deserialize, Serialize};

/// What the panel is judging against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JudgeCriteria {
    /// The goal the candidate must satisfy (e.g. "implements the ticket without regressions").
    pub goal: String,
    /// Minimum score (0–100) for a single judge to consider the candidate passing.
    pub threshold: u8,
}

/// One judge's independent verdict on a candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JudgeVerdict {
    pub judge: String,
    pub score: u8,
    pub passed: bool,
    pub notes: String,
}

/// A judge scores a candidate. Distinct implementations = distinct lenses (correctness, security,
/// style…); their independence is what makes the panel meaningful.
pub trait Judge: Send + Sync {
    fn id(&self) -> &str;
    fn score(&self, candidate: &str, criteria: &JudgeCriteria) -> JudgeVerdict;
}

/// The panel's aggregate verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PanelVerdict {
    pub verdicts: Vec<JudgeVerdict>,
    /// Mean score across the panel (0–100).
    pub aggregate: u8,
    /// Whether a strict majority of judges passed.
    pub consensus_pass: bool,
    /// True when this verdict was produced by [`JudgePanel::evaluate_submission`], which structurally
    /// withholds the coder's self-summary from every judge (`CODE_REVIEW_PIPELINE.md` §5 — the Judge
    /// must not inherit the coder's completion claim). `false` for the raw [`JudgePanel::evaluate`]
    /// path, where the caller vouches for what the candidate string contains.
    pub context_isolation_confirmed: bool,
}

/// What the coder submitted for adjudication. The `self_summary` is the coder's own claim of
/// completeness — a finder ([`Reviewer`]) may read it, but the [`JudgePanel`]'s completion judgment
/// must never see it (anti-sycophancy: a confident summary must not talk the Judge into `approve`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoderSubmission {
    pub candidate: String,
    pub self_summary: String,
}

/// A panel of independent judges.
pub struct JudgePanel {
    judges: Vec<Box<dyn Judge>>,
}

impl JudgePanel {
    pub fn new(judges: Vec<Box<dyn Judge>>) -> Self {
        JudgePanel { judges }
    }

    pub fn len(&self) -> usize {
        self.judges.len()
    }
    pub fn is_empty(&self) -> bool {
        self.judges.is_empty()
    }

    /// Each judge scores the candidate INDEPENDENTLY (given only the candidate + criteria — never a
    /// peer's verdict). Consensus is a strict majority; the aggregate is the mean score.
    pub fn evaluate(&self, candidate: &str, criteria: &JudgeCriteria) -> PanelVerdict {
        let verdicts: Vec<JudgeVerdict> = self
            .judges
            .iter()
            .map(|j| j.score(candidate, criteria))
            .collect();
        let n = verdicts.len();
        let passed = verdicts.iter().filter(|v| v.passed).count();
        let consensus_pass = n > 0 && passed * 2 > n;
        let aggregate = if n == 0 {
            0
        } else {
            (verdicts.iter().map(|v| v.score as u32).sum::<u32>() / n as u32) as u8
        };
        PanelVerdict {
            verdicts,
            aggregate,
            consensus_pass,
            context_isolation_confirmed: false,
        }
    }

    /// Adjudicate a [`CoderSubmission`] with **context isolation**: each judge sees ONLY the
    /// candidate + criteria — never `submission.self_summary`. The returned verdict carries
    /// `context_isolation_confirmed = true`. This is the Judge role of `CODE_REVIEW_PIPELINE.md` §5,
    /// architecturally separated from the finder [`Reviewer`] role below.
    pub fn evaluate_submission(
        &self,
        submission: &CoderSubmission,
        criteria: &JudgeCriteria,
    ) -> PanelVerdict {
        // Structural withholding: only `.candidate` crosses into the panel.
        let mut v = self.evaluate(&submission.candidate, criteria);
        v.context_isolation_confirmed = true;
        v
    }
}

// ============================ LLM Review role (finder, not adjudicator) ============================

/// Severity of a review finding. Distinct from the pipeline's SAST severity; scoped to human-style
/// code-review findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReviewSeverity {
    Info,
    Minor,
    Major,
    Critical,
}

/// One finding from the LLM Review stage (`CODE_REVIEW_PIPELINE.md` §4 stage 9). Anti-noise: a
/// finding MUST cite the exact lines and articulate the concrete failure mode; an unreferenced
/// stylistic opinion is filtered by [`ReviewFinding::is_actionable`] before it reaches the coder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewFinding {
    pub severity: ReviewSeverity,
    /// The exact 1-based lines the finding anchors to (empty ⇒ not actionable).
    pub lines: Vec<usize>,
    /// The concrete failure mode ("if `amount` is negative here, the retry double-credits").
    pub message: String,
}

impl ReviewFinding {
    /// A finding is actionable only if it cites at least one line and states a concrete failure.
    #[must_use]
    pub fn is_actionable(&self) -> bool {
        !self.lines.is_empty() && self.message.trim().len() >= 8
    }
}

/// The LLM Review role: finds and lists issues against a diff + task. It does **not** decide overall
/// completion (that is the [`JudgePanel`]). It may see the coder's self-summary (it is a finder;
/// correlated blind spots are a cost/quality tradeoff, not a safety hole — §5).
pub trait Reviewer: Send + Sync {
    fn review(&self, submission: &CoderSubmission, task: &str) -> Vec<ReviewFinding>;
}

/// Run a reviewer and keep only actionable findings (drops unreferenced noise).
pub fn actionable_review(
    reviewer: &dyn Reviewer,
    submission: &CoderSubmission,
    task: &str,
) -> Vec<ReviewFinding> {
    reviewer
        .review(submission, task)
        .into_iter()
        .filter(ReviewFinding::is_actionable)
        .collect()
}

// ============================ Stuck / thrash detector ============================

/// Why a self-heal loop was diagnosed as stuck — distinct from the round-cap (`CODE_REVIEW_PIPELINE`
/// §6): a cap alone still burns N rounds making no progress; the detector recognizes thrashing early.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StuckKind {
    /// The last `window` attempts made no material change (near-identical candidates).
    NoProgress,
    /// The candidate oscillates — it re-equals a candidate from an earlier round (fix for A reopens
    /// B, fix for B reopens A).
    Cycle,
}

/// A stuck diagnosis with a human-legible reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StuckDiagnosis {
    pub kind: StuckKind,
    pub reason: String,
}

/// Detects a stuck/thrashing self-heal loop from the sequence of candidates it produces. Pure and
/// deterministic: similarity is token-set Jaccard, no clock/rng.
#[derive(Debug, Clone)]
pub struct StuckDetector {
    /// Number of most-recent attempts examined for no-progress (>= 2 to be meaningful).
    window: usize,
    /// Similarity in `[0,1]` at/above which two adjacent candidates count as "no material change".
    threshold: f64,
    history: Vec<String>,
}

impl StuckDetector {
    /// `window` most-recent attempts, `threshold` adjacent-similarity for no-progress.
    #[must_use]
    pub fn new(window: usize, threshold: f64) -> Self {
        StuckDetector {
            window: window.max(2),
            threshold: threshold.clamp(0.0, 1.0),
            history: Vec::new(),
        }
    }

    /// Feed the next candidate. Returns `Some(diagnosis)` the first time the loop is judged stuck.
    pub fn observe(&mut self, candidate: &str) -> Option<StuckDiagnosis> {
        // Cycle (oscillation A→B→A): this candidate re-equals a NON-immediate earlier candidate,
        // AND the immediately-previous candidate differs from it (so it truly diverged and came
        // back). Exact consecutive repeats are handled by the no-progress path below, not here.
        if self.history.len() >= 2 {
            let last_differs = self.history.last().map(|l| l != candidate).unwrap_or(false);
            if last_differs
                && self.history[..self.history.len() - 1]
                    .iter()
                    .any(|prev| prev == candidate)
            {
                self.history.push(candidate.to_string());
                return Some(StuckDiagnosis {
                    kind: StuckKind::Cycle,
                    reason: "candidate re-equals an earlier round (oscillation)".to_string(),
                });
            }
        }
        self.history.push(candidate.to_string());

        // No-progress: the last `window` candidates are all pairwise-adjacent similar.
        if self.history.len() >= self.window {
            let tail = &self.history[self.history.len() - self.window..];
            let stuck = tail
                .windows(2)
                .all(|p| jaccard(&p[0], &p[1]) >= self.threshold);
            if stuck {
                return Some(StuckDiagnosis {
                    kind: StuckKind::NoProgress,
                    reason: format!(
                        "no material change across the last {} attempts",
                        self.window
                    ),
                });
            }
        }
        None
    }
}

/// Token-set Jaccard similarity of two strings (1.0 identical token sets, 0.0 disjoint).
fn jaccard(a: &str, b: &str) -> f64 {
    use std::collections::BTreeSet;
    let sa: BTreeSet<&str> = a.split_whitespace().collect();
    let sb: BTreeSet<&str> = b.split_whitespace().collect();
    if sa.is_empty() && sb.is_empty() {
        return 1.0;
    }
    let inter = sa.intersection(&sb).count() as f64;
    let union = sa.union(&sb).count() as f64;
    if union == 0.0 {
        1.0
    } else {
        inter / union
    }
}

/// Produces a candidate for an attempt, optionally using the previous round's feedback.
pub trait Generator: Send + Sync {
    fn generate(&self, attempt: usize, feedback: &[String]) -> String;
}

/// The result of a deterministic check (compile/test/lint).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyResult {
    pub passed: bool,
    pub diagnostics: Vec<String>,
}

/// Runs deterministic checks on a candidate before it is judged.
pub trait Verifier: Send + Sync {
    fn verify(&self, candidate: &str) -> VerifyResult;
}

/// A verifier that always passes — for surfaces with no deterministic check to run.
pub struct NoVerifier;
impl Verifier for NoVerifier {
    fn verify(&self, _candidate: &str) -> VerifyResult {
        VerifyResult {
            passed: true,
            diagnostics: Vec::new(),
        }
    }
}

/// Loop budget.
#[derive(Debug, Clone, Copy)]
pub struct LoopConfig {
    pub max_iters: usize,
    /// Optional stuck-detector window. `Some((window, threshold))` aborts early (as `capped`, with a
    /// diagnosis) when the loop thrashes/makes no progress, *before* the round-cap burns the budget.
    /// `None` (default) preserves the pure round-cap behavior.
    pub stuck: Option<(usize, f64)>,
}

impl Default for LoopConfig {
    fn default() -> Self {
        LoopConfig {
            max_iters: 3,
            stuck: None,
        }
    }
}

/// The outcome of a judge loop. **Invariant:** `succeeded` and `capped` are never both true — if the
/// budget ran out without consensus, `capped = true` and `succeeded = false`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoopOutcome {
    /// The best candidate seen (the consensus one if `succeeded`, else the highest-scoring verified
    /// attempt, else the last attempt).
    pub candidate: String,
    /// How many attempts were made.
    pub iterations: usize,
    /// The panel verdict for `candidate`, if it passed deterministic verification.
    pub verdict: Option<PanelVerdict>,
    /// Whether `candidate` passed deterministic verification.
    pub verified: bool,
    /// True iff the loop hit its budget without consensus. Never reported as success.
    pub capped: bool,
    /// True iff the panel reached consensus within budget.
    pub succeeded: bool,
    /// The stuck/thrash diagnosis, if the loop was aborted early by the detector (implies `capped`).
    pub stuck: Option<StuckDiagnosis>,
}

/// The judge loop: generate → verify → judge → iterate, bounded.
///
/// GAP-AUDIT gap6-injection-judge-consolidation (item 2) — `JudgeLoop`/[`Generator`]/[`Verifier`]
/// have exactly one caller anywhere in the tree: `ainxt-surface/tests/dod_p3_matrix.rs`'s
/// `JUDGE-CAPPED-001` scenario (a test, not a served path). The real production self-heal loop,
/// `ainxt_pipeline::selfheal::run_selfheal_reclassified` (reachable from the composition root via the
/// `/v1/edit` and `/v1/edit/classified` write routes in `ainxt-server`'s `edit_handler`/
/// `classified_edit_handler`, through `EditEngine::run_edit_turn_full_guarded` — NOT
/// `/v1/edit/review`, which runs the crate's separate, single-pass, no-loop `surface::run_review`),
/// hand-rolls its own round loop instead of calling `JudgeLoop`. That is not a missing guarantee,
/// though — side by side:
///
/// - **Bound mechanism**: `JudgeLoop::run` is `for attempt in 0..self.config.max_iters.max(1)`
///   (this file). `run_selfheal_reclassified` is `for round in 0..config.max_rounds.max(1)`
///   (`ainxt-pipeline/src/selfheal.rs`) — the identical shape, additionally reinforced by an explicit
///   `if round + 1 >= max { return ... Capped }` check one round before the range would exhaust, so
///   the loop can never silently fall off the end without an honest `Capped` outcome already having
///   fired.
/// - **Stuck detection**: both loops plug in the SAME [`StuckDetector`] type from this crate
///   (`self.config.stuck.map(|(w, t)| StuckDetector::new(w, t))` — verbatim identical in both files)
///   to abort early on thrash before burning the whole budget.
/// - **Building blocks**: `selfheal.rs` does not reimplement judging — it imports and calls this
///   crate's own [`JudgePanel`], [`StuckDetector`], and [`Reviewer`]/`actionable_review` directly
///   (`ainxt-pipeline/src/selfheal.rs`'s `use ainxt_judge::{...}`). Only the outer control-flow shell
///   (round counting, re-classification, stage caching) is independently implemented, not the
///   generate/verify/judge primitives themselves.
/// - **Anti-sycophancy invariant**: `LoopOutcome` encodes "never report success on exhaustion" as a
///   documented boolean invariant (`succeeded` and `capped` are never both true). `selfheal.rs`'s
///   `PipelineOutcome` (`ainxt-pipeline/src/outcome.rs`) encodes the same idea more strongly in the
///   type system: `PipelineOutcome::Complete` is the only variant that yields a `CommitApproval`, and
///   `CommitApproval` has no public constructor (a private `seal` field) — no renderer can fabricate a
///   "done" without a genuine `Complete`, whereas `Capped`/`Blocked` can only ever render as an honest
///   gap report.
///
/// The two loops are genuinely equivalent in strength (both are hard-capped by iteration count, both
/// layer the same stuck-detector, neither has a wall-clock timeout) — legitimately superseded,
/// unreachable-in-production code kept as a general-purpose generate/verify/judge orchestrator for a
/// caller that is not the code-edit self-heal pipeline.
pub struct JudgeLoop {
    panel: JudgePanel,
    verifier: Box<dyn Verifier>,
    config: LoopConfig,
}

impl JudgeLoop {
    pub fn new(panel: JudgePanel, verifier: Box<dyn Verifier>, config: LoopConfig) -> Self {
        JudgeLoop {
            panel,
            verifier,
            config,
        }
    }

    /// Run the loop against a generator + criteria. Deterministic control flow; the honest-`capped`
    /// contract holds regardless of what the seams do.
    pub fn run(&self, generator: &dyn Generator, criteria: &JudgeCriteria) -> LoopOutcome {
        let max = self.config.max_iters.max(1);
        let mut feedback: Vec<String> = Vec::new();
        // best = (candidate, verdict, verified)
        let mut best: Option<(String, Option<PanelVerdict>, bool)> = None;
        let mut detector = self.config.stuck.map(|(w, t)| StuckDetector::new(w, t));

        for attempt in 0..max {
            let candidate = generator.generate(attempt, &feedback);

            // Stuck/thrash detection is distinct from the round-cap: it aborts early (honest capped)
            // rather than burning the whole budget making no progress.
            if let Some(det) = detector.as_mut() {
                if let Some(diag) = det.observe(&candidate) {
                    // Fold the current candidate into `best` if it's the first verified/seen one.
                    let vr = self.verifier.verify(&candidate);
                    if vr.passed {
                        let verdict = self.panel.evaluate(&candidate, criteria);
                        let is_better = match &best {
                            Some((_, Some(prev), true)) => verdict.aggregate > prev.aggregate,
                            _ => true,
                        };
                        if is_better {
                            best = Some((candidate.clone(), Some(verdict), true));
                        }
                    } else if best.is_none() {
                        best = Some((candidate, None, false));
                    }
                    let (candidate, verdict, verified) = best.unwrap_or_default();
                    return LoopOutcome {
                        candidate,
                        iterations: attempt + 1,
                        verdict,
                        verified,
                        capped: true,
                        succeeded: false,
                        stuck: Some(diag),
                    };
                }
            }

            let vr = self.verifier.verify(&candidate);
            if !vr.passed {
                // Deterministic failure: feed diagnostics back; a broken candidate is never judged.
                feedback = vr.diagnostics;
                if best.is_none() {
                    best = Some((candidate, None, false));
                }
                continue;
            }

            let verdict = self.panel.evaluate(&candidate, criteria);

            let is_better = match &best {
                Some((_, Some(prev), true)) => verdict.aggregate > prev.aggregate,
                _ => true, // any verified candidate beats a non-verified/absent best
            };
            if is_better {
                best = Some((candidate.clone(), Some(verdict.clone()), true));
            }

            if verdict.consensus_pass {
                return LoopOutcome {
                    candidate,
                    iterations: attempt + 1,
                    verdict: Some(verdict),
                    verified: true,
                    capped: false,
                    succeeded: true,
                    stuck: None,
                };
            }

            feedback = verdict.verdicts.iter().map(|v| v.notes.clone()).collect();
        }

        let (candidate, verdict, verified) = best.unwrap_or_default();
        LoopOutcome {
            candidate,
            iterations: max,
            verdict,
            verified,
            capped: true,
            succeeded: false,
            stuck: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    /// A judge that passes iff the candidate contains `needle`.
    struct KeywordJudge {
        id: String,
        needle: String,
    }
    impl Judge for KeywordJudge {
        fn id(&self) -> &str {
            &self.id
        }
        fn score(&self, candidate: &str, _c: &JudgeCriteria) -> JudgeVerdict {
            let passed = candidate.contains(&self.needle);
            JudgeVerdict {
                judge: self.id.clone(),
                score: if passed { 90 } else { 30 },
                passed,
                notes: if passed {
                    "ok".into()
                } else {
                    format!("missing {}", self.needle)
                },
            }
        }
    }

    fn criteria() -> JudgeCriteria {
        JudgeCriteria {
            goal: "implement it".into(),
            threshold: 60,
        }
    }

    fn panel_of(needles: &[&str]) -> JudgePanel {
        JudgePanel::new(
            needles
                .iter()
                .enumerate()
                .map(|(i, n)| {
                    Box::new(KeywordJudge {
                        id: format!("j{i}"),
                        needle: n.to_string(),
                    }) as Box<dyn Judge>
                })
                .collect(),
        )
    }

    #[test]
    fn consensus_needs_a_strict_majority() {
        let panel = panel_of(&["ALPHA", "BETA", "GAMMA"]);
        // Candidate has ALPHA + BETA but not GAMMA → 2/3 pass → consensus.
        let v = panel.evaluate("has ALPHA and BETA", &criteria());
        assert!(v.consensus_pass);
        assert_eq!(v.verdicts.len(), 3);
        assert_eq!(v.aggregate, (90 + 90 + 30) / 3);
        // Candidate has only ALPHA → 1/3 → no consensus.
        assert!(!panel.evaluate("has ALPHA only", &criteria()).consensus_pass);
        // A tie (2 judges, 1 pass) is NOT a strict majority.
        assert!(
            !panel_of(&["ALPHA", "ZETA"])
                .evaluate("has ALPHA", &criteria())
                .consensus_pass
        );
    }

    /// Generator that returns a fixed sequence of candidates and records the feedback it received.
    struct ScriptedGenerator {
        outputs: Vec<String>,
        seen_feedback: Arc<Mutex<Vec<Vec<String>>>>,
    }
    impl Generator for ScriptedGenerator {
        fn generate(&self, attempt: usize, feedback: &[String]) -> String {
            self.seen_feedback.lock().unwrap().push(feedback.to_vec());
            self.outputs.get(attempt).cloned().unwrap_or_default()
        }
    }

    #[test]
    fn succeeds_within_budget() {
        let gen = ScriptedGenerator {
            outputs: vec!["nope".into(), "has ALPHA and BETA".into()],
            seen_feedback: Arc::new(Mutex::new(Vec::new())),
        };
        let lp = JudgeLoop::new(
            panel_of(&["ALPHA", "BETA"]),
            Box::new(NoVerifier),
            LoopConfig {
                max_iters: 3,
                stuck: None,
            },
        );
        let out = lp.run(&gen, &criteria());
        assert!(out.succeeded && !out.capped);
        assert_eq!(out.iterations, 2);
        assert!(out.verdict.unwrap().consensus_pass);
    }

    #[test]
    fn caps_honestly_when_never_passing() {
        let gen = ScriptedGenerator {
            outputs: vec!["nope".into(); 5],
            seen_feedback: Arc::new(Mutex::new(Vec::new())),
        };
        let lp = JudgeLoop::new(
            panel_of(&["ALPHA", "BETA"]),
            Box::new(NoVerifier),
            LoopConfig {
                max_iters: 3,
                stuck: None,
            },
        );
        let out = lp.run(&gen, &criteria());
        // THE invariant: capped ⇒ not succeeded.
        assert!(out.capped && !out.succeeded);
        assert_eq!(out.iterations, 3);
        // Best verified attempt is still returned (with its sub-consensus verdict), never as success.
        assert!(out.verified);
        assert!(!out.verdict.unwrap().consensus_pass);
    }

    #[test]
    fn verifier_gates_the_panel() {
        // A judge that counts how many times it was consulted.
        struct CountingJudge {
            calls: Arc<AtomicUsize>,
        }
        impl Judge for CountingJudge {
            fn id(&self) -> &str {
                "counter"
            }
            fn score(&self, candidate: &str, _c: &JudgeCriteria) -> JudgeVerdict {
                self.calls.fetch_add(1, Ordering::SeqCst);
                let passed = candidate.contains("good");
                JudgeVerdict {
                    judge: "counter".into(),
                    score: if passed { 90 } else { 10 },
                    passed,
                    notes: String::new(),
                }
            }
        }
        // Verifier fails anything containing "broken".
        struct RejectBroken;
        impl Verifier for RejectBroken {
            fn verify(&self, candidate: &str) -> VerifyResult {
                if candidate.contains("broken") {
                    VerifyResult {
                        passed: false,
                        diagnostics: vec!["does not compile".into()],
                    }
                } else {
                    VerifyResult {
                        passed: true,
                        diagnostics: vec![],
                    }
                }
            }
        }
        let calls = Arc::new(AtomicUsize::new(0));
        let panel = JudgePanel::new(vec![Box::new(CountingJudge {
            calls: calls.clone(),
        })]);
        let gen = ScriptedGenerator {
            outputs: vec!["broken attempt".into(), "good attempt".into()],
            seen_feedback: Arc::new(Mutex::new(Vec::new())),
        };
        let seen = gen.seen_feedback.clone();
        let lp = JudgeLoop::new(
            panel,
            Box::new(RejectBroken),
            LoopConfig {
                max_iters: 3,
                stuck: None,
            },
        );
        let out = lp.run(&gen, &criteria());
        assert!(out.succeeded);
        // The judge ran ONCE — only for the candidate that passed verification.
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // The verifier's diagnostics were fed to the second generation.
        assert_eq!(
            seen.lock().unwrap()[1],
            vec!["does not compile".to_string()]
        );
    }

    #[test]
    fn judge_feedback_flows_to_the_next_attempt() {
        let gen = ScriptedGenerator {
            outputs: vec!["has ALPHA only".into(), "has ALPHA and BETA".into()],
            seen_feedback: Arc::new(Mutex::new(Vec::new())),
        };
        let seen = gen.seen_feedback.clone();
        let lp = JudgeLoop::new(
            panel_of(&["ALPHA", "BETA"]),
            Box::new(NoVerifier),
            LoopConfig {
                max_iters: 3,
                stuck: None,
            },
        );
        let out = lp.run(&gen, &criteria());
        assert!(out.succeeded);
        // Attempt 2 received the failing judge's note ("missing BETA").
        assert!(seen.lock().unwrap()[1]
            .iter()
            .any(|f| f.contains("missing BETA")));
    }

    #[test]
    fn verdict_serde_round_trips() {
        let v = JudgeVerdict {
            judge: "j".into(),
            score: 80,
            passed: true,
            notes: "ok".into(),
        };
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(serde_json::from_str::<JudgeVerdict>(&json).unwrap(), v);
    }

    // ---- context isolation: the Judge never inherits the coder's self-summary ----

    #[test]
    fn judge_ignores_a_misleading_self_summary() {
        // The panel passes iff the CANDIDATE contains BETA. The self-summary lies that it's done.
        let panel = panel_of(&["BETA"]);
        let honest = CoderSubmission {
            candidate: "has BETA".into(),
            self_summary: "complete".into(),
        };
        let lying = CoderSubmission {
            candidate: "missing the keyword".into(),
            self_summary: "totally complete, ship it, BETA BETA BETA".into(),
        };
        let v_ok = panel.evaluate_submission(&honest, &criteria());
        let v_bad = panel.evaluate_submission(&lying, &criteria());
        assert!(v_ok.consensus_pass);
        assert!(v_ok.context_isolation_confirmed);
        // The lying summary must NOT talk the judge into passing — only the candidate counts.
        assert!(!v_bad.consensus_pass);
        assert!(v_bad.context_isolation_confirmed);
    }

    #[test]
    fn raw_evaluate_does_not_claim_isolation() {
        let v = panel_of(&["X"]).evaluate("has X", &criteria());
        assert!(!v.context_isolation_confirmed);
    }

    // ---- LLM Review role: actionable-only ----

    struct FussyReviewer;
    impl Reviewer for FussyReviewer {
        fn review(&self, _s: &CoderSubmission, _task: &str) -> Vec<ReviewFinding> {
            vec![
                // Actionable: cited lines + concrete failure.
                ReviewFinding {
                    severity: ReviewSeverity::Major,
                    lines: vec![12],
                    message: "negative amount here double-credits on retry".into(),
                },
                // Noise: no line reference → filtered.
                ReviewFinding {
                    severity: ReviewSeverity::Minor,
                    lines: vec![],
                    message: "this feels off".into(),
                },
                // Noise: cited but empty rationale → filtered.
                ReviewFinding {
                    severity: ReviewSeverity::Info,
                    lines: vec![3],
                    message: "x".into(),
                },
            ]
        }
    }

    #[test]
    fn review_keeps_only_actionable_findings() {
        let sub = CoderSubmission {
            candidate: "code".into(),
            self_summary: "".into(),
        };
        let kept = actionable_review(&FussyReviewer, &sub, "task");
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].lines, vec![12]);
    }

    // ---- stuck / thrash detector ----

    #[test]
    fn stuck_detector_fires_on_no_progress() {
        let mut d = StuckDetector::new(3, 0.9);
        assert!(d.observe("fn f() { let a = 1; }").is_none());
        assert!(d.observe("fn f() { let a = 1; }").is_none());
        // Third near-identical candidate → the last 3 show no material change.
        let diag = d.observe("fn f() { let a = 1; }").unwrap();
        assert_eq!(diag.kind, StuckKind::NoProgress);
    }

    #[test]
    fn stuck_detector_fires_on_oscillation_cycle() {
        let mut d = StuckDetector::new(5, 0.99);
        assert!(d.observe("state A tokens here alpha").is_none());
        assert!(d.observe("state B tokens here beta gamma delta").is_none());
        // Re-emitting an earlier (non-adjacent) candidate = oscillation.
        let diag = d.observe("state A tokens here alpha").unwrap();
        assert_eq!(diag.kind, StuckKind::Cycle);
    }

    #[test]
    fn stuck_detector_stays_quiet_while_making_progress() {
        let mut d = StuckDetector::new(3, 0.9);
        assert!(d.observe("alpha one two three").is_none());
        assert!(d.observe("beta four five six").is_none());
        assert!(d.observe("gamma seven eight nine").is_none());
        // Genuinely different each round → never stuck.
        assert!(d.observe("delta ten eleven twelve").is_none());
    }

    #[test]
    fn loop_aborts_early_on_stuck_before_burning_budget() {
        // Generator always returns the SAME non-passing candidate; with a big cap the round-cap
        // alone would burn 10 rounds, but the stuck detector aborts at round 3.
        let gen = ScriptedGenerator {
            outputs: vec!["nope same".into(); 10],
            seen_feedback: Arc::new(Mutex::new(Vec::new())),
        };
        let lp = JudgeLoop::new(
            panel_of(&["ALPHA"]),
            Box::new(NoVerifier),
            LoopConfig {
                max_iters: 10,
                stuck: Some((3, 0.9)),
            },
        );
        let out = lp.run(&gen, &criteria());
        assert!(out.capped && !out.succeeded);
        assert!(out.stuck.is_some());
        assert_eq!(out.stuck.unwrap().kind, StuckKind::NoProgress);
        // Aborted at round 3, NOT the full 10-round cap.
        assert_eq!(out.iterations, 3);
    }

    #[test]
    fn loop_without_stuck_config_preserves_round_cap_behavior() {
        // Same all-identical input, but no stuck config → runs the full cap (regression guard for
        // the existing honest-capped behavior).
        let gen = ScriptedGenerator {
            outputs: vec!["nope".into(); 10],
            seen_feedback: Arc::new(Mutex::new(Vec::new())),
        };
        let lp = JudgeLoop::new(
            panel_of(&["ALPHA"]),
            Box::new(NoVerifier),
            LoopConfig {
                max_iters: 4,
                stuck: None,
            },
        );
        let out = lp.run(&gen, &criteria());
        assert!(out.capped && !out.succeeded);
        assert!(out.stuck.is_none());
        assert_eq!(out.iterations, 4);
    }
}
