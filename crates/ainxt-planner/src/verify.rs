// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Verification-at-scale — the three-way "never done until proven" gate (pure logic).
//!
//! Design: `docs/architecture/LONG_HORIZON_PROGRAMS.md` (ADR-027) §6 and
//! `docs/architecture/LOOP_AND_AGENT_TEAMS.md` §7 (the "three non-substitutable proofs").
//!
//! A module — and a whole program — is *never* marked done on a self-report. Completion is proven
//! compositionally by three **independent, non-substitutable** verdicts combined here as pure logic:
//!
//! 1. a **deterministic gate** — compile + tests + SAST hard-block (a critical/high finding blocks
//!    *regardless of any confidence score*, §6 / CODE_REVIEW §3 Tier-3);
//! 2. an **adversarial gate** — the Breaker's counterexamples (any surviving counterexample blocks);
//! 3. a **semantic Judge** — with the **cross-model** requirement of §10 enforced structurally
//!    (a same-model producer/judge pairing is rejected: thousands of modules judged by their own
//!    producer would share systematic blind spots).
//!
//! Applied at three scopes (§6): **per-module** → **per-edge integration** → **program regression
//! sweep with attribution** → an independent **program-level Judge**. A program reaches
//! [`GateOutcome::Complete`] only when *all* hold; any red is [`GateOutcome::Blocked`] (which the
//! Program layer maps to `CAPPED_PARTIAL`), and a gate that could not *finish* yields the honest
//! [`GateOutcome::Capped`] — never a silent `Complete`.
//!
//! Everything here is deterministic and score-integer (0..=100, no float), so each rule is a
//! property a unit test asserts on concrete verdicts.

use crate::mtg::ModuleRef;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// The outcome of a verification gate at any scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GateOutcome {
    /// All three proofs are green and every gate ran to completion — proven done.
    Complete,
    /// No blocking failure, but at least one gate could not finish (e.g. budget/time). Honest
    /// partial: the runtime must not treat this as `Complete`.
    Capped { reason: String },
    /// At least one proof failed. Carries every reason, sorted, so the report is complete.
    Blocked { reasons: Vec<String> },
}

impl GateOutcome {
    /// True only for [`GateOutcome::Complete`].
    pub fn is_complete(&self) -> bool {
        matches!(self, GateOutcome::Complete)
    }
}

impl fmt::Display for GateOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GateOutcome::Complete => f.write_str("complete"),
            GateOutcome::Capped { reason } => write!(f, "capped: {reason}"),
            GateOutcome::Blocked { reasons } => write!(f, "blocked: {}", reasons.join("; ")),
        }
    }
}

/// The deterministic gate: compile + tests + static analysis (§6). A `false` `completed` means the
/// gate itself did not finish (e.g. the toolchain timed out) — distinct from a clean failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterministicVerdict {
    pub compiled: bool,
    pub tests_passed: bool,
    /// Critical/high SAST findings. **Any** entry is a hard block regardless of the Judge score
    /// (e.g. an accidental PAN-pattern log in generated code) — CODE_REVIEW §3 Tier-3.
    pub blocking_findings: Vec<String>,
    /// Whether the deterministic gate ran to completion.
    pub completed: bool,
}

impl DeterministicVerdict {
    /// A fully-green deterministic verdict.
    pub fn green() -> Self {
        DeterministicVerdict {
            compiled: true,
            tests_passed: true,
            blocking_findings: Vec::new(),
            completed: true,
        }
    }
}

/// The adversarial gate (the Breaker, §6 / AGENT_TESTER): an exploratory attempt loop whose
/// surviving `counterexamples` are hard blocks. `completed=false` means the Breaker was cut short.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdversarialVerdict {
    pub attempts: u32,
    /// Counterexamples that survived adversarial re-verification (false positives already removed).
    pub counterexamples: Vec<String>,
    pub completed: bool,
}

impl AdversarialVerdict {
    /// A green adversarial verdict: `attempts` attacks tried, none found a counterexample.
    pub fn green(attempts: u32) -> Self {
        AdversarialVerdict {
            attempts,
            counterexamples: Vec::new(),
            completed: true,
        }
    }
}

/// The semantic Judge verdict (§6/§10). Scores are integers in `0..=100` to keep the gate
/// deterministic. The `producer_model`/`judge_model` pair enforces the §10 cross-model rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JudgeVerdict {
    /// Judge score, 0..=100.
    pub score: u32,
    /// Minimum acceptable score.
    pub threshold: u32,
    /// The model that PRODUCED the work.
    pub producer_model: String,
    /// The model that JUDGED it — must differ from the producer (§10).
    pub judge_model: String,
    /// Whether the Judge ran to completion.
    pub completed: bool,
}

impl JudgeVerdict {
    /// A passing, cross-model judge verdict.
    pub fn pass(score: u32, threshold: u32, producer: &str, judge: &str) -> Self {
        JudgeVerdict {
            score,
            threshold,
            producer_model: producer.to_string(),
            judge_model: judge.to_string(),
            completed: true,
        }
    }
}

/// Combine the three independent proofs into a single outcome (§6). The precedence is deliberate:
///
/// * **any** blocking condition ⇒ [`GateOutcome::Blocked`] (reasons collected, sorted, de-duplicated);
/// * else if any gate did not finish ⇒ [`GateOutcome::Capped`] (honest partial, never `Complete`);
/// * else ⇒ [`GateOutcome::Complete`].
///
/// Blocking conditions: compile failure; test failure; **any** SAST blocking finding (regardless of
/// Judge score); **any** surviving adversarial counterexample; a same-model producer/judge pairing
/// (§10); a Judge score below threshold.
pub fn three_way_gate(
    det: &DeterministicVerdict,
    adv: &AdversarialVerdict,
    judge: &JudgeVerdict,
) -> GateOutcome {
    let mut reasons: BTreeSet<String> = BTreeSet::new();

    if !det.compiled {
        reasons.insert("deterministic: compile failed".to_string());
    }
    if !det.tests_passed {
        reasons.insert("deterministic: tests failed".to_string());
    }
    for finding in &det.blocking_findings {
        reasons.insert(format!("sast-hard-block: {finding}"));
    }
    for ce in &adv.counterexamples {
        reasons.insert(format!("adversarial-counterexample: {ce}"));
    }
    // §10 cross-model: producer and judge must differ. Enforced regardless of score, because a
    // same-model judge is a structural blind spot, not a low score.
    if judge.producer_model == judge.judge_model {
        reasons.insert(format!(
            "cross-model-violation: producer and judge are both '{}'",
            judge.producer_model
        ));
    }
    // The SAST hard-block already fired above; the Judge score is a *separate* axis and cannot
    // rescue a hard block, nor can a high score bypass one.
    if judge.score < judge.threshold {
        reasons.insert(format!(
            "judge-below-threshold: {} < {}",
            judge.score, judge.threshold
        ));
    }

    if !reasons.is_empty() {
        return GateOutcome::Blocked {
            reasons: reasons.into_iter().collect(),
        };
    }

    if !det.completed {
        return GateOutcome::Capped {
            reason: "deterministic gate did not complete".to_string(),
        };
    }
    if !adv.completed {
        return GateOutcome::Capped {
            reason: "adversarial gate did not complete".to_string(),
        };
    }
    if !judge.completed {
        return GateOutcome::Capped {
            reason: "judge did not complete".to_string(),
        };
    }

    GateOutcome::Complete
}

/// A per-edge integration verdict (§6.2): the gate outcome for the seam between a just-committed
/// node and an already-committed neighbor, scoped to that edge's blast radius.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeVerification {
    /// `(committed_node, already_committed_neighbor)`.
    pub edge: (ModuleRef, ModuleRef),
    pub outcome: GateOutcome,
}

impl EdgeVerification {
    pub fn new(from: impl Into<ModuleRef>, to: impl Into<ModuleRef>, outcome: GateOutcome) -> Self {
        EdgeVerification {
            edge: (from.into(), to.into()),
            outcome,
        }
    }
}

/// A record of one committed node, for regression attribution (§6.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitRecord {
    pub node: ModuleRef,
    /// Monotonic commit sequence number (from the Event Log / git history graph).
    pub seq: u64,
    /// The area this commit touched — the node's own ref plus its blast radius.
    pub touches: BTreeSet<ModuleRef>,
}

impl CommitRecord {
    pub fn new(node: impl Into<ModuleRef>, seq: u64, touches: BTreeSet<ModuleRef>) -> Self {
        CommitRecord {
            node: node.into(),
            seq,
            touches,
        }
    }
}

/// Attribute a program-scale regression to the node that **introduced** it (§6.3).
///
/// The acceptance case: node 5 was committed early and was green; later node 400 reintroduces a
/// regression in node 5's area. Attribution must name **400** (the latest committer whose change
/// touched the failing area), not 5. So among all commits whose `touches` cover `failing_area`, the
/// one with the **highest `seq`** wins (ties broken by the largest ref for determinism). Returns
/// `None` if no committed node's change touched the failing area.
pub fn attribute_regression(
    failing_area: &ModuleRef,
    commits: &[CommitRecord],
) -> Option<ModuleRef> {
    commits
        .iter()
        .filter(|c| c.node == *failing_area || c.touches.contains(failing_area))
        .max_by(|a, b| a.seq.cmp(&b.seq).then_with(|| a.node.cmp(&b.node)))
        .map(|c| c.node.clone())
}

/// Everything the `COMPLETED` gate needs (§6). A program is `Complete` only when all four hold.
#[derive(Debug, Clone)]
pub struct ProgramCompletionInput<'a> {
    /// Every MTG leaf node that must be committed with a `Complete` per-module outcome.
    pub all_leaves: &'a BTreeSet<ModuleRef>,
    /// Per-module (node-level) outcomes, keyed by node ref.
    pub leaf_outcomes: &'a BTreeMap<ModuleRef, GateOutcome>,
    /// Per-edge integration outcomes.
    pub edge_outcomes: &'a [EdgeVerification],
    /// Whether the final program regression sweep is green.
    pub final_sweep_green: bool,
    /// The independent program-level Judge (§6(d)) — cross-model where the data-class allows.
    pub program_judge: &'a JudgeVerdict,
}

/// The program-level `COMPLETED` gate (§6). Returns [`GateOutcome::Complete`] iff:
/// (a) every leaf is present with a `Complete` per-module outcome; (b) every edge integration is
/// `Complete`; (c) the final regression sweep is green; (d) the independent program Judge passes
/// (cross-model + at/above threshold). Otherwise [`GateOutcome::Blocked`] naming every failing
/// clause — which the Program layer records as `CAPPED_PARTIAL`. "Done" is never claimed, only proven.
pub fn program_completed(input: &ProgramCompletionInput<'_>) -> GateOutcome {
    let mut reasons: BTreeSet<String> = BTreeSet::new();

    // (a) every leaf committed + per-module Complete.
    for leaf in input.all_leaves {
        match input.leaf_outcomes.get(leaf) {
            None => {
                reasons.insert(format!("leaf-not-verified: {leaf}"));
            }
            Some(GateOutcome::Complete) => {}
            Some(other) => {
                reasons.insert(format!("leaf-not-complete: {leaf} ({other})"));
            }
        }
    }

    // (b) every edge integration Complete.
    for edge in input.edge_outcomes {
        if !edge.outcome.is_complete() {
            reasons.insert(format!(
                "edge-not-complete: {}->{} ({})",
                edge.edge.0, edge.edge.1, edge.outcome
            ));
        }
    }

    // (c) final regression sweep green.
    if !input.final_sweep_green {
        reasons.insert("program-regression-sweep: red".to_string());
    }

    // (d) independent program Judge — cross-model + threshold.
    let j = input.program_judge;
    if j.producer_model == j.judge_model {
        reasons.insert(format!(
            "program-judge-cross-model-violation: both '{}'",
            j.producer_model
        ));
    }
    if j.score < j.threshold {
        reasons.insert(format!(
            "program-judge-below-threshold: {} < {}",
            j.score, j.threshold
        ));
    }
    if !j.completed {
        reasons.insert("program-judge: did not complete".to_string());
    }

    if reasons.is_empty() {
        GateOutcome::Complete
    } else {
        GateOutcome::Blocked {
            reasons: reasons.into_iter().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mref(s: &str) -> ModuleRef {
        ModuleRef::new(s)
    }

    // ---- three-way gate ---------------------------------------------------

    #[test]
    fn all_green_is_complete() {
        let out = three_way_gate(
            &DeterministicVerdict::green(),
            &AdversarialVerdict::green(50),
            &JudgeVerdict::pass(90, 80, "qwen", "glm"),
        );
        assert_eq!(out, GateOutcome::Complete);
    }

    #[test]
    fn sast_hard_block_wins_even_with_a_perfect_judge_score() {
        // A perfect (100/100) Judge score cannot rescue a critical SAST finding.
        let det = DeterministicVerdict {
            compiled: true,
            tests_passed: true,
            blocking_findings: vec!["PAN pattern logged".to_string()],
            completed: true,
        };
        let out = three_way_gate(
            &det,
            &AdversarialVerdict::green(10),
            &JudgeVerdict::pass(100, 80, "qwen", "glm"),
        );
        match out {
            GateOutcome::Blocked { reasons } => {
                assert!(reasons.iter().any(|r| r.contains("sast-hard-block")));
            }
            other => panic!("expected Blocked, got {other:?}"),
        }
    }

    #[test]
    fn surviving_adversarial_counterexample_blocks() {
        let adv = AdversarialVerdict {
            attempts: 100,
            counterexamples: vec!["negative amount underflows".to_string()],
            completed: true,
        };
        let out = three_way_gate(
            &DeterministicVerdict::green(),
            &adv,
            &JudgeVerdict::pass(95, 80, "qwen", "glm"),
        );
        assert!(
            matches!(out, GateOutcome::Blocked { reasons } if reasons.iter().any(|r| r.contains("adversarial-counterexample")))
        );
    }

    #[test]
    fn same_model_producer_and_judge_is_rejected() {
        // §10: thousands of modules judged by their own producer share blind spots -> rejected.
        let out = three_way_gate(
            &DeterministicVerdict::green(),
            &AdversarialVerdict::green(10),
            &JudgeVerdict::pass(99, 80, "qwen", "qwen"),
        );
        assert!(
            matches!(out, GateOutcome::Blocked { reasons } if reasons.iter().any(|r| r.contains("cross-model-violation")))
        );
    }

    #[test]
    fn judge_below_threshold_blocks() {
        let out = three_way_gate(
            &DeterministicVerdict::green(),
            &AdversarialVerdict::green(10),
            &JudgeVerdict::pass(70, 80, "qwen", "glm"),
        );
        assert!(
            matches!(out, GateOutcome::Blocked { reasons } if reasons.iter().any(|r| r.contains("judge-below-threshold")))
        );
    }

    #[test]
    fn incomplete_gate_is_capped_not_complete_when_nothing_blocks() {
        // No blocking failure, but the adversarial Breaker was cut short -> honest Capped.
        let adv = AdversarialVerdict {
            attempts: 3,
            counterexamples: Vec::new(),
            completed: false,
        };
        let out = three_way_gate(
            &DeterministicVerdict::green(),
            &adv,
            &JudgeVerdict::pass(90, 80, "qwen", "glm"),
        );
        assert_eq!(
            out,
            GateOutcome::Capped {
                reason: "adversarial gate did not complete".to_string()
            }
        );
    }

    #[test]
    fn a_block_takes_precedence_over_an_incomplete_gate() {
        // Even if a gate didn't finish, a real failure must surface as Blocked, not Capped.
        let det = DeterministicVerdict {
            compiled: false,
            tests_passed: true,
            blocking_findings: Vec::new(),
            completed: false,
        };
        let out = three_way_gate(
            &det,
            &AdversarialVerdict::green(10),
            &JudgeVerdict::pass(90, 80, "qwen", "glm"),
        );
        assert!(matches!(out, GateOutcome::Blocked { .. }));
    }

    #[test]
    fn multiple_failures_are_all_reported_sorted_and_deduped() {
        let det = DeterministicVerdict {
            compiled: false,
            tests_passed: false,
            blocking_findings: vec!["x".to_string(), "x".to_string()], // duplicate
            completed: true,
        };
        let out = three_way_gate(
            &det,
            &AdversarialVerdict::green(10),
            &JudgeVerdict::pass(90, 80, "qwen", "glm"),
        );
        match out {
            GateOutcome::Blocked { reasons } => {
                // compile + tests + one (deduped) sast finding = 3 reasons.
                assert_eq!(reasons.len(), 3);
                // Sorted (BTreeSet order).
                let mut sorted = reasons.clone();
                sorted.sort();
                assert_eq!(reasons, sorted);
            }
            other => panic!("expected Blocked, got {other:?}"),
        }
    }

    // ---- regression attribution ------------------------------------------

    #[test]
    fn regression_is_attributed_to_the_latest_introducer_not_the_original_author() {
        // Node 5 committed the area early and green; node 400 later reintroduces a regression there.
        let area = mref("payments::fees");
        let commits = vec![
            CommitRecord::new("node5", 5, [area.clone()].into_iter().collect()),
            CommitRecord::new(
                "node400",
                400,
                [area.clone(), mref("payments::rounding")]
                    .into_iter()
                    .collect(),
            ),
        ];
        assert_eq!(attribute_regression(&area, &commits), Some(mref("node400")));
    }

    #[test]
    fn regression_attribution_matches_the_node_by_its_own_ref_too() {
        let area = mref("ledger");
        let commits = vec![CommitRecord::new("ledger", 12, BTreeSet::new())];
        assert_eq!(attribute_regression(&area, &commits), Some(mref("ledger")));
    }

    #[test]
    fn regression_with_no_touching_commit_is_unattributed() {
        let commits = vec![CommitRecord::new(
            "unrelated",
            9,
            [mref("elsewhere")].into_iter().collect(),
        )];
        assert_eq!(attribute_regression(&mref("orphan"), &commits), None);
    }

    #[test]
    fn attribution_tie_break_is_deterministic() {
        // Two commits at the same seq touching the same area: the larger ref wins, deterministically.
        let area = mref("a");
        let commits = vec![
            CommitRecord::new("nodeA", 7, [area.clone()].into_iter().collect()),
            CommitRecord::new("nodeB", 7, [area.clone()].into_iter().collect()),
        ];
        assert_eq!(attribute_regression(&area, &commits), Some(mref("nodeB")));
    }

    // ---- program COMPLETED gate ------------------------------------------

    fn leaves(names: &[&str]) -> BTreeSet<ModuleRef> {
        names.iter().map(|s| mref(s)).collect()
    }

    #[test]
    fn program_is_complete_only_when_every_clause_is_green() {
        let all = leaves(&["a", "b"]);
        let mut outcomes = BTreeMap::new();
        outcomes.insert(mref("a"), GateOutcome::Complete);
        outcomes.insert(mref("b"), GateOutcome::Complete);
        let edges = vec![EdgeVerification::new("a", "b", GateOutcome::Complete)];
        let judge = JudgeVerdict::pass(90, 80, "qwen", "glm");
        let input = ProgramCompletionInput {
            all_leaves: &all,
            leaf_outcomes: &outcomes,
            edge_outcomes: &edges,
            final_sweep_green: true,
            program_judge: &judge,
        };
        assert_eq!(program_completed(&input), GateOutcome::Complete);
    }

    #[test]
    fn one_blocked_leaf_prevents_program_completion() {
        let all = leaves(&["a", "b"]);
        let mut outcomes = BTreeMap::new();
        outcomes.insert(mref("a"), GateOutcome::Complete);
        outcomes.insert(
            mref("b"),
            GateOutcome::Blocked {
                reasons: vec!["tests failed".to_string()],
            },
        );
        let judge = JudgeVerdict::pass(90, 80, "qwen", "glm");
        let input = ProgramCompletionInput {
            all_leaves: &all,
            leaf_outcomes: &outcomes,
            edge_outcomes: &[],
            final_sweep_green: true,
            program_judge: &judge,
        };
        assert!(
            matches!(program_completed(&input), GateOutcome::Blocked { reasons } if reasons.iter().any(|r| r.contains("leaf-not-complete: b")))
        );
    }

    #[test]
    fn a_missing_leaf_verdict_prevents_completion() {
        let all = leaves(&["a", "b"]);
        let mut outcomes = BTreeMap::new();
        outcomes.insert(mref("a"), GateOutcome::Complete);
        // b never verified.
        let judge = JudgeVerdict::pass(90, 80, "qwen", "glm");
        let input = ProgramCompletionInput {
            all_leaves: &all,
            leaf_outcomes: &outcomes,
            edge_outcomes: &[],
            final_sweep_green: true,
            program_judge: &judge,
        };
        assert!(
            matches!(program_completed(&input), GateOutcome::Blocked { reasons } if reasons.iter().any(|r| r.contains("leaf-not-verified: b")))
        );
    }

    #[test]
    fn a_red_edge_or_red_sweep_or_bad_program_judge_each_block_completion() {
        let all = leaves(&["a"]);
        let mut outcomes = BTreeMap::new();
        outcomes.insert(mref("a"), GateOutcome::Complete);
        let judge_ok = JudgeVerdict::pass(90, 80, "qwen", "glm");

        // Red edge.
        let edges = vec![EdgeVerification::new(
            "a",
            "b",
            GateOutcome::Blocked {
                reasons: vec!["contract broken".to_string()],
            },
        )];
        let input = ProgramCompletionInput {
            all_leaves: &all,
            leaf_outcomes: &outcomes,
            edge_outcomes: &edges,
            final_sweep_green: true,
            program_judge: &judge_ok,
        };
        assert!(
            matches!(program_completed(&input), GateOutcome::Blocked { reasons } if reasons.iter().any(|r| r.contains("edge-not-complete")))
        );

        // Red sweep.
        let input = ProgramCompletionInput {
            all_leaves: &all,
            leaf_outcomes: &outcomes,
            edge_outcomes: &[],
            final_sweep_green: false,
            program_judge: &judge_ok,
        };
        assert!(
            matches!(program_completed(&input), GateOutcome::Blocked { reasons } if reasons.iter().any(|r| r.contains("program-regression-sweep")))
        );

        // Same-model program judge.
        let judge_bad = JudgeVerdict::pass(90, 80, "qwen", "qwen");
        let input = ProgramCompletionInput {
            all_leaves: &all,
            leaf_outcomes: &outcomes,
            edge_outcomes: &[],
            final_sweep_green: true,
            program_judge: &judge_bad,
        };
        assert!(
            matches!(program_completed(&input), GateOutcome::Blocked { reasons } if reasons.iter().any(|r| r.contains("program-judge-cross-model-violation")))
        );
    }
}
