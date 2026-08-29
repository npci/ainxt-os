// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! **Cost-budgeted, multi-round** optimization (`PROMPT_ENGINEERING.md` §5.6, gap BJ residual-risk).
//! A single [`crate::optimize`] pass is one bounded scoring round; a real optimizer iterates
//! (propose → evaluate → select → re-propose from the winner) and each round costs
//! `candidates × eval-set-size × per-call cost`. Left unbounded this either gets skipped under cost
//! pressure or becomes a line-item nobody owns. This module makes the run an **explicitly budgeted
//! offline job**: hard caps on rounds, candidates/round, total model calls, and total cost, with the
//! spend accounted exactly — the loop stops the moment the next unit of work would breach the budget.
//!
//! Deterministic (propose + optimize are deterministic; no clock/rng): same seed + catalog + budget →
//! same rounds, same spend, same winner.

use crate::propose::{propose, Exemplar, ProposeCatalog, ProposeConfig};
use crate::{optimize, ModelSeam, PromptVariant, VariantOutcome};
use ainxt_eval::{EvalCase, QualityJudge};
use serde::{Deserialize, Serialize};

/// Per-call cost model (abstract cost units — a real deployment plugs in ₹/token × tokens/call).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CostModel {
    pub cost_per_call: u64,
}

impl Default for CostModel {
    fn default() -> Self {
        CostModel { cost_per_call: 1 }
    }
}

/// The hard budget for an optimization run. Every cap is enforced; the run never exceeds any of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptBudget {
    /// Maximum optimization rounds.
    pub max_rounds: usize,
    /// Maximum candidates evaluated per round (post-propose truncation).
    pub max_candidates_per_round: usize,
    /// Hard cap on total model calls across the whole run (`Σ candidates × eval-set-size`).
    pub max_total_calls: u64,
    /// Hard cap on total cost units across the whole run.
    pub max_cost: u64,
}

impl Default for OptBudget {
    fn default() -> Self {
        OptBudget {
            max_rounds: 5,
            max_candidates_per_round: 12,
            max_total_calls: 10_000,
            max_cost: 10_000,
        }
    }
}

/// Why the budgeted loop stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StopReason {
    /// All configured rounds were used.
    RoundsExhausted,
    /// The next round could not afford even one candidate within the remaining call/cost budget.
    BudgetExhausted,
    /// A round produced no candidate better than the incumbent (beyond the improvement margin).
    Converged,
    /// The gold set was empty — nothing to optimize against.
    EmptyGold,
}

/// The result of a budgeted run: the best variant found + exact spend accounting.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BudgetedOutcome {
    pub model_id: String,
    /// The best variant's scored outcome, if any round certified one.
    pub best: Option<VariantOutcome>,
    /// The best variant's template (so the caller can bridge it to a Registry DRAFT).
    pub best_template: Option<String>,
    pub rounds_run: usize,
    /// Total model calls actually made.
    pub calls_used: u64,
    /// Total cost units actually spent (`calls_used × cost_per_call`).
    pub cost_used: u64,
    pub stop_reason: StopReason,
}

/// Run a cost-budgeted, multi-round optimization for one model. `improve_margin` is the pass-rate
/// improvement a round's winner must beat to justify continuing (non-inferiority for churn control).
#[allow(clippy::too_many_arguments)]
pub fn optimize_budgeted(
    seed: &PromptVariant,
    catalog: &ProposeCatalog,
    exemplars: &[Exemplar],
    propose_cfg: ProposeConfig,
    gold: &[EvalCase],
    judge: &dyn QualityJudge,
    model: &dyn ModelSeam,
    cost: CostModel,
    budget: OptBudget,
    improve_margin: f64,
) -> BudgetedOutcome {
    let model_id = model.id().to_string();
    let gold_n = gold.len() as u64;

    if gold_n == 0 {
        return BudgetedOutcome {
            model_id,
            best: None,
            best_template: None,
            rounds_run: 0,
            calls_used: 0,
            cost_used: 0,
            stop_reason: StopReason::EmptyGold,
        };
    }

    let mut calls_used: u64 = 0;
    let mut cost_used: u64 = 0;
    let mut rounds_run = 0usize;
    let mut best: Option<VariantOutcome> = None;
    let mut best_template: Option<String> = None;
    let mut current_seed = seed.clone();

    let stop_reason = loop {
        if rounds_run >= budget.max_rounds {
            break StopReason::RoundsExhausted;
        }

        // Propose from the current best seed, then cap to the per-round candidate budget.
        let mut cands = propose(&current_seed, catalog, exemplars, propose_cfg);
        if cands.len() > budget.max_candidates_per_round {
            cands.truncate(budget.max_candidates_per_round.max(1));
        }

        // How many candidates can we AFFORD within the remaining call + cost budgets?
        let remaining_calls = budget.max_total_calls.saturating_sub(calls_used);
        let affordable_by_calls = remaining_calls / gold_n;
        let affordable_by_cost = if cost.cost_per_call == 0 {
            u64::MAX
        } else {
            let per_candidate_cost = gold_n.saturating_mul(cost.cost_per_call);
            budget.max_cost.saturating_sub(cost_used) / per_candidate_cost.max(1)
        };
        let affordable = affordable_by_calls.min(affordable_by_cost) as usize;
        if affordable == 0 {
            break StopReason::BudgetExhausted;
        }
        if cands.len() > affordable {
            cands.truncate(affordable);
        }

        // Evaluate this round (accounting is exact: optimize evaluates each candidate on every case).
        let opt = optimize(&cands, gold, judge, model);
        let evaluated = cands.len() as u64;
        calls_used += evaluated * gold_n;
        cost_used += evaluated * gold_n * cost.cost_per_call;
        rounds_run += 1;

        let Some(round_winner) = opt.winner_outcome().cloned() else {
            break StopReason::Converged;
        };
        let winner_template = cands
            .iter()
            .find(|c| c.id == round_winner.variant_id)
            .map(|c| c.template.clone());

        match &best {
            None => {
                current_seed = PromptVariant::new(
                    &round_winner.variant_id,
                    winner_template.as_deref().unwrap_or(&current_seed.template),
                );
                best_template = winner_template;
                best = Some(round_winner);
            }
            Some(prev) => {
                if round_winner.report.pass_rate > prev.report.pass_rate + improve_margin {
                    current_seed = PromptVariant::new(
                        &round_winner.variant_id,
                        winner_template.as_deref().unwrap_or(&current_seed.template),
                    );
                    best_template = winner_template;
                    best = Some(round_winner);
                } else {
                    // No material improvement — keep the incumbent and stop (don't burn budget).
                    break StopReason::Converged;
                }
            }
        }
    };

    BudgetedOutcome {
        model_id,
        best,
        best_template,
        rounds_run,
        calls_used,
        cost_used,
        stop_reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ainxt_eval::{EvalCase, EvalCriteria, QualityJudge, QualityScore};
    use ainxt_types::Tier;

    struct SbsModel;
    impl ModelSeam for SbsModel {
        fn id(&self) -> &str {
            "sbs"
        }
        fn tier(&self) -> Tier {
            Tier::Medium
        }
        fn complete(&self, prompt: &str) -> String {
            let mut out = prompt.to_string();
            if prompt.contains("step by step") && prompt.contains("instant transfer") {
                out.push_str(" UPI");
            }
            out
        }
    }
    struct TermJudge;
    impl QualityJudge for TermJudge {
        fn score(&self, _i: &str, output: &str, c: &EvalCriteria) -> QualityScore {
            let needle = c.rubric.split_whitespace().last().unwrap_or("");
            let s = if !needle.is_empty() && output.contains(needle) {
                90
            } else {
                10
            };
            QualityScore {
                score: s,
                rationale: String::new(),
            }
        }
    }
    fn seed() -> PromptVariant {
        PromptVariant::new("seed", "{input}")
    }
    fn gold() -> Vec<EvalCase> {
        vec![EvalCase::new(
            "g",
            "instant transfer",
            "must mention UPI",
            60,
        )]
    }

    // --- PRMT-09: the budget is a HARD cap on spend -----------------------------------------

    #[test]
    fn gap_ainxt_promptopt_prmt_09_run_never_exceeds_the_call_and_cost_budget() {
        let budget = OptBudget {
            max_rounds: 10,
            max_candidates_per_round: 100,
            max_total_calls: 7, // gold_n = 1 → at most 7 candidate-evals total
            max_cost: 1_000,
        };
        let out = optimize_budgeted(
            &seed(),
            &ProposeCatalog::default(),
            &[],
            ProposeConfig::default(),
            &gold(),
            &TermJudge,
            &SbsModel,
            CostModel { cost_per_call: 2 },
            budget,
            0.001,
        );
        assert!(
            out.calls_used <= 7,
            "must never exceed max_total_calls, got {}",
            out.calls_used
        );
        // Cost accounting is exact.
        assert_eq!(out.cost_used, out.calls_used * 2);
        assert!(out.cost_used <= budget.max_cost);
    }

    #[test]
    fn gap_ainxt_promptopt_prmt_09_zero_call_budget_stops_before_any_work() {
        let budget = OptBudget {
            max_rounds: 5,
            max_candidates_per_round: 10,
            max_total_calls: 0, // cannot afford a single candidate
            max_cost: 1_000,
        };
        let out = optimize_budgeted(
            &seed(),
            &ProposeCatalog::default(),
            &[],
            ProposeConfig::default(),
            &gold(),
            &TermJudge,
            &SbsModel,
            CostModel::default(),
            budget,
            0.001,
        );
        assert_eq!(out.stop_reason, StopReason::BudgetExhausted);
        assert_eq!(out.rounds_run, 0);
        assert_eq!(out.calls_used, 0);
        assert!(out.best.is_none());
    }

    #[test]
    fn gap_ainxt_promptopt_prmt_09_multi_round_finds_the_winner_then_converges() {
        // Generous budget: the loop finds the "step by step" winner in round 1, then round 2 proposes
        // from it, finds nothing strictly better, and CONVERGES (bounded, not infinite).
        let out = optimize_budgeted(
            &seed(),
            &ProposeCatalog::default(),
            &[],
            ProposeConfig::default(),
            &gold(),
            &TermJudge,
            &SbsModel,
            CostModel::default(),
            OptBudget::default(),
            0.001,
        );
        assert_eq!(out.stop_reason, StopReason::Converged);
        assert!(out.rounds_run >= 1 && out.rounds_run <= OptBudget::default().max_rounds);
        let best = out.best.as_ref().expect("a winner should be found");
        assert!(
            (best.report.pass_rate - 1.0).abs() < 1e-9,
            "the winner unlocks the model"
        );
        assert!(out.best_template.as_ref().unwrap().contains("step by step"));
    }

    #[test]
    fn gap_ainxt_promptopt_prmt_09_max_rounds_is_respected() {
        let budget = OptBudget {
            max_rounds: 1,
            max_candidates_per_round: 100,
            max_total_calls: 10_000,
            max_cost: 10_000,
        };
        let out = optimize_budgeted(
            &seed(),
            &ProposeCatalog::default(),
            &[],
            ProposeConfig::default(),
            &gold(),
            &TermJudge,
            &SbsModel,
            CostModel::default(),
            budget,
            0.001,
        );
        // One round runs, then the round cap ends the loop.
        assert_eq!(out.rounds_run, 1);
        assert_eq!(out.stop_reason, StopReason::RoundsExhausted);
        assert!(out.best.is_some());
    }

    #[test]
    fn gap_ainxt_promptopt_prmt_09_empty_gold_is_a_noop() {
        let out = optimize_budgeted(
            &seed(),
            &ProposeCatalog::default(),
            &[],
            ProposeConfig::default(),
            &[],
            &TermJudge,
            &SbsModel,
            CostModel::default(),
            OptBudget::default(),
            0.001,
        );
        assert_eq!(out.stop_reason, StopReason::EmptyGold);
        assert_eq!(out.calls_used, 0);
        assert!(out.best.is_none());
    }

    #[test]
    fn budgeted_outcome_serializes_round_trip() {
        let out = optimize_budgeted(
            &seed(),
            &ProposeCatalog::default(),
            &[],
            ProposeConfig::default(),
            &gold(),
            &TermJudge,
            &SbsModel,
            CostModel::default(),
            OptBudget::default(),
            0.001,
        );
        let json = serde_json::to_string(&out).unwrap();
        let back: BudgetedOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(back, out);
    }
}
