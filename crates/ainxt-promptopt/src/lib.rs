// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-promptopt — automated prompt optimization (Phase P5, `PROMPT_ENGINEERING.md` §5, gap **BJ**).
//!
//! Hand-tuning task instructions "by feel" does not scale to dozens of Roles × several model
//! families, and it silently degrades quality on the models a human never tunes against
//! (`PROMPT_ENGINEERING.md` §4/§5.4). This crate treats prompt text as a **search space** and the
//! quality-eval **gold set** as the **objective function** — the platform capability, not a one-off
//! script. It is built *on* the eval keystone [`ainxt_eval`]: a variant is turned into an
//! [`ainxt_eval::EvalSystem`] and scored with the very same [`ainxt_eval::run_eval`], so the
//! optimizer inherits the gate's independent-judge discipline instead of inventing a second scorer.
//!
//! What this crate adds on top of the eval core — the three disciplines the core assumes exist:
//!
//! 1. **Search + ranking.** [`PromptVariant`]s are each scored into an [`ainxt_eval::EvalReport`],
//!    ranked (pass-rate, then mean, then id — fully deterministic), and a [winner](ModelOptimization::winner)
//!    is chosen. See [`optimize`].
//! 2. **A/B with non-inferiority.** A challenger only displaces the champion if it is **better beyond
//!    a margin** ([`ab_promote`]); an equal-or-marginal challenger keeps the incumbent. This is the
//!    superiority mirror of the eval gate's non-inferiority idea — a change is a *claim* that must be
//!    demonstrated, not assumed.
//! 3. **Holdout / overfit guard** (gap **AQ**, `PROMPT_ENGINEERING.md` PE10 / `EVAL_PLATFORM.md`
//!    §9). [`optimize_with_holdout`] picks the winner on a *train* split, then confirms it on a
//!    **disjoint holdout**; a winner that aces train but regresses on the holdout is flagged
//!    [`overfit`](HoldoutOutcome::overfit) — reusing [`ainxt_eval::evaluate_gate`] as the
//!    regression detector so the two subsystems can never drift apart.
//!
//! Plus **per-model keying** ([`optimize_all`]): the optimizer runs once per model, and results carry
//! the model's id + [`Tier`] so the best string for one model is never mixed with another's.
//!
//! Clean-room; deterministic (the model is an injected [`ModelSeam`] — no clock/rng/I/O here);
//! exhaustively testable.

use ainxt_eval::{
    evaluate_gate_statistical_dropin, run_eval, EvalReport, EvalSystem, GatePolicy, QualityJudge,
};
use ainxt_types::Tier;
use serde::{Deserialize, Serialize};

pub mod bridge;
pub mod budget;
pub mod constrained_judge;
pub mod propose;

/// The placeholder a [`PromptVariant`] template substitutes the case input into.
pub const INPUT_PLACEHOLDER: &str = "{input}";

/// One candidate prompt in the search space. `template` is authored prose containing
/// [`INPUT_PLACEHOLDER`] (`{input}`); rendering substitutes the case input at that point.
///
/// A template with no placeholder is legal (a fixed prompt that ignores the input) — this is exactly
/// how an *overfit* variant that bakes answers into its text looks, which the holdout guard catches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromptVariant {
    pub id: String,
    pub template: String,
}

impl PromptVariant {
    pub fn new(id: &str, template: &str) -> Self {
        PromptVariant {
            id: id.into(),
            template: template.into(),
        }
    }

    /// Substitute `input` for every `{input}` placeholder, yielding the concrete prompt sent to the
    /// model. Deterministic; every occurrence is replaced.
    pub fn render(&self, input: &str) -> String {
        self.template.replace(INPUT_PLACEHOLDER, input)
    }

    /// Whether the template actually references the input. A `false` here on a variant that wins is a
    /// smell the holdout guard is designed to expose (a prompt that ignores its input generalizes by
    /// luck, if at all).
    pub fn uses_input(&self) -> bool {
        self.template.contains(INPUT_PLACEHOLDER)
    }
}

/// The model under optimization — an injected seam so the optimizer stays deterministic and testable.
/// A real implementation calls a provider gateway; tests use fixed models. `id` + [`tier`](ModelSeam::tier)
/// are the per-model key: the optimizer runs once per model and never mixes their results
/// (`PROMPT_ENGINEERING.md` §5.4).
pub trait ModelSeam: Send + Sync {
    /// Stable identity of this model (family/deployment). Used as the per-model result key.
    fn id(&self) -> &str;
    /// The complexity/routing tier this model serves (ADR-006). Recorded on results so a variant
    /// tuned for one tier is never assumed valid for another.
    fn tier(&self) -> Tier;
    /// Produce an output for a fully-rendered prompt.
    fn complete(&self, prompt: &str) -> String;
}

/// Adapts a `(variant, model)` pair into an [`EvalSystem`] so a variant can be scored on the gold set
/// through the exact same [`run_eval`] the eval gate uses: render the variant template with the case
/// input, then ask the model to complete it.
pub struct VariantSystem<'a> {
    pub variant: &'a PromptVariant,
    pub model: &'a dyn ModelSeam,
}

impl EvalSystem for VariantSystem<'_> {
    fn respond(&self, input: &str) -> String {
        self.model.complete(&self.variant.render(input))
    }
}

/// One variant's full scored result on a gold set (the per-variant [`EvalReport`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VariantOutcome {
    pub variant_id: String,
    pub report: EvalReport,
}

/// The optimization result for a single model: every variant ranked, plus the winning variant id.
///
/// Ranking is deterministic — descending pass-rate, then descending mean score, then **ascending id**
/// as the final tie-break — so the same inputs always yield the same order and the same winner. The
/// `winner` is `None` when there is nothing to certify (no variants, or an empty gold set — a winner
/// chosen with zero evidence is not a winner).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelOptimization {
    pub model_id: String,
    pub tier: Tier,
    pub ranked: Vec<VariantOutcome>,
    pub winner: Option<String>,
}

impl ModelOptimization {
    /// The winning variant's full outcome, if a winner was certified.
    pub fn winner_outcome(&self) -> Option<&VariantOutcome> {
        let id = self.winner.as_ref()?;
        self.ranked.iter().find(|o| &o.variant_id == id)
    }
}

/// Score and rank `variants` on `gold` for a single `model`, choosing a deterministic winner.
///
/// Each variant is adapted via [`VariantSystem`] and scored through [`run_eval`] with the shared
/// `judge`. Empty inputs are handled: no variants → empty ranking, `winner = None`; empty gold set →
/// variants are still listed (each with an `n == 0` report) but `winner = None`.
pub fn optimize(
    variants: &[PromptVariant],
    gold: &[ainxt_eval::EvalCase],
    judge: &dyn QualityJudge,
    model: &dyn ModelSeam,
) -> ModelOptimization {
    let mut ranked: Vec<VariantOutcome> = variants
        .iter()
        .map(|variant| {
            let system = VariantSystem { variant, model };
            VariantOutcome {
                variant_id: variant.id.clone(),
                report: run_eval(gold, &system, judge),
            }
        })
        .collect();

    // Deterministic ordering: higher pass-rate first, then higher mean, then lexicographic id.
    // `total_cmp` avoids any NaN ambiguity (pass_rate is always a finite ratio in [0, 1]).
    ranked.sort_by(|a, b| {
        b.report
            .pass_rate
            .total_cmp(&a.report.pass_rate)
            .then_with(|| b.report.mean.cmp(&a.report.mean))
            .then_with(|| a.variant_id.cmp(&b.variant_id))
    });

    let winner = if variants.is_empty() || gold.is_empty() {
        None
    } else {
        ranked.first().map(|o| o.variant_id.clone())
    };

    ModelOptimization {
        model_id: model.id().into(),
        tier: model.tier(),
        ranked,
        winner,
    }
}

/// Run [`optimize`] once per model, keyed by model, so results are never mixed across models
/// (`PROMPT_ENGINEERING.md` §5.4 — "per-model, always"). The returned vec preserves `models` order,
/// and each entry carries its own `model_id`/`tier`.
pub fn optimize_all(
    variants: &[PromptVariant],
    gold: &[ainxt_eval::EvalCase],
    judge: &dyn QualityJudge,
    models: &[&dyn ModelSeam],
) -> Vec<ModelOptimization> {
    models
        .iter()
        .map(|model| optimize(variants, gold, judge, *model))
        .collect()
}

/// The A/B decision: does the challenger earn promotion, or does the incumbent hold?
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Promotion {
    /// The challenger is better beyond the margin — promote it.
    PromoteChallenger,
    /// The challenger is not better beyond the margin — keep the champion (non-inferiority default).
    KeepChampion,
}

/// A/B result: both scored reports, the pass-rate delta, and the decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AbResult {
    pub champion_id: String,
    pub challenger_id: String,
    pub champion: EvalReport,
    pub challenger: EvalReport,
    /// `challenger.pass_rate − champion.pass_rate` (positive = challenger ahead).
    pub delta: f64,
    /// The superiority margin (pass-rate points) the challenger had to beat.
    pub margin: f64,
    pub decision: Promotion,
}

impl AbResult {
    /// The id that should be live after this A/B (challenger iff promoted, else champion).
    pub fn winner_id(&self) -> &str {
        match self.decision {
            Promotion::PromoteChallenger => &self.challenger_id,
            Promotion::KeepChampion => &self.champion_id,
        }
    }
}

/// A/B test a `challenger` against the live `champion` on `gold`, promoting **only if the challenger
/// is better than the champion beyond `margin`** (pass-rate points). This is the superiority mirror
/// of the eval gate's non-inferiority rule: a marginal or equal challenger — noise, not signal —
/// keeps the incumbent, so churn is not mistaken for progress. `margin` should be `>= 0`.
pub fn ab_promote(
    champion: &PromptVariant,
    challenger: &PromptVariant,
    gold: &[ainxt_eval::EvalCase],
    judge: &dyn QualityJudge,
    model: &dyn ModelSeam,
    margin: f64,
) -> AbResult {
    let champ_report = run_eval(
        gold,
        &VariantSystem {
            variant: champion,
            model,
        },
        judge,
    );
    let chall_report = run_eval(
        gold,
        &VariantSystem {
            variant: challenger,
            model,
        },
        judge,
    );
    let delta = chall_report.pass_rate - champ_report.pass_rate;
    let decision = if delta > margin {
        Promotion::PromoteChallenger
    } else {
        Promotion::KeepChampion
    };
    AbResult {
        champion_id: champion.id.clone(),
        challenger_id: challenger.id.clone(),
        champion: champ_report,
        challenger: chall_report,
        delta,
        margin,
        decision,
    }
}

/// Train→holdout optimization result. The winner is chosen on `train`, then re-scored on a disjoint
/// `holdout`; [`overfit`](Self::overfit) is set when the winner won on train but regressed on the
/// holdout beyond the confirmation margin.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HoldoutOutcome {
    pub model_id: String,
    pub tier: Tier,
    /// The full ranking on the train split.
    pub train: ModelOptimization,
    /// The winning variant id (chosen on train), or `None` if nothing could be certified.
    pub winner: Option<String>,
    /// The winner's train report (the score it was chosen on).
    pub winner_train: Option<EvalReport>,
    /// The winner's holdout report (the confirming score), or `None` if the holdout is empty.
    pub winner_holdout: Option<EvalReport>,
    /// True when the winner regressed on the holdout beyond the confirmation margin — a candidate
    /// that memorized the visible set (gap AQ / PE10). Never `true` without a non-empty holdout.
    pub overfit: bool,
    /// The non-inferiority margin (pass-rate points) used to confirm the winner on the holdout.
    pub margin: f64,
}

/// Optimize on `train`, then **confirm the winner on a disjoint `holdout`** (gap AQ / PE10).
///
/// The winner is chosen exactly as [`optimize`] would on the train split, then re-scored on the
/// holdout. Overfit detection reuses [`evaluate_gate_statistical_dropin`]'s non-inferiority check
/// (holdout report vs the winner's train report, absolutes relaxed, `noninferiority_margin = margin`):
/// if the holdout is a blocking regression against train, the winner is flagged
/// [`overfit`](HoldoutOutcome::overfit). When the holdout re-probes the *same* case identities as
/// train (a paired confirmation), the drop-in runs the per-case statistical test and catches a real
/// quality regression even when the pass-rate is unchanged; with disjoint ids it fails closed on the
/// aggregate arithmetic exactly as before.
///
/// Callers should ensure `train` and `holdout` are disjoint (the "sealed holdout" discipline,
/// `EVAL_PLATFORM.md` §9); this function does not deduplicate them. When the holdout is empty there is
/// nothing to confirm against, so `overfit` is `false` and `winner_holdout` is `None` (a missing
/// confirmation is never silently treated as a pass *or* a regression).
pub fn optimize_with_holdout(
    variants: &[PromptVariant],
    train: &[ainxt_eval::EvalCase],
    holdout: &[ainxt_eval::EvalCase],
    judge: &dyn QualityJudge,
    model: &dyn ModelSeam,
    margin: f64,
) -> HoldoutOutcome {
    let train_opt = optimize(variants, train, judge, model);
    let model_id = train_opt.model_id.clone();
    let tier = train_opt.tier;

    let Some(winner_id) = train_opt.winner.clone() else {
        // No winner certified on train (no variants / empty train set): nothing to confirm.
        return HoldoutOutcome {
            model_id,
            tier,
            train: train_opt,
            winner: None,
            winner_train: None,
            winner_holdout: None,
            overfit: false,
            margin,
        };
    };

    let winner_train = train_opt.winner_outcome().map(|o| o.report.clone());

    // Re-score the *winning variant* on the holdout. It must exist among the variants (it came from
    // train_opt), so the lookup is guaranteed to succeed for a certified winner.
    let winner_variant = variants.iter().find(|v| v.id == winner_id);
    let winner_holdout = match winner_variant {
        Some(v) if !holdout.is_empty() => Some(run_eval(
            holdout,
            &VariantSystem { variant: v, model },
            judge,
        )),
        _ => None,
    };

    // Overfit = the winner regresses on the holdout beyond `margin`, detected by REUSING the eval
    // gate: baseline = train report, candidate = holdout report, absolutes relaxed to isolate the
    // non-inferiority signal. An empty holdout yields no confirmation and thus no overfit flag.
    let overfit = match (&winner_train, &winner_holdout) {
        (Some(train_rep), Some(holdout_rep)) => {
            let policy = GatePolicy {
                min_pass_rate: 0.0,
                min_mean: 0,
                noninferiority_margin: margin,
            };
            !evaluate_gate_statistical_dropin(holdout_rep, &policy, Some(train_rep)).is_pass()
        }
        _ => false,
    };

    HoldoutOutcome {
        model_id,
        tier,
        train: train_opt,
        winner: Some(winner_id),
        winner_train,
        winner_holdout,
        overfit,
        margin,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ainxt_eval::{EvalCase, EvalCriteria, QualityScore};

    // --- Fixtures ------------------------------------------------------------------------------
    //
    // A tiny payments "knowledge" model: it reveals the canonical scheme term for a topic ONLY when
    // the prompt contains the right instruction marker. Model A unlocks on "step by step"; model B
    // unlocks on "in detail". This is what makes per-model tuning real — the same instruction is a
    // key for one model and a no-op for the other.

    const TABLE: [(&str, &str); 4] = [
        ("instant transfer", "UPI"),
        ("bulk clearing", "NACH"),
        ("high value", "RTGS"),
        ("deferred net", "NEFT"),
    ];

    fn reveal_if(prompt: &str, marker: &str) -> String {
        let mut out = prompt.to_string();
        if prompt.contains(marker) {
            for (topic, term) in TABLE {
                if prompt.contains(topic) {
                    out.push(' ');
                    out.push_str(term);
                }
            }
        }
        out
    }

    struct DomainModelA;
    impl ModelSeam for DomainModelA {
        fn id(&self) -> &str {
            "domain-a"
        }
        fn tier(&self) -> Tier {
            Tier::Medium
        }
        fn complete(&self, prompt: &str) -> String {
            reveal_if(prompt, "step by step")
        }
    }

    struct DomainModelB;
    impl ModelSeam for DomainModelB {
        fn id(&self) -> &str {
            "domain-b"
        }
        fn tier(&self) -> Tier {
            Tier::Complex
        }
        fn complete(&self, prompt: &str) -> String {
            reveal_if(prompt, "in detail")
        }
    }

    /// Rewards relevance (the rubric's expected scheme term appearing in the output) and, separately,
    /// showing work ("step by step"). needle = the rubric's last word.
    struct RichJudge;
    impl QualityJudge for RichJudge {
        fn score(&self, _input: &str, output: &str, criteria: &EvalCriteria) -> QualityScore {
            let needle = criteria.rubric.split_whitespace().last().unwrap_or("");
            let mut s: u8 = 20;
            if !needle.is_empty() && output.contains(needle) {
                s += 50;
            }
            if output.contains("step by step") {
                s += 30;
            }
            QualityScore {
                score: s,
                rationale: String::new(),
            }
        }
    }

    fn train_gold() -> Vec<EvalCase> {
        vec![
            EvalCase::new("t_upi", "instant transfer", "must mention UPI", 60),
            EvalCase::new("t_nach", "bulk clearing", "must mention NACH", 60),
        ]
    }

    fn holdout_gold() -> Vec<EvalCase> {
        vec![
            EvalCase::new("h_rtgs", "high value", "must mention RTGS", 60),
            EvalCase::new("h_neft", "deferred net", "must mention NEFT", 60),
        ]
    }

    fn guided() -> PromptVariant {
        PromptVariant::new("guided", "Explain step by step about {input}")
    }
    fn plain() -> PromptVariant {
        PromptVariant::new("plain", "{input}")
    }

    // --- render --------------------------------------------------------------------------------

    #[test]
    fn render_substitutes_every_placeholder_and_no_placeholder_is_inert() {
        let v = PromptVariant::new("v", "a {input} b {input}");
        assert_eq!(v.render("X"), "a X b X");
        assert!(v.uses_input());

        let fixed = PromptVariant::new("f", "no placeholder here");
        assert_eq!(fixed.render("X"), "no placeholder here");
        assert!(!fixed.uses_input());
    }

    // --- (1) a clearly-better variant wins -----------------------------------------------------

    #[test]
    fn clearly_better_variant_wins() {
        let gold = train_gold();
        let opt = optimize(&[plain(), guided()], &gold, &RichJudge, &DomainModelA);

        assert_eq!(opt.winner.as_deref(), Some("guided"));
        assert_eq!(opt.model_id, "domain-a");
        assert_eq!(opt.tier, Tier::Medium);

        // The guided variant reveals the scheme term AND shows work → 100 on both cases → pass-rate 1.
        let win = opt.winner_outcome().unwrap();
        assert!((win.report.pass_rate - 1.0).abs() < 1e-9);
        assert_eq!(win.report.mean, 100);

        // Plain never triggers the reveal → misses the term → 20 → nothing passes.
        let loser = opt.ranked.iter().find(|o| o.variant_id == "plain").unwrap();
        assert!((loser.report.pass_rate - 0.0).abs() < 1e-9);
        assert_eq!(loser.report.mean, 20);

        // Ranked most-to-least: guided ahead of plain.
        assert_eq!(opt.ranked[0].variant_id, "guided");
        assert_eq!(opt.ranked[1].variant_id, "plain");
    }

    // --- (2) ties break deterministically ------------------------------------------------------

    #[test]
    fn ties_break_deterministically_by_id() {
        // Two variants with identical templates → identical reports → the tie must break by id asc.
        let vb = PromptVariant::new("v_b", "Explain step by step about {input}");
        let va = PromptVariant::new("v_a", "Explain step by step about {input}");
        let gold = train_gold();

        // Order the inputs so the tie-break, not input order, decides the winner.
        let opt = optimize(&[vb.clone(), va.clone()], &gold, &RichJudge, &DomainModelA);
        assert_eq!(opt.winner.as_deref(), Some("v_a"));
        assert_eq!(opt.ranked[0].variant_id, "v_a");
        assert_eq!(opt.ranked[1].variant_id, "v_b");
        // Both genuinely tied on the metrics.
        assert_eq!(opt.ranked[0].report.mean, opt.ranked[1].report.mean);
        assert!((opt.ranked[0].report.pass_rate - opt.ranked[1].report.pass_rate).abs() < 1e-9);

        // Reversing the input order yields the SAME deterministic winner.
        let opt2 = optimize(&[va, vb], &gold, &RichJudge, &DomainModelA);
        assert_eq!(opt2.winner.as_deref(), Some("v_a"));
        assert_eq!(opt2.ranked[0].variant_id, "v_a");
    }

    // --- (4) A/B non-inferiority ---------------------------------------------------------------

    #[test]
    fn within_margin_challenger_does_not_displace_champion() {
        let gold = train_gold();
        // Champion and challenger are equally good (identical behavior) → delta 0 → keep champion.
        let champion = PromptVariant::new("champ", "Explain step by step about {input}");
        let challenger = PromptVariant::new("chall", "Explain step by step about {input}");
        let ab = ab_promote(
            &champion,
            &challenger,
            &gold,
            &RichJudge,
            &DomainModelA,
            0.05,
        );

        assert_eq!(ab.decision, Promotion::KeepChampion);
        assert!(ab.delta.abs() < 1e-9);
        assert_eq!(ab.winner_id(), "champ");
    }

    #[test]
    fn challenger_better_beyond_margin_is_promoted() {
        let gold = train_gold();
        // Champion is the weak "plain" (pass-rate 0); challenger "guided" (pass-rate 1) → +1.0 > margin.
        let ab = ab_promote(&plain(), &guided(), &gold, &RichJudge, &DomainModelA, 0.05);
        assert_eq!(ab.decision, Promotion::PromoteChallenger);
        assert!((ab.delta - 1.0).abs() < 1e-9);
        assert_eq!(ab.winner_id(), "guided");
    }

    // --- (5) holdout / overfit guard -----------------------------------------------------------

    #[test]
    fn overfit_variant_wins_train_but_is_flagged_on_holdout() {
        // This variant BAKES the train answers into its text and never asks the model to show work,
        // so it "passes" train by memorization and collapses on the holdout schemes.
        let overfit = PromptVariant::new("overfit", "Known answers UPI NACH regarding {input}");
        let out = optimize_with_holdout(
            &[overfit],
            &train_gold(),
            &holdout_gold(),
            &RichJudge,
            &DomainModelA,
            0.05,
        );

        assert_eq!(out.winner.as_deref(), Some("overfit"));
        // Wins train (contains the baked UPI/NACH terms → 70 ≥ 60 threshold).
        let tr = out.winner_train.as_ref().unwrap();
        assert!((tr.pass_rate - 1.0).abs() < 1e-9);
        // Collapses on holdout (RTGS/NEFT never appear) → pass-rate 0.
        let ho = out.winner_holdout.as_ref().unwrap();
        assert!((ho.pass_rate - 0.0).abs() < 1e-9);
        assert!(
            out.overfit,
            "a winner that regresses on the holdout must be flagged overfit"
        );
    }

    #[test]
    fn robust_winner_is_confirmed_on_holdout() {
        // The generalizing variant unlocks the model's knowledge for ANY topic → confirmed on holdout.
        let out = optimize_with_holdout(
            &[guided(), plain()],
            &train_gold(),
            &holdout_gold(),
            &RichJudge,
            &DomainModelA,
            0.05,
        );

        assert_eq!(out.winner.as_deref(), Some("guided"));
        let ho = out.winner_holdout.as_ref().unwrap();
        assert!((ho.pass_rate - 1.0).abs() < 1e-9);
        assert!(
            !out.overfit,
            "a winner that holds up on the holdout must NOT be flagged overfit"
        );
    }

    #[test]
    fn empty_holdout_yields_no_confirmation_and_no_false_overfit() {
        let out = optimize_with_holdout(
            &[guided()],
            &train_gold(),
            &[],
            &RichJudge,
            &DomainModelA,
            0.05,
        );
        assert_eq!(out.winner.as_deref(), Some("guided"));
        assert!(
            out.winner_holdout.is_none(),
            "no holdout → nothing to confirm against"
        );
        assert!(
            !out.overfit,
            "a missing confirmation must never be reported as a regression"
        );
    }

    // --- (6) per-model keying ------------------------------------------------------------------

    #[test]
    fn per_model_results_stay_separated_with_different_winners() {
        // "step by step" is the key for model A; "in detail" is the key for model B. Each model's best
        // variant is a DIFFERENT string — the exact failure "optimize once, use everywhere" hides.
        let sd = PromptVariant::new("sd", "Explain step by step about {input}");
        let dd = PromptVariant::new("dd", "Describe in detail about {input}");
        let variants = [sd, dd];
        let gold = train_gold();

        let a = DomainModelA;
        let b = DomainModelB;
        let models: [&dyn ModelSeam; 2] = [&a, &b];
        let results = optimize_all(&variants, &gold, &RichJudge, &models);

        assert_eq!(results.len(), 2);
        // Model A: only "sd" unlocks it.
        assert_eq!(results[0].model_id, "domain-a");
        assert_eq!(results[0].tier, Tier::Medium);
        assert_eq!(results[0].winner.as_deref(), Some("sd"));
        // Model B: only "dd" unlocks it.
        assert_eq!(results[1].model_id, "domain-b");
        assert_eq!(results[1].tier, Tier::Complex);
        assert_eq!(results[1].winner.as_deref(), Some("dd"));
        // The winners genuinely differ across models — results were not mixed.
        assert_ne!(results[0].winner, results[1].winner);
    }

    // --- empty inputs handled ------------------------------------------------------------------

    #[test]
    fn empty_variants_produce_no_winner() {
        let opt = optimize(&[], &train_gold(), &RichJudge, &DomainModelA);
        assert!(opt.ranked.is_empty());
        assert!(opt.winner.is_none());
        assert!(opt.winner_outcome().is_none());
        assert_eq!(opt.model_id, "domain-a");
    }

    #[test]
    fn empty_gold_set_certifies_no_winner_but_still_lists_variants() {
        let opt = optimize(&[guided(), plain()], &[], &RichJudge, &DomainModelA);
        assert_eq!(opt.ranked.len(), 2);
        // Nothing was measured → no evidence → no winner.
        assert!(opt.winner.is_none());
        // Each report is empty (n == 0), pass-rate 0.
        assert!(opt.ranked.iter().all(|o| o.report.n == 0));
        assert!(opt.ranked.iter().all(|o| o.report.pass_rate.abs() < 1e-9));
    }

    #[test]
    fn holdout_with_no_train_winner_is_not_overfit() {
        // No variants → no train winner → nothing to confirm, never overfit.
        let out = optimize_with_holdout(
            &[],
            &train_gold(),
            &holdout_gold(),
            &RichJudge,
            &DomainModelA,
            0.05,
        );
        assert!(out.winner.is_none());
        assert!(out.winner_train.is_none());
        assert!(out.winner_holdout.is_none());
        assert!(!out.overfit);
    }

    #[test]
    fn r4_stat_holdout_flags_within_passrate_regression() {
        // A PAIRED holdout: it re-probes the SAME case identities as train (ids c0..c11), so the
        // holdout guard can compare the winner case-by-case. The winner still PASSES every holdout
        // case (holdout pass-rate == train pass-rate == 1.0), but each case's score drops ~16 points
        // — a genuine quality regression. The naive aggregate check (pass-rate only) sees no drop and
        // clears it as not-overfit (fail-before). The statistically-valid drop-in pairs by id and
        // flags the significant per-case regression as overfit (pass-after).
        struct EchoModel;
        impl ModelSeam for EchoModel {
            fn id(&self) -> &str {
                "echo"
            }
            fn tier(&self) -> Tier {
                Tier::Medium
            }
            fn complete(&self, prompt: &str) -> String {
                prompt.to_string()
            }
        }
        // The output is a numeric string; the judge reads it back as the score.
        struct DigitJudge;
        impl QualityJudge for DigitJudge {
            fn score(&self, _input: &str, output: &str, _criteria: &EvalCriteria) -> QualityScore {
                QualityScore {
                    score: output.trim().parse::<u8>().unwrap_or(0),
                    rationale: String::new(),
                }
            }
        }
        // A pass-through variant: render(input) == input, echoed by the model → output == input.
        let passthrough = PromptVariant::new("passthrough", "{input}");
        // Train: high scores (~90), every case passes (>= 60 threshold).
        let train: Vec<EvalCase> = (0..12)
            .map(|i| {
                let s = 89 + (i % 3) as u8; // 89..91
                EvalCase::new(&format!("c{i}"), &s.to_string(), "score", 60)
            })
            .collect();
        // Holdout re-probes the SAME ids but the winner scores ~16 points lower — still all passing.
        let holdout: Vec<EvalCase> = (0..12)
            .map(|i| {
                let s = 73 + (i % 3) as u8 - (i % 2) as u8; // 72..75
                EvalCase::new(&format!("c{i}"), &s.to_string(), "score", 60)
            })
            .collect();

        let out = optimize_with_holdout(
            &[passthrough],
            &train,
            &holdout,
            &DigitJudge,
            &EchoModel,
            0.05,
        );

        assert_eq!(out.winner.as_deref(), Some("passthrough"));
        // Both runs are 100% pass-rate — the only signal the naive gate watches is unchanged.
        let tr = out.winner_train.as_ref().unwrap();
        let ho = out.winner_holdout.as_ref().unwrap();
        assert!((tr.pass_rate - 1.0).abs() < 1e-9);
        assert!((ho.pass_rate - 1.0).abs() < 1e-9);
        // The statistical drop-in catches the per-case regression the naive pass-rate gate missed.
        assert!(
            out.overfit,
            "a winner whose per-case scores regress on a paired holdout must be flagged overfit \
             even when pass-rate is unchanged"
        );
    }

    // --- serialization (the result is a durable record, like EvalReport) -----------------------

    #[test]
    fn model_optimization_serializes_round_trip() {
        let opt = optimize(
            &[guided(), plain()],
            &train_gold(),
            &RichJudge,
            &DomainModelA,
        );
        let json = serde_json::to_string(&opt).unwrap();
        let back: ModelOptimization = serde_json::from_str(&json).unwrap();
        assert_eq!(back, opt);
        // A concrete field survives the round-trip (not a tautological check).
        assert_eq!(back.winner.as_deref(), Some("guided"));
    }
}
