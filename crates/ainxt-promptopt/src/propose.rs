// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! The optimizer **Propose** step (`PROMPT_ENGINEERING.md` §5.2, gap BJ; audit: "a variant SELECTOR,
//! not a GENERATOR"). Given a seed prompt, this generates the candidate search space the
//! [`crate::optimize`] step then scores — deterministically, so the same seed + catalog always yield
//! the same candidates (no rng, reproducible optimization runs).
//!
//! Candidate axes (a bounded cross-product, `PROMPT_ENGINEERING.md` §5.2):
//! * **instruction rephrasing** — prepend an instruction lead from the catalog;
//! * **few-shot bootstrapping** — prepend `k` worked exemplars (`k` in `0..=max_shots`);
//! * **output-format restatement placement** — none / trailing / both-ends (recency helps weak
//!   models, §4);
//! * **decomposition granularity** — optionally add a "numbered steps" directive.
//!
//! Every generated candidate preserves the seed's `{input}` placeholder, so it remains a real prompt
//! the model fills with the case input. The seed itself is always candidate 0 (the incumbent must be
//! in the race). Candidates are deduplicated by rendered template and capped at `max_candidates`.

use crate::{PromptVariant, INPUT_PLACEHOLDER};

/// A worked example used for few-shot bootstrapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exemplar {
    pub input: String,
    pub output: String,
}

impl Exemplar {
    pub fn new(input: &str, output: &str) -> Self {
        Exemplar {
            input: input.into(),
            output: output.into(),
        }
    }
}

/// The proposal catalog — the building blocks the Propose step recombines.
#[derive(Debug, Clone)]
pub struct ProposeCatalog {
    /// Instruction leads to try prepending (e.g. "Explain step by step."). An empty lead (no
    /// rephrasing) is always tried in addition to these.
    pub instruction_leads: Vec<String>,
    /// A restated output-format directive (e.g. "Answer as a JSON object.").
    pub format_directive: Option<String>,
    /// A decomposition directive (e.g. "Break the problem into numbered steps.").
    pub decomposition_directive: Option<String>,
}

impl Default for ProposeCatalog {
    fn default() -> Self {
        ProposeCatalog {
            instruction_leads: vec![
                "Explain step by step.".to_string(),
                "Think carefully before answering.".to_string(),
                "In detail:".to_string(),
            ],
            format_directive: None,
            decomposition_directive: Some("Break the problem into numbered steps.".to_string()),
        }
    }
}

/// Where to restate the format directive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Placement {
    None,
    Trailing,
    BothEnds,
}

/// Configuration bounding the search space (cost-bounded, §5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProposeConfig {
    /// Maximum few-shot exemplars to bootstrap (`k` ranges `0..=max_shots`).
    pub max_shots: usize,
    /// Hard cap on the number of candidates returned (including the seed).
    pub max_candidates: usize,
}

impl Default for ProposeConfig {
    fn default() -> Self {
        ProposeConfig {
            max_shots: 2,
            max_candidates: 24,
        }
    }
}

/// Generate the candidate variants for `seed`. Deterministic and bounded.
pub fn propose(
    seed: &PromptVariant,
    catalog: &ProposeCatalog,
    exemplars: &[Exemplar],
    cfg: ProposeConfig,
) -> Vec<PromptVariant> {
    let mut out: Vec<PromptVariant> = Vec::new();
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    // Candidate 0 is always the incumbent seed.
    seen.insert(seed.template.clone());
    out.push(seed.clone());

    // Leads: the empty lead (no rephrasing) plus each catalog lead.
    let mut leads: Vec<Option<&str>> = vec![None];
    leads.extend(catalog.instruction_leads.iter().map(|s| Some(s.as_str())));

    let placements = match &catalog.format_directive {
        Some(_) => vec![Placement::None, Placement::Trailing, Placement::BothEnds],
        None => vec![Placement::None],
    };

    let max_shots = cfg.max_shots.min(exemplars.len());

    // Deterministic nested enumeration (stable order → reproducible).
    for &lead in &leads {
        for shots in 0..=max_shots {
            for &placement in &placements {
                for &decompose in &[false, true] {
                    if catalog.decomposition_directive.is_none() && decompose {
                        continue;
                    }
                    let template = build_template(
                        &seed.template,
                        lead,
                        &exemplars[..shots],
                        placement,
                        catalog.format_directive.as_deref(),
                        if decompose {
                            catalog.decomposition_directive.as_deref()
                        } else {
                            None
                        },
                    );
                    // Must still reference the input, and must be genuinely new.
                    if !template.contains(INPUT_PLACEHOLDER) || seen.contains(&template) {
                        continue;
                    }
                    seen.insert(template.clone());
                    let id = format!("cand-{:03}", out.len());
                    out.push(PromptVariant::new(&id, &template));
                    if out.len() >= cfg.max_candidates {
                        return out;
                    }
                }
            }
        }
    }
    out
}

/// Assemble one candidate template from the chosen building blocks.
fn build_template(
    seed_template: &str,
    lead: Option<&str>,
    shots: &[Exemplar],
    placement: Placement,
    format_directive: Option<&str>,
    decomposition: Option<&str>,
) -> String {
    let mut t = String::new();
    if let Some(l) = lead {
        t.push_str(l);
        t.push('\n');
    }
    if matches!(placement, Placement::BothEnds) {
        if let Some(fd) = format_directive {
            t.push_str(fd);
            t.push('\n');
        }
    }
    if let Some(d) = decomposition {
        t.push_str(d);
        t.push('\n');
    }
    for ex in shots {
        t.push_str("Example input: ");
        t.push_str(&ex.input);
        t.push_str("\nExample output: ");
        t.push_str(&ex.output);
        t.push_str("\n\n");
    }
    t.push_str(seed_template);
    if matches!(placement, Placement::Trailing | Placement::BothEnds) {
        if let Some(fd) = format_directive {
            t.push('\n');
            t.push_str(fd);
        }
    }
    t
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{optimize, ModelSeam};
    use ainxt_eval::{EvalCase, EvalCriteria, QualityJudge, QualityScore};
    use ainxt_types::Tier;

    fn plain_seed() -> PromptVariant {
        PromptVariant::new("seed", "{input}")
    }

    #[test]
    fn seed_is_always_candidate_zero() {
        let cands = propose(
            &plain_seed(),
            &ProposeCatalog::default(),
            &[],
            ProposeConfig::default(),
        );
        assert_eq!(cands[0].id, "seed");
        assert_eq!(cands[0].template, "{input}");
    }

    #[test]
    fn candidates_are_distinct_preserve_input_and_are_capped() {
        let cfg = ProposeConfig {
            max_shots: 2,
            max_candidates: 10,
        };
        let exemplars = [
            Exemplar::new("instant transfer", "UPI"),
            Exemplar::new("bulk", "NACH"),
        ];
        let cands = propose(&plain_seed(), &ProposeCatalog::default(), &exemplars, cfg);
        assert!(cands.len() <= 10, "respects max_candidates");
        assert!(cands.len() > 1, "generates real alternatives");
        // All keep the placeholder.
        assert!(cands.iter().all(|c| c.uses_input()));
        // All templates are distinct.
        let mut templates: Vec<&String> = cands.iter().map(|c| &c.template).collect();
        templates.sort();
        let before = templates.len();
        templates.dedup();
        assert_eq!(before, templates.len(), "no duplicate candidates");
    }

    #[test]
    fn proposal_is_deterministic() {
        let a = propose(
            &plain_seed(),
            &ProposeCatalog::default(),
            &[],
            ProposeConfig::default(),
        );
        let b = propose(
            &plain_seed(),
            &ProposeCatalog::default(),
            &[],
            ProposeConfig::default(),
        );
        assert_eq!(a, b, "same seed + catalog → identical candidates");
    }

    // A domain model that only reveals the scheme term when the prompt shows work "step by step" —
    // exactly the lead the Propose step will try. This proves Propose actually EXPANDS the search into
    // a strictly-better region a bare seed never reaches.
    struct StepByStepModel;
    impl ModelSeam for StepByStepModel {
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
        fn score(&self, _input: &str, output: &str, criteria: &EvalCriteria) -> QualityScore {
            let needle = criteria.rubric.split_whitespace().last().unwrap_or("");
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

    #[test]
    fn propose_then_optimize_finds_a_variant_that_beats_the_seed() {
        let gold = vec![EvalCase::new(
            "g",
            "instant transfer",
            "must mention UPI",
            60,
        )];
        let seed = plain_seed();

        // The seed alone never unlocks the model.
        let seed_only = optimize(
            std::slice::from_ref(&seed),
            &gold,
            &TermJudge,
            &StepByStepModel,
        );
        assert!((seed_only.winner_outcome().unwrap().report.pass_rate).abs() < 1e-9);

        // Propose expands the space; optimize now finds a "step by step" candidate that passes.
        let cands = propose(
            &seed,
            &ProposeCatalog::default(),
            &[],
            ProposeConfig::default(),
        );
        assert!(
            cands.iter().any(|c| c.template.contains("step by step")),
            "the Propose step must generate the winning phrasing"
        );
        let opt = optimize(&cands, &gold, &TermJudge, &StepByStepModel);
        let win = opt.winner_outcome().unwrap();
        assert!(
            (win.report.pass_rate - 1.0).abs() < 1e-9,
            "an expanded candidate should reach pass-rate 1.0 where the seed scored 0"
        );
        assert!(win.report.results[0].output.contains("UPI"));
    }

    #[test]
    fn few_shot_exemplars_appear_in_generated_candidates() {
        let exemplars = [Exemplar::new("bulk clearing", "NACH")];
        let cfg = ProposeConfig {
            max_shots: 1,
            max_candidates: 50,
        };
        let cands = propose(&plain_seed(), &ProposeCatalog::default(), &exemplars, cfg);
        assert!(
            cands
                .iter()
                .any(|c| c.template.contains("Example input: bulk clearing")),
            "few-shot bootstrapping must inject exemplars"
        );
    }

    #[test]
    fn format_directive_placement_expands_candidates() {
        let catalog = ProposeCatalog {
            instruction_leads: vec![],
            format_directive: Some("Answer as JSON.".to_string()),
            decomposition_directive: None,
        };
        let cands = propose(&plain_seed(), &catalog, &[], ProposeConfig::default());
        // None + trailing + both-ends placements → the seed plus 2 format-bearing variants.
        let with_fmt = cands
            .iter()
            .filter(|c| c.template.contains("Answer as JSON."))
            .count();
        assert!(
            with_fmt >= 2,
            "trailing and both-ends placements both appear"
        );
    }
}
