// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Bridges the **deterministic graph checks** (`ainxt-semantic`) into the pipeline's scalar inputs, so
//! Architecture Review (`CODE_REVIEW_PIPELINE.md` §4 stage 7) and Regression Detection (stage 8) are
//! *computed* by the pipeline rather than invented by a caller. Previously `gate`/`confidence`
//! consumed a caller-supplied `architecture_violations: u32` and `blast_radius_test_coverage: f64`
//! with nothing computing them; these functions turn the edit's files into those numbers.

use crate::capability::Language;
use crate::stage::{Stage, StageReport, StageVerdict};
use ainxt_semantic::arch::{ArchViolation, LayerContract, LayerManifest};
use ainxt_semantic::graph::SourceFile;
use ainxt_semantic::regression::{analyze, CochangeGraph, RegressionReport};
use ainxt_semantic::{list_definitions, Language as AstLanguage};
use std::collections::{BTreeMap, BTreeSet};

/// GAP-FIX gap6-semantic-lsp-signature-layermanifest item 3 — the conventional, git-controlled path
/// (relative to the reviewed repo's own root) a `LayerManifest` (serde JSON — see
/// `ainxt_semantic::arch::LayerManifest`) is discovered at, mirroring the Python SDLC pipeline's
/// `.sdlc.yml` convention (`CLAUDE.md` "Language Detection"): the contract lives IN the repo, checked
/// in and versioned alongside the code it constrains, discovered from what is actually being reviewed
/// — never a separate daemon-level config path a reviewer would have to keep in sync by hand.
pub const ARCH_MANIFEST_PATH: &str = ".arch.json";

/// Resolve the [`LayerContract`] Architecture Review (stage 7) should apply to THIS round: if the
/// edit's own current file set checks in a [`ARCH_MANIFEST_PATH`] `LayerManifest`, that is loaded and
/// takes precedence (`LayerContract::from_manifest`) — "declared once per module, read every time"
/// (`CODE_REVIEW_PIPELINE.md` §4 stage 7). Otherwise falls back to `fallback`, the deployment's
/// statically-configured contract (`EditEngine::with_semantic_review`'s `contract`, `None` on the
/// shipped default). A manifest file present but unparseable is treated as "not declared" — it never
/// silently WIDENS the effective contract past what the deployment's own static fallback already
/// asserts; a malformed checked-in file is a human's problem to fix, not a reason to invent stricter
/// boundaries no one actually reviewed.
#[must_use]
pub fn repo_layer_contract(
    files: &[(String, String)],
    fallback: Option<&LayerContract>,
) -> Option<LayerContract> {
    if let Some((_, content)) = files.iter().find(|(p, _)| p == ARCH_MANIFEST_PATH) {
        if let Ok(manifest) = serde_json::from_str::<LayerManifest>(content) {
            return Some(LayerContract::from_manifest(&manifest));
        }
    }
    fallback.cloned()
}

/// The count of deterministic architecture boundary violations *introduced* by an edit — the number
/// the Commit Gate hard-blocks on (§8). Diffs the post-edit import edges against the layering contract
/// and attributes only the newly-introduced violations to this edit.
#[must_use]
pub fn architecture_violation_count(
    before: &[SourceFile],
    after: &[SourceFile],
    contract: &LayerContract,
) -> u32 {
    contract.new_violations(before, after).len() as u32
}

/// The blast-radius test-coverage overlap `[0,1]` the Confidence Score's regression term consumes,
/// computed from the test graph (stage 8), plus the full regression report for the gap output.
#[must_use]
pub fn test_coverage_overlap(
    files: &[SourceFile],
    touched_names: &[&str],
    touched_files: &[&str],
    cochange: &CochangeGraph,
    coupling_threshold: usize,
) -> (f64, RegressionReport) {
    let report = analyze(
        files,
        touched_names,
        touched_files,
        cochange,
        coupling_threshold,
    );
    (report.coverage_overlap, report)
}

// ===========================================================================
// The wired stage-7 + stage-8 seam the LIVE edit turn runs each self-heal round
// ===========================================================================

/// The deployment-level Architecture Review (stage 7) + Regression Detection (stage 8) seams a
/// surface/engine wires in once and reuses for every code-editing turn — the direct analogue of
/// [`crate::perf::PerfConfig`]. No per-turn baseline: the pre-edit baseline is supplied per turn by the
/// edit-turn gate (it is the turn's `original_files`).
///
/// Before this seam existed the pipeline's `architecture_violations` / `blast_radius_test_coverage`
/// were caller-supplied scalars with nothing computing them from a *live* edit; wiring this config into
/// [`crate::EditEngine::with_semantic_review`] makes a live edit turn compute both from the edit itself.
pub struct SemanticGateConfig<'a> {
    /// Stage 7: the declared module-boundary contract. `None` = no layering contract wired (the arch
    /// hard-gate is inert; a live edit is never blocked for a boundary the deployment never declared).
    pub contract: Option<&'a LayerContract>,
    /// Stage 8: the git-history co-change graph for change-coupling advisories (never gating).
    pub cochange: &'a CochangeGraph,
    /// Minimum historical co-change count for a coupling advisory.
    pub coupling_threshold: usize,
}

/// The computed output of stages 7 + 8 for one candidate file set: the architecture-violation count
/// the Commit Gate hard-blocks on, the blast-radius test coverage the Confidence Score folds in, and
/// the two honest [`StageReport`]s (journaled + surfaced in the gap report).
#[derive(Debug, Clone)]
pub struct SemanticGateReport {
    /// Stage 7 — the number of forbidden boundary edges the edit *introduced* (hard-block if `> 0`).
    pub architecture_violations: u32,
    /// The exact introduced violations (each carries the un-paraphrased import string).
    pub new_violations: Vec<ArchViolation>,
    /// Stage 8 — the fraction `[0,1]` of the touched blast radius reached by a test.
    pub coverage: f64,
    /// The full regression report (uncovered symbols + coupling advisories) for the gap output.
    pub regression: RegressionReport,
    /// The stage-7 report to fold into the pipeline's report set.
    pub arch_report: StageReport,
    /// The stage-8 report to fold into the pipeline's report set.
    pub regression_report: StageReport,
}

/// Map the pipeline capability language onto the AST grammar, if one exists (Rust/Python only).
fn ast_lang(lang: Language) -> Option<AstLanguage> {
    match lang {
        Language::Rust => Some(AstLanguage::Rust),
        Language::Python => Some(AstLanguage::Python),
        Language::Go => Some(AstLanguage::Go),
        Language::JavaScript => Some(AstLanguage::JavaScript),
        Language::TypeScript => Some(AstLanguage::TypeScript),
        Language::Java => Some(AstLanguage::Java),
        Language::Cobol | Language::Other => None,
    }
}

fn to_source_files(files: &[(String, String)], sl: AstLanguage) -> Vec<SourceFile> {
    files
        .iter()
        .map(|(p, c)| SourceFile::new(p.clone(), sl, c.clone()))
        .collect()
}

/// `name -> definition text` for every def in `src` (first span wins on a duplicate name). Empty on a
/// parse error — a file we cannot parse contributes no signal.
fn defs(src: &str, sl: AstLanguage) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    if let Ok(ds) = list_definitions(src, sl) {
        for d in ds {
            let text = src
                .get(d.span.start_byte..d.span.end_byte)
                .unwrap_or_default()
                .to_string();
            out.entry(d.name).or_insert(text);
        }
    }
    out
}

/// The touched files (content differs vs the baseline) and the added/changed/removed symbol names —
/// the "touched blast radius" the stage-8 coverage is computed over. Conservative: a symbol whose text
/// changed at all is touched (any doubt widens the touched set, never shrinks it).
fn touched(
    baseline: &[(String, String)],
    current: &[(String, String)],
    sl: AstLanguage,
) -> (Vec<String>, Vec<String>) {
    let base: BTreeMap<&str, &str> = baseline
        .iter()
        .map(|(p, c)| (p.as_str(), c.as_str()))
        .collect();
    let mut files = Vec::new();
    let mut names: BTreeSet<String> = BTreeSet::new();
    for (p, c) in current {
        let old = base.get(p.as_str()).copied().unwrap_or("");
        if old == c.as_str() {
            continue;
        }
        files.push(p.clone());
        let od = defs(old, sl);
        let nd = defs(c, sl);
        for (name, text) in &nd {
            if od.get(name).map(String::as_str) != Some(text.as_str()) {
                names.insert(name.clone());
            }
        }
        for name in od.keys() {
            if !nd.contains_key(name) {
                names.insert(name.clone());
            }
        }
    }
    (files, names.into_iter().collect())
}

/// **Run Architecture Review (stage 7) + Regression Detection (stage 8) over one candidate file set.**
///
/// This is the function the LIVE edit turn calls each self-heal round (via the seam threaded through
/// [`crate::selfheal::run_selfheal_full`]): it diffs the edit's import edges against the layering
/// contract (stage 7, a deterministic hard-gate) and computes the blast-radius test coverage from the
/// test graph (stage 8, folded into the Confidence Score) — turning both from caller-invented scalars
/// into computations over the code itself.
///
/// A language with no AST grammar is an honest `Skipped` for both stages (never a silent "boundaries
/// clean / fully covered"); coverage falls back to a neutral `1.0` and no violations are asserted.
#[must_use]
pub fn analyze_semantic_gate(
    lang: Language,
    baseline: &[(String, String)],
    current: &[(String, String)],
    contract: Option<&LayerContract>,
    cochange: &CochangeGraph,
    coupling_threshold: usize,
) -> SemanticGateReport {
    let Some(sl) = ast_lang(lang) else {
        let reason =
            format!("no AST grammar for {lang:?} — manual boundary/coverage review required");
        return SemanticGateReport {
            architecture_violations: 0,
            new_violations: Vec::new(),
            coverage: 1.0,
            regression: RegressionReport {
                uncovered: BTreeSet::new(),
                covered: BTreeSet::new(),
                coverage_overlap: 1.0,
                coupling_advisories: Vec::new(),
            },
            arch_report: StageReport::skipped(Stage::Architecture, reason.clone()),
            regression_report: StageReport::skipped(Stage::Regression, reason),
        };
    };

    let before = to_source_files(baseline, sl);
    let after = to_source_files(current, sl);

    // Stage 7 — Architecture Review (deterministic hard-gate).
    let (architecture_violations, new_violations, arch_report) = match contract {
        Some(c) => {
            let v = c.new_violations(&before, &after);
            let n = v.len() as u32;
            let report = if n > 0 {
                StageReport::fail(
                    Stage::Architecture,
                    true,
                    v.iter()
                        .map(ArchViolation::to_string)
                        .collect::<Vec<_>>()
                        .join("; "),
                )
            } else {
                StageReport::pass(Stage::Architecture, true)
            };
            (n, v, report)
        }
        // No contract declared: nothing to check (not a skip-for-want-of-tooling).
        None => (0, Vec::new(), StageReport::pass(Stage::Architecture, true)),
    };

    // Stage 8 — Regression Detection (coverage folds into the Confidence Score; coupling is advisory).
    let (touched_files, touched_names) = touched(baseline, current, sl);
    let tf: Vec<&str> = touched_files.iter().map(String::as_str).collect();
    let tn: Vec<&str> = touched_names.iter().map(String::as_str).collect();
    let regression = analyze(&after, &tn, &tf, cochange, coupling_threshold);
    let coverage = regression.coverage_overlap;
    let regression_verdict =
        if regression.uncovered_fraction() > 0.0 || !regression.coupling_advisories.is_empty() {
            StageVerdict::Advisory {
                detail: format!(
                "{:.0}% of the touched blast radius uncovered; {} change-coupling advisory(ies)",
                regression.uncovered_fraction() * 100.0,
                regression.coupling_advisories.len()
            ),
            }
        } else {
            StageVerdict::Pass
        };
    let regression_report = StageReport {
        stage: Stage::Regression,
        verdict: regression_verdict,
        deterministic: true,
    };

    SemanticGateReport {
        architecture_violations,
        new_violations,
        coverage,
        regression,
        arch_report,
        regression_report,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ainxt_semantic::Language as AstLang;

    fn rs(path: &str, src: &str) -> SourceFile {
        SourceFile::new(path, AstLang::Rust, src)
    }

    #[test]
    fn gap_ainxt_pipeline_edit_07_pipeline_computes_arch_violations_not_caller() {
        let contract = LayerContract::new()
            .layer("ui", &["ui/"])
            .layer("db", &["db::"])
            .allow("ui", "api");
        let before = vec![rs("src/ui/a.rs", "fn a() {}\n")];
        let after = vec![rs("src/ui/a.rs", "use crate::db::conn;\nfn a() {}\n")];
        let n = architecture_violation_count(&before, &after, &contract);
        assert_eq!(n, 1, "the pipeline itself computed the boundary violation");
    }

    #[test]
    fn gap_ainxt_pipeline_edit_08_pipeline_computes_coverage_not_caller() {
        let lib = rs(
            "lib.rs",
            "pub fn covered() -> i32 { 1 }\npub fn naked() -> i32 { 2 }\n",
        );
        let tests = rs("t.rs", "#[test]\nfn test_it() { covered(); }\n");
        let files = vec![lib, tests];
        let (overlap, report) = test_coverage_overlap(
            &files,
            &["covered", "naked"],
            &["lib.rs"],
            &CochangeGraph::new(),
            2,
        );
        assert!((overlap - 0.5).abs() < 1e-9);
        assert!((report.uncovered_fraction() - 0.5).abs() < 1e-9);
    }

    // ---- GAP-FIX gap6-semantic-lsp-signature-layermanifest item 3: a checked-in `.arch.json`
    // LayerManifest is loaded and takes precedence over the engine's static contract. ----

    #[test]
    fn gap6_repo_layer_contract_loads_a_checked_in_manifest_over_the_static_fallback() {
        let manifest_json = r#"{"layers":{"ui":["ui/"],"db":["db::"]},"allowed":[]}"#;
        let files = vec![
            (
                "src/ui/a.rs".to_string(),
                "use crate::db::conn;\nfn a() {}\n".to_string(),
            ),
            (ARCH_MANIFEST_PATH.to_string(), manifest_json.to_string()),
        ];
        // No static (engine-level) contract at all — exactly the shipped default
        // (`EditEngine::with_semantic_review(None, ...)`).
        let contract = repo_layer_contract(&files, None).expect("manifest present and parses");
        let after = vec![rs("src/ui/a.rs", "use crate::db::conn;\nfn a() {}\n")];
        let violations = contract.violations(&after);
        assert_eq!(
            violations.len(),
            1,
            "the checked-in manifest's ui->db boundary must be enforced"
        );
        assert_eq!(violations[0].to_layer, "db");
    }

    #[test]
    fn gap6_repo_layer_contract_falls_back_when_no_manifest_is_checked_in() {
        let static_contract = LayerContract::new()
            .layer("ui", &["ui/"])
            .layer("db", &["db::"]);
        let files = vec![("src/ui/a.rs".to_string(), "fn a() {}\n".to_string())];
        let resolved = repo_layer_contract(&files, Some(&static_contract));
        assert!(
            resolved.is_some(),
            "the static fallback must be used when no manifest is checked in"
        );
    }

    #[test]
    fn gap6_repo_layer_contract_falls_back_on_an_unparseable_checked_in_manifest() {
        // A malformed checked-in file must never silently widen the effective contract past the
        // deployment's own static fallback (here: `None`, i.e. no boundary at all).
        let files = vec![(
            ARCH_MANIFEST_PATH.to_string(),
            "{ not valid json".to_string(),
        )];
        assert!(repo_layer_contract(&files, None).is_none());
    }
}
