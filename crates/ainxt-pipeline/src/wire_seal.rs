// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! **Wire-policy sealing** (`CODE_REVIEW_PIPELINE.md` §2/§7/§8 + `SEMANTIC_EDITING.md` §2/§6) — the
//! boundary that makes the Commit Gate's policy *server-derived and un-forgeable by the client*.
//!
//! [`crate::selfheal::SelfHealConfig`] is a `Deserialize` struct carried verbatim as
//! [`crate::edit_turn::EditRequest::config`], so **every** field in it arrives from the wire. Two of
//! those fields are not the requester's to state:
//!
//! - **`policy: GatePolicy`** — the auto-complete / review / trivial-floor thresholds are *deployment
//!   policy* ("score >= auto_complete_threshold (policy, e.g. 90)"). A caller holding
//!   `CAP_EDIT_APPLY` that posts `auto_complete_threshold: 0` would auto-complete any Tier-0/1 edit
//!   at Confidence 0. The gate is the runtime's decision, not the requester's — so the wire value is
//!   **discarded** and replaced by the [`DeploymentEditPolicy`] the engine was assembled with.
//! - **`rung: Rung`** — the ladder rung is *what the engine actually resolved at*, and it drives both
//!   the Confidence Score's fidelity penalty (`Rung::confidence_penalty`, −8 for a text patch) and
//!   the `TextPatch ⇒ Moderate` risk escalation that forces the mandatory-Judge gate. On
//!   `POST /v1/edit` nothing runs the ladder — the body carries an already-resolved `applied_files`
//!   set — so a body declaring `rung: "lsp"` for a raw text patch erases both. The wire value is
//!   therefore treated as a **floor only**: the rung is [`derive_rung`]d from the actual diff + AST
//!   and the *least-trusted* of (declared, derived) wins. A client can make itself look worse, never
//!   better, and [`Rung::Lsp`] is **structurally unreachable** from this path (only a real
//!   [`crate::semantic_turn`] ladder run, with a live language-server driver, can record rung 1).
//!
//! Two further fields are sealed for the same reason: `judge_approved` (a verdict only a real
//! context-isolated [`ainxt_judge::JudgePanel`] may produce — §5) and `max_rounds` (a spend budget).
//! `tier` is *not* sealed here because it is already escalate-only downstream
//! ([`crate::classify::classify_edit`]): a declared tier is a floor that classification can only
//! raise.
//!
//! Everything here is pure, deterministic, offline: no I/O, no clock, no model.

use crate::capability::Language;
use crate::gate::GatePolicy;
use crate::selfheal::SelfHealConfig;
use ainxt_semantic::ladder::Rung;
use ainxt_semantic::{first_parse_error_line, list_definitions, Language as SemLang};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The **deployment's** edit policy — the half of [`SelfHealConfig`] that is policy rather than
/// request. A surface constructs one at startup (from its config file) and hands it to
/// [`crate::edit_turn::EditEngine::with_edit_policy`]; it is never deserialized from a turn body.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct DeploymentEditPolicy {
    /// The Commit Gate thresholds. Replaces whatever the wire declared.
    pub gate: GatePolicy,
    /// Hard ceiling on the self-heal round budget a request may ask for (spend control).
    pub max_rounds_cap: u8,
    /// Ceiling on the caller-*declared* blast-radius test coverage. Coverage is a measurement, not a
    /// request field: when the stage-8 semantic seam is wired the loop computes it from the test
    /// call-graph and this is irrelevant; when it is not wired, a declared `1.0` would silently erase
    /// the whole `30 * (1 - coverage)` regression term. Default `1.0` preserves the historical
    /// behaviour; a deployment with no stage-8 seam should lower it.
    pub max_declared_coverage: f64,
}

impl Default for DeploymentEditPolicy {
    fn default() -> Self {
        DeploymentEditPolicy {
            gate: GatePolicy::default(),
            max_rounds_cap: 5,
            max_declared_coverage: 1.0,
        }
    }
}

/// What the seal actually changed, one line per overridden field — journaled/returned so the
/// override is auditable rather than silent (a caller that posted a forged threshold sees exactly
/// which field the runtime replaced, and a regulator reading the trail sees the same).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireSealReport {
    pub overrides: Vec<String>,
    /// The rationale from [`derive_rung`] (why the rung resolved where it did).
    pub rung_rationale: Vec<String>,
}

impl WireSealReport {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.overrides.is_empty()
    }
}

/// The rung the diff can actually be *evidenced* at, plus the auditable reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RungDerivation {
    pub rung: Rung,
    pub rationale: Vec<String>,
}

/// Map the pipeline's capability language to the AST engine's grammar set. Deliberately broader than
/// [`crate::classify`]'s (which is Rust/Python only): rung derivation *degrades* on a missing grammar,
/// so covering more grammars can only make the derived rung more accurate, never more permissive.
fn sem_lang(lang: Language) -> Option<SemLang> {
    match lang {
        Language::Rust => Some(SemLang::Rust),
        Language::Python => Some(SemLang::Python),
        Language::Go => Some(SemLang::Go),
        Language::JavaScript => Some(SemLang::JavaScript),
        Language::TypeScript => Some(SemLang::TypeScript),
        Language::Java => Some(SemLang::Java),
        Language::Cobol | Language::Other => None,
    }
}

/// The source with every top-level definition span removed, then comment/format-normalized — the
/// "scaffolding" an AST-precise edit engine would leave untouched. Two versions of a file whose
/// residues match differ **only inside whole definitions**, which is exactly the class of change the
/// AST rung ([`ainxt_semantic::replace_function`] / `ops`) can produce.
fn definition_residue(src: &str, sl: SemLang, lang: Language) -> String {
    let mut spans: Vec<(usize, usize)> = list_definitions(src, sl)
        .map(|ds| {
            ds.iter()
                .map(|d| (d.span.start_byte, d.span.end_byte))
                .collect()
        })
        .unwrap_or_default();
    spans.sort_unstable();
    // Merge overlapping/nested spans (a method inside an impl block, a nested closure definition).
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(spans.len());
    for (s, e) in spans {
        match merged.last_mut() {
            Some(last) if s <= last.1 => last.1 = last.1.max(e),
            _ => merged.push((s, e)),
        }
    }
    let mut out = String::with_capacity(src.len());
    let mut cur = 0usize;
    for (s, e) in merged {
        if s > cur {
            out.push_str(src.get(cur..s).unwrap_or(""));
        }
        cur = cur.max(e);
    }
    if cur < src.len() {
        out.push_str(src.get(cur..).unwrap_or(""));
    }
    crate::classify::code_signature(lang, &out)
}

/// The rung a single changed file's diff can be evidenced at. Never [`Rung::Lsp`].
fn derive_file_rung(lang: Language, path: &str, old: &str, new: &str) -> (Rung, String) {
    let Some(sl) = sem_lang(lang) else {
        return (
            Rung::TextPatch,
            format!("{path}: no AST grammar for {lang:?} — content-level patch, cannot be evidenced above the text rung"),
        );
    };
    // A file the engine cannot re-parse after the edit was not produced by any structural rung.
    match first_parse_error_line(new, sl) {
        Ok(None) => {}
        Ok(Some(line)) => {
            return (
                Rung::TextPatch,
                format!("{path}: post-edit content has a parse error at line {line} — text rung"),
            )
        }
        Err(_) => {
            return (
                Rung::TextPatch,
                format!("{path}: post-edit content is not parseable — text rung"),
            )
        }
    }
    if old.is_empty() {
        return (
            Rung::Ast,
            format!("{path}: new file, parses cleanly — AST rung"),
        );
    }
    if !matches!(first_parse_error_line(old, sl), Ok(None)) {
        return (
            Rung::StructuredPatch,
            format!("{path}: pre-edit content does not parse — no AST diff possible, structured-patch rung"),
        );
    }
    if definition_residue(old, sl, lang) == definition_residue(new, sl, lang) {
        (
            Rung::Ast,
            format!("{path}: change is confined to whole definition spans — AST rung"),
        )
    } else {
        (
            Rung::StructuredPatch,
            format!(
                "{path}: change touches source outside any definition span — structured-patch rung"
            ),
        )
    }
}

/// **Derive the edit-engine rung from the actual change** (`SEMANTIC_EDITING.md` §2/§6), rather than
/// believing the wire.
///
/// The rung recorded for a turn is the *least-trusted* rung across the edit set (the design's "lowest
/// rung used across the edit set"). [`Rung::Lsp`] is never returned: rung 1 means a language server
/// computed the refactor, which only [`crate::semantic_turn`] can witness — a `POST /v1/edit` body
/// carrying already-resolved file contents has no such evidence, and claiming it would erase both the
/// −8 fidelity penalty and the `TextPatch ⇒ Moderate` escalation that forces the mandatory Judge.
#[must_use]
pub fn derive_rung(
    lang: Language,
    original: &[(String, String)],
    applied: &[(String, String)],
) -> RungDerivation {
    let orig: BTreeMap<&str, &str> = original
        .iter()
        .map(|(p, c)| (p.as_str(), c.as_str()))
        .collect();
    let mut worst = Rung::Ast;
    let mut rationale = Vec::new();
    let mut changed = 0usize;
    for (path, new_src) in applied {
        let old = orig.get(path.as_str()).copied().unwrap_or("");
        if old == new_src.as_str() {
            continue;
        }
        changed += 1;
        let (r, why) = derive_file_rung(lang, path, old, new_src);
        rationale.push(why);
        worst = worst.max(r);
    }
    if changed == 0 {
        rationale.push("no file content changed — nothing to evidence".to_string());
    }
    RungDerivation {
        rung: worst,
        rationale,
    }
}

/// **Seal a wire-supplied [`SelfHealConfig`] against the deployment's policy.** Called at the wire
/// boundary (`POST /v1/edit`), before the turn is assembled and before any stage runs.
///
/// Post-conditions (each one an invariant a test asserts):
/// 1. `out.policy == deployment.gate` — the caller's thresholds are gone, whatever they were.
/// 2. `out.rung == max(declared, derive_rung(..))` — worse-or-equal; `Lsp` unreachable.
/// 3. `out.judge_approved.is_none()` — only a real context-isolated panel run may set it (§5).
/// 4. `out.max_rounds <= deployment.max_rounds_cap`.
/// 5. `out.blast_radius_test_coverage <= deployment.max_declared_coverage`.
/// 6. `out.tier == in.tier` — the declared tier stays a *floor*; escalation happens downstream.
#[must_use]
pub fn seal_wire_config(
    cfg: SelfHealConfig,
    original: &[(String, String)],
    applied: &[(String, String)],
    deployment: &DeploymentEditPolicy,
) -> (SelfHealConfig, WireSealReport) {
    let mut out = cfg;
    let mut report = WireSealReport::default();

    if out.policy != deployment.gate {
        report.overrides.push(format!(
            "gate policy: wire-declared {:?} discarded → deployment policy {:?} (§8: thresholds are \
             deployment policy, not a request field)",
            out.policy, deployment.gate
        ));
        out.policy = deployment.gate;
    }

    let derived = derive_rung(out.lang, original, applied);
    let effective = out.rung.max(derived.rung);
    if effective != out.rung {
        report.overrides.push(format!(
            "edit rung: wire-declared {} not evidenced by the diff → derived {} (least-trusted of the \
             two; a declared rung is a floor, never an upgrade)",
            out.rung.as_str(),
            effective.as_str()
        ));
    }
    out.rung = effective;
    report.rung_rationale = derived.rationale;

    if out.judge_approved.is_some() {
        report.overrides.push(
            "judge_approved: a wire-asserted Judge verdict is not an independent adjudication (§5) → \
             cleared; only a context-isolated panel run may set it"
                .to_string(),
        );
        out.judge_approved = None;
    }

    if out.max_rounds > deployment.max_rounds_cap {
        report.overrides.push(format!(
            "max_rounds: {} clamped to the deployment cap {}",
            out.max_rounds, deployment.max_rounds_cap
        ));
        out.max_rounds = deployment.max_rounds_cap;
    }

    if out.blast_radius_test_coverage > deployment.max_declared_coverage {
        report.overrides.push(format!(
            "blast_radius_test_coverage: declared {:.2} clamped to the deployment ceiling {:.2} \
             (coverage is measured by stage 8, not declared)",
            out.blast_radius_test_coverage, deployment.max_declared_coverage
        ));
        out.blast_radius_test_coverage = deployment.max_declared_coverage;
    }

    (out, report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(p: &str, c: &str) -> (String, String) {
        (p.to_string(), c.to_string())
    }

    #[test]
    fn declared_lsp_rung_on_a_raw_text_patch_is_derived_down() {
        let orig = vec![f("a.rs", "fn a() { 1 }\n")];
        // Unparseable garbage: no structural rung could have produced it.
        let applied = vec![f("a.rs", "fn a() { 1 }\n@@@ not rust @@@\n")];
        let d = derive_rung(Language::Rust, &orig, &applied);
        assert_eq!(d.rung, Rung::TextPatch);
    }

    #[test]
    fn body_only_change_derives_the_ast_rung() {
        let orig = vec![f("a.rs", "fn a() -> i32 { 1 }\n")];
        let applied = vec![f("a.rs", "fn a() -> i32 { 2 }\n")];
        assert_eq!(derive_rung(Language::Rust, &orig, &applied).rung, Rung::Ast);
    }

    #[test]
    fn derivation_never_returns_the_lsp_rung() {
        let orig = vec![f("a.rs", "fn a() -> i32 { 1 }\n")];
        let applied = vec![f("a.rs", "fn a() -> i32 { 2 }\n")];
        assert_ne!(derive_rung(Language::Rust, &orig, &applied).rung, Rung::Lsp);
    }

    #[test]
    fn no_grammar_language_is_the_text_rung() {
        let orig = vec![f("a.cbl", "MOVE 1 TO X.\n")];
        let applied = vec![f("a.cbl", "MOVE 2 TO X.\n")];
        assert_eq!(
            derive_rung(Language::Cobol, &orig, &applied).rung,
            Rung::TextPatch
        );
    }

    #[test]
    fn seal_replaces_a_forged_zero_threshold_policy() {
        let cfg = SelfHealConfig {
            policy: GatePolicy {
                auto_complete_threshold: 0,
                review_threshold: 0,
                trivial_auto_approve_floor: 0,
            },
            ..Default::default()
        };
        let orig = vec![f("a.rs", "fn a() -> i32 { 1 }\n")];
        let applied = vec![f("a.rs", "fn a() -> i32 { 2 }\n")];
        let (sealed, report) =
            seal_wire_config(cfg, &orig, &applied, &DeploymentEditPolicy::default());
        assert_eq!(sealed.policy, GatePolicy::default());
        assert!(!report.is_empty());
    }

    #[test]
    fn seal_clears_a_wire_asserted_judge_verdict_and_caps_rounds() {
        let cfg = SelfHealConfig {
            judge_approved: Some(true),
            max_rounds: 200,
            ..Default::default()
        };
        let (sealed, _) = seal_wire_config(cfg, &[], &[], &DeploymentEditPolicy::default());
        assert!(sealed.judge_approved.is_none());
        assert_eq!(sealed.max_rounds, 5);
    }

    #[test]
    fn seal_keeps_the_declared_tier_as_a_floor() {
        let cfg = SelfHealConfig {
            tier: crate::risk::RiskTier::Moderate,
            ..Default::default()
        };
        let (sealed, _) = seal_wire_config(cfg, &[], &[], &DeploymentEditPolicy::default());
        assert_eq!(sealed.tier, crate::risk::RiskTier::Moderate);
    }

    #[test]
    fn a_declared_worse_rung_is_kept() {
        let cfg = SelfHealConfig {
            rung: Rung::TextPatch,
            ..Default::default()
        };
        let orig = vec![f("a.rs", "fn a() -> i32 { 1 }\n")];
        let applied = vec![f("a.rs", "fn a() -> i32 { 2 }\n")];
        let (sealed, _) = seal_wire_config(cfg, &orig, &applied, &DeploymentEditPolicy::default());
        assert_eq!(sealed.rung, Rung::TextPatch);
    }
}
