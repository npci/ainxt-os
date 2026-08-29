// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Scored indirect-injection detector (ADR-009).
//!
//! This is the real detection engine behind the [`crate::InjectionScanner`] seam. It replaces the
//! original fixed substring list with a **weighted, multi-signal score**:
//!
//! * **phrase signals** — the specific coercion phrasings (instruction-override, action-coercion,
//!   prompt-exfiltration, …) that are unambiguous in untrusted DATA. The lexicon is **not
//!   English-only**: it carries the same coercion families in the major languages AiNxt serves
//!   (Devanagari Hindi + Hinglish transliteration, plus Spanish/French/German/Portuguese/Russian/
//!   Chinese/Arabic/Japanese), because this is a multilingual deployment and a Hindi or
//!   regional injection must not fall through to only the language-neutral signals;
//! * **homoglyph / mixed-script evasion** — an attacker who writes `іgnоre prеvious` with Cyrillic
//!   look-alike letters defeats a raw substring list; the detector folds Unicode confusables back
//!   to ASCII and re-scans, and a coercion phrase revealed only *after* de-homoglyphing is treated
//!   as deliberate obfuscation (a novel-phrasing evasion), while Latin/Cyrillic-or-Greek script
//!   mixing inside a single token is a weak corroborating signal on its own;
//! * **imperative-verb** — a command sentence *directed at the assistant* (a base-form verb at the
//!   start of a sentence/line), which alone is weak but corroborates other signals;
//! * **role-spoof** — content forging a system/assistant turn (`system:`, ChatML tokens,
//!   `you are now …`) to impersonate a trusted role;
//! * **tool-invocation** — untrusted content asking to call a tool/function, or *naming an internal
//!   tool* (a caller-supplied allow-list makes this a strong signal — a document should never name
//!   your private tools);
//! * **encoded-payload** — base64 / hex / percent-encoded blobs and zero-width / bidi control
//!   characters used to smuggle instructions past a naive substring scan; encoded blobs are
//!   *decoded and re-scanned*, so a base64-hidden "ignore previous instructions" is still caught.
//!
//! Signals are grouped by category (max weight per category) and summed, clamped to `1.0`. A turn
//! is `Suspicious` once the score crosses the configured threshold — so a lone weak signal (e.g. a
//! bare imperative in a legitimate runbook) does **not** flag, but corroborating signals do. This is
//! the "scored, not a fixed list" property the audit demands, and it is fully deterministic
//! (no clock, no rng).

use crate::{InjectionScanner, InjectionVerdict, Provenance};
use std::collections::BTreeMap;

/// One contributing detection signal.
#[derive(Debug, Clone, PartialEq)]
pub struct DetectionSignal {
    /// Stable taxonomy label (e.g. `"instruction-override"`, `"encoded-payload"`).
    pub category: &'static str,
    /// This signal's contribution weight in `[0.0, 1.0]`.
    pub weight: f32,
    /// Human-readable evidence (the matched phrase / decoded fragment / marker).
    pub evidence: String,
}

/// The full scored assessment of one piece of untrusted content.
#[derive(Debug, Clone, PartialEq)]
pub struct InjectionAssessment {
    /// Combined score in `[0.0, 1.0]` (per-category max, summed, clamped).
    pub score: f32,
    /// Every signal that fired, in detection order.
    pub signals: Vec<DetectionSignal>,
}

impl InjectionAssessment {
    /// No signals fired at all.
    pub fn is_empty(&self) -> bool {
        self.signals.is_empty()
    }
    /// Distinct categories that fired, sorted and de-duplicated.
    pub fn categories(&self) -> Vec<&'static str> {
        let mut c: Vec<&'static str> = self.signals.iter().map(|s| s.category).collect();
        c.sort_unstable();
        c.dedup();
        c
    }
    /// One reason string per signal, `"{category}: {evidence}"`.
    pub fn reasons(&self) -> Vec<String> {
        self.signals
            .iter()
            .map(|s| format!("{}: {}", s.category, s.evidence))
            .collect()
    }
}

/// Configurable scored detector. `Default` uses `suspicious_threshold = 0.5` and no known tools.
#[derive(Debug, Clone)]
pub struct InjectionDetector {
    /// Score at/above which a turn is reported `Suspicious`.
    pub suspicious_threshold: f32,
    /// Internal tool names. If any appears verbatim in untrusted content it is a strong signal —
    /// an external document should never reference your private tool registry.
    pub known_tool_names: Vec<String>,
    /// Weight of a **directed** compositional override (an override-class token aimed at the prior
    /// directions inside one sentence). Defaults to `0.5` — crosses the default threshold alone.
    pub compositional_weight: f32,
    /// Weight for descriptive third-person prose ("the bank *may revoke* the mandate") rather
    /// than instructions aimed at the assistant. Defaults to `0.25` — below the default threshold,
    /// so ordinary business prose corroborates but never taints a turn on its own.
    pub descriptive_weight: f32,
}

impl Default for InjectionDetector {
    fn default() -> Self {
        InjectionDetector {
            suspicious_threshold: 0.5,
            known_tool_names: Vec::new(),
            compositional_weight: 0.5,
            descriptive_weight: 0.25,
        }
    }
}

impl InjectionDetector {
    /// Builder: supply the internal tool-name allow-list to strengthen tool-coercion detection.
    pub fn with_tools(mut self, tools: impl IntoIterator<Item = String>) -> Self {
        self.known_tool_names = tools.into_iter().collect();
        self
    }

    /// Builder: override the suspicious threshold (clamped to `[0.0, 1.0]`).
    pub fn with_threshold(mut self, t: f32) -> Self {
        self.suspicious_threshold = t.clamp(0.0, 1.0);
        self
    }

    /// Builder: set compositional weights (directed/descriptive), clamped `[0.0, 1.0]`.
    /// Exposed for config-tuned false-positive tolerance without forking the detector.
    pub fn with_compositional_weights(mut self, directed: f32, descriptive: f32) -> Self {
        self.compositional_weight = directed.clamp(0.0, 1.0);
        self.descriptive_weight = descriptive.clamp(0.0, 1.0);
        self
    }

    /// Produce the full scored assessment. Trusted content (user-authored) always scores `0.0`.
    pub fn assess(&self, text: &str, provenance: Provenance) -> InjectionAssessment {
        if provenance.is_trusted() {
            return InjectionAssessment {
                score: 0.0,
                signals: Vec::new(),
            };
        }
        self.assess_text(text)
    }

    /// Provenance-agnostic scoring core: run every layer regardless of trust.
    /// For callers that own the trust decision (e.g. guardrails jailbreak rail).
    /// [`Self::assess`] is the provenance-gated wrapper (trusted → 0.0).
    pub fn assess_text(&self, text: &str) -> InjectionAssessment {
        let mut signals: Vec<DetectionSignal> = Vec::new();
        let lower = text.to_lowercase();

        scan_phrases_into(&lower, "", &mut signals);
        scan_multilingual_into(&lower, "", &mut signals);
        self.compositional(&lower, "", &mut signals);
        self.homoglyph(&lower, &mut signals);
        detect_imperative(&lower, &mut signals);
        detect_role_spoof(&lower, &mut signals);
        detect_tool_invocation(&lower, &self.known_tool_names, &mut signals);
        detect_encoded_payloads(text, &lower, &mut signals);

        let score = combined_score(&signals);
        InjectionAssessment { score, signals }
    }

    fn compositional(&self, lower: &str, prefix: &str, out: &mut Vec<DetectionSignal>) {
        detect_compositional_override_weighted(
            lower,
            prefix,
            self.compositional_weight,
            self.descriptive_weight,
            out,
        );
    }

    fn homoglyph(&self, lower: &str, out: &mut Vec<DetectionSignal>) {
        detect_homoglyph_evasion_weighted(
            lower,
            self.compositional_weight,
            self.descriptive_weight,
            out,
        );
    }
}

// ---------------- evasion-only layers (reused by the guardrails jailbreak rail) ----------------

/// Which evasion/paraphrase layers [`evasion_assessment`] runs, and at what weight.
/// These make the detector robust to rewording/obfuscation — as opposed to the untrusted-content
/// signals (imperative-verb, role-spoof, tool-invocation) that only apply to DATA.
#[derive(Debug, Clone)]
pub struct EvasionLayers {
    /// Multilingual coercion lexicon (Hindi/Hinglish/Spanish/French/German/Portuguese/Russian/
    /// Chinese/Arabic/Japanese).
    pub multilingual: bool,
    /// Compositional (co-occurrence) override — catches novel/reworded phrasings.
    pub compositional: bool,
    /// Homoglyph / mixed-script fold-and-rescan.
    pub homoglyph: bool,
    /// base64 / hex / percent decode-and-rescan + zero-width/bidi smuggling.
    pub encoded: bool,
    /// Weight for a *directed* compositional override.
    pub compositional_weight: f32,
    /// Weight for a *descriptive* compositional co-occurrence.
    pub descriptive_weight: f32,
}

impl Default for EvasionLayers {
    fn default() -> Self {
        EvasionLayers {
            multilingual: true,
            compositional: true,
            homoglyph: true,
            encoded: true,
            compositional_weight: 0.5,
            descriptive_weight: 0.25,
        }
    }
}

/// Run only the evasion/paraphrase layers over `text` (provenance-agnostic). This is the seam
/// `ainxt-guardrails`' jailbreak rail reuses so USER-side jailbreak detection inherits the SAME
/// multilingual lexicon, compositional-override, homoglyph fold-and-rescan and base64/hex/percent
/// decode-and-rescan coverage as the indirect-injection detector — instead of maintaining a second,
/// English-only substring table. The English phrase table is deliberately NOT included: its
/// action-coercion / exfiltration entries ("send an email", "forward this") are legitimate USER
/// requests and would misfire on the input path; they remain part of the untrusted-content detector.
pub fn evasion_assessment(text: &str, layers: &EvasionLayers) -> InjectionAssessment {
    let lower = text.to_lowercase();
    let mut signals: Vec<DetectionSignal> = Vec::new();
    if layers.multilingual {
        scan_multilingual_into(&lower, "", &mut signals);
    }
    if layers.compositional {
        detect_compositional_override_weighted(
            &lower,
            "",
            layers.compositional_weight,
            layers.descriptive_weight,
            &mut signals,
        );
    }
    if layers.homoglyph {
        detect_homoglyph_evasion_weighted(
            &lower,
            layers.compositional_weight,
            layers.descriptive_weight,
            &mut signals,
        );
    }
    if layers.encoded {
        detect_encoded_payloads(text, &lower, &mut signals);
    }
    let score = combined_score(&signals);
    InjectionAssessment { score, signals }
}

impl InjectionScanner for InjectionDetector {
    fn scan(&self, text: &str, provenance: Provenance) -> InjectionVerdict {
        let a = self.assess(text, provenance);
        if !a.is_empty() && a.score >= self.suspicious_threshold {
            InjectionVerdict::Suspicious(a.reasons())
        } else {
            InjectionVerdict::Clean
        }
    }
}

// ---------------- ML/NLI classifier seam (ADR-009) ----------------

/// The ML seam for indirect-injection detection — the mirror of the guardrails `TextClassifier`.
/// A production deployment plugs a fine-tuned prompt-injection / NLI classifier in here; offline /
/// air-gapped deployments simply omit it and keep only the deterministic heuristic. Trusted
/// (user-authored) content is never passed to the model — provenance is supplied so the classifier
/// may condition on the source, but the [`MlAugmentedDetector`] short-circuits trusted content to
/// `0.0` before ever calling it (fail-safe: no cost, no exposure on trusted input).
pub trait InjectionModel: Send + Sync {
    /// Probability-like score in `[0.0, 1.0]` that untrusted `text` carries an injection.
    fn injection_score(&self, text: &str, provenance: Provenance) -> f32;
}

/// Wraps a heuristic [`InjectionDetector`] with an ML [`InjectionModel`], combining them as
/// `max(heuristic, model)` — exactly like the guardrails rails' `max(heuristic, classifier)` floor.
/// The model can only ever make detection *stricter*: a paraphrased/novel injection the phrase and
/// compositional tables miss is still caught by the model, while a model that goes soft can never
/// lower the deterministic floor. Implements [`InjectionScanner`] so it drops straight into the
/// runtime's existing scanner seam.
pub struct MlAugmentedDetector {
    base: InjectionDetector,
    model: Box<dyn InjectionModel>,
}

impl MlAugmentedDetector {
    pub fn new(base: InjectionDetector, model: Box<dyn InjectionModel>) -> Self {
        MlAugmentedDetector { base, model }
    }

    /// Combined score `max(heuristic, model)`. Trusted content short-circuits to `0.0` (the model is
    /// never invoked on user-authored input).
    pub fn score(&self, text: &str, provenance: Provenance) -> f32 {
        if provenance.is_trusted() {
            return 0.0;
        }
        let heuristic = self.base.assess(text, provenance).score;
        let ml = self.model.injection_score(text, provenance).clamp(0.0, 1.0);
        heuristic.max(ml)
    }
}

impl InjectionScanner for MlAugmentedDetector {
    fn scan(&self, text: &str, provenance: Provenance) -> InjectionVerdict {
        if provenance.is_trusted() {
            return InjectionVerdict::Clean;
        }
        let a = self.base.assess(text, provenance);
        let score = self.score(text, provenance);
        if score >= self.base.suspicious_threshold {
            // Keep the heuristic's reasons; name the model when it — not the phrase table — crossed.
            let mut reasons = a.reasons();
            if score > a.score + f32::EPSILON {
                reasons.push(format!("ml-classifier: injection score {score:.2}"));
            }
            if reasons.is_empty() {
                reasons.push(format!("ml-classifier: injection score {score:.2}"));
            }
            InjectionVerdict::Suspicious(reasons)
        } else {
            InjectionVerdict::Clean
        }
    }
}

/// Group signals by category, take the max weight per category, sum across categories, clamp to 1.0.
fn combined_score(signals: &[DetectionSignal]) -> f32 {
    let mut per: BTreeMap<&'static str, f32> = BTreeMap::new();
    for s in signals {
        let e = per.entry(s.category).or_insert(0.0);
        if s.weight > *e {
            *e = s.weight;
        }
    }
    per.values().sum::<f32>().min(1.0)
}

// ---------------- phrase table ----------------

/// (substring, category, weight). Weights are tuned so a single unambiguous coercion phrase
/// (`>= 0.5`) crosses the default threshold on its own, while softer phrasings need corroboration.
const PHRASES: &[(&str, &str, f32)] = &[
    // instruction override
    ("ignore previous", "instruction-override", 0.5),
    ("ignore all previous", "instruction-override", 0.5),
    ("ignore the above", "instruction-override", 0.5),
    ("ignore prior", "instruction-override", 0.5),
    ("ignore your instructions", "instruction-override", 0.5),
    ("disregard the above", "instruction-override", 0.5),
    ("disregard previous", "instruction-override", 0.5),
    ("disregard prior", "instruction-override", 0.5),
    ("disregard your instructions", "instruction-override", 0.5),
    ("forget previous", "instruction-override", 0.5),
    ("forget all previous", "instruction-override", 0.5),
    ("forget everything", "instruction-override", 0.45),
    ("new instructions", "instruction-override", 0.4),
    ("updated instructions", "instruction-override", 0.4),
    ("override your", "instruction-override", 0.45),
    ("do not follow", "instruction-override", 0.3),
    // prompt / policy exfiltration
    ("system prompt", "prompt-exfiltration", 0.45),
    ("reveal your", "prompt-exfiltration", 0.45),
    ("print your instructions", "prompt-exfiltration", 0.45),
    ("show me your instructions", "prompt-exfiltration", 0.45),
    ("repeat your system", "prompt-exfiltration", 0.45),
    ("what are your instructions", "prompt-exfiltration", 0.4),
    ("your hidden", "prompt-exfiltration", 0.3),
    // role hijack
    ("you must now", "role-hijack", 0.45),
    ("you are now", "role-hijack", 0.45),
    ("you should now", "role-hijack", 0.4),
    ("from now on you", "role-hijack", 0.4),
    ("act as if you", "role-hijack", 0.4),
    ("pretend to be", "role-hijack", 0.4),
    ("pretend you are", "role-hijack", 0.4),
    // exfiltration (outbound)
    ("send an email", "exfiltration", 0.4),
    ("send email to", "exfiltration", 0.4),
    ("forward this", "exfiltration", 0.4),
    ("exfiltrate", "exfiltration", 0.5),
    ("upload it to", "exfiltration", 0.4),
    ("post it to", "exfiltration", 0.4),
    ("leak the", "exfiltration", 0.4),
    // financial action coercion
    ("transfer all", "action-coercion", 0.5),
    ("transfer to account", "action-coercion", 0.5),
    ("wire all", "action-coercion", 0.5),
    ("move all funds", "action-coercion", 0.5),
    ("initiate a payment", "action-coercion", 0.4),
    // tool coercion (phrase-level; structural detection adds more)
    ("call the tool", "tool-coercion", 0.4),
    ("call the function", "tool-coercion", 0.4),
    ("invoke the tool", "tool-coercion", 0.4),
    ("invoke the function", "tool-coercion", 0.4),
    // destructive
    ("delete all", "destructive-coercion", 0.5),
    ("drop table", "destructive-coercion", 0.5),
    ("rm -rf", "destructive-coercion", 0.5),
    ("truncate table", "destructive-coercion", 0.45),
];

/// Scan `lower` for every phrase and push a signal per match (deduped by phrase per call site).
fn scan_phrases_into(lower: &str, evidence_prefix: &str, out: &mut Vec<DetectionSignal>) {
    for &(pat, cat, weight) in PHRASES {
        if lower.contains(pat) {
            out.push(DetectionSignal {
                category: cat,
                weight,
                evidence: format!("{evidence_prefix}{pat:?}"),
            });
        }
    }
}

// ---------------- multilingual coercion lexicon ----------------

/// (substring, category, weight) in the languages AiNxt actually serves. Weights mirror the English
/// table so a single unambiguous non-English coercion (`>= 0.5`) crosses the default threshold on
/// its own — a Hindi/regional injection is no longer dependent on role-spoof/encoding to fire.
///
/// Entries are matched case-insensitively against `text.to_lowercase()`. For scripts with case
/// (Latin/Cyrillic) the pattern is stored lower-case; case-less scripts (Devanagari, CJK, Arabic)
/// are unaffected by lowering. Patterns are deliberately short *stems* (e.g. the verb + object head)
/// so inflection/spacing variation around them does not defeat the match.
const MULTILINGUAL_PHRASES: &[(&str, &str, f32)] = &[
    // ---- Hindi (Devanagari) ----
    ("नज़रअंदाज़", "instruction-override", 0.5),  // "ignore"
    ("नजरअंदाज", "instruction-override", 0.5),  // "ignore" (no nuqta)
    ("अनदेखा कर", "instruction-override", 0.5), // "disregard / overlook"
    ("भूल जाओ", "instruction-override", 0.5),   // "forget"
    ("भूल जा", "instruction-override", 0.45),
    ("पिछले निर्देश", "instruction-override", 0.45), // "previous instructions"
    ("नए निर्देश", "instruction-override", 0.4),    // "new instructions"
    ("सिस्टम प्रॉम्प्ट", "prompt-exfiltration", 0.45), // "system prompt"
    ("अपने निर्देश दिखा", "prompt-exfiltration", 0.45), // "show your instructions"
    ("सारे पैसे भेज", "action-coercion", 0.5),        // "send all the money"
    ("सारा पैसा भेज", "action-coercion", 0.5),
    ("पैसे ट्रांसफर", "action-coercion", 0.5), // "transfer money"
    ("पैसा ट्रांसफर", "action-coercion", 0.5),
    ("स्थानांतरित कर", "action-coercion", 0.45), // "transfer"
    ("सभी हटा", "destructive-coercion", 0.5),  // "delete all"
    ("सब कुछ हटा", "destructive-coercion", 0.5),
    ("डिलीट कर", "destructive-coercion", 0.45), // "delete"
    // ---- Hinglish / romanised Hindi (Latin script) ----
    ("nazarandaaz", "instruction-override", 0.5),
    ("nazar andaaz", "instruction-override", 0.5),
    ("andekha kar", "instruction-override", 0.45),
    ("bhool jao", "instruction-override", 0.5),
    ("bhool ja", "instruction-override", 0.45),
    ("pichle nirdesh", "instruction-override", 0.45),
    ("saara paisa bhej", "action-coercion", 0.5),
    ("saare paise bhej", "action-coercion", 0.5),
    ("paisa transfer", "action-coercion", 0.5),
    ("paise transfer", "action-coercion", 0.5),
    ("sab kuch delete", "destructive-coercion", 0.5),
    ("sabhi delete", "destructive-coercion", 0.45),
    ("hata do", "destructive-coercion", 0.45),
    // ---- Spanish ----
    ("ignora las instrucciones", "instruction-override", 0.5),
    ("ignora todas las", "instruction-override", 0.5),
    ("ignora las anteriores", "instruction-override", 0.5),
    ("olvida las instrucciones", "instruction-override", 0.5),
    ("transfiere todo", "action-coercion", 0.5),
    ("envía todo el dinero", "action-coercion", 0.5),
    ("elimina todo", "destructive-coercion", 0.5),
    ("borra todo", "destructive-coercion", 0.5),
    // ---- French ----
    ("ignore les instructions", "instruction-override", 0.5),
    ("ignorez les instructions", "instruction-override", 0.5),
    ("oublie les instructions", "instruction-override", 0.5),
    ("transférez tout", "action-coercion", 0.5),
    ("transfère tout", "action-coercion", 0.5),
    ("supprime tout", "destructive-coercion", 0.5),
    // ---- German ----
    ("ignoriere die anweisungen", "instruction-override", 0.5),
    ("ignoriere alle vorherigen", "instruction-override", 0.5),
    ("vergiss die anweisungen", "instruction-override", 0.5),
    ("überweise alles", "action-coercion", 0.5),
    ("lösche alle", "destructive-coercion", 0.5),
    // ---- Portuguese ----
    ("ignore as instruções", "instruction-override", 0.5),
    ("ignore todas as anteriores", "instruction-override", 0.5),
    ("transfira tudo", "action-coercion", 0.5),
    ("apague tudo", "destructive-coercion", 0.5),
    // ---- Russian (Cyrillic) ----
    ("игнорируй", "instruction-override", 0.5), // "ignore"
    ("игнорируйте", "instruction-override", 0.5),
    ("забудь предыдущие", "instruction-override", 0.5), // "forget previous"
    ("переведи все деньги", "action-coercion", 0.5),    // "transfer all money"
    ("удали все", "destructive-coercion", 0.5),         // "delete all"
    // ---- Chinese (Simplified) ----
    ("忽略之前", "instruction-override", 0.5), // "ignore previous"
    ("忽略所有", "instruction-override", 0.5), // "ignore all"
    ("忘记之前", "instruction-override", 0.5), // "forget previous"
    ("转移所有资金", "action-coercion", 0.5),  // "transfer all funds"
    ("转账", "action-coercion", 0.4),          // "transfer / remit"
    ("删除所有", "destructive-coercion", 0.5), // "delete all"
    ("系统提示词", "prompt-exfiltration", 0.45), // "system prompt"
    // ---- Arabic ----
    ("تجاهل التعليمات", "instruction-override", 0.5), // "ignore the instructions"
    ("تجاهل جميع", "instruction-override", 0.5),      // "ignore all"
    ("حوّل كل الأموال", "action-coercion", 0.5),        // "transfer all money"
    ("احذف كل", "destructive-coercion", 0.5),         // "delete all"
    // ---- Japanese ----
    ("以前の指示を無視", "instruction-override", 0.5), // "ignore previous instructions"
    ("すべて無視", "instruction-override", 0.45),
    ("全額送金", "action-coercion", 0.5), // "remit the full amount"
    ("すべて削除", "destructive-coercion", 0.5), // "delete everything"
];

/// Scan `lower` for every multilingual coercion stem and push a signal per match.
fn scan_multilingual_into(lower: &str, evidence_prefix: &str, out: &mut Vec<DetectionSignal>) {
    for &(pat, cat, weight) in MULTILINGUAL_PHRASES {
        if lower.contains(pat) {
            out.push(DetectionSignal {
                category: cat,
                weight,
                evidence: format!("{evidence_prefix}{pat:?}"),
            });
        }
    }
}

// ---------------- compositional (co-occurrence) override ----------------
//
// The phrase/multilingual tables above catch *known* coercion wordings. They cannot catch a
// *reworded* / novel injection ("the guidance you were handed earlier should be overruled") because
// the exact substring never appears. This layer is the "scored, not a fixed list" property taken to
// its conclusion: instead of matching a full phrase, it matches the CO-OCCURRENCE within one
// sentence of two independent semantic classes —
//
//   * an OVERRIDE token   (ignore / disregard / forget / overrule / nullify / … + regional twins), and
//   * an INSTRUCTION-reference token (instructions / rules / guidance / prompt / policy / … ) OR a
//     PRIOR-reference token (previous / above / earlier / preceding / …).
//
// Word order, connectives, and the language of the glue between them are irrelevant, so unseen
// phrasings and regional rewordings both fire. It stays PRECISE because it needs *both* classes:
// an override token about data ("forget cached balances") or a lone policy noun ("the settlement
// rules") does not cross. Class members are matched as substrings within a single sentence segment,
// which is script-agnostic (works for whitespace-less CJK as well as spaced scripts).

/// Override-class tokens: verbs/stems that nullify or set aside directions (English + regional).
/// Kept to *strong* overrides so ordinary business prose (cancel/skip an order) does not trip.
const OVERRIDE_TOKENS: &[&str] = &[
    // English
    "ignore",
    "disregard",
    "forget",
    "override",
    "overrid",
    "overrule",
    "bypass",
    "nullify",
    "negate",
    "countermand",
    "rescind",
    "revoke",
    "contravene",
    "disobey",
    "pay no attention",
    "pay no heed",
    "set aside",
    "no longer follow",
    "no longer apply",
    "stop following",
    "cease following",
    "must not follow",
    "should not follow",
    "treat as void",
    "as void",
    // Hindi (Devanagari) — ignore / disregard / forget stems
    "नज़रअंदाज",
    "नजरअंदाज",
    "अनदेखा",
    "भूल",
    "भुला",
    "अनसुना",
    // Hinglish / romanised
    "nazarandaaz",
    "nazar andaaz",
    "andekha",
    "bhool",
    "bhula",
    "bhula do",
    "ansuna",
    // Spanish
    "ignora",
    "ignore",
    "omite",
    "omita",
    "olvida",
    "olvide",
    "descarta",
    "descarte",
    "desestima",
    // French
    "ignorez",
    "oublie",
    "oubliez",
    "négligez",
    "neglige",
    "ne suivez pas",
    // German
    "ignoriere",
    "ignorier",
    "vergiss",
    "missachte",
    "missachten",
    // Portuguese
    "esqueça",
    "esqueca",
    "desconsidere",
    "desconsidera",
    // Russian
    "игнорир",
    "забудь",
    "забудьте",
    "пренебрег",
    "отмени",
    // Chinese
    "忽略",
    "忘记",
    "无视",
    "忽视",
    // Arabic
    "تجاهل",
    "تناسى",
    "انس",
    // Japanese
    "無視",
    "忘れ",
];

/// Instruction-reference tokens: the *object* an injection tells the model to override — the prior
/// directions themselves. Multilingual.
const INSTRUCTION_REF_TOKENS: &[&str] = &[
    // English
    "instruction",
    "directive",
    "direction",
    "guideline",
    "guidance",
    "prompt",
    "policy",
    "policies",
    "rule",
    "rules",
    "constraint",
    "restriction",
    "order",
    "orders",
    "command",
    "commands",
    "system message",
    "your rules",
    "your prompt",
    // Hindi / Hinglish
    "निर्देश",
    "नियम",
    "प्रॉम्प्ट",
    "आदेश",
    "हिदायत",
    "दिशानिर्देश",
    "nirdesh",
    "niyam",
    "aadesh",
    "hidayat",
    "prompt",
    // Spanish / Portuguese
    "instruccion",
    "instrucción",
    "instrucciones",
    "regla",
    "reglas",
    "directriz",
    "directrices",
    "instrução",
    "instruções",
    "regra",
    "regras",
    // French
    "consigne",
    "consignes",
    "règle",
    "règles",
    "directive",
    "directives",
    // German
    "anweisung",
    "anweisungen",
    "regel",
    "regeln",
    "vorgabe",
    "vorgaben",
    // Russian
    "инструкц",
    "правил",
    "указани",
    // Chinese
    "指令",
    "指示",
    "规则",
    "提示词",
    "命令",
    // Arabic
    "تعليمات",
    "قواعد",
    "التوجيهات",
    // Japanese
    "指示",
    "命令",
    "規則",
    "ルール",
];

/// Prior-reference tokens: temporal/positional markers meaning "the earlier ones", which turn a bare
/// override into a directed one ("forget everything above"). Multilingual.
const PRIOR_REF_TOKENS: &[&str] = &[
    // English
    "previous",
    "prior",
    "above",
    "earlier",
    "preceding",
    "foregoing",
    "aforementioned",
    "before",
    "at the start",
    "at the outset",
    "you were given",
    "you were handed",
    // Hindi / Hinglish
    "पिछले",
    "पूर्व",
    "ऊपर",
    "पहले",
    "pichle",
    "purane",
    "pehle",
    "upar",
    // Spanish / Portuguese
    "anterior",
    "anteriores",
    "previas",
    "de antes",
    "acima",
    // French
    "précédent",
    "précédentes",
    "antérieures",
    "ci-dessus",
    // German
    "vorherigen",
    "vorherige",
    "obigen",
    "obige",
    // Russian
    "предыдущ",
    "выше",
    "ранее",
    // Chinese
    "之前",
    "以前",
    "上面",
    "先前",
    // Arabic
    "السابق",
    "أعلاه",
    // Japanese
    "以前",
    "前の",
    "上記",
];

// PRECISION (R16). The bare "override token + reference token anywhere in the sentence, matched as
// substrings" rule fires on ordinary regulated-payments prose — "The bank may revoke the mandate
// under policy 4.2" scored exactly the default threshold and TAINTED the turn, gating every
// side-effecting tool for a legitimate request. Three precision layers keep the novel-phrasing
// coverage while removing that false-positive class:
//
//   1. **word-start matching for ASCII tokens** — "order" no longer matches inside "reorder" /
//      "recorder"; non-ASCII patterns (Devanagari/CJK/Arabic/Cyrillic) keep plain substring matching
//      because those scripts have no ASCII-style word boundaries;
//   2. **citation context** — an instruction-reference that is CITED ("under policy 4.2", "per rule
//      12", "as per section 3") is a document reference, not the assistant's own directions, so it
//      does not satisfy the reference class;
//   3. **directed vs descriptive** — a sentence aimed at the assistant (second-person marker, or an
//      imperative-lead override verb) keeps the full directed weight; third-person descriptive prose
//      (modal + override: "may revoke"; inflected override: "was rescinded") gets the sub-threshold
//      DESCRIPTIVE weight, so it corroborates other signals but never taints on its own.

/// True when `pat` occurs in `seg` at a word start. For non-ASCII patterns the boundary concept does
/// not apply (CJK has no spaces, Devanagari/Arabic join) so plain substring matching is used.
fn find_token(seg: &str, pat: &str) -> Option<usize> {
    if !pat.is_ascii() {
        return seg.find(pat);
    }
    let mut from = 0;
    while let Some(rel) = seg[from..].find(pat) {
        let at = from + rel;
        let prev_ok = seg[..at]
            .chars()
            .next_back()
            .map(|c| !c.is_alphanumeric() && c != '_')
            .unwrap_or(true);
        if prev_ok {
            return Some(at);
        }
        from = at + pat.len().max(1);
        if from >= seg.len() {
            break;
        }
    }
    None
}

/// Second-person markers across served languages — the strongest sign a sentence addresses the
/// assistant rather than describing a third party.
const SECOND_PERSON_MARKERS: &[&str] = &[
    "you",
    "your",
    "yours",
    "yourself",
    "आप",
    "तुम",
    "तुम्हें",
    "aap",
    "tum",
    "tumhe",
    "usted",
    "ustedes",
    "vous",
    "tú",
    "du ",
    "ihr ",
    "dich",
    "dir",
    "вы",
    "тебе",
    "тебя",
    "你",
    "您",
    "أنت",
    "あなた",
];

/// Modals/auxiliaries that mark DESCRIPTIVE third-person prose when they immediately precede an
/// override verb ("the bank *may revoke*", "settlement *will be rescinded*").
const DESCRIPTIVE_MODALS: &[&str] = &[
    "may", "might", "can", "could", "shall", "will", "would", "must", "is", "are", "was", "were",
    "be", "been", "being", "cannot", "cant",
    // Infinitive / nominalised use ("the authority TO revoke", "the right TO override") is a
    // description of a capability, never an instruction to the assistant.
    "to",
];

/// Citation lead-ins: an instruction-reference introduced by one of these is a *document citation*
/// ("under policy 4.2", "per rule 12"), not the assistant's own directions.
const CITATION_LEADINS: &[&str] = &[
    "under",
    "per",
    "pursuant",
    "section",
    "clause",
    "chapter",
    "article",
    "annex",
    "annexure",
    "schedule",
    "appendix",
    "paragraph",
    "para",
    "regulation",
    "circular",
    "accordance",
    "according",
    "governed",
    "subject",
];

fn words(seg: &str) -> Vec<&str> {
    seg.split_whitespace().collect()
}

/// Index of the whitespace-word containing byte offset `at`.
fn word_index_at(seg: &str, at: usize) -> usize {
    let before = &seg[..at];
    let n = before.split_whitespace().count();
    if before.is_empty() || before.ends_with(char::is_whitespace) {
        n
    } else {
        n.saturating_sub(1)
    }
}

/// The up-to-`n` whitespace-words immediately preceding the word containing byte offset `at`.
fn preceding_words<'a>(w: &'a [&'a str], at_word: usize, n: usize) -> &'a [&'a str] {
    let hi = at_word.min(w.len());
    let lo = hi.saturating_sub(n);
    &w[lo..hi]
}

fn has_second_person(seg: &str) -> bool {
    SECOND_PERSON_MARKERS.iter().any(|m| {
        if m.is_ascii() {
            find_token(seg, m.trim()).is_some()
        } else {
            seg.contains(m)
        }
    })
}

/// The segment opens with a directive/override verb (after softeners) — imperative mood.
fn has_imperative_lead(seg: &str) -> bool {
    let trimmed = seg.trim_start_matches(|c: char| !c.is_alphanumeric());
    let mut it = trimmed.split_whitespace();
    let mut first = it.next().unwrap_or("");
    while matches!(
        first,
        "please" | "now" | "kindly" | "just" | "then" | "immediately"
    ) {
        first = match it.next() {
            Some(w) => w,
            None => return false,
        };
    }
    let head = first.trim_matches(|c: char| !c.is_alphanumeric());
    DIRECTIVE_VERBS.contains(&head) || OVERRIDE_TOKENS.iter().any(|t| t.is_ascii() && *t == head)
}

/// Descriptive-prose markers around an ASCII override token: a preceding modal/auxiliary within two
/// words, or an inflected form (`-s` / `-d` / `-ed` suffix) which cannot be an imperative.
fn is_descriptive_override(seg: &str, tok: &str, at: usize) -> bool {
    if !tok.is_ascii() {
        return false;
    }
    let after = seg.get(at + tok.len()..).unwrap_or("");
    let inflected = after.starts_with('s') || after.starts_with('d') || after.starts_with("ed");
    if inflected {
        return true;
    }
    let w = words(seg);
    preceding_words(&w, word_index_at(seg, at), 2)
        .iter()
        .any(|x| {
            let x = x.trim_matches(|c: char| !c.is_alphanumeric());
            DESCRIPTIVE_MODALS.contains(&x)
        })
}

/// A reference token that is CITED (led by "under/per/section/…" within two words, or followed
/// by an identifier like `4.2`, `12`, `no.`) refers to a document, not the assistant's directions.
fn is_cited_reference(seg: &str, tok: &str, at: usize) -> bool {
    let w = words(seg);
    // A wider window than the modal check: "in section 6 of the rules" puts the lead-in four words
    // ahead of the reference token.
    let lead = preceding_words(&w, word_index_at(seg, at), 4)
        .iter()
        .any(|x| {
            let x = x.trim_matches(|c: char| !c.is_alphanumeric());
            CITATION_LEADINS.contains(&x)
        });
    if lead {
        return true;
    }
    // "policy 4.2" / "rule 12" — an identifier immediately after the reference token.
    let after = seg.get(at + tok.len()..).unwrap_or("").trim_start_matches(|c: char| c.is_alphanumeric());
    after
        .split_whitespace()
        .next()
        .map(|n| {
            n.chars()
                .next()
                .map(|c| c.is_ascii_digit())
                .unwrap_or(false)
                || n == "no."
        })
        .unwrap_or(false)
}

/// Fire an `instruction-override` signal when a sentence has an override-class token AND an
/// (uncited) instruction-reference OR prior-reference token — a reworded override in any language.
/// Directed phrasing → `directed_weight` (crosses threshold alone); descriptive prose →
/// sub-threshold `descriptive_weight`. Deduped to one signal per call site.
fn detect_compositional_override_weighted(
    text: &str,
    evidence_prefix: &str,
    directed_weight: f32,
    descriptive_weight: f32,
    out: &mut Vec<DetectionSignal>,
) {
    for seg in text.split(['\n', '.', '!', '?', ';']) {
        let Some((ov, ov_at)) = OVERRIDE_TOKENS
            .iter()
            .find_map(|&t| find_token(seg, t).map(|at| (t, at)))
        else {
            continue;
        };
        let refm = INSTRUCTION_REF_TOKENS
            .iter()
            .find_map(|&t| find_token(seg, t).map(|at| (t, at)))
            .filter(|(t, at)| !is_cited_reference(seg, t, *at))
            .or_else(|| {
                PRIOR_REF_TOKENS
                    .iter()
                    .find_map(|&t| find_token(seg, t).map(|at| (t, at)))
            });
        let Some((refm, _)) = refm else { continue };
        let directed = has_second_person(seg) || has_imperative_lead(seg);
        let descriptive = !directed && is_descriptive_override(seg, ov, ov_at);
        let (weight, shape) = if descriptive {
            (descriptive_weight, "descriptive")
        } else {
            (directed_weight, "directed")
        };
        out.push(DetectionSignal {
            category: "instruction-override",
            weight,
            evidence: format!(
                "{evidence_prefix}{shape} override {ov:?} against prior directions ({refm:?})"
            ),
        });
        return;
    }
}

// ---------------- homoglyph / mixed-script evasion ----------------

/// Fold a Unicode confusable (a Cyrillic/Greek/full-width look-alike) to its ASCII twin. Returns
/// the character unchanged when it is not a known confusable, so pure-ASCII text is untouched.
fn fold_confusable(c: char) -> char {
    match c {
        // Cyrillic look-alikes
        'а' => 'a',
        'е' => 'e',
        'о' => 'o',
        'р' => 'p',
        'с' => 'c',
        'у' => 'y',
        'х' => 'x',
        'к' => 'k',
        'м' => 'm',
        'т' => 't',
        'в' => 'b',
        'н' => 'h',
        'і' => 'i',
        'ј' => 'j',
        'ѕ' => 's',
        'ԁ' => 'd',
        'ԛ' => 'q',
        'ԝ' => 'w',
        'ѐ' => 'e',
        'ы' => 'l',
        'г' => 'r',
        // Greek look-alikes
        'ο' => 'o',
        'α' => 'a',
        'ε' => 'e',
        'ρ' => 'p',
        'ν' => 'v',
        'ι' => 'i',
        'τ' => 't',
        'υ' => 'u',
        'κ' => 'k',
        'χ' => 'x',
        'ϲ' => 'c',
        // Full-width ASCII (U+FF21..FF5A) → ASCII
        '\u{FF01}'..='\u{FF5E}' => char::from_u32(c as u32 - 0xFEE0).unwrap_or(c),
        _ => c,
    }
}

/// True when a token mixes ASCII-Latin with Cyrillic/Greek letters — a homoglyph-evasion
/// signature (`іgnоre` = Latin g/n/r + Cyrillic і/о + Latin e). Pure-script prose never trips.
fn has_mixed_script_token(s: &str) -> bool {
    for token in s.split_whitespace() {
        let mut latin = false;
        let mut confusable_script = false;
        for c in token.chars() {
            if c.is_ascii_alphabetic() {
                latin = true;
            } else if matches!(c, '\u{0400}'..='\u{04FF}' | '\u{0370}'..='\u{03FF}') {
                confusable_script = true;
            }
            if latin && confusable_script {
                return true;
            }
        }
    }
    false
}

/// Detect coercion phrases hidden behind confusable look-alikes, and record script-mixing as a weak
/// corroborating obfuscation signal. Fold-and-rescan reveals `іgnоre prеvious` → `ignore previous`;
/// a phrase that appears only after folding is unambiguous evasion (attackers do not accidentally
/// spell an override with Cyrillic letters), so it is scored as a strong encoded-payload signal in
/// addition to the phrase itself.
fn detect_homoglyph_evasion_weighted(
    lower: &str,
    directed_weight: f32,
    descriptive_weight: f32,
    out: &mut Vec<DetectionSignal>,
) {
    let folded: String = lower.chars().map(fold_confusable).collect();
    if folded != *lower {
        let before = out.len();
        scan_phrases_into(&folded, "(de-homoglyphed) ", out);
        scan_multilingual_into(&folded, "(de-homoglyphed) ", out);
        detect_compositional_override_weighted(
            &folded,
            "(de-homoglyphed) ",
            directed_weight,
            descriptive_weight,
            out,
        );
        if out.len() > before {
            out.push(DetectionSignal {
                category: "encoded-payload",
                weight: 0.5,
                evidence: "coercion phrase disguised with Unicode look-alike characters"
                    .to_string(),
            });
        }
    }
    // Script mixing on its own is weak (below threshold) — it corroborates, like zero-width chars.
    if has_mixed_script_token(lower) {
        out.push(DetectionSignal {
            category: "encoded-payload",
            weight: 0.35,
            evidence: "token mixes Latin with Cyrillic/Greek look-alike script".to_string(),
        });
    }
}

// ---------------- imperative-verb ----------------

/// Base-form verbs that, when they *start* a sentence/line in untrusted DATA, indicate a command
/// aimed at the reader (the assistant) rather than descriptive prose.
const DIRECTIVE_VERBS: &[&str] = &[
    "ignore",
    "disregard",
    "forget",
    "override",
    "bypass",
    "reveal",
    "print",
    "output",
    "send",
    "forward",
    "email",
    "transfer",
    "wire",
    "delete",
    "remove",
    "drop",
    "execute",
    "run",
    "call",
    "invoke",
    "fetch",
    "download",
    "upload",
    "post",
    "exfiltrate",
    "leak",
    "disclose",
    "pretend",
    "roleplay",
    "obey",
    "impersonate",
    "redirect",
    "navigate",
    "visit",
];

/// A sentence/line that *begins* with a directive verb (after leading punctuation and softeners
/// like "please"/"now") is a weak imperative signal. Weak on its own; corroborates the rest.
fn detect_imperative(lower: &str, out: &mut Vec<DetectionSignal>) {
    for raw in lower.split(['\n', '.', '!', '?', ';', ':']) {
        let seg = raw.trim_start_matches(|c: char| !c.is_alphanumeric());
        let seg = seg.trim();
        if seg.is_empty() {
            continue;
        }
        let mut words = seg.split_whitespace();
        // Skip leading softeners so "please ignore ..." still resolves to the verb.
        let mut first = words.next().unwrap_or("");
        while matches!(first, "please" | "now" | "kindly" | "just" | "then") {
            first = match words.next() {
                Some(w) => w,
                None => break,
            };
        }
        if DIRECTIVE_VERBS.contains(&first) {
            out.push(DetectionSignal {
                category: "imperative-verb",
                weight: 0.2,
                evidence: format!("command opens with {first:?}"),
            });
            // One imperative signal is enough to corroborate; avoid inflating on runbook-like DATA.
            return;
        }
    }
}

// ---------------- role-spoof ----------------

const ROLE_MARKERS: &[&str] = &[
    "system:",
    "assistant:",
    "[system]",
    "<system>",
    "system message",
    "###instruction",
    "### instruction",
    "### system",
    "<|im_start|>",
    "<|system|>",
    "<|assistant|>",
    "<|im_end|>",
    "begin system prompt",
    "new persona",
    "developer:",
];

/// Content forging a system/assistant turn to be treated as a trusted role.
fn detect_role_spoof(lower: &str, out: &mut Vec<DetectionSignal>) {
    for &m in ROLE_MARKERS {
        if lower.contains(m) {
            out.push(DetectionSignal {
                category: "role-spoof",
                weight: 0.45,
                evidence: format!("forged role marker {m:?}"),
            });
            return;
        }
    }
}

// ---------------- tool-invocation ----------------

/// Untrusted content asking to call a tool/function, or naming an internal tool.
fn detect_tool_invocation(lower: &str, known_tools: &[String], out: &mut Vec<DetectionSignal>) {
    const STRUCTURAL: &[&str] = &[
        "<tool_call>",
        "tool_call",
        "function_call",
        "\"tool\":",
        "\"function\":",
        "\"tool_name\":",
        "use the tool",
        "use the function",
        "run the command",
    ];
    for &s in STRUCTURAL {
        if lower.contains(s) {
            out.push(DetectionSignal {
                category: "tool-invocation",
                weight: 0.4,
                evidence: format!("tool-call syntax {s:?}"),
            });
            break;
        }
    }
    // A document naming your private tools is strong: it implies knowledge of internal state.
    for t in known_tools {
        let tl = t.to_lowercase();
        if !tl.is_empty() && lower.contains(&tl) {
            out.push(DetectionSignal {
                category: "tool-invocation",
                weight: 0.5,
                evidence: format!("names internal tool {t:?}"),
            });
            break;
        }
    }
}

// ---------------- encoded-payload ----------------

/// Unicode control characters with no legitimate role in instruction-bearing prose.
fn has_obfuscation_chars(text: &str) -> bool {
    text.chars().any(|c| {
        matches!(c,
            '\u{200B}'..='\u{200F}'   // zero-width space/joiner/marks + LRM/RLM
            | '\u{202A}'..='\u{202E}' // bidi embeddings/overrides
            | '\u{2066}'..='\u{2069}' // bidi isolates
            | '\u{FEFF}'              // BOM / zero-width no-break space
        )
    })
}

/// Decode base64 / hex / percent-encoded blobs and re-scan them; flag zero-width/bidi smuggling.
fn detect_encoded_payloads(original: &str, lower: &str, out: &mut Vec<DetectionSignal>) {
    if has_obfuscation_chars(original) {
        out.push(DetectionSignal {
            category: "encoded-payload",
            weight: 0.35,
            evidence: "zero-width / bidi control characters present".to_string(),
        });
    }

    // base64 runs
    for run in alphabet_runs(original, is_base64_char) {
        if run.len() < 24 {
            continue;
        }
        if let Some(bytes) = b64_decode(run) {
            rescan_decoded(&bytes, "base64", out);
        }
    }
    // hex runs
    for run in alphabet_runs(original, |c| c.is_ascii_hexdigit()) {
        if run.len() < 32 || run.len() % 2 != 0 {
            continue;
        }
        if let Some(bytes) = hex_decode(run) {
            rescan_decoded(&bytes, "hex", out);
        }
    }
    // percent-encoding (decode the whole text once if it looks percent-encoded)
    if percent_triples(lower) >= 3 {
        let decoded = percent_decode(original);
        if decoded != original {
            let dl = decoded.to_lowercase();
            let before = out.len();
            scan_phrases_into(&dl, "(url-decoded) ", out);
            if out.len() > before {
                out.push(DetectionSignal {
                    category: "encoded-payload",
                    weight: 0.4,
                    evidence: "percent-encoded instructions".to_string(),
                });
            }
        }
    }
}

/// If a decoded blob is mostly printable, re-scan it for injection phrases; a hit is strong.
fn rescan_decoded(bytes: &[u8], kind: &str, out: &mut Vec<DetectionSignal>) {
    if bytes.is_empty() {
        return;
    }
    let printable = bytes
        .iter()
        .filter(|&&b| b == b'\n' || b == b'\t' || (0x20..=0x7e).contains(&b))
        .count();
    // Require the decode to be mostly text — random ciphertext/binary is not a smuggled instruction.
    if (printable as f32) / (bytes.len() as f32) < 0.8 {
        return;
    }
    let decoded = String::from_utf8_lossy(bytes).to_lowercase();
    let before = out.len();
    scan_phrases_into(&decoded, &format!("({kind}-decoded) "), out);
    if out.len() > before {
        out.push(DetectionSignal {
            category: "encoded-payload",
            weight: 0.5,
            evidence: format!("{kind}-encoded instructions"),
        });
    }
}

/// Yield maximal runs of characters matching `pred`.
fn alphabet_runs(s: &str, pred: impl Fn(char) -> bool) -> Vec<&str> {
    let bytes = s.as_bytes();
    let mut runs = Vec::new();
    let mut start: Option<usize> = None;
    for (i, ch) in s.char_indices() {
        if pred(ch) {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(st) = start.take() {
            runs.push(&s[st..i]);
        }
    }
    if let Some(st) = start {
        runs.push(&s[st..bytes.len()]);
    }
    runs
}

fn is_base64_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='
}

fn b64_val(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let clean: Vec<u8> = s.bytes().filter(|&c| c != b'=').collect();
    let mut out = Vec::with_capacity(clean.len() / 4 * 3 + 3);
    for chunk in clean.chunks(4) {
        if chunk.len() < 2 {
            return None;
        }
        let mut buf = [0u8; 4];
        for (i, &c) in chunk.iter().enumerate() {
            buf[i] = b64_val(c)?;
        }
        out.push((buf[0] << 2) | (buf[1] >> 4));
        if chunk.len() >= 3 {
            out.push((buf[1] << 4) | (buf[2] >> 2));
        }
        if chunk.len() == 4 {
            out.push((buf[2] << 6) | buf[3]);
        }
    }
    Some(out)
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if b.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() / 2);
    for pair in b.chunks_exact(2) {
        out.push((hex_val(pair[0])? << 4) | hex_val(pair[1])?);
    }
    Some(out)
}

/// Count `%XX` hex triples so we only bother url-decoding text that is actually percent-encoded.
fn percent_triples(s: &str) -> usize {
    let b = s.as_bytes();
    let mut n = 0;
    let mut i = 0;
    while i + 2 < b.len() {
        if b[i] == b'%' && b[i + 1].is_ascii_hexdigit() && b[i + 2].is_ascii_hexdigit() {
            n += 1;
            i += 3;
        } else {
            i += 1;
        }
    }
    n
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex_val(b[i + 1]), hex_val(b[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}
