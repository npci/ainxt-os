// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Constrained / grammar decoding (`PROMPT_ENGINEERING.md` §4, PE3) — generalized to **every**
//! structured-output prompt in the system (tool-call arguments, Role Spec JSON, eval-judge verdicts,
//! doc-gen `{format, content}` payloads), not just intent classification.
//!
//! The design's core commitment: on a weak self-hosted model a Role that must return
//! `{ticket_id, resolution, confidence}` gets a **syntactically valid object 100% of the time**, not
//! "usually". Two mechanisms, layered, and the runtime **never trusts the model's own claim** that it
//! produced valid output — it always validates:
//!
//! 1. **Grammar attachment (the load-bearing technique).** A [`JsonSchema`] compiles to a **GBNF
//!    grammar** ([`JsonSchema::to_gbnf`]) that a native decoder (vLLM / Outlines / lm-format-enforcer)
//!    enforces at the token-sampling level — the model literally cannot emit an invalid token. When
//!    the serving layer reports [`ConstrainedDecoder::grammar_native`], validity is guaranteed by
//!    construction; the engine still validates once as a fail-closed backstop against a lying/misbuilt
//!    decoder.
//! 2. **Bounded repair loop (the backstop for models without native constrained decoding).** Strict
//!    prompted-JSON + re-prompt with the precise validation error, **capped** retries, then a
//!    *structured error* — never a silently-invalid object handed downstream.
//!
//! Enterprise, not happy-path: provider decode failures propagate (never swallowed), the repair loop
//! is hard-bounded (no unbounded model spend), and a [`Cancel`] seam aborts mid-loop (cancel/timeout).
//! Deterministic given deterministic seams; no clock/rng/I/O in this module.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------------------------
// Schema subset
// ---------------------------------------------------------------------------------------------

/// A JSON scalar type in the enforced schema subset. Enough for tool args / Role Spec / judge
/// verdicts / doc-gen payloads without dragging in a full JSON-Schema engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "type", content = "values")]
pub enum FieldType {
    String,
    Integer,
    Number,
    Boolean,
    /// A string constrained to one of a fixed set of values (a closed enum).
    Enum(Vec<String>),
}

/// One field's spec.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldSpec {
    pub ty: FieldType,
}

impl FieldSpec {
    pub fn new(ty: FieldType) -> Self {
        FieldSpec { ty }
    }
}

/// A minimal JSON-schema subset: a flat object of typed fields, some required, with a switch for
/// whether extra keys are tolerated. Fields are a `BTreeMap` so grammar/validation order is stable
/// (deterministic GBNF, reproducible in replay).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonSchema {
    pub fields: BTreeMap<String, FieldSpec>,
    pub required: Vec<String>,
    /// When false, an output containing a key not in `fields` is rejected (the strict default).
    pub allow_additional: bool,
}

impl JsonSchema {
    /// A strict object schema (no additional properties) from `(name, type, required)` triples.
    pub fn object(fields: impl IntoIterator<Item = (&'static str, FieldType, bool)>) -> Self {
        let mut map = BTreeMap::new();
        let mut required = Vec::new();
        for (name, ty, req) in fields {
            map.insert(name.to_string(), FieldSpec::new(ty));
            if req {
                required.push(name.to_string());
            }
        }
        required.sort();
        JsonSchema {
            fields: map,
            required,
            allow_additional: false,
        }
    }

    /// Validate a model output string against this schema. Returns `Ok(canonical_value)` on success or
    /// a precise, model-readable error string (fed back into the repair prompt) on failure.
    pub fn validate(&self, output: &str) -> Result<serde_json::Value, String> {
        let trimmed = output.trim();
        let value: serde_json::Value = serde_json::from_str(trimmed)
            .map_err(|e| format!("not valid JSON: {e}. Output ONLY a single JSON object."))?;
        let obj = value
            .as_object()
            .ok_or_else(|| "top-level value must be a JSON object ({ ... }).".to_string())?;

        // Required fields present.
        for req in &self.required {
            if !obj.contains_key(req) {
                return Err(format!("missing required field '{req}'."));
            }
        }
        // No undeclared keys (unless allowed).
        if !self.allow_additional {
            for key in obj.keys() {
                if !self.fields.contains_key(key) {
                    return Err(format!(
                        "unexpected field '{key}'. Allowed fields: {}.",
                        self.field_list()
                    ));
                }
            }
        }
        // Type-check every present field.
        for (name, spec) in &self.fields {
            if let Some(v) = obj.get(name) {
                check_type(name, &spec.ty, v)?;
            }
        }
        Ok(value)
    }

    fn field_list(&self) -> String {
        self.fields.keys().cloned().collect::<Vec<_>>().join(", ")
    }

    /// Compile to a **GBNF grammar** for a native constrained decoder (vLLM/Outlines/
    /// lm-format-enforcer). Deterministic: the same schema always yields the same grammar text so a
    /// turn's grammar is reproducible in forensic replay. Required fields appear in a fixed order;
    /// the emitted grammar constrains the object to exactly the declared keys.
    pub fn to_gbnf(&self) -> String {
        let ordered: Vec<&String> = self.fields.keys().collect();
        // Partition the declared fields into required vs optional (stable field-key order). A REQUIRED
        // field is a mandatory member of the object; an OPTIONAL field must be genuinely omittable —
        // the earlier grammar chained EVERY field as required and so forced an absent optional field to
        // appear, producing a grammar the schema itself would reject. This faithfully represents
        // optional fields (§4): required fields form the mandatory core, each optional field is an
        // omittable, leading-comma group.
        let required_set: std::collections::BTreeSet<&str> =
            self.required.iter().map(|s| s.as_str()).collect();
        let mut req_idx = Vec::new();
        let mut opt_idx = Vec::new();
        for (i, name) in ordered.iter().enumerate() {
            if required_set.contains(name.as_str()) {
                req_idx.push(i);
            } else {
                opt_idx.push(i);
            }
        }

        let mut g = String::new();
        g.push_str("root ::= \"{\" ws ");
        if !req_idx.is_empty() {
            // Mandatory required core, in order.
            let core: Vec<String> = req_idx.iter().map(|i| format!("kv-{i}")).collect();
            g.push_str(&core.join(" \",\" ws "));
            // Each optional field: an omittable ( "," ws kv )? group. A required member always precedes
            // it, so the leading comma is always valid JSON whether or not the optional is emitted.
            for i in &opt_idx {
                g.push_str(&format!(" ( \",\" ws kv-{i} )?"));
            }
        } else if !opt_idx.is_empty() {
            // No required fields: the entire member list is optional (an empty object is valid), and
            // any subset of the optional members may appear — the first present member carries no
            // leading comma, subsequent members do (always-valid JSON). The validator remains the
            // fail-closed backstop on which specific keys/types are allowed.
            g.push_str("members?");
        }
        g.push_str(" ws \"}\"\n");

        if req_idx.is_empty() && !opt_idx.is_empty() {
            let alts: Vec<String> = opt_idx.iter().map(|i| format!("kv-{i}")).collect();
            g.push_str("members ::= member ( \",\" ws member )*\n");
            g.push_str(&format!("member ::= {}\n", alts.join(" | ")));
        }

        for (i, name) in ordered.iter().enumerate() {
            let spec = &self.fields[*name];
            g.push_str(&format!(
                "kv-{i} ::= \"\\\"{name}\\\"\" ws \":\" ws {}\n",
                gbnf_value_rule(&spec.ty)
            ));
        }
        // Shared terminals.
        g.push_str("string ::= \"\\\"\" ([^\"\\\\] | \"\\\\\" .)* \"\\\"\"\n");
        g.push_str("integer ::= \"-\"? [0-9]+\n");
        g.push_str("number ::= \"-\"? [0-9]+ (\".\" [0-9]+)?\n");
        g.push_str("boolean ::= \"true\" | \"false\"\n");
        g.push_str("ws ::= [ \\t\\n]*\n");
        g
    }
}

fn gbnf_value_rule(ty: &FieldType) -> String {
    match ty {
        FieldType::String => "string".to_string(),
        FieldType::Integer => "integer".to_string(),
        FieldType::Number => "number".to_string(),
        FieldType::Boolean => "boolean".to_string(),
        FieldType::Enum(values) => values
            .iter()
            .map(|v| format!("\"\\\"{v}\\\"\""))
            .collect::<Vec<_>>()
            .join(" | "),
    }
}

fn check_type(name: &str, ty: &FieldType, v: &serde_json::Value) -> Result<(), String> {
    let ok = match ty {
        FieldType::String => v.is_string(),
        FieldType::Integer => v.is_i64() || v.is_u64(),
        FieldType::Number => v.is_number(),
        FieldType::Boolean => v.is_boolean(),
        FieldType::Enum(values) => v
            .as_str()
            .map(|s| values.iter().any(|allowed| allowed == s))
            .unwrap_or(false),
    };
    if ok {
        Ok(())
    } else {
        let want = match ty {
            FieldType::Enum(values) => format!("one of [{}]", values.join(", ")),
            other => format!("{other:?}"),
        };
        Err(format!(
            "field '{name}' has the wrong type: expected {want}, got {v}."
        ))
    }
}

// ---------------------------------------------------------------------------------------------
// Serving seam + cancel
// ---------------------------------------------------------------------------------------------

/// A provider/serving failure surfaced from a decode attempt (a real error, never masked as output).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError(pub String);

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "decode failed: {}", self.0)
    }
}
impl std::error::Error for DecodeError {}

/// The constrained-decoding serving seam. A production impl calls the Provider Gateway with the grammar
/// attached when `grammar_native`; tests inject fakes. Kept a trait so the runtime's structured-output
/// guarantee is independent of any specific serving stack.
pub trait ConstrainedDecoder: Send + Sync {
    /// True when this decoder enforces the grammar at the token-sampling level (vLLM/Outlines/
    /// lm-format-enforcer) — output is valid by construction. False = the engine must run the repair
    /// backstop.
    fn grammar_native(&self) -> bool;
    /// Produce output for `prompt`, attaching `grammar` when the decoder is grammar-native.
    fn decode(&self, prompt: &str, grammar: Option<&str>) -> Result<String, DecodeError>;
}

/// A cooperative cancellation seam (cancel/timeout support in the repair loop).
pub trait Cancel {
    fn is_cancelled(&self) -> bool;
}

/// Never-cancel default.
pub struct NeverCancel;
impl Cancel for NeverCancel {
    fn is_cancelled(&self) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------------------------
// The engine
// ---------------------------------------------------------------------------------------------

/// How the valid output was obtained (for telemetry + the acceptance test PE3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DecodeMethod {
    /// The serving layer enforced the grammar at token-sampling level.
    NativeGrammar,
    /// Prompted-JSON that validated on the first attempt (no repair needed).
    PromptedFirstTry,
    /// Prompted-JSON that needed `repairs` re-prompts before validating.
    Repaired { repairs: usize },
}

/// A validated structured output.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StructuredOutput {
    /// The raw, schema-valid model text.
    pub raw: String,
    /// The parsed canonical value.
    pub value: serde_json::Value,
    pub method: DecodeMethod,
}

/// A structured failure — the engine NEVER returns an invalid object; on failure it returns one of
/// these so the caller fails closed (e.g. abstain, escalate, or surface an error to the user).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StructuredError {
    /// The provider/serving layer failed a decode attempt.
    Decode(DecodeError),
    /// A grammar-native decoder produced output that STILL failed validation — a serving-layer defect;
    /// fail closed rather than trust it (`PROMPT_ENGINEERING.md` §4: never trust the model's claim).
    NativeGrammarViolated(String),
    /// The repair budget was exhausted without a valid output; carries the last validation error.
    Unrepairable { attempts: usize, last_error: String },
    /// Cancelled (timeout / client abort) before a valid output was produced.
    Cancelled,
}

impl std::fmt::Display for StructuredError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StructuredError::Decode(e) => write!(f, "{e}"),
            StructuredError::NativeGrammarViolated(e) => {
                write!(f, "grammar-native decoder produced invalid output: {e}")
            }
            StructuredError::Unrepairable {
                attempts,
                last_error,
            } => write!(
                f,
                "structured output unrepairable after {attempts} attempt(s): {last_error}"
            ),
            StructuredError::Cancelled => write!(f, "structured decoding cancelled"),
        }
    }
}
impl std::error::Error for StructuredError {}

/// The structured-output engine: guarantees a schema-valid object or a structured error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StructuredOutputEngine {
    /// Maximum number of *repair* re-prompts (total attempts = `max_repairs + 1`). Hard cap so a
    /// pathological model cannot spin the tool loop forever (bounded cost).
    pub max_repairs: usize,
}

impl Default for StructuredOutputEngine {
    fn default() -> Self {
        StructuredOutputEngine { max_repairs: 3 }
    }
}

impl StructuredOutputEngine {
    pub fn new(max_repairs: usize) -> Self {
        StructuredOutputEngine { max_repairs }
    }

    /// Generate a schema-valid structured output for `base_prompt`, or a [`StructuredError`].
    ///
    /// * grammar-native decoder → decode once with the grammar, validate as a backstop.
    /// * otherwise → prompted-JSON + bounded repair loop, re-prompting with the exact validation error.
    pub fn generate(
        &self,
        decoder: &dyn ConstrainedDecoder,
        schema: &JsonSchema,
        base_prompt: &str,
        cancel: &dyn Cancel,
    ) -> Result<StructuredOutput, StructuredError> {
        if cancel.is_cancelled() {
            return Err(StructuredError::Cancelled);
        }
        let grammar = schema.to_gbnf();

        if decoder.grammar_native() {
            let raw = decoder
                .decode(base_prompt, Some(&grammar))
                .map_err(StructuredError::Decode)?;
            // Belt-and-braces: validate even a "guaranteed valid" output — never trust the claim.
            let value = schema
                .validate(&raw)
                .map_err(StructuredError::NativeGrammarViolated)?;
            return Ok(StructuredOutput {
                raw,
                value,
                method: DecodeMethod::NativeGrammar,
            });
        }

        // Prompted-JSON + bounded repair loop.
        let mut last_error = String::new();
        for attempt in 0..=self.max_repairs {
            if cancel.is_cancelled() {
                return Err(StructuredError::Cancelled);
            }
            let prompt = if attempt == 0 {
                prompted_json(base_prompt, schema)
            } else {
                repair_prompt(base_prompt, schema, &last_error)
            };
            let raw = decoder
                .decode(&prompt, None)
                .map_err(StructuredError::Decode)?;
            match schema.validate(&raw) {
                Ok(value) => {
                    let method = if attempt == 0 {
                        DecodeMethod::PromptedFirstTry
                    } else {
                        DecodeMethod::Repaired { repairs: attempt }
                    };
                    return Ok(StructuredOutput { raw, value, method });
                }
                Err(e) => last_error = e,
            }
        }
        Err(StructuredError::Unrepairable {
            attempts: self.max_repairs + 1,
            last_error,
        })
    }
}

/// The strict prompted-JSON instruction appended to the base prompt (the fallback for non-native
/// decoders). Restated at the END (recency helps weak models, §4).
fn prompted_json(base_prompt: &str, schema: &JsonSchema) -> String {
    format!(
        "{base_prompt}\n\nRespond with a SINGLE JSON object and nothing else — no prose, no code \
         fences. Required fields: [{}]. Allowed fields: [{}].",
        schema.required.join(", "),
        schema.field_list()
    )
}

/// The repair re-prompt: the base + the exact validation error the last attempt produced.
fn repair_prompt(base_prompt: &str, schema: &JsonSchema, last_error: &str) -> String {
    format!(
        "{}\n\nYour previous response was invalid: {last_error}\nReturn a corrected single JSON \
         object with fields [{}] and nothing else.",
        prompted_json(base_prompt, schema),
        schema.field_list()
    )
}

// ---------------------------------------------------------------------------------------------
// Catalog — the canonical structured-output schemas, so constrained decoding is GENERALIZED to
// EVERY structured-output prompt (§4, PE3), not re-invented per call site.
// ---------------------------------------------------------------------------------------------

/// The system's structured-output call sites (`PROMPT_ENGINEERING.md` §4, PE3). Each maps to a
/// canonical [`JsonSchema`]; every caller that needs a structured object goes through
/// [`StructuredOutputEngine::generate`] with the schema from [`StructuredOutputKind::schema`] — so the
/// grammar-attach + validate + bounded-repair guarantee applies uniformly (a weak self-hosted model
/// returns a syntactically valid object 100% of the time on ALL of these, not just intent).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StructuredOutputKind {
    /// A tool-call envelope: which tool + its arguments (the per-tool argument schema composes on top).
    ToolCall,
    /// A Role Spec object emitted by the Role authoring/repair path.
    RoleSpec,
    /// An eval / LLM-judge verdict `{score, passed, rationale}`.
    JudgeVerdict,
    /// A doc-generation payload `{format, content}`.
    DocGenPayload,
    /// The conversation-intelligence **intent classification** verdict `{intent, confidence,
    /// clarify}` — the original constrained-decoding call site the design generalized OUTWARD from
    /// (§4 "not just intent classification"). Included here so intent, too, goes through the one
    /// grammar-attach + validate + bounded-repair guarantee rather than a bespoke parser.
    IntentClassification,
}

impl StructuredOutputKind {
    /// The canonical schema for this call site. Strict (no additional properties) so an off-schema key
    /// is rejected, not silently passed downstream.
    pub fn schema(self) -> JsonSchema {
        match self {
            StructuredOutputKind::ToolCall => JsonSchema::object([
                ("tool", FieldType::String, true),
                ("arguments", FieldType::String, true),
            ]),
            StructuredOutputKind::RoleSpec => JsonSchema::object([
                ("id", FieldType::String, true),
                ("model", FieldType::String, true),
                (
                    "tier",
                    FieldType::Enum(vec!["simple".into(), "medium".into(), "complex".into()]),
                    true,
                ),
                ("system_prompt", FieldType::String, true),
            ]),
            StructuredOutputKind::JudgeVerdict => JsonSchema::object([
                ("score", FieldType::Integer, true),
                ("passed", FieldType::Boolean, true),
                ("rationale", FieldType::String, true),
            ]),
            StructuredOutputKind::DocGenPayload => JsonSchema::object([
                (
                    "format",
                    FieldType::Enum(vec![
                        "docx".into(),
                        "pptx".into(),
                        "pdf".into(),
                        "xlsx".into(),
                    ]),
                    true,
                ),
                ("content", FieldType::String, true),
            ]),
            StructuredOutputKind::IntentClassification => JsonSchema::object([
                (
                    "intent",
                    FieldType::Enum(vec![
                        "qa".into(),
                        "doc-generation".into(),
                        "action".into(),
                        "clarify".into(),
                    ]),
                    true,
                ),
                ("confidence", FieldType::Number, true),
                // Optional: present only when the classifier wants to ask a clarifying question. Proves
                // the catalog carries a genuinely optional field through the (now faithful) grammar.
                ("clarify", FieldType::String, false),
            ]),
        }
    }

    /// Every call site in the catalog (so a test / tool can iterate them and assert the guarantee holds
    /// on ALL of them — the "generalized to every structured-output prompt" claim, PE3).
    pub fn all() -> [StructuredOutputKind; 5] {
        [
            StructuredOutputKind::ToolCall,
            StructuredOutputKind::RoleSpec,
            StructuredOutputKind::JudgeVerdict,
            StructuredOutputKind::DocGenPayload,
            StructuredOutputKind::IntentClassification,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    fn ticket_schema() -> JsonSchema {
        JsonSchema::object([
            ("ticket_id", FieldType::String, true),
            ("resolution", FieldType::String, true),
            ("confidence", FieldType::Number, true),
            (
                "severity",
                FieldType::Enum(vec!["low".into(), "high".into()]),
                false,
            ),
        ])
    }

    // --- validation --------------------------------------------------------------------------

    #[test]
    fn valid_object_passes_and_bad_ones_fail_with_readable_errors() {
        let s = ticket_schema();
        assert!(s
            .validate(r#"{"ticket_id":"T1","resolution":"done","confidence":0.9}"#)
            .is_ok());
        // Missing required.
        assert!(s
            .validate(r#"{"ticket_id":"T1","resolution":"done"}"#)
            .unwrap_err()
            .contains("missing required field 'confidence'"));
        // Wrong type.
        assert!(s
            .validate(r#"{"ticket_id":"T1","resolution":"done","confidence":"high"}"#)
            .unwrap_err()
            .contains("wrong type"));
        // Undeclared key.
        assert!(s
            .validate(r#"{"ticket_id":"T1","resolution":"d","confidence":1,"x":2}"#)
            .unwrap_err()
            .contains("unexpected field 'x'"));
        // Enum out of range.
        assert!(s
            .validate(r#"{"ticket_id":"T","resolution":"d","confidence":1,"severity":"medium"}"#)
            .unwrap_err()
            .contains("severity"));
        // Not JSON at all.
        assert!(s.validate("sorry, here is your ticket").is_err());
    }

    #[test]
    fn gbnf_grammar_is_deterministic_and_mentions_every_field() {
        let s = ticket_schema();
        let g1 = s.to_gbnf();
        let g2 = s.to_gbnf();
        assert_eq!(g1, g2, "grammar must be deterministic for replay");
        for f in ["ticket_id", "resolution", "confidence", "severity"] {
            assert!(g1.contains(f), "grammar must constrain field {f}");
        }
        // Enum values are baked into the grammar as literal alternatives.
        assert!(g1.contains("\\\"low\\\"") && g1.contains("\\\"high\\\""));
        assert!(g1.contains("root ::="));
    }

    // --- fakes -------------------------------------------------------------------------------

    /// A native grammar decoder: because it "enforces" the grammar, it returns a valid object.
    struct NativeDecoder;
    impl ConstrainedDecoder for NativeDecoder {
        fn grammar_native(&self) -> bool {
            true
        }
        fn decode(&self, _p: &str, grammar: Option<&str>) -> Result<String, DecodeError> {
            assert!(grammar.is_some(), "native decoder must receive the grammar");
            Ok(r#"{"ticket_id":"T","resolution":"reset password","confidence":0.8}"#.to_string())
        }
    }

    /// A WEAK model: on the first (no-error) prompt it emits invalid JSON (prose + trailing junk);
    /// once the prompt carries a repair error ("was invalid"), it emits a valid object. This models
    /// exactly the self-hosted failure the repair loop exists to fix.
    struct WeakModel;
    impl ConstrainedDecoder for WeakModel {
        fn grammar_native(&self) -> bool {
            false
        }
        fn decode(&self, prompt: &str, _g: Option<&str>) -> Result<String, DecodeError> {
            if prompt.contains("was invalid") {
                Ok(r#"{"ticket_id":"T","resolution":"done","confidence":0.5}"#.to_string())
            } else {
                Ok("Sure! {ticket_id: T, ...} hope that helps".to_string())
            }
        }
    }

    /// A hopeless model that never produces valid JSON — exercises the bounded budget.
    struct HopelessModel;
    impl ConstrainedDecoder for HopelessModel {
        fn grammar_native(&self) -> bool {
            false
        }
        fn decode(&self, _p: &str, _g: Option<&str>) -> Result<String, DecodeError> {
            Ok("never json".to_string())
        }
    }

    struct FailingProvider;
    impl ConstrainedDecoder for FailingProvider {
        fn grammar_native(&self) -> bool {
            false
        }
        fn decode(&self, _p: &str, _g: Option<&str>) -> Result<String, DecodeError> {
            Err(DecodeError("upstream 503".into()))
        }
    }

    // --- PE3: 100/100 schema-valid on a weak model via the repair loop -----------------------

    #[test]
    fn gap_ainxt_prompt_prmt_02_constrained_decoding_100_of_100_valid() {
        let engine = StructuredOutputEngine::default();
        let schema = ticket_schema();

        // Native path: valid by construction, validated as a backstop.
        let out = engine
            .generate(&NativeDecoder, &schema, "resolve the ticket", &NeverCancel)
            .unwrap();
        assert_eq!(out.method, DecodeMethod::NativeGrammar);
        assert!(schema.validate(&out.raw).is_ok());

        // The load-bearing claim: 100 consecutive weak-model calls → 100 schema-valid outputs,
        // zero parse failures — the exact PE3 acceptance criterion.
        for _ in 0..100 {
            let out = engine
                .generate(&WeakModel, &schema, "resolve the ticket", &NeverCancel)
                .unwrap();
            assert_eq!(out.method, DecodeMethod::Repaired { repairs: 1 });
            assert!(
                schema.validate(&out.raw).is_ok(),
                "every structured output must be schema-valid"
            );
        }
    }

    #[test]
    fn gap_ainxt_prompt_prmt_02_repair_budget_is_bounded_and_fails_closed() {
        let engine = StructuredOutputEngine::new(2);
        let schema = ticket_schema();
        let err = engine
            .generate(&HopelessModel, &schema, "x", &NeverCancel)
            .unwrap_err();
        match err {
            StructuredError::Unrepairable { attempts, .. } => assert_eq!(attempts, 3),
            other => panic!("expected Unrepairable, got {other:?}"),
        }
    }

    #[test]
    fn gap_ainxt_prompt_prmt_02_provider_error_propagates_not_swallowed() {
        let engine = StructuredOutputEngine::default();
        let err = engine
            .generate(&FailingProvider, &ticket_schema(), "x", &NeverCancel)
            .unwrap_err();
        assert!(matches!(err, StructuredError::Decode(_)));
    }

    #[test]
    fn gap_ainxt_prompt_prmt_02_cancellation_aborts_the_loop() {
        struct AfterN {
            calls: AtomicUsize,
            trip_at: usize,
            flag: AtomicBool,
        }
        impl Cancel for AfterN {
            fn is_cancelled(&self) -> bool {
                let n = self.calls.fetch_add(1, Ordering::SeqCst);
                if n >= self.trip_at {
                    self.flag.store(true, Ordering::SeqCst);
                }
                self.flag.load(Ordering::SeqCst)
            }
        }
        let engine = StructuredOutputEngine::new(10);
        let cancel = AfterN {
            calls: AtomicUsize::new(0),
            trip_at: 2,
            flag: AtomicBool::new(false),
        };
        let err = engine
            .generate(&HopelessModel, &ticket_schema(), "x", &cancel)
            .unwrap_err();
        assert_eq!(err, StructuredError::Cancelled);
    }

    #[test]
    fn gap_ainxt_prompt_prmt_02_native_decoder_that_lies_fails_closed() {
        // A "native" decoder that actually returns garbage must be caught, not trusted.
        struct LyingNative;
        impl ConstrainedDecoder for LyingNative {
            fn grammar_native(&self) -> bool {
                true
            }
            fn decode(&self, _p: &str, _g: Option<&str>) -> Result<String, DecodeError> {
                Ok("definitely not json".to_string())
            }
        }
        let engine = StructuredOutputEngine::default();
        let err = engine
            .generate(&LyingNative, &ticket_schema(), "x", &NeverCancel)
            .unwrap_err();
        assert!(matches!(err, StructuredError::NativeGrammarViolated(_)));
    }
}
