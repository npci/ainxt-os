// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! `LabelModel` over a real provider — the model-agnostic / capability-aware
//! extraction seam for the Stage-2 intent classifier (gap CONV-03,
//! `CONVERSATION_INTELLIGENCE.md` §5).
//!
//! The conversation crate ([`ainxt_convo::ModelIntentClassifier`]) drives Stage-2
//! through the object-safe, deliberately-synchronous [`ainxt_classify::LabelModel`]
//! seam: prompt in, raw completion text out. Until now the only implementations of
//! that seam were test doubles, so the model-agnostic path could never execute on a
//! real transport. This module supplies the missing production adapter:
//!
//! * [`ProviderLabelModel`] wraps any [`ConstrainedProvider`] and implements
//!   `LabelModel`. When the model's capability flags advertise grammar support it
//!   derives a **real** GBNF grammar / JSON-schema enum from the classifier's own
//!   constraint line and hands it to the transport, so a grammar-aware server
//!   (vLLM / llama.cpp / OpenAI json-schema) pins decoding to the label vocabulary.
//!   When the model has no grammar support it sends the plain steering prompt — the
//!   same cascade, only the extraction technique differs per model (§5).
//! * [`ConstrainedProvider`] is the transport seam: `stream_constrained(prompt,
//!   grammar)`. [`OpenAiSchemaProvider`](crate::OpenAiSchemaProvider) implements it
//!   natively (vLLM `guided_choice` / `guided_grammar`), covering every
//!   OpenAI-schema OSS endpoint. Vendors without a wire-level grammar knob simply
//!   ignore the grammar and prompt-steer.
//!
//! The async provider stream is bridged to the synchronous seam on a dedicated
//! current-thread runtime (see [`ProviderLabelModel::drain`]) so it is safe whether
//! or not the caller is already inside a Tokio runtime — `blocking_recv` would panic
//! inside an async context and `block_in_place` needs the multi-thread flavor, so
//! neither is safe as a universal bridge.

use ainxt_classify::{LabelModel, ModelError};
use ainxt_protocol::Event;
use tokio::sync::mpsc;

/// A constrained-decoding grammar over a fixed set of literal label alternatives.
///
/// Rendered two ways so any grammar-aware transport can consume it: [`to_gbnf`] for
/// llama.cpp / vLLM `guided_grammar`, and [`to_json_schema`] for OpenAI-style
/// json-schema-constrained decoding (a `string` with an `enum`). Both express the
/// identical constraint — the model may emit exactly one of the alternatives.
///
/// [`to_gbnf`]: LabelGrammar::to_gbnf
/// [`to_json_schema`]: LabelGrammar::to_json_schema
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelGrammar {
    alternatives: Vec<String>,
}

impl LabelGrammar {
    /// Build a grammar from an ordered, de-duplicated list of allowed labels.
    /// Empty / blank entries are dropped; declaration order is preserved (it is the
    /// classifier's tie-break order).
    pub fn new(alternatives: impl IntoIterator<Item = String>) -> Self {
        let mut out: Vec<String> = Vec::new();
        for a in alternatives {
            let a = a.trim().to_string();
            if !a.is_empty() && !out.contains(&a) {
                out.push(a);
            }
        }
        LabelGrammar { alternatives: out }
    }

    /// The allowed labels, in declaration order.
    pub fn alternatives(&self) -> &[String] {
        &self.alternatives
    }

    /// `true` when there is nothing to constrain (no alternatives parsed). The
    /// adapter treats an empty grammar as "no grammar" so it never sends a degenerate
    /// `root ::=` to a server.
    pub fn is_empty(&self) -> bool {
        self.alternatives.is_empty()
    }

    /// Render as a GBNF grammar: `root ::= "a" | "b" | "c"`.
    pub fn to_gbnf(&self) -> String {
        let alts = self
            .alternatives
            .iter()
            .map(|a| format!("\"{}\"", gbnf_escape(a)))
            .collect::<Vec<_>>()
            .join(" | ");
        format!("root ::= {alts}")
    }

    /// Render as a JSON schema pinning the output to one of the labels:
    /// `{ "type": "string", "enum": [...] }`.
    pub fn to_json_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "string",
            "enum": self.alternatives,
        })
    }
}

/// Escape a label for embedding inside a GBNF double-quoted literal.
fn gbnf_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Extract the allowed label alternatives from a Stage-2 constraint prompt.
///
/// [`ainxt_classify::build_prompt`] renders `Reply with EXACTLY one of: a | b | c`.
/// This parses that line back into `[a, b, c]` so the transport adapter can synthesize
/// a grammar without the classifier having to thread the [`LabelSet`] through the
/// text-only seam. Returns `None` if the marker line is absent (the adapter then
/// falls back to unconstrained prompting).
///
/// [`LabelSet`]: ainxt_classify::LabelSet
pub fn parse_alternatives(prompt: &str) -> Option<Vec<String>> {
    const MARKER: &str = "EXACTLY one of:";
    for line in prompt.lines() {
        if let Some(idx) = line.find(MARKER) {
            let tail = &line[idx + MARKER.len()..];
            let alts: Vec<String> = tail
                .split('|')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if !alts.is_empty() {
                return Some(alts);
            }
        }
    }
    None
}

/// A model transport that can optionally apply grammar-constrained decoding.
///
/// This extends the plain [`Provider`](ainxt_runtime::provider::Provider) streaming
/// contract with a grammar channel the base seam cannot carry (its `stream` takes only
/// a prompt). `grammar == None` means "decode freely" — identical to the base provider.
pub trait ConstrainedProvider: Send + Sync {
    /// Start streaming a completion for `prompt`. When `grammar` is `Some` and the
    /// transport supports it, decoding is pinned to the grammar's alternatives; when
    /// `None`, or unsupported, decoding is free and the prompt is the only steering.
    fn stream_constrained(
        &self,
        prompt: &str,
        grammar: Option<&LabelGrammar>,
    ) -> mpsc::Receiver<Event>;
}

/// The production [`LabelModel`]: a Stage-2 classifier backed by a real streaming
/// provider, capability-aware per CONV-03.
///
/// `grammar_constrained` mirrors the model's `ModelCaps.grammar_constrained` flag
/// (the conversation crate selects prompt strategy + repair budget from the same
/// flag; this adapter selects the *extraction technique*). When set, [`classify`]
/// derives a [`LabelGrammar`] from the prompt and constrains decoding; when clear, it
/// prompts freely. Either way it returns the raw completion text and lets
/// ainxt-classify parse it — the runtime, not the model, owns control-flow.
///
/// [`classify`]: LabelModel::classify
pub struct ProviderLabelModel<C: ConstrainedProvider> {
    transport: C,
    grammar_constrained: bool,
}

impl<C: ConstrainedProvider> ProviderLabelModel<C> {
    /// Wrap `transport`, declaring whether its underlying model supports
    /// grammar-constrained decoding. Pass the same value carried in the model's
    /// `ModelCaps.grammar_constrained` so prompt strategy and extraction technique
    /// agree.
    pub fn new(transport: C, grammar_constrained: bool) -> Self {
        ProviderLabelModel {
            transport,
            grammar_constrained,
        }
    }

    /// Whether this adapter will apply grammar-constrained decoding.
    pub fn grammar_constrained(&self) -> bool {
        self.grammar_constrained
    }

    /// Drive the provider stream to completion on a dedicated current-thread runtime
    /// and collect the text. Runs on its own OS thread so it works whether or not the
    /// caller is inside a Tokio runtime (the `LabelModel` seam is synchronous by
    /// design). Maps a transport [`Event::Error`] or an empty completion to a
    /// [`ModelError`]; a merely-unparseable completion is *not* an error here — the
    /// classifier's repair/clarify budget handles that.
    fn drain(&self, prompt: &str, grammar: Option<&LabelGrammar>) -> Result<String, ModelError> {
        let transport = &self.transport;
        std::thread::scope(|scope| {
            scope
                .spawn(move || {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|e| ModelError(format!("classify runtime build failed: {e}")))?;
                    rt.block_on(async move {
                        let mut rx = transport.stream_constrained(prompt, grammar);
                        let mut buf = String::new();
                        while let Some(ev) = rx.recv().await {
                            match ev {
                                Event::TextDelta(t) => buf.push_str(&t),
                                Event::Error(e) => return Err(ModelError(e)),
                                Event::Done => break,
                                _ => {}
                            }
                        }
                        if buf.trim().is_empty() {
                            return Err(ModelError("empty completion from provider".into()));
                        }
                        Ok(buf)
                    })
                })
                .join()
                .map_err(|_| ModelError("classify worker thread panicked".into()))?
        })
    }
}

impl<C: ConstrainedProvider> LabelModel for ProviderLabelModel<C> {
    fn classify(&self, prompt: &str) -> Result<String, ModelError> {
        // Capability-aware extraction (§5): a grammar-capable model gets a real
        // grammar derived from the classifier's own constraint line; a weak model
        // gets the plain prompt (the constraint line is still its steering).
        let grammar = if self.grammar_constrained {
            parse_alternatives(prompt).map(LabelGrammar::new)
        } else {
            None
        };
        let grammar = grammar.filter(|g| !g.is_empty());
        self.drain(prompt, grammar.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_alternatives_from_constraint_prompt() {
        let p = "Classify the intent.\n\nReply with EXACTLY one of: chitchat | qa | code\n\
                 Respond with only the single label.";
        let alts = parse_alternatives(p).expect("marker present");
        assert_eq!(alts, vec!["chitchat", "qa", "code"]);
    }

    #[test]
    fn parse_alternatives_none_without_marker() {
        assert!(parse_alternatives("just a plain sentence").is_none());
    }

    #[test]
    fn grammar_renders_gbnf_and_json_schema() {
        let g = LabelGrammar::new(["qa".to_string(), "code".to_string(), "qa".to_string()]);
        // Dedup + order preserved.
        assert_eq!(g.alternatives(), &["qa".to_string(), "code".to_string()]);
        assert_eq!(g.to_gbnf(), r#"root ::= "qa" | "code""#);
        assert_eq!(
            g.to_json_schema(),
            serde_json::json!({"type": "string", "enum": ["qa", "code"]})
        );
    }

    #[test]
    fn gbnf_escapes_quotes_and_backslash() {
        let g = LabelGrammar::new([r#"a"b\c"#.to_string()]);
        assert_eq!(g.to_gbnf(), r#"root ::= "a\"b\\c""#);
    }
}
