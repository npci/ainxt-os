// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Dual-LLM / privileged-quarantined pattern (ADR-009, design A).
//!
//! The strongest structural defense against *indirect* prompt injection is not detection at all —
//! it is never letting a privileged, tool-wielding model read attacker-controlled bytes as
//! instructions. This module implements the **dual-LLM** pattern:
//!
//! * a **Privileged** context (the model that can call tools / take actions) sees the user's own
//!   instructions and, in place of any untrusted content, only an opaque **symbol** (`$UNTRUSTED_0`)
//!   plus its provenance — never the raw bytes. Instructions hidden inside the untrusted content can
//!   therefore never reach the model that can act on them;
//! * a **Quarantined** context (a model with NO tool access) is the only thing that ever reads the
//!   raw untrusted content, and it may return only a **constrained, typed value** — a bool, a number,
//!   or a member of a fixed enum — never free text. That typed channel cannot smuggle an instruction
//!   back into the privileged context: an enum answer is validated against the allowed set
//!   (fail-closed to a caller-chosen default when the quarantined model returns anything off-list).
//!
//! Everything here is deterministic and dependency-light. The [`QuarantinedLlm`] trait is the seam
//! where a real quarantined model plugs in; offline tests use a fake. Trusted (user-authored)
//! content is never quarantined — it is the legitimate instruction channel.

use crate::Provenance;

/// A constrained value a quarantined model is allowed to return. Deliberately has **no free-text
/// variant**: the whole point of quarantine is that untrusted content cannot re-enter the privileged
/// context as arbitrary text (which could carry an injected instruction). Everything the privileged
/// side learns from untrusted data is a bool, a number, or a validated enum label.
#[derive(Debug, Clone, PartialEq)]
pub enum QuarantinedValue {
    Bool(bool),
    Number(f64),
    /// A label guaranteed to be a member of the schema's allowed set (validated on construction).
    Enum(String),
}

/// The typed shape a quarantined extraction must conform to. The privileged side declares the schema
/// up front; the quarantined model's raw answer is coerced/validated to it.
#[derive(Debug, Clone, PartialEq)]
pub enum QuarantineSchema {
    Bool,
    Number,
    /// Closed vocabulary; a quarantined answer not in this list is rejected (fail-closed).
    Enum(Vec<String>),
}

/// The seam a real quarantined model implements. It receives the raw untrusted content and a
/// caller's question, and returns a *raw* answer string; the broker then validates that raw answer
/// against the [`QuarantineSchema`] before any value crosses into the privileged context. The model
/// has, by construction of this API, no way to invoke a tool.
pub trait QuarantinedLlm: Send + Sync {
    /// Answer `query` about `untrusted` content. The return is a raw string, deliberately never
    /// trusted verbatim — [`QuarantineBroker::resolve`] validates/coerces it to a typed value.
    fn extract(&self, untrusted: &str, query: &str) -> String;
}

/// One quarantined item.
struct Entry {
    symbol: String,
    raw: String,
    provenance: Provenance,
}

/// Mediates between the privileged and quarantined contexts. Untrusted content is registered here
/// (never inlined into the privileged prompt); the privileged prompt refers to it by symbol.
#[derive(Default)]
pub struct QuarantineBroker {
    entries: Vec<Entry>,
}

impl QuarantineBroker {
    pub fn new() -> Self {
        QuarantineBroker {
            entries: Vec::new(),
        }
    }

    /// Register a piece of untrusted content and return the opaque **symbol** to place in the
    /// privileged prompt in its stead. Trusted (user-authored) content is NOT quarantined — it is
    /// returned unchanged so the user's own instructions still reach the privileged model directly.
    pub fn quarantine(&mut self, text: &str, provenance: Provenance) -> String {
        if provenance.is_trusted() {
            return text.to_string();
        }
        let symbol = format!("$UNTRUSTED_{}", self.entries.len());
        self.entries.push(Entry {
            symbol: symbol.clone(),
            raw: text.to_string(),
            provenance,
        });
        symbol
    }

    /// Number of quarantined items.
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The text safe to hand the PRIVILEGED model for a symbol: the symbol plus its provenance tag,
    /// never the raw bytes. `None` if the symbol is unknown.
    pub fn privileged_reference(&self, symbol: &str) -> Option<String> {
        self.entries.iter().find(|e| e.symbol == symbol).map(|e| {
            format!(
                "{sym} (opaque {tag} content held in quarantine — not shown to this context)",
                sym = e.symbol,
                tag = provenance_tag(e.provenance),
            )
        })
    }

    /// The raw content for the QUARANTINED model only. Callers must only pass this to a
    /// [`QuarantinedLlm`], never into a privileged / tool-wielding prompt.
    pub fn raw_for_quarantined(&self, symbol: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|e| e.symbol == symbol)
            .map(|e| e.raw.as_str())
    }

    /// Run the quarantined model against one symbol and validate its raw answer against `schema`,
    /// returning a typed value that is safe to hand back to the privileged context. On any
    /// validation failure (unparsable / off-enum answer) the caller-supplied `default` is used —
    /// fail-closed, so a quarantined model cannot smuggle an out-of-schema string across the barrier.
    pub fn resolve(
        &self,
        symbol: &str,
        query: &str,
        schema: &QuarantineSchema,
        model: &dyn QuarantinedLlm,
        default: QuarantinedValue,
    ) -> QuarantinedValue {
        let Some(raw) = self.raw_for_quarantined(symbol) else {
            return default;
        };
        let answer = model.extract(raw, query);
        coerce(&answer, schema).unwrap_or(default)
    }

    /// Leak check: assert a would-be PRIVILEGED prompt does not contain any quarantined raw content
    /// verbatim (a defense-in-depth guard against a caller accidentally inlining untrusted bytes).
    /// `Ok(())` when clean; `Err(reason)` naming the leaking symbol otherwise. Only non-trivial
    /// content (>= 12 chars) is checked so incidental short substrings don't false-positive.
    pub fn assert_no_leak(&self, privileged_prompt: &str) -> Result<(), String> {
        for e in &self.entries {
            let raw = e.raw.trim();
            if raw.len() >= 12 && privileged_prompt.contains(raw) {
                return Err(format!(
                    "quarantine leak: raw untrusted content for {} appears in the privileged prompt",
                    e.symbol
                ));
            }
        }
        Ok(())
    }
}

fn provenance_tag(p: Provenance) -> &'static str {
    match p {
        Provenance::UserDirect => "user",
        Provenance::Retrieved => "retrieved-document",
        Provenance::ToolResult => "tool-result",
        Provenance::Connector => "connector-data",
    }
}

/// Validate/coerce a quarantined model's raw answer into the declared typed shape. Returns `None`
/// (→ fail-closed default) when the answer does not conform — including an enum answer that is not a
/// member of the allowed set, which is the channel an injection would try to abuse.
fn coerce(raw: &str, schema: &QuarantineSchema) -> Option<QuarantinedValue> {
    let t = raw.trim();
    match schema {
        QuarantineSchema::Bool => match t.to_ascii_lowercase().as_str() {
            "true" | "yes" | "1" => Some(QuarantinedValue::Bool(true)),
            "false" | "no" | "0" => Some(QuarantinedValue::Bool(false)),
            _ => None,
        },
        QuarantineSchema::Number => t.parse::<f64>().ok().map(QuarantinedValue::Number),
        QuarantineSchema::Enum(allowed) => allowed
            .iter()
            .find(|a| a.trim().eq_ignore_ascii_case(t))
            .map(|a| QuarantinedValue::Enum(a.clone())),
    }
}
