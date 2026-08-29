// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R11 (Prompt Engineering, §BE) — ADAPTIVE REASONING DEPTH on the *layered served path*.
//!
//! The shipped default served the layered per-model prompt via `compile_turn`, which always ran at a
//! fixed tier (no depth classification → no routing-by-depth on the production path). This proves the
//! new `PromptService::compile_turn_adaptive` entrypoint: it classifies the RAW user message, injects a
//! depth-appropriate `[REASONING]` directive into the compiled system prompt, and returns the depth so
//! the caller routes by it (`depth.tier()`). The forensic record is still written BEFORE returning.
//!
//! FAIL-BEFORE: `compile_turn_adaptive` did not exist (won't compile). PASS-AFTER: green. Offline.

use ainxt_prompt::layered::{HeuristicTokens, PromptEventRecord, TruncatingCondenser};
use ainxt_prompt::registry::content_fingerprint;
use ainxt_prompt::served::default_served_chat_prompts;
use ainxt_prompt::service::{EventSink, NullSink, PromptService};
use ainxt_prompt::{HeuristicComplexity, ReasoningDepth};
use ainxt_types::Tier;
use std::sync::Mutex;

struct RecordingSink(Mutex<Vec<PromptEventRecord>>);
impl EventSink for RecordingSink {
    fn record_prompt(&self, record: &PromptEventRecord) {
        self.0.lock().unwrap().push(record.clone());
    }
}

static EST: HeuristicTokens = HeuristicTokens;
static COND: TruncatingCondenser = TruncatingCondenser;
fn svc() -> PromptService<'static> {
    PromptService::new(&EST, &COND, 10_000)
}

#[test]
fn r11_layered_served_compile_is_adaptive_deep_vs_shallow() {
    let served = default_served_chat_prompts();
    let ids: Vec<&str> = served.layer_ids.iter().map(|s| s.as_str()).collect();
    let fam = &served.families[0];
    let service = svc();

    // A DEEP query ("analyze … trade-offs") → Deep depth, Complex tier, deep directive injected.
    let (deep, depth) = service
        .compile_turn_adaptive(
            &served.registry,
            &served.deployment,
            &NullSink,
            "turn-deep",
            fam,
            &ids,
            "Retrieved: settlement windows.",
            &served.control_sha,
            "Analyze why the settlement window design causes reconciliation risk and the trade-offs.",
            &HeuristicComplexity,
        )
        .unwrap();
    assert_eq!(depth, ReasoningDepth::Deep);
    assert_eq!(depth.tier(), Tier::Complex);
    assert!(
        deep.text.contains("[REASONING]"),
        "a reasoning directive must be injected"
    );
    assert!(
        deep.text.contains("step by step"),
        "the DEEP directive must be present on the served layered prompt"
    );

    // A trivial greeting → Shallow depth, Simple tier, concise directive.
    let (shallow, sdepth) = service
        .compile_turn_adaptive(
            &served.registry,
            &served.deployment,
            &NullSink,
            "turn-hi",
            fam,
            &ids,
            "ctx",
            &served.control_sha,
            "hi",
            &HeuristicComplexity,
        )
        .unwrap();
    assert_eq!(sdepth, ReasoningDepth::Shallow);
    assert_eq!(sdepth.tier(), Tier::Simple);
    assert!(shallow.text.contains("Answer directly and concisely."));
    // The two depths produce genuinely different prompts (depth is load-bearing, not cosmetic).
    assert_ne!(deep.text, shallow.text);
}

#[test]
fn r11_plain_compile_turn_has_no_reasoning_block_but_adaptive_does() {
    // Proves the delta this gap closes: the pre-existing layered path had NO reasoning directive.
    let served = default_served_chat_prompts();
    let ids: Vec<&str> = served.layer_ids.iter().map(|s| s.as_str()).collect();
    let fam = &served.families[0];
    let service = svc();

    let plain = service
        .compile_turn(
            &served.registry,
            &served.deployment,
            &NullSink,
            "t",
            fam,
            &ids,
            "ctx",
            &served.control_sha,
        )
        .unwrap();
    assert!(
        !plain.text.contains("[REASONING]"),
        "the fixed path carries no depth directive"
    );

    let (adaptive, _) = service
        .compile_turn_adaptive(
            &served.registry,
            &served.deployment,
            &NullSink,
            "t",
            fam,
            &ids,
            "ctx",
            &served.control_sha,
            "Explain and analyze the design in detail.",
            &HeuristicComplexity,
        )
        .unwrap();
    assert!(adaptive.text.contains("[REASONING]"));
}

#[test]
fn r11_adaptive_compile_records_forensically_before_returning() {
    let served = default_served_chat_prompts();
    let ids: Vec<&str> = served.layer_ids.iter().map(|s| s.as_str()).collect();
    let fam = &served.families[0];
    let sink = RecordingSink(Mutex::new(Vec::new()));
    let service = svc();

    let (compiled, _) = service
        .compile_turn_adaptive(
            &served.registry,
            &served.deployment,
            &sink,
            "turn-x",
            fam,
            &ids,
            "ctx",
            &served.control_sha,
            "why does this happen",
            &HeuristicComplexity,
        )
        .unwrap();

    let recs = sink.0.lock().unwrap();
    assert_eq!(
        recs.len(),
        1,
        "exactly one forensic record, emitted before return"
    );
    // The record's hash covers the EXACT compiled text (including the injected reasoning block) →
    // the served turn's depth decision is byte-for-byte replayable.
    assert_eq!(recs[0].prompt_hash, content_fingerprint(&compiled.text));
}
