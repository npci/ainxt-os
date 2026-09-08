// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Which intent classifier the SERVED chat surface wires by default.
//!
//! History, because the answer here has changed twice. GAP-FIX conversation-intelligence made the
//! composition root reach `ChatSurface::from_engine_classified_numeric_gated_with_prompt`, so on the
//! air-gapped default (no grammar/schema-capable model configured) a genuinely ambiguous turn got a
//! confidence-graded Stage-3 clarify from `ainxt_convo::ModelIntentClassifier::offline()` instead of
//! being resolved silently by deterministic priority order.
//!
//! That was then reverted deliberately (see the `LATENCY FIX` comment at the wiring site in
//! `ainxt-runtimed`): the model-backed classifier makes a SEPARATE LLM call before the answer,
//! adding seconds to every turn. For plain Q&A chat the deterministic `HeuristicClassifier` is
//! considered sufficient; the model-backed path remains available via
//! `from_engine_classified_numeric_gated_with_prompt` for agentic surfaces that carry side effects.
//!
//! This test pins the CURRENT contract through the real composition-root entrypoint
//! (`build_chat_surface_wired`), so that re-introducing a per-turn classification call to the chat
//! surface has to be a conscious decision rather than a silent latency regression.
//!
//! NOTE: the consequence is that the served chat default does NOT ask for clarification on genuine
//! lexical ambiguity — it answers. Stage-3 clarify is still covered at the unit level in
//! `ainxt-chat` / `ainxt-convo`.

use ainxt_context::Corpus;
use ainxt_runtimed::{build_chat_surface_wired, load_layered};
use ainxt_types::{DataClass, Principal};

#[tokio::test(flavor = "multi_thread")]
async fn r_served_default_chat_surface_wires_the_latency_optimised_heuristic_classifier() {
    // No providers configured at all — the shipped air-gapped default posture.
    let loaded = load_layered(&[("x", "version = 1")]).unwrap();
    let (
        chat,
        _wire_rx,
        report,
        _ledger,
        _reconciler,
        _probe,
        _tools,
        _memory_backend,
        _outsourcing,
        _mandate_registry,
        _mcp_admin,
        _serving,
    ) = build_chat_surface_wired(&loaded, Corpus::new()).unwrap();

    assert!(
        report
            .iter()
            .any(|l| l.contains("heuristic intent classifier wired")),
        "the assembly report must record which classifier the served chat surface got: {report:?}"
    );
    assert!(
        !report.iter().any(|l| l.contains("offline Stage-3")),
        "the chat surface must NOT wire the model-backed Stage-3 classifier — that is the per-turn \
         LLM call the latency fix removed: {report:?}"
    );

    let principal = Principal::user("u", &["chat.send"]).with_clearance(DataClass::Public);
    // "compare this code" carries BOTH a comparison cue and a code cue — genuine lexical ambiguity.
    // The heuristic resolves it by priority order and answers; it does not stop to ask.
    let reply = chat
        .turn(
            "s-stage3",
            &principal,
            "compare this code",
            DataClass::Public,
        )
        .await
        .expect("turn must complete");

    assert!(
        !matches!(reply, ainxt_chat::ChatReply::Clarify { .. }),
        "the latency-optimised served default answers an ambiguous turn rather than clarifying — a \
         Clarify here means the per-turn classification call is back: {reply:?}"
    );
}
