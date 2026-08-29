// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX conversation-intelligence — the served chat/code/sdlc/buddy engine builder
//! (`build_chat_surface_wired_authz` in `ainxt-runtimed`) fell back to
//! `ChatSurface::from_engine_numeric_gated_with_prompt` (hardcoded `ChatClassifier::Heuristic`) when
//! no live grammar/schema-capable model is configured — the shipped air-gapped default. This never
//! reached `ChatSurface::from_engine_classified_numeric_gated_with_prompt`'s own already-fixed `None`
//! arm (see its GAP-FIX doc comment in `ainxt-chat`), which installs
//! `ainxt_convo::ModelIntentClassifier::offline()` — a real confidence-graded Stage-3 "ask third"
//! classifier over the zero-infra `LexicalLabelModel`. So on the SHIPPED daemon (no live model
//! configured is the default posture), a genuinely ambiguous turn was silently resolved by the bare
//! deterministic-priority `HeuristicClassifier` instead of asking for clarification — Stage-3 was
//! reachable only from `ainxt-chat`'s/`ainxt-convo`'s own tests, never a served turn.
//!
//! Proves the fix through the REAL composition-root entrypoint (`build_chat_surface_wired`, the
//! function `assemble_chat`/`assemble_chat_governed`/`assemble_surface` all bottom out through) with
//! the default config (no `[[models.providers]]` grammar/schema-capable entry) — not `ainxt-chat`'s
//! own unit-level constructor.

use ainxt_context::Corpus;
use ainxt_runtimed::{build_chat_surface_wired, load_layered};
use ainxt_types::{DataClass, Principal};

#[tokio::test(flavor = "multi_thread")]
async fn r_served_default_engine_clarifies_on_genuine_lexical_ambiguity_not_silent_heuristic() {
    // No providers configured at all ⇒ `build_chat_classifier_model` returns `None` ⇒ the fixed arm.
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
        report.iter().any(|l| l.contains("offline Stage-3")),
        "the assembly report must record the offline Stage-3 classifier, not the bare heuristic: \
         {report:?}"
    );

    let principal = Principal::user("u", &["chat.send"]).with_clearance(DataClass::Public);
    // "compare this code" carries BOTH a comparison cue and a code cue — a real ambiguity the bare
    // HeuristicClassifier resolves silently by priority order and never asks about (see
    // `ainxt-chat/tests/r6_served_intelligence.rs`'s identical scenario at the unit level).
    let reply = chat
        .turn(
            "s-stage3",
            &principal,
            "compare this code",
            DataClass::Public,
        )
        .await
        .expect("turn must complete");

    match reply {
        ainxt_chat::ChatReply::Clarify { question } => {
            assert!(
                !question.is_empty(),
                "a clarify reply must carry a real question"
            );
        }
        other => panic!(
            "the served default (no live model configured) must clarify on genuine ambiguity via \
             the offline Stage-3 classifier, not silently answer: {other:?}"
        ),
    }
}
