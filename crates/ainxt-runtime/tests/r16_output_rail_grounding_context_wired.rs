// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R16 gap closure — subsystem `guardrails-injection`: the served OUTPUT rail call site inside
//! `Engine::run_turn` (`rails.evaluate(&final_text, &[])`) always evaluated the OUTPUT rail chain
//! against an EMPTY grounding slice, so `GroundednessRail` / `CitationRail` could never fire no matter
//! how `[guardrails]` is configured — pinned by
//! `ainxt-guardrails/tests/r15_output_rails_closed_by_empty_grounding_at_engine_call_site.rs`, whose own
//! doc comment states "nothing in `ainxt-runtime` is touched by this test" (i.e. it proves the RailChain
//! side is correct but does NOT touch the real served call site). This is every surface built over this
//! engine (chat/code/sdlc/program/team), not only the chat surface's separate,
//! RAG-context-aware `ConversationManager::check_grounding`.
//!
//! This test drives the REAL `Engine::run_turn_collect` end to end and proves the call site now threads
//! the turn's actually-retrieved content (the Context-Fabric memory-layer hits the engine already reads
//! and injects into the prompt, per `wire2_mem_04_test.rs`) into the rail context, instead of `&[]`.
//!
//! Deterministic discriminator: `CitationRail::check` short-circuits to `Pass` when `context.is_empty()`
//! (see `ainxt-guardrails/src/lib.rs`), so an answer with a citation index past the retrieved source
//! count is a "fabricated citation" ONLY when the rail is given a real, non-empty source list:
//!   - WITH a memory reader attached (one real source retrieved): a `[2]` citation is out of range and
//!     is FLAGGED.
//!   - WITHOUT a memory reader (no retrieved content at all): the exact same answer is NOT flagged,
//!     because there is genuinely nothing to fabricate a citation against — proving the call site is
//!     wired to the turn's REAL grounding, not just always populated / always empty.

use std::sync::{Arc, Mutex};

use ainxt_memory::{InMemoryStore, MemoryItem, MemoryKind, MemoryStore, Provenance, Scope};
use ainxt_protocol::{Event, Request};
use ainxt_runtime::audit::{AuditRecord, AuditSink};
use ainxt_runtime::authz::RbacAuthorizer;
use ainxt_runtime::compliance::RedactAndProceed;
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtime::{Engine, GuardrailsConfig, RailMode, SharedMemoryStore};
use ainxt_types::{DataClass, Principal};
use tokio::sync::mpsc;

/// Streams a fixed answer that cites a SECOND source (`[2]`) when at most one source is ever
/// retrieved this turn — a fabricated / out-of-range citation.
struct FixedAnswer(String);
impl Provider for FixedAnswer {
    fn id(&self) -> &str {
        "prov"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, _prompt: &str) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(8);
        let answer = self.0.clone();
        tokio::spawn(async move {
            let _ = tx.send(Event::TextDelta(answer)).await;
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

#[derive(Clone, Default)]
struct SharedAudit(Arc<Mutex<Vec<String>>>);
impl AuditSink for SharedAudit {
    fn record(&self, rec: AuditRecord) {
        self.0.lock().unwrap().push(rec.summary);
    }
}

fn store_with_one_fact() -> InMemoryStore {
    let mut store = InMemoryStore::new();
    store
        .write(MemoryItem::new(
            "fact-1",
            MemoryKind::UserPreference,
            Scope::User("alice".to_string()),
            "settlement fact",
            "the netting window closes at 22:00 IST",
            Provenance::human("alice", 1.0),
        ))
        .unwrap();
    store
}

const FABRICATED_CITATION_ANSWER: &str = "the netting window closes at 22:00 IST [2]";

fn engine(memory: Option<SharedMemoryStore>, audit: SharedAudit) -> Engine {
    let mut router = ModelRouter::new();
    router.register(Box::new(FixedAnswer(
        FABRICATED_CITATION_ANSWER.to_string(),
    )));
    let mut eng = Engine::new(
        Box::new(RedactAndProceed),
        Box::new(RbacAuthorizer),
        Box::new(audit),
        router,
    )
    .with_guardrails(&GuardrailsConfig {
        // Audit (not Enforce): `CitationRail::check` only ever returns `Flag`, never `Block`, so the
        // mode choice does not change the outcome here — Audit is the redact-don't-block posture the
        // recommended preset uses for citation in production.
        citation: RailMode::Audit,
        ..Default::default()
    });
    if let Some(m) = memory {
        eng = eng.with_memory(Box::new(m));
    }
    eng
}

async fn run(eng: &Engine) -> ainxt_runtime::TurnOutcome {
    let alice = Principal::user("alice", &["chat.send"]);
    eng.run_turn_collect(
        &alice,
        &Request::chat(
            "s",
            "t",
            "what closes the netting window?",
            DataClass::Public,
        ),
    )
    .await
    .expect("turn completes")
}

fn flagged_citation(audit: &SharedAudit) -> bool {
    audit
        .0
        .lock()
        .unwrap()
        .iter()
        .any(|s| s.contains("output guardrails flagged") && s.contains("citation"))
}

#[tokio::test]
async fn r16_output_rail_call_site_grounds_citation_rail_on_real_retrieved_context() {
    // --- WITH a real retrieved source (one memory hit): the fabricated `[2]` citation IS caught. ---
    let audit = SharedAudit::default();
    let eng = engine(
        Some(SharedMemoryStore::new(store_with_one_fact())),
        audit.clone(),
    );
    let out = run(&eng).await;

    assert_eq!(
        out.provider, "prov",
        "Audit mode never blocks — the answer must still stream"
    );
    assert!(
        out.final_text.contains("22:00 IST"),
        "the answer still reaches the user under Audit; got {:?}",
        out.final_text
    );
    assert!(
        flagged_citation(&audit),
        "the citation rail must be evaluated against the turn's real (non-empty) retrieved context \
         and flag the out-of-range [2] citation; audit={:?}",
        audit.0.lock().unwrap()
    );

    // --- WITHOUT any retrieved content (no memory reader attached): the SAME fabricated-citation
    //     answer is genuinely NOT flagged — there is nothing retrieved to fabricate a citation
    //     against. This is the discriminator that proves the call site threads the turn's REAL
    //     grounding rather than a constant (always-empty or always-populated) context. ---
    let audit2 = SharedAudit::default();
    let eng2 = engine(None, audit2.clone());
    let out2 = run(&eng2).await;

    assert_eq!(out2.provider, "prov");
    assert!(
        !flagged_citation(&audit2),
        "with zero retrieved content the citation rail has nothing to check against and must not \
         flag; audit={:?}",
        audit2.0.lock().unwrap()
    );
}
