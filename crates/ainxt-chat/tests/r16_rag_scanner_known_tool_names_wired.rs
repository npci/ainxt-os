// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R16 gap closure — subsystem `guardrails-injection`: the RETRIEVED-content injection scanner's
//! "a document naming an internal tool" strong signal
//! (`ainxt_injection::InjectionDetector::known_tool_names`, weight 0.5 — crosses the default 0.5
//! threshold ALONE) never received the served registry's REAL tool names anywhere in the
//! composition root. Every `ChatSurface` constructor built its `ConversationManager` over the bare
//! `HeuristicInjectionScanner` (`InjectionDetector::default()`, empty `known_tool_names`), so a
//! poisoned KB chunk that ONLY names a real internal tool — no coercion phrase, no imperative, no
//! role-spoof, nothing else a heuristic scanner would catch — scored `0.0` and was never tainted.
//! The detector itself was fully built and unit-tested
//! (`ainxt-injection/tests/detect_test.rs::known_tool_name_in_untrusted_content_is_strong`,
//! `ainxt-injection/tests/r16_retrieved_content_indirect_injection_gate.rs::
//! r16_detector_is_config_driven_including_the_internal_tool_name_signal`) but had ZERO callers
//! outside those crate-local tests: `ainxt_tools::ToolRuntime` (the served registry) had no way to
//! hand its registered names to anything, and no `ChatSurface`/`ConversationManager` constructor
//! accepted a pre-configured detector at all.
//!
//! Fix: `ainxt_tools::ToolRuntime::tool_names()` (new) + `ChatSurface::with_injection_scanner`
//! (new, delegates to the already-public `ConversationManager::with_injection_scanner`) let
//! `ainxt-runtimed`'s composition root build the RAG scanner from the SAME `Arc<ToolRuntime>` it
//! installs on the engine: `InjectionDetector::default().with_tools(tools.tool_names())`.
//!
//! This test drives the SAME corpus chunk through a REAL, full `ChatSurface::turn()` (real
//! retrieval, real engine, real injection-taint audit call) twice — before wiring (documents
//! today's dead signal) and after (this closure) — with nothing else different.

use std::sync::{Arc, Mutex};

use ainxt_cache::{CacheConfig, Clock};
use ainxt_chat::ChatSurface;
use ainxt_context::{Chunk, Corpus};
use ainxt_injection::InjectionDetector;
use ainxt_protocol::Event;
use ainxt_runtime::audit::{AuditRecord, AuditSink};
use ainxt_runtime::authz::RbacAuthorizer;
use ainxt_runtime::compliance::RedactAndProceed;
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtime::Engine;
use ainxt_types::{DataClass, Principal};
use tokio::sync::mpsc;

#[derive(Debug, Default)]
struct FixedClock;
impl Clock for FixedClock {
    fn now(&self) -> u64 {
        1
    }
}

struct EchoProvider;
impl Provider for EchoProvider {
    fn id(&self) -> &str {
        "echo"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, _prompt: &str) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(8);
        tokio::spawn(async move {
            let _ = tx.send(Event::TextDelta("acknowledged".into())).await;
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

/// A KB chunk that names a real internal tool and NOTHING else suspicious — no coercion phrase, no
/// imperative-verb, no role-spoof, no encoded payload. Heavy keyword overlap with the query so
/// retrieval surfaces it regardless of ranking specifics; the only thing under test is whether the
/// tool-name signal fires, not whether retrieval works.
const NAMES_INTERNAL_TOOL_ONLY: &str =
    "Settlement reference guide: the ledger_transfer routine finalizes settlement for the nostro leg.";
const QUERY: &str = "settlement reference guide nostro leg finalize";

fn corpus() -> Corpus {
    Corpus::new().with(Chunk::new(
        "kb-1",
        "kb",
        NAMES_INTERNAL_TOOL_ONLY,
        DataClass::Internal,
    ))
}

fn router() -> ModelRouter {
    let mut r = ModelRouter::new();
    r.register(Box::new(EchoProvider));
    r
}

fn engine(audit: SharedAudit) -> Engine {
    Engine::new(
        Box::new(RedactAndProceed),
        Box::new(RbacAuthorizer),
        Box::new(audit),
        router(),
    )
}

fn tainted(audit: &SharedAudit) -> bool {
    audit
        .0
        .lock()
        .unwrap()
        .iter()
        .any(|s| s.contains("retrieval injection scan flagged"))
}

#[tokio::test]
async fn r16_rag_scanner_catches_internal_tool_name_once_the_registry_names_are_wired() {
    let principal = Principal::user("u", &["chat.send"]).with_clearance(DataClass::Internal);

    // --- BEFORE: the bare scanner every ChatSurface constructor built pre-closure
    //     (`HeuristicInjectionScanner` / `InjectionDetector::default()`, empty `known_tool_names`). ---
    let audit_before = SharedAudit::default();
    let chat_before = ChatSurface::from_engine(
        engine(audit_before.clone()),
        corpus(),
        CacheConfig::default(),
        Box::new(FixedClock),
    );
    let _ = chat_before
        .turn("s1", &principal, QUERY, DataClass::Internal)
        .await
        .expect("turn completes");
    assert!(
        !tainted(&audit_before),
        "FAIL-BEFORE control: a chunk that ONLY names an internal tool must NOT taint through the \
         pre-closure scanner (documents today's dead signal); audit={:?}",
        audit_before.0.lock().unwrap()
    );

    // --- AFTER: the SAME chunk, SAME query, through a scanner built with the real registry's tool
    //     names — exactly `ainxt-runtimed`'s new
    //     `InjectionDetector::default().with_tools(tools.tool_names())` wiring via the new
    //     `ChatSurface::with_injection_scanner`. ---
    let audit_after = SharedAudit::default();
    let chat_after = ChatSurface::from_engine(
        engine(audit_after.clone()),
        corpus(),
        CacheConfig::default(),
        Box::new(FixedClock),
    )
    .with_injection_scanner(Box::new(
        InjectionDetector::default().with_tools(vec!["ledger_transfer".to_string()]),
    ));
    let _ = chat_after
        .turn("s2", &principal, QUERY, DataClass::Internal)
        .await
        .expect("turn completes");
    assert!(
        tainted(&audit_after),
        "PASS-AFTER: naming a real internal tool must now taint the turn once the registry's names \
         reach the detector; audit={:?}",
        audit_after.0.lock().unwrap()
    );
    assert!(
        audit_after
            .0
            .lock()
            .unwrap()
            .iter()
            .any(|s| s.contains("ledger_transfer")),
        "the audit trail must record WHICH internal tool name fired, for regulator review"
    );
}
