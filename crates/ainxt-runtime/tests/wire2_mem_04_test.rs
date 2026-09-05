// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Wiring test for gap MEM-04: memory is read on the LIVE turn pipeline as Context-Fabric layer 12.
//!
//! Constructs the REAL `Engine` with a `SharedMemoryStore` attached and drives it end-to-end. It
//! proves:
//!   1. On the context-assembly step the engine calls the REAL `read_for_turn` under the CALLER's
//!      identity scope, and threads the governed hits into the prompt the provider actually sees.
//!   2. The per-turn lineage `(id, version)` is recorded to the audit trail (forensic replay, §7.4).
//!   3. Identity scoping is enforced by the engine path: a DIFFERENT caller's personal memory is NOT
//!      injected (no cross-user leak) — the read is pre-rank filtered, not a scope bypass.
//!   4. With NO memory reader attached the prompt is unchanged (pre-wire behavior preserved).

use std::sync::{Arc, Mutex};

use ainxt_memory::{InMemoryStore, MemoryItem, MemoryKind, MemoryStore, Provenance, Scope};
use ainxt_protocol::{Event, Request};
use ainxt_runtime::audit::{AuditRecord, AuditSink};
use ainxt_runtime::authz::RbacAuthorizer;
use ainxt_runtime::compliance::RedactAndProceed;
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtime::{Engine, SharedMemoryStore};
use ainxt_types::{DataClass, Principal};
use tokio::sync::mpsc;

/// Records the exact prompt it was streamed, then answers "ok".
struct PromptCapture {
    prompts: Arc<Mutex<Vec<String>>>,
}
impl Provider for PromptCapture {
    fn id(&self) -> &str {
        "capture"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, prompt: &str) -> mpsc::Receiver<Event> {
        self.prompts.lock().unwrap().push(prompt.to_string());
        let (tx, rx) = mpsc::channel(8);
        tokio::spawn(async move {
            let _ = tx.send(Event::TextDelta("ok".into())).await;
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

fn pref_for(user: &str, body: &str) -> MemoryItem {
    MemoryItem::new(
        &format!("pref-{user}"),
        MemoryKind::UserPreference,
        Scope::User(user.to_string()),
        "verbosity preference",
        body,
        Provenance::human(user, 1.0),
    )
}

/// A fresh store seeded with alice's AND bob's personal preferences (InMemoryStore is not Clone).
fn mk_store() -> InMemoryStore {
    let mut store = InMemoryStore::new();
    store
        .write(pref_for("alice", "alice prefers terse answers"))
        .unwrap();
    store
        .write(pref_for("bob", "bob prefers verbose answers"))
        .unwrap();
    store
}

fn build(reader: Option<SharedMemoryStore>) -> (Engine, Arc<Mutex<Vec<String>>>, SharedAudit) {
    let prompts = Arc::new(Mutex::new(Vec::new()));
    let audit = SharedAudit::default();
    let mut router = ModelRouter::new();
    router.register(Box::new(PromptCapture {
        prompts: prompts.clone(),
    }));
    let mut eng = Engine::new(
        Box::new(RedactAndProceed),
        Box::new(RbacAuthorizer),
        Box::new(audit.clone()),
        router,
    );
    if let Some(r) = reader {
        eng = eng.with_memory(Box::new(r));
    }
    (eng, prompts, audit)
}

#[tokio::test]
async fn wire2_mem_04() {
    // --- 1+2. Wired: alice's turn injects HER preference into the prompt, and lineage is audited. ---
    {
        let (eng, prompts, audit) = build(Some(SharedMemoryStore::new(mk_store())));
        let alice = Principal::user("alice", &["chat.send"]);
        let req = Request::chat("s", "t1", "how many decimals?", DataClass::Public);
        let out = eng.run_turn_collect(&alice, &req).await.unwrap();
        assert_eq!(out.final_text, "ok");

        let seen = prompts.lock().unwrap();
        let prompt = seen.last().expect("a prompt was streamed");
        assert!(
            prompt.contains("alice prefers terse answers"),
            "alice's governed memory must be threaded into the live prompt; got: {prompt}"
        );
        assert!(
            prompt.contains("[memory context"),
            "the memory context fence must be present; got: {prompt}"
        );
        // No cross-user leak on alice's own turn.
        assert!(
            !prompt.contains("bob prefers"),
            "another user's personal memory must NOT be injected"
        );

        let a = audit.0.lock().unwrap();
        assert!(
            a.iter()
                .any(|s| s.contains("memory read 1 item(s)") && s.contains("pref-alice@v")),
            "the per-turn memory lineage must be audited for forensic replay; audit={a:?}"
        );
    }

    // --- 3. Identity scoping on the engine path: an OUTSIDER caller with no personal memory gets
    //        nothing injected (pre-rank filter, not a bypass). ---
    {
        let (eng, prompts, _audit) = build(Some(SharedMemoryStore::new(mk_store())));
        let carol = Principal::user("carol", &["chat.send"]);
        let req = Request::chat("s", "t2", "hello", DataClass::Public);
        let _ = eng.run_turn_collect(&carol, &req).await.unwrap();
        let seen = prompts.lock().unwrap();
        let prompt = seen.last().unwrap();
        assert!(
            !prompt.contains("[memory context"),
            "a caller with no personal memory must get no memory block; got: {prompt}"
        );
        assert!(
            !prompt.contains("prefers"),
            "no other user's memory may leak"
        );
    }

    // --- 4. Control: NO memory reader → the prompt is exactly the (compliance-scanned) user input. ---
    {
        let (eng, prompts, audit) = build(None);
        let alice = Principal::user("alice", &["chat.send"]);
        let req = Request::chat("s", "t3", "how many decimals?", DataClass::Public);
        let _ = eng.run_turn_collect(&alice, &req).await.unwrap();
        let seen = prompts.lock().unwrap();
        let prompt = seen.last().unwrap();
        assert_eq!(
            prompt, "how many decimals?",
            "with no memory reader the prompt is unchanged (pre-wire behavior)"
        );
        assert!(
            !audit
                .0
                .lock()
                .unwrap()
                .iter()
                .any(|s| s.contains("memory read")),
            "no memory audit line when memory is not wired"
        );
    }
}
