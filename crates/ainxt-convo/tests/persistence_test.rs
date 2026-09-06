// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Durability/resume: with event-log-backed sessions, the referent-resolution fix survives a
//! process restart — turn 2 ("generate this as pdf") resolves to the PERSISTED prior answer.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use ainxt_convo::{ConversationManager, HeuristicClassifier, ManagerOutcome, PersistentSessions};
use ainxt_eventlog::JsonlEventLog;
use ainxt_protocol::Event;
use ainxt_runtime::engine_with_defaults;
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_types::{DataClass, Principal};
use tokio::sync::mpsc;

struct UpiProvider;
impl Provider for UpiProvider {
    fn id(&self) -> &str {
        "mock"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, _prompt: &str) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(8);
        tokio::spawn(async move {
            let _ = tx
                .send(Event::TextDelta(
                    "UPI transaction volume grew ~45% YoY.".to_string(),
                ))
                .await;
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

fn temp_dir() -> PathBuf {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("ainxt-convo-persist-{}-{n}", std::process::id()))
}

fn manager_on(dir: &PathBuf) -> ConversationManager<HeuristicClassifier> {
    let mut router = ModelRouter::new();
    router.register(Box::new(UpiProvider));
    let log = JsonlEventLog::open(dir).expect("open log");
    ConversationManager::with_stores(
        engine_with_defaults(router),
        HeuristicClassifier,
        Box::new(PersistentSessions::new(log)),
        None,
    )
}

fn user() -> Principal {
    Principal::user("analyst", &["chat.send"])
}

#[tokio::test]
async fn referent_fix_survives_a_restart() {
    let dir = temp_dir();

    // Session 1: ask the question; the answer is persisted to the event log.
    {
        let m1 = manager_on(&dir);
        let a1 = m1
            .handle("s", &user(), "UPI growth?", DataClass::Public)
            .await
            .unwrap();
        assert!(matches!(a1, ManagerOutcome::Answer { .. }));
    } // drop everything — simulate a process restart

    // Session 2: a BRAND-NEW manager + fresh event log on the SAME dir (no in-memory state).
    let m2 = manager_on(&dir);
    let out = m2
        .handle("s", &user(), "generate this as pdf", DataClass::Public)
        .await
        .unwrap();
    match out {
        ManagerOutcome::Document { content, .. } => {
            assert!(
                content.contains("UPI"),
                "referent must resolve from the PERSISTED prior answer after restart: {content:?}"
            );
            assert!(
                !content.contains("generate this as pdf"),
                "must not be the instruction"
            );
        }
        other => panic!("expected a Document resolved from persisted history, got {other:?}"),
    }

    std::fs::remove_dir_all(&dir).ok();
}
