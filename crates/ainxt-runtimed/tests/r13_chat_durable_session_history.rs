// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! r13_chat_durable_session_history — GAP-AUDIT conversation-intelligence #2.
//!
//! `ainxt_convo::PersistentSessions` (durable, CHD-redacted, event-log-backed conversation history)
//! was fully built and unit-tested, but every served `ChatSurface` constructor built its
//! `ConversationManager` over the default `InMemorySessions` — so a served conversation's turn
//! history was lost on every daemon restart, even when `[server] event_log_dir` (the AUDIT log) was
//! configured, because nothing ever wired a SEPARATE durable store for CONVERSATION history at all.
//!
//! This drives one real turn through a `ChatSurface` built with `[server] chat_sessions_dir` set,
//! drops the surface (simulating a daemon restart), and proves the turn's history is durably readable
//! from a FRESH, independent handle over the same directory — the restart-survivability the feature
//! promises.

use ainxt_context::Corpus;
use ainxt_convo::{PersistentSessions, SessionStore};
use ainxt_runtimed::{build_chat_surface, load_layered, open_guarded_event_log};
use ainxt_types::{DataClass, Principal};

#[tokio::test(flavor = "multi_thread")]
async fn r13_chat_session_history_survives_a_simulated_restart() {
    let dir = std::env::temp_dir().join(format!("ainxt-test-chat-sessions-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let src = format!(
        "version = 1\n[server]\nchat_sessions_dir = {:?}\n",
        dir.to_string_lossy()
    );
    let loaded = load_layered(&[("x", &src)]).unwrap();

    {
        let (chat, report) = build_chat_surface(&loaded, Corpus::new()).unwrap();
        assert!(
            report
                .iter()
                .any(|r| r.contains("durable session history wired")),
            "the assembly report must announce durable session history: {report:?}"
        );
        let principal = Principal::user("u", &["chat.send"]).with_clearance(DataClass::Public);
        chat.turn("s-durable", &principal, "what is UPI?", DataClass::Public)
            .await
            .expect("turn must complete");
        // `chat` (and its in-process manager) is dropped here — simulating a daemon restart.
    }

    // A FRESH, independent handle over the SAME directory must see the turn's history — proving the
    // store is genuinely durable, not an in-memory store that happened to still be alive.
    let log = open_guarded_event_log(&dir).expect("reopen the same durable directory");
    let sessions = PersistentSessions::new(log);
    let history = sessions.history("s-durable");
    assert!(
        !history.is_empty(),
        "the session's history must survive a simulated restart: got {history:?}"
    );
    assert!(
        history.iter().any(|m| m.text.contains("what is UPI?")),
        "the user's turn must be durably recorded: {history:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn r13_chat_session_history_is_in_memory_by_default() {
    // No `chat_sessions_dir` configured: pre-existing behavior, unaffected. Sanity check that the
    // assembly report does NOT claim durable history when it wasn't requested.
    let loaded = load_layered(&[("x", "version = 1")]).unwrap();
    let (_chat, report) = build_chat_surface(&loaded, Corpus::new()).unwrap();
    assert!(
        !report.iter().any(|r| r.contains("durable session history wired")),
        "no chat_sessions_dir configured: history must stay in-memory (unchanged default): {report:?}"
    );
}
