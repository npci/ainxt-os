// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX regulated-fi-responsible-lifecycle (gap6, item 1) — closes the audited finding that
//! `ainxt_lifecycle::guarded::RetentionSweeper`/`sweep_now` never ran against real data: both live
//! call sites of `erase_subject_guarded` (`ainxt-runtimed::AssembledFull::erase_subject_attested`,
//! `ainxt-server::regfi_erasure_handler`) passed an explicitly EMPTY tier slice (`&mut []`), so
//! `RetentionSweeper`, `SessionReplayTier` (formerly nonexistent), `ErasableTier`, and
//! `erase_subject_from_tier` never ran against real data — only the empty-tier mirror/decide path
//! executed. A fired deferral updated the §6 mirror row but never touched the actual bytes sitting in
//! the served-turn replay `SessionStore`.
//!
//! This test drives the EXACT shipped composition (`assemble_chat` -> `assemble_full` ->
//! `serve_full_ext`) over a real socket + a real `reqwest` client (same harness as
//! `r16_regfi_erasure_guards_mirrored_turn.rs`), and proves the REAL mounted tier is swept:
//!
//! 1. A served `/v1/chat` turn for `"alice"` carrying `Pii` data is driven to completion — the
//!    served-turn write path mirrors it into the LIVE retention store AND persists the actual
//!    conversational bytes into the LIVE replay `SessionStore`.
//! 2. `POST /v1/regfi/erasure` for `"alice"` at a `now` well before the statutory `Pii` retention
//!    floor: the record is DEFERRED (`RetentionFloor`), never hard-erased — and the real session bytes
//!    still exist afterward (never-hard-delete-before-floor is a physical guarantee).
//! 3. `AssembledFull::run_retention_sweep_tick` (the new §6.3 cadence driver, the same method
//!    `spawn_retention_sweep`'s background loop calls) is driven ONCE at a `now` past the record's
//!    floor-expiry. The deferred entry fires AND propagates into the mounted `SessionReplayTier` —
//!    proven by reading the LIVE `SessionStore` directly afterward and finding the turn's event text
//!    erased (empty), not merely the §6 mirror row removed from the retention store.
//!
//! Fail-before/pass-after: reverting the `SessionReplayTier` mount at either erasure call site (back to
//! `&mut []`) makes step 3's final assertion fail — the sweep still fires the deferred queue and removes
//! the mirror row (the store-only half was already correct), but the REAL session bytes survive
//! untouched, which is exactly the audited defect.
//!
//! Deterministic ticks for the retention decision (`now` values passed explicitly to the erasure route
//! and to `run_retention_sweep_tick`); only the served turn's `created_tick` comes from real wall-clock
//! time (persisted by the shipped write path), which this test reads back rather than assumes.

use std::time::{SystemTime, UNIX_EPOCH};

use ainxt_runtimed::{assemble_chat, assemble_full, AssembledFull, SERVED_TURN_TIER};

/// The statutory retention floor `mounts::build_record_store` gives `DataClass::Pii` — 365 days in
/// seconds. Duplicated here (not `pub` on the mounts module) the same way `r16_regfi_erasure_guards_
/// mirrored_turn.rs` duplicates no lifecycle constants: this test reads the record's OWN
/// `created_tick` back from the live store and only needs the floor WIDTH to compute a `now` safely
/// past its expiry.
const PII_RETENTION_FLOOR_TICKS: u64 = 365 * 24 * 60 * 60;

fn loaded_with_unique_log() -> ainxt_runtimed::LoadedConfig {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("ainxt-gap6-lifecycle-{nanos}"));
    let src = format!(
        "version = 1\n[server]\nevent_log_dir = {:?}\n",
        dir.to_string_lossy()
    );
    ainxt_runtimed::load_layered(&[("gap6-lifecycle", &src)]).expect("load offline config")
}

/// Serve the EXACT fully-wired app `main` ships and return the bound address.
async fn serve_shipped(full: &AssembledFull) -> std::net::SocketAddr {
    let app = full.to_full_app();
    let ext = full.to_full_app_ext();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(ainxt_server::serve_full_ext(listener, app, ext));
    addr
}

#[tokio::test(flavor = "multi_thread")]
async fn retention_sweeper_deletes_real_session_bytes_at_floor_expiry() {
    use ainxt_lifecycle::guarded::qualified_id;

    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let loaded = loaded_with_unique_log();
    let assembled = assemble_chat(&loaded).expect("assemble chat");
    let full = assemble_full(&loaded, assembled).expect("assemble full");

    let addr = serve_shipped(&full).await;
    let client = reqwest::Client::new();

    let qid = qualified_id(SERVED_TURN_TIER, "u1");

    // Drive a served chat turn for alice carrying Pii data to completion.
    let chat = client
        .post(format!("http://{addr}/v1/chat"))
        .header("content-type", "application/json")
        .header("x-ainxt-user", "alice")
        .header("x-ainxt-clearance", "pii")
        .header("x-ainxt-department", "payments")
        .body(
            serde_json::json!({
                "session": "conv-gap6", "turn": "u1", "input": "what is my account status?",
                "data_class": "pii", "caps": ["chat.send"]
            })
            .to_string(),
        )
        .send()
        .await
        .expect("chat send");
    assert_eq!(
        chat.status().as_u16(),
        200,
        "the shipped daemon must serve the chat turn"
    );
    let _ = chat
        .text()
        .await
        .expect("drain chat body (lets the write-path task run)");

    // Sanity: the write path mirrored the turn AND wrote real bytes into the replay store.
    let created_tick = {
        let rs = full.retention.lock().unwrap();
        let rec = rs
            .get(&qid)
            .expect("served turn must be mirrored into the retention store");
        assert_eq!(rec.subject_id, "alice");
        rec.created_tick
    };
    let real_bytes_present = |full: &AssembledFull| -> bool {
        let durable = full
            .replay_store
            .load("conv-gap6")
            .expect("load session")
            .expect("session must exist");
        let rec = ainxt_replay::SessionRecording::from_durable(durable);
        rec.events()
            .iter()
            .any(|e| e.turn_id == "u1" && !e.text.is_empty())
    };
    assert!(
        real_bytes_present(&full),
        "sanity: the served turn's real content must be persisted in the replay store"
    );

    // Request erasure for alice well before the Pii statutory floor elapses: the record must be
    // DEFERRED, and the bytes must physically survive (never-hard-delete-before-floor).
    let erasure = client
        .post(format!("http://{addr}/v1/regfi/erasure"))
        .header("content-type", "application/json")
        .header("x-ainxt-user", "dpo")
        .header("x-ainxt-caps", "retention.admin")
        .body(serde_json::json!({"subject_id": "alice", "now": 1000}).to_string())
        .send()
        .await
        .expect("erasure send");
    assert_eq!(
        erasure.status().as_u16(),
        200,
        "erasure with CAP_RETENTION_ADMIN must be 200"
    );
    let att: serde_json::Value = erasure.json().await.expect("attestation json");
    let erased: Vec<String> = att
        .get("resolution")
        .and_then(|r| r.get("erased"))
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    assert!(
        !erased.contains(&qid),
        "the Pii record must not be hard-erased before its statutory floor elapses: {att}"
    );
    assert!(
        full.retention.lock().unwrap().get(&qid).is_some(),
        "the mirrored record must still exist in the retention store before floor-expiry"
    );
    assert!(
        real_bytes_present(&full),
        "the real session bytes must physically survive while the retention floor holds"
    );

    // Drive ONE retention-sweep tick (the same composition-root method `spawn_retention_sweep`'s
    // background loop calls) at a `now` safely past the record's floor-expiry.
    let sweep_now = created_tick + PII_RETENTION_FLOOR_TICKS + 10;
    let report = full
        .run_retention_sweep_tick(sweep_now)
        .expect("the sweeper is always due on its first tick");
    assert!(
        report.deferred_fired.contains(&qid),
        "the deferred queue must fire once the floor elapses: {report:?}"
    );
    assert!(
        report.tier_erased.contains(&qid),
        "the fired deferral must propagate into the REAL mounted SessionReplayTier: {report:?}"
    );

    // The §6 mirror row is gone from the retention store...
    assert!(
        full.retention.lock().unwrap().get(&qid).is_none(),
        "the retention store's mirror row must be removed once the sweep fires it"
    );
    // ...AND — the actual defect this test proves closed — the REAL bytes are gone from the live
    // replay SessionStore, not just the mirror row.
    assert!(
        !real_bytes_present(&full),
        "the sweep must delete the ACTUAL served-turn bytes in the replay store, not just the §6 \
         mirror row"
    );
    // The turn itself is never deleted (ainxt-replay's own invariant) — only its content bytes.
    {
        let durable = full.replay_store.load("conv-gap6").unwrap().unwrap();
        let rec = ainxt_replay::SessionRecording::from_durable(durable);
        assert!(
            rec.tree().turn("u1").is_some(),
            "the turn/tree row must remain (audit trail) — only the bytes are erased"
        );
    }
}
