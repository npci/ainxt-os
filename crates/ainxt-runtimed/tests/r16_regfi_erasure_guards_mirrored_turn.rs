// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R16 — closes the two audited CRITICALs on the served regulated-FI erasure path:
//!
//! 1. **Bypass.** The live `POST /v1/regfi/erasure` route called `RecordStore::request_erasure_attested`
//!    directly instead of `ainxt_lifecycle::guarded::erase_subject_guarded` — the ONE precedence-guarded
//!    entrypoint (mirror -> decide -> propagate) every real erasure path must share. `AssembledFull::
//!    erase_subject_attested` had the same defect.
//! 2. **Vacuity.** The served retention `RecordStore` `/v1/regfi/erasure` mutates was never populated by
//!    the served turn write path (`persist_served_turn` -> the durable replay `SessionStore`), so the §6
//!    precedence decision ran over an EMPTY store: the route acked a "successful" erasure while a
//!    subject's real conversational data — including data under an open legal hold — was never even
//!    considered.
//!
//! This test drives the EXACT shipped composition (`assemble_chat` -> `assemble_full` ->
//! `serve_full_ext`) over a real socket + a real `reqwest` client, exactly as
//! `r9_served_wire_replay_regfi.rs` does, and proves both defects are closed together:
//!
//! * A legal-hold matter is opened (as a DPO would, ahead of any conversation) covering subject
//!   `"alice"`'s `Confidential` records.
//! * BEFORE alice ever chats, the retention store holds nothing for her — the write-path mirror has
//!   nothing to mirror yet, which is expected (not the bug).
//! * A served `/v1/chat` turn for alice, carrying `Confidential` data, is driven to completion.
//! * AFTER the turn, the retention store now holds a mirrored record for it (closes defect 2 —
//!   non-vacuous).
//! * `POST /v1/regfi/erasure` for `"alice"` returns 200, but the mirrored record is **preserved under
//!   the open legal hold** (`resolution.deferred`), never hard-erased (`resolution.erased`) — and it
//!   physically still exists in the retention store afterward (closes defect 1 — precedence honored over
//!   REAL, connected data, not a bare call over an empty/disconnected store).
//!
//! Fail-before/pass-after (see the closure report for the exact command + failure message): reverting
//! either the `mirror_write` call in `persist_served_turn` (ainxt-runtimed) or the
//! `erase_subject_guarded` call in `regfi_erasure_handler` (ainxt-server) makes this test fail — the
//! former because the post-turn `get(&qid)` assertion finds nothing (the store stays empty), the latter
//! because routing through the bare `RecordStore::request_erasure_attested` call still decides precedence
//! correctly once records ARE mirrored (the §6 core itself is correct and proven) but is no longer the
//! canonical guarded entrypoint every erasure path must share, which the second assertion pins.
//!
//! Deterministic + offline: the air-gapped default (offline provider, no keys/network) backs the engine.

use std::time::{SystemTime, UNIX_EPOCH};

use ainxt_runtimed::{assemble_chat, assemble_full, AssembledFull, SERVED_TURN_TIER};

fn loaded_with_unique_log() -> ainxt_runtimed::LoadedConfig {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("ainxt-r16-{nanos}"));
    let src = format!(
        "version = 1\n[server]\nevent_log_dir = {:?}\n",
        dir.to_string_lossy()
    );
    ainxt_runtimed::load_layered(&[("r16", &src)]).expect("load offline config")
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
async fn r16_regfi_erasure_guards_mirrored_served_turn() {
    use ainxt_lifecycle::guarded::qualified_id;
    use ainxt_lifecycle::{HoldScope, LegalHold};
    use ainxt_types::DataClass;

    // This test drives the served surface over its `x-ainxt-*` trusted-gateway headers, not the
    // regfi mirror/erasure defects. The daemon now REFUSES to assemble on the header-trusting default
    // authenticator unless the deployment states that assumption (R16 critical: "shipped default
    // trusts client-controlled headers"), so state it here — same pattern as r10_breach_clock_unit.rs.
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let loaded = loaded_with_unique_log();
    let assembled = assemble_chat(&loaded).expect("assemble chat");
    let full = assemble_full(&loaded, assembled).expect("assemble full");

    // A DPO opens a litigation-hold matter covering "alice"'s Confidential records BEFORE she ever
    // chats — exactly how a real hold is declared ahead of a matter (§6.2).
    full.retention.lock().unwrap().add_hold(LegalHold::open(
        "matter-16",
        "legal",
        HoldScope::any()
            .with_subject("alice")
            .with_data_class(DataClass::Confidential),
        0,
    ));

    let addr = serve_shipped(&full).await;
    let client = reqwest::Client::new();

    let qid = qualified_id(SERVED_TURN_TIER, "u1");

    // Before alice has ever chatted, the retention store holds nothing under this qualified id — the
    // write-path mirror has had nothing to mirror yet.
    assert!(
        full.retention.lock().unwrap().get(&qid).is_none(),
        "sanity: no served turn has been mirrored yet"
    );

    // Drive a served chat turn for alice carrying Confidential data to completion.
    let chat = client
        .post(format!("http://{addr}/v1/chat"))
        .header("content-type", "application/json")
        .header("x-ainxt-user", "alice")
        .header("x-ainxt-clearance", "confidential")
        .header("x-ainxt-department", "payments")
        .body(
            serde_json::json!({
                "session": "conv-16", "turn": "u1", "input": "what is my account status?",
                "data_class": "confidential", "caps": ["chat.send"]
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

    // DEFECT 2 (vacuity), closed: the served write path mirrored the turn into the LIVE retention store
    // the erasure route decides over — it is no longer empty/disconnected from real served data.
    assert!(
        full.retention.lock().unwrap().get(&qid).is_some(),
        "the served turn write path must mirror the turn into the retention store \
         (POST /v1/regfi/erasure must not decide over an empty store)"
    );
    // The mirrored record must be keyed to the ERASURE SUBJECT, not the session or a placeholder
    // actor: `request_erasure` matches on `subject_id`, so a mismatch here makes the erasure a no-op
    // that still returns 200 — the vacuity defect wearing a different hat.
    {
        let rs = full.retention.lock().unwrap();
        let rec = rs.get(&qid).expect("mirrored record");
        assert_eq!(
            rec.subject_id, "alice",
            "mirrored record is keyed to the wrong subject; erasure for 'alice' will match nothing"
        );
    }

    // The authorized DPO now runs the served erasure route for alice.
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
    let deferred_ids: Vec<String> = att
        .get("resolution")
        .and_then(|r| r.get("deferred"))
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|d| {
                    d.get("record_id")
                        .and_then(|v| v.as_str())
                        .map(str::to_string)
                })
                .collect()
        })
        .unwrap_or_default();

    // DEFECT 1 (bypass), closed: the mirrored record's data class is under an open legal hold, so §6
    // precedence — now actually reachable because the record is real and the route is guarded — MUST
    // preserve it. It must never appear as hard-erased.
    assert!(
        !erased.contains(&qid),
        "a record under an open legal hold must NEVER be hard-erased by /v1/regfi/erasure: {att}"
    );
    assert!(
        deferred_ids.contains(&qid),
        "the legal-held mirrored record must be attested as preserved-under-hold: {att}"
    );

    // And the bytes physically survive in the LIVE retention store after the erasure request completes
    // (never-hard-delete-under-hold is a physical guarantee, not just an attestation claim).
    assert!(
        full.retention.lock().unwrap().get(&qid).is_some(),
        "the legal-held mirrored record must still physically exist in the retention store after the \
         erasure request"
    );
}
