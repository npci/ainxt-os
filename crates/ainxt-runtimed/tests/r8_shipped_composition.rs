// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-8 — three shipped-composition gaps closed on the ASSEMBLED daemon (fail-before / pass-after):
//!
//!   1. **CRITICAL — served retrieval enforces node-ACL pre-rank.** `corpus_for_scope` (the
//!      `ainxt-context` corpus the LIVE `ChatSurface` grounds over) now carries each KB document's
//!      per-node ACL (department / `ad_level` / groups) + RLS row-attributes, so a served chat turn
//!      is department-node-ACL filtered PRE-RANK. Before the fix the corpus dropped every non-class
//!      axis, so a cross-department document leaked into a caller's grounding + citations.
//!   2. **Guardrails + injection ON in the shipped daemon config.** `load_shipped` prepends the
//!      `SHIPPED_DEFAULTS` base layer (guardrails=audit, injection=enforce), so the shipped daemon is
//!      safety-on-by-default — and a served chat turn still 200s (audit flags-and-proceeds; a chat
//!      turn with no untrusted input is never injection-tainted).
//!   3. **Served replay write-path round-trips through the ONE durable SessionStore.** The served
//!      write-path (`AssembledFull::record_served_turn`) persists a turn tree into the SAME
//!      `SessionStore` the `/v1/replay/step` route serves from: before a write the served route 404s
//!      (empty store); after, it pages the served-recorded session.
//!
//! Deterministic + offline: the offline provider (no keys/network) backs the engine; the transport,
//! the SessionManager spine and the governed surfaces are the REAL production types.

use std::time::{SystemTime, UNIX_EPOCH};

use ainxt_chat::ChatReply;
use ainxt_context::{Chunk, Corpus};
use ainxt_profile::RetrievalScope;
use ainxt_runtimed::{
    assemble_full, assemble_surface, build_chat_surface, corpus_for_scope, load_layered,
    load_shipped, KbConfig, KbDocument, KbScope, LoadedConfig, ServedTurn,
};
use ainxt_types::{DataClass, Principal};

// ============================ helpers ============================

fn unique_log_src() -> String {
    // R16 critical: the daemon now refuses the header-trusting default authenticator unless the
    // deployment states the assumption (see r10_breach_clock_unit.rs) — state it here.
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("ainxt-r8sc-{nanos}"));
    format!(
        "version = 1\n[server]\nevent_log_dir = {:?}\n",
        dir.to_string_lossy()
    )
}

/// Two Confidential settlement docs, each node-ACL locked to a DIFFERENT department. A platform-scope
/// surface indexes both; the pre-rank RBAC decides who grounds on which.
fn kb_two_departments() -> KbConfig {
    let doc = |id: &str, dept: &str| KbDocument {
        id: id.into(),
        source: format!("{id}.md"),
        text: format!("settlement reconciliation runbook for department {dept}"),
        data_class: DataClass::Confidential,
        scope: KbScope::Platform,
        namespace: None,
        repo: None,
        department: Some(dept.into()),
        max_ad_level: None,
        allow_groups: vec![],
        deny_groups: vec![],
        row_attributes: std::collections::BTreeMap::new(),
    };
    KbConfig {
        documents: vec![doc("settle-a", "alpha"), doc("settle-b", "beta")],
        rls_department_isolation: false,
        rag_enabled: true,
    }
}

fn offline_loaded() -> LoadedConfig {
    load_layered(&[("t", "version = 1")]).expect("offline config")
}

/// The citation chunk-ids a served chat turn grounded on, for the given corpus + caller.
async fn served_citation_ids(
    loaded: &LoadedConfig,
    corpus: Corpus,
    caller: &Principal,
) -> Vec<String> {
    let (chat, _report) = build_chat_surface(loaded, corpus).expect("build chat surface");
    let reply = chat
        .turn(
            "s1",
            caller,
            "what is the settlement reconciliation runbook",
            DataClass::Confidential,
        )
        .await
        .expect("served chat turn");
    match reply {
        ChatReply::Answer { citations, .. } => citations.into_iter().map(|c| c.chunk_id).collect(),
        other => panic!("expected a grounded Answer, got {other:?}"),
    }
}

// ============================ item 1 — CRITICAL: node-ACL pre-rank on the LIVE served path ==========

#[tokio::test(flavor = "multi_thread")]
async fn r8_served_chat_enforces_node_acl_pre_rank() {
    let loaded = offline_loaded();
    let kb = kb_two_departments();

    // A caller in department alpha, cleared for Confidential (so the class filter admits both docs —
    // only the node-ACL can distinguish them).
    let alpha = Principal::user("u-alpha", &["chat.send"])
        .with_clearance(DataClass::Confidential)
        .with_department("alpha");

    // FAIL-BEFORE: the OLD corpus (no ACL — chunks built class-only, exactly what `corpus_for_scope`
    // produced before the fix) leaks beta's department-locked doc into an alpha caller's grounding.
    let no_acl: Vec<Chunk> = kb
        .documents
        .iter()
        .map(|d| Chunk::new(&d.id, &d.source, &d.text, d.data_class))
        .collect();
    let leaked = served_citation_ids(&loaded, Corpus::load(no_acl), &alpha).await;
    assert!(
        leaked.contains(&"settle-b".to_string()),
        "fail-before: a class-only corpus (no node-ACL) leaks beta's department-locked doc to an \
         alpha caller — the CRITICAL: {leaked:?}"
    );

    // PASS-AFTER: `corpus_for_scope` now preserves the per-node ACL, so the LIVE served retrieval
    // filters beta's doc PRE-RANK for an alpha caller — its existence never leaks into citations.
    let corpus = corpus_for_scope(&kb, RetrievalScope::PlatformAndNamespace);
    let ids = served_citation_ids(&loaded, corpus, &alpha).await;
    assert!(
        ids.contains(&"settle-a".to_string()),
        "alpha's own department doc must ground on the served path: {ids:?}"
    );
    assert!(
        !ids.contains(&"settle-b".to_string()),
        "beta's node-ACL doc must be filtered PRE-RANK for an alpha caller on the LIVE served chat \
         path — existence never leaks: {ids:?}"
    );
}

// ============================ item 2 — guardrails + injection ON in the shipped config ==============

#[test]
fn r8_shipped_defaults_turn_guardrails_and_injection_on() {
    // FAIL-BEFORE: the raw config (no shipped base) has both safety layers OFF — the pre-fix posture.
    let raw = load_layered(&[("t", "version = 1")]).expect("raw config");
    assert!(
        raw.runtime.guardrails.is_off(),
        "without the shipped base, guardrails default OFF"
    );
    assert!(
        raw.runtime.injection.is_off(),
        "without the shipped base, injection defaults OFF"
    );

    // PASS-AFTER: the SHIPPED daemon config (load_shipped prepends SHIPPED_DEFAULTS) turns both ON.
    let shipped = load_shipped(&[("t", "version = 1")]).expect("shipped config");
    assert!(
        !shipped.runtime.guardrails.is_off(),
        "the shipped daemon config must default guardrails ON"
    );
    assert!(
        !shipped.runtime.injection.is_off(),
        "the shipped daemon config must default injection ON"
    );
    assert_eq!(
        shipped.runtime.injection.mode_label(),
        "enforce",
        "shipped injection default = enforce (the real ADR-009 defense)"
    );

    // A deployment can still OVERRIDE back to off (config-first) — the base is a default, not a lock.
    let overridden = load_shipped(&[(
        "deploy",
        "version = 1\n[guardrails]\njailbreak = \"off\"\ngroundedness = \"off\"\ntoxicity = \"off\"\nsystem_prompt_leak = \"off\"\ncitation = \"off\"\n[injection]\nmode = \"off\"\n",
    )])
    .expect("override config");
    assert!(
        overridden.runtime.guardrails.is_off(),
        "a deployment may override guardrails off"
    );
    assert!(
        overridden.runtime.injection.is_off(),
        "a deployment may override injection off"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn r8_shipped_defaults_still_serve_chat_200() {
    // The shipped daemon (guardrails=audit + injection=enforce ON) must STILL serve a basic chat turn
    // on the air-gapped default — audit flags-and-proceeds and a no-untrusted-input turn is never
    // tainted, so /v1/chat stays 200 (the round-4 ship invariant, now with the safety layers ON).
    let loaded = load_shipped(&[("t", &unique_log_src())]).expect("shipped config");
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat");
    let full = assemble_full(&loaded, assembled).expect("assemble full");
    assert!(
        !loaded.runtime.guardrails.is_off() && !loaded.runtime.injection.is_off(),
        "the served daemon runs with the safety layers ON"
    );

    let app = full.to_full_app();
    let ext = full.to_full_app_ext();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(ainxt_server::serve_full_ext(listener, app, ext));
    let client = reqwest::Client::new();
    let chat = client
        .post(format!("http://{addr}/v1/chat"))
        .header("content-type", "application/json")
        .header("x-ainxt-user", "alice")
        .header("x-ainxt-clearance", "internal")
        .body(
            serde_json::json!({"session":"s1","turn":"t1","input":"hello","data_class":"public","caps":["chat.send"]})
                .to_string(),
        )
        .send()
        .await
        .expect("chat send")
        .status()
        .as_u16();
    assert_eq!(
        chat, 200,
        "shipped daemon (safety ON) must still serve chat: got {chat}"
    );
}

// ============================ item 4 — served replay write-path round-trips the ONE store ===========

#[tokio::test(flavor = "multi_thread")]
async fn r8_served_replay_write_path_round_trips_through_one_store() {
    let loaded = load_shipped(&[("t", &unique_log_src())]).expect("shipped config");
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat");
    let full = assemble_full(&loaded, assembled).expect("assemble full");

    // The running server's /v1/replay/step reads the SAME store Arc the write-path writes to.
    let app = full.to_full_app();
    let ext = full.to_full_app_ext();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(ainxt_server::serve_full_ext(listener, app, ext));
    let client = reqwest::Client::new();

    let step = |session: &str| {
        let client = client.clone();
        let session = session.to_string();
        async move {
            client
                .post(format!("http://{addr}/v1/replay/step"))
                .header("content-type", "application/json")
                .header("x-ainxt-user", "alice")
                .header("x-ainxt-clearance", "confidential")
                .header("x-ainxt-caps", "chat.send")
                .body(serde_json::json!({"session": session, "from_index": 0}).to_string())
                .send()
                .await
                .expect("replay/step send")
        }
    };

    // FAIL-BEFORE: nothing on the served path has persisted this session → the served route 404s.
    let before = step("served-1").await.status().as_u16();
    assert_eq!(
        before, 404,
        "before the served write-path, /v1/replay/step has no served session to page: got {before}"
    );

    // Served WRITE-PATH: persist a served turn into the ONE durable store the route reads.
    full.record_served_turn(&ServedTurn {
        session: "served-1".into(),
        participant: "alice".into(),
        turn_id: "u1".into(),
        user_input: "what is the settlement runbook".into(),
        answer_text: "the runbook is in the ops wiki".into(),
        data_class: DataClass::Internal,
        at_millis: 1,
    })
    .expect("served replay write-path persists the turn");

    // PASS-AFTER: the SAME served route now pages the served-recorded session (round-trip closed).
    let resp = step("served-1").await;
    let after = resp.status().as_u16();
    assert_eq!(
        after, 200,
        "after the served write-path, /v1/replay/step pages the recorded session through the ONE \
         store: got {after}"
    );
    let page: serde_json::Value = resp.json().await.expect("replay page json");
    let step_count = page
        .get("steps")
        .and_then(|s| s.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    assert!(
        step_count > 0,
        "the served-recorded session must page at least one replay step: {page}"
    );

    // The store instance the write-path used and the one the route serves are the SAME (one store).
    assert!(
        !full
            .replay_store()
            .load("served-1")
            .expect("load")
            .is_none(),
        "the served turn is durable in the ONE SessionStore"
    );
}
