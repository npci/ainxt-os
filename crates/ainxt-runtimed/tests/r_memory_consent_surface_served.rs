// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-3 memory — precise verification of the consent-management HTTP surface (design
//! `ENTERPRISE_MEMORY_LEARNING.md` §5 acceptance test "Consent round-trip": "a user's 'what do you
//! remember about me' view returns every item across all tiers with provenance ... delete removes the
//! item from active retrieval immediately"; §9 "Right-to-erasure cascade").
//!
//! A prior audit left this "partially wired via memory_delete_handler/export_subject_handler, not
//! fully verified." Every existing test that touches these routes either drives the standalone
//! `memory_router()` helper directly with a hand-built `ConsentBacking` (`ainxt-server`'s own
//! `#[cfg(test)]` module), or exercises a DIFFERENT slice of MEM-10 (`r16_memory_re_redact_sweep.rs`
//! drives the re-redact tick, never an HTTP route). None of them prove the three routes are actually
//! reachable through the EXACT shipped composition (`assemble_chat` -> `assemble_full` ->
//! `serve_full_ext`) over a real socket, wired to the SAME backend the chat engine itself writes to —
//! which is the one thing "reachability" actually means for a served daemon.
//!
//! This test closes that verification gap and pins the finding: **all three DPDP primitives the
//! design actually specifies for this surface — view (`GET /memory/consent`), export
//! (`GET /memory/export`), and erase (`DELETE /memory`) — are real and HTTP-reachable** over the
//! shipped daemon. (The design's own vocabulary at §5/§9 is view/edit/delete/export, never a
//! grant/revoke opt-in toggle — "revoke" maps onto erasure, which this proves end-to-end, including
//! that the erasure is durably visible to a subsequent independent read, not just a 200 status code.)
//!
//! Fail-before/pass-after: this test only requires code already on this branch (no new production
//! code was needed to CLOSE this item — verification found the surface already fully wired); it fails
//! if `memory_router` is ever unmounted from `assemble_full`'s router, or if any of the three handlers
//! stop reading/writing through the SAME `ConsentBacking` the chat engine's own memory reader uses.

use std::time::{SystemTime, UNIX_EPOCH};

use ainxt_memory::{
    ConsentBacking, DurableMemoryStore, MemoryItem, MemoryKind, MemoryStore, Provenance, Scope,
};
use ainxt_runtimed::{assemble_chat, assemble_full, AssembledFull};

fn loaded_with_unique_log() -> ainxt_runtimed::LoadedConfig {
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("ainxt-r-memconsent-{nanos}"));
    let src = format!(
        "version = 1\n[server]\nevent_log_dir = {:?}\n",
        dir.to_string_lossy()
    );
    ainxt_runtimed::load_layered(&[("r-memconsent", &src)]).expect("load offline config")
}

/// Serve the EXACT fully-wired app `main` ships and return the bound address — same helper shape as
/// `r16_regfi_erasure_guards_mirrored_turn.rs`'s `serve_shipped`.
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
async fn r_memory_consent_view_export_erase_are_all_served_over_the_shipped_daemon() {
    let loaded = loaded_with_unique_log();
    let assembled = assemble_chat(&loaded).expect("assemble chat");
    let full = assemble_full(&loaded, assembled).expect("assemble full");

    // Write a personal fact for "bob" directly into the SAME backend the served consent surface reads
    // — exactly how a real `remember` tool call or session-end promotion would populate it (this test
    // is about the SERVED SURFACE's reachability, not the write trigger, which is proven elsewhere).
    let backing = full
        .memory_consent
        .clone()
        .expect("a chat-engine surface exposes a memory backing (MEM-10)");
    let backend = match backing.as_ref() {
        ConsentBacking::Durable(backend) => backend.clone(),
        ConsentBacking::InMemory(_) => panic!("the shipped chat surface uses the Durable backing"),
    };
    {
        let mut store = DurableMemoryStore::open(backend.clone()).expect("open store");
        store
            .write(MemoryItem::new(
                "bob-pref-1",
                MemoryKind::Semantic,
                Scope::User("bob".into()),
                "preferred contact hours",
                "bob prefers async communication after 4pm IST",
                Provenance::human("bob", 1.0),
            ))
            .expect("seed write");
    }

    let addr = serve_shipped(&full).await;
    let client = reqwest::Client::new();

    // ---- 1. VIEW: GET /memory/consent — "what do you remember about me" ----
    let view = client
        .get(format!("http://{addr}/memory/consent?subject=bob"))
        .header("x-ainxt-user", "bob")
        .send()
        .await
        .expect("consent view request");
    assert_eq!(
        view.status().as_u16(),
        200,
        "GET /memory/consent must be served, not 404/unreachable"
    );
    let view_body: serde_json::Value = view.json().await.expect("consent view is JSON");
    assert_eq!(view_body["subject"], "bob");
    let view_text = view_body.to_string();
    assert!(
        view_text.contains("bob-pref-1"),
        "the consent view must surface the item actually written to the SAME backend the chat engine \
         writes to, not an empty/disconnected store: {view_text}"
    );

    // ---- 2. EXPORT: GET /memory/export — DPDP portability ----
    let export = client
        .get(format!("http://{addr}/memory/export?subject=bob"))
        .header("x-ainxt-user", "bob")
        .send()
        .await
        .expect("export request");
    assert_eq!(
        export.status().as_u16(),
        200,
        "GET /memory/export must be served, not 404/unreachable"
    );
    let export_body: serde_json::Value = export.json().await.expect("export is JSON");
    assert_eq!(export_body["subject"], "bob");
    let export_text = export_body.to_string();
    assert!(
        export_text.contains("bob-pref-1") && export_text.contains("async communication"),
        "the export must be a real machine-readable dump of the subject's actual data: {export_text}"
    );

    // A caller who is NOT the subject (and not an admin/break-glass) must be refused — the surface is
    // identity-derived, not a bare query-param lookup anyone can hit.
    let forbidden = client
        .get(format!("http://{addr}/memory/export?subject=bob"))
        .header("x-ainxt-user", "mallory")
        .send()
        .await
        .expect("forbidden export request");
    assert_eq!(
        forbidden.status().as_u16(),
        403,
        "a non-owner, non-break-glass caller must be refused another subject's export"
    );

    // ---- 3. ERASE: DELETE /memory — right-to-erasure ----
    let delete = client
        .delete(format!("http://{addr}/memory?subject=bob"))
        .header("x-ainxt-user", "bob")
        .send()
        .await
        .expect("delete request");
    assert_eq!(
        delete.status().as_u16(),
        200,
        "DELETE /memory must be served, not 404/unreachable"
    );
    let delete_body: serde_json::Value = delete.json().await.expect("delete response is JSON");
    assert_eq!(delete_body["subject"], "bob");
    assert_eq!(
        delete_body["removed"], 1,
        "exactly the one seeded item must be reported removed"
    );

    // Durability check: a SUBSEQUENT, independent read (a fresh HTTP call, not a cached response) must
    // show the item is really gone — proving the erasure landed in the durable backend, not just that
    // the route returned 200.
    let view_after = client
        .get(format!("http://{addr}/memory/consent?subject=bob"))
        .header("x-ainxt-user", "bob")
        .send()
        .await
        .expect("post-erase consent view request");
    assert_eq!(view_after.status().as_u16(), 200);
    let view_after_body: serde_json::Value =
        view_after.json().await.expect("post-erase view is JSON");
    assert!(
        !view_after_body.to_string().contains("bob-pref-1"),
        "the erased item must not reappear in a fresh view after DELETE /memory: {view_after_body}"
    );

    // And a THIRD, wholly independent store opened fresh over a clone of the SAME backend confirms the
    // erasure is durable at the storage layer, not an artifact of the served route's own transient view.
    let independent = DurableMemoryStore::open(backend).expect("reopen over the same backend");
    assert!(
        independent.get("bob-pref-1").is_none(),
        "the item must be gone from the durable backend itself, independently of the served route"
    );
}
