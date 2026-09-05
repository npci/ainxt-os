// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! gap6-pipeline-edit-tooling item 4 — proving test through the REAL served `/v1/edit/semantic` route
//! (the exact production composition `assemble_full`/`app_full_ext` builds, mirroring
//! `r8_shipped_auth_edit.rs`'s pattern), not a hand-assembled test-only `EditEngine`.
//!
//! `AgentOp::Rename` now falls back to `ainxt_edit::field_rename_via_xref` when the AST symbol graph
//! reports `SymbolNotFound` (struct/enum fields are not graph nodes at all — see
//! `ainxt_semantic::graph::DefKind`), proving the field-rename primitives are genuinely reached from
//! production, never just `ainxt-edit`'s own tests.

use std::time::{SystemTime, UNIX_EPOCH};

use ainxt_runtimed::{assemble_full, assemble_surface, load_layered, LoadedConfig};

fn loaded() -> LoadedConfig {
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("ainxt-gap6-field-rename-{nanos}"));
    let src = format!(
        "version = 1\n[server]\nevent_log_dir = {:?}\n",
        dir.to_string_lossy()
    );
    load_layered(&[("gap6-field-rename", &src)]).expect("load offline config")
}

/// Assemble the fully-wired shipped surface and serve it over HTTP — the REAL production composition
/// root (`ainxt-runtimed::assemble_full` -> `ainxt-server::app_full_ext`), exactly as the daemon boots.
async fn serve(loaded: &LoadedConfig) -> std::net::SocketAddr {
    let assembled = assemble_surface(loaded, "chat").expect("assemble chat surface");
    let full = assemble_full(loaded, assembled).expect("assemble fully-wired surface");
    let app = full.to_full_app();
    let ext = full.to_full_app_ext();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(ainxt_server::serve_full_ext(listener, app, ext));
    addr
}

async fn post_semantic(addr: std::net::SocketAddr, body: &serde_json::Value) -> serde_json::Value {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{addr}/v1/edit/semantic"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header("x-ainxt-user", "dev")
        .header("x-ainxt-caps", "code.edit.apply")
        .body(body.to_string())
        .send()
        .await
        .expect("send");
    assert_ne!(
        resp.status().as_u16(),
        404,
        "/v1/edit/semantic must be served by the shipped daemon"
    );
    assert!(
        resp.status().is_success(),
        "authorized semantic edit reaches the gate: {}",
        resp.status()
    );
    serde_json::from_str(&resp.text().await.expect("body")).expect("json")
}

fn self_heal_config() -> serde_json::Value {
    serde_json::json!({
        "lang": "rust",
        "tier": "local",
        "rung": "ast",
        "max_rounds": 5,
        "stuck": [3, 0.9],
        "blast_radius_test_coverage": 1.0,
        "architecture_violations": 0,
        "judge_approved": null,
        "policy": { "auto_complete_threshold": 90, "review_threshold": 70, "trivial_auto_approve_floor": 60 },
        "blast_fan_out": 0
    })
}

/// `AgentOp::Rename` on a struct **field** (not a function/type — the AST symbol graph never models
/// fields) now falls back to `ainxt_edit::field_rename_via_xref` through the real served route instead
/// of refusing with `SymbolNotFound`, and rewrites every whole-word occurrence — never a declaration-
/// only edit that would leave a call site dangling (the exact historical bug `ainxt-edit`'s module doc
/// encodes as an invariant). Before this round, `field_rename_is_safe`/`field_rename_via_xref` had zero
/// callers outside `ainxt-edit`'s own `#[cfg(test)]` module.
#[tokio::test(flavor = "multi_thread")]
async fn gap6_rename_falls_back_to_field_rename_via_xref_on_the_served_route() {
    let loaded = loaded();
    let addr = serve(&loaded).await;

    let src = "struct Widget {\n    count: i64,\n}\n\nfn bump(w: &mut Widget) {\n    w.count = w.count + 1;\n}\n\nfn peek(w: &Widget) -> i64 {\n    w.count\n}\n";
    let body = serde_json::json!({
        "edit_id": "gap6-field-rename",
        "files": [{"path": "f.rs", "lang": "rust", "source": src}],
        "op": { "op": "rename", "old": "count", "new": "total" },
        "config": self_heal_config(),
    });

    let v = post_semantic(addr, &body).await;
    assert_eq!(
        v["kind"], "resolved",
        "a field rename must now plan successfully via the xref fallback, not PlanRejected: {v}"
    );
    assert_eq!(
        v["rung"], "structured_patch",
        "the field-rename fallback is a text-level xref rewrite, never claimed as AST-grade: {v}"
    );
    // `ainxt_edit::field_rename_via_xref` genuinely ran and its rewrite committed.
    assert_eq!(
        v["response"]["result"], "committed",
        "the field-rename fallback's rewrite must commit through the full gate: {v}"
    );
    assert_eq!(
        v["response"]["versions"]["f.rs"], 1,
        "the field-renamed file must be committed: {v}"
    );
}

/// A rename whose `old` identifier does not occur anywhere in the file (not a function/type, and not
/// present as text either) is still honestly refused — the fallback does not turn every failed AST
/// rename into a fabricated success.
#[tokio::test(flavor = "multi_thread")]
async fn gap6_rename_of_a_truly_absent_identifier_is_still_plan_rejected() {
    let loaded = loaded();
    let addr = serve(&loaded).await;

    let src = "struct Widget {\n    count: i64,\n}\n";
    let body = serde_json::json!({
        "edit_id": "gap6-field-rename-absent",
        "files": [{"path": "f2.rs", "lang": "rust", "source": src}],
        "op": { "op": "rename", "old": "nonexistent_xyz", "new": "whatever" },
        "config": self_heal_config(),
    });

    let v = post_semantic(addr, &body).await;
    assert_eq!(
        v["kind"], "plan_rejected",
        "an identifier absent from the file entirely must still be refused, never fabricated: {v}"
    );
}
