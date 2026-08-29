// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! gap6-pipeline-edit-tooling item 3 — proving test through the REAL served `/v1/edit/semantic` route
//! (the exact production composition `assemble_full`/`app_full_ext` builds, mirroring
//! `r8_shipped_auth_edit.rs`'s pattern), not a hand-assembled test-only `EditEngine`.
//!
//! `AgentOp::ReplaceFunction` now drives `ladder_driver::run_replace_ladder` from the served route: one
//! test resolves at the AST rung (`ainxt_semantic::replace_function`), a second forces the AST rung to
//! fail (an absent function name) and resolves at the structured-patch rung, proving
//! `ainxt_edit::apply` (`structured_apply`) is genuinely reached from production — before this round
//! `run_replace_ladder` had zero production callers and `ainxt_edit::apply`'s only non-test caller was
//! that same orphaned function.

use std::time::{SystemTime, UNIX_EPOCH};

use ainxt_runtimed::{assemble_full, assemble_surface, load_layered, LoadedConfig};

fn loaded() -> LoadedConfig {
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("ainxt-gap6-replace-fn-{nanos}"));
    let src = format!(
        "version = 1\n[server]\nevent_log_dir = {:?}\n",
        dir.to_string_lossy()
    );
    load_layered(&[("gap6-replace-fn", &src)]).expect("load offline config")
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

/// `AgentOp::ReplaceFunction` resolves at the **AST rung** through the real served route: the wired
/// ladder (`ladder_driver::run_replace_ladder`) calls `ainxt_semantic::replace_function` directly and
/// succeeds, so no structured/text fallback is ever consulted.
#[tokio::test(flavor = "multi_thread")]
async fn gap6_replace_function_resolves_at_ast_rung_on_the_served_route() {
    let loaded = loaded();
    let addr = serve(&loaded).await;

    let src = "fn caller() -> i32 {\n    target()\n}\n\nfn target() -> i32 {\n    1\n}\n";
    let body = serde_json::json!({
        "edit_id": "gap6-replace-ast",
        "files": [{"path": "w.rs", "lang": "rust", "source": src}],
        "op": {
            "op": "replace_function",
            "file": "w.rs",
            "function_name": "target",
            "new_def": "fn target() -> i32 {\n    2\n}"
        },
        "config": self_heal_config(),
    });

    let v = post_semantic(addr, &body).await;
    assert_eq!(v["kind"], "resolved", "the op must plan successfully: {v}");
    assert_eq!(
        v["rung"], "ast",
        "a resolvable function name/new_def must resolve at the AST rung: {v}"
    );
    // The trivial body replace actually commits through the full gate, proving the ladder's AST rung
    // genuinely spliced the new function body in, not merely "planned" something inert.
    assert_eq!(
        v["response"]["result"], "committed",
        "a clean single-function body replace must commit: {v}"
    );
    assert_eq!(
        v["response"]["versions"]["w.rs"], 1,
        "the replaced file must be committed: {v}"
    );
}

/// `AgentOp::ReplaceFunction` falls to the **structured-patch rung** through the real served route when
/// the AST rung cannot resolve `function_name` — proving `ainxt_edit::apply` (`structured_apply`) is
/// genuinely reached from production.
#[tokio::test(flavor = "multi_thread")]
async fn gap6_replace_function_falls_to_structured_patch_on_the_served_route() {
    let loaded = loaded();
    let addr = serve(&loaded).await;

    let src = "fn caller() -> i32 {\n    target()\n}\n\nfn target() -> i32 {\n    1\n}\n";
    let body = serde_json::json!({
        "edit_id": "gap6-replace-structured",
        "files": [{"path": "w2.rs", "lang": "rust", "source": src}],
        "op": {
            "op": "replace_function",
            // No function named this exists — forces `ainxt_semantic::replace_function` to fail
            // (`SemanticError::FunctionNotFound`), falling the ladder to the structured-patch rung.
            "file": "w2.rs",
            "function_name": "does_not_exist",
            "new_def": "fn does_not_exist() -> i32 {\n    9\n}",
            "anchored_edits": [
                {"op": "replace", "anchor": "    1\n", "replacement": "    2\n"}
            ]
        },
        "config": self_heal_config(),
    });

    let v = post_semantic(addr, &body).await;
    assert_eq!(
        v["kind"], "resolved",
        "the structured fallback must still plan successfully: {v}"
    );
    assert_eq!(
        v["rung"], "structured_patch",
        "the AST rung must have fallen through to the structured-patch rung: {v}"
    );
    assert_eq!(
        v["response"]["result"], "committed",
        "the structured-patched edit must commit through the full gate: {v}"
    );
    assert_eq!(
        v["response"]["versions"]["w2.rs"], 1,
        "the structured-patched file must be committed: {v}"
    );
}
