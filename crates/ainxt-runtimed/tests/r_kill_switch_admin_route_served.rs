// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX identity-payments (ADR-022 §17/§19 "big red button" + direct revoke) — PROVES THE REAL
//! OPERATOR TRIGGER, not merely the composition-root passthrough.
//!
//! Before this fix: `ainxt_identity::control::ControlPlane::pull_kill_switch`/`release_kill_switch`/
//! `revoke_run`/`revoke_user` were fully implemented and unit-tested, and `AssembledFull` even exposed
//! served passthroughs (`AssembledFull::pull_kill_switch` etc., GAP-FIX `e759a5a`) — but NOTHING on the
//! shipped daemon ever called those passthroughs: no HTTP route, no CLI subcommand. Every prior proving
//! test (`r_kill_switch_served.rs`, `gap_identity_payments_chat_governed_selectable.rs`) constructs an
//! `AssembledFull` in-process and calls `full.pull_kill_switch(..)` directly — which proves the
//! passthrough method WORKS, but not that an operator could ever REACH it on a running daemon. That is
//! exactly the gap this test closes.
//!
//! This test drives the REAL served path end-to-end over actual HTTP, using the SAME composition
//! functions `ainxt-runtimed`'s `main.rs` calls (`assemble_selected_governed` +
//! `assemble_full_with_control_plane`) and the SAME transport entrypoint the shipped binary calls
//! (`ainxt_server::serve_full_ext` — `main.rs` calls `full.to_full_app()`/`full.to_full_app_ext()` into
//! exactly this function). A live `reqwest` client:
//!  1. is refused (403) pulling the kill-switch as a non-admin;
//!  2. successfully starts a `chat_governed` session over `/v1/chat`;
//!  3. pulls the workforce kill-switch over `POST /admin/killswitch/pull` as an admin;
//!  4. observes the VERY NEXT turn of the SAME already-in-flight session denied over `/v1/chat` —
//!     proving the HTTP write landed on the EXACT SAME `ControlPlane` the served dispatch admission
//!     reads, not a second, disjoint instance;
//!  5. reads the pull back over `GET /admin/killswitch/audit`;
//!  6. releases over `POST /admin/killswitch/release` (audit trail survives the release);
//!  7. revokes a run and a user over `POST /admin/revoke/{run,user}`, and confirms the effect is
//!     visible on the SAME live plane via `AssembledFull::{is_run_revoked,is_user_revoked}` — the
//!     composition root's own read-only queries over the identical shared `Arc<Mutex<ControlPlane>>`.
//!
//! FAIL-BEFORE / PASS-AFTER: before this fix, `/admin/killswitch/*` and `/admin/revoke/*` did not
//! exist on the served router at all — every request in this test would 404.

use std::sync::{Arc, Mutex};

use ainxt_identity::control::ControlPlane;
use ainxt_runtimed::{assemble_full_with_control_plane, assemble_selected_governed, load_layered};

fn loaded_with_unique_log(tag: &str) -> ainxt_runtimed::LoadedConfig {
    // R16 critical: state the trusted-gateway assumption (every served daemon test in this crate does).
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("ainxt-r-killswitch-admin-{tag}-{nanos}"));
    let src = format!(
        "version = 1\n[server]\nevent_log_dir = {:?}\n",
        dir.to_string_lossy()
    );
    load_layered(&[("r-killswitch-admin", &src)]).expect("load offline config")
}

#[tokio::test(flavor = "multi_thread")]
async fn kill_switch_and_revoke_admin_routes_are_served_and_reach_the_real_dispatch_admission() {
    let control = Arc::new(Mutex::new(ControlPlane::new()));
    let loaded = loaded_with_unique_log("main");
    // The EXACT dispatch used by `main.rs`: the selector and `assemble_full` share ONE plane.
    let assembled = assemble_selected_governed(&loaded, "chat_governed", control.clone())
        .expect("chat_governed must be selectable from the daemon's dispatch table");
    let full = assemble_full_with_control_plane(&loaded, assembled, control)
        .expect("assemble_full_with_control_plane must assemble the governed surface");

    // Serve the REAL fully-wired app + additive ext (identical to what `main.rs` hands
    // `ainxt_server::serve_full_ext`) over a real TCP socket.
    let app = full.to_full_app();
    let ext = full.to_full_app_ext();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(ainxt_server::serve_full_ext(listener, app, ext));

    let client = reqwest::Client::new();
    let base = format!("http://{addr}");

    // ---- 1. A non-admin is refused the kill-switch route (403), never a silent no-op. ----
    let denied = client
        .post(format!("{base}/admin/killswitch/pull"))
        .header("x-ainxt-user", "u-junior")
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(
            serde_json::json!({
                "scope": "workforce",
                "puller_id": "u-junior",
                "ad_level": 1,
                "can_approve": true,
                "now": 1
            })
            .to_string(),
        )
        .send()
        .await
        .expect("denied send");
    assert_eq!(
        denied.status().as_u16(),
        403,
        "a non-admin caller must be refused the admin route"
    );

    // ---- 2. The `chat_governed` session's FIRST turn succeeds (healthy plane, admitted). ----
    let chat = |turn: &str, input: &str| {
        let client = client.clone();
        let base = base.clone();
        let turn = turn.to_string();
        let input = input.to_string();
        async move {
            client
                .post(format!("{base}/v1/chat"))
                .header("x-ainxt-user", "u-bob")
                .header("x-ainxt-caps", "chat.send")
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(
                    serde_json::json!({
                        "session": "s-killswitch-admin-1",
                        "turn": turn,
                        "input": input,
                        "data_class": "internal"
                    })
                    .to_string(),
                )
                .send()
                .await
                .expect("chat send")
                .text()
                .await
                .expect("chat body")
        }
    };
    let before = chat("t1", "hello").await;
    assert!(
        !before.contains("\"error\""),
        "the first turn on a healthy plane must be admitted: {before}"
    );

    // ---- 3. An admin pulls the workforce kill-switch over the REAL HTTP admin route. ----
    let pulled = client
        .post(format!("{base}/admin/killswitch/pull"))
        .header("x-ainxt-user", "u-exec")
        .header("x-ainxt-role", "admin")
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(
            serde_json::json!({
                "scope": "workforce",
                "puller_id": "u-exec",
                "ad_level": 1,
                "can_approve": true,
                "now": 5
            })
            .to_string(),
        )
        .send()
        .await
        .expect("pull send");
    assert_eq!(pulled.status().as_u16(), 200, "an admin pull must succeed");
    let pulled_body: serde_json::Value =
        serde_json::from_str(&pulled.text().await.unwrap()).unwrap();
    assert_eq!(pulled_body["pulled"]["puller"], "u-exec");

    // ---- 4. THE LOAD-BEARING ASSERTION: the VERY NEXT turn of the SAME already-in-flight session,
    // driven purely over HTTP, is now denied — proving the admin route's write reached the EXACT SAME
    // `ControlPlane` the served `chat_governed` dispatch admission consults, over the full HTTP stack,
    // with zero direct calls into `AssembledFull` from this point in the test. ----
    let after = chat("t2", "are you still there").await;
    assert!(
        after.contains("\"error\""),
        "a workforce kill-switch pulled over the REAL admin HTTP route must deny the next turn of an \
         already-in-flight chat_governed session: {after}"
    );

    // ---- 5. The read-only audit route reflects the pull. ----
    let audit = client
        .get(format!("{base}/admin/killswitch/audit"))
        .header("x-ainxt-user", "u-exec")
        .header("x-ainxt-role", "admin")
        .send()
        .await
        .expect("audit send");
    assert_eq!(audit.status().as_u16(), 200);
    let audit_body: serde_json::Value = serde_json::from_str(&audit.text().await.unwrap()).unwrap();
    assert_eq!(audit_body["audit"].as_array().unwrap().len(), 1);
    assert_eq!(audit_body["audit"][0]["puller"], "u-exec");

    // ---- 6. Release is a live lever, not a one-way trip — and the immutable audit trail survives. ----
    let released = client
        .post(format!("{base}/admin/killswitch/release"))
        .header("x-ainxt-user", "u-exec")
        .header("x-ainxt-role", "admin")
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(serde_json::json!({ "scope": "workforce" }).to_string())
        .send()
        .await
        .expect("release send");
    assert_eq!(released.status().as_u16(), 200);
    let audit_after_release = client
        .get(format!("{base}/admin/killswitch/audit"))
        .header("x-ainxt-user", "u-exec")
        .header("x-ainxt-role", "admin")
        .send()
        .await
        .expect("audit after release send");
    let audit_after_release_body: serde_json::Value =
        serde_json::from_str(&audit_after_release.text().await.unwrap()).unwrap();
    assert_eq!(
        audit_after_release_body["audit"].as_array().unwrap().len(),
        1,
        "release must not erase the immutable §19 audit trail"
    );

    // ---- 7. Revoke-run / revoke-user over the REAL HTTP admin routes, reaching the SAME plane the
    // composition root's own read-only queries observe (no second, disjoint registry). ----
    assert!(!full.is_run_revoked("run-rogue-1"));
    let revoked_run = client
        .post(format!("{base}/admin/revoke/run"))
        .header("x-ainxt-user", "u-exec")
        .header("x-ainxt-role", "admin")
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(serde_json::json!({ "run_id": "run-rogue-1" }).to_string())
        .send()
        .await
        .expect("revoke run send");
    assert_eq!(revoked_run.status().as_u16(), 200);
    assert!(
        full.is_run_revoked("run-rogue-1"),
        "the HTTP revoke-run write must land on the SAME shared ControlPlane the composition root reads"
    );
    assert!(
        !full.is_run_revoked("run-other"),
        "revocation is scoped to the named run, not a blanket halt"
    );

    assert!(!full.is_user_revoked("u-mallory"));
    let revoked_user = client
        .post(format!("{base}/admin/revoke/user"))
        .header("x-ainxt-user", "u-exec")
        .header("x-ainxt-role", "admin")
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(serde_json::json!({ "user_id": "u-mallory" }).to_string())
        .send()
        .await
        .expect("revoke user send");
    assert_eq!(revoked_user.status().as_u16(), 200);
    assert!(full.is_user_revoked("u-mallory"));
    assert!(!full.is_user_revoked("u-other"));
}

/// The admin route fails CLOSED (404), never a silent no-op, when the served composition installed no
/// shared control plane at all (the legacy `app`/`app_with_auth` transport, or an `app_full_ext` build
/// whose composition genuinely installed none).
#[tokio::test(flavor = "multi_thread")]
async fn kill_switch_admin_route_fails_closed_when_unconfigured() {
    let loaded = loaded_with_unique_log("unconfigured");
    let assembled =
        ainxt_runtimed::assemble_surface(&loaded, "chat").expect("assemble chat surface");
    let full =
        ainxt_runtimed::assemble_full(&loaded, assembled).expect("assemble fully-wired surface");

    // Use the base `app_full` (no `ext`) so `control_plane` is unset on `AppState` — mirroring
    // `gap_regfi_outsourcing_admin_route_fails_closed_when_unconfigured`'s pattern for the sibling
    // FI-03 admin route.
    let app = full.to_full_app();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(ainxt_server::serve_full(listener, app));

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{addr}/admin/killswitch/pull"))
        .header("x-ainxt-user", "u-exec")
        .header("x-ainxt-role", "admin")
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(
            serde_json::json!({
                "scope": "workforce",
                "puller_id": "u-exec",
                "ad_level": 1,
                "can_approve": true,
                "now": 1
            })
            .to_string(),
        )
        .send()
        .await
        .expect("pull send");
    assert_eq!(
        resp.status().as_u16(),
        404,
        "an unconfigured control plane must fail closed (404), never a silent 200 no-op"
    );
}
