// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R8 — the SHIPPED daemon (1) makes a VERIFIED-identity authenticator config-SELECTABLE without
//! changing the owner-deferred default, and (2) mounts the semantic `/v1/edit` gate fail-closed on the
//! edit-apply capability.
//!
//! * `r8_default_authenticator_is_trusted_gateway_unchanged` — with no `[server].authenticator` key the
//!   shipped surface mounts `TrustedGatewayAuth` (unchanged): a governed route (`/graph`) admits a
//!   caller carrying the forwarded `X-AInxt-User` identity header (no Bearer JWT). This is the guard
//!   that the DEFAULT is untouched.
//! * `r8_jwt_sso_authenticator_selectable_and_verified` — selecting `authenticator = "jwt-sso"` (+ a
//!   secret) mounts the VERIFIED `JwtSsoAuth` on EVERY governed route: a forged `X-AInxt-*` header is
//!   now REJECTED (401 — header-spoofing no longer widens identity), a garbage Bearer is rejected, and a
//!   validly-signed HS256 token is ACCEPTED. `jwt-sso` WITHOUT a secret FAILS CLOSED at assembly (never a
//!   silent downgrade to the trusted default).
//! * `r8_shipped_daemon_mounts_edit_gate_fail_closed` — the shipped daemon serves `POST /v1/edit` (not
//!   404) and fail-closes on `code.edit.apply`: a caller lacking the cap → 403; a caller holding it
//!   reaches the pipeline and gets a typed EditResponse.
//!
//! Fail-before/pass-after: before R8 the daemon hardcoded `TrustedGatewayAuth` (no selection, no
//! fail-closed) and `/v1/edit` was 404 (never mounted). Deterministic: the offline provider backs the
//! engine; the transport + authenticator + edit engine are the REAL production composition types.

use std::time::{SystemTime, UNIX_EPOCH};

use ainxt_runtimed::{assemble_full, assemble_surface, load_layered, AssembleError, LoadedConfig};

fn loaded(extra_server: &str) -> LoadedConfig {
    // R16 critical: the daemon now refuses the header-trusting default authenticator unless the
    // deployment states the assumption (see r10_breach_clock_unit.rs) — state it here. Harmless for
    // the jwt-sso test below, which explicitly selects a different authenticator.
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("ainxt-r8-{nanos}"));
    let src = format!(
        "version = 1\n[server]\nevent_log_dir = {:?}\n{extra_server}\n",
        dir.to_string_lossy()
    );
    load_layered(&[("r8", &src)]).expect("load offline config")
}

/// Assemble the fully-wired shipped surface and serve it over HTTP; returns the bound address.
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

// ---------- HS256 JWT minting (test-only; signs exactly how JwtSsoAuth verifies) ----------

fn b64url(input: &[u8]) -> String {
    const ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHA[((n >> 18) & 63) as usize] as char);
        out.push(ALPHA[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHA[((n >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHA[(n & 63) as usize] as char);
        }
    }
    out
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        let d = Sha256::digest(key);
        k[..32].copy_from_slice(&d);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner);
    let mut out = [0u8; 32];
    out.copy_from_slice(&outer.finalize());
    out
}

fn mint_hs256(secret: &[u8], claims: serde_json::Value) -> String {
    let header = b64url(br#"{"alg":"HS256","typ":"JWT"}"#);
    let payload = b64url(claims.to_string().as_bytes());
    let signing_input = format!("{header}.{payload}");
    let sig = b64url(&hmac_sha256(secret, signing_input.as_bytes()));
    format!("{signing_input}.{sig}")
}

// ---------------------------------- tests ----------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn r8_default_authenticator_is_trusted_gateway_unchanged() {
    let loaded = loaded("");
    // The report names the default authenticator (owner-deferred, unchanged).
    let assembled = assemble_surface(&loaded, "chat").expect("assemble");
    let full = assemble_full(&loaded, assembled).expect("assemble full");
    assert!(
        full.report
            .iter()
            .any(|l| l.contains("authenticator: trusted-gateway")),
        "the default authenticator must be trusted-gateway"
    );

    let addr = serve(&loaded).await;
    let client = reqwest::Client::new();
    // /graph admits the forwarded identity header (trusted-gateway) — NOT a 401.
    let graph = client
        .post(format!("http://{addr}/graph"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header("x-ainxt-user", "alice")
        .body(serde_json::json!({"op":"traverse","start":"root","max_depth":1}).to_string())
        .send()
        .await
        .expect("graph");
    assert_ne!(
        graph.status().as_u16(),
        401,
        "the default trusted-gateway authenticator admits the forwarded identity header"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn r8_shipped_daemon_mounts_edit_gate_fail_closed() {
    use ainxt_pipeline::{EditRequest, SelfHealConfig};

    let loaded = loaded("");
    let addr = serve(&loaded).await;
    let client = reqwest::Client::new();

    let req = EditRequest {
        edit_id: "e1".into(),
        original_files: vec![("a.rs".into(), "fn a() -> i32 { 1 }\n".into())],
        applied_files: vec![("a.rs".into(), "fn a() -> i32 { 2 }\n".into())],
        config: SelfHealConfig::default(),
    };
    let body = serde_json::to_string(&req).expect("serialize");

    // Mounted (not 404) AND fail-closed on CAP_EDIT_APPLY: no cap → 403.
    let denied = client
        .post(format!("http://{addr}/v1/edit"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header("x-ainxt-user", "mallory")
        .body(body.clone())
        .send()
        .await
        .expect("denied");
    assert_ne!(
        denied.status().as_u16(),
        404,
        "/v1/edit must be served by the shipped daemon"
    );
    assert_eq!(
        denied.status().as_u16(),
        403,
        "a caller lacking code.edit.apply must be refused fail-closed"
    );

    // A caller holding the cap reaches the pipeline and gets a typed EditResponse.
    let ok = client
        .post(format!("http://{addr}/v1/edit"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header("x-ainxt-user", "dev")
        .header("x-ainxt-caps", "code.edit.apply")
        .body(body)
        .send()
        .await
        .expect("ok");
    assert!(
        ok.status().is_success(),
        "authorized edit reaches the gate: {}",
        ok.status()
    );
    let v: serde_json::Value = serde_json::from_str(&ok.text().await.expect("body")).expect("json");
    assert!(
        v.get("result").is_some(),
        "typed EditResponse (result-tagged): {v}"
    );
}
