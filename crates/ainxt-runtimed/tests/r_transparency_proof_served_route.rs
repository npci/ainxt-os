// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX identity-payments (ADR-022 §13/§22 #3, gap6 audit item 1) — PROVES A REAL HTTP REQUEST
//! WRITES AN ISSUANCE ENTRY VIA THE REAL CHAT/IDENTITY PATH, REQUESTS ITS INCLUSION PROOF, AND
//! VERIFIES IT, END TO END.
//!
//! Before this fix: `TransparencyLog::inclusion_proof`/`InclusionProof::verify` were fully
//! implemented and exhaustively unit-tested (`ainxt-identity/tests/r11_transparency_and_attestation.rs`)
//! — the module's entire stated purpose is letting "a party outside the runtime" verify an inclusion
//! proof for an issued Agent Workload Credential. The WRITE side was genuinely wired
//! (`chat_identity.rs::GovernedChatSurface` appends on every newly-minted chat-run credential,
//! `chat_identity.rs:266`), but nothing anywhere served a proof: zero HTTP route, zero served code
//! path ever called `inclusion_proof`/`.verify()` outside `ainxt-identity`'s own tests. Even
//! `assemble_chat_governed_with_transparency` — the ONE composition function that DOES wire a live
//! log — had its returned handle immediately discarded by every real caller
//! (`assemble_selected_governed`/`assemble_chat_governed`), so a `--surface chat_governed` daemon's
//! own transparency log was unreachable from the moment it was minted.
//!
//! This test drives the REAL served path end-to-end over actual HTTP, using the SAME composition
//! functions `main.rs`'s boot sequence now calls
//! (`assemble_selected_governed_with_transparency` + `assemble_full_with_control_plane_and_transparency`)
//! and the SAME transport entrypoint (`ainxt_server::serve_full_ext`):
//!
//!  1. a `chat_governed` session's first turn, over `POST /v1/chat`, mints a per-Run
//!     `AgentWorkloadCredential` and appends its `IssuanceEntry` to the LIVE transparency log
//!     (`chat_identity.rs::GovernedChatSurface::mint_session`) — the REAL write path, not a
//!     hand-built log seeded by the test;
//!  2. an authorized caller requests `GET /v1/transparency/proof/:run_id` (the chat session id IS the
//!     identity-plane `run_id`, `chat_identity.rs`'s own `mint_session`) over the REAL HTTP admin
//!     route;
//!  3. the returned proof + root, decoded straight off the wire with zero special-cased test access to
//!     the log, verify against [`ainxt_identity::transparency::InclusionProof::verify`] — an external
//!     auditor's exact contract;
//!  4. a caller lacking `CAP_TRANSPARENCY_READ` is refused (403); an unknown `run_id` is refused (404);
//!     an unconfigured surface (plain `"chat"`, which wires no transparency log) fails closed (404),
//!     never a silent empty-proof no-op.
//!
//! FAIL-BEFORE / PASS-AFTER: before this fix, `GET /v1/transparency/proof/*` did not exist on the
//! served router at all — every request in this test would 404 regardless of capability or `run_id`.

use std::sync::{Arc, Mutex};

use ainxt_identity::control::ControlPlane;
use ainxt_identity::transparency::{InclusionProof, Sha256Hasher};
use ainxt_runtimed::{
    assemble_full_with_control_plane, assemble_full_with_control_plane_and_transparency,
    assemble_selected_governed, assemble_selected_governed_with_transparency, load_layered,
};

fn loaded_with_unique_log(tag: &str) -> ainxt_runtimed::LoadedConfig {
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("ainxt-r-transparency-route-{tag}-{nanos}"));
    let src = format!(
        "version = 1\n[server]\nevent_log_dir = {:?}\n",
        dir.to_string_lossy()
    );
    load_layered(&[("r-transparency-route", &src)]).expect("load offline config")
}

fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn served_transparency_proof_route_verifies_a_real_chat_governed_issuance_end_to_end() {
    let control = Arc::new(Mutex::new(ControlPlane::new()));
    let loaded = loaded_with_unique_log("main");
    let (assembled, transparency) =
        assemble_selected_governed_with_transparency(&loaded, "chat_governed", control.clone())
            .expect("chat_governed must be selectable and wire a transparency log");
    assert!(
        transparency.is_some(),
        "sanity: chat_governed must wire a live transparency log"
    );
    let full = assemble_full_with_control_plane_and_transparency(
        &loaded,
        assembled,
        control,
        transparency,
    )
    .expect("assemble_full_with_control_plane_and_transparency must assemble the governed surface");

    let app = full.to_full_app();
    let ext = full.to_full_app_ext();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(ainxt_server::serve_full_ext(listener, app, ext));

    let client = reqwest::Client::new();
    let base = format!("http://{addr}");
    let run_id = "s-transparency-1";

    // ---- 1. A chat_governed turn mints an AWC and appends its issuance via the REAL write path. ----
    let chat_resp = client
        .post(format!("{base}/v1/chat"))
        .header("x-ainxt-user", "u-alice")
        .header("x-ainxt-caps", "chat.send")
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(
            serde_json::json!({
                "session": run_id,
                "turn": "t1",
                "input": "hello",
                "data_class": "internal"
            })
            .to_string(),
        )
        .send()
        .await
        .expect("chat send");
    assert_eq!(chat_resp.status().as_u16(), 200);
    let chat_body = chat_resp.text().await.expect("chat body");
    assert!(
        !chat_body.contains("\"error\""),
        "the first chat_governed turn must be admitted (issuance must have succeeded): {chat_body}"
    );

    // ---- 2. An authorized external party requests the inclusion proof over the REAL HTTP route. ----
    let proof_resp = client
        .get(format!("{base}/v1/transparency/proof/{run_id}"))
        .header("x-ainxt-user", "u-auditor")
        .header("x-ainxt-caps", "identity.transparency.read")
        .send()
        .await
        .expect("proof send");
    assert_eq!(
        proof_resp.status().as_u16(),
        200,
        "an authorized caller must be served a proof for a real issuance"
    );
    let body: serde_json::Value =
        serde_json::from_str(&proof_resp.text().await.unwrap()).expect("proof body is JSON");

    // ---- 3. Independently verify the proof against the returned root — the external-auditor
    // contract `InclusionProof::verify` exists for, exercised with ZERO special-cased test access to
    // the log (only what the wire handed back). ----
    let proof: InclusionProof =
        serde_json::from_value(body["proof"].clone()).expect("proof deserializes");
    let root = from_hex(body["root_hex"].as_str().expect("root_hex is a hex string"));
    assert!(
        proof.verify(&Sha256Hasher, &root),
        "the served proof must verify against the served root — the exact external-auditor check"
    );
    assert_eq!(
        proof.entry.run_id, run_id,
        "the proof's entry must be THIS run's issuance"
    );

    // A tampered entry (a forged measurement) must NOT verify — the proof is not merely present, it
    // is cryptographically load-bearing.
    let mut tampered = proof.clone();
    tampered.entry.attestation_ref = "m-EVIL".to_string();
    assert!(
        !tampered.verify(&Sha256Hasher, &root),
        "a tampered entry must fail verification"
    );

    // ---- 4a. A caller lacking CAP_TRANSPARENCY_READ is refused (403), never handed the proof. ----
    let denied = client
        .get(format!("{base}/v1/transparency/proof/{run_id}"))
        .header("x-ainxt-user", "u-nobody")
        .send()
        .await
        .expect("denied send");
    assert_eq!(denied.status().as_u16(), 403);

    // ---- 4b. An unknown run_id is refused (404), never a fabricated/empty proof. ----
    let missing = client
        .get(format!("{base}/v1/transparency/proof/no-such-run"))
        .header("x-ainxt-user", "u-auditor")
        .header("x-ainxt-caps", "identity.transparency.read")
        .send()
        .await
        .expect("missing send");
    assert_eq!(missing.status().as_u16(), 404);
}

/// The default `"chat"` surface wires no transparency log; the route still mounts but fails closed
/// (404) — never a silent no-op that would let a caller believe a proof exists when none does.
#[tokio::test(flavor = "multi_thread")]
async fn transparency_proof_route_fails_closed_when_no_log_is_wired() {
    let control = Arc::new(Mutex::new(ControlPlane::new()));
    let loaded = loaded_with_unique_log("unconfigured");
    let assembled = assemble_selected_governed(&loaded, "chat", control.clone())
        .expect("the shipped default surface must assemble");
    let full = assemble_full_with_control_plane(&loaded, assembled, control)
        .expect("assemble_full_with_control_plane must assemble the unconfigured surface");

    let app = full.to_full_app();
    let ext = full.to_full_app_ext();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(ainxt_server::serve_full_ext(listener, app, ext));

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{addr}/v1/transparency/proof/whatever"))
        .header("x-ainxt-user", "u-auditor")
        .header("x-ainxt-caps", "identity.transparency.read")
        .send()
        .await
        .expect("send");
    assert_eq!(
        resp.status().as_u16(),
        404,
        "no transparency log wired must fail closed (route not mounted), never a silent 200"
    );
}
