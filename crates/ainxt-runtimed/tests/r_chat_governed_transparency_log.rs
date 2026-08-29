// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX identity-payments (ADR-022 §13) — chat_governed's AWC issuance now feeds the SAME
//! append-only, Merkle-committed, inclusion-proof-verifiable transparency log the Program/Team
//! surfaces already feed (see `r13_program_transparency_log.rs`/`r13_team_transparency_log.rs`).
//!
//! Before this fix: `assemble_program_surface_with_transparency`/`assemble_team_surface_with_transparency`
//! wired `ProgramSurface::with_transparency_log`/`TeamSurface::with_transparency_log`, but
//! `GovernedChatSurface` (`ainxt-runtimed/src/chat_identity.rs`) — which mints/renews an AWC on
//! EVERY turn of a chat run via `ControlPlane::issue_jit`/`authorize_dispatch` — had no
//! `with_transparency_log` seam at all and `assemble_chat_governed` never built one, so a chat run's
//! credential issuance had zero external-auditor inclusion-proof-verifiable record, unlike the SAME
//! class of event on Program/Team.
//!
//! This drives the REAL `assemble_chat_governed_with_transparency` composition function (the same
//! shape `assemble_program_surface_with_transparency` already established, mirrored here) end-to-end
//! over `Client::in_process`, and proves the chat run's credential issuance lands in the log with a
//! verifiable inclusion proof against the log's current root — the exact external-auditor scenario
//! ADR-022 §22 #3 describes, now also covering chat_governed.

use std::sync::{Arc, Mutex};

use ainxt_client::{Client, ClientConfig};
use ainxt_identity::control::ControlPlane;
use ainxt_identity::transparency::Sha256Hasher;
use ainxt_runtimed::{assemble_chat_governed_with_transparency, load_layered};
use ainxt_types::Principal;

#[tokio::test(flavor = "multi_thread")]
async fn r_chat_governed_run_credential_issuance_lands_in_the_transparency_log() {
    // R16 critical: state the trusted-gateway assumption (every served daemon test in this crate does).
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let loaded = load_layered(&[("x", "version = 1")]).unwrap();
    let control = Arc::new(Mutex::new(ControlPlane::new()));

    let (assembled, log) =
        assemble_chat_governed_with_transparency(&loaded, control, "chat").expect("assembles");
    assert!(
        log.lock().unwrap().is_empty(),
        "sanity: the log starts empty"
    );

    let client = Client::in_process(
        assembled.manager.clone(),
        Principal::user("u-bob", &["chat.send"]),
        ClientConfig::default(),
    );
    let out = client
        .chat("s-chat-transp-1", "t1", "hello")
        .unwrap()
        .collect()
        .await;
    assert!(
        out.completed && out.error.is_none(),
        "the first turn on a healthy plane must be admitted and complete: {out:?}"
    );

    // The Run's credential issuance was appended — durably, before any output was streamed back.
    {
        let log = log.lock().unwrap();
        assert_eq!(
            log.len(),
            1,
            "exactly one issuance must be logged for one chat run"
        );
        let idx = log
            .index_of_run("s-chat-transp-1")
            .expect("the chat run's own run_id (its session id) must be findable in the log");
        let entry = log.entry(idx).expect("entry must exist at its own index");
        assert_eq!(entry.run_id, "s-chat-transp-1");
        assert!(
            entry.def_ref.starts_with("def:chat/"),
            "the logged entry must carry the chat def_kind: {}",
            entry.def_ref
        );

        // The external-auditor scenario (ADR-022 §22 #3): an inclusion proof against the log's OWN
        // root verifies WITHOUT any special access — just the root + the proof + the entry.
        let root = log.root();
        let proof = log
            .inclusion_proof(idx)
            .expect("an inclusion proof must exist for a logged entry");
        assert!(
            proof.verify(&Sha256Hasher, &root),
            "the inclusion proof must verify against the log's current root"
        );
    }

    // A SECOND turn of the SAME already-in-flight chat run drives a §15 renewal (not a fresh
    // mint) — mirroring exactly what Program/Team's own transparency-log tests establish (they log
    // the initial issuance, not every renewal): the log must still have exactly ONE entry.
    let out2 = client
        .chat("s-chat-transp-1", "t2", "are you still there")
        .unwrap()
        .collect()
        .await;
    assert!(
        out2.completed && out2.error.is_none(),
        "the second turn must also complete: {out2:?}"
    );
    assert_eq!(
        log.lock().unwrap().len(),
        1,
        "a same-run renewal must not double-log the issuance"
    );

    // A DISTINCT chat run gets its OWN, second logged issuance.
    let out3 = client
        .chat("s-chat-transp-2", "t1", "a different run")
        .unwrap()
        .collect()
        .await;
    assert!(out3.completed && out3.error.is_none());
    let log = log.lock().unwrap();
    assert_eq!(
        log.len(),
        2,
        "a distinct chat run gets its own logged issuance"
    );
    let idx2 = log
        .index_of_run("s-chat-transp-2")
        .expect("the second run must be independently findable in the log");
    assert_eq!(log.entry(idx2).unwrap().run_id, "s-chat-transp-2");
}
