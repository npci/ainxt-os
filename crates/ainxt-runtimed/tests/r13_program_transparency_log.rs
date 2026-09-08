// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! r13_program_transparency_log — GAP-AUDIT identity-payments #1.
//!
//! `ainxt_identity::transparency::TransparencyLog` (the append-only, Merkle-committed, HMAC-signable
//! issuance log ADR-022 §13/§22 scenario 3 designs for external auditor verification) was fully built
//! and unit-tested but had ZERO live callers anywhere in the served path — `mint_run_authority` never
//! appended to one, so a real deployment had no durable, tamper-evident record that a Run's
//! `AgentWorkloadCredential` was ever issued, let alone one an external auditor could verify via an
//! inclusion proof without trusting the runtime.
//!
//! This drives a REAL `ProgramSurface` (the same object `assemble_program_surface` composes) wired
//! with `.with_transparency_log(...)`, runs one program turn end-to-end, and proves the Run's
//! credential issuance landed in the log with a verifiable inclusion proof against the log's current
//! root — the exact external-auditor scenario ADR-022 §22 #3 describes.

use ainxt_client::{Client, ClientConfig};
use ainxt_identity::transparency::{Sha256Hasher, TransparencyLog};
use ainxt_runtimed::{build_engine_ext, load_layered, ProgramSurface};
use ainxt_session::SessionManager;
use ainxt_types::Principal;
use std::sync::{Arc, Mutex};

#[tokio::test(flavor = "multi_thread")]
async fn r13_program_run_credential_issuance_lands_in_the_transparency_log() {
    let loaded = load_layered(&[("x", "version = 1")]).unwrap();
    let (
        engine,
        _report,
        _ledger,
        _reconciler,
        _dispatch_probe,
        _tools,
        _outsourcing,
        _mandate_registry,
        _mcp_admin,
        _prompt_cache,
        _serving,
    ) = build_engine_ext(&loaded.runtime).unwrap();

    let log = Arc::new(Mutex::new(TransparencyLog::new(Sha256Hasher)));
    {
        let guard = log.lock().unwrap();
        assert!(guard.is_empty(), "sanity: the log starts empty");
    }

    let surface =
        ProgramSurface::new(Arc::new(engine), "program").with_transparency_log(log.clone());
    let manager = Arc::new(SessionManager::new(Arc::new(surface), loaded.session));

    let client = Client::in_process(
        manager,
        Principal::user("dev", &["chat.send"]),
        ClientConfig::default(),
    );
    let out = client
        .chat(
            "s-transp",
            "t-transp",
            "migrate the legacy settlement module",
        )
        .unwrap()
        .collect()
        .await;
    assert!(out.completed, "the program turn must complete");

    // The Run's credential issuance was appended — durably, before any output was streamed back.
    let log = log.lock().unwrap();
    assert_eq!(
        log.len(),
        1,
        "exactly one issuance must be logged for one Run"
    );
    let idx = log
        .index_of_run("s-transp:t-transp")
        .expect("the Run's own run_id (session:turn) must be findable in the log");
    let entry = log.entry(idx).expect("entry must exist at its own index");
    assert_eq!(entry.run_id, "s-transp:t-transp");
    assert!(
        entry.def_ref.starts_with("def:program/"),
        "the logged entry must carry the program def_kind: {}",
        entry.def_ref
    );

    // The external-auditor scenario (ADR-022 §22 #3): an inclusion proof against the log's OWN root
    // verifies WITHOUT any special access — just the root + the proof + the entry.
    let root = log.root();
    let proof = log
        .inclusion_proof(idx)
        .expect("an inclusion proof must exist for a logged entry");
    assert!(
        proof.verify(&Sha256Hasher, &root),
        "the inclusion proof must verify against the log's current root"
    );
}
