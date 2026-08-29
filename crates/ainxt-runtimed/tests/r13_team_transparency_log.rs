// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! r13_team_transparency_log — GAP-AUDIT identity-payments #1 (Team-side counterpart of
//! r13_program_transparency_log.rs). `drive_served_team` mints a per-Run credential via
//! `mint_run_credential` and, before this fix, never appended it to any transparency log either —
//! the SAME zero-live-caller gap as the Program driver, on the Team driver's own mint call site.

use ainxt_client::{Client, ClientConfig};
use ainxt_identity::transparency::{Sha256Hasher, TransparencyLog};
use ainxt_runtimed::{build_engine_ext, compose_served_team, load_layered, TeamSurface};
use ainxt_session::SessionManager;
use ainxt_types::{DataClass, Principal};
use std::sync::{Arc, Mutex};

#[tokio::test(flavor = "multi_thread")]
async fn r13_team_run_credential_issuance_lands_in_the_transparency_log() {
    let (_graph, _team, _seed) = compose_served_team("ship the feature").unwrap();

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
        let log_guard = log.lock().unwrap();
        assert!(log_guard.is_empty(), "sanity: the log starts empty");
    }

    let surface = TeamSurface::new(Arc::new(engine), "team").with_transparency_log(log.clone());
    let manager = Arc::new(SessionManager::new(Arc::new(surface), loaded.session));

    let client = Client::in_process(
        manager,
        Principal::user("dev", &["chat.send"]).with_clearance(DataClass::Public),
        ClientConfig::default(),
    );
    let out = client
        .chat(
            "team-transp",
            "t1",
            "add input validation to the settlement module",
        )
        .unwrap()
        .collect()
        .await;
    assert!(out.completed, "the team turn must complete");

    let log = log.lock().unwrap();
    assert_eq!(
        log.len(),
        1,
        "exactly one issuance must be logged for one Team Run"
    );
    let idx = log
        .index_of_run("team-transp:t1")
        .expect("the Run's own run_id (session:turn) must be findable in the log");
    let entry = log.entry(idx).expect("entry must exist at its own index");
    assert!(
        entry.def_ref.starts_with("def:team/"),
        "the logged entry must carry the team def_kind: {}",
        entry.def_ref
    );

    let root = log.root();
    let proof = log
        .inclusion_proof(idx)
        .expect("an inclusion proof must exist for a logged entry");
    assert!(
        proof.verify(&Sha256Hasher, &root),
        "the inclusion proof must verify against the log's current root"
    );
}
