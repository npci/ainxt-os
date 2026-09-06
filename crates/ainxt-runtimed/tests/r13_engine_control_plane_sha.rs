// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! r13_engine_control_plane_sha — GAP-FIX turn-pipeline.
//!
//! `Engine::with_control_plane_sha` was never called on the served flagship chat engine
//! (`build_chat_engine_with_authz`), so the engine's OWN inner `WireEvent`/`EventEnvelope` stream
//! always stamped `control_plane_sha = "unpinned"` regardless of `AINXT_CONTROL_PLANE_SHA` — even
//! though the reproducibility pin (ADR-026 §6.2) is exactly what a resumed/replayed session relies on
//! to prove which control-repo commit a turn's definitions were pinned to.

use ainxt_context::Corpus;
use ainxt_runtimed::{build_chat_surface_wired, load_layered};
use ainxt_types::{DataClass, Principal};

#[tokio::test(flavor = "multi_thread")]
async fn r13_served_chat_engine_stamps_the_configured_control_plane_sha() {
    std::env::set_var("AINXT_CONTROL_PLANE_SHA", "deadbeefcafef00d");
    let loaded = load_layered(&[("x", "version = 1")]).unwrap();
    let (
        chat,
        mut wire_rx,
        _report,
        _ledger,
        _reconciler,
        _probe,
        _tools,
        _memory_backend,
        _outsourcing,
        _mandate_registry,
        _mcp_admin,
        _serving,
    ) = build_chat_surface_wired(&loaded, Corpus::new()).unwrap();

    let principal = Principal::user("u", &["chat.send"]).with_clearance(DataClass::Public);
    chat.turn("s-sha", &principal, "hello", DataClass::Public)
        .await
        .expect("turn must complete");

    let mut saw_pinned = false;
    while let Ok(env) = wire_rx.try_recv() {
        assert_ne!(
            env.control_plane_sha, "unpinned",
            "every engine-emitted envelope must carry the configured sha, not the default: {env:?}"
        );
        if env.control_plane_sha == "deadbeefcafef00d" {
            saw_pinned = true;
        }
    }
    assert!(
        saw_pinned,
        "at least one envelope must carry the exact configured control-plane sha"
    );
    std::env::remove_var("AINXT_CONTROL_PLANE_SHA");
}
