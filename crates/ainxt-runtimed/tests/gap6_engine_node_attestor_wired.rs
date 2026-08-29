// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX gap6-composition-root (Item 1, ADR-021 §8.2/§8.3, serving-ops SRV-02) — `Engine::
//! with_node_attestor` (`ainxt-runtime`) and `ainxt_runtime::serving::ServingGateAttestor` (the
//! bridge onto `ainxt-serving`'s `ServingGate::pre_serve_check`) were fully implemented and
//! exhaustively unit-tested (`ainxt-runtime/tests/r3_turn_pipeline_test.rs`) but had ZERO
//! production callers: the daemon's `/v1/chat` Stage-1 fence (`ainxt-server::lib.rs`) already called
//! `ServingGate::pre_serve_check` directly, but only over the caller's naively-DECLARED
//! `data_class` — never the engine's own §4.2 tri-signal ESCALATED `route_class` (derived from the
//! ACTUAL turn content via the compliance arg-scanner, which can escalate a smuggled PAN/secret
//! regardless of what the caller declared). `Engine::with_node_attestor` is what re-checks the
//! ESCALATED class, but nothing in the composition root ever called it.
//!
//! This test drives the REAL, `pub` composition-root function
//! [`ainxt_runtimed::build_engine_ext_with_mcp`] — one of the two functions this gap names
//! explicitly (the other, `build_chat_engine_with_authz`, is `fn`-private but wires the identical
//! mechanism; see its own doc comment) — with a `[[serving.nodes]]` pool declared, and proves:
//!
//!  1. a regulated turn is refused BEFORE any provider dispatch while the declared node is
//!     unattested, via the REAL `Engine`'s own `node_attestor` hook (not just a config assertion);
//!  2. after attesting the node through the REAL `ServingGate`/`AttestationGate::submit_quote` —
//!     the SAME shared `Arc<Mutex<ServingGate>>` instance `build_engine_ext_with_mcp` attached to
//!     the engine, never a bespoke standalone attestor — the identical turn is no longer refused by
//!     attestation;
//!  3. the air-gapped default (no `[[serving.nodes]]`) never calls `Engine::with_node_attestor` at
//!     all, so a regulated turn on the shipped default is not suddenly fenced off with no way to
//!     ever attest (mirrors the `ainxt-server` Stage-1 guard's own `!candidates.is_empty()` check).

use ainxt_protocol::Request;
use ainxt_runtime::TurnError;
use ainxt_runtimed::{build_engine_ext_with_mcp, load_layered, LoadedConfig};
use ainxt_serving::attestation::{
    AllowListVerifier, AttestationQuote, Measurements, ReferenceValues, TrustTier,
};
use ainxt_types::{DataClass, Principal};

fn config_with_pool() -> LoadedConfig {
    let src = "version = 1\n\
               [[serving.nodes]]\n\
               node_id = \"gpu-a\"\n\
               routable = true\n";
    load_layered(&[("gap6-attestor", src)]).expect("load config with a declared serving pool")
}

fn config_without_pool() -> LoadedConfig {
    load_layered(&[("gap6-attestor-default", "version = 1\n")]).expect("load default config")
}

fn good_quote(node: &str) -> AttestationQuote {
    AttestationQuote {
        node_id: node.into(),
        tier: TrustTier::CcEnclave,
        measurements: Measurements {
            firmware_hash: "fw-1".into(),
            driver_version: "drv-1".into(),
            binary_hash: "bin-1".into(),
        },
        signature: "sig-ok".into(),
    }
}

fn refs() -> ReferenceValues {
    ReferenceValues::new()
        .allow_firmware("fw-1")
        .allow_driver("drv-1")
        .allow_binary("bin-1")
}

#[tokio::test(flavor = "multi_thread")]
async fn a_declared_pool_fails_a_regulated_turn_closed_until_the_real_gate_attests_it() {
    let loaded = config_with_pool();
    let (
        engine,
        report,
        _ledger,
        _reconciler,
        _dispatch_probe,
        _tools,
        _outsourcing,
        _mandate_registry,
        _mcp_admin,
        _prompt_cache,
        serving,
    ) = build_engine_ext_with_mcp(
        &loaded.runtime,
        &loaded.mcp,
        &loaded.payments,
        &loaded.serving,
    )
    .expect("the real composition root assembles a declared-pool engine");

    // Sanity: the composition root's own assembly report records that it wired the attestor.
    assert!(
        report
            .iter()
            .any(|l| l.contains("Engine::with_node_attestor")),
        "assembly report must record the node-attestation wiring: {report:?}"
    );
    assert_eq!(
        serving.1.len(),
        1,
        "the declared node is bound onto the shared serving handle"
    );

    let principal = Principal::user("u", &["chat.send"]).with_clearance(DataClass::Confidential);
    let req = Request::chat(
        "s-gap6-attestor",
        "t1",
        "regulated work",
        DataClass::Confidential,
    );

    // 1. UNATTESTED: the REAL engine's own node-attestation hook refuses the turn before any
    //    provider dispatch — this is `Engine::with_node_attestor`'s enforcement, not the (separate,
    //    pre-existing) `ainxt-server` Stage-1 fence, which this test never touches.
    let denied = engine
        .run_turn_collect(&principal, &req)
        .await
        .expect_err("an unattested regulated turn must fail closed");
    match denied {
        TurnError::Denied(msg) => assert!(
            msg.contains("attestation"),
            "the refusal must be the node-attestation gate, got: {msg}"
        ),
        other => panic!("expected TurnError::Denied(attestation ...), got {other:?}"),
    }

    // 2. Attest the node through the REAL ServingGate/AttestationGate `submit_quote` — the SAME
    //    `Arc<Mutex<ServingGate>>` this test read out of the composition root's own return value,
    //    which is the IDENTICAL instance `Engine::with_node_attestor`'s `ServingGateAttestor` closed
    //    over. No bespoke standalone attestor is constructed anywhere in this test.
    //
    //    `node_attestor_over` (the composition root's own wiring) evaluates freshness against REAL
    //    wall-clock time (`SystemTime::now()`), not a logical tick counter, so the quote must be
    //    submitted at a REAL "now" too — otherwise a `now=0` submission looks expired-by-decades the
    //    instant the attestor re-checks it against the real clock a moment later.
    let real_now = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    };
    {
        let mut gate = serving.0.lock().expect("serving gate lock");
        gate.attestation_mut()
            .submit_quote(
                &good_quote("gpu-a"),
                real_now(),
                &AllowListVerifier::new().accept("sig-ok"),
                &refs(),
            )
            .expect("a valid quote for an allow-listed node must be accepted");
    }

    // 3. ADMITTED: the identical turn, on the identical engine, is no longer refused by attestation.
    //    (The air-gapped test config declares no model providers, so the turn still cannot reach a
    //    live model — that is an unrelated, pre-existing routing concern, never the attestation gate
    //    under test here; the proof is that the SPECIFIC attestation denial is gone.)
    match engine.run_turn_collect(&principal, &req).await {
        Err(TurnError::Denied(msg)) => assert!(
            !msg.contains("attestation"),
            "after attesting the node, the turn must no longer fail closed on attestation: {msg}"
        ),
        _ => {}
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_air_gapped_default_never_wires_the_attestor_at_all() {
    let loaded = config_without_pool();
    assert!(
        loaded.serving.is_empty(),
        "default config declares no serving nodes"
    );
    let (engine, report, .., serving) = build_engine_ext_with_mcp(
        &loaded.runtime,
        &loaded.mcp,
        &loaded.payments,
        &loaded.serving,
    )
    .expect("the real composition root assembles the air-gapped default");
    assert!(
        serving.1.is_empty(),
        "no nodes declared ⇒ empty shared serving handle"
    );
    assert!(
        !report.iter().any(|l| l.contains("Engine::with_node_attestor")),
        "the air-gapped default must NOT wire the node-attestor (r4 shipped-chat guard): {report:?}"
    );

    // A regulated turn on the air-gapped default is unaffected by this fix — never suddenly fenced
    // off with no node that could ever attest. (No providers are configured either, so this may still
    // fail for an unrelated routing reason — the proof is the ABSENCE of an attestation denial.)
    let principal = Principal::user("u", &["chat.send"]).with_clearance(DataClass::Confidential);
    let req = Request::chat(
        "s-gap6-attestor-default",
        "t1",
        "regulated work",
        DataClass::Confidential,
    );
    match engine.run_turn_collect(&principal, &req).await {
        Err(TurnError::Denied(msg)) => assert!(
            !msg.contains("attestation"),
            "the air-gapped default must never deny a turn for attestation reasons: {msg}"
        ),
        _ => {}
    }
}
