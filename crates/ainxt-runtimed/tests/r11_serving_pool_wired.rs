// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-11 Serving-Ops gap-1 (SRV-01, HIGH) — the attestation node-fence + SLO-aware QoS admission
//! are no longer INERT on the shipped daemon.
//!
//! The audit found `build_serving()` hard-coded an EMPTY node pool (`Vec::new()`), so on the shipped
//! `ainxt-runtimed` binary the §8.2 attestation fence and §2 QoS admission never fired — a deployment
//! had no way to advertise its GPU fleet without editing source. This round adds a `[serving]` config
//! section the daemon binds the pool + admission tuning onto, so the fence goes LIVE on the SHIPPED
//! path when nodes are declared — while the air-gapped default (no `[serving]`) keeps the pool empty,
//! preserving the round-4 shipped-chat guard (no pool ⇒ no 503).
//!
//! Fail-before: `LoadedConfig` had no `serving` field and `build_serving` took no config — a
//! `[serving]` layer was an "unknown field" parse error and the pool was always empty. Pass-after:
//! a declared pool makes `full.serving.1` non-empty and the fence enforces for real (regulated turn
//! fails closed on an unattested node; a live TEE quote then admits it; QoS enqueues/sheds), on both
//! the assembled gate AND the served HTTP path — and the default stays inert.

use std::time::{SystemTime, UNIX_EPOCH};

use ainxt_runtimed::{assemble_full, assemble_surface, load_layered, LoadedConfig};
use ainxt_serving::attestation::{
    AllowListVerifier, AttestationQuote, Measurements, ReferenceValues, TrustTier,
};
use ainxt_serving::gate::PreServeVerdict;
use ainxt_serving::slo::{QosRequest, SloDecision};
use ainxt_serving::PriorityClass;
use ainxt_types::DataClass;

fn unique_log_dir(tag: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir()
        .join(format!("ainxt-r11-{tag}-{nanos}"))
        .to_string_lossy()
        .into_owned()
}

/// A config declaring a live serving pool of two routable nodes + a bounded QoS queue + §2 WFQ.
fn served_pool_config() -> LoadedConfig {
    // R16 critical: the daemon now refuses the header-trusting default authenticator unless the
    // deployment states the assumption (see r10_breach_clock_unit.rs) — state it here.
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let dir = unique_log_dir("pool");
    let src = format!(
        "version = 1\n\
         [server]\n\
         event_log_dir = {dir:?}\n\
         [serving]\n\
         qos_queue_depth = 2\n\
         fairness_capacity = 10\n\
         fairness_min_share = 10\n\
         scheduler_capacity = 2\n\
         [[serving.nodes]]\n\
         node_id = \"gpu-a\"\n\
         routable = true\n\
         [[serving.nodes]]\n\
         node_id = \"gpu-b\"\n\
         routable = true\n\
         [serving.wfq]\n\
         quantum_unit = 1\n\
         [serving.wfq.weights]\n\
         \"dept-ops\" = 3\n"
    );
    load_layered(&[("r11", &src)]).expect("load config with a serving pool")
}

fn default_config() -> LoadedConfig {
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let dir = unique_log_dir("default");
    let src = format!("version = 1\n[server]\nevent_log_dir = {dir:?}\n");
    load_layered(&[("r11d", &src)]).expect("load default config")
}

#[test]
fn r11_configured_pool_makes_attestation_fence_and_qos_live() {
    let loaded = served_pool_config();
    // The parsed config carries the declared nodes + WFQ.
    assert_eq!(loaded.serving.nodes.len(), 2, "[[serving.nodes]] parsed");
    assert!(loaded.serving.wfq.is_some(), "[serving.wfq] parsed");

    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");

    // The pool is BOUND onto the served fence — no longer the empty inert default.
    assert_eq!(
        full.serving.1.len(),
        2,
        "the configured node pool is bound onto the served gate"
    );
    let nodes = full.serving.1.clone();
    let now = 1_000u64;

    {
        let mut gate = full.serving.0.lock().expect("gate lock");
        // WFQ minimum-service ordering was wired from `[serving.wfq]`.
        assert!(
            gate.has_wfq(),
            "the served gate orders its wait queue by §2 WFQ (config-driven)"
        );

        // (1) LIVE fence: a regulated turn FAILS CLOSED onto an unattested-but-routable node — the fence
        //     is no longer inert, it enforces ADR-021 §8.2 on the shipped path.
        assert_eq!(
            gate.pre_serve_check(DataClass::RegulatedPayment, &nodes, now, true),
            PreServeVerdict::FailClosedNoAttestedCapacity,
            "regulated turn must fail closed on an unattested node"
        );
        // (2) A non-regulated turn is admitted onto a routable node (the fence does not over-block).
        assert!(
            gate.pre_serve_check(DataClass::Internal, &nodes, now, true)
                .is_admitted(),
            "internal turn admitted on a routable node"
        );

        // (3) A live TEE quote (the seam) attests gpu-a as a CC-enclave → the SAME regulated turn is now
        //     admitted onto exactly that node. This is the needs_hot_wiring path (the daemon owns the
        //     quote-refresh loop); driven here through the real AttestationGate entrypoint.
        let verifier = AllowListVerifier::new().accept("sig-ok");
        let refs = ReferenceValues::new()
            .allow_firmware("fw-1")
            .allow_driver("drv-1")
            .allow_binary("bin-1");
        let quote = AttestationQuote {
            node_id: "gpu-a".into(),
            tier: TrustTier::CcEnclave,
            measurements: Measurements {
                firmware_hash: "fw-1".into(),
                driver_version: "drv-1".into(),
                binary_hash: "bin-1".into(),
            },
            signature: "sig-ok".into(),
        };
        gate.attestation_mut()
            .submit_quote(&quote, now, &verifier, &refs)
            .expect("valid quote attests gpu-a");
        assert_eq!(
            gate.pre_serve_check(DataClass::RegulatedPayment, &nodes, now, true),
            PreServeVerdict::Admit {
                node_id: "gpu-a".into()
            },
            "regulated turn admitted onto the now-attested node"
        );

        // (4) LIVE QoS admission: with fairness_capacity=2 + queue_depth=2, a burst of same-tenant P1
        //     turns is admitted, then ENQUEUED up to the ceiling, then SHED — bounded backpressure, not
        //     an unbounded queue and never a silent drop.
        let mut decisions = Vec::new();
        for seq in 0..6u64 {
            let req = QosRequest::new(seq, PriorityClass::Standard, "dept-ops");
            decisions.push(gate.pre_serve(&req));
        }
        assert!(
            decisions
                .iter()
                .any(|d| matches!(d, SloDecision::Admitted { .. })),
            "some turns admitted: {decisions:?}"
        );
        assert!(
            decisions
                .iter()
                .any(|d| matches!(d, SloDecision::Enqueued { .. })),
            "over-capacity turns are enqueued (bounded), not dropped: {decisions:?}"
        );
        assert!(
            decisions.iter().any(|d| matches!(d, SloDecision::Shed(_))),
            "the queue ceiling sheds honestly once full: {decisions:?}"
        );
    }
}

#[test]
fn r11_default_config_leaves_fence_inert() {
    // The air-gapped default (no `[serving]`) advertises NO nodes — the fence stays inert (the round-4
    // shipped-chat guard: no pool ⇒ no 503).
    let loaded = default_config();
    assert!(
        loaded.serving.is_empty(),
        "default config declares no serving nodes"
    );
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");
    assert!(
        full.serving.1.is_empty(),
        "air-gapped default advertises no serving nodes"
    );
}

async fn post_chat(client: &reqwest::Client, addr: &std::net::SocketAddr, data_class: &str) -> u16 {
    client
        .post(format!("http://{addr}/v1/chat"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header("x-ainxt-user", "alice")
        .header("x-ainxt-clearance", "regulated-payment")
        .body(
            serde_json::json!({
                "session": "s1",
                "turn": "t1",
                "input": "hello",
                "data_class": data_class,
                "caps": ["chat.send"]
            })
            .to_string(),
        )
        .send()
        .await
        .expect("request send")
        .status()
        .as_u16()
}

#[tokio::test(flavor = "multi_thread")]
async fn r11_served_http_chat_fence_live_with_pool_but_no_normal_regression() {
    let loaded = served_pool_config();
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");
    assert_eq!(full.serving.1.len(), 2, "served HTTP path has a live pool");

    let app = full.to_full_app();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(ainxt_server::serve_full_ext(
        listener,
        app,
        full.to_full_app_ext(),
    ));
    let client = reqwest::Client::new();

    // A normal (non-regulated) turn STILL serves with a live pool — no 503 regression (the shipped-chat
    // guard holds even when the fence is active, because a routable node admits it).
    let internal = post_chat(&client, &addr, "internal").await;
    assert_ne!(internal, 404, "/v1/chat mounted");
    assert_ne!(
        internal, 503,
        "a normal turn on a routable-node pool must not 503 (no empty-pool regression): got {internal}"
    );

    // A REGULATED turn on the unattested pool is FENCED at the shipped HTTP path — fail-closed 403,
    // never routed onto an untrusted node (ADR-021 §8.2), proving the fence is LIVE end-to-end.
    let regulated = post_chat(&client, &addr, "regulated-payment").await;
    assert_eq!(
        regulated, 403,
        "regulated turn must be fenced (403 fail-closed) on an unattested pool: got {regulated}"
    );

    // GAP-AUDIT regulated-fi #3 — the fail-closed refusal above must arm a §2.1 (ADR-020) serving-ops
    // incident on the SAME live register `/v1/regfi/auditor` reads, not just an HTTP 403 with no
    // supervisory trace. Before this fix `ainxt-server`'s `AppState` had no `incidents` handle at all.
    assert_eq!(
        full.incidents
            .lock()
            .expect("incident lock")
            .incidents()
            .count(),
        1,
        "the fail-closed refusal must arm exactly one serving-ops incident on the shared register"
    );
}
