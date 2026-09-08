// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R15 COMPOSE — three additive `ainxt-runtime` seams (`Request::pinned_tier` + `tier_eligible` hard
//! filter, `Engine::with_complexity_classifier`, `Engine::with_dispatch_probe`) were real but NOT yet
//! mounted on the served path. This round hot-wires all three at the composition root
//! (`ainxt-runtimed`) and this file proves each landed:
//!
//!   * `r15_compose_pinned_tier_reaches_engine` — the `sdlc` surface profile now HARD-pins its tier
//!     (`ainxt_profile::ModelPolicy::pin_tier`); `TurnPlan::to_request` carries that pin onto
//!     `ainxt_protocol::Request::pinned_tier`. FAIL-BEFORE: `pinned_tier` was always `None` on every
//!     surface's request (the field/plumbing did not exist), so a Simple-tier-only router would have
//!     silently served an `sdlc` turn on the wrong-tier model. PASS-AFTER: the pinned turn fails CLOSED
//!     against a Simple-only router (a typed routing error, never a wrong-tier model) and succeeds once
//!     a Complex-tier provider is registered, routed to exactly that provider.
//!   * `r15_compose_classifier_mounted_on_daemon` — both engine-builder composition sites
//!     (`build_engine_ext` for the bare engine, and the flagship chat/code/sdlc/buddy engine builder
//!     behind `assemble_chat`) mount `ainxt_runtime::complexity::HeuristicComplexityClassifier` via
//!     `Engine::with_complexity_classifier`. FAIL-BEFORE: neither builder called it (the engine used its
//!     default `TierFromRequest` classifier — an unpinned served turn never genuinely derived a tier from
//!     content). PASS-AFTER: the assembly report documents the mount on BOTH composition sites.
//!   * `r15_compose_dispatch_probe_observable` — the shared `ainxt_runtime::dispatch::DispatchProbe`
//!     attached to the served chat engine is threaded out through `Assembled`/`AssembledFull`/
//!     `FullAppExt`/`AppState` and sampled into the per-turn telemetry sink
//!     (`TelemetrySink::record_dispatch`) on every served `/v1/chat` turn. FAIL-BEFORE: no probe was
//!     attached and `AppState` had no field to carry one, so `record_dispatch` was never called on the
//!     served path (parallel-dispatch concurrency was observable only inside `ainxt-runtime`'s own
//!     tests). PASS-AFTER: a served turn over real HTTP produces at least one recorded dispatch snapshot.
//!
//! Deterministic + offline: the air-gapped default (offline provider, no keys/network) backs every real
//! HTTP turn; the hand-built engines in the first test use small, in-test fake providers instead of a
//! live model so tier-eligibility can be proven without live infra.

use std::time::{SystemTime, UNIX_EPOCH};

use ainxt_protocol::Event;
use ainxt_runtime::audit::InMemoryAudit;
use ainxt_runtime::authz::RbacAuthorizer;
use ainxt_runtime::compliance::RedactAndProceed;
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtime::{CancelToken, Engine, TurnError};
use ainxt_runtimed::{assemble_chat, assemble_full, build_engine_ext, load_layered, LoadedConfig};
use ainxt_skill::{NoExecutor, SkillRegistry, SkillRuntime};
use ainxt_surface::SurfaceCatalog;
use ainxt_types::{DataClass, Principal, Tier};

fn offline() -> LoadedConfig {
    load_layered(&[("x", "version = 1")]).unwrap()
}

fn loaded_with_unique_log() -> LoadedConfig {
    // R16 critical: the daemon now refuses the header-trusting default authenticator unless the
    // deployment states the assumption (see r10_breach_clock_unit.rs) — state it here.
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("ainxt-r15-compose-{nanos}"));
    let src = format!(
        "version = 1\n[server]\nevent_log_dir = {:?}\n",
        dir.to_string_lossy()
    );
    load_layered(&[("r15compose", &src)]).expect("load offline config")
}

/// A minimal in-test provider that always answers with a fixed text and declares a fixed tier — no
/// network, deterministic, used only to prove the router's tier-eligibility gate without live infra.
struct FakeTierProvider {
    id: &'static str,
    tier: Option<Tier>,
}

impl Provider for FakeTierProvider {
    fn id(&self) -> &str {
        self.id
    }
    fn eligible(&self, _data_class: DataClass) -> bool {
        true
    }
    fn tier(&self) -> Option<Tier> {
        self.tier
    }
    fn stream(&self, _prompt: &str) -> tokio::sync::mpsc::Receiver<Event> {
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        let id = self.id.to_string();
        tokio::spawn(async move {
            let _ = tx.send(Event::TextDelta(format!("served-by:{id}"))).await;
        });
        rx
    }
}

fn engine_over(providers: Vec<FakeTierProvider>) -> Engine {
    let mut router = ModelRouter::new();
    for p in providers {
        router.register(Box::new(p));
    }
    Engine::new(
        Box::new(RedactAndProceed),
        Box::new(RbacAuthorizer),
        Box::new(InMemoryAudit::default()),
        router,
    )
}

/// R15 COMPOSE — needs_hot_wiring #1: `Request::pinned_tier` reaches the engine's HARD tier filter via
/// the served surface-plan → request mapping.
#[tokio::test(flavor = "multi_thread")]
async fn r15_compose_pinned_tier_reaches_engine() {
    let catalog = SurfaceCatalog::builtin().expect("builtin catalog resolves");
    let skills = SkillRuntime::new(SkillRegistry::new(), Box::new(NoExecutor));
    let principal = Principal::user("u", &["chat.send"]).with_department("payments");

    // The shipped `sdlc` profile HARD-pins Complex (ModelPolicy::pin_tier = true).
    let sdlc_plan = catalog
        .bind("sdlc", &skills)
        .expect("sdlc is a builtin surface")
        .plan(&principal, "add a health endpoint", DataClass::Public, &[])
        .expect("sdlc admits this turn");
    assert_eq!(
        sdlc_plan.pinned_tier,
        Some(Tier::Complex),
        "the shipped sdlc profile must hard-pin Complex via ModelPolicy::pin_tier"
    );
    let sdlc_req = sdlc_plan.to_request("s1", "t1", "add a health endpoint");
    assert_eq!(
        sdlc_req.pinned_tier,
        Some(Tier::Complex),
        "TurnPlan::to_request must carry the surface's hard pin onto the wire Request"
    );

    // The shipped `chat` profile stays unpinned — a soft preference only.
    let chat_plan = catalog
        .bind("chat", &skills)
        .expect("chat is a builtin surface")
        .plan(&principal, "how did UPI grow?", DataClass::Public, &[])
        .expect("chat admits this turn");
    assert_eq!(
        chat_plan.pinned_tier, None,
        "the shipped chat profile must stay unpinned by default"
    );
    let chat_req = chat_plan.to_request("s2", "t2", "how did UPI grow?");
    assert_eq!(chat_req.pinned_tier, None);

    // FAIL-CLOSED PROOF: against a router with ONLY a Simple-tier provider, the unpinned chat turn
    // still routes (soft preference tolerates off-tier — pre-existing graceful fallback), but the
    // hard-pinned sdlc turn is REFUSED — a typed routing error, never a silently wrong-tier model.
    let simple_only = engine_over(vec![FakeTierProvider {
        id: "simple-model",
        tier: Some(Tier::Simple),
    }]);
    let cancel = CancelToken::new();

    let (tx, rx) = tokio::sync::mpsc::channel(16);
    let chat_outcome = simple_only
        .run_turn_cancellable(&principal, &chat_req, tx, &cancel)
        .await;
    drop(rx);
    assert!(
        chat_outcome.is_ok(),
        "an unpinned turn must still route via the soft preference: {chat_outcome:?}"
    );

    let (tx2, rx2) = tokio::sync::mpsc::channel(16);
    let sdlc_outcome = simple_only
        .run_turn_cancellable(&principal, &sdlc_req, tx2, &cancel)
        .await;
    drop(rx2);
    assert!(
        matches!(sdlc_outcome, Err(TurnError::Routing(_))),
        "a HARD-PINNED Complex turn must fail CLOSED against a Simple-only router, never silently \
         serve the wrong tier: {sdlc_outcome:?}"
    );

    // Register a Complex-tier provider too — the pinned turn now succeeds, routed to exactly it (the
    // Simple-tier provider is excluded by the hard filter, not merely deprioritized).
    let both = engine_over(vec![
        FakeTierProvider {
            id: "simple-model",
            tier: Some(Tier::Simple),
        },
        FakeTierProvider {
            id: "complex-model",
            tier: Some(Tier::Complex),
        },
    ]);
    let (tx3, rx3) = tokio::sync::mpsc::channel(16);
    let summary = both
        .run_turn_cancellable(&principal, &sdlc_req, tx3, &cancel)
        .await
        .expect("a Complex-tier provider is now eligible");
    drop(rx3);
    assert_eq!(
        summary.provider, "complex-model",
        "the pinned turn must route to the Complex-tier provider, never the Simple one"
    );
}

/// R15 COMPOSE — needs_hot_wiring #2: `Engine::with_complexity_classifier` is mounted at BOTH served
/// engine-builder composition sites (the bare engine and the flagship chat/code/sdlc/buddy engine).
#[test]
fn r15_compose_classifier_mounted_on_daemon() {
    let loaded = offline();

    let (
        _engine,
        report,
        _ledger,
        _reconciler,
        _probe,
        _tools,
        _outsourcing,
        _mandate_registry,
        _mcp_admin,
        _prompt_cache,
        _serving,
    ) = build_engine_ext(&loaded.runtime).expect("bare engine assembles");
    assert!(
        report.iter().any(|r| r.contains("HeuristicComplexityClassifier")),
        "build_engine_ext must mount the in-engine complexity classifier so an unpinned served turn \
         genuinely derives its tier from content: {report:?}"
    );

    let chat = assemble_chat(&loaded).expect("chat surface assembles");
    assert!(
        chat.report.iter().any(|r| r.contains("HeuristicComplexityClassifier")),
        "the flagship chat/code/sdlc/buddy engine builder must ALSO mount the classifier, not just \
         the bare-engine composition path: {:?}",
        chat.report
    );
}

/// R15 COMPOSE — needs_hot_wiring #3: the engine's shared `DispatchProbe` is threaded through the
/// composition (`Assembled` → `AssembledFull` → `FullAppExt` → `AppState`) and sampled into the
/// per-turn telemetry sink on a REAL served `/v1/chat` turn over HTTP.
#[tokio::test(flavor = "multi_thread")]
async fn r15_compose_dispatch_probe_observable() {
    let loaded = loaded_with_unique_log();
    let assembled = assemble_chat(&loaded).expect("assemble chat");
    assert!(
        assembled.dispatch_probe.is_some(),
        "the assembled chat surface must expose the engine's shared DispatchProbe"
    );
    let full = assemble_full(&loaded, assembled).expect("assemble full");

    let telemetry = std::sync::Arc::new(ainxt_telemetry::InMemoryTelemetry::new());
    let app = full.to_full_app();
    let mut ext = full.to_full_app_ext();
    assert!(
        ext.dispatch_probe.is_some(),
        "AssembledFull::to_full_app_ext must hand the transport the engine's DispatchProbe"
    );
    ext.telemetry = Some(telemetry.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(ainxt_server::serve_full_ext(listener, app, ext));

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{addr}/v1/chat"))
        .header("content-type", "application/json")
        .header("x-ainxt-user", "alice")
        .header("x-ainxt-clearance", "internal")
        .header("x-ainxt-department", "payments")
        .body(
            serde_json::json!({
                "session": "s1", "turn": "t1", "input": "hello there",
                "data_class": "public", "caps": ["chat.send"]
            })
            .to_string(),
        )
        .send()
        .await
        .expect("chat send");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "the shipped daemon serves the chat turn"
    );
    let _ = resp.text().await; // drain fully so the wire-forwarding task's telemetry write has run

    // The telemetry write races the response body finishing (best-effort background task) — poll
    // briefly rather than assume it has already landed.
    let mut tries = 0;
    while telemetry.dispatch_snapshots().is_empty() && tries < 100 {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        tries += 1;
    }
    assert!(
        !telemetry.dispatch_snapshots().is_empty(),
        "a served /v1/chat turn must sample the engine's DispatchProbe into telemetry via \
         record_dispatch — before this round's wiring, AppState carried no probe and record_dispatch \
         was never called on the served path"
    );
}
