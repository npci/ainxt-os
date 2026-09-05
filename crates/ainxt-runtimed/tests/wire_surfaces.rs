// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Wiring proofs for the composition root (`ainxt-runtimed`): the surface subsystem is now REACHABLE
//! on the served path, not just unit-tested in isolation. Each test constructs the REAL assembled
//! object the daemon builds (grounded `ChatSurface`, profile-enforcing `ProfiledSurface`, the full
//! `assemble_surface` stack) and asserts the wired behavior end-to-end. Each fails before the wire
//! (bare `ConversationManager::new` had no retriever/cache; the served path had no profile lookup)
//! and passes after.
//!
//!   * `wire_surf_02` — the assembled chat surface GROUNDS and CITES (SURF-02).
//!   * `wire_surf_03` — the assembled chat surface CACHES, scoping-safe: a cacheable-class repeat is a
//!     cache hit; an above-ceiling class is never cached (SURF-03).
//!   * `wire_surf_01` — the served path looks the profile up in a `SurfaceCatalog` and ENFORCES it:
//!     a principal that fails the RBAC floor is refused BEFORE the model turn; an admitted one reaches
//!     the grounded engine. Also proven through the full `assemble_surface` daemon + client (SURF-01).
//!   * `wire_surf_04` — the daemon builds a `SkillRuntime` and passes it to the binding, so behavioral
//!     skills inject into the system prompt (persona → behavioral → user turn) on the served request
//!     (SURF-04).

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use ainxt_chat::ChatReply;
use ainxt_context::{Chunk, Corpus};
use ainxt_protocol::{Event, Request};
use ainxt_runtime::{CancelToken, TurnError, TurnHandler, TurnSummary};
use ainxt_runtimed::{
    assemble_surface, build_chat_surface, load_layered, LoadedConfig, ProfiledSurface,
};
use ainxt_skill::{NativeSkillExecutor, SkillManifest, SkillRegistry, SkillRuntime};
use ainxt_surface::SurfaceCatalog;
use ainxt_types::{DataClass, Principal};
use tokio::sync::mpsc;

/// The daemon's default offline config (no keys ⇒ deterministic offline provider, independent of env).
fn offline_config() -> LoadedConfig {
    load_layered(&[("x", "version = 1")]).unwrap()
}

/// A corpus with one Public chunk about UPI, so the lexical retriever grounds a UPI question.
fn upi_corpus() -> Corpus {
    Corpus::new().with(Chunk::new(
        "kb-upi-1",
        "platform_kb",
        "UPI transaction volume grew about 45 percent year over year across member banks.",
        DataClass::Public,
    ))
}

/// The daemon's deployment skill runtime (empty registry + the real native executor), exactly as
/// `ainxt_runtimed::build_skill_runtime` builds it.
fn daemon_skills() -> SkillRuntime {
    SkillRuntime::new(SkillRegistry::new(), Box::new(NativeSkillExecutor::new()))
}

/// Drive one turn through a handler and collect both the result and everything streamed to the sink.
async fn drive(
    handler: &dyn TurnHandler,
    principal: &Principal,
    req: &Request,
) -> (Result<TurnSummary, TurnError>, Vec<Event>) {
    let (tx, mut rx) = mpsc::channel::<Event>(64);
    let cancel = CancelToken::new();
    let res = handler.handle_turn(principal, req, tx, &cancel).await;
    let mut events = Vec::new();
    while let Some(ev) = rx.recv().await {
        events.push(ev);
    }
    (res, events)
}

fn streamed_text(events: &[Event]) -> String {
    events
        .iter()
        .filter_map(|e| match e {
            Event::TextDelta(t) => Some(t.as_str()),
            _ => None,
        })
        .collect()
}

// ============================ SURF-02 — grounding + citation ============================

#[tokio::test(flavor = "multi_thread")]
async fn wire_surf_02() {
    // The REAL object the daemon assembles for the chat surface, but with a seeded corpus.
    let (chat, report) = build_chat_surface(&offline_config(), upi_corpus()).unwrap();
    assert!(
        report.iter().any(|r| r.contains("grounded ChatSurface")),
        "assembly report must record the grounded surface: {report:?}"
    );

    let user = Principal::user("u", &["chat.send"]).with_department("payments");
    let reply = chat
        .turn("s1", &user, "how did UPI grow?", DataClass::Public)
        .await
        .expect("grounded chat turn");

    match reply {
        ChatReply::Answer {
            citations,
            from_cache,
            ..
        } => {
            assert!(!from_cache, "first turn must not be a cache hit");
            // The wire: from_engine builds the grounded ConversationManager, so retrieval runs and the
            // answer carries a citation. Before the wire (bare ConversationManager::new) this was empty.
            assert!(
                !citations.is_empty(),
                "grounded surface must cite its retrieved source"
            );
            assert!(
                citations.iter().any(|c| c.source == "platform_kb"),
                "citation must lineage back to the corpus source: {citations:?}"
            );
        }
        other => panic!("expected a grounded Answer, got {other:?}"),
    }
}

// ============================ SURF-03 — scoping-safe response cache ============================

#[tokio::test(flavor = "multi_thread")]
async fn wire_surf_03() {
    let (chat, _r) = build_chat_surface(&offline_config(), upi_corpus()).unwrap();
    // Clearance to read RegulatedPayment: the turn pipeline now enforces the clearance-vs-data-class
    // read seam (ADR-012), so the sensitive-class leg below must be authored by a principal cleared for
    // it — the point of this test is the cache-scoping decision, not the read-authz gate. We do NOT
    // bypass the seam; we satisfy it, then assert the sensitive class is still never cached.
    let user = Principal::user("u", &["chat.send"])
        .with_department("payments")
        .with_clearance(DataClass::RegulatedPayment);

    // A cacheable-class (Public) question, asked twice, is served from the cache the second time.
    let first = chat
        .turn("s1", &user, "how did UPI grow?", DataClass::Public)
        .await
        .unwrap();
    assert!(matches!(
        first,
        ChatReply::Answer {
            from_cache: false,
            ..
        }
    ));
    let second = chat
        .turn("s1", &user, "how did UPI grow?", DataClass::Public)
        .await
        .unwrap();
    match second {
        ChatReply::Answer {
            from_cache,
            provider,
            ..
        } => {
            assert!(from_cache, "a repeated cacheable turn must hit the cache");
            assert_eq!(provider, "cache");
        }
        other => panic!("expected a cached Answer, got {other:?}"),
    }

    // An above-ceiling class (RegulatedPayment > Internal) is NEVER cached — repeats are always fresh.
    let hi1 = chat
        .turn(
            "s2",
            &user,
            "settlement question",
            DataClass::RegulatedPayment,
        )
        .await
        .unwrap();
    assert!(matches!(
        hi1,
        ChatReply::Answer {
            from_cache: false,
            ..
        }
    ));
    let hi2 = chat
        .turn(
            "s2",
            &user,
            "settlement question",
            DataClass::RegulatedPayment,
        )
        .await
        .unwrap();
    assert!(
        matches!(
            hi2,
            ChatReply::Answer {
                from_cache: false,
                ..
            }
        ),
        "a sensitive-class turn must never be served from cache"
    );
}

// ============================ SURF-01 — per-turn profile lookup + enforcement ============================

/// Build the REAL profiled chat surface the daemon serves: builtin catalog + daemon skill runtime +
/// grounded ChatSurface, bound to the `chat` profile. This is exactly `assemble_surface`'s composition.
fn profiled_chat() -> ProfiledSurface {
    let catalog = SurfaceCatalog::builtin().unwrap();
    let (chat, _r) = build_chat_surface(&offline_config(), Corpus::new()).unwrap();
    ProfiledSurface::new(catalog, Arc::new(daemon_skills()), "chat", Arc::new(chat))
}

#[tokio::test(flavor = "multi_thread")]
async fn wire_surf_01() {
    let surface = profiled_chat();

    // The `chat` profile is department-scoped: a principal with NO department fails the RBAC floor and
    // is refused BEFORE any model turn — the profile is enforced on the served path.
    let no_dept = Principal::user("u", &["chat.send"]);
    let req = Request::chat("s1", "t1", "how did UPI grow?", DataClass::Public);
    let (res, events) = drive(&surface, &no_dept, &req).await;
    assert!(
        matches!(res, Err(TurnError::Denied(_))),
        "a principal below the surface RBAC floor must be denied, got {res:?}"
    );
    assert!(
        events.iter().any(|e| matches!(e, Event::Error(_))),
        "denial must surface an error event"
    );
    assert!(
        !streamed_text(&events).contains("offline mode"),
        "a denied turn must never reach the model"
    );

    // A principal that satisfies the profile (user + chat.send + a department) is admitted and the
    // planned turn reaches the grounded engine.
    let ok = Principal::user("u", &["chat.send"]).with_department("payments");
    let (res, events) = drive(&surface, &ok, &req).await;
    let summary = res.expect("admitted turn must run");
    assert_eq!(summary.provider, "offline");
    assert!(
        streamed_text(&events).contains("offline mode"),
        "an admitted turn must reach the model: {events:?}"
    );
}

// ---- GAP-FIX surfaces-profiles-skills-config: Request.request_override reaches
// SurfaceBinding::plan_with_request_override (previously hardcoded `None` on every served turn). ----
#[tokio::test(flavor = "multi_thread")]
async fn wire_surf_05_request_override_reaches_the_binding() {
    let surface = profiled_chat();
    let ok = Principal::user("u", &["chat.send"]).with_department("payments");

    // Before this fix, `Request.request_override` did not exist and `ProfiledSurface::handle_turn`
    // always called the plain `.plan()` — a widening override attempt would have had ZERO effect
    // (the field couldn't even be set). Now a widening attempt (changing the surface id, refused by
    // `enforce_request_layer_invariants`) is actually evaluated and refused fail-closed.
    let widening = Request::chat("s1", "t1", "how did UPI grow?", DataClass::Public)
        .with_request_override("id = \"not-chat\"");
    let (res, _events) = drive(&surface, &ok, &widening).await;
    match res {
        Err(TurnError::Denied(msg)) => {
            assert!(
                msg.contains("surface id"),
                "the refusal must come from the request-layer invariant check: {msg}"
            );
        }
        other => panic!("a widening request override must be refused fail-closed, got {other:?}"),
    }

    // A benign/empty override is a no-op — an admitted principal's turn is unaffected.
    let benign = Request::chat("s1", "t2", "how did UPI grow?", DataClass::Public);
    let (res, events) = drive(&surface, &ok, &benign).await;
    assert!(
        res.is_ok(),
        "no override must behave exactly as before: {res:?}"
    );
    assert!(streamed_text(&events).contains("offline mode"));
}

#[tokio::test(flavor = "multi_thread")]
async fn wire_surf_01_end_to_end_via_daemon() {
    use ainxt_client::{Client, ClientConfig};

    // The FULL daemon assembly (catalog lookup + skill runtime + grounded surface + SessionManager
    // spine) served to a real client. Proves the profiled path is what the daemon actually serves.
    let assembled = assemble_surface(&offline_config(), "chat").unwrap();
    assert!(
        assembled
            .report
            .iter()
            .any(|r| r.contains("profile-enforced")),
        "assembly report must record the profiled surface: {:?}",
        assembled.report
    );
    let client = Client::in_process(
        assembled.manager,
        Principal::user("u", &["chat.send"]).with_department("payments"),
        ClientConfig::default(),
    );
    let out = client
        .chat("s", "t", "how did UPI grow?")
        .unwrap()
        .collect()
        .await;
    assert!(
        out.completed,
        "the profiled daemon must complete an admitted turn"
    );
    assert!(
        out.text.contains("offline mode"),
        "served text: {}",
        out.text
    );
}

// ============================ SURF-04 — SkillRuntime injection on the served path ============================

/// A test-only inner handler that records the profiled request it receives — lets us prove the plan's
/// assembled system prompt (persona → behavioral skill) reaches the engine request.
struct Recorder {
    seen: Arc<Mutex<Vec<Request>>>,
}

impl TurnHandler for Recorder {
    fn handle_turn<'a>(
        &'a self,
        _principal: &'a Principal,
        req: &'a Request,
        sink: mpsc::Sender<Event>,
        _cancel: &'a CancelToken,
    ) -> Pin<Box<dyn Future<Output = Result<TurnSummary, TurnError>> + Send + 'a>> {
        let captured = req.clone();
        let seen = self.seen.clone();
        Box::pin(async move {
            seen.lock().unwrap().push(captured);
            let _ = sink.send(Event::TextDelta("RECORDED".into())).await;
            let _ = sink.send(Event::Done).await;
            Ok(TurnSummary {
                final_text: "RECORDED".into(),
                redactions: 0,
                provider: "recorder".into(),
                ..Default::default()
            })
        })
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn wire_surf_04() {
    // A deployment profile that references a behavioral skill, and a SkillRuntime that has it.
    let catalog = SurfaceCatalog::from_toml_sources(&[(
        "custom",
        "id = \"custom\"\npersona = \"PERSONA-X\"\nskills = [\"sop\"]\n[rbac]\nmin_role = \"user\"",
    )])
    .unwrap();
    let mut registry = SkillRegistry::new();
    registry.register(SkillManifest::behavioral(
        "sop",
        "BEHAVIOR-Y: follow the RCA procedure.",
    ));
    let skills = SkillRuntime::new(registry, Box::new(NativeSkillExecutor::new()));

    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorder = Recorder { seen: seen.clone() };
    let surface = ProfiledSurface::new(catalog, Arc::new(skills), "custom", Arc::new(recorder));

    let user = Principal::user("u", &[]);
    let req = Request::chat("s1", "t1", "hello world", DataClass::Public);
    let (res, _events) = drive(&surface, &user, &req).await;
    res.expect("the custom profile admits this principal");

    // The recorded request carries persona → behavioral skill → user turn, IN THAT ORDER — proof the
    // SkillRuntime was built, passed to the binding, and its injection ran on the served path.
    let captured = seen.lock().unwrap();
    let input = &captured.first().expect("a turn was recorded").input;
    let persona = input.find("PERSONA-X").expect("persona must be injected");
    let behavior = input
        .find("BEHAVIOR-Y")
        .expect("behavioral skill must be injected");
    let user_turn = input
        .find("hello world")
        .expect("user turn must be present");
    assert!(
        persona < behavior && behavior < user_turn,
        "injection order must be persona → behavioral → user turn: {input:?}"
    );
}

// ============ SURF-13/14 composition root — SurfaceArtifacts: REMOVED, see decision below ==========
//
// GAP-AUDIT surfaces-profiles-skills-config (item 3) — `wire_surf_13_14_composition_root` used to live
// here, proving `assemble_surface`'s `Assembled.artifact` (an `ainxt_surface::SurfaceArtifacts`) was a
// real, working runtime. It was exactly the "constructs its own instance, never proven through the
// real served route" pattern this audit round exists to catch: `Assembled.artifact` had exactly ONE
// downstream reader — `assemble_full_with_control_plane`'s destructure, which immediately dropped it
// (see that function's former `_surface_artifacts` binding) — so this test's assertions never told you
// anything about what a live HTTP request to the served daemon actually does. The REAL served
// document-generation path is `POST /v1/artifact`, backed by `mounts::build_artifact_runtime`'s
// `ArtifactRuntime` (registers ALL renderers, including binary pdf/docx/xlsx — a strict superset of
// the two text-only renderers `SurfaceArtifacts::with_default_scanner()` ever offered). That mechanism
// already has a genuine live-HTTP proving test: `r6_shipped_cluster.rs`'s `/v1/artifact` POST via a
// real `reqwest` client against a server built from `assemble_full`, plus `full.artifact.formats()` on
// the SAME `AssembledFull` a served daemon actually returns. `SurfaceArtifacts` was removed from the
// composition root (`ainxt-runtimed/src/lib.rs`'s `Assembled` struct) rather than kept for a test that
// could never observe the real served path; see the DECISION comment on `Assembled` for the full
// reasoning. The type itself (`ainxt_surface::SurfaceArtifacts`) is untouched in `ainxt-surface`.
