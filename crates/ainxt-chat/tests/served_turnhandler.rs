// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Served-surface tests (gap SURF-02/03): the Chat surface driven through the `TurnHandler` seam the
//! daemon's `SessionManager` actually uses — proving the SERVED path grounds, cites, and caches
//! (scoping-safe), not just the orphaned non-streaming `turn()`.

use ainxt_cache::{CacheConfig, FixedClock};
use ainxt_chat::{ChatReply, ChatSurface};
use ainxt_compliance::StrongRedactor;
use ainxt_context::{Chunk, Corpus};
use ainxt_protocol::{Event, Request};
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtime::{CancelToken, Engine, InMemoryAudit, RbacAuthorizer, TurnHandler, TurnSummary};
use ainxt_types::{DataClass, Principal};
use tokio::sync::mpsc;

/// A provider that PROVES grounding: it reports whether the distinctive retrieved fact reached the
/// assembled prompt. If the retriever fed the corpus chunk in, the prompt contains "real-time
/// payments" and the model answers "grounded:yes"; otherwise "grounded:no".
struct GroundingProvider;
impl Provider for GroundingProvider {
    fn id(&self) -> &str {
        "mock"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, prompt: &str) -> mpsc::Receiver<Event> {
        let grounded = prompt.to_lowercase().contains("real-time payments");
        let (tx, rx) = mpsc::channel(8);
        tokio::spawn(async move {
            let msg = if grounded {
                "UPI grew fast. grounded:yes"
            } else {
                "grounded:no"
            };
            let _ = tx.send(Event::TextDelta(msg.into())).await;
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

fn surface() -> ChatSurface {
    let mut router = ModelRouter::new();
    router.register(Box::new(GroundingProvider));
    // Build the engine the way the daemon does (mandatory gates), then hand it to `from_engine` —
    // exercising the daemon-consumable seam, not the all-in-one `new`.
    let engine = Engine::new(
        Box::new(StrongRedactor::new()),
        Box::new(RbacAuthorizer),
        Box::new(InMemoryAudit::default()),
        router,
    );
    let corpus = Corpus::new().with(Chunk::new(
        "upi",
        "kb",
        "UPI is a real-time payments system whose transaction volume grew rapidly year over year",
        DataClass::Public,
    ));
    let cfg = CacheConfig {
        capacity: 128,
        ttl_ticks: 100,
        semantic_threshold: 0.99,
    };
    ChatSurface::from_engine(engine, corpus, cfg, Box::new(FixedClock(0)))
}

fn user() -> Principal {
    Principal::user("analyst", &["chat.send"])
}

/// Drive one turn through the `TurnHandler` seam; return the summary and the streamed text.
async fn serve(
    s: &ChatSurface,
    session: &str,
    principal: &Principal,
    input: &str,
    dc: DataClass,
) -> (TurnSummary, String) {
    let (tx, mut rx) = mpsc::channel::<Event>(64);
    let cancel = CancelToken::new();
    let req = Request::chat(session, "t", input, dc);
    let summary = s
        .handle_turn(principal, &req, tx, &cancel)
        .await
        .expect("served turn");
    let mut text = String::new();
    while let Some(ev) = rx.recv().await {
        if let Event::TextDelta(t) = ev {
            text.push_str(&t);
        }
    }
    (summary, text)
}

#[tokio::test]
async fn gap_ainxt_chat_surf_02_served_turnhandler_grounds_the_answer() {
    let s = surface();
    let (summary, text) = serve(&s, "s1", &user(), "How did UPI grow?", DataClass::Public).await;
    assert_eq!(summary.provider, "mock");
    assert!(
        text.contains("grounded:yes"),
        "the served TurnHandler must feed clearance-filtered retrieval into the prompt: {text}"
    );
}

#[tokio::test]
async fn gap_ainxt_chat_surf_02_served_surface_produces_citations() {
    // Citations are carried on the (same-surface) answer contract — grounding yields a citation.
    let s = surface();
    let reply = s
        .turn("sc", &user(), "How did UPI grow?", DataClass::Public)
        .await
        .unwrap();
    match reply {
        ChatReply::Answer { citations, .. } => {
            assert!(
                !citations.is_empty(),
                "a grounded answer must carry at least one citation"
            );
        }
        o => panic!("expected a grounded Answer, got {o:?}"),
    }
}

#[tokio::test]
async fn gap_ainxt_chat_surf_03_served_turnhandler_caches_scoping_safely() {
    let s = surface();

    // First identical turn: a miss (real provider answers).
    let (s1, t1) = serve(&s, "s2", &user(), "How did UPI grow?", DataClass::Public).await;
    assert_eq!(s1.provider, "mock", "first turn is a cache miss");

    // Second identical turn (same clearance + class + input): a cache HIT via the served path.
    let (s2, t2) = serve(&s, "s2", &user(), "How did UPI grow?", DataClass::Public).await;
    assert_eq!(
        s2.provider, "cache",
        "the served path must cache and re-serve"
    );
    assert_eq!(t1, t2, "the cached answer must match the original");

    // Scoping: a caller with a DIFFERENT clearance must not read the first caller's slot.
    let higher = Principal::user("exec", &["chat.send"]).with_clearance(DataClass::Confidential);
    let (s3, _) = serve(&s, "s2", &higher, "How did UPI grow?", DataClass::Public).await;
    assert_eq!(
        s3.provider, "mock",
        "a different clearance must not share another clearance's cache slot"
    );
}

/// GAP-FIX conversation-intelligence "command pipelines never reach a served classifier":
/// `ainxt_convo::command_pipeline::CommandPipelineRegistry`/`stage1_signal_with_commands` were real
/// and tested, but `HeuristicClassifier::classify` — the classifier this surface's served `TurnHandler`
/// actually runs — called the registry-less `stage1_signal`, so a deployment's own registered `/name`
/// macro could never be recognized on a real turn; it fell through to plain Q&A grounding on the
/// literal slash-command text instead. Proven on the LIVE `handle_turn` seam, not a bespoke unit call
/// to `classify_with_commands` in isolation: a registered `/standup` macro's expanded steps reach the
/// streamed text, and the GroundingProvider — which would answer "grounded:no" for any turn that
/// actually reached the model — is never invoked (`summary.provider == "chat"`, the short-circuit
/// terminal, exactly like the built-in `/pdf` etc.).
#[tokio::test]
async fn gap_convo_command_pipeline_reaches_served_turnhandler_classifier() {
    use ainxt_convo::command_pipeline::{CommandPipelineDef, CommandPipelineRegistry, CommandStep};

    let mut registry = CommandPipelineRegistry::new();
    registry.register(
        CommandPipelineDef::new(
            "standup",
            vec![
                CommandStep::new("Summarize yesterday's commits for {args}"),
                CommandStep::new("Given this summary:\n{step_1}\nDraft a 3-bullet standup update"),
            ],
        )
        .with_description("Generate a standup update from recent commits"),
    );
    let s = surface().with_command_registry(registry);

    let (summary, text) = serve(
        &s,
        "cmd1",
        &user(),
        "/standup team-payments",
        DataClass::Public,
    )
    .await;
    assert_eq!(
        summary.provider, "chat",
        "a registered command pipeline must short-circuit BEFORE any provider call (Stage-1), \
         exactly like the built-in slash commands: {summary:?}"
    );
    assert!(
        text.contains("Summarize yesterday's commits for team-payments"),
        "the served TurnHandler must recognize the registered `/standup` command and emit its \
         first expanded step, not fall through to Q&A grounding on the literal slash-command text: \
         {text}"
    );
    assert!(
        text.contains("Draft a 3-bullet standup update"),
        "both of the macro's expanded steps must reach the served turn: {text}"
    );

    // Negative control: an UNREGISTERED `/name` still falls through past commands to the built-in
    // Stage-1 (no match) and then normal Q&A grounding — proving the fix does not make the classifier
    // swallow every leading slash, only ones actually present in the registry.
    let (unreg_summary, unreg_text) = serve(
        &s,
        "cmd2",
        &user(),
        "/incident-report db-outage",
        DataClass::Public,
    )
    .await;
    assert_eq!(
        unreg_summary.provider, "mock",
        "an unregistered `/name` must fall through to normal Q&A grounding: {unreg_summary:?}"
    );
    assert!(
        unreg_text.contains("grounded:no"),
        "an unregistered slash command must ground as an ordinary (unmatched) query: {unreg_text}"
    );
}

#[tokio::test]
async fn gap_ainxt_chat_surf_03_served_turnhandler_never_caches_sensitive_class() {
    let s = surface();
    // Cleared to READ Confidential (clearance-vs-data-class read seam, ADR-012): the assertion is that
    // an above-cacheable-max class is never cached, so the caller must legitimately pass the read gate.
    let u = user().with_clearance(DataClass::Confidential);
    // Two identical Confidential (above cacheable_max = Internal) turns: NEITHER is ever cached.
    let (a, _) = serve(&s, "s3", &u, "How did UPI grow?", DataClass::Confidential).await;
    let (b, _) = serve(&s, "s3", &u, "How did UPI grow?", DataClass::Confidential).await;
    assert_eq!(a.provider, "mock");
    assert_eq!(
        b.provider, "mock",
        "an above-Internal (Confidential) answer must never be cached on the served path"
    );
}
