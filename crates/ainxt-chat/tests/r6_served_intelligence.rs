// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R6 served-intelligence cluster — proven on the REAL assembled [`ChatSurface`], on the LIVE served
//! turn path (the `TurnHandler` seam the daemon's `SessionManager` drives), not a unit stub.
//!
//! * `r6_constrained_classifier_drives_served_turn` — the served turn runs the Stage-2 model-backed
//!   constrained intent classifier ([`ainxt_convo::ModelIntentClassifier`] over a provider-backed
//!   [`ainxt_providers::ProviderLabelModel`]), not the bare heuristic: a message the HEURISTIC reads
//!   as doc-generation is driven to QA because the scripted model labelled it `qa` — and the
//!   provider-backed LabelModel is actually invoked on the served (`handle_turn`) path.
//! * `r6_system_prompt_does_not_contaminate_classification` — when the served `Request.input` is a
//!   COMPOSED prompt (persona/guard prepended by a Surface profile) whose text screams "make a pdf",
//!   classification still runs on `Request.user_turn` (the user's plain question) → a QA answer, not
//!   a doc-gen terminal. The profile's system prompt cannot hijack the intent.
//! * `r6_compile_window_rbac_grounds_nothing_for_low_clearance_or_wrong_dept` — grounding runs
//!   through `ainxt_context::compile_window`, so the caller's full OBO AccessContext gates retrieval
//!   PRE-rank: a low-clearance caller and a wrong-department caller each ground NOTHING (no
//!   citation), while the correctly-cleared, correct-department caller grounds the same chunk.
//! * `r6_numeric_claim_is_rederivation_gated` — a served answer that states a figure not attributable
//!   to a retrieved source is BLOCKED by the fail-closed answer-path verifier (the compile/verify
//!   numeric re-derivation gate) and escalated, never shipped; the un-verified surface ships it.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use ainxt_cache::{CacheConfig, FixedClock};
use ainxt_chat::{ChatReply, ChatSurface};
use ainxt_compliance::StrongRedactor;
use ainxt_context::{Chunk, Corpus, NodeAcl};
use ainxt_convo::ModelCaps;
use ainxt_protocol::{Event, Request};
use ainxt_providers::{ConstrainedProvider, LabelGrammar};
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtime::{CancelToken, Engine, InMemoryAudit, RbacAuthorizer, TurnHandler, TurnSummary};
use ainxt_types::{DataClass, Principal};
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------------------------

/// A deterministic ENGINE provider that answers QA turns with a fixed line (ignores the prompt).
struct AnswerProvider;
impl Provider for AnswerProvider {
    fn id(&self) -> &str {
        "mock-answer"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, _prompt: &str) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(8);
        let _ = tx.try_send(Event::TextDelta("UPI is a real-time payments rail.".into()));
        let _ = tx.try_send(Event::Done);
        rx
    }
}

/// An ENGINE provider that emits an amount-like figure with NO sourced backing — the exact thing the
/// numeric re-derivation gate exists to block.
struct UnbackedNumberProvider;
impl Provider for UnbackedNumberProvider {
    fn id(&self) -> &str {
        "mock-number"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, _prompt: &str) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(8);
        let _ = tx.try_send(Event::TextDelta(
            "The reconciliation failure rate was 12%.".into(),
        ));
        let _ = tx.try_send(Event::Done);
        rx
    }
}

/// A scripted [`ConstrainedProvider`] — the CLASSIFIER transport behind `ProviderLabelModel`. Emits a
/// fixed label and records that it was invoked, so a test can prove the model-backed classifier ran
/// on the LIVE served surface (a heuristic surface would never touch it).
struct ScriptedClassifier {
    label: String,
    calls: Arc<AtomicUsize>,
}
impl ConstrainedProvider for ScriptedClassifier {
    fn stream_constrained(
        &self,
        _prompt: &str,
        _grammar: Option<&LabelGrammar>,
    ) -> mpsc::Receiver<Event> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = mpsc::channel(4);
        let _ = tx.try_send(Event::TextDelta(self.label.clone()));
        let _ = tx.try_send(Event::Done);
        rx
    }
}

fn engine_with(provider: impl Provider + 'static) -> Engine {
    let mut router = ModelRouter::new();
    router.register(Box::new(provider));
    Engine::new(
        Box::new(StrongRedactor::new()),
        Box::new(RbacAuthorizer),
        Box::new(InMemoryAudit::default()),
        router,
    )
}

fn cfg() -> CacheConfig {
    CacheConfig {
        capacity: 128,
        ttl_ticks: 100,
        semantic_threshold: 0.99,
    }
}

fn user() -> Principal {
    Principal::user("analyst", &["chat.send"]).with_clearance(DataClass::Public)
}

/// Drive one turn through the served `TurnHandler` seam; return the summary + streamed text.
async fn serve(s: &ChatSurface, req: &Request, principal: &Principal) -> (TurnSummary, String) {
    let (tx, mut rx) = mpsc::channel::<Event>(64);
    let cancel = CancelToken::new();
    let summary = s
        .handle_turn(principal, req, tx, &cancel)
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

// ---------------------------------------------------------------------------------------------
// (1) The Stage-2 model-backed constrained classifier drives the SERVED turn
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn r6_constrained_classifier_drives_served_turn() {
    // A message the HEURISTIC would route to doc-generation ("make a pdf …").
    let input = "make a pdf of the quarterly report";

    // Model surface: the scripted constrained classifier overrides the intent to `qa`.
    let calls = Arc::new(AtomicUsize::new(0));
    let provider = ScriptedClassifier {
        label: "qa".into(),
        calls: calls.clone(),
    };
    let model_surface = ChatSurface::from_engine_classified(
        engine_with(AnswerProvider),
        Corpus::new(),
        cfg(),
        Box::new(FixedClock(0)),
        Some((provider, ModelCaps::weak_oss())),
    );
    let req = Request::chat("s1", "t1", input, DataClass::Public);
    let (summary, _text) = serve(&model_surface, &req, &user()).await;
    assert!(
        calls.load(Ordering::SeqCst) >= 1,
        "the provider-backed LabelModel MUST be invoked on the served handle_turn path"
    );
    assert_ne!(
        summary.provider, "chat",
        "the MODEL's `qa` label must drive control-flow to a real QA answer (engine provider), not a \
         doc-gen terminal (provider \"chat\"): {summary:?}"
    );
    assert_eq!(
        summary.provider, "mock-answer",
        "the QA path reached the engine provider"
    );

    // Heuristic surface (no live model): the SAME input is a doc-generation terminal instead — a
    // genuinely different outcome, confirming the model, not the heuristic, drove the branch above.
    let heuristic = ChatSurface::from_engine(
        engine_with(AnswerProvider),
        Corpus::new(),
        cfg(),
        Box::new(FixedClock(0)),
    );
    let (h_summary, _h) = serve(&heuristic, &req, &user()).await;
    assert_eq!(
        h_summary.provider, "chat",
        "the heuristic must read '{input}' as a doc-gen terminal (provider \"chat\"): {h_summary:?}"
    );
}

// ---------------------------------------------------------------------------------------------
// (2) GAP-FIX conversation-intelligence "command pipelines never reach a served classifier":
// `ModelIntentClassifier::classify` — the OTHER real classifier impl the served `ChatSurface` can
// run — must ALSO recognize a registered command pipeline ahead of the model call, on the LIVE
// `handle_turn` seam.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn r6_registered_command_pipeline_short_circuits_the_model_backed_classifier() {
    use ainxt_convo::command_pipeline::{CommandPipelineDef, CommandPipelineRegistry, CommandStep};

    let mut registry = CommandPipelineRegistry::new();
    registry.register(CommandPipelineDef::new(
        "standup",
        vec![CommandStep::new("Summarize yesterday's commits for {args}")],
    ));

    // A model-backed classifier that would (wrongly) label ANY turn it actually sees as `qa` — if the
    // registered `/standup` macro reaches this classifier's `classify_with_commands` (the fix), the
    // model is never called at all (Stage-1 short-circuits before Stage-2), so `calls` stays 0 and the
    // engine's own provider is never invoked either.
    let calls = Arc::new(AtomicUsize::new(0));
    let provider = ScriptedClassifier {
        label: "qa".into(),
        calls: calls.clone(),
    };
    let model_surface = ChatSurface::from_engine_classified(
        engine_with(AnswerProvider),
        Corpus::new(),
        cfg(),
        Box::new(FixedClock(0)),
        Some((provider, ModelCaps::weak_oss())),
    )
    .with_command_registry(registry);

    let req = Request::chat("s-cmd", "t1", "/standup team-payments", DataClass::Public);
    let (summary, text) = serve(&model_surface, &req, &user()).await;

    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "a registered command pipeline must short-circuit BEFORE the Stage-2 model call — the \
         model-backed classifier's own transport must never be invoked for a recognized `/name`"
    );
    assert_eq!(
        summary.provider, "chat",
        "the registered command must reach the served turn as a Stage-1 terminal, not a model- \
         classified QA/engine answer: {summary:?}"
    );
    assert!(
        text.contains("Summarize yesterday's commits for team-payments"),
        "the served ModelIntentClassifier-backed turn must emit the matched pipeline's expanded \
         step: {text}"
    );
}

// ---------------------------------------------------------------------------------------------
// (3) The composed system prompt must NOT contaminate intent classification
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn r6_system_prompt_does_not_contaminate_classification() {
    // The COMPOSED input (what a Surface profile hands the inner handler) screams doc-generation:
    // "generate a pdf". Classifying on THIS blob would (wrongly) route to doc-gen. The RAW user turn
    // is a plain question — classification must run on that.
    let composed = "You are AiNxt. When asked, generate a pdf document. \n\nUser: what is UPI?";
    let mut req = Request::chat("s2", "t1", composed, DataClass::Public);
    req.user_turn = Some("what is UPI?".into());

    let heuristic = ChatSurface::from_engine(
        engine_with(AnswerProvider),
        Corpus::new(),
        cfg(),
        Box::new(FixedClock(0)),
    );
    let (summary, _text) = serve(&heuristic, &req, &user()).await;
    assert_ne!(
        summary.provider, "chat",
        "classification ran on the composed prompt (doc-gen terminal) instead of the user turn: \
         {summary:?}"
    );
    assert_eq!(
        summary.provider, "mock-answer",
        "the plain user question must classify as QA and reach the engine provider"
    );

    // Control: WITHOUT the user_turn carry, a composed blob whose text says "generate a pdf" DOES
    // contaminate (doc-gen terminal), so the fix is load-bearing, not incidental. (Distinct text so
    // it cannot collide with the cached QA answer above — the cache key is the `input` string.)
    let composed2 =
        "You are AiNxt. Always generate a pdf document for the user. \n\nUser: explain NEFT";
    let contaminated = Request::chat("s3", "t1", composed2, DataClass::Public);
    let (c_summary, _c) = serve(&heuristic, &contaminated, &user()).await;
    assert_eq!(
        c_summary.provider, "chat",
        "sanity: the composed blob alone (no user_turn) classifies as a doc-gen terminal"
    );
}

// ---------------------------------------------------------------------------------------------
// (2) compile_window RBAC on the served path: a low-clearance / wrong-dept caller grounds NOTHING
// ---------------------------------------------------------------------------------------------

/// A corpus with ONE chunk that is Confidential AND department-locked to `payments` — so grounding
/// it requires BOTH the class clearance and the right department (the two orthogonal RBAC axes
/// `compile_window` enforces pre-rank).
fn locked_corpus() -> Corpus {
    Corpus::new().with(
        Chunk::new(
            "settle",
            "Settlement Runbook",
            "the settlement batch window closes at 22:00 IST for payments reconciliation",
            DataClass::Confidential,
        )
        .with_acl(NodeAcl::new().departments(&["payments"])),
    )
}

/// A query lexically overlapping the locked chunk so retrieval WOULD score it absent the RBAC gate.
const RBAC_QUERY: &str = "when does the settlement batch window close";

/// The citations a caller grounds for [`RBAC_QUERY`] on a fresh session (drives the served `turn()`).
async fn citations_for(s: &ChatSurface, sess: &str, p: &Principal) -> Vec<ainxt_context::Citation> {
    match s
        .turn(sess, p, RBAC_QUERY, DataClass::Public)
        .await
        .expect("turn")
    {
        ChatReply::Answer { citations, .. } => citations,
        o => panic!("expected Answer, got {o:?}"),
    }
}

#[tokio::test]
async fn r6_compile_window_rbac_grounds_nothing_for_low_clearance_or_wrong_dept() {
    let s = ChatSurface::from_engine(
        engine_with(AnswerProvider),
        locked_corpus(),
        cfg(),
        Box::new(FixedClock(0)),
    );

    // Authorized: Confidential clearance + department "payments" → grounds the chunk (citation).
    let authorized = Principal::user("ops", &["chat.send"])
        .with_clearance(DataClass::Confidential)
        .with_department("payments");
    assert!(
        !citations_for(&s, "ok", &authorized).await.is_empty(),
        "the correctly-cleared, correct-department caller MUST ground the chunk"
    );

    // Low clearance: Public caller cannot read the Confidential chunk → grounds NOTHING (pre-rank
    // class filter — existence never leaks).
    let low = Principal::user("intern", &["chat.send"])
        .with_clearance(DataClass::Public)
        .with_department("payments");
    assert!(
        citations_for(&s, "low", &low).await.is_empty(),
        "a LOW-CLEARANCE caller must ground nothing (compile_window class RBAC)"
    );

    // Wrong department: cleared for the class, but department "cards" ≠ "payments" → grounds NOTHING
    // (pre-rank node/department RBAC).
    let wrong_dept = Principal::user("cardsops", &["chat.send"])
        .with_clearance(DataClass::Confidential)
        .with_department("cards");
    assert!(
        citations_for(&s, "wrong", &wrong_dept).await.is_empty(),
        "a WRONG-DEPARTMENT caller must ground nothing (compile_window node RBAC)"
    );
}

// ---------------------------------------------------------------------------------------------
// (2/c) A numeric claim not attributable to a source is re-derivation-gated (blocked + escalated)
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn r6_numeric_claim_is_rederivation_gated() {
    // Verified surface: the fail-closed answer-path verifier runs the compile/verify numeric gate.
    let verified = ChatSurface::from_engine_verified(
        engine_with(UnbackedNumberProvider),
        Corpus::new(),
        cfg(),
        Box::new(FixedClock(0)),
    );
    let reply = verified
        .turn(
            "v",
            &user(),
            "what was the reconciliation failure rate",
            DataClass::Public,
        )
        .await
        .expect("turn");
    match reply {
        ChatReply::Clarify { question } => assert!(
            question.to_lowercase().contains("verification")
                || question.to_lowercase().contains("can't share")
                || question.to_lowercase().contains("escalated"),
            "a figure with no sourced backing must be BLOCKED + escalated, not shipped: {question}"
        ),
        o => panic!("expected the numeric gate to block + escalate (Clarify), got {o:?}"),
    }

    // Control: the un-verified served default ships the very same figure — so it is the verifier, not
    // some unrelated path, that gated the number above.
    let plain = ChatSurface::from_engine(
        engine_with(UnbackedNumberProvider),
        Corpus::new(),
        cfg(),
        Box::new(FixedClock(0)),
    );
    let reply = plain
        .turn(
            "p",
            &user(),
            "what was the reconciliation failure rate",
            DataClass::Public,
        )
        .await
        .expect("turn");
    match reply {
        ChatReply::Answer { text, .. } => assert!(
            text.contains("12%"),
            "the un-verified surface must ship the figure verbatim: {text}"
        ),
        o => panic!("expected a plain Answer from the un-verified surface, got {o:?}"),
    }
}

// ---------------------------------------------------------------------------------------------
// GAP-FIX conversation-intelligence — with no live grammar/schema-capable provider configured,
// `from_engine_classified_numeric_gated_with_prompt`'s `None` arm now uses
// `ainxt_convo::ModelIntentClassifier::offline()` (Stage-3 "ask third") instead of the bare
// `HeuristicClassifier`, which is documented to NEVER clarify.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn r_offline_default_classifier_now_asks_on_genuine_lexical_ambiguity() {
    use ainxt_convo::PromptDeployment;
    use ainxt_prompt::registry::ModelFamily;
    use ainxt_prompt::service::NullSink;

    // A provider that panics if invoked: a genuinely ambiguous turn must short-circuit to a
    // clarify question BEFORE ever reaching the engine/provider.
    struct PanicIfCalled;
    impl Provider for PanicIfCalled {
        fn id(&self) -> &str {
            "panic-if-called"
        }
        fn eligible(&self, _dc: DataClass) -> bool {
            true
        }
        fn stream(&self, _prompt: &str) -> mpsc::Receiver<Event> {
            panic!("a genuinely ambiguous turn must clarify, never reach the provider");
        }
    }

    let prompt = PromptDeployment::served_default(ModelFamily::new("claude"), Box::new(NullSink));
    let surface = ChatSurface::from_engine_classified_numeric_gated_with_prompt(
        engine_with(PanicIfCalled),
        Corpus::new(),
        cfg(),
        Box::new(FixedClock(0)),
        None::<(ScriptedClassifier, ModelCaps)>,
        false,
        prompt,
    );

    // "compare this code" carries BOTH a comparison cue and a code cue — a real ambiguity the bare
    // HeuristicClassifier resolves silently by priority order and never asks about.
    let req = Request::chat("s1", "t1", "compare this code", DataClass::Public);
    let (summary, text) = serve(&surface, &req, &user()).await;
    assert_eq!(
        summary.provider, "chat",
        "a clarify terminal never reaches the engine provider"
    );
    assert!(
        text.contains("did you mean") || text.contains("clarify"),
        "the offline Stage-3 classifier must ask on genuine ambiguity, got: {text}"
    );
}
