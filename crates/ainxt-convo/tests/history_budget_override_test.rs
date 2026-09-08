// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX surfaces-profiles-skills-config — `ainxt_surface::TurnPlan::history_budget_tokens` was
//! computed on every bound plan but `TurnPlan::to_request` never put it on `ainxt_protocol::Request`,
//! so a surface's declared history/context budget was dead: the served conversation layer always
//! assembled against its own hardcoded default (`ainxt_convo::PromptDeployment`'s 10,000-token
//! default), never the surface's actual policy.
//!
//! FAIL-BEFORE: `Request` had no `history_budget_tokens` field at all, and
//! `ConversationManager::run_turn_streaming`'s prompt-service branch always built the layered
//! `PromptService` from `ps.budget_tokens` (the deployment default) — a `Request` could not influence
//! the assembly budget no matter what a bound `TurnPlan` declared.
//!
//! PASS-AFTER: `Request::history_budget_tokens` carries the surface's declared budget (`to_request`
//! sets it from `TurnPlan::history_budget_tokens`, `ainxt-surface/src/lib.rs`), and
//! `run_turn_streaming` uses it — when present — instead of the deployment's own default.
//!
//! Proven with a `CapturingProvider` (the r14 pattern) that records the EXACT compiled prompt the
//! provider receives: a long grounded-context marker sentence survives fully when the request carries
//! no override (falls back to the deployment's generous 10,000-token default), but is condensed away
//! entirely when the request pins a near-zero history budget — deterministic, offline, no network.

use std::sync::{Arc, Mutex};

use ainxt_context::{Chunk, Corpus, LexicalRetriever};
use ainxt_convo::{ConversationManager, HeuristicClassifier, PromptDeployment};
use ainxt_prompt::registry::ModelFamily;
use ainxt_prompt::service::NullSink;
use ainxt_protocol::{Event, Request};
use ainxt_runtime::engine_with_defaults;
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtime::{CancelToken, Engine};
use ainxt_types::{DataClass, Principal};
use tokio::sync::mpsc;

/// A long, distinctive grounding sentence. Long enough that a near-zero history budget cannot fit any
/// of it once the served persona's L1-L4 preamble is accounted for, but comfortably short of the
/// deployment's default 10,000-token budget.
const MARKER: &str = "SETTLEMENT-MARKER the UPI settlement window closes precisely at twenty two \
hundred hours IST every single day without exception across every member bank in the network nationwide";

/// Records the exact prompt it was sent, and answers with a benign short reply.
struct CapturingProvider {
    seen: Arc<Mutex<String>>,
}
impl Provider for CapturingProvider {
    fn id(&self) -> &str {
        "capturing"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, prompt: &str) -> mpsc::Receiver<Event> {
        *self.seen.lock().unwrap() = prompt.to_string();
        let (tx, rx) = mpsc::channel(8);
        tokio::spawn(async move {
            let _ = tx.send(Event::TextDelta("ack".into())).await;
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

fn engine_with(p: CapturingProvider) -> Engine {
    let mut router = ModelRouter::new();
    router.register(Box::new(p));
    engine_with_defaults(router)
}

fn corpus() -> Corpus {
    Corpus::new().with(Chunk::new(
        "kb-1",
        "ops-handbook",
        MARKER,
        DataClass::Public,
    ))
}

fn user() -> Principal {
    Principal::user("u", &["chat.send"]).with_clearance(DataClass::Public)
}

async fn drive_streaming(m: &ConversationManager<HeuristicClassifier>, req: &Request) {
    let (tx, mut rx) = mpsc::channel::<Event>(64);
    let cancel = CancelToken::new();
    let _ = m.run_turn_streaming(&user(), req, tx, &cancel).await;
    while rx.recv().await.is_some() {}
}

fn manager(seen: Arc<Mutex<String>>) -> ConversationManager<HeuristicClassifier> {
    ConversationManager::with_retriever(
        engine_with(CapturingProvider { seen }),
        HeuristicClassifier,
        Box::new(LexicalRetriever::new(corpus())),
    )
    .with_prompt_service(PromptDeployment::served_default(
        ModelFamily::new("claude"),
        Box::new(NullSink),
    ))
}

#[tokio::test(flavor = "multi_thread")]
async fn no_override_falls_back_to_the_deployment_default_budget() {
    let seen = Arc::new(Mutex::new(String::new()));
    let m = manager(seen.clone());

    // No `history_budget_tokens` set — byte-identical pre-fix behavior: the deployment's own
    // generous default (10,000) governs assembly, so the grounded marker survives uncondensed.
    let req = Request::chat(
        "s1",
        "t1",
        "how does UPI settlement work?",
        DataClass::Public,
    );
    drive_streaming(&m, &req).await;

    let sent = seen.lock().unwrap().clone();
    assert!(
        sent.contains("SETTLEMENT-MARKER"),
        "with no override the default budget must comfortably fit the grounded context: {sent}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_pinned_history_budget_on_the_request_overrides_the_deployment_default() {
    let seen = Arc::new(Mutex::new(String::new()));
    let m = manager(seen.clone());

    // Exactly what `ainxt_surface::TurnPlan::to_request` now produces for a surface whose profile
    // declares a tight history/context budget: the plan's `history_budget_tokens` rides the Request.
    let req = Request::chat(
        "s2",
        "t2",
        "how does UPI settlement work?",
        DataClass::Public,
    )
    .with_history_budget_tokens(1);
    drive_streaming(&m, &req).await;

    let sent = seen.lock().unwrap().clone();
    assert!(
        !sent.contains("SETTLEMENT-MARKER"),
        "a pinned near-zero history budget must actually constrain assembly (the L1-L4 persona alone \
         exceeds it, so L5 condenses to empty) — the override must not be silently discarded: {sent}"
    );
}
