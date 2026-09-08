// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R14 (surfaces-profiles-skills, HIGH) — the profile **persona + skill injection + `## Surface
//! Policy` directives** an upstream `ProfiledSurface` composes into `Request::input` reach the
//! provider's SYSTEM PROMPT on the served path, instead of being DROPPED when the layered Prompt
//! Service compiles its own registry persona over the de-contaminated grounding body.
//!
//! FAIL-BEFORE: `run_turn_streaming`'s prompt-service branch compiled over `body` (built from the
//! de-contaminated user turn only), so the composed profile prefix never reached the model — the
//! provider saw the registry persona but NOT "PERSONA-ACME" / the surface policy.
//! PASS-AFTER: the profile prefix is folded into the compiled-prompt input (before `compile_turn`, so
//! the durable forensic record stays faithful), and the provider receives it. Offline + deterministic.

use std::sync::{Arc, Mutex};

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

/// Records the exact prompt it was sent, and answers with a benign short reply (so the output leak
/// rail never redacts it — we assert on what the provider RECEIVED, not on the streamed answer).
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

async fn drive_streaming(m: &ConversationManager<HeuristicClassifier>, req: &Request) {
    let user = Principal::user("u", &["chat.send"])
        .with_department("payments")
        .with_clearance(DataClass::Public);
    let (tx, mut rx) = mpsc::channel::<Event>(64);
    let cancel = CancelToken::new();
    let _ = m.run_turn_streaming(&user, req, tx, &cancel).await;
    while rx.recv().await.is_some() {}
}

#[tokio::test(flavor = "multi_thread")]
async fn r14_profile_directives_reach_the_served_system_prompt() {
    let seen = Arc::new(Mutex::new(String::new()));
    let m = ConversationManager::new(
        engine_with(CapturingProvider { seen: seen.clone() }),
        HeuristicClassifier,
    )
    .with_prompt_service(PromptDeployment::served_default(
        ModelFamily::new("claude"),
        Box::new(NullSink),
    ));

    // Exactly what `ainxt_surface::TurnPlan::to_request` produces: persona + `## Surface Policy`
    // composed into `input`, with the raw user turn carried separately.
    let user_turn = "how did UPI grow?";
    let composed = format!(
        "PERSONA-ACME: you are the ACME payments analyst.\n\n## Surface Policy\n- read-only\n\n{user_turn}"
    );
    let req = Request::chat("s", "t", &composed, DataClass::Public).with_user_turn(user_turn);
    drive_streaming(&m, &req).await;

    let sent = seen.lock().unwrap().clone();
    assert!(
        sent.contains("PERSONA-ACME"),
        "the profile persona must reach the provider's system prompt (not be dropped): {sent}"
    );
    assert!(
        sent.contains("Surface Policy") && sent.contains("read-only"),
        "the surface-policy directives must reach the system prompt: {sent}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn r14_unwrapped_chat_path_is_unchanged() {
    // No composed prefix (input == user turn): the plain chat path must be byte-identical — no
    // phantom directive block injected.
    let seen = Arc::new(Mutex::new(String::new()));
    let m = ConversationManager::new(
        engine_with(CapturingProvider { seen: seen.clone() }),
        HeuristicClassifier,
    )
    .with_prompt_service(PromptDeployment::served_default(
        ModelFamily::new("claude"),
        Box::new(NullSink),
    ));

    let req = Request::chat("s", "t", "how did UPI grow?", DataClass::Public);
    drive_streaming(&m, &req).await;

    let sent = seen.lock().unwrap().clone();
    assert!(
        !sent.contains("Surface Policy") && !sent.contains("PERSONA-ACME"),
        "the unwrapped chat path must inject no profile directive block: {sent}"
    );
}
