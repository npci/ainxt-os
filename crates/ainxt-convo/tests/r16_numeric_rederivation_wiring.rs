// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R16 fix — the numeric re-derivation gate stub (`AnswerVerifier::with_rederiver` was dead
//! plumbing on the live turn path; see the fix comments in `ainxt-convo/src/lib.rs` next to
//! `tool_ground_truth`/`ChainRederiver`). Before the fix, `ConversationManager`'s live verify call
//! sites always called `verify_answer_live`, which hardcodes an EMPTY re-deriver internally — no
//! injected executor, and no per-turn `ClaimSource`, was ever consulted. That means a genuinely
//! wrong ledger figure the model stated could still SHIP if a retrieved chunk happened to repeat
//! the same wrong number (a stale/poisoned chunk "verifying" a bad figure by text-agreement alone)
//! — exactly the failure mode `STRUCTURED_FEDERATED_RETRIEVAL.md` §5.2 exists to close.
//!
//! These tests construct a REAL `ConversationManager` over a REAL `Engine` with a REAL tool round
//! trip (mirrors `wiring_test.rs`'s `gap_prompt_01_tool_sourced_figure_is_not_flagged_under_tools_only`
//! harness) and prove:
//!
//! 1. A stated figure that matches a stale retrieved chunk but MISMATCHES this turn's own tool
//!    result is now BLOCKED (the tool-sourced re-derivation ground truth wins) — this is the exact
//!    scenario that would previously have shipped, because the old code path never built or
//!    consulted any turn-level re-derivation ground truth.
//! 2. An ordinary RAG turn with no tool call this turn is UNAFFECTED — it still ships on
//!    source-text agreement exactly as before (the fix degrades safely, no regression).
//! 3. A stated figure that AGREES with this turn's own tool result ships (the gate is a genuine
//!    diff-or-block, not a fail-closed-everything trap).

use ainxt_context::{Chunk, Corpus, LexicalRetriever};
use ainxt_convo::{AnswerVerifier, ConversationManager, HeuristicClassifier, ManagerOutcome};
use ainxt_protocol::Event;
use ainxt_runtime::engine_with_defaults;
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_types::{DataClass, Principal};
use tokio::sync::mpsc;

const Q: &str = "what is the total settlements amount?";

fn stale_settlement_corpus() -> Corpus {
    // A retrieved chunk that repeats the STALE/WRONG figure (999000) — the "poisoned chunk agrees
    // with the model's bad number" scenario the tool-sourced re-derivation gate must catch.
    Corpus::new().with(Chunk::new(
        "stale",
        "stale.md",
        "The total settlements amount is 999000 rupees.",
        DataClass::Public,
    ))
}

fn tool_principal() -> Principal {
    Principal::user("analyst", &["chat.send", "tool.lookup"]).with_clearance(DataClass::Public)
}

/// Returns a fixed answer regardless of the prompt (no tool call, ordinary RAG turn).
struct FixedProvider(&'static str);
impl Provider for FixedProvider {
    fn id(&self) -> &str {
        "fixed"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, _prompt: &str) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(8);
        let ans = self.0.to_string();
        tokio::spawn(async move {
            let _ = tx.send(Event::TextDelta(ans)).await;
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

/// Calls the `lookup` tool once (which independently returns the TRUE settlement figure,
/// 1245600), then answers with `final_answer` — either the stale/wrong figure or the true one,
/// depending on the test.
struct ToolThenAnswerProvider {
    final_answer: &'static str,
}
impl Provider for ToolThenAnswerProvider {
    fn id(&self) -> &str {
        "agent"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, prompt: &str) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(8);
        let have_result = prompt.contains("[tool lookup result");
        let final_answer = self.final_answer.to_string();
        tokio::spawn(async move {
            if have_result {
                let _ = tx.send(Event::TextDelta(final_answer)).await;
            } else {
                let _ = tx
                    .send(Event::ToolCallStart {
                        id: "t1".into(),
                        name: "lookup".into(),
                        args: String::new(),
                    })
                    .await;
            }
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

struct SettlementLookupTool;
impl ainxt_tools::Tool for SettlementLookupTool {
    fn name(&self) -> &str {
        "lookup"
    }
    fn effect_class(&self) -> ainxt_tools::EffectClass {
        ainxt_tools::EffectClass::Idempotent
    }
    fn execute(&self, _args: &str) -> Result<String, ainxt_tools::ToolError> {
        // The TRUE, server-computed settlement figure this turn — independent of anything the
        // model states or any retrieved text.
        Ok("1245600".to_string())
    }
}

fn engine_with_lookup_tool(final_answer: &'static str) -> ainxt_runtime::Engine {
    let mut router = ModelRouter::new();
    router.register(Box::new(ToolThenAnswerProvider { final_answer }));
    let mut tools = ainxt_tools::ToolRuntime::new(
        Box::new(ainxt_tools::InMemoryLedger::new()),
        Box::new(ainxt_tools::ManualReconciler),
    );
    tools.register(Box::new(SettlementLookupTool));
    engine_with_defaults(router).with_tools(tools)
}

/// (1) The stated figure (999000) matches the stale retrieved chunk but MISMATCHES this turn's
/// OWN tool result (1245600) — must be BLOCKED. Before the R16 fix, `verify_answer_live` never
/// built or consulted any tool-sourced ground truth, so this figure would have shipped on
/// source-text agreement with the stale chunk alone.
#[tokio::test]
async fn tool_rederivation_catches_stale_source_agreement() {
    let engine = engine_with_lookup_tool("The total settlements amount is 999000 rupees.");
    let m = ConversationManager::with_retriever(
        engine,
        HeuristicClassifier,
        Box::new(LexicalRetriever::new(stale_settlement_corpus())),
    )
    .with_verifier(AnswerVerifier::numeric_gate_only());

    match m
        .handle("s", &tool_principal(), Q, DataClass::Public)
        .await
        .unwrap()
    {
        ManagerOutcome::Clarify { question } => {
            assert!(
                question.contains("verification"),
                "escalation message: {question}"
            );
        }
        other => panic!(
            "a figure that matches a STALE retrieved chunk but mismatches this turn's OWN tool \
             result must be blocked by the tool-sourced re-derivation gate; got {other:?}"
        ),
    }
}

/// (2) No tool call this turn (ordinary RAG turn) — the fix must degrade safely to the prior
/// source-text-agreement behavior, so an unrelated/ordinary turn is unaffected.
#[tokio::test]
async fn no_tool_call_this_turn_falls_back_to_source_text_and_ships() {
    let m = ConversationManager::with_retriever(
        engine_with_plain("The total settlements amount is 999000 rupees."),
        HeuristicClassifier,
        Box::new(LexicalRetriever::new(stale_settlement_corpus())),
    )
    .with_verifier(AnswerVerifier::numeric_gate_only());

    assert!(
        matches!(
            m.handle("s", &tool_principal(), Q, DataClass::Public)
                .await
                .unwrap(),
            ManagerOutcome::Answer { .. }
        ),
        "an ordinary RAG turn with no tool call this turn must be unaffected by the tool-sourced \
         re-derivation ground truth: source-text agreement alone still ships"
    );
}

/// (3) The stated figure AGREES with this turn's own tool result — must ship. Proves the gate is
/// a genuine diff-or-block, not a fail-closed-everything trap once a tool call happens.
#[tokio::test]
async fn tool_rederivation_ships_when_answer_agrees_with_tool_result() {
    let engine = engine_with_lookup_tool("The total settlements amount is 1245600 rupees.");
    let m = ConversationManager::with_retriever(
        engine,
        HeuristicClassifier,
        Box::new(LexicalRetriever::new(stale_settlement_corpus())),
    )
    .with_verifier(AnswerVerifier::numeric_gate_only());

    assert!(
        matches!(
            m.handle("s", &tool_principal(), Q, DataClass::Public)
                .await
                .unwrap(),
            ManagerOutcome::Answer { .. }
        ),
        "a figure that agrees with this turn's own tool result must ship"
    );
}

fn engine_with_plain(answer: &'static str) -> ainxt_runtime::Engine {
    let mut router = ModelRouter::new();
    router.register(Box::new(FixedProvider(answer)));
    engine_with_defaults(router)
}
