// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Output-side groundedness rail (ADR-008) wired into the ConversationManager.
//!
//! DEFAULT OFF. When turned on it checks the model's ANSWER against the retrieved context (the
//! faithfulness check the Context Fabric defers). Audit flags; Enforce also caveats — but never
//! hard-blocks (redact-don't-block), and the PERSISTED answer stays clean for referent resolution.

use ainxt_context::{Chunk, Corpus, LexicalRetriever};
use ainxt_convo::{
    ConversationManager, GroundingStatus, HeuristicClassifier, ManagerOutcome, Role,
};
use ainxt_guardrails::{GuardrailsConfig, RailMode};
use ainxt_protocol::Event;
use ainxt_runtime::engine_with_defaults;
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_types::{DataClass, Principal};
use tokio::sync::mpsc;

/// Ignores the prompt and returns a fixed answer — lets us drive grounded vs hallucinated.
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

// A well-supported answer (every content token appears in the corpus chunk).
const GROUNDED_ANSWER: &str = "UPI transaction volume grew strongly year over year";
// A hallucination — no content token overlaps the corpus.
const HALLUCINATION: &str = "the moon landing was filmed on a distant asteroid";

fn corpus() -> Corpus {
    Corpus::new().with(Chunk::new(
        "pub-upi",
        "upi-report.md",
        "UPI transaction volume grew strongly year over year",
        DataClass::Public,
    ))
}

fn grounded_manager(
    answer: &'static str,
    cfg: Option<GuardrailsConfig>,
) -> ConversationManager<HeuristicClassifier> {
    let mut router = ModelRouter::new();
    router.register(Box::new(FixedProvider(answer)));
    let mut m = ConversationManager::with_retriever(
        engine_with_defaults(router),
        HeuristicClassifier,
        Box::new(LexicalRetriever::new(corpus())),
    );
    if let Some(cfg) = cfg {
        m = m.with_guardrails(cfg);
    }
    m
}

fn audit() -> GuardrailsConfig {
    GuardrailsConfig {
        groundedness: RailMode::Audit,
        ..Default::default()
    }
}
fn enforce() -> GuardrailsConfig {
    GuardrailsConfig {
        groundedness: RailMode::Enforce,
        ..Default::default()
    }
}

fn user() -> Principal {
    Principal::user("analyst", &["chat.send"]).with_clearance(DataClass::Public)
}

const Q: &str = "how did UPI transaction volume grow?";

#[tokio::test]
async fn off_by_default_grounding_is_not_checked() {
    // No guardrails configured → even a hallucination is NotChecked (the gateway owns this).
    let m = grounded_manager(HALLUCINATION, None);
    match m.handle("s", &user(), Q, DataClass::Public).await.unwrap() {
        ManagerOutcome::Answer {
            text, grounding, ..
        } => {
            assert_eq!(grounding, GroundingStatus::NotChecked);
            assert_eq!(
                text, HALLUCINATION,
                "text must be untouched when the rail is off"
            );
        }
        other => panic!("expected Answer, got {other:?}"),
    }
}

#[tokio::test]
async fn audit_flags_ungrounded_but_does_not_caveat() {
    let m = grounded_manager(HALLUCINATION, Some(audit()));
    match m.handle("s", &user(), Q, DataClass::Public).await.unwrap() {
        ManagerOutcome::Answer {
            text, grounding, ..
        } => {
            assert!(
                matches!(grounding, GroundingStatus::Unsupported(_)),
                "audit must flag: {grounding:?}"
            );
            assert_eq!(
                text, HALLUCINATION,
                "audit mode must NOT modify the answer text"
            );
            assert!(!text.contains('⚠'));
        }
        other => panic!("expected Answer, got {other:?}"),
    }
    // Audit persists the clean answer too (mirrors the Enforce persistence test).
    let last = m
        .history("s")
        .into_iter()
        .rev()
        .find(|msg| msg.role == Role::Assistant)
        .unwrap();
    assert_eq!(last.text, HALLUCINATION);
}

#[tokio::test]
async fn audit_leaves_a_grounded_answer_clean_and_grounded() {
    // The grounded-pass path was previously only exercised under Enforce.
    let m = grounded_manager(GROUNDED_ANSWER, Some(audit()));
    match m.handle("s", &user(), Q, DataClass::Public).await.unwrap() {
        ManagerOutcome::Answer {
            text, grounding, ..
        } => {
            assert_eq!(
                grounding,
                GroundingStatus::Grounded,
                "audit must not flag a grounded answer"
            );
            assert_eq!(
                text, GROUNDED_ANSWER,
                "audit never modifies a grounded answer"
            );
        }
        other => panic!("expected Answer, got {other:?}"),
    }
}

#[tokio::test]
async fn enforce_caveats_an_ungrounded_answer_but_keeps_the_content() {
    let m = grounded_manager(HALLUCINATION, Some(enforce()));
    match m.handle("s", &user(), Q, DataClass::Public).await.unwrap() {
        ManagerOutcome::Answer {
            text,
            grounding,
            citations,
            ..
        } => {
            assert!(matches!(grounding, GroundingStatus::Unsupported(_)));
            assert!(
                text.contains('⚠'),
                "enforce must prepend a visible caveat: {text}"
            );
            assert!(text.contains("not be fully supported"));
            assert!(
                text.contains(HALLUCINATION),
                "enforce caveats but never drops the content"
            );
            // Caveating must NOT wipe the citation lineage.
            assert!(!citations.is_empty(), "citations must survive caveating");
        }
        other => panic!("expected Answer, got {other:?}"),
    }
}

#[tokio::test]
async fn a_grounded_answer_passes_even_in_enforce() {
    let m = grounded_manager(GROUNDED_ANSWER, Some(enforce()));
    match m.handle("s", &user(), Q, DataClass::Public).await.unwrap() {
        ManagerOutcome::Answer {
            text,
            grounding,
            provider,
            citations,
        } => {
            assert_eq!(grounding, GroundingStatus::Grounded);
            assert_eq!(text, GROUNDED_ANSWER, "a grounded answer is never caveated");
            // The grounding wiring must not have dropped provider or citation lineage.
            assert_eq!(provider, "fixed");
            assert_eq!(citations.len(), 1);
            assert_eq!(citations[0].source, "upi-report.md");
            assert_eq!(citations[0].marker, "[1]");
        }
        other => panic!("expected Answer, got {other:?}"),
    }
}

#[tokio::test]
async fn no_retrieval_context_means_not_checked() {
    // Guardrails ON but manager has NO retriever → nothing to ground against → NotChecked.
    let mut router = ModelRouter::new();
    router.register(Box::new(FixedProvider(HALLUCINATION)));
    let m = ConversationManager::new(engine_with_defaults(router), HeuristicClassifier)
        .with_guardrails(enforce());
    match m.handle("s", &user(), Q, DataClass::Public).await.unwrap() {
        ManagerOutcome::Answer {
            text, grounding, ..
        } => {
            assert_eq!(grounding, GroundingStatus::NotChecked);
            assert_eq!(text, HALLUCINATION);
        }
        other => panic!("expected Answer, got {other:?}"),
    }
}

#[tokio::test]
async fn enforce_persists_the_clean_answer_not_the_caveated_one() {
    // The caveat is a live presentation decision; the referent/history must stay clean so a
    // later "make this a pdf" resolves the real answer, not the "⚠ ..." wrapper.
    let m = grounded_manager(HALLUCINATION, Some(enforce()));
    let _ = m.handle("s", &user(), Q, DataClass::Public).await.unwrap();
    let history = m.history("s");
    let last = history
        .iter()
        .rev()
        .find(|msg| msg.role == Role::Assistant)
        .unwrap();
    assert_eq!(
        last.text, HALLUCINATION,
        "persisted answer must be the clean original"
    );
    assert!(!last.text.contains('⚠'));
}

// ---------------------------------------------------------------------------
// Boundary + invariant hardening (from adversarial review of this change).
// ---------------------------------------------------------------------------

// Just UNDER the 0.3 overlap threshold: 2 of 7 content tokens are in the corpus → Unsupported.
const NEAR_MISS: &str = "volume grew amid weaker sluggish offshore dividends"; // 2/7 = 0.286
                                                                               // Just OVER the threshold: 3 of 8 content tokens are in the corpus → Grounded.
const NEAR_HIT: &str = "volume grew strongly amid weaker sluggish offshore dividends"; // 3/8 = 0.375

#[tokio::test]
async fn grounding_pins_the_overlap_boundary_through_the_manager() {
    // Just under → Unsupported (and, in Enforce, caveated).
    let under = grounded_manager(NEAR_MISS, Some(enforce()));
    match under
        .handle("s", &user(), Q, DataClass::Public)
        .await
        .unwrap()
    {
        ManagerOutcome::Answer {
            grounding, text, ..
        } => {
            assert!(
                matches!(grounding, GroundingStatus::Unsupported(_)),
                "2/7 must be below 0.3"
            );
            assert!(text.contains('⚠'));
        }
        other => panic!("expected Answer, got {other:?}"),
    }
    // Just over → Grounded (no caveat).
    let over = grounded_manager(NEAR_HIT, Some(enforce()));
    match over
        .handle("s", &user(), Q, DataClass::Public)
        .await
        .unwrap()
    {
        ManagerOutcome::Answer {
            grounding, text, ..
        } => {
            assert_eq!(
                grounding,
                GroundingStatus::Grounded,
                "3/8 must be at/above 0.3"
            );
            assert_eq!(text, NEAR_HIT);
        }
        other => panic!("expected Answer, got {other:?}"),
    }
}

#[tokio::test]
async fn an_answer_backed_only_by_an_above_clearance_chunk_is_not_grounded() {
    // The clearance filter (pre-rank) must feed grounding: a Public-cleared user's answer that
    // matches ONLY a Confidential chunk cannot be scored Grounded — the chunk never enters the
    // context the rail checks against. Guards against grounding drifting to the raw corpus.
    const CONF: &str = "settlement margin figures revised sharply downward internally";
    let corpus = Corpus::new()
        .with(Chunk::new(
            "pub-upi",
            "upi-report.md",
            "UPI transaction volume grew strongly year over year",
            DataClass::Public,
        ))
        .with(Chunk::new(
            "conf-margin",
            "margins.md",
            CONF,
            DataClass::Confidential,
        ));
    let mut router = ModelRouter::new();
    router.register(Box::new(FixedProvider(CONF))); // answer overlaps ONLY the confidential chunk
    let m = ConversationManager::with_retriever(
        engine_with_defaults(router),
        HeuristicClassifier,
        Box::new(LexicalRetriever::new(corpus)),
    )
    .with_guardrails(enforce());

    // Public-cleared user: the confidential chunk is filtered before ranking.
    match m.handle("s", &user(), Q, DataClass::Public).await.unwrap() {
        ManagerOutcome::Answer { grounding, .. } => {
            assert!(
                matches!(grounding, GroundingStatus::Unsupported(_)),
                "an answer supported only by an above-clearance chunk must not be Grounded: {grounding:?}"
            );
        }
        other => panic!("expected Answer, got {other:?}"),
    }
}

#[tokio::test]
async fn a_live_config_with_groundedness_off_is_a_noop() {
    // Distinct code path from `None`: a Some(cfg) whose groundedness is Off (here jailbreak is
    // Audit) must still leave the answer NotChecked and untouched, even with real context.
    let cfg = GuardrailsConfig {
        jailbreak: RailMode::Audit,
        groundedness: RailMode::Off,
        ..Default::default()
    };
    let m = grounded_manager(HALLUCINATION, Some(cfg));
    match m.handle("s", &user(), Q, DataClass::Public).await.unwrap() {
        ManagerOutcome::Answer {
            text, grounding, ..
        } => {
            assert_eq!(grounding, GroundingStatus::NotChecked);
            assert_eq!(
                text, HALLUCINATION,
                "groundedness=off must not touch the answer"
            );
        }
        other => panic!("expected Answer, got {other:?}"),
    }
}

#[tokio::test]
async fn grounding_uses_the_union_of_all_retrieved_chunks() {
    // An answer supported by the UNION of two chunks (but by neither alone) must be Grounded.
    // Guards against a regression that grounds against only the top/first chunk.
    let corpus = Corpus::new()
        .with(Chunk::new(
            "a",
            "a.md",
            "settlement window adjusted",
            DataClass::Public,
        ))
        .with(Chunk::new(
            "b",
            "b.md",
            "latency reduced significantly",
            DataClass::Public,
        ));
    let mut router = ModelRouter::new();
    // 5 content tokens; 1 in chunk A (settlement), 1 in chunk B (latency) → union 2/5 = 0.4.
    // Each chunk alone would be 1/5 = 0.2 < 0.3 → would wrongly flag if only one chunk were used.
    router.register(Box::new(FixedProvider(
        "settlement latency improved across regions",
    )));
    let m = ConversationManager::with_retriever(
        engine_with_defaults(router),
        HeuristicClassifier,
        Box::new(LexicalRetriever::new(corpus)),
    )
    .with_guardrails(enforce());

    match m
        .handle("s", &user(), "settlement latency", DataClass::Public)
        .await
        .unwrap()
    {
        ManagerOutcome::Answer { grounding, .. } => {
            assert_eq!(
                grounding,
                GroundingStatus::Grounded,
                "the union of chunks must ground the answer"
            );
        }
        other => panic!("expected Answer, got {other:?}"),
    }
}

#[tokio::test]
async fn a_trivial_answer_is_not_checked_rather_than_falsely_grounded() {
    // Empty / short-only answers have nothing evaluable; they must be NotChecked, never labelled
    // Grounded (which would assert support that was never verified). Payment answers like "42",
    // "yes", "UPI" are exactly this case.
    for trivial in ["", "   ", "42 yes UPI"] {
        let m = grounded_manager(trivial, Some(enforce()));
        match m.handle("s", &user(), Q, DataClass::Public).await.unwrap() {
            ManagerOutcome::Answer { grounding, .. } => {
                assert_eq!(
                    grounding,
                    GroundingStatus::NotChecked,
                    "trivial answer {trivial:?} must be NotChecked"
                );
            }
            other => panic!("expected Answer, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn doc_generation_is_inert_to_guardrails_and_stays_clean() {
    // Turn 1: an ungrounded QA answer under Enforce (displayed caveated, persisted clean).
    // Turn 2: "generate this as pdf" must yield a Document whose content is the CLEAN prior
    // answer — never grounded, never caveated. Protects the instruction != content fix.
    let m = grounded_manager(HALLUCINATION, Some(enforce()));
    let a1 = m.handle("s", &user(), Q, DataClass::Public).await.unwrap();
    assert!(matches!(a1, ManagerOutcome::Answer { .. }));

    match m
        .handle("s", &user(), "generate this as pdf", DataClass::Public)
        .await
        .unwrap()
    {
        ManagerOutcome::Document { content, .. } => {
            assert_eq!(
                content, HALLUCINATION,
                "the PDF content is the clean prior answer"
            );
            assert!(
                !content.contains('⚠'),
                "the doc path must never carry the caveat"
            );
            assert!(!content.contains("not be fully supported"));
        }
        other => panic!("expected a Document, got {other:?}"),
    }
}
