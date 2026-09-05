// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! The **live scoring backend** behind the [`crate::QualityJudge`] seam (EVAL_PLATFORM.md §4.1 —
//! round-15 gap: "Calibrated LLM-judge — live scoring backend").
//!
//! Before this module, the Judge's "production backend" was a promise in a docstring
//! ([`crate::semantic`]: "the production Judge is a pinned, calibrated LLM reached over the Provider
//! Gateway — a live model call"). Nothing in the crate actually reached the Provider Gateway; only the
//! offline [`crate::semantic::SemanticOverlapJudge`] stand-in existed. [`LiveProviderJudge`] is that
//! backend, for real: it drives ANY [`ainxt_runtime::provider::Provider`] adapter (the Anthropic /
//! OpenAI-schema / Gemini adapters in `ainxt-providers`, or a fake in a test) through the SAME
//! event-enum seam (ADR-006) the rest of the runtime uses, so the pinned Judge model is reached with no
//! bespoke HTTP client living in this crate.
//!
//! What is proven **offline, with no network and no API key** — and is exercised by this module's
//! tests — is the entire plumbing around the live call:
//!
//! 1. [`build_judge_prompt`] — the exact rubric-scoring prompt text (unit-testable, no network);
//! 2. draining a [`Provider::stream`] event receiver into its concatenated text reply, failing closed
//!    (never fabricating a score) on an [`ainxt_protocol::Event::Error`];
//! 3. [`parse_judge_reply`] — tolerant `SCORE:`/`RATIONALE:` extraction from the model's raw text,
//!    returning `None` (not a fake `0`) on a genuinely unparseable reply so the caller can decide how
//!    to fail closed;
//! 4. [`LiveProviderJudge`] wiring all three into the [`QualityJudge`] seam, exercised end-to-end
//!    against a scripted [`Provider`] test double — the exact discipline `ainxt-providers` itself uses
//!    (`SseNormalizer` unit tests against recorded fixture bytes, no network).
//!
//! **What remains infra-gated** is the one thing that categorically needs live infrastructure: an
//! actual TCP connection to `api.anthropic.com` (or an OpenAI-schema / Gemini endpoint) with a real,
//! provisioned API key. Constructing a real `AnthropicProvider`/`OpenAiSchemaProvider`/`GeminiProvider`
//! and handing it to [`LiveProviderJudge::new`] is a **one-line composition** at the call site (the CI
//! gate binary / dogfood runner in the reserved daemon crates) — nothing here changes. This mirrors
//! `ainxt-providers`'s own `#[ignore]`d live smoke tests (env-var gated, skipped by default).
//!
//! `score()` builds a **fresh, dedicated current-thread Tokio runtime per call** and blocks on it —
//! correct and simple for this seam's real caller (a plain, non-async CI-gate process; see
//! `crate::ci::run_release_gate_ci`), and it deliberately avoids ever nesting a runtime inside another
//! runtime's worker thread (which panics). A caller that is itself already running inside an async
//! server MUST invoke `score()` from a blocking context (e.g. `tokio::task::spawn_blocking`) — exactly
//! as any synchronous FFI-style call into a blocking bridge must be.

use crate::{EvalCriteria, QualityJudge, QualityScore};
use ainxt_protocol::Event;
use ainxt_runtime::provider::Provider;
use std::sync::Arc;

const SCORE_TAG: &str = "SCORE:";
const RATIONALE_TAG: &str = "RATIONALE:";

/// Build the exact rubric-scoring prompt sent to the pinned Judge model. A free function (not a
/// private detail of [`LiveProviderJudge`]) so the wire text is unit-testable with no network call.
pub fn build_judge_prompt(input: &str, output: &str, criteria: &EvalCriteria) -> String {
    format!(
        "You are a calibrated evaluation judge. Score the ANSWER against the RUBRIC on a 0-100 \
         scale (0 = fails the rubric entirely, 100 = fully satisfies it). Respond with EXACTLY one \
         line in the form: {SCORE_TAG} <integer 0-100> {RATIONALE_TAG} <one sentence>\n\n\
         RUBRIC: {}\n\nQUESTION: {}\n\nANSWER: {}\n",
        criteria.rubric, input, output
    )
}

/// Parse a Judge model's raw text reply into a [`QualityScore`]. Tolerant of surrounding prose (scans
/// for the first `SCORE:` token rather than requiring an exact-format reply) so a chatty model that
/// prefaces its verdict still parses. Returns `None` — never a fabricated score — when no `SCORE:`
/// token with a parseable 0-100 integer is present, so a genuinely unparseable reply is visible to the
/// caller as a governance failure rather than silently becoming a `0`.
pub fn parse_judge_reply(reply: &str) -> Option<QualityScore> {
    let idx = reply.find(SCORE_TAG)?;
    let rest = &reply[idx + SCORE_TAG.len()..];
    let digits: String = rest
        .trim_start()
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    if digits.is_empty() {
        return None;
    }
    let score: u32 = digits.parse().ok()?;
    let score = score.min(100) as u8;
    let rationale = reply
        .find(RATIONALE_TAG)
        .map(|i| reply[i + RATIONALE_TAG.len()..].trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| reply.trim().to_string());
    Some(QualityScore { score, rationale })
}

/// Drain a [`Provider::stream`] receiver into its concatenated text reply. Judge scoring is a pure
/// text turn, so tool-call/approval/usage events are ignored; an [`Event::Error`] short-circuits with
/// `Err` (fail-closed — a transport failure must never be silently treated as an empty, passing reply).
async fn drain_reply(mut rx: tokio::sync::mpsc::Receiver<Event>) -> Result<String, String> {
    let mut out = String::new();
    while let Some(ev) = rx.recv().await {
        match ev {
            Event::TextDelta(s) => out.push_str(&s),
            Event::Error(e) => return Err(e),
            Event::Done => break,
            // GAP-AUDIT turn-pipeline #6 — reasoning content is not the judge's scored answer
            // (mirrors the tool/usage arms below): ignored here, never concatenated into `out`.
            Event::ReasoningDelta(_)
            | Event::ToolCallStart { .. }
            | Event::ToolResult { .. }
            // GAP2 harness-sdk — an artifact reference is not scored text either; ignored for the
            // same reason as `ToolResult` above.
            | Event::Artifact { .. }
            | Event::Usage { .. } => {}
            Event::ApprovalRequest { .. } => {
                return Err("judge model requested tool approval — refusing to score".into());
            }
        }
    }
    Ok(out)
}

/// **The live scoring backend**: a pinned model reached over a real [`Provider`] adapter (Anthropic /
/// OpenAI-schema / Gemini in `ainxt-providers`, or a scripted double in tests), behind the exact same
/// [`QualityJudge`] seam [`crate::semantic::SemanticOverlapJudge`] fulfils offline. Wrap this in
/// [`crate::judge::CalibratedJudge::admit`] to get the full governed instrument (self-preference /
/// in-house-only refusals, pinned version stamping) over a real model.
pub struct LiveProviderJudge {
    provider: Arc<dyn Provider>,
}

impl LiveProviderJudge {
    /// `provider` is any [`Provider`] adapter — production callers hand in a real
    /// `AnthropicProvider`/`OpenAiSchemaProvider`/`GeminiProvider` (infra-gated: needs a live endpoint
    /// + API key); tests hand in a scripted double.
    pub fn new(provider: Arc<dyn Provider>) -> Self {
        LiveProviderJudge { provider }
    }

    /// Send `prompt` to the provider and drain its reply, bridging the sync [`QualityJudge`] seam into
    /// the provider's async `stream()`. Builds a fresh, dedicated current-thread runtime and drives
    /// `provider.stream()` *inside* that runtime's `block_on` (never before it) — `Provider::stream`
    /// implementations `tokio::spawn` their driving task, which panics outside an active runtime.
    fn score_blocking(&self, prompt: &str) -> Result<String, String> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("failed to start judge runtime: {e}"))?;
        let provider = Arc::clone(&self.provider);
        let prompt = prompt.to_string();
        rt.block_on(async move {
            let rx = provider.stream(&prompt);
            drain_reply(rx).await
        })
    }
}

impl QualityJudge for LiveProviderJudge {
    fn score(&self, input: &str, output: &str, criteria: &EvalCriteria) -> QualityScore {
        let prompt = build_judge_prompt(input, output, criteria);
        match self.score_blocking(&prompt) {
            Ok(reply) => parse_judge_reply(&reply).unwrap_or_else(|| QualityScore {
                score: 0,
                rationale: format!(
                    "live judge reply unparseable — failing closed, not fabricating a score: {reply:?}"
                ),
            }),
            Err(e) => QualityScore {
                score: 0,
                rationale: format!("live judge call failed — failing closed: {e}"),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ainxt_types::DataClass;
    use tokio::sync::mpsc;

    /// A scripted [`Provider`] double: streams fixed `TextDelta` chunks then `Done`. No network — the
    /// same discipline `ainxt-providers`'s own fixture-driven `SseNormalizer` tests use.
    struct ScriptedProvider {
        chunks: Vec<String>,
    }
    impl Provider for ScriptedProvider {
        fn id(&self) -> &str {
            "scripted-judge"
        }
        fn eligible(&self, _data_class: DataClass) -> bool {
            true
        }
        fn stream(&self, _prompt: &str) -> mpsc::Receiver<Event> {
            let (tx, rx) = mpsc::channel(16);
            let chunks = self.chunks.clone();
            tokio::spawn(async move {
                for c in chunks {
                    if tx.send(Event::TextDelta(c)).await.is_err() {
                        return;
                    }
                }
                let _ = tx.send(Event::Done).await;
            });
            rx
        }
    }

    /// A [`Provider`] double that only ever errors — proves the fail-closed path.
    struct ErroringProvider;
    impl Provider for ErroringProvider {
        fn id(&self) -> &str {
            "erroring-judge"
        }
        fn eligible(&self, _data_class: DataClass) -> bool {
            true
        }
        fn stream(&self, _prompt: &str) -> mpsc::Receiver<Event> {
            let (tx, rx) = mpsc::channel(4);
            tokio::spawn(async move {
                let _ = tx.send(Event::Error("upstream 503".into())).await;
            });
            rx
        }
    }

    fn criteria() -> EvalCriteria {
        EvalCriteria {
            rubric: "must mention the T+1 settlement cycle".into(),
            threshold: 60,
        }
    }

    #[test]
    fn r15_build_judge_prompt_embeds_rubric_question_and_answer() {
        let c = criteria();
        let p = build_judge_prompt("when does settlement run", "it runs on a T+1 cycle", &c);
        assert!(p.contains(&c.rubric));
        assert!(p.contains("when does settlement run"));
        assert!(p.contains("it runs on a T+1 cycle"));
        assert!(p.contains("SCORE:"), "instructs the exact reply format");
    }

    #[test]
    fn r15_parse_judge_reply_extracts_score_and_rationale() {
        let r = parse_judge_reply("SCORE: 87 RATIONALE: fully grounded and concise").unwrap();
        assert_eq!(r.score, 87);
        assert_eq!(r.rationale, "fully grounded and concise");
    }

    #[test]
    fn r15_parse_judge_reply_tolerates_a_prose_prefix() {
        let r = parse_judge_reply("Sure, here is my verdict.\nSCORE: 42\nRATIONALE: partial match")
            .unwrap();
        assert_eq!(r.score, 42);
        assert_eq!(r.rationale, "partial match");
    }

    #[test]
    fn r15_parse_judge_reply_clamps_an_out_of_range_score() {
        let r = parse_judge_reply("SCORE: 137 RATIONALE: overconfident model").unwrap();
        assert_eq!(r.score, 100, "a >100 reply is clamped, never overflowed");
    }

    #[test]
    fn r15_parse_judge_reply_is_none_on_unparseable_text() {
        assert!(
            parse_judge_reply("I refuse to answer this question").is_none(),
            "no fabricated score for an unparseable reply"
        );
    }

    #[test]
    fn r15_live_provider_judge_scores_via_the_real_provider_seam_offline() {
        let provider = Arc::new(ScriptedProvider {
            chunks: vec!["SCORE: 91 ".into(), "RATIONALE: matches the rubric".into()],
        });
        let judge = LiveProviderJudge::new(provider);
        let verdict = judge.score("q", "a", &criteria());
        assert_eq!(verdict.score, 91);
        assert!(verdict.rationale.contains("matches the rubric"));
    }

    #[test]
    fn r15_live_provider_judge_fails_closed_on_provider_error() {
        let judge = LiveProviderJudge::new(Arc::new(ErroringProvider));
        let v = judge.score("q", "a", &criteria());
        assert_eq!(
            v.score, 0,
            "a transport failure fails closed, never a fabricated pass"
        );
        assert!(v.rationale.contains("upstream 503"));
    }

    #[test]
    fn r15_live_provider_judge_fails_closed_on_unparseable_reply() {
        let provider = Arc::new(ScriptedProvider {
            chunks: vec!["I decline to provide a numeric score.".into()],
        });
        let judge = LiveProviderJudge::new(provider);
        let v = judge.score("q", "a", &criteria());
        assert_eq!(v.score, 0, "unparseable reply fails closed");
        assert!(v.rationale.contains("unparseable"));
    }

    /// The live backend plugs into [`crate::run_eval`] unchanged, exactly like the offline
    /// [`crate::semantic::SemanticOverlapJudge`] — the seam is genuinely interchangeable.
    #[test]
    fn r15_live_provider_judge_plugs_into_run_eval_unchanged() {
        struct EchoSystem;
        impl crate::EvalSystem for EchoSystem {
            fn respond(&self, input: &str) -> String {
                format!("answer for: {input}")
            }
        }
        let provider = Arc::new(ScriptedProvider {
            chunks: vec!["SCORE: 75 RATIONALE: adequate".into()],
        });
        let judge = LiveProviderJudge::new(provider);
        let cases = vec![crate::EvalCase::new("c1", "q1", "must be adequate", 60)];
        let report = crate::run_eval(&cases, &EchoSystem, &judge);
        assert_eq!(report.n, 1);
        assert_eq!(report.results[0].score, 75);
        assert!(report.results[0].passed);
    }
}
