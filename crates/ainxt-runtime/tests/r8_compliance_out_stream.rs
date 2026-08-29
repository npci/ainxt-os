// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-8 compliance-OUT safety on the provider stream (`Engine::run_turn_cancellable`).
//!
//! Two real highs closed here:
//!
//!  (1) The catch-all `Some(other) => sink.send(other)` arm used to forward provider-emitted
//!      `Event` variants (`ToolResult`, `ApprovalRequest`, any future variant) to the transport
//!      UNSCANNED — so I4 ("nothing text-bearing leaves the runtime unscanned") held only for
//!      `TextDelta`/`ToolCallStart`/`Usage`. Every outbound event is now routed through
//!      compliance-OUT (`scan_outbound_event`). `r8_tool_result_with_pan_is_redacted` proves a
//!      provider `ToolResult` carrying a PAN is redacted before it reaches the sink; the
//!      `ApprovalRequest` case is covered too.
//!
//!  (2) `safe_output_split` used to hold back only a trailing *alnum* run, so a secret that is NOT
//!      a contiguous alnum/`=` run — a spaced PAN "4111 1111 1111 1111" or a multi-word
//!      ACCOUNT_NAME_COMBO — could have its leading group flushed at the first separator before the
//!      detector ever saw the whole token. It now holds back the maximal trailing run of
//!      secret-relevant characters (alnum, `=`, space, `-`), bounded to a window, so a spaced secret
//!      split across streamed deltas is buffered whole. `r8_spaced_pan_split_across_deltas_*` proves
//!      an unredacted prefix never leaves.
//!
//! Redact-and-proceed is preserved throughout: turns complete, nothing is hard-blocked.

use ainxt_protocol::{Event, Request};
use ainxt_runtime::compliance::{ComplianceGate, Direction, Redacted};
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtime::{Engine, InMemoryAudit, RbacAuthorizer};
use ainxt_types::{DataClass, Principal};
use tokio::sync::mpsc;

/// Detector stand-in for the enterprise PCI engine: redacts any run of digits/spaces/hyphens
/// containing >= 13 digits (a PAN in contiguous OR spaced/hyphenated form) — but ONLY when it sees
/// the whole token in a single `scan` call. A leading fragment scanned in isolation (< 13 digits)
/// is NOT redacted, which is exactly what makes a leaked prefix observable in these tests.
struct PanGate;

impl PanGate {
    fn flush(buf: &mut String, out: &mut String, count: &mut usize) {
        let digits = buf.chars().filter(|c| c.is_ascii_digit()).count();
        if digits >= 13 {
            out.push_str("[REDACTED-PAN]");
            *count += 1;
        } else {
            out.push_str(buf);
        }
        buf.clear();
    }
    fn redact(text: &str) -> (String, usize) {
        let mut out = String::with_capacity(text.len());
        let mut buf = String::new();
        let mut count = 0usize;
        for c in text.chars() {
            if c.is_ascii_digit() || c == ' ' || c == '-' {
                buf.push(c);
            } else {
                Self::flush(&mut buf, &mut out, &mut count);
                out.push(c);
            }
        }
        Self::flush(&mut buf, &mut out, &mut count);
        (out, count)
    }
}

impl ComplianceGate for PanGate {
    fn scan(&self, text: &str, _dir: Direction) -> Redacted {
        let (text, redactions) = Self::redact(text);
        Redacted { text, redactions }
    }
}

/// Streams a fixed, caller-supplied sequence of provider events.
struct Scripted {
    events: std::sync::Mutex<Option<Vec<Event>>>,
}
impl Scripted {
    fn new(events: Vec<Event>) -> Self {
        Self {
            events: std::sync::Mutex::new(Some(events)),
        }
    }
}
impl Provider for Scripted {
    fn id(&self) -> &str {
        "scripted"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, _prompt: &str) -> mpsc::Receiver<Event> {
        let evs = self.events.lock().unwrap().take().unwrap_or_default();
        let (tx, rx) = mpsc::channel(16);
        tokio::spawn(async move {
            for e in evs {
                if tx.send(e).await.is_err() {
                    return;
                }
            }
        });
        rx
    }
}

fn engine(events: Vec<Event>) -> Engine {
    let mut router = ModelRouter::new();
    router.register(Box::new(Scripted::new(events)));
    Engine::new(
        Box::new(PanGate),
        Box::new(RbacAuthorizer),
        Box::new(InMemoryAudit::default()),
        router,
    )
}

fn principal() -> Principal {
    Principal::user("u", &["chat.send"])
}

async fn run(eng: &Engine) -> ainxt_runtime::TurnOutcome {
    eng.run_turn_collect(
        &principal(),
        &Request::chat("s", "t", "go", DataClass::Public),
    )
    .await
    .expect("turn completes (redact-and-proceed, never blocked)")
}

// (1) HIGH: a provider ToolResult carrying a PAN must be redacted on the catch-all outbound path,
//     never forwarded to the transport raw.
#[tokio::test]
async fn r8_tool_result_with_pan_is_redacted() {
    let eng = engine(vec![
        Event::ToolResult {
            id: "call-1".into(),
            output: "card on file: 4111111111111111".into(),
        },
        Event::Done,
    ]);
    let out = run(&eng).await;

    let tr = out
        .events
        .iter()
        .find_map(|e| match e {
            Event::ToolResult { output, .. } => Some(output.clone()),
            _ => None,
        })
        .expect("a ToolResult must be forwarded to the sink");

    assert!(
        !tr.contains("4111111111111111"),
        "the PAN must NOT reach the transport in a ToolResult; got {tr:?}"
    );
    assert!(
        tr.contains("[REDACTED-PAN]"),
        "the ToolResult PAN must be redacted by compliance-OUT; got {tr:?}"
    );
    assert!(out.redactions >= 1, "the redaction must be counted");
}

// (1) HIGH, cont.: an ApprovalRequest summary is a text-bearing field and must also be scanned.
#[tokio::test]
async fn r8_approval_request_summary_is_redacted() {
    let eng = engine(vec![
        Event::ApprovalRequest {
            id: "appr-1".into(),
            summary: "refund to account 4111111111111111 requested".into(),
        },
        Event::Done,
    ]);
    let out = run(&eng).await;

    let summary = out
        .events
        .iter()
        .find_map(|e| match e {
            Event::ApprovalRequest { summary, .. } => Some(summary.clone()),
            _ => None,
        })
        .expect("an ApprovalRequest must be forwarded to the sink");

    assert!(
        !summary.contains("4111111111111111"),
        "the PAN must NOT reach the transport in an ApprovalRequest summary; got {summary:?}"
    );
    assert!(
        summary.contains("[REDACTED-PAN]"),
        "the ApprovalRequest summary must be redacted; got {summary:?}"
    );
}

// (2) HIGH: a SPACED PAN split across two streamed deltas — where the first delta ends on a
//     separator so the old alnum-only split would flush a sub-threshold (12-digit) prefix — must
//     never leave the runtime as an unredacted prefix. The whole token is buffered and redacted.
#[tokio::test]
async fn r8_spaced_pan_split_across_deltas_never_leaks_prefix() {
    // delta1 ends with a space after 12 digits; delta2 supplies the final group (16 digits total).
    // Old behaviour: "4111 1111 1111 " (12 digits, < detector threshold) would be emitted at the
    // separator boundary and slip through un-redacted.
    let eng = engine(vec![
        Event::TextDelta("4111 1111 1111 ".into()),
        Event::TextDelta("1111".into()),
        Event::Done,
    ]);
    let out = run(&eng).await;

    // No emitted event may carry ANY fragment of the raw PAN.
    for e in &out.events {
        if let Event::TextDelta(t) = e {
            assert!(
                !t.contains("4111"),
                "an unredacted PAN prefix leaked in a delta: {t:?}"
            );
        }
    }
    assert!(
        !out.final_text.contains("4111"),
        "final text must contain no raw PAN digits; got {:?}",
        out.final_text
    );
    assert!(
        out.final_text.contains("[REDACTED-PAN]"),
        "the buffered spaced PAN must be redacted whole; got {:?}",
        out.final_text
    );
    assert!(out.redactions >= 1, "the redaction must be counted");
}

// (2) HIGH, cont.: a spaced PAN streamed one character at a time (worst-case fragmentation) is
//     still buffered whole and redacted — proving the hold-back is not a single-boundary special
//     case.
#[tokio::test]
async fn r8_spaced_pan_streamed_char_by_char_never_leaks_prefix() {
    let pan = "4111 1111 1111 1111";
    let mut events: Vec<Event> = pan
        .chars()
        .map(|c| Event::TextDelta(c.to_string()))
        .collect();
    events.push(Event::TextDelta(". thanks!".into())); // trailing hard separator + benign tail
    events.push(Event::Done);

    let eng = engine(events);
    let out = run(&eng).await;

    for e in &out.events {
        if let Event::TextDelta(t) = e {
            assert!(!t.contains("4111"), "leaked PAN fragment in a delta: {t:?}");
        }
    }
    assert!(
        !out.final_text.contains("4111"),
        "raw PAN in final text: {:?}",
        out.final_text
    );
    assert!(
        out.final_text.contains("[REDACTED-PAN]"),
        "PAN not redacted: {:?}",
        out.final_text
    );
    assert!(
        out.final_text.contains("thanks!"),
        "the benign tail after the secret must still stream (redact-and-proceed): {:?}",
        out.final_text
    );
}
