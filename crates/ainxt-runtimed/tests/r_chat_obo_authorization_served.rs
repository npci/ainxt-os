// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX regulated-fi-responsible-lifecycle (Pass-5 [AI] confused-deputy / ADR-022 §12,
//! `ainxt_identity::authz::RunAuthorization`).
//!
//! `RunAuthorization`/`authorize_str` turn the OBO delegation-chain algebra into a live per-dispatch
//! decision, but had ZERO callers anywhere in the served daemon before this fix: nothing rooted a
//! chain at the turn's REAL authenticated principal and checked it before dispatch, so a human whose
//! own JWT happened to carry a reserved payment-initiation verb
//! ([`ainxt_identity::RESERVED_PAYMENT_INITIATION_CAPABILITIES`]) could still have an agent run chat
//! turns "on their behalf" with the grant-layer confused-deputy check never actually exercised on the
//! live path. [`GovernedChatSurface`] now roots a [`RunAuthorization`] at the turn's real principal and
//! the just-(re)admitted credential, denying fail-closed on a structurally invalid chain.
//!
//! FAIL-BEFORE / PASS-AFTER: before this fix `GovernedChatSurface` never called
//! `RunAuthorization::authorize_str` anywhere, so a principal carrying `"payment:initiate"` sailed
//! straight through the §17/§19 admission gate (which knows nothing about capability content) and
//! reached the inner chat handler. After the fix such a principal is denied on every turn.

use std::sync::{Arc, Mutex};

use ainxt_identity::control::ControlPlane;
use ainxt_protocol::{Event, Request};
use ainxt_runtime::{CancelToken, TurnError, TurnHandler, TurnSummary};
use ainxt_runtimed::GovernedChatSurface;
use ainxt_types::{DataClass, Principal, Tier};
use tokio::sync::mpsc;

/// An inner [`TurnHandler`] standing in for the grounded chat turn: if it runs, the identity +
/// OBO-authorization gate admitted the turn.
struct EchoHandler;

impl TurnHandler for EchoHandler {
    fn handle_turn<'a>(
        &'a self,
        _principal: &'a Principal,
        req: &'a Request,
        sink: mpsc::Sender<Event>,
        _cancel: &'a CancelToken,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<TurnSummary, TurnError>> + Send + 'a>,
    > {
        Box::pin(async move {
            let text = format!("echo:{}", req.input);
            let _ = sink.send(Event::TextDelta(text.clone())).await;
            let _ = sink.send(Event::Done).await;
            Ok(TurnSummary {
                final_text: text,
                redactions: 0,
                provider: "echo".into(),
                ..Default::default()
            })
        })
    }
}

fn req(session: &str, turn: u64) -> Request {
    Request {
        session: session.into(),
        turn: format!("t{turn}"),
        input: format!("hello {turn}"),
        data_class: DataClass::Internal,
        tier: Tier::Medium,
        forced_provider: None,
        untrusted_tainted: false,
        user_turn: None,
        namespace: None,
        pinned_tier: None,
        request_override: None,
        history_budget_tokens: None,
    }
}

async fn drive(
    surface: &GovernedChatSurface,
    p: &Principal,
    r: &Request,
) -> Result<TurnSummary, TurnError> {
    let (tx, mut rx) = mpsc::channel::<Event>(64);
    let cancel = CancelToken::new();
    let res = surface.handle_turn(p, r, tx, &cancel).await;
    while rx.recv().await.is_some() {}
    res
}

// A normal principal (granted exactly `chat.send`, no reserved verb) is admitted through the NEW OBO
// authorization check exactly as before — the fix must not regress the ordinary path.
#[tokio::test]
async fn ordinary_principal_is_admitted_through_the_obo_authorization_check() {
    let control = Arc::new(Mutex::new(ControlPlane::new()));
    let surface = GovernedChatSurface::new(Arc::new(EchoHandler), control, "chat");
    let p = Principal::user("u-alice", &["chat.send"]).with_clearance(DataClass::Internal);

    let out = drive(&surface, &p, &req("chat-run-obo-1", 1))
        .await
        .expect("an ordinary principal must be admitted");
    assert_eq!(out.final_text, "echo:hello 1");

    // Renewal chain keeps working across several turns under the new check too.
    for t in 2..=4 {
        drive(&surface, &p, &req("chat-run-obo-1", t))
            .await
            .expect("subsequent turns admitted");
    }
}

// GAP-FIX proof: a principal whose OWN JWT carries a reserved payment-initiation verb is refused on
// EVERY turn — the OBO chain is structurally invalid (VerifyError::ReservedCapability), so the
// confused-deputy check denies fail-closed BEFORE the inner chat handler ever runs, even though the
// §17/§19 admission gate (which does not inspect capability content) would have admitted it.
#[tokio::test]
async fn principal_carrying_a_reserved_payment_verb_is_denied_by_obo_authorization() {
    let control = Arc::new(Mutex::new(ControlPlane::new()));
    let surface = GovernedChatSurface::new(Arc::new(EchoHandler), control, "chat");
    // A human whose JWT (perhaps via an over-broad role grant) also carries `payment:initiate`.
    let tainted = Principal::user("u-mallory", &["chat.send", "payment:initiate"])
        .with_clearance(DataClass::Internal);

    let err = drive(&surface, &tainted, &req("chat-run-obo-2", 1))
        .await
        .expect_err("a principal carrying a reserved payment verb must be denied");
    assert!(
        matches!(err, TurnError::Denied(_)),
        "expected a Denied turn error, got {err:?}"
    );

    // The denial is NOT a one-off: it holds on every subsequent turn of the same run too (the
    // principal's own capability set never changes), proving this is a structural grant-layer refusal,
    // not a transient admission hiccup.
    let err2 = drive(&surface, &tainted, &req("chat-run-obo-2", 2))
        .await
        .expect_err("the confused-deputy refusal must persist across turns");
    assert!(matches!(err2, TurnError::Denied(_)));
}
