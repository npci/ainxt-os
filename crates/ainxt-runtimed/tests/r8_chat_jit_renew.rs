// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-8 — §15 short-TTL JIT **renew-and-re-attest** is DRIVABLE on a chat run (ADR-022 §15 +
//! §17/§19). Before this, the chat served path minted no per-Run credential and never drove §15, so a
//! multi-turn chat run was a single standing grant and a mid-run kill-switch/revocation could not
//! reach its next turn. [`GovernedChatSurface`] wires the fused per-dispatch entrypoint
//! (`ControlPlane::authorize_dispatch`) onto every chat turn.
//!
//! These tests drive the wire directly (an echo inner handler stands in for the grounded chat turn —
//! the identity governance is the unit under test):
//!
//!   * across a multi-turn chat run the short-TTL credential renews-and-re-attests (its `issued_at`
//!     advances; the attested measurement is carried forward) — §15 is drivable;
//!   * a kill-switch pulled MID-RUN on the shared control plane denies the NEXT turn immediately
//!     (fail-closed: the inner turn never runs) — §17/§19 reaches an in-flight chat run;
//!   * a kill-switch engaged BEFORE a new chat run refuses issuance JIT at run start (§19).
//!
//! Deterministic: logical time is the surface's per-session turn clock; no wall clock is read.

use std::sync::{Arc, Mutex};

use ainxt_identity::authority::KillScope;
use ainxt_identity::control::ControlPlane;
use ainxt_protocol::{Event, Request};
use ainxt_runtime::{CancelToken, TurnError, TurnHandler, TurnSummary};
use ainxt_runtimed::GovernedChatSurface;
use ainxt_types::{DataClass, Principal, Tier};
use tokio::sync::mpsc;

/// An inner [`TurnHandler`] standing in for the grounded chat turn: it streams a token and returns.
/// If it runs, the identity gate admitted the turn.
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

fn principal() -> Principal {
    Principal::user("u-alice", &["chat.send"]).with_clearance(DataClass::Internal)
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

/// Drive one turn and drain its event stream; returns the turn result.
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

// R8 — §15 renew-and-re-attest is drivable across a multi-turn chat run.
#[tokio::test]
async fn r8_chat_run_renews_and_reattests_short_ttl_credential() {
    let control = Arc::new(Mutex::new(ControlPlane::new()));
    let surface = GovernedChatSurface::new(Arc::new(EchoHandler), control, "chat");
    let p = principal();
    let session = "chat-run-1";

    // The first turn mints the JIT short-TTL credential.
    drive(&surface, &p, &req(session, 1))
        .await
        .expect("turn 1 admitted");
    let first = surface
        .credential_for(session)
        .expect("credential minted at run start");
    assert_eq!(
        first.attestation_ref, "runtimed-attested-chat-workload",
        "attested, not self-asserted"
    );
    let first_issued = first.issued_at;

    // Drive several more turns of the SAME chat run — the credential renews as the run clock advances.
    for t in 2..=6 {
        drive(&surface, &p, &req(session, t))
            .await
            .expect("turn admitted");
    }

    let renewals = surface.renewals_for(session);
    assert!(
        renewals >= 2,
        "a multi-turn chat run must drive §15 renew-and-re-attest (got {renewals} renewals)"
    );
    let latest = surface.credential_for(session).unwrap();
    assert!(
        latest.issued_at.tick() > first_issued.tick(),
        "the re-attested credential's issued_at must advance (was {:?}, now {:?})",
        first_issued,
        latest.issued_at
    );
    // Re-attestation carries the attested facts forward — a renewal is not a downgrade to self-assertion.
    assert_eq!(latest.attestation_ref, "runtimed-attested-chat-workload");
    assert_eq!(
        latest.run_id, session,
        "same chat run, re-authorized identity"
    );
}

// R8 — §17/§19: a kill-switch pulled MID-RUN denies the next chat turn immediately (fail-closed).
#[tokio::test]
async fn r8_mid_run_kill_switch_denies_next_chat_turn() {
    let control = Arc::new(Mutex::new(ControlPlane::new()));
    let surface = GovernedChatSurface::new(Arc::new(EchoHandler), control.clone(), "chat");
    let p = principal();
    let session = "chat-run-2";

    // Turn 1 proceeds under a clean plane.
    drive(&surface, &p, &req(session, 1))
        .await
        .expect("turn 1 admitted");

    // A senior approver pulls the workforce kill-switch mid-run.
    {
        let mut guard = control.lock().unwrap();
        guard
            .pull_kill_switch(
                KillScope::Workforce,
                "u-exec",
                1,
                true,
                ainxt_identity::LogicalTime(2),
            )
            .expect("senior approver may pull the workforce kill-switch");
    } // guard released before the next await point

    // The very next turn of the in-flight chat run is DENIED (never reaches the inner echo handler).
    let err = drive(&surface, &p, &req(session, 2)).await.unwrap_err();
    assert!(
        matches!(err, TurnError::Denied(_)),
        "a mid-run kill-switch must deny the next chat turn, got {err:?}"
    );

    // Releasing the halt lets the run proceed again — the control is a live lever, not a one-way trip.
    {
        let mut guard = control.lock().unwrap();
        guard.release_kill_switch(&KillScope::Workforce);
    } // guard released before the next await point
    drive(&surface, &p, &req(session, 3))
        .await
        .expect("turn admitted after release");
}

// R8 — §19: a kill-switch engaged BEFORE a new chat run refuses issuance JIT at run start.
#[tokio::test]
async fn r8_kill_switch_refuses_new_chat_run_at_issuance() {
    let control = Arc::new(Mutex::new(ControlPlane::new()));
    let surface = GovernedChatSurface::new(Arc::new(EchoHandler), control.clone(), "chat");
    let p = principal();

    {
        let mut guard = control.lock().unwrap();
        guard
            .pull_kill_switch(
                KillScope::Workforce,
                "u-exec",
                1,
                true,
                ainxt_identity::LogicalTime(1),
            )
            .unwrap();
    } // guard released before the next await point

    // A brand-new chat run cannot even obtain its first credential (issue_jit gated on the shared plane).
    let err = drive(&surface, &p, &req("chat-run-3", 1))
        .await
        .unwrap_err();
    assert!(
        matches!(err, TurnError::Denied(_)),
        "a workforce kill-switch must refuse a new chat run at issuance, got {err:?}"
    );
    assert_eq!(surface.renewals_for("chat-run-3"), 0);
}
