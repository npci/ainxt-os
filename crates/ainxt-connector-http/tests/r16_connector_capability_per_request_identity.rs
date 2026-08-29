// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX guardrails-injection "connector-provenance lost".
//!
//! Before this round, [`ConnectorCapability`] bound ONE concrete `Principal` at CONSTRUCTION time,
//! because [`ConnectorInvoker::invoke_in`] resolves the OAuth token per `(tenant, principal.user_id,
//! connector)`. The served [`ToolRuntime`] is a single `Arc<ToolRuntime>` shared across ALL concurrent
//! requests, installed ONCE at engine-assembly (`Engine::with_shared_tools`) — so a construction-time-
//! baked principal would misattribute EVERY caller's connector calls to whichever identity happened to
//! be bound when the capability was registered. The unsafe shortcut (bake one shared principal) would
//! have silently run user B's connector call under user A's identity.
//!
//! The fix: [`ConnectorCapability`] now holds a `PrincipalResolver` and re-resolves the acting
//! principal on every dispatch from the `caller` [`ainxt_tools::Tool::execute_as`] receives — the same
//! `user_id` [`ToolRuntime::dispatch_for`]/[`ToolRuntime::dispatch_obo`] already thread down to the
//! exactly-once ledger key (§1.2), extended past the ledger to the tool body itself. The identity-less
//! [`ainxt_tools::Tool::execute`] entrypoint (reachable only via the unattributed `ToolRuntime::
//! dispatch`) now refuses outright rather than guessing an identity.
//!
//! These tests prove BOTH halves fail-closed AND fail-open-correctly:
//!   1. two concurrent requests from DIFFERENT principals, dispatched through the SAME shared
//!      `Arc<ToolRuntime>`/`ConnectorCapability` registered ONCE, are each attributed to their OWN
//!      principal — never cross-contaminated (the exact bug class this closes);
//!   2. a connector call reached with no caller identity (the legacy unattributed `dispatch`) is
//!      refused, never silently run under a default/guessed identity.
//!
//! Fail-before/pass-after: before this round, `ConnectorCapability::new` only accepted a single bound
//! `Principal`, so test (1) below — asserting the SAME registered instance correctly attributes two
//! DIFFERENT concurrent callers — could not even be expressed; the API had no per-call identity input.

use std::sync::{Arc, Barrier};
use std::thread;

use ainxt_connector::{
    AllowAllPolicy, AuthKind, CapabilityConnectorAuthorizer, ConnectorDef, ConnectorRegistry,
    ConnectorRuntime, InMemoryConnectorAudit, MarkerEgressGuard,
};
use ainxt_connector_http::{
    ConnectorCapability, ConnectorInvoker, GitLab, StubTransport, TokenSource,
};
use ainxt_tools::{DispatchResult, EffectClass, InMemoryLedger, ManualReconciler, ToolRuntime};
use ainxt_types::{DataClass, Principal};

const NOW: u64 = 1_000_000;

/// A `TokenSource` that returns a distinct, per-user bearer token (`AT-{user}`), so a captured
/// request's `Authorization` header unambiguously reveals which principal's credential was actually
/// used for that call.
struct PerUserTokenSource;
impl TokenSource for PerUserTokenSource {
    fn access_token(&self, user: &str, _connector: &str, _now_unix: u64) -> Result<String, String> {
        Ok(format!("AT-{user}"))
    }
}

fn connector_runtime() -> Arc<ConnectorRuntime> {
    let mut reg = ConnectorRegistry::new();
    reg.register(
        ConnectorDef::new("gitlab", "GitLab", AuthKind::ApiToken)
            .with_max_egress_class(DataClass::Internal),
    );
    Arc::new(ConnectorRuntime::new(
        reg,
        Box::new(AllowAllPolicy),
        Box::new(CapabilityConnectorAuthorizer),
        Box::new(MarkerEgressGuard),
        Box::new(InMemoryConnectorAudit::new()),
    ))
}

fn tool_runtime() -> ToolRuntime {
    ToolRuntime::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler))
}

/// Build a `ConnectorCapability` whose resolver knows exactly `alice` and `bob` — proving the
/// resolver, not the constructor, is what supplies per-call identity.
fn cap_for_alice_and_bob(invoker: Arc<ConnectorInvoker>) -> ConnectorCapability {
    let gl = GitLab::new("https://gl.example.invalid");
    ConnectorCapability::new(
        "gitlab.get_project",
        invoker,
        Arc::new(|uid: &str| match uid {
            "alice" => Some(Principal::user("alice", &["connector.gitlab"])),
            "bob" => Some(Principal::user("bob", &["connector.gitlab"])),
            _ => None,
        }),
        "tenant-shared",
        DataClass::Internal,
        Arc::new(move |args: &str| {
            let v: serde_json::Value = serde_json::from_str(args).map_err(|e| e.to_string())?;
            let project = v
                .get("project")
                .and_then(|p| p.as_str())
                .ok_or("missing 'project'")?;
            Ok(gl.get_project(project))
        }),
    )
    .with_effect(EffectClass::Idempotent)
    .with_clock(Arc::new(|| NOW))
}

/// **The proving test.** Two threads hammer the SAME `Arc<ToolRuntime>` (one `ConnectorCapability`
/// registered ONCE — exactly the served-daemon shape via `Engine::with_shared_tools`), each thread
/// always dispatching as its OWN principal (`dispatch_for("alice", ..)` / `dispatch_for("bob", ..)`),
/// synchronized on a barrier every round so the two dispatches genuinely race on the shared registry
/// and shared capability instance. A construction-time-baked principal (the unsafe shortcut) could not
/// pass this: every call from BOTH threads would have carried the ONE identity baked in at
/// registration, regardless of which thread/user actually dispatched it.
#[test]
fn cross_user_concurrent_dispatch_never_cross_attributes_identity() {
    let stub = StubTransport::new();
    let invoker = Arc::new(ConnectorInvoker::new(
        connector_runtime(),
        Box::new(stub.clone()),
        Box::new(PerUserTokenSource),
    ));

    let mut tr = tool_runtime();
    tr.register(Box::new(cap_for_alice_and_bob(invoker)));
    let tr = Arc::new(tr); // ONE shared registry, dispatched concurrently — the served-path shape.

    const ROUNDS: usize = 50;
    let barrier = Arc::new(Barrier::new(2));

    let tr_a = tr.clone();
    let barrier_a = barrier.clone();
    let alice = thread::spawn(move || {
        for i in 0..ROUNDS {
            barrier_a.wait();
            let args = format!(r#"{{"project":"alice-repo-{i}"}}"#);
            let r = tr_a.dispatch_for("alice", "gitlab.get_project", &args);
            assert!(
                matches!(r, DispatchResult::Ok(_)),
                "alice's call should succeed: {r:?}"
            );
        }
    });

    let tr_b = tr.clone();
    let barrier_b = barrier.clone();
    let bob = thread::spawn(move || {
        for i in 0..ROUNDS {
            barrier_b.wait();
            let args = format!(r#"{{"project":"bob-repo-{i}"}}"#);
            let r = tr_b.dispatch_for("bob", "gitlab.get_project", &args);
            assert!(
                matches!(r, DispatchResult::Ok(_)),
                "bob's call should succeed: {r:?}"
            );
        }
    });

    alice.join().expect("alice thread panicked");
    bob.join().expect("bob thread panicked");

    // Every request that reached the wire must carry the bearer token for the SAME user whose repo
    // it requested — never the other user's, and never a single shared/baked identity. This is the
    // precise cross-contamination assertion: pre-fix, EVERY call (from both threads) would have used
    // whichever ONE principal was baked in at `ConnectorCapability::new`, which this loop would catch
    // as soon as it hit a request whose URL/token pairing didn't match.
    let sent = stub.sent();
    assert_eq!(
        sent.len(),
        ROUNDS * 2,
        "every dispatched call must reach the wire exactly once"
    );
    let mut alice_calls = 0;
    let mut bob_calls = 0;
    for req in &sent {
        let bearer = req
            .headers
            .iter()
            .find(|(k, _)| k == "Authorization")
            .map(|(_, v)| v.as_str())
            .unwrap_or_else(|| panic!("no Authorization header on {req:?}"));
        if req.url.contains("alice-repo") {
            assert_eq!(
                bearer, "Bearer AT-alice",
                "alice's project call must carry ALICE's token, not another principal's: {req:?}"
            );
            alice_calls += 1;
        } else if req.url.contains("bob-repo") {
            assert_eq!(
                bearer, "Bearer AT-bob",
                "bob's project call must carry BOB's token, not another principal's: {req:?}"
            );
            bob_calls += 1;
        } else {
            panic!("unexpected request on the wire: {req:?}");
        }
    }
    assert_eq!(
        alice_calls, ROUNDS,
        "every one of alice's dispatches must have reached the wire as alice"
    );
    assert_eq!(
        bob_calls, ROUNDS,
        "every one of bob's dispatches must have reached the wire as bob"
    );
}

/// The identity-less entrypoint must refuse outright rather than silently running under a default or
/// guessed principal. This is what makes the isolation above STRUCTURAL rather than incidental: there
/// is no remaining code path that can execute a connector call without a real per-request caller.
#[test]
fn execute_without_a_caller_identity_fails_closed_not_silently() {
    let stub = StubTransport::new();
    let invoker = Arc::new(ConnectorInvoker::new(
        connector_runtime(),
        Box::new(stub.clone()),
        Box::new(PerUserTokenSource),
    ));

    let mut tr = tool_runtime();
    tr.register(Box::new(cap_for_alice_and_bob(invoker)));

    // The legacy unattributed path — no `user_id` at all, so no `caller` reaches `execute_as`.
    match tr.dispatch("gitlab.get_project", r#"{"project":"alice-repo-0"}"#) {
        DispatchResult::Failed(msg) => {
            assert!(
                msg.contains("per-request principal") || msg.contains("no acting principal"),
                "must fail closed naming the missing per-request identity, got: {msg}"
            );
        }
        other => panic!("expected Failed (no caller identity), got {other:?}"),
    }
    assert_eq!(
        stub.sent_count(),
        0,
        "fail-closed: no bytes on the wire without a real caller"
    );
}

/// A `user_id` the resolver does not recognize must also fail closed — never fall back to running the
/// call as some other (e.g. the first-registered) principal.
#[test]
fn execute_for_an_unresolvable_user_fails_closed() {
    let stub = StubTransport::new();
    let invoker = Arc::new(ConnectorInvoker::new(
        connector_runtime(),
        Box::new(stub.clone()),
        Box::new(PerUserTokenSource),
    ));

    let mut tr = tool_runtime();
    tr.register(Box::new(cap_for_alice_and_bob(invoker)));

    match tr.dispatch_for(
        "mallory",
        "gitlab.get_project",
        r#"{"project":"alice-repo-0"}"#,
    ) {
        DispatchResult::Failed(msg) => {
            assert!(
                msg.contains("no resolvable principal"),
                "must fail closed naming the unresolvable principal, got: {msg}"
            );
        }
        other => panic!("expected Failed (unresolvable principal), got {other:?}"),
    }
    assert_eq!(
        stub.sent_count(),
        0,
        "fail-closed: no bytes on the wire for an unknown principal"
    );
}
