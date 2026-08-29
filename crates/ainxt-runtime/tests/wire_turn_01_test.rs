// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Wiring test for gap TURN-01: the pre-turn budget gate is enforced INSIDE the assembled
//! `run_turn_cancellable` pipeline — an over-ceiling turn is denied right after authz and BEFORE any
//! provider is contacted (cost enforced pre-turn, not merely recorded post-hoc).
//!
//! This constructs the REAL `Engine` (not a mock of the gate) and drives it end-to-end. It fails
//! before the wire (no budget gate → the provider is called and the turn succeeds) and passes after
//! (a denying `BudgetStore` → the provider is never called and the turn returns `Denied`).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use ainxt_protocol::{Event, Request};
use ainxt_runtime::budget::{BudgetSnapshot, BudgetStore};
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtime::{engine_with_defaults, TurnError};
use ainxt_types::{DataClass, Principal};
use tokio::sync::mpsc;

/// Provider that flips a flag the instant its stream is invoked — the tripwire proving whether the
/// budget gate stopped the turn BEFORE any provider call.
struct TripwireProvider {
    called: Arc<AtomicBool>,
}
impl Provider for TripwireProvider {
    fn id(&self) -> &str {
        "tripwire"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, _prompt: &str) -> mpsc::Receiver<Event> {
        self.called.store(true, Ordering::SeqCst);
        let (tx, rx) = mpsc::channel(8);
        tokio::spawn(async move {
            let _ = tx.send(Event::TextDelta("served".into())).await;
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

/// Fixed per-user budget: `spent` already consumed against `limit` (0 = no ceiling).
struct FixedBudget {
    spent: u64,
    limit: u64,
}
impl BudgetStore for FixedBudget {
    fn snapshot(&self, _p: &Principal) -> BudgetSnapshot {
        BudgetSnapshot::new(self.spent, self.limit)
    }
}

fn principal() -> Principal {
    Principal::user("u", &["chat.send"])
}

async fn run(
    eng: &ainxt_runtime::Engine,
    req: &Request,
) -> (Result<ainxt_runtime::TurnSummary, TurnError>, Vec<Event>) {
    let (tx, mut rx) = mpsc::channel::<Event>(64);
    let p = principal();
    let fut = eng.run_turn(&p, req, tx);
    let drain = async move {
        let mut v = Vec::new();
        while let Some(e) = rx.recv().await {
            v.push(e);
        }
        v
    };
    tokio::join!(fut, drain)
}

#[tokio::test]
async fn wire_turn_01() {
    let req = Request::chat("s", "t", "please answer this question", DataClass::Public);

    // --- Control: NO ceiling configured (default store is unlimited) → the turn runs normally and
    //     the provider IS called. (This is exactly the pre-wire behavior.) ---
    {
        let called = Arc::new(AtomicBool::new(false));
        let mut router = ModelRouter::new();
        router.register(Box::new(TripwireProvider {
            called: called.clone(),
        }));
        let eng = engine_with_defaults(router); // no budget store == no ceiling
        let (res, _events) = run(&eng, &req).await;
        assert!(res.is_ok(), "unlimited budget must allow the turn");
        assert!(
            called.load(Ordering::SeqCst),
            "with no ceiling the provider must be called"
        );
    }

    // --- Wired behavior: a store whose projected spend exceeds the limit → the turn is DENIED
    //     pre-turn; the provider is NEVER contacted. ---
    {
        let called = Arc::new(AtomicBool::new(false));
        let mut router = ModelRouter::new();
        router.register(Box::new(TripwireProvider {
            called: called.clone(),
        }));
        // estimate = len/4 (>=1) ≈ 6 for this input; spent 9 + est would exceed limit 10.
        let eng = engine_with_defaults(router).with_budget_store(Box::new(FixedBudget {
            spent: 9,
            limit: 10,
        }));

        let (res, events) = run(&eng, &req).await;

        assert!(
            matches!(res, Err(TurnError::Denied(_))),
            "an over-ceiling turn must be denied, got {res:?}"
        );
        assert!(
            !called.load(Ordering::SeqCst),
            "the budget gate must deny BEFORE any provider call"
        );
        // The typed protocol error surfaced as a session-level error event.
        assert!(
            events
                .iter()
                .any(|e| matches!(e, Event::Error(m) if m.contains("over budget"))),
            "the budget denial must be emitted as a session error event; events={events:?}"
        );
    }

    // --- A generous ceiling still allows (proves the gate is a real threshold, not a hard block). ---
    {
        let called = Arc::new(AtomicBool::new(false));
        let mut router = ModelRouter::new();
        router.register(Box::new(TripwireProvider {
            called: called.clone(),
        }));
        let eng = engine_with_defaults(router).with_budget_store(Box::new(FixedBudget {
            spent: 1,
            limit: 1_000_000,
        }));
        let (res, _events) = run(&eng, &req).await;
        assert!(res.is_ok(), "an under-ceiling turn must proceed");
        assert!(called.load(Ordering::SeqCst));
    }
}
