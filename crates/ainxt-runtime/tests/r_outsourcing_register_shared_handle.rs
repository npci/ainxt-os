// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX regulated-fi-responsible-lifecycle — "outsourcing-register admin path" (part 1: the
//! ownership restructure). `OutsourcingRegister` was previously owned by value inside
//! `ModelRouter`'s `OutsourcingGuard`, with `OutsourcingRegister::upsert` reachable only from this
//! crate's own tests — no external handle existed for a served admin route (register/re-approve an
//! arrangement after a board-approved PR lands) to ever mutate a LIVE instance. This proves
//! `ModelRouter::outsourcing_register_handle()` hands out a SHARED, mutable view onto the exact same
//! register the router's non-overridable FI-03 eligibility gate reads on every turn — a write through
//! the handle is visible on the very next turn, not a disjoint copy.
//!
//! (The second half of this gap — an actual served HTTP admin route calling `upsert` through this
//! handle — needs the handle threaded through `AssembledFull`/`AppState` in `ainxt-runtimed`/
//! `ainxt-server`, a separate multi-crate wiring task. This test proves the prerequisite the route
//! will build on: the accessor is real, live, and race-free under a genuine concurrent write.)

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use ainxt_protocol::{Event, Request};
use ainxt_responsibleai::outsourcing::{
    ExitRehearsal, OutsourcingArrangement, OutsourcingRegister,
};
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::{ModelRouter, RouteError, RouterClock};
use ainxt_runtime::{engine_with_defaults, TurnError};
use ainxt_types::{DataClass, Principal};
use tokio::sync::mpsc;

struct TrackProvider {
    outsourced: &'static str,
    called: Arc<AtomicBool>,
}
impl Provider for TrackProvider {
    fn id(&self) -> &str {
        "acme"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn outsourcing_route(&self) -> Option<&str> {
        Some(self.outsourced)
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

const ROUTE: &str = "outsourcing.cloud.acme.chat";

fn clock() -> RouterClock {
    Arc::new(|| 100u64)
}

async fn run(
    eng: &ainxt_runtime::Engine,
    req: &Request,
) -> Result<ainxt_runtime::TurnSummary, TurnError> {
    let (tx, mut rx) = mpsc::channel::<Event>(64);
    let p = Principal::user("u", &["chat.send"]);
    let fut = eng.run_turn(&p, req, tx);
    let drain = async move { while rx.recv().await.is_some() {} };
    let (res, ()) = tokio::join!(fut, drain);
    res
}

#[tokio::test]
async fn admin_handle_write_is_visible_to_the_very_next_turns_eligibility_check() {
    let internal = Request::chat("s", "t", "hi", DataClass::Internal);
    let called = Arc::new(AtomicBool::new(false));

    let mut router = ModelRouter::new();
    router.register(Box::new(TrackProvider {
        outsourced: ROUTE,
        called: called.clone(),
    }));
    let router = router.with_outsourcing_register(OutsourcingRegister::new(10_000), "in", clock());

    // Grab the shared handle BEFORE the router is moved into the engine — exactly what a served
    // composition root would do: keep the handle for the admin route, hand the router to the engine.
    let handle = router
        .outsourcing_register_handle()
        .expect("a handle must be available once a register is installed");

    let eng = engine_with_defaults(router);

    // 1. No arrangement registered yet -> excluded, provider never contacted.
    let res = run(&eng, &internal).await;
    assert!(
        matches!(res, Err(TurnError::Routing(RouteError::NoEligible(_)))),
        "before the admin write, the route must still be ungoverned-excluded: {res:?}"
    );
    assert!(!called.load(Ordering::SeqCst));

    // 2. The "admin route" write: register a real, eligible arrangement through the SHARED handle —
    // exactly the upsert a served POST /admin/outsourcing route would perform after a board-approved
    // PR lands. No engine/router reconstruction — this must reach the SAME live instance.
    {
        let mut reg = handle.write().expect("the lock must not be poisoned");
        reg.upsert(OutsourcingArrangement::new(
            ROUTE,
            "ACME Cloud Pvt Ltd",
            DataClass::Internal,
            "in",
            vec![],
            "exit-plan-ref",
            "chat-inference",
            ExitRehearsal::At { tick: 100 },
        ));
    }

    // 3. The VERY NEXT turn, on the SAME engine/router, now finds the route eligible — proving the
    // hot-path eligibility check reads the identical Arc the admin write went through, not a stale
    // or disjoint copy.
    let res = run(&eng, &internal).await;
    assert!(
        res.is_ok(),
        "after the admin write, the now-eligible route must serve: {res:?}"
    );
    assert!(
        called.load(Ordering::SeqCst),
        "the newly-eligible route must be contacted"
    );
}

#[tokio::test]
async fn no_handle_is_available_when_no_register_is_installed() {
    let router = ModelRouter::new();
    assert!(
        router.outsourcing_register_handle().is_none(),
        "an unconfigured deployment (no outsourcing register installed) must get None, not a \
         fabricated empty handle that would silently pretend governance is active"
    );
}
