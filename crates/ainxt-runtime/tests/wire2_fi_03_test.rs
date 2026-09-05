// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Wiring test for gap FI-03: the RBI IT/cloud-outsourcing register is the model router's
//! NON-OVERRIDABLE eligibility input. An external/outsourced route is excluded BEFORE ranking and
//! BEFORE failover unless the register says it is eligible for the request's data class + residency.
//!
//! Drives the REAL assembled `Engine`. It proves, on the live path:
//!   1. An outsourced route with NO register entry never routes (no ungoverned outsourcing).
//!   2. An outsourced route whose permitted ceiling is below the request's data class is excluded.
//!   3. A residency mismatch excludes the route.
//!   4. A registered, in-ceiling, in-residency route IS selected.
//!   5. An IN-HOUSE route (no outsourcing id) is never gated by the register.
//!   6. The gate is non-overridable: a FORCED ineligible outsourced route is still refused.

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

/// A provider that records whether it was ever streamed. `outsourced` gives the register route id
/// (`Some`) for an external route, or `None` for an in-house route.
struct TrackProvider {
    id: &'static str,
    outsourced: Option<&'static str>,
    called: Arc<AtomicBool>,
}
impl Provider for TrackProvider {
    fn id(&self) -> &str {
        self.id
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true // data-class fitness is a separate axis; this test isolates the outsourcing register
    }
    fn outsourcing_route(&self) -> Option<&str> {
        self.outsourced
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

/// A register whose one arrangement permits up to `permitted`, resident in `residency`.
fn register(permitted: DataClass, residency: &str) -> OutsourcingRegister {
    let mut reg = OutsourcingRegister::new(10_000);
    reg.upsert(OutsourcingArrangement::new(
        ROUTE,
        "ACME Cloud Pvt Ltd",
        permitted,
        residency,
        vec![],
        "exit-plan-ref",
        "chat-inference",
        ExitRehearsal::At { tick: 100 },
    ));
    reg
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
async fn wire2_fi_03() {
    let internal = Request::chat("s", "t", "hi", DataClass::Internal);

    // --- 1. Outsourced route, NO register entry → excluded; only provider → NoEligible; never called. ---
    {
        let called = Arc::new(AtomicBool::new(false));
        let mut router = ModelRouter::new();
        router.register(Box::new(TrackProvider {
            id: "acme",
            outsourced: Some(ROUTE),
            called: called.clone(),
        }));
        let router =
            router.with_outsourcing_register(OutsourcingRegister::new(10_000), "in", clock());
        let eng = engine_with_defaults(router);
        let res = run(&eng, &internal).await;
        assert!(
            matches!(res, Err(TurnError::Routing(RouteError::NoEligible(_)))),
            "an unregistered outsourced route must be excluded, got {res:?}"
        );
        assert!(
            !called.load(Ordering::SeqCst),
            "an unregistered outsourced route must never be contacted"
        );
    }

    // --- 2. Registered but permitted ceiling (Public) below the request class (Internal) → excluded. ---
    {
        let called = Arc::new(AtomicBool::new(false));
        let mut router = ModelRouter::new();
        router.register(Box::new(TrackProvider {
            id: "acme",
            outsourced: Some(ROUTE),
            called: called.clone(),
        }));
        let router =
            router.with_outsourcing_register(register(DataClass::Public, "in"), "in", clock());
        let eng = engine_with_defaults(router);
        let res = run(&eng, &internal).await;
        assert!(matches!(
            res,
            Err(TurnError::Routing(RouteError::NoEligible(_)))
        ));
        assert!(!called.load(Ordering::SeqCst));
    }

    // --- 3. Residency mismatch (route resident in "eu", deployment "in") → excluded. ---
    {
        let called = Arc::new(AtomicBool::new(false));
        let mut router = ModelRouter::new();
        router.register(Box::new(TrackProvider {
            id: "acme",
            outsourced: Some(ROUTE),
            called: called.clone(),
        }));
        let router =
            router.with_outsourcing_register(register(DataClass::Internal, "eu"), "in", clock());
        let eng = engine_with_defaults(router);
        let res = run(&eng, &internal).await;
        assert!(matches!(
            res,
            Err(TurnError::Routing(RouteError::NoEligible(_)))
        ));
        assert!(!called.load(Ordering::SeqCst));
    }

    // --- 4. Registered, in-ceiling, in-residency → selected; provider IS called; turn succeeds. ---
    {
        let called = Arc::new(AtomicBool::new(false));
        let mut router = ModelRouter::new();
        router.register(Box::new(TrackProvider {
            id: "acme",
            outsourced: Some(ROUTE),
            called: called.clone(),
        }));
        let router =
            router.with_outsourcing_register(register(DataClass::Internal, "in"), "in", clock());
        let eng = engine_with_defaults(router);
        let res = run(&eng, &internal).await;
        assert!(
            res.is_ok(),
            "an eligible outsourced route must serve, got {res:?}"
        );
        assert!(
            called.load(Ordering::SeqCst),
            "the eligible route must be contacted"
        );
    }

    // --- 5. An IN-HOUSE route (no outsourcing id) is NOT gated by the register even with a register
    //        configured and no entry for it → it serves. ---
    {
        let called = Arc::new(AtomicBool::new(false));
        let mut router = ModelRouter::new();
        router.register(Box::new(TrackProvider {
            id: "on-prem-llm",
            outsourced: None,
            called: called.clone(),
        }));
        let router =
            router.with_outsourcing_register(OutsourcingRegister::new(10_000), "in", clock());
        let eng = engine_with_defaults(router);
        let res = run(&eng, &internal).await;
        assert!(
            res.is_ok(),
            "an in-house route is not outsourcing and must serve"
        );
        assert!(called.load(Ordering::SeqCst));
    }

    // --- 6. Non-overridable: FORCING an ineligible outsourced route is still refused. ---
    {
        let called = Arc::new(AtomicBool::new(false));
        let mut router = ModelRouter::new();
        router.register(Box::new(TrackProvider {
            id: "acme",
            outsourced: Some(ROUTE),
            called: called.clone(),
        }));
        // Register permits only Public; request is Internal → ineligible even though forced.
        let router =
            router.with_outsourcing_register(register(DataClass::Public, "in"), "in", clock());
        let eng = engine_with_defaults(router);
        let mut forced = internal.clone();
        forced.forced_provider = Some("acme".to_string());
        let res = run(&eng, &forced).await;
        assert!(
            matches!(
                res,
                Err(TurnError::Routing(RouteError::ForcedNotEligible(_, _)))
            ),
            "a forced ineligible outsourced route must be refused (non-overridable), got {res:?}"
        );
        assert!(!called.load(Ordering::SeqCst));
    }
}
