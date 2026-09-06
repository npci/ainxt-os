// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! BE routing: the Model Router prefers a provider whose tier matches the request's (reasoning
//! depth → tier), while never weakening the data-class gate and gracefully falling back.

use ainxt_protocol::{Event, Request};
use ainxt_runtime::engine_with_defaults;
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_types::{DataClass, Principal, Tier};
use tokio::sync::mpsc;

/// Serves any data class; declares a tier and echoes its id.
struct Tiered {
    id: &'static str,
    tier: Option<Tier>,
}
impl Provider for Tiered {
    fn id(&self) -> &str {
        self.id
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn tier(&self) -> Option<Tier> {
        self.tier
    }
    fn stream(&self, _prompt: &str) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(4);
        let id = self.id.to_string();
        tokio::spawn(async move {
            let _ = tx.send(Event::TextDelta(id)).await;
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

fn user() -> Principal {
    Principal::user("u", &["chat.send"])
}
fn req_tier(tier: Tier) -> Request {
    let mut r = Request::chat("s", "t", "hi", DataClass::Public);
    r.tier = tier;
    r
}

fn engine_two_tiers() -> ainxt_runtime::Engine {
    let mut router = ModelRouter::new();
    // "cheap" registered FIRST — so absent tier preference it would always win.
    router.register(Box::new(Tiered {
        id: "cheap",
        tier: Some(Tier::Simple),
    }));
    router.register(Box::new(Tiered {
        id: "strong",
        tier: Some(Tier::Complex),
    }));
    engine_with_defaults(router)
}

#[tokio::test]
async fn router_prefers_the_provider_matching_the_requested_tier() {
    let eng = engine_two_tiers();

    // A Complex-tier request must reach the strong model even though cheap is registered first.
    let out = eng
        .run_turn_collect(&user(), &req_tier(Tier::Complex))
        .await
        .unwrap();
    assert_eq!(
        out.provider, "strong",
        "a deep/Complex turn routes to the matching (strong) provider"
    );

    // A Simple-tier request routes to the cheap model.
    let out = eng
        .run_turn_collect(&user(), &req_tier(Tier::Simple))
        .await
        .unwrap();
    assert_eq!(
        out.provider, "cheap",
        "a shallow/Simple turn routes to the cheap provider"
    );
}

#[tokio::test]
async fn no_tier_match_falls_back_to_first_eligible() {
    // Neither provider serves Medium → graceful fallback to registration order (cheap first).
    let eng = engine_two_tiers();
    let out = eng
        .run_turn_collect(&user(), &req_tier(Tier::Medium))
        .await
        .unwrap();
    assert_eq!(
        out.provider, "cheap",
        "when no provider matches the tier, order is unchanged"
    );
}

#[tokio::test]
async fn tierless_providers_are_unaffected_by_tier_preference() {
    // Both providers declare no tier (default) → tier preference is a no-op; first eligible wins.
    let mut router = ModelRouter::new();
    router.register(Box::new(Tiered {
        id: "a",
        tier: None,
    }));
    router.register(Box::new(Tiered {
        id: "b",
        tier: None,
    }));
    let eng = engine_with_defaults(router);
    let out = eng
        .run_turn_collect(&user(), &req_tier(Tier::Complex))
        .await
        .unwrap();
    assert_eq!(
        out.provider, "a",
        "tierless providers keep first-eligible order"
    );
}
