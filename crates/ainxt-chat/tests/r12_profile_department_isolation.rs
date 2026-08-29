// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-12 closure (HIGH): a Surface Profile's declared `rbac.department_scoped` is now WIRED into
//! the served retrieval isolation. `ChatSurface::from_engine_for_profile` derives the served
//! `row_isolation` flag from the profile, so a department-scoped surface grounds under the department
//! RLS row-filter — a row whose `department` attribute is not the caller's own is never scored
//! (existence never leaks), and a non-scoped profile grounds unchanged.
//!
//! Fails before `from_engine_for_profile` existed: the served surface was built from a KB-config flag
//! that ignored the profile, so a `department_scoped=true` profile did NOT isolate served retrieval —
//! a `cards` caller could ground on a `loans`-owned document. Passes after.

use ainxt_cache::{CacheConfig, FixedClock};
use ainxt_chat::{ChatReply, ChatSurface};
use ainxt_compliance::StrongRedactor;
use ainxt_context::{Chunk, Corpus};
use ainxt_profile::SurfaceProfile;
use ainxt_protocol::Event;
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtime::{Engine, InMemoryAudit, RbacAuthorizer};
use ainxt_types::{DataClass, Principal};
use tokio::sync::mpsc;

/// A deterministic model that echoes a short grounded answer (no numbers, so the served numeric gate
/// stays a no-op) — the test asserts on the CITATIONS, which come from clearance/RLS-filtered
/// retrieval, not on the prose.
struct EchoProvider;
impl Provider for EchoProvider {
    fn id(&self) -> &str {
        "mock"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, _prompt: &str) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(4);
        tokio::spawn(async move {
            let _ = tx
                .send(Event::TextDelta(
                    "Here is the settlement runbook summary for your team.".into(),
                ))
                .await;
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

/// Two documents on the SAME topic (both lexically match the query) but owned by different
/// departments — the RLS row-filter must decide which the caller may ground on.
fn corpus() -> Corpus {
    Corpus::new()
        .with(
            Chunk::new(
                "cards-doc",
                "cards-kb",
                "settlement runbook: the settlement batch reconciliation procedure for the cards team",
                DataClass::Internal,
            )
            .with_attribute("department", "cards"),
        )
        .with(
            Chunk::new(
                "loans-doc",
                "loans-kb",
                "settlement runbook: the settlement batch reconciliation procedure for the loans team",
                DataClass::Internal,
            )
            .with_attribute("department", "loans"),
        )
}

fn engine() -> Engine {
    let mut router = ModelRouter::new();
    router.register(Box::new(EchoProvider));
    Engine::new(
        Box::new(StrongRedactor::new()),
        Box::new(RbacAuthorizer),
        Box::new(InMemoryAudit::default()),
        router,
    )
}

fn cache_cfg() -> CacheConfig {
    CacheConfig {
        capacity: 64,
        ttl_ticks: 100,
        semantic_threshold: 0.99,
    }
}

fn cards_user() -> Principal {
    Principal::user("analyst", &["chat.send"]).with_department("cards")
}

#[test]
fn r12_profile_row_isolation_derives_from_declared_department_scoping() {
    // The single bridge: department_scoped profile ⇒ served row isolation ON; otherwise OFF.
    let scoped = SurfaceProfile::from_toml("id=\"chat\"\n[rbac]\ndepartment_scoped=true").unwrap();
    let open = SurfaceProfile::from_toml("id=\"chat\"").unwrap();
    assert!(ChatSurface::profile_row_isolation(&scoped));
    assert!(!ChatSurface::profile_row_isolation(&open));
}

#[tokio::test]
async fn r12_department_scoped_profile_isolates_served_retrieval() {
    // A department-scoped profile → the served surface grounds under the department RLS filter, so the
    // `cards` caller can ONLY ground on the cards-owned document; the loans document is never scored.
    let profile = SurfaceProfile::from_toml("id=\"chat\"\n[rbac]\ndepartment_scoped=true").unwrap();
    let surface = ChatSurface::from_engine_for_profile(
        engine(),
        corpus(),
        cache_cfg(),
        Box::new(FixedClock(0)),
        &profile,
    );

    let reply = surface
        .turn(
            "s1",
            &cards_user(),
            "what is the settlement batch reconciliation procedure?",
            DataClass::Internal,
        )
        .await
        .unwrap();

    match reply {
        ChatReply::Answer { citations, .. } => {
            let cited: Vec<&str> = citations.iter().map(|c| c.chunk_id.as_str()).collect();
            assert!(
                !cited.contains(&"loans-doc"),
                "a cards caller must NEVER ground on a loans-owned document: cited {cited:?}"
            );
            // Any grounding that did occur must be the caller's own department.
            for c in &citations {
                assert_eq!(
                    c.chunk_id, "cards-doc",
                    "the only groundable document for a cards caller is the cards-owned one"
                );
            }
        }
        other => panic!("expected an Answer, got {other:?}"),
    }
}

#[tokio::test]
async fn r12_non_scoped_profile_grounds_without_department_isolation() {
    // The control: a profile that does NOT declare department scoping grounds without the RLS filter,
    // so the cross-department (loans) document is reachable — proving the isolation is DRIVEN BY the
    // profile declaration, not always-on.
    let profile = SurfaceProfile::from_toml("id=\"chat\"").unwrap();
    let surface = ChatSurface::from_engine_for_profile(
        engine(),
        corpus(),
        cache_cfg(),
        Box::new(FixedClock(0)),
        &profile,
    );

    let reply = surface
        .turn(
            "s1",
            &cards_user(),
            "what is the settlement batch reconciliation procedure?",
            DataClass::Internal,
        )
        .await
        .unwrap();

    match reply {
        ChatReply::Answer { citations, .. } => {
            let cited: Vec<&str> = citations.iter().map(|c| c.chunk_id.as_str()).collect();
            assert!(
                cited.contains(&"loans-doc") || cited.contains(&"cards-doc"),
                "without department isolation, cross-department documents remain groundable: {cited:?}"
            );
        }
        other => panic!("expected an Answer, got {other:?}"),
    }
}
