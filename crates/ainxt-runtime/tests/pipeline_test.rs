// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Turn-pipeline tests (async): mandatory gates, redaction in/out, and non-overridable
//! data-class routing. These prove the enterprise invariants, not just the happy path.

use std::sync::{Arc, Mutex};

use ainxt_protocol::{Event, Request};
use ainxt_runtime::audit::{AuditRecord, AuditSink};
use ainxt_runtime::authz::RbacAuthorizer;
use ainxt_runtime::compliance::RedactAndProceed;
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::{ModelRouter, RouteError};
use ainxt_runtime::{Engine, TurnError};
use ainxt_types::{DataClass, Principal};
use tokio::sync::mpsc;

// ---- test doubles ----

struct MockProvider {
    id: String,
    eligible: Vec<DataClass>,
    canned: Vec<Event>,
    seen: Arc<Mutex<Option<String>>>,
}
impl MockProvider {
    fn new(
        id: &str,
        eligible: &[DataClass],
        canned: Vec<Event>,
    ) -> (Self, Arc<Mutex<Option<String>>>) {
        let seen = Arc::new(Mutex::new(None));
        (
            MockProvider {
                id: id.to_string(),
                eligible: eligible.to_vec(),
                canned,
                seen: seen.clone(),
            },
            seen,
        )
    }
}
impl Provider for MockProvider {
    fn id(&self) -> &str {
        &self.id
    }
    fn eligible(&self, dc: DataClass) -> bool {
        self.eligible.contains(&dc)
    }
    fn stream(&self, prompt: &str) -> mpsc::Receiver<Event> {
        *self.seen.lock().unwrap() = Some(prompt.to_string());
        let (tx, rx) = mpsc::channel(64);
        let canned = self.canned.clone();
        tokio::spawn(async move {
            for e in canned {
                if tx.send(e).await.is_err() {
                    break;
                }
            }
        });
        rx
    }
}

#[derive(Clone, Default)]
struct SharedAudit(Arc<Mutex<Vec<AuditRecord>>>);
impl AuditSink for SharedAudit {
    fn record(&self, rec: AuditRecord) {
        self.0.lock().unwrap().push(rec);
    }
}

const ALL: &[DataClass] = &[
    DataClass::Public,
    DataClass::Internal,
    DataClass::Confidential,
    DataClass::RegulatedPayment,
    DataClass::Pii,
];

fn engine(router: ModelRouter, audit: SharedAudit) -> Engine {
    Engine::new(
        Box::new(RedactAndProceed),
        Box::new(RbacAuthorizer),
        Box::new(audit),
        router,
    )
}

// ---- tests ----

#[tokio::test]
async fn happy_chat_streams_and_audits() {
    let (p, _seen) = MockProvider::new(
        "mock",
        ALL,
        vec![Event::TextDelta("hello".into()), Event::Done],
    );
    let mut router = ModelRouter::new();
    router.register(Box::new(p));
    let audit = SharedAudit::default();
    let eng = engine(router, audit.clone());

    let out = eng
        .run_turn_collect(
            &Principal::user("u", &["chat.send"]),
            &Request::chat("s", "t", "hi", DataClass::Public),
        )
        .await
        .expect("turn ok");

    assert_eq!(out.final_text, "hello");
    assert_eq!(out.provider, "mock");
    assert!(out.events.contains(&Event::Done));
    assert_eq!(
        audit.0.lock().unwrap().len(),
        1,
        "audit must record every turn"
    );
}

#[tokio::test]
async fn compliance_redacts_input_before_provider_sees_it() {
    let (p, seen) = MockProvider::new("mock", ALL, vec![Event::Done]);
    let mut router = ModelRouter::new();
    router.register(Box::new(p));
    let eng = engine(router, SharedAudit::default());

    eng.run_turn_collect(
        &Principal::user("u", &["chat.send"]),
        &Request::chat(
            "s",
            "t",
            "my card 4111111111111111 ok",
            DataClass::Confidential,
        ),
    )
    .await
    .unwrap();

    let prompt = seen.lock().unwrap().clone().unwrap();
    assert!(
        prompt.contains("[REDACTED-PAN]"),
        "PAN must be redacted IN: {prompt}"
    );
    assert!(
        !prompt.contains("4111111111111111"),
        "raw PAN must not reach provider"
    );
}

#[tokio::test]
async fn compliance_redacts_model_output() {
    let (p, _seen) = MockProvider::new(
        "mock",
        ALL,
        vec![
            Event::TextDelta("num 4111111111111111 PAN=999888777666".into()),
            Event::Done,
        ],
    );
    let mut router = ModelRouter::new();
    router.register(Box::new(p));
    let eng = engine(router, SharedAudit::default());

    let out = eng
        .run_turn_collect(
            &Principal::user("u", &["chat.send"]),
            &Request::chat("s", "t", "x", DataClass::Public),
        )
        .await
        .unwrap();

    assert!(
        !out.final_text.contains("4111111111111111"),
        "PAN leaked OUT: {}",
        out.final_text
    );
    assert!(
        !out.final_text.contains("PAN="),
        "PAN marker leaked OUT: {}",
        out.final_text
    );
    assert!(out.redactions >= 1);
}

#[tokio::test]
async fn authz_denies_without_capability_and_never_calls_provider() {
    let (p, seen) = MockProvider::new("mock", ALL, vec![Event::Done]);
    let mut router = ModelRouter::new();
    router.register(Box::new(p));
    let eng = engine(router, SharedAudit::default());

    let err = eng
        .run_turn_collect(
            &Principal::user("u", &[]),
            &Request::chat("s", "t", "hi", DataClass::Public),
        )
        .await
        .unwrap_err();

    assert!(matches!(err, TurnError::Denied(_)));
    assert!(
        seen.lock().unwrap().is_none(),
        "provider must NOT be called when authz denies"
    );
}

#[tokio::test]
async fn regulated_data_never_routes_to_a_cloud_provider() {
    let (cloud, _c) = MockProvider::new(
        "cloud",
        &[DataClass::Public, DataClass::Internal],
        vec![Event::Done],
    );
    let (local, _l) = MockProvider::new(
        "local",
        ALL,
        vec![Event::TextDelta("ok".into()), Event::Done],
    );
    let mut router = ModelRouter::new();
    router.register(Box::new(cloud));
    router.register(Box::new(local));
    let eng = engine(router, SharedAudit::default());

    let out = eng
        .run_turn_collect(
            &Principal::user("u", &["chat.send"]),
            &Request::chat("s", "t", "settlement query", DataClass::RegulatedPayment),
        )
        .await
        .unwrap();
    assert_eq!(
        out.provider, "local",
        "regulated data must route in-house, never to cloud"
    );
}

#[tokio::test]
async fn forcing_a_cloud_provider_for_regulated_data_is_refused() {
    let mut router = ModelRouter::new();
    let (cloud, _c) = MockProvider::new("cloud", &[DataClass::Public], vec![Event::Done]);
    let (local, _l) = MockProvider::new("local", ALL, vec![Event::Done]);
    router.register(Box::new(cloud));
    router.register(Box::new(local));
    let eng = engine(router, SharedAudit::default());

    let mut req = Request::chat("s", "t", "x", DataClass::RegulatedPayment);
    req.forced_provider = Some("cloud".into());

    let err = eng
        .run_turn_collect(&Principal::user("u", &["chat.send"]), &req)
        .await
        .unwrap_err();
    assert_eq!(
        err,
        TurnError::Routing(RouteError::ForcedNotEligible(
            "cloud".into(),
            DataClass::RegulatedPayment
        )),
        "the data-class gate is non-overridable even by an explicit forced provider"
    );
}

#[tokio::test]
async fn no_eligible_provider_errors_rather_than_falling_back() {
    let mut router = ModelRouter::new();
    let (cloud, _c) = MockProvider::new(
        "cloud",
        &[DataClass::Public, DataClass::Internal],
        vec![Event::Done],
    );
    router.register(Box::new(cloud));
    let eng = engine(router, SharedAudit::default());

    let err = eng
        .run_turn_collect(
            &Principal::user("u", &["chat.send"]),
            &Request::chat("s", "t", "x", DataClass::Pii),
        )
        .await
        .unwrap_err();
    assert_eq!(
        err,
        TurnError::Routing(RouteError::NoEligible(DataClass::Pii))
    );
}
