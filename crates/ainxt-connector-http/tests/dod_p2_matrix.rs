// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! P2-EXIT DoD acceptance matrix — drive the assembled Connector Runtime through the scenario
//! harness across the Phase-2 acceptance categories, with layered oracles + JUnit for CI.
//!
//! Each scenario exercises one P2 exit criterion end-to-end against the real connector stack (mock
//! transport / mock IdP, per the P1 pattern — no network): OAuth authorization-code+PKCE E2E,
//! concurrent-refresh collapse (thundering herd → one call), key rotation, per-user isolation,
//! air-gap soft-degrade, org/dept policy deny, incremental consent, egress DLP, and the data-class
//! egress ceiling. Scenarios are written to fail-red if the invariant they name breaks.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Instant;

use ainxt_connector::{
    AllowAllPolicy, AuthKind, CapabilityConnectorAuthorizer, ConnectorDef, ConnectorPolicy,
    ConnectorRegistry, ConnectorRuntime, DeptRuleTable, InMemoryConnectorAudit, MarkerEgressGuard,
};
use ainxt_connector_http::{
    ConnectorCallError, ConnectorInvoker, GitLab, Graph, HttpRefreshExecutor, HttpResponse,
    StaticTokenSource, StubTransport, TransportError,
};
use ainxt_oauth::{OAuthProvider, TokenRequest, TokenSet};
use ainxt_refresh::{InMemoryRefreshLock, RefreshCoordinator, RefreshExecutor};
use ainxt_scenario::{Category, Expectation, Observation, Runner, Scenario, Target};
use ainxt_token::{AeadCodec, InMemoryTokenStore, KeyRing, SecretCodec, TokenVault};
use ainxt_types::{DataClass, Principal};

const NOW: u64 = 1_000_000;

fn provider() -> OAuthProvider {
    OAuthProvider {
        authorize_endpoint: "https://idp.example.invalid/authorize".into(),
        token_endpoint: "https://idp.example.invalid/token".into(),
        client_id: "client-1".into(),
        redirect_uri: "https://app.example.invalid/cb".into(),
        scopes: vec![],
    }
}

fn registry() -> ConnectorRegistry {
    let mut r = ConnectorRegistry::new();
    r.register(
        ConnectorDef::new("gitlab", "GitLab", AuthKind::ApiToken)
            .with_max_egress_class(DataClass::Internal),
    );
    r.register(
        ConnectorDef::new("graph", "Graph", AuthKind::OAuth2AuthCode)
            .with_max_egress_class(DataClass::Confidential),
    );
    r
}

fn runtime(policy: Box<dyn ConnectorPolicy>) -> Arc<ConnectorRuntime> {
    Arc::new(ConnectorRuntime::new(
        registry(),
        policy,
        Box::new(CapabilityConnectorAuthorizer),
        Box::new(MarkerEgressGuard),
        Box::new(InMemoryConnectorAudit::new()),
    ))
}

fn vault(key: u8) -> TokenVault {
    TokenVault::new(
        Box::new(AeadCodec::new(KeyRing::new(1, [key; 32]))),
        Box::new(InMemoryTokenStore::new()),
    )
}

/// Executor that counts network refreshes and returns a fresh 1h token.
struct CountingExecutor {
    calls: Arc<AtomicU32>,
}
impl RefreshExecutor for CountingExecutor {
    fn execute(&self, _r: &TokenRequest) -> Result<TokenSet, String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(TokenSet {
            access_token: "NEW".into(),
            refresh_token: Some("R2".into()),
            expires_in: Some(3600),
            scope: vec![],
            token_type: "Bearer".into(),
        })
    }
}

fn ok(output: String) -> Observation {
    Observation {
        output,
        error: None,
        side_effects: Vec::new(),
        latency_ms: 0,
    }
}
fn err(message: String) -> Observation {
    Observation {
        output: String::new(),
        error: Some(message),
        side_effects: Vec::new(),
        latency_ms: 0,
    }
}

struct P2DodTarget;

impl Target for P2DodTarget {
    fn run(&self, s: &Scenario) -> Observation {
        let started = Instant::now();
        let mut obs = match s.id.as_str() {
            "OAUTH-E2E-001" => run_oauth_e2e(),
            "REFRESH-RACE-001" => run_refresh_race(),
            "ROTATE-001" => run_rotate(),
            "ISOLATION-001" => run_isolation(),
            "AIRGAP-001" => run_airgap(),
            "POLICY-DENY-001" => run_policy_deny(),
            "CONSENT-001" => run_consent(),
            "EGRESS-DLP-001" => run_egress_dlp(),
            "CEILING-001" => run_ceiling(),
            other => err(format!("unknown scenario {other}")),
        };
        obs.latency_ms = started.elapsed().as_millis() as u64;
        obs
    }
}

/// OAuth authorization-code + PKCE, end to end: begin → exchange (mock IdP) → store → load.
fn run_oauth_e2e() -> Observation {
    let p = provider();
    let start = ainxt_oauth::begin(&p, &["openid".into(), "offline_access".into()]);
    let pkce_s256 =
        start.url.contains("code_challenge_method=S256") && !start.pkce.challenge.is_empty();

    // Mock IdP returns a token for the code+verifier exchange.
    let stub = StubTransport::new();
    stub.push_response(HttpResponse::new(
        200,
        br#"{"access_token":"AT1","refresh_token":"RT1","expires_in":3600,"scope":"openid offline_access","token_type":"Bearer"}"#.to_vec(),
    ));
    let exec = HttpRefreshExecutor::new(Box::new(stub));
    let req = ainxt_oauth::exchange_code(&p, "auth-code", &start.pkce);
    let ts = match exec.execute(&req) {
        Ok(t) => t,
        Err(e) => return err(format!("exchange failed: {e}")),
    };

    // Persist encrypted, then read it back.
    let v = vault(1);
    let blob = serde_json::to_vec(&ts).unwrap();
    v.save("u", "graph", &blob, ts.expires_at(NOW), &ts.scope)
        .unwrap();
    let loaded: TokenSet = serde_json::from_slice(&v.load("u", "graph").unwrap().unwrap()).unwrap();

    ok(format!(
        "oauth-e2e S256={pkce_s256} access={} scopes={}",
        loaded.access_token,
        loaded.scope.join(",")
    ))
}

/// Thundering herd: many concurrent callers, one stale token → exactly one network refresh.
fn run_refresh_race() -> Observation {
    let v = vault(2);
    let seed = TokenSet {
        access_token: "OLD".into(),
        refresh_token: Some("R1".into()),
        expires_in: Some(0),
        scope: vec![],
        token_type: "Bearer".into(),
    };
    v.save(
        "u",
        "graph",
        &serde_json::to_vec(&seed).unwrap(),
        Some(NOW),
        &[],
    )
    .unwrap(); // due now

    let calls = Arc::new(AtomicU32::new(0));
    let coord = Arc::new(RefreshCoordinator::new(
        "graph",
        provider(),
        v,
        Box::new(InMemoryRefreshLock::new()),
        Box::new(CountingExecutor {
            calls: calls.clone(),
        }),
    ));

    let mut handles = Vec::new();
    for _ in 0..12 {
        let c = coord.clone();
        handles.push(std::thread::spawn(move || c.ensure_fresh("u", NOW)));
    }
    for h in handles {
        if let Err(e) = h.join().unwrap() {
            return err(format!("a concurrent refresh failed: {e}"));
        }
    }
    ok(format!("refreshes={}", calls.load(Ordering::SeqCst)))
}

/// Key rotation: seal under v1, rotate to v2 — the old record still opens, new records use v2.
fn run_rotate() -> Observation {
    let c1 = AeadCodec::new(KeyRing::new(1, [1u8; 32]));
    let sealed_v1 = c1.seal(b"legacy-token", b"u\0graph").unwrap();
    let c2 = AeadCodec::new(KeyRing::new(1, [1u8; 32]).rotate_to(2, [2u8; 32]));
    let old_ok = c2
        .open(&sealed_v1, b"u\0graph")
        .map(|p| p == b"legacy-token")
        .unwrap_or(false);
    let fresh = c2.seal(b"new-token", b"u\0graph").unwrap();
    ok(format!("rotation old-ok={old_ok} new-key={}", fresh.key_id))
}

/// Per-user isolation: one user's token is invisible to another; listings are per-user.
fn run_isolation() -> Observation {
    let v = vault(3);
    v.save("alice", "graph", b"ALICE-SECRET", None, &[])
        .unwrap();
    let alice_ok = v.load("alice", "graph").unwrap().as_deref() == Some(b"ALICE-SECRET".as_ref());
    let bob_empty = v.load("bob", "graph").unwrap().is_none();
    let bob_conns = v.connectors_for("bob").unwrap().len();
    ok(format!(
        "isolation alice-ok={alice_ok} bob-empty={bob_empty} bob-conns={bob_conns}"
    ))
}

/// Air-gap: an unreachable proxy is a soft-degrade, never a crash.
fn run_airgap() -> Observation {
    let stub = StubTransport::new();
    stub.push_error(TransportError::Unavailable("proxy unreachable".into()));
    let inv = ConnectorInvoker::new(
        runtime(Box::new(AllowAllPolicy)),
        Box::new(stub),
        Box::new(StaticTokenSource("T".into())),
    );
    let p = Principal::user("u", &["connector.graph"]);
    match inv.invoke(&p, NOW, DataClass::Internal, Graph::new().get_me()) {
        Err(e) if e.is_soft_degrade() => ok("air-gap soft-degrade handled".into()),
        Err(e) => err(format!("expected soft-degrade, got hard error: {e}")),
        Ok(_) => err("expected soft-degrade, call unexpectedly succeeded".into()),
    }
}

/// Org/dept policy deny: a disallowed department is refused before any network call.
fn run_policy_deny() -> Observation {
    let policy = DeptRuleTable::new().allow_dept("gitlab", "payments-eng");
    let stub = StubTransport::new();
    let inv = ConnectorInvoker::new(
        runtime(Box::new(policy)),
        Box::new(stub.clone()),
        Box::new(StaticTokenSource("T".into())),
    );
    let p = Principal::user("u", &["connector.gitlab"]).with_department("hr");
    match inv.invoke(
        &p,
        NOW,
        DataClass::Internal,
        GitLab::new("https://gl").get_project("g/r"),
    ) {
        Err(ConnectorCallError::Admission(e)) => err(format!("{e}; sent={}", stub.sent_count())),
        other => err(format!("expected admission denial, got {other:?}")),
    }
}

/// Incremental consent: a required scope not in the granted set is detected.
fn run_consent() -> Observation {
    let granted = vec!["openid".to_string()];
    let required = vec!["openid".to_string(), "Mail.Send".to_string()];
    let missing = ainxt_oauth::missing_scopes(&granted, &required);
    let needs = ainxt_oauth::needs_consent(&granted, &required);
    ok(format!(
        "consent-required={needs} missing={}",
        missing.join(",")
    ))
}

/// Egress DLP: a write body carrying secrets is redacted before it leaves.
fn run_egress_dlp() -> Observation {
    let stub = StubTransport::new();
    stub.push_response(HttpResponse::new(201, Vec::new()));
    let inv = ConnectorInvoker::new(
        runtime(Box::new(AllowAllPolicy)),
        Box::new(stub.clone()),
        Box::new(StaticTokenSource("T".into())),
    );
    let p = Principal::user("u", &["connector.gitlab"]);
    let note = GitLab::new("https://gl").post_mr_note(
        "g/r",
        1,
        "card 4111111111111111 SECRET=s3cr3t-v4lue",
    );
    match inv.invoke(&p, NOW, DataClass::Internal, note) {
        Ok(out) => {
            let sent = stub.sent();
            let body = sent[0]
                .body
                .as_ref()
                .map(|b| String::from_utf8_lossy(b).into_owned())
                .unwrap_or_default();
            ok(format!(
                "egress redactions={} body={body}",
                out.egress_redactions
            ))
        }
        Err(e) => err(format!("egress call failed: {e}")),
    }
}

/// Data-class ceiling: regulated data is refused egress to a cloud connector, and never sent.
fn run_ceiling() -> Observation {
    let stub = StubTransport::new();
    let inv = ConnectorInvoker::new(
        runtime(Box::new(AllowAllPolicy)),
        Box::new(stub.clone()),
        Box::new(StaticTokenSource("T".into())),
    );
    let p = Principal::user("u", &["connector.gitlab"]);
    let note = GitLab::new("https://gl").post_mr_note("g/r", 1, "settlement-secret");
    match inv.invoke(&p, NOW, DataClass::RegulatedPayment, note) {
        Err(ConnectorCallError::Egress(e)) => err(format!("{e}; sent={}", stub.sent_count())),
        other => err(format!("expected egress refusal, got {other:?}")),
    }
}

fn contains(cs: &[&str]) -> Expectation {
    Expectation {
        must_contain: cs.iter().map(|s| s.to_string()).collect(),
        must_complete: true,
        ..Default::default()
    }
}

fn matrix() -> Vec<Scenario> {
    vec![
        Scenario::new(
            "OAUTH-E2E-001",
            "authorization-code + PKCE end to end (mock IdP)",
            Category::Custom,
            "authorize graph",
            contains(&["S256=true", "access=AT1"]),
        ),
        Scenario::new(
            "REFRESH-RACE-001",
            "12 concurrent callers collapse to exactly one refresh",
            Category::Concurrency,
            "refresh under contention",
            contains(&["refreshes=1"]),
        ),
        Scenario::new(
            "ROTATE-001",
            "key rotation keeps old records readable, new records use the new key",
            Category::Custom,
            "rotate the key ring",
            contains(&["old-ok=true", "new-key=2"]),
        ),
        Scenario::new(
            "ISOLATION-001",
            "a user's token is structurally invisible to another user",
            Category::Custom,
            "cross-user access attempt",
            Expectation {
                must_contain: vec!["bob-empty=true".into(), "alice-ok=true".into()],
                must_complete: true,
                forbidden_leak_markers: vec!["ALICE-SECRET".into()],
                ..Default::default()
            },
        ),
        Scenario::new(
            "AIRGAP-001",
            "unreachable proxy degrades gracefully (no crash)",
            Category::AirGap,
            "connector call with no network",
            contains(&["soft-degrade"]),
        ),
        Scenario::new(
            "POLICY-DENY-001",
            "org/dept policy refuses the call before any network I/O",
            Category::RbacDeny,
            "disallowed department",
            Expectation {
                must_complete: false,
                must_error_contains: vec!["denied".into(), "sent=0".into()],
                ..Default::default()
            },
        ),
        Scenario::new(
            "CONSENT-001",
            "a missing required scope triggers incremental consent",
            Category::AuthExpiry,
            "operation needs Mail.Send",
            contains(&["consent-required=true", "Mail.Send"]),
        ),
        Scenario::new(
            "EGRESS-DLP-001",
            "secrets in an outbound write body are redacted",
            Category::ComplianceRedaction,
            "post a note containing a PAN and a secret",
            Expectation {
                must_contain: vec!["[REDACTED-PAN]".into()],
                must_complete: true,
                // The secret VALUE must never egress — not just the marker label.
                forbidden_leak_markers: vec!["4111111111111111".into(), "s3cr3t-v4lue".into()],
                ..Default::default()
            },
        ),
        Scenario::new(
            "CEILING-001",
            "regulated data is refused egress to a cloud connector and never sent",
            Category::DataClassLeak,
            "regulated write to a cloud connector",
            Expectation {
                must_complete: false,
                must_error_contains: vec!["egress".into(), "sent=0".into()],
                forbidden_leak_markers: vec!["settlement-secret".into()],
                ..Default::default()
            },
        ),
    ]
}

#[test]
fn p2_exit_acceptance_matrix_is_green() {
    let report = Runner::with_default_oracles().run(&matrix(), &P2DodTarget);
    eprintln!("{}", report.summary());
    assert!(
        report.junit_xml().contains("<testsuite"),
        "JUnit report is produced for CI"
    );
    assert!(
        report.all_passed(),
        "P2 acceptance matrix must be green:\n{}",
        report.summary()
    );
    assert!(
        report.coverage().len() >= 6,
        "matrix must cover >= 6 P2 categories (got {})",
        report.coverage().len()
    );
}
