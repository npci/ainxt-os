// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! P4-EXIT DoD acceptance matrix — drive the client layer (Rust SDK + headless CLI + protocol
//! versioning) through the scenario harness across the P4 acceptance categories, with layered
//! oracles + JUnit. Scenarios cover SDK chat + backpressure, the CLI's headless output modes / stdin
//! / exit codes, and protocol backward-compat across a version bump. All run offline (no network to
//! any real model provider) — but the CLI-* scenarios drive `run_cli`'s REAL `/v1/chat` HTTP/SSE
//! path, so a real (loopback-only, `OfflineProvider`-backed) daemon is served for the duration of
//! the test and `AINXT_RUNTIME_URL` is pointed at it, rather than asserting against a daemon that
//! was never started.

use ainxt_cli::{run_cli, OfflineProvider, EXIT_OK, EXIT_USAGE};
use ainxt_client::{Client, ClientConfig, ClientError};
use ainxt_protocol::{is_compatible, Event, Request, VERSION};
use ainxt_runtime::engine_with_defaults;
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_scenario::{Category, Expectation, Observation, Runner, Scenario, Target};
use ainxt_session::{SessionConfig, SessionManager};
use ainxt_types::{DataClass, Principal};
use std::sync::Arc;
use tokio::sync::mpsc;

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

fn args(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}

/// Never produces output — occupies a session so the global cap can be hit.
struct BlockProvider;
impl Provider for BlockProvider {
    fn id(&self) -> &str {
        "block"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, _prompt: &str) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(8);
        tokio::spawn(async move {
            let _hold = tx;
            std::future::pending::<()>().await;
        });
        rx
    }
}

fn offline_client() -> Client {
    let mut router = ModelRouter::new();
    router.register(Box::new(OfflineProvider));
    let manager = Arc::new(SessionManager::new(
        Arc::new(engine_with_defaults(router)),
        SessionConfig::default(),
    ));
    Client::in_process(
        manager,
        Principal::user("u", &["chat.send"]),
        ClientConfig::default(),
    )
}

/// Serve a REAL offline daemon (the SAME `OfflineProvider`-backed engine `offline_client()` drives
/// in-process) on an ephemeral loopback port, and return its bound address. `run_cli`'s `run`
/// subcommand always speaks real HTTP/SSE to `AINXT_RUNTIME_URL` — this gives the CLI-* scenarios a
/// real peer to speak it to. Uses the FULLY-WIRED transport ([`ainxt_server::app_full`]), not the
/// legacy [`ainxt_server::app`]: `run_cli` decodes the tagged `WireEvent` envelope, which only the
/// fully-wired path emits (the legacy path emits the older bare `Event` shape).
async fn serve_offline_daemon() -> std::net::SocketAddr {
    let mut router = ModelRouter::new();
    router.register(Box::new(OfflineProvider));
    let manager = Arc::new(SessionManager::new(
        Arc::new(engine_with_defaults(router)),
        SessionConfig::default(),
    ));
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let log_dir = std::env::temp_dir().join(format!("ainxt-cli-dod-p4-{nanos}"));
    let event_log: Arc<dyn ainxt_eventlog::EventLog> =
        Arc::new(ainxt_eventlog::JsonlEventLog::open(log_dir).expect("open log"));
    let cfg = ainxt_server::FullApp {
        manager,
        auth: Arc::new(ainxt_server::TrustedGatewayAuth),
        event_log,
        control_plane_sha: "dod-p4-matrix-test".to_string(),
        serving: None,
        graph: None,
        ledger_schema: None,
        harness: None,
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(ainxt_server::serve_full(listener, cfg));
    addr
}

fn block_client() -> Client {
    let mut router = ModelRouter::new();
    router.register(Box::new(BlockProvider));
    let cfg = SessionConfig {
        max_sessions: 1,
        ..Default::default()
    };
    let manager = Arc::new(SessionManager::new(
        Arc::new(engine_with_defaults(router)),
        cfg,
    ));
    Client::in_process(
        manager,
        Principal::user("u", &["chat.send"]),
        ClientConfig::default(),
    )
}

struct P4DodTarget {
    rt: tokio::runtime::Runtime,
}

impl Target for P4DodTarget {
    fn run(&self, s: &Scenario) -> Observation {
        match s.id.as_str() {
            "SDK-CHAT-001" => self.rt.block_on(async {
                let out = offline_client()
                    .chat("s", "t", "hi")
                    .unwrap()
                    .collect()
                    .await;
                ok(format!(
                    "sdk-chat completed={} text={}",
                    out.completed, out.text
                ))
            }),
            "SDK-BACKPRESSURE-001" => self.rt.block_on(async {
                let client = block_client();
                let _a = client.chat("A", "t", "hi").unwrap(); // occupies the only slot (hangs)
                match client.chat("B", "t", "hi") {
                    Err(ClientError::Backpressure(_)) => {
                        err("backpressure: second session shed".into())
                    }
                    // NOTE: this failure message must NOT contain the token "backpressure" — the
                    // oracle checks must_error_contains(["backpressure"]), so a broken load-shedder
                    // that served the 2nd session has to produce a message the oracle REJECTS.
                    _ => err("load-shedding FAILED: a session past the cap was served".into()),
                }
            }),
            "CLI-PRINT-001" => self.rt.block_on(async {
                let mut buf = Vec::new();
                let code = run_cli(&args(&["run", "hi"]), "", &mut buf).await;
                let s = String::from_utf8_lossy(&buf);
                ok(format!(
                    "cli-print exit={code} has-text={}",
                    s.contains("offline mode")
                ))
            }),
            "CLI-JSON-001" => self.rt.block_on(async {
                let mut buf = Vec::new();
                let code = run_cli(&args(&["run", "--json", "hi"]), "", &mut buf).await;
                let s = String::from_utf8_lossy(&buf).into_owned();
                let done = s.lines().any(|l| l == "\"Done\"");
                let valid = s
                    .lines()
                    .filter(|l| !l.is_empty())
                    .all(|l| serde_json::from_str::<serde_json::Value>(l).is_ok());
                ok(format!(
                    "cli-json exit={code} done={done} valid-ndjson={valid}"
                ))
            }),
            "CLI-STDIN-001" => self.rt.block_on(async {
                let mut buf = Vec::new();
                let code = run_cli(&args(&["run"]), "piped question\n", &mut buf).await;
                ok(format!(
                    "cli-stdin exit={code} produced={}",
                    !buf.is_empty()
                ))
            }),
            "CLI-USAGE-001" => self.rt.block_on(async {
                let mut buf = Vec::new();
                let code = run_cli(&args(&["run", "--bogus"]), "", &mut buf).await;
                ok(format!("cli-usage exit={code}"))
            }),
            "PROTO-COMPAT-001" => {
                let newer = r#"{"session":"s","turn":"t","input":"hi","data_class":"internal","tier":"simple","forced_provider":null,"untrusted_tainted":false,"future_field":true}"#;
                let additive_ok = serde_json::from_str::<Request>(newer).is_ok();
                ok(format!(
                    "proto additive-ok={additive_ok} compat={}",
                    is_compatible(VERSION, VERSION)
                ))
            }
            // A major gap beyond the N-2 support window (client 1 vs server 4) is incompatible.
            "PROTO-BUMP-001" => ok(format!("proto-bump compatible={}", is_compatible(1, 4))),
            other => err(format!("unknown scenario {other}")),
        }
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
            "SDK-CHAT-001",
            "SDK chat streams and collects a completed turn",
            Category::Custom,
            "sdk",
            contains(&["completed=true", "offline mode"]),
        ),
        Scenario::new(
            "SDK-BACKPRESSURE-001",
            "SDK surfaces backpressure as a typed error under the session cap",
            Category::Backpressure,
            "sdk-bp",
            Expectation {
                must_complete: false,
                must_error_contains: vec!["backpressure".into()],
                ..Default::default()
            },
        ),
        Scenario::new(
            "CLI-PRINT-001",
            "CLI --print returns the final text with exit 0",
            Category::Custom,
            "cli",
            contains(&["exit=0", "has-text=true"]),
        ),
        Scenario::new(
            "CLI-JSON-001",
            "CLI --json emits valid NDJSON ending in Done, exit 0",
            Category::Custom,
            "cli",
            contains(&["exit=0", "done=true", "valid-ndjson=true"]),
        ),
        Scenario::new(
            "CLI-STDIN-001",
            "CLI reads the turn from stdin, exit 0",
            Category::Custom,
            "cli",
            contains(&["exit=0", "produced=true"]),
        ),
        Scenario::new(
            "CLI-USAGE-001",
            "CLI returns a distinct usage exit code on bad args",
            Category::Custom,
            "cli",
            contains(&[&format!("exit={EXIT_USAGE}")]),
        ),
        Scenario::new(
            "PROTO-COMPAT-001",
            "an additive field from a newer peer is ignored (backward-compat)",
            Category::Custom,
            "proto",
            contains(&["additive-ok=true", "compat=true"]),
        ),
        Scenario::new(
            "PROTO-BUMP-001",
            "a major protocol bump beyond the N-2 support window is detected as incompatible",
            Category::Custom,
            "proto",
            contains(&["compatible=false"]),
        ),
    ]
}

#[test]
fn p4_exit_acceptance_matrix_is_green() {
    // Assert the exit-code contract the CLI scenarios rely on.
    assert_eq!(EXIT_OK, 0);
    assert_eq!(EXIT_USAGE, 2);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("rt");
    let addr = rt.block_on(serve_offline_daemon());
    std::env::set_var("AINXT_RUNTIME_URL", format!("http://{addr}/v1/chat"));

    let target = P4DodTarget { rt };
    let report = Runner::with_default_oracles().run(&matrix(), &target);
    eprintln!("{}", report.summary());
    assert!(
        report.junit_xml().contains("<testsuite"),
        "JUnit report is produced for CI"
    );
    assert!(
        report.all_passed(),
        "P4 acceptance matrix must be green:\n{}",
        report.summary()
    );
    assert!(
        report.coverage().len() >= 2,
        "matrix must cover >= 2 P4 categories (got {})",
        report.coverage().len()
    );
}
