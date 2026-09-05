// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! GAP5 regulated-fi-responsible-lifecycle #1 — served-path proving test for the outsourcing-register
//! admin write, driven through the DAEMON'S OWN composed router.
//!
//! The mechanism (`POST /admin/outsourcing/register` at `ainxt-server/src/lib.rs` sharing the live
//! `Arc<RwLock<OutsourcingRegister>>` handle with the router's own FI-03 eligibility gate) was already
//! wired and covered by two existing tests:
//!   * `ainxt-runtime`'s `r_outsourcing_register_shared_handle.rs` / `wire2_fi_03_test.rs` — drive a
//!     HAND-BUILT `ModelRouter`/`Engine` directly (no HTTP, no served composition root at all).
//!   * `ainxt-server`'s own inline `#[cfg(test)]` — a real HTTP round-trip, but still over a
//!     hand-built `ModelRouter` + `SessionManager` the test assembles itself and feeds into
//!     `app_full_ext` — never through `ainxt-runtimed`'s composition root.
//!
//! Neither exercises the function the shipped daemon's `--surface` dispatch table actually calls
//! (`ainxt_runtimed::assemble_selected` at `ainxt-runtimed/src/lib.rs` ~2892, which `main.rs` drives via
//! `assemble_selected_governed` -> `assemble_full_with_control_plane` -> `AssembledFull::to_full_app`/
//! `to_full_app_ext` -> `ainxt_server::serve_full_ext` — the EXACT chain below). This test proves the
//! admin write is visible on THAT composed router, over a real HTTP round-trip, with a real (mocked,
//! loopback) cloud provider actually contacted once eligible — closing the "test gap, not a wiring gap"
//! the audit called out.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener as StdTcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ainxt_responsibleai::outsourcing::derive_route_id;
use ainxt_runtimed::{assemble_full, assemble_selected, load_layered};

/// A minimal raw-socket mock server speaking just enough of the Anthropic Messages (`/v1/messages`)
/// streaming schema for `ainxt_providers::AnthropicProvider` (the REAL adapter the daemon's
/// `build_provider` wires for a `kind = "anthropic"` entry) to parse a genuine SSE response. Plain `std`
/// blocking sockets on a dedicated OS thread — no axum/mockito dev-dependency, no network egress
/// (127.0.0.1 loopback only), no tokio feature-flag surface to worry about.
///
/// Deliberately Anthropic, not OpenAI-schema: `build_chat_classifier_model` (the Stage-2 intent
/// classifier wiring) picks up the FIRST `open-ai-schema`/`local` provider with a base_url + key and
/// calls it directly for EVERY turn's classification step — a path that bypasses the Model Router (and
/// therefore the FI-03 outsourcing register) entirely. An `anthropic`-kind provider is invisible to that
/// classifier match (it only matches `OpenAiSchema | Local`), so the ONLY caller that can ever reach
/// this mock is the router's real, outsourcing-register-gated generation call — exactly what this test
/// needs to isolate.
fn spawn_mock_anthropic_server(reply_text: &'static str) -> (String, Arc<AtomicBool>) {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind mock server");
    let addr = listener.local_addr().expect("mock server addr");
    let called = Arc::new(AtomicBool::new(false));
    let called_for_thread = called.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut socket = match stream {
                Ok(s) => s,
                Err(_) => continue,
            };
            called_for_thread.store(true, Ordering::SeqCst);
            let mut buf = [0u8; 4096];
            let mut received = Vec::new();
            // Drain until the end of the request headers; the small JSON body typically arrives in the
            // same read over loopback, but we don't need to parse it at all to answer.
            loop {
                match socket.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        received.extend_from_slice(&buf[..n]);
                        if received.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let sse = format!(
                "data: {{\"type\":\"content_block_delta\",\"delta\":{{\"type\":\"text_delta\",\"text\":\"{reply_text}\"}}}}\n\n\
                 data: {{\"type\":\"message_stop\"}}\n\n"
            );
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                sse.len(),
                sse
            );
            let _ = socket.write_all(response.as_bytes());
            let _ = socket.shutdown(Shutdown::Both);
        }
    });
    (format!("http://{addr}"), called)
}

/// Build a `LoadedConfig` wiring a single CLOUD-kind (`anthropic`) provider at `base_url` — never
/// exempt from the FI-03 outsourcing register (only `offline`/`local` are, per `in_house_exemptions`),
/// and invisible to the Stage-2 classifier's `open-ai-schema`/`local`-only match (see
/// `spawn_mock_anthropic_server`'s doc) — over a unique per-test event-log dir (mirrors
/// `r15_compose_wiring.rs`'s `loaded_with_unique_log`).
/// Reconstruct the assistant's fully-streamed reply text by concatenating every `text.delta` wire
/// event's `text` field, in emission order, from a raw `/v1/chat` SSE response body. The daemon's own
/// streaming-redaction carry (`ainxt-server/src/lib.rs`, "streaming-redaction carry") may split a
/// single upstream provider delta into several `text.delta` wire events at arbitrary byte boundaries —
/// asserting on a bare contiguous substring of the raw SSE body is WRONG (it depends on an
/// implementation-detail chunk boundary that has nothing to do with what this test is proving) and a
/// naive version of this test caught exactly that false negative: the mock's single upstream delta
/// `"served-by-daemons-own-router"` was actually split into two wire events (`"served-by-daemons-own-"`
/// then `"router"`) before ever reaching this client.
fn concat_text_deltas(body: &str) -> String {
    let mut out = String::new();
    for line in body.lines() {
        let Some(json_str) = line.strip_prefix("data: ") else {
            continue;
        };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(json_str) else {
            continue;
        };
        if v.get("type").and_then(|t| t.as_str()) == Some("text.delta") {
            if let Some(t) = v.get("text").and_then(|t| t.as_str()) {
                out.push_str(t);
            }
        }
    }
    out
}

fn loaded_with_cloud_provider(base_url: &str) -> ainxt_runtimed::LoadedConfig {
    // R16 critical: the daemon refuses the header-trusting default authenticator unless the deployment
    // states the assumption (see r10_breach_clock_unit.rs) — state it here, exactly as every other
    // served-HTTP test in this crate does.
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    // The adapter factory only wires an `Anthropic` provider when a non-empty key is present
    // (`build_provider`); the mock server never checks it.
    std::env::set_var("ANTHROPIC_API_KEY", "test-key-not-real");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("ainxt-gap5-regfi-{nanos}"));
    let src = format!(
        "version = 1\n\
         [server]\n\
         event_log_dir = {:?}\n\
         [[models.providers]]\n\
         id = \"acme-cloud\"\n\
         kind = \"anthropic\"\n\
         base_url = {:?}\n\
         eligible = [\"internal\"]\n",
        dir.to_string_lossy(),
        base_url,
    );
    load_layered(&[("gap5-regfi", &src)]).expect("load config with a cloud provider")
}

/// Read an SSE body to its terminal event, bounded by an idle deadline.
///
/// `Response::text()` waits for the server to CLOSE the connection. For a
/// streaming endpoint that is not the same as "the turn finished", and when the
/// stream stayed open this test hung forever. Reading to the terminal event
/// instead is both correct for SSE and diagnosable: on timeout it reports what
/// actually arrived rather than nothing at all.
async fn read_sse(mut resp: reqwest::Response) -> String {
    let mut body = String::new();
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(remaining, resp.chunk()).await {
            Ok(Ok(Some(chunk))) => {
                body.push_str(&String::from_utf8_lossy(&chunk));
                // Terminal events of the wire protocol.
                if body.contains("\"type\":\"turn.completed\"")
                    || body.contains("\"type\":\"turn.failed\"")
                    || body.contains("data: \"Done\"")
                {
                    return body;
                }
            }
            Ok(Ok(None)) => return body, // server closed: end of stream
            Ok(Err(e)) => panic!("SSE stream error after {body:?}: {e}"),
            Err(_) => break,             // idle deadline
        }
    }
    panic!(
        "SSE stream produced no terminal event within 15s. Received {} byte(s):\n{}",
        body.len(),
        body
    )
}

/// Block until the spawned server is actually answering, or fail with a clear
/// message.
///
/// `tokio::spawn(serve_...)` returns immediately; the listener is bound but
/// nothing has called `accept()` until the task is first polled. Any request
/// issued before that sits in the accept backlog. Usually the task is polled
/// within microseconds, which is why this raced only intermittently -- and an
/// intermittent infinite hang is worse than a consistent failure, because it
/// stalls CI with nothing to attribute it to.
///
/// Any HTTP response proves the server is up; the status is irrelevant here.
async fn wait_until_serving(client: &reqwest::Client, base: &str) {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut last: Option<String> = None;
    while Instant::now() < deadline {
        match client
            .get(format!("{base}/"))
            .timeout(Duration::from_secs(2))
            .send()
            .await
        {
            Ok(_) => return,
            Err(e) => last = Some(e.to_string()),
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!(
        "daemon at {base} never began serving within 20s; last error: {}",
        last.unwrap_or_else(|| "none".into())
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_outsourcing_write_reaches_the_daemons_own_composed_router() {
    let (base_url, provider_called) = spawn_mock_anthropic_server("served-by-daemons-own-router");
    let loaded = loaded_with_cloud_provider(&base_url);

    // The SAME composition-root dispatch `main.rs`'s `--surface` table drives
    // (`assemble_selected` at ainxt-runtimed/src/lib.rs ~2892) — NOT a hand-built `ModelRouter` like
    // `wire2_fi_03_test.rs`/`r_outsourcing_register_shared_handle.rs` use.
    let assembled =
        assemble_selected(&loaded, "chat").expect("assemble_selected(loaded, \"chat\")");
    let full = assemble_full(&loaded, assembled).expect("assemble_full");
    assert_eq!(
        full.outsourcing_residency, "in",
        "default residency is India"
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind daemon listener");
    let daemon_addr = listener.local_addr().expect("daemon addr");
    // The EXACT call `main.rs` makes to serve the assembled daemon:
    // `ainxt_server::serve_full_ext(listener, full.to_full_app(), full.to_full_app_ext())`.
    tokio::spawn(ainxt_server::serve_full_ext(
        listener,
        full.to_full_app(),
        full.to_full_app_ext(),
    ));
    let base = format!("http://{daemon_addr}");
    // A timeout is not optional here. `serve_full_ext` is SPAWNED, so binding the
    // listener (which already happened above) is not the same as the server
    // accepting: a connect succeeds against the kernel backlog whether or not the
    // serve task has been polled. With `reqwest::Client::new()` -- no timeout --
    // a server that never accepts, or a spawned task that ended early, turns this
    // test into an INFINITE HANG rather than a failure. Measured: 2 hangs in 5
    // runs of this binary in isolation; in a workspace run it stalls the whole
    // suite with no output and no failing test to point at.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("build http client");
    wait_until_serving(&client, &base).await;

    // The router derives this route id AUTHORITATIVELY (`derive_route_id`, ADR-012/FI-03 §3.2) — it is
    // never taken from the provider adapter's own (possibly absent) self-declaration.
    let route_id = derive_route_id("acme-cloud");

    // 1. BEFORE the admin write: the cloud route is external-by-construction with no register entry yet
    // -> excluded before ranking/failover, on the daemon's OWN composed router. The mock provider must
    // never be contacted.
    let before = client
        .post(format!("{base}/v1/chat"))
        .header("x-ainxt-user", "alice")
        .header("x-ainxt-caps", "chat.send")
        // The shipped "chat" surface profile is department-scoped (RLS row isolation); a principal
        // with no department is refused BEFORE the router even runs (`BindingError::DepartmentRequired`)
        // — orthogonal to the FI-03 gate this test exercises, so it must not be the reason either
        // `/v1/chat` call below is excluded.
        .header("x-ainxt-department", "engineering")
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(
            serde_json::json!({
                "session": "s-regfi-1", "turn": "t1", "input": "hi", "data_class": "internal"
            })
            .to_string(),
        )
        .send()
        .await
        .expect("before send");
    assert!(
        before.status().is_success(),
        "the SSE endpoint itself must still accept the request"
    );
    let before_body = read_sse(before).await;
    assert!(
        !concat_text_deltas(&before_body).contains("served-by-daemons-own-router"),
        "an unregistered outsourced route must stay excluded on the daemon's OWN composed router: \
         {before_body}"
    );
    assert!(
        !before_body.contains("department"),
        "the exclusion must be the FI-03 outsourcing gate, not an unrelated department-scoping \
         refusal: {before_body}"
    );
    assert!(
        !provider_called.load(Ordering::SeqCst),
        "the ungoverned route must never be contacted before the admin write"
    );

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let register_body = serde_json::json!({
        "id": route_id,
        "provider_legal_entity": "ACME Cloud Pvt Ltd",
        "permitted_data_class": "internal",
        "data_residency": "in",
        "sub_processors": [],
        "exit_plan_ref": "exit-plan-ref",
        "concentration_tag": "chat-inference",
        "last_exit_rehearsal": {"kind": "at", "tick": now},
        "contract_ref": "contract-1",
        "board_approval_ref": "board-pr-42",
    });

    // 2. A non-admin caller is refused (403) — registering governance is not routine traffic.
    let denied = client
        .post(format!("{base}/admin/outsourcing/register"))
        .header("x-ainxt-user", "alice")
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(register_body.to_string())
        .send()
        .await
        .expect("denied send");
    assert_eq!(
        denied.status().as_u16(),
        403,
        "a non-admin must be refused the admin route"
    );

    // 3. The admin registers the board-approved arrangement over the daemon's REAL admin route
    // (`POST /admin/outsourcing/register`, mounted on the SAME router this test's `/v1/chat` calls hit).
    let registered = client
        .post(format!("{base}/admin/outsourcing/register"))
        .header("x-ainxt-user", "root")
        .header("x-ainxt-role", "admin")
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(register_body.to_string())
        .send()
        .await
        .expect("register send");
    assert_eq!(
        registered.status().as_u16(),
        200,
        "an admin write must succeed"
    );
    let registered_json: serde_json::Value =
        serde_json::from_str(&registered.text().await.expect("registered body")).expect("json");
    assert_eq!(registered_json["registered"], route_id);

    // 4. The VERY NEXT served `/v1/chat` turn, on the SAME running daemon — its OWN composed router,
    // built via `assemble_selected` -> `assemble_full` -> `to_full_app`/`to_full_app_ext` ->
    // `serve_full_ext`, exactly `main.rs`'s call chain — now finds the route eligible and actually
    // reaches the real (mocked, loopback) provider over HTTP, proving the admin write landed on the
    // IDENTICAL live register the router's hot-path eligibility check reads.
    let after = client
        .post(format!("{base}/v1/chat"))
        .header("x-ainxt-user", "alice")
        .header("x-ainxt-caps", "chat.send")
        .header("x-ainxt-department", "engineering")
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(
            serde_json::json!({
                "session": "s-regfi-2", "turn": "t2", "input": "hi", "data_class": "internal"
            })
            .to_string(),
        )
        .send()
        .await
        .expect("after send");
    assert!(after.status().is_success());
    let after_body = read_sse(after).await;
    assert!(
        concat_text_deltas(&after_body).contains("served-by-daemons-own-router"),
        "the now-eligible outsourced route must serve through the daemon's own composed router: \
         {after_body}"
    );
    assert!(
        after_body.contains("\"model\":\"acme-cloud\""),
        "the turn.rationale event must name the newly-registered outsourced provider as the model \
         that actually served the turn: {after_body}"
    );
    assert!(
        provider_called.load(Ordering::SeqCst),
        "the newly-eligible provider must actually be contacted over HTTP"
    );
}
