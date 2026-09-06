// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! GAP6 telemetry-cost-rollup — served-path proving test for the cost-attribution/FinOps chargeback
//! mechanism, driven through the DAEMON'S OWN composed router.
//!
//! The audit found: `ainxt_telemetry::PriceTable`/`ModelPrice::cost_micros`/`TelemetryConfig::price_table`
//! and `CostRollup`/`InMemoryTelemetry::rollup`/`actors_by_cost`/`providers_by_cost` were fully
//! implemented and unit-tested, but every call anywhere in the workspace outside `ainxt-telemetry`'s own
//! tests was confined to `ainxt-server`'s OWN `#[cfg(test)]` module hand-building an `Engine` directly
//! via `engine_with_defaults(router).with_pricing(pricing)` — never through `ainxt-runtimed`'s
//! composition root (`build_engine_ext`/`build_chat_engine_with_authz`), which built every served
//! engine with `Engine::new`'s default EMPTY `PriceTable::new()` (every provider prices at 0,
//! regardless of real usage). This test drives the SAME chain `main.rs`'s `--surface` dispatch table
//! actually calls (`assemble_selected("chat")` -> `assemble_full` -> `to_full_app`/`to_full_app_ext` ->
//! `ainxt_server::serve_full_ext`, mirroring `gap5_regfi_outsourcing_admin_daemon_composed_router.rs`)
//! and proves, over a REAL HTTP round-trip against a REAL (mocked, loopback) cloud provider:
//!   1. a deployment-configured `[telemetry.pricing.<id>]` table is genuinely consulted when pricing a
//!      real turn's on-wire `usage.cost` (not the empty default, not a provider self-report);
//!   2. the shipped daemon's BUILT-IN reference price table (`ainxt_runtimed::default_price_table`)
//!      applies for a known canonical model id even with NO `[telemetry.pricing]` configured at all;
//!   3. the new `GET /admin/telemetry/cost-rollup` route — admin-gated, 403 otherwise — returns a real,
//!      non-empty actor/provider chargeback breakdown aggregated from real served turns, over the
//!      daemon's OWN live `InMemoryTelemetry`, not a second, disconnected aggregation;
//!   4. the route fails closed (404, never a fabricated empty breakdown) when the configured sink does
//!      not retain turns in-process (`sink = "otlp"`).
//!
//! Deliberately an `anthropic`-kind mock provider (mirroring
//! `gap5_regfi_outsourcing_admin_daemon_composed_router.rs`), not `open-ai-schema`/`local`: the "chat"
//! surface's Stage-2 intent classifier (`build_chat_classifier_model`) picks up the FIRST
//! `open-ai-schema`/`local` provider with a base_url + key and calls it DIRECTLY for every turn's
//! classification step, bypassing the Model Router entirely — an `open-ai-schema`/`local` mock here
//! would be silently hijacked as the classifier backend (and answer classification prompts with the
//! literal chat reply text this test expects on the wire, producing a spurious `ambiguous` clarify
//! instead of a routed turn). An `anthropic`-kind mock is invisible to that classifier match, so the
//! ONLY caller that can ever reach it is the router's real, priced generation call — exactly what this
//! test needs to isolate. Being a CLOUD kind, it is never FI-03-outsourcing-exempt, so each test first
//! registers the board-approved arrangement over the daemon's OWN `/admin/outsourcing/register` route
//! (the identical admin step `gap5_regfi_outsourcing_admin_daemon_composed_router.rs` performs) before
//! sending the turn that is actually priced/rolled-up.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener as StdTcpListener};
use std::time::{SystemTime, UNIX_EPOCH};

use ainxt_responsibleai::outsourcing::derive_route_id;
use ainxt_runtimed::{assemble_full, assemble_selected, load_layered};

/// A minimal raw-socket mock server speaking just enough of the Anthropic Messages streaming schema
/// (`message_start` with input usage, a text delta, `message_delta` with output usage, `message_stop`)
/// for `ainxt_providers::AnthropicProvider` — the REAL adapter the daemon's `build_provider` wires for a
/// `kind = "anthropic"` entry — to parse a genuine priced turn. Mirrors
/// `gap5_regfi_outsourcing_admin_daemon_composed_router.rs`'s mock server, extended with the
/// `usage`-bearing SSE fields that test left unset.
fn spawn_mock_anthropic_server(
    reply_text: &'static str,
    input_tokens: u64,
    output_tokens: u64,
) -> String {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind mock server");
    let addr = listener.local_addr().expect("mock server addr");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut socket = match stream {
                Ok(s) => s,
                Err(_) => continue,
            };
            let mut buf = [0u8; 4096];
            let mut received = Vec::new();
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
                "data: {{\"type\":\"message_start\",\"message\":{{\"id\":\"msg_1\",\"type\":\"message\",\
                 \"role\":\"assistant\",\"content\":[],\"stop_reason\":null,\
                 \"usage\":{{\"input_tokens\":{input_tokens},\"output_tokens\":0}}}}}}\n\n\
                 data: {{\"type\":\"content_block_delta\",\"delta\":{{\"type\":\"text_delta\",\"text\":\"{reply_text}\"}}}}\n\n\
                 data: {{\"type\":\"message_delta\",\"delta\":{{\"stop_reason\":\"end_turn\"}},\
                 \"usage\":{{\"output_tokens\":{output_tokens}}}}}\n\n\
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
    format!("http://{addr}")
}

/// Reconstruct the assistant's fully-streamed reply text by concatenating every `text.delta` wire
/// event's `text` field from a raw `/v1/chat` SSE response body (mirrors the gap5 reference test's
/// `concat_text_deltas` — a bare substring check is wrong because the daemon's own streaming-redaction
/// carry may split one upstream delta into several wire events at arbitrary byte boundaries).
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

fn unique_dir(tag: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("ainxt-gap6-telemetry-{tag}-{nanos}"))
}

/// Build a `LoadedConfig` wiring a single CLOUD (`anthropic`) provider at `base_url`, with `pricing_toml`
/// spliced in verbatim (empty string = no `[telemetry]` section at all, exercising the shipped default
/// reference price table instead of a configured one).
fn loaded_with_cloud_provider(
    provider_id: &str,
    base_url: &str,
    pricing_toml: &str,
) -> ainxt_runtimed::LoadedConfig {
    // R16 critical: state the header-trusting-authenticator assumption explicitly, exactly as every
    // other served-HTTP test in this crate does (see `r10_breach_clock_unit.rs`).
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    // The adapter factory only wires an `Anthropic` provider when a non-empty key is present
    // (`build_provider`); the mock server never checks it.
    std::env::set_var("ANTHROPIC_API_KEY", "test-key-not-real");
    let dir = unique_dir("cfg");
    let src = format!(
        "version = 1\n\
         [server]\n\
         event_log_dir = {:?}\n\
         [[models.providers]]\n\
         id = {:?}\n\
         kind = \"anthropic\"\n\
         base_url = {:?}\n\
         eligible = [\"internal\"]\n\
         {pricing_toml}\n",
        dir.to_string_lossy(),
        provider_id,
        base_url,
    );
    load_layered(&[("gap6-telemetry", &src)]).expect("load config with a cloud provider")
}

async fn spawn_daemon(loaded: &ainxt_runtimed::LoadedConfig) -> String {
    let assembled = assemble_selected(loaded, "chat").expect("assemble_selected(loaded, \"chat\")");
    let full = assemble_full(loaded, assembled).expect("assemble_full");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind daemon listener");
    let daemon_addr = listener.local_addr().expect("daemon addr");
    // The EXACT call `main.rs` makes to serve the assembled daemon.
    tokio::spawn(ainxt_server::serve_full_ext(
        listener,
        full.to_full_app(),
        full.to_full_app_ext(),
    ));
    format!("http://{daemon_addr}")
}

/// Register the board-approved FI-03 outsourcing arrangement for `provider_id` over the daemon's OWN
/// `POST /admin/outsourcing/register` route — the SAME admin step
/// `gap5_regfi_outsourcing_admin_daemon_composed_router.rs` performs, required before a CLOUD-kind
/// route is eligible for ranking/failover at all (externality is authoritative-by-construction; a
/// provider adapter cannot self-declare its way past this).
async fn register_outsourcing(client: &reqwest::Client, base: &str, provider_id: &str) {
    let route_id = derive_route_id(provider_id);
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
    let resp = client
        .post(format!("{base}/admin/outsourcing/register"))
        .header("x-ainxt-user", "root")
        .header("x-ainxt-role", "admin")
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(register_body.to_string())
        .send()
        .await
        .expect("register send");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "the FI-03 admin registration must succeed"
    );
}

async fn send_chat_turn(client: &reqwest::Client, base: &str, session: &str, turn: &str) -> String {
    let resp = client
        .post(format!("{base}/v1/chat"))
        .header("x-ainxt-user", "alice")
        .header("x-ainxt-caps", "chat.send")
        // The shipped "chat" surface profile is department-scoped (RLS row isolation).
        .header("x-ainxt-department", "engineering")
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(
            serde_json::json!({
                "session": session, "turn": turn, "input": "hi", "data_class": "internal"
            })
            .to_string(),
        )
        .send()
        .await
        .expect("chat send");
    assert!(resp.status().is_success(), "status: {}", resp.status());
    resp.text().await.expect("chat body")
}

/// (1) + (3): a deployment-configured `[telemetry.pricing]` table is genuinely consulted by the REAL
/// composed engine (not the empty `Engine::new` default) when pricing a real on-wire turn, AND the new
/// `GET /admin/telemetry/cost-rollup` route surfaces a real, non-empty actor/provider chargeback
/// breakdown aggregated from that SAME served turn — admin-gated (403 for a non-admin caller).
#[tokio::test(flavor = "multi_thread")]
async fn pricing_config_flows_through_daemons_own_composed_router_to_wire_cost_and_rollup() {
    let base_url = spawn_mock_anthropic_server("priced-by-config", 1_000_000, 1_000_000);
    let loaded = loaded_with_cloud_provider(
        "acme-cloud",
        &base_url,
        "[telemetry.pricing.acme-cloud]\n\
         input_micros_per_million = 3000000\n\
         output_micros_per_million = 15000000\n",
    );
    let base = spawn_daemon(&loaded).await;
    let client = reqwest::Client::new();
    register_outsourcing(&client, &base, "acme-cloud").await;

    let body = send_chat_turn(&client, &base, "s-gap6-1", "t1").await;
    assert!(
        concat_text_deltas(&body).contains("priced-by-config"),
        "the real (mocked) provider must have actually served the turn: {body}"
    );
    // The on-wire usage event carries the model actually routed and the cost PRICED off the
    // deployment-configured table (3+15 per 1e6 tokens = 18.0), never 0.0/an unpriced default.
    assert!(
        body.contains("\"type\":\"usage\"") && body.contains("\"model\":\"acme-cloud\""),
        "on-wire usage must name the actually-routed provider: {body}"
    );
    assert!(
        body.contains("\"cost\":18.0"),
        "on-wire usage must carry the cost PRICED by the composed engine's real PriceTable \
         (config-declared 3+15 per 1e6 tokens = 18.0), not 0.0 (the bypassed/unconfigured default): {body}"
    );

    // A non-admin caller is refused the chargeback breakdown (403) — cost data is sensitive.
    let denied = client
        .get(format!("{base}/admin/telemetry/cost-rollup"))
        .header("x-ainxt-user", "alice")
        .send()
        .await
        .expect("denied send");
    assert_eq!(
        denied.status().as_u16(),
        403,
        "a non-admin must be refused the cost-rollup route"
    );

    // The admin reads the REAL rollup off the daemon's own live InMemoryTelemetry, driven by the
    // ACTUAL served turn above — not a second, disconnected aggregation built by hand in a test.
    let rollup_resp = client
        .get(format!("{base}/admin/telemetry/cost-rollup"))
        .header("x-ainxt-user", "root")
        .header("x-ainxt-role", "admin")
        .send()
        .await
        .expect("rollup send");
    assert_eq!(
        rollup_resp.status().as_u16(),
        200,
        "an admin read must succeed"
    );
    let rollup: serde_json::Value =
        serde_json::from_str(&rollup_resp.text().await.expect("rollup body")).expect("rollup json");

    assert_eq!(
        rollup["total"]["turns"], 1,
        "exactly one served turn must be rolled up: {rollup}"
    );
    assert_eq!(
        rollup["total"]["cost_micros"], 18_000_000u64,
        "the total bucket must carry the priced cost in integer micros: {rollup}"
    );
    // The chargeback key is the authenticated PRINCIPAL (`x-ainxt-user`), not the session id.
    let actors = rollup["actors_by_cost"]
        .as_array()
        .expect("actors_by_cost array");
    assert_eq!(
        actors.len(),
        1,
        "non-empty per-actor chargeback breakdown: {rollup}"
    );
    assert_eq!(actors[0]["actor"], "alice");
    assert_eq!(actors[0]["cost_micros"], 18_000_000u64);
    let providers = rollup["providers_by_cost"]
        .as_array()
        .expect("providers_by_cost array");
    assert_eq!(
        providers.len(),
        1,
        "non-empty per-provider FinOps breakdown: {rollup}"
    );
    assert_eq!(providers[0]["provider"], "acme-cloud");
    assert_eq!(providers[0]["cost_micros"], 18_000_000u64);
}

/// (2): the shipped daemon's BUILT-IN reference price table applies for a known canonical model id
/// even with NO `[telemetry.pricing]` layer configured at all — proving the composed engine is never
/// left at `Engine::new`'s empty-PriceTable default (which prices every provider at 0) just because a
/// deployment did not declare its own rates.
#[tokio::test(flavor = "multi_thread")]
async fn default_reference_price_table_applies_with_no_pricing_configured() {
    // "claude-sonnet-4-6" is a canonical model name from CLAUDE.md's Model Usage Policy /
    // `ainxt_runtimed::default_price_table` — used here as the provider id, exactly as
    // `runtimed.example.toml`'s shipped examples name their provider entries after the canonical model.
    let base_url = spawn_mock_anthropic_server("priced-by-default-table", 1_000_000, 1_000_000);
    let loaded = loaded_with_cloud_provider("claude-sonnet-4-6", &base_url, "");
    let base = spawn_daemon(&loaded).await;
    let client = reqwest::Client::new();
    register_outsourcing(&client, &base, "claude-sonnet-4-6").await;

    let body = send_chat_turn(&client, &base, "s-gap6-2", "t1").await;
    assert!(
        concat_text_deltas(&body).contains("priced-by-default-table"),
        "{body}"
    );
    // The shipped default_price_table prices claude-sonnet-4-6 at $3/$15 per 1e6 in/out tokens too
    // (same anchor as the ainxt-server unit tests use), so this must NOT be 0.0/absent.
    assert!(
        body.contains("\"cost\":18.0"),
        "an unconfigured deployment must still get the shipped reference price for a known canonical \
         model, not 0.0: {body}"
    );
}

/// (4): the cost-rollup route fails CLOSED (404, never a fabricated empty breakdown) when the
/// configured telemetry sink does not retain turns in-process (`sink = "otlp"` only ever exports).
#[tokio::test(flavor = "multi_thread")]
async fn cost_rollup_route_404s_when_sink_does_not_retain_turns() {
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let dir = unique_dir("otlp-cfg");
    let src = format!(
        "version = 1\n[server]\nevent_log_dir = {:?}\n[telemetry]\nsink = \"otlp\"\n",
        dir.to_string_lossy()
    );
    let loaded = load_layered(&[("gap6-telemetry-otlp", &src)]).expect("load config");
    let base = spawn_daemon(&loaded).await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{base}/admin/telemetry/cost-rollup"))
        .header("x-ainxt-user", "root")
        .header("x-ainxt-role", "admin")
        .send()
        .await
        .expect("rollup send");
    assert_eq!(
        resp.status().as_u16(),
        404,
        "an export-only sink must never fabricate an in-process rollup"
    );
}
