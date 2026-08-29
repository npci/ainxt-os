// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX data-surfaces-artifacts "bank onboarding as a Program never selectable":
//! `ainxt_planner::bank_onboarding::bank_onboarding_program` built a correct, real topology (KYC
//! data-class registration → federated-broker credential issuance → member-bank connectivity check)
//! and was proven via the generic `ainxt_planner::program` engine, but the served Program surface
//! (`assemble_program_surface`/`ProgramSurface::handle_turn`) always composed via the generic
//! `MigrationBlueprint::compose` planner — there was ZERO reference to `bank_onboarding_program`
//! anywhere in `ainxt-runtimed`, so a served turn could never select it no matter what a caller sent.
//!
//! * `gap5_program_bank_onboarding_selectable_through_the_real_surface_dispatch` — proven through
//!   `assemble_selected`, the EXACT function `main.rs`'s `--surface` dispatch calls
//!   (`assemble_selected_governed` falls through to it for any surface id other than
//!   `"chat_governed"`), with the new `"program_bank_onboarding"` arm, driven end-to-end through the
//!   live `SessionManager`/`TurnHandler` seam via `Client::in_process`. The served governance default
//!   (`ServedProgramGovernance::served_default`, `critical_path_approved: false`, §8 "no forced
//!   commit") correctly holds the topology's real KYC node — a `CheckpointClass::CriticalPath` node,
//!   by design, since it registers a regulated data class — for human approval: an honest
//!   `CappedPartial` with the module turn never run, NOT a fabricated green. This is itself strong
//!   proof of reachability: the SAME driver under the SAME governance completes the generic topology
//!   (see the second test below and `r3_program_served_over_protocol`), so a DIFFERENT (capped)
//!   outcome, produced ONLY by selecting `"program_bank_onboarding"`, is direct evidence the real
//!   `bank_onboarding_program` topology — with its real checkpoint class — reached the driver.
//! * `gap5_program_bank_onboarding_completes_end_to_end_when_checkpoint_approved` — the SAME real
//!   `ProgramSurface::handle_turn` (constructed the same way `r13_program_transparency_log.rs` builds
//!   one directly, still the exact function `SessionManager` drives), with governance that pre-
//!   approves the checkpoint (`ServedProgramGovernance::unbounded_approved`, a normal, documented,
//!   public governance choice) — proving the topology is not just selectABLE but fully functional:
//!   all three real bank-onboarding nodes commit, in dependency order, and NONE of the generic
//!   topology's node names appear.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ainxt_client::{Client, ClientConfig};
use ainxt_runtimed::{
    assemble_selected, bank_id_from_input, build_engine_ext, load_layered, LoadedConfig,
    ProgramSurface, ProgramTopology, ServedProgramGovernance,
};
use ainxt_session::SessionManager;
use ainxt_types::Principal;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const BANK_ONBOARDING_NODE_SUFFIXES: [&str; 3] = [
    "kyc-data-class-registration",
    "federated-broker-credential-issuance",
    "member-bank-connectivity-check",
];

/// Find the first `\r\n\r\n` header/body separator in a raw byte buffer.
fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// GAP-FIX planner-assurance-revision (item 1) — a minimal, hand-rolled mock OpenAI-`/chat/completions`-
/// schema upstream (the SAME raw-socket pattern `gap5_fabric_mount_served.rs`'s `spawn_mock_llm` uses,
/// stripped of prompt capture): replies to EVERY request with the SAME fixed `text`, regardless of what
/// was asked. Needed because `assemble_selected`'s air-gapped default (`OfflineProvider`) always streams
/// a prompt-invariant "offline mode: no model configured." — content that carries none of a real goal's
/// keywords and therefore genuinely (and correctly) fails the served Program driver's now-real,
/// content-varying `RubricJudge` (no longer a fabricated fixed pass). This mock stubs only the vendor
/// HTTP endpoint the real `OpenAiSchemaProvider` calls (`kind = "local"`), exactly as a live
/// deployment's own local vLLM/Ollama endpoint would be configured — never the Judge/driver under test.
async fn spawn_mock_llm_fixed_text(text: String) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock llm");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => break,
            };
            let text = text.clone();
            tokio::spawn(async move {
                let mut buf: Vec<u8> = Vec::new();
                let mut chunk = [0u8; 8192];
                let (headers_end, content_length) = loop {
                    let n = match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(pos) = find_double_crlf(&buf) {
                        let headers = String::from_utf8_lossy(&buf[..pos]).to_string();
                        let cl = headers
                            .lines()
                            .find_map(|l| {
                                let (k, v) = l.split_once(':')?;
                                if k.trim().eq_ignore_ascii_case("content-length") {
                                    v.trim().parse::<usize>().ok()
                                } else {
                                    None
                                }
                            })
                            .unwrap_or(0);
                        if buf.len() >= pos + 4 + cl {
                            break (pos, cl);
                        }
                    }
                };
                let _ = (headers_end, content_length); // only the framing is needed, never the content
                let sse = format!(
                    "data: {{\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"model\":\"mock\",\"choices\":[{{\"index\":0,\"delta\":{{\"content\":{text:?}}},\"finish_reason\":null}}]}}\n\n\
                     data: {{\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"model\":\"mock\",\"choices\":[{{\"index\":0,\"delta\":{{}},\"finish_reason\":\"stop\"}}]}}\n\n\
                     data: [DONE]\n\n"
                );
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    sse.len(),
                    sse
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    addr
}

/// A config identical to `load_layered(&[("t", "version = 1")])` except it also wires a `kind = "local"`
/// provider pointed at a mock upstream that always replies `text` — see [`spawn_mock_llm_fixed_text`].
fn loaded_with_fixed_text_provider(mock_addr: std::net::SocketAddr, tag: &str) -> LoadedConfig {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let src = format!(
        "version = 1\n\
         [[models.providers]]\n\
         id = \"mock-llm-{tag}-{nanos}\"\n\
         kind = \"local\"\n\
         base_url = \"http://{mock_addr}\"\n\
         eligible = [\"internal\"]\n"
    );
    load_layered(&[("t", &src)]).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn gap5_program_bank_onboarding_selectable_through_the_real_surface_dispatch() {
    let loaded = load_layered(&[("t", "version = 1")]).unwrap();

    // The REAL `--surface` dispatch table `main.rs` uses (`assemble_selected`), not a bespoke
    // constructor call that bypasses it.
    let assembled = assemble_selected(&loaded, "program_bank_onboarding").unwrap();
    assert!(
        assembled
            .report
            .iter()
            .any(|r| r.contains("program topology: bank-onboarding")),
        "the selected surface must announce the bank-onboarding topology, not the generic default: \
         {:?}",
        assembled.report
    );

    let client = Client::in_process(
        assembled.manager,
        Principal::user("dev", &["chat.send"]),
        ClientConfig::default(),
    );
    let out = client
        .chat("s-bank", "t1", "Onboard NewBank Ltd")
        .unwrap()
        .collect()
        .await;
    assert!(
        out.completed,
        "the served turn itself must complete (the RUN outcome is capped, not the turn)"
    );
    assert!(
        out.text.contains("CappedPartial"),
        "the served default governance (checkpoints NOT auto-approved, §8) must hold the real \
         topology's CriticalPath KYC node for human approval — an honest CappedPartial, never a \
         fabricated Completed: {}",
        out.text
    );
    assert!(
        out.text.contains("0 committed"),
        "zero nodes may commit until the checkpoint is approved: {}",
        out.text
    );
    // Negative control: the generic topology's own node names must NOT appear — proving the served
    // surface genuinely switched planners, rather than running both / falling back silently.
    assert!(
        !out.text.contains("module:assess") && !out.text.contains("module:migrate"),
        "a bank-onboarding-selected surface must not also run the generic MigrationBlueprint nodes: {}",
        out.text
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn gap5_program_bank_onboarding_completes_end_to_end_when_checkpoint_approved() {
    // GAP-FIX planner-assurance-revision (item 1) — the served Program driver's semantic Judge is now a
    // REAL, content-varying `RubricJudge`, never a fabricated fixed pass; the air-gapped default
    // `OfflineProvider`'s prompt-invariant "offline mode: no model configured." text carries none of
    // this Run's goal keywords ("Onboard NewBank Ltd") and would now genuinely (and correctly) fail the
    // Judge. A mock `kind = "local"` upstream supplies a genuinely substantive, on-goal artifact instead
    // — exactly as a live deployment's own local vLLM/Ollama endpoint would.
    let mock_addr = spawn_mock_llm_fixed_text(
        "onboarded newbank ltd successfully: completed kyc data class registration, issued the \
         federated broker credential, and verified member bank connectivity with boundary tests for \
         empty and invalid inputs."
            .to_string(),
    )
    .await;
    let loaded = loaded_with_fixed_text_provider(mock_addr, "bank-approved");
    let (
        engine,
        _report,
        _ledger,
        _reconciler,
        _dispatch_probe,
        _tools,
        _outsourcing,
        _mandate_registry,
        _mcp_admin,
        _prompt_cache,
        _serving,
    ) = build_engine_ext(&loaded.runtime).unwrap();

    // The exact same `ProgramSurface` object `assemble_program_surface_bank_onboarding` composes —
    // built directly here (the same pattern `r13_program_transparency_log.rs` uses to drive a real
    // `ProgramSurface`), with governance that pre-approves the checkpoint gate so the run can proceed
    // to completion instead of stopping at the human checkpoint proven above.
    let surface = ProgramSurface::new(Arc::new(engine), "program-bank-onboarding")
        .with_topology(ProgramTopology::BankOnboarding)
        .with_governance(ServedProgramGovernance::unbounded_approved());
    let manager = Arc::new(SessionManager::new(Arc::new(surface), loaded.session));

    let client = Client::in_process(
        manager,
        Principal::user("dev", &["chat.send"]),
        ClientConfig::default(),
    );
    let out = client
        .chat("s-bank-approved", "t1", "Onboard NewBank Ltd")
        .unwrap()
        .collect()
        .await;
    assert!(
        out.completed,
        "the served bank-onboarding program turn must complete"
    );
    assert!(
        out.text.contains("Completed"),
        "with the checkpoint approved, the real bank-onboarding topology must reach a genuine \
         Completed outcome: {}",
        out.text
    );

    // `bank_id_from_input` is the SAME slugifier `ProgramSurface::handle_turn` uses internally —
    // asserting against it (rather than a hand-guessed literal) keeps this test honest about what the
    // served path is actually supposed to derive from the raw turn text.
    let bank_id = bank_id_from_input("Onboard NewBank Ltd");
    assert_eq!(bank_id, "onboard-newbank-ltd");

    for suffix in BANK_ONBOARDING_NODE_SUFFIXES {
        let node_label = format!("module:{bank_id}-{suffix}");
        assert!(
            out.text.contains(&node_label),
            "the served turn must run and commit the REAL bank_onboarding_program topology's \
             `{node_label}` node, not the generic assess/migrate/verify graph: {}",
            out.text
        );
    }
    assert!(
        !out.text.contains("module:assess") && !out.text.contains("module:migrate"),
        "a bank-onboarding-selected surface must not also run the generic MigrationBlueprint nodes: {}",
        out.text
    );
}

/// The pre-existing `"program"` selector (and therefore every existing deployment/test) is completely
/// unaffected by this addition — `ProgramTopology::Generic` stays the default end to end, and (unlike
/// the bank-onboarding topology) completes under the SAME served-default governance because none of
/// its nodes are a `CheckpointClass::CriticalPath` human gate.
#[tokio::test(flavor = "multi_thread")]
async fn gap5_program_default_selector_is_unaffected_by_the_new_topology_field() {
    // GAP-FIX planner-assurance-revision (item 1) — a genuinely substantive, on-goal artifact is
    // required for the served Program driver's REAL RubricJudge to pass; see
    // `spawn_mock_llm_fixed_text`'s doc comment.
    let mock_addr = spawn_mock_llm_fixed_text(
        "migrated the legacy module successfully: assessed dependencies, executed the migration, and \
         verified the result with boundary tests for empty and negative edge cases."
            .to_string(),
    )
    .await;
    let loaded = loaded_with_fixed_text_provider(mock_addr, "generic");
    let assembled = assemble_selected(&loaded, "program").unwrap();
    assert!(
        assembled
            .report
            .iter()
            .any(|r| r.contains("program topology: generic")),
        "the pre-existing default selector must still report the generic topology: {:?}",
        assembled.report
    );

    let client = Client::in_process(
        assembled.manager,
        Principal::user("dev", &["chat.send"]),
        ClientConfig::default(),
    );
    let out = client
        .chat("s-generic", "t1", "migrate the legacy module")
        .unwrap()
        .collect()
        .await;
    assert!(out.completed);
    assert!(
        out.text.contains("module:assess") && out.text.contains("module:migrate"),
        "the default selector must still run the generic MigrationBlueprint graph, unchanged: {}",
        out.text
    );
}

/// `bank_id_from_input`'s slugification, exercised directly — freeform text becomes a stable,
/// node-id-safe token, and an empty/all-punctuation turn falls back to a non-empty placeholder rather
/// than collapsing every derived node id's prefix into a bare leading `-`.
#[test]
fn gap5_bank_id_from_input_slugifies_and_never_returns_empty() {
    assert_eq!(
        bank_id_from_input("Onboard New Bank Ltd"),
        "onboard-new-bank-ltd"
    );
    assert_eq!(bank_id_from_input("  newbank  "), "newbank");
    assert_eq!(bank_id_from_input("New-Bank_42!"), "new-bank_42");
    assert_eq!(bank_id_from_input(""), "unspecified-bank");
    assert_eq!(bank_id_from_input("!!!"), "unspecified-bank");
}

/// `ProgramTopology::default()` is `Generic` — every pre-existing `ProgramSurface::new` caller keeps
/// its exact prior composition behavior with no code change required.
#[test]
fn gap5_program_topology_default_is_generic() {
    assert_eq!(ProgramTopology::default(), ProgramTopology::Generic);
}
