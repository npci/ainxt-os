// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R3 — the assembled daemon serves the RICH path. Each test drives a REAL assembled object
//! (`ChatSurface` / `ProgramSurface` / `DurableMemoryReader`) and proves a gap closed, fail-before /
//! pass-after:
//!
//! * `r3_grounded_corpus_cited_answer` — the live corpus loader + hybrid retriever produce a CITED
//!   answer from a KB seeded via config (CTX-fabric "live retrieval corpus is populated" + SURF-03).
//! * `r3_retrieval_scope_enforced_on_served_path` — a repo-scoped surface grounds ONLY on repo docs
//!   and a platform surface ONLY on platform docs; the two are disjoint (SURF-01).
//! * `r3_program_served_over_protocol` — Programs are reachable from the live served path: a turn
//!   over the `SessionManager` spine drives the Program Supervisor with real engine turns (LOOP-01).
//! * `r3_durable_memory_wired_and_hydrates` — the durable memory store returns a written fact via the
//!   Context-Fabric read path and hydrates it after reopen (MEM durable store).

use ainxt_chat::{ChatReply, ChatSurface};
use ainxt_client::{Client, ClientConfig};
use ainxt_profile::RetrievalScope;
use ainxt_protocol::Event;
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtime::{engine_with_defaults, memory::MemoryReader};
use ainxt_runtimed::{
    assemble_program_surface, build_chat_surface, corpus_for_scope, load_layered,
    scope_for_surface, DurableMemoryReader,
};
use ainxt_types::{DataClass, Principal};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

/// Find the first `\r\n\r\n` header/body separator in a raw byte buffer.
fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// GAP-FIX planner-assurance-revision (item 1) — a minimal, hand-rolled mock OpenAI-`/chat/completions`-
/// schema upstream (the SAME raw-socket pattern `gap5_fabric_mount_served.rs`'s `spawn_mock_llm` uses):
/// replies to EVERY request with the SAME fixed `text`. Needed because `assemble_program_surface`'s
/// air-gapped default (`OfflineProvider`) always streams a prompt-invariant "offline mode: no model
/// configured." — content that carries none of a real goal's keywords and therefore genuinely (and
/// correctly) fails the served Program driver's now-real, content-varying `RubricJudge` (no longer a
/// fabricated fixed pass). This mock stubs only the vendor HTTP endpoint the real `OpenAiSchemaProvider`
/// calls (`kind = "local"`), exactly as a live deployment's own local vLLM/Ollama endpoint would be.
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
                loop {
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
                            break;
                        }
                    }
                }
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
fn loaded_with_fixed_text_provider(
    mock_addr: std::net::SocketAddr,
    tag: &str,
) -> ainxt_runtimed::LoadedConfig {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
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

fn analyst() -> Principal {
    Principal::user("analyst", &["chat.send"]).with_clearance(DataClass::Public)
}

// A provider that just echoes the prompt it received (so a grounding chunk that reached the prompt is
// observable). Grounding + citations do not depend on it — they are produced by the retriever.
struct EchoProvider;
impl Provider for EchoProvider {
    fn id(&self) -> &str {
        "echo"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, prompt: &str) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(8);
        let p = prompt.to_string();
        tokio::spawn(async move {
            let _ = tx.send(Event::TextDelta(p)).await;
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

// ---------------------------------------------------------------------------------------------
// CTX-fabric / SURF-03 — the live corpus loader + hybrid retriever yield a CITED answer.
// ---------------------------------------------------------------------------------------------
#[tokio::test]
async fn r3_grounded_corpus_cited_answer() {
    // A KB seeded via config (the `[[kb.documents]]` the daemon parses at load).
    let cfg = r#"
        version = 1
        [[kb.documents]]
        id = "upi-1"
        source = "ops-handbook"
        text = "UPI is a real-time payments system; settlement runs in deferred net batches via the national switch."
        scope = "platform"
        data_class = "public"
    "#;
    let loaded = load_layered(&[("t", cfg)]).unwrap();
    assert_eq!(loaded.kb.len(), 1, "KB must parse from config");

    // The daemon's real chat-surface assembly, over the scope-loaded corpus (platform+namespace).
    let corpus = corpus_for_scope(&loaded.kb, RetrievalScope::PlatformAndNamespace);
    assert_eq!(
        corpus.len(),
        1,
        "corpus must be populated (not the empty stub)"
    );
    let (chat, _report) = build_chat_surface(&loaded, corpus).unwrap();

    let reply = chat
        .turn(
            "s1",
            &analyst(),
            "How does UPI settlement work?",
            DataClass::Public,
        )
        .await
        .unwrap();
    match reply {
        ChatReply::Answer { citations, .. } => {
            assert!(
                !citations.is_empty(),
                "a grounded answer over a populated corpus must carry at least one citation"
            );
            assert!(
                citations.iter().any(|c| c.chunk_id == "upi-1"),
                "the citation must point at the loaded document: {citations:?}"
            );
        }
        o => panic!("expected a grounded Answer, got {o:?}"),
    }
}

// ---------------------------------------------------------------------------------------------
// SURF-01 — profile retrieval scope enforced on the served grounding path.
// ---------------------------------------------------------------------------------------------
#[tokio::test]
async fn r3_retrieval_scope_enforced_on_served_path() {
    let cfg = r#"
        version = 1
        [[kb.documents]]
        id = "plat"
        text = "platform deploy runbook shared across every team"
        scope = "platform"
        [[kb.documents]]
        id = "repo"
        text = "the cards-service repository deploy runbook"
        scope = "repo"
        repo = "cards-service"
    "#;
    let loaded = load_layered(&[("t", cfg)]).unwrap();

    // The scope→surface mapping the served path resolves from the profile catalog.
    assert_eq!(
        scope_for_surface("chat"),
        RetrievalScope::PlatformAndNamespace
    );
    assert_eq!(scope_for_surface("sdlc"), RetrievalScope::RepoScoped);
    assert_eq!(scope_for_surface("code"), RetrievalScope::RepoScoped);

    // Build the SAME scoped corpus the surface serves at, hand it to a REAL ChatSurface, and ground
    // a query that overlaps BOTH docs. Scope is enforced structurally: the out-of-scope doc is not in
    // the corpus, so it can never be cited.
    let query = "deploy runbook";

    // Repo-scoped surface (sdlc/code): must cite ONLY the repo doc.
    let repo_corpus = corpus_for_scope(&loaded.kb, RetrievalScope::RepoScoped);
    assert_eq!(repo_corpus.len(), 1);
    let mut r1 = ModelRouter::new();
    r1.register(Box::new(EchoProvider));
    let repo_surface = ChatSurface::from_engine(
        engine_with_defaults(r1),
        repo_corpus,
        Default::default(),
        Box::new(FixedClock),
    );
    match repo_surface
        .turn("s", &analyst(), query, DataClass::Public)
        .await
        .unwrap()
    {
        ChatReply::Answer { citations, .. } => {
            assert!(
                citations.iter().any(|c| c.chunk_id == "repo"),
                "repo surface must cite the repo doc"
            );
            assert!(
                !citations.iter().any(|c| c.chunk_id == "plat"),
                "repo-scoped surface must NEVER reach the platform doc: {citations:?}"
            );
        }
        o => panic!("expected Answer, got {o:?}"),
    }

    // Platform surface (chat/buddy): must cite ONLY the platform doc.
    let plat_corpus = corpus_for_scope(&loaded.kb, RetrievalScope::PlatformAndNamespace);
    assert_eq!(plat_corpus.len(), 1);
    let mut r2 = ModelRouter::new();
    r2.register(Box::new(EchoProvider));
    let plat_surface = ChatSurface::from_engine(
        engine_with_defaults(r2),
        plat_corpus,
        Default::default(),
        Box::new(FixedClock),
    );
    match plat_surface
        .turn("s", &analyst(), query, DataClass::Public)
        .await
        .unwrap()
    {
        ChatReply::Answer { citations, .. } => {
            assert!(
                citations.iter().any(|c| c.chunk_id == "plat"),
                "platform surface must cite the platform doc"
            );
            assert!(
                !citations.iter().any(|c| c.chunk_id == "repo"),
                "platform surface must NEVER reach the repo-private doc: {citations:?}"
            );
        }
        o => panic!("expected Answer, got {o:?}"),
    }
}

// A zero clock for the ChatSurface response cache (deterministic in tests).
struct FixedClock;
impl ainxt_cache::Clock for FixedClock {
    fn now(&self) -> u64 {
        0
    }
}

// ---------------------------------------------------------------------------------------------
// LOOP-01 — Programs reachable from the live served path (POST /v1/chat → run_program).
// ---------------------------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
async fn r3_program_served_over_protocol() {
    // GAP-FIX planner-assurance-revision (item 1) — a genuinely substantive, on-goal artifact is
    // required for the served Program driver's REAL RubricJudge to pass; see
    // `spawn_mock_llm_fixed_text`'s doc comment.
    let mock_addr = spawn_mock_llm_fixed_text(
        "migrated the legacy module successfully: assessed dependencies, executed the migration, and \
         verified the result with boundary tests for empty and negative edge cases."
            .to_string(),
    )
    .await;
    let loaded = loaded_with_fixed_text_provider(mock_addr, "r3-program");
    let assembled = assemble_program_surface(&loaded, "program").unwrap();
    assert!(
        assembled
            .report
            .iter()
            .any(|r| r.contains("Program Supervisor served over the protocol")),
        "the program surface must announce it is served: {:?}",
        assembled.report
    );

    let client = Client::in_process(
        assembled.manager,
        Principal::user("dev", &["chat.send"]),
        ClientConfig::default(),
    );
    let out = client
        .chat("s", "t", "migrate the legacy module")
        .unwrap()
        .collect()
        .await;
    assert!(out.completed, "the served program turn must complete");
    assert!(
        out.text.contains("Completed"),
        "the served path must drive the Program Supervisor to a terminal outcome: {}",
        out.text
    );
    assert!(
        out.text.contains("module:assess")
            && out.text.contains("module:migrate")
            && out.text.contains("module:verify"),
        "the served path must run the MigrationBlueprint::compose multi-node graph: {}",
        out.text
    );
}

// ---------------------------------------------------------------------------------------------
// MEM — durable memory store wired into the assembled memory layer; survives reopen.
// ---------------------------------------------------------------------------------------------
#[test]
fn r3_durable_memory_wired_and_hydrates() {
    use ainxt_memory::fabric::TaskKind;
    use ainxt_memory::{
        AccessScope, MemoryItem, MemoryKind, MemorySqlBackend, MemoryStore, Provenance, Scope,
    };

    // The shared backend a restart / a second process would reopen.
    let backend = MemorySqlBackend::new();
    let reader = DurableMemoryReader::open(backend.clone()).unwrap();

    // Author a user-preference fact directly on the durable store (write-through + compliance-on-write).
    {
        let mut store = reader.store();
        let item = MemoryItem::new(
            "pref-1",
            MemoryKind::UserPreference,
            Scope::User("alice".into()),
            "indentation",
            "alice prefers tabs over spaces",
            Provenance::human("alice", 1.0),
        );
        store.write(item).expect("durable write");
    }

    // Read it back through the runtime's Context-Fabric MemoryReader seam (CasualChat plans a
    // user-preference query). This is exactly what the engine calls per turn.
    let access = AccessScope::from_principal(Principal::user("alice", &[]));
    let (hits, lineage) = reader.read_for_turn("t1", &TaskKind::CasualChat, &access, 1);
    assert!(
        hits.iter().any(|h| h.item.id == "pref-1"),
        "the durable store must return the written fact via read_for_turn"
    );
    assert_eq!(lineage.turn_id, "t1");
    assert!(
        lineage.injected.iter().any(|(id, _)| id == "pref-1"),
        "lineage must record the injection"
    );

    // Durability: a SECOND reader over the SAME backend hydrates the committed row (restart-durable).
    let reader2 = DurableMemoryReader::open(backend.clone()).unwrap();
    let (hits2, _) = reader2.read_for_turn("t2", &TaskKind::CasualChat, &access, 2);
    assert!(
        hits2.iter().any(|h| h.item.id == "pref-1"),
        "a reopened durable store must hydrate the persisted fact"
    );
}
