// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R10 — the SERVED-path gap closures proven on the assembled daemon, fail-before / pass-after:
//!
//! 1. `r10_served_program_failing_proof_is_capped_partial` — the served `run_program` path drives
//!    `ainxt_planner::driver::drive_program_verified` with three REAL proof seams (engine-derived
//!    deterministic/adversarial + an injected cross-model judge + an engine-derived program-scale
//!    verifier). A FAILING program-scale proof (regression sweep RED) yields an honest
//!    `CappedPartial`, never `Completed` — the program-scale COMPLETED gate genuinely runs.
//!    `r10_served_program_default_proofs_complete` is the pass-after contrast (all proofs green →
//!    `Completed`), proving the cap above is the failing proof, not a broken pipeline.
//! 2. `r10_wrong_dept_caller_grounds_nothing_on_served_chat` — the served chat grounding runs the
//!    per-node ACL pre-rank (`corpus_for_scope` carries the department node-ACL onto every chunk); a
//!    wrong-department caller grounds NOTHING (no citation), while the correct-department caller
//!    grounds the same doc. `r10_rls_row_filter_isolates_cross_dept_row_on_served_chat` proves the
//!    orthogonal RLS row-filter: with row isolation enabled, a caller grounds only the row whose
//!    `department` attribute is its own (fail-closed, existence never leaks).
//! 3. `r10_unreproducible_ledger_figure_blocked_on_served_path` — the served chat default
//!    (`from_engine_numeric_gated`) runs the numeric re-derivation HARD gate: a stated figure not
//!    attributable to a retrieved source is BLOCKED + escalated, never shipped; the un-gated surface
//!    ships the same figure (control).
//! 4. `r10_daemon_spawns_reconciler_sweep_over_shared_ledger` — the assembled daemon holds + spawns a
//!    background `ReconcilerSweeper` over the SAME shared exactly-once ledger the served engine's
//!    unified Capability registry dispatches through; a lost-ack `PENDING` row is actively acted on.
//! 5. `r10_mcp_runtime_registers_into_served_unified_registry` — the MCP runtime's pinned tools
//!    register into the SAME unified Capability registry the served engine uses.

use std::sync::Arc;

use ainxt_cache::{CacheConfig, FixedClock};
use ainxt_chat::{ChatReply, ChatSurface};
use ainxt_compliance::StrongRedactor;
use ainxt_context::Corpus;
use ainxt_mcp::{
    AuthProvider, InMemoryPinStore, McpError, McpRegistry, McpServer, McpTransport, NoAuth,
    ToolManifest, ToolResult,
};
use ainxt_planner::program::{NodeClass, NodeDecl, ProgramOutcome};
use ainxt_profile::RetrievalScope;
use ainxt_protocol::Event;
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtime::{CancelToken, Engine, InMemoryAudit, RbacAuthorizer};
use ainxt_runtimed::{
    assemble_full, assemble_program, assemble_surface, build_chat_surface,
    build_unified_capability_registry_shared, corpus_for_scope, drive_served_program_verified,
    load_layered, register_served_mcp_runtime, LoadedConfig, ProgramProofSeams, RunIdentitySpec,
    SodApprover,
};
use ainxt_tools::{ReconcilerSweeper, RecordingEscalationSink};
use ainxt_types::{DataClass, Principal};
use tokio::sync::mpsc;

fn offline() -> LoadedConfig {
    load_layered(&[("t", "version = 1")]).unwrap()
}

fn program_nodes() -> Vec<NodeDecl> {
    vec![
        NodeDecl::new("assess", NodeClass::MigrationRun),
        NodeDecl::new("migrate", NodeClass::MigrationRun).depends_on("assess"),
    ]
}

fn program_identity(run_id: &str) -> RunIdentitySpec {
    RunIdentitySpec::new("agent", "r10-prog", run_id, DataClass::Internal, "u-alice")
}

// ============================================================================
// (1) Served program: a failing program-scale proof yields CappedPartial, never Completed
// ============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn r10_served_program_failing_proof_is_capped_partial() {
    let pr = assemble_program(&offline()).expect("assemble program runtime");
    // The EXACT served `run_program` driver (`drive_served_program_verified` — what `ProgramSurface`
    // calls), but with the program-scale regression sweep forced RED. Every module still commits its
    // three-way proof, but the program-scale COMPLETED gate blocks → honest CappedPartial.
    let run = drive_served_program_verified(
        pr.engine(),
        program_identity("prog-fail-sweep"),
        "migrate the settlement module",
        program_nodes(),
        None,
        None,
        SodApprover::Distinct,
        CancelToken::new(),
        ProgramProofSeams::with_failing_regression_sweep(),
    )
    .await
    .expect("the run drives to a terminal outcome (a failing proof is a cap, not a crash)");

    assert_eq!(
        run.outcome,
        ProgramOutcome::CappedPartial,
        "a served program with a RED program-scale proof must be CappedPartial, never Completed"
    );
    assert_ne!(run.outcome, ProgramOutcome::Completed);
    // A real module engine turn still ran for each node (the cap is the program-scale gate, not an
    // empty pipeline).
    assert!(
        !run.turns.is_empty(),
        "the served program must still drive real module turns before the program-scale cap"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn r10_served_program_default_proofs_complete() {
    // GAP-FIX planner-assurance-revision (item 1) — a genuinely substantive, on-goal artifact is
    // required for the served Judge (now real, content-varying `RubricJudge`) to pass; see
    // `FixedTextProvider`'s doc comment.
    let engine = Arc::new(engine_with(FixedTextProvider {
        text: "migrated the settlement module: assessed dependencies and executed the settlement \
               cutover successfully, with boundary tests covering empty and negative edge cases."
            .to_string(),
    }));
    // PASS-AFTER contrast: the SAME served driver + SAME goal with the offline-default proofs (all
    // green) drives to Completed — proving the cap above is the failing proof, not a broken pipeline.
    let run = drive_served_program_verified(
        engine,
        program_identity("prog-default"),
        "migrate the settlement module",
        program_nodes(),
        None,
        None,
        SodApprover::Distinct,
        CancelToken::new(),
        ProgramProofSeams::offline_default(),
    )
    .await
    .expect("distinct approver + green proofs → the program runs");

    assert_eq!(
        run.outcome,
        ProgramOutcome::Completed,
        "with all proofs green the served program completes"
    );
    assert!(
        run.program.state().committed_nodes_are_all_proven(),
        "every committed node carries a durable Complete three-way proof"
    );
    assert!(
        run.renewals > 0,
        "§15 JIT identity renewal is applied on the served Run"
    );
}

// ============================================================================
// (2) Served chat grounding: node-ACL + RLS row-filter pre-rank
// ============================================================================

fn analyst_in(dept: &str) -> Principal {
    Principal::user("analyst", &["chat.send"])
        .with_clearance(DataClass::Internal)
        .with_department(dept)
}

#[tokio::test]
async fn r10_wrong_dept_caller_grounds_nothing_on_served_chat() {
    // A doc gated by a per-node DEPARTMENT ACL (corpus_for_scope carries it onto the chunk).
    let cfg = r#"
        version = 1
        [[kb.documents]]
        id = "settle-1"
        source = "settlement-runbook"
        text = "Settlement reconciliation runs in deferred net batches via the payment switch."
        scope = "platform"
        data_class = "internal"
        department = "settlement-eng"
    "#;
    let loaded = load_layered(&[("t", cfg)]).unwrap();
    let corpus = corpus_for_scope(&loaded.kb, RetrievalScope::PlatformAndNamespace);
    let (chat, _r) = build_chat_surface(&loaded, corpus).unwrap();

    // Right department → grounds the doc (a citation).
    let right = chat
        .turn(
            "s-ok",
            &analyst_in("settlement-eng"),
            "How does settlement reconciliation work?",
            DataClass::Internal,
        )
        .await
        .unwrap();
    match right {
        ChatReply::Answer { citations, .. } => assert!(
            citations.iter().any(|c| c.chunk_id == "settle-1"),
            "the correct-department caller must ground the doc: {citations:?}"
        ),
        o => panic!("expected a grounded Answer for the right department, got {o:?}"),
    }

    // Wrong department → grounds NOTHING (pre-rank node ACL; existence never leaks).
    let wrong = chat
        .turn(
            "s-no",
            &analyst_in("hr"),
            "How does settlement reconciliation work?",
            DataClass::Internal,
        )
        .await
        .unwrap();
    // A no-grounding answer may also come back as a plain answer with no citations — either way,
    // the wrong-dept doc must never be cited. A Clarify is acceptable (nothing to ground).
    if let ChatReply::Answer { citations, .. } = wrong {
        assert!(
            citations.is_empty(),
            "a WRONG-department caller must ground NOTHING on the served path: {citations:?}"
        );
    }
}

#[tokio::test]
async fn r10_rls_row_filter_isolates_cross_dept_row_on_served_chat() {
    // Two docs with NO node-ACL (department unset) but each carrying an RLS `department` ROW attribute,
    // and RLS row isolation ENABLED. The row-filter (bound from the OBO principal) is then the ONLY
    // gate — proving the served grounding runs the RLS row-filter pre-rank, distinct from node ACL.
    let cfg = r#"
        version = 1
        [kb]
        rls_department_isolation = true
        [[kb.documents]]
        id = "row-settle"
        source = "ledger"
        text = "Settlement reconciliation batch totals for the day."
        scope = "platform"
        data_class = "internal"
        row_attributes = { department = "settlement-eng" }
        [[kb.documents]]
        id = "row-hr"
        source = "ledger"
        text = "Settlement reconciliation payroll totals for the day."
        scope = "platform"
        data_class = "internal"
        row_attributes = { department = "hr" }
    "#;
    let loaded = load_layered(&[("t", cfg)]).unwrap();
    assert!(
        loaded.kb.rls_department_isolation,
        "RLS isolation must parse from config"
    );
    let corpus = corpus_for_scope(&loaded.kb, RetrievalScope::PlatformAndNamespace);
    let (chat, _r) = build_chat_surface(&loaded, corpus).unwrap();

    let reply = chat
        .turn(
            "rls",
            &analyst_in("settlement-eng"),
            "settlement reconciliation totals",
            DataClass::Internal,
        )
        .await
        .unwrap();
    match reply {
        ChatReply::Answer { citations, .. } => {
            assert!(
                citations.iter().any(|c| c.chunk_id == "row-settle"),
                "the caller must ground its OWN department's row: {citations:?}"
            );
            assert!(
                !citations.iter().any(|c| c.chunk_id == "row-hr"),
                "the RLS row-filter must exclude a cross-department row (existence never leaks): {citations:?}"
            );
        }
        o => panic!("expected a grounded Answer, got {o:?}"),
    }
}

// ============================================================================
// (3) Served numeric re-derivation hard gate on ledger answers
// ============================================================================

/// GAP-FIX planner-assurance-revision (item 1) — a fixed-text model [`Provider`]: the served Program
/// driver's semantic Judge is now a REAL, content-varying `RubricJudge`, never a fabricated fixed pass,
/// so `assemble_program`'s air-gapped `OfflineProvider` (a prompt-invariant "offline mode: no model
/// configured.") can no longer stand in for "the goal was genuinely achieved" — it carries none of a
/// real goal's keywords. This supplies a genuinely substantive, on-goal, safe artifact instead.
struct FixedTextProvider {
    text: String,
}
impl Provider for FixedTextProvider {
    fn id(&self) -> &str {
        "r10-test-producer"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, _prompt: &str) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(8);
        let text = self.text.clone();
        tokio::spawn(async move {
            let _ = tx.send(Event::TextDelta(text)).await;
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

/// An ENGINE provider that emits an amount-like figure with NO sourced backing — the exact thing the
/// served numeric re-derivation gate exists to block.
struct UnbackedNumberProvider;
impl Provider for UnbackedNumberProvider {
    fn id(&self) -> &str {
        "mock-number"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, _prompt: &str) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(8);
        let _ = tx.try_send(Event::TextDelta(
            "The reconciliation failure rate was 12%.".into(),
        ));
        let _ = tx.try_send(Event::Done);
        rx
    }
}

fn engine_with(provider: impl Provider + 'static) -> Engine {
    let mut router = ModelRouter::new();
    router.register(Box::new(provider));
    Engine::new(
        Box::new(StrongRedactor::new()),
        Box::new(RbacAuthorizer),
        Box::new(InMemoryAudit::default()),
        router,
    )
}

#[tokio::test]
async fn r10_unreproducible_ledger_figure_blocked_on_served_path() {
    let user = Principal::user("analyst", &["chat.send"]).with_clearance(DataClass::Public);

    // The SERVED default constructor (`from_engine_numeric_gated`, row-isolation off): the numeric
    // re-derivation HARD gate blocks a figure not attributable to any retrieved source.
    let gated = ChatSurface::from_engine_numeric_gated(
        engine_with(UnbackedNumberProvider),
        Corpus::new(),
        CacheConfig::default(),
        Box::new(FixedClock(0)),
        false,
    );
    let reply = gated
        .turn(
            "g",
            &user,
            "what was the reconciliation failure rate",
            DataClass::Public,
        )
        .await
        .expect("turn");
    match reply {
        ChatReply::Clarify { question } => assert!(
            question.to_lowercase().contains("verification")
                || question.to_lowercase().contains("can't share")
                || question.to_lowercase().contains("escalated"),
            "an unreproducible ledger figure must be BLOCKED + escalated on the served path: {question}"
        ),
        o => panic!("expected the served numeric gate to block (Clarify), got {o:?}"),
    }

    // Control: the un-gated surface ships the very same figure — proving it is the served numeric gate
    // that blocked it above, not some unrelated path.
    let plain = ChatSurface::from_engine(
        engine_with(UnbackedNumberProvider),
        Corpus::new(),
        CacheConfig::default(),
        Box::new(FixedClock(0)),
    );
    let reply = plain
        .turn(
            "p",
            &user,
            "what was the reconciliation failure rate",
            DataClass::Public,
        )
        .await
        .expect("turn");
    match reply {
        ChatReply::Answer { text, .. } => assert!(
            text.contains("12%"),
            "the un-gated surface must ship the figure verbatim: {text}"
        ),
        o => panic!("expected a plain Answer from the un-gated surface, got {o:?}"),
    }
}

// ============================================================================
// (4) The daemon spawns a ReconcilerSweeper over the SHARED exactly-once ledger
// ============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn r10_daemon_spawns_reconciler_sweep_over_shared_ledger() {
    // R16 critical: the daemon now refuses the header-trusting default authenticator unless the
    // deployment states the assumption (see r10_breach_clock_unit.rs) — state it here.
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let assembled = assemble_surface(&offline(), "chat").expect("assemble chat surface");
    let full = assemble_full(&offline(), assembled).expect("assemble fully-wired surface");

    // The daemon holds the sweeper over the served engine's shared ledger, and starts it on daemon
    // start (the handle is held for the process lifetime; here we stop it cleanly).
    assert!(
        full.reconciler_sweeper.is_some(),
        "the fully-wired daemon must hold a ReconcilerSweeper over the shared capability ledger"
    );
    let handle = full
        .spawn_reconciler_sweep()
        .expect("the daemon spawns the background sweep");
    handle.stop();

    // Prove the sweep genuinely ACTS on a lost-ack PENDING row of the SHARED ledger: build the SAME
    // unified registry the served engine uses, plant a lost-ack row, and sweep it.
    let mut report = Vec::new();
    let (_tools, ledger, reconciler) = build_unified_capability_registry_shared(&mut report);
    // A side-effecting capability call that CLAIMED the ledger but whose ack was lost (process died
    // mid-flight) leaves a PENDING row carrying its reconcile-probe metadata.
    let _ = ledger.claim("lost-ack-1");
    ledger.record_pending_meta("lost-ack-1", "settlement.notify", "{\"batch\":\"b1\"}");
    let sweeper = ReconcilerSweeper::new(
        Arc::clone(&ledger),
        Arc::clone(&reconciler),
        Arc::new(RecordingEscalationSink::new()),
        "r10-test-node",
        0, // min_age 0: a just-claimed lost-ack row is immediately eligible in this deterministic test
        30,
    );
    let swept = sweeper.sweep_once();
    let acted = swept.committed.len() + swept.failed.len() + swept.escalated.len();
    assert!(
        acted >= 1,
        "the sweep must ACT on the lost-ack PENDING row over the shared ledger (never passive expiry): {swept:?}"
    );
    assert!(
        swept.escalated.contains(&"lost-ack-1".to_string()),
        "the default ManualReconciler has no auto-probe → the lost-ack row is escalated for review: {swept:?}"
    );
}

// ============================================================================
// (5) The MCP runtime registers into the served unified Capability registry
// ============================================================================

/// A deterministic, network-free MCP transport exposing one read-only tool.
struct FakeTransport;
impl McpTransport for FakeTransport {
    fn connect(&self, _token: Option<&str>) -> Result<(), McpError> {
        Ok(())
    }
    fn list_tools(&self) -> Result<Vec<ToolManifest>, McpError> {
        Ok(vec![ToolManifest::new(
            "search_code",
            "search the repository source code",
        )])
    }
    fn call_tool(&self, tool: &str, args: &str) -> Result<ToolResult, McpError> {
        Ok(ToolResult::ok(&format!("mcp:{tool}:{args}")))
    }
}

#[test]
fn r10_mcp_runtime_registers_into_served_unified_registry() {
    // Build the SAME unified Capability registry the served engine dispatches through.
    let mut report = Vec::new();
    let (mut registry, _ledger, _reconciler) =
        build_unified_capability_registry_shared(&mut report);
    // It already carries the built-in native capability.
    let native: Vec<String> = registry.schemas().into_iter().map(|s| s.name).collect();
    assert!(
        native.iter().any(|n| n == "query_ledger"),
        "the served registry ships the native query_ledger capability: {native:?}"
    );

    // A real (in-memory) MCP runtime, TOFU-pinned + approved (first-use is quarantined by design).
    let mut mcp = McpRegistry::new();
    mcp.register(McpServer::new(
        "git",
        "https://git.example/mcp",
        Box::new(FakeTransport),
    ));
    let mcp = Arc::new(mcp);
    let auth: Arc<dyn AuthProvider> = Arc::new(NoAuth);
    let pins = InMemoryPinStore::new();
    let d1 = mcp.discover_pinned("alice", auth.as_ref(), &pins);
    assert!(
        d1.plannable().is_empty(),
        "TOFU: nothing plannable before approval"
    );
    d1.servers[0].approve(&pins, "alice", 1);

    // The runtimed-level wire registers the pinned MCP tools into the SAME unified registry.
    let admitted = register_served_mcp_runtime(&mut registry, mcp, auth, &pins, "alice");
    let git_search = McpRegistry::qualify("https://git.example/mcp", "search_code");
    assert!(
        admitted.contains(&git_search),
        "the MCP tool must register into the served unified registry: {admitted:?}"
    );
    let all: Vec<String> = registry.schemas().into_iter().map(|s| s.name).collect();
    assert!(
        all.iter().any(|n| n == &git_search) && all.iter().any(|n| n == "query_ledger"),
        "native + MCP capabilities co-exist in ONE registry (one dispatch path): {all:?}"
    );
}
