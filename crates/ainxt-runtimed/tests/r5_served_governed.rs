// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R5 — the SHIPPED daemon (`assemble_full` / `AssembledFull`) exercises the served-path governance
//! leaves that every phase built but left unreachable:
//!
//! * a **regulated turn is department + node-ACL filtered pre-rank** on the served Context-Fabric
//!   compile path (`context-fabric` / `surfaces-profiles-skills-config`);
//! * the RBI **outsourcing register** is installed on the router as its non-overridable eligibility
//!   input, and the online **canary/auto-rollback/drift** controller is live on the served surface
//!   (`regulated-fi-responsible-lifecycle` / `eval-tester-scenarios`);
//! * a **budget-capped durable Program** run **reports capped** (`CappedPartial`) and its state
//!   **durably persists** so it is resumable (`loop-teams-longhorizon`).
//!
//! The air-gapped default still serves a basic chat turn — no empty-pool 503.

use std::collections::BTreeMap;
use std::sync::Arc;

use ainxt_eventlog::EventLog;
use ainxt_planner::program::{NodeClass, NodeDecl};
use ainxt_profile::RetrievalScope;
use ainxt_runtimed::governed::{
    access_for, compile_served_context, eligible_default, retrieval_corpus_for_scope,
};
use ainxt_runtimed::{
    assemble_chat, assemble_full, build_engine, capped_config, load_layered, run_program_durable,
    KbConfig, KbDocument, KbScope, RunIdentitySpec,
};
use ainxt_types::{DataClass, Principal};

/// A daemon config whose KB carries two Pii settlement docs, each node-ACL locked to a different
/// department — the served corpus a regulated turn grounds over.
fn loaded_with_governed_kb() -> ainxt_runtimed::LoadedConfig {
    // R16 critical: the daemon now refuses the header-trusting default authenticator unless the
    // deployment states the assumption (see r10_breach_clock_unit.rs) — state it here.
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let mut loaded = load_layered(&[("base", "version = 1")]).unwrap();
    let doc = |id: &str, dept: &str| KbDocument {
        id: id.into(),
        source: format!("{id}.md"),
        text: format!("settlement reconciliation runbook for {dept}"),
        data_class: DataClass::Pii,
        scope: KbScope::Platform,
        namespace: None,
        repo: None,
        department: Some(dept.into()),
        max_ad_level: None,
        allow_groups: vec![],
        deny_groups: vec![],
        row_attributes: BTreeMap::new(),
    };
    loaded.kb = KbConfig {
        documents: vec![doc("settle-alpha", "alpha"), doc("settle-beta", "beta")],
        rls_department_isolation: false,
        rag_enabled: true,
    };
    loaded
}

#[test]
fn assemble_full_reports_the_served_governance_wiring() {
    let loaded = loaded_with_governed_kb();
    let assembled = assemble_chat(&loaded).unwrap();
    let full = assemble_full(&loaded, assembled).unwrap();

    let joined = full.report.join("\n");
    assert!(
        joined.contains("RBI outsourcing register installed"),
        "the router must install the outsourcing register as its eligibility input:\n{joined}"
    );
    assert!(
        joined.contains("release control:"),
        "the online canary/auto-rollback/drift controller must be live on the served surface:\n{joined}"
    );
    assert_eq!(
        full.outsourcing_residency, "in",
        "default residency is India"
    );
}

/// GUARD-09/GUARD-07: the served ChatSurface's `ConversationManager` must actually receive the
/// deployment's `[guardrails]` config (groundedness/citation/strict), not build every served
/// manager with guardrails permanently `None` regardless of config. Fail-before: no call in the
/// composition ever reached `ConversationManager::with_guardrails` — `[guardrails] groundedness =
/// "enforce"` had zero effect on the served chat path.
#[test]
fn served_chat_surface_applies_the_configured_guardrails() {
    // R16 critical: state the trusted-gateway assumption (see r10_breach_clock_unit.rs).
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let src = "version = 1\n\
        [guardrails]\n\
        groundedness = \"enforce\"\n\
        groundedness_strict = true\n\
        citation = \"audit\"\n";
    let loaded = load_layered(&[("t", src)]).unwrap();
    assert!(
        loaded.runtime.guardrails.groundedness_strict,
        "sanity: the config layer must parse the new groundedness_strict field"
    );
    let assembled = assemble_chat(&loaded).unwrap();
    let full = assemble_full(&loaded, assembled).unwrap();
    let joined = full.report.join("\n");
    assert!(
        joined.contains("groundedness=Enforce") && joined.contains("groundedness_strict=true"),
        "the served chat surface must report the config it actually applied, not a permanently \
         inert default:\n{joined}"
    );
    assert!(
        joined.contains("live"),
        "a non-Off guardrails config must be reported LIVE on the served surface:\n{joined}"
    );

    // Regression guard: the shipped-default air-gapped config (guardrails untouched by the caller)
    // must still report something — never panic — and an all-Off config must say "inert".
    let off = load_layered(&[("o", "version = 1")]).unwrap();
    assert!(
        off.runtime.guardrails.is_off(),
        "sanity: default config is all-Off"
    );
    let assembled_off = assemble_chat(&off).unwrap();
    let full_off = assemble_full(&off, assembled_off).unwrap();
    assert!(
        full_off.report.iter().any(|r| r.contains("inert")),
        "an all-Off guardrails config must be reported inert:\n{:?}",
        full_off.report
    );
}

#[test]
fn regulated_turn_is_department_and_node_acl_filtered_on_the_served_path() {
    let loaded = loaded_with_governed_kb();
    // The served surface's platform-scope corpus, built from the DAEMON KB with ACLs preserved.
    let scope = RetrievalScope::PlatformAndNamespace;
    let corpus = retrieval_corpus_for_scope(&loaded.kb, scope);
    assert_eq!(corpus.len(), 2, "both docs are in scope before RBAC");

    // A regulated (Pii) turn from an alpha-department caller.
    let principal = Principal::user("u-alpha", &["chat.send"])
        .with_clearance(DataClass::Pii)
        .with_department("alpha");
    assert!(
        principal.clearance.is_regulated(),
        "this is a regulated turn"
    );
    let access = access_for(&principal, Some(3), &[]);
    let seeds = BTreeMap::new();

    let window = compile_served_context(
        &corpus,
        "settlement reconciliation",
        &access,
        None,
        None,
        &seeds,
        eligible_default(),
    );
    let cited: Vec<&str> = window
        .context
        .citations
        .iter()
        .map(|c| c.chunk_id.as_str())
        .collect();
    assert!(
        cited.contains(&"settle-alpha"),
        "alpha's own doc grounds: {cited:?}"
    );
    assert!(
        !cited.contains(&"settle-beta"),
        "beta's node-ACL doc is filtered PRE-RANK for the alpha caller — existence never leaks: {cited:?}"
    );
    // Budget-fit ran against the eligible-model set (a fitted window has a positive target).
    assert!(
        window.window_tokens > 0,
        "the eligible-floor budget fit produced a window"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn budget_capped_durable_program_reports_capped_and_persists() {
    let loaded = load_layered(&[("base", "version = 1")]).unwrap();
    let (engine, _r) = build_engine(&loaded.runtime).unwrap();
    let engine = Arc::new(engine);

    let dir = std::env::temp_dir().join(format!(
        "ainxt-r5-durable-prog-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));

    let identity = RunIdentitySpec::new(
        "program",
        "r5-capped",
        "r5-capped-run",
        DataClass::Internal,
        "u1",
    );
    // A 1-token ceiling: the first module's real engine turn spends past it → BudgetExhausted →
    // the program reports a terminal CappedPartial (never a fabricated Completed).
    let run = run_program_durable(
        engine.clone(),
        identity,
        "reconcile the ledger",
        vec![
            NodeDecl::new("n1", NodeClass::MigrationRun),
            NodeDecl::new("n2", NodeClass::MigrationRun),
            NodeDecl::new("n3", NodeClass::MigrationRun),
        ],
        capped_config(1),
        None,
        dir.clone(),
    )
    .await
    .expect("durable program run");

    assert!(
        format!("{:?}", run.report.outcome).contains("CappedPartial"),
        "a budget-capped program must report CappedPartial, got {:?}",
        run.report.outcome
    );
    // Durable: the event stream persisted to disk (Created + Decomposed + supervisor events).
    assert!(
        run.events.len() >= 2,
        "the durable log must hold at least the seeded Created + Decomposed events"
    );
    let jsonl_files: Vec<_> = std::fs::read_dir(&dir)
        .expect("durable dir exists")
        .filter_map(|e| e.ok())
        .collect();
    assert!(
        !jsonl_files.is_empty(),
        "the durable program log wrote records to disk"
    );

    // Resumable: reopening the SAME durable dir replays the persisted stream (no re-seed, no loss).
    let identity2 = RunIdentitySpec::new(
        "program",
        "r5-capped",
        "r5-capped-run",
        DataClass::Internal,
        "u1",
    );
    let resumed = run_program_durable(
        engine,
        identity2,
        "reconcile the ledger",
        vec![
            NodeDecl::new("n1", NodeClass::MigrationRun),
            NodeDecl::new("n2", NodeClass::MigrationRun),
            NodeDecl::new("n3", NodeClass::MigrationRun),
        ],
        capped_config(1),
        None,
        dir.clone(),
    )
    .await
    .expect("resumed durable program run");
    assert!(
        resumed.events.len() >= run.events.len(),
        "resuming preserves the durable event history (never fewer events than before)"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn served_release_controller_rolls_back_a_regression() {
    use ainxt_canary::experiment::{Notifier, PointerController};
    use ainxt_quality::monitor::DriftResponder;

    struct MemPointer(String);
    impl PointerController for MemPointer {
        fn current(&self) -> String {
            self.0.clone()
        }
        fn flip(&mut self, to: &str) -> String {
            std::mem::replace(&mut self.0, to.to_string())
        }
    }
    struct Sink;
    impl Notifier for Sink {
        fn notify(&mut self, _m: &str) {}
    }
    impl DriftResponder for Sink {
        fn open_ticket(&mut self, _s: &str) {}
        fn rollback_last_good(&mut self) -> bool {
            true
        }
    }

    // R16 critical: the daemon now refuses the header-trusting default authenticator unless the
    // deployment states the assumption (see r10_breach_clock_unit.rs) — state it here.
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let loaded = load_layered(&[("base", "version = 1")]).unwrap();
    let assembled = assemble_chat(&loaded).unwrap();
    let full = assemble_full(&loaded, assembled).unwrap();

    let mut ptr = MemPointer("env/prod".into());
    let (mut n, mut r) = (Sink, Sink);
    let mut rolled_back = false;
    for _ in 0..500 {
        let step = full.release_controller.lock().unwrap().ingest(
            "env/candidate",
            5.0,
            &mut ptr,
            &mut n,
            &mut r,
        );
        if step.rolled_back() {
            rolled_back = true;
            break;
        }
    }
    assert!(
        rolled_back,
        "the served controller auto-rolls-back an established regression"
    );
    assert_eq!(
        ptr.current(),
        "env/prod",
        "the deploy pointer returns to the champion"
    );
}

/// The air-gapped default still serves a basic chat turn — no empty-pool 503.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn air_gapped_default_still_serves_a_basic_chat_turn() {
    use ainxt_client::{Client, ClientConfig};

    // R16 critical: the daemon now refuses the header-trusting default authenticator unless the
    // deployment states the assumption (see r10_breach_clock_unit.rs) — state it here.
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let loaded = load_layered(&[("base", "version = 1")]).unwrap();
    let assembled = assemble_chat(&loaded).unwrap();
    let full = assemble_full(&loaded, assembled).unwrap();
    let client = Client::in_process(
        full.manager.clone(),
        Principal::user("u", &["chat.send"]),
        ClientConfig::default(),
    );
    let out = client.chat("s", "t", "hi").unwrap().collect().await;
    assert!(
        out.completed,
        "the air-gapped daemon must complete a basic chat turn (no 503)"
    );
}

/// FI-01 §5.4: `AssembledFull::sweep_event_log` must actually catch a write that bypassed the
/// daemon's `GuardedEventLog` wrapper — the defense-in-depth proof that the write-path guard held,
/// not merely a mechanism nobody ever calls against a real sink.
#[test]
fn sweep_event_log_catches_a_bypassed_raw_write() {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("ainxt-fi01-sweep-{nanos}"));
    let src = format!(
        "version = 1\n[server]\nevent_log_dir = {:?}\n",
        dir.to_string_lossy()
    );
    let loaded = load_layered(&[("t", &src)]).unwrap();
    let assembled = assemble_chat(&loaded).unwrap();
    let full = assemble_full(&loaded, assembled).unwrap();

    // Baseline: a session with only genuinely-guarded writes sweeps clean (the positive proof).
    full.event_log
        .append(
            "sweep-sess",
            "alice",
            "note",
            "hello, nothing sensitive here",
        )
        .unwrap();
    assert!(
        full.sweep_event_log("sweep-sess", 1000).is_empty(),
        "a session with only guarded writes must sweep clean"
    );
    assert_eq!(
        full.incidents.lock().unwrap().incidents().count(),
        0,
        "a clean sweep must arm no incident"
    );

    // Simulate a write-path bypass: a SEPARATE, unwrapped `JsonlEventLog` instance pointed at the
    // SAME directory appends a raw PAN directly — exactly what landing a record via any future
    // caller that skips `GuardedEventLog`/`StrongMemoryRedactor` would look like. `records()` reads
    // straight off disk, so the daemon's own (guarded) handle sees it too.
    let bare = ainxt_eventlog::JsonlEventLog::open(&dir).unwrap();
    bare.append(
        "sweep-sess",
        "eve",
        "note",
        "refund to card 4111111111111111 done",
    )
    .unwrap();

    let hits = full.sweep_event_log("sweep-sess", 2000);
    assert_eq!(
        hits.len(),
        1,
        "the sweep must catch exactly the bypassed record: {hits:?}"
    );
    assert!(
        !hits[0].sample.contains("4111111111111111"),
        "the sweep's own sample must be redacted, never echo the raw PAN it found"
    );
    // FI-02: the hit must also have armed a real §5.4 store-sweep incident on the served register —
    // not just been returned to a caller who might do nothing with it.
    assert_eq!(
        full.incidents.lock().unwrap().incidents().count(),
        1,
        "a sweep hit must arm exactly one store-sweep incident on the live served register"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// GAP-AUDIT regulated-fi #4 — `sweep_event_log` required a caller to already know which session to
/// check; `sweep_all_sessions` (built on the new `EventLog::sessions()`) covers every session the
/// daemon's own log knows about, which is what makes a cadence-driven, unattended sweep possible.
/// Proves it catches a bypass in a session NOBODY names explicitly, across multiple sessions.
#[test]
fn sweep_all_sessions_catches_a_bypass_without_being_told_the_session_name() {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("ainxt-fi04-sweep-all-{nanos}"));
    let src = format!(
        "version = 1\n[server]\nevent_log_dir = {:?}\n",
        dir.to_string_lossy()
    );
    let loaded = load_layered(&[("t", &src)]).unwrap();
    let assembled = assemble_chat(&loaded).unwrap();
    let full = assemble_full(&loaded, assembled).unwrap();

    full.event_log
        .append("sess-a", "alice", "note", "clean")
        .unwrap();
    full.event_log
        .append("sess-b", "bob", "note", "also clean")
        .unwrap();

    // A write-path bypass lands a raw PAN in a THIRD session the test never names to `sweep_event_log`
    // directly — only `sweep_all_sessions` can find it, because it enumerates the log itself.
    let bare = ainxt_eventlog::JsonlEventLog::open(&dir).unwrap();
    bare.append(
        "sess-c-bypassed",
        "eve",
        "note",
        "refund to card 4111111111111111 done",
    )
    .unwrap();

    assert!(
        full.event_log.sessions().len() >= 3,
        "the log must enumerate all three sessions it holds: {:?}",
        full.event_log.sessions()
    );

    let hits = full.sweep_all_sessions(500);
    assert_eq!(
        hits.len(),
        1,
        "sweep_all_sessions must find the bypassed record without being told which session: {hits:?}"
    );
    assert_eq!(
        full.incidents.lock().unwrap().incidents().count(),
        1,
        "the cross-session sweep must arm exactly one store-sweep incident"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// GAP-AUDIT regulated-fi #4 — `CadenceScheduler` (fully implemented and unit-tested in `ainxt-incident`
/// in isolation) is now LIVE on `AssembledFull`, seeded with the India-default schedule (all three
/// monitors due immediately on a fresh register).
#[test]
fn cadence_scheduler_is_live_on_the_served_surface_and_seeded_with_the_india_regulatory_default() {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("ainxt-fi04-cadence-{nanos}"));
    let src = format!(
        "version = 1\n[server]\nevent_log_dir = {:?}\n",
        dir.to_string_lossy()
    );
    let loaded = load_layered(&[("t", &src)]).unwrap();
    let assembled = assemble_chat(&loaded).unwrap();
    let full = assemble_full(&loaded, assembled).unwrap();

    let due = full.cadence.lock().unwrap().due(0);
    assert!(
        due.iter()
            .any(|m| m == ainxt_incident::cadence::MONITOR_STORE_SWEEP),
        "a fresh cadence schedule must have the store-sweep monitor due immediately: {due:?}"
    );
    assert!(
        due.iter()
            .any(|m| m == ainxt_incident::cadence::MONITOR_NTP_SKEW),
        "a fresh cadence schedule must have the NTP-skew monitor due immediately: {due:?}"
    );

    // `mark_ran` genuinely advances the schedule (proving this is the REAL scheduler, not a stub).
    full.cadence
        .lock()
        .unwrap()
        .mark_ran(ainxt_incident::cadence::MONITOR_STORE_SWEEP, 0);
    let due_after = full.cadence.lock().unwrap().due(1);
    assert!(
        !due_after
            .iter()
            .any(|m| m == ainxt_incident::cadence::MONITOR_STORE_SWEEP),
        "store-sweep must not be due again immediately after marking it ran: {due_after:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
