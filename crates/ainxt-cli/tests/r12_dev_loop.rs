// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! r12 — the CLI local dev loop: hot-reload + harness test (gap "CLI local dev loop: hot-reload +
//! harness test").
//!
//! `ainxt harness test` runs a manifest offline and returns a deterministic PASS/FAIL + exit code (a
//! local acceptance smoke for CI/dev, no server). `ainxt harness dev --watch` hot-reloads: it
//! re-runs the harness whenever the manifest source changes. The reload DECISION and the loop are
//! pure/offline (the OS file-watch that feeds the loop is the only infra part), and are exercised
//! here directly with a scripted content sequence so the loop's correctness is proven without a real
//! filesystem watcher.

use ainxt_cli::{
    dev_should_reload, parse_args, run_cli, run_harness_dev_watch, HarnessCommand, HarnessSub,
    Parsed, EXIT_OK, EXIT_TURN_ERROR,
};
use ainxt_types::DataClass;

const VALID: &str = r#"{"kind":"harness","id":"demo","version":"1.0.0","owner":"me",
  "requested_capabilities":["kb.search"],
  "steps":[{"id":"s1","kind":"llm","capability":"kb.search","estimated_tokens":1}]}"#;

// A manifest whose step uses a capability it never requested → lint RED.
const LINT_RED: &str = r#"{"kind":"harness","id":"bad","version":"1.0.0","owner":"me",
  "requested_capabilities":[],
  "steps":[{"id":"s1","kind":"llm","capability":"kb.search","estimated_tokens":1}]}"#;

fn write_temp(name: &str, content: &str) -> String {
    let mut p = std::env::temp_dir();
    p.push(format!("ainxt_r12_{}_{}.json", std::process::id(), name));
    std::fs::write(&p, content).expect("write temp manifest");
    p.to_string_lossy().into_owned()
}

fn cli(argv: &[&str]) -> (i32, String) {
    let argv: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
    let mut out: Vec<u8> = Vec::new();
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let code = rt.block_on(run_cli(&argv, "", &mut out));
    (code, String::from_utf8(out).unwrap())
}

#[test]
fn r12_harness_test_passes_on_a_valid_manifest() {
    let path = write_temp("ok", VALID);
    let (code, text) = cli(&["harness", "test", &path]);
    assert_eq!(code, EXIT_OK, "valid manifest must PASS: {text}");
    assert!(text.contains("test: PASS"), "expected PASS line: {text}");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn r12_harness_test_fails_on_a_lint_red_manifest() {
    let path = write_temp("bad", LINT_RED);
    let (code, text) = cli(&["harness", "test", &path]);
    assert_eq!(code, EXIT_TURN_ERROR, "lint-red manifest must FAIL: {text}");
    assert!(text.contains("test: FAIL"), "expected FAIL line: {text}");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn r12_parses_dev_watch_and_test_subcommands() {
    match parse_args(&["harness", "dev", "m.json", "--watch"].map(String::from)).unwrap() {
        Parsed::Harness(HarnessCommand {
            sub: HarnessSub::Dev,
            watch,
            ..
        }) => assert!(watch),
        other => panic!("expected dev --watch, got {other:?}"),
    }
    match parse_args(&["harness", "test", "m.json"].map(String::from)).unwrap() {
        Parsed::Harness(HarnessCommand {
            sub: HarnessSub::Test,
            ..
        }) => {}
        other => panic!("expected test, got {other:?}"),
    }
}

#[test]
fn r12_reload_decision_only_fires_on_change() {
    // First observation always runs; an identical re-read does NOT; a changed read does.
    assert!(dev_should_reload(None, VALID), "first observation runs");
    assert!(
        !dev_should_reload(Some(VALID), VALID),
        "unchanged source must not re-run"
    );
    assert!(
        dev_should_reload(Some(VALID), LINT_RED),
        "changed source re-runs"
    );
}

#[test]
fn r12_dev_watch_reruns_exactly_on_each_change() {
    // A scripted poll sequence: v1, v1 (no-op), v2, then stop. The loop must re-run only on the two
    // DISTINCT sources, and end on the last run's exit code.
    let v1 = VALID.to_string();
    let v1_again = VALID.to_string();
    let v2 = LINT_RED.to_string(); // a change that lints RED → EXIT_TURN_ERROR on that run
    let mut seq = vec![v1, v1_again, v2].into_iter();
    let poll: ainxt_cli::DevPoll = Box::new(move || seq.next());

    let cmd = HarnessCommand {
        sub: HarnessSub::Dev,
        path: "scripted".into(),
        mode: ainxt_cli::OutputMode::Print,
        data_class: DataClass::Internal,
        watch: true,
    };

    let mut out: Vec<u8> = Vec::new();
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let exit = rt.block_on(run_harness_dev_watch(&cmd, &mut out, poll));
    let text = String::from_utf8(out).unwrap();

    // Exactly two re-runs (the duplicate v1 was skipped).
    assert!(text.contains("change #1"), "first change must run: {text}");
    assert!(
        text.contains("change #2"),
        "the distinct second source must run: {text}"
    );
    assert!(
        !text.contains("change #3"),
        "the duplicate source must NOT re-run: {text}"
    );
    // The last run (LINT_RED) failed, so the loop returns the failing exit code.
    assert_eq!(
        exit, EXIT_TURN_ERROR,
        "loop returns the last run's exit code: {text}"
    );
}
