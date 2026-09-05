// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R14 (served-composition) — the SHIPPED daemon's `/v1/chat` compile is wired to a durable
//! ForensicFileSink (durable-before-provider, PE11) AND, when `[server] prompt_dir` is configured, to a
//! GIT-NATIVE FILE-sourced prompt registry (§3). Before this round the served ChatSurface compiled over
//! a `NullSink` (forensic persistence was caller-discretionary and OFF on the served path) and always
//! served the hardcoded canonical constant bodies. Now `build_served_chat_prompt` injects both into the
//! served compile, so a real served chat turn leaves a replayable forensic record on disk.
//!
//! FAIL-BEFORE: no forensic record was written by a served turn (NullSink); `prompt_dir` had no effect.
//! PASS-AFTER: green, offline, deterministic. The real git repo (branch protection / signed tags) and a
//! Postgres/WORM sink are the infra seams; the file loader + `ForensicFileSink` are proven offline here.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use ainxt_client::{Client, ClientConfig};
use ainxt_prompt::service::ForensicFileSink;
use ainxt_runtimed::{assemble_selected, load_layered, LoadedConfig};
use ainxt_types::Principal;

fn tmp(tag: &str) -> PathBuf {
    static CTR: AtomicU64 = AtomicU64::new(0);
    let n = CTR.fetch_add(1, Ordering::SeqCst);
    let p = std::env::temp_dir().join(format!("ainxt-r14-{tag}-{}-{n}", std::process::id()));
    let _ = fs::remove_dir_all(&p);
    p
}

fn config_with(event_log_dir: &Path, prompt_dir: Option<&Path>) -> LoadedConfig {
    let mut src = format!(
        "version = 1\n[server]\nevent_log_dir = {:?}\n",
        event_log_dir.to_string_lossy()
    );
    if let Some(pd) = prompt_dir {
        src.push_str(&format!("prompt_dir = {:?}\n", pd.to_string_lossy()));
    }
    load_layered(&[("r14", &src)]).expect("load config")
}

async fn one_chat_turn(loaded: &LoadedConfig) {
    let assembled = assemble_selected(loaded, "chat").expect("assemble chat");
    let client = Client::in_process(
        assembled.manager,
        Principal::user("u", &["chat.send"]).with_department("payments"),
        ClientConfig::default(),
    );
    let out = client
        .chat("s", "t1", "how did UPI settlement grow?")
        .unwrap()
        .collect()
        .await;
    assert!(out.completed, "the served chat turn completes");
}

#[tokio::test(flavor = "multi_thread")]
async fn r14_served_chat_turn_writes_durable_forensic_record() {
    let log_dir = tmp("forensic-served");
    let loaded = config_with(&log_dir, None);
    one_chat_turn(&loaded).await;

    // A FRESH reader over the daemon's forensic path (an independent auditor / a restarted process)
    // sees the durable record the served compile fsync'd BEFORE the provider call — no in-process state.
    let forensic = log_dir.join("prompt-forensic.jsonl");
    let records = ForensicFileSink::new(&forensic)
        .records()
        .expect("durable forensic records readable after the served turn");
    assert!(
        !records.is_empty(),
        "a served /v1/chat turn must durably record its compiled prompt before the provider call (PE11)"
    );
    // The shipped canonical constant deployment is NOT git-native, so the control SHA is not gitfs-*.
    assert!(
        !records[0].control_sha.starts_with("gitfs-"),
        "the default (no prompt_dir) served registry is the constant deployment: {}",
        records[0].control_sha
    );
    let _ = fs::remove_dir_all(&log_dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn r14_prompt_dir_makes_served_registry_git_native() {
    let tree = tmp("prompt-tree");
    build_prompt_tree(&tree);
    let log_dir = tmp("forensic-gitnative");
    let loaded = config_with(&log_dir, Some(&tree));

    // The assembly report records that the served registry is git-native FILE-sourced.
    let assembled =
        assemble_selected(&loaded, "chat").expect("assemble chat over git-native prompts");
    assert!(
        assembled
            .report
            .iter()
            .any(|r| r.contains("GIT-NATIVE FILE-sourced")),
        "prompt_dir must make the served registry file-sourced: {:?}",
        assembled.report
    );

    // A served turn's forensic record is attributed to the file tree's content-address (gitfs-*).
    one_chat_turn(&loaded).await;
    let forensic = log_dir.join("prompt-forensic.jsonl");
    let records = ForensicFileSink::new(&forensic).records().expect("records");
    assert!(!records.is_empty(), "a served turn records forensically");
    assert!(
        records[0].control_sha.starts_with("gitfs-"),
        "the git-native served registry attributes the forensic record to the file tree: {}",
        records[0].control_sha
    );
    let _ = fs::remove_dir_all(&tree);
    let _ = fs::remove_dir_all(&log_dir);
}

// A minimal but real git-native chat prompt tree (four L1..L4 layers, two per-model variants each).
fn build_prompt_tree(root: &Path) {
    fs::create_dir_all(root).unwrap();
    let layers = [
        ("prompt.chat.persona", "persona", "eval.chat.persona"),
        ("prompt.chat.policy", "policy", "eval.chat.policy"),
        ("prompt.chat.task", "task", "eval.chat.task"),
        ("prompt.chat.guards", "guards", "eval.chat.guards"),
    ];
    for (id, layer, eval_set) in layers {
        let dir = root.join(id);
        fs::create_dir_all(&dir).unwrap();
        let manifest = format!(
            r#"{{
                "kind": "prompt", "id": "{id}", "layer": "{layer}", "version": "1.0.0",
                "owner": "platform-prompt-eng", "author": "prompt-studio",
                "model_variants": ["claude", "qwen"],
                "eval_set": {{ "id": "{eval_set}", "version": "^1.0.0" }}
            }}"#
        );
        fs::write(dir.join("definition.json"), manifest).unwrap();
        fs::write(
            dir.join("variant.claude.md"),
            format!("FILE-{layer}-claude body"),
        )
        .unwrap();
        fs::write(
            dir.join("variant.qwen.md"),
            format!("FILE-{layer}-qwen body"),
        )
        .unwrap();
    }
}
