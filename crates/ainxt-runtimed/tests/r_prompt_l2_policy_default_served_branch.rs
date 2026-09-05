// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! gap5-prompt-governance #2 — `[policy] l2_body` (`ainxt_config::PolicyEngineConfig`, resolved
//! through the real layered TOML merge) must reach the L2 layer of the DEFAULT served `/v1/chat`
//! compile (`build_served_chat_prompt`'s no-`prompt_dir` branch) — not just the git-native
//! `prompt_dir` branch and the unreachable `governed::assemble_served_prompt_engine_from_config`
//! (nothing in `main.rs`/the `--surface` dispatch table ever calls that function).
//!
//! FAIL-BEFORE: the default branch called `ainxt_convo::PromptDeployment::served_default`, which
//! always passed `None` for the L2 override — a deployment/tenant `[policy]` layer had ZERO effect on
//! a served turn compiled without `prompt_dir` configured (the shipped default for every daemon that
//! hasn't opted into git-native prompt files).
//! PASS-AFTER: a served `/v1/chat` turn's forensically-recorded L2 (Policy) layer content-hash changes
//! when `[policy] l2_body` is configured, and ONLY the L2 layer's hash changes — L1/L3/L4 are
//! untouched, matching the design's "a policy change updates every Role's L2 without touching any
//! Role's L3" guarantee.
//!
//! This goes through the REAL served composition root: `assemble_selected(loaded, "chat")` is the
//! exact function `ainxt-runtimed`'s `main.rs` calls for the default (and every) `--surface chat`
//! daemon, followed by a real in-process chat turn via `ainxt_client::Client` (the same client used by
//! `r14_served_forensic_prompt.rs`) — not a bespoke instance of `PromptDeployment`/`ServedChatPrompts`
//! built directly in the test.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use ainxt_client::{Client, ClientConfig};
use ainxt_prompt::registry::Layer;
use ainxt_prompt::service::ForensicFileSink;
use ainxt_runtimed::{assemble_selected, load_layered};
use ainxt_types::Principal;

fn tmp_dir(tag: &str) -> PathBuf {
    static CTR: AtomicU64 = AtomicU64::new(0);
    let n = CTR.fetch_add(1, Ordering::SeqCst);
    let p = std::env::temp_dir().join(format!("ainxt-r-l2policy-{tag}-{}-{n}", std::process::id()));
    let _ = fs::remove_dir_all(&p);
    p
}

/// Run one real served chat turn through the REAL composition root (`assemble_selected`, the same
/// function `main.rs` calls) and return its durably-recorded forensic layer tuple.
async fn served_layers(
    event_log_dir: &std::path::Path,
    policy_toml: Option<&str>,
) -> Vec<(Layer, String)> {
    let mut src = format!(
        "version = 1\n[server]\nevent_log_dir = {:?}\n",
        event_log_dir.to_string_lossy()
    );
    if let Some(p) = policy_toml {
        src.push_str("[policy]\n");
        src.push_str(p);
        src.push('\n');
    }
    let loaded = load_layered(&[("t", &src)]).expect("load config");
    let assembled =
        assemble_selected(&loaded, "chat").expect("assemble the REAL served chat surface");

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
    assert!(out.completed, "the real served chat turn completes");

    let forensic = event_log_dir.join("prompt-forensic.jsonl");
    let records = ForensicFileSink::new(&forensic)
        .records()
        .expect("durable forensic record readable after the served turn");
    assert_eq!(records.len(), 1, "exactly one served turn recorded");
    records[0]
        .layers
        .iter()
        .map(|l| (l.layer, l.content_hash.clone()))
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn default_served_branch_reads_config_sourced_l2_body_and_only_l2_changes() {
    let dir_default = tmp_dir("default");
    let dir_custom = tmp_dir("custom");

    // Turn A: no [policy] layer at all — the shipped-default L2 body.
    let baseline = served_layers(&dir_default, None).await;

    // Turn B: a deployment/tenant layer overrides [policy] l2_body — a genuinely different clause, as
    // a real RBI-disclosure-requirement change would look.
    let custom = served_layers(
        &dir_custom,
        Some(r#"l2_body = "A NEW RBI disclosure clause applies to every response, superseding the shipped default text.""#),
    )
    .await;

    assert_eq!(baseline.len(), 4, "L1..L4 all present");
    assert_eq!(custom.len(), 4, "L1..L4 all present");

    for (layer, base_hash) in &baseline {
        let custom_hash = &custom
            .iter()
            .find(|(l, _)| l == layer)
            .expect("layer present in both")
            .1;
        if *layer == Layer::Policy {
            assert_ne!(
                base_hash, custom_hash,
                "L2 (Policy) content-hash MUST change when [policy] l2_body is config-sourced — the \
                 default served branch must actually read the resolved config, not the compiled-in \
                 default"
            );
        } else {
            assert_eq!(
                base_hash, custom_hash,
                "{layer:?} must be byte-for-byte unchanged — an L2 policy change must not touch any \
                 other layer, per PROMPT_ENGINEERING.md §2"
            );
        }
    }

    let _ = fs::remove_dir_all(&dir_default);
    let _ = fs::remove_dir_all(&dir_custom);
}

#[tokio::test(flavor = "multi_thread")]
async fn default_served_branch_with_no_policy_layer_is_byte_identical_to_shipped_default() {
    let dir_a = tmp_dir("noop-a");
    let dir_b = tmp_dir("noop-b");

    // No [policy] layer in either — must be deterministic/identical (additive change, not a behavior
    // change for an unconfigured deployment).
    let a = served_layers(&dir_a, None).await;
    let b = served_layers(&dir_b, None).await;
    assert_eq!(
        a, b,
        "an unconfigured [policy] layer must serve byte-identical layers every time"
    );

    let _ = fs::remove_dir_all(&dir_a);
    let _ = fs::remove_dir_all(&dir_b);
}
