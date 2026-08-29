// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! gap5-prompt-governance #3 — steerability gating must actually FILTER the real served chat family
//! list, not sit crate-tested with zero callers outside `ainxt-prompt`'s own `#[cfg(test)]`
//! (`steerability_gated_served_chat_prompts`/`steerability_eligible_families`).
//!
//! FAIL-BEFORE: `[steerability]` had no config binding at all — a deployment could not supply measured
//! scores, and `build_served_chat_prompt`'s default branch unconditionally served
//! `default_chat_families()` regardless of any measured instruction-following pass-rate.
//! PASS-AFTER: a `[steerability]` config layer (resolved through the SAME real layered TOML merge as
//! every other config domain) actually changes which families the REAL served daemon deploys:
//!   1. every candidate family below the bar (or unmeasured) ⇒ `assemble_selected` fails closed with a
//!      typed config error — never silently serves an ungated set;
//!   2. the daemon's own active model family excluded by the gate ⇒ the deployment still assembles
//!      (other families cleared the bar), but a REAL served chat turn for that family fails closed at
//!      `compile_turn` — proving the family list reaching `ServedChatPrompts` was genuinely narrowed,
//!      not just logged;
//!   3. the active family included ⇒ unchanged: a real served turn completes normally.
//!
//! This goes through the REAL served composition root: `assemble_selected(loaded, "chat")` — the exact
//! function `ainxt-runtimed`'s `main.rs` calls for `--surface chat` — followed (where relevant) by a
//! real in-process turn via `ainxt_client::Client`, exactly like `r14_served_forensic_prompt.rs`.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use ainxt_client::{Client, ClientConfig};
use ainxt_runtimed::{assemble_selected, load_layered, AssembleError};
use ainxt_types::Principal;

fn tmp_dir(tag: &str) -> PathBuf {
    static CTR: AtomicU64 = AtomicU64::new(0);
    let n = CTR.fetch_add(1, Ordering::SeqCst);
    let p = std::env::temp_dir().join(format!("ainxt-r-steer-{tag}-{}-{n}", std::process::id()));
    let _ = fs::remove_dir_all(&p);
    p
}

fn config_with_steerability(
    event_log_dir: &std::path::Path,
    steerability_toml: &str,
) -> ainxt_runtimed::LoadedConfig {
    let src = format!(
        "version = 1\n[server]\nevent_log_dir = {:?}\n{steerability_toml}\n",
        event_log_dir.to_string_lossy()
    );
    load_layered(&[("t", &src)]).expect("load config")
}

/// A steerability layer where NO candidate family clears the bar: one measured-but-low score
/// ("openai" at 0.1) and every other candidate family is entirely unmeasured (no evidence is never a
/// pass, per §9) — so the eligible set is empty regardless of which family the daemon is configured
/// to actively serve.
const ALL_EXCLUDED: &str = r#"
[steerability]
min_bar = 0.95

[[steerability.scores]]
model_family = "openai"
artifact_version = "1.0.0"
n = 20
passed = 2
pass_rate = 0.1
verdicts = []
"#;

/// A steerability layer where ONLY "openai" clears the bar — the daemon's own active family
/// (`ainxt_chat::DEFAULT_CHAT_FAMILY` == "claude") is unmeasured, hence excluded, but the gate still
/// yields a non-empty eligible set (so assembly itself must not fail).
const ACTIVE_FAMILY_EXCLUDED: &str = r#"
[steerability]
min_bar = 0.7

[[steerability.scores]]
model_family = "openai"
artifact_version = "1.0.0"
n = 20
passed = 18
pass_rate = 0.9
verdicts = []
"#;

/// A steerability layer where the active "claude" family itself clears the bar — the gate is active
/// but does not exclude the family the daemon actually serves.
const ACTIVE_FAMILY_INCLUDED: &str = r#"
[steerability]
min_bar = 0.5

[[steerability.scores]]
model_family = "claude"
artifact_version = "1.0.0"
n = 20
passed = 18
pass_rate = 0.9
verdicts = []
"#;

#[test]
fn all_candidates_below_bar_fails_closed_at_the_real_composition_root() {
    let dir = tmp_dir("all-excluded");
    let loaded = config_with_steerability(&dir, ALL_EXCLUDED);

    let err = assemble_selected(&loaded, "chat").err().expect(
        "no served family clears the bar -> assembly must fail closed, never silently serve",
    );
    match err {
        AssembleError::Config(msg) => {
            assert!(
                msg.contains("steerability gate"),
                "the fail-closed error must name the steerability gate: {msg}"
            );
        }
        other => panic!("expected AssembleError::Config, got {other:?}"),
    }

    let _ = fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn gate_excluding_the_active_family_still_assembles_but_the_real_served_turn_fails_closed() {
    let dir = tmp_dir("active-excluded");
    let loaded = config_with_steerability(&dir, ACTIVE_FAMILY_EXCLUDED);

    // Assembly succeeds — "openai" cleared the bar, so the eligible set is non-empty.
    let assembled = assemble_selected(&loaded, "chat").expect(
        "a non-empty eligible set (openai) must not fail assembly even though the daemon's \
                 own active family (claude) was excluded by the gate",
    );
    assert!(
        assembled
            .report
            .iter()
            .any(|r| r.contains("steerability gate ACTIVE")),
        "the assembly report must record the gate is active: {:?}",
        assembled.report
    );

    // But a REAL served chat turn (always compiled for the daemon's configured "claude" family) must
    // fail closed: the family list `ServedChatPrompts` was built from genuinely excluded "claude", so
    // `PromptService::compile_turn` has no pinned variant for it.
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
    assert!(
        !out.completed,
        "a served turn for a family the steerability gate excluded must never complete normally \
         (fail-closed, §9) — got {out:?}"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn gate_including_the_active_family_serves_a_real_turn_normally() {
    let dir = tmp_dir("active-included");
    let loaded = config_with_steerability(&dir, ACTIVE_FAMILY_INCLUDED);

    let assembled = assemble_selected(&loaded, "chat").expect("assembly succeeds");
    assert!(
        assembled
            .report
            .iter()
            .any(|r| r.contains("steerability gate ACTIVE")),
        "gate must be recorded active: {:?}",
        assembled.report
    );

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
    assert!(
        out.completed,
        "the gate must not break a real served turn for a family it actually clears: {out:?}"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn unconfigured_steerability_layer_is_byte_identical_to_the_unfiltered_default() {
    let dir = tmp_dir("noop");
    let loaded = config_with_steerability(&dir, "");
    let assembled =
        assemble_selected(&loaded, "chat").expect("assembly succeeds with no [steerability] layer");
    assert!(
        !assembled
            .report
            .iter()
            .any(|r| r.contains("steerability gate")),
        "an unconfigured deployment must show no steerability gate activity at all: {:?}",
        assembled.report
    );
    let _ = fs::remove_dir_all(&dir);
}
