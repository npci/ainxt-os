// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R14 (served-composition, HIGH) — the daemon `--surface` selector assembles the 3-tier **Team**
//! loop and the AiNxt-OS **Workforce** factory, mirroring `program`. Before this round both were built
//! unit-tested but UNREACHABLE from the shipped binary: there was no `main` match arm, so
//! `--surface team` / `--surface workforce` fell through to the profile-catalog path and errored
//! ("unknown surface"). `assemble_selected` — the single composition-root dispatch `main` now calls —
//! routes each to its real assembled surface, and this test drives each end-to-end through a client.
//!
//! FAIL-BEFORE: `assemble_selected` did not exist and `--surface team`/`workforce` errored.
//! PASS-AFTER: green, offline, deterministic (offline provider; the un-forgeable Breaker runs its
//! actual adversarial pass through the offline `CompliantExecutor`).

use ainxt_client::{Client, ClientConfig};
use ainxt_runtimed::{assemble_full, assemble_selected, load_layered, LoadedConfig};
use ainxt_types::Principal;

fn offline() -> LoadedConfig {
    load_layered(&[("x", "version = 1")]).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn r14_surface_team_assembles_the_three_tier_team_loop() {
    let assembled = assemble_selected(&offline(), "team").expect("--surface team must assemble");
    assert!(
        assembled
            .report
            .iter()
            .any(|r| r.contains("3-tier Team loop")),
        "the team selector must assemble the hierarchical 3-tier Team surface: {:?}",
        assembled.report
    );
    let client = Client::in_process(
        assembled.manager,
        Principal::user("u", &["chat.send"]).with_department("payments"),
        ClientConfig::default(),
    );
    let out = client
        .chat("s", "t", "ship the feature")
        .unwrap()
        .collect()
        .await;
    assert!(out.completed, "the served team turn completes");
    assert!(
        out.text.contains("team") && out.text.contains("task turn"),
        "the served team surface streams a real 3-tier run projection: {}",
        out.text
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn r14_surface_workforce_assembles_the_role_factory() {
    let assembled =
        assemble_selected(&offline(), "workforce").expect("--surface workforce must assemble");
    assert!(
        assembled
            .report
            .iter()
            .any(|r| r.contains("workforce factory")),
        "the workforce selector must assemble the AiNxt-OS Role factory: {:?}",
        assembled.report
    );
    let client = Client::in_process(
        assembled.manager,
        Principal::user("u", &["chat.send"]).with_department("support"),
        ClientConfig::default(),
    );
    let out = client
        .chat("s", "t", "publish an L1 support role")
        .unwrap()
        .collect()
        .await;
    assert!(out.completed, "the served workforce turn completes");
    // GAP-CLOSE os-workforce #1 (live RoleExecutor) made this a REAL adversarial run: with no live
    // model configured (this test's `offline()` config), the executor's own canned "offline mode: no
    // model configured" text cannot possibly satisfy 4 DIFFERENT adversarial probes (injection-ignore,
    // over-privilege, out-of-scope escalation, quality bar) that each expect a distinct contextual
    // response. Fabricating a pass here would be exactly the "never a fabricated pass" violation
    // ADR-012 forbids. The surface is still genuinely reached (not "unknown surface") and fails
    // CLOSED with a clear, explained reason — that reachability + honesty is what this test now
    // proves, not a fabricated PASSED verdict.
    let err = out.error.as_deref().unwrap_or_default();
    assert!(
        err.contains("workforce gate refused (fail-closed)")
            && err.contains("Breaker adversarial RUN failed"),
        "the served workforce surface must reach the REAL validate + adversarial Breaker gate and \
         fail closed without a live model, not fabricate a pass or surface an unrelated error: {err}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn r14_surface_program_and_chat_selectors_unchanged() {
    // R16 critical: the daemon now refuses the header-trusting default authenticator unless the
    // deployment states the assumption (see r10_breach_clock_unit.rs) — state it here.
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    // Regression: the pre-existing selectors still resolve exactly as before.
    let prog = assemble_selected(&offline(), "program").expect("program");
    assert!(prog.report.iter().any(|r| r.contains("Program Supervisor")));
    let chat = assemble_selected(&offline(), "chat").expect("chat");
    assert!(chat.report.iter().any(|r| r.contains("profile-enforced")));
    // A fully-wired app still builds over the team surface (the r4 augmentation is surface-agnostic).
    let team = assemble_selected(&offline(), "team").expect("team");
    assert!(
        assemble_full(&offline(), team).is_ok(),
        "team surface augments into the full app"
    );
}
