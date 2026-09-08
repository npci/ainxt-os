// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R11 (Prompt Engineering, §BH) — numeric-via-tools is the DEFAULT on the payments chat surface. The
//! generic served default is `Allow`; the payments served default is `ToolsOnly`, and the output-path
//! enforcement then flags an amount-like figure that no tool produced (a wrong figure moves money) and
//! passes a tool-sourced one.
//!
//! FAIL-BEFORE: `payments_served_chat_prompts` / `PromptConfig::payments` did not exist. PASS-AFTER: green.

use ainxt_prompt::layered::{HeuristicTokens, TruncatingCondenser};
use ainxt_prompt::served::{default_payments_served_chat_prompts, default_served_chat_prompts};
use ainxt_prompt::service::PromptService;
use ainxt_prompt::{NumericPolicy, PromptConfig};

#[test]
fn r11_payments_surface_defaults_to_tools_only_generic_stays_allow() {
    assert_eq!(
        default_payments_served_chat_prompts().numeric,
        NumericPolicy::ToolsOnly,
        "the payments chat surface must ship numeric-via-tools ON by default"
    );
    assert_eq!(
        default_served_chat_prompts().numeric,
        NumericPolicy::Allow,
        "the generic (non-payments) default stays Allow"
    );
    assert_eq!(PromptConfig::payments().numeric, NumericPolicy::ToolsOnly);
    assert_eq!(PromptConfig::default().numeric, NumericPolicy::Allow);
}

#[test]
fn r11_payments_default_enforces_numbers_come_from_tools() {
    let payments = default_payments_served_chat_prompts();
    let est = HeuristicTokens;
    let cond = TruncatingCondenser;
    let svc = PromptService::new(&est, &cond, 10_000);
    let secret = "SYSTEM: internal chat instructions";

    // An invented settlement figure with no tool behind it → flagged under the payments default.
    let invented = svc.inspect_output(
        secret,
        "The total settlement is ₹12,45,600 across all banks.",
        payments.numeric,
        &[],
    );
    assert!(
        invented.numeric_violated(),
        "an unsourced amount must be flagged on a payments surface"
    );
    assert!(!invented.is_clean());

    // The same figure, but a tool returned it → sourced → clean.
    let sourced = svc.inspect_output(
        secret,
        "The total settlement is ₹12,45,600 across all banks.",
        payments.numeric,
        &["1245600"],
    );
    assert!(!sourced.numeric_violated());
    assert!(sourced.is_clean());
}
