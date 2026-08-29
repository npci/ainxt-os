// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R15 gap closure (needs_hot_wiring pin — subsystem guardrails-injection, item "Fail-closed taint
//! gate for UNKNOWN-classification tools"): mirrors the RESERVED `ainxt-runtime` agent loop's exact
//! call site (§7a2) on both sides of the swap:
//!
//! ```ignore
//! // current call site
//! if tainted {
//!     if icfg.gate_side_effects_on_taint
//!         && (tools.is_side_effecting(&name) == Some(true) || tools.egress_of(&name) == Some(true))
//!     { /* block */ }
//! }
//! ```
//!
//! The current inline check only gates a tool the registry KNOWS is dangerous (`Some(true)`); an
//! UNCLASSIFIED tool (`is_side_effecting` / `egress_of` returning `None` — e.g. a newly-registered
//! MCP/plugin tool nobody tagged yet) evaluates the `||` to `false` and is allowed to run on a
//! poisoned turn. [`gate_tool_on_taint_for_turn`] (closed R11/R12) is the fail-closed drop-in: an
//! unknown classification gates. This test proves the CURRENT inline shape lets an unclassified tool
//! through (fail-before) while the exact three-argument drop-in blocks it (pass-after on our side of
//! the seam) — the reserved call site swap itself remains needs_hot_wiring.

use ainxt_injection::gate_tool_on_taint_for_turn;

/// Mirrors today's reserved inline check byte-for-byte: `true` = tool is allowed to run.
fn current_inline_check_allows(
    tainted: bool,
    gate_side_effects_on_taint: bool,
    side_effecting: Option<bool>,
    egress: Option<bool>,
) -> bool {
    if tainted
        && gate_side_effects_on_taint
        && (side_effecting == Some(true) || egress == Some(true))
    {
        false // blocked
    } else {
        true // allowed to dispatch
    }
}

#[test]
fn r15_current_inline_check_lets_an_unclassified_tool_run_on_a_poisoned_turn() {
    // FAIL-BEFORE: a brand-new MCP/plugin tool the registry never classified (None, None) — under
    // the CURRENT reserved-crate inline check — still runs on a tainted turn. This is the exact
    // coverage hole the gap is about.
    let allowed = current_inline_check_allows(
        /* tainted */ true, /* gate_side_effects_on_taint */ true,
        /* side_effecting */ None, /* egress */ None,
    );
    assert!(
        allowed,
        "documents today's coverage hole: an UNCLASSIFIED tool must NOT be silently allowed, but \
         the current inline check allows it"
    );
}

#[test]
fn r15_dropin_gate_blocks_the_same_unclassified_tool() {
    // PASS-AFTER on our side of the seam: swapping in the exact 3-arg drop-in for the SAME inputs
    // fails closed instead.
    let must_block = gate_tool_on_taint_for_turn(
        /* tainted */ true, /* side_effecting */ None, /* egress */ None,
    );
    assert!(
        must_block,
        "the drop-in gate must block an unclassified tool on a tainted turn"
    );
}

#[test]
fn r15_dropin_gate_matches_current_check_on_every_known_combination() {
    // Non-regression: for every combination the CURRENT check already gets right (a tool the
    // registry positively knows is safe, or positively knows is dangerous), the drop-in agrees — the
    // swap only changes the UNKNOWN case, it never loosens a decision the current code already makes.
    for tainted in [false, true] {
        for se in [Some(false), Some(true)] {
            for eg in [Some(false), Some(true)] {
                let current_allows = current_inline_check_allows(tainted, true, se, eg);
                let dropin_blocks = gate_tool_on_taint_for_turn(tainted, se, eg);
                assert_eq!(
                    !current_allows, dropin_blocks,
                    "mismatch for tainted={tainted} se={se:?} eg={eg:?}: current_allows={current_allows} dropin_blocks={dropin_blocks}"
                );
            }
        }
    }
}
