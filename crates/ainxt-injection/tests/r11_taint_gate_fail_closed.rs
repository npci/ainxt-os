// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R11 gap closure (entrypoint proof): the injection taint-gate's coverage must NOT silently depend
//! on the registry having classified every tool. [`gate_tool_on_taint`] is fail-closed: on a
//! tainted turn a tool is safe to run only when it is KNOWN non-side-effecting AND KNOWN
//! non-egress; an UNKNOWN (`None`) classification is gated.
//!
//! NOTE (needs_hot_wiring): the runtime engine (RESERVED crate `ainxt-runtime`) currently gates with
//! an inline `is_side_effecting(name) == Some(true) || egress_of(name) == Some(true)` check, which
//! lets an UNCLASSIFIED tool (`None`) through on a poisoned turn. Swapping that call-site to
//! `gate_tool_on_taint(...)` closes the coverage gap. This test pins the entrypoint's semantics.

use ainxt_injection::gate_tool_on_taint;

#[test]
fn r11_taint_gate_blocks_unknown_classification() {
    // Unknown side-effecting AND unknown egress → gated (fail-closed). This is the case the old
    // inline `== Some(true)` check let slip through.
    assert!(gate_tool_on_taint(None, None));
    // Unknown side-effect but known non-egress → still gated (one unknown is enough).
    assert!(gate_tool_on_taint(None, Some(false)));
    assert!(gate_tool_on_taint(Some(false), None));
}

#[test]
fn r11_taint_gate_blocks_known_dangerous_tools() {
    assert!(
        gate_tool_on_taint(Some(true), Some(false)),
        "side-effecting must gate"
    );
    assert!(
        gate_tool_on_taint(Some(false), Some(true)),
        "egress must gate"
    );
    assert!(gate_tool_on_taint(Some(true), Some(true)));
}

#[test]
fn r11_taint_gate_allows_only_known_safe_tools() {
    // The ONLY combination that runs on a tainted turn: known non-side-effecting AND known non-egress.
    assert!(!gate_tool_on_taint(Some(false), Some(false)));
}
