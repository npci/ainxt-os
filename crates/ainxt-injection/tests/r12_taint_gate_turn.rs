// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R12 gap closure (fail-closed taint gate on UNCLASSIFIED tools): the turn-aware drop-in
//! [`gate_tool_on_taint_for_turn`] replaces the reserved runtime call-site's inline
//! `is_side_effecting(name) == Some(true) || egress_of(name) == Some(true)` check, which let an
//! UNCLASSIFIED (`None`) tool run on a poisoned turn. Fail-before: the three-argument helper did not
//! exist. (The reserved `ainxt-runtime` call-site swap is reported needs_hot_wiring.)

use ainxt_injection::gate_tool_on_taint_for_turn;

#[test]
fn r12_non_tainted_turn_gates_nothing() {
    // With no taint, even a known-dangerous tool is not gated by THIS control.
    assert!(!gate_tool_on_taint_for_turn(false, Some(true), Some(true)));
    assert!(!gate_tool_on_taint_for_turn(false, None, None));
}

#[test]
fn r12_tainted_turn_fails_closed_on_unclassified_tool() {
    // The regression the old inline check had: an UNCLASSIFIED tool slipping through on a poison turn.
    assert!(
        gate_tool_on_taint_for_turn(true, None, None),
        "unknown classification must gate"
    );
    assert!(gate_tool_on_taint_for_turn(true, None, Some(false)));
    assert!(gate_tool_on_taint_for_turn(true, Some(false), None));
}

#[test]
fn r12_tainted_turn_gates_known_dangerous_and_allows_known_safe() {
    assert!(
        gate_tool_on_taint_for_turn(true, Some(true), Some(false)),
        "side-effecting gates"
    );
    assert!(
        gate_tool_on_taint_for_turn(true, Some(false), Some(true)),
        "egress gates"
    );
    // The ONLY tool that runs on a tainted turn: KNOWN non-side-effecting AND KNOWN non-egress.
    assert!(!gate_tool_on_taint_for_turn(true, Some(false), Some(false)));
}
