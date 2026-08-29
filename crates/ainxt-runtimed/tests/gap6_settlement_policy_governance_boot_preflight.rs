// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX payments-governance (IDN-10, ADR-026 §4.4/§4.5): `ainxt_payments::boundary::
//! SettlementPolicy` / `PolicyGovernance` / `authorize_edit` / `build_boundary` were fully
//! implemented and exhaustively unit-tested (`ainxt-payments/tests/r11_payment_boundary_gaps.rs`) but
//! had ZERO composition-root callers. Investigation of the daemon's actual boot path
//! (`ainxt-runtimed::npci_payment_boundary_resolver`, called from `build_engine_ext_with_mcp` /
//! `build_chat_engine_with_authz`, the only two real `Engine::with_payment_boundary_resolver` call
//! sites in the composition root) found the served boundary was ALWAYS the hardcoded
//! `PaymentBoundary::npci()` constant — there was in fact NO live mechanism (config, hot-reload, or
//! otherwise) for a deployment to change what counts as "payment" short of editing this crate's Rust
//! source and recompiling, and even then no dual-council check ran over that diff; only ordinary code
//! review (whatever the real GitLab CODEOWNERS happens to require) governed it.
//!
//! The fix adds a new `[payments]` config section (`PaymentsConfig`: `settlement_policy` +
//! `settlement_governance`, both `Option`, both empty by default — byte-identical
//! `PaymentBoundary::npci()` behavior unchanged) and a boot preflight
//! (`ainxt_runtimed::resolve_payment_boundary`, private but invoked from every real assemble/build
//! entrypoint) that calls `SettlementPolicy::authorize_edit` against the shipped baseline before the
//! daemon will assemble AT ALL — fail-closed.
//!
//! This test drives `ainxt_runtimed::build_engine_ext_with_mcp` — the REAL, `pub`, served
//! composition-root function `assemble` (the `--surface engine` default `main.rs` boots) and the
//! Program/Team surfaces all call directly with `&loaded.mcp`/`&loaded.payments` — over a config
//! carrying a `[payments]` section, proving:
//! 1. an unauthorized edit (missing the security-council sign-off) REFUSES to assemble;
//! 2. a policy with no governance evidence at all is ALSO refused (never silently ignored);
//! 3. a fully dual-council-authorized edit assembles AND the served `Engine`'s REAL classifier
//!    (`Engine::probe_payment_boundary`, the exact field the dispatch-time approval gate consults)
//!    genuinely reflects the new perimeter pattern — not just that `authorize_edit` accepted it in
//!    isolation.
//!
//! Note: `build_engine`/`build_engine_ext` (the bare-`RuntimeConfig` convenience wrappers) always pass
//! `PaymentsConfig::default()` — the SAME pre-existing pattern `McpConfig::default()` already uses on
//! that path (see `build_engine_ext`'s own doc: "`build_engine`... only ever sees a bare
//! `RuntimeConfig`, never the wider `LoadedConfig` an `[[mcp.servers]]` section lives on"). A
//! `[payments]` layer therefore genuinely requires the `LoadedConfig`-aware entrypoint, exactly like
//! `[[mcp.servers]]` does — this test exercises that real entrypoint directly.

use ainxt_payments::boundary::{PolicyGovernance, SettlementPolicy};
use ainxt_runtimed::{build_engine_ext_with_mcp, load_layered, AssembleError, McpConfig};

/// Serialize a proposed `(SettlementPolicy, PolicyGovernance)` pair into a `[payments.*]` TOML config
/// layer — the git-controlled artifact shape `SettlementPolicy`'s own doc describes, round-tripped
/// through real `Serialize` impls rather than hand-typed (avoids drifting from the real perimeter
/// pattern list if `PaymentBoundary::npci_reserved()` ever grows).
fn toml_layer(policy: &SettlementPolicy, gov: Option<&PolicyGovernance>) -> String {
    let mut root = toml::value::Table::new();
    root.insert("version".into(), toml::Value::Integer(1));
    let mut payments = toml::value::Table::new();
    payments.insert(
        "settlement_policy".into(),
        toml::Value::try_from(policy).expect("SettlementPolicy serializes to TOML"),
    );
    if let Some(gov) = gov {
        payments.insert(
            "settlement_governance".into(),
            toml::Value::try_from(gov).expect("PolicyGovernance serializes to TOML"),
        );
    }
    root.insert("payments".into(), toml::Value::Table(payments));
    toml::to_string(&toml::Value::Table(root)).expect("layer serializes")
}

fn full_governance() -> PolicyGovernance {
    PolicyGovernance {
        payments_council_approved: true,
        security_council_approved: true,
        commit_signed: true,
        author_can_approve: true,
        author_ad_level: 3,
    }
}

/// A legitimate edit: adds ONE new reserved perimeter pattern on top of the shipped baseline. The
/// one-way ratchet only forbids REMOVING a reserved pattern, never adding one.
fn edit_adding_new_rail() -> SettlementPolicy {
    let mut next = SettlementPolicy::default_baseline("proposed-sha");
    next.perimeter_patterns
        .insert("newrail-settlement.".to_string());
    next
}

#[test]
fn unauthorized_boundary_edit_refuses_to_assemble_the_real_daemon() {
    // Missing the SECURITY council's sign-off — `authorize_edit` must refuse (dual-council, not
    // single-council, is the whole point of IDN-10).
    let under_governed = PolicyGovernance {
        security_council_approved: false,
        ..full_governance()
    };
    let src = toml_layer(&edit_adding_new_rail(), Some(&under_governed));
    let loaded = load_layered(&[("t", &src)]).expect(
        "the config itself PARSES fine — governance is an assemble-time gate, not a parse-time one",
    );

    match build_engine_ext_with_mcp(
        &loaded.runtime,
        &McpConfig::default(),
        &loaded.payments,
        &loaded.serving,
    ) {
        Err(AssembleError::Config(msg)) => {
            assert!(
                msg.contains("governance"),
                "the refusal must name the governance gate, got: {msg}"
            );
        }
        Ok(_) => panic!(
            "an unauthorized settlement-policy edit must refuse to assemble the REAL daemon \
             composition root (build_engine_ext_with_mcp), but it assembled successfully"
        ),
        Err(other) => {
            panic!("expected AssembleError::Config, got a different AssembleError variant: {other}")
        }
    }
}

#[test]
fn policy_without_any_governance_evidence_is_a_config_error_never_silently_ignored() {
    // `settlement_policy` set, `settlement_governance` entirely omitted.
    let src = toml_layer(&edit_adding_new_rail(), None);
    let loaded = load_layered(&[("t", &src)]).expect("config parses (governance is Option)");
    match build_engine_ext_with_mcp(
        &loaded.runtime,
        &McpConfig::default(),
        &loaded.payments,
        &loaded.serving,
    ) {
        Err(AssembleError::Config(_)) => {}
        Ok(_) => panic!(
            "a proposed policy edit with NO governance evidence at all must be a config error, \
             never silently ignored (and never silently applied ungoverned), but it assembled \
             successfully"
        ),
        Err(other) => {
            panic!("expected AssembleError::Config, got a different AssembleError variant: {other}")
        }
    }
}

#[test]
fn fully_authorized_boundary_edit_assembles_and_the_served_engine_reflects_it() {
    let src = toml_layer(&edit_adding_new_rail(), Some(&full_governance()));
    let loaded = load_layered(&[("t", &src)]).expect("config parses");
    let (engine, ..) = build_engine_ext_with_mcp(
        &loaded.runtime,
        &McpConfig::default(),
        &loaded.payments,
        &loaded.serving,
    )
    .expect("a fully dual-council-authorized edit must assemble the REAL daemon");

    // The NEW rail is live on the REAL served engine's classifier — proving the governed policy
    // reached `Engine::with_payment_boundary_resolver`, not just that `authorize_edit` accepted it
    // in isolation with nothing downstream ever consuming the result.
    let new_rail = engine.probe_payment_boundary("newrail-settlement.bank", "{}");
    assert_ne!(
        new_rail,
        ainxt_protocol::PaymentBoundary::None,
        "the governance-authorized new perimeter pattern must be live on the REAL served engine"
    );

    // The pre-existing shipped baseline perimeter survives the edit untouched (one-way ratchet) and is
    // still gated — the governed edit only ever ADDS coverage, never silently narrows it.
    //
    // `"x402.pay"` is a destination that genuinely matches `SettlementPerimeter::default_reserved`
    // (the `"x402."` pattern). The earlier probe used `"settlement.example.transfer"` with a
    // `settlement-account:` resource key, which matches neither facet here: no default pattern is a
    // substring of that name, and the resource-key facet resolves through
    // `ToolRuntime::resource_of`, which is `None` for a tool this runtime never registers.
    let baseline = engine.probe_payment_boundary("x402.pay", "{}");
    assert_ne!(
        baseline,
        ainxt_protocol::PaymentBoundary::None,
        "the shipped baseline perimeter must still be enforced after a governed additive edit"
    );

    // An ordinary, unrelated tool call is still never over-blocked by the governed edit.
    assert_eq!(
        engine.probe_payment_boundary("lookup", "{}"),
        ainxt_protocol::PaymentBoundary::None,
        "the governed edit must not over-block ordinary tool dispatch"
    );
}

#[test]
fn no_payments_config_layer_keeps_the_shipped_npci_boundary_byte_identical() {
    // No `[payments]` section at all — the pre-existing, unconfigured posture.
    let loaded = load_layered(&[("t", "version = 1\n")]).expect("config parses");
    let (engine, ..) = build_engine_ext_with_mcp(
        &loaded.runtime,
        &McpConfig::default(),
        &loaded.payments,
        &loaded.serving,
    )
    .expect("the unconfigured default must still assemble");
    // `"x402.pay"` matches `SettlementPerimeter::default_reserved`'s `"x402."` pattern by
    // destination alone, so this asserts the shipped perimeter without depending on a registered
    // tool for the resource-key facet (see the note on the baseline probe above).
    let boundary = engine.probe_payment_boundary("x402.pay", "{}");
    assert_ne!(
        boundary,
        ainxt_protocol::PaymentBoundary::None,
        "byte-identical to every prior release: the shipped perimeter is enforced with no \
         [payments] config layer present"
    );
    // The un-governed new rail from the other tests must NOT be reserved here.
    assert_eq!(
        engine.probe_payment_boundary("newrail-settlement.bank", "{}"),
        ainxt_protocol::PaymentBoundary::None,
        "a pattern never proposed through the governance gate must not be reserved"
    );
}
