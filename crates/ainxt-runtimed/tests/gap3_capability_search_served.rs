// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-AUDIT tooling-mcp-plugins-routing — "Ranking escape valve capability.search never
//! registered". `ainxt_mcp::capability_search`/`ainxt_mcp::CAPABILITY_SEARCH` (§2.4 — a BM25 search
//! over the FULL TOFU-approved MCP tool universe, for when the model's bounded top-K candidate set
//! doesn't include a tool it needs) existed and was unit-tested in `ainxt-mcp`, but was never
//! registered as a dispatchable `Tool` anywhere on the served path — the model had a name for the
//! escape valve and no way to actually call it: dispatching `"capability.search"` against the served
//! registry returned `Blocked("unknown tool: capability.search")`, indistinguishable from a typo.
//!
//! This proves the fix against the REAL served composition root
//! (`ainxt_runtimed::build_unified_capability_registry_shared` — the exact function
//! `build_engine_ext` calls), not a hand-assembled registry:
//!   * `capability.search` appears in the registry's own `schemas()` (the model's function-calling
//!     manifest) — it is now DISCOVERABLE, not just callable.
//!   * dispatching it (attributed, exactly as the served engine's agent loop dispatches every other
//!     capability) returns `Ok`, never `Blocked("unknown tool: ...")` — the model can genuinely call
//!     it. The air-gapped default has no MCP servers configured, so the honest result is an empty
//!     match list (`{"matches":[]}`) — the same "reachable but excludes everything until a deployment
//!     configures real servers" posture the SAME function already uses for `federated_query`/
//!     `named_fabric_query` right above it, not a fabricated non-empty result.
//!   * the caller-attribution gate is real: an UNATTRIBUTED dispatch (no acting principal) is refused
//!     with a specific, named reason, never silently defaulted to some ambient identity's view.
//!   * an empty query is refused before any search runs.

use ainxt_runtimed::build_unified_capability_registry_shared;
use ainxt_tools::DispatchResult;

#[test]
fn capability_search_is_discoverable_in_the_served_registrys_own_manifest() {
    let mut report = Vec::new();
    let (registry, _ledger, _reconciler) = build_unified_capability_registry_shared(&mut report);
    let names: Vec<String> = registry.schemas().into_iter().map(|s| s.name).collect();
    assert!(
        names.iter().any(|n| n == ainxt_mcp::CAPABILITY_SEARCH),
        "capability.search must appear in the served registry's function-calling manifest: {names:?}"
    );
}

#[test]
fn capability_search_dispatches_through_the_real_served_registry_instead_of_unknown_tool() {
    let mut report = Vec::new();
    let (registry, _ledger, _reconciler) = build_unified_capability_registry_shared(&mut report);

    // Attributed dispatch — the SAME entrypoint (`dispatch_for`) the served engine's agent loop uses
    // to fold the acting principal into the call. Before this fix there was no registered tool named
    // "capability.search" at all, so this would have been `Blocked("unknown tool: ...")`.
    match registry.dispatch_for(
        "alice",
        ainxt_mcp::CAPABILITY_SEARCH,
        "find a ticketing tool",
    ) {
        DispatchResult::Ok(body) => {
            let json: serde_json::Value =
                serde_json::from_str(&body).expect("capability.search must return valid JSON");
            assert!(
                json.get("matches").and_then(|m| m.as_array()).is_some(),
                "response must carry a 'matches' array: {body}"
            );
            // Air-gapped default: no MCP servers configured on this registry, so the honest result is
            // EMPTY — never a fabricated hit — matching the sibling federated_query/named_fabric_query
            // defaults in the same composition function.
            assert_eq!(
                json["matches"].as_array().unwrap().len(),
                0,
                "no MCP servers are configured on the air-gapped default, so matches must be empty: {body}"
            );
        }
        other => panic!(
            "capability.search must be genuinely dispatchable on the real served registry, not \
             refused as an unknown/unregistered tool: {other:?}"
        ),
    }
}

#[test]
fn capability_search_refuses_an_unattributed_caller_less_dispatch() {
    let mut report = Vec::new();
    let (registry, _ledger, _reconciler) = build_unified_capability_registry_shared(&mut report);

    // Plain `dispatch` (no acting principal at all) — the legacy/unattributed entrypoint. The
    // searchable tool universe depends on WHICH principal's TOFU-approval state is being consulted,
    // so this must fail closed by name, never silently resolve to some default identity's view.
    match registry.dispatch(ainxt_mcp::CAPABILITY_SEARCH, "anything") {
        DispatchResult::Failed(reason) => assert!(
            reason.contains("execute_as") && reason.contains("caller-attributed"),
            "must name why an unattributed call is refused: {reason}"
        ),
        other => panic!("expected a caller-attribution refusal, got {other:?}"),
    }
}

#[test]
fn capability_search_refuses_an_empty_query_before_searching() {
    let mut report = Vec::new();
    let (registry, _ledger, _reconciler) = build_unified_capability_registry_shared(&mut report);

    match registry.dispatch_for("alice", ainxt_mcp::CAPABILITY_SEARCH, "   ") {
        DispatchResult::Failed(reason) => {
            assert!(reason.contains("non-empty query"), "reason: {reason}")
        }
        other => panic!("expected a refusal for an empty/whitespace-only query, got {other:?}"),
    }
}
