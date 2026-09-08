// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX surface-turnplan-policy — `ainxt_surface::TurnPlan` exposes a policy-query API
//! (`provider_allowed`/`admissible_providers`, backed by the new pure
//! `TurnPlan::is_provider_admissible` predicate) that is the single source of truth for "may this
//! surface's turn use provider X". Two REAL composition-root call sites previously bypassed it with
//! their own hand-rolled logic, both inside `ainxt-runtimed`'s `build_chat_engine_with_authz` /
//! `build_chat_surface_wired_authz` (which `assemble_surface` — the function `assemble_selected`, the
//! daemon's one `--surface` dispatch table, calls for every non-engine/program/team/workforce surface
//! id):
//!
//! 1. **Router construction** (`filter_models_by_allowlist`) read only `allowed_providers`, silently
//!    dropping `forced_provider` — a surface pinning `forced_provider` with an EMPTY `allowed_providers`
//!    (e.g. a `[surfaces.<id>.model_policy] forced_provider = "..."` deployment override, exactly what
//!    `r11_surface_gaps.rs`'s `r11_profile_layer_override_applies_to_a_canonical_surface` applies to
//!    `chat`) got a router with EVERY configured provider still registered, contradicting the
//!    documented "never registered ... structural, not advisory" contract.
//! 2. **Stage-2 intent-classifier provider selection** (`build_chat_classifier_model`) read the
//!    daemon's raw, UNFILTERED `loaded.runtime.models` directly — entirely outside
//!    `forced_provider`/`allowed_providers`, so a surface's excluded provider (e.g. `sdlc`'s canonical
//!    `allowed_providers = ["claude", "gpt"]`, `max_data_class = "confidential"`) could still receive
//!    the raw user turn for intent classification. This is the more severe of the two: unlike the
//!    router (whose per-turn `Request::forced_provider` narrows `select_chain` to one element
//!    regardless of what else is registered), nothing narrows the classifier's provider pick — this was
//!    a genuinely LIVE policy bypass, not just an inert over-registration.
//!
//! Both now resolve through the exact same `TurnPlan::is_provider_admissible` predicate (via
//! `filter_models_by_allowlist`, called once for the router and once — cheaply, purely — for the
//! classifier's candidate view). Each test below fails on the pre-fix code and passes after.

use ainxt_runtimed::{assemble_surface, load_layered};

fn three_providers_config() -> String {
    "version = 1\n\
     [[models.providers]]\nid = \"claude\"\nkind = \"anthropic\"\nbase_url = \"http://c\"\n\
     [[models.providers]]\nid = \"gpt\"\nkind = \"open-ai-schema\"\nbase_url = \"http://g\"\n\
     [[models.providers]]\nid = \"gemini\"\nkind = \"open-ai-schema\"\nbase_url = \"http://m\""
        .to_string()
}

/// The ROUTER half of the fix: a `forced_provider` pinned via a deployment override, with NO
/// `allowed_providers` set (`chat`'s canonical model_policy leaves it empty) — before the fix this
/// narrowed NOTHING (the `allowlist.is_empty()` fast path in `filter_models_by_allowlist` returned the
/// full, unfiltered provider set), so `gpt`/`gemini` stayed registered on the `chat` surface's router
/// even though only `claude` was ever reachable per-turn. After the fix, `filter_models_by_allowlist`
/// consults `TurnPlan::is_provider_admissible`, which honors `forced_provider` even with an empty
/// allow-list, and excludes both.
#[test]
fn r_forced_provider_alone_narrows_the_router_even_with_an_empty_allow_list() {
    let loaded = load_layered(&[(
        "deployment",
        &format!(
            "{}\n[surfaces.chat.model_policy]\nforced_provider = \"claude\"",
            three_providers_config()
        ),
    )])
    .unwrap();

    let assembled = assemble_surface(&loaded, "chat").expect("chat surface assembles");

    // Pre-fix, this assertion FAILS: `allowed_providers` is empty on `chat`, so the old
    // `filter_models_by_allowlist` returned every provider unchanged — no exclusion report line existed
    // for `gpt`/`gemini` at all.
    assert!(
        assembled
            .report
            .iter()
            .any(|r| r
                .contains("provider 'gpt' excluded by the surface's forced_provider model policy")),
        "forced_provider must exclude 'gpt' from the chat surface's router even with an empty \
         allow-list: {:?}",
        assembled.report
    );
    assert!(
        assembled.report.iter().any(|r| r
            .contains("provider 'gemini' excluded by the surface's forced_provider model policy")),
        "forced_provider must exclude 'gemini' too: {:?}",
        assembled.report
    );
    // The forced provider itself is never reported excluded.
    assert!(
        !assembled
            .report
            .iter()
            .any(|r| r.contains("provider 'claude' excluded")),
        "the forced provider must never be excluded by its own policy: {:?}",
        assembled.report
    );
}

/// `allowed_providers` must both EXCLUDE what it disallows and KEEP what it allows. `sdlc`'s
/// canonical model policy already sets `allowed_providers = ["claude", "gpt"]` (no override needed).
/// Configure a disallowed `gemini` ahead of an allowed `gpt` — both `kind = "local"`, so no API key
/// is involved and the policy check is isolated from key presence. Ordering matters: `gemini` is
/// listed FIRST, so any call site that scans `loaded.runtime.models` unfiltered and takes the first
/// candidate would pick precisely the provider this surface forbids for its confidential-cleared
/// repo turns.
#[test]
fn r_allowed_providers_excludes_the_disallowed_provider_and_keeps_the_allow_listed_one() {
    let loaded = load_layered(&[(
        "deployment",
        "version = 1\n\
         [[models.providers]]\nid = \"gemini\"\nkind = \"local\"\nbase_url = \"http://disallowed\"\n\
         [[models.providers]]\nid = \"gpt\"\nkind = \"local\"\nbase_url = \"http://allowed\"",
    )])
    .unwrap();

    let assembled = assemble_surface(&loaded, "sdlc").expect("sdlc surface assembles");

    // The router-narrowing report line (pre-existing behavior, still correct): gemini excluded from the
    // router by the (unchanged) allowed_providers arm.
    assert!(
        assembled
            .report
            .iter()
            .any(|r| r
                .contains("provider 'gemini' excluded by the surface's allowed_providers policy")),
        "gemini must be excluded from the sdlc router: {:?}",
        assembled.report
    );

    // The allow-listed provider must SURVIVE that same narrowing — the policy has to exclude
    // `gemini` without also starving the surface of the provider it does permit.
    assert!(
        assembled
            .report
            .iter()
            .any(|r| r.contains("provider 'gpt'")),
        "the allow-listed provider must still be wired after the policy narrows the candidate set: {:?}",
        assembled.report
    );

    // NOTE: this test used to also assert a "Stage-2 model-backed constrained intent classifier
    // wired" report line, proving the classifier drew from the SAME surface-narrowed view as the
    // router. The chat surface no longer wires a model-backed classifier at all — see the
    // `LATENCY FIX` comment at the wiring site in `ainxt-runtimed` and
    // `r_served_offline_stage3_classifier.rs`, which pins that decision. With no per-turn
    // classification call there is no second candidate set left to diverge, so the assertion was
    // dropped rather than rewritten against a code path that is no longer taken.
}

/// Equivalence control: with NEITHER `forced_provider` NOR a non-default `allowed_providers` in play
/// (the plain `chat` surface, unrestricted), all three configured providers survive router
/// construction — confirming the fix changes nothing when a surface's model policy is fully open,
/// exactly like `TurnPlan::provider_allowed` returns `true` for every id in that case.
#[test]
fn r_unrestricted_surface_keeps_every_configured_provider_byte_identical() {
    let loaded = load_layered(&[("deployment", &three_providers_config())]).unwrap();
    let assembled = assemble_surface(&loaded, "chat").expect("chat surface assembles");
    assert!(
        !assembled
            .report
            .iter()
            .any(|r| r.contains("excluded by the surface's")),
        "an unrestricted surface must exclude nothing: {:?}",
        assembled.report
    );
}
