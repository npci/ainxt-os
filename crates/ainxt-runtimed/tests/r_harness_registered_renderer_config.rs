// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX harness-sdk-governance — `ainxt_admission::RegisteredRendererResolver` (fail-closed on an
//! unregistered `HarnessRenderer::Custom` declaration) was fully implemented and tested, but the
//! shipped daemon's `mounts::build_harness_mounts` always installed the permissive
//! `AnyRendererResolver` (every custom renderer id accepted) — so a manifest declaring an unbacked
//! custom renderer was silently admitted on the served `/v1/harness/{id}/run` bridge instead of
//! refused. `[harness] registered_renderers` is now a real, parseable config section that installs
//! the fail-closed resolver on the composition-root-built `HarnessMounts`.

use ainxt_admission::{
    CapabilityGrant, HarnessManifest, HarnessOutcome, HarnessRenderer, HarnessStep, StepKind,
};
use ainxt_runtimed::{assemble_chat, assemble_full, load_layered};
use ainxt_types::Principal;

fn unique_log_dir(tag: &str) -> String {
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir()
        .join(format!("ainxt-r-renderer-cfg-{tag}-{nanos}"))
        .to_string_lossy()
        .into_owned()
}

fn manifest_with_renderer(renderer: HarnessRenderer) -> HarnessManifest {
    let mut m = HarnessManifest::new(
        "diag.selftest",
        vec![HarnessStep {
            id: "s1".into(),
            kind: StepKind::Skill,
            capability: "diag.selftest".into(),
            estimated_tokens: 1,
            input: None,
        }],
    )
    .with_capabilities(["diag.selftest"]);
    m.owner = "test".into();
    m.version = "1.0.0".into();
    m.renderer = renderer;
    m
}

fn caller() -> Principal {
    Principal::user("alice", &["diag.selftest"])
}

#[test]
fn r_declared_renderers_make_the_harness_bridge_fail_closed_on_an_unregistered_custom_renderer() {
    let dir = unique_log_dir("declared");
    let src = format!(
        "version = 1\n\
         [server]\n\
         event_log_dir = {dir:?}\n\
         [harness]\n\
         registered_renderers = [\"settlement-dashboard\"]\n"
    );
    let loaded =
        load_layered(&[("r-renderer", &src)]).expect("load config with registered renderers");
    assert_eq!(
        loaded.harness.registered_renderers,
        vec!["settlement-dashboard".to_string()],
        "[harness] registered_renderers must parse into LoadedConfig"
    );

    let assembled = assemble_chat(&loaded).expect("assemble chat surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");

    let grant = CapabilityGrant::new(["diag.selftest"]);

    // A REGISTERED custom renderer still runs to completion.
    let ok = manifest_with_renderer(HarnessRenderer::Custom("settlement-dashboard".into()));
    let outcome = full
        .harness
        .runtime
        .run(&ok, &grant, &caller(), full.harness.executor.as_ref());
    assert!(
        outcome.is_completed(),
        "a registered custom renderer must still be admitted: {outcome:?}"
    );

    // An UNREGISTERED custom renderer is now refused at admission — the real bug's symptom, fixed.
    let bad = manifest_with_renderer(HarnessRenderer::Custom("not-bundled-anywhere".into()));
    let outcome = full
        .harness
        .runtime
        .run(&bad, &grant, &caller(), full.harness.executor.as_ref());
    match outcome {
        HarnessOutcome::RendererUnavailable(id) => assert_eq!(id, "not-bundled-anywhere"),
        other => panic!(
            "an unregistered custom renderer must be refused once [harness] registered_renderers is \
             declared, got: {other:?}"
        ),
    }
}

#[test]
fn r_no_harness_config_keeps_the_permissive_default_unchanged() {
    let dir = unique_log_dir("default");
    let src = format!("version = 1\n[server]\nevent_log_dir = {dir:?}\n");
    let loaded = load_layered(&[("r-renderer-default", &src)]).expect("load default config");
    assert!(
        loaded.harness.registered_renderers.is_empty(),
        "no [harness] section declared ⇒ empty (unchanged permissive default)"
    );

    let assembled = assemble_chat(&loaded).expect("assemble chat surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");

    // ANY custom renderer id is still admitted — byte-identical to before this fix.
    let grant = CapabilityGrant::new(["diag.selftest"]);
    let m = manifest_with_renderer(HarnessRenderer::Custom("anything-goes".into()));
    let outcome = full
        .harness
        .runtime
        .run(&m, &grant, &caller(), full.harness.executor.as_ref());
    assert!(
        outcome.is_completed(),
        "with no [harness] config, any custom renderer must still be admitted (unchanged default): \
         {outcome:?}"
    );
}
