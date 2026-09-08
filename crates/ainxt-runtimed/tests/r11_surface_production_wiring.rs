// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-11 served-path proof for the surface subsystem: the daemon's deployment `SkillRuntime` is
//! ACTIVE in production wiring (registered handlers + profile skill refs) — a profile referencing a
//! built-in behavioral skill injects it into the served system prompt through the real
//! `ProfiledSurface` composition (SURF medium).
//!
//! Fails before `build_skill_runtime` shipped the built-ins (it returned an EMPTY registry, so a
//! profile skill ref produced `SkillError::NotFound` and the turn was DENIED before the model);
//! passes after — the built-in citation-discipline SOP reaches the composed request.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use ainxt_protocol::{Event, Request};
use ainxt_runtime::{CancelToken, TurnError, TurnHandler, TurnSummary};
use ainxt_runtimed::{
    assemble_surface, build_skill_runtime, load_layered, LoadedConfig, ProfiledSurface,
};
use ainxt_skill::builtin;
use ainxt_surface::SurfaceCatalog;
use ainxt_types::{DataClass, Principal};
use tokio::sync::mpsc;

/// Records the profiled request the inner handler receives (so we can inspect the composed prompt).
struct Recorder {
    seen: Arc<Mutex<Vec<Request>>>,
}
impl TurnHandler for Recorder {
    fn handle_turn<'a>(
        &'a self,
        _principal: &'a Principal,
        req: &'a Request,
        sink: mpsc::Sender<Event>,
        _cancel: &'a CancelToken,
    ) -> Pin<Box<dyn Future<Output = Result<TurnSummary, TurnError>> + Send + 'a>> {
        let captured = req.clone();
        let seen = self.seen.clone();
        Box::pin(async move {
            seen.lock().unwrap().push(captured);
            let _ = sink.send(Event::Done).await;
            Ok(TurnSummary {
                final_text: String::new(),
                redactions: 0,
                provider: "recorder".into(),
                ..Default::default()
            })
        })
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn r11_daemon_skill_runtime_resolves_builtin_profile_skill_refs_on_served_path() {
    // A deployment profile that references the built-in citation-discipline behavioral skill.
    let catalog = SurfaceCatalog::from_toml_sources(&[(
        "audit",
        &format!(
            "id = \"audit\"\npersona = \"AUDITOR-PERSONA\"\nskills = [\"{}\"]",
            builtin::CITATION_DISCIPLINE
        ),
    )])
    .unwrap();

    // The EXACT deployment skill runtime the daemon builds — now shipping the built-ins.
    let skills = build_skill_runtime();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let surface = ProfiledSurface::new(
        catalog,
        Arc::new(skills),
        "audit",
        Arc::new(Recorder { seen: seen.clone() }),
    );

    let (tx, mut rx) = mpsc::channel::<Event>(16);
    let cancel = CancelToken::new();
    let req = Request::chat(
        "s",
        "t",
        "what were the settlement figures?",
        DataClass::Public,
    );
    let res = surface
        .handle_turn(&Principal::user("u", &[]), &req, tx, &cancel)
        .await;
    while rx.recv().await.is_some() {}
    res.expect("the built-in skill ref must resolve (not NotFound → not a denial)");

    // The composed request carries persona → the built-in behavioral SOP → user turn, proving the
    // daemon's skill runtime resolved the profile ref and injected on the served path.
    let captured = seen.lock().unwrap();
    let input = &captured.first().expect("a turn was recorded").input;
    let persona_at = input.find("AUDITOR-PERSONA").expect("persona injected");
    let sop_at = input
        .find("Cite every factual claim")
        .expect("built-in SOP injected");
    let user_at = input.find("settlement figures").expect("user turn present");
    assert!(
        persona_at < sop_at && sop_at < user_at,
        "injection order wrong: {input}"
    );
}

fn offline_config() -> LoadedConfig {
    load_layered(&[("x", "version = 1")]).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn r11_non_chat_surface_engine_is_bounded_by_declared_capabilities() {
    // The `code` surface declares 5 capabilities; the daemon must build its served engine with a
    // SurfaceScopedAuthorizer bounding tool dispatch to that declared set (gap SURF high).
    let assembled = assemble_surface(&offline_config(), "code").expect("code surface assembles");
    assert!(
        assembled
            .report
            .iter()
            .any(|r| r.contains("SurfaceScopedAuthorizer") && r.contains("declared capabilit")),
        "the served code surface must record the capability-scope authorizer: {:?}",
        assembled.report
    );

    // The chat surface (offers only chat.send) also assembles with the scope authorizer — bounding it
    // to zero tool capabilities, so it can never dispatch a tool at all.
    let chat = assemble_surface(&offline_config(), "chat").expect("chat surface assembles");
    assert!(chat
        .report
        .iter()
        .any(|r| r.contains("SurfaceScopedAuthorizer")));
}

#[test]
fn r11_deployment_surface_override_flows_from_config_to_the_served_catalog() {
    use ainxt_surface::SurfaceCatalog;
    use ainxt_types::Tier;

    // A deployment tweaks the chat surface's default tier via `[surfaces.chat.model_policy]` — the
    // config-first layer-override path (SURF medium: profile layer-override wired into the served
    // daemon path). No `id`, no persona, nothing else restated.
    let loaded = load_layered(&[(
        "deployment",
        "version = 1\n[surfaces.chat.model_policy]\ndefault_tier = \"complex\"",
    )])
    .unwrap();
    assert_eq!(
        loaded.surfaces.len(),
        1,
        "the [surfaces] override was parsed"
    );

    // This is EXACTLY what assemble_surface builds — the catalog the served surface binds against.
    let catalog = SurfaceCatalog::builtin_with_overrides(&loaded.surfaces.as_refs()).unwrap();
    let chat = catalog.get("chat").unwrap();
    assert_eq!(
        chat.model_policy.default_tier,
        Tier::Complex,
        "override applied on served path"
    );
    // The untouched canonical fields survived the deep merge.
    assert!(chat.persona.contains("AiNxt"));
    assert!(chat.rbac.department_scoped);

    // A daemon with NO [surfaces] override parses an empty set (byte-identical to the builtin catalog).
    assert!(offline_config().surfaces.is_empty());
}

#[test]
fn r11_surface_allowed_providers_is_enforced_server_side_on_the_router() {
    // Three providers are configured, but the sdlc surface's model policy allows only claude + gpt.
    // The surface's router must be built WITHOUT gemini — enforced server-side, not advisory.
    let loaded = load_layered(&[(
        "deployment",
        "version = 1\n\
         [[models.providers]]\nid = \"claude\"\nkind = \"anthropic\"\nbase_url = \"http://c\"\n\
         [[models.providers]]\nid = \"gpt\"\nkind = \"open-ai-schema\"\nbase_url = \"http://g\"\n\
         [[models.providers]]\nid = \"gemini\"\nkind = \"open-ai-schema\"\nbase_url = \"http://m\"",
    )])
    .unwrap();

    let assembled = assemble_surface(&loaded, "sdlc").expect("sdlc surface assembles");
    // gemini is excluded by the surface's allowed_providers policy (claude + gpt only).
    assert!(
        assembled
            .report
            .iter()
            .any(|r| r.contains("provider 'gemini' excluded by the surface's allowed_providers")),
        "gemini must be excluded from the sdlc surface router: {:?}",
        assembled.report
    );
    // claude and gpt were NOT excluded by policy (they may still be skipped for a missing key, but
    // never by the surface allow-list).
    assert!(
        !assembled
            .report
            .iter()
            .any(|r| r.contains("provider 'claude' excluded by the surface")),
        "an allow-listed provider must not be excluded by policy: {:?}",
        assembled.report
    );
}
