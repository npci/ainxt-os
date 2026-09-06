// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Surface catalog — the daemon-consumable registry of resolved [`SurfaceProfile`]s.
//!
//! The composition daemon needs one place to answer "give me the profile for surface `id`" and then
//! bind it for a turn. This module is that entry point:
//!
//! - [`builtin_profiles`] returns the four canonical surfaces (chat/code/sdlc/buddy) **embedded at
//!   compile time** from `profiles/*.toml`, so the daemon does not depend on a filesystem layout.
//! - [`SurfaceCatalog`] owns a set of profiles keyed by `id`, resolves deployment overrides via the
//!   layered loader, and hands out a [`SurfaceBinding`] ready to `plan()` a turn.
//!
//! Keeping this here (rather than in the daemon) means the profile → binding path is a real,
//! testable library surface, not a hardcoded assembly inside the binary.

use std::collections::BTreeMap;

use ainxt_profile::{ProfileError, SurfaceProfile};
use ainxt_skill::SkillRuntime;

use crate::SurfaceBinding;

/// The canonical profile TOMLs, embedded at compile time.
const CHAT: &str = include_str!("../profiles/chat.toml");
const CODE: &str = include_str!("../profiles/code.toml");
const SDLC: &str = include_str!("../profiles/sdlc.toml");
const BUDDY: &str = include_str!("../profiles/buddy.toml");

/// The four canonical surfaces, resolved + validated. Returns an error if a shipped profile is
/// malformed (a build/packaging bug), rather than panicking inside the library.
pub fn builtin_profiles() -> Result<Vec<SurfaceProfile>, ProfileError> {
    [CHAT, CODE, SDLC, BUDDY]
        .iter()
        .map(|src| SurfaceProfile::from_toml(src))
        .collect()
}

/// The raw embedded TOML source of a canonical surface, by id — the *base layer* a deployment override
/// merges on top of. `None` for a non-canonical id (a deployment cannot layer-override a surface the
/// build does not ship).
pub fn builtin_profile_toml(id: &str) -> Option<&'static str> {
    match id {
        "chat" => Some(CHAT),
        "code" => Some(CODE),
        "sdlc" => Some(SDLC),
        "buddy" => Some(BUDDY),
        _ => None,
    }
}

/// A registry of resolved surface profiles keyed by their `id`. Fail-closed: a lookup for an unknown
/// surface returns `None` (the daemon must decide what to do — never fabricate a default surface).
#[derive(Debug, Default, Clone)]
pub struct SurfaceCatalog {
    profiles: BTreeMap<String, SurfaceProfile>,
}

impl SurfaceCatalog {
    /// An empty catalog.
    pub fn new() -> Self {
        SurfaceCatalog::default()
    }

    /// The catalog pre-populated with the four canonical surfaces.
    pub fn builtin() -> Result<Self, ProfileError> {
        let mut c = SurfaceCatalog::new();
        for p in builtin_profiles()? {
            c.insert(p);
        }
        Ok(c)
    }

    /// The catalog of canonical surfaces with **deployment layer-overrides** applied — the served-path
    /// entrypoint for the layered profile merge (`defaults → deployment → …`, `ADR-004`). Each
    /// `(id, override_toml)` is resolved as `[canonical(id), override]`, so a deployment tweaks a single
    /// nested field of a canonical surface (e.g. `chat`'s `model_policy.default_tier`) WITHOUT restating
    /// the rest — the untouched fields (persona, RBAC floor, retrieval scope, capabilities) survive the
    /// deep merge. Fail-closed:
    ///
    /// * an override for a non-canonical id is an error (a deployment cannot layer-override a surface
    ///   the build does not ship — it must register a full profile via [`insert`](Self::insert));
    /// * an override that produces an invalid profile aborts the whole load (no partial catalog).
    ///
    /// Non-overridden surfaces keep their canonical profile. This is what makes the profile
    /// layer-override *live on the served daemon path*, not just a library capability of the loader.
    pub fn builtin_with_overrides(overrides: &[(&str, &str)]) -> Result<Self, ProfileError> {
        let mut c = SurfaceCatalog::builtin()?;
        for (id, override_toml) in overrides {
            let base = builtin_profile_toml(id).ok_or_else(|| {
                ProfileError::Invalid(format!(
                    "cannot layer-override unknown canonical surface '{id}' \
                     (register a full profile instead)"
                ))
            })?;
            let resolved = SurfaceProfile::resolve(&[(id, base), ("deployment", override_toml)])?;
            // The override must not silently repoint the id (a deployment tweaks a surface, it does
            // not rename it). The resolved id must still be `id`.
            if resolved.id != *id {
                return Err(ProfileError::Invalid(format!(
                    "layer-override for '{id}' changed the surface id to '{}'",
                    resolved.id
                )));
            }
            c.insert(resolved);
        }
        Ok(c)
    }

    /// The full **defaults → deployment → tenant** chain (ADR-004) applied to each canonical surface
    /// — the served-path entrypoint that closes the gap in [`builtin_with_overrides`] (which only ever
    /// applies a single "deployment" layer): a deployment can layer a cross-cutting override, and a
    /// tenant/org can layer a MORE-specific override on top of that, without either restating the
    /// other's fields. `deployment_overrides` and `tenant_overrides` are independent `(id, toml)`
    /// lists — a surface with no entry in one of them simply skips that layer (defaulting to an empty
    /// table, i.e. no-op). This, together with [`ainxt_profile::SurfaceProfile::with_request_layer`]
    /// applied per turn, is what makes the FULL five-layer chain
    /// (`defaults → deployment → tenant → profile → request`) actually consumed on the served surface
    /// path — `defaults` is the embedded canonical TOML, `deployment`/`tenant` are applied here at
    /// catalog-build time (producing the resolved "surface profile" rung), and `request` is applied at
    /// plan-time, per turn, never here.
    ///
    /// Fail-closed, same as [`builtin_with_overrides`]: an override for a non-canonical id, or one that
    /// silently repoints the surface id, aborts the whole load.
    pub fn builtin_with_tenant_overrides(
        deployment_overrides: &[(&str, &str)],
        tenant_overrides: &[(&str, &str)],
    ) -> Result<Self, ProfileError> {
        let mut c = SurfaceCatalog::builtin()?;
        let mut ids: Vec<&str> = deployment_overrides.iter().map(|(id, _)| *id).collect();
        ids.extend(tenant_overrides.iter().map(|(id, _)| *id));
        ids.sort_unstable();
        ids.dedup();
        for id in ids {
            let base = builtin_profile_toml(id).ok_or_else(|| {
                ProfileError::Invalid(format!(
                    "cannot layer-override unknown canonical surface '{id}' \
                     (register a full profile instead)"
                ))
            })?;
            let deployment = deployment_overrides
                .iter()
                .find(|(oid, _)| *oid == id)
                .map(|(_, src)| *src)
                .unwrap_or("");
            let tenant = tenant_overrides
                .iter()
                .find(|(oid, _)| *oid == id)
                .map(|(_, src)| *src)
                .unwrap_or("");
            let resolved = SurfaceProfile::resolve(&[
                (id, base),
                ("deployment", deployment),
                ("tenant", tenant),
            ])?;
            if resolved.id != id {
                return Err(ProfileError::Invalid(format!(
                    "layer-override for '{id}' changed the surface id to '{}'",
                    resolved.id
                )));
            }
            c.insert(resolved);
        }
        Ok(c)
    }

    /// Insert (or replace) a profile, keyed by its `id`. Returns the previous profile, if any.
    pub fn insert(&mut self, profile: SurfaceProfile) -> Option<SurfaceProfile> {
        self.profiles.insert(profile.id.clone(), profile)
    }

    /// Resolve each `(name, toml)` source as a full profile and register it. A source that fails to
    /// resolve/validate aborts the whole load (fail-closed: a bad deployment config never boots a
    /// partial catalog).
    pub fn from_toml_sources(sources: &[(&str, &str)]) -> Result<Self, ProfileError> {
        let mut c = SurfaceCatalog::new();
        for (_, src) in sources {
            c.insert(SurfaceProfile::from_toml(src)?);
        }
        Ok(c)
    }

    /// Resolve one surface from ordered layers (`defaults → deployment → tenant → profile`) and
    /// register it — the deployment-override path (a deployment tweaks one nested field of a base
    /// profile without restating the rest). Returns the registered id.
    pub fn insert_layered(&mut self, layers: &[(&str, &str)]) -> Result<String, ProfileError> {
        let p = SurfaceProfile::resolve(layers)?;
        let id = p.id.clone();
        self.insert(p);
        Ok(id)
    }

    /// The profile for a surface id, if registered.
    pub fn get(&self, id: &str) -> Option<&SurfaceProfile> {
        self.profiles.get(id)
    }

    /// The registered surface ids (sorted).
    pub fn ids(&self) -> Vec<&str> {
        self.profiles.keys().map(String::as_str).collect()
    }

    pub fn contains(&self, id: &str) -> bool {
        self.profiles.contains_key(id)
    }
    pub fn len(&self) -> usize {
        self.profiles.len()
    }
    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }

    /// Bind surface `id` to a skill runtime, producing a [`SurfaceBinding`] ready to `plan()` a turn.
    /// `None` if the surface is not registered. This is the daemon's one-call path:
    /// `catalog.bind("chat", &skills)?.plan(principal, input, data_class, guards)`.
    pub fn bind<'a>(&'a self, id: &str, skills: &'a SkillRuntime) -> Option<SurfaceBinding<'a>> {
        self.get(id).map(|p| SurfaceBinding::new(p, skills))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ainxt_profile::{Autonomy, RetrievalScope};
    use ainxt_skill::{NoExecutor, SkillRegistry, SkillRuntime};
    use ainxt_types::{DataClass, Principal, Tier};

    fn skills() -> SkillRuntime {
        SkillRuntime::new(SkillRegistry::new(), Box::new(NoExecutor))
    }

    fn dept_user() -> Principal {
        Principal::user("u", &["chat.send"]).with_department("payments")
    }

    #[test]
    fn builtin_catalog_has_the_four_canonical_surfaces() {
        let c = SurfaceCatalog::builtin().unwrap();
        assert_eq!(c.ids(), vec!["buddy", "chat", "code", "sdlc"]);
        assert!(c.contains("chat"));
        assert_eq!(c.get("sdlc").unwrap().autonomy, Autonomy::ActWithApproval);
        assert!(c.get("nonexistent").is_none());
    }

    #[test]
    fn bind_then_plan_is_the_daemon_path() {
        let c = SurfaceCatalog::builtin().unwrap();
        let sk = skills();
        let plan = c
            .bind("chat", &sk)
            .expect("chat is registered")
            .plan(&dept_user(), "how did UPI grow?", DataClass::Public, &[])
            .unwrap();
        assert_eq!(plan.retrieval, RetrievalScope::PlatformAndNamespace);
        assert_eq!(plan.department_scope.as_deref(), Some("payments"));
        assert!(!plan.allow_side_effects);
    }

    #[test]
    fn bind_unknown_surface_is_none() {
        let c = SurfaceCatalog::builtin().unwrap();
        let sk = skills();
        assert!(c.bind("ghost", &sk).is_none());
    }

    #[test]
    fn insert_layered_applies_a_more_specific_override() {
        // Defaults set a nested tier; the profile layer (more specific) overrides just that field
        // without restating the rest.
        let mut c = SurfaceCatalog::new();
        let defaults = r#"[model_policy]
            default_tier = "complex""#;
        let profile = r#"id = "code"
            [model_policy]
            default_tier = "simple""#;
        let id = c
            .insert_layered(&[("defaults", defaults), ("profile", profile)])
            .unwrap();
        assert_eq!(id, "code");
        assert_eq!(
            c.get("code").unwrap().model_policy.default_tier,
            Tier::Simple
        );
    }

    #[test]
    fn from_toml_sources_registers_each_by_id() {
        let c =
            SurfaceCatalog::from_toml_sources(&[("a", r#"id = "alpha""#), ("b", r#"id = "beta""#)])
                .unwrap();
        assert_eq!(c.ids(), vec!["alpha", "beta"]);
    }

    #[test]
    fn from_toml_sources_fails_closed_on_a_bad_profile() {
        // Missing id → the whole load aborts (no partial catalog).
        let err = SurfaceCatalog::from_toml_sources(&[
            ("ok", r#"id = "alpha""#),
            ("bad", r#"persona = "no id""#),
        ]);
        assert!(err.is_err());
    }

    // ==================== full defaults→deployment→tenant chain (R15) ====================

    #[test]
    fn r15_tenant_layer_overrides_deployment_which_overrides_canonical_defaults() {
        // canonical `chat` ships `autonomy = "read-only"` and `model_policy.default_tier = "simple"`.
        let c = SurfaceCatalog::builtin_with_tenant_overrides(
            &[("chat", "[model_policy]\ndefault_tier = \"medium\"")],
            &[("chat", "[model_policy]\ndefault_tier = \"complex\"")],
        )
        .unwrap();
        // The tenant layer (most specific of the two) wins over the deployment layer.
        assert_eq!(
            c.get("chat").unwrap().model_policy.default_tier,
            Tier::Complex
        );
        // A field neither layer touches survives from the canonical defaults.
        assert_eq!(
            c.get("chat").unwrap().autonomy,
            ainxt_profile::Autonomy::ReadOnly
        );
    }

    #[test]
    fn r15_a_surface_with_only_a_tenant_override_and_no_deployment_override_still_resolves() {
        let c = SurfaceCatalog::builtin_with_tenant_overrides(
            &[],
            &[("code", "[model_policy]\ndefault_tier = \"complex\"")],
        )
        .unwrap();
        assert_eq!(
            c.get("code").unwrap().model_policy.default_tier,
            Tier::Complex
        );
        // Untouched canonical surfaces are still present.
        assert!(c.contains("chat") && c.contains("sdlc") && c.contains("buddy"));
    }

    #[test]
    fn r15_a_surface_with_only_a_deployment_override_and_no_tenant_override_still_resolves() {
        let c = SurfaceCatalog::builtin_with_tenant_overrides(
            &[("buddy", "[model_policy]\ndefault_tier = \"complex\"")],
            &[],
        )
        .unwrap();
        assert_eq!(
            c.get("buddy").unwrap().model_policy.default_tier,
            Tier::Complex
        );
    }

    #[test]
    fn r15_tenant_override_for_an_unknown_canonical_surface_is_rejected() {
        let err = SurfaceCatalog::builtin_with_tenant_overrides(&[], &[("ghost", "id=\"ghost\"")]);
        assert!(err.is_err());
    }

    #[test]
    fn r15_no_overrides_at_all_is_byte_identical_to_plain_builtin() {
        let plain = SurfaceCatalog::builtin().unwrap();
        let layered = SurfaceCatalog::builtin_with_tenant_overrides(&[], &[]).unwrap();
        assert_eq!(plain.ids(), layered.ids());
        for id in plain.ids() {
            assert_eq!(plain.get(id), layered.get(id));
        }
    }
}
