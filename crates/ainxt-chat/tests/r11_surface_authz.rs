// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-11 closure: a non-chat surface executes only its DECLARED capabilities/connectors on the LIVE
//! served engine (SURF high). The engine consults `Authorizer::authorize_tool` before every tool /
//! connector dispatch; `SurfaceScopedAuthorizer` narrows that decision to the surface's declared set,
//! so a tool the surface does not offer is refused — even for an admin whose broad RBAC would allow it.
//!
//! Fails before `SurfaceScopedAuthorizer` existed (the served engine used a bare `RbacAuthorizer`, so
//! an admin could dispatch ANY registered tool regardless of the surface's declaration); passes after.

use ainxt_chat::SurfaceScopedAuthorizer;
use ainxt_compliance::StrongRedactor;
use ainxt_runtime::authz::{Authorizer, Decision};
use ainxt_runtime::router::ModelRouter;
use ainxt_runtime::{Engine, InMemoryAudit, RbacAuthorizer};
use ainxt_types::Principal;

/// A `code`-surface-scoped authorizer: offers grep/read/edit/bash + a connector, but NOT `tool.delete`.
fn code_scoped() -> SurfaceScopedAuthorizer {
    SurfaceScopedAuthorizer::new(
        Box::new(RbacAuthorizer),
        [
            "chat.send".to_string(),
            "tool.grep".to_string(),
            "tool.read".to_string(),
            "tool.edit".to_string(),
            "connector.gitlab".to_string(),
        ],
    )
}

#[test]
fn r11_surface_scoped_authorizer_restricts_to_declared_tools_even_for_admin() {
    let authz = code_scoped();
    let admin = Principal::admin("root"); // admin RBAC allows every capability at the base layer

    // A DECLARED tool: authorized (the base admin grant + in-scope) — the engine dispatch entrypoint.
    assert_eq!(authz.authorize_tool(&admin, "grep", None), Decision::Allow);
    assert_eq!(authz.authorize_tool(&admin, "edit", None), Decision::Allow);
    // A declared connector.
    assert_eq!(authz.authorize(&admin, "connector.gitlab"), Decision::Allow);

    // A tool the surface does NOT declare is refused for the admin — the surface cannot dispatch a
    // capability outside its declaration, even though the admin's base RBAC would allow it. The
    // engine's fine-grained entrypoint denies it…
    assert!(
        matches!(
            authz.authorize_tool(&admin, "delete", None),
            Decision::Deny(_)
        ),
        "an undeclared tool must be refused even for an admin"
    );
    // …and the direct capability check attributes the denial to the SURFACE SCOPE (not the base RBAC,
    // which would allow the admin) — proving it is the surface declaration doing the narrowing.
    match authz.authorize(&admin, "tool.delete") {
        Decision::Deny(m) => assert!(
            m.contains("outside this surface's declared capability set"),
            "denial must come from the surface scope, got: {m}"
        ),
        Decision::Allow => panic!("the surface scope must deny an undeclared tool for an admin"),
    }
    // Undeclared connector likewise.
    assert!(matches!(
        authz.authorize(&admin, "connector.jira"),
        Decision::Deny(_)
    ));

    // A NON-scoped capability (chat.send) defers to the base authorizer unchanged.
    assert_eq!(authz.authorize(&admin, "chat.send"), Decision::Allow);
}

#[test]
fn r11_surface_scoped_authorizer_still_honors_the_base_principal_gate() {
    // A plain user without the base capability is denied even for a DECLARED tool — the wrapper never
    // escalates; the base RBAC gate still runs.
    let authz = code_scoped();
    let user = Principal::user("u", &["chat.send"]); // holds chat.send, NOT tool.grep
    match authz.authorize_tool(&user, "grep", None) {
        Decision::Deny(_) => {}
        Decision::Allow => panic!("the base principal gate must still deny a cap the user lacks"),
    }
    // A user who holds the declared cap AND is in-surface-scope is allowed.
    let dev = Principal::user("d", &["tool.grep"]);
    assert_eq!(authz.authorize_tool(&dev, "grep", None), Decision::Allow);
    // …but a cap the user holds yet the surface does NOT declare is still refused (scope wins).
    let powerful = Principal::user("p", &["tool.delete"]);
    assert!(matches!(
        powerful
            .has_cap("tool.delete") // sanity: the user really holds it
            .then(|| authz.authorize_tool(&powerful, "delete", None))
            .unwrap(),
        Decision::Deny(_)
    ));
}

#[test]
fn r11_surface_scoped_authorizer_is_engine_consumable() {
    // Proof it plugs into the real Engine constructor as the mandatory authz gate — this is exactly how
    // the composition daemon builds a non-chat surface's engine so its tool loop is scope-bounded.
    let _engine = Engine::new(
        Box::new(StrongRedactor::new()),
        Box::new(code_scoped()),
        Box::new(InMemoryAudit::default()),
        ModelRouter::new(),
    );
}
