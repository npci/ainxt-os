// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R16 CRITICAL — the SHIPPED DAEMON must not silently trust client-controlled identity.
//!
//! `TrustedGatewayAuth` derives role, capabilities and clearance from `X-AInxt-*` headers. Reachable
//! directly, any caller can assert `role: admin` / `clearance: restricted` — above every RBAC gate in
//! the runtime. That is the intended design *behind a gateway that already validated the token*, so
//! the assumption is permitted; what is not permitted is inheriting it by silence.
//!
//! The daemon therefore fails closed: an operator who configures nothing gets a refusal naming both
//! supported ways forward, instead of a header-trusting daemon nobody audited.
//!
//! FAIL-BEFORE: `assemble_surface` succeeded with no configuration at all.
//! PASS-AFTER: it returns `AssembleError::Config` unless the deployment states the assumption
//! (`AINXT_TRUSTED_GATEWAY=1`) or selects the verifying `jwt-sso` authenticator.

use ainxt_runtimed::{assemble_full, assemble_surface, load_layered, LoadedConfig};

fn offline_cfg(tag: &str) -> LoadedConfig {
    let dir = std::env::temp_dir().join(format!("ainxt-r16-auth-{tag}"));
    let src = format!(
        "[server]\nevent_log_dir = \"{}\"\n",
        dir.to_string_lossy().replace('\\', "/")
    );
    load_layered(&[("r16auth", &src)]).expect("load offline config")
}

// ONE test, sequential: `AINXT_TRUSTED_GATEWAY` is process-wide, so two tests toggling it in the
// same binary race each other (they did — the "accepts" case set it and the "refuses" case then saw
// it set and passed vacuously). Both phases therefore run in order, in a single test.
#[test]
fn r16_daemon_fails_closed_on_the_header_trusting_default_and_starts_when_accepted() {
    // PHASE 1 — the operator who configured nothing.
    std::env::remove_var("AINXT_TRUSTED_GATEWAY");
    let cfg = offline_cfg("unset");
    let assembled = assemble_surface(&cfg, "chat").expect("surface assembly is not the auth gate");
    let msg = match assemble_full(&cfg, assembled) {
        Err(e) => format!("{e:?}"),
        Ok(_) => panic!(
            "the daemon started on an unaccepted header-trusting default — any caller can assert \
             role: admin / clearance: restricted, above every RBAC gate"
        ),
    };
    assert!(
        msg.contains("Refusing to start"),
        "the refusal must say it is refusing: {msg}"
    );
    // Actionable or it is just an obstacle: both supported remedies must be named.
    assert!(
        msg.contains("AINXT_TRUSTED_GATEWAY"),
        "refusal must name the explicit-acceptance path: {msg}"
    );
    assert!(
        msg.contains("jwt-sso"),
        "refusal must name the verifying-authenticator path: {msg}"
    );

    // PHASE 2 — the deployment that genuinely sits behind a validating gateway says so, and is served.
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let cfg2 = offline_cfg("set");
    let assembled2 = assemble_surface(&cfg2, "chat").expect("assemble chat surface");
    let out = assemble_full(&cfg2, assembled2);
    let ok = out.is_ok();
    std::env::remove_var("AINXT_TRUSTED_GATEWAY");
    assert!(
        ok,
        "an explicitly-accepted trusted-gateway deployment must still start"
    );
}
