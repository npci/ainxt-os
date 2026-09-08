// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R13 §3.2 — **dependency isolation** proven offline against the [`PluginRegistry`] switchboard.
//!
//! §3.2 says: a plugin's dependencies live inside its own module (no shared, mutable, process-wide
//! graph), one plugin's state can never collide with or destabilize another's, and plugin-to-plugin
//! interaction goes **only** through the host's typed capability call — never a direct in-process call
//! between two plugin instances. The concrete WASM host links each module independently and routes peer
//! calls through the same switchboard; these tests pin the routing/isolation contract offline, without
//! wasmtime (which is infra-gated behind the Gate-#0 license review).

use ainxt_plugin::{PeerCall, PluginError, PluginRegistry, RegisterError, ResourceLimits};

fn limits() -> ResourceLimits {
    ResourceLimits::default()
}

/// A plugin registered with an effective set, an exposed set, and its body. Thin helper so each test
/// reads as intent.
fn reg(
    r: &mut PluginRegistry,
    id: &str,
    effective: &[&str],
    exposes: &[&str],
    body: fn(&str, &PeerCall<'_>) -> Result<String, PluginError>,
) {
    r.register(
        id,
        effective.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        exposes.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        limits(),
        Box::new(body),
    )
    .expect("registration succeeds");
}

#[test]
fn peer_call_routes_only_through_the_registry_never_a_direct_handle() {
    // B exposes "kv.read"; A is granted "kv.read" and reaches B ONLY by naming the capability. A holds
    // no reference to B — the registry is the switchboard.
    let mut r = PluginRegistry::new();
    reg(&mut r, "provider_b", &[], &["kv.read"], |input, _ctx| {
        Ok(format!("B-served:{input}"))
    });
    reg(&mut r, "caller_a", &["kv.read"], &[], |input, ctx| {
        let served = ctx.call("kv.read", input)?;
        Ok(format!("A-wraps[{served}]"))
    });

    let out = r.invoke("caller_a", "acct-42").expect("A runs");
    assert_eq!(out.output, "A-wraps[B-served:acct-42]");
    // A exercised exactly the capability it was granted — recorded for audit.
    assert_eq!(out.used_capabilities, vec!["kv.read".to_string()]);
}

#[test]
fn peer_call_is_gated_by_the_callers_own_grant_no_ambient_authority() {
    // A tries to reach a capability it was NOT granted. Even though a provider exists, A's own effective
    // set gate refuses it first — no ambient authority, not even for peer calls.
    let mut r = PluginRegistry::new();
    reg(&mut r, "provider", &[], &["fs.write"], |_i, _c| {
        Ok("wrote /etc/passwd".into())
    });
    reg(&mut r, "attacker", &["net.fetch"], &[], |i, ctx| {
        ctx.call("fs.write", i) // fs.write not in attacker's effective set
    });

    let err = r.invoke("attacker", "x").unwrap_err();
    assert_eq!(err, PluginError::CapabilityDenied("fs.write".into()));
}

#[test]
fn calling_a_capability_no_one_exposes_is_a_hard_error_not_a_silent_noop() {
    // A is granted the capability, but no plugin provides it. That must be a hard, typed error — a
    // payments platform never swallows a missing dependency.
    let mut r = PluginRegistry::new();
    reg(&mut r, "a", &["ledger.post"], &[], |i, ctx| {
        ctx.call("ledger.post", i)
    });
    let err = r.invoke("a", "x").unwrap_err();
    assert_eq!(
        err,
        PluginError::CapabilityUnavailable("ledger.post".into())
    );
}

#[test]
fn provider_confinement_does_not_leak_to_or_from_the_caller() {
    // B internally needs "secret.sign" (granted to B only). A calls B's exposed "sign" capability; B
    // succeeds using ITS OWN grant. A, given the same capability name directly, cannot use it — B's
    // authority never leaked to A, and A's context never touched B's internals.
    let mut r = PluginRegistry::new();
    reg(
        &mut r,
        "signer_b",
        &["secret.sign"],
        &["sign"],
        |input, ctx| {
            ctx.use_capability("secret.sign")?; // B's own private authority
            Ok(format!("signed({input})"))
        },
    );
    // A is granted "sign" (to route to B) but NOT "secret.sign".
    reg(&mut r, "caller_a", &["sign"], &[], |input, ctx| {
        let signed = ctx.call("sign", input)?;
        // A must not be able to wield B's private authority itself.
        let leaked = ctx.use_capability("secret.sign");
        assert_eq!(
            leaked,
            Err(PluginError::CapabilityDenied("secret.sign".into())),
            "B's authority must not leak to A"
        );
        Ok(signed)
    });

    let out = r.invoke("caller_a", "msg").expect("A runs");
    assert_eq!(out.output, "signed(msg)");
    // A's audit trail shows only "sign" — never B's private "secret.sign".
    assert_eq!(out.used_capabilities, vec!["sign".to_string()]);
}

#[test]
fn inter_plugin_cycle_is_bounded_not_a_hang_or_stack_overflow() {
    // A exposes "a" and calls "b"; B exposes "b" and calls "a" — a cycle. The bounded depth turns it
    // into a contained trap; the host survives (this test returning at all is the proof it didn't hang
    // or overflow the stack).
    let mut r = PluginRegistry::new().with_max_depth(4);
    reg(&mut r, "a", &["b"], &["a"], |i, ctx| ctx.call("b", i));
    reg(&mut r, "b", &["a"], &["b"], |i, ctx| ctx.call("a", i));

    let err = r.invoke("a", "x").unwrap_err();
    assert_eq!(err, PluginError::CallDepthExceeded { max_depth: 4 });

    // The registry is still usable afterwards — a good, non-cyclic plugin runs fine.
    reg(&mut r, "ok", &[], &[], |i, _c| Ok(format!("ok:{i}")));
    assert_eq!(r.invoke("ok", "y").unwrap().output, "ok:y");
}

#[test]
fn duplicate_exposer_is_rejected_so_routing_is_never_ambiguous() {
    let mut r = PluginRegistry::new();
    reg(&mut r, "first", &[], &["cap.x"], |_i, _c| Ok("1".into()));
    let err = r
        .register(
            "second",
            Vec::<String>::new(),
            vec!["cap.x".to_string()],
            limits(),
            Box::new(|_i, _c| Ok("2".into())),
        )
        .unwrap_err();
    assert_eq!(
        err,
        RegisterError::DuplicateExposer {
            capability: "cap.x".into(),
            existing: "first".into(),
        }
    );
}

#[test]
fn state_is_isolated_across_invocations_of_the_same_plugin() {
    // A registry plugin cannot accumulate state across calls — each invocation gets a fresh confined
    // context. We prove the used-capability set does not carry over.
    let mut r = PluginRegistry::new();
    reg(&mut r, "p", &["cap.a", "cap.b"], &[], |input, ctx| {
        if input == "use-a" {
            ctx.use_capability("cap.a")?;
        } else {
            ctx.use_capability("cap.b")?;
        }
        Ok("ok".into())
    });

    let first = r.invoke("p", "use-a").unwrap();
    assert_eq!(first.used_capabilities, vec!["cap.a".to_string()]);
    let second = r.invoke("p", "use-b").unwrap();
    // Fresh context: only cap.b — cap.a from the previous call did NOT persist.
    assert_eq!(second.used_capabilities, vec!["cap.b".to_string()]);
}

#[test]
fn a_panicking_registry_plugin_is_isolated_and_peers_survive() {
    let mut r = PluginRegistry::new();
    reg(&mut r, "boom", &[], &[], |_i, _c| panic!("plugin blew up"));
    reg(&mut r, "healthy", &[], &[], |i, _c| Ok(format!("fine:{i}")));

    let err = r.invoke("boom", "x").unwrap_err();
    assert!(
        matches!(err, PluginError::Trap(_)),
        "panic must be isolated"
    );
    // The registry survives; a co-located plugin still runs.
    assert_eq!(r.invoke("healthy", "y").unwrap().output, "fine:y");
}
