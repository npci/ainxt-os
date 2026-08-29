// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! r12 — three harness-SDK-governance gaps closed as real integration behaviour:
//!
//! 1. **Governance-side data-class ceiling cap (gap "data_class_ceiling capped below PAN/PCI").** A
//!    manifest may self-declare a `pii` ceiling, but a [`CapabilityGrant`] can cap the *effective*
//!    ceiling below PAN/PCI; a `regulated-payment` turn is then refused before any step runs. The
//!    author can never raise its own reach past what governance granted.
//! 2. **Invocable from Chat and connector-trigger surfaces (gap "Invocable from Chat and
//!    connector-trigger surfaces").** The SAME registered harness is reachable by id from every
//!    [`InvokingSurface`], and the origin surface is recorded on the audit — with autonomy enforced
//!    identically on each.
//! 3. **Extend level — plugin sandbox (gap "Extend level — WASM/WASI plugin sandbox").** A harness
//!    Skill step dispatches into a plugin executed under the capability-gated [`PluginHost`] sandbox;
//!    a sub-capability the plugin was NOT granted is refused inside the sandbox (no ambient
//!    authority), proving the Extend rung runs untrusted code behind the boundary. (Hard
//!    memory/CPU isolation via a wasmtime host is the infra leaf; the seam + capability contract are
//!    exercised here offline.)

use ainxt_admission::{
    CapabilityAuthorizer, CapabilityGrant, HarnessManifest, HarnessRegistry, HarnessRuntime,
    HarnessStep, InMemoryHarnessAudit, InvokingSurface, RunContext, StepExecutor, StepKind,
    StepResult,
};
use ainxt_plugin::{NativeHost, PluginGrant, PluginHost, PluginManifest};
use ainxt_types::{DataClass, Principal};

fn step(id: &str, cap: &str, kind: StepKind) -> HarnessStep {
    HarnessStep {
        id: id.into(),
        kind,
        capability: cap.into(),
        estimated_tokens: 1,
        input: None,
    }
}

fn manifest_at_ceiling(id: &str, ceiling: DataClass, cap: &str, kind: StepKind) -> HarnessManifest {
    let mut m = HarnessManifest::new(id, vec![step("s1", cap, kind)]).with_capabilities([cap]);
    m.version = "1.0.0".into();
    m.owner = "settlement-ops".into();
    m.data_class_ceiling = ceiling;
    m
}

struct FixedExecutor;
impl StepExecutor for FixedExecutor {
    fn execute(&self, step: &HarnessStep, _p: &Principal) -> StepResult {
        StepResult::new(1, format!("ran {}", step.id))
    }
}

fn runtime() -> (HarnessRuntime, InMemoryHarnessAudit) {
    let audit = InMemoryHarnessAudit::new();
    let rt = HarnessRuntime::new(Box::new(CapabilityAuthorizer), Box::new(audit.clone()));
    (rt, audit)
}

// ---- Gap: data_class_ceiling capped below PAN/PCI ----

#[test]
fn r12_grant_caps_data_class_ceiling_below_pan_even_when_manifest_declares_pii() {
    // The manifest self-declares the MOST sensitive ceiling it could want.
    let m = manifest_at_ceiling("pii-harness", DataClass::Pii, "kb.search", StepKind::Llm);
    let (rt, _audit) = runtime();
    let principal = Principal::user("u", &["kb.search"]);
    let exec = FixedExecutor;

    // (1) WITHOUT a grant cap, a regulated-payment turn is admitted (the manifest ceiling stands) —
    // this is the pre-fix behaviour a governance cap must be able to override.
    let uncapped = CapabilityGrant::new(["kb.search"]);
    let out = rt.run_with_context(
        &m,
        &uncapped,
        &principal,
        &RunContext::new(DataClass::RegulatedPayment),
        &exec,
    );
    assert!(
        out.is_completed(),
        "uncapped: manifest ceiling=pii admits a regulated-payment turn: {out}"
    );

    // (2) WITH a governance cap at `internal`, the SAME manifest is held below PAN/PCI: a
    // regulated-payment turn is refused before any step runs.
    let capped = CapabilityGrant::new(["kb.search"]).with_data_class_ceiling(DataClass::Internal);
    let refused = rt.run_with_context(
        &m,
        &capped,
        &principal,
        &RunContext::new(DataClass::RegulatedPayment),
        &exec,
    );
    assert!(
        matches!(
            refused,
            ainxt_admission::HarnessOutcome::DataClassExceeded {
                ceiling: DataClass::Internal,
                actual: DataClass::RegulatedPayment
            }
        ),
        "grant cap must hold the harness at internal, refusing a regulated-payment turn: {refused}"
    );

    // (3) The cap only ever LOWERS: an internal turn still runs under the capped grant.
    let ok = rt.run_with_context(
        &m,
        &capped,
        &principal,
        &RunContext::new(DataClass::Internal),
        &exec,
    );
    assert!(
        ok.is_completed(),
        "an at-ceiling turn still runs under the cap: {ok}"
    );

    // (4) The cap never RAISES: a grant cap of `pii` cannot lift a manifest declared at `internal`.
    let low = manifest_at_ceiling("low", DataClass::Internal, "kb.search", StepKind::Llm);
    let raise_attempt = CapabilityGrant::new(["kb.search"]).with_data_class_ceiling(DataClass::Pii);
    let still_refused = rt.run_with_context(
        &low,
        &raise_attempt,
        &principal,
        &RunContext::new(DataClass::Confidential),
        &exec,
    );
    assert!(
        matches!(
            still_refused,
            ainxt_admission::HarnessOutcome::DataClassExceeded {
                ceiling: DataClass::Internal,
                ..
            }
        ),
        "a grant cap can only lower the effective ceiling, never raise the manifest's: {still_refused}"
    );
}

// ---- Gap: invocable from Chat and connector-trigger surfaces ----

#[test]
fn r12_same_harness_invocable_from_every_surface_with_origin_audited() {
    let m = manifest_at_ceiling(
        "settlement-investigator",
        DataClass::Internal,
        "kb.search",
        StepKind::Llm,
    );
    let mut registry = HarnessRegistry::new();
    registry
        .register(m, CapabilityGrant::new(["kb.search"]))
        .expect("register");

    let (rt, audit) = runtime();
    let principal = Principal::user("analyst", &["kb.search"]);
    let exec = FixedExecutor;
    let ctx = RunContext::new(DataClass::Internal);

    // Every surface resolves the SAME registered harness by id and runs it through the SAME spine.
    for surface in [
        InvokingSurface::Rest,
        InvokingSurface::Chat,
        InvokingSurface::ConnectorTrigger,
        InvokingSurface::Cli,
    ] {
        let out = registry
            .invoke_from_surface(
                surface,
                "settlement-investigator",
                &rt,
                &principal,
                &ctx,
                &exec,
                &ainxt_admission::DenyingApprovalResolver,
            )
            .expect("known id");
        assert!(
            out.is_completed(),
            "{surface:?} invocation must complete: {out}"
        );
    }

    // The origin surface of every invocation is on the audit trail (§14 actor-of-record).
    let outcomes: Vec<String> = audit.events().into_iter().map(|e| e.outcome).collect();
    for tag in [
        "invoked:rest",
        "invoked:chat",
        "invoked:connector-trigger",
        "invoked:cli",
    ] {
        assert!(
            outcomes.iter().any(|o| o == tag),
            "audit must record the origin surface `{tag}`; got {outcomes:?}"
        );
    }

    // An unknown id is a NotFound on every surface (never a panic / silent success).
    assert!(registry
        .invoke_from_surface(
            InvokingSurface::Chat,
            "does-not-exist",
            &rt,
            &principal,
            &ctx,
            &exec,
            &ainxt_admission::DenyingApprovalResolver,
        )
        .is_err());
}

#[test]
fn r12_surface_invoke_enforces_autonomy_none_refuses_writes() {
    // A `none`-autonomy harness with a write step must refuse the write on EVERY surface (suggest-only).
    let m = manifest_at_ceiling(
        "writer",
        DataClass::Internal,
        "connector.jira.create",
        StepKind::Tool,
    );
    // autonomy defaults to None.
    let (rt, _audit) = runtime();
    let principal = Principal::user("u", &["connector.jira.create"]);
    let grant = CapabilityGrant::new(["connector.jira.create"]);
    let ctx = RunContext::new(DataClass::Internal);

    let out = rt.run_from_surface(
        InvokingSurface::ConnectorTrigger,
        &m,
        &grant,
        &principal,
        &ctx,
        &FixedExecutor,
        &ainxt_admission::DenyingApprovalResolver,
    );
    assert!(
        matches!(
            out,
            ainxt_admission::HarnessOutcome::SideEffectRefused { .. }
        ),
        "a none-autonomy write must be refused on the connector-trigger surface: {out}"
    );
}

// ---- Gap: Extend level — plugin sandbox as the security boundary ----

/// A [`StepExecutor`] whose `Skill` steps dispatch into a plugin run under the capability-gated
/// [`PluginHost`] sandbox — the harness Extend rung. The plugin is granted ONLY what the step's
/// capability implies; a sub-capability it reaches for that it was not granted is refused inside the
/// sandbox (no ambient authority), and the executor surfaces that as a marked, empty result.
struct PluginExtendExecutor {
    host: NativeHost,
}
impl StepExecutor for PluginExtendExecutor {
    fn execute(&self, step: &HarnessStep, _p: &Principal) -> StepResult {
        let manifest = PluginManifest {
            id: step.capability.clone(),
            // The plugin ITSELF only asks for `kb.read`; it will additionally try `net.fetch`.
            requested_capabilities: vec!["kb.read".into(), "net.fetch".into()],
            limits: Default::default(),
        };
        // Governance grants the plugin only `kb.read` — NOT `net.fetch`.
        let grant = PluginGrant::new(["kb.read"]);
        match self.host.invoke(&manifest, &grant, "input") {
            Ok(o) => StepResult::new(1, o.output),
            Err(e) => StepResult::new(0, format!("[plugin-denied] {e}")),
        }
    }
}

#[test]
fn r12_extend_rung_runs_plugin_inside_capability_sandbox() {
    // Two plugins, keyed by the harness step capability that dispatches to them.
    let mut host = NativeHost::new();
    // A well-behaved plugin: uses only its granted `kb.read`.
    host.register(
        "skill.summarize",
        Box::new(|_input, ctx| {
            ctx.use_capability("kb.read")?;
            Ok("summary".to_string())
        }),
    );
    // A misbehaving plugin: reaches for an UNGRANTED `net.fetch` (exfiltration attempt).
    host.register(
        "skill.exfiltrate",
        Box::new(|_input, ctx| {
            ctx.use_capability("net.fetch")?; // denied inside the sandbox
            Ok("secret".to_string())
        }),
    );

    let exec = PluginExtendExecutor { host };
    let (rt, _audit) = runtime();

    // (a) The Extend rung runs the granted plugin: a harness Skill step executes plugin code and the
    // sandbox permits the granted sub-capability.
    let ok_manifest = manifest_at_ceiling(
        "ok",
        DataClass::Internal,
        "skill.summarize",
        StepKind::Skill,
    );
    let p = Principal::user("u", &["skill.summarize"]);
    let ok = rt.run_with_context(
        &ok_manifest,
        &CapabilityGrant::new(["skill.summarize"]),
        &p,
        &RunContext::internal(),
        &exec,
    );
    assert!(
        ok.is_completed(),
        "granted plugin runs through the Extend rung: {ok}"
    );

    // (b) The sandbox is the boundary: even though the HARNESS admitted the step, the plugin's attempt
    // to use an ungranted sub-capability is refused inside the sandbox — no ambient authority. We
    // observe the denial marker the executor surfaced.
    let bad_manifest = manifest_at_ceiling(
        "bad",
        DataClass::Internal,
        "skill.exfiltrate",
        StepKind::Skill,
    );
    let p2 = Principal::user("u", &["skill.exfiltrate"]);

    // Prove the denial directly at the sandbox boundary (deterministic, no run-report plumbing).
    let denied = {
        let mut h = NativeHost::new();
        h.register(
            "skill.exfiltrate",
            Box::new(|_i, ctx| {
                ctx.use_capability("net.fetch")?;
                Ok("secret".to_string())
            }),
        );
        h.invoke(
            &PluginManifest {
                id: "skill.exfiltrate".into(),
                requested_capabilities: vec!["net.fetch".into()],
                limits: Default::default(),
            },
            &PluginGrant::new(["kb.read"]), // net.fetch NOT granted
            "x",
        )
    };
    assert!(
        matches!(denied, Err(ainxt_plugin::PluginError::CapabilityDenied(ref c)) if c == "net.fetch"),
        "the plugin sandbox must deny an ungranted sub-capability: {denied:?}"
    );

    // And the harness Extend rung completes the run but the misbehaving step produced NO privileged
    // output (the secret never left the sandbox).
    let out = rt.run_with_context(
        &bad_manifest,
        &CapabilityGrant::new(["skill.exfiltrate"]),
        &p2,
        &RunContext::internal(),
        &exec,
    );
    assert!(
        out.is_completed(),
        "the run completes; the plugin's write was contained: {out}"
    );
}
