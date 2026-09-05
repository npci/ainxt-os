// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! P5-EXIT DoD acceptance matrix — drive the extensibility subsystems (harness capability-permission
//! runtime, git-native governance + marketplace, plugin isolation) through the scenario harness. The
//! headline is the **safety invariants**: an engineer-authored harness/plugin cannot disable
//! compliance/RBAC, exceed its budget, exceed granted permissions, or escape its sandbox.

use ainxt_admission::{
    lint_manifest, CapabilityAuthorizer, CapabilityGrant, HarnessBudget, HarnessManifest,
    HarnessOutcome, HarnessRbac, HarnessRuntime, HarnessStep, InMemoryHarnessAudit,
    PaymentBoundary, RunContext, StepExecutor, StepKind, StepResult,
};
use ainxt_governance::{
    advance, advance_with_evidence, gate_push, publish, start, CodeownersApproval, GitEvent,
    GovEvidence, GovernanceState, MarkerPrereceiveGate, MarketError, Marketplace, PinnedSource,
    PublishRequest, Signature, SingleOwnerPolicy, TrustedKeyVerifier,
};
use ainxt_plugin::{
    NativeHost, PluginError, PluginGrant, PluginHost, PluginManifest, ResourceLimits,
};
use ainxt_scenario::{Category, Expectation, Observation, Runner, Scenario, Target};
use ainxt_types::{DataClass, Principal, Role};

fn ok(output: String) -> Observation {
    Observation {
        output,
        error: None,
        side_effects: Vec::new(),
        latency_ms: 0,
    }
}
fn err(message: String) -> Observation {
    Observation {
        output: String::new(),
        error: Some(message),
        side_effects: Vec::new(),
        latency_ms: 0,
    }
}

struct FixedExecutor;
impl StepExecutor for FixedExecutor {
    fn execute(&self, step: &HarnessStep, _p: &Principal) -> StepResult {
        StepResult::new(10, format!("ran {}", step.id))
    }
}

fn step(id: &str, cap: &str, kind: StepKind) -> HarnessStep {
    HarnessStep {
        id: id.into(),
        kind,
        capability: cap.into(),
        estimated_tokens: 10,
        input: None,
    }
}

fn manifest(
    caps: &[&str],
    steps: Vec<HarnessStep>,
    budget: HarnessBudget,
    rbac: HarnessRbac,
) -> HarnessManifest {
    let mut m =
        HarnessManifest::new("h", steps).with_capabilities(caps.iter().map(|s| s.to_string()));
    m.budget = budget;
    m.rbac = rbac;
    m
}

fn harness_runtime() -> HarnessRuntime {
    HarnessRuntime::new(
        Box::new(CapabilityAuthorizer),
        Box::new(InMemoryHarnessAudit::new()),
    )
}

struct P5DodTarget;

impl Target for P5DodTarget {
    fn run(&self, s: &Scenario) -> Observation {
        match s.id.as_str() {
            "HARNESS-HAPPY-001" => {
                let rt = harness_runtime();
                let m = manifest(
                    &["llm.call", "tool.grep"],
                    vec![
                        step("s1", "llm.call", StepKind::Llm),
                        step("s2", "tool.grep", StepKind::Tool),
                    ],
                    HarnessBudget::default(),
                    HarnessRbac::default(),
                );
                let out = rt.run(
                    &m,
                    &CapabilityGrant::new(["llm.call", "tool.grep"]),
                    &Principal::user("u", &["llm.call", "tool.grep"]),
                    &FixedExecutor,
                );
                match out {
                    HarnessOutcome::Completed {
                        steps_run,
                        tool_calls,
                        ..
                    } => ok(format!(
                        "harness completed steps={steps_run} tool-calls={tool_calls}"
                    )),
                    other => err(format!("expected completion, got {other}")),
                }
            }
            "HARNESS-NO-BYPASS-001" => {
                // The manifest schema cannot express a gate bypass.
                let bad = r#"{"id":"h","steps":[],"disable_compliance":true}"#;
                let rejected = serde_json::from_str::<HarnessManifest>(bad).is_err();
                ok(format!("harness bypass-field-rejected={rejected}"))
            }
            "HARNESS-CAP-DENY-001" => {
                let rt = harness_runtime();
                let m = manifest(
                    &["tool.delete"],
                    vec![step("s1", "tool.delete", StepKind::Tool)],
                    HarnessBudget::default(),
                    HarnessRbac::default(),
                );
                // Requested + principal-held, but NOT granted by governance.
                match rt.run(
                    &m,
                    &CapabilityGrant::new(["tool.grep"]),
                    &Principal::user("u", &["tool.delete"]),
                    &FixedExecutor,
                ) {
                    HarnessOutcome::CapabilityDenied { .. } => {
                        err("capability denied: ungranted".into())
                    }
                    other => err(format!("expected capability denial, got {other}")),
                }
            }
            "HARNESS-BUDGET-001" => {
                let rt = harness_runtime();
                let budget = HarnessBudget {
                    max_steps: 1,
                    ..HarnessBudget::default()
                };
                let m = manifest(
                    &["c"],
                    vec![
                        step("s1", "c", StepKind::Llm),
                        step("s2", "c", StepKind::Llm),
                    ],
                    budget,
                    HarnessRbac::default(),
                );
                match rt.run(
                    &m,
                    &CapabilityGrant::new(["c"]),
                    &Principal::user("u", &["c"]),
                    &FixedExecutor,
                ) {
                    HarnessOutcome::BudgetExceeded { limit, .. } => {
                        err(format!("budget exceeded: {limit}"))
                    }
                    other => err(format!("expected budget exceed, got {other}")),
                }
            }
            "HARNESS-RBAC-001" => {
                let rt = harness_runtime();
                let m = manifest(
                    &["c"],
                    vec![step("s1", "c", StepKind::Llm)],
                    HarnessBudget::default(),
                    HarnessRbac {
                        min_role: Role::Admin,
                        required_caps: vec![],
                    },
                );
                match rt.run(
                    &m,
                    &CapabilityGrant::new(["c"]),
                    &Principal::user("u", &["c"]),
                    &FixedExecutor,
                ) {
                    HarnessOutcome::Rejected(_) => err("rejected: role below floor".into()),
                    other => err(format!("expected rbac rejection, got {other}")),
                }
            }
            "HARNESS-DATACLASS-001" => {
                let rt = harness_runtime();
                let mut m = manifest(
                    &["llm.call"],
                    vec![step("s1", "llm.call", StepKind::Llm)],
                    HarnessBudget::default(),
                    HarnessRbac::default(),
                );
                m.data_class_ceiling = DataClass::Internal;
                // A regulated-payment turn into an internal-ceiling harness is refused.
                match rt.run_with_context(
                    &m,
                    &CapabilityGrant::new(["llm.call"]),
                    &Principal::user("u", &["llm.call"]),
                    &RunContext::new(DataClass::RegulatedPayment),
                    &FixedExecutor,
                ) {
                    HarnessOutcome::DataClassExceeded { .. } => {
                        err("data class exceeds harness ceiling".into())
                    }
                    other => err(format!("expected data-class refusal, got {other}")),
                }
            }
            "HARNESS-PAYMENT-001" => {
                let rt = harness_runtime();
                // payment_boundary defaults to None; a rail step must be refused.
                let m = manifest(
                    &["connector.upi.initiate"],
                    vec![step("s1", "connector.upi.initiate", StepKind::Tool)],
                    HarnessBudget::default(),
                    HarnessRbac::default(),
                );
                match rt.run(
                    &m,
                    &CapabilityGrant::new(["connector.upi.initiate"]),
                    &Principal::user("u", &["connector.upi.initiate"]),
                    &FixedExecutor,
                ) {
                    HarnessOutcome::PaymentBoundaryViolation { declared, .. } => {
                        assert_eq!(declared, PaymentBoundary::None);
                        err("payment boundary violation".into())
                    }
                    other => err(format!("expected payment-boundary refusal, got {other}")),
                }
            }
            "HARNESS-LINT-001" => {
                // A manifest missing its owner fails manifest-lint (ADR-026 CI gate).
                let mut m = manifest(
                    &["llm.call"],
                    vec![step("s1", "llm.call", StepKind::Llm)],
                    HarnessBudget::default(),
                    HarnessRbac::default(),
                );
                m.owner = String::new();
                match lint_manifest(&m) {
                    Err(findings) if findings.iter().any(|f| f.code == "owner") => {
                        err("lint failed: owner required".into())
                    }
                    _ => err("expected a lint failure for the missing owner".into()),
                }
            }
            "GOV-SIGNED-MERGE-001" => {
                // A git-native merge requires CODEOWNERS approval + a verified signature.
                let codeowners = SingleOwnerPolicy {
                    owner: "settlement-ops".into(),
                };
                let verifier = TrustedKeyVerifier::new(["release-key"]);
                let payload = "merge -> main";
                let approval = CodeownersApproval {
                    approver: "alice".into(),
                    groups: vec!["settlement-ops".into()],
                };
                let good = Signature {
                    key_id: "release-key".into(),
                    signature: TrustedKeyVerifier::expected_signature("release-key", payload),
                };
                let approved = advance_with_evidence(
                    GovernanceState::PendingApproval,
                    GitEvent::MergeApproved,
                    GovEvidence::Merge {
                        path: "harnesses/rca.md",
                        approval: &approval,
                        payload,
                        signature: &good,
                    },
                    &codeowners,
                    &verifier,
                )
                .map(|s| s == GovernanceState::Approved)
                .unwrap_or(false);
                // A forged signature must be rejected.
                let forged = Signature {
                    key_id: "release-key".into(),
                    signature: "forged".into(),
                };
                let rejected = advance_with_evidence(
                    GovernanceState::PendingApproval,
                    GitEvent::MergeApproved,
                    GovEvidence::Merge {
                        path: "harnesses/rca.md",
                        approval: &approval,
                        payload,
                        signature: &forged,
                    },
                    &codeowners,
                    &verifier,
                )
                .is_err();
                ok(format!(
                    "gov signed-merge approved={approved} forged-rejected={rejected}"
                ))
            }
            "GOV-LIFECYCLE-001" => {
                let mut st = start();
                for ev in [
                    GitEvent::OpenPr,
                    GitEvent::MergeApproved,
                    GitEvent::PromoteSignedTag,
                ] {
                    st = match advance(st, ev) {
                        Ok(s) => s,
                        Err(e) => return err(format!("lifecycle broke: {e}")),
                    };
                }
                let pr = publish(PublishRequest {
                    definition_id: "harness.rca".into(),
                    branch: "publish/rca".into(),
                    path: "harnesses/rca.md".into(),
                    content: "id=\"rca\"".into(),
                });
                ok(format!(
                    "gov reached={st:?} publish-target={} files={}",
                    pr.target,
                    pr.files.len()
                ))
            }
            "GOV-PREGATE-001" => {
                let pr = publish(PublishRequest {
                    definition_id: "x".into(),
                    branch: "b".into(),
                    path: "x.md".into(),
                    content: "leak PAN=4111111111111111".into(),
                });
                match gate_push(&pr, &MarkerPrereceiveGate) {
                    Err(findings) if !findings.is_empty() => {
                        err("pre-receive gate blocked PII push".into())
                    }
                    _ => err("expected the gate to block a PII push".into()),
                }
            }
            "MARKET-TOFU-001" => {
                let mut m = Marketplace::new();
                let src = |h: &str| PinnedSource {
                    name: "acme".into(),
                    repo_url: "https://git/acme".into(),
                    pinned_hash: h.into(),
                };
                let first = m.resolve(src("hash-1")).is_ok();
                match m.resolve(src("hash-TAMPERED")) {
                    Err(MarketError::HashMismatch { .. }) => {
                        ok(format!("market first-pin={first} tamper-rejected=true"))
                    }
                    other => err(format!("expected hash mismatch, got {other:?}")),
                }
            }
            "PLUGIN-CONFINE-001" => {
                let mut host = NativeHost::new();
                host.register(
                    "evil",
                    Box::new(|_i, ctx| {
                        ctx.use_capability("fs.delete")?; // never granted → no ambient authority
                        Ok("deleted".into())
                    }),
                );
                let man = PluginManifest {
                    id: "evil".into(),
                    requested_capabilities: vec!["fs.delete".into()],
                    limits: ResourceLimits::default(),
                };
                match host.invoke(&man, &PluginGrant::new(["net.fetch"]), "x") {
                    Err(PluginError::CapabilityDenied(_)) => {
                        err("plugin denied ungranted capability".into())
                    }
                    other => err(format!("expected capability denial, got {other:?}")),
                }
            }
            "PLUGIN-ISOLATE-001" => {
                let mut host = NativeHost::new();
                host.register("boom", Box::new(|_i, _ctx| panic!("blew up")));
                let man = PluginManifest {
                    id: "boom".into(),
                    requested_capabilities: vec![],
                    limits: ResourceLimits::default(),
                };
                let trapped = matches!(
                    host.invoke(&man, &PluginGrant::default(), "x"),
                    Err(PluginError::Trap(_))
                );
                // Host still works after isolating the panic.
                host.register("ok", Box::new(|_i, _ctx| Ok("fine".into())));
                let survived = host
                    .invoke(
                        &PluginManifest {
                            id: "ok".into(),
                            requested_capabilities: vec![],
                            limits: ResourceLimits::default(),
                        },
                        &PluginGrant::default(),
                        "y",
                    )
                    .is_ok();
                ok(format!(
                    "plugin panic-trapped={trapped} host-survived={survived}"
                ))
            }
            other => err(format!("unknown scenario {other}")),
        }
    }
}

fn contains(cs: &[&str]) -> Expectation {
    Expectation {
        must_contain: cs.iter().map(|s| s.to_string()).collect(),
        must_complete: true,
        ..Default::default()
    }
}
fn expect_err(cs: &[&str]) -> Expectation {
    Expectation {
        must_complete: false,
        must_error_contains: cs.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    }
}

fn matrix() -> Vec<Scenario> {
    vec![
        Scenario::new(
            "HARNESS-HAPPY-001",
            "a declarative harness runs within policy",
            Category::Custom,
            "h",
            contains(&["completed", "tool-calls=1"]),
        ),
        Scenario::new(
            "HARNESS-NO-BYPASS-001",
            "the manifest schema cannot disable compliance/RBAC",
            Category::Custom,
            "h",
            contains(&["bypass-field-rejected=true"]),
        ),
        Scenario::new(
            "HARNESS-CAP-DENY-001",
            "a harness cannot exceed its granted permissions",
            Category::Custom,
            "h",
            expect_err(&["capability denied"]),
        ),
        Scenario::new(
            "HARNESS-BUDGET-001",
            "a harness cannot exceed its budget",
            Category::Custom,
            "h",
            expect_err(&["budget exceeded"]),
        ),
        Scenario::new(
            "HARNESS-RBAC-001",
            "a principal below the RBAC floor is rejected",
            Category::RbacDeny,
            "h",
            expect_err(&["role below floor"]),
        ),
        Scenario::new(
            "HARNESS-DATACLASS-001",
            "a turn above the harness data-class ceiling is refused",
            Category::Custom,
            "h",
            expect_err(&["data class exceeds"]),
        ),
        Scenario::new(
            "HARNESS-PAYMENT-001",
            "a payment-rail step is refused when payment_boundary is none",
            Category::Custom,
            "h",
            expect_err(&["payment boundary violation"]),
        ),
        Scenario::new(
            "HARNESS-LINT-001",
            "manifest-lint fails a manifest missing its owner",
            Category::Custom,
            "h",
            expect_err(&["owner required"]),
        ),
        Scenario::new(
            "GOV-SIGNED-MERGE-001",
            "a git-native merge needs CODEOWNERS approval + a verified signature",
            Category::Custom,
            "g",
            contains(&["approved=true", "forged-rejected=true"]),
        ),
        Scenario::new(
            "GOV-LIFECYCLE-001",
            "git-native lifecycle reaches production; publish emits a PR",
            Category::Custom,
            "g",
            contains(&["reached=Production", "publish-target=main", "files=1"]),
        ),
        Scenario::new(
            "GOV-PREGATE-001",
            "the pre-receive gate blocks a PII push (never redacts)",
            Category::Custom,
            "g",
            expect_err(&["blocked PII"]),
        ),
        Scenario::new(
            "MARKET-TOFU-001",
            "a tampered marketplace hash is rejected (TOFU pin)",
            Category::Custom,
            "m",
            contains(&["tamper-rejected=true"]),
        ),
        Scenario::new(
            "PLUGIN-CONFINE-001",
            "a plugin cannot use an ungranted capability (no ambient authority)",
            Category::Injection,
            "p",
            expect_err(&["denied ungranted"]),
        ),
        Scenario::new(
            "PLUGIN-ISOLATE-001",
            "a panicking plugin is isolated; the host survives",
            Category::Custom,
            "p",
            contains(&["panic-trapped=true", "host-survived=true"]),
        ),
    ]
}

#[test]
fn p5_exit_acceptance_matrix_is_green() {
    let report = Runner::with_default_oracles().run(&matrix(), &P5DodTarget);
    eprintln!("{}", report.summary());
    assert!(
        report.junit_xml().contains("<testsuite"),
        "JUnit report is produced for CI"
    );
    assert!(
        report.all_passed(),
        "P5 acceptance matrix must be green:\n{}",
        report.summary()
    );
    assert!(
        report.coverage().len() >= 3,
        "matrix must cover >= 3 P5 categories (got {})",
        report.coverage().len()
    );
}
