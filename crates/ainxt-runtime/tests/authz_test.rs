// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! On-behalf-of, fine-grained tool+resource authorization (ADR-003) — the confused-deputy
//! defense. Every tool call is authorized as THIS principal against THIS tool + resource before
//! dispatch; a denial is fail-closed (never dispatched), surfaced, and audited.

use std::sync::{Arc, Mutex};

use ainxt_protocol::{Event, Request};
use ainxt_runtime::audit::{AuditRecord, AuditSink};
use ainxt_runtime::authz::RbacAuthorizer;
use ainxt_runtime::compliance::RedactAndProceed;
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtime::Engine;
use ainxt_tools::{
    EffectClass, InMemoryLedger, ManualReconciler, RiskTier, Tool, ToolError, ToolRuntime,
};
use ainxt_types::{DataClass, Principal};
use tokio::sync::mpsc;

// A tool that records every arg it actually executes on (so tests see exactly what dispatched).
struct RecordingTool {
    name: &'static str,
    effect: EffectClass,
    risk: RiskTier,
    has_resource: bool,
    executed: Arc<Mutex<Vec<String>>>,
}
impl Tool for RecordingTool {
    fn name(&self) -> &str {
        self.name
    }
    fn effect_class(&self) -> EffectClass {
        self.effect
    }
    fn risk_tier(&self) -> RiskTier {
        self.risk
    }
    fn idempotency_key(&self, args: &str) -> Option<String> {
        if self.effect == EffectClass::SideEffecting {
            Some(args.to_string())
        } else {
            None
        }
    }
    fn resource(&self, args: &str) -> Option<String> {
        if self.has_resource {
            Some(args.to_string())
        } else {
            None
        }
    }
    fn execute(&self, args: &str) -> Result<String, ToolError> {
        self.executed
            .lock()
            .unwrap()
            .push(format!("{}:{args}", self.name));
        Ok(format!("{}:{args}", self.name))
    }
}

/// Emits a scripted list of (tool, args) calls in round 1, then answers "done".
struct ScriptedProvider {
    calls: Vec<(String, String)>,
}
impl Provider for ScriptedProvider {
    fn id(&self) -> &str {
        "agent"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, prompt: &str) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(16);
        let done = prompt.contains("[tool");
        let calls = self.calls.clone();
        tokio::spawn(async move {
            if done {
                let _ = tx.send(Event::TextDelta("done".into())).await;
            } else {
                for (i, (name, args)) in calls.into_iter().enumerate() {
                    let _ = tx
                        .send(Event::ToolCallStart {
                            id: format!("c{i}"),
                            name,
                            args,
                        })
                        .await;
                }
            }
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

#[derive(Clone, Default)]
struct SharedAudit(Arc<Mutex<Vec<String>>>);
impl AuditSink for SharedAudit {
    fn record(&self, rec: AuditRecord) {
        self.0.lock().unwrap().push(rec.summary);
    }
}

struct Harness {
    engine: Engine,
    executed: Arc<Mutex<Vec<String>>>,
    audit: SharedAudit,
}

fn call(tool: &str, args: &str) -> (String, String) {
    (tool.to_string(), args.to_string())
}

fn build(calls: Vec<(String, String)>) -> Harness {
    let executed = Arc::new(Mutex::new(Vec::new()));
    let audit = SharedAudit::default();
    let mut router = ModelRouter::new();
    router.register(Box::new(ScriptedProvider { calls }));
    let mut tools = ToolRuntime::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler));
    tools.register(Box::new(RecordingTool {
        name: "transfer",
        effect: EffectClass::SideEffecting,
        risk: RiskTier::Low,
        has_resource: true,
        executed: executed.clone(),
    }));
    tools.register(Box::new(RecordingTool {
        name: "lookup",
        effect: EffectClass::Pure,
        risk: RiskTier::Low,
        has_resource: false,
        executed: executed.clone(),
    }));
    tools.register(Box::new(RecordingTool {
        name: "wire",
        effect: EffectClass::SideEffecting,
        risk: RiskTier::High,
        has_resource: true,
        executed: executed.clone(),
    }));
    let engine = Engine::new(
        Box::new(RedactAndProceed),
        Box::new(RbacAuthorizer),
        Box::new(audit.clone()),
        router,
    )
    .with_tools(tools);
    Harness {
        engine,
        executed,
        audit,
    }
}

fn req() -> Request {
    Request::chat("s", "t", "go", DataClass::Public)
}
fn executed(h: &Harness) -> Vec<String> {
    h.executed.lock().unwrap().clone()
}
fn audited(h: &Harness) -> Vec<String> {
    h.audit.0.lock().unwrap().clone()
}

#[tokio::test]
async fn unauthorized_tool_is_refused_never_dispatched_and_audited() {
    let h = build(vec![call("transfer", "acct-1")]);
    let principal = Principal::user("u", &["chat.send"]); // no tool.transfer
    let out = h.engine.run_turn_collect(&principal, &req()).await.unwrap();

    assert!(
        executed(&h).is_empty(),
        "an unauthorized tool must NEVER dispatch"
    );
    assert!(out
        .events
        .iter()
        .any(|e| matches!(e, Event::ToolResult { output, .. } if output.contains("unauthorized"))));
    assert!(
        audited(&h).iter().any(|s| s.contains("tool authz denied")),
        "a refusal must be audited"
    );
    // The model receives the denial and can still finish the turn.
    assert_eq!(
        out.final_text, "done",
        "the turn continues after a fail-closed refusal"
    );
}

#[tokio::test]
async fn broad_capability_authorizes_any_resource() {
    let h = build(vec![call("transfer", "acct-9")]);
    let principal = Principal::user("u", &["chat.send", "tool.transfer"]);
    let _ = h.engine.run_turn_collect(&principal, &req()).await.unwrap();
    assert_eq!(executed(&h), vec!["transfer:acct-9"]);
}

#[tokio::test]
async fn scoped_capability_authorizes_only_the_matching_resource() {
    let allow = build(vec![call("transfer", "acct-1")]);
    let p = Principal::user("u", &["chat.send", "tool.transfer:acct-1"]);
    let _ = allow.engine.run_turn_collect(&p, &req()).await.unwrap();
    assert_eq!(executed(&allow), vec!["transfer:acct-1"]);

    let deny = build(vec![call("transfer", "acct-2")]);
    let out = deny.engine.run_turn_collect(&p, &req()).await.unwrap();
    assert!(
        executed(&deny).is_empty(),
        "a scoped grant must not authorize a different resource"
    );
    // The denial does NOT leak the (possibly sensitive) resource value.
    assert!(out
        .events
        .iter()
        .any(|e| matches!(e, Event::ToolResult { output, .. } if output.contains("unauthorized"))));
    assert!(
        !audited(&deny).iter().any(|s| s.contains("acct-2")),
        "the resource value must not leak into audit"
    );
}

#[tokio::test]
async fn numeric_account_resources_are_scoped_correctly_despite_pan_redaction() {
    // A 16-digit account (PAN-length) must still be authorized/denied per-resource — the decision
    // uses the RAW args, not the redacted token. Regression for the compliance-redaction bug.
    let own = "4111111111111111";
    let other = "4222222222222222";
    let p = Principal::user("u", &["chat.send", &format!("tool.transfer:{own}")]);

    let allow = build(vec![call("transfer", own)]);
    let _ = allow.engine.run_turn_collect(&p, &req()).await.unwrap();
    assert_eq!(
        executed(&allow),
        vec![format!("transfer:{own}")],
        "owner's numeric account authorizes"
    );

    let deny = build(vec![call("transfer", other)]);
    let _ = deny.engine.run_turn_collect(&p, &req()).await.unwrap();
    assert!(
        executed(&deny).is_empty(),
        "a different numeric account must be denied"
    );
    assert!(
        !audited(&deny).iter().any(|s| s.contains(other)),
        "raw account must not leak into audit"
    );
}

#[tokio::test]
async fn distinct_numeric_accounts_each_execute_once_no_dedup_collapse() {
    // Two different PAN-length accounts in one turn, broad grant: BOTH must execute (the
    // idempotency key must derive from raw args, not the shared redaction token).
    let a = "4111111111111111";
    let b = "4222222222222222";
    let h = build(vec![call("transfer", a), call("transfer", b)]);
    let p = Principal::user("u", &["chat.send", "tool.transfer"]);
    let _ = h.engine.run_turn_collect(&p, &req()).await.unwrap();
    assert_eq!(
        executed(&h),
        vec![format!("transfer:{a}"), format!("transfer:{b}")],
        "distinct numeric accounts must not collapse to one idempotency key"
    );
}

#[tokio::test]
async fn a_pure_resource_less_tool_also_requires_its_capability() {
    // authz applies to Pure tools too (via the resource-less `tool.<name>` branch).
    let deny = build(vec![call("lookup", "q")]);
    let p_no = Principal::user("u", &["chat.send"]);
    let _ = deny.engine.run_turn_collect(&p_no, &req()).await.unwrap();
    assert!(
        executed(&deny).is_empty(),
        "even a Pure tool needs its capability"
    );

    let allow = build(vec![call("lookup", "q")]);
    let p_yes = Principal::user("u", &["chat.send", "tool.lookup"]);
    let _ = allow.engine.run_turn_collect(&p_yes, &req()).await.unwrap();
    assert_eq!(executed(&allow), vec!["lookup:q"]);
}

#[tokio::test]
async fn per_call_isolation_one_authorized_one_denied_in_a_round() {
    // Scoped to acct-1 only; a round asks to transfer acct-1 (allowed) AND acct-2 (denied).
    let h = build(vec![call("transfer", "acct-1"), call("transfer", "acct-2")]);
    let p = Principal::user("u", &["chat.send", "tool.transfer:acct-1"]);
    let _ = h.engine.run_turn_collect(&p, &req()).await.unwrap();
    assert_eq!(
        executed(&h),
        vec!["transfer:acct-1"],
        "only the authorized call runs; the other is refused"
    );
}

#[tokio::test]
async fn authz_precedes_the_approval_gate() {
    // `wire` is High-risk AND the user lacks `tool.wire`; there is NO approval gate configured.
    // If approval ran first, a high-risk tool with no gate is fail-closed as "denied: no approval
    // gate...". Because AUTHZ runs FIRST, the refusal is "unauthorized" instead — proving order.
    let h = build(vec![call("wire", "acct-1")]);
    let p = Principal::user("u", &["chat.send"]); // no tool.wire
    let out = h.engine.run_turn_collect(&p, &req()).await.unwrap();
    assert!(executed(&h).is_empty());
    let tool_result = out.events.iter().find_map(|e| match e {
        Event::ToolResult { output, .. } => Some(output.clone()),
        _ => None,
    });
    let tr = tool_result.expect("a ToolResult was emitted");
    assert!(
        tr.contains("unauthorized"),
        "authz must refuse before the approval gate: {tr}"
    );
    assert!(
        !tr.contains("approval gate"),
        "the approval-gate refusal must not be what fires first"
    );
}

#[tokio::test]
async fn admin_is_authorized_for_any_tool() {
    let h = build(vec![call("transfer", "acct-1")]);
    let admin = Principal::admin("root");
    let _ = h.engine.run_turn_collect(&admin, &req()).await.unwrap();
    assert_eq!(
        executed(&h),
        vec!["transfer:acct-1"],
        "admin carries broad authority by design"
    );
}

#[tokio::test]
async fn authorization_follows_the_specific_principal() {
    let denied = build(vec![call("transfer", "acct-1")]);
    let _ = denied
        .engine
        .run_turn_collect(&Principal::user("alice", &["chat.send"]), &req())
        .await
        .unwrap();
    assert!(executed(&denied).is_empty(), "alice is not authorized");

    let allowed = build(vec![call("transfer", "acct-1")]);
    let _ = allowed
        .engine
        .run_turn_collect(
            &Principal::user("bob", &["chat.send", "tool.transfer"]),
            &req(),
        )
        .await
        .unwrap();
    assert_eq!(
        executed(&allowed),
        vec!["transfer:acct-1"],
        "bob is, on his own authority"
    );
}
