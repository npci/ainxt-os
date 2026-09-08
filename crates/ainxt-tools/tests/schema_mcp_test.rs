// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Tool schema + arg validation + the manifest, and the MCP-as-native adapter (ADR-002).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use ainxt_tools::mcp::{McpTool, McpTransport};
use ainxt_tools::{
    validate_args, EffectClass, Field, FieldType, InMemoryLedger, ManualReconciler, ParamSpec,
    Tool, ToolError, ToolRuntime, ToolSchema,
};

// ---- arg validation ----

fn object_spec() -> ParamSpec {
    ParamSpec::Object {
        fields: vec![
            Field::required("account", FieldType::String),
            Field::required("amount", FieldType::Integer),
            Field::optional("memo", FieldType::String),
        ],
        additional: false,
    }
}

#[test]
fn text_spec_accepts_anything() {
    assert!(validate_args(&ParamSpec::Text, "literally anything {[(").is_ok());
}

#[test]
fn object_spec_accepts_a_well_formed_object() {
    assert!(validate_args(&object_spec(), r#"{"account":"a1","amount":100}"#).is_ok());
    assert!(validate_args(
        &object_spec(),
        r#"{"account":"a1","amount":100,"memo":"rent"}"#
    )
    .is_ok());
}

#[test]
fn object_spec_rejects_malformed_and_invalid_args() {
    // Not JSON at all (the classic malformed/partial tool-call).
    assert!(validate_args(&object_spec(), r#"{"account":"a1", "amount":"#).is_err());
    // Missing a required field.
    assert!(validate_args(&object_spec(), r#"{"account":"a1"}"#)
        .unwrap_err()
        .contains("amount"));
    // Wrong type.
    assert!(
        validate_args(&object_spec(), r#"{"account":"a1","amount":"lots"}"#)
            .unwrap_err()
            .contains("amount")
    );
    // Unexpected field (additional=false).
    assert!(
        validate_args(&object_spec(), r#"{"account":"a1","amount":1,"x":true}"#)
            .unwrap_err()
            .contains("x")
    );
    // Not an object.
    assert!(validate_args(&object_spec(), r#"[1,2,3]"#).is_err());
}

#[test]
fn explicit_null_is_treated_as_absent() {
    // A common LLM shape: optional param sent as explicit null → accepted (treated absent).
    assert!(validate_args(&object_spec(), r#"{"account":"a1","amount":1,"memo":null}"#).is_ok());
    // A required field sent as null → reported as missing (not "wrong type").
    let err = validate_args(&object_spec(), r#"{"account":null,"amount":1}"#).unwrap_err();
    assert!(
        err.contains("missing required field 'account'"),
        "null required field must read as missing: {err}"
    );
}

// ---- a structured native tool + the manifest ----

struct PayTool;
impl Tool for PayTool {
    fn name(&self) -> &str {
        "pay"
    }
    fn effect_class(&self) -> EffectClass {
        EffectClass::SideEffecting
    }
    fn idempotency_key(&self, args: &str) -> Option<String> {
        Some(args.to_string())
    }
    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "pay".into(),
            description: "Pay an account".into(),
            parameters: object_spec(),
        }
    }
    fn execute(&self, args: &str) -> Result<String, ToolError> {
        Ok(format!("paid:{args}"))
    }
}

fn runtime() -> ToolRuntime {
    ToolRuntime::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler))
}

#[test]
fn runtime_validates_against_the_registered_tools_schema() {
    let mut rt = runtime();
    rt.register(Box::new(PayTool));
    assert!(rt.validate("pay", r#"{"account":"a","amount":5}"#).is_ok());
    assert!(
        rt.validate("pay", r#"{"account":"a"}"#).is_err(),
        "missing required field is rejected"
    );
    // Unknown tool: validation defers (dispatch surfaces the unknown-tool error).
    assert!(rt.validate("nope", "{}").is_ok());
}

#[test]
fn manifest_lists_every_tool_schema() {
    let mut rt = runtime();
    rt.register(Box::new(PayTool));
    let schemas = rt.schemas();
    let pay = schemas
        .iter()
        .find(|s| s.name == "pay")
        .expect("pay in manifest");
    assert_eq!(pay.description, "Pay an account");
    assert!(matches!(pay.parameters, ParamSpec::Object { .. }));
}

// ---- MCP-as-native adapter ----

struct MockMcp {
    calls: Arc<AtomicUsize>,
}
impl McpTransport for MockMcp {
    fn list(&self) -> Vec<ToolSchema> {
        vec![ToolSchema {
            name: "remote_search".into(),
            description: "search a remote KB".into(),
            parameters: ParamSpec::Text,
        }]
    }
    fn call(&self, tool: &str, args: &str) -> Result<String, ToolError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(format!("mcp:{tool}:{args}"))
    }
}

#[test]
fn an_mcp_tool_is_registered_and_dispatched_like_a_native_tool() {
    let calls = Arc::new(AtomicUsize::new(0));
    let transport = Arc::new(MockMcp {
        calls: calls.clone(),
    });
    let schema = transport.list().into_iter().next().unwrap();

    let mut rt = runtime();
    // Default MCP effect = SideEffecting (conservative) → exactly-once via the ledger.
    rt.register(Box::new(McpTool::new(transport.clone(), schema)));

    // Appears in the manifest identically to a native tool.
    assert!(rt.schemas().iter().any(|s| s.name == "remote_search"));
    // Classified conservatively: side-effecting + egress (gated + ledgered).
    assert_eq!(rt.is_side_effecting("remote_search"), Some(true));
    assert_eq!(rt.egress_of("remote_search"), Some(true));

    // Dispatched through the SAME pipeline; the ledger dedups a retry (exactly-once).
    use ainxt_tools::DispatchResult;
    let r1 = rt.dispatch("remote_search", "q");
    assert!(matches!(r1, DispatchResult::Ok(ref s) if s == "mcp:remote_search:q"));
    let r2 = rt.dispatch("remote_search", "q");
    assert!(
        matches!(r2, DispatchResult::Deduped(_)),
        "a retried MCP side-effect is deduped, not re-called"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the remote MCP tool executed exactly once"
    );
}

#[test]
fn mcp_idempotency_key_is_canonical_across_arg_reordering() {
    // A lost-ack retry that reorders JSON keys / reformats whitespace is the SAME logical call and
    // must be deduped — not executed a second time (no double debit, ADR-013).
    let calls = Arc::new(AtomicUsize::new(0));
    let transport = Arc::new(MockMcp {
        calls: calls.clone(),
    });
    let schema = ToolSchema {
        name: "pay".into(),
        description: "".into(),
        parameters: ParamSpec::Text,
    };
    let mut rt = runtime();
    rt.register(Box::new(McpTool::new(transport, schema))); // SideEffecting by default → ledgered

    use ainxt_tools::DispatchResult;
    let r1 = rt.dispatch("pay", r#"{"account":"A","amount":100}"#);
    assert!(matches!(r1, DispatchResult::Ok(_)));
    // Reordered keys + extra whitespace = the same logical call.
    let r2 = rt.dispatch("pay", r#"{ "amount":100 ,  "account":"A" }"#);
    assert!(
        matches!(r2, DispatchResult::Deduped(_)),
        "a reordered retry must dedup, not re-execute"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "exactly one remote execution across reordered retries"
    );
}

#[test]
fn an_mcp_tool_is_high_risk_by_default_and_risk_is_configurable() {
    let transport = Arc::new(MockMcp {
        calls: Arc::new(AtomicUsize::new(0)),
    });
    let schema = ToolSchema {
        name: "remote_pay".into(),
        description: "".into(),
        parameters: ParamSpec::Text,
    };
    let mut rt = runtime();
    // Default: an opaque remote side-effecting tool is High-risk (approval gate must clear it).
    rt.register(Box::new(McpTool::new(transport.clone(), schema.clone())));
    assert_eq!(
        rt.risk_tier("remote_pay"),
        Some(ainxt_tools::RiskTier::High)
    );

    // A trusted read-only remote tool can be relaxed.
    let mut rt2 = runtime();
    rt2.register(Box::new(
        McpTool::new(transport, schema)
            .with_effect(EffectClass::Pure)
            .with_risk_tier(ainxt_tools::RiskTier::Low),
    ));
    assert_eq!(
        rt2.risk_tier("remote_pay"),
        Some(ainxt_tools::RiskTier::Low)
    );
}

#[test]
fn an_mcp_tool_declared_pure_is_not_ledgered() {
    let calls = Arc::new(AtomicUsize::new(0));
    let transport = Arc::new(MockMcp {
        calls: calls.clone(),
    });
    let schema = transport.list().into_iter().next().unwrap();
    let mut rt = runtime();
    rt.register(Box::new(
        McpTool::new(transport, schema).with_effect(EffectClass::Pure),
    ));
    // Pure → runs every time; but STILL egress (so injection gating still applies at the engine).
    let _ = rt.dispatch("remote_search", "q");
    let _ = rt.dispatch("remote_search", "q");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "a pure MCP tool runs every time"
    );
    assert_eq!(rt.egress_of("remote_search"), Some(true));
}
