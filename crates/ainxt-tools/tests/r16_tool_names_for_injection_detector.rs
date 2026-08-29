// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R16 gap closure — subsystem `guardrails-injection`: `ToolRuntime` had no way to hand its
//! registered capability names to anything, so `ainxt_injection::InjectionDetector::with_tools`
//! (the "an external document should never reference your private tool registry" strong signal,
//! ADR-009) was UNREACHABLE from the served registry — `ToolRuntime::tool_names()` closes that.
//!
//! Composed with `ainxt-chat/tests/r16_rag_scanner_known_tool_names_wired.rs` (the full served-path
//! proof) and `ainxt-injection/tests/detect_test.rs::known_tool_name_in_untrusted_content_is_strong`
//! (the detector-level proof); this test is the missing middle link: the registry → name list.

use ainxt_tools::{EffectClass, InMemoryLedger, ManualReconciler, Tool, ToolError, ToolRuntime};

struct Noop(&'static str);
impl Tool for Noop {
    fn name(&self) -> &str {
        self.0
    }
    fn effect_class(&self) -> EffectClass {
        EffectClass::Pure
    }
    fn execute(&self, args: &str) -> Result<String, ToolError> {
        Ok(args.to_string())
    }
}

#[test]
fn r16_tool_names_reflects_every_registered_tool() {
    let mut rt = ToolRuntime::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler));
    assert!(
        rt.tool_names().is_empty(),
        "an empty registry must report no names"
    );

    rt.register(Box::new(Noop("query_ledger")));
    rt.register(Box::new(Noop("ledger_transfer")));

    let mut names = rt.tool_names();
    names.sort();
    assert_eq!(
        names,
        vec!["ledger_transfer".to_string(), "query_ledger".to_string()],
        "tool_names() must reflect every registered tool, so a detector built from it (\
         ainxt_injection::InjectionDetector::with_tools) genuinely knows the served registry"
    );
}
