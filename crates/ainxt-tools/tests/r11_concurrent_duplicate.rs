// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R11 §1.2 scenario 2 — concurrent duplicate retries of the SAME side-effecting action (identical
//! idempotency key, no resource_key) block briefly on the first's in-flight claim and return the same
//! result; the underlying capability is invoked exactly once, never twice in parallel.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use ainxt_tools::{
    canonical_key, DispatchResult, EffectClass, InMemoryLedger, ManualReconciler, RiskTier, Tool,
    ToolError, ToolRuntime,
};

/// A side-effecting tool with NO resource_key (so ONLY the per-key lock can serialize duplicates).
/// Counts invocations and sleeps briefly to widen the concurrency window.
struct CountingSink {
    calls: Arc<AtomicUsize>,
}
impl Tool for CountingSink {
    fn name(&self) -> &str {
        "create_mr"
    }
    fn effect_class(&self) -> EffectClass {
        EffectClass::SideEffecting
    }
    fn risk_tier(&self) -> RiskTier {
        RiskTier::Low
    }
    fn idempotency_key(&self, args: &str) -> Option<String> {
        Some(canonical_key("create_mr", args))
    }
    fn execute(&self, args: &str) -> Result<String, ToolError> {
        // The one real side effect; sleep so a racing duplicate overlaps the in-flight window.
        self.calls.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(std::time::Duration::from_millis(80));
        Ok(format!("mr-for-{args}"))
    }
}

#[test]
fn concurrent_duplicates_execute_exactly_once_and_share_the_result() {
    let calls = Arc::new(AtomicUsize::new(0));
    // Build + register, THEN share across threads.
    let mut owned = ToolRuntime::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler));
    owned.register(Box::new(CountingSink {
        calls: Arc::clone(&calls),
    }));
    let rt = Arc::new(owned);

    let args = r#"{"branch":"feature/x","title":"add"}"#;
    let mut handles = Vec::new();
    for _ in 0..8 {
        let rt = Arc::clone(&rt);
        handles.push(std::thread::spawn(move || rt.dispatch("create_mr", args)));
    }
    let results: Vec<DispatchResult> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    // Exactly ONE real execution despite 8 concurrent identical retries.
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the side effect must fire exactly once under concurrent duplicates"
    );
    // Exactly one Ok; the rest are Deduped with the SAME stored result.
    let oks = results
        .iter()
        .filter(|r| matches!(r, DispatchResult::Ok(_)))
        .count();
    let deduped = results
        .iter()
        .filter(|r| matches!(r, DispatchResult::Deduped(_)))
        .count();
    assert_eq!(oks, 1, "exactly one caller actually ran the effect");
    assert_eq!(
        deduped, 7,
        "every concurrent duplicate returned the stored result"
    );
    for r in &results {
        match r {
            DispatchResult::Ok(s) | DispatchResult::Deduped(s) => {
                assert_eq!(s, "mr-for-{\"branch\":\"feature/x\",\"title\":\"add\"}")
            }
            other => panic!("unexpected {other:?}"),
        }
    }
}
