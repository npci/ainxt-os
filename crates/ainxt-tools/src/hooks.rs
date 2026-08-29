// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Pre/post hooks for the Tool Runtime — deterministic guardrails around a call.
//!
//! The reference architecture draws the Tool-Calling Layer with four boxes: Tools,
//! a Permission Checker, an Injection Scan, and **Pre/Post Hooks (deterministic
//! guardrails)**. This crate already implements the first three — per-call OBO
//! authorisation lives in [`crate::CapabilityRegistry`]'s `dispatch_obo` path,
//! which authorises, records the decision BEFORE acting, and refuses with no
//! ambient fallback. Hooks were the one box with nothing behind it.
//!
//! # Why hooks are not just "more policy"
//!
//! Authorisation answers *may this actor call this tool*. A hook answers a
//! different question: *is this specific call, with these arguments, returning this
//! content, acceptable*. Two concrete cases the design calls for:
//!
//! * a `regulator_site_fetch` capability whose post-hook **verifies the returned
//!   PDF's hash** matches the regulator's published version — a mismatch must
//!   REFUSE, because returning unverified content is the whole thing the check
//!   exists to prevent;
//! * a connector post-hook that **redacts customer identifiers** before the result
//!   re-enters a model's context.
//!
//! Neither is expressible as an allow/deny on the actor.
//!
//! # Deliberate design choices
//!
//! * **Hooks refuse by returning `Err`.** A guardrail that only logs is decoration:
//!   the caller proceeds with the unverified value anyway.
//! * **Pre-hooks may rewrite arguments; post-hooks may rewrite output.** Redaction
//!   is a rewrite, not a veto, and forcing it to be a veto would mean dropping
//!   otherwise-good results.
//! * **Ordering is fixed and documented** (below), because a redactor running
//!   before a hash check would verify the hash of already-modified content and
//!   always fail.
//! * **No I/O, no async, no allocation of a runtime.** Hooks run inside the
//!   dispatch path; anything that can block belongs in the capability itself.
//!
//! This mirrors the gateway's `services/tool_hooks.py`. The two are intentionally
//! kept semantically identical: per ADR-031 the gateway is the authoritative
//! authorizer and the runtime sits behind it on loopback, so this layer is
//! defence-in-depth. Where they could disagree, the gateway wins — it is the one
//! users actually reach.

use std::collections::BTreeMap;
use std::sync::Arc;

/// Why a hook refused a call. Carried back to the caller as a `Blocked` dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookRefusal {
    pub tool: String,
    pub hook: String,
    pub reason: String,
}

impl HookRefusal {
    pub fn new(
        tool: impl Into<String>,
        hook: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            tool: tool.into(),
            hook: hook.into(),
            reason: reason.into(),
        }
    }
}

impl std::fmt::Display for HookRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} refused by {}: {}", self.tool, self.hook, self.reason)
    }
}

/// Runs before a capability executes. May rewrite the arguments or refuse.
pub trait PreHook: Send + Sync {
    /// Stable name, used in refusal messages and audit records.
    fn name(&self) -> &str;
    /// Return the arguments to actually dispatch with, or refuse.
    fn before(&self, tool: &str, args: &str, actor: Option<&str>) -> Result<String, HookRefusal>;
}

/// Runs after a capability executes. May rewrite the output or refuse it.
pub trait PostHook: Send + Sync {
    fn name(&self) -> &str;
    fn after(&self, tool: &str, output: &str, actor: Option<&str>) -> Result<String, HookRefusal>;
}

/// Registry of hooks, keyed by capability name plus a global set.
///
/// Global hooks apply to every capability. Only put something here if it is
/// correct for a tool you have never seen — output redaction qualifies; a hook
/// that refuses calls does not, because a blanket refuser silently disables the
/// whole tool runtime.
#[derive(Default, Clone)]
pub struct HookRegistry {
    global_pre: Vec<Arc<dyn PreHook>>,
    global_post: Vec<Arc<dyn PostHook>>,
    per_tool_pre: BTreeMap<String, Vec<Arc<dyn PreHook>>>,
    per_tool_post: BTreeMap<String, Vec<Arc<dyn PostHook>>>,
}

impl std::fmt::Debug for HookRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HookRegistry")
            .field("global_pre", &self.global_pre.len())
            .field("global_post", &self.global_post.len())
            .field("tools_with_pre", &self.per_tool_pre.len())
            .field("tools_with_post", &self.per_tool_post.len())
            .finish()
    }
}

impl HookRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_global_pre(&mut self, hook: Arc<dyn PreHook>) -> &mut Self {
        self.global_pre.push(hook);
        self
    }

    pub fn add_global_post(&mut self, hook: Arc<dyn PostHook>) -> &mut Self {
        self.global_post.push(hook);
        self
    }

    pub fn add_pre(&mut self, tool: impl Into<String>, hook: Arc<dyn PreHook>) -> &mut Self {
        self.per_tool_pre.entry(tool.into()).or_default().push(hook);
        self
    }

    pub fn add_post(&mut self, tool: impl Into<String>, hook: Arc<dyn PostHook>) -> &mut Self {
        self.per_tool_post
            .entry(tool.into())
            .or_default()
            .push(hook);
        self
    }

    /// Global pre-hooks, then tool-specific.
    ///
    /// Global first so a platform-wide argument check cannot be bypassed by a
    /// tool-specific hook rewriting the arguments past it.
    pub fn run_pre(
        &self,
        tool: &str,
        args: &str,
        actor: Option<&str>,
    ) -> Result<String, HookRefusal> {
        let mut current = args.to_string();
        for hook in self.global_pre.iter() {
            current = hook.before(tool, &current, actor)?;
        }
        if let Some(hooks) = self.per_tool_pre.get(tool) {
            for hook in hooks {
                current = hook.before(tool, &current, actor)?;
            }
        }
        Ok(current)
    }

    /// Tool-specific post-hooks, then global.
    ///
    /// Reversed relative to `run_pre`, and that asymmetry is deliberate: a targeted
    /// transform (verify this PDF's hash) must see the RAW output, while a blanket
    /// transform (redact identifiers) should run last so nothing escapes it. Run a
    /// redactor first and the hash check verifies modified bytes and always fails.
    pub fn run_post(
        &self,
        tool: &str,
        output: &str,
        actor: Option<&str>,
    ) -> Result<String, HookRefusal> {
        let mut current = output.to_string();
        if let Some(hooks) = self.per_tool_post.get(tool) {
            for hook in hooks {
                current = hook.after(tool, &current, actor)?;
            }
        }
        for hook in self.global_post.iter() {
            current = hook.after(tool, &current, actor)?;
        }
        Ok(current)
    }

    pub fn counts(&self) -> (usize, usize, usize, usize) {
        (
            self.global_pre.len(),
            self.global_post.len(),
            self.per_tool_pre.values().map(|v| v.len()).sum(),
            self.per_tool_post.values().map(|v| v.len()).sum(),
        )
    }
}

// ── Built-in hooks ───────────────────────────────────────────────────────────

/// Refuses output whose SHA-256 does not match an expected digest.
///
/// The worked example from the design: a regulator-document fetch must prove the
/// bytes match the published version. Refuses rather than warns — a caller handed
/// unverified content would use it.
pub struct HashVerifyHook {
    expected_hex: String,
}

impl HashVerifyHook {
    pub fn new(expected_hex: impl Into<String>) -> Self {
        Self {
            expected_hex: expected_hex.into().to_lowercase(),
        }
    }

    /// Hex SHA-256, computed with the crate's existing `sha2` dependency.
    fn digest(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(bytes);
        h.finalize().iter().map(|b| format!("{b:02x}")).collect()
    }
}

impl PostHook for HashVerifyHook {
    fn name(&self) -> &str {
        "hash-verify"
    }

    fn after(&self, tool: &str, output: &str, _actor: Option<&str>) -> Result<String, HookRefusal> {
        let got = Self::digest(output.as_bytes());
        if got != self.expected_hex {
            return Err(HookRefusal::new(
                tool,
                self.name(),
                format!(
                    "content hash mismatch — expected {}…, got {}…; refusing to return \
                     unverified content",
                    self.expected_hex.chars().take(16).collect::<String>(),
                    got.chars().take(16).collect::<String>()
                ),
            ));
        }
        Ok(output.to_string())
    }
}

/// Refuses a call whose arguments contain any forbidden substring.
///
/// Substring matching, not regex, on purpose: this runs inside dispatch, and a
/// caller-supplied pattern is a ReDoS surface. The compliance and injection crates
/// are where pattern-based detection belongs.
pub struct DenyArgsHook {
    needles: Vec<String>,
    why: String,
}

impl DenyArgsHook {
    pub fn new(needles: Vec<String>, why: impl Into<String>) -> Self {
        Self {
            needles: needles.into_iter().map(|n| n.to_lowercase()).collect(),
            why: why.into(),
        }
    }
}

impl PreHook for DenyArgsHook {
    fn name(&self) -> &str {
        "deny-args"
    }

    fn before(&self, tool: &str, args: &str, _actor: Option<&str>) -> Result<String, HookRefusal> {
        let low = args.to_lowercase();
        for needle in &self.needles {
            if low.contains(needle.as_str()) {
                return Err(HookRefusal::new(
                    tool,
                    self.name(),
                    format!("arguments contain a forbidden term ({})", self.why),
                ));
            }
        }
        Ok(args.to_string())
    }
}

/// Truncates oversized output.
///
/// Rewrites rather than refuses: an over-long result is usually still useful, and
/// dropping it entirely would be a worse outcome than trimming it. The marker makes
/// the truncation visible so a reader is never silently shown a partial answer.
pub struct TruncateOutputHook {
    max_chars: usize,
}

impl TruncateOutputHook {
    pub fn new(max_chars: usize) -> Self {
        Self { max_chars }
    }
}

impl PostHook for TruncateOutputHook {
    fn name(&self) -> &str {
        "truncate-output"
    }

    fn after(
        &self,
        _tool: &str,
        output: &str,
        _actor: Option<&str>,
    ) -> Result<String, HookRefusal> {
        if output.chars().count() <= self.max_chars {
            return Ok(output.to_string());
        }
        let kept: String = output.chars().take(self.max_chars).collect();
        Ok(format!("{kept}… [truncated by tool hook]"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct UppercaseArgs;
    impl PreHook for UppercaseArgs {
        fn name(&self) -> &str {
            "uppercase"
        }
        fn before(&self, _t: &str, args: &str, _a: Option<&str>) -> Result<String, HookRefusal> {
            Ok(args.to_uppercase())
        }
    }

    struct TagOutput(&'static str);
    impl PostHook for TagOutput {
        fn name(&self) -> &str {
            "tag"
        }
        fn after(&self, _t: &str, out: &str, _a: Option<&str>) -> Result<String, HookRefusal> {
            Ok(format!("{out}|{}", self.0))
        }
    }

    #[test]
    fn empty_registry_is_a_passthrough() {
        let r = HookRegistry::new();
        assert_eq!(r.run_pre("t", "args", None).unwrap(), "args");
        assert_eq!(r.run_post("t", "out", None).unwrap(), "out");
    }

    #[test]
    fn pre_hooks_rewrite_arguments() {
        let mut r = HookRegistry::new();
        r.add_pre("t", Arc::new(UppercaseArgs));
        assert_eq!(r.run_pre("t", "hello", None).unwrap(), "HELLO");
        // A hook registered for one tool must not affect another.
        assert_eq!(r.run_pre("other", "hello", None).unwrap(), "hello");
    }

    #[test]
    fn post_order_is_tool_specific_then_global() {
        // The asymmetry matters: a targeted hook must see the RAW output.
        let mut r = HookRegistry::new();
        r.add_post("t", Arc::new(TagOutput("specific")));
        r.add_global_post(Arc::new(TagOutput("global")));
        assert_eq!(r.run_post("t", "x", None).unwrap(), "x|specific|global");
    }

    #[test]
    fn pre_order_is_global_then_tool_specific() {
        let mut r = HookRegistry::new();
        r.add_global_pre(Arc::new(UppercaseArgs));
        r.add_pre("t", Arc::new(UppercaseArgs));
        assert_eq!(r.run_pre("t", "ab", None).unwrap(), "AB");
    }

    #[test]
    fn hash_verify_accepts_matching_content() {
        let expected = HashVerifyHook::digest(b"the regulator pdf");
        let hook = HashVerifyHook::new(expected);
        assert_eq!(
            hook.after("regulator_site_fetch", "the regulator pdf", None)
                .unwrap(),
            "the regulator pdf"
        );
    }

    #[test]
    fn hash_verify_refuses_tampered_content() {
        let hook = HashVerifyHook::new(HashVerifyHook::digest(b"original"));
        let err = hook
            .after("regulator_site_fetch", "tampered", None)
            .unwrap_err();
        assert_eq!(err.hook, "hash-verify");
        assert!(err.reason.contains("hash mismatch"), "{}", err.reason);
        // Refusal, not a warning — the caller gets nothing rather than bad bytes.
    }

    #[test]
    fn a_refusing_hook_stops_the_chain() {
        let mut r = HookRegistry::new();
        r.add_post("t", Arc::new(HashVerifyHook::new("deadbeef")));
        r.add_global_post(Arc::new(TagOutput("should-not-run")));
        let err = r.run_post("t", "anything", None).unwrap_err();
        assert!(!err.reason.contains("should-not-run"));
    }

    #[test]
    fn deny_args_refuses_forbidden_terms() {
        let hook = DenyArgsHook::new(vec!["DROP TABLE".into()], "destructive SQL");
        assert!(hook.before("q", "select 1", None).is_ok());
        let err = hook.before("q", "drop table users", None).unwrap_err();
        assert!(err.reason.contains("destructive SQL"), "{}", err.reason);
    }

    #[test]
    fn truncate_rewrites_rather_than_refusing() {
        let hook = TruncateOutputHook::new(5);
        let out = hook.after("t", "abcdefghij", None).unwrap();
        assert!(out.starts_with("abcde"));
        assert!(
            out.contains("truncated"),
            "truncation must be visible: {out}"
        );
        // Under the limit is untouched.
        assert_eq!(hook.after("t", "abc", None).unwrap(), "abc");
    }

    #[test]
    fn truncate_is_char_safe_on_multibyte() {
        // Byte-slicing here would panic mid-codepoint.
        let hook = TruncateOutputHook::new(2);
        let out = hook.after("t", "पेमेंट", None).unwrap();
        assert!(out.contains("truncated"));
    }

    #[test]
    fn counts_report_what_is_registered() {
        let mut r = HookRegistry::new();
        r.add_global_pre(Arc::new(UppercaseArgs));
        r.add_post("t", Arc::new(TagOutput("x")));
        assert_eq!(r.counts(), (1, 0, 0, 1));
    }
}
