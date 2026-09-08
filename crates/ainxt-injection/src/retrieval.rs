// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! **Indirect-injection defense for RETRIEVED content** — the served entrypoint (ADR-009, design A).
//!
//! This is the primary agentic attack vector: the user never typed "wire the funds", but a poisoned
//! knowledge-base document / connector email / tool result did, and a naive agent obeys it. Stopping
//! it needs three things to happen on *every* turn that grounds on untrusted content, not just on
//! the turns where someone remembered to install a scanner:
//!
//! 1. **scan** every retrieved chunk with the scored detector ([`crate::InjectionDetector`], or an
//!    ML/NLI [`InjectionModel`](crate::InjectionModel) plugged into the same seam);
//! 2. **fence** the chunk as DATA ([`wrap_untrusted`]) so the model does not read it as instructions;
//! 3. **taint** the turn when a chunk is suspicious, so the runtime's fail-closed tool gate
//!    ([`gate_tool_on_taint_for_turn`]) refuses side-effecting / egress tools for the rest of the turn
//!    and the outbound guard ([`guard_egress_for_turn`]) treats ANY egress finding as blocking.
//!
//! [`RetrievalGuard`] packages all three behind ONE call so a surface cannot accidentally wire up
//! scanning-without-taint, or taint-without-fencing. It is built entirely from
//! [`InjectionDefenseConfig`] — a serde config type — so the detector's threshold, the internal
//! tool-name allow-list and the egress policy are deployment configuration, never hardcoded.
//!
//! `Audit` semantics are honoured on this path: in `Audit` the chunks are still scanned and the
//! findings are still recorded (that is what "detect + record, still proceed" means), only the taint
//! flag is withheld. `Off` short-circuits before any work.

use crate::detect::{InjectionDetector, InjectionModel, MlAugmentedDetector};
use crate::egress::{
    gate_tool_on_taint_for_turn, guard_egress_for_turn, EgressDecision, EgressPolicy,
};
use crate::{
    wrap_untrusted, InjectionConfig, InjectionMode, InjectionScanner, InjectionVerdict, Provenance,
};
use serde::{Deserialize, Serialize};

fn default_true() -> bool {
    true
}
fn default_threshold() -> f32 {
    0.5
}
fn default_directed_weight() -> f32 {
    0.5
}
fn default_descriptive_weight() -> f32 {
    0.25
}

/// The **full** injection-defense configuration: [`InjectionConfig`]'s mode/gate plus everything the
/// detector and the egress guard need. Deserializes from exactly the same table as
/// [`InjectionConfig`] (`mode`, `gate_side_effects_on_taint`) with every new key defaulted, so it is
/// a drop-in replacement for a `RuntimeConfig.injection` field without breaking existing config
/// files — and it is what makes the detector *reachable from configuration*: threshold, internal
/// tool names, ML seam toggle and the whole [`EgressPolicy`] (allow-list included) now come from the
/// config layer instead of a compile-time default.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct InjectionDefenseConfig {
    /// `Off` / `Audit` / `Enforce` — mirrors [`InjectionConfig::mode`].
    pub mode: InjectionMode,
    /// Gate side-effecting / egress tools on a tainted turn.
    #[serde(default = "default_true")]
    pub gate_side_effects_on_taint: bool,
    /// Scan RETRIEVED (RAG / connector) chunks, not only tool results. Default `true` — retrieved
    /// content is the primary indirect-injection vector.
    #[serde(default = "default_true")]
    pub scan_retrieved: bool,
    /// Fence untrusted chunks as DATA before they reach the model. Default `true`.
    #[serde(default = "default_true")]
    pub fence_untrusted: bool,
    /// Detector score at/above which a chunk is `Suspicious`.
    #[serde(default = "default_threshold")]
    pub suspicious_threshold: f32,
    /// Weight of a DIRECTED compositional override (see [`InjectionDetector`]).
    #[serde(default = "default_directed_weight")]
    pub compositional_weight: f32,
    /// Weight of a DESCRIPTIVE compositional co-occurrence (kept sub-threshold so ordinary
    /// payments/legal prose does not taint a turn).
    #[serde(default = "default_descriptive_weight")]
    pub descriptive_weight: f32,
    /// Internal tool names. A retrieved document that names your private tools is a strong signal;
    /// supplying the registry's names here is what activates that signal in production.
    pub known_tool_names: Vec<String>,
    /// Outbound DLP + destination policy for the mirror control (design T).
    pub egress: EgressPolicy,
}

impl Default for InjectionDefenseConfig {
    fn default() -> Self {
        InjectionDefenseConfig {
            mode: InjectionMode::Off,
            gate_side_effects_on_taint: true,
            scan_retrieved: true,
            fence_untrusted: true,
            suspicious_threshold: default_threshold(),
            compositional_weight: default_directed_weight(),
            descriptive_weight: default_descriptive_weight(),
            known_tool_names: Vec::new(),
            egress: EgressPolicy::default(),
        }
    }
}

impl InjectionDefenseConfig {
    /// Widen an existing [`InjectionConfig`] (mode + gate) into the full defense config, leaving the
    /// new knobs at their defaults. This is the compatibility path for a caller that already holds
    /// the narrow config.
    pub fn from_injection(cfg: &InjectionConfig) -> Self {
        InjectionDefenseConfig {
            mode: cfg.mode,
            gate_side_effects_on_taint: cfg.gate_side_effects_on_taint,
            ..Default::default()
        }
    }

    /// Narrow back to [`InjectionConfig`] for call sites that still take the small type.
    pub fn injection_config(&self) -> InjectionConfig {
        InjectionConfig {
            mode: self.mode,
            gate_side_effects_on_taint: self.gate_side_effects_on_taint,
            ..Default::default()
        }
    }

    /// Batteries-included preset: `Enforce`, retrieved-chunk scanning on, fail-closed tool gate,
    /// plus the deployment's egress allow-list.
    pub fn recommended(
        allowed_domains: impl IntoIterator<Item = String>,
        known_tool_names: impl IntoIterator<Item = String>,
    ) -> Self {
        InjectionDefenseConfig {
            mode: InjectionMode::Enforce,
            known_tool_names: known_tool_names.into_iter().collect(),
            egress: EgressPolicy::recommended(allowed_domains),
            ..Default::default()
        }
    }

    pub fn is_off(&self) -> bool {
        self.mode == InjectionMode::Off
    }

    /// The scored detector this config describes.
    pub fn detector(&self) -> InjectionDetector {
        InjectionDetector::default()
            .with_threshold(self.suspicious_threshold)
            .with_compositional_weights(self.compositional_weight, self.descriptive_weight)
            .with_tools(self.known_tool_names.clone())
    }
}

/// One suspicious chunk, recorded for the audit log.
#[derive(Debug, Clone, PartialEq)]
pub struct RetrievalFinding {
    /// Index of the chunk in the supplied slice.
    pub index: usize,
    /// Where the chunk came from.
    pub provenance: Provenance,
    /// One reason per matched detector category.
    pub reasons: Vec<String>,
}

/// The outcome of scanning a turn's retrieved context.
#[derive(Debug, Clone, PartialEq)]
pub struct RetrievalScan {
    /// The mode the scan ran under.
    pub mode: InjectionMode,
    /// At least one chunk was suspicious. Recorded in BOTH `Audit` and `Enforce`.
    pub suspicious: bool,
    /// Whether the TURN is tainted — `Enforce` only (`Audit` = detect + record, still proceed).
    pub tainted: bool,
    /// One entry per suspicious chunk.
    pub findings: Vec<RetrievalFinding>,
}

impl RetrievalScan {
    fn clean(mode: InjectionMode) -> Self {
        RetrievalScan {
            mode,
            suspicious: false,
            tainted: false,
            findings: Vec::new(),
        }
    }
    /// Audit-log lines (`chunk #i (retrieved-document): reason; …`) for every suspicious chunk.
    pub fn audit_records(&self) -> Vec<String> {
        self.findings
            .iter()
            .map(|f| {
                format!(
                    "chunk #{} ({}): {}",
                    f.index,
                    f.provenance.tag_public(),
                    f.reasons.join("; ")
                )
            })
            .collect()
    }
}

/// The served indirect-injection guard: scan → fence → taint, built from configuration.
///
/// Install one per surface (or per engine) and call [`RetrievalGuard::scan_context`] with the turn's
/// retrieved chunks BEFORE the model call; carry [`RetrievalScan::tainted`] into the request so the
/// tool gate and egress guard see it.
///
/// GAP-AUDIT gap6-injection-judge-consolidation (item 1) — `RetrievalGuard` and
/// [`InjectionDefenseConfig`] have ZERO callers in the real composition root (`ainxt-runtimed`) or in
/// any served surface: `grep`-confirmed, the only tree-wide hits outside this file are this crate's
/// own `tests/r16_retrieved_content_indirect_injection_gate.rs` (which exercises `RetrievalGuard` in
/// isolation, never through a served constructor) and a doc-comment mention in
/// `ainxt-chat/tests/r16_served_rag_injection_defense.rs`. That is not an unguarded hole, though: the
/// scan+fence+taint contract this type packages is already implemented, independently, on the actual
/// served path:
///
/// - **scan**: `ChatSurface::assemble_with_prompt` (`ainxt-chat/src/lib.rs`) wires
///   `ConversationManager::with_injection(InjectionConfig::recommended())` (hardcoded `Enforce`) into
///   every served constructor; `ConversationManager::handle`/`handle_streaming`
///   (`ainxt-convo/src/lib.rs`, both the non-streaming and streaming turn paths) scan every retrieved
///   chunk via `self.injection_scanner.scan(t, Provenance::Retrieved)` — the identical
///   [`InjectionScanner`] seam `RetrievalGuard::scan_context` calls — additionally OR'd with
///   `ainxt_prompt::confirm_tool_call`'s literal-imperative-override gate, which `RetrievalGuard`
///   does not have.
/// - **fence**: [`wrap_untrusted`] already runs on the served path independent of this type
///   (`ainxt-context/src/lib.rs`'s context-compile step, and again on tool-result text in
///   `ainxt-runtime/src/lib.rs`).
/// - **taint**: `ConversationManager` sets the REAL `Request.untrusted_tainted` field
///   (`ainxt-protocol`), which `ainxt-runtime`'s `Engine` reads directly to gate every tool dispatch
///   (`gate_tool_on_taint_for_turn`) and every egress-declared tool (`guard_egress_for_turn`) — the
///   IDENTICAL two functions [`RetrievalGuard::gate_tool`]/[`RetrievalGuard::guard_egress`] merely
///   wrap. A poisoned-document taint on the wired path is consumed one level deeper (inside the
///   engine's own dispatch loop, plus a real audit-sink call via `Engine::audit_injection_taint`)
///   than `RetrievalScan::tainted` ever is, since nothing constructs a `RetrievalGuard` in production
///   to read it.
///
/// The one seam `RetrievalGuard` exposes that the wired path does not yet use is
/// [`MlAugmentedDetector`]'s ML/NLI-model-augmented scoring — but that seam is not unique to
/// `RetrievalGuard`: `ConversationManager::with_injection_scanner` / `Engine::with_injection_scanner`
/// already accept any `Box<dyn InjectionScanner>`, and `MlAugmentedDetector` implements that trait, so
/// a deployment can wire ML-augmented detection into the *existing* composition root with zero
/// `RetrievalGuard` involvement. `RetrievalGuard` is genuinely equivalent in strength to the wired
/// path (both implement "scan retrieved content, fence it as data, taint the turn on a hit, gate
/// tools/egress on taint" — the wired path's version is the more deeply-integrated one) —
/// legitimately superseded, unreachable-in-production code kept as a stronger-typed, single-call
/// convenience primitive for a caller of this crate that does NOT route through
/// `ChatSurface`/`ConversationManager`.
pub struct RetrievalGuard {
    cfg: InjectionDefenseConfig,
    scanner: Box<dyn InjectionScanner>,
}

impl RetrievalGuard {
    /// Build from configuration using the deterministic scored detector.
    pub fn from_config(cfg: &InjectionDefenseConfig) -> Self {
        RetrievalGuard {
            cfg: cfg.clone(),
            scanner: Box::new(cfg.detector()),
        }
    }

    /// Build from configuration with an ML/NLI [`InjectionModel`] plugged into the detection seam.
    /// The effective score is `max(heuristic, model)` — the model can only make detection stricter.
    pub fn with_model(cfg: &InjectionDefenseConfig, model: Box<dyn InjectionModel>) -> Self {
        RetrievalGuard {
            cfg: cfg.clone(),
            scanner: Box::new(MlAugmentedDetector::new(cfg.detector(), model)),
        }
    }

    /// Build from configuration with a fully custom scanner (the widest seam).
    pub fn with_scanner(cfg: &InjectionDefenseConfig, scanner: Box<dyn InjectionScanner>) -> Self {
        RetrievalGuard {
            cfg: cfg.clone(),
            scanner,
        }
    }

    pub fn config(&self) -> &InjectionDefenseConfig {
        &self.cfg
    }

    /// Whether this guard does anything at all (`mode != Off` and retrieved-scanning enabled).
    pub fn scans_retrieved(&self) -> bool {
        self.cfg.mode != InjectionMode::Off && self.cfg.scan_retrieved
    }

    /// Scan a turn's untrusted context. `Audit` records findings without tainting; `Enforce` records
    /// AND taints; `Off` returns a clean scan without touching the chunks.
    pub fn scan_context<S: AsRef<str>>(
        &self,
        chunks: &[S],
        provenance: Provenance,
    ) -> RetrievalScan {
        if !self.scans_retrieved() {
            return RetrievalScan::clean(self.cfg.mode);
        }
        let mut findings = Vec::new();
        for (index, chunk) in chunks.iter().enumerate() {
            if let InjectionVerdict::Suspicious(reasons) =
                self.scanner.scan(chunk.as_ref(), provenance)
            {
                findings.push(RetrievalFinding {
                    index,
                    provenance,
                    reasons,
                });
            }
        }
        let suspicious = !findings.is_empty();
        RetrievalScan {
            mode: self.cfg.mode,
            suspicious,
            // Audit = detect + record, still proceed. Only Enforce taints the turn.
            tainted: suspicious && self.cfg.mode == InjectionMode::Enforce,
            findings,
        }
    }

    /// Fence one untrusted chunk as DATA (instruction/data separation). Returns the chunk unchanged
    /// when fencing is disabled or the content is trusted.
    pub fn fence(&self, chunk: &str, provenance: Provenance) -> String {
        if !self.cfg.fence_untrusted || provenance.is_trusted() {
            return chunk.to_string();
        }
        wrap_untrusted(chunk, provenance)
    }

    /// Scan AND fence in one pass — the single call a surface makes on its retrieved context. Returns
    /// the scan plus the model-safe chunk texts, in the same order.
    pub fn guard_context<S: AsRef<str>>(
        &self,
        chunks: &[S],
        provenance: Provenance,
    ) -> (RetrievalScan, Vec<String>) {
        let scan = self.scan_context(chunks, provenance);
        let fenced = chunks
            .iter()
            .map(|c| self.fence(c.as_ref(), provenance))
            .collect();
        (scan, fenced)
    }

    /// Fail-closed tool gate for a turn (`true` = the tool must be blocked). An UNCLASSIFIED tool
    /// (`None`) is gated on a tainted turn. Honours `gate_side_effects_on_taint`.
    pub fn gate_tool(
        &self,
        tainted: bool,
        side_effecting: Option<bool>,
        egress: Option<bool>,
    ) -> bool {
        if !self.cfg.gate_side_effects_on_taint {
            return false;
        }
        gate_tool_on_taint_for_turn(tainted, side_effecting, egress)
    }

    /// Outbound guard for a tool argument / connector payload, using the configured
    /// [`EgressPolicy`]. On a tainted turn ANY finding blocks (the exfiltration half of the chain).
    pub fn guard_egress(&self, payload: &str, tainted: bool) -> EgressDecision {
        guard_egress_for_turn(payload, &self.cfg.egress, tainted)
    }
}

impl Provenance {
    /// Public, stable label for audit records (`"retrieved-document"`, `"tool-result"`, …).
    pub fn tag_public(self) -> &'static str {
        match self {
            Provenance::UserDirect => "user",
            Provenance::Retrieved => "retrieved-document",
            Provenance::ToolResult => "tool-result",
            Provenance::Connector => "connector-data",
        }
    }
}
