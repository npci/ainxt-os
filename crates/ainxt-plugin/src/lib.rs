// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-plugin — programmatic plugin isolation (Phase 5).
//!
//! Plugins are untrusted code. This crate confines them by **capability-based security**: a plugin
//! is handed a [`PluginContext`] that exposes *only* its effective capabilities (`requested ∩
//! granted`) and nothing else. It has **no ambient authority** — it cannot reach a tool, connector,
//! or resource it wasn't granted, because the only door is the context, and the context refuses an
//! ungranted capability. On top of that:
//!
//! - **Output is size-limited** — a plugin cannot flood the caller.
//! - **A trap or panic is isolated** — the host catches it and survives ([`PluginError::Trap`]).
//! - **Memory + time limits are declared** and enforced by the isolating runtime.
//!
//! The isolation *mechanism* is a seam ([`PluginHost`]). [`NativeHost`] enforces the capability +
//! output + panic contract in-process (for tests and trusted first-party plugins). A **WASM/WASI**
//! host — the real sandbox for third-party code, giving hard memory/time isolation via wasmtime — IS
//! wired as `ainxt_wasm::WasmPluginHost`, a real implementation of this same [`PluginHost`] trait (its
//! `Apache-2.0 WITH LLVM-exception` license exception is reviewed and already in `deny.toml`, closing
//! the Gate-#0 legal item this crate's doc used to defer on). `ainxt-wasm` depends on this crate (not
//! the other way around — this crate has no wasm dependency), so the composition the security-boundary
//! tests pin (`GuardedHost<H>` wrapping either host) drops `WasmPluginHost` in unchanged.
//!
//! Clean-room throughout; the capability-confinement contract is original to AiNxt.

use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;
use std::fmt;
use std::panic::AssertUnwindSafe;

use serde::{Deserialize, Serialize};

/// Resource limits for a plugin invocation. `max_output_bytes` is enforced by every host;
/// `max_millis` / `max_memory_bytes` are enforced by the isolating (WASM) host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimits {
    pub max_output_bytes: usize,
    pub max_millis: u64,
    pub max_memory_bytes: usize,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        ResourceLimits {
            max_output_bytes: 64 * 1024,
            max_millis: 5_000,
            max_memory_bytes: 16 * 1024 * 1024,
        }
    }
}

/// What a plugin declares: its id, the capabilities it asks for, and its limits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginManifest {
    pub id: String,
    #[serde(default)]
    pub requested_capabilities: Vec<String>,
    #[serde(default)]
    pub limits: ResourceLimits,
}

/// What governance granted the plugin.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginGrant {
    pub granted: Vec<String>,
}

impl PluginGrant {
    pub fn new<S: Into<String>>(caps: impl IntoIterator<Item = S>) -> Self {
        PluginGrant {
            granted: caps.into_iter().map(Into::into).collect(),
        }
    }
}

/// A plugin failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginError {
    /// The plugin tried to use a capability it wasn't granted (no ambient authority).
    CapabilityDenied(String),
    /// The plugin's output exceeded the size limit.
    OutputTooLarge { limit: usize, actual: usize },
    /// The plugin trapped/panicked/errored — isolated; the host survives.
    Trap(String),
    /// No such plugin is registered.
    NotFound(String),
    /// A plugin asked to invoke a capability that no plugin in the registry EXPOSES (§3.2). Distinct
    /// from [`PluginError::CapabilityDenied`] (which is the caller's own grant failing): here the
    /// caller *was* granted the capability, but there is no provider to route the typed call to. A
    /// hard error, never a silent no-op — a payments platform does not swallow a missing dependency.
    CapabilityUnavailable(String),
    /// The registry-mediated plugin-to-plugin call chain exceeded its bounded depth (§3.2). A cycle
    /// (A calls B calls A) or a runaway fan-out is stopped here as a contained trap rather than
    /// overflowing the host stack — inter-plugin calls can never hang or crash the host.
    CallDepthExceeded { max_depth: usize },
    /// The plugin exceeded its host-enforced wall-clock budget (§3.5). The host stopped waiting and
    /// returned promptly so the calling turn and co-located work are unaffected — a runaway plugin
    /// cannot pin the turn. (A native host cannot *forcibly* terminate the guest thread; hard
    /// CPU/memory kill via wasmtime epoch-interruption is `ainxt_wasm::WasmPluginHost`'s job — see
    /// [`GuardedHost`].)
    WallClockExceeded { limit_millis: u64 },
}

impl fmt::Display for PluginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PluginError::CapabilityDenied(c) => {
                write!(f, "plugin denied capability '{c}' (not granted)")
            }
            PluginError::OutputTooLarge { limit, actual } => {
                write!(f, "plugin output {actual}B exceeds limit {limit}B")
            }
            PluginError::Trap(m) => write!(f, "plugin trapped: {m}"),
            PluginError::NotFound(id) => write!(f, "no plugin '{id}'"),
            PluginError::CapabilityUnavailable(c) => {
                write!(f, "no plugin exposes capability '{c}'")
            }
            PluginError::CallDepthExceeded { max_depth } => {
                write!(f, "plugin-to-plugin call depth exceeded max {max_depth}")
            }
            PluginError::WallClockExceeded { limit_millis } => {
                write!(f, "plugin exceeded its {limit_millis}ms wall-clock budget")
            }
        }
    }
}
impl std::error::Error for PluginError {}

/// The only door a plugin has to the outside world. It exposes exactly the effective capabilities and
/// nothing else — using a capability not in the set is refused, and every use is recorded.
pub struct PluginContext {
    granted: BTreeSet<String>,
    used: RefCell<BTreeSet<String>>,
    pub limits: ResourceLimits,
}

impl PluginContext {
    fn new(granted: BTreeSet<String>, limits: ResourceLimits) -> Self {
        PluginContext {
            granted,
            used: RefCell::new(BTreeSet::new()),
            limits,
        }
    }

    /// A plugin MUST call this before performing an action gated by `capability`. Returns
    /// [`PluginError::CapabilityDenied`] if it is not in the effective set (no ambient authority).
    pub fn use_capability(&self, capability: &str) -> Result<(), PluginError> {
        if self.granted.contains(capability) {
            self.used.borrow_mut().insert(capability.to_string());
            Ok(())
        } else {
            Err(PluginError::CapabilityDenied(capability.to_string()))
        }
    }

    /// Whether a capability is in the effective set (without recording a use).
    pub fn has_capability(&self, capability: &str) -> bool {
        self.granted.contains(capability)
    }

    fn used(&self) -> Vec<String> {
        self.used.borrow().iter().cloned().collect()
    }
}

/// The result of a successful plugin invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginOutput {
    pub output: String,
    /// The capabilities the plugin actually exercised (for audit).
    pub used_capabilities: Vec<String>,
}

/// A plugin's code: input + its confined context → output (or a typed error).
pub type PluginFn = Box<dyn Fn(&str, &PluginContext) -> Result<String, PluginError> + Send + Sync>;

/// The isolation seam. Every host enforces the same contract: effective = `requested ∩ granted`, no
/// ambient authority, output size limit, trap isolation.
pub trait PluginHost {
    fn invoke(
        &self,
        manifest: &PluginManifest,
        grant: &PluginGrant,
        input: &str,
    ) -> Result<PluginOutput, PluginError>;
}

/// In-process host — runs registered Rust plugins under the capability + output + panic contract.
/// (Hard memory/time isolation is the WASM host's job; this host is for tests and trusted plugins.)
#[derive(Default)]
pub struct NativeHost {
    plugins: std::collections::BTreeMap<String, PluginFn>,
}

impl NativeHost {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a plugin implementation under an id.
    pub fn register(&mut self, id: impl Into<String>, plugin: PluginFn) {
        self.plugins.insert(id.into(), plugin);
    }
}

impl PluginHost for NativeHost {
    fn invoke(
        &self,
        manifest: &PluginManifest,
        grant: &PluginGrant,
        input: &str,
    ) -> Result<PluginOutput, PluginError> {
        let plugin = self
            .plugins
            .get(&manifest.id)
            .ok_or_else(|| PluginError::NotFound(manifest.id.clone()))?;

        // Effective authority = requested ∩ granted (least privilege).
        let granted: BTreeSet<&str> = grant.granted.iter().map(String::as_str).collect();
        let effective: BTreeSet<String> = manifest
            .requested_capabilities
            .iter()
            .filter(|c| granted.contains(c.as_str()))
            .cloned()
            .collect();

        let ctx = PluginContext::new(effective, manifest.limits);

        // Isolate a panic — a misbehaving plugin must never take the host down.
        let result = std::panic::catch_unwind(AssertUnwindSafe(|| plugin(input, &ctx)));
        let output = match result {
            Ok(Ok(o)) => o,
            Ok(Err(e)) => return Err(e), // typed plugin error (e.g. CapabilityDenied) propagates
            Err(_) => return Err(PluginError::Trap("plugin panicked".into())),
        };

        if output.len() > manifest.limits.max_output_bytes {
            return Err(PluginError::OutputTooLarge {
                limit: manifest.limits.max_output_bytes,
                actual: output.len(),
            });
        }
        Ok(PluginOutput {
            output,
            used_capabilities: ctx.used(),
        })
    }
}

// ============================ Host-enforced resource limits (§3.5) ============================

/// A [`PluginHost`] decorator that enforces the **wall-clock** limit from the host side, not by the
/// guest's cooperation (§3.5). It runs the wrapped host's invocation on a worker thread and stops
/// waiting once `manifest.limits.max_millis` elapses, returning [`PluginError::WallClockExceeded`]
/// promptly — so a busy-loop or a sleeping plugin can never pin the calling turn or starve
/// co-located work. `max_millis == 0` means "no wall-clock bound" (pass-through).
///
/// Honest scope: a *native* host cannot forcibly terminate the guest thread (Rust has no safe
/// thread-kill), so a runaway thread keeps running detached after we return — it just no longer
/// blocks anyone. Hard CPU-slice and memory-ceiling enforcement that actually *kills* the guest is
/// the wasmtime epoch-interruption / `StoreLimits` job of `ainxt_wasm::WasmPluginHost` (real, wired —
/// only the served-path deployment image is infra-gated); this decorator is the offline, real
/// host-side wall-clock bound that closes the "turn stays responsive" half of §3.5 for `NativeHost`
/// today, and it composes in front of the WASM host unchanged.
///
/// `H` is `?Sized` so a composition root that only ever holds a type-erased
/// `Arc<dyn PluginHost + Send + Sync>` (the shape `ainxt_runtimed::ApprovedPlugin::host` carries,
/// since a single served registry mixes `NativeHost` and `ainxt_wasm::WasmPluginHost` entries behind
/// one trait object) can wrap it via [`GuardedHost::from_arc`] without needing the concrete host
/// type — [`GuardedHost::new`] still requires a `Sized` host, since it takes one by value.
pub struct GuardedHost<H: PluginHost + Send + Sync + ?Sized + 'static> {
    inner: std::sync::Arc<H>,
}

impl<H: PluginHost + Send + Sync + 'static> GuardedHost<H> {
    pub fn new(inner: H) -> Self {
        GuardedHost {
            inner: std::sync::Arc::new(inner),
        }
    }
}

impl<H: PluginHost + Send + Sync + ?Sized + 'static> GuardedHost<H> {
    /// Wrap a host already behind an `Arc` (e.g. shared with the dispatcher, or already type-erased
    /// as `Arc<dyn PluginHost + Send + Sync>`).
    pub fn from_arc(inner: std::sync::Arc<H>) -> Self {
        GuardedHost { inner }
    }
}

impl<H: PluginHost + Send + Sync + ?Sized + 'static> PluginHost for GuardedHost<H> {
    fn invoke(
        &self,
        manifest: &PluginManifest,
        grant: &PluginGrant,
        input: &str,
    ) -> Result<PluginOutput, PluginError> {
        let limit = manifest.limits.max_millis;
        if limit == 0 {
            // No wall-clock bound requested — run inline (still gets the inner host's capability +
            // output + panic contract).
            return self.inner.invoke(manifest, grant, input);
        }
        let inner = std::sync::Arc::clone(&self.inner);
        let m = manifest.clone();
        let g = grant.clone();
        let i = input.to_string();
        let (tx, rx) = std::sync::mpsc::channel();
        // Detached worker: if it overruns, we abandon it (it cannot block us) — the host survives.
        std::thread::spawn(move || {
            let r = inner.invoke(&m, &g, &i);
            let _ = tx.send(r); // receiver may be gone (we timed out) — a harmless no-op then.
        });
        match rx.recv_timeout(std::time::Duration::from_millis(limit)) {
            Ok(r) => r,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                Err(PluginError::WallClockExceeded {
                    limit_millis: limit,
                })
            }
            // The worker dropped the sender without sending — treat as an isolated trap, never a hang.
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(PluginError::Trap(
                "plugin worker terminated without a result".into(),
            )),
        }
    }
}

// ==================== §3.2 Dependency isolation — registry-mediated inter-plugin calls ====================
//
// GAP-AUDIT plugin-sandbox-registry — investigated whether `PluginRegistry`/`CapabilityDispatch`/
// `PeerCall` (below) need to be wired into the served composition root, the same way `GuardedHost`
// (above) was. Verdict: NO — there is no code change here, and here is why.
//
// The served plugin path is `ainxt_tools::plugin_bridge::PluginCapability::execute` →
// `self.host.invoke(&self.manifest, &self.grant, args)`, where `host` is whatever
// `ainxt_runtimed::register_served_plugin_runtime` was handed (`NativeHost` or
// `ainxt_wasm::WasmPluginHost`) — never a `PluginRegistry`. Neither host gives an admitted plugin ANY
// door to reach another plugin:
//   - `NativeHost::invoke` runs the guest's `PluginFn` against a bare [`PluginContext`], which exposes
//     only `use_capability`/`has_capability` (capability bookkeeping) — no method to call anything.
//   - `ainxt_wasm::WasmPluginHost::invoke` links a WASM guest against a FIXED, capability-scoped set
//     of host imports (`fs_read`, `kv_set`, `kv_get` — see `ainxt-wasm`'s §3.1 section); there is no
//     "invoke another plugin's capability" import, so a guest cannot even ask for one.
// A capability request that resolves to another PLUGIN (rather than a native tool or an MCP server)
// is not a thing the served system does today: `PluginManifest::requested_capabilities` names
// capabilities a plugin wants from ITS OWN grant, not a routing target, and nothing in
// `ainxt-runtimed`, `ainxt-tools`, or `ainxt-server` ever constructs a `PluginRegistry` or a
// `dyn CapabilityDispatch` outside this crate's own `r13_plugin_dependency_isolation.rs` test.
//
// So the "unbounded inter-plugin recursion" this mechanism guards against cannot occur on the served
// path today — there is exactly one plugin invocation per dispatch, with zero capacity for that
// invocation to reach a second plugin. Wiring `PluginRegistry` into
// `plugin_bridge::PluginCapability::execute` now would mean fabricating a brand-new capability
// (multi-plugin composition) rather than closing an existing gap — out of scope here. The mechanism
// itself is real, sound, and already fully unit-tested (`r13_plugin_dependency_isolation.rs`,
// including the bounded-call-depth proof); it is the RIGHT thing to reach for the day a served flow
// actually lets one plugin's capability resolve to another plugin's, at which point THIS is the seam
// to route it through — not something to delete as dead code.
//
/// The **only** path from one plugin to another (§3.2). Plugin-to-plugin interaction never happens by
/// a direct in-process call between two plugin instances (the way native shared-library plugins reach
/// into each other) — it is a typed, capability-*named* call routed through the host registry, so one
/// plugin can neither hold a reference to another's state nor destabilize it. Implemented by
/// [`PluginRegistry`].
pub trait CapabilityDispatch {
    /// Route a capability-named call to whichever plugin EXPOSES it, running that provider under its
    /// OWN confinement, and return its output text. The caller never learns which plugin served it or
    /// touches its internals.
    fn invoke_capability(&self, capability: &str, input: &str) -> Result<String, PluginError>;
}

/// The confined handle a registry-hosted plugin receives (§3.2). Like [`PluginContext`] it exposes only
/// the plugin's effective capabilities and records use, but it adds exactly one door outward:
/// [`PeerCall::call`], the registry-mediated peer invocation. There is no field, method, or handle by
/// which the plugin can reach another plugin instance directly.
pub struct PeerCall<'a> {
    granted: &'a BTreeSet<String>,
    used: &'a RefCell<BTreeSet<String>>,
    dispatch: &'a dyn CapabilityDispatch,
    /// The resource limits declared for this plugin.
    pub limits: ResourceLimits,
}

impl<'a> PeerCall<'a> {
    /// Record use of `capability`, or refuse it if it is not in the effective set (no ambient
    /// authority — identical contract to [`PluginContext::use_capability`]).
    pub fn use_capability(&self, capability: &str) -> Result<(), PluginError> {
        if self.granted.contains(capability) {
            self.used.borrow_mut().insert(capability.to_string());
            Ok(())
        } else {
            Err(PluginError::CapabilityDenied(capability.to_string()))
        }
    }

    /// Whether `capability` is in this plugin's effective set (without recording a use).
    pub fn has_capability(&self, capability: &str) -> bool {
        self.granted.contains(capability)
    }

    /// Invoke a peer plugin's exposed capability (§3.2). Gated **twice**: first by this plugin's own
    /// effective set (a plugin cannot call a capability it wasn't granted — no ambient authority even
    /// for peer calls), then routed through the registry to whichever plugin exposes it, which runs
    /// under its own independent confinement. The result is just text — the caller never sees the
    /// provider's identity, capabilities, or state.
    pub fn call(&self, capability: &str, input: &str) -> Result<String, PluginError> {
        self.use_capability(capability)?;
        self.dispatch.invoke_capability(capability, input)
    }
}

/// A registry-hosted plugin: input + its confined [`PeerCall`] handle → output (or a typed error).
pub type RegisteredPluginFn =
    Box<dyn Fn(&str, &PeerCall<'_>) -> Result<String, PluginError> + Send + Sync>;

struct RegisteredPlugin {
    run: RegisteredPluginFn,
    /// The plugin's effective capability set (already `requested ∩ granted`).
    granted: BTreeSet<String>,
    limits: ResourceLimits,
}

/// The host registry that enforces §3.2 dependency isolation. Each plugin is registered with its
/// effective capability set, the capabilities it *exposes* to peers, and its limits. The registry is
/// the single typed switchboard: a plugin reaches a peer only by naming a capability, and the registry
/// routes it — there is no in-process handle from one plugin to another, so one plugin's dependency
/// versions/state can never collide with or destabilize another's. Inter-plugin call depth is bounded
/// so a cycle can never hang or overflow the host.
///
/// This is the capability-confinement seam ([`PluginHost`]) extended with the one legitimate
/// inter-plugin edge; the WASM host implements the same routing (each module linked independently, no
/// shared mutable dependency graph, peer calls only through this switchboard).
pub struct PluginRegistry {
    plugins: std::collections::BTreeMap<String, RegisteredPlugin>,
    /// capability -> id of the plugin that exposes it. First registration wins; a later duplicate
    /// exposer is rejected at registration so routing is never ambiguous.
    exposer: std::collections::BTreeMap<String, String>,
    depth: Cell<usize>,
    max_depth: usize,
}

impl Default for PluginRegistry {
    fn default() -> Self {
        PluginRegistry {
            plugins: std::collections::BTreeMap::new(),
            exposer: std::collections::BTreeMap::new(),
            depth: Cell::new(0),
            max_depth: 8,
        }
    }
}

/// Why registering a plugin was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegisterError {
    /// Two plugins tried to expose the same capability — routing would be ambiguous.
    DuplicateExposer {
        capability: String,
        existing: String,
    },
}
impl fmt::Display for RegisterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegisterError::DuplicateExposer {
                capability,
                existing,
            } => write!(
                f,
                "capability '{capability}' is already exposed by plugin '{existing}'"
            ),
        }
    }
}
impl std::error::Error for RegisterError {}

impl PluginRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the bounded inter-plugin call depth (default 8). A depth of 0 forbids peer calls
    /// entirely (every plugin fully isolated).
    pub fn with_max_depth(mut self, max_depth: usize) -> Self {
        self.max_depth = max_depth;
        self
    }

    /// Register a plugin. `effective` is its already-resolved capability set (`requested ∩ granted`);
    /// `exposes` are the capabilities it offers to peers via [`PeerCall::call`]. A capability may be
    /// exposed by at most one plugin.
    pub fn register<S: Into<String>>(
        &mut self,
        id: impl Into<String>,
        effective: impl IntoIterator<Item = S>,
        exposes: impl IntoIterator<Item = S>,
        limits: ResourceLimits,
        run: RegisteredPluginFn,
    ) -> Result<(), RegisterError> {
        let id = id.into();
        let granted: BTreeSet<String> = effective.into_iter().map(Into::into).collect();
        for cap in exposes {
            let cap = cap.into();
            if let Some(existing) = self.exposer.get(&cap) {
                return Err(RegisterError::DuplicateExposer {
                    capability: cap,
                    existing: existing.clone(),
                });
            }
            self.exposer.insert(cap, id.clone());
        }
        self.plugins.insert(
            id,
            RegisteredPlugin {
                run,
                granted,
                limits,
            },
        );
        Ok(())
    }

    /// Invoke a plugin by id as the top-level entrypoint (depth resets to 0 for each top-level call).
    /// Runs under the plugin's own confinement, isolates a panic, and enforces the output-size cap —
    /// the same contract [`NativeHost`] gives, plus registry-mediated peer calls.
    pub fn invoke(&self, id: &str, input: &str) -> Result<PluginOutput, PluginError> {
        self.depth.set(0);
        self.run_plugin(id, input)
    }

    fn run_plugin(&self, id: &str, input: &str) -> Result<PluginOutput, PluginError> {
        let plugin = self
            .plugins
            .get(id)
            .ok_or_else(|| PluginError::NotFound(id.to_string()))?;

        // Fresh confinement every invocation — no state carries across calls (§3.5 statelessness).
        let used = RefCell::new(BTreeSet::new());
        let call = PeerCall {
            granted: &plugin.granted,
            used: &used,
            dispatch: self,
            limits: plugin.limits,
        };

        let result = std::panic::catch_unwind(AssertUnwindSafe(|| (plugin.run)(input, &call)));
        let output = match result {
            Ok(Ok(o)) => o,
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(PluginError::Trap(format!("plugin '{id}' panicked"))),
        };
        if output.len() > plugin.limits.max_output_bytes {
            return Err(PluginError::OutputTooLarge {
                limit: plugin.limits.max_output_bytes,
                actual: output.len(),
            });
        }
        let used_capabilities = used.borrow().iter().cloned().collect();
        Ok(PluginOutput {
            output,
            used_capabilities,
        })
    }
}

impl CapabilityDispatch for PluginRegistry {
    fn invoke_capability(&self, capability: &str, input: &str) -> Result<String, PluginError> {
        // Bound the chain BEFORE routing: a cycle (A→B→A) or runaway fan-out is a contained trap, never
        // a stack overflow or a hang. The depth is restored on the way out so sequential (non-nested)
        // peer calls are unaffected.
        let depth = self.depth.get();
        if depth >= self.max_depth {
            return Err(PluginError::CallDepthExceeded {
                max_depth: self.max_depth,
            });
        }
        let provider = self
            .exposer
            .get(capability)
            .ok_or_else(|| PluginError::CapabilityUnavailable(capability.to_string()))?
            .clone();
        self.depth.set(depth + 1);
        let result = self.run_plugin(&provider, input).map(|o| o.output);
        self.depth.set(depth);
        result
    }
}

// ==================== Plugin supply-chain: signing, allow-list, lockfile (§3.3/§3.4) ====================

/// Signing, publisher allow-list, `control.lock` hash-pin, git-native lifecycle, and publish-time
/// scanning (§3.3/§3.4, ADR-026). Third-party plugin CODE is executed in our sandbox, so — unlike an
/// MCP manifest (declarations that merely steer the planner) — its provenance must be cryptographically
/// established and re-verified **on every load**, not only at install: a key compromised today must not
/// ride on yesterday's install.
///
/// What is real and offline here: the artifact content-hash, the detached-signature verify against a
/// publisher allow-list, the `control.lock` hash-pin that gates the exact bytes allowed to run in an
/// environment, the import-vs-declared-need publish gate, the dependency-advisory scan, and the
/// git-native lifecycle state machine (branch=DRAFT → PR=PENDING_APPROVAL → merge=APPROVED → signed
/// tag=PRODUCTION). The [`Signer`]/[`Verifier`] and [`DependencyScanner`] are seams: the offline
/// reference impls are a keyed-hash signer and an advisory-set scanner; production plugs keyless /
/// transparency-log signing (sigstore-style) and a live vuln database behind the same traits
/// (infra-gated — a network + a signing identity).
pub mod supply_chain {
    use super::PluginManifest;
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use std::collections::{BTreeMap, BTreeSet};
    use std::fmt::Write as _;

    /// Hex-encode digest bytes without depending on `sha2`'s output type implementing `LowerHex`
    /// (it does not, across the `digest`/`sha2` 0.10 → 0.11 transition) or on an extra `hex` crate.
    fn to_hex(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            write!(s, "{:02x}", b).expect("writing to a String never fails");
        }
        s
    }

    /// Content hash over the WASM binary bytes AND the normalized manifest, each length-prefixed so a
    /// field boundary cannot be forged by shifting bytes (the same canonical discipline as the event
    /// log and the MCP TOFU pin). SHA-256, hex. This is the value pinned in `control.lock` and signed.
    pub fn artifact_hash(wasm: &[u8], manifest: &PluginManifest) -> String {
        let mut h = Sha256::new();
        // 1) the binary
        h.update((wasm.len() as u64).to_le_bytes());
        h.update(wasm);
        // 2) the manifest, field by length-prefixed field (id, sorted requested caps, limits)
        h.update((manifest.id.len() as u64).to_le_bytes());
        h.update(manifest.id.as_bytes());
        let mut caps: Vec<&String> = manifest.requested_capabilities.iter().collect();
        caps.sort();
        h.update((caps.len() as u64).to_le_bytes());
        for c in caps {
            h.update((c.len() as u64).to_le_bytes());
            h.update(c.as_bytes());
        }
        for v in [
            manifest.limits.max_output_bytes as u64,
            manifest.limits.max_millis,
            manifest.limits.max_memory_bytes as u64,
        ] {
            h.update(v.to_le_bytes());
        }
        to_hex(&h.finalize())
    }

    /// The detached-signature producer seam. A real deployment uses keyless / transparency-log signing
    /// tied to a verified publisher identity (§3.4); the offline reference is [`HmacSigner`].
    pub trait Signer: Send + Sync {
        /// Sign a payload (the artifact hash) — the detached signature bytes, hex.
        fn sign(&self, payload: &str) -> String;
        /// The publisher identity this signer signs as.
        fn publisher(&self) -> &str;
    }

    /// The detached-signature verifier seam — checks a signature was produced by a *specific*
    /// publisher over a *specific* payload. Real impl: verify against the publisher's transparency-log
    /// key. Offline reference: [`HmacVerifier`].
    pub trait Verifier: Send + Sync {
        fn verify(&self, publisher: &str, payload: &str, signature: &str) -> bool;
    }

    /// Offline reference [`Signer`]: a keyed SHA-256 over the payload (an HMAC-shaped stand-in for a
    /// real signing key). Deterministic and dependency-light so the supply-chain enforcement is fully
    /// testable without a signing identity or a network.
    pub struct HmacSigner {
        publisher: String,
        secret: String,
    }
    impl HmacSigner {
        pub fn new(publisher: impl Into<String>, secret: impl Into<String>) -> Self {
            HmacSigner {
                publisher: publisher.into(),
                secret: secret.into(),
            }
        }
    }
    fn keyed_digest(secret: &str, publisher: &str, payload: &str) -> String {
        let mut h = Sha256::new();
        for field in [secret, publisher, payload] {
            h.update((field.len() as u64).to_le_bytes());
            h.update(field.as_bytes());
        }
        to_hex(&h.finalize())
    }
    impl Signer for HmacSigner {
        fn sign(&self, payload: &str) -> String {
            keyed_digest(&self.secret, &self.publisher, payload)
        }
        fn publisher(&self) -> &str {
            &self.publisher
        }
    }

    /// Offline reference [`Verifier`]: a `publisher -> secret` key ring. A signature verifies iff it
    /// equals the keyed digest recomputed with that publisher's key — so a signature by one publisher
    /// cannot be replayed as another's, and a payload (hash) tampered after signing fails.
    #[derive(Default)]
    pub struct HmacVerifier {
        keys: BTreeMap<String, String>,
    }
    impl HmacVerifier {
        pub fn new() -> Self {
            Self::default()
        }
        pub fn with_key(mut self, publisher: impl Into<String>, secret: impl Into<String>) -> Self {
            self.keys.insert(publisher.into(), secret.into());
            self
        }
    }
    impl Verifier for HmacVerifier {
        fn verify(&self, publisher: &str, payload: &str, signature: &str) -> bool {
            match self.keys.get(publisher) {
                Some(secret) => keyed_digest(secret, publisher, payload) == signature,
                None => false, // unknown publisher — never verifies
            }
        }
    }

    /// The set of publisher identities permitted to sign a loadable plugin (§3.4). Checked **before
    /// every load**, so a publisher removed after a key compromise stops being loadable immediately —
    /// even for a plugin installed while it was still trusted.
    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    pub struct PublisherAllowList {
        publishers: BTreeSet<String>,
    }
    impl PublisherAllowList {
        pub fn new<S: Into<String>>(publishers: impl IntoIterator<Item = S>) -> Self {
            PublisherAllowList {
                publishers: publishers.into_iter().map(Into::into).collect(),
            }
        }
        pub fn allows(&self, publisher: &str) -> bool {
            self.publishers.contains(publisher)
        }
        pub fn revoke(&mut self, publisher: &str) {
            self.publishers.remove(publisher);
        }
    }

    /// A signed plugin artifact: the manifest, the pinned artifact hash, the signing publisher, and
    /// the detached signature over the hash. The bytes themselves live in git-LFS / a content-addressed
    /// object store (§3.4) and are supplied to [`verify_for_load`] separately — this record is what the
    /// git control repo carries.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct SignedPlugin {
        pub manifest: PluginManifest,
        /// [`artifact_hash`] of the approved bytes+manifest.
        pub artifact_hash: String,
        pub publisher: String,
        pub version: String,
        /// Detached signature over `artifact_hash`, by `publisher`.
        pub signature: String,
    }
    impl SignedPlugin {
        /// Build + sign an artifact for `wasm`/`manifest` with `signer` at `version`.
        pub fn sign(
            wasm: &[u8],
            manifest: &PluginManifest,
            version: &str,
            signer: &dyn Signer,
        ) -> Self {
            let hash = artifact_hash(wasm, manifest);
            let signature = signer.sign(&hash);
            SignedPlugin {
                manifest: manifest.clone(),
                artifact_hash: hash,
                publisher: signer.publisher().to_string(),
                version: version.to_string(),
                signature,
            }
        }
    }

    /// One `control.lock` entry (§3.4): the exact `{plugin_id, version, content_hash, signer}` approved
    /// to run in an environment. The lockfile is a versioned, reviewed file in the git control repo;
    /// this is the plugin-specific case of ADR-026's `control.lock`.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct LockEntry {
        pub plugin_id: String,
        pub version: String,
        pub content_hash: String,
        pub signer: String,
    }

    /// The per-environment plugin lockfile — `plugin_id -> LockEntry`. What is approved to run here is
    /// a git-tracked fact, not mutable runtime state.
    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    pub struct ControlLock {
        entries: BTreeMap<String, LockEntry>,
    }
    impl ControlLock {
        pub fn new() -> Self {
            Self::default()
        }
        pub fn pin(&mut self, entry: LockEntry) {
            self.entries.insert(entry.plugin_id.clone(), entry);
        }
        pub fn get(&self, plugin_id: &str) -> Option<&LockEntry> {
            self.entries.get(plugin_id)
        }
    }

    /// Why a load was refused (§3.4). Every one is a HARD failure — the runtime never executes a binary
    /// that does not match exactly what was reviewed, signed, and pinned.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum LoadError {
        /// The signing publisher is not (or no longer) on the allow-list.
        PublisherNotAllowed(String),
        /// The detached signature did not verify against the publisher over the artifact hash.
        SignatureInvalid,
        /// No `control.lock` entry pins this plugin id in this environment.
        NotInLock(String),
        /// The fetched bytes' hash does not match the lockfile pin (tamper / wrong artifact).
        HashMismatch { pinned: String, actual: String },
        /// The signed record's own hash disagrees with the fetched bytes (a re-signed different binary).
        SignedHashMismatch,
        /// The pinned version / signer disagrees with the signed record.
        LockRecordMismatch,
    }
    impl std::fmt::Display for LoadError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                LoadError::PublisherNotAllowed(p) => {
                    write!(f, "publisher '{p}' is not allow-listed")
                }
                LoadError::SignatureInvalid => write!(f, "detached signature did not verify"),
                LoadError::NotInLock(id) => {
                    write!(f, "plugin '{id}' is not pinned in control.lock")
                }
                LoadError::HashMismatch { pinned, actual } => {
                    write!(f, "binary hash {actual} does not match the pinned {pinned}")
                }
                LoadError::SignedHashMismatch => {
                    write!(
                        f,
                        "the signed record's hash does not match the fetched binary"
                    )
                }
                LoadError::LockRecordMismatch => {
                    write!(
                        f,
                        "the lockfile version/signer does not match the signed record"
                    )
                }
            }
        }
    }
    impl std::error::Error for LoadError {}

    /// Wire [`verify_for_load`] into an ACTUAL plugin load path (§3.4). Previously `verify_for_load`
    /// was a pure, correctly-implemented verification function that nothing ever *called* before
    /// registering a plugin into a host — a real gap: a caller could verify and then register
    /// regardless of the result, or simply never verify at all. This function closes that: `register`
    /// (the host's own registration call — e.g. `ainxt_wasm::WasmPluginHost::register`) is invoked
    /// **only if every §3.4 check passes**; on any [`LoadError`] the closure is never called, so a
    /// tampered binary, an unpinned plugin, or a publisher revoked after signing is provably never
    /// registered — not merely "would have failed verification if someone had asked."
    pub fn load_verified<F: FnOnce(String, Vec<u8>)>(
        fetched_wasm: Vec<u8>,
        signed: &SignedPlugin,
        lock: &ControlLock,
        allow: &PublisherAllowList,
        verifier: &dyn Verifier,
        register: F,
    ) -> Result<(), LoadError> {
        verify_for_load(&fetched_wasm, signed, lock, allow, verifier)?;
        register(signed.manifest.id.clone(), fetched_wasm);
        Ok(())
    }

    /// The load-time gate run **on every load** (§3.4), not just at install. In order: publisher
    /// allow-list → signature verify over the artifact hash → the fetched bytes hash the same as the
    /// signed record → a lock entry exists → the lock's hash/version/signer match. Any failure is a
    /// hard refusal; only an all-clear returns `Ok`.
    pub fn verify_for_load(
        fetched_wasm: &[u8],
        signed: &SignedPlugin,
        lock: &ControlLock,
        allow: &PublisherAllowList,
        verifier: &dyn Verifier,
    ) -> Result<(), LoadError> {
        // 1) publisher allow-list (re-checked every load — revocation is immediate).
        if !allow.allows(&signed.publisher) {
            return Err(LoadError::PublisherNotAllowed(signed.publisher.clone()));
        }
        // 2) signature verifies over the artifact hash, by this publisher.
        if !verifier.verify(&signed.publisher, &signed.artifact_hash, &signed.signature) {
            return Err(LoadError::SignatureInvalid);
        }
        // 3) the fetched bytes actually hash to what was signed (no swap after signing).
        let actual = artifact_hash(fetched_wasm, &signed.manifest);
        if actual != signed.artifact_hash {
            return Err(LoadError::SignedHashMismatch);
        }
        // 4) a lockfile entry pins this plugin in this environment.
        let entry = lock
            .get(&signed.manifest.id)
            .ok_or_else(|| LoadError::NotInLock(signed.manifest.id.clone()))?;
        // 5) the pin matches the fetched bytes AND the signed record's version/signer.
        if entry.content_hash != actual {
            return Err(LoadError::HashMismatch {
                pinned: entry.content_hash.clone(),
                actual,
            });
        }
        if entry.version != signed.version || entry.signer != signed.publisher {
            return Err(LoadError::LockRecordMismatch);
        }
        Ok(())
    }

    /// The publish-time **import-vs-declared-need** check (§3.3): every host import (capability) the
    /// plugin *requests* must appear in the `justified` set the PR author documented a need for. A
    /// plugin that asks for `fs.write` to "read a config" fails here — at the PR, not as a shipped
    /// surprise. Returns the unjustified imports (empty ⇒ pass).
    pub fn import_check(manifest: &PluginManifest, justified: &[&str]) -> Vec<String> {
        let ok: BTreeSet<&str> = justified.iter().copied().collect();
        manifest
            .requested_capabilities
            .iter()
            .filter(|c| !ok.contains(c.as_str()))
            .cloned()
            .collect()
    }

    /// The publish-time dependency/vulnerability scan seam (§3.4). Real impl: a live advisory DB
    /// (infra-gated). Offline reference: [`AdvisoryScanner`].
    pub trait DependencyScanner: Send + Sync {
        /// Return the advisory ids that hit for the given declared dependency coordinates (empty ⇒
        /// clean).
        fn scan(&self, dependencies: &[String]) -> Vec<String>;
    }

    /// Offline reference [`DependencyScanner`]: flags any declared dependency present in a known-bad
    /// advisory set. Enough to prove "a vulnerable dependency blocks APPROVED" offline; production
    /// swaps a live vuln feed behind the trait.
    #[derive(Default)]
    pub struct AdvisoryScanner {
        bad: BTreeSet<String>,
    }
    impl AdvisoryScanner {
        pub fn new<S: Into<String>>(bad: impl IntoIterator<Item = S>) -> Self {
            AdvisoryScanner {
                bad: bad.into_iter().map(Into::into).collect(),
            }
        }
        pub fn scan(&self, dependencies: &[String]) -> Vec<String> {
            <Self as DependencyScanner>::scan(self, dependencies)
        }
    }
    impl DependencyScanner for AdvisoryScanner {
        fn scan(&self, dependencies: &[String]) -> Vec<String> {
            dependencies
                .iter()
                .filter(|d| self.bad.contains(d.as_str()))
                .cloned()
                .collect()
        }
    }

    /// The git-native plugin lifecycle stage (§3.3, ADR-026). Mirrors the control-plane workflow:
    /// authoring on a branch is DRAFT; a PR is PENDING_APPROVAL; a merge under CODEOWNERS is APPROVED;
    /// a signed release tag on the prod ref is PRODUCTION.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum Stage {
        Draft,
        PendingApproval,
        Approved,
        Production,
    }

    /// Evidence the CI/git gate presents to justify a stage transition (§3.3). Enforced, not trusted:
    /// a promotion that lacks its evidence is refused.
    #[derive(Debug, Clone, Default)]
    pub struct PromotionEvidence {
        /// A PR is open (Draft → PendingApproval).
        pub pull_request_open: bool,
        /// The import-vs-declared-need check passed (PendingApproval → Approved).
        pub import_check_passed: bool,
        /// The dependency/vuln scan came back clean (PendingApproval → Approved).
        pub scan_clean: bool,
        /// The merge landed under CODEOWNERS review (PendingApproval → Approved).
        pub codeowners_merge: bool,
        /// A signed release tag exists on the prod ref (Approved → Production).
        pub signed_release_tag: bool,
    }

    /// Why a lifecycle promotion was refused.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum PromoteError {
        /// Not a legal forward transition (stages advance one step at a time, no skipping).
        IllegalTransition { from: Stage, to: Stage },
        /// The evidence required for this transition was missing.
        MissingEvidence(&'static str),
    }
    impl std::fmt::Display for PromoteError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                PromoteError::IllegalTransition { from, to } => {
                    write!(f, "illegal plugin lifecycle transition {from:?} -> {to:?}")
                }
                PromoteError::MissingEvidence(what) => {
                    write!(f, "missing promotion evidence: {what}")
                }
            }
        }
    }
    impl std::error::Error for PromoteError {}

    /// Attempt a git-native lifecycle promotion (§3.3). Only single-step forward transitions are legal,
    /// and each demands its evidence — notably, **PRODUCTION requires a signed release tag** (the
    /// signed-tag-equals-production rule) and APPROVED requires the import check + clean scan + a
    /// CODEOWNERS merge. Returns the new stage or a structured refusal.
    pub fn promote(from: Stage, to: Stage, ev: &PromotionEvidence) -> Result<Stage, PromoteError> {
        match (from, to) {
            (Stage::Draft, Stage::PendingApproval) => {
                if !ev.pull_request_open {
                    return Err(PromoteError::MissingEvidence("an open pull request"));
                }
                Ok(to)
            }
            (Stage::PendingApproval, Stage::Approved) => {
                if !ev.import_check_passed {
                    return Err(PromoteError::MissingEvidence(
                        "the import-vs-declared-need check must pass",
                    ));
                }
                if !ev.scan_clean {
                    return Err(PromoteError::MissingEvidence(
                        "a clean dependency/vuln scan",
                    ));
                }
                if !ev.codeowners_merge {
                    return Err(PromoteError::MissingEvidence("a CODEOWNERS-reviewed merge"));
                }
                Ok(to)
            }
            (Stage::Approved, Stage::Production) => {
                if !ev.signed_release_tag {
                    return Err(PromoteError::MissingEvidence(
                        "a signed release tag on the prod ref (signed-tag = production)",
                    ));
                }
                Ok(to)
            }
            (from, to) => Err(PromoteError::IllegalTransition { from, to }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host_with(id: &str, plugin: PluginFn) -> NativeHost {
        let mut h = NativeHost::new();
        h.register(id, plugin);
        h
    }

    fn manifest(id: &str, caps: &[&str], limits: ResourceLimits) -> PluginManifest {
        PluginManifest {
            id: id.into(),
            requested_capabilities: caps.iter().map(|s| s.to_string()).collect(),
            limits,
        }
    }

    #[test]
    fn plugin_runs_with_granted_capability() {
        let host = host_with(
            "greet",
            Box::new(|input, ctx| {
                ctx.use_capability("net.fetch")?;
                Ok(format!("fetched for {input}"))
            }),
        );
        let m = manifest("greet", &["net.fetch"], ResourceLimits::default());
        let out = host
            .invoke(&m, &PluginGrant::new(["net.fetch"]), "x")
            .unwrap();
        assert_eq!(out.output, "fetched for x");
        assert_eq!(out.used_capabilities, vec!["net.fetch".to_string()]);
    }

    #[test]
    fn no_ambient_authority_ungranted_capability_is_denied() {
        // The plugin asks for a capability that was NOT granted → the context refuses it. The plugin
        // has no other door to the outside world.
        let host = host_with(
            "evil",
            Box::new(|_input, ctx| {
                ctx.use_capability("fs.delete")?; // never granted
                Ok("deleted everything".into())
            }),
        );
        let m = manifest("evil", &["fs.delete"], ResourceLimits::default());
        let err = host
            .invoke(&m, &PluginGrant::new(["net.fetch"]), "x")
            .unwrap_err();
        assert_eq!(err, PluginError::CapabilityDenied("fs.delete".into()));
    }

    #[test]
    fn effective_is_requested_intersect_granted() {
        // Granted but NOT requested → not in the effective set → using it is denied.
        let host = host_with(
            "p",
            Box::new(|_i, ctx| {
                ctx.use_capability("tool.write")?;
                Ok("wrote".into())
            }),
        );
        let m = manifest("p", &["tool.read"], ResourceLimits::default()); // requested only read
        let err = host
            .invoke(&m, &PluginGrant::new(["tool.read", "tool.write"]), "x")
            .unwrap_err();
        assert_eq!(err, PluginError::CapabilityDenied("tool.write".into()));
    }

    #[test]
    fn output_over_limit_is_refused() {
        let host = host_with("big", Box::new(|_i, _ctx| Ok("x".repeat(100))));
        let m = manifest(
            "big",
            &[],
            ResourceLimits {
                max_output_bytes: 10,
                ..Default::default()
            },
        );
        let err = host.invoke(&m, &PluginGrant::default(), "x").unwrap_err();
        assert!(matches!(
            err,
            PluginError::OutputTooLarge {
                limit: 10,
                actual: 100
            }
        ));
    }

    #[test]
    fn a_panicking_plugin_is_isolated() {
        let host = host_with("boom", Box::new(|_i, _ctx| panic!("plugin blew up")));
        let m = manifest("boom", &[], ResourceLimits::default());
        let err = host.invoke(&m, &PluginGrant::default(), "x").unwrap_err();
        assert!(
            matches!(err, PluginError::Trap(_)),
            "a panic must be isolated, not crash the host"
        );
        // The host is still usable afterwards.
        let host2 = host_with("ok", Box::new(|_i, _ctx| Ok("fine".into())));
        assert!(host2
            .invoke(
                &manifest("ok", &[], ResourceLimits::default()),
                &PluginGrant::default(),
                "y"
            )
            .is_ok());
    }

    #[test]
    fn plugin_returning_error_is_a_trap_not_a_crash() {
        let host = host_with(
            "err",
            Box::new(|_i, _ctx| Err(PluginError::Trap("bad input".into()))),
        );
        let m = manifest("err", &[], ResourceLimits::default());
        assert!(matches!(
            host.invoke(&m, &PluginGrant::default(), "x").unwrap_err(),
            PluginError::Trap(_)
        ));
    }

    #[test]
    fn unknown_plugin_is_not_found() {
        let host = NativeHost::new();
        let m = manifest("ghost", &[], ResourceLimits::default());
        assert_eq!(
            host.invoke(&m, &PluginGrant::default(), "x").unwrap_err(),
            PluginError::NotFound("ghost".into())
        );
    }

    #[test]
    fn manifest_serde_round_trips_and_rejects_unknown_fields() {
        let m = manifest("p", &["c"], ResourceLimits::default());
        assert_eq!(
            serde_json::from_str::<PluginManifest>(&serde_json::to_string(&m).unwrap()).unwrap(),
            m
        );
        assert!(
            serde_json::from_str::<PluginManifest>(r#"{"id":"p","escape_sandbox":true}"#).is_err()
        );
    }
}
