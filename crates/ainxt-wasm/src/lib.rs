// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-wasm — a capability-confined WASM plugin sandbox (ADR-024).
//!
//! Third-party and machine-generated plugins are the platform's largest untrusted-code surface. On
//! a PCI/DSS payments platform a plugin must be assumed **hostile or buggy**: it may try to reach
//! the filesystem, the network, or the clock; it may spin forever; it may allocate without bound;
//! it may deliberately trap to try to take the host down. This sandbox is built so that none of
//! those succeed.
//!
//! # The two invariants
//!
//! 1. **Zero ambient authority.** A plugin gets *nothing* it was not explicitly granted. There is
//!    no WASI, no clock, no filesystem, no host functions. A module is instantiated against an
//!    **empty** import set, so a module that imports *anything* — a host function, a memory, a
//!    table, a global — fails to instantiate ([`SandboxError::Instantiate`]). Authority is granted
//!    by construction, never ambient. (Granting specific capabilities is a deliberate future seam;
//!    the default, and the only mode today, is deny-all.)
//!
//! 2. **Hard resource ceilings, enforced by the runtime, not by trust.**
//!    - **Fuel.** The [`wasmtime::Engine`] is built with fuel consumption ON and every [`Store`]
//!      is charged exactly [`SandboxConfig::fuel`] units. When fuel runs out the guest is trapped
//!      ([`SandboxError::OutOfFuel`]) — an infinite loop is *stopped*, it never hangs the caller.
//!    - **Memory.** A [`StoreLimits`] cap bounds guest memory to
//!      [`SandboxConfig::max_memory_bytes`]. A declared minimum above the cap fails to instantiate;
//!      a `memory.grow` past the cap fails *cleanly* (the guest sees `-1`, the host is unaffected).
//!    - **Output.** Returned values are encoded and bounded by
//!      [`SandboxConfig::max_output_bytes`] ([`SandboxError::OutputTooLarge`]) so a plugin cannot
//!      flood the host with an unbounded result.
//!
//! Any guest trap — an explicit `unreachable`, an out-of-bounds access, a division by zero — is
//! caught and returned as [`SandboxError::Trapped`]. The host process is never brought down by
//! guest behaviour, and the same [`WasmSandbox`] can be reused for the next call.
//!
//! # Why this shape
//!
//! `wasmtime` carries its own `unsafe` (a JIT must); *this* crate adds none — `unsafe_code` is
//! forbidden. All host state lives in an owned [`HostState`] carried by the `Store`, so the
//! resource limiter is plain safe Rust. The public surface deals in a small, engine-agnostic
//! [`Value`] type rather than leaking `wasmtime::Val`, so the runtime's plugin contract does not
//! bind callers to a specific WASM engine version.

use wasmtime::{
    Caller, Config, Engine, Instance, Linker, Memory, Module, Store, StoreLimits,
    StoreLimitsBuilder, Trap, Val, ValType,
};

// ============================ Configuration ============================

/// Hard resource ceilings applied to every plugin invocation.
///
/// These are limits, not requests: they are enforced by the wasmtime runtime, so a plugin cannot
/// exceed them regardless of what it attempts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SandboxConfig {
    /// Fuel units granted to a single call. Roughly one unit per executed wasm instruction; when it
    /// reaches zero the guest is trapped as [`SandboxError::OutOfFuel`]. Bounds *time*.
    pub fuel: u64,
    /// Maximum linear-memory size, in bytes, the guest may occupy. A declared minimum above this
    /// fails instantiation; a `memory.grow` past it returns `-1` to the guest. Bounds *space*.
    pub max_memory_bytes: usize,
    /// Maximum size, in bytes, of the encoded return values. Bounds the guest's *output*.
    pub max_output_bytes: usize,
    /// Real, host-enforced wall-clock ceiling for a single call, in milliseconds (§3.5). Distinct
    /// from `fuel`: fuel counts executed wasm *instructions*, so a call that spends real time inside
    /// a granted host function (a slow scoped-filesystem read, a KV lookup under contention) burns
    /// little or no fuel yet can still run long. This is enforced via wasmtime epoch-based
    /// interruption — a background watchdog increments the shared engine epoch once the deadline
    /// elapses, which traps the guest at its VERY NEXT epoch check point (every loop back-edge and
    /// function entry, including the instant control returns to guest code after a host-function
    /// call) — with **no guest cooperation and no way for the guest to see or disable it**. `None`
    /// disables the wall-clock ceiling (fuel/memory ceilings still apply).
    pub max_wall_clock_ms: Option<u64>,
}

impl SandboxConfig {
    /// A conservative default suitable for small, short-lived plugin calls: 10M fuel units, 16 MiB
    /// of guest memory, 1 MiB of output, 5s real wall-clock ceiling.
    pub const fn conservative() -> SandboxConfig {
        SandboxConfig {
            fuel: 10_000_000,
            max_memory_bytes: 16 * 1024 * 1024,
            max_output_bytes: 1024 * 1024,
            max_wall_clock_ms: Some(5_000),
        }
    }
}

impl Default for SandboxConfig {
    fn default() -> SandboxConfig {
        SandboxConfig::conservative()
    }
}

// ============================ Values ============================

/// An engine-agnostic WebAssembly scalar, used for both call arguments and results.
///
/// Deliberately narrow: the numeric types a plugin contract needs. Reference types, `v128`, and
/// other exotic values are intentionally unsupported and surface as errors rather than being
/// silently coerced — a payments platform does not guess at ABI.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Value {
    /// A 32-bit integer.
    I32(i32),
    /// A 64-bit integer.
    I64(i64),
    /// A 32-bit float.
    F32(f32),
    /// A 64-bit float.
    F64(f64),
}

impl Value {
    fn to_val(self) -> Val {
        match self {
            Value::I32(x) => Val::I32(x),
            Value::I64(x) => Val::I64(x),
            Value::F32(x) => Val::F32(x.to_bits()),
            Value::F64(x) => Val::F64(x.to_bits()),
        }
    }

    fn from_val(v: &Val) -> Result<Value, SandboxError> {
        match v {
            Val::I32(x) => Ok(Value::I32(*x)),
            Val::I64(x) => Ok(Value::I64(*x)),
            Val::F32(bits) => Ok(Value::F32(f32::from_bits(*bits))),
            Val::F64(bits) => Ok(Value::F64(f64::from_bits(*bits))),
            other => Err(SandboxError::UnsupportedResult(format!("{other:?}"))),
        }
    }

    /// Whether this value satisfies the expected parameter type.
    fn matches(&self, ty: &ValType) -> bool {
        matches!(
            (self, ty),
            (Value::I32(_), ValType::I32)
                | (Value::I64(_), ValType::I64)
                | (Value::F32(_), ValType::F32)
                | (Value::F64(_), ValType::F64)
        )
    }

    /// Append this value's little-endian byte encoding to `buf`.
    fn encode_into(&self, buf: &mut Vec<u8>) {
        match *self {
            Value::I32(x) => buf.extend_from_slice(&x.to_le_bytes()),
            Value::I64(x) => buf.extend_from_slice(&x.to_le_bytes()),
            Value::F32(x) => buf.extend_from_slice(&x.to_bits().to_le_bytes()),
            Value::F64(x) => buf.extend_from_slice(&x.to_bits().to_le_bytes()),
        }
    }
}

// ============================ Errors ============================

/// Every way a sandboxed call can fail. All are recoverable by the host — none of them represents
/// the host process being compromised or crashed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SandboxError {
    /// The wasmtime engine could not be constructed with the requested configuration.
    EngineInit(String),
    /// The module bytes (wasm binary or, with the `wat` feature, WAT text) failed to compile.
    Compile(String),
    /// The module could not be instantiated. The dominant cause is an **ungranted import** — the
    /// module asked for authority it was not given — but a declared memory minimum above the cap
    /// also lands here. Either way, no guest code ran.
    Instantiate(String),
    /// The named export does not exist, or exists but is not a function.
    FuncNotFound(String),
    /// The supplied arguments do not match the function signature (arity or type).
    Signature(String),
    /// The call exhausted its fuel and was trapped. An infinite loop ends up here, bounded, rather
    /// than hanging the host.
    OutOfFuel,
    /// The guest trapped (an explicit `unreachable`, an out-of-bounds access, an integer divide by
    /// zero, a stack overflow, …). The host survives; the message describes the trap.
    Trapped(String),
    /// The function returned successfully but its encoded result exceeded
    /// [`SandboxConfig::max_output_bytes`].
    OutputTooLarge {
        /// Bytes the guest actually produced.
        produced: usize,
        /// The configured ceiling.
        limit: usize,
    },
    /// A returned value used a type outside the supported scalar set (e.g. a reference or `v128`).
    UnsupportedResult(String),
    /// The call exceeded its REAL wall-clock ceiling ([`SandboxConfig::max_wall_clock_ms`]) — §3.5's
    /// hard, host-enforced kill via wasmtime epoch interruption, distinct from [`SandboxError::OutOfFuel`]
    /// (which bounds wasm *instructions*, not real time). Raised even when the guest is blocked inside
    /// a slow granted host function (§3.1 capability import), where fuel does not advance at all.
    WallClockExceeded {
        /// The configured ceiling that was exceeded.
        limit_millis: u64,
    },
    /// An unexpected runtime error that is not one of the categories above.
    Internal(String),
}

impl core::fmt::Display for SandboxError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SandboxError::EngineInit(m) => write!(f, "engine initialization failed: {m}"),
            SandboxError::Compile(m) => write!(f, "module compilation failed: {m}"),
            SandboxError::Instantiate(m) => write!(f, "module instantiation failed: {m}"),
            SandboxError::FuncNotFound(n) => write!(f, "exported function not found: {n}"),
            SandboxError::Signature(m) => write!(f, "argument signature mismatch: {m}"),
            SandboxError::OutOfFuel => write!(f, "execution ran out of fuel (trapped, not hung)"),
            SandboxError::Trapped(m) => write!(f, "guest trapped: {m}"),
            SandboxError::OutputTooLarge { produced, limit } => {
                write!(
                    f,
                    "output too large: {produced} bytes exceeds limit of {limit}"
                )
            }
            SandboxError::UnsupportedResult(m) => write!(f, "unsupported result value: {m}"),
            SandboxError::WallClockExceeded { limit_millis } => write!(
                f,
                "execution exceeded its {limit_millis}ms real wall-clock ceiling (trapped, not hung)"
            ),
            SandboxError::Internal(m) => write!(f, "internal sandbox error: {m}"),
        }
    }
}

impl std::error::Error for SandboxError {}

// ============================ Output ============================

/// The result of a successful sandboxed call.
#[derive(Debug, Clone, PartialEq)]
pub struct Output {
    /// The values the exported function returned, in order.
    pub values: Vec<Value>,
    /// The little-endian byte encoding of `values`, already checked against
    /// [`SandboxConfig::max_output_bytes`].
    pub encoded: Vec<u8>,
    /// Fuel consumed by the call — an observable, monotone cost signal for budgeting/telemetry.
    pub fuel_consumed: u64,
}

/// The result of a successful [`WasmSandbox::run_with_input`] call: the UTF-8 text the guest wrote
/// back into its own linear memory, plus the fuel it cost.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextOutput {
    /// The guest's returned UTF-8 text (bounds-checked against the guest memory and capped by
    /// [`SandboxConfig::max_output_bytes`]).
    pub text: String,
    /// Fuel consumed across the alloc + call — an observable cost signal.
    pub fuel_consumed: u64,
}

// ============================ Host state ============================

/// Owned per-call host state carried by the `Store`. Kept in safe Rust so the limiter needs no
/// `unsafe`. `caps` is `None` for the numeric/text-only entrypoints ([`WasmSandbox::run`] /
/// [`WasmSandbox::run_with_input`]) and `Some` only under [`WasmSandbox::run_with_capabilities`],
/// where it backs the granted host-import functions (§3.1).
struct HostState {
    limits: StoreLimits,
    caps: Option<GrantedCapabilities>,
    /// Names of granted capabilities the guest actually exercised this call (for honest audit).
    used: std::collections::BTreeSet<&'static str>,
}

// ============================ Real wall-clock kill (§3.5, epoch interruption) ============================

/// A background timer that increments the sandbox's shared [`Engine`] epoch **exactly once**, after
/// `duration`, unless [`EpochWatchdog::disarm`] cancels it first. This is wasmtime's real,
/// host-enforced, guest-cannot-disable wall-clock bound: `fuel` counts executed wasm *instructions*,
/// so a call that spends real time blocked inside a granted host function (a slow scoped-filesystem
/// read, a contended KV lookup) burns little or no fuel yet can still run arbitrarily long. Epoch
/// interruption is independent of fuel and of the guest's own code — the watchdog thread fires
/// regardless of what the guest is doing, and the *next* epoch check point (which wasmtime inserts at
/// every backward branch and every host-function return point) traps.
struct EpochWatchdog {
    cancel: Option<std::sync::mpsc::Sender<()>>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl EpochWatchdog {
    /// Arm a watchdog that will call `engine.increment_epoch()` once, after `duration`, unless
    /// disarmed first.
    fn arm(engine: Engine, duration: std::time::Duration) -> EpochWatchdog {
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let handle = std::thread::spawn(move || {
            match rx.recv_timeout(duration) {
                // Disarmed in time (or the sender was dropped without firing) — the call finished
                // within budget, so the epoch must never advance for it.
                Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    engine.increment_epoch();
                }
            }
        });
        EpochWatchdog {
            cancel: Some(tx),
            handle: Some(handle),
        }
    }

    /// Cancel the watchdog (the call finished in time) and join its thread, so the next call starts
    /// from a clean slate — no stray late `increment_epoch()` can ever land on a future, unrelated
    /// call.
    fn disarm(mut self) {
        if let Some(tx) = self.cancel.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for EpochWatchdog {
    /// Best-effort cancel if a caller forgets to `disarm()` explicitly (e.g. an early `?` return).
    /// Never blocks on join during drop/unwind — only `disarm()` gives that ordering guarantee.
    fn drop(&mut self) {
        if let Some(tx) = self.cancel.take() {
            let _ = tx.send(());
        }
    }
}

// ============================ Sandbox ============================

/// A reusable, capability-confined WASM execution sandbox.
///
/// One [`Engine`] (with fuel enabled) is built at construction and shared across calls; each
/// [`WasmSandbox::run`] gets a fresh `Store` with its own fuel budget and memory limiter, so calls
/// are isolated from one another and a trap in one leaves the sandbox usable for the next.
pub struct WasmSandbox {
    engine: Engine,
    config: SandboxConfig,
}

impl WasmSandbox {
    /// Build a sandbox with the given ceilings. Turns fuel consumption ON in the engine — this is
    /// the load-bearing switch behind [`SandboxError::OutOfFuel`].
    pub fn new(config: SandboxConfig) -> Result<WasmSandbox, SandboxError> {
        let mut cfg = Config::new();
        cfg.consume_fuel(true);
        // Epoch interruption is always ENABLED at the engine level (§3.5): every store below sets an
        // explicit deadline before running any guest code (wasmtime traps immediately on a deadline of
        // 0 otherwise), so this is safe regardless of whether a given call configures a wall-clock
        // ceiling — only a call that arms a watchdog can ever have the epoch actually advance.
        cfg.epoch_interruption(true);
        let engine = Engine::new(&cfg).map_err(|e| SandboxError::EngineInit(e.to_string()))?;
        Ok(WasmSandbox { engine, config })
    }

    /// The ceilings this sandbox enforces.
    pub fn config(&self) -> &SandboxConfig {
        &self.config
    }

    /// Arm a real wall-clock watchdog for this sandbox's configured ceiling, if any. Callers set the
    /// store's epoch deadline to `1` (reached the instant the engine's epoch is incremented once) and
    /// pass the SAME value here; `disarm()`-ing the returned guard after a successful call prevents any
    /// late `increment_epoch()` from bleeding into a future call.
    fn arm_wallclock(&self) -> Option<EpochWatchdog> {
        self.config
            .max_wall_clock_ms
            .map(|ms| EpochWatchdog::arm(self.engine.clone(), std::time::Duration::from_millis(ms)))
    }

    /// Map a trap to the crate's error taxonomy, distinguishing the real wall-clock kill
    /// ([`Trap::Interrupt`], from epoch interruption) from every other trap category
    /// ([`trap_to_error`]) — both are isolated faults the host survives.
    fn trap_or_wallclock(&self, err: &wasmtime::Error) -> SandboxError {
        if let Some(trap) = err.downcast_ref::<Trap>() {
            if matches!(trap, Trap::Interrupt) {
                if let Some(ms) = self.config.max_wall_clock_ms {
                    return SandboxError::WallClockExceeded { limit_millis: ms };
                }
            }
            return trap_to_error(trap);
        }
        SandboxError::Trapped(format!("{err:#}"))
    }

    /// Compile, instantiate (with zero ambient authority), and call `func_name(args)`.
    ///
    /// `module_bytes` may be a wasm binary or, because the `wat` feature is enabled, inline WAT
    /// text. The module is instantiated against an **empty** import set: if it imports anything it
    /// was not granted, this returns [`SandboxError::Instantiate`] and no guest code runs.
    pub fn run(
        &self,
        module_bytes: &[u8],
        func_name: &str,
        args: &[Value],
    ) -> Result<Output, SandboxError> {
        let module = Module::new(&self.engine, module_bytes)
            .map_err(|e| SandboxError::Compile(format!("{e:#}")))?;

        // Per-call store: fresh fuel budget and a memory limiter capped at max_memory_bytes.
        let limits = StoreLimitsBuilder::new()
            .memory_size(self.config.max_memory_bytes)
            .build();
        let mut store = Store::new(
            &self.engine,
            HostState {
                limits,
                caps: None,
                used: std::collections::BTreeSet::new(),
            },
        );
        store.limiter(|state| &mut state.limits);
        store
            .set_fuel(self.config.fuel)
            .map_err(|e| SandboxError::Internal(format!("set_fuel: {e:#}")))?;
        // §3.5: a deadline must be set before ANY guest code runs (wasmtime traps immediately on the
        // default deadline of 0) — `1` is reached the instant the watchdog fires once.
        store.set_epoch_deadline(1);

        // Zero ambient authority: instantiate against no imports. A module importing anything
        // ungranted fails here. (A trap in a start section is reported as Trapped.)
        let watchdog = self.arm_wallclock();
        let instance = match Instance::new(&mut store, &module, &[]) {
            Ok(instance) => instance,
            Err(err) => {
                if let Some(w) = watchdog {
                    w.disarm();
                }
                if let Some(trap) = err.downcast_ref::<Trap>() {
                    return Err(trap_to_error(trap));
                }
                return Err(SandboxError::Instantiate(format!("{err:#}")));
            }
        };

        let func = match instance.get_func(&mut store, func_name) {
            Some(f) => f,
            None => {
                if let Some(w) = watchdog {
                    w.disarm();
                }
                return Err(SandboxError::FuncNotFound(func_name.to_string()));
            }
        };

        // Validate the argument list against the real signature before calling, so an ABI mismatch
        // is a clean typed error instead of an opaque wasmtime failure.
        let ty = func.ty(&store);
        let params: Vec<ValType> = ty.params().collect();
        if params.len() != args.len() {
            if let Some(w) = watchdog {
                w.disarm();
            }
            return Err(SandboxError::Signature(format!(
                "expected {} argument(s), got {}",
                params.len(),
                args.len()
            )));
        }
        for (index, (arg, expected)) in args.iter().zip(params.iter()).enumerate() {
            if !arg.matches(expected) {
                if let Some(w) = watchdog {
                    w.disarm();
                }
                return Err(SandboxError::Signature(format!(
                    "argument {index}: {arg:?} does not match {expected:?}"
                )));
            }
        }
        let result_count = ty.results().count();

        let call_args: Vec<Val> = args.iter().map(|v| v.to_val()).collect();
        let mut call_results = vec![Val::I32(0); result_count];

        let fuel_before = store.get_fuel().unwrap_or(self.config.fuel);
        let call_result = func.call(&mut store, &call_args, &mut call_results);
        if let Some(w) = watchdog {
            w.disarm();
        }
        if let Err(err) = call_result {
            return Err(self.trap_or_wallclock(&err));
        }
        let fuel_after = store.get_fuel().unwrap_or(0);
        let fuel_consumed = fuel_before.saturating_sub(fuel_after);

        let mut values = Vec::with_capacity(call_results.len());
        for raw in &call_results {
            values.push(Value::from_val(raw)?);
        }

        let mut encoded = Vec::new();
        for value in &values {
            value.encode_into(&mut encoded);
        }
        if encoded.len() > self.config.max_output_bytes {
            return Err(SandboxError::OutputTooLarge {
                produced: encoded.len(),
                limit: self.config.max_output_bytes,
            });
        }

        Ok(Output {
            values,
            encoded,
            fuel_consumed,
        })
    }

    /// Run `func_name`, passing the guest a UTF-8 **text** `input` through the guest's OWN linear
    /// memory — the *granted linear-memory capability* (the ADR-024 follow-up to the numeric-only
    /// ABI) that lets a plugin/skill see the user's turn text, not just numeric args.
    ///
    /// The contract is entirely guest-side (still ZERO ambient authority — the module is instantiated
    /// against an EMPTY import set, so it gets no host functions; the host only reads/writes memory the
    /// guest itself allocated). The module must export:
    ///
    /// - `memory` — its linear memory;
    /// - `alloc(len: i32) -> i32` — reserve `len` writable bytes and return their offset;
    /// - `func_name(ptr: i32, len: i32) -> (i32 out_ptr, i32 out_len)` — read the `len` input bytes at
    ///   `ptr` and return the location of its UTF-8 result in the same memory.
    ///
    /// Enterprise-hard: fuel/memory ceilings still apply (an alloc that grows past the cap fails
    /// cleanly, an infinite loop traps as [`SandboxError::OutOfFuel`]); every offset/length is
    /// bounds-checked against the guest memory; the returned text is capped by
    /// [`SandboxConfig::max_output_bytes`] and must be valid UTF-8 (a payments platform never guesses
    /// at bytes). Any guest trap is isolated; the host survives.
    pub fn run_with_input(
        &self,
        module_bytes: &[u8],
        alloc_name: &str,
        func_name: &str,
        input: &str,
    ) -> Result<TextOutput, SandboxError> {
        // Input must be addressable by the guest's i32 ABI.
        let in_len = i32::try_from(input.len()).map_err(|_| {
            SandboxError::Signature(format!(
                "input of {} bytes exceeds the i32 memory ABI limit",
                input.len()
            ))
        })?;

        let module = Module::new(&self.engine, module_bytes)
            .map_err(|e| SandboxError::Compile(format!("{e:#}")))?;

        let limits = StoreLimitsBuilder::new()
            .memory_size(self.config.max_memory_bytes)
            .build();
        let mut store = Store::new(
            &self.engine,
            HostState {
                limits,
                caps: None,
                used: std::collections::BTreeSet::new(),
            },
        );
        store.limiter(|state| &mut state.limits);
        store
            .set_fuel(self.config.fuel)
            .map_err(|e| SandboxError::Internal(format!("set_fuel: {e:#}")))?;
        store.set_epoch_deadline(1);

        // Zero ambient authority: instantiate against no imports.
        let watchdog = self.arm_wallclock();
        let instance = match Instance::new(&mut store, &module, &[]) {
            Ok(instance) => instance,
            Err(err) => {
                if let Some(w) = watchdog {
                    w.disarm();
                }
                if let Some(trap) = err.downcast_ref::<Trap>() {
                    return Err(trap_to_error(trap));
                }
                return Err(SandboxError::Instantiate(format!("{err:#}")));
            }
        };

        let memory: Memory = match instance.get_memory(&mut store, "memory") {
            Some(m) => m,
            None => {
                if let Some(w) = watchdog {
                    w.disarm();
                }
                return Err(SandboxError::Signature(
                    "guest exports no linear 'memory'".into(),
                ));
            }
        };
        let alloc = match instance.get_func(&mut store, alloc_name) {
            Some(f) => f,
            None => {
                if let Some(w) = watchdog {
                    w.disarm();
                }
                return Err(SandboxError::FuncNotFound(alloc_name.to_string()));
            }
        };
        let func = match instance.get_func(&mut store, func_name) {
            Some(f) => f,
            None => {
                if let Some(w) = watchdog {
                    w.disarm();
                }
                return Err(SandboxError::FuncNotFound(func_name.to_string()));
            }
        };

        let fuel_before = store.get_fuel().unwrap_or(self.config.fuel);

        // 1. alloc(in_len) -> ptr — still under the SAME watchdog as the main call (§3.5: the whole
        // guest interaction shares one wall-clock budget).
        let ptr = match self.call_i32_i32(&mut store, &alloc, in_len, alloc_name) {
            Ok(p) => p,
            Err(e) => {
                if let Some(w) = watchdog {
                    w.disarm();
                }
                return Err(e);
            }
        };

        // 2. write the input bytes into the guest's memory at ptr (bounds-checked by wasmtime).
        if let Err(e) = memory.write(&mut store, ptr as usize, input.as_bytes()) {
            if let Some(w) = watchdog {
                w.disarm();
            }
            return Err(SandboxError::Trapped(format!(
                "writing input into guest memory failed: {e}"
            )));
        }

        // 3. func(ptr, len) -> (out_ptr, out_len)
        let ty = func.ty(&store);
        if ty.params().count() != 2 || ty.results().count() != 2 {
            if let Some(w) = watchdog {
                w.disarm();
            }
            return Err(SandboxError::Signature(format!(
                "text-ABI function '{func_name}' must be (i32 ptr, i32 len) -> (i32 out_ptr, i32 out_len)"
            )));
        }
        let args = [Val::I32(ptr), Val::I32(in_len)];
        let mut results = [Val::I32(0), Val::I32(0)];
        let call_result = func.call(&mut store, &args, &mut results);
        if let Some(w) = watchdog {
            w.disarm();
        }
        if let Err(err) = call_result {
            return Err(self.trap_or_wallclock(&err));
        }
        let out_ptr = results[0]
            .i32()
            .ok_or_else(|| SandboxError::Signature("out_ptr is not an i32".into()))?;
        let out_len = results[1]
            .i32()
            .ok_or_else(|| SandboxError::Signature("out_len is not an i32".into()))?;

        let fuel_after = store.get_fuel().unwrap_or(0);
        let fuel_consumed = fuel_before.saturating_sub(fuel_after);

        if out_ptr < 0 || out_len < 0 {
            return Err(SandboxError::Trapped(format!(
                "guest returned a negative pointer/length ({out_ptr}, {out_len})"
            )));
        }
        let out_len = out_len as usize;
        if out_len > self.config.max_output_bytes {
            return Err(SandboxError::OutputTooLarge {
                produced: out_len,
                limit: self.config.max_output_bytes,
            });
        }

        // 4. read out_len bytes at out_ptr, bounds-checked against the guest memory.
        let start = out_ptr as usize;
        let data = memory.data(&store);
        let end = start.checked_add(out_len).ok_or_else(|| {
            SandboxError::Trapped("guest output slice overflows the address space".into())
        })?;
        if end > data.len() {
            return Err(SandboxError::Trapped(format!(
                "guest output [{start}..{end}) is out of bounds (memory is {} bytes)",
                data.len()
            )));
        }
        let text = String::from_utf8(data[start..end].to_vec())
            .map_err(|_| SandboxError::Trapped("guest output is not valid UTF-8".into()))?;

        Ok(TextOutput {
            text,
            fuel_consumed,
        })
    }

    /// Call a guest `(i32) -> i32` function, returning the result. A signature mismatch or a trap is a
    /// clean typed error.
    fn call_i32_i32(
        &self,
        store: &mut Store<HostState>,
        func: &wasmtime::Func,
        arg: i32,
        name: &str,
    ) -> Result<i32, SandboxError> {
        let ty = func.ty(&*store);
        if ty.params().count() != 1 || ty.results().count() != 1 {
            return Err(SandboxError::Signature(format!(
                "'{name}' must be (i32) -> i32"
            )));
        }
        let mut results = [Val::I32(0)];
        if let Err(err) = func.call(&mut *store, &[Val::I32(arg)], &mut results) {
            return Err(self.trap_or_wallclock(&err));
        }
        results[0]
            .i32()
            .ok_or_else(|| SandboxError::Signature(format!("'{name}' did not return an i32")))
    }
}

/// Map a wasmtime [`Trap`] to the crate's error taxonomy. Fuel exhaustion is distinguished so an
/// infinite loop reads as [`SandboxError::OutOfFuel`] rather than a generic trap.
fn trap_to_error(trap: &Trap) -> SandboxError {
    match trap {
        Trap::OutOfFuel => SandboxError::OutOfFuel,
        other => SandboxError::Trapped(format!("{other}")),
    }
}

// ============================ Real capability-scoped host imports (§3.1) ============================
//
// §3.1's sandbox model is not "deny everything, forever" — it is WASI's CAPABILITY model: a plugin
// gets exactly the host functions its manifest declared AND was granted, nothing ambient. Every prior
// test in this crate proves the DENY half (an ungranted import fails to instantiate). This section
// proves the GRANT half concretely, with two representative host-enforced capabilities the design
// names explicitly (§3.1: "a filesystem read on a scoped directory... a KV slice"):
//
//   * `env.fs_read`        — read a file, but ONLY inside a host-declared scoped root directory. A
//     guest that supplies `../../etc/passwd` (or an absolute path) is refused by the HOST's
//     path-scoping check, not by guest cooperation.
//   * `env.kv_get`/`kv_set` — a shared key-value slice, but ONLY for keys under a host-declared
//     prefix. A guest reading/writing a key outside its prefix is refused by the host.
//
// Authority is granted by CONSTRUCTION: a module is instantiated against a [`Linker`] that contains
// ONLY the host functions this specific call was granted ([`GrantedCapabilities`]); a module
// importing anything else still fails to instantiate exactly as the zero-capability path does. This
// is what makes the sandbox "capability-based" rather than merely "all-or-nothing".

/// A filesystem-read capability scoped to one root directory (§3.1). The host resolves and
/// canonicalizes every guest-supplied relative path against `root` and refuses anything that would
/// escape it (`..` traversal, an absolute path, a symlink that resolves outside) — enforced by the
/// HOST, never by the guest's cooperation.
pub struct FsReadCapability {
    root: std::path::PathBuf,
}

impl FsReadCapability {
    /// Scope reads to `root`. `root` is canonicalized eagerly so every later comparison is exact.
    pub fn new(root: impl Into<std::path::PathBuf>) -> std::io::Result<FsReadCapability> {
        let root = std::fs::canonicalize(root.into())?;
        Ok(FsReadCapability { root })
    }

    /// Resolve a guest-supplied relative path against `root`, refusing anything that would escape it.
    /// An absolute path or a `..` component is refused before touching the filesystem; the RESULT is
    /// then canonicalized (resolving symlinks too) and must still be under `root` — the hard boundary
    /// check, not merely the string-level pre-filter.
    fn resolve(&self, guest_path: &str) -> Result<std::path::PathBuf, ()> {
        let p = std::path::Path::new(guest_path);
        if p.is_absolute() {
            return Err(());
        }
        if p.components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(());
        }
        let joined = self.root.join(p);
        let resolved = std::fs::canonicalize(&joined).map_err(|_| ())?;
        if resolved.starts_with(&self.root) {
            Ok(resolved)
        } else {
            Err(())
        }
    }

    fn read(&self, guest_path: &str) -> Result<Vec<u8>, ()> {
        let resolved = self.resolve(guest_path)?;
        std::fs::read(resolved).map_err(|_| ())
    }
}

/// A shared, in-memory key-value store, scoped per-capability by key PREFIX (§3.1's "a KV slice").
/// Multiple plugins/capabilities can share one [`KvStore`] while each only ever sees its own prefix's
/// keys — enforced by [`KvCapability::in_scope`], never by guest cooperation.
#[derive(Default)]
pub struct KvStore {
    inner: std::sync::Mutex<std::collections::BTreeMap<String, Vec<u8>>>,
}

impl KvStore {
    pub fn new() -> std::sync::Arc<KvStore> {
        std::sync::Arc::new(KvStore::default())
    }
    fn get(&self, key: &str) -> Option<Vec<u8>> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(key)
            .cloned()
    }
    fn set(&self, key: &str, value: Vec<u8>) {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key.to_string(), value);
    }
}

/// A [`KvStore`] handle scoped to one key prefix (§3.1). A guest may only get/set keys that start with
/// `prefix` — the host refuses anything else, so one plugin's KV slice can never read or clobber
/// another's even though they share the same backing store.
#[derive(Clone)]
pub struct KvCapability {
    store: std::sync::Arc<KvStore>,
    prefix: String,
}

impl KvCapability {
    pub fn new(store: std::sync::Arc<KvStore>, prefix: impl Into<String>) -> KvCapability {
        KvCapability {
            store,
            prefix: prefix.into(),
        }
    }
    fn in_scope(&self, key: &str) -> bool {
        key.starts_with(self.prefix.as_str())
    }
}

/// The capabilities granted for ONE sandboxed call (§3.1). `None` fields are simply absent host
/// imports — a guest importing `env.fs_read` when `fs_read` is `None` fails to instantiate exactly
/// like importing an unknown host function, because the [`Linker`] never defines it.
#[derive(Clone, Default)]
pub struct GrantedCapabilities {
    pub fs_read: Option<std::sync::Arc<FsReadCapability>>,
    pub kv: Option<KvCapability>,
}

impl GrantedCapabilities {
    pub fn none() -> GrantedCapabilities {
        GrantedCapabilities::default()
    }
    pub fn with_fs_read(mut self, cap: FsReadCapability) -> GrantedCapabilities {
        self.fs_read = Some(std::sync::Arc::new(cap));
        self
    }
    pub fn with_kv(mut self, cap: KvCapability) -> GrantedCapabilities {
        self.kv = Some(cap);
        self
    }
}

/// Host-function error codes returned to the GUEST as plain `i32`s (WASI-style — no exceptions cross
/// the ABI boundary). Negative = failure; a non-negative `fs_read`/`kv_get` result is the byte count
/// written into the guest-supplied output buffer.
const HOST_ERR_DENIED: i32 = -1; // ungranted (unreachable in practice — an ungranted fn is never linked)
const HOST_ERR_NOT_FOUND: i32 = -2; // file/key does not exist
const HOST_ERR_OUT_OF_SCOPE: i32 = -3; // path escapes root / key outside prefix
const HOST_ERR_BUFFER_TOO_SMALL: i32 = -4; // guest's output buffer can't hold the result
const HOST_ERR_BAD_UTF8: i32 = -5; // guest-supplied path/key was not valid UTF-8

impl WasmSandbox {
    /// Run `func_name(ptr,len)->(out_ptr,out_len)` (the same text ABI as
    /// [`WasmSandbox::run_with_input`]) but instantiate the module against a [`Linker`] carrying ONLY
    /// the host functions `caps` actually grants (§3.1). A module that imports a host function this
    /// call did NOT grant fails to instantiate — authority is granted by CONSTRUCTION, never ambient,
    /// exactly as the zero-import path proves, but now some calls legitimately get SOMETHING.
    ///
    /// Granted functions, when present:
    /// * `env.fs_read(path_ptr,path_len,out_ptr,out_cap) -> i32` — reads a file under
    ///   [`GrantedCapabilities::fs_read`]'s scoped root; returns the byte count written or a negative
    ///   `HOST_ERR_*` code. A path that escapes the root is refused by the HOST
    ///   (`HOST_ERR_OUT_OF_SCOPE`) regardless of how the guest phrases the traversal.
    /// * `env.kv_get(key_ptr,key_len,out_ptr,out_cap) -> i32` /
    ///   `env.kv_set(key_ptr,key_len,val_ptr,val_len) -> i32` — get/set a value in
    ///   [`GrantedCapabilities::kv`]'s store; a key outside the granted prefix is refused
    ///   (`HOST_ERR_OUT_OF_SCOPE`).
    ///
    /// Returns the decoded text output plus the sorted list of granted capability names the guest
    /// actually exercised (for honest audit — never claim a capability was "used" if it never was).
    /// Fuel/memory/output/wall-clock ceilings all still apply, identically to
    /// [`WasmSandbox::run_with_input`].
    pub fn run_with_capabilities(
        &self,
        module_bytes: &[u8],
        alloc_name: &str,
        func_name: &str,
        input: &str,
        caps: &GrantedCapabilities,
    ) -> Result<(TextOutput, Vec<&'static str>), SandboxError> {
        let in_len = i32::try_from(input.len()).map_err(|_| {
            SandboxError::Signature(format!(
                "input of {} bytes exceeds the i32 memory ABI limit",
                input.len()
            ))
        })?;

        let module = Module::new(&self.engine, module_bytes)
            .map_err(|e| SandboxError::Compile(format!("{e:#}")))?;

        let limits = StoreLimitsBuilder::new()
            .memory_size(self.config.max_memory_bytes)
            .build();
        let mut store = Store::new(
            &self.engine,
            HostState {
                limits,
                caps: Some(caps.clone()),
                used: std::collections::BTreeSet::new(),
            },
        );
        store.limiter(|state| &mut state.limits);
        store
            .set_fuel(self.config.fuel)
            .map_err(|e| SandboxError::Internal(format!("set_fuel: {e:#}")))?;
        store.set_epoch_deadline(1);

        let mut linker: Linker<HostState> = Linker::new(&self.engine);
        if caps.fs_read.is_some() {
            linker
                .func_wrap("env", "fs_read", host_fs_read)
                .map_err(|e| SandboxError::Internal(format!("linker fs_read: {e:#}")))?;
        }
        if caps.kv.is_some() {
            linker
                .func_wrap("env", "kv_get", host_kv_get)
                .map_err(|e| SandboxError::Internal(format!("linker kv_get: {e:#}")))?;
            linker
                .func_wrap("env", "kv_set", host_kv_set)
                .map_err(|e| SandboxError::Internal(format!("linker kv_set: {e:#}")))?;
        }

        let watchdog = self.arm_wallclock();
        let instance = match linker.instantiate(&mut store, &module) {
            Ok(instance) => instance,
            Err(err) => {
                if let Some(w) = watchdog {
                    w.disarm();
                }
                if let Some(trap) = err.downcast_ref::<Trap>() {
                    return Err(trap_to_error(trap));
                }
                // §3.1: the dominant cause is an ungranted import — the module asked for a host
                // function this call's Linker never defined.
                return Err(SandboxError::Instantiate(format!("{err:#}")));
            }
        };

        let memory: Memory = match instance.get_memory(&mut store, "memory") {
            Some(m) => m,
            None => {
                if let Some(w) = watchdog {
                    w.disarm();
                }
                return Err(SandboxError::Signature(
                    "guest exports no linear 'memory'".into(),
                ));
            }
        };
        let alloc = match instance.get_func(&mut store, alloc_name) {
            Some(f) => f,
            None => {
                if let Some(w) = watchdog {
                    w.disarm();
                }
                return Err(SandboxError::FuncNotFound(alloc_name.to_string()));
            }
        };
        let func = match instance.get_func(&mut store, func_name) {
            Some(f) => f,
            None => {
                if let Some(w) = watchdog {
                    w.disarm();
                }
                return Err(SandboxError::FuncNotFound(func_name.to_string()));
            }
        };

        let fuel_before = store.get_fuel().unwrap_or(self.config.fuel);

        let ptr = match self.call_i32_i32(&mut store, &alloc, in_len, alloc_name) {
            Ok(p) => p,
            Err(e) => {
                if let Some(w) = watchdog {
                    w.disarm();
                }
                return Err(e);
            }
        };
        if let Err(e) = memory.write(&mut store, ptr as usize, input.as_bytes()) {
            if let Some(w) = watchdog {
                w.disarm();
            }
            return Err(SandboxError::Trapped(format!(
                "writing input into guest memory failed: {e}"
            )));
        }

        let ty = func.ty(&store);
        if ty.params().count() != 2 || ty.results().count() != 2 {
            if let Some(w) = watchdog {
                w.disarm();
            }
            return Err(SandboxError::Signature(format!(
                "text-ABI function '{func_name}' must be (i32 ptr, i32 len) -> (i32 out_ptr, i32 out_len)"
            )));
        }
        let args = [Val::I32(ptr), Val::I32(in_len)];
        let mut call_results = [Val::I32(0), Val::I32(0)];
        let call_result = func.call(&mut store, &args, &mut call_results);
        if let Some(w) = watchdog {
            w.disarm();
        }
        if let Err(err) = call_result {
            return Err(self.trap_or_wallclock(&err));
        }
        let out_ptr = call_results[0]
            .i32()
            .ok_or_else(|| SandboxError::Signature("out_ptr is not an i32".into()))?;
        let out_len = call_results[1]
            .i32()
            .ok_or_else(|| SandboxError::Signature("out_len is not an i32".into()))?;

        let fuel_after = store.get_fuel().unwrap_or(0);
        let fuel_consumed = fuel_before.saturating_sub(fuel_after);

        if out_ptr < 0 || out_len < 0 {
            return Err(SandboxError::Trapped(format!(
                "guest returned a negative pointer/length ({out_ptr}, {out_len})"
            )));
        }
        let out_len = out_len as usize;
        if out_len > self.config.max_output_bytes {
            return Err(SandboxError::OutputTooLarge {
                produced: out_len,
                limit: self.config.max_output_bytes,
            });
        }
        let start = out_ptr as usize;
        let data = memory.data(&store);
        let end = start.checked_add(out_len).ok_or_else(|| {
            SandboxError::Trapped("guest output slice overflows the address space".into())
        })?;
        if end > data.len() {
            return Err(SandboxError::Trapped(format!(
                "guest output [{start}..{end}) is out of bounds (memory is {} bytes)",
                data.len()
            )));
        }
        let text = String::from_utf8(data[start..end].to_vec())
            .map_err(|_| SandboxError::Trapped("guest output is not valid UTF-8".into()))?;

        let used: Vec<&'static str> = store.data().used.iter().copied().collect();
        Ok((
            TextOutput {
                text,
                fuel_consumed,
            },
            used,
        ))
    }
}

/// Read `len` bytes of guest memory at `ptr` as a UTF-8 string, or `None` on an out-of-bounds/invalid
/// slice.
fn read_guest_utf8(caller: &mut Caller<'_, HostState>, ptr: i32, len: i32) -> Option<String> {
    if ptr < 0 || len < 0 {
        return None;
    }
    let memory = caller.get_export("memory")?.into_memory()?;
    let start = ptr as usize;
    let end = start.checked_add(len as usize)?;
    let data = memory.data(&*caller);
    if end > data.len() {
        return None;
    }
    String::from_utf8(data[start..end].to_vec()).ok()
}

/// Write `bytes` into the guest's output buffer at `(out_ptr, out_cap)`, returning the byte count
/// written or [`HOST_ERR_BUFFER_TOO_SMALL`] if it does not fit. The guest owns and pre-allocates the
/// buffer (a WASI-style convention) — the host never calls back into a guest allocator.
fn write_guest_buf(
    caller: &mut Caller<'_, HostState>,
    out_ptr: i32,
    out_cap: i32,
    bytes: &[u8],
) -> i32 {
    if out_ptr < 0 || out_cap < 0 || bytes.len() > out_cap as usize {
        return HOST_ERR_BUFFER_TOO_SMALL;
    }
    let Some(memory) = caller.get_export("memory").and_then(|e| e.into_memory()) else {
        return HOST_ERR_BUFFER_TOO_SMALL;
    };
    if memory.write(&mut *caller, out_ptr as usize, bytes).is_err() {
        return HOST_ERR_BUFFER_TOO_SMALL;
    }
    bytes.len() as i32
}

/// `env.fs_read(path_ptr, path_len, out_ptr, out_cap) -> i32` (§3.1). Only ever linked when
/// [`GrantedCapabilities::fs_read`] is `Some` — reachable at all only because authority was granted by
/// construction.
fn host_fs_read(
    mut caller: Caller<'_, HostState>,
    path_ptr: i32,
    path_len: i32,
    out_ptr: i32,
    out_cap: i32,
) -> i32 {
    let Some(path) = read_guest_utf8(&mut caller, path_ptr, path_len) else {
        return HOST_ERR_BAD_UTF8;
    };
    let Some(cap) = caller.data().caps.as_ref().and_then(|c| c.fs_read.clone()) else {
        return HOST_ERR_DENIED;
    };
    let bytes = match cap.read(&path) {
        Ok(b) => b,
        Err(()) => {
            // Distinguish "escaped the scoped root" from "just doesn't exist" for audit clarity —
            // both are refusals; `resolve` already enforces the boundary either way.
            if cap.resolve(&path).is_err() {
                return HOST_ERR_OUT_OF_SCOPE;
            }
            return HOST_ERR_NOT_FOUND;
        }
    };
    caller.data_mut().used.insert("fs.read");
    write_guest_buf(&mut caller, out_ptr, out_cap, &bytes)
}

/// `env.kv_get(key_ptr, key_len, out_ptr, out_cap) -> i32` (§3.1). Only ever linked when
/// [`GrantedCapabilities::kv`] is `Some`.
fn host_kv_get(
    mut caller: Caller<'_, HostState>,
    key_ptr: i32,
    key_len: i32,
    out_ptr: i32,
    out_cap: i32,
) -> i32 {
    let Some(key) = read_guest_utf8(&mut caller, key_ptr, key_len) else {
        return HOST_ERR_BAD_UTF8;
    };
    let Some(cap) = caller.data().caps.as_ref().and_then(|c| c.kv.clone()) else {
        return HOST_ERR_DENIED;
    };
    if !cap.in_scope(&key) {
        return HOST_ERR_OUT_OF_SCOPE;
    }
    let Some(value) = cap.store.get(&key) else {
        return HOST_ERR_NOT_FOUND;
    };
    caller.data_mut().used.insert("kv.get");
    write_guest_buf(&mut caller, out_ptr, out_cap, &value)
}

/// `env.kv_set(key_ptr, key_len, val_ptr, val_len) -> i32` (§3.1). Only ever linked when
/// [`GrantedCapabilities::kv`] is `Some`. Returns `0` on success or a negative `HOST_ERR_*` code.
fn host_kv_set(
    mut caller: Caller<'_, HostState>,
    key_ptr: i32,
    key_len: i32,
    val_ptr: i32,
    val_len: i32,
) -> i32 {
    let Some(key) = read_guest_utf8(&mut caller, key_ptr, key_len) else {
        return HOST_ERR_BAD_UTF8;
    };
    let value_bytes = {
        if val_ptr < 0 || val_len < 0 {
            None
        } else {
            let start = val_ptr as usize;
            let end = start.checked_add(val_len as usize);
            match caller.get_export("memory").and_then(|e| e.into_memory()) {
                Some(memory) => {
                    let data = memory.data(&caller);
                    match end {
                        Some(end) if end <= data.len() => Some(data[start..end].to_vec()),
                        _ => None,
                    }
                }
                None => None,
            }
        }
    };
    let Some(value_bytes) = value_bytes else {
        return HOST_ERR_BUFFER_TOO_SMALL;
    };
    let Some(cap) = caller.data().caps.as_ref().and_then(|c| c.kv.clone()) else {
        return HOST_ERR_DENIED;
    };
    if !cap.in_scope(&key) {
        return HOST_ERR_OUT_OF_SCOPE;
    }
    cap.store.set(&key, value_bytes);
    caller.data_mut().used.insert("kv.set");
    0
}

// ============================ PluginHost seam implementation ============================

use ainxt_plugin::{
    PluginError, PluginGrant, PluginHost, PluginManifest, PluginOutput, ResourceLimits,
};

/// The **real** WASM implementation of the [`ainxt_plugin::PluginHost`] seam.
///
/// `NativeHost` (in `ainxt-plugin`) enforces the capability + output + panic contract in-process for
/// trusted first-party plugins and tests; `WasmPluginHost` is the hard-isolation host for untrusted
/// third-party code, backed by [`WasmSandbox`]. It implements the *same* trait, so the composition the
/// security-boundary tests pin (`GuardedHost<H>` wrapping either host) is unchanged — this is the
/// "the wasmtime host drops in without changing the contract" claim made concrete.
///
/// # Isolation properties inherited from [`WasmSandbox`]
///
/// - **§3.1 authority granted by construction, never ambient.** Each module is instantiated against a
///   Linker carrying ONLY the `requested ∩ granted` host functions ([`run_with_capabilities`] via
///   [`resolve_granted_capabilities`]) — a module importing anything else fails to instantiate
///   ([`PluginError::Trap`]). A capability the guest was NOT granted is never linked at all, so there
///   is no ambient syscall surface; a capability it WAS granted (`fs.read`/`kv`, §3.1) IS a real,
///   scoped host import the guest can actually call — `used_capabilities` reports only what it
///   genuinely exercised, never the governance view of what it merely holds.
/// - **§3.2 dependency isolation.** Every invocation gets a FRESH `Store`/`Instance`, so one call's
///   guest state (globals, linear memory) never carries into another — modules are linked
///   independently with no shared mutable graph.
/// - **§3.5 hard resource ceilings.** Fuel bounds compute (an infinite loop traps as out-of-fuel, never
///   a hang), a `StoreLimits` cap bounds memory, an output-size cap bounds the result, and the
///   manifest's wall-clock budget is a REAL host-enforced ceiling via wasmtime epoch-interruption
///   (not cooperative) — all enforced by the runtime, not by guest cooperation.
///
/// # Legal / runtime gate
///
/// `wasmtime` is `Apache-2.0 WITH LLVM-exception` (permissive, but a distinct SPDX id); the reviewed
/// `deny.toml` exception (Gate #0) is already in place. The isolation code is real, wired as a real
/// [`PluginHost`] implementation, and exercised offline by the tests in this crate — the only
/// remaining item is a live wasm runtime present in the deployment image, which is a packaging
/// concern, not a code gap.
pub struct WasmPluginHost {
    /// id -> the plugin's wasm bytes (or inline WAT, since the `wat` feature is on).
    modules: std::collections::BTreeMap<String, Vec<u8>>,
    /// The guest's allocator export name (reserves writable bytes for the input).
    alloc_name: String,
    /// The guest's entrypoint export name (`(ptr,len)->(out_ptr,out_len)` text ABI).
    entry_name: String,
    /// Fuel granted per call (bounds compute; `ResourceLimits` has no instruction budget of its own).
    fuel: u64,
    /// The shared KV backing store for every `kv:<prefix>` grant this host resolves (§3.1). Shared
    /// ACROSS invocations and plugins so persistent state is possible when deliberately granted, per
    /// prefix — never ambient, never accidental.
    kv_store: std::sync::Arc<KvStore>,
}

impl WasmPluginHost {
    /// A host expecting the conventional `alloc` / `run` text-ABI exports and a conservative fuel
    /// budget.
    pub fn new() -> Self {
        WasmPluginHost {
            modules: std::collections::BTreeMap::new(),
            alloc_name: "alloc".to_string(),
            entry_name: "run".to_string(),
            fuel: SandboxConfig::conservative().fuel,
            kv_store: KvStore::new(),
        }
    }

    /// Override the allocator / entrypoint export names.
    pub fn with_abi(
        mut self,
        alloc_name: impl Into<String>,
        entry_name: impl Into<String>,
    ) -> Self {
        self.alloc_name = alloc_name.into();
        self.entry_name = entry_name.into();
        self
    }

    /// Override the per-call fuel budget (bounds compute).
    pub fn with_fuel(mut self, fuel: u64) -> Self {
        self.fuel = fuel;
        self
    }

    /// Register a plugin's wasm bytes (or inline WAT) under an id.
    pub fn register(&mut self, id: impl Into<String>, module_bytes: impl Into<Vec<u8>>) {
        self.modules.insert(id.into(), module_bytes.into());
    }

    /// The shared KV store backing every `kv:<prefix>` grant (§3.1) — exposed so a caller/test can
    /// pre-seed or inspect state across invocations.
    pub fn kv_store(&self) -> &std::sync::Arc<KvStore> {
        &self.kv_store
    }

    /// Map the seam's [`ResourceLimits`] onto a [`SandboxConfig`]: memory + output ceilings come from
    /// the manifest, the instruction (fuel) budget from the host.
    fn config_for(&self, limits: &ResourceLimits) -> SandboxConfig {
        SandboxConfig {
            fuel: self.fuel,
            max_memory_bytes: limits.max_memory_bytes,
            max_output_bytes: limits.max_output_bytes,
            // §3.5: the manifest's declared wall-clock budget is now a REAL host-enforced ceiling
            // for the WASM host — epoch-interruption, not a cooperative check. `0` means "no bound"
            // (matches `ResourceLimits::default`'s non-zero convention only when explicitly set to
            // zero by a caller), consistent with `GuardedHost`'s own `max_millis == 0` pass-through.
            max_wall_clock_ms: if limits.max_millis == 0 {
                None
            } else {
                Some(limits.max_millis)
            },
        }
    }
}

impl Default for WasmPluginHost {
    fn default() -> Self {
        Self::new()
    }
}

/// Translate a [`SandboxError`] into the seam's [`PluginError`] taxonomy, so a WASM failure reads the
/// same as a native one to every caller of the trait.
fn to_plugin_error(err: SandboxError) -> PluginError {
    match err {
        SandboxError::OutputTooLarge { produced, limit } => PluginError::OutputTooLarge {
            limit,
            actual: produced,
        },
        // Everything else — a trap, out-of-fuel, an ungranted import, a compile/signature failure — is
        // an isolated fault the host survives; it maps to the seam's Trap with the descriptive message.
        other => PluginError::Trap(other.to_string()),
    }
}

/// Resolve the requested∩granted capability set into concrete host imports (§3.1). Grant strings use
/// a small `capability:param` convention:
/// * `fs.read:<root-dir>` — a scoped filesystem-read rooted at `<root-dir>`.
/// * `kv:<prefix>` — KV access scoped to `<prefix>` in the host's shared [`KvStore`].
///
/// A capability is effective only if BOTH the plugin's manifest names its BARE form in
/// `requested_capabilities` (`fs.read`, `kv`) AND the grant supplies a matching parameterized entry —
/// the identical requested∩granted least-privilege discipline [`ainxt_plugin::NativeHost`] enforces,
/// made concrete for a host that can actually expose something to the guest. A grant string with no
/// matching request (or a request with no matching grant) resolves to nothing — the corresponding
/// host function is simply never linked, so a guest importing it fails to instantiate exactly like any
/// other ungranted import.
fn resolve_granted_capabilities(
    manifest: &PluginManifest,
    grant: &PluginGrant,
    kv_store: &std::sync::Arc<KvStore>,
) -> GrantedCapabilities {
    let requested: std::collections::BTreeSet<&str> = manifest
        .requested_capabilities
        .iter()
        .map(String::as_str)
        .collect();
    let mut caps = GrantedCapabilities::none();
    for g in &grant.granted {
        if let Some(root) = g.strip_prefix("fs.read:") {
            if requested.contains("fs.read") {
                if let Ok(cap) = FsReadCapability::new(root) {
                    caps = caps.with_fs_read(cap);
                }
            }
        } else if let Some(prefix) = g.strip_prefix("kv:") {
            if requested.contains("kv") {
                caps = caps.with_kv(KvCapability::new(std::sync::Arc::clone(kv_store), prefix));
            }
        }
    }
    caps
}

impl PluginHost for WasmPluginHost {
    fn invoke(
        &self,
        manifest: &PluginManifest,
        grant: &PluginGrant,
        input: &str,
    ) -> Result<PluginOutput, PluginError> {
        let bytes = self
            .modules
            .get(&manifest.id)
            .ok_or_else(|| PluginError::NotFound(manifest.id.clone()))?;

        let sandbox = WasmSandbox::new(self.config_for(&manifest.limits))
            .map_err(|e| PluginError::Trap(format!("engine init: {e}")))?;

        // §3.1: authority is granted by CONSTRUCTION — only the requested∩granted capabilities become
        // linkable host imports; anything else the guest imports fails to instantiate, exactly as the
        // zero-capability path always has.
        let caps = resolve_granted_capabilities(manifest, grant, &self.kv_store);
        let (text, used) = sandbox
            .run_with_capabilities(bytes, &self.alloc_name, &self.entry_name, input, &caps)
            .map_err(to_plugin_error)?;

        Ok(PluginOutput {
            output: text.text,
            // Honest audit: only capabilities the guest ACTUALLY exercised, never the governance
            // view of what it was merely granted.
            used_capabilities: used.into_iter().map(str::to_string).collect(),
        })
    }
}

// ============================ Tests ============================

#[cfg(test)]
mod tests {
    use super::*;

    const ADD_WAT: &str = r#"
        (module
          (func (export "add") (param i32 i32) (result i32)
            local.get 0
            local.get 1
            i32.add))
    "#;

    fn sandbox() -> WasmSandbox {
        WasmSandbox::new(SandboxConfig::default()).expect("engine builds")
    }

    #[test]
    fn add_returns_the_sum_and_encodes_it() {
        let out = sandbox()
            .run(ADD_WAT.as_bytes(), "add", &[Value::I32(40), Value::I32(2)])
            .expect("add runs");
        assert_eq!(out.values, vec![Value::I32(42)]);
        // Concrete encoding: 42 as little-endian i32. Fails if serialization is gutted.
        assert_eq!(out.encoded, 42_i32.to_le_bytes().to_vec());
        // Real work consumes fuel — a stubbed executor would report zero.
        assert!(out.fuel_consumed > 0, "expected fuel to be consumed");
    }

    #[test]
    fn add_computes_a_different_concrete_value() {
        // Second concrete case so the test can't be satisfied by hardcoding 42.
        let out = sandbox()
            .run(ADD_WAT.as_bytes(), "add", &[Value::I32(-5), Value::I32(12)])
            .expect("add runs");
        assert_eq!(out.values, vec![Value::I32(7)]);
        assert_eq!(out.encoded, 7_i32.to_le_bytes().to_vec());
    }

    #[test]
    fn i64_multiply_returns_correct_wide_value() {
        let wat = r#"
            (module
              (func (export "mul") (param i64 i64) (result i64)
                local.get 0
                local.get 1
                i64.mul))
        "#;
        let out = sandbox()
            .run(
                wat.as_bytes(),
                "mul",
                &[Value::I64(1_000_000), Value::I64(1_000_000)],
            )
            .expect("mul runs");
        assert_eq!(out.values, vec![Value::I64(1_000_000_000_000)]);
        assert_eq!(out.encoded, 1_000_000_000_000_i64.to_le_bytes().to_vec());
    }

    #[test]
    fn infinite_loop_is_stopped_by_fuel_not_a_hang() {
        // A finite fuel budget guarantees this returns rather than hanging the test runner.
        let cfg = SandboxConfig {
            fuel: 100_000,
            max_memory_bytes: 1 << 20,
            max_output_bytes: 1024,
            max_wall_clock_ms: None,
        };
        let sb = WasmSandbox::new(cfg).unwrap();
        let wat = r#"(module (func (export "spin") (loop br 0)))"#;
        let err = sb.run(wat.as_bytes(), "spin", &[]).unwrap_err();
        assert_eq!(err, SandboxError::OutOfFuel);
    }

    #[test]
    fn ungranted_import_fails_to_instantiate_zero_ambient_authority() {
        // The module asks for a host function it was never granted. It must not instantiate.
        let wat = r#"
            (module
              (import "env" "exfiltrate" (func (param i32)))
              (func (export "noop")))
        "#;
        let err = sandbox().run(wat.as_bytes(), "noop", &[]).unwrap_err();
        assert!(
            matches!(err, SandboxError::Instantiate(_)),
            "expected Instantiate, got {err:?}"
        );
    }

    #[test]
    fn imported_memory_also_denied() {
        // Authority via an imported memory is ambient authority too — also denied.
        let wat = r#"
            (module
              (import "env" "mem" (memory 1))
              (func (export "noop")))
        "#;
        let err = sandbox().run(wat.as_bytes(), "noop", &[]).unwrap_err();
        assert!(
            matches!(err, SandboxError::Instantiate(_)),
            "expected Instantiate, got {err:?}"
        );
    }

    #[test]
    fn unreachable_is_trapped_and_host_survives() {
        let sb = sandbox();
        let wat = r#"(module (func (export "boom") unreachable))"#;
        let err = sb.run(wat.as_bytes(), "boom", &[]).unwrap_err();
        assert!(
            matches!(err, SandboxError::Trapped(_)),
            "expected Trapped, got {err:?}"
        );

        // Host survived: the SAME sandbox still runs a subsequent module correctly.
        let out = sb
            .run(ADD_WAT.as_bytes(), "add", &[Value::I32(2), Value::I32(3)])
            .expect("sandbox still usable after a guest trap");
        assert_eq!(out.values, vec![Value::I32(5)]);
    }

    #[test]
    fn integer_divide_by_zero_is_trapped_not_a_crash() {
        let wat = r#"
            (module
              (func (export "div") (param i32 i32) (result i32)
                local.get 0
                local.get 1
                i32.div_s))
        "#;
        let err = sandbox()
            .run(wat.as_bytes(), "div", &[Value::I32(10), Value::I32(0)])
            .unwrap_err();
        assert!(
            matches!(err, SandboxError::Trapped(_)),
            "expected Trapped, got {err:?}"
        );
    }

    #[test]
    fn memory_grow_past_cap_fails_cleanly_returning_minus_one() {
        // Cap = exactly one 64 KiB page: the declared minimum fits, but growing beyond fails.
        let cfg = SandboxConfig {
            fuel: 10_000_000,
            max_memory_bytes: 65_536,
            max_output_bytes: 1024,
            max_wall_clock_ms: None,
        };
        let sb = WasmSandbox::new(cfg).unwrap();
        let wat = r#"
            (module
              (memory 1)
              (func (export "grow") (result i32)
                (memory.grow (i32.const 10))))
        "#;
        let out = sb
            .run(wat.as_bytes(), "grow", &[])
            .expect("grow runs (cleanly, no trap)");
        // memory.grow returns -1 when the runtime refuses the growth — a clean failure.
        assert_eq!(out.values, vec![Value::I32(-1)]);
    }

    #[test]
    fn declared_memory_above_cap_fails_to_instantiate() {
        // Two pages declared as the minimum, but the cap only permits one.
        let cfg = SandboxConfig {
            fuel: 1_000_000,
            max_memory_bytes: 65_536,
            max_output_bytes: 1024,
            max_wall_clock_ms: None,
        };
        let sb = WasmSandbox::new(cfg).unwrap();
        let wat = r#"(module (memory 2) (func (export "noop")))"#;
        let err = sb.run(wat.as_bytes(), "noop", &[]).unwrap_err();
        assert!(
            matches!(err, SandboxError::Instantiate(_)),
            "expected Instantiate, got {err:?}"
        );
    }

    #[test]
    fn oversized_output_is_rejected() {
        // A function returning two i64 (16 bytes) against an 8-byte output cap.
        let cfg = SandboxConfig {
            fuel: 1_000_000,
            max_memory_bytes: 1 << 20,
            max_output_bytes: 8,
            max_wall_clock_ms: None,
        };
        let sb = WasmSandbox::new(cfg).unwrap();
        let wat = r#"
            (module
              (func (export "pair") (result i64 i64)
                i64.const 1
                i64.const 2))
        "#;
        let err = sb.run(wat.as_bytes(), "pair", &[]).unwrap_err();
        assert_eq!(
            err,
            SandboxError::OutputTooLarge {
                produced: 16,
                limit: 8
            }
        );
    }

    #[test]
    fn output_exactly_at_cap_is_accepted() {
        // Boundary: 16 bytes with a 16-byte cap must pass (off-by-one guard).
        let cfg = SandboxConfig {
            fuel: 1_000_000,
            max_memory_bytes: 1 << 20,
            max_output_bytes: 16,
            max_wall_clock_ms: None,
        };
        let sb = WasmSandbox::new(cfg).unwrap();
        let wat = r#"
            (module
              (func (export "pair") (result i64 i64)
                i64.const 7
                i64.const 9))
        "#;
        let out = sb
            .run(wat.as_bytes(), "pair", &[])
            .expect("at-cap output accepted");
        assert_eq!(out.values, vec![Value::I64(7), Value::I64(9)]);
        assert_eq!(out.encoded.len(), 16);
    }

    #[test]
    fn missing_export_is_reported() {
        let err = sandbox()
            .run(ADD_WAT.as_bytes(), "does_not_exist", &[])
            .unwrap_err();
        assert_eq!(
            err,
            SandboxError::FuncNotFound("does_not_exist".to_string())
        );
    }

    #[test]
    fn wrong_argument_arity_is_rejected_before_call() {
        let err = sandbox()
            .run(ADD_WAT.as_bytes(), "add", &[Value::I32(1)])
            .unwrap_err();
        assert!(
            matches!(err, SandboxError::Signature(_)),
            "expected Signature, got {err:?}"
        );
    }

    #[test]
    fn wrong_argument_type_is_rejected_before_call() {
        // `add` wants (i32, i32); passing an i64 first is a type mismatch.
        let err = sandbox()
            .run(ADD_WAT.as_bytes(), "add", &[Value::I64(1), Value::I32(2)])
            .unwrap_err();
        assert!(
            matches!(err, SandboxError::Signature(_)),
            "expected Signature, got {err:?}"
        );
    }

    #[test]
    fn invalid_module_bytes_fail_to_compile() {
        let err = sandbox()
            .run(b"(module (this is not valid wat", "x", &[])
            .unwrap_err();
        assert!(
            matches!(err, SandboxError::Compile(_)),
            "expected Compile, got {err:?}"
        );
    }

    #[test]
    fn zero_result_function_returns_empty_output() {
        let wat = r#"(module (func (export "noop")))"#;
        let out = sandbox()
            .run(wat.as_bytes(), "noop", &[])
            .expect("noop runs");
        assert!(out.values.is_empty());
        assert!(out.encoded.is_empty());
    }

    #[test]
    fn config_is_exposed() {
        let cfg = SandboxConfig {
            fuel: 42,
            max_memory_bytes: 4096,
            max_output_bytes: 256,
            max_wall_clock_ms: None,
        };
        let sb = WasmSandbox::new(cfg).unwrap();
        assert_eq!(*sb.config(), cfg);
    }

    // ============================ r15: WasmPluginHost — the real Extend-level PluginHost ============================
    //
    // `WasmPluginHost` (the `ainxt_plugin::PluginHost` implementation) had ZERO tests despite being
    // fully wired — these close that gap: a manifest/grant flows through the SAME seam `NativeHost`
    // implements, capabilities are real host imports (not decorative), and every PluginHost failure
    // mode (NotFound / OutputTooLarge / Trap-on-ungranted-import) round-trips through the real sandbox.

    /// Pure computation, no host imports at all: echoes the input back as the output. Must instantiate
    /// and run under `GrantedCapabilities::none()` — zero ambient authority never blocks a plugin that
    /// asked for nothing.
    const ECHO_WAT: &str = r#"
        (module
          (memory (export "memory") 1)
          (func (export "alloc") (param $size i32) (result i32) (i32.const 4096))
          (func (export "run") (param $ptr i32) (param $len i32) (result i32 i32)
            local.get $ptr
            local.get $len))
    "#;

    /// Imports `env.fs_read` — fails to instantiate unless the host actually links it (i.e. the
    /// capability was requested AND granted).
    const FS_READ_IMPORTING_WAT: &str = r#"
        (module
          (import "env" "fs_read" (func $fs_read (param i32 i32 i32 i32) (result i32)))
          (memory (export "memory") 1)
          (func (export "alloc") (param $size i32) (result i32) (i32.const 4096))
          (func (export "run") (param $path_ptr i32) (param $path_len i32) (result i32 i32)
            (local $n i32)
            (local.set $n (call $fs_read (local.get $path_ptr) (local.get $path_len) (i32.const 2048) (i32.const 512)))
            (if (i32.lt_s (local.get $n) (i32.const 0))
              (then (return (i32.const 0) (i32.const 0))))
            (i32.const 2048)
            (local.get $n)))
    "#;

    /// Treats the input as a KV key and stores `value = key` under it via `env.kv_set`.
    const KV_SET_WAT: &str = r#"
        (module
          (import "env" "kv_set" (func $kv_set (param i32 i32 i32 i32) (result i32)))
          (memory (export "memory") 1)
          (func (export "alloc") (param $size i32) (result i32) (i32.const 4096))
          (func (export "run") (param $key_ptr i32) (param $key_len i32) (result i32 i32)
            (drop (call $kv_set (local.get $key_ptr) (local.get $key_len) (local.get $key_ptr) (local.get $key_len)))
            (i32.const 0)
            (i32.const 0)))
    "#;

    /// Treats the input as a KV key and reads the value back via `env.kv_get`.
    const KV_GET_WAT: &str = r#"
        (module
          (import "env" "kv_get" (func $kv_get (param i32 i32 i32 i32) (result i32)))
          (memory (export "memory") 1)
          (func (export "alloc") (param $size i32) (result i32) (i32.const 4096))
          (func (export "run") (param $key_ptr i32) (param $key_len i32) (result i32 i32)
            (local $n i32)
            (local.set $n (call $kv_get (local.get $key_ptr) (local.get $key_len) (i32.const 2048) (i32.const 512)))
            (if (i32.lt_s (local.get $n) (i32.const 0))
              (then (return (i32.const 0) (i32.const 0))))
            (i32.const 2048)
            (local.get $n)))
    "#;

    fn pm(id: &str, caps: &[&str]) -> PluginManifest {
        PluginManifest {
            id: id.to_string(),
            requested_capabilities: caps.iter().map(|s| s.to_string()).collect(),
            limits: ResourceLimits::default(),
        }
    }

    #[test]
    fn r15_wasm_host_runs_a_pure_plugin_with_zero_capabilities() {
        let mut host = WasmPluginHost::new();
        host.register("echo", ECHO_WAT.as_bytes());
        let out = host
            .invoke(&pm("echo", &[]), &PluginGrant::default(), "hello")
            .expect("pure computation needs no capability");
        assert_eq!(out.output, "hello");
        assert!(out.used_capabilities.is_empty());
    }

    #[test]
    fn r15_wasm_host_denies_an_ungranted_capability_by_failing_to_link() {
        // Requested but NOT granted: the host function is never defined, so the guest's import fails
        // to instantiate — authority denied by CONSTRUCTION, not a runtime permission check.
        let mut host = WasmPluginHost::new();
        host.register("reader", FS_READ_IMPORTING_WAT.as_bytes());
        let err = host
            .invoke(
                &pm("reader", &["fs.read"]),
                &PluginGrant::default(),
                "secret.txt",
            )
            .expect_err("an ungranted fs.read import must fail to instantiate");
        assert!(
            matches!(err, PluginError::Trap(_)),
            "expected Trap, got {err:?}"
        );
    }

    #[test]
    fn r15_wasm_host_denies_fs_read_when_the_manifest_never_requested_it() {
        // Granted but not REQUESTED: `resolve_granted_capabilities` only links a capability that is
        // BOTH requested and granted — least privilege on both axes, exactly like `NativeHost`.
        let dir = std::env::temp_dir().join(format!("ainxt-wasm-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("secret.txt"), b"top secret").unwrap();

        let mut host = WasmPluginHost::new();
        host.register("reader", FS_READ_IMPORTING_WAT.as_bytes());
        let grant = PluginGrant::new([format!("fs.read:{}", dir.display())]);
        // Manifest never lists "fs.read" among its requested_capabilities.
        let err = host
            .invoke(&pm("reader", &[]), &grant, "secret.txt")
            .expect_err("a granted-but-unrequested capability must not be linked");
        assert!(
            matches!(err, PluginError::Trap(_)),
            "expected Trap, got {err:?}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn r15_wasm_host_fs_read_capability_is_a_real_host_import_that_actually_reads() {
        let dir =
            std::env::temp_dir().join(format!("ainxt-wasm-test-fsread-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("secret.txt"), b"top secret contents").unwrap();

        let mut host = WasmPluginHost::new();
        host.register("reader", FS_READ_IMPORTING_WAT.as_bytes());
        let grant = PluginGrant::new([format!("fs.read:{}", dir.display())]);
        let out = host
            .invoke(&pm("reader", &["fs.read"]), &grant, "secret.txt")
            .expect("requested + granted fs.read must actually read the file");
        assert_eq!(out.output, "top secret contents");
        // Honest audit: the capability was ACTUALLY exercised, not just held.
        assert_eq!(out.used_capabilities, vec!["fs.read".to_string()]);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn r15_wasm_host_fs_read_cannot_escape_its_scoped_root() {
        let dir =
            std::env::temp_dir().join(format!("ainxt-wasm-test-escape-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let mut host = WasmPluginHost::new();
        host.register("reader", FS_READ_IMPORTING_WAT.as_bytes());
        let grant = PluginGrant::new([format!("fs.read:{}", dir.display())]);
        // A `..` traversal attempting to reach outside the scoped root yields an empty (host-refused)
        // read, never an escape — the guest's own ABI returns (0,0) when the host function reports a
        // negative (refused) code.
        let out = host
            .invoke(&pm("reader", &["fs.read"]), &grant, "../../../etc/passwd")
            .expect("the call itself succeeds; the host merely refuses the read");
        assert_eq!(
            out.output, "",
            "an out-of-scope path must never be readable"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn r15_wasm_host_kv_capability_is_shared_and_scoped_across_invocations() {
        // Every invocation gets a FRESH Store/Instance, but the KV STORE is shared across invocations
        // on the same host — proving persistent state is possible when deliberately granted, per
        // prefix, never ambient.
        let mut host = WasmPluginHost::new();
        host.register("kv_set", KV_SET_WAT.as_bytes());
        host.register("kv_get", KV_GET_WAT.as_bytes());
        let grant = PluginGrant::new(["kv:tenant-a:"]);

        let set_out = host
            .invoke(&pm("kv_set", &["kv"]), &grant, "tenant-a:mykey")
            .expect("kv.set must succeed under a granted+requested kv capability");
        assert_eq!(set_out.used_capabilities, vec!["kv.set".to_string()]);

        let get_out = host
            .invoke(&pm("kv_get", &["kv"]), &grant, "tenant-a:mykey")
            .expect("kv.get must read back what kv.set persisted");
        assert_eq!(get_out.output, "tenant-a:mykey");
        assert_eq!(get_out.used_capabilities, vec!["kv.get".to_string()]);

        // A key outside the granted prefix is refused (empty read), never leaked cross-tenant.
        let other_grant = PluginGrant::new(["kv:tenant-b:"]);
        let denied = host
            .invoke(&pm("kv_get", &["kv"]), &other_grant, "tenant-a:mykey")
            .expect("the call succeeds; the host refuses the out-of-scope key");
        assert_eq!(
            denied.output, "",
            "a different tenant's prefix must never read tenant-a's key"
        );
    }

    #[test]
    fn r15_wasm_host_reports_not_found_for_an_unregistered_id() {
        let host = WasmPluginHost::new();
        let err = host
            .invoke(&pm("does-not-exist", &[]), &PluginGrant::default(), "hi")
            .expect_err("an unregistered plugin id must be refused");
        assert!(matches!(err, PluginError::NotFound(id) if id == "does-not-exist"));
    }

    #[test]
    fn r15_wasm_host_enforces_output_too_large_through_the_seam() {
        let mut host = WasmPluginHost::new();
        host.register("echo", ECHO_WAT.as_bytes());
        let mut manifest = pm("echo", &[]);
        manifest.limits.max_output_bytes = 4; // "hello" (5 bytes) exceeds this
        let err = host
            .invoke(&manifest, &PluginGrant::default(), "hello")
            .expect_err("an over-limit output must be refused");
        assert_eq!(
            err,
            PluginError::OutputTooLarge {
                limit: 4,
                actual: 5
            }
        );
    }

    #[test]
    fn r15_wasm_host_is_drop_in_compatible_with_the_guarded_host_decorator() {
        // The exact composition claim the doc makes: GuardedHost<H> wraps ANY PluginHost, including
        // WasmPluginHost, unchanged — proving the wall-clock decorator and the WASM host compose.
        use ainxt_plugin::GuardedHost;
        let mut inner = WasmPluginHost::new();
        inner.register("echo", ECHO_WAT.as_bytes());
        let guarded = GuardedHost::new(inner);
        let mut manifest = pm("echo", &[]);
        manifest.limits.max_millis = 5_000; // generous — this call is instant
        let out = guarded
            .invoke(&manifest, &PluginGrant::default(), "wrapped")
            .expect("WasmPluginHost must drop in behind GuardedHost unchanged");
        assert_eq!(out.output, "wrapped");
    }
}
