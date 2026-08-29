// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Sandboxed **arbitrary user-code** execution-skill executor — the OS-process half of the
//! isolation-host seam (gap SURF-05, "Docker/native-process sandbox"). Where [`super::WasmSkillExecutor`]
//! runs a compiled WASM module and [`super::NativeSkillExecutor`] runs a trusted compiled-in Rust
//! handler, this runs a skill's manifest `body` as literal source for a real, separate OS process
//! (e.g. `/bin/sh -c <body>`) — the tier that lets a skill author ship an actual shell/Python snippet
//! without recompiling the runtime.
//!
//! **Honest scope.** This is the NATIVE-PROCESS tier, not a container. It gives:
//!
//! - **cleared environment** — the child inherits no ambient env vars (only an explicit allow-list,
//!   `PATH` by default) so host secrets/API keys never leak into the script;
//! - **an isolated, disposable working directory** — a fresh empty temp dir per invocation, removed
//!   afterwards, so the script has no default access to real repository files;
//! - **a hard wall-clock timeout** — a watcher thread kills the child if it outlives the configured
//!   budget, so a hanging/looping script can never hang the turn;
//! - **an output-size ceiling** — the reader kills the child and fails closed the moment captured
//!   stdout exceeds the ceiling, so a runaway/binary-spewing script can never blow up the prompt;
//! - **fail-closed process semantics** — a non-zero exit, a spawn failure, or non-UTF-8 output is a
//!   [`SkillError::Execution`], never a silently-empty or truncated context injection.
//!
//! It does **NOT** provide container-grade isolation: no network namespace, no cgroup memory/CPU cap,
//! no syscall filter. A deployment that needs that (the `--network none`, memory/CPU-capped Docker
//! tier CLAUDE.md describes for the Python platform's `sandbox/docker_executor.py`) needs a live
//! Docker daemon, which is genuinely infra — out of scope for this offline runtime crate. This
//! executor is the real, immediately-usable tier that does not require any infra to exist or be
//! tested.
//!
//! `unsafe_code = "forbid"` is honored throughout: every isolation property here is built from safe
//! `std::process` primitives (no raw `libc`/`rlimit` calls).
//!
//! GAP-AUDIT gap6-composition-root (Item 2) — DECISION: NOT registered as a
//! [`super::DispatchingSkillExecutor`] tier in the served composition root
//! (`ainxt-runtimed::build_skill_runtime`/`build_skill_runtime_from_config`). Investigated: no
//! `SkillManifest`/`SkillType` field, no compiled-in builtin skill, and no git-native
//! `definition.md` front-matter convention (a closed, fail-closed field set — see
//! `ainxt_skill::control`) ever declares a "run my body as a literal shell/Python script" execution
//! mode; every `Execution`-type skill not registered on `WasmSkillExecutor` falls back to
//! `NativeSkillExecutor`, whose contract is a compiled-in Rust handler keyed by skill id, with
//! `body` read as PARAMETERS, never as source. Wiring this executor into the served path today would
//! require fabricating both a new skill category and an interpreter policy with no real
//! caller-declared use case behind either. See `build_skill_runtime`'s own doc comment in
//! `ainxt-runtimed` for the full investigation trail.

use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use super::{SkillError, SkillExecutor, SkillManifest, DEFAULT_MAX_SKILL_OUTPUT_BYTES};

static SANDBOX_SEQ: AtomicU64 = AtomicU64::new(0);

/// A **sandboxed, arbitrary-user-code** execution-skill executor: every registered skill's manifest
/// `body` is run as literal source for a fresh, isolated OS process (see module docs for the exact
/// isolation properties and their honest limits). All skills routed through one executor instance
/// share the same interpreter (e.g. `["/bin/sh", "-c"]` or `["python3", "-c"]`) — a deployment builds
/// one executor per language/runtime it wants to offer.
pub struct NativeProcessSkillExecutor {
    /// `interpreter[0]` is the program; `interpreter[1..]` are fixed leading args (e.g. `-c`). The
    /// skill's manifest `body` is appended as the final argument (never interpolated into a shell
    /// string the executor itself builds — it is a single argv entry, exactly as the OS hands it to
    /// the child's `argv[]`).
    interpreter: Vec<String>,
    /// Hard wall-clock budget; a child still running after this is killed (never hangs the turn).
    timeout: Duration,
    /// Output-size ceiling in bytes; captured stdout over this kills the child and fails closed.
    max_output_bytes: usize,
    /// Extra environment variables granted to the child (name, value), on top of the cleared base
    /// environment. `PATH` is always granted from the host so the interpreter can be found on `$PATH`
    /// unless the caller already grants its own `PATH`.
    env_allowlist: Vec<(String, String)>,
}

impl NativeProcessSkillExecutor {
    /// Build an executor for `interpreter` (must be non-empty — `interpreter[0]` is the program to
    /// spawn) with conservative defaults: a 5-second timeout and the crate's standard output ceiling.
    pub fn new(interpreter: Vec<String>) -> Self {
        NativeProcessSkillExecutor {
            interpreter,
            timeout: Duration::from_secs(5),
            max_output_bytes: DEFAULT_MAX_SKILL_OUTPUT_BYTES,
            env_allowlist: Vec::new(),
        }
    }

    /// Convenience constructor for a POSIX-shell interpreter (`/bin/sh -c <body>`).
    pub fn posix_shell() -> Self {
        Self::new(vec!["/bin/sh".to_string(), "-c".to_string()])
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_max_output_bytes(mut self, max_output_bytes: usize) -> Self {
        self.max_output_bytes = max_output_bytes;
        self
    }

    /// Grant one additional environment variable to every spawned child (on top of the cleared base
    /// environment). Use sparingly — every grant widens what the arbitrary script can read.
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env_allowlist.push((key.into(), value.into()));
        self
    }

    fn spawn(&self, source: &str) -> Result<Child, String> {
        if self.interpreter.is_empty() {
            return Err("no interpreter configured".to_string());
        }
        let mut cmd = Command::new(&self.interpreter[0]);
        cmd.args(&self.interpreter[1..]);
        cmd.arg(source);
        // Cleared environment: the child inherits nothing ambient. `PATH` is granted from the host by
        // default so the interpreter itself (and anything it shells out to) can be located; a caller
        // that wants a fully bare environment can override via a future `without_path` if ever needed.
        cmd.env_clear();
        if let Ok(path) = std::env::var("PATH") {
            cmd.env("PATH", path);
        }
        for (k, v) in &self.env_allowlist {
            cmd.env(k, v);
        }
        let sandbox_dir = std::env::temp_dir().join(format!(
            "ainxt-skill-sandbox-{}-{}",
            std::process::id(),
            SANDBOX_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&sandbox_dir)
            .map_err(|e| format!("failed to create sandbox working dir: {e}"))?;
        cmd.current_dir(&sandbox_dir);
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        let child = cmd
            .spawn()
            .map_err(|e| format!("failed to spawn sandboxed process: {e}"))?;
        // Best-effort cleanup; a leaked empty temp dir is not a correctness issue and must never fail
        // the invocation.
        let _ = std::fs::remove_dir_all(&sandbox_dir);
        Ok(child)
    }
}

impl SkillExecutor for NativeProcessSkillExecutor {
    fn execute(&self, skill: &SkillManifest, user_input: &str) -> Result<String, SkillError> {
        let mut child = self
            .spawn(&skill.body)
            .map_err(|message| SkillError::Execution {
                skill: skill.id.clone(),
                message,
            })?;

        // Feed the user turn on stdin, off the main thread, so a script that reads stdin before
        // writing output cannot deadlock against a blocked writer.
        if let Some(mut stdin) = child.stdin.take() {
            let input = user_input.to_string();
            let _ = thread::spawn(move || {
                let _ = stdin.write_all(input.as_bytes());
            });
        }
        let mut stdout = child.stdout.take();

        let child = Arc::new(Mutex::new(child));
        let done = Arc::new(Mutex::new(false));

        // Watcher thread: kill the child if it outlives the timeout. Never hangs the turn.
        let watcher_child = Arc::clone(&child);
        let watcher_done = Arc::clone(&done);
        let timeout = self.timeout;
        let watcher = thread::spawn(move || {
            let start = Instant::now();
            loop {
                if *watcher_done.lock().unwrap() {
                    return;
                }
                if start.elapsed() >= timeout {
                    if let Ok(mut c) = watcher_child.lock() {
                        let _ = c.kill();
                    }
                    return;
                }
                thread::sleep(Duration::from_millis(20));
            }
        });

        // Read capped stdout on the main thread; overflow kills the child and fails closed.
        let mut buf: Vec<u8> = Vec::new();
        let mut overflow = false;
        if let Some(out) = stdout.as_mut() {
            let mut chunk = [0u8; 4096];
            loop {
                match out.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        buf.extend_from_slice(&chunk[..n]);
                        if buf.len() > self.max_output_bytes {
                            overflow = true;
                            if let Ok(mut c) = child.lock() {
                                let _ = c.kill();
                            }
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        }

        *done.lock().unwrap() = true;
        let _ = watcher.join();
        let status = child.lock().unwrap().wait();

        if overflow {
            return Err(SkillError::Execution {
                skill: skill.id.clone(),
                message: format!(
                    "sandboxed output exceeded the {}-byte ceiling (process killed)",
                    self.max_output_bytes
                ),
            });
        }
        match status {
            Ok(st) if st.success() => String::from_utf8(buf).map_err(|_| SkillError::Execution {
                skill: skill.id.clone(),
                message: "sandboxed output was not valid UTF-8".to_string(),
            }),
            Ok(st) => Err(SkillError::Execution {
                skill: skill.id.clone(),
                message: format!(
                    "sandboxed process exited with status {:?} (killed after {:?} if it hung)",
                    st.code(),
                    self.timeout
                ),
            }),
            Err(e) => Err(SkillError::Execution {
                skill: skill.id.clone(),
                message: format!("failed to wait on sandboxed process: {e}"),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SkillManifest;

    fn sh() -> NativeProcessSkillExecutor {
        NativeProcessSkillExecutor::posix_shell().with_timeout(Duration::from_millis(800))
    }

    #[test]
    fn r15_runs_a_real_process_and_captures_stdout() {
        let exec = sh();
        let skill = SkillManifest::execution("echoer", "printf '%s' hello-from-sandbox");
        let out = exec.execute(&skill, "").unwrap();
        assert_eq!(out, "hello-from-sandbox");
    }

    #[test]
    fn r15_user_turn_reaches_the_child_via_stdin() {
        let exec = sh();
        let skill = SkillManifest::execution("catter", "cat");
        let out = exec.execute(&skill, "ping-123").unwrap();
        assert_eq!(out, "ping-123");
    }

    #[test]
    fn r15_a_hanging_process_is_killed_by_the_timeout_not_left_to_hang() {
        let exec =
            NativeProcessSkillExecutor::posix_shell().with_timeout(Duration::from_millis(150));
        let skill = SkillManifest::execution("hanger", "sleep 30");
        let start = Instant::now();
        let err = exec.execute(&skill, "").unwrap_err();
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "the sandbox must kill a hanging child promptly, not wait out the real sleep: {:?}",
            start.elapsed()
        );
        assert!(matches!(err, SkillError::Execution { .. }));
    }

    #[test]
    fn r15_output_ceiling_kills_the_child_and_fails_closed() {
        let exec = sh().with_max_output_bytes(16);
        // Emits far more than the 16-byte ceiling.
        let skill = SkillManifest::execution("flooder", "head -c 100000 /dev/zero");
        let err = exec.execute(&skill, "").unwrap_err();
        match err {
            SkillError::Execution { message, .. } => {
                assert!(message.contains("ceiling"), "unexpected message: {message}")
            }
            other => panic!("expected Execution error, got {other:?}"),
        }
    }

    #[test]
    fn r15_nonzero_exit_is_a_hard_error() {
        let exec = sh();
        let skill = SkillManifest::execution("failer", "exit 3");
        let err = exec.execute(&skill, "").unwrap_err();
        assert!(matches!(err, SkillError::Execution { .. }));
    }

    #[test]
    fn r15_environment_is_cleared_ambient_secrets_never_reach_the_child() {
        std::env::set_var("AINXT_SANDBOX_TEST_SECRET", "top-secret-value");
        let exec = sh();
        let skill =
            SkillManifest::execution("leaker", "printf '[%s]' \"$AINXT_SANDBOX_TEST_SECRET\"");
        let out = exec.execute(&skill, "").unwrap();
        std::env::remove_var("AINXT_SANDBOX_TEST_SECRET");
        assert_eq!(
            out, "[]",
            "an ambient host env var must never reach the sandboxed child: {out}"
        );
    }

    #[test]
    fn r15_an_explicitly_granted_env_var_does_reach_the_child() {
        let exec = sh().with_env("AINXT_SANDBOX_GRANTED", "granted-value");
        let skill = SkillManifest::execution("reader", "printf '%s' \"$AINXT_SANDBOX_GRANTED\"");
        let out = exec.execute(&skill, "").unwrap();
        assert_eq!(out, "granted-value");
    }

    #[test]
    fn r15_no_registered_interpreter_fails_closed() {
        let exec = NativeProcessSkillExecutor::new(Vec::new());
        let skill = SkillManifest::execution("x", "echo hi");
        let err = exec.execute(&skill, "").unwrap_err();
        assert!(matches!(err, SkillError::Execution { .. }));
    }
}
