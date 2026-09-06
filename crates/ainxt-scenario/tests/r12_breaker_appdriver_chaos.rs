// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-12 gap-closing integration test (eval-tester-scenarios, LOW):
//! **"Breaker drives the REAL app (browser/computer-use/CLI-pty) + gated chaos/fault injection
//! (AGENT_TESTER §3/§5)."**
//!
//! Driving a live browser/CLI-pty/computer-use surface and killing real processes needs an authorized
//! test environment (infra-gated). What is closable offline is proof that (a) the exploration loop
//! drives the `AppDriver` seam unchanged — via `TargetAppDriver` / `AppDriverTarget` — and that (b) a
//! failure surfaced ONLY by an injected `ChaosController` fault is caught, verified and minimized like
//! any other finding.
//!
//! Fail-before: `TargetAppDriver` / `AppDriverTarget` / `ScriptedChaos` / `ChaosDriver` did not exist.
//! Pass-after: with no fault the app is clean; injecting `worker-kill` makes the Breaker (driving the
//! app through the `AppDriver` seam) find, verify and minimize the induced crash; an unknown fault is
//! refused; `clear()` restores the app.

use ainxt_scenario::breaker::{
    AppDriver, AppDriverTarget, Breaker, ChaosController, ChaosDriver, ListLens, ScriptedChaos,
};
use ainxt_scenario::{Category, CrashOracle, Expectation, Observation, Scenario};

/// A benign "real app" behind the AppDriver seam: echoes, never errors on its own.
struct EchoApp;
impl AppDriver for EchoApp {
    fn drive(&mut self, s: &Scenario) -> Observation {
        Observation {
            output: format!("ok: {}", s.input),
            error: None,
            side_effects: vec![],
            latency_ms: 1,
        }
    }
}

fn crash_hunting_breaker() -> Breaker {
    let lens = ListLens::new(
        "chaos",
        vec![Scenario::new(
            "CH-1",
            "drive under load",
            Category::Custom,
            "run the settlement batch now please",
            Expectation {
                must_complete: true,
                ..Default::default()
            },
        )],
    );
    Breaker::new(vec![Box::new(CrashOracle)], vec![Box::new(lens)])
}

#[test]
fn r12_breaker_appdriver_chaos() {
    let breaker = crash_hunting_breaker();

    // --- 1. No fault injected: the app is clean, the Breaker finds nothing (driving the seam). -----
    {
        let mut driver =
            ChaosDriver::new(EchoApp, ScriptedChaos::new(&["worker-kill", "net-drop"]));
        let target = AppDriverTarget::new(&mut driver);
        let report = breaker.explore(&target);
        assert!(
            !report.has_findings(),
            "with no injected fault the real app is clean: {:?}",
            report.findings
        );
        assert!(report.total_drives >= 1, "the seam WAS driven");
    }

    // --- 2. Inject a process-kill fault: the crash now manifests ONLY under chaos and is caught. ---
    {
        let mut driver =
            ChaosDriver::new(EchoApp, ScriptedChaos::new(&["worker-kill", "net-drop"]));
        assert!(driver.inject("worker-kill"), "a catalogued fault injects");
        assert!(
            !driver.inject("meltdown-9000"),
            "an uncatalogued fault is refused, never silently 'injected'"
        );
        let target = AppDriverTarget::new(&mut driver);
        let report = breaker.explore(&target);
        assert!(
            report.has_findings(),
            "the injected crash must be found by driving the app under chaos"
        );
        let f = &report.findings[0];
        assert_eq!(f.oracle, "crash");
        assert!(
            f.reason.contains("crash") || f.reason.contains("error"),
            "the finding names the injected crash: {}",
            f.reason
        );
        // A minimized reproducing input is recorded (the crash fires regardless of input, so ddmin
        // shrinks the verbose scenario toward its 1-minimal form).
        assert!(
            !f.minimized_input.is_empty(),
            "a minimized repro is recorded: {:?}",
            f.minimized_input
        );
    }

    // --- 3. clear() restores the app — the fault is no longer active. -----------------------------
    {
        let mut driver = ChaosDriver::new(EchoApp, ScriptedChaos::new(&["worker-kill"]));
        driver.inject("worker-kill");
        driver.clear();
        let target = AppDriverTarget::new(&mut driver);
        let report = breaker.explore(&target);
        assert!(
            !report.has_findings(),
            "clearing the fault restores the app"
        );
    }
}
