// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX identity-payments (ADR-022 §19 (c) / ADR-020 / ADR-027 §7, gap6 audit item 2) — PROVES A
//! REAL PREEMPTION SIGNAL THROUGH `KillSwitch` REACHES AND MUTATES THE REAL SERVING-OPS SCHEDULER.
//!
//! Before this fix: `KillSwitch::signal_preemption`/`PreemptionSink`/`PreemptDirective`/
//! `RunningProgramRun` were fully implemented and unit-tested in `ainxt-identity`, and the module's
//! own doc explicitly claimed "the real deployment wires `ainxt-serving`'s preemptor in behind it" —
//! but `ainxt-serving` had ZERO `impl PreemptionSink` anywhere in the workspace; the ONLY implementor
//! was `ainxt-identity/tests/r12_kill_switch_preemption.rs`'s own hand-rolled `RecordingScheduler`
//! test double. `POST /admin/killswitch/pull` (the real operator trigger, proven reachable by
//! `r_kill_switch_admin_route_served.rs`) only ever called `ControlPlane::pull_kill_switch` — it never
//! signalled preemption to anything, so a halted scope denied only a Run's *next* issuance/renewal,
//! never work already in flight.
//!
//! This test drives the REAL served admin route over actual HTTP (the SAME composition functions
//! `main.rs` calls: `assemble_selected_governed` + `assemble_full_with_control_plane`, the SAME
//! transport entrypoint `ainxt_server::serve_full_ext`) against a REAL `ainxt_serving::gate::ServingGate`
//! — the production scheduler type the served daemon holds (`AssembledFull::serving` /
//! `ainxt-server`'s `ServingAdmission::gate`), never a test double:
//!
//!  1. a sequence carrying the identity-plane `run_id` "run-halt-me" is admitted into the REAL
//!     `ServingGate` (mirroring what a served `/v1/chat` turn's `QosRequest::with_run_id` does);
//!  2. an admin pulls a `KillScope::Run("run-halt-me")` kill-switch over `POST /admin/killswitch/pull`,
//!     supplying the caller-known `running` snapshot naming that Run;
//!  3. the SAME `ServingGate` instance — read back directly, with zero calls back into
//!     `AssembledFull`/`ControlPlane` from this point — now reports that sequence preempted, its
//!     progress preserved, and an unrelated sequence untouched.
//!
//! FAIL-BEFORE / PASS-AFTER: before this fix, `KillSwitchPullRequest` carried no `running` field and
//! the handler never touched `state.serving` at all, so the admitted sequence would still be running
//! after the pull.

use std::sync::{Arc, Mutex};

use ainxt_identity::control::ControlPlane;
use ainxt_runtimed::{assemble_full_with_control_plane, assemble_selected_governed, load_layered};
use ainxt_serving::slo::QosRequest;
use ainxt_serving::PriorityClass;

fn loaded_with_unique_log(tag: &str) -> ainxt_runtimed::LoadedConfig {
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("ainxt-r-preempt-serving-{tag}-{nanos}"));
    let src = format!(
        "version = 1\n[server]\nevent_log_dir = {:?}\n",
        dir.to_string_lossy()
    );
    load_layered(&[("r-preempt-serving", &src)]).expect("load offline config")
}

#[tokio::test(flavor = "multi_thread")]
async fn kill_switch_pull_admin_route_force_preempts_a_real_admitted_sequence_on_the_real_serving_gate(
) {
    let control = Arc::new(Mutex::new(ControlPlane::new()));
    let loaded = loaded_with_unique_log("main");
    let assembled = assemble_selected_governed(&loaded, "chat", control.clone())
        .expect("the shipped default surface must assemble");
    let full = assemble_full_with_control_plane(&loaded, assembled, control)
        .expect("assemble_full_with_control_plane must assemble the fully-wired surface");

    // The REAL, production `Arc<Mutex<ServingGate>>` this daemon serves `/v1/chat` and `/v1/infer`
    // admission through — taken BEFORE serving starts, exactly the handle `to_full_app_ext` hands the
    // transport (`ServingAdmission::gate`).
    let serving_gate = full.serving.0.clone();

    // Admit a sequence correlated to an identity-plane `run_id`, mirroring what a served `/v1/chat`
    // turn's `QosRequest::with_run_id` does today (see `chat_handler`). Deliberately Interactive/P0 —
    // `PreemptionScheduler::admit`'s OWN eviction would never select a P0 as a victim, so a passing
    // test here proves the kill-switch path is a DIFFERENT, authority-scoped preemption, not merely a
    // side effect of ordinary admission contention.
    {
        let mut gate = serving_gate.lock().expect("serving gate lock");
        let decision = gate.pre_serve(
            &QosRequest::new(1, PriorityClass::Interactive, "payments-eng")
                .with_run_id("run-halt-me")
                .with_work(1_000, 4),
        );
        assert!(
            matches!(
                decision,
                ainxt_serving::slo::SloDecision::Admitted { preempted: None }
            ),
            "sanity: the sequence must be admitted with a free slot, got {decision:?}"
        );
        gate.scheduler_mut()
            .advance(1, 12)
            .expect("advance the admitted sequence to prove committed progress is preserved");
        assert!(gate.scheduler().is_running(1));
    }
    // An unrelated sequence, admitted under a DIFFERENT run_id AND a different fairness tenant (the
    // shipped default per-tenant quota is 1 concurrent slot — see `build_serving`'s
    // `fairness_min_share` default — so a second "payments-eng" arrival would be rejected over-quota
    // for a reason having nothing to do with this test), must be unaffected by the pull below.
    {
        let mut gate = serving_gate.lock().expect("serving gate lock");
        let decision = gate.pre_serve(
            &QosRequest::new(2, PriorityClass::Standard, "other-dept").with_run_id("run-unrelated"),
        );
        assert!(
            matches!(decision, ainxt_serving::slo::SloDecision::Admitted { .. }),
            "sanity: the unrelated sequence must be admitted too, got {decision:?}"
        );
    }

    // Serve the REAL fully-wired app + additive ext over a real TCP socket — identical to what
    // `main.rs` hands `ainxt_server::serve_full_ext`.
    let app = full.to_full_app();
    let ext = full.to_full_app_ext();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(ainxt_server::serve_full_ext(listener, app, ext));

    let client = reqwest::Client::new();
    let base = format!("http://{addr}");

    // An admin pulls a Run-scoped kill-switch, supplying the caller-known running snapshot — the
    // REAL HTTP admin route, not a direct in-process call into `ControlPlane`/`ServingGate`.
    let pulled = client
        .post(format!("{base}/admin/killswitch/pull"))
        .header("x-ainxt-user", "u-exec")
        .header("x-ainxt-role", "admin")
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(
            serde_json::json!({
                "scope": { "run": "run-halt-me" },
                "puller_id": "u-exec",
                "ad_level": 1,
                "can_approve": true,
                "now": 5,
                "running": [
                    {
                        "run_id": "run-halt-me",
                        "def_ref": "def:agent/coder@v1",
                        "department": "payments-eng",
                        "data_class": "internal",
                        "is_program": false
                    }
                ]
            })
            .to_string(),
        )
        .send()
        .await
        .expect("pull send");
    assert_eq!(pulled.status().as_u16(), 200, "an admin pull must succeed");
    let pulled_body: serde_json::Value =
        serde_json::from_str(&pulled.text().await.unwrap()).unwrap();
    assert_eq!(
        pulled_body["preempted"].as_array().unwrap().len(),
        1,
        "the pull response must report exactly one delivered PreemptDirective: {pulled_body}"
    );
    assert_eq!(pulled_body["preempted"][0]["run_id"], "run-halt-me");

    // THE LOAD-BEARING ASSERTION: the SAME real `ServingGate` instance, read back directly, now
    // reports the targeted sequence preempted — a REAL mutation of the REAL scheduler through the REAL
    // HTTP admin route, not a test double and not a hand-simulated call.
    {
        let gate = serving_gate.lock().expect("serving gate lock");
        assert!(
            !gate.scheduler().is_running(1),
            "the halted Run's sequence must no longer be running on the real ServingGate"
        );
        let rec = gate
            .scheduler()
            .preempted(1)
            .expect("the sequence must have moved into the scheduler's preempted set");
        assert_eq!(
            rec.resume_from, 12,
            "committed progress must be preserved, not lost"
        );
        assert!(
            gate.scheduler().is_running(2),
            "an unrelated run_id's sequence must be completely unaffected by the pull"
        );
    }
}

/// A pull whose `running` list names no admitted sequence is a real, honest no-op — never a spurious
/// mutation and never an error (mirrors `PreemptionSink::preempt`'s idempotency contract).
#[tokio::test(flavor = "multi_thread")]
async fn kill_switch_pull_with_no_matching_running_run_is_a_harmless_no_op() {
    let control = Arc::new(Mutex::new(ControlPlane::new()));
    let loaded = loaded_with_unique_log("noop");
    let assembled = assemble_selected_governed(&loaded, "chat", control.clone()).unwrap();
    let full = assemble_full_with_control_plane(&loaded, assembled, control).unwrap();

    let app = full.to_full_app();
    let ext = full.to_full_app_ext();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(ainxt_server::serve_full_ext(listener, app, ext));

    let client = reqwest::Client::new();
    let pulled = client
        .post(format!("http://{addr}/admin/killswitch/pull"))
        .header("x-ainxt-user", "u-exec")
        .header("x-ainxt-role", "admin")
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(
            serde_json::json!({
                "scope": { "run": "run-does-not-exist" },
                "puller_id": "u-exec",
                "ad_level": 1,
                "can_approve": true,
                "now": 1,
                "running": [
                    {
                        "run_id": "run-does-not-exist",
                        "def_ref": "def:agent/coder@v1",
                        "department": null,
                        "data_class": "internal",
                        "is_program": false
                    }
                ]
            })
            .to_string(),
        )
        .send()
        .await
        .expect("pull send");
    assert_eq!(pulled.status().as_u16(), 200);
    let body: serde_json::Value = serde_json::from_str(&pulled.text().await.unwrap()).unwrap();
    // A directive is still computed and delivered (the Run's SCOPE matches) — the sink itself is what
    // is idempotent/no-op when the named `run_id` was never admitted anywhere.
    assert_eq!(body["preempted"].as_array().unwrap().len(), 1);
}
