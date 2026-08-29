// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP5 regulated-fi-responsible-lifecycle #2 — break-glass campaign restart-durability.
//!
//! `BreakGlassProgram` (`ainxt-lifecycle`) is itself durable/serde (ADR-027: "durable, resumable,
//! checkpointed... Program... survives restarts") and was already exhaustively unit-tested as such in
//! its own crate. But the SERVED registry (`AssembledFull::breakglass`, threaded onto
//! `FullAppExt::breakglass` and driven by `POST /v1/regfi/breakglass/{open,step}`) held every campaign
//! ONLY in a process-local `Arc<Mutex<BTreeMap<program_id, BreakGlassProgram>>>` — a daemon restart
//! mid-campaign silently lost every in-progress program (the open + every completed step), with no way
//! to recover it, contradicting that exact restart guarantee for this exact mechanism.
//!
//! The fix threads the daemon's own durable Event Log (`AssembledFull::event_log` / the SAME
//! `FullApp::event_log` `regfi_router`'s other routes already use) into every `open`/`step`: each
//! mutation checkpoints a full serde snapshot of the `BreakGlassProgram` as a new record on its
//! `breakglass-{program_id}` session (see `ainxt_runtimed::recover_break_glass_programs`'s doc for why
//! the session id is hyphen- not colon-delimited — an earlier colon-delimited version of this fix
//! silently failed to recover anything, because `EventLog::sessions()` returns the `safe_name`-
//! sanitized on-disk filename stem and a colon does not survive that sanitization; this test caught it).
//! `recover_break_glass_programs` replays each session's LATEST checkpoint back into the in-memory
//! registry on every assembly (daemon start AND restart).
//!
//! This test simulates a genuine restart: it assembles the daemon TWICE from the SAME
//! `[server] event_log_dir` (a real restart re-reads the identical durable directory a deployment
//! mounts — it never carries in-memory state across the process boundary), dropping the first
//! `AssembledFull` entirely (an unclean `kill -9`, not a graceful shutdown) before assembling the
//! second. It drives `AssembledFull::{open_break_glass_program,step_break_glass_program,
//! break_glass_progress}` directly — the exact methods `ainxt-server`'s
//! `POST /v1/regfi/breakglass/{open,step,progress}` handlers checkpoint through on the served path
//! (see that crate's `breakglass_open_handler`/`breakglass_step_handler`/`checkpoint_breakglass_program`).

use std::time::{SystemTime, UNIX_EPOCH};

use ainxt_lifecycle::breakglass::{RedactionTarget, BREAK_GLASS_CAP};
use ainxt_runtimed::{assemble_full, assemble_selected, load_layered};
use ainxt_types::Principal;

/// Build a `LoadedConfig` over a unique per-test `[server] event_log_dir` — the SAME idiom
/// `r15_compose_wiring.rs`'s `loaded_with_unique_log` uses. `tag` distinguishes the "fresh registry"
/// negative-control test from the "restart" positive test so their durable directories never collide.
fn loaded_with_unique_log(tag: &str) -> ainxt_runtimed::LoadedConfig {
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("ainxt-gap5-regfi-breakglass-{tag}-{nanos}"));
    let src = format!(
        "version = 1\n[server]\nevent_log_dir = {:?}\n",
        dir.to_string_lossy()
    );
    load_layered(&[("gap5-regfi-breakglass", &src)]).expect("load offline config")
}

fn targets(n: usize) -> Vec<RedactionTarget> {
    (0..n)
        .map(|i| RedactionTarget {
            record_id: format!("held-rec-{i}"),
            original_evidence_hash: format!("evhash-{i}"),
            note: "leaked email in a floored log".into(),
        })
        .collect()
}

fn dpo() -> Principal {
    Principal::user("dpo-1", &[BREAK_GLASS_CAP])
}

#[test]
fn break_glass_campaign_survives_a_daemon_restart() {
    let loaded = loaded_with_unique_log("restart");

    // "Process 1" — the daemon's real composition root: `assemble_selected` -> `assemble_full`, the
    // EXACT chain `main.rs` drives (via `assemble_selected_governed` -> `assemble_full_with_control_plane`,
    // which delegates to these for the default/ungoverned case).
    let assembled1 = assemble_selected(&loaded, "chat").expect("assemble_selected (process 1)");
    let full1 = assemble_full(&loaded, assembled1).expect("assemble_full (process 1)");

    full1
        .open_break_glass_program(&dpo(), "campaign-1", "detector-miss", targets(3))
        .expect("open");
    assert_eq!(
        full1.break_glass_progress(&dpo(), "campaign-1").unwrap(),
        (0, 3),
        "freshly opened: nothing done yet"
    );

    full1
        .step_break_glass_program(&dpo(), "campaign-1", 100)
        .expect("step 1")
        .expect("a target was pending");
    assert_eq!(
        full1.break_glass_progress(&dpo(), "campaign-1").unwrap(),
        (1, 3),
        "one of three targets attested"
    );

    // "kill -9": drop process 1's ENTIRE in-memory state with no graceful shutdown/flush — the only
    // thing that can possibly survive is whatever was durably checkpointed to disk.
    drop(full1);

    // "Process 2" — a FRESH daemon assembly (`assemble_selected` -> `assemble_full`) from the SAME
    // `[server] event_log_dir`. This is not a shortcut: it is the identical composition-root call a
    // real restarted daemon process makes, over the same durable directory a deployment mounts.
    let assembled2 =
        assemble_selected(&loaded, "chat").expect("assemble_selected (process 2 / restart)");
    let full2 = assemble_full(&loaded, assembled2).expect("assemble_full (process 2 / restart)");

    // The campaign is back, resumed exactly where it left off — 1 of 3 already attested, never lost
    // and never silently reset to (0, 3) or fabricated as complete.
    assert_eq!(
        full2.break_glass_progress(&dpo(), "campaign-1").unwrap(),
        (1, 3),
        "the campaign must survive the daemon restart with its partial progress intact"
    );

    // The recovered campaign can still be driven to completion on the NEW process — proving the
    // recovered `BreakGlassProgram` is a genuinely live, steppable object, not an inert snapshot.
    full2
        .step_break_glass_program(&dpo(), "campaign-1", 200)
        .expect("step 2")
        .expect("second target pending");
    full2
        .step_break_glass_program(&dpo(), "campaign-1", 200)
        .expect("step 3")
        .expect("third target pending");
    assert_eq!(
        full2.break_glass_progress(&dpo(), "campaign-1").unwrap(),
        (3, 3)
    );
    assert!(
        full2
            .step_break_glass_program(&dpo(), "campaign-1", 200)
            .expect("step on a complete program")
            .is_none(),
        "stepping a complete program is a no-op, mirroring BreakGlassProgram::step's own idempotence"
    );
}

#[test]
fn a_fresh_daemon_with_no_prior_campaigns_recovers_none() {
    // Negative control: the recovery scan over an EMPTY (never-written-to) durable directory must not
    // fabricate a campaign that never existed.
    let loaded = loaded_with_unique_log("empty");
    let assembled = assemble_selected(&loaded, "chat").expect("assemble_selected");
    let full = assemble_full(&loaded, assembled).expect("assemble_full");
    assert!(
        full.break_glass_progress(&dpo(), "nonexistent").is_err(),
        "an unopened program id must stay unknown on a fresh daemon"
    );
}
