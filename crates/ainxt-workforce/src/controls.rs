// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! **Running the §6/§7 controls continuously in production** — the nightly-sweep orchestrator that
//! turns the pure lifecycle ([`crate::lifecycle`]) and oversight ([`crate::oversight`]) logic into a
//! scheduled job that writes data-plane rows, sends owner/manager digests, and routes events to the
//! Event Log (WORKFORCE_AND_OS §8: "the §6 lifecycle sweeps and §7 oversight-health metrics run
//! continuously in production, not just at build/deploy time").
//!
//! The three production side effects are seams:
//! - [`DataPlaneStore`] — the amber decay flags, orphan rows, and oversight metrics (§6/§7 write to
//!   Postgres/Redis in prod);
//! - [`Notifier`] — the owner / manager digest notifications (email/Teams in prod);
//! - [`EventLog`] — the tamper-evident routing record (orphan→manager, oversight-amber, decoy
//!   incidents).
//!
//! The crate ships in-memory recording implementations ([`InMemoryDataPlane`], [`RecordingNotifier`],
//! [`InMemoryEventLog`]) so the whole orchestrator is deterministic and testable offline. Binding the
//! seams to live Postgres/Redis + a real cron/scheduler is a downstream, infra-gated wiring step; the
//! orchestrator itself is pure and clock-free (the caller supplies the "day number").
//!
//! **Anti-storm guarantee (§6.1):** digests are aggregated *per recipient*, so an owner with three
//! decayed definitions gets one digest, not three.

use std::collections::BTreeMap;

use crate::lifecycle::{
    decay_sweep, orphan_sweep, recert_sweep, DecayFlag, DecayThresholds, DefinitionTelemetry,
    OrgTree, OrphanFlag, RecertNudge,
};

/// The default §6.2 re-certification cadence (days since the last SIGNED commit) used by
/// [`NightlyControls::run_nightly`]; override per-deployment via
/// [`NightlyControls::run_nightly_with_recert`].
pub const DEFAULT_RECERT_AFTER_DAYS: u64 = 365;
use crate::oversight::{oversight_health, ApprovalEvent, OversightMetrics};

// ============================ Seams ============================

/// Where the sweep persists its findings (Postgres/Redis in production).
pub trait DataPlaneStore {
    fn write_decay_flag(&mut self, flag: &DecayFlag);
    fn write_orphan_flag(&mut self, flag: &OrphanFlag);
    fn write_oversight_metric(&mut self, metric: &OversightMetrics);
    /// §6.2: persist a re-certification nudge (data-plane, never a git mutation).
    fn write_recert_nudge(&mut self, nudge: &RecertNudge);
}

/// How owner/manager digests are delivered (email/Teams in production).
pub trait Notifier {
    fn digest(&mut self, recipient: &str, subject: &str, body: &str);
}

/// The tamper-evident routing/audit record (Event Log in production).
pub trait EventLog {
    fn append(&mut self, kind: &str, subject: &str, detail: &str);
}

// ============================ Offline recording implementations ============================

/// An in-memory data plane that records exactly what the sweep wrote (offline conformance).
#[derive(Debug, Default)]
pub struct InMemoryDataPlane {
    pub decay_flags: Vec<DecayFlag>,
    pub orphan_flags: Vec<OrphanFlag>,
    pub oversight_metrics: Vec<OversightMetrics>,
    pub recert_nudges: Vec<RecertNudge>,
}

impl DataPlaneStore for InMemoryDataPlane {
    fn write_decay_flag(&mut self, flag: &DecayFlag) {
        self.decay_flags.push(flag.clone());
    }
    fn write_orphan_flag(&mut self, flag: &OrphanFlag) {
        self.orphan_flags.push(flag.clone());
    }
    fn write_oversight_metric(&mut self, metric: &OversightMetrics) {
        self.oversight_metrics.push(metric.clone());
    }
    fn write_recert_nudge(&mut self, nudge: &RecertNudge) {
        self.recert_nudges.push(nudge.clone());
    }
}

/// A digest one recipient received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentDigest {
    pub recipient: String,
    pub subject: String,
    pub body: String,
}

/// A notifier that records every digest (offline conformance).
#[derive(Debug, Default)]
pub struct RecordingNotifier {
    pub sent: Vec<SentDigest>,
}

impl RecordingNotifier {
    /// How many digests a given recipient received (for the anti-storm assertion).
    pub fn count_for(&self, recipient: &str) -> usize {
        self.sent
            .iter()
            .filter(|d| d.recipient == recipient)
            .count()
    }
}

impl Notifier for RecordingNotifier {
    fn digest(&mut self, recipient: &str, subject: &str, body: &str) {
        self.sent.push(SentDigest {
            recipient: recipient.to_string(),
            subject: subject.to_string(),
            body: body.to_string(),
        });
    }
}

/// An Event Log entry the sweep routed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoggedEvent {
    pub kind: String,
    pub subject: String,
    pub detail: String,
}

/// An in-memory Event Log (offline conformance).
#[derive(Debug, Default)]
pub struct InMemoryEventLog {
    pub events: Vec<LoggedEvent>,
}

impl InMemoryEventLog {
    pub fn count_of_kind(&self, kind: &str) -> usize {
        self.events.iter().filter(|e| e.kind == kind).count()
    }
}

impl EventLog for InMemoryEventLog {
    fn append(&mut self, kind: &str, subject: &str, detail: &str) {
        self.events.push(LoggedEvent {
            kind: kind.to_string(),
            subject: subject.to_string(),
            detail: detail.to_string(),
        });
    }
}

// ============================ The orchestrator ============================

/// What one nightly run produced (a summary for logs/metrics).
#[derive(Debug, Clone, PartialEq)]
pub struct SweepSummary {
    pub decay_flagged: usize,
    pub orphans_flagged: usize,
    pub oversight_metrics: usize,
    pub oversight_amber: usize,
    /// §6.2: definitions nudged for re-certification this run.
    pub recert_nudged: usize,
    pub digests_sent: usize,
    pub events_routed: usize,
}

/// The nightly controls orchestrator. Holds the three seams; every method drives them from the pure
/// §6/§7 logic. Generic over the seam implementations so production can swap in live-backed ones.
pub struct NightlyControls<'a, S: DataPlaneStore, N: Notifier, L: EventLog> {
    pub store: &'a mut S,
    pub notifier: &'a mut N,
    pub event_log: &'a mut L,
}

impl<'a, S: DataPlaneStore, N: Notifier, L: EventLog> NightlyControls<'a, S, N, L> {
    pub fn new(store: &'a mut S, notifier: &'a mut N, event_log: &'a mut L) -> Self {
        NightlyControls {
            store,
            notifier,
            event_log,
        }
    }

    /// Run the full nightly sweep: §6.1 decay, §6.3 orphan detection, §7.1 oversight-health, §6.2
    /// re-certification nudge (at the deployment's default `DEFAULT_RECERT_AFTER_DAYS` cadence — use
    /// [`NightlyControls::run_nightly_with_recert`] to override it). Persists every finding to the
    /// data plane, aggregates digests per recipient (no storm), and routes orphan + oversight-amber
    /// events to the Event Log.
    pub fn run_nightly(
        &mut self,
        defs: &[DefinitionTelemetry],
        decay_th: &DecayThresholds,
        codeowners: &std::collections::BTreeSet<String>,
        org: &OrgTree,
        approval_events: &[ApprovalEvent],
        oversight_min_count: usize,
    ) -> SweepSummary {
        self.run_nightly_with_recert(
            defs,
            decay_th,
            codeowners,
            org,
            approval_events,
            oversight_min_count,
            DEFAULT_RECERT_AFTER_DAYS,
        )
    }

    /// [`NightlyControls::run_nightly`] with an explicit §6.2 re-certification cadence
    /// (`recert_after_days`): the continuous half of ADR-026 §5 — a definition whose last SIGNED
    /// commit is older than this is nudged for re-certification (one aggregated digest per owner, no
    /// storm), closing the gap where [`crate::lifecycle::needs_recert`] existed as pure logic nobody
    /// ever called from the nightly orchestrator.
    #[allow(clippy::too_many_arguments)]
    pub fn run_nightly_with_recert(
        &mut self,
        defs: &[DefinitionTelemetry],
        decay_th: &DecayThresholds,
        codeowners: &std::collections::BTreeSet<String>,
        org: &OrgTree,
        approval_events: &[ApprovalEvent],
        oversight_min_count: usize,
        recert_after_days: u64,
    ) -> SweepSummary {
        let mut digests_sent = 0usize;
        let mut events_routed = 0usize;

        // ---- §6.1 decay: persist each flag; ONE aggregated digest per owner. ----
        let decay = decay_sweep(defs, decay_th);
        let mut by_owner: BTreeMap<String, Vec<&DecayFlag>> = BTreeMap::new();
        for f in &decay {
            self.store.write_decay_flag(f);
            by_owner.entry(f.owner.clone()).or_default().push(f);
        }
        for (owner, flags) in &by_owner {
            let ids: Vec<&str> = flags.iter().map(|f| f.definition_id.as_str()).collect();
            self.notifier.digest(
                owner,
                "decay-sweep digest",
                &format!(
                    "{} of your definition(s) are decaying: {}",
                    flags.len(),
                    ids.join(", ")
                ),
            );
            digests_sent += 1;
        }

        // ---- §6.3 orphan: persist; route to Event Log; ONE aggregated digest per manager. ----
        let orphans = orphan_sweep(defs, codeowners, org);
        let mut by_manager: BTreeMap<String, Vec<&OrphanFlag>> = BTreeMap::new();
        for f in &orphans {
            self.store.write_orphan_flag(f);
            self.event_log.append(
                "orphan-detected",
                &f.definition_id,
                &format!(
                    "owner '{}' ({}); routed to manager {:?}",
                    f.owner, f.reason, f.notify_manager
                ),
            );
            events_routed += 1;
            if let Some(mgr) = &f.notify_manager {
                by_manager.entry(mgr.clone()).or_default().push(f);
            }
        }
        for (mgr, flags) in &by_manager {
            let ids: Vec<&str> = flags.iter().map(|f| f.definition_id.as_str()).collect();
            self.notifier.digest(
                mgr,
                "orphaned-definition digest",
                &format!(
                    "{} orphaned definition(s) need reassignment: {}",
                    flags.len(),
                    ids.join(", ")
                ),
            );
            digests_sent += 1;
        }

        // ---- §7.1 oversight-health: persist every metric; route the amber ones to the Event Log. ----
        let metrics = oversight_health(approval_events, oversight_min_count);
        let mut amber = 0usize;
        for m in &metrics {
            self.store.write_oversight_metric(m);
            if m.amber {
                amber += 1;
                self.event_log.append(
                    "oversight-amber",
                    &format!("{}::{}", m.approver, m.role),
                    &format!(
                        "median_latency={}s override_rate={} count={} (complacency signature)",
                        m.median_latency_secs, m.override_rate, m.count
                    ),
                );
                events_routed += 1;
            }
        }

        // ---- §6.2 re-certification: persist each nudge; ONE aggregated digest per owner. ----
        let recerts = recert_sweep(defs, recert_after_days);
        let mut by_owner_recert: BTreeMap<String, Vec<&RecertNudge>> = BTreeMap::new();
        for n in &recerts {
            self.store.write_recert_nudge(n);
            by_owner_recert.entry(n.owner.clone()).or_default().push(n);
        }
        for (owner, nudges) in &by_owner_recert {
            let ids: Vec<&str> = nudges.iter().map(|n| n.definition_id.as_str()).collect();
            self.notifier.digest(
                owner,
                "re-certification nudge",
                &format!(
                    "{} of your definition(s) are due for re-certification (last signed commit too old): {}",
                    nudges.len(),
                    ids.join(", ")
                ),
            );
            digests_sent += 1;
        }

        SweepSummary {
            decay_flagged: decay.len(),
            orphans_flagged: orphans.len(),
            oversight_metrics: metrics.len(),
            oversight_amber: amber,
            recert_nudged: recerts.len(),
            digests_sent,
            events_routed,
        }
    }

    /// Route a §7.2 attention-check **incident** immediately (not nightly): an approved known-bad
    /// decoy is a hard-fail — logged to the Event Log and escalated to the manager for immediate
    /// review + mandatory retraining. This routes the audit record + the incident notification.
    pub fn route_decoy_incident(&mut self, approver: &str, role: &str, manager: &str) {
        self.event_log.append(
            "attention-check-incident",
            &format!("{approver}::{role}"),
            "approver approved a known-bad decoy; mandatory retraining flagged",
        );
        self.notifier.digest(
            manager,
            "attention-check incident",
            &format!("approver '{approver}' approved a decoy on role '{role}' — immediate review + retraining"),
        );
    }
}
