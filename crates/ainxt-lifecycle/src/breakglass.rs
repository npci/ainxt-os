// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Break-glass PII-slipped-a-floor/hold remediation Program (FI-11; `REGULATED_FI_COMPLIANCE_OPS.md`
//! §6.5; Q1/ADR-027 Long-Horizon Program).
//!
//! A detector miss can land erasable PII inside a record that is under a **retention floor** or a
//! **legal hold** — the one place a normal erasure cannot touch (§6.1 precedence). The design's
//! remediation is *not* a delete (that would violate the floor/hold and destroy evidentiary value):
//! it is a **scoped, authorized, checkpointed redaction-with-attestation** that removes just the PII
//! payload while **preserving the record's evidentiary hash-chain** — each redaction emits a signed,
//! hash-chained [`RedactionAttestation`] linked to the record's original evidentiary hash, so the
//! fact-of-redaction is itself tamper-evident and admissible.
//!
//! Because such a remediation spans systems and time, it is a **Long-Horizon Program (Q1)**: durable
//! (serde), resumable after a `kill -9`, and with **partial completion as a first-class outcome** —
//! [`step`](BreakGlassProgram::step) processes one target at a time and checkpoints, so a crash loses
//! at most the in-flight item and a restart continues from the checkpoint. Authorization is explicit
//! (a granted [`BREAK_GLASS_CAP`], not merely admin) and reason-coded. Pure/deterministic — logical
//! ticks and the original evidentiary hashes are injected; no clock/rng/I/O.

use std::collections::VecDeque;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use ainxt_types::Principal;

use crate::Deferral;

/// The capability a principal must be **explicitly granted** to open a break-glass Program. Deliberately
/// checked against the principal's granted caps (not the admin shortcut) — break-glass is least-privilege.
pub const BREAK_GLASS_CAP: &str = "lifecycle:break-glass-remediate";

/// One record to remediate: it lives under a floor/hold and a detector-miss left erasable PII in it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactionTarget {
    pub record_id: String,
    /// The record's hash/position in its evidentiary chain — the redaction attests **against** this,
    /// preserving the chain rather than deleting the record.
    pub original_evidence_hash: String,
    /// PII-free note on why the payload must be redacted (e.g. "email leaked into a PMLA-floored log").
    pub note: String,
}

impl RedactionTarget {
    /// Build a break-glass target for a record a DSAR erasure **deferred** (a [`Deferral`] from
    /// [`RecordStore::request_erasure`](crate::RecordStore::request_erasure) / a DSAR erasure
    /// fulfilment): a record the statutory retention floor or an active legal hold preserved — the one
    /// place §6.1 forbids a normal erasure — but which a detector-miss left erasable PII inside. The
    /// remediation is a redaction-with-attestation, never a delete. `evidence_hash` is the record's
    /// position in its evidentiary chain (resolved by the caller from the incident / Event-Log tier)
    /// so the redaction attests **against** it and preserves the chain.
    pub fn from_deferral(deferral: &Deferral, evidence_hash: &str, note: &str) -> Self {
        Self {
            record_id: deferral.record_id.clone(),
            original_evidence_hash: evidence_hash.to_string(),
            note: note.to_string(),
        }
    }
}

/// Build the break-glass redaction targets for **every** record a DSAR erasure deferred (held /
/// floor-bound). This is the seam that connects the DSAR + retention/hold precedence (§6.1) to the
/// break-glass remediation Program (§6.5): a subject asked to be forgotten, the records could not be
/// deleted (held/floored), so the DPO redacts the slipped PII in place while preserving each record's
/// evidentiary hash. `evidence_hash_of(record_id)` resolves each record's evidentiary-chain hash; the
/// caller owns that resolution so this stays pure, clock-free, and acyclic. Order follows the input
/// deferrals (already id-sorted by the erasure resolution), so the result is deterministic.
pub fn targets_from_deferrals(
    deferrals: &[Deferral],
    note: &str,
    evidence_hash_of: impl Fn(&str) -> String,
) -> Vec<RedactionTarget> {
    deferrals
        .iter()
        .map(|d| RedactionTarget::from_deferral(d, &evidence_hash_of(&d.record_id), note))
        .collect()
}

/// A signed, hash-chained attestation that a target's PII payload was redacted in place. The chain
/// links `prev_hash` + the record id + its original evidence hash + the attestor, so the remediation
/// trail is itself tamper-evident ([`BreakGlassProgram::verify`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactionAttestation {
    pub seq: u64,
    pub record_id: String,
    pub original_evidence_hash: String,
    pub attestor: String,
    pub reason_code: String,
    pub tick: u64,
    pub prev_hash: String,
    pub hash: String,
}

const GENESIS: &str = "GENESIS";

fn attest_hash(
    prev: &str,
    seq: u64,
    record_id: &str,
    original_evidence_hash: &str,
    attestor: &str,
    reason_code: &str,
    tick: u64,
) -> String {
    let mut h = Sha256::new();
    for field in [
        prev,
        record_id,
        original_evidence_hash,
        attestor,
        reason_code,
    ] {
        h.update((field.len() as u64).to_le_bytes());
        h.update(field.as_bytes());
    }
    h.update(seq.to_le_bytes());
    h.update(tick.to_le_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect::<String>()
}

/// An error opening or stepping a break-glass Program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BreakGlassError {
    /// The principal was not explicitly granted [`BREAK_GLASS_CAP`].
    Unauthorized(String),
    /// A Program cannot be opened with no targets.
    NoTargets,
}

impl std::fmt::Display for BreakGlassError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BreakGlassError::Unauthorized(u) => {
                write!(f, "principal `{u}` lacks the break-glass capability")
            }
            BreakGlassError::NoTargets => {
                write!(f, "break-glass Program needs at least one target")
            }
        }
    }
}

impl std::error::Error for BreakGlassError {}

/// A tamper break in the attestation chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationTamper {
    SeqGap { expected: u64, found: u64 },
    BrokenChain { seq: u64 },
    HashMismatch { seq: u64 },
}

/// The durable, resumable break-glass remediation Program (Q1). Serde-serializable so it survives a
/// restart; `pending` shrinks and `attestations` grows one checkpointed step at a time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BreakGlassProgram {
    pub program_id: String,
    pub attestor: String,
    pub reason_code: String,
    pending: VecDeque<RedactionTarget>,
    attestations: Vec<RedactionAttestation>,
    total: usize,
}

impl BreakGlassProgram {
    /// Open a Program. Requires `principal` to hold [`BREAK_GLASS_CAP`] **explicitly** (least-privilege
    /// — an admin without the grant is refused), a reason code, and at least one target.
    pub fn open(
        program_id: &str,
        principal: &Principal,
        reason_code: &str,
        targets: Vec<RedactionTarget>,
    ) -> Result<Self, BreakGlassError> {
        // Explicit grant only — do NOT use has_cap (which auto-allows admins).
        if !principal.caps.iter().any(|c| c == BREAK_GLASS_CAP) {
            return Err(BreakGlassError::Unauthorized(principal.user_id.clone()));
        }
        if targets.is_empty() {
            return Err(BreakGlassError::NoTargets);
        }
        let total = targets.len();
        Ok(Self {
            program_id: program_id.to_string(),
            attestor: principal.user_id.clone(),
            reason_code: reason_code.to_string(),
            pending: targets.into(),
            attestations: Vec::new(),
            total,
        })
    }

    /// Process the next pending target: emit a hash-chained redaction attestation and checkpoint (the
    /// target leaves `pending`). Returns the attestation, or `None` when the Program is complete.
    /// Idempotent at the boundary: calling `step` on a complete Program is a no-op returning `None`.
    pub fn step(&mut self, now: u64) -> Option<&RedactionAttestation> {
        let target = self.pending.pop_front()?;
        let seq = self.attestations.len() as u64;
        let prev = self
            .attestations
            .last()
            .map_or(GENESIS, |a| a.hash.as_str());
        let hash = attest_hash(
            prev,
            seq,
            &target.record_id,
            &target.original_evidence_hash,
            &self.attestor,
            &self.reason_code,
            now,
        );
        self.attestations.push(RedactionAttestation {
            seq,
            record_id: target.record_id,
            original_evidence_hash: target.original_evidence_hash,
            attestor: self.attestor.clone(),
            reason_code: self.reason_code.clone(),
            tick: now,
            prev_hash: prev.to_string(),
            hash,
        });
        self.attestations.last()
    }

    /// Drive the Program to completion (or until `max_steps` this invocation — bounding work per call
    /// so a very large campaign can be sliced across scheduler ticks). Returns steps taken.
    pub fn run(&mut self, now: u64, max_steps: usize) -> usize {
        let mut n = 0;
        while n < max_steps && self.step(now).is_some() {
            n += 1;
        }
        n
    }

    /// `(done, total)` — partial completion is a first-class, inspectable outcome.
    pub fn progress(&self) -> (usize, usize) {
        (self.attestations.len(), self.total)
    }

    pub fn is_complete(&self) -> bool {
        self.pending.is_empty()
    }

    /// The remediation trail (each redaction attestation).
    pub fn attestations(&self) -> &[RedactionAttestation] {
        &self.attestations
    }

    /// Re-verify the attestation hash-chain end-to-end (the remediation trail is admissible too).
    pub fn verify(&self) -> Result<usize, AttestationTamper> {
        let mut prev = GENESIS.to_string();
        for (i, a) in self.attestations.iter().enumerate() {
            let expected = i as u64;
            if a.seq != expected {
                return Err(AttestationTamper::SeqGap {
                    expected,
                    found: a.seq,
                });
            }
            if a.prev_hash != prev {
                return Err(AttestationTamper::BrokenChain { seq: a.seq });
            }
            let recomputed = attest_hash(
                &prev,
                a.seq,
                &a.record_id,
                &a.original_evidence_hash,
                &a.attestor,
                &a.reason_code,
                a.tick,
            );
            if recomputed != a.hash {
                return Err(AttestationTamper::HashMismatch { seq: a.seq });
            }
            prev = a.hash.clone();
        }
        Ok(self.attestations.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn targets(n: usize) -> Vec<RedactionTarget> {
        (0..n)
            .map(|i| RedactionTarget {
                record_id: format!("held-rec-{i}"),
                original_evidence_hash: format!("evhash-{i}"),
                note: "leaked email in a floored log".into(),
            })
            .collect()
    }

    fn authorized() -> Principal {
        Principal::user("dpo-breakglass", &[BREAK_GLASS_CAP])
    }

    #[test]
    fn gap_ainxt_lifecycle_fi11_unauthorized_principal_cannot_open_break_glass() {
        // Least-privilege: even an admin without the explicit grant is refused (break-glass is not a
        // default admin power).
        let admin = Principal::admin("root");
        assert!(matches!(
            BreakGlassProgram::open("p1", &admin, "detector-miss", targets(2)),
            Err(BreakGlassError::Unauthorized(_))
        ));
        // A principal explicitly granted the cap succeeds.
        assert!(BreakGlassProgram::open("p1", &authorized(), "detector-miss", targets(2)).is_ok());
        // No targets is refused.
        assert!(matches!(
            BreakGlassProgram::open("p1", &authorized(), "r", vec![]),
            Err(BreakGlassError::NoTargets)
        ));
    }

    #[test]
    fn gap_ainxt_lifecycle_fi11_resumable_checkpointed_partial_completion_with_intact_chain() {
        // The Program survives a restart (serde), ships partial completion, and its redaction-
        // attestation chain (preserving each record's evidentiary hash) verifies end-to-end.
        let mut prog =
            BreakGlassProgram::open("p1", &authorized(), "detector-miss", targets(3)).unwrap();
        assert_eq!(prog.progress(), (0, 3));

        // Do one step, then "crash": serialize the checkpointed state.
        prog.step(100).unwrap();
        assert_eq!(prog.progress(), (1, 3));
        assert!(!prog.is_complete());
        let snapshot = serde_json::to_string(&prog).unwrap();

        // Restart: deserialize and continue — no work lost, no double-processing.
        let mut resumed: BreakGlassProgram = serde_json::from_str(&snapshot).unwrap();
        assert_eq!(resumed.progress(), (1, 3));
        let done = resumed.run(200, 100);
        assert_eq!(done, 2, "exactly the two remaining targets are processed");
        assert!(resumed.is_complete());
        assert_eq!(resumed.progress(), (3, 3));

        // Each attestation preserves its record's original evidentiary hash.
        assert_eq!(resumed.attestations().len(), 3);
        assert_eq!(resumed.attestations()[0].original_evidence_hash, "evhash-0");
        assert_eq!(resumed.attestations()[2].original_evidence_hash, "evhash-2");

        // The remediation trail is tamper-evident.
        assert_eq!(resumed.verify(), Ok(3));

        // Stepping a complete Program is a safe no-op.
        assert!(resumed.step(300).is_none());
    }

    #[test]
    fn r5_dsar_breakglass_e2e() {
        // Round-5 end-to-end seam: a DSAR erasure runs through the retention-floor / legal-hold
        // precedence, the held/floored records are DEFERRED (not deleted), and the DPO opens a
        // break-glass Program built DIRECTLY from those deferrals to redact the slipped PII in place —
        // preserving each record's evidentiary hash. This exercises the previously-missing seam
        // between the DSAR precedence core and the break-glass remediation Program.
        use crate::dsar::{DsarKind, DsarRegister};
        use crate::{HoldScope, LegalHold, Record, RecordStore, RetentionPolicy};
        use ainxt_types::DataClass;

        // A subject with one legal-held record and one floor-bound record — neither is erasable now.
        let mut store = RecordStore::new()
            .with_policy(RetentionPolicy::new(DataClass::Pii, 10_000).with_floor(180));
        store.put(Record::new("held-log", "erin", DataClass::Pii, 0));
        store.put(Record::new("floored-txn", "erin", DataClass::Pii, 50));
        // Legal-hold matter covers the first record only.
        store.add_hold(LegalHold::open(
            "matter-9",
            "dpo",
            HoldScope::any()
                .with_subject("erin")
                .with_created_range(Some(0), Some(0)),
            0,
        ));

        // DSAR erasure at tick 60: both records are within-floor/held → deferred, not deleted.
        let mut reg = DsarRegister::new();
        reg.open("d-erin", "erin", DsarKind::Erasure, 0, 1_000)
            .unwrap();
        reg.authenticate("d-erin", true, 1).unwrap();
        let res = reg.fulfill_erasure("d-erin", &mut store, 60).unwrap();
        assert!(
            res.erased.is_empty(),
            "held/floored records must NOT be erased"
        );
        assert_eq!(res.deferred.len(), 2);
        assert!(store.get("held-log").is_some());
        assert!(store.get("floored-txn").is_some());

        // Build the break-glass targets straight from the DSAR deferrals (the new seam). The
        // evidence-chain hash is resolved by the caller (here, a fixed stand-in for the incident tier).
        let targets = targets_from_deferrals(
            &res.deferred,
            "detector-miss: PII in held/floored record",
            |rid| format!("evchain-{rid}"),
        );
        assert_eq!(targets.len(), 2);

        // The DPO (explicitly granted the cap) opens and runs the redaction Program.
        let dpo = Principal::user("dpo-erin", &[BREAK_GLASS_CAP]);
        let mut prog =
            BreakGlassProgram::open("bg-erin", &dpo, "dsar-deferred-pii", targets).unwrap();
        assert_eq!(prog.run(100, 100), 2);
        assert!(prog.is_complete());
        // Each attestation preserves the record's original evidentiary hash (redact, don't delete).
        let att = prog.attestations();
        assert_eq!(att[0].original_evidence_hash, "evchain-floored-txn");
        assert_eq!(att[1].original_evidence_hash, "evchain-held-log");
        assert_eq!(prog.verify(), Ok(2));

        // The held/floored records STILL EXIST — break-glass redacted, it did not delete (§6.1 intact).
        assert!(store.get("held-log").is_some());
        assert!(store.get("floored-txn").is_some());
        // The DSAR register remains tamper-evident.
        assert!(reg.verify().is_ok());
    }

    #[test]
    fn gap_ainxt_lifecycle_fi11_tampered_attestation_trail_is_detected() {
        let mut prog = BreakGlassProgram::open("p1", &authorized(), "r", targets(2)).unwrap();
        prog.run(100, 10);
        assert_eq!(prog.verify(), Ok(2));
        // Tamper via serde round-trip mutation.
        let mut json: serde_json::Value = serde_json::to_value(&prog).unwrap();
        json["attestations"][0]["tick"] = serde_json::json!(999_999);
        let tampered: BreakGlassProgram = serde_json::from_value(json).unwrap();
        assert!(tampered.verify().is_err());
    }
}
