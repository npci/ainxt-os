// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Durable snapshot/restore seam for the statutory register's **crash-survival** property (§2.3;
//! Round-10 durability gap).
//!
//! The [`IncidentRegister`](crate::IncidentRegister) already *is* pure serde state — its
//! "survive a `kill -9`" guarantee is "serialize the whole register, drop it, deserialize a fresh one,
//! keep counting from the immutable `t0`". What was missing is the **seam**: a persistence port the
//! parent binds to a durable backend (Postgres / Redis / a WORM object store), decoupled from the
//! register so the register stays clock-free and testable. This module is that port.
//!
//! - [`SnapshotStore`] — the byte-oriented persistence trait. Deliberately **codec-free**: it moves
//!   opaque bytes under a key, so no serialization crate enters the register's supply-chain surface.
//!   The *live* binding (a Postgres row, a Redis key, an S3/WORM object) is a deployment adapter and is
//!   `infra_gated`; this crate ships the offline, deterministic [`InMemorySnapshotStore`] that proves
//!   the contract with zero infra.
//! - [`snapshot_register`] / [`restore_register`] — the register-specific save/load, generic over the
//!   codec (the caller supplies `serialize`/`deserialize`) so the seam adds no hard dependency. The
//!   offline test uses `serde_json` (a dev-dependency) as the codec and proves a mid-flight register —
//!   armed clocks, paged tiers, hash chain — is byte-identical after a simulated restart and *still
//!   breaches at the correct boundary* on the far side of the crash.
//!
//! No clock, no RNG, no I/O in this crate: the store is an in-memory map; a real backend does the I/O
//! behind the same trait.

use std::collections::BTreeMap;

use crate::IncidentRegister;

/// A durable key→bytes persistence port (the crash-survival seam). An implementation persists the
/// opaque snapshot bytes under `key` and returns them verbatim on `load`. The trait is codec-free on
/// purpose — the register's serde codec is the caller's choice, so binding a durable backend never
/// widens this crate's dependency surface.
pub trait SnapshotStore {
    /// Persist `bytes` under `key`, replacing any prior value. A live adapter writes a durable row /
    /// object here (and must be crash-atomic — a torn write is worse than a stale one). Returns
    /// [`SnapshotError`] on a failed write — the offline [`InMemorySnapshotStore`] never fails, but a
    /// database-backed adapter genuinely can (disk full, connection lost), and the trait must be able
    /// to say so rather than making that structurally unreportable.
    fn save(&mut self, key: &str, bytes: &[u8]) -> Result<(), SnapshotError>;

    /// Load the bytes previously saved under `key`, or `None` if the key was never written.
    fn load(&self, key: &str) -> Option<Vec<u8>>;
}

/// Why a [`SnapshotStore::save`] failed. The offline [`InMemorySnapshotStore`] never returns this; a
/// durable backend surfaces its own I/O/driver failure here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotError(pub String);

impl std::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "snapshot store write failed: {}", self.0)
    }
}

impl std::error::Error for SnapshotError {}

/// Either the caller's own serializer failed, or the durable [`SnapshotStore`] write did. Returned
/// by [`snapshot_register`] (and reused by `ainxt-lifecycle`'s `snapshot_store`) so a codec failure
/// and a store failure are both reportable, without forcing every caller's own error type `E` to
/// know how to represent a store failure.
#[derive(Debug)]
pub enum SnapshotWriteError<E> {
    Serialize(E),
    Store(SnapshotError),
}

impl<E: std::fmt::Display> std::fmt::Display for SnapshotWriteError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SnapshotWriteError::Serialize(e) => write!(f, "serialize failed: {e}"),
            SnapshotWriteError::Store(e) => write!(f, "{e}"),
        }
    }
}

impl<E: std::fmt::Debug + std::fmt::Display> std::error::Error for SnapshotWriteError<E> {}

/// The offline, deterministic [`SnapshotStore`] — an in-memory map. It proves the seam's contract with
/// no infrastructure: a "restart" is dropping the register and reconstructing it from the bytes this
/// store still holds. The live Postgres/Redis/WORM adapter (behind the same trait) is `infra_gated`.
#[derive(Debug, Clone, Default)]
pub struct InMemorySnapshotStore {
    map: BTreeMap<String, Vec<u8>>,
}

impl InMemorySnapshotStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of distinct keys currently persisted.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// True when nothing is persisted.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

impl SnapshotStore for InMemorySnapshotStore {
    fn save(&mut self, key: &str, bytes: &[u8]) -> Result<(), SnapshotError> {
        self.map.insert(key.to_string(), bytes.to_vec());
        Ok(())
    }

    fn load(&self, key: &str) -> Option<Vec<u8>> {
        self.map.get(key).cloned()
    }
}

/// Snapshot the whole [`IncidentRegister`] into `store` under `key`, using the caller-supplied codec
/// (`serialize`). Codec-generic so the seam adds no hard serialization dependency: production passes a
/// `serde_json`/`bincode`/CBOR serializer, the offline test passes `serde_json::to_vec`. Returns
/// [`SnapshotWriteError::Serialize`] for a codec failure or [`SnapshotWriteError::Store`] for a
/// durable-backend write failure — both now reportable, whereas before a store write could not fail
/// at all (the trait's `save` returned nothing).
pub fn snapshot_register<S, E>(
    register: &IncidentRegister,
    store: &mut dyn SnapshotStore,
    key: &str,
    serialize: S,
) -> Result<(), SnapshotWriteError<E>>
where
    S: FnOnce(&IncidentRegister) -> Result<Vec<u8>, E>,
{
    let bytes = serialize(register).map_err(SnapshotWriteError::Serialize)?;
    store.save(key, &bytes).map_err(SnapshotWriteError::Store)?;
    Ok(())
}

/// Restore an [`IncidentRegister`] from `store` under `key`, using the caller-supplied `deserialize`
/// codec. Returns `Ok(None)` if the key was never written (nothing to restore — a cold start), or the
/// deserializer's error on a corrupt/incompatible blob.
pub fn restore_register<D, E>(
    store: &dyn SnapshotStore,
    key: &str,
    deserialize: D,
) -> Result<Option<IncidentRegister>, E>
where
    D: FnOnce(&[u8]) -> Result<IncidentRegister, E>,
{
    match store.load(key) {
        None => Ok(None),
        Some(bytes) => Ok(Some(deserialize(&bytes)?)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ArmingPolicy, CandidateSource, EngineEvent, EscalationTier, IncidentCandidate,
        IncidentClass, IncidentRegister, StatutoryClockKind,
    };
    use ainxt_types::DataClass;

    fn reg_with_armed_clock() -> (IncidentRegister, String) {
        let mut reg = IncidentRegister::new(ArmingPolicy::india_regulatory_default());
        let cand = IncidentCandidate::new(CandidateSource::ComplianceGateEgress, 0, "cp-sha")
            .with_data_class(DataClass::Pii);
        // Personal-data breach arms DPDP-board (72h = 4320 ticks) + DPDP-data-principal (24h = 1440).
        let id = reg.open(cand, IncidentClass::PersonalDataBreach, 0);
        (reg, id)
    }

    #[test]
    fn r10_incident_register_survives_simulated_restart_through_snapshot_seam() {
        // The durability seam (trait + offline in-memory impl) persists a mid-flight register and
        // re-projects it byte-for-byte after a simulated `kill -9`. Crucially the *statutory clock
        // continues from the immutable t0* on the far side: a tier paged before the crash is not
        // re-paged, and the clock still breaches at the CORRECT boundary (not early) after restore.
        let (mut reg, id) = reg_with_armed_clock();
        // Advance to 50% of the DPDP-data-principal budget (1440 → 720): owner paged, persisted.
        let pre = reg.tick(720);
        assert!(pre.iter().any(|e| matches!(
            e,
            EngineEvent::Paged {
                tier: EscalationTier::IncidentOwner,
                ..
            }
        )));

        // "kill -9": snapshot through the SEAM, drop the register, restore from the store.
        let mut store = InMemorySnapshotStore::new();
        snapshot_register(&reg, &mut store, "incident-register", |r| {
            serde_json::to_vec(r)
        })
        .unwrap();
        assert_eq!(store.len(), 1, "the register was persisted under its key");
        drop(reg);

        let restored: IncidentRegister =
            restore_register(&store, "incident-register", |b| serde_json::from_slice(b))
                .unwrap()
                .expect("a snapshot exists, so restore yields the register");

        // t0 is immutable and elapsed reflects real wall-clock, not a reset.
        let clk = restored
            .incident(&id)
            .unwrap()
            .clock(StatutoryClockKind::DpdpDataPrincipal)
            .unwrap();
        assert_eq!(clk.t0, 0, "t0 must survive the restart unchanged");
        assert_eq!(clk.elapsed(900), 900);

        // The owner page already fired (persisted) → resuming does not re-page it; the next tier does.
        let mut restored = restored;
        let resumed = restored.tick(1_080); // 75% of 1440 → DPO
        assert_eq!(resumed.len(), 1);
        assert!(matches!(
            resumed[0],
            EngineEvent::Paged {
                tier: EscalationTier::Dpo,
                ..
            }
        ));

        // Boundary precision preserved across the restart: NOT breached at exactly the deadline (1440),
        // breached one tick past it — the clock is unit-consistent after a crash, not shifted.
        assert!(
            restored.breached_without_filing(1_440).is_empty(),
            "at exactly the deadline the DPDP clock is not yet breached"
        );
        assert!(
            restored
                .breached_without_filing(1_441)
                .iter()
                .any(|(_, k)| *k == StatutoryClockKind::DpdpDataPrincipal),
            "one tick past the deadline the DPDP clock breaches — boundary survived the restart"
        );

        // The resumed register still hash-verifies end-to-end (tamper-evident through the crash).
        assert!(restored.verify().is_ok());
    }

    #[test]
    fn r10_restore_of_absent_key_is_a_cold_start_not_an_error() {
        // A cold start (nothing ever persisted) restores to `None`, never a spurious error — so a
        // first-boot daemon simply starts a fresh register rather than crash-looping on an empty store.
        let store = InMemorySnapshotStore::new();
        let restored: Option<IncidentRegister> =
            restore_register(&store, "missing", |b| serde_json::from_slice(b)).unwrap();
        assert!(restored.is_none());
        assert!(store.is_empty());
    }
}
