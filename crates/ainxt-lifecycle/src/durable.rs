// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Durable snapshot/restore for the retention store's **legal-hold matters** and
//! **deferred-erasure queue** (§6.2 / §6.3; Round-10 durability gap).
//!
//! A legal hold and a queued-but-not-yet-fired erasure are *obligations that outlive a process*: if a
//! `kill -9` between "erasure requested, deferred under a floor/hold" and "floor elapsed, fire it" lost
//! the queue, the runtime would silently drop a data principal's right-to-erasure — a DPDP breach that
//! is structurally invisible. So the [`RecordStore`](crate::RecordStore) must survive a restart with its
//! holds and deferred queue intact and *continue firing on schedule*.
//!
//! The seam is deliberately the **same** [`SnapshotStore`](ainxt_incident::durable::SnapshotStore) port
//! the statutory incident register uses (`ainxt-lifecycle` already depends on `ainxt-incident`, acyclic),
//! so a deployment binds ONE durable backend for both regulated-FI state machines. This module ships the
//! codec-generic [`snapshot_store`] / [`restore_store`] helpers over the `RecordStore`; the offline test
//! proves a deferred erasure queued before a crash still fires at floor-expiry after the restart. The
//! live Postgres/WORM binding behind the trait is `infra_gated`.

pub use ainxt_incident::durable::{InMemorySnapshotStore, SnapshotError, SnapshotStore, SnapshotWriteError};

use crate::RecordStore;

/// Snapshot the whole [`RecordStore`] — records, policies, audit trail, **legal-hold matters, and the
/// deferred-erasure queue** — into `store` under `key`, using the caller-supplied `serialize` codec
/// (codec-generic so the seam adds no hard serialization dependency). Returns
/// [`SnapshotWriteError::Serialize`] for a codec failure or [`SnapshotWriteError::Store`] for a
/// durable-backend write failure.
pub fn snapshot_store<S, E>(
    record_store: &RecordStore,
    store: &mut dyn SnapshotStore,
    key: &str,
    serialize: S,
) -> Result<(), SnapshotWriteError<E>>
where
    S: FnOnce(&RecordStore) -> Result<Vec<u8>, E>,
{
    let bytes = serialize(record_store).map_err(SnapshotWriteError::Serialize)?;
    store.save(key, &bytes).map_err(SnapshotWriteError::Store)?;
    Ok(())
}

/// Restore a [`RecordStore`] from `store` under `key` with the caller-supplied `deserialize` codec.
/// `Ok(None)` on a cold start (nothing persisted); the deserializer's error on a corrupt blob.
pub fn restore_store<D, E>(
    store: &dyn SnapshotStore,
    key: &str,
    deserialize: D,
) -> Result<Option<RecordStore>, E>
where
    D: FnOnce(&[u8]) -> Result<RecordStore, E>,
{
    match store.load(key) {
        None => Ok(None),
        Some(bytes) => Ok(Some(deserialize(&bytes)?)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HoldScope, LegalHold, Record, RecordStore, RetentionPolicy};
    use ainxt_types::DataClass;

    #[test]
    fn r10_holds_and_deferred_queue_survive_restart_and_still_fire_on_schedule() {
        // A DSAR erasure lands inside a statutory retention floor → deferred (not deleted) and QUEUED.
        // A `kill -9` before floor-expiry must not drop that obligation: after a simulated restart the
        // legal-hold matters and the deferred-erasure queue are intact, and the queued erasure STILL
        // fires automatically when the floor elapses on the far side of the crash.
        let mut record_store = RecordStore::new()
            .with_policy(RetentionPolicy::new(DataClass::RegulatedPayment, 10_000).with_floor(180));
        record_store.put(Record::new("txn", "erin", DataClass::RegulatedPayment, 0));
        // Also a per-matter legal hold, to prove hold state survives too.
        record_store.add_hold(LegalHold::open(
            "matter-durable",
            "dpo",
            HoldScope::any().with_subject("someone-else"),
            0,
        ));
        // Request erasure at tick 50 — within the floor → deferred + queued (not deleted).
        let res = record_store.request_erasure("erin", 50);
        assert!(res.erased.is_empty());
        assert_eq!(res.deferred.len(), 1);
        assert_eq!(record_store.deferred_queue().len(), 1);

        // "kill -9": snapshot through the SEAM, drop the store, restore from the persisted bytes.
        let mut sink = InMemorySnapshotStore::new();
        snapshot_store(&record_store, &mut sink, "retention-store", |s| {
            serde_json::to_vec(s)
        })
        .unwrap();
        drop(record_store);

        let mut restored: RecordStore =
            restore_store(&sink, "retention-store", |b| serde_json::from_slice(b))
                .unwrap()
                .expect("a snapshot exists");

        // The queue and the hold matter survived the restart.
        assert_eq!(
            restored.deferred_queue().len(),
            1,
            "deferred queue survived restart"
        );
        assert!(
            restored.hold("matter-durable").unwrap().is_active(),
            "legal-hold matter survived restart"
        );
        assert!(
            restored.get("txn").is_some(),
            "the floor-bound record was preserved, not dropped"
        );

        // Before floor-expiry the queue still does not fire; AT floor-expiry it fires automatically —
        // the obligation continued on schedule through the crash.
        assert!(restored.run_deferred(179).is_empty());
        assert!(restored.get("txn").is_some());
        let fired = restored.run_deferred(180);
        assert_eq!(fired, vec!["txn".to_string()]);
        assert!(
            restored.get("txn").is_none(),
            "the deferred erasure fired post-restart at floor-expiry"
        );
    }

    #[test]
    fn r10_restore_of_absent_key_is_a_cold_start_not_an_error() {
        let sink = InMemorySnapshotStore::new();
        let restored: Option<RecordStore> =
            restore_store(&sink, "missing", |b| serde_json::from_slice(b)).unwrap();
        assert!(restored.is_none());
    }
}
