// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! r6_sql_ledger_postgres_seam — OFFLINE proof of the infra-gated Postgres ledger driver's SQL.
//!
//! The real cross-process dedup guarantee is provided by Postgres's own `PRIMARY KEY` +
//! `INSERT ... ON CONFLICT DO NOTHING` and requires a LIVE database, so `PostgresSqlLedgerDriver`
//! bound to a real connection is **infra-gated** — it cannot be exercised offline without faking a
//! database. What we CAN prove offline, honestly, is the driver's contract with the DB round-trip
//! seam (`SqlExecutor`): it emits the load-bearing `ON CONFLICT DO NOTHING` claim, the conditional
//! `FAILED`→`PENDING` re-claim, and the conditional lease `UPDATE`, and it maps rows-affected to the
//! right `SqlClaim`. This test drives the driver against a recording MOCK executor — it asserts the
//! SQL SHAPE and the rows-affected → claim mapping, NOT live dedup (that stays infra-gated).

use std::sync::Mutex;

use ainxt_tools::{
    PostgresSqlLedgerDriver, SqlClaim, SqlError, SqlExecutor, SqlLedgerDriver, SqlValue,
};

/// A recording mock DB. `execute` pops the next scripted rows-affected; `query_opt` pops the next
/// scripted row. Every statement issued is recorded so the test can assert the SQL shape.
#[derive(Default)]
struct MockExecutor {
    execute_returns: Mutex<Vec<u64>>,
    query_returns: Mutex<Vec<Option<Vec<Option<String>>>>>,
    log: Mutex<Vec<String>>,
}
impl MockExecutor {
    fn scripted(
        execute_returns: Vec<u64>,
        query_returns: Vec<Option<Vec<Option<String>>>>,
    ) -> Self {
        MockExecutor {
            execute_returns: Mutex::new(execute_returns),
            query_returns: Mutex::new(query_returns),
            log: Mutex::new(Vec::new()),
        }
    }
    fn sql_log(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }
    fn issued(&self, needle: &str) -> bool {
        self.sql_log().iter().any(|s| s.contains(needle))
    }
}
impl SqlExecutor for MockExecutor {
    fn execute(&self, sql: &str, _params: &[SqlValue]) -> Result<u64, SqlError> {
        self.log.lock().unwrap().push(sql.to_string());
        Ok(self
            .execute_returns
            .lock()
            .unwrap()
            .drain(..1)
            .next()
            .unwrap_or(0))
    }
    fn query_opt(
        &self,
        sql: &str,
        _params: &[SqlValue],
    ) -> Result<Option<Vec<Option<String>>>, SqlError> {
        self.log.lock().unwrap().push(sql.to_string());
        Ok(self
            .query_returns
            .lock()
            .unwrap()
            .drain(..1)
            .next()
            .flatten())
    }
    fn query(&self, sql: &str, _params: &[SqlValue]) -> Result<Vec<Vec<Option<String>>>, SqlError> {
        self.log.lock().unwrap().push(sql.to_string());
        Ok(Vec::new())
    }
}

#[test]
fn r6_sql_ledger_postgres_seam() {
    // ---- DDL: the unique arbiter is a PRIMARY KEY on the idempotency key ----
    let ddl = PostgresSqlLedgerDriver::<MockExecutor>::DDL;
    assert!(
        ddl.contains("idempotency_key TEXT PRIMARY KEY"),
        "PK arbitrates cross-process claims"
    );
    assert!(
        ddl.contains("state IN ('PENDING','COMMITTED','FAILED','MANUAL')"),
        "state machine CHECK"
    );

    // ---- Claim WON: the atomic ON CONFLICT DO NOTHING insert affected 1 row ----
    let mock = MockExecutor::scripted(vec![/*insert*/ 1], vec![]);
    let driver = PostgresSqlLedgerDriver::new(mock);
    assert_eq!(driver.claim_upsert("k1", 100), SqlClaim::Won);
    let m = driver_into_mock(&driver);
    assert!(
        m.issued("ON CONFLICT (idempotency_key) DO NOTHING"),
        "must emit the unique-key upsert"
    );

    // ---- Claim on an EXISTING COMMITTED row: insert affected 0, select returns COMMITTED ----
    let mock = MockExecutor::scripted(
        vec![/*insert*/ 0],
        vec![Some(vec![Some("COMMITTED".into()), Some("ref-42".into())])],
    );
    let driver = PostgresSqlLedgerDriver::new(mock);
    assert_eq!(
        driver.claim_upsert("k2", 100),
        SqlClaim::AlreadyCommitted("ref-42".into()),
        "existing COMMITTED row is deduped to its stored result"
    );

    // ---- Claim on a cleanly-FAILED row: insert 0, select FAILED, conditional re-claim UPDATE lands ----
    let mock = MockExecutor::scripted(
        vec![/*insert*/ 0, /*reclaim update*/ 1],
        vec![Some(vec![Some("FAILED".into()), None])],
    );
    let driver = PostgresSqlLedgerDriver::new(mock);
    assert_eq!(
        driver.claim_upsert("k3", 200),
        SqlClaim::Won,
        "FAILED row re-claimed"
    );
    let m = driver_into_mock(&driver);
    assert!(m.issued("state='PENDING'"), "re-claim flips FAILED→PENDING");
    assert!(
        m.issued("WHERE idempotency_key=$1 AND state='FAILED'"),
        "conditional on FAILED only"
    );

    // ---- Claim on a PENDING row: insert 0, select PENDING → InDoubt (never a second Won) ----
    let mock = MockExecutor::scripted(
        vec![/*insert*/ 0],
        vec![Some(vec![Some("PENDING".into()), None])],
    );
    let driver = PostgresSqlLedgerDriver::new(mock);
    assert_eq!(driver.claim_upsert("k4", 100), SqlClaim::InDoubt);

    // ---- Lease: the conditional UPDATE gates on state + a dead/absent lease; rows>0 ⇒ acquired ----
    let mock = MockExecutor::scripted(vec![/*lease update*/ 1], vec![]);
    let driver = PostgresSqlLedgerDriver::new(mock);
    assert!(
        driver.try_lease("k5", "node-A", 30),
        "lease acquired when UPDATE affects a row"
    );
    let m = driver_into_mock(&driver);
    assert!(
        m.issued("state='PENDING' AND (lease_expires IS NULL OR lease_expires <= $4)"),
        "lease is conditional — exactly one node's UPDATE lands"
    );

    // ---- Lease contention: the conditional UPDATE affected 0 rows ⇒ not acquired ----
    let mock = MockExecutor::scripted(vec![/*lease update*/ 0], vec![]);
    let driver = PostgresSqlLedgerDriver::new(mock);
    assert!(
        !driver.try_lease("k6", "node-B", 30),
        "no lease when a peer already holds it"
    );
}

/// The driver owns the executor; borrow it back through the driver's accessor for assertions.
fn driver_into_mock(driver: &PostgresSqlLedgerDriver<MockExecutor>) -> &MockExecutor {
    driver.executor()
}
