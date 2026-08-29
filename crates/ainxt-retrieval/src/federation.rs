// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Federated privacy-preserving cross-member-bank aggregation.
//!
//! Design: `docs/architecture/STRUCTURED_FEDERATED_RETRIEVAL.md` §6 ("Federated
//! privacy-preserving cross-member-bank tier", Pass-5 gap 15). the operator can compute a network-wide
//! signal (e.g. mule-account velocity across banks) **without any bank's raw rows ever leaving
//! its own boundary** — only local, DP-noised partial aggregates are transmitted, the broker
//! sums them, and a k-anonymity floor plus a privacy-budget ledger bound what leaks.
//!
//! This module implements the broker-side and bank-side *logic* of §6, all pure and
//! **deterministic** (the DP noise is drawn from a caller-supplied seed via a splitmix64 PRNG —
//! no system RNG, `DETERMINISTIC` mandate — so a query is reproducible for audit):
//!
//! - **Closed-vocabulary federation** ([`FederationRegistry`], §6.2): `federatedSignal` is
//!   refused unless the metric is on the git-reviewed `federated: true` whitelist — no open
//!   cross-bank query surface exists.
//! - **Local-before-transmit DP noise** ([`noise_partial`], §6.2 step 3): each bank adds
//!   calibrated Laplace noise (scale = sensitivity/ε) to its partial *before* it leaves the
//!   tenant boundary; the true value is never transmitted.
//! - **Privacy-budget ledger** ([`EpsilonLedger`], §6.3): a per-(metric, window) append-only ε
//!   budget; each query debits ε, and when the budget is exhausted further queries are
//!   *refused* (never silently re-noised weaker), defeating averaging-out attacks.
//! - **K-anonymity floor** ([`aggregate`], §6.2 step 4): any bucket contributed to by fewer than
//!   `min_banks` banks, or underpinned by fewer than `min_underlying` transactions, is suppressed
//!   and merged into an `"other"` bucket — never returned as a distinguishable small cell.
//! - **Disclosure opt-in** (§6.4): per-bank breakdowns are withheld by default and only included
//!   when disclosure is explicitly enabled (a standing, git-reviewed consent record upstream).
//!
//! Physical tenant isolation itself (each bank's own schema/namespace, no cross-tenant read
//! credential) is an infra property (§6.1) enforced at the connection layer, not here; this
//! module assumes it and operates only on the noised partials a bank chooses to emit. The ε/k
//! parameter *choice* is a Risk + member-bank governance judgment (§ residual risks) — this
//! bounds erosion given a chosen ε, it does not pick the right ε.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------------------
// Closed-vocabulary federation whitelist (§6.2)
// ---------------------------------------------------------------------------------------

/// The git-reviewed set of metric ids flagged `federated: true` — the ONLY metrics
/// `federatedSignal` may run. A metric not in this set structurally cannot be federated.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationRegistry {
    federated: BTreeSet<String>,
}

/// Rejection when a caller asks to federate a metric that is not whitelisted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotFederated {
    pub metric_id: String,
}

impl FederationRegistry {
    pub fn new() -> Self {
        FederationRegistry::default()
    }

    /// Whitelist a metric id as federatable.
    pub fn allow(mut self, metric_id: &str) -> Self {
        self.federated.insert(metric_id.to_string());
        self
    }

    pub fn is_federated(&self, metric_id: &str) -> bool {
        self.federated.contains(metric_id)
    }

    /// Guard the federation boundary: `Ok(())` iff the metric is whitelisted, else the call is
    /// rejected *before any bank is contacted* (§6.2 step 1).
    pub fn require_federated(&self, metric_id: &str) -> Result<(), NotFederated> {
        if self.is_federated(metric_id) {
            Ok(())
        } else {
            Err(NotFederated {
                metric_id: metric_id.to_string(),
            })
        }
    }
}

// ---------------------------------------------------------------------------------------
// Deterministic differential-privacy noise (§6.2 step 3)
// ---------------------------------------------------------------------------------------

/// A seeded splitmix64 step — a tiny, dependency-free PRNG used ONLY to make the DP draw
/// deterministic and reproducible from an explicit seed (never a system RNG).
fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Map a 64-bit draw to a uniform `f64` in `[0, 1)` using the top 53 bits (full mantissa).
fn unit_f64(x: u64) -> f64 {
    (x >> 11) as f64 / ((1u64 << 53) as f64)
}

/// DP calibration for one metric: the query's sensitivity (max change from one record) and the
/// ε spent. Laplace scale is `sensitivity / epsilon` — smaller ε (stronger privacy) = more noise.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct DpParams {
    pub epsilon: f64,
    pub sensitivity: f64,
}

impl DpParams {
    /// Laplace scale `b = sensitivity / epsilon`. Guards ε<=0 by treating it as maximal noise.
    pub fn scale(&self) -> f64 {
        if self.epsilon <= 0.0 {
            f64::INFINITY
        } else {
            self.sensitivity / self.epsilon
        }
    }
}

/// Deterministic Laplace(0, scale) sample via inverse-CDF from a seeded uniform. Two calls with
/// the same seed and scale produce the same value (reproducible for audit); different seeds
/// (e.g. derived from `query_hash + bank_id`) give independent draws.
pub fn laplace_noise(seed: u64, scale: f64) -> f64 {
    if !scale.is_finite() || scale <= 0.0 {
        return 0.0;
    }
    let mut s = seed ^ 0xD1B5_4A32_D192_ED03;
    let raw = splitmix64(&mut s);
    // Uniform in (-0.5, 0.5), clamped off the poles so ln() is finite.
    let mut u = unit_f64(raw) - 0.5;
    if u <= -0.5 {
        u = -0.5 + 1e-12;
    }
    let sign = if u < 0.0 { -1.0 } else { 1.0 };
    let mag = (1.0 - 2.0 * u.abs()).max(1e-12);
    -scale * sign * mag.ln()
}

/// A bank's LOCAL partial for one bucket, computed inside the bank's boundary. `true_value` and
/// `underlying_count` never leave the tenant — only the noised form ([`NoisedPartial`]) does.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BankPartial {
    pub bank_id: String,
    pub bucket: String,
    pub true_value: f64,
    pub underlying_count: u64,
}

/// The only thing transmitted across the tenant boundary: a DP-noised partial. Carries the
/// underlying transaction count for the broker's k-anonymity floor (it is a count of records,
/// not any record's content).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NoisedPartial {
    pub bank_id: String,
    pub bucket: String,
    pub value: f64,
    pub underlying_count: u64,
}

/// Add calibrated DP noise to a bank partial BEFORE it leaves the boundary (§6.2 step 3). The
/// `seed` should be derived from the query hash + bank id so the draw is per-query, per-bank,
/// and reproducible.
pub fn noise_partial(p: &BankPartial, dp: DpParams, seed: u64) -> NoisedPartial {
    NoisedPartial {
        bank_id: p.bank_id.clone(),
        bucket: p.bucket.clone(),
        value: p.true_value + laplace_noise(seed, dp.scale()),
        underlying_count: p.underlying_count,
    }
}

// ---------------------------------------------------------------------------------------
// Privacy-budget ledger (§6.3)
// ---------------------------------------------------------------------------------------

/// Refusal when a federated query would exceed the per-(metric, window) ε budget.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BudgetExhausted {
    pub metric_id: String,
    pub window: String,
    pub requested: f64,
    pub already_spent: f64,
    pub budget: f64,
}

/// Append-only per-(metric, window) ε ledger (§6.3). Each `federatedSignal` debits ε; when the
/// budget is spent, further queries against that exact metric/window are **refused** — not
/// silently re-noised weaker — which is what stops repeated queries from averaging out the noise.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct EpsilonLedger {
    spent: BTreeMap<(String, String), f64>,
}

/// One append-only ε-spend record (§6.3) — the durable unit. Replaying every record in order
/// reconstructs the ledger exactly, which is what makes the budget survive a process restart.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EpsilonSpend {
    pub metric_id: String,
    pub window: String,
    pub epsilon: f64,
    /// Monotonic sequence number within the journal (gap detection at replay).
    pub seq: u64,
}

/// The **durability seam** for the ε ledger (§6.3: "the same durability discipline as the
/// Side-Effect Ledger"). A production deployment implements this over the append-only Postgres
/// table the Event Log lives in; offline it is proven against [`InMemoryEpsilonJournal`].
///
/// **INFRA-GATED**: only the storage is. The write-ahead discipline — *persist the debit BEFORE the
/// in-memory ledger advances, and refuse the query if the persist fails* — is enforced here in
/// [`EpsilonLedger::try_spend_durable`] and is fully exercised offline.
pub trait EpsilonLedgerStore {
    /// Append one spend record durably. `false` = the append did NOT commit; the caller MUST refuse
    /// the query (never spend privacy budget that a restart would forget).
    fn append(&mut self, record: &EpsilonSpend) -> bool;
    /// Every record ever appended, in order — replayed at startup to rebuild the ledger.
    fn load(&self) -> Vec<EpsilonSpend>;
}

/// The offline reference journal: an in-process append-only log with an injectable write failure,
/// so the fail-closed write-ahead path is a tested behaviour rather than a claim.
#[derive(Debug, Clone, Default)]
pub struct InMemoryEpsilonJournal {
    records: Vec<EpsilonSpend>,
    /// When set, the next `append` fails (models a durable-store outage).
    pub fail_next_append: bool,
}

impl InMemoryEpsilonJournal {
    pub fn new() -> Self {
        InMemoryEpsilonJournal::default()
    }
    pub fn len(&self) -> usize {
        self.records.len()
    }
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

impl EpsilonLedgerStore for InMemoryEpsilonJournal {
    fn append(&mut self, record: &EpsilonSpend) -> bool {
        if self.fail_next_append {
            self.fail_next_append = false;
            return false;
        }
        self.records.push(record.clone());
        true
    }
    fn load(&self) -> Vec<EpsilonSpend> {
        self.records.clone()
    }
}

/// Why a durable ε debit was refused.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EpsilonSpendError {
    /// The budget for this (metric, window) is exhausted.
    Exhausted(BudgetExhausted),
    /// The spend could not be persisted. The query is refused: an un-persisted debit would be
    /// forgotten on restart, restoring exactly the averaging-out attack the ledger bounds.
    NotDurable { metric_id: String, window: String },
}

impl EpsilonLedger {
    pub fn new() -> Self {
        EpsilonLedger::default()
    }

    /// Rebuild the ledger by replaying a durable journal (§6.3) — what a process does at startup so
    /// the privacy budget does NOT reset when the runtime restarts.
    pub fn replay(records: &[EpsilonSpend]) -> Self {
        let mut spent: BTreeMap<(String, String), f64> = BTreeMap::new();
        for r in records {
            *spent
                .entry((r.metric_id.clone(), r.window.clone()))
                .or_insert(0.0) += r.epsilon;
        }
        EpsilonLedger { spent }
    }

    /// Load the ledger from a durable store.
    pub fn load_from(store: &dyn EpsilonLedgerStore) -> Self {
        EpsilonLedger::replay(&store.load())
    }

    /// Number of durable records this ledger would have written (its journal length is the caller's
    /// concern; this is the count of distinct (metric, window) keys carrying spend).
    pub fn keys(&self) -> usize {
        self.spent.len()
    }

    /// **Write-ahead** ε debit (§6.3): check the budget, then PERSIST the spend, and only then
    /// advance the in-memory ledger. Any failure leaves the ledger unchanged and refuses the query.
    ///
    /// This is the durability discipline the in-memory-only [`try_spend`](Self::try_spend) cannot
    /// give: after a crash, [`load_from`](Self::load_from) replays the journal and the budget picks
    /// up exactly where it left off, so a restart cannot be used to re-open a spent budget.
    pub fn try_spend_durable(
        &mut self,
        store: &mut dyn EpsilonLedgerStore,
        metric_id: &str,
        window: &str,
        epsilon: f64,
        budget: f64,
    ) -> Result<f64, EpsilonSpendError> {
        let key = (metric_id.to_string(), window.to_string());
        let already = *self.spent.get(&key).unwrap_or(&0.0);
        if already + epsilon > budget + 1e-12 {
            return Err(EpsilonSpendError::Exhausted(BudgetExhausted {
                metric_id: metric_id.to_string(),
                window: window.to_string(),
                requested: epsilon,
                already_spent: already,
                budget,
            }));
        }
        let seq = store.load().len() as u64 + 1;
        let record = EpsilonSpend {
            metric_id: metric_id.to_string(),
            window: window.to_string(),
            epsilon,
            seq,
        };
        if !store.append(&record) {
            return Err(EpsilonSpendError::NotDurable {
                metric_id: metric_id.to_string(),
                window: window.to_string(),
            });
        }
        let now = already + epsilon;
        self.spent.insert(key, now);
        Ok(budget - now)
    }

    /// ε already spent against this metric/window.
    pub fn spent(&self, metric_id: &str, window: &str) -> f64 {
        *self
            .spent
            .get(&(metric_id.to_string(), window.to_string()))
            .unwrap_or(&0.0)
    }

    /// Try to debit `epsilon` against `budget` for this metric/window. On success the ledger is
    /// advanced and the remaining budget returned; on exhaustion the ledger is unchanged and the
    /// query is refused. A query that would land *exactly* on the budget is allowed; one that
    /// would exceed it is refused.
    pub fn try_spend(
        &mut self,
        metric_id: &str,
        window: &str,
        epsilon: f64,
        budget: f64,
    ) -> Result<f64, BudgetExhausted> {
        let key = (metric_id.to_string(), window.to_string());
        let already = *self.spent.get(&key).unwrap_or(&0.0);
        // Tolerance so floating-point accumulation can't spuriously reject a within-budget spend.
        if already + epsilon > budget + 1e-12 {
            return Err(BudgetExhausted {
                metric_id: metric_id.to_string(),
                window: window.to_string(),
                requested: epsilon,
                already_spent: already,
                budget,
            });
        }
        self.spent.insert(key, already + epsilon);
        Ok((budget - (already + epsilon)).max(0.0))
    }
}

// ---------------------------------------------------------------------------------------
// Broker aggregation with k-anonymity (§6.2 step 4) + disclosure (§6.4)
// ---------------------------------------------------------------------------------------

/// K-anonymity floor: a bucket must be contributed to by at least `min_banks` banks AND
/// underpinned by at least `min_underlying` transactions, or it is suppressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KAnonConfig {
    pub min_banks: usize,
    pub min_underlying: u64,
}

/// One surviving aggregate bucket.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BucketResult {
    pub bucket: String,
    pub value: f64,
    pub contributing_banks: usize,
    pub underlying_count: u64,
}

/// The broker's final federated result (§6.2 step 5). Per-bank breakdowns are `None` unless
/// disclosure was explicitly enabled — default is aggregate-only, always.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FederatedResult {
    /// Buckets that cleared the k-anonymity floor, sorted by bucket id.
    pub buckets: Vec<BucketResult>,
    /// Bucket ids that were suppressed for failing the k-floor and merged into `"other"`.
    pub suppressed_buckets: Vec<String>,
    /// The catch-all bucket accumulating suppressed cells (present iff anything was suppressed).
    pub other: Option<BucketResult>,
    /// Per-bank breakdown — `Some` only when disclosure is enabled (§6.4).
    pub per_bank: Option<Vec<NoisedPartial>>,
}

/// Aggregate noised partials across banks, applying the k-anonymity floor and disclosure policy
/// (§6.2 step 4 / §6.4). Deterministic: buckets and per-bank rows are id-sorted.
pub fn aggregate(
    partials: &[NoisedPartial],
    k: &KAnonConfig,
    disclose_per_bank: bool,
) -> FederatedResult {
    // Group by bucket → (summed value, distinct banks, summed underlying).
    let mut acc: BTreeMap<String, (f64, BTreeSet<String>, u64)> = BTreeMap::new();
    for p in partials {
        let e = acc
            .entry(p.bucket.clone())
            .or_insert((0.0, BTreeSet::new(), 0));
        e.0 += p.value;
        e.1.insert(p.bank_id.clone());
        e.2 = e.2.saturating_add(p.underlying_count);
    }

    let mut buckets = Vec::new();
    let mut suppressed_buckets = Vec::new();
    let mut other_value = 0.0f64;
    let mut other_banks: BTreeSet<String> = BTreeSet::new();
    let mut other_underlying = 0u64;
    let mut any_suppressed = false;

    for (bucket, (value, banks, underlying)) in acc {
        if banks.len() >= k.min_banks && underlying >= k.min_underlying {
            buckets.push(BucketResult {
                bucket,
                value,
                contributing_banks: banks.len(),
                underlying_count: underlying,
            });
        } else {
            any_suppressed = true;
            suppressed_buckets.push(bucket);
            other_value += value;
            other_banks.extend(banks);
            other_underlying = other_underlying.saturating_add(underlying);
        }
    }

    let other = if any_suppressed {
        Some(BucketResult {
            bucket: "other".to_string(),
            value: other_value,
            contributing_banks: other_banks.len(),
            underlying_count: other_underlying,
        })
    } else {
        None
    };

    let per_bank = if disclose_per_bank {
        let mut rows = partials.to_vec();
        rows.sort_by(|a, b| {
            a.bank_id
                .cmp(&b.bank_id)
                .then_with(|| a.bucket.cmp(&b.bucket))
        });
        Some(rows)
    } else {
        None
    };

    FederatedResult {
        buckets,
        suppressed_buckets,
        other,
        per_bank,
    }
}

// ---------------------------------------------------------------------------------------
// Federated Query Broker: dispatch + tenant isolation (§6.1)
// ---------------------------------------------------------------------------------------

/// A member-bank tenant, addressed only through this seam. The broker never holds a bank's
/// credentials and never reads its rows; it asks the tenant to compute its OWN local partials
/// **inside its own boundary** and return them already DP-noised. A real deployment implements
/// this over an authenticated per-tenant transport (mTLS to the bank's federated agent); physical
/// tenant isolation (separate schema/namespace, no cross-tenant read credential) is the infra
/// property this seam assumes (§6.1).
pub trait BankTenant {
    /// The tenant's own bank id — the broker asserts every returned partial carries THIS id, so a
    /// tenant cannot (accidentally or maliciously) speak for another bank.
    fn bank_id(&self) -> &str;

    /// Compute this tenant's local, already-noised partials for the compiled metric/window inside
    /// the tenant boundary. `None` = the tenant was unreachable or refused (broker treats a missing
    /// tenant as contributing nothing, never as zero — see [`DispatchReport::unreachable`]).
    fn local_partials(&self, metric_id: &str, window: &str) -> Option<Vec<NoisedPartial>>;
}

/// Why a federated dispatch was refused before any aggregation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FederationError {
    /// The metric is not on the git-reviewed federated whitelist (§6.2 step 1).
    NotFederated { metric_id: String },
    /// The per-(metric, window) ε budget is exhausted (§6.3) — refused, not silently re-noised.
    BudgetExhausted(BudgetExhausted),
    /// A tenant returned a partial attributed to a DIFFERENT bank id — a tenant-isolation
    /// violation (§6.1). The whole dispatch is aborted: no bank may speak for another.
    TenantIsolationViolation {
        expected_bank: String,
        got_bank: String,
    },
}

/// The result of a broker dispatch: the aggregate plus which tenants were reachable, for audit.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DispatchReport {
    pub result: FederatedResult,
    /// Bank ids that returned partials.
    pub contributed: Vec<String>,
    /// Bank ids that were unreachable/refused (contributed nothing — NOT counted as zero).
    pub unreachable: Vec<String>,
    /// ε remaining in the ledger for this metric/window after the debit.
    pub epsilon_remaining: f64,
    /// Contributing banks that have **no standing per-metric-class disclosure consent** (§6.4).
    /// Non-empty ⇒ the per-bank breakdown was withheld from `result.per_bank` even though the
    /// caller asked for it. Recorded (never silently dropped) so the refusal is auditable.
    #[serde(default)]
    pub disclosure_withheld_for: Vec<String>,
}

// ---------------------------------------------------------------------------------------
// Per-bank disclosure consent (§6.4) — a git-reviewed control-plane record, not a caller bool
// ---------------------------------------------------------------------------------------

/// One member bank's standing, git-reviewed opt-in to per-bank disclosure, for a specific set of
/// metric classes (`control-plane/federation/disclosure-consent/{bank_id}.yml`, §6.4). Revocable by
/// that bank: setting `revoked` (or removing the file) withdraws it for every metric class at once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisclosureConsent {
    pub bank_id: String,
    /// The metric CLASSES (not individual metric ids) this bank consents to be named in.
    #[serde(default)]
    pub metric_classes: BTreeSet<String>,
    /// A bank may revoke at any time; a revoked record is retained (for audit) but consents to
    /// nothing.
    #[serde(default)]
    pub revoked: bool,
}

impl DisclosureConsent {
    pub fn new(bank_id: &str) -> Self {
        DisclosureConsent {
            bank_id: bank_id.to_string(),
            metric_classes: BTreeSet::new(),
            revoked: false,
        }
    }

    /// Opt in to being named in per-bank breakdowns of one metric class.
    pub fn allow_class(mut self, metric_class: &str) -> Self {
        self.metric_classes.insert(metric_class.to_string());
        self
    }

    pub fn revoked(mut self) -> Self {
        self.revoked = true;
        self
    }

    fn permits(&self, metric_class: &str) -> bool {
        !self.revoked && self.metric_classes.contains(metric_class)
    }
}

/// Why a disclosure-consent control-plane load failed closed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsentLoadError {
    Parse {
        file_id: String,
        error: String,
    },
    /// The record's declared `bank_id` does not match the file it lives in — exactly the drift a
    /// per-bank file layout exists to make reviewable.
    BankIdMismatch {
        file_id: String,
        declared: String,
    },
    Duplicate {
        bank_id: String,
    },
}

/// The loaded set of per-bank disclosure consents. **Absence is refusal**: a bank with no record
/// (or a revoked one, or one that does not name this metric class) is never disclosed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisclosureConsentRegistry {
    consents: BTreeMap<String, DisclosureConsent>,
}

impl DisclosureConsentRegistry {
    pub fn new() -> Self {
        DisclosureConsentRegistry::default()
    }

    /// Build from already-read control-plane records (the caller does the `std::fs` walk, exactly
    /// as for the metric catalog — this crate stays I/O-free). All-or-nothing.
    pub fn load(records: Vec<DisclosureConsent>) -> Result<Self, ConsentLoadError> {
        let mut consents: BTreeMap<String, DisclosureConsent> = BTreeMap::new();
        for r in records {
            if consents.contains_key(&r.bank_id) {
                return Err(ConsentLoadError::Duplicate { bank_id: r.bank_id });
            }
            consents.insert(r.bank_id.clone(), r);
        }
        Ok(DisclosureConsentRegistry { consents })
    }

    /// Parse + load a set of `{bank_id}.json` control-plane files the caller has already read
    /// (`file_id` = the file's bank id). A record whose declared `bank_id` disagrees with its file
    /// fails the WHOLE load.
    pub fn load_from_files(files: &[(&str, &str)]) -> Result<Self, ConsentLoadError> {
        let mut records = Vec::with_capacity(files.len());
        for (file_id, json) in files {
            let r: DisclosureConsent =
                serde_json::from_str(json).map_err(|e| ConsentLoadError::Parse {
                    file_id: file_id.to_string(),
                    error: e.to_string(),
                })?;
            if r.bank_id != *file_id {
                return Err(ConsentLoadError::BankIdMismatch {
                    file_id: file_id.to_string(),
                    declared: r.bank_id,
                });
            }
            records.push(r);
        }
        DisclosureConsentRegistry::load(records)
    }

    /// Does this bank consent to being named in a per-bank breakdown of `metric_class`?
    pub fn permits(&self, bank_id: &str, metric_class: &str) -> bool {
        self.consents
            .get(bank_id)
            .is_some_and(|c| c.permits(metric_class))
    }

    /// The contributing banks that do NOT consent — non-empty means the breakdown is withheld.
    pub fn withheld(&self, banks: &[String], metric_class: &str) -> Vec<String> {
        banks
            .iter()
            .filter(|b| !self.permits(b, metric_class))
            .cloned()
            .collect()
    }
}

/// The Federated Query Broker (§6.1). Composes the whole tier end to end:
/// whitelist gate → ε-budget debit → per-tenant dispatch through the [`BankTenant`] seam →
/// **tenant-isolation enforcement** (every partial must carry its own tenant's bank id) →
/// k-anonymity aggregation → aggregate-only result (per-bank disclosure only on explicit opt-in).
///
/// The broker itself never touches raw rows or cross-tenant credentials; it orchestrates the
/// isolated tenants and the privacy machinery. `dispatch` is fail-closed at every gate.
pub struct FederatedBroker<'a> {
    pub registry: &'a FederationRegistry,
    pub k: KAnonConfig,
    /// DP calibration applied by tenants; carried for audit/provenance in the report path.
    pub dp: DpParams,
    /// The §6.4 per-bank disclosure consents. `None` = **no consent record is loaded at all**, so
    /// no per-bank breakdown is ever disclosed regardless of what the caller asks for.
    pub consent: Option<&'a DisclosureConsentRegistry>,
    /// The metric CLASS consent is checked against (§6.4 is per-metric-class, not per-metric-id).
    /// Defaults to the metric id when a deployment has not classified its metrics — strictly the
    /// narrower reading, so an unclassified metric cannot ride on a broad class consent.
    pub metric_class: Option<String>,
}

impl<'a> FederatedBroker<'a> {
    pub fn new(registry: &'a FederationRegistry, k: KAnonConfig, dp: DpParams) -> Self {
        FederatedBroker {
            registry,
            k,
            dp,
            consent: None,
            metric_class: None,
        }
    }

    /// Attach the loaded §6.4 disclosure-consent control plane. Without this, per-bank disclosure
    /// is structurally impossible (the fail-closed default).
    pub fn with_consent(mut self, consent: &'a DisclosureConsentRegistry) -> Self {
        self.consent = Some(consent);
        self
    }

    /// Set the metric class consent is evaluated against (defaults to the metric id).
    pub fn with_metric_class(mut self, metric_class: &str) -> Self {
        self.metric_class = Some(metric_class.to_string());
        self
    }

    /// Run a federated query. Debits `epsilon` (against `budget`) on the shared [`EpsilonLedger`]
    /// only after the whitelist check passes; if the budget is exhausted the query is refused and
    /// the ledger is left unchanged. Then dispatches to every tenant, enforcing that each tenant
    /// speaks only for itself, and aggregates under the k-anonymity floor.
    #[allow(clippy::too_many_arguments)]
    pub fn dispatch(
        &self,
        metric_id: &str,
        window: &str,
        epsilon: f64,
        budget: f64,
        ledger: &mut EpsilonLedger,
        tenants: &[&dyn BankTenant],
        disclose_per_bank: bool,
    ) -> Result<DispatchReport, FederationError> {
        // 1. Whitelist gate — refuse before contacting any bank.
        self.registry
            .require_federated(metric_id)
            .map_err(|e| FederationError::NotFederated {
                metric_id: e.metric_id,
            })?;

        // 2. Privacy-budget debit — refuse (and leave ledger unchanged) if exhausted.
        let epsilon_remaining = ledger
            .try_spend(metric_id, window, epsilon, budget)
            .map_err(FederationError::BudgetExhausted)?;

        // 3. Dispatch to each isolated tenant, enforcing tenant isolation.
        let mut all_partials: Vec<NoisedPartial> = Vec::new();
        let mut contributed: Vec<String> = Vec::new();
        let mut unreachable: Vec<String> = Vec::new();
        for t in tenants {
            match t.local_partials(metric_id, window) {
                None => unreachable.push(t.bank_id().to_string()),
                Some(partials) => {
                    for p in &partials {
                        if p.bank_id != t.bank_id() {
                            // A tenant tried to attribute data to another bank — abort.
                            return Err(FederationError::TenantIsolationViolation {
                                expected_bank: t.bank_id().to_string(),
                                got_bank: p.bank_id.clone(),
                            });
                        }
                    }
                    if !partials.is_empty() {
                        contributed.push(t.bank_id().to_string());
                    }
                    all_partials.extend(partials);
                }
            }
        }
        contributed.sort();
        contributed.dedup();
        unreachable.sort();

        // 4. §6.4 disclosure-consent gate: a per-bank breakdown is included ONLY if EVERY
        // contributing bank has a standing, un-revoked, per-metric-class opt-in in the loaded
        // consent control plane. A caller-supplied `disclose_per_bank` is a *request*, never an
        // authorization — with no consent registry loaded, or any bank missing/revoked, the
        // breakdown is withheld and the aggregate still ships (never a hard failure).
        let metric_class = self
            .metric_class
            .clone()
            .unwrap_or_else(|| metric_id.to_string());
        let disclosure_withheld_for: Vec<String> = if disclose_per_bank {
            match self.consent {
                Some(c) => c.withheld(&contributed, &metric_class),
                None => contributed.clone(),
            }
        } else {
            Vec::new()
        };
        let disclose = disclose_per_bank && disclosure_withheld_for.is_empty();

        // 5. Aggregate under the k-anonymity floor + the consent-gated disclosure decision.
        let result = aggregate(&all_partials, &self.k, disclose);
        Ok(DispatchReport {
            result,
            contributed,
            unreachable,
            epsilon_remaining,
            disclosure_withheld_for,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn np(bank: &str, bucket: &str, value: f64, underlying: u64) -> NoisedPartial {
        NoisedPartial {
            bank_id: bank.into(),
            bucket: bucket.into(),
            value,
            underlying_count: underlying,
        }
    }

    // --- whitelist (§6.2) ----------------------------------------------------------

    #[test]
    fn non_whitelisted_metric_is_rejected_before_contacting_banks() {
        let reg = FederationRegistry::new().allow("mule_velocity");
        assert!(reg.require_federated("mule_velocity").is_ok());
        let err = reg
            .require_federated("account_balance_snapshot")
            .unwrap_err();
        assert_eq!(err.metric_id, "account_balance_snapshot");
    }

    // --- DP noise (§6.2 step 3) ----------------------------------------------------

    #[test]
    fn laplace_is_deterministic_and_zero_for_degenerate_scale() {
        // Same seed + scale → identical draw (reproducible for audit).
        assert_eq!(laplace_noise(42, 2.0), laplace_noise(42, 2.0));
        // Different seeds → (almost surely) different draws.
        assert_ne!(laplace_noise(1, 2.0), laplace_noise(2, 2.0));
        // Non-positive / non-finite scale → no noise (never NaN).
        assert_eq!(laplace_noise(7, 0.0), 0.0);
        assert_eq!(laplace_noise(7, f64::INFINITY), 0.0);
    }

    #[test]
    fn noise_calibrates_to_epsilon_and_hides_the_true_value() {
        let p = BankPartial {
            bank_id: "b1".into(),
            bucket: "reason_a".into(),
            true_value: 100.0,
            underlying_count: 5000,
        };
        // Strong privacy (small ε) → large scale → the transmitted value is NOT the true value.
        let strong = noise_partial(
            &p,
            DpParams {
                epsilon: 0.1,
                sensitivity: 1.0,
            },
            123,
        );
        assert!(
            (strong.value - 100.0).abs() > 1e-9,
            "noise must perturb the value"
        );
        // The true value never leaves: underlying_count is transmitted (a count, not content).
        assert_eq!(strong.underlying_count, 5000);
        // Averaging MANY independent draws recovers the true value in expectation (Laplace is
        // zero-mean) — this is precisely why §6.3's ε ledger must bound repeated queries.
        let mean: f64 = (0..4000)
            .map(|s| {
                noise_partial(
                    &p,
                    DpParams {
                        epsilon: 1.0,
                        sensitivity: 1.0,
                    },
                    s,
                )
                .value
            })
            .sum::<f64>()
            / 4000.0;
        assert!(
            (mean - 100.0).abs() < 3.0,
            "noise is zero-mean (got {mean})"
        );
    }

    // --- ε ledger (§6.3) -----------------------------------------------------------

    #[test]
    fn ledger_debits_then_refuses_when_budget_exhausted() {
        let mut led = EpsilonLedger::new();
        // Budget 1.0; three 0.4 spends → third exceeds and is refused.
        // Remaining budget is a float sum — compare with tolerance (0.2 is not bit-exact in f64).
        assert!((led.try_spend("m", "2026-07", 0.4, 1.0).unwrap() - 0.6).abs() < 1e-9);
        assert!((led.try_spend("m", "2026-07", 0.4, 1.0).unwrap() - 0.2).abs() < 1e-9);
        let refused = led.try_spend("m", "2026-07", 0.4, 1.0).unwrap_err();
        assert!((refused.already_spent - 0.8).abs() < 1e-9);
        assert_eq!(refused.budget, 1.0);
        // The refused spend did NOT advance the ledger.
        assert!((led.spent("m", "2026-07") - 0.8).abs() < 1e-9);
        // A different window has its own fresh budget.
        assert!(led.try_spend("m", "2026-08", 0.4, 1.0).is_ok());
    }

    #[test]
    fn ledger_allows_spend_landing_exactly_on_budget() {
        let mut led = EpsilonLedger::new();
        assert_eq!(led.try_spend("m", "w", 1.0, 1.0), Ok(0.0));
        assert!(led.try_spend("m", "w", 0.0001, 1.0).is_err());
    }

    // --- k-anonymity + aggregation (§6.2 step 4) -----------------------------------

    #[test]
    fn small_cell_is_suppressed_into_other_not_returned_distinctly() {
        let k = KAnonConfig {
            min_banks: 3,
            min_underlying: 100,
        };
        let partials = vec![
            // "reason_a": 3 banks, plenty underlying → survives.
            np("b1", "reason_a", 10.0, 200),
            np("b2", "reason_a", 12.0, 300),
            np("b3", "reason_a", 9.0, 150),
            // "reason_rare": only 2 banks → below min_banks → suppressed.
            np("b1", "reason_rare", 1.0, 40),
            np("b2", "reason_rare", 1.0, 30),
        ];
        let res = aggregate(&partials, &k, false);
        // reason_a survives; reason_rare is suppressed and merged into "other".
        assert_eq!(res.buckets.len(), 1);
        assert_eq!(res.buckets[0].bucket, "reason_a");
        assert_eq!(res.buckets[0].contributing_banks, 3);
        assert_eq!(res.suppressed_buckets, vec!["reason_rare".to_string()]);
        let other = res.other.expect("suppressed cells merge into other");
        assert!((other.value - 2.0).abs() < 1e-9);
        assert_eq!(other.contributing_banks, 2);
        // The rare bucket is NOT independently visible.
        assert!(res.buckets.iter().all(|b| b.bucket != "reason_rare"));
    }

    #[test]
    fn underlying_transaction_floor_also_suppresses() {
        // 3 banks (passes min_banks) but too few underlying transactions → still suppressed.
        let k = KAnonConfig {
            min_banks: 3,
            min_underlying: 1000,
        };
        let partials = vec![
            np("b1", "reason_a", 1.0, 5),
            np("b2", "reason_a", 1.0, 5),
            np("b3", "reason_a", 1.0, 5),
        ];
        let res = aggregate(&partials, &k, false);
        assert!(
            res.buckets.is_empty(),
            "the underlying-count floor must suppress"
        );
        assert_eq!(res.suppressed_buckets, vec!["reason_a".to_string()]);
    }

    // --- disclosure opt-in (§6.4) --------------------------------------------------

    #[test]
    fn per_bank_breakdown_withheld_by_default() {
        let k = KAnonConfig {
            min_banks: 1,
            min_underlying: 0,
        };
        let partials = vec![np("b1", "x", 5.0, 10), np("b2", "x", 6.0, 20)];
        // Default: aggregate-only.
        let default = aggregate(&partials, &k, false);
        assert!(
            default.per_bank.is_none(),
            "per-bank rows are withheld by default"
        );
        assert_eq!(default.buckets.len(), 1);
        // With explicit disclosure consent: per-bank rows included, id-sorted.
        let disclosed = aggregate(&partials, &k, true);
        let rows = disclosed.per_bank.expect("disclosure enabled");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].bank_id, "b1");
        assert_eq!(rows[1].bank_id, "b2");
    }

    #[test]
    fn end_to_end_bank_side_noise_then_broker_aggregate() {
        // Two banks noise their partials locally, then the broker aggregates — the broker never
        // sees a true value, only noised partials + underlying counts.
        let reg = FederationRegistry::new().allow("mule_velocity");
        reg.require_federated("mule_velocity").expect("whitelisted");
        let dp = DpParams {
            epsilon: 5.0,
            sensitivity: 1.0,
        }; // light noise for a stable assert
        let locals = [
            BankPartial {
                bank_id: "b1".into(),
                bucket: "high".into(),
                true_value: 50.0,
                underlying_count: 800,
            },
            BankPartial {
                bank_id: "b2".into(),
                bucket: "high".into(),
                true_value: 70.0,
                underlying_count: 900,
            },
            BankPartial {
                bank_id: "b3".into(),
                bucket: "high".into(),
                true_value: 60.0,
                underlying_count: 700,
            },
        ];
        let noised: Vec<NoisedPartial> = locals
            .iter()
            .enumerate()
            .map(|(i, p)| noise_partial(p, dp, i as u64 + 1))
            .collect();
        let k = KAnonConfig {
            min_banks: 3,
            min_underlying: 100,
        };
        let res = aggregate(&noised, &k, false);
        assert_eq!(res.buckets.len(), 1);
        // True sum is 180; with light noise the aggregate is close but not exact.
        let v = res.buckets[0].value;
        assert!(
            (v - 180.0).abs() < 30.0,
            "noised aggregate near true sum (got {v})"
        );
        assert_eq!(res.buckets[0].contributing_banks, 3);
        assert!(res.per_bank.is_none());
    }

    // --- broker dispatch + tenant isolation (§6.1) ---------------------------------

    /// A fake in-boundary tenant returning pre-noised partials (or `None` = unreachable).
    struct FakeTenant {
        id: String,
        partials: Option<Vec<NoisedPartial>>,
    }
    impl BankTenant for FakeTenant {
        fn bank_id(&self) -> &str {
            &self.id
        }
        fn local_partials(&self, _metric_id: &str, _window: &str) -> Option<Vec<NoisedPartial>> {
            self.partials.clone()
        }
    }

    fn broker_reg() -> FederationRegistry {
        FederationRegistry::new().allow("mule_velocity")
    }

    #[test]
    fn gap_ctx_08_broker_dispatches_aggregates_and_debits_ledger() {
        let reg = broker_reg();
        let broker = FederatedBroker::new(
            &reg,
            KAnonConfig {
                min_banks: 3,
                min_underlying: 100,
            },
            DpParams {
                epsilon: 1.0,
                sensitivity: 1.0,
            },
        );
        let t1 = FakeTenant {
            id: "b1".into(),
            partials: Some(vec![np("b1", "high", 50.0, 400)]),
        };
        let t2 = FakeTenant {
            id: "b2".into(),
            partials: Some(vec![np("b2", "high", 60.0, 500)]),
        };
        let t3 = FakeTenant {
            id: "b3".into(),
            partials: Some(vec![np("b3", "high", 70.0, 600)]),
        };
        let mut ledger = EpsilonLedger::new();
        let report = broker
            .dispatch(
                "mule_velocity",
                "2026-07",
                0.5,
                1.0,
                &mut ledger,
                &[&t1, &t2, &t3],
                false,
            )
            .expect("dispatch ok");
        assert_eq!(report.result.buckets.len(), 1);
        assert_eq!(report.result.buckets[0].contributing_banks, 3);
        assert_eq!(report.contributed, vec!["b1", "b2", "b3"]);
        assert!(
            report.result.per_bank.is_none(),
            "aggregate-only by default"
        );
        // Ledger was debited 0.5 of 1.0.
        assert!((report.epsilon_remaining - 0.5).abs() < 1e-9);
        assert!((ledger.spent("mule_velocity", "2026-07") - 0.5).abs() < 1e-9);
    }

    #[test]
    fn gap_ctx_08_broker_refuses_non_whitelisted_and_exhausted_budget() {
        let reg = broker_reg();
        let broker = FederatedBroker::new(
            &reg,
            KAnonConfig {
                min_banks: 1,
                min_underlying: 0,
            },
            DpParams {
                epsilon: 1.0,
                sensitivity: 1.0,
            },
        );
        let t = FakeTenant {
            id: "b1".into(),
            partials: Some(vec![np("b1", "x", 1.0, 10)]),
        };
        let mut ledger = EpsilonLedger::new();

        // Non-whitelisted metric → refused before contacting banks, ledger untouched.
        let err = broker
            .dispatch("account_balance", "w", 0.1, 1.0, &mut ledger, &[&t], false)
            .unwrap_err();
        assert!(matches!(err, FederationError::NotFederated { .. }));
        assert_eq!(ledger.spent("account_balance", "w"), 0.0);

        // Exhaust the budget, then the next dispatch is refused.
        broker
            .dispatch("mule_velocity", "w", 1.0, 1.0, &mut ledger, &[&t], false)
            .unwrap();
        let refused = broker
            .dispatch("mule_velocity", "w", 0.5, 1.0, &mut ledger, &[&t], false)
            .unwrap_err();
        assert!(matches!(refused, FederationError::BudgetExhausted(_)));
    }

    #[test]
    fn gap_ctx_08_broker_enforces_tenant_isolation() {
        let reg = broker_reg();
        let broker = FederatedBroker::new(
            &reg,
            KAnonConfig {
                min_banks: 1,
                min_underlying: 0,
            },
            DpParams {
                epsilon: 1.0,
                sensitivity: 1.0,
            },
        );
        // b1 tries to return a partial attributed to b2 — must abort the whole dispatch.
        let rogue = FakeTenant {
            id: "b1".into(),
            partials: Some(vec![np("b2", "x", 1.0, 10)]),
        };
        let mut ledger = EpsilonLedger::new();
        let err = broker
            .dispatch(
                "mule_velocity",
                "w",
                0.1,
                1.0,
                &mut ledger,
                &[&rogue],
                false,
            )
            .unwrap_err();
        assert_eq!(
            err,
            FederationError::TenantIsolationViolation {
                expected_bank: "b1".into(),
                got_bank: "b2".into()
            }
        );
    }

    #[test]
    fn gap_ctx_08_broker_reports_unreachable_tenants_not_as_zero() {
        let reg = broker_reg();
        let broker = FederatedBroker::new(
            &reg,
            KAnonConfig {
                min_banks: 2,
                min_underlying: 0,
            },
            DpParams {
                epsilon: 1.0,
                sensitivity: 1.0,
            },
        );
        let t1 = FakeTenant {
            id: "b1".into(),
            partials: Some(vec![np("b1", "x", 1.0, 10)]),
        };
        let down = FakeTenant {
            id: "b2".into(),
            partials: None,
        };
        let t3 = FakeTenant {
            id: "b3".into(),
            partials: Some(vec![np("b3", "x", 1.0, 10)]),
        };
        let mut ledger = EpsilonLedger::new();
        let report = broker
            .dispatch(
                "mule_velocity",
                "w",
                0.1,
                1.0,
                &mut ledger,
                &[&t1, &down, &t3],
                false,
            )
            .unwrap();
        assert_eq!(report.unreachable, vec!["b2"]);
        assert_eq!(report.contributed, vec!["b1", "b3"]);
    }
}
