// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Route-ready entrypoints for the data-lifecycle surface (`REGULATED_FI_COMPLIANCE_OPS.md`
//! §4.4 DSAR workflow + §6 retention-floor / legal-hold / deferred-erasure precedence store).
//!
//! [`crate::dsar`] and [`crate`] hold the *engines*: [`DsarRegister`], [`RecordStore`], the
//! precedence functions. A transport needs a single, capability-gated, serde-round-trippable call it
//! can mount per route — this module is that seam. Two route-ready services:
//!
//! - [`DsarWorkflow`] — the §4.4 access / correction / erasure / grievance state machine. It owns the
//!   hash-chained [`DsarRegister`] and dispatches a [`DsarCommand`]; the RBAC gate is
//!   [`CAP_DSAR_OPERATE`]. Erasure runs **through** the caller's [`RecordStore`] (so §6 precedence
//!   applies); access resolves the caller-assembled cross-tier [`CompleteLineage`].
//! - [`RetentionService`] — the §6 precedence store. It owns the [`RecordStore`] and dispatches a
//!   [`RetentionCommand`] (set-policy / open-hold / release-hold / purge / request-erasure /
//!   run-deferred); the RBAC gate is [`CAP_RETENTION_ADMIN`].
//!
//! Both are pure and deterministic (logical `now` injected — no clock/RNG/I/O). **Instantiation on
//! the served daemon is `ainxt-runtimed`'s hot-wiring**: it owns one shared [`RecordStore`] (durable,
//! behind the store seam), passes `retention.store_mut()` into [`DsarWorkflow::handle`] for erasure,
//! and hydrates the live cross-tier lineage. Nothing here reaches for infrastructure directly.

use serde::{Deserialize, Serialize};

use ainxt_types::{Principal, Role};

use crate::dsar::{CompleteLineage, DsarError, DsarKind, DsarRegister, DsarRequest, LineageExport};
use crate::{ErasureResolution, LegalHold, RecordStore, RetentionPolicy};

/// Capability admitting the DSAR operator surface (the DPO / privacy officer who runs a request on a
/// subject's behalf). `role == Admin` implies it, per [`Principal::has_cap`].
pub const CAP_DSAR_OPERATE: &str = "dsar.operate";

/// GAP-FIX regulated-fi-responsible-lifecycle (FI-09 RBAC decision) — the extra gate
/// [`DsarWorkflow::handle`]'s `Access` arm (and [`DsarWorkflow::fulfill_access`]) require ON TOP OF
/// [`CAP_DSAR_OPERATE`]. Access/portability is categorically more sensitive than the other DSAR ops:
/// erasure/correction/grievance act on already-known individual records, but a completeness-checked
/// Access export assembles and hands back the subject's ENTIRE cross-tier PII footprint (session +
/// episodic + semantic memory, embeddings, traces, incident linkage) in a single payload — the highest-
/// value exfiltration target this surface exposes. Any `CAP_DSAR_OPERATE` holder (a DPO clerk doing
/// routine intake) is not automatically commensurate with that; this additionally requires the operator
/// to be a senior/approving actor, mirroring the platform's existing `can_approve` JWT claim
/// (`ad_level <= 3` — see `CLAUDE.md` Auth section) carried onto [`Principal::ad_level`].
/// `Role::Admin` still implies it (the same admin bypass [`Principal::has_cap`] already grants
/// everywhere else). Fail-closed: a principal with no `ad_level` (predates the claim, or is genuinely
/// unscoped) is REFUSED, never allowed by omission — the same posture [`Principal::ad_level`]'s own doc
/// mandates for the Context-Fabric RBAC axis.
pub fn can_approve_dsar_access(principal: &Principal) -> bool {
    principal.role == Role::Admin || matches!(principal.ad_level, Some(level) if level <= 3)
}

/// Capability admitting the retention / legal-hold administration surface (custodian / DPO).
pub const CAP_RETENTION_ADMIN: &str = "retention.admin";

// ============================ DSAR workflow (§4.4) ============================

/// One DSAR command the route-ready [`DsarWorkflow::handle`] dispatches. `now` (the logical tick) is
/// supplied by the caller, not embedded, so the same command replays deterministically.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case", deny_unknown_fields)]
pub enum DsarCommand {
    /// Open a new DSAR (status `Received`). `sla_ticks` is the DPDP response window.
    Open {
        id: String,
        subject_id: String,
        kind: DsarKind,
        sla_ticks: u64,
    },
    /// Identity-proof the data principal (§4.4 step 1). `proof_ok=false` terminates without leak.
    Authenticate { id: String, proof_ok: bool },
    /// Record a correction fulfilment for `n_records`.
    Correct { id: String, n_records: usize },
    /// Fulfil an erasure **through §6 precedence** against the caller's [`RecordStore`].
    Erase { id: String },
    /// Route a grievance to the DPO.
    Grievance { id: String },
    /// GAP-FIX regulated-fi-responsible-lifecycle (FI-09) — fulfil an access/portability request
    /// against a caller-hydrated cross-tier `lineage` (`DsarWorkflow::handle`'s `lineage` param —
    /// used ONLY by this variant, mirroring how `store` is used only by [`DsarCommand::Erase`]).
    /// `require_complete` mirrors [`crate::dsar::DsarRegister::fulfill_access_complete`]'s own flag:
    /// `true` refuses the export if any mandated tier has no live resolver rather than certifying a
    /// partial one. Additionally gated on [`can_approve_dsar_access`] (see that function's doc) — this
    /// is the one DSAR op that is NOT authorized by [`CAP_DSAR_OPERATE`] alone.
    Access {
        id: String,
        #[serde(default = "default_require_complete")]
        require_complete: bool,
    },
}

/// `DsarCommand::Access`'s default `require_complete` when the wire caller omits it — fail-closed
/// (never silently certify a best-effort export).
fn default_require_complete() -> bool {
    true
}

/// The serializable outcome of a [`DsarWorkflow::handle`] call. Every variant carries the post-command
/// [`DsarRequest`] snapshot (status, SLA deadline) a transport returns to the caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "kebab-case")]
pub enum DsarOutcome {
    /// A state transition with no data payload (open / authenticate / correct / grievance).
    Receipt { request: DsarRequest },
    /// An erasure fulfilment, carrying which records were erased now and which were deferred (§6).
    Erasure {
        request: DsarRequest,
        resolution: ErasureResolution,
    },
    /// An access/portability fulfilment — the completeness-checked cross-tier export
    /// ([`DsarCommand::Access`]).
    AccessExport {
        request: DsarRequest,
        export: LineageExport,
    },
}

/// Why a route-ready DSAR call was refused — the serializable superset of [`DsarError`] plus
/// [`NotAuthorized`](DsarRouteError::NotAuthorized). A transport maps `NotAuthorized`→403,
/// `UnknownRequest`→404, everything else→409/422.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum DsarRouteError {
    /// The caller does not hold [`CAP_DSAR_OPERATE`] (checked before any state lookup). → 403.
    NotAuthorized,
    UnknownRequest(String),
    DuplicateRequest(String),
    /// A fulfilment was attempted before identity proofing (would act without authentication).
    IdentityNotProofed(String),
    /// The op does not match the request's kind (e.g. erasure on an access request).
    WrongKind {
        expected: String,
        got: String,
    },
    AlreadyTerminal(String),
    /// A completeness-required access fulfilment was refused because a mandated tier had no resolver.
    IncompleteLineage {
        missing: Vec<String>,
    },
    /// [`DsarCommand::Access`] was dispatched through [`DsarWorkflow::handle`] with no hydrated
    /// `lineage` argument. Distinct from `IncompleteLineage` (a lineage WAS hydrated but is partial):
    /// this means the caller (the served transport / an embedder) never attempted hydration at all —
    /// a caller bug, not a client-supplied refusal, so a transport should map this to 500, not 422/403.
    LineageUnavailable,
}

impl From<DsarError> for DsarRouteError {
    fn from(e: DsarError) -> Self {
        match e {
            DsarError::UnknownRequest(id) => DsarRouteError::UnknownRequest(id),
            DsarError::DuplicateRequest(id) => DsarRouteError::DuplicateRequest(id),
            DsarError::IdentityNotProofed(id) => DsarRouteError::IdentityNotProofed(id),
            DsarError::WrongKind { expected, got } => DsarRouteError::WrongKind {
                expected: format!("{expected:?}"),
                got: format!("{got:?}"),
            },
            DsarError::AlreadyTerminal(id) => DsarRouteError::AlreadyTerminal(id),
            DsarError::IncompleteLineage { missing } => {
                DsarRouteError::IncompleteLineage { missing }
            }
        }
    }
}

impl std::fmt::Display for DsarRouteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DsarRouteError::NotAuthorized => write!(f, "not authorized to operate DSARs"),
            DsarRouteError::UnknownRequest(id) => write!(f, "unknown DSAR request `{id}`"),
            DsarRouteError::DuplicateRequest(id) => write!(f, "duplicate DSAR request `{id}`"),
            DsarRouteError::IdentityNotProofed(id) => {
                write!(f, "DSAR `{id}`: identity not proofed — fulfilment refused")
            }
            DsarRouteError::WrongKind { expected, got } => {
                write!(f, "DSAR kind mismatch: expected {expected}, got {got}")
            }
            DsarRouteError::AlreadyTerminal(id) => write!(f, "DSAR `{id}` is already terminal"),
            DsarRouteError::IncompleteLineage { missing } => write!(
                f,
                "DSAR access refused — cross-tier lineage incomplete, missing: {}",
                missing.join(", ")
            ),
            DsarRouteError::LineageUnavailable => write!(
                f,
                "DSAR access dispatched with no hydrated lineage — caller error, not a client refusal"
            ),
        }
    }
}

impl std::error::Error for DsarRouteError {}

/// The route-ready §4.4 DSAR workflow service. Owns the hash-chained [`DsarRegister`]; the retention
/// [`RecordStore`] is passed in (the daemon owns one shared store — see the module doc).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DsarWorkflow {
    register: DsarRegister,
}

impl DsarWorkflow {
    pub fn new() -> Self {
        Self::default()
    }

    /// Restore a workflow around an existing (e.g. deserialized-from-durable-store) register.
    pub fn from_register(register: DsarRegister) -> Self {
        Self { register }
    }

    /// Read-only view of the underlying register (for the tamper-evident audit surface).
    pub fn register(&self) -> &DsarRegister {
        &self.register
    }

    /// GAP-FIX regulated-fi-responsible-lifecycle — `DsarRegister::overdue`/`refresh_overdue` (the
    /// SLA-breach sweep: mark every non-terminal request past its DPDP response deadline) had zero
    /// callers outside `ainxt-lifecycle`'s own tests. `DsarWorkflow::handle` dispatches
    /// Open/Authenticate/Correct/Grievance/Erase but has no SLA-sweep command; the `register` field is
    /// private, so a served caller needs these thin passthroughs to reach it.
    pub fn overdue(&self, now: u64) -> Vec<String> {
        self.register.overdue(now)
    }

    /// Mutating counterpart to [`Self::overdue`] — actually mark the newly-overdue requests, so a
    /// dashboard sweep both refreshes state AND reports what just crossed the SLA line.
    pub fn refresh_overdue(&mut self, now: u64) -> Vec<String> {
        self.register.refresh_overdue(now)
    }

    fn receipt(&self, id: &str) -> DsarOutcome {
        DsarOutcome::Receipt {
            request: self
                .register
                .request(id)
                .cloned()
                .expect("request exists immediately after a successful transition"),
        }
    }

    /// **The route-ready DSAR dispatch entrypoint** (`POST /v1/dsar`). Fail-closed: the caller must
    /// hold [`CAP_DSAR_OPERATE`] (checked before any state lookup). `store` is the shared §6 retention
    /// store, used only by [`DsarCommand::Erase`] (so an erasure DSAR runs through hold/floor
    /// precedence); `lineage` is used only by [`DsarCommand::Access`] (the caller-hydrated cross-tier
    /// resolve — `None` when the caller has not attempted hydration, which fails [`DsarCommand::Access`]
    /// closed with [`DsarRouteError::LineageUnavailable`]); the other commands ignore both.
    pub fn handle(
        &mut self,
        principal: &Principal,
        cmd: &DsarCommand,
        store: &mut RecordStore,
        lineage: Option<&CompleteLineage>,
        now: u64,
    ) -> Result<DsarOutcome, DsarRouteError> {
        if !principal.has_cap(CAP_DSAR_OPERATE) {
            return Err(DsarRouteError::NotAuthorized);
        }
        match cmd {
            DsarCommand::Open {
                id,
                subject_id,
                kind,
                sla_ticks,
            } => {
                self.register.open(id, subject_id, *kind, now, *sla_ticks)?;
                Ok(self.receipt(id))
            }
            DsarCommand::Authenticate { id, proof_ok } => {
                self.register.authenticate(id, *proof_ok, now)?;
                Ok(self.receipt(id))
            }
            DsarCommand::Correct { id, n_records } => {
                self.register.fulfill_correction(id, *n_records, now)?;
                Ok(self.receipt(id))
            }
            DsarCommand::Grievance { id } => {
                self.register.route_grievance(id, now)?;
                Ok(self.receipt(id))
            }
            DsarCommand::Erase { id } => {
                let resolution = self.register.fulfill_erasure(id, store, now)?;
                let request = self
                    .register
                    .request(id)
                    .cloned()
                    .expect("request exists immediately after fulfilment");
                Ok(DsarOutcome::Erasure {
                    request,
                    resolution,
                })
            }
            DsarCommand::Access {
                id,
                require_complete,
            } => {
                // FI-09 RBAC decision — Access additionally requires the platform's `can_approve`
                // senior/approving-actor gate; `CAP_DSAR_OPERATE` (checked above) alone is not
                // commensurate with a full cross-tier PII export. See `can_approve_dsar_access`'s doc.
                if !can_approve_dsar_access(principal) {
                    return Err(DsarRouteError::NotAuthorized);
                }
                let lineage = lineage.ok_or(DsarRouteError::LineageUnavailable)?;
                let export =
                    self.register
                        .fulfill_access_complete(id, lineage, *require_complete, now)?;
                Ok(DsarOutcome::AccessExport {
                    request: self
                        .register
                        .request(id)
                        .cloned()
                        .expect("request exists immediately after a successful fulfilment"),
                    export,
                })
            }
        }
    }

    /// **The route-ready access/portability entrypoint** (`POST /v1/dsar/{id}/access`). Cap-gated
    /// (both [`CAP_DSAR_OPERATE`] AND [`can_approve_dsar_access`] — see that function's doc for why
    /// Access is not authorized by [`CAP_DSAR_OPERATE`] alone), then delegates to the
    /// completeness-checked cross-tier resolve: when `require_complete` and a mandated tier has no
    /// resolver, the fulfilment is refused ([`DsarRouteError::IncompleteLineage`]) rather than
    /// certifying a best-effort export. The daemon assembles `lineage` from the live Redis / Postgres /
    /// KG / embeddings / trace tiers. Kept as a direct entrypoint alongside [`Self::handle`]'s
    /// [`DsarCommand::Access`] arm (which delegates to the SAME [`can_approve_dsar_access`] gate and
    /// the SAME [`crate::dsar::DsarRegister::fulfill_access_complete`]) for embedders that prefer a
    /// typed call over wire-command dispatch.
    pub fn fulfill_access(
        &mut self,
        principal: &Principal,
        id: &str,
        lineage: &CompleteLineage,
        require_complete: bool,
        now: u64,
    ) -> Result<LineageExport, DsarRouteError> {
        if !principal.has_cap(CAP_DSAR_OPERATE) || !can_approve_dsar_access(principal) {
            return Err(DsarRouteError::NotAuthorized);
        }
        Ok(self
            .register
            .fulfill_access_complete(id, lineage, require_complete, now)?)
    }
}

// ============================ retention precedence store (§6) ============================

/// One retention-store command the route-ready [`RetentionService::handle`] dispatches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case", deny_unknown_fields)]
pub enum RetentionCommand {
    /// Register/replace the retention policy for a data class (TTL ceiling + statutory floor).
    SetPolicy { policy: RetentionPolicy },
    /// Open (or replace) a per-matter legal hold (§6.2).
    OpenHold { hold: LegalHold },
    /// Release a matter at `now` (§6.3). Fires nothing itself — follow with `RunDeferred`.
    ReleaseHold { matter_id: String },
    /// TTL sweep (skips held / floor-bound records).
    Purge,
    /// Right-to-erasure for one subject **through §6 precedence** (erase-now / defer-with-record).
    RequestErasure { subject_id: String },
    /// Fire every queued deferred erasure whose hold has released and floor elapsed at `now`.
    RunDeferred,
}

/// The serializable outcome of a [`RetentionService::handle`] call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "kebab-case")]
pub enum RetentionOutcome {
    /// A control-plane mutation that returns no ids (set-policy / open-hold).
    Ack,
    /// A hold release; `released` is false if the matter was absent or already released.
    Released { released: bool },
    /// A TTL sweep — the purged record ids (ascending).
    Purged { ids: Vec<String> },
    /// An erasure request — erased-now vs deferred-with-record.
    Erasure { resolution: ErasureResolution },
    /// A deferred-queue run — the fired record ids (ascending).
    Fired { ids: Vec<String> },
}

/// Why a route-ready retention call was refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum RetentionRouteError {
    /// The caller does not hold [`CAP_RETENTION_ADMIN`]. → 403.
    NotAuthorized,
}

impl std::fmt::Display for RetentionRouteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RetentionRouteError::NotAuthorized => {
                write!(f, "not authorized to administer retention")
            }
        }
    }
}

impl std::error::Error for RetentionRouteError {}

/// The route-ready §6 retention / legal-hold / deferred-erasure precedence store service. Owns the
/// [`RecordStore`]; the daemon shares this one store with [`DsarWorkflow`] for erasure.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RetentionService {
    store: RecordStore,
}

impl RetentionService {
    pub fn new() -> Self {
        Self::default()
    }

    /// Wrap an existing (e.g. durable-store-hydrated) [`RecordStore`].
    pub fn with_store(store: RecordStore) -> Self {
        Self { store }
    }

    /// Read-only view of the store (audit trail, deferred queue, holds).
    pub fn store(&self) -> &RecordStore {
        &self.store
    }

    /// Mutable handle the daemon threads into [`DsarWorkflow::handle`] for erasure — the two surfaces
    /// operate on the **same** store so precedence is consistent across both routes.
    pub fn store_mut(&mut self) -> &mut RecordStore {
        &mut self.store
    }

    /// **The route-ready retention dispatch entrypoint** (`POST /v1/retention`). Fail-closed on
    /// [`CAP_RETENTION_ADMIN`], then applies the §6 precedence operation deterministically at `now`.
    pub fn handle(
        &mut self,
        principal: &Principal,
        cmd: &RetentionCommand,
        now: u64,
    ) -> Result<RetentionOutcome, RetentionRouteError> {
        if !principal.has_cap(CAP_RETENTION_ADMIN) {
            return Err(RetentionRouteError::NotAuthorized);
        }
        Ok(match cmd {
            RetentionCommand::SetPolicy { policy } => {
                self.store.set_policy(*policy);
                RetentionOutcome::Ack
            }
            RetentionCommand::OpenHold { hold } => {
                self.store.add_hold(hold.clone());
                RetentionOutcome::Ack
            }
            RetentionCommand::ReleaseHold { matter_id } => RetentionOutcome::Released {
                released: self.store.release_hold(matter_id, now),
            },
            RetentionCommand::Purge => RetentionOutcome::Purged {
                ids: self.store.purge_expired(now),
            },
            RetentionCommand::RequestErasure { subject_id } => RetentionOutcome::Erasure {
                resolution: self.store.request_erasure(subject_id, now),
            },
            RetentionCommand::RunDeferred => RetentionOutcome::Fired {
                ids: self.store.run_deferred(now),
            },
        })
    }
}
