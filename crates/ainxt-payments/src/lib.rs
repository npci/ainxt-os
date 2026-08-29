// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-payments — the payment action boundary.
//!
//! Design: `docs/architecture/AGENT_IDENTITY_AND_PAYMENT_BOUNDARY.md` (ADR-016), sitting atop
//! the Side-Effect Ledger's saga / exactly-once substrate (ADR-013) and the data-class →
//! residency routing rule (ADR-012).
//!
//! # Why this crate exists
//!
//! Moving value is a categorically harder class than "side-effecting" (ADR-016 §1): a completed
//! inter-bank settlement is often **non-compensable**, and a payment whose outcome is *unknown*
//! must never be blindly retried — a retried "initiate settlement" is a double-pay, and the payment switch is
//! the switch the whole country's payments run through. This crate is the pure, deterministic
//! heart of the value-movement safety machinery. It answers three questions with code, not
//! convention:
//!
//! 1. **Which state transitions are legal?** A settlement moves `Draft → Reserved → Committed`,
//!    with `Compensated`, `Failed`, and `InDoubt` as the off-ramps. [`SagaState::apply`] is the
//!    single authority: a legal event returns the next state; an illegal one (e.g. committing a
//!    `Draft`, or committing an `InDoubt`) returns a [`TransitionError`] — **never** a silent
//!    no-op that lets a caller believe money moved when it did not.
//! 2. **Did we already do this?** [`SettlementCoordinator`] keys every settlement on its
//!    `idempotency_key`. Committing the same key twice returns the **first** [`CommitOutcome`]
//!    and applies **no second effect** — the exactly-once guarantee, asserted to the exact minor
//!    unit in the tests.
//! 3. **Is this even allowed?** [`PolicyGate`] runs before a reservation is ever taken: an
//!    over-ceiling amount is blocked; a high-value amount needs **two distinct** approvers (the
//!    same approver twice is refused — self-collusion is not dual control); and a regulated /
//!    PII intent is flagged **in-house-only**, never cloud-eligible (ADR-012).
//!
//! # In-doubt is the load-bearing case
//!
//! The dangerous real-world state is not "it failed" — it's "we don't know" (ADR-016 §1: an
//! honest `FAILED_PARTIAL` for a sent email is a catastrophe for moved money). A commit whose
//! downstream result is [`CommitSignal::Unknown`] moves the saga to [`SagaState::InDoubt`], which
//! is **terminal to `commit`**: the only way out is explicit [`SettlementCoordinator::reconcile`]
//! after checking the rails' actual state. There is deliberately **no** code path that
//! auto-retries a commit from `InDoubt` — that is exactly the double-pay this crate prevents.
//!
//! # Determinism (why the guarantees are testable)
//!
//! This crate reads no clock, draws no randomness, and does no I/O. The commit *result* (did the
//! downstream rail succeed / fail / time out) is an **injected parameter** ([`CommitSignal`]),
//! and reconciliation findings are injected too ([`ReconcileFinding`]) — so the same sequence of
//! events always produces the same states, outcomes, and settled total. The safety properties
//! below are things a unit test can *assert*, not hope for.
//!
//! # Scope — what this crate is NOT
//!
//! Consistent with ADR-016, this crate models the *adjacent* safety substrate — the state
//! machine, idempotency, and policy gate a payment-*system* uses. The apex ADR-016 guarantee
//! that the **agent runtime** has *no dispatch path* to initiate value movement lives at the
//! capability-registry / effect-class layer (a different crate); nothing here grants an agent the
//! ability to move money. This is the correctness core money-movement code is built on, exercised
//! by tests that fail loudly if the logic is gutted.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub mod boundary;
pub mod front_matter;
pub mod mandate;

// ===========================================================================
// Identifiers & value objects
// ===========================================================================

/// A settlement account reference (debtor or creditor). Opaque string identity; the crate never
/// interprets it beyond equality (a debtor may not equal its creditor — see [`PaymentIntent::validate`]).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AccountRef(pub String);

impl AccountRef {
    pub fn new(s: impl Into<String>) -> Self {
        AccountRef(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An approver's stable identity. Dual control keys on *distinct* values of this type, so two
/// approvals from the same `ApproverId` count as one (see [`PolicyGate::evaluate`]).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ApproverId(pub String);

impl ApproverId {
    pub fn new(s: impl Into<String>) -> Self {
        ApproverId(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A single approval offered toward dual control — the approver plus the *authority* they carry.
/// An approval only *counts* toward the dual-control quorum if it is genuinely authorized:
/// `can_approve` must be set, and (when the gate configures an authority ceiling) the approver's
/// `ad_level` must be at or below it (lower = more senior, per the AD org tree). This closes the
/// completeness gap where any opaque id counted: a non-approver, or an approver too junior to sign
/// a high-value settlement, no longer satisfies dual control (ADR-016 §6 / ADR-022 §18 — approver
/// authority is `ad_level <= 3` in the canonical policy).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approval {
    pub approver: ApproverId,
    /// AD seniority level (0 = most senior). Compared against the gate's authority ceiling.
    pub ad_level: u8,
    /// Whether this principal holds the approval authority claim at all.
    pub can_approve: bool,
}

impl Approval {
    /// A fully-authorized approval at `ad_level` (the common case in tests and callers who have
    /// already checked the JWT `can_approve` claim).
    pub fn authorized(approver: impl Into<String>, ad_level: u8) -> Self {
        Approval {
            approver: ApproverId::new(approver),
            ad_level,
            can_approve: true,
        }
    }

    /// A raw approval with an explicit `can_approve` claim.
    pub fn new(approver: impl Into<String>, ad_level: u8, can_approve: bool) -> Self {
        Approval {
            approver: ApproverId::new(approver),
            ad_level,
            can_approve,
        }
    }
}

/// An ISO-4217-shaped currency code (exactly three ASCII uppercase letters). Validated on
/// construction so a malformed code can never reach the ledger.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Currency(String);

impl Currency {
    /// Construct a currency, rejecting anything that is not three ASCII uppercase letters.
    pub fn new(code: impl AsRef<str>) -> Result<Self, IntentError> {
        let code = code.as_ref();
        if code.len() == 3 && code.bytes().all(|b| b.is_ascii_uppercase()) {
            Ok(Currency(code.to_string()))
        } else {
            Err(IntentError::InvalidCurrency(code.to_string()))
        }
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// ===========================================================================
// PaymentIntent
// ===========================================================================

/// A request to move a fixed amount from `debtor` to `creditor`, carrying the `idempotency_key`
/// that makes settlement exactly-once and the `data_class` that drives residency (ADR-012).
///
/// Amounts are held in **minor units** (paise, cents) as a `u64` — never floating point, so no
/// rounding drift can create or destroy value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentIntent {
    /// Unique intent id (audit correlation).
    pub id: String,
    /// The exactly-once key. Two intents with the same key are the *same* settlement.
    pub idempotency_key: String,
    /// Amount to move, in minor units. Must be strictly positive.
    pub amount_minor: u64,
    pub currency: Currency,
    pub debtor: AccountRef,
    pub creditor: AccountRef,
    /// Sensitivity of the data this settlement carries — drives in-house-only residency.
    pub data_class: ainxt_types::DataClass,
}

impl PaymentIntent {
    /// Validate the intent's *structural* invariants. Rejects a zero amount (a zero-value transfer
    /// is a bug, not a payment), a self-payment (`debtor == creditor` moves nothing but can mask
    /// a mis-wired call), and empty id / idempotency_key (un-attributable, un-deduplicable).
    pub fn validate(&self) -> Result<(), IntentError> {
        if self.id.trim().is_empty() {
            return Err(IntentError::EmptyId);
        }
        if self.idempotency_key.trim().is_empty() {
            return Err(IntentError::EmptyIdempotencyKey);
        }
        if self.amount_minor == 0 {
            return Err(IntentError::ZeroAmount);
        }
        if self.debtor == self.creditor {
            return Err(IntentError::SelfPayment);
        }
        Ok(())
    }

    /// Regulated-payment / PII intents must never leave in-house infrastructure (ADR-012).
    pub fn requires_in_house(&self) -> bool {
        self.data_class.is_regulated()
    }
}

/// Why a [`PaymentIntent`] is structurally invalid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntentError {
    EmptyId,
    EmptyIdempotencyKey,
    ZeroAmount,
    SelfPayment,
    InvalidCurrency(String),
}

impl fmt::Display for IntentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IntentError::EmptyId => write!(f, "payment intent id is empty"),
            IntentError::EmptyIdempotencyKey => write!(f, "idempotency_key is empty"),
            IntentError::ZeroAmount => write!(f, "amount_minor must be strictly positive"),
            IntentError::SelfPayment => write!(f, "debtor and creditor must differ"),
            IntentError::InvalidCurrency(c) => {
                write!(
                    f,
                    "invalid currency code {c:?} (need 3 ASCII uppercase letters)"
                )
            }
        }
    }
}

impl std::error::Error for IntentError {}

// ===========================================================================
// The settlement SAGA state machine
// ===========================================================================

/// The lifecycle of one settlement. The happy path is `Draft → Reserved → Committed`; the other
/// three are terminal off-ramps except [`SagaState::InDoubt`], which is resolvable only by
/// reconciliation. Terminal states (`Committed`, `Compensated`, `Failed`) accept no further event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SagaState {
    /// Created, no funds reserved. The only legal event is [`SagaEvent::Reserve`].
    Draft,
    /// Funds reserved / authorization held. May commit, compensate, or (on an unknown commit
    /// result) fall in-doubt.
    Reserved,
    /// Value moved. Terminal and, per ADR-016 §1, treated as non-compensable here.
    Committed,
    /// The reservation was released cleanly; no value moved. Terminal.
    Compensated,
    /// The attempt failed before any value moved. Terminal.
    Failed,
    /// A commit returned an unknown result — value *may or may not* have moved. Resolvable only by
    /// [`SagaEvent::Reconcile`]; **never** by another commit.
    InDoubt,
}

impl SagaState {
    /// True once no further event is legal.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            SagaState::Committed | SagaState::Compensated | SagaState::Failed
        )
    }
}

impl fmt::Display for SagaState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            SagaState::Draft => "draft",
            SagaState::Reserved => "reserved",
            SagaState::Committed => "committed",
            SagaState::Compensated => "compensated",
            SagaState::Failed => "failed",
            SagaState::InDoubt => "in-doubt",
        };
        f.write_str(s)
    }
}

/// The result a downstream rail reports for a commit attempt — an **injected** parameter, so the
/// state machine stays deterministic and every branch (including the dangerous unknown one) is
/// unit-testable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CommitSignal {
    /// The rail confirmed the value moved.
    Succeeded,
    /// The rail confirmed nothing moved (safe to treat as failed).
    Failed,
    /// Timeout / lost response — the outcome is unknown. Forces [`SagaState::InDoubt`].
    Unknown,
}

/// What an out-of-band reconciliation established about an in-doubt settlement — an injected
/// parameter (the crate does not query rails).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReconcileFinding {
    /// The rail's records show the value *did* move — record it once, land on `Committed`.
    Settled,
    /// The rail's records show the value did *not* move — land on `Compensated`.
    NotSettled,
    /// Still indeterminate — remain `InDoubt`, reconcile again later.
    StillUnknown,
}

/// An event applied to a [`SagaState`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SagaEvent {
    Reserve,
    Commit(CommitSignal),
    Compensate,
    Reconcile(ReconcileFinding),
}

impl fmt::Display for SagaEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SagaEvent::Reserve => write!(f, "reserve"),
            SagaEvent::Commit(s) => write!(f, "commit({s:?})"),
            SagaEvent::Compensate => write!(f, "compensate"),
            SagaEvent::Reconcile(r) => write!(f, "reconcile({r:?})"),
        }
    }
}

/// An event was applied to a state that does not accept it — the state machine's rejection of an
/// illegal transition. Carries `from`/`event` so the caller (and audit) sees exactly what was
/// refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransitionError {
    pub from: SagaState,
    pub event: SagaEvent,
}

impl fmt::Display for TransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "illegal saga transition: {} is not legal from state {}",
            self.event, self.from
        )
    }
}

impl std::error::Error for TransitionError {}

impl SagaState {
    /// Apply an event, returning the next state or a [`TransitionError`]. This is the **single**
    /// authority on legality: everything else (the coordinator, tests) defers to it. An illegal
    /// combination is always an `Err`, never a silent no-op — a caller can never mistake "refused"
    /// for "done".
    pub fn apply(self, event: SagaEvent) -> Result<SagaState, TransitionError> {
        // Fully qualified on purpose: `Failed` names both a `CommitSignal` and a `SagaState`
        // variant, so glob-importing both would make it ambiguous. Clarity over brevity.
        use CommitSignal as C;
        use ReconcileFinding as R;
        use SagaEvent::{Commit, Compensate, Reconcile, Reserve};
        use SagaState::*;

        match (self, event) {
            (Draft, Reserve) => Ok(Reserved),

            (Reserved, Commit(C::Succeeded)) => Ok(Committed),
            (Reserved, Commit(C::Failed)) => Ok(Failed),
            (Reserved, Commit(C::Unknown)) => Ok(InDoubt),
            (Reserved, Compensate) => Ok(Compensated),

            // InDoubt is resolvable ONLY by reconciliation — never by a re-commit (double-pay).
            (InDoubt, Reconcile(R::Settled)) => Ok(Committed),
            (InDoubt, Reconcile(R::NotSettled)) => Ok(Compensated),
            (InDoubt, Reconcile(R::StillUnknown)) => Ok(InDoubt),

            // Everything else — commit-from-Draft, re-reserve, any event on a terminal state,
            // commit-from-InDoubt, reconcile on a non-InDoubt state — is refused.
            (from, event) => Err(TransitionError { from, event }),
        }
    }
}

// ===========================================================================
// PolicyGate — ceilings, dual control, residency
// ===========================================================================

/// The authorization tier of the principal requesting a settlement. Each tier has its own amount
/// ceiling; an unconfigured tier is fail-closed (denies everything).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApprovalTier {
    Standard,
    Elevated,
    Privileged,
}

/// Where a settlement's data may be processed (ADR-012). A regulated/PII intent is always
/// [`Residency::InHouseOnly`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Residency {
    InHouseOnly,
    CloudEligible,
}

/// The gate's verdict when it *allows* a settlement to reserve. Records the applied ceiling, the
/// residency, and the distinct approvers that satisfied dual control — an audit-ready decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateDecision {
    pub tier: ApprovalTier,
    pub ceiling_minor: u64,
    pub residency: Residency,
    /// True iff the amount was at/above the dual-control threshold (i.e. two approvers were needed).
    pub dual_control_required: bool,
    /// The distinct approver ids that authorized this settlement (sorted, deduplicated).
    pub approvers: Vec<ApproverId>,
}

impl GateDecision {
    /// Convenience: may this settlement's data be sent to a cloud model/route?
    pub fn cloud_eligible(&self) -> bool {
        matches!(self.residency, Residency::CloudEligible)
    }
}

/// Why the gate refused a settlement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDenied {
    /// Amount exceeds the requesting tier's ceiling.
    OverCeiling {
        amount_minor: u64,
        ceiling_minor: u64,
    },
    /// A high-value settlement needs N distinct *authorized* approvers; fewer counted. Approvals
    /// that lacked `can_approve` or exceeded the authority ceiling do not count (see [`Approval`]).
    DualControlRequired {
        distinct_approvers: usize,
        needed: usize,
    },
    /// The requesting tier has no ceiling configured — fail-closed.
    TierNotConfigured(ApprovalTier),
}

impl fmt::Display for PolicyDenied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyDenied::OverCeiling {
                amount_minor,
                ceiling_minor,
            } => write!(
                f,
                "amount {amount_minor} exceeds tier ceiling {ceiling_minor}"
            ),
            PolicyDenied::DualControlRequired {
                distinct_approvers,
                needed,
            } => write!(
                f,
                "dual control needs {needed} distinct approvers, got {distinct_approvers}"
            ),
            PolicyDenied::TierNotConfigured(t) => {
                write!(f, "no ceiling configured for tier {t:?} (fail-closed)")
            }
        }
    }
}

impl std::error::Error for PolicyDenied {}

/// The number of distinct approvers a high-value settlement requires.
pub const DUAL_CONTROL_APPROVERS: usize = 2;

/// Enforces the three non-negotiable pre-conditions on any settlement *before* a reservation is
/// taken: a per-tier amount ceiling, dual control above a high-value threshold, and data
/// residency. Pure and config-driven; construct it, set ceilings, then [`PolicyGate::evaluate`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyGate {
    ceilings: BTreeMap<ApprovalTier, u64>,
    /// Settlements whose amount is `>=` this need [`PolicyGate::required_approvers`] distinct
    /// *authorized* approvers.
    dual_control_threshold_minor: u64,
    /// How many distinct authorized approvers a high-value settlement needs (default
    /// [`DUAL_CONTROL_APPROVERS`] = 2; the design permits a small N).
    required_approvers: usize,
    /// If set, an approval only counts when `ad_level <= this` (lower = more senior). `None`
    /// means the gate does not check seniority (only `can_approve`).
    max_approver_ad_level: Option<u8>,
}

impl PolicyGate {
    /// A gate with the given high-value dual-control threshold and no tier ceilings yet
    /// (every tier fail-closed until configured). Requires [`DUAL_CONTROL_APPROVERS`] approvers by
    /// default and does not check seniority until [`with_approver_authority`](PolicyGate::with_approver_authority).
    pub fn new(dual_control_threshold_minor: u64) -> Self {
        PolicyGate {
            ceilings: BTreeMap::new(),
            dual_control_threshold_minor,
            required_approvers: DUAL_CONTROL_APPROVERS,
            max_approver_ad_level: None,
        }
    }

    /// Set (or replace) a tier's amount ceiling. Builder-style for ergonomic construction.
    pub fn with_ceiling(mut self, tier: ApprovalTier, ceiling_minor: u64) -> Self {
        self.ceilings.insert(tier, ceiling_minor);
        self
    }

    /// Require `n` distinct authorized approvers for high-value settlements (a small N ≥ 1).
    pub fn with_required_approvers(mut self, n: usize) -> Self {
        self.required_approvers = n.max(1);
        self
    }

    /// Require approvers to be at or above a seniority (`ad_level <= max_ad_level`) *and* to hold
    /// `can_approve`. Without this, only `can_approve` is checked. Canonical policy is `<= 3`.
    pub fn with_approver_authority(mut self, max_ad_level: u8) -> Self {
        self.max_approver_ad_level = Some(max_ad_level);
        self
    }

    /// Set a tier's ceiling in place.
    pub fn set_ceiling(&mut self, tier: ApprovalTier, ceiling_minor: u64) {
        self.ceilings.insert(tier, ceiling_minor);
    }

    /// The dual-control threshold in minor units.
    pub fn dual_control_threshold_minor(&self) -> u64 {
        self.dual_control_threshold_minor
    }

    /// How many distinct authorized approvers a high-value settlement requires.
    pub fn required_approvers(&self) -> usize {
        self.required_approvers
    }

    /// True if `approval` carries the authority to count toward the quorum: it must hold
    /// `can_approve`, and — when an authority ceiling is configured — be senior enough
    /// (`ad_level <= max`).
    fn approval_counts(&self, approval: &Approval) -> bool {
        if !approval.can_approve {
            return false;
        }
        match self.max_approver_ad_level {
            Some(max) => approval.ad_level <= max,
            None => true,
        }
    }

    /// Evaluate an intent for a requesting `tier` with a set of `approvals`.
    ///
    /// Order of checks (each fail-closed):
    /// 1. **Tier configured** — an unknown/unconfigured tier denies everything.
    /// 2. **Ceiling** — `amount > ceiling` → [`PolicyDenied::OverCeiling`].
    /// 3. **Dual control** — if `amount >= threshold`, the count of *distinct authorized* approvers
    ///    must be `>= required_approvers`. An approval that lacks `can_approve` or exceeds the
    ///    authority ceiling does **not** count; two approvals from the same id count as one
    ///    (self-collusion is not dual control), so `[a, a]` is refused while distinct `[a, b]`
    ///    (both authorized) passes.
    /// 4. **Residency** — a regulated/PII intent is forced [`Residency::InHouseOnly`].
    pub fn evaluate(
        &self,
        intent: &PaymentIntent,
        tier: ApprovalTier,
        approvals: &[Approval],
    ) -> Result<GateDecision, PolicyDenied> {
        let ceiling = *self
            .ceilings
            .get(&tier)
            .ok_or(PolicyDenied::TierNotConfigured(tier))?;

        if intent.amount_minor > ceiling {
            return Err(PolicyDenied::OverCeiling {
                amount_minor: intent.amount_minor,
                ceiling_minor: ceiling,
            });
        }

        let dual_control_required = intent.amount_minor >= self.dual_control_threshold_minor;

        // Distinct AUTHORIZED approvers only — a BTreeSet dedups and yields a deterministic sorted
        // order; unauthorized approvals (no can_approve / too junior) never enter the set.
        let distinct: BTreeSet<&ApproverId> = approvals
            .iter()
            .filter(|&a| self.approval_counts(a))
            .map(|a| &a.approver)
            .collect();
        if dual_control_required && distinct.len() < self.required_approvers {
            return Err(PolicyDenied::DualControlRequired {
                distinct_approvers: distinct.len(),
                needed: self.required_approvers,
            });
        }

        let residency = if intent.requires_in_house() {
            Residency::InHouseOnly
        } else {
            Residency::CloudEligible
        };

        Ok(GateDecision {
            tier,
            ceiling_minor: ceiling,
            residency,
            dual_control_required,
            approvers: distinct.into_iter().cloned().collect(),
        })
    }
}

// ===========================================================================
// SettlementCoordinator — idempotency + effects over the state machine
// ===========================================================================

/// The outcome of a commit / compensate / reconcile call. `effected_amount_minor` is the value
/// actually moved by *this* settlement (non-zero only once it reaches `Committed`); `replayed` is
/// true when the call was an idempotent no-op returning a previously-recorded outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitOutcome {
    pub idempotency_key: String,
    pub state: SagaState,
    pub effected_amount_minor: u64,
    /// True when this call performed no new effect and returned a prior recorded outcome.
    pub replayed: bool,
}

/// Errors from the coordinator (a superset of the state machine's, plus idempotency / lookup).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoordinatorError {
    InvalidIntent(IntentError),
    PolicyDenied(PolicyDenied),
    /// A reservation already exists for this idempotency_key.
    DuplicateKey(String),
    /// No settlement is tracked for this idempotency_key.
    /// Checkmarx CX-FP: unit variant — key deliberately excluded from error payload.
    UnknownKey,
    /// The requested transition is illegal from the settlement's current state.
    IllegalTransition(TransitionError),
    /// A commit was attempted on an in-doubt settlement — refused; reconcile instead of retrying.
    InDoubtRequiresReconciliation(String),
    /// Reconciliation was attempted on a settlement that is not in-doubt.
    /// Checkmarx CX-FP: key field removed — idempotency key excluded from error payload.
    NotInDoubt {
        state: SagaState,
    },
}

impl fmt::Display for CoordinatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CoordinatorError::InvalidIntent(e) => write!(f, "invalid intent: {e}"),
            CoordinatorError::PolicyDenied(e) => write!(f, "policy denied: {e}"),
            CoordinatorError::DuplicateKey(k) => {
                write!(f, "a settlement already exists for idempotency_key {k:?}")
            }
            CoordinatorError::UnknownKey => {
                write!(f, "no settlement found for the given idempotency key")
            }
            CoordinatorError::IllegalTransition(e) => write!(f, "{e}"),
            CoordinatorError::InDoubtRequiresReconciliation(k) => write!(
                f,
                "settlement {k:?} is in-doubt: reconcile explicitly, never re-commit (double-pay risk)"
            ),
            CoordinatorError::NotInDoubt { state } => {
                write!(f, "settlement is {state}, not in-doubt; nothing to reconcile")
            }
        }
    }
}

impl std::error::Error for CoordinatorError {}

impl From<IntentError> for CoordinatorError {
    fn from(e: IntentError) -> Self {
        CoordinatorError::InvalidIntent(e)
    }
}
impl From<PolicyDenied> for CoordinatorError {
    fn from(e: PolicyDenied) -> Self {
        CoordinatorError::PolicyDenied(e)
    }
}
impl From<TransitionError> for CoordinatorError {
    fn from(e: TransitionError) -> Self {
        CoordinatorError::IllegalTransition(e)
    }
}

/// One tracked settlement.
#[derive(Debug, Clone)]
struct SagaRecord {
    intent: PaymentIntent,
    decision: GateDecision,
    state: SagaState,
    /// Recorded once the settlement reaches a *terminal* state, so replays return it verbatim.
    terminal_outcome: Option<CommitOutcome>,
}

/// Coordinates settlements: runs the [`PolicyGate`], drives the [`SagaState`] machine, and — the
/// point of the whole crate — enforces **exactly-once** on the `idempotency_key`. It owns the
/// running settled total and effect count so the "one effect" guarantee is directly observable.
///
/// Deterministic: no clock, no rng. The commit result and reconciliation finding are injected by
/// the caller, so a given sequence of calls always yields the same states and settled total.
#[derive(Debug, Clone)]
pub struct SettlementCoordinator {
    gate: PolicyGate,
    sagas: BTreeMap<String, SagaRecord>,
    /// Sum of all value actually moved (minor units). `u128` so a long ledger cannot overflow.
    total_settled_minor: u128,
    /// Number of settlements that actually moved value — the "effect count".
    settled_count: u64,
}

impl SettlementCoordinator {
    pub fn new(gate: PolicyGate) -> Self {
        SettlementCoordinator {
            gate,
            sagas: BTreeMap::new(),
            total_settled_minor: 0,
            settled_count: 0,
        }
    }

    /// Total value moved so far, across all settlements (minor units).
    pub fn total_settled_minor(&self) -> u128 {
        self.total_settled_minor
    }

    /// How many settlements have actually moved value.
    pub fn settled_count(&self) -> u64 {
        self.settled_count
    }

    /// Current state of a settlement, if tracked.
    pub fn state_of(&self, idempotency_key: &str) -> Option<SagaState> {
        self.sagas.get(idempotency_key).map(|r| r.state)
    }

    /// The [`GateDecision`] that authorized a settlement's reservation, if tracked — the audit
    /// record of which tier, ceiling, approvers, and residency admitted this money movement.
    pub fn decision_of(&self, idempotency_key: &str) -> Option<&GateDecision> {
        self.sagas.get(idempotency_key).map(|r| &r.decision)
    }

    /// Reserve funds for an intent after passing the [`PolicyGate`]. This is the *only* entry that
    /// creates a settlement (`Draft → Reserved`). Rejects a structurally invalid intent, a
    /// policy-denied intent (no reservation is taken — over-ceiling/dual-control failures never
    /// create a saga), and a duplicate `idempotency_key`.
    pub fn reserve(
        &mut self,
        intent: PaymentIntent,
        tier: ApprovalTier,
        approvals: &[Approval],
    ) -> Result<GateDecision, CoordinatorError> {
        intent.validate()?;

        if self.sagas.contains_key(&intent.idempotency_key) {
            return Err(CoordinatorError::DuplicateKey(intent.idempotency_key));
        }

        let decision = self.gate.evaluate(&intent, tier, approvals)?;

        // Drive the state machine from the canonical Draft start so legality is table-defined.
        let state = SagaState::Draft.apply(SagaEvent::Reserve)?;

        self.sagas.insert(
            intent.idempotency_key.clone(),
            SagaRecord {
                intent,
                decision: decision.clone(),
                state,
                terminal_outcome: None,
            },
        );
        Ok(decision)
    }

    /// Commit a reserved settlement with the downstream rail's reported `signal`.
    ///
    /// Exactly-once & in-doubt semantics:
    /// * If the settlement is already **`Committed`**, this is an idempotent replay: the first
    ///   [`CommitOutcome`] is returned with `replayed = true` and **no** second effect (this is
    ///   the double-pay guard).
    /// * If the settlement is **`InDoubt`**, the commit is *refused*
    ///   ([`CoordinatorError::InDoubtRequiresReconciliation`]) — there is no auto-retry path.
    /// * Otherwise the state machine decides: `Succeeded → Committed` (value moves *once*),
    ///   `Unknown → InDoubt` (no effect), `Failed → Failed` (no effect). A commit from any other
    ///   state (e.g. a terminal `Compensated`/`Failed`) is an illegal transition.
    pub fn commit(
        &mut self,
        idempotency_key: &str,
        signal: CommitSignal,
    ) -> Result<CommitOutcome, CoordinatorError> {
        let record = self
            .sagas
            .get_mut(idempotency_key)
            .ok_or_else(|| CoordinatorError::UnknownKey)?;

        // Idempotent replay: a committed key returns its first outcome, no second effect.
        if record.state == SagaState::Committed {
            let mut out = record
                .terminal_outcome
                .clone()
                .expect("committed record must carry its outcome");
            out.replayed = true;
            return Ok(out);
        }

        // In-doubt is terminal to commit — reconcile, never retry.
        if record.state == SagaState::InDoubt {
            return Err(CoordinatorError::InDoubtRequiresReconciliation(
                idempotency_key.to_string(),
            ));
        }

        let next = record.state.apply(SagaEvent::Commit(signal))?;
        record.state = next;

        let outcome = match next {
            SagaState::Committed => {
                // The single value-moving effect. Recorded exactly once.
                let amount = record.intent.amount_minor;
                self.total_settled_minor += amount as u128;
                self.settled_count += 1;
                let out = CommitOutcome {
                    idempotency_key: idempotency_key.to_string(),
                    state: SagaState::Committed,
                    effected_amount_minor: amount,
                    replayed: false,
                };
                record.terminal_outcome = Some(out.clone());
                out
            }
            SagaState::Failed => {
                let out = CommitOutcome {
                    idempotency_key: idempotency_key.to_string(),
                    state: SagaState::Failed,
                    effected_amount_minor: 0,
                    replayed: false,
                };
                record.terminal_outcome = Some(out.clone());
                out
            }
            SagaState::InDoubt => CommitOutcome {
                idempotency_key: idempotency_key.to_string(),
                state: SagaState::InDoubt,
                effected_amount_minor: 0,
                replayed: false,
            },
            // apply() over Commit(_) from Reserved can only yield the three states above.
            other => unreachable!("commit produced unexpected state {other}"),
        };
        Ok(outcome)
    }

    /// Compensate (release) a reserved settlement — `Reserved → Compensated`. Idempotent on an
    /// already-compensated key. A committed settlement cannot be compensated (non-compensable,
    /// ADR-016 §1); an in-doubt settlement must be reconciled first.
    pub fn compensate(&mut self, idempotency_key: &str) -> Result<CommitOutcome, CoordinatorError> {
        let record = self
            .sagas
            .get_mut(idempotency_key)
            .ok_or_else(|| CoordinatorError::UnknownKey)?;

        if record.state == SagaState::Compensated {
            let mut out = record
                .terminal_outcome
                .clone()
                .expect("compensated record must carry its outcome");
            out.replayed = true;
            return Ok(out);
        }
        if record.state == SagaState::InDoubt {
            return Err(CoordinatorError::InDoubtRequiresReconciliation(
                idempotency_key.to_string(),
            ));
        }

        let next = record.state.apply(SagaEvent::Compensate)?;
        record.state = next;
        let out = CommitOutcome {
            idempotency_key: idempotency_key.to_string(),
            state: next,
            effected_amount_minor: 0,
            replayed: false,
        };
        record.terminal_outcome = Some(out.clone());
        Ok(out)
    }

    /// Resolve an in-doubt settlement with an out-of-band `finding`. This is the *only* legal exit
    /// from [`SagaState::InDoubt`]:
    /// * `Settled` → the value moved during the unknown commit; record it **once** and land on
    ///   `Committed` (no double count — the unknown commit itself moved nothing in the ledger).
    /// * `NotSettled` → nothing moved; land on `Compensated`.
    /// * `StillUnknown` → remain `InDoubt`; reconcile again later.
    ///
    /// Refuses reconciliation on any non-in-doubt settlement.
    pub fn reconcile(
        &mut self,
        idempotency_key: &str,
        finding: ReconcileFinding,
    ) -> Result<CommitOutcome, CoordinatorError> {
        let record = self
            .sagas
            .get_mut(idempotency_key)
            .ok_or_else(|| CoordinatorError::UnknownKey)?;

        if record.state != SagaState::InDoubt {
            return Err(CoordinatorError::NotInDoubt {
                state: record.state,
            });
        }

        let next = record.state.apply(SagaEvent::Reconcile(finding))?;
        record.state = next;

        let outcome = match next {
            SagaState::Committed => {
                let amount = record.intent.amount_minor;
                self.total_settled_minor += amount as u128;
                self.settled_count += 1;
                let out = CommitOutcome {
                    idempotency_key: idempotency_key.to_string(),
                    state: SagaState::Committed,
                    effected_amount_minor: amount,
                    replayed: false,
                };
                record.terminal_outcome = Some(out.clone());
                out
            }
            SagaState::Compensated => {
                let out = CommitOutcome {
                    idempotency_key: idempotency_key.to_string(),
                    state: SagaState::Compensated,
                    effected_amount_minor: 0,
                    replayed: false,
                };
                record.terminal_outcome = Some(out.clone());
                out
            }
            // StillUnknown keeps it InDoubt.
            SagaState::InDoubt => CommitOutcome {
                idempotency_key: idempotency_key.to_string(),
                state: SagaState::InDoubt,
                effected_amount_minor: 0,
                replayed: false,
            },
            other => unreachable!("reconcile produced unexpected state {other}"),
        };
        Ok(outcome)
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ainxt_types::DataClass;

    fn inr(code: &str) -> Currency {
        Currency::new(code).unwrap()
    }

    fn intent(key: &str, amount: u64, dc: DataClass) -> PaymentIntent {
        PaymentIntent {
            id: format!("intent-{key}"),
            idempotency_key: key.to_string(),
            amount_minor: amount,
            currency: inr("INR"),
            debtor: AccountRef::new("acct-debtor"),
            creditor: AccountRef::new("acct-creditor"),
            data_class: dc,
        }
    }

    fn gate() -> PolicyGate {
        // Standard ceiling 100_000; dual control at/above 50_000.
        PolicyGate::new(50_000)
            .with_ceiling(ApprovalTier::Standard, 100_000)
            .with_ceiling(ApprovalTier::Privileged, 10_000_000)
    }

    /// Fully-authorized approvals (can_approve, senior ad_level=2) — the common fixture.
    fn approvers(ids: &[&str]) -> Vec<Approval> {
        ids.iter().map(|s| Approval::authorized(*s, 2)).collect()
    }

    /// The distinct approver-id list a [`GateDecision`] should report for `ids`.
    fn approver_ids(ids: &[&str]) -> Vec<ApproverId> {
        ids.iter().map(|s| ApproverId::new(*s)).collect()
    }

    // ---- legal happy path: reserve -> commit ------------------------------
    #[test]
    fn legal_reserve_then_commit_moves_value_once() {
        let mut c = SettlementCoordinator::new(gate());
        let i = intent("k1", 25_000, DataClass::Internal);
        let decision = c.reserve(i, ApprovalTier::Standard, &[]).unwrap();
        assert_eq!(decision.residency, Residency::CloudEligible);
        assert!(!decision.dual_control_required); // below 50_000
        assert_eq!(c.state_of("k1"), Some(SagaState::Reserved));
        // The authorizing decision is retained for audit.
        assert_eq!(c.decision_of("k1"), Some(&decision));
        assert_eq!(c.decision_of("missing"), None);

        let out = c.commit("k1", CommitSignal::Succeeded).unwrap();
        assert_eq!(out.state, SagaState::Committed);
        assert_eq!(out.effected_amount_minor, 25_000);
        assert!(!out.replayed);
        assert_eq!(c.total_settled_minor(), 25_000);
        assert_eq!(c.settled_count(), 1);
    }

    // ---- exactly-once: double commit = one effect, exact amount -----------
    #[test]
    fn double_commit_same_key_is_one_effect_exact_amount() {
        let mut c = SettlementCoordinator::new(gate());
        c.reserve(
            intent("k1", 40_000, DataClass::Internal),
            ApprovalTier::Standard,
            &[],
        )
        .unwrap();

        let first = c.commit("k1", CommitSignal::Succeeded).unwrap();
        assert_eq!(first.effected_amount_minor, 40_000);
        assert!(!first.replayed);

        // Re-commit the SAME key — even with a different signal — returns the FIRST outcome.
        let replay = c.commit("k1", CommitSignal::Succeeded).unwrap();
        assert!(replay.replayed);
        assert_eq!(replay.state, SagaState::Committed);
        assert_eq!(replay.effected_amount_minor, 40_000);

        // Exactly one effect: total moved is the amount ONCE, not twice.
        assert_eq!(c.total_settled_minor(), 40_000);
        assert_eq!(c.settled_count(), 1);
    }

    #[test]
    fn many_commits_same_key_never_double_pay() {
        let mut c = SettlementCoordinator::new(gate());
        c.reserve(
            intent("k1", 33_333, DataClass::Internal),
            ApprovalTier::Standard,
            &[],
        )
        .unwrap();
        c.commit("k1", CommitSignal::Succeeded).unwrap();
        for _ in 0..10 {
            let r = c.commit("k1", CommitSignal::Succeeded).unwrap();
            assert!(r.replayed);
        }
        assert_eq!(c.total_settled_minor(), 33_333);
        assert_eq!(c.settled_count(), 1);
    }

    // ---- illegal transition: commit from Draft ---------------------------
    #[test]
    fn commit_from_draft_is_rejected() {
        let err = SagaState::Draft
            .apply(SagaEvent::Commit(CommitSignal::Succeeded))
            .unwrap_err();
        assert_eq!(err.from, SagaState::Draft);
        assert_eq!(err.event, SagaEvent::Commit(CommitSignal::Succeeded));
    }

    #[test]
    fn state_machine_legal_and_illegal_edges() {
        use CommitSignal::*;
        use SagaEvent::*;
        // Legal edges.
        assert_eq!(
            SagaState::Draft.apply(Reserve).unwrap(),
            SagaState::Reserved
        );
        assert_eq!(
            SagaState::Reserved.apply(Commit(Succeeded)).unwrap(),
            SagaState::Committed
        );
        assert_eq!(
            SagaState::Reserved.apply(Commit(Unknown)).unwrap(),
            SagaState::InDoubt
        );
        assert_eq!(
            SagaState::Reserved.apply(Commit(Failed)).unwrap(),
            SagaState::Failed
        );
        assert_eq!(
            SagaState::Reserved.apply(Compensate).unwrap(),
            SagaState::Compensated
        );
        assert_eq!(
            SagaState::InDoubt
                .apply(Reconcile(ReconcileFinding::Settled))
                .unwrap(),
            SagaState::Committed
        );
        assert_eq!(
            SagaState::InDoubt
                .apply(Reconcile(ReconcileFinding::NotSettled))
                .unwrap(),
            SagaState::Compensated
        );

        // Illegal edges — each an Err, never a silent no-op.
        assert!(SagaState::Reserved.apply(Reserve).is_err());
        assert!(SagaState::Committed.apply(Commit(Succeeded)).is_err());
        assert!(SagaState::Committed.apply(Compensate).is_err());
        assert!(SagaState::Compensated.apply(Commit(Succeeded)).is_err());
        assert!(SagaState::Failed.apply(Commit(Succeeded)).is_err());
        // The double-pay edge: you cannot commit an in-doubt settlement.
        assert!(SagaState::InDoubt.apply(Commit(Succeeded)).is_err());
        // Reconcile is illegal off a non-in-doubt state.
        assert!(SagaState::Reserved
            .apply(Reconcile(ReconcileFinding::Settled))
            .is_err());
    }

    #[test]
    fn coordinator_rejects_illegal_commit_after_compensate() {
        let mut c = SettlementCoordinator::new(gate());
        c.reserve(
            intent("k1", 10_000, DataClass::Internal),
            ApprovalTier::Standard,
            &[],
        )
        .unwrap();
        c.compensate("k1").unwrap();
        // Committing a compensated settlement is an illegal transition, not an idempotent success.
        let err = c.commit("k1", CommitSignal::Succeeded).unwrap_err();
        assert!(matches!(err, CoordinatorError::IllegalTransition(_)));
        assert_eq!(c.total_settled_minor(), 0);
    }

    // ---- over-ceiling blocked --------------------------------------------
    #[test]
    fn over_ceiling_is_blocked_and_takes_no_reservation() {
        let mut c = SettlementCoordinator::new(gate());
        // 200_000 > Standard ceiling 100_000.
        let err = c
            .reserve(
                intent("k1", 200_000, DataClass::Internal),
                ApprovalTier::Standard,
                &[],
            )
            .unwrap_err();
        assert_eq!(
            err,
            CoordinatorError::PolicyDenied(PolicyDenied::OverCeiling {
                amount_minor: 200_000,
                ceiling_minor: 100_000,
            })
        );
        // No saga was created — an over-ceiling attempt leaves no reservation behind.
        assert_eq!(c.state_of("k1"), None);
    }

    #[test]
    fn unconfigured_tier_fails_closed() {
        let mut c = SettlementCoordinator::new(gate()); // Elevated has no ceiling
        let err = c
            .reserve(
                intent("k1", 1, DataClass::Internal),
                ApprovalTier::Elevated,
                &[],
            )
            .unwrap_err();
        assert_eq!(
            err,
            CoordinatorError::PolicyDenied(PolicyDenied::TierNotConfigured(ApprovalTier::Elevated))
        );
    }

    // ---- dual control needs two DISTINCT approvers -----------------------
    #[test]
    fn dual_control_requires_two_distinct_approvers() {
        let g = gate();
        let big = intent("k1", 5_000_000, DataClass::Internal); // >= 50_000 threshold

        // Zero approvers: denied.
        assert_eq!(
            g.evaluate(&big, ApprovalTier::Privileged, &[]).unwrap_err(),
            PolicyDenied::DualControlRequired {
                distinct_approvers: 0,
                needed: 2
            }
        );

        // Same approver twice is NOT dual control: distinct count is 1 → denied.
        assert_eq!(
            g.evaluate(
                &big,
                ApprovalTier::Privileged,
                &approvers(&["alice", "alice"])
            )
            .unwrap_err(),
            PolicyDenied::DualControlRequired {
                distinct_approvers: 1,
                needed: 2
            }
        );

        // Two distinct approvers: allowed.
        let ok = g
            .evaluate(
                &big,
                ApprovalTier::Privileged,
                &approvers(&["alice", "bob"]),
            )
            .unwrap();
        assert!(ok.dual_control_required);
        assert_eq!(ok.approvers, approver_ids(&["alice", "bob"])); // sorted-distinct
    }

    #[test]
    fn below_threshold_needs_no_approvers() {
        let g = gate();
        let small = intent("k1", 49_999, DataClass::Internal); // just under threshold
        let ok = g.evaluate(&small, ApprovalTier::Standard, &[]).unwrap();
        assert!(!ok.dual_control_required);
    }

    #[test]
    fn duplicate_approvers_still_pass_when_two_are_distinct() {
        let g = gate();
        let big = intent("k1", 60_000, DataClass::Internal); // >= 50_000 threshold, <= 100_000 ceiling
        let ok = g
            .evaluate(&big, ApprovalTier::Standard, &approvers(&["a", "b", "a"]))
            .unwrap();
        assert_eq!(ok.approvers, approver_ids(&["a", "b"]));
    }

    // ---- dual-control completeness: approver AUTHORITY --------------------
    #[test]
    fn approval_without_can_approve_does_not_count() {
        let g = gate();
        let big = intent("k1", 60_000, DataClass::Internal); // >= threshold, <= ceiling
                                                             // Two distinct ids, but `bob` cannot approve -> only one counts -> denied.
        let apprs = vec![
            Approval::authorized("alice", 2),
            Approval::new("bob", 2, false),
        ];
        assert_eq!(
            g.evaluate(&big, ApprovalTier::Standard, &apprs)
                .unwrap_err(),
            PolicyDenied::DualControlRequired {
                distinct_approvers: 1,
                needed: 2
            }
        );
        // Give bob real authority -> now two distinct authorized approvers pass.
        let apprs_ok = vec![
            Approval::authorized("alice", 2),
            Approval::authorized("bob", 2),
        ];
        let d = g.evaluate(&big, ApprovalTier::Standard, &apprs_ok).unwrap();
        assert_eq!(d.approvers, approver_ids(&["alice", "bob"]));
    }

    #[test]
    fn too_junior_approver_does_not_count_under_authority_ceiling() {
        // Authority ceiling: only ad_level <= 3 may approve.
        let g = gate().with_approver_authority(3);
        let big = intent("k1", 60_000, DataClass::Internal);
        // alice is senior (2); carol is too junior (5) -> only one counts -> denied.
        let apprs = vec![
            Approval::authorized("alice", 2),
            Approval::authorized("carol", 5),
        ];
        assert_eq!(
            g.evaluate(&big, ApprovalTier::Standard, &apprs)
                .unwrap_err(),
            PolicyDenied::DualControlRequired {
                distinct_approvers: 1,
                needed: 2
            }
        );
        // Replace carol with a senior bob (3, at the boundary) -> passes.
        let apprs_ok = vec![
            Approval::authorized("alice", 2),
            Approval::authorized("bob", 3),
        ];
        assert!(g.evaluate(&big, ApprovalTier::Standard, &apprs_ok).is_ok());
    }

    #[test]
    fn required_approvers_is_configurable() {
        // A three-person quorum for high-value settlements.
        let g = gate().with_required_approvers(3);
        assert_eq!(g.required_approvers(), 3);
        let big = intent("k1", 60_000, DataClass::Internal);
        // Two distinct authorized approvers are now insufficient.
        assert_eq!(
            g.evaluate(&big, ApprovalTier::Standard, &approvers(&["a", "b"]))
                .unwrap_err(),
            PolicyDenied::DualControlRequired {
                distinct_approvers: 2,
                needed: 3
            }
        );
        // Three distinct authorized approvers pass.
        let d = g
            .evaluate(&big, ApprovalTier::Standard, &approvers(&["a", "b", "c"]))
            .unwrap();
        assert_eq!(d.approvers, approver_ids(&["a", "b", "c"]));
    }

    #[test]
    fn reserve_enforces_approver_authority_end_to_end() {
        // A coordinator whose gate demands two ad_level<=3 approvers.
        let g = PolicyGate::new(50_000)
            .with_ceiling(ApprovalTier::Privileged, 10_000_000)
            .with_approver_authority(3);
        let mut c = SettlementCoordinator::new(g);
        // One senior + one junior -> reservation refused, no saga created.
        let err = c
            .reserve(
                intent("k1", 70_000, DataClass::RegulatedPayment),
                ApprovalTier::Privileged,
                &[
                    Approval::authorized("alice", 2),
                    Approval::authorized("carol", 6),
                ],
            )
            .unwrap_err();
        assert!(matches!(
            err,
            CoordinatorError::PolicyDenied(PolicyDenied::DualControlRequired { .. })
        ));
        assert_eq!(c.state_of("k1"), None);
        // Two senior approvers -> reservation succeeds.
        c.reserve(
            intent("k1", 70_000, DataClass::RegulatedPayment),
            ApprovalTier::Privileged,
            &[
                Approval::authorized("alice", 2),
                Approval::authorized("bob", 3),
            ],
        )
        .unwrap();
        assert_eq!(c.state_of("k1"), Some(SagaState::Reserved));
    }

    // ---- regulated intent is in-house-only -------------------------------
    #[test]
    fn regulated_intent_is_in_house_only() {
        let g = gate();
        for dc in [DataClass::RegulatedPayment, DataClass::Pii] {
            let i = intent("k1", 10_000, dc);
            assert!(i.requires_in_house());
            let d = g.evaluate(&i, ApprovalTier::Standard, &[]).unwrap();
            assert_eq!(d.residency, Residency::InHouseOnly);
            assert!(!d.cloud_eligible());
        }
        // A non-regulated intent stays cloud-eligible.
        let pub_i = intent("k2", 10_000, DataClass::Public);
        assert!(!pub_i.requires_in_house());
        assert!(g
            .evaluate(&pub_i, ApprovalTier::Standard, &[])
            .unwrap()
            .cloud_eligible());
    }

    // ---- in-doubt requires reconciliation, never auto-retry ---------------
    #[test]
    fn in_doubt_requires_reconciliation_and_is_not_auto_retried() {
        let mut c = SettlementCoordinator::new(gate());
        c.reserve(
            intent("k1", 70_000, DataClass::RegulatedPayment),
            ApprovalTier::Privileged,
            &approvers(&["a", "b"]),
        )
        .unwrap();

        // Commit returns an unknown result -> InDoubt, no value moved.
        let out = c.commit("k1", CommitSignal::Unknown).unwrap();
        assert_eq!(out.state, SagaState::InDoubt);
        assert_eq!(out.effected_amount_minor, 0);
        assert_eq!(c.total_settled_minor(), 0);

        // Re-committing an in-doubt settlement is REFUSED — no blind retry / double-pay.
        let err = c.commit("k1", CommitSignal::Succeeded).unwrap_err();
        assert!(matches!(
            err,
            CoordinatorError::InDoubtRequiresReconciliation(_)
        ));
        assert_eq!(c.total_settled_minor(), 0);
        assert_eq!(c.settled_count(), 0);
        assert_eq!(c.state_of("k1"), Some(SagaState::InDoubt));

        // Explicit reconciliation finds it DID settle -> record the value once.
        let recon = c.reconcile("k1", ReconcileFinding::Settled).unwrap();
        assert_eq!(recon.state, SagaState::Committed);
        assert_eq!(recon.effected_amount_minor, 70_000);
        assert_eq!(c.total_settled_minor(), 70_000);
        assert_eq!(c.settled_count(), 1);
    }

    #[test]
    fn in_doubt_reconcile_not_settled_compensates_no_value() {
        let mut c = SettlementCoordinator::new(gate());
        c.reserve(
            intent("k1", 80_000, DataClass::Internal),
            ApprovalTier::Privileged,
            &approvers(&["a", "b"]),
        )
        .unwrap();
        c.commit("k1", CommitSignal::Unknown).unwrap();
        let out = c.reconcile("k1", ReconcileFinding::NotSettled).unwrap();
        assert_eq!(out.state, SagaState::Compensated);
        assert_eq!(c.total_settled_minor(), 0);
        assert_eq!(c.settled_count(), 0);
    }

    #[test]
    fn in_doubt_still_unknown_stays_in_doubt() {
        let mut c = SettlementCoordinator::new(gate());
        c.reserve(
            intent("k1", 80_000, DataClass::Internal),
            ApprovalTier::Privileged,
            &approvers(&["a", "b"]),
        )
        .unwrap();
        c.commit("k1", CommitSignal::Unknown).unwrap();
        let out = c.reconcile("k1", ReconcileFinding::StillUnknown).unwrap();
        assert_eq!(out.state, SagaState::InDoubt);
        // Still resolvable later; still no value moved.
        assert_eq!(c.total_settled_minor(), 0);
        let out2 = c.reconcile("k1", ReconcileFinding::Settled).unwrap();
        assert_eq!(out2.state, SagaState::Committed);
        assert_eq!(c.total_settled_minor(), 80_000);
    }

    #[test]
    fn reconcile_on_non_in_doubt_is_refused() {
        let mut c = SettlementCoordinator::new(gate());
        c.reserve(
            intent("k1", 10_000, DataClass::Internal),
            ApprovalTier::Standard,
            &[],
        )
        .unwrap();
        let err = c.reconcile("k1", ReconcileFinding::Settled).unwrap_err();
        assert!(matches!(
            err,
            CoordinatorError::NotInDoubt {
                state: SagaState::Reserved,
            }
        ));
    }

    // ---- misc coordinator invariants -------------------------------------
    #[test]
    fn duplicate_reservation_key_is_rejected() {
        let mut c = SettlementCoordinator::new(gate());
        c.reserve(
            intent("k1", 10_000, DataClass::Internal),
            ApprovalTier::Standard,
            &[],
        )
        .unwrap();
        let err = c
            .reserve(
                intent("k1", 20_000, DataClass::Internal),
                ApprovalTier::Standard,
                &[],
            )
            .unwrap_err();
        assert_eq!(err, CoordinatorError::DuplicateKey("k1".to_string()));
    }

    #[test]
    fn commit_unknown_key_is_rejected() {
        let mut c = SettlementCoordinator::new(gate());
        let err = c.commit("nope", CommitSignal::Succeeded).unwrap_err();
        assert_eq!(err, CoordinatorError::UnknownKey);
    }

    #[test]
    fn independent_settlements_accumulate_exactly() {
        let mut c = SettlementCoordinator::new(gate());
        c.reserve(
            intent("k1", 10_000, DataClass::Internal),
            ApprovalTier::Standard,
            &[],
        )
        .unwrap();
        c.reserve(
            intent("k2", 15_000, DataClass::Internal),
            ApprovalTier::Standard,
            &[],
        )
        .unwrap();
        c.commit("k1", CommitSignal::Succeeded).unwrap();
        c.commit("k2", CommitSignal::Succeeded).unwrap();
        assert_eq!(c.total_settled_minor(), 25_000);
        assert_eq!(c.settled_count(), 2);
        // A failed commit on a third moves nothing. (Amount kept below the dual-control threshold
        // so a single-party reservation is valid — this test is about the FAILED-commit effect,
        // not the approval policy, which its own tests cover.)
        c.reserve(
            intent("k3", 30_000, DataClass::Internal),
            ApprovalTier::Standard,
            &[],
        )
        .unwrap();
        let out = c.commit("k3", CommitSignal::Failed).unwrap();
        assert_eq!(out.state, SagaState::Failed);
        assert_eq!(c.total_settled_minor(), 25_000);
        assert_eq!(c.settled_count(), 2);
    }

    // ---- intent validation ------------------------------------------------
    #[test]
    fn intent_validation_rejects_bad_intents() {
        let mut i = intent("k1", 0, DataClass::Internal);
        assert_eq!(i.validate(), Err(IntentError::ZeroAmount));
        i.amount_minor = 100;
        i.creditor = i.debtor.clone();
        assert_eq!(i.validate(), Err(IntentError::SelfPayment));
        assert!(Currency::new("inr").is_err());
        assert!(Currency::new("RUPEE").is_err());
        assert!(Currency::new("INR").is_ok());

        // A zero-amount intent never even reaches the gate/saga.
        let mut c = SettlementCoordinator::new(gate());
        let err = c
            .reserve(
                intent("k9", 0, DataClass::Internal),
                ApprovalTier::Standard,
                &[],
            )
            .unwrap_err();
        assert_eq!(
            err,
            CoordinatorError::InvalidIntent(IntentError::ZeroAmount)
        );
    }
}
