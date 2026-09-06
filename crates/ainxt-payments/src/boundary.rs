// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! The egress settlement-perimeter deny-list and the payment-initiation signature classifier.
//!
//! Design: `docs/architecture/AGENT_IDENTITY_AND_PAYMENT_BOUNDARY.md` — ADR-016 **§4.4** (Layer 5,
//! the egress settlement-perimeter deny-list: rails / core-banking-ledger / agent-payment-protocol
//! endpoints are a *reserved, un-allow-listable range*), **§4.5** (the payment-initiation
//! *signature* — a deterministic, reviewed, non-LLM classifier), and **§4.6/§4 Layer 6** (the
//! pre-dispatch tripwire that screens the *actual* effect of a call, independent of what a
//! capability *declared*).
//!
//! # What this module is (and is not)
//!
//! It is the **pure decision core** of two of ADR-016's five independent structural denials:
//!
//! * [`SettlementPerimeter`] — the un-allow-listable destination range, and [`EgressAllowList`],
//!   an allow-list that *structurally refuses* to add any destination inside the perimeter (so
//!   "just allow-list this one settlement endpoint" is not expressible);
//! * [`PaymentBoundary`] — the §4.5 signature classifier: given a resolved [`OutboundCall`]
//!   (destination + `resource_key` + payload semantics), it returns whether the call is
//!   `PaymentInitiating` — catching a call that *lied* about its effect class or was
//!   *dynamically constructed*, by inspecting the actual effect.
//!
//! It is **not** the wiring: the ADR-016 apex `effect_class::PaymentInitiating` (Layer 1), the
//! `CapabilityRegistry` refusal (Layer 2), the dispatch spine, and the network transport that
//! *calls* this classifier live in the tool/runtime/connector crates. This crate owns the
//! payment-domain policy those layers evaluate — so the recogniser is a versioned, testable,
//! reviewed artifact here, not a buried constant scattered across the runtime.
//!
//! # Determinism
//!
//! No clock, no rng, no I/O. Every pattern/prefix/message-type is data supplied at construction (a
//! git-controlled policy in the real deployment), and matching is a pure function — so "what counts
//! as payment initiation" is a fixed, exhaustively-testable decision.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

// ===========================================================================
// The settlement perimeter (ADR-016 §4.4) — un-allow-listable destinations
// ===========================================================================

/// The reserved, **un-allow-listable** set of value-movement destination patterns (§4.4): the
/// rails endpoints (UPI/IMPS/NEFT/RTGS/NACH/AePS/FASTag), core-banking/ledger *settlement* APIs,
/// and every 2026 agent-payment-protocol endpoint (AP2/ACP/Trusted-Agent/Agent-Pay/x402). A
/// destination matches if its (lowercased) text contains any reserved pattern. Patterns can only be
/// **added** (a new rail is reserved too); there is no removal-to-allow — the perimeter is a
/// one-way ratchet, which is what makes it un-allow-listable.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementPerimeter {
    patterns: BTreeSet<String>,
}

impl SettlementPerimeter {
    /// An empty perimeter (test/uncommon use). Prefer [`SettlementPerimeter::default_reserved`].
    pub fn empty() -> Self {
        Self::default()
    }

    /// The canonical default reserved perimeter: national rails settlement endpoints,
    /// core-banking/ledger settlement APIs, and the agent-payment-protocol networks ADR-016 §5
    /// places off-limits. Illustrative-but-real patterns; the deployed list is a git-controlled
    /// policy under the payments-council + security-council CODEOWNERS.
    pub fn default_reserved() -> Self {
        let patterns = [
            // National rails settlement / clearing endpoints.
            "upi-settlement.",
            "imps-settlement.",
            "neft.rbi",
            "rtgs.rbi",
            "nach.npci",
            "aeps-settlement.",
            "fastag-settlement.",
            "settlement.npci",
            "netting.npci",
            // Core-banking / ledger settlement APIs.
            "corebanking-settlement",
            "ledger-settlement",
            // 2026 agent-payment protocols (ADR-016 §5) — value-bearing, categorically hostile.
            "ap2.",
            "agentpayments.google",
            "agenticcommerce.",
            "acp.stripe",
            "trustedagent.visa",
            "agentpay.mastercard",
            "x402.",
            "402.coinbase",
        ];
        SettlementPerimeter {
            patterns: patterns.into_iter().map(str::to_string).collect(),
        }
    }

    /// Deprecated alias for [`default_reserved`](SettlementPerimeter::default_reserved).
    /// Use `default_reserved()` in new code.
    #[deprecated(since = "1.0.0", note = "use `default_reserved()` instead")]
    pub fn npci_reserved() -> Self {
        Self::default_reserved()
    }

    /// Reserve an additional destination pattern (one-way; there is no un-reserve).
    pub fn reserve(&mut self, pattern: impl Into<String>) {
        self.patterns.insert(pattern.into().to_lowercase());
    }

    /// Builder form of [`reserve`](SettlementPerimeter::reserve).
    pub fn with_pattern(mut self, pattern: impl Into<String>) -> Self {
        self.reserve(pattern);
        self
    }

    /// True iff `destination` falls inside the reserved perimeter.
    pub fn contains(&self, destination: &str) -> bool {
        let d = destination.to_lowercase();
        self.patterns.iter().any(|p| d.contains(p.as_str()))
    }

    /// A snapshot of the reserved patterns (for serialising the git-controlled [`SettlementPolicy`]).
    pub fn patterns_snapshot(&self) -> BTreeSet<String> {
        self.patterns.clone()
    }
}

/// The single reason an egress destination was refused: it is inside the un-allow-listable
/// settlement perimeter (§4.4). A distinct, structured error so audit sees *why* the wire said no.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerimeterViolation {
    pub destination: String,
}

impl fmt::Display for PerimeterViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "destination {:?} is inside the reserved settlement perimeter and cannot be allow-listed",
            self.destination
        )
    }
}

impl std::error::Error for PerimeterViolation {}

/// A capability's outbound egress allow-list that is **structurally incapable** of permitting a
/// settlement-perimeter destination (§4.4). [`allow`](EgressAllowList::allow) refuses to add a
/// perimeter destination, and [`is_allowed`](EgressAllowList::is_allowed) re-checks the perimeter
/// as belt-and-suspenders, so even a corrupted allow-set can never open the wire to value movement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressAllowList {
    perimeter: SettlementPerimeter,
    allowed: BTreeSet<String>,
}

impl EgressAllowList {
    /// A fresh allow-list guarded by `perimeter`.
    pub fn new(perimeter: SettlementPerimeter) -> Self {
        EgressAllowList {
            perimeter,
            allowed: BTreeSet::new(),
        }
    }

    /// Attempt to allow-list `destination`. Refused with [`PerimeterViolation`] if it is inside the
    /// settlement perimeter — the perimeter is un-allow-listable by construction.
    pub fn allow(&mut self, destination: impl Into<String>) -> Result<(), PerimeterViolation> {
        let dest = destination.into();
        if self.perimeter.contains(&dest) {
            return Err(PerimeterViolation { destination: dest });
        }
        self.allowed.insert(dest);
        Ok(())
    }

    /// True iff `destination` was explicitly allowed **and** is not (now) inside the perimeter.
    /// The perimeter check wins even if the allow-set somehow contains a perimeter entry.
    pub fn is_allowed(&self, destination: &str) -> bool {
        !self.perimeter.contains(destination) && self.allowed.contains(destination)
    }
}

// ===========================================================================
// Payload semantics for the §4.5 signature
// ===========================================================================

/// A UPI-layer operation. The value-moving ones (collect / request-to-pay / credit push) are
/// payment-initiating; the read-only ones (balance / status) are adjacent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UpiOperation {
    Collect,
    RequestToPay,
    CreditPush,
    BalanceEnquiry,
    StatusCheck,
}

impl UpiOperation {
    /// True for the operations that move value.
    pub fn moves_value(self) -> bool {
        matches!(
            self,
            UpiOperation::Collect | UpiOperation::RequestToPay | UpiOperation::CreditPush
        )
    }
}

/// A 2026 agent-payment protocol credential (§5). All are value-bearing → always initiating.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AgentPayProtocol {
    Ap2CartMandate,
    AcpSharedPaymentToken,
    VisaTrustedAgent,
    MastercardAgentPay,
    X402Funded,
}

/// The payment-relevant semantics of a call's payload (§4.5). `Benign` carries nothing
/// payment-shaped; the rest are the recognisable value-movement signatures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadSignal {
    /// Nothing payment-shaped.
    Benign,
    /// An ISO 20022 message identifier, e.g. `"pacs.008.001.09"` (clearing & settlement,
    /// value-moving) or `"camt.053"` (cash-management reporting, read-only).
    Iso20022 { message_type: String },
    /// A UPI-layer operation.
    Upi(UpiOperation),
    /// A NACH mandate execution (a scheduled debit) — value-moving.
    NachMandateExecution,
    /// A value-bearing agent-payment-protocol credential (§5).
    AgentPaymentCredential(AgentPayProtocol),
    /// A two-phase `commit` whose `dry_run` preview showed a value delta (§4.5).
    ValueDeltaCommit,
}

impl PayloadSignal {
    /// Whether an ISO 20022 message type is value-moving: `pacs.*` (payments clearing & settlement)
    /// and `pain.*` (payment initiation) move value; `camt.*` (cash-management reporting) is
    /// read-only. Case-insensitive; an unknown family is treated conservatively as **not** value-
    /// moving here because the destination/resource signatures are the belt to this suspenders.
    fn iso20022_moves_value(message_type: &str) -> bool {
        let m = message_type.to_ascii_lowercase();
        m.starts_with("pacs.") || m.starts_with("pain.")
    }
}

// ===========================================================================
// The outbound call and the §4.5 classifier
// ===========================================================================

/// A resolved outbound call, as seen by the pre-dispatch tripwire (§4.6): where it goes, which
/// resource it names, and what its payload means. This is what the runtime resolves *just before*
/// dispatch and hands to [`PaymentBoundary::classify`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboundCall {
    /// The resolved network destination (URL/host).
    pub destination: String,
    /// The resource the call names, e.g. `"settlement-account:HDFC0001"`, `"netting-batch:B-42"`,
    /// or a benign `"settlement-report:2026-07"`.
    pub resource_key: String,
    /// The payment-relevant semantics of the payload.
    pub payload: PayloadSignal,
}

impl OutboundCall {
    /// Convenience constructor for a benign read (no payment payload).
    pub fn read(destination: impl Into<String>, resource_key: impl Into<String>) -> Self {
        OutboundCall {
            destination: destination.into(),
            resource_key: resource_key.into(),
            payload: PayloadSignal::Benign,
        }
    }

    /// Build an outbound call from a **§1.4 two-phase commit's `dry_run` preview** (§4.5): the
    /// payload signal is *derived* from [`DryRunValueSnapshot::payload_signal`], not declared by
    /// the caller. This is the concrete link from "a capability ran `dry_run` and the preview
    /// showed a value delta" to the classifier's `ValueDeltaCommit` signature — a capability that
    /// mis-declared its effect class (or a dynamically-constructed call that only reveals its true
    /// effect at preview time) is still caught here on the *actual* previewed numbers, exactly the
    /// "inspects the actual effect... regardless of the effect class a capability declared"
    /// guarantee [`PaymentBoundary::classify`] documents for its other signals.
    pub fn from_dry_run(
        destination: impl Into<String>,
        resource_key: impl Into<String>,
        snapshot: DryRunValueSnapshot,
    ) -> Self {
        OutboundCall {
            destination: destination.into(),
            resource_key: resource_key.into(),
            payload: snapshot.payload_signal(),
        }
    }
}

/// A snapshot of the value-bearing amount a **§1.4 two-phase commit's `dry_run` preview** reports
/// for BEFORE the commit, and what the same preview shows it would be AFTER the commit actually
/// applied (§4.5). This is the concrete detector behind [`PayloadSignal::ValueDeltaCommit`]: the
/// dry_run/commit machinery ([`crate`] callers hold the real preview numbers; see
/// `ainxt_tools::ToolRuntime::dry_run`) hands the runtime these two numbers, and this type turns
/// them into the classifier's payload signal deterministically — no LLM, no heuristic string
/// parsing of the human-readable preview text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DryRunValueSnapshot {
    /// The value-bearing field's amount BEFORE commit, in minor units (e.g. paise) — signed so a
    /// debit-shaped preview and a credit-shaped preview are both representable.
    pub before_minor_units: i64,
    /// The same field's amount the `dry_run` preview shows it would be AFTER commit applied.
    pub after_minor_units: i64,
}

impl DryRunValueSnapshot {
    /// A preview with no value movement at all (e.g. a metadata-only dry_run).
    pub fn unchanged(amount_minor_units: i64) -> Self {
        DryRunValueSnapshot {
            before_minor_units: amount_minor_units,
            after_minor_units: amount_minor_units,
        }
    }

    /// True iff the preview shows ANY change — the §4.5 "value delta" trigger. A decrease
    /// (a debit) counts exactly as much as an increase (a credit): both move value.
    pub fn has_value_delta(&self) -> bool {
        self.before_minor_units != self.after_minor_units
    }

    /// The signed delta (`after - before`); zero iff [`has_value_delta`](Self::has_value_delta) is
    /// false.
    pub fn delta_minor_units(&self) -> i64 {
        self.after_minor_units - self.before_minor_units
    }

    /// The [`PayloadSignal`] this snapshot classifies to: `ValueDeltaCommit` if the preview shows
    /// a delta, `Benign` otherwise. This is the sole production path that constructs
    /// `PayloadSignal::ValueDeltaCommit` — no call site declares it directly, it is always
    /// *derived* from a real before/after preview pair.
    pub fn payload_signal(&self) -> PayloadSignal {
        if self.has_value_delta() {
            PayloadSignal::ValueDeltaCommit
        } else {
            PayloadSignal::Benign
        }
    }
}

/// Why a call matched the payment-initiation signature (§4.5). A call may match several reasons at
/// once — all are reported (defense-in-depth visibility), and any one is sufficient to deny.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InitiationReason {
    /// The destination is inside the settlement perimeter (§4.4).
    SettlementPerimeterDestination,
    /// The `resource_key` names a settlement account / netting batch / ledger-settlement target.
    SettlementResourceKey,
    /// The payload carries a value-moving rails message type (ISO 20022 pacs./pain.).
    RailsMessageType(String),
    /// A value-moving UPI operation (collect / request-to-pay / credit-push).
    UpiValueOperation,
    /// A NACH mandate execution (debit).
    NachMandateExecution,
    /// A value-bearing agent-payment-protocol credential (§5).
    AgentPaymentCredential,
    /// A two-phase commit whose dry-run preview showed a value delta.
    ValueDeltaCommit,
}

/// The classifier's verdict for one call (§4.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum PaymentInitiationVerdict {
    /// The call moves no value — at most payment-adjacent; may proceed under the normal gates.
    Adjacent,
    /// The call is (or resolves to) payment initiation — the apex forbidden class. The `reasons`
    /// set names every signature it matched.
    Initiating { reasons: BTreeSet<InitiationReason> },
}

impl PaymentInitiationVerdict {
    /// True iff this verdict is `Initiating`.
    pub fn is_initiating(&self) -> bool {
        matches!(self, PaymentInitiationVerdict::Initiating { .. })
    }
}

/// A denial from [`PaymentBoundary::screen`] — a call that matched the payment-initiation signature
/// and must be aborted pre-dispatch (§4.6). Carries the matched reasons for the security incident.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundaryDenied {
    pub destination: String,
    pub resource_key: String,
    pub reasons: BTreeSet<InitiationReason>,
}

impl fmt::Display for BoundaryDenied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<String> = self.reasons.iter().map(|r| format!("{r:?}")).collect();
        write!(
            f,
            "payment-initiation boundary denied call to {:?} (resource {:?}); matched: [{}]",
            self.destination,
            self.resource_key,
            names.join(", ")
        )
    }
}

impl std::error::Error for BoundaryDenied {}

/// The §4.5/§4.6 payment-initiation signature classifier: a deterministic, reviewed (non-LLM)
/// recogniser combining the settlement perimeter (destination), a set of reserved settlement
/// resource-key prefixes, and the payload semantics. It is the runtime tripwire's decision core —
/// it inspects the *actual* effect of a call regardless of the effect class a capability declared.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentBoundary {
    perimeter: SettlementPerimeter,
    /// Reserved resource-key prefixes that denote a settlement *write target* (e.g.
    /// `"settlement-account:"`, `"netting-batch:"`, `"ledger-settlement:"`). Chosen as prefixes so
    /// a read like `"settlement-report:..."` does **not** false-positive.
    settlement_resource_prefixes: BTreeSet<String>,
}

impl Default for PaymentBoundary {
    fn default() -> Self {
        PaymentBoundary::payment_default()
    }
}

impl PaymentBoundary {
    /// The canonical default payment boundary: the reserved perimeter plus the default settlement
    /// resource prefixes. Configurable by deployers via `with_perimeter` / `with_resource_prefix`.
    pub fn payment_default() -> Self {
        let prefixes = [
            "settlement-account:",
            "netting-batch:",
            "ledger-settlement:",
        ];
        PaymentBoundary {
            perimeter: SettlementPerimeter::default_reserved(),
            settlement_resource_prefixes: prefixes.into_iter().map(str::to_string).collect(),
        }
    }

    /// Deprecated alias for [`payment_default`](PaymentBoundary::payment_default).
    /// Use `payment_default()` in new code.
    #[deprecated(since = "1.0.0", note = "use `payment_default()` instead")]
    pub fn npci() -> Self {
        Self::payment_default()
    }

    /// Build a boundary over an explicit perimeter (custom deployments / tests).
    pub fn with_perimeter(perimeter: SettlementPerimeter) -> Self {
        PaymentBoundary {
            perimeter,
            settlement_resource_prefixes: BTreeSet::new(),
        }
    }

    /// Reserve an additional settlement resource-key prefix.
    pub fn with_resource_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.settlement_resource_prefixes
            .insert(prefix.into().to_lowercase());
        self
    }

    /// The underlying perimeter (to build a guarded [`EgressAllowList`]).
    pub fn perimeter(&self) -> &SettlementPerimeter {
        &self.perimeter
    }

    fn resource_is_settlement_target(&self, resource_key: &str) -> bool {
        let r = resource_key.to_lowercase();
        self.settlement_resource_prefixes
            .iter()
            .any(|p| r.starts_with(p.as_str()))
    }

    /// Classify a resolved outbound call (§4.5). Collects every matched signature so a
    /// mis-declared or dynamically-constructed payment call is caught even if only one facet gives
    /// it away.
    pub fn classify(&self, call: &OutboundCall) -> PaymentInitiationVerdict {
        let mut reasons: BTreeSet<InitiationReason> = BTreeSet::new();

        if self.perimeter.contains(&call.destination) {
            reasons.insert(InitiationReason::SettlementPerimeterDestination);
        }
        if self.resource_is_settlement_target(&call.resource_key) {
            reasons.insert(InitiationReason::SettlementResourceKey);
        }
        match &call.payload {
            PayloadSignal::Benign => {}
            PayloadSignal::Iso20022 { message_type } => {
                if PayloadSignal::iso20022_moves_value(message_type) {
                    reasons.insert(InitiationReason::RailsMessageType(message_type.clone()));
                }
            }
            PayloadSignal::Upi(op) => {
                if op.moves_value() {
                    reasons.insert(InitiationReason::UpiValueOperation);
                }
            }
            PayloadSignal::NachMandateExecution => {
                reasons.insert(InitiationReason::NachMandateExecution);
            }
            PayloadSignal::AgentPaymentCredential(_) => {
                reasons.insert(InitiationReason::AgentPaymentCredential);
            }
            PayloadSignal::ValueDeltaCommit => {
                reasons.insert(InitiationReason::ValueDeltaCommit);
            }
        }

        if reasons.is_empty() {
            PaymentInitiationVerdict::Adjacent
        } else {
            PaymentInitiationVerdict::Initiating { reasons }
        }
    }

    /// The pre-dispatch tripwire (§4.6): `Ok(())` if the call is at most adjacent, else
    /// [`BoundaryDenied`] with the matched reasons — the caller aborts the turn (and, per §4.6,
    /// quarantines the capability, revokes the acting identity, and raises an incident: those are
    /// the runtime's actions on this fail-closed signal).
    pub fn screen(&self, call: &OutboundCall) -> Result<(), BoundaryDenied> {
        match self.classify(call) {
            PaymentInitiationVerdict::Adjacent => Ok(()),
            PaymentInitiationVerdict::Initiating { reasons } => Err(BoundaryDenied {
                destination: call.destination.clone(),
                resource_key: call.resource_key.clone(),
                reasons,
            }),
        }
    }
}

// ===========================================================================
// The canonical effect-class (ADR-016 §3.1) — IDN-11
// ===========================================================================

/// The canonical four-value effect classification the Side-Effect Ledger's type system is designed
/// around (ADR-016 §3.1: `Pure | Idempotent | SideEffecting | PaymentInitiating`); this is the
/// payment-domain source of truth for the full enum. **Closed (IDN-11):** the wired
/// `ainxt-tools::EffectClass` no longer folds `Idempotent` into `SideEffecting` — it `pub use`-adopts
/// this exact enum directly (`ainxt_tools::EffectClass = PaymentEffectClass`), so there is a single
/// four-value type, not a divergent 3-value copy. **`PaymentInitiating` has no dispatch arm** —
/// [`is_dispatchable`](PaymentEffectClass::is_dispatchable) returns `false` for it, the apex boundary
/// made explicit at the type level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PaymentEffectClass {
    /// No side effects — safe to run every time (never ledgered).
    Pure,
    /// Naturally idempotent under its own key — safe to retry without a ledger dedup (§3.1). The
    /// wired `ainxt-tools::EffectClass` carries this value too (IDN-11) — it is not folded away.
    Idempotent,
    /// Changes the world — must be exactly-once (ledgered).
    SideEffecting,
    /// **Moves value.** The apex forbidden class — no dispatch arm exists (§3.1/§3).
    PaymentInitiating,
}

impl PaymentEffectClass {
    /// True iff a capability of this effect class may be dispatched at all. `PaymentInitiating` is
    /// the sole non-dispatchable class — the "deliberate hole where a capability would otherwise go".
    pub fn is_dispatchable(self) -> bool {
        !matches!(self, PaymentEffectClass::PaymentInitiating)
    }

    /// True iff dispatching this class requires a ledger exactly-once record.
    pub fn requires_ledger(self) -> bool {
        matches!(self, PaymentEffectClass::SideEffecting)
    }
}

// ===========================================================================
// EgressGuard — the composed Layer-5 + Layer-6 dispatch gate (IDN-01)
// ===========================================================================

/// Why a dispatch was denied by the composed [`EgressGuard`] (§4 Layers 5+6). Either the payload/
/// resource/destination classified as payment-initiation (Layer 6 tripwire), or the destination was
/// not on the capability's egress allow-list (Layer 5). Both are fail-closed and carry the evidence
/// the runtime needs to abort the turn, quarantine the capability, revoke the acting identity
/// (ADR-022 §17), and raise an incident (§4.6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "denial", rename_all = "snake_case")]
pub enum DispatchDenied {
    /// The call matched the payment-initiation signature (Layer 6).
    PaymentInitiation(BoundaryDenied),
    /// The destination is not allow-listed for this capability (Layer 5). Note: a settlement-
    /// perimeter destination is *also* un-allow-listable, so it can never reach here as "allowed".
    NotAllowListed { destination: String },
}

impl fmt::Display for DispatchDenied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DispatchDenied::PaymentInitiation(b) => write!(f, "{b}"),
            DispatchDenied::NotAllowListed { destination } => write!(
                f,
                "destination {destination:?} is not on the capability's egress allow-list"
            ),
        }
    }
}

impl std::error::Error for DispatchDenied {}

impl DispatchDenied {
    /// True iff the denial was a payment-initiation match (the case that triggers identity
    /// revocation + incident, §4.6), vs a plain allow-list miss.
    pub fn is_payment_initiation(&self) -> bool {
        matches!(self, DispatchDenied::PaymentInitiation(_))
    }
}

/// The single pre-dispatch gate the runtime/connector calls on **every** outbound call, composing
/// ADR-016 Layer 5 (egress allow-list + un-allow-listable settlement perimeter) and Layer 6 (the
/// payment-initiation signature tripwire) into one decision. This is the clean entrypoint that
/// closes IDN-01: `ainxt-connector-http`'s egress path invokes [`screen`](EgressGuard::screen)
/// before any bytes leave, so the settlement perimeter and tripwire stop being dead code on the
/// live path.
/// `Default` is the canonical payment boundary (`PaymentBoundary::default()` == `payment_default()`), so the
/// derived impl is exactly the intended settlement perimeter — not an empty boundary.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressGuard {
    boundary: PaymentBoundary,
}

impl EgressGuard {
    /// Build a guard over an explicit boundary (custom deployments / tests).
    pub fn new(boundary: PaymentBoundary) -> Self {
        EgressGuard { boundary }
    }

    /// The classifier this guard screens with (to build a perimeter-guarded [`EgressAllowList`]).
    pub fn boundary(&self) -> &PaymentBoundary {
        &self.boundary
    }

    /// A perimeter-guarded egress allow-list keyed to this guard's settlement perimeter — the
    /// capability's allow-set can never include a settlement destination by construction (§4.4).
    pub fn new_allow_list(&self) -> EgressAllowList {
        EgressAllowList::new(self.boundary.perimeter().clone())
    }

    /// Screen a resolved outbound call before dispatch (§4 Layers 5+6). Fail-closed:
    /// 1. **Layer 6** — if the call classifies as payment-initiation, deny (regardless of the
    ///    capability's declared effect class or allow-list). This is checked *first* because a
    ///    mis-declared payment call to a benign-looking host must still be caught.
    /// 2. **Layer 5** — otherwise the destination must be on the capability's `allow_list`
    ///    (which structurally cannot contain a settlement destination).
    ///
    /// Returns `Ok(())` only if the call is at most payment-adjacent **and** explicitly allowed.
    pub fn screen(
        &self,
        call: &OutboundCall,
        allow_list: &EgressAllowList,
    ) -> Result<(), DispatchDenied> {
        // Layer 6: the payment-initiation tripwire on the actual effect.
        if let Err(denied) = self.boundary.screen(call) {
            return Err(DispatchDenied::PaymentInitiation(denied));
        }
        // Layer 5: the destination must be explicitly allowed (perimeter already excluded).
        if !allow_list.is_allowed(&call.destination) {
            return Err(DispatchDenied::NotAllowListed {
                destination: call.destination.clone(),
            });
        }
        Ok(())
    }
}

// ===========================================================================
// Layer-6 graduated tripwire response (ADR-016 §4.6 / §3.5) — IDN-09
// ===========================================================================

/// One remediation the Layer-6 tripwire orders when it catches a mis-declared / dynamically-built
/// payment-initiation call at dispatch (§4.6). The design mandates a *graduated* response — not a
/// bare "deny and log": the turn aborts, the offending capability is quarantined, the acting
/// identity is revoked (ADR-022 §17), and a security incident is raised (ADR-017 breach clock).
/// Modelled as ordered, structured directives (not side effects) so this crate stays pure and
/// deterministic; the runtime applies each against the real registry / identity control-plane /
/// incident system. `Ord` is derived so a caller can dedupe/sort; the natural declaration order is
/// the intended escalation order.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum TripwireAction {
    /// Abort the in-flight turn immediately (no bytes leave, §4.6). Always first.
    AbortTurn { turn_id: String },
    /// Quarantine the capability that attempted the call so it can neither be re-selected nor
    /// dispatched pending review — a stronger state than "disabled" (§3.5/§4.6).
    QuarantineCapability { capability_id: String },
    /// Revoke the acting agent identity that carried the call (ADR-022 §17). Carried as the actor
    /// URI string so this crate needs no dependency on `ainxt-identity` (acyclic); the runtime maps
    /// it onto the identity control-plane's `revoke_run`.
    RevokeActingIdentity { acting_identity: String },
    /// Raise a security incident on the breach clock (ADR-017) carrying the matched signature
    /// reasons so responders see *why* it tripped.
    RaiseIncident {
        capability_id: String,
        acting_identity: String,
        reasons: BTreeSet<InitiationReason>,
    },
}

/// The complete graduated response the Layer-6 tripwire emits for one caught payment-initiation
/// attempt (§4.6). Fail-closed and total: [`plan`](GraduatedResponse::plan) always yields the four
/// escalation directives in order, so a caller cannot accidentally quarantine-without-revoking or
/// revoke-without-incident — the escalation is atomic by construction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraduatedResponse {
    pub actions: Vec<TripwireAction>,
}

impl GraduatedResponse {
    /// Build the full graduated response for a `PaymentInitiation` denial (§4.6). Deterministic and
    /// total: abort → quarantine → revoke → incident, every time.
    pub fn plan(
        denied: &BoundaryDenied,
        turn_id: impl Into<String>,
        capability_id: impl Into<String>,
        acting_identity: impl Into<String>,
    ) -> Self {
        let capability_id = capability_id.into();
        let acting_identity = acting_identity.into();
        GraduatedResponse {
            actions: vec![
                TripwireAction::AbortTurn {
                    turn_id: turn_id.into(),
                },
                TripwireAction::QuarantineCapability {
                    capability_id: capability_id.clone(),
                },
                TripwireAction::RevokeActingIdentity {
                    acting_identity: acting_identity.clone(),
                },
                TripwireAction::RaiseIncident {
                    capability_id,
                    acting_identity,
                    reasons: denied.reasons.clone(),
                },
            ],
        }
    }

    /// The capability the runtime must quarantine (convenience accessor).
    pub fn quarantined_capability(&self) -> Option<&str> {
        self.actions.iter().find_map(|a| match a {
            TripwireAction::QuarantineCapability { capability_id } => Some(capability_id.as_str()),
            _ => None,
        })
    }

    /// The acting identity the runtime must revoke (convenience accessor).
    pub fn revoked_identity(&self) -> Option<&str> {
        self.actions.iter().find_map(|a| match a {
            TripwireAction::RevokeActingIdentity { acting_identity } => {
                Some(acting_identity.as_str())
            }
            _ => None,
        })
    }
}

impl EgressGuard {
    /// The full Layer-6 tripwire: screen the call and, if it is a mis-declared payment-initiation
    /// attempt, return the complete [`GraduatedResponse`] the runtime must enact (abort + quarantine
    /// revoke identity + incident, §4.6). `Ok(())` when the call is at most adjacent **and**
    /// allow-listed. A plain allow-list miss (Layer 5) is *not* escalated to a graduated response —
    /// it is a policy denial, returned as `Err(Ok(DispatchDenied))`; only a payment-initiation match
    /// (Layer 6) triggers the graduated remediation, returned as `Err(Err(GraduatedResponse))`.
    #[allow(clippy::result_large_err, clippy::type_complexity)]
    pub fn screen_with_response(
        &self,
        call: &OutboundCall,
        allow_list: &EgressAllowList,
        turn_id: &str,
        capability_id: &str,
        acting_identity: &str,
    ) -> Result<(), Result<DispatchDenied, GraduatedResponse>> {
        match self.screen(call, allow_list) {
            Ok(()) => Ok(()),
            Err(DispatchDenied::PaymentInitiation(denied)) => Err(Err(GraduatedResponse::plan(
                &denied,
                turn_id,
                capability_id,
                acting_identity,
            ))),
            Err(other @ DispatchDenied::NotAllowListed { .. }) => Err(Ok(other)),
        }
    }
}

// ===========================================================================
// §4.6 remediation ENACTMENT seam — turn the graduated directives into enforced
// side effects on the LIVE egress path (IDN-09 live-wire, R14)
// ===========================================================================

/// The runtime-side seam a §4.6 [`GraduatedResponse`] is *enacted* against on the live egress path.
/// This crate stays pure — it emits ordered directives (data); an implementor of this trait binds
/// each directive to a real side effect: quarantining the offending capability in the registry,
/// revoking the acting identity on the identity control-plane (ADR-022 §17), and opening a security
/// incident on the breach clock (ADR-017). This is what makes the graduated response *enforced*
/// rather than advisory: the live dispatch gate calls [`enact`](GraduatedResponse::enact) on **every**
/// payment-initiation tripwire, so the three escalation actions are always emitted, never merely
/// described.
pub trait TripwireRemediation: Send + Sync {
    /// Quarantine the offending capability — neither re-selectable nor dispatchable, pending review
    /// (a stronger state than "disabled", §3.5/§4.6).
    fn quarantine_capability(&self, capability_id: &str);
    /// Revoke the acting agent identity that carried the mis-declared call (ADR-022 §17). The
    /// implementor maps the actor URI onto the identity control-plane's `revoke_run`/`revoke_user`.
    fn revoke_acting_identity(&self, acting_identity: &str);
    /// Raise a security incident on the breach clock (ADR-017) carrying the matched signature reasons
    /// so responders see *why* the tripwire fired.
    fn raise_incident(
        &self,
        capability_id: &str,
        acting_identity: &str,
        reasons: &BTreeSet<InitiationReason>,
    );
}

/// Proof that a [`GraduatedResponse`] was fully enacted against a [`TripwireRemediation`] on the live
/// path (§4.6). Fail-closed and total: because [`GraduatedResponse::plan`] always emits the four
/// directives in order, a successful [`enact`](GraduatedResponse::enact) always sets all four fields —
/// a caller can never observe a partial remediation (quarantine-without-revoke, revoke-without-
/// incident). [`is_complete`](EnactedRemediation::is_complete) asserts that invariant at the call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnactedRemediation {
    /// The turn that was aborted (no bytes leave — enforced by the caller returning the denial).
    pub aborted_turn: Option<String>,
    /// The capability the runtime quarantined.
    pub quarantined_capability: Option<String>,
    /// The acting identity the runtime revoked.
    pub revoked_identity: Option<String>,
    /// Whether a security incident was raised.
    pub raised_incident: bool,
}

impl EnactedRemediation {
    /// True iff every §4.6 escalation directive fired: abort **and** quarantine **and** revoke **and**
    /// incident. For a response built by [`GraduatedResponse::plan`] this is always true post-`enact`.
    pub fn is_complete(&self) -> bool {
        self.aborted_turn.is_some()
            && self.quarantined_capability.is_some()
            && self.revoked_identity.is_some()
            && self.raised_incident
    }
}

impl GraduatedResponse {
    /// Enact this graduated response against the runtime `remediator`, in escalation order, returning
    /// a receipt proving each directive fired (§4.6). Total: every directive in `actions` is applied.
    /// `AbortTurn` is enforced by the caller returning the denial (no bytes leave) — it is recorded in
    /// the receipt for the audit trail. Because [`plan`](GraduatedResponse::plan) is total, this always
    /// yields a complete [`EnactedRemediation`] (all three side-effecting actions emitted).
    pub fn enact(&self, remediator: &dyn TripwireRemediation) -> EnactedRemediation {
        let mut receipt = EnactedRemediation {
            aborted_turn: None,
            quarantined_capability: None,
            revoked_identity: None,
            raised_incident: false,
        };
        for action in &self.actions {
            match action {
                TripwireAction::AbortTurn { turn_id } => {
                    receipt.aborted_turn = Some(turn_id.clone());
                }
                TripwireAction::QuarantineCapability { capability_id } => {
                    remediator.quarantine_capability(capability_id);
                    receipt.quarantined_capability = Some(capability_id.clone());
                }
                TripwireAction::RevokeActingIdentity { acting_identity } => {
                    remediator.revoke_acting_identity(acting_identity);
                    receipt.revoked_identity = Some(acting_identity.clone());
                }
                TripwireAction::RaiseIncident {
                    capability_id,
                    acting_identity,
                    reasons,
                } => {
                    remediator.raise_incident(capability_id, acting_identity, reasons);
                    receipt.raised_incident = true;
                }
            }
        }
        receipt
    }
}

/// What a [`RecordingRemediation`] captured — the emitted §4.6 directives, made observable.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RecordedRemediations {
    pub quarantined: Vec<String>,
    pub revoked: Vec<String>,
    pub incidents: Vec<(String, String, BTreeSet<InitiationReason>)>,
}

/// An in-memory [`TripwireRemediation`] that *records* the enacted directives — the OSS default so the
/// three §4.6 actions are observable/auditable even before a deployment binds the real identity
/// control-plane + incident register. Thread-safe (interior mutability) so it can be shared (`Arc`)
/// across the live dispatch path. A production deployment swaps a control-plane-backed implementor
/// behind the same seam with no change to the dispatch gate.
#[derive(Debug, Default)]
pub struct RecordingRemediation {
    inner: std::sync::Mutex<RecordedRemediations>,
}

impl RecordingRemediation {
    pub fn new() -> Self {
        Self::default()
    }
    /// A snapshot of everything recorded so far.
    pub fn snapshot(&self) -> RecordedRemediations {
        self.inner
            .lock()
            .expect("remediation lock poisoned")
            .clone()
    }
    pub fn quarantined(&self) -> Vec<String> {
        self.inner
            .lock()
            .expect("remediation lock poisoned")
            .quarantined
            .clone()
    }
    pub fn revoked(&self) -> Vec<String> {
        self.inner
            .lock()
            .expect("remediation lock poisoned")
            .revoked
            .clone()
    }
    pub fn incident_count(&self) -> usize {
        self.inner
            .lock()
            .expect("remediation lock poisoned")
            .incidents
            .len()
    }
}

impl TripwireRemediation for RecordingRemediation {
    fn quarantine_capability(&self, capability_id: &str) {
        self.inner
            .lock()
            .expect("remediation lock poisoned")
            .quarantined
            .push(capability_id.to_string());
    }
    fn revoke_acting_identity(&self, acting_identity: &str) {
        self.inner
            .lock()
            .expect("remediation lock poisoned")
            .revoked
            .push(acting_identity.to_string());
    }
    fn raise_incident(
        &self,
        capability_id: &str,
        acting_identity: &str,
        reasons: &BTreeSet<InitiationReason>,
    ) {
        self.inner
            .lock()
            .expect("remediation lock poisoned")
            .incidents
            .push((
                capability_id.to_string(),
                acting_identity.to_string(),
                reasons.clone(),
            ));
    }
}

// ===========================================================================
// §4.4/§4.5 settlement-perimeter + signature list as git-controlled policy — IDN-10
// ===========================================================================

/// Why editing the settlement policy was refused (§4.4/§4.5 + ADR-026). The perimeter and the
/// payment-initiation signature list are *audited, evolvable artifacts*, not buried constants — so
/// a change is gated on **both** the payments-council **and** the security-council CODEOWNERS plus a
/// signed `ad_level<=3` `can_approve` commit, and the one-way-ratchet on the perimeter is enforced
/// (a pattern can be reserved, never removed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyEditError {
    /// The change lacked payments-council CODEOWNERS approval.
    MissingPaymentsCouncilApproval,
    /// The change lacked security-council CODEOWNERS approval.
    MissingSecurityCouncilApproval,
    /// The authorizing commit was unsigned or lacked `can_approve`.
    UnsignedOrUnauthorizedCommit,
    /// The signing committer is too junior (`ad_level > 3`).
    InsufficientAuthorAuthority { ad_level: u8, max: u8 },
    /// The edit tried to *remove* a reserved perimeter pattern — forbidden (one-way ratchet, §4.4).
    PerimeterRemovalForbidden { pattern: String },
}

impl fmt::Display for PolicyEditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyEditError::MissingPaymentsCouncilApproval => {
                write!(
                    f,
                    "settlement-policy edit requires payments-council CODEOWNERS approval"
                )
            }
            PolicyEditError::MissingSecurityCouncilApproval => {
                write!(
                    f,
                    "settlement-policy edit requires security-council CODEOWNERS approval"
                )
            }
            PolicyEditError::UnsignedOrUnauthorizedCommit => {
                write!(
                    f,
                    "settlement-policy edit requires a signed, can_approve commit"
                )
            }
            PolicyEditError::InsufficientAuthorAuthority { ad_level, max } => write!(
                f,
                "settlement-policy editor ad_level {ad_level} exceeds required <= {max}"
            ),
            PolicyEditError::PerimeterRemovalForbidden { pattern } => write!(
                f,
                "settlement-perimeter pattern {pattern:?} cannot be removed (one-way ratchet, §4.4)"
            ),
        }
    }
}

impl std::error::Error for PolicyEditError {}

/// The evidence a CI check / pre-receive hook presents about the commit editing the settlement
/// policy (§4.4/§4.5 governance). Both councils are required — this is the one dual-council artifact
/// in the payment boundary, because loosening "what counts as payment" is the highest-blast-radius
/// change in the system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyGovernance {
    pub payments_council_approved: bool,
    pub security_council_approved: bool,
    pub commit_signed: bool,
    pub author_can_approve: bool,
    pub author_ad_level: u8,
}

/// The maximum author AD seniority permitted to edit the settlement policy: `ad_level <= 3`.
pub const POLICY_EDITOR_MAX_AD_LEVEL: u8 = 3;

/// The **git-controlled** settlement policy (§4.4 perimeter + §4.5 signature list) — a versioned,
/// diff-reviewed, serde-(de)serializable artifact loaded from the control-plane repo, **not** a
/// buried constant. It is the single source of truth for "what counts as payment initiation": the
/// reserved destination `perimeter_patterns` (§4.4) and the settlement `resource_prefixes` (§4.5).
/// [`build_boundary`](SettlementPolicy::build_boundary) turns it into the runtime [`PaymentBoundary`]
/// the tripwire screens with, so editing the policy in git changes enforcement — after the
/// dual-council governance gate ([`authorize_edit`](SettlementPolicy::authorize_edit)) passes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementPolicy {
    /// Monotonic policy version (bumped on every governed edit).
    pub version: u32,
    /// The control-plane commit SHA this policy revision was authored at (attribution, ADR-026).
    pub control_commit_sha: String,
    /// §4.4 — the reserved, un-allow-listable destination patterns.
    pub perimeter_patterns: BTreeSet<String>,
    /// §4.5 — the reserved settlement-target resource-key prefixes.
    pub resource_prefixes: BTreeSet<String>,
}

impl SettlementPolicy {
    /// The canonical default baseline policy at a given commit — the git-serialisable equivalent of
    /// [`PaymentBoundary::payment_default`], so the shipped default is itself an inspectable artifact.
    pub fn default_baseline(control_commit_sha: impl Into<String>) -> Self {
        let boundary = PaymentBoundary::payment_default();
        SettlementPolicy {
            version: 1,
            control_commit_sha: control_commit_sha.into(),
            perimeter_patterns: boundary.perimeter().patterns_snapshot(),
            resource_prefixes: boundary.settlement_resource_prefixes.clone(),
        }
    }

    /// Deprecated alias for [`default_baseline`](SettlementPolicy::default_baseline).
    /// Use `default_baseline()` in new code.
    #[deprecated(since = "1.0.0", note = "use `default_baseline()` instead")]
    pub fn npci_baseline(control_commit_sha: impl Into<String>) -> Self {
        Self::default_baseline(control_commit_sha)
    }

    /// Build the runtime [`PaymentBoundary`] this policy defines (§4.4/§4.5). Deterministic: the same
    /// policy revision always yields the same enforcement boundary.
    pub fn build_boundary(&self) -> PaymentBoundary {
        let mut perimeter = SettlementPerimeter::empty();
        for p in &self.perimeter_patterns {
            perimeter.reserve(p.clone());
        }
        let mut boundary = PaymentBoundary::with_perimeter(perimeter);
        for prefix in &self.resource_prefixes {
            boundary = boundary.with_resource_prefix(prefix.clone());
        }
        boundary
    }

    /// Authorize and apply a governed edit producing `next` from `self` (§4.4/§4.5 + ADR-026 §5/§8).
    /// Fail-closed: **both** councils, a signed `ad_level<=3` `can_approve` commit, and the perimeter
    /// one-way ratchet (no reserved pattern may be dropped) are all enforced. On success the returned
    /// policy carries `next`'s patterns/prefixes with `version` bumped and the new commit SHA stamped.
    pub fn authorize_edit(
        &self,
        next: &SettlementPolicy,
        gov: &PolicyGovernance,
    ) -> Result<SettlementPolicy, PolicyEditError> {
        if !gov.payments_council_approved {
            return Err(PolicyEditError::MissingPaymentsCouncilApproval);
        }
        if !gov.security_council_approved {
            return Err(PolicyEditError::MissingSecurityCouncilApproval);
        }
        if !gov.commit_signed || !gov.author_can_approve {
            return Err(PolicyEditError::UnsignedOrUnauthorizedCommit);
        }
        if gov.author_ad_level > POLICY_EDITOR_MAX_AD_LEVEL {
            return Err(PolicyEditError::InsufficientAuthorAuthority {
                ad_level: gov.author_ad_level,
                max: POLICY_EDITOR_MAX_AD_LEVEL,
            });
        }
        // One-way ratchet: every currently-reserved perimeter pattern must survive the edit.
        for p in &self.perimeter_patterns {
            if !next.perimeter_patterns.contains(p) {
                return Err(PolicyEditError::PerimeterRemovalForbidden { pattern: p.clone() });
            }
        }
        Ok(SettlementPolicy {
            version: self.version + 1,
            control_commit_sha: next.control_commit_sha.clone(),
            perimeter_patterns: next.perimeter_patterns.clone(),
            resource_prefixes: next.resource_prefixes.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- IDN-09 (R14): the §4.6 graduated response is ENACTED (not advisory) through the seam ----

    #[test]
    fn r14_graduated_response_enact_emits_all_three_actions() {
        // A payment-initiation tripwire produces a total graduated response. `enact` drives the
        // remediation seam and returns a receipt proving abort + quarantine + revoke + incident all
        // fired — this is what makes the response ENFORCED rather than a bare data structure.
        let guard = EgressGuard::default();
        let allow = guard.new_allow_list();
        let call = OutboundCall {
            destination: "https://upi-settlement.example.internal/collect".into(),
            resource_key: String::new(),
            payload: PayloadSignal::Benign,
        };
        // Layer-6 fires (a perimeter destination). screen_with_response yields the graduated response.
        let response = match guard.screen_with_response(
            &call,
            &allow,
            "turn-42",
            "connector.gitlab",
            "user:mallory",
        ) {
            Err(Err(r)) => r,
            other => panic!("expected a graduated response on a perimeter tripwire, got {other:?}"),
        };

        let rec = RecordingRemediation::new();
        // Before enact: nothing emitted (proves the response is inert until enacted).
        assert!(
            rec.quarantined().is_empty() && rec.revoked().is_empty() && rec.incident_count() == 0
        );

        let receipt = response.enact(&rec);

        // The receipt is complete and total — all three side-effecting actions fired, in order.
        assert!(
            receipt.is_complete(),
            "graduated remediation must be total: {receipt:?}"
        );
        assert_eq!(receipt.aborted_turn.as_deref(), Some("turn-42"));
        assert_eq!(
            receipt.quarantined_capability.as_deref(),
            Some("connector.gitlab")
        );
        assert_eq!(receipt.revoked_identity.as_deref(), Some("user:mallory"));
        assert!(receipt.raised_incident);

        // The seam actually received each directive (not merely described).
        assert_eq!(rec.quarantined(), vec!["connector.gitlab".to_string()]);
        assert_eq!(rec.revoked(), vec!["user:mallory".to_string()]);
        assert_eq!(rec.incident_count(), 1);
        // A plain allow-list miss (Layer 5) is NOT escalated to a graduated response.
        let benign = OutboundCall {
            destination: "https://not-allow-listed.internal/x".into(),
            resource_key: String::new(),
            payload: PayloadSignal::Benign,
        };
        assert!(matches!(
            guard.screen_with_response(&benign, &allow, "t", "c", "a"),
            Err(Ok(DispatchDenied::NotAllowListed { .. }))
        ));
    }

    // ---- the perimeter is un-allow-listable (§4.4) -----------------------
    #[test]
    fn perimeter_matches_rails_and_agent_pay_endpoints() {
        let p = SettlementPerimeter::default_reserved();
        assert!(p.contains("https://upi-settlement.example.internal/collect"));
        assert!(p.contains("https://rtgs.rbi.org.in/post"));
        // The shipped NACH pattern is `"nach.npci"` (see `default_reserved`), so the host has to
        // contain it. This previously asserted `https://nach.example.local/mandate`, which matches
        // no pattern in the default perimeter at all — the assertion had been failing since before
        // the OSS audit, unnoticed because there is no CI and the workspace was not being compiled.
        assert!(p.contains("https://nach.npci.example.internal/mandate"));
        assert!(p.contains("https://ap2.agentpayments.google/mandate"));
        assert!(p.contains("https://x402.coinbase.com/pay"));
        // A benign internal service is NOT in the perimeter.
        assert!(!p.contains("https://jira.example.internal/rest/api"));
        assert!(!p.contains("https://reports.internal/settlement-report/july"));
    }

    #[test]
    fn egress_allow_list_refuses_perimeter_but_allows_benign() {
        let p = SettlementPerimeter::default_reserved();
        let mut al = EgressAllowList::new(p);
        // A benign endpoint can be allow-listed and is then allowed.
        assert_eq!(al.allow("https://jira.example.internal/rest"), Ok(()));
        assert!(al.is_allowed("https://jira.example.internal/rest"));
        // A settlement endpoint is refused — un-allow-listable.
        let err = al
            .allow("https://upi-settlement.example.internal/collect")
            .unwrap_err();
        assert_eq!(
            err.destination,
            "https://upi-settlement.example.internal/collect"
        );
        // And it is never considered allowed.
        assert!(!al.is_allowed("https://upi-settlement.example.internal/collect"));
    }

    #[test]
    fn perimeter_wins_even_if_allow_set_is_corrupted() {
        // Construct an allow-list whose perimeter is EXTENDED after a dest was allowed: is_allowed
        // must still deny, proving the perimeter is the final word (belt-and-suspenders).
        let mut al = EgressAllowList::new(SettlementPerimeter::empty());
        al.allow("https://newrail.example/pay").unwrap();
        assert!(al.is_allowed("https://newrail.example/pay"));
        // Now the same host is reserved as a new rail (one-way ratchet on the perimeter).
        let mut p = SettlementPerimeter::empty();
        p.reserve("newrail.example");
        let guarded = EgressAllowList {
            perimeter: p,
            allowed: {
                let mut s = BTreeSet::new();
                s.insert("https://newrail.example/pay".to_string());
                s
            },
        };
        assert!(
            !guarded.is_allowed("https://newrail.example/pay"),
            "a now-reserved destination is denied despite being in the allow-set"
        );
    }

    // ---- the §4.5 classifier ---------------------------------------------
    #[test]
    fn destination_in_perimeter_classifies_initiating() {
        let b = PaymentBoundary::payment_default();
        let call = OutboundCall::read("https://upi-settlement.example.internal/collect", "txn:abc");
        let v = b.classify(&call);
        assert!(v.is_initiating());
        match v {
            PaymentInitiationVerdict::Initiating { reasons } => {
                assert!(reasons.contains(&InitiationReason::SettlementPerimeterDestination));
            }
            _ => unreachable!(),
        }
        assert!(b.screen(&call).is_err());
    }

    #[test]
    fn settlement_resource_key_classifies_initiating_but_report_does_not() {
        let b = PaymentBoundary::payment_default();
        // A settlement-account write target on a benign host is still initiating (resource sig).
        let write = OutboundCall::read("https://internal.svc/api", "settlement-account:HDFC0001");
        assert!(b.classify(&write).is_initiating());
        // A settlement *report* read is adjacent — the prefix is settlement-report:, not a target.
        let report = OutboundCall::read("https://internal.svc/api", "settlement-report:2026-07");
        assert_eq!(b.classify(&report), PaymentInitiationVerdict::Adjacent);
        assert!(b.screen(&report).is_ok());
    }

    #[test]
    fn iso20022_pacs_and_pain_move_value_camt_does_not() {
        let b = PaymentBoundary::payment_default();
        let pacs = OutboundCall {
            destination: "https://internal.svc/iso".to_string(),
            resource_key: "msg:1".to_string(),
            payload: PayloadSignal::Iso20022 {
                message_type: "pacs.008.001.09".to_string(),
            },
        };
        match b.classify(&pacs) {
            PaymentInitiationVerdict::Initiating { reasons } => assert!(reasons.contains(
                &InitiationReason::RailsMessageType("pacs.008.001.09".to_string())
            )),
            _ => panic!("pacs.* must be initiating"),
        }
        let pain = OutboundCall {
            payload: PayloadSignal::Iso20022 {
                message_type: "PAIN.001".to_string(), // case-insensitive
            },
            ..pacs.clone()
        };
        assert!(b.classify(&pain).is_initiating());
        // camt.* (reporting) is read-only -> adjacent.
        let camt = OutboundCall {
            payload: PayloadSignal::Iso20022 {
                message_type: "camt.053.001.08".to_string(),
            },
            ..pacs
        };
        assert_eq!(b.classify(&camt), PaymentInitiationVerdict::Adjacent);
    }

    #[test]
    fn upi_value_ops_initiate_but_reads_are_adjacent() {
        let b = PaymentBoundary::payment_default();
        for op in [
            UpiOperation::Collect,
            UpiOperation::RequestToPay,
            UpiOperation::CreditPush,
        ] {
            let call = OutboundCall {
                destination: "https://internal.svc/upi".to_string(),
                resource_key: "vpa:x@y".to_string(),
                payload: PayloadSignal::Upi(op),
            };
            assert!(b.classify(&call).is_initiating(), "{op:?} must initiate");
        }
        for op in [UpiOperation::BalanceEnquiry, UpiOperation::StatusCheck] {
            let call = OutboundCall {
                destination: "https://internal.svc/upi".to_string(),
                resource_key: "vpa:x@y".to_string(),
                payload: PayloadSignal::Upi(op),
            };
            assert_eq!(
                b.classify(&call),
                PaymentInitiationVerdict::Adjacent,
                "{op:?} is a read"
            );
        }
    }

    #[test]
    fn nach_mandate_and_agent_pay_and_value_delta_all_initiate() {
        let b = PaymentBoundary::payment_default();
        let nach = OutboundCall {
            destination: "https://internal.svc/nach".to_string(),
            resource_key: "mandate:M1".to_string(),
            payload: PayloadSignal::NachMandateExecution,
        };
        assert!(b.classify(&nach).is_initiating());

        let ap2 = OutboundCall {
            destination: "https://internal.svc/relay".to_string(),
            resource_key: "cart:1".to_string(),
            payload: PayloadSignal::AgentPaymentCredential(AgentPayProtocol::Ap2CartMandate),
        };
        assert!(b.screen(&ap2).is_err());

        let vdc = OutboundCall {
            destination: "https://internal.svc/2pc".to_string(),
            resource_key: "op:commit".to_string(),
            payload: PayloadSignal::ValueDeltaCommit,
        };
        assert!(b.classify(&vdc).is_initiating());
    }

    #[test]
    fn a_mis_declared_call_is_caught_by_multiple_independent_signatures() {
        // A capability that lied (claims a benign host) but whose resolved call hits the perimeter
        // AND names a settlement target AND carries a pacs message: all three reasons reported.
        let b = PaymentBoundary::payment_default();
        let call = OutboundCall {
            destination: "https://ledger-settlement.core.internal/post".to_string(),
            resource_key: "ledger-settlement:BATCH-9".to_string(),
            payload: PayloadSignal::Iso20022 {
                message_type: "pacs.009".to_string(),
            },
        };
        match b.classify(&call) {
            PaymentInitiationVerdict::Initiating { reasons } => {
                assert!(reasons.contains(&InitiationReason::SettlementPerimeterDestination));
                assert!(reasons.contains(&InitiationReason::SettlementResourceKey));
                assert!(reasons
                    .iter()
                    .any(|r| matches!(r, InitiationReason::RailsMessageType(_))));
                assert!(
                    reasons.len() >= 3,
                    "defense-in-depth: several independent catches"
                );
            }
            _ => panic!("must be initiating"),
        }
    }

    #[test]
    fn a_genuinely_adjacent_call_passes() {
        // Reading a settlement report from a benign internal host with a benign payload — the
        // largest legitimate category (payment-adjacent analysis) is not blocked.
        let b = PaymentBoundary::payment_default();
        let call = OutboundCall::read("https://reports.internal/api", "settlement-report:2026-07");
        assert_eq!(b.classify(&call), PaymentInitiationVerdict::Adjacent);
        assert!(b.screen(&call).is_ok());
    }

    // ---- IDN-11: canonical four-value effect class ------------------------
    #[test]
    fn gap_idn_11_effect_class_has_idempotent_and_payment_is_non_dispatchable() {
        assert!(PaymentEffectClass::Pure.is_dispatchable());
        assert!(PaymentEffectClass::Idempotent.is_dispatchable());
        assert!(PaymentEffectClass::SideEffecting.is_dispatchable());
        // The apex class has no dispatch arm — structurally non-dispatchable.
        assert!(!PaymentEffectClass::PaymentInitiating.is_dispatchable());
        // Only SideEffecting needs a ledger exactly-once record; Idempotent does not.
        assert!(PaymentEffectClass::SideEffecting.requires_ledger());
        assert!(!PaymentEffectClass::Idempotent.requires_ledger());
        assert!(!PaymentEffectClass::Pure.requires_ledger());
    }

    // ---- IDN-01: the composed EgressGuard (Layers 5 + 6) -----------------
    #[test]
    fn gap_idn_01_egress_guard_denies_settlement_even_with_allow_list() {
        let guard = EgressGuard::default();
        let mut allow = guard.new_allow_list();
        // The capability legitimately allow-lists a benign host.
        allow.allow("https://reports.internal/api").unwrap();
        // A benign adjacent read to the allowed host passes both layers.
        let ok = OutboundCall::read("https://reports.internal/api", "settlement-report:2026-07");
        assert!(guard.screen(&ok, &allow).is_ok());

        // A mis-declared payment call to a settlement endpoint is DENIED by Layer 6 (the tripwire),
        // and the settlement host could never have been allow-listed anyway (Layer 5 / §4.4).
        let settle = OutboundCall {
            destination: "https://upi-settlement.example.internal/collect".to_string(),
            resource_key: "settlement-account:HDFC0001".to_string(),
            payload: PayloadSignal::Upi(UpiOperation::Collect),
        };
        // Attempting to allow-list the settlement host is refused up-front.
        assert!(allow
            .allow("https://upi-settlement.example.internal/collect")
            .is_err());
        let denied = guard.screen(&settle, &allow).unwrap_err();
        assert!(
            denied.is_payment_initiation(),
            "must be a Layer-6 payment-initiation denial"
        );
        match denied {
            DispatchDenied::PaymentInitiation(b) => {
                assert!(b
                    .reasons
                    .contains(&InitiationReason::SettlementPerimeterDestination));
                assert!(b.reasons.contains(&InitiationReason::UpiValueOperation));
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn gap_idn_01_egress_guard_denies_unlisted_benign_destination() {
        // An adjacent call to a host that was never allow-listed is denied by Layer 5 — the guard
        // is default-deny on egress, not default-allow.
        let guard = EgressGuard::default();
        let allow = guard.new_allow_list(); // nothing allowed
        let call = OutboundCall::read("https://unknown.internal/api", "doc:1");
        let err = guard.screen(&call, &allow).unwrap_err();
        assert!(!err.is_payment_initiation());
        assert_eq!(
            err,
            DispatchDenied::NotAllowListed {
                destination: "https://unknown.internal/api".to_string(),
            }
        );
    }

    #[test]
    fn gap_idn_01_mis_declared_payment_to_benign_host_still_caught() {
        // A capability lies: it allow-lists a benign host, then carries a pacs.* settlement message
        // to it. Layer 6 catches the payload semantics even though Layer 5 would have allowed the host.
        let guard = EgressGuard::default();
        let mut allow = guard.new_allow_list();
        allow.allow("https://internal.svc/iso").unwrap();
        let call = OutboundCall {
            destination: "https://internal.svc/iso".to_string(),
            resource_key: "msg:1".to_string(),
            payload: PayloadSignal::Iso20022 {
                message_type: "pacs.008".to_string(),
            },
        };
        let err = guard.screen(&call, &allow).unwrap_err();
        assert!(err.is_payment_initiation());
    }
}
