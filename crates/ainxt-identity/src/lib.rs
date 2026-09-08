// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-identity — agent workload identity & on-behalf-of (OBO) delegation.
//!
//! Design: `docs/architecture/AGENT_IDENTITY_AND_PAYMENT_BOUNDARY.md`
//! (ADR-022 — non-human identity lifecycle, §12 composite per-Run identity, §15 OBO
//! inheritance) and Pass-5 gap **[AI]** — *confused-deputy / on-behalf-of authz*.
//!
//! # The one thing this crate guarantees
//!
//! An agent acts **as** the human that authorized it, under a scope that can only ever
//! **narrow** as authority flows down the chain user → agent → sub-agent — it can **never
//! widen** (privilege escalation). A sub-agent cannot do anything the agent could not, which
//! cannot do anything the user could not. This is the *identity-layer* half of the
//! confused-deputy defense: even a fully-compromised sub-agent holding a valid credential is
//! bounded below the intersection of every grant above it, and any attempt to grant *more*
//! than one holds is rejected structurally, naming the offending hop.
//!
//! # What is real here (pure, deterministic, no I/O)
//!
//! * [`AgentId`] — a workload identity: *which running instance is this?* A `definition`
//!   (the versioned role, rooted in the git control plane, ADR-022 §12) plus a per-Run
//!   `run_id`. Two Runs of the same role have **different** `run_id`s and therefore **distinct
//!   identities** (ADR-022 §12 "not a shared token, by construction") — equality is structural,
//!   so the connectivity check below can tell one Run's credential from another's.
//! * [`Actor`] — [`Actor::Human`] (a JWT principal — the accountable **root** of authority)
//!   or [`Actor::Agent`] (a workload). Humans authorize; only agents receive delegated
//!   authority. Authority never flows *back* to a human mid-chain.
//! * [`Delegation`] — one hop: `{delegator, delegate, scope, not_after}`. The `scope` is the
//!   [`Capability`] set the delegator confers on the delegate; `not_after` is the
//!   caller-supplied [`LogicalTime`] the grant is valid through (inclusive). **No wall clock:**
//!   time is a parameter, so authority is reproducible.
//! * [`DelegationChain`] — the ordered hops user → agent → sub-agent.
//! * [`DelegationChain::verify`] — the heart. A chain is valid at `now` **iff** all of:
//!   1. it is non-empty and its **root delegator is a human** ([`VerifyError::RootNotHuman`]);
//!   2. every **delegate is an agent** ([`VerifyError::DelegateNotAgent`]) — authority never
//!      lands back on a human;
//!   3. no hop delegates **to itself** ([`VerifyError::SelfDelegation`]) and no identity
//!      **repeats** ([`VerifyError::CyclicChain`]) — the chain is a simple path;
//!   4. it is **connected** — each hop's delegator is the previous hop's delegate
//!      ([`VerifyError::BrokenLink`]);
//!   5. every hop's **scope narrows** — `scope ⊆ delegator's scope`; a widening hop is
//!      rejected as [`VerifyError::ScopeWidening`] **naming the hop and the offending
//!      capabilities**;
//!   6. every hop's **authority window narrows** — a sub-delegation may not outlive its
//!      delegator ([`VerifyError::ExpiryWidening`]); and
//!   7. **no hop is expired** at `now` ([`VerifyError::Expired`]).
//! * [`DelegationChain::effective_scope`] — the **intersection** of every hop's scope. Because
//!   scope only narrows in a valid chain this equals the leaf's scope, but it is computed as a
//!   true intersection so it is correct (and empty-safe) for *any* chain, and is naturally
//!   **capped by the root** (the root is one of the sets intersected).
//! * [`DelegationChain::can`] — authorizes a capability **iff** the chain verifies at `now`
//!   **and** the capability is in the effective scope. A capability the root held but a hop
//!   dropped is denied, because it is absent from the intersection.
//!
//! # Why the extra invariants (3, 6) beyond the brief's three
//!
//! The brief's core is subset-narrowing + not-expired + connected. This crate additionally
//! rejects cycles/self-delegation (3) and expiry-widening (6) because they are the same
//! privilege-escalation class viewed from a different axis, and payments software must design
//! the adversarial case first: a cycle is a replay/loop attempt that connectivity alone does
//! not catch, and a sub-delegation whose `not_after` exceeds its delegator's is *time*
//! escalation exactly as adding a capability is *scope* escalation. Both are cheap, structural,
//! and named — never silently tolerated.
//!
//! # What is deliberately a seam (absent by design, not stubbed)
//!
//! Credential *issuance* (the Agent Identity Authority / attestation / short-TTL renewal,
//! ADR-022 §13/§15), cryptographic signing of the credential, the transparency log, revocation
//! sets, and the anomaly monitor are the operational, I/O-bearing halves that live in the live
//! runtime and other crates. This crate owns exactly the **pure authority algebra** those
//! layers depend on: what a delegation *means*, when a chain is *valid*, and what it *permits*.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

pub mod authority;
pub mod authz;
pub mod control;
pub mod remediation;
pub mod sod;
pub mod transparency;

// ---------------------------------------------------------------------------
// Logical time
// ---------------------------------------------------------------------------

/// A monotonic logical tick supplied by the caller — the crate never reads a wall clock, so
/// every authority decision is reproducible. A grant is valid *through* its `not_after` tick
/// (inclusive); it is expired once `now` has moved strictly past it.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct LogicalTime(pub u64);

impl LogicalTime {
    pub const fn new(tick: u64) -> Self {
        LogicalTime(tick)
    }
    pub const fn tick(self) -> u64 {
        self.0
    }
}

impl From<u64> for LogicalTime {
    fn from(t: u64) -> Self {
        LogicalTime(t)
    }
}

impl fmt::Display for LogicalTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "t{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// Capability
// ---------------------------------------------------------------------------

/// A single authority verb (e.g. `"repo:read"`, `"jira:comment"`). Scopes are sets of these.
/// Kept an opaque string newtype so the capability vocabulary lives in the control plane
/// (ADR-026), not baked into this crate.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Capability(pub String);

/// The reserved payment-*initiation* capability verbs (ADR-016 §3.3 / §4 Layer 3): the authority to
/// move value is **not representable** as a grant. A [`DelegationChain`] whose any hop's scope
/// contains one of these is rejected by [`DelegationChain::verify`] as
/// [`VerifyError::ReservedCapability`] — so even a fully-privileged human's OBO context cannot carry
/// the authority to an agent, closing confused-deputy (Pass-5 [AI]) for this class at the *grant*
/// layer, not merely by the downstream absence of a dispatch arm. This list is the identity-layer
/// mirror of the git-controlled §4.5 payment-signature policy; it is intentionally the small set of
/// unambiguous value-movement verbs (initiation/authorization/commit/settlement/mandate-signing),
/// never a broad `payment:*` prefix that would trip a legitimate `payment:read`.
pub const RESERVED_PAYMENT_INITIATION_CAPABILITIES: &[&str] = &[
    "payment:initiate",
    "payment:authorize",
    "payment:commit",
    "payment:send",
    "settlement:initiate",
    "settlement:commit",
    "settlement:release",
    "settlement:post",
    "netting:release",
    "mandate:sign",
    "mandate:present",
    "value:transfer",
    "value:move",
];

impl Capability {
    pub fn new(name: impl Into<String>) -> Self {
        Capability(name.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    /// True iff this capability is a reserved payment-initiation verb that can never appear in any
    /// grant (ADR-016 §4 Layer 3). Case-insensitive so a `PAYMENT:INITIATE` variant cannot smuggle
    /// the authority past the check.
    pub fn is_reserved_payment_initiation(&self) -> bool {
        let c = self.0.to_ascii_lowercase();
        RESERVED_PAYMENT_INITIATION_CAPABILITIES
            .iter()
            .any(|r| c == *r)
    }
}

impl From<&str> for Capability {
    fn from(s: &str) -> Self {
        Capability(s.to_string())
    }
}

impl From<String> for Capability {
    fn from(s: String) -> Self {
        Capability(s)
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Build a capability set from string-like items — an ergonomic constructor for grants and
/// for tests. Deduplicates and orders deterministically via [`BTreeSet`].
pub fn scope<I, S>(items: I) -> BTreeSet<Capability>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    items.into_iter().map(|s| Capability(s.into())).collect()
}

/// Narrow a *requested* capability set to what is actually *available* — the pure
/// scope-narrowing primitive that OBO sub-delegation is built on (ADR-022 §15). The result is
/// exactly `available ∩ requested`, so it can only ever be a **subset of `available`**: a caller
/// that requests more than it holds gets the intersection, never the union. Requesting a superset
/// is therefore a *narrowing* (the excess is dropped), not an escalation — the excess can never
/// leak into a grant. Deterministic and order-independent via [`BTreeSet`].
pub fn narrow_scope(
    available: &BTreeSet<Capability>,
    requested: &BTreeSet<Capability>,
) -> BTreeSet<Capability> {
    available.intersection(requested).cloned().collect()
}

// ---------------------------------------------------------------------------
// Workload identity & actor
// ---------------------------------------------------------------------------

/// A per-Run agent workload identity (ADR-022 §12). `definition` names the versioned role as
/// approved in the git control plane; `run_id` is the ephemeral per-Run instance. Structural
/// equality means two Runs of the same role are **distinct** identities — the invariant that
/// makes "not a shared token" true and lets [`DelegationChain::verify`] distinguish the actor
/// receiving a delegation from the one granting it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AgentId {
    /// The versioned role/definition this workload runs (e.g. `"role/coder@v3"`).
    pub definition: String,
    /// The ephemeral per-Run instance id — unique per Run.
    pub run_id: String,
}

impl AgentId {
    pub fn new(definition: impl Into<String>, run_id: impl Into<String>) -> Self {
        AgentId {
            definition: definition.into(),
            run_id: run_id.into(),
        }
    }
    /// A clean-room trust-domain identity URI for logs/audit (ADR-022 §12 shape).
    /// The trust domain segment is configurable via the `AINXT_TRUST_DOMAIN` environment variable
    /// (default: `"ainxt"`). Set it to your organisation's identifier at deployment time.
    pub fn uri(&self) -> String {
        let trust_domain =
            std::env::var("AINXT_TRUST_DOMAIN").unwrap_or_else(|_| "ainxt".to_string());
        format!(
            "ainxt-id://{}/agent/{}/run/{}",
            trust_domain, self.definition, self.run_id
        )
    }
}

impl fmt::Display for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.uri())
    }
}

/// Who is acting or granting. A [`Actor::Human`] carries the JWT principal id and is the only
/// legitimate **root** of a delegation chain (the accountable authority, ADR-022 §11). An
/// [`Actor::Agent`] is a workload that may receive — and further narrow — delegated authority.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Actor {
    /// The authenticated human principal (JWT `sub`) — the root of authority.
    Human(String),
    /// A per-Run agent workload identity.
    Agent(AgentId),
}

impl Actor {
    pub fn human(user_id: impl Into<String>) -> Self {
        Actor::Human(user_id.into())
    }
    pub fn agent(id: AgentId) -> Self {
        Actor::Agent(id)
    }
    /// Root a delegation chain at the authenticated principal (the OBO human, ADR-022 §12).
    pub fn from_principal(principal: &ainxt_types::Principal) -> Self {
        Actor::Human(principal.user_id.clone())
    }
    pub fn is_human(&self) -> bool {
        matches!(self, Actor::Human(_))
    }
    pub fn is_agent(&self) -> bool {
        matches!(self, Actor::Agent(_))
    }
    /// A stable label for the audit trail (ADR-022 §14 "actor of record").
    pub fn label(&self) -> String {
        match self {
            Actor::Human(id) => format!("human:{id}"),
            Actor::Agent(id) => id.uri(),
        }
    }
}

impl fmt::Display for Actor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.label())
    }
}

// ---------------------------------------------------------------------------
// Delegation hop
// ---------------------------------------------------------------------------

/// One on-behalf-of hop: `delegator` confers `scope` on `delegate`, valid through `not_after`.
/// The delegate may re-delegate only a subset of `scope`, for no longer than `not_after` —
/// enforced by [`DelegationChain::verify`], never assumed here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delegation {
    pub delegator: Actor,
    pub delegate: Actor,
    pub scope: BTreeSet<Capability>,
    pub not_after: LogicalTime,
}

impl Delegation {
    /// Construct a hop. `not_after` is a raw logical tick — the field it lands in is the
    /// strongly-typed [`LogicalTime`]; callers who already hold a [`LogicalTime`] can build the
    /// struct literal directly or pass `lt.tick()`.
    pub fn new(
        delegator: Actor,
        delegate: Actor,
        scope: BTreeSet<Capability>,
        not_after: u64,
    ) -> Self {
        Delegation {
            delegator,
            delegate,
            scope,
            not_after: LogicalTime(not_after),
        }
    }

    /// True if this grant has expired by `now` (valid *through* `not_after`, inclusive).
    pub fn is_expired_at(&self, now: LogicalTime) -> bool {
        now > self.not_after
    }
}

// ---------------------------------------------------------------------------
// Verification failure
// ---------------------------------------------------------------------------

/// Why a [`DelegationChain`] is not a valid delegation of authority at a given time. Every
/// variant names the exact offending `hop` (0-indexed) so a rejection is diagnosable and a
/// widening attempt is attributable — never a bare boolean.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum VerifyError {
    /// The chain has no hops — there is no authority to delegate.
    EmptyChain,
    /// The chain's root delegator is not a human. Authority must root in an accountable person.
    RootNotHuman,
    /// A hop delegates to a non-agent (a human). Authority never flows back to a human.
    DelegateNotAgent { hop: usize },
    /// A hop delegates to itself — a degenerate/loop grant.
    SelfDelegation { hop: usize },
    /// A hop's delegator is not the previous hop's delegate — the chain is not connected.
    BrokenLink { hop: usize },
    /// An identity appears more than once — the chain is not a simple path (cycle/replay).
    CyclicChain { hop: usize },
    /// A hop's scope contains a reserved payment-initiation capability (ADR-016 §4 Layer 3): the
    /// authority to move value is not representable as a grant, so the whole chain is invalid and
    /// authorizes nothing. Names the offending hop and the reserved capabilities.
    ReservedCapability {
        hop: usize,
        reserved: BTreeSet<Capability>,
    },
    /// A hop grants capabilities its delegator does not hold — privilege escalation. The
    /// `offending` set is exactly the widened capabilities, in deterministic order.
    ScopeWidening {
        hop: usize,
        offending: BTreeSet<Capability>,
    },
    /// A hop's authority window outlives its delegator's — time escalation.
    ExpiryWidening {
        hop: usize,
        hop_not_after: LogicalTime,
        delegator_not_after: LogicalTime,
    },
    /// A hop is expired at `now`.
    Expired {
        hop: usize,
        not_after: LogicalTime,
        now: LogicalTime,
    },
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::EmptyChain => write!(f, "delegation chain is empty"),
            VerifyError::RootNotHuman => {
                write!(f, "chain root delegator is not a human (authority must root in a person)")
            }
            VerifyError::DelegateNotAgent { hop } => {
                write!(f, "hop {hop} delegates to a non-agent (authority cannot flow back to a human)")
            }
            VerifyError::SelfDelegation { hop } => {
                write!(f, "hop {hop} delegates to itself")
            }
            VerifyError::BrokenLink { hop } => {
                write!(f, "hop {hop} is not connected: its delegator is not hop {}'s delegate", hop - 1)
            }
            VerifyError::CyclicChain { hop } => {
                write!(f, "hop {hop} reintroduces an identity already in the chain (cycle)")
            }
            VerifyError::ReservedCapability { hop, reserved } => {
                let names: Vec<&str> = reserved.iter().map(Capability::as_str).collect();
                write!(
                    f,
                    "hop {hop} carries reserved payment-initiation capabilities that are not grantable: [{}]",
                    names.join(", ")
                )
            }
            VerifyError::ScopeWidening { hop, offending } => {
                let names: Vec<&str> = offending.iter().map(Capability::as_str).collect();
                write!(
                    f,
                    "hop {hop} widens scope beyond its delegator; offending capabilities: [{}]",
                    names.join(", ")
                )
            }
            VerifyError::ExpiryWidening {
                hop,
                hop_not_after,
                delegator_not_after,
            } => write!(
                f,
                "hop {hop} extends authority to {hop_not_after} beyond its delegator's {delegator_not_after}"
            ),
            VerifyError::Expired {
                hop,
                not_after,
                now,
            } => write!(f, "hop {hop} expired at {not_after} (now {now})"),
        }
    }
}

impl std::error::Error for VerifyError {}

// ---------------------------------------------------------------------------
// Sub-delegation construction failure
// ---------------------------------------------------------------------------

/// Why a safe sub-delegation could not be constructed by
/// [`DelegationChain::delegate_to`]. Distinct from [`VerifyError`] because these are failures to
/// *build* a narrowing hop, not failures to *validate* an existing chain — though a widening or
/// cyclic result is surfaced through [`DelegateError::ChainInvalid`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegateError {
    /// The chain being delegated *from* does not verify at `now`, so it holds no authority to
    /// pass on. Also carries a cyclic/expired result if the produced hop would be invalid.
    ChainInvalid(VerifyError),
    /// The proposed delegate is not an agent workload — authority never lands on a human.
    DelegateNotAgent,
    /// After narrowing to the intersection of the requested scope and the chain's effective
    /// scope, nothing remains to grant — a delegation of no authority is refused rather than
    /// minting an empty, useless (and confusing) credential.
    EmptyScope,
}

impl fmt::Display for DelegateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DelegateError::ChainInvalid(e) => {
                write!(f, "cannot delegate from an invalid chain: {e}")
            }
            DelegateError::DelegateNotAgent => {
                write!(
                    f,
                    "delegate must be an agent workload (authority cannot land on a human)"
                )
            }
            DelegateError::EmptyScope => {
                write!(f, "narrowed delegation scope is empty; nothing to grant")
            }
        }
    }
}

impl std::error::Error for DelegateError {}

// ---------------------------------------------------------------------------
// Delegation chain
// ---------------------------------------------------------------------------

/// An ordered on-behalf-of chain user → agent → sub-agent. The public authority algebra —
/// [`verify`](DelegationChain::verify), [`effective_scope`](DelegationChain::effective_scope),
/// and [`can`](DelegationChain::can) — is defined over this.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationChain {
    pub hops: Vec<Delegation>,
}

impl DelegationChain {
    /// A chain from an explicit hop list.
    pub fn new(hops: Vec<Delegation>) -> Self {
        DelegationChain { hops }
    }

    /// An empty chain — verifies to [`VerifyError::EmptyChain`] and authorizes nothing.
    pub fn empty() -> Self {
        DelegationChain { hops: Vec::new() }
    }

    /// Append a hop (mutable builder).
    pub fn push(&mut self, hop: Delegation) {
        self.hops.push(hop);
    }

    /// Append a hop (chaining builder).
    pub fn then(mut self, hop: Delegation) -> Self {
        self.hops.push(hop);
        self
    }

    pub fn len(&self) -> usize {
        self.hops.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hops.is_empty()
    }

    /// The root of authority (the first hop's delegator) — the accountable human, if any.
    pub fn root(&self) -> Option<&Actor> {
        self.hops.first().map(|h| &h.delegator)
    }

    /// The current acting identity (the last hop's delegate) — the leaf sub-agent, if any.
    pub fn leaf(&self) -> Option<&Actor> {
        self.hops.last().map(|h| &h.delegate)
    }

    /// Verify the chain is a valid delegation of authority at `now`. See the crate/type docs
    /// for the full IFF. Returns `Ok(())` when valid, or the first violating condition — with
    /// the offending hop named — otherwise. Checks are ordered so that a more fundamental
    /// defect (structure, then connectivity, then narrowing, then expiry) is reported first.
    pub fn verify(&self, now: LogicalTime) -> Result<(), VerifyError> {
        if self.hops.is_empty() {
            return Err(VerifyError::EmptyChain);
        }
        // The root of authority must be an accountable human (ADR-022 §11).
        if !self.hops[0].delegator.is_human() {
            return Err(VerifyError::RootNotHuman);
        }

        // Track every identity already in the chain so a repeat is a detectable cycle. The
        // root delegator is present from the start.
        let mut seen: BTreeSet<&Actor> = BTreeSet::new();
        seen.insert(&self.hops[0].delegator);

        for (i, hop) in self.hops.iter().enumerate() {
            // Authority only ever lands on an agent workload, never back on a human.
            if !hop.delegate.is_agent() {
                return Err(VerifyError::DelegateNotAgent { hop: i });
            }
            // No hop may delegate to itself.
            if hop.delegator == hop.delegate {
                return Err(VerifyError::SelfDelegation { hop: i });
            }
            // The authority to move value is not representable as a grant (ADR-016 §4 Layer 3): a
            // scope containing a reserved payment-initiation verb invalidates the whole chain, so
            // no OBO context can ever carry payment authority to an agent.
            let reserved: BTreeSet<Capability> = hop
                .scope
                .iter()
                .filter(|c| c.is_reserved_payment_initiation())
                .cloned()
                .collect();
            if !reserved.is_empty() {
                return Err(VerifyError::ReservedCapability { hop: i, reserved });
            }

            if i > 0 {
                let prev = &self.hops[i - 1];
                // Connectivity: each delegate is the next delegator.
                if hop.delegator != prev.delegate {
                    return Err(VerifyError::BrokenLink { hop: i });
                }
                // Scope may only narrow — the delegate cannot confer authority the delegator
                // does not itself hold (subset, equality allowed).
                if !hop.scope.is_subset(&prev.scope) {
                    let offending = hop.scope.difference(&prev.scope).cloned().collect();
                    return Err(VerifyError::ScopeWidening { hop: i, offending });
                }
                // The authority window may only shrink — a sub-delegation cannot outlive its
                // delegator's grant.
                if hop.not_after > prev.not_after {
                    return Err(VerifyError::ExpiryWidening {
                        hop: i,
                        hop_not_after: hop.not_after,
                        delegator_not_after: prev.not_after,
                    });
                }
            }

            // The chain must be a simple path — no identity appears twice.
            if seen.contains(&hop.delegate) {
                return Err(VerifyError::CyclicChain { hop: i });
            }
            seen.insert(&hop.delegate);

            // The grant must not be expired at `now`.
            if hop.is_expired_at(now) {
                return Err(VerifyError::Expired {
                    hop: i,
                    not_after: hop.not_after,
                    now,
                });
            }
        }
        Ok(())
    }

    /// True iff the chain verifies at `now`.
    pub fn is_valid(&self, now: LogicalTime) -> bool {
        self.verify(now).is_ok()
    }

    /// The effective scope: the intersection of every hop's scope, naturally capped by the
    /// root. This is a pure set computation independent of validity/time — a capability the
    /// root held but any hop dropped is absent from the result. An empty chain has an empty
    /// effective scope.
    pub fn effective_scope(&self) -> BTreeSet<Capability> {
        let mut hops = self.hops.iter();
        let Some(first) = hops.next() else {
            return BTreeSet::new();
        };
        let mut acc = first.scope.clone();
        for hop in hops {
            // Intersect down; once empty it stays empty.
            acc = acc.intersection(&hop.scope).cloned().collect();
            if acc.is_empty() {
                break;
            }
        }
        acc
    }

    /// The effective scope, but only if the chain verifies at `now`; otherwise the verification
    /// error. Use this when you want the authorized capability set of a valid chain in one call.
    pub fn verified_effective_scope(
        &self,
        now: LogicalTime,
    ) -> Result<BTreeSet<Capability>, VerifyError> {
        self.verify(now)?;
        Ok(self.effective_scope())
    }

    /// Authorize `capability` at `now`: true **iff** the chain verifies **and** the capability
    /// is in the effective scope. A dropped-mid-chain capability is denied even if the root had
    /// it; any capability is denied on an invalid or expired chain.
    pub fn can(&self, capability: &Capability, now: LogicalTime) -> bool {
        self.verify(now).is_ok() && self.effective_scope().contains(capability)
    }

    /// [`can`](DelegationChain::can) with a `&str` capability — an ergonomic wrapper.
    pub fn can_str(&self, capability: &str, now: LogicalTime) -> bool {
        self.can(&Capability::from(capability), now)
    }

    /// Safely extend this chain by delegating a **narrowed** subset of its current authority to
    /// `delegate`, valid for no longer than the current leaf (ADR-022 §15 OBO inheritance). This
    /// is the *constructive* counterpart to [`verify`](DelegationChain::verify): rather than
    /// checking a hop the caller built, it **builds a hop that cannot escalate**:
    ///
    /// * the granted scope is `narrow_scope(effective_scope, requested_scope)` — the intersection
    ///   of what the chain actually holds with what the caller asked for, so a request for more
    ///   than is held silently narrows to the held subset instead of widening;
    /// * the authority window is `min(requested_not_after, leaf_not_after)` — a sub-delegation can
    ///   never outlive its delegator even if a longer TTL is requested.
    ///
    /// The returned chain is **guaranteed to `verify(now)`** (the method re-verifies before
    /// returning, so a delegate that would form a cycle, or a `requested_not_after` already in the
    /// past, is reported as [`DelegateError::ChainInvalid`] rather than yielding a bad credential).
    /// Refuses up-front if this chain is invalid at `now`, the delegate is not an agent, or the
    /// narrowed scope is empty.
    pub fn delegate_to(
        &self,
        delegate: Actor,
        requested_scope: &BTreeSet<Capability>,
        requested_not_after: LogicalTime,
        now: LogicalTime,
    ) -> Result<DelegationChain, DelegateError> {
        // The chain must currently hold authority to pass any on.
        self.verify(now).map_err(DelegateError::ChainInvalid)?;
        if !delegate.is_agent() {
            return Err(DelegateError::DelegateNotAgent);
        }
        // Narrow: grant only the intersection of what we hold and what was asked for.
        let granted = narrow_scope(&self.effective_scope(), requested_scope);
        if granted.is_empty() {
            return Err(DelegateError::EmptyScope);
        }
        // `verify` above guarantees a non-empty chain, so a leaf hop exists.
        let Some(leaf_hop) = self.hops.last() else {
            return Err(DelegateError::ChainInvalid(VerifyError::EmptyChain));
        };
        let not_after = requested_not_after.min(leaf_hop.not_after);
        let hop = Delegation {
            delegator: leaf_hop.delegate.clone(),
            delegate,
            scope: granted,
            not_after,
        };
        let mut extended = self.clone();
        extended.push(hop);
        // Postcondition: the produced chain verifies (catches cycles / a past `not_after`).
        extended.verify(now).map_err(DelegateError::ChainInvalid)?;
        Ok(extended)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // Fixtures: a canonical user -> agent -> sub-agent chain builder.
    // ------------------------------------------------------------------

    fn user() -> Actor {
        Actor::human("u-alice")
    }
    fn agent() -> Actor {
        Actor::agent(AgentId::new("role/coder@v3", "run-1"))
    }
    fn subagent() -> Actor {
        Actor::agent(AgentId::new("role/tester@v2", "run-2"))
    }

    /// user{scopes...} --tU--> agent{...} --tA--> sub{...}
    fn chain(
        u_scope: &[&str],
        u_t: u64,
        a_scope: &[&str],
        a_t: u64,
        s_scope: &[&str],
        s_t: u64,
    ) -> DelegationChain {
        DelegationChain::new(vec![
            Delegation::new(user(), agent(), scope(u_scope.to_vec()), u_t),
            Delegation::new(agent(), subagent(), scope(a_scope.to_vec()), a_t),
            // second-level sub-delegation reuses `subagent` as delegator into a fresh leaf
            Delegation::new(
                subagent(),
                Actor::agent(AgentId::new("role/linter@v1", "run-3")),
                scope(s_scope.to_vec()),
                s_t,
            ),
        ])
    }

    fn t(x: u64) -> LogicalTime {
        LogicalTime(x)
    }

    // ------------------------------------------------------------------
    // 1. A narrowing chain verifies and yields the intersected scope.
    // ------------------------------------------------------------------

    #[test]
    fn narrowing_chain_verifies_and_intersects() {
        let c = chain(
            &["repo:read", "repo:write", "jira:comment"],
            100,
            &["repo:read", "repo:write"],
            90,
            &["repo:read"],
            80,
        );
        assert_eq!(
            c.verify(t(50)),
            Ok(()),
            "a strictly-narrowing chain is valid"
        );
        assert_eq!(
            c.effective_scope(),
            scope(vec!["repo:read"]),
            "effective scope is the intersection = the leaf's single retained capability"
        );
        assert!(c.can_str("repo:read", t(50)));
        assert!(!c.can_str("repo:write", t(50)), "dropped at the leaf hop");
        assert!(
            !c.can_str("jira:comment", t(50)),
            "dropped at the first sub-hop"
        );
    }

    #[test]
    fn equal_scope_hops_are_valid_narrowing_is_not_strict() {
        // subset allows equality — a hop that re-confers the exact same scope is legal.
        let c = DelegationChain::new(vec![
            Delegation::new(user(), agent(), scope(vec!["a", "b"]), 10),
            Delegation::new(agent(), subagent(), scope(vec!["a", "b"]), 10),
        ]);
        assert_eq!(c.verify(t(5)), Ok(()));
        assert_eq!(c.effective_scope(), scope(vec!["a", "b"]));
    }

    // ------------------------------------------------------------------
    // 2. A widening hop is rejected, naming the hop and the capabilities.
    // ------------------------------------------------------------------

    #[test]
    fn widening_hop_is_rejected_naming_hop_and_capability() {
        // sub-agent (hop 1) tries to grant `admin:all` that the agent never held.
        let c = DelegationChain::new(vec![
            Delegation::new(user(), agent(), scope(vec!["repo:read", "repo:write"]), 10),
            Delegation::new(
                agent(),
                subagent(),
                scope(vec!["repo:read", "admin:all"]),
                10,
            ),
        ]);
        match c.verify(t(5)) {
            Err(VerifyError::ScopeWidening { hop, offending }) => {
                assert_eq!(hop, 1, "the offending hop is named");
                assert_eq!(
                    offending,
                    scope(vec!["admin:all"]),
                    "exactly the widened capability is reported"
                );
            }
            other => panic!("expected ScopeWidening, got {other:?}"),
        }
        assert!(
            !c.can_str("admin:all", t(5)),
            "escalated cap is never authorized"
        );
        assert!(
            !c.can_str("repo:read", t(5)),
            "an invalid chain authorizes nothing"
        );
    }

    // ------------------------------------------------------------------
    // 3. Effective scope is the intersection across all hops.
    // ------------------------------------------------------------------

    #[test]
    fn effective_scope_is_intersection_across_all_hops() {
        // Each hop drops a different capability; intersection is what survives all of them.
        let c = DelegationChain::new(vec![
            Delegation::new(user(), agent(), scope(vec!["a", "b", "c", "d"]), 10),
            Delegation::new(agent(), subagent(), scope(vec!["a", "b", "c"]), 10),
            Delegation::new(
                subagent(),
                Actor::agent(AgentId::new("role/x@v1", "run-9")),
                scope(vec!["a", "b"]),
                10,
            ),
        ]);
        assert_eq!(c.verify(t(5)), Ok(()));
        assert_eq!(c.effective_scope(), scope(vec!["a", "b"]));
    }

    // ------------------------------------------------------------------
    // 4. An expired hop invalidates the chain.
    // ------------------------------------------------------------------

    #[test]
    fn expired_hop_invalidates_chain() {
        // A legal (non-widening) time chain whose agent->sub hop (hop 1) expires at t=90.
        let c = DelegationChain::new(vec![
            Delegation::new(user(), agent(), scope(vec!["a", "b"]), 100),
            Delegation::new(agent(), subagent(), scope(vec!["a"]), 90),
        ]);
        assert_eq!(c.verify(t(50)), Ok(()), "valid before expiry");
        assert_eq!(
            c.verify(t(90)),
            Ok(()),
            "valid exactly at not_after (inclusive)"
        );
        match c.verify(t(91)) {
            Err(VerifyError::Expired {
                hop,
                not_after,
                now,
            }) => {
                assert_eq!(hop, 1);
                assert_eq!(not_after, t(90));
                assert_eq!(now, t(91));
            }
            other => panic!("expected Expired, got {other:?}"),
        }
        assert!(!c.can_str("a", t(91)), "expired chain authorizes nothing");
    }

    // ------------------------------------------------------------------
    // 5. A broken link is rejected.
    // ------------------------------------------------------------------

    #[test]
    fn broken_link_is_rejected() {
        // hop 1's delegator is a DIFFERENT agent than hop 0's delegate.
        let other_agent = Actor::agent(AgentId::new("role/other@v1", "run-x"));
        let c = DelegationChain::new(vec![
            Delegation::new(user(), agent(), scope(vec!["a"]), 10),
            Delegation::new(other_agent, subagent(), scope(vec!["a"]), 10),
        ]);
        assert_eq!(c.verify(t(5)), Err(VerifyError::BrokenLink { hop: 1 }));
        assert!(!c.can_str("a", t(5)));
    }

    #[test]
    fn same_role_different_run_is_a_broken_link() {
        // Two Runs of the SAME definition are DISTINCT identities: reusing the definition but
        // a new run_id does not connect the chain — proves identity is per-Run, not per-role.
        let agent_run_a = Actor::agent(AgentId::new("role/coder@v3", "run-1"));
        let agent_run_b = Actor::agent(AgentId::new("role/coder@v3", "run-777"));
        let c = DelegationChain::new(vec![
            Delegation::new(user(), agent_run_a, scope(vec!["a"]), 10),
            Delegation::new(agent_run_b, subagent(), scope(vec!["a"]), 10),
        ]);
        assert_eq!(c.verify(t(5)), Err(VerifyError::BrokenLink { hop: 1 }));
    }

    // ------------------------------------------------------------------
    // 6. sub-agent <= agent <= user (layered non-escalation).
    // ------------------------------------------------------------------

    #[test]
    fn subagent_cannot_exceed_agent_which_cannot_exceed_user() {
        // Case A: the agent tries to exceed the user at hop 0->1.
        let agent_exceeds_user = DelegationChain::new(vec![
            Delegation::new(user(), agent(), scope(vec!["read"]), 10),
            Delegation::new(agent(), subagent(), scope(vec!["read", "write"]), 10),
        ]);
        assert!(
            matches!(
                agent_exceeds_user.verify(t(5)),
                Err(VerifyError::ScopeWidening { hop: 1, .. })
            ),
            "agent cannot exceed user"
        );

        // Case B: the agent stays within the user, but the sub-agent tries to exceed the agent.
        let sub_exceeds_agent = DelegationChain::new(vec![
            Delegation::new(user(), agent(), scope(vec!["read", "write"]), 10),
            Delegation::new(agent(), subagent(), scope(vec!["read"]), 10),
            Delegation::new(
                subagent(),
                Actor::agent(AgentId::new("role/x@v1", "run-9")),
                scope(vec!["read", "write"]), // write was dropped at hop 1
                10,
            ),
        ]);
        match sub_exceeds_agent.verify(t(5)) {
            Err(VerifyError::ScopeWidening { hop, offending }) => {
                assert_eq!(hop, 2);
                assert_eq!(offending, scope(vec!["write"]));
            }
            other => panic!("expected ScopeWidening at hop 2, got {other:?}"),
        }
    }

    // ------------------------------------------------------------------
    // 7. can() denies a capability dropped mid-chain even if the root had it.
    // ------------------------------------------------------------------

    #[test]
    fn can_denies_capability_dropped_mid_chain() {
        // Root grants {settle-read, code}; the agent drops `settle-read`; the leaf can only code.
        let c = DelegationChain::new(vec![
            Delegation::new(user(), agent(), scope(vec!["settle-read", "code"]), 10),
            Delegation::new(agent(), subagent(), scope(vec!["code"]), 10),
        ]);
        assert_eq!(c.verify(t(5)), Ok(()));
        assert!(c.can_str("code", t(5)), "retained capability is authorized");
        assert!(
            !c.can_str("settle-read", t(5)),
            "a capability the root held but a hop dropped is denied"
        );
    }

    // ------------------------------------------------------------------
    // 8. Structural rejections: root-not-human, delegate-not-agent, self, cycle.
    // ------------------------------------------------------------------

    #[test]
    fn root_delegator_must_be_human() {
        let c = DelegationChain::new(vec![Delegation::new(
            agent(), // an agent as the root of authority — illegal
            subagent(),
            scope(vec!["a"]),
            10,
        )]);
        assert_eq!(c.verify(t(5)), Err(VerifyError::RootNotHuman));
    }

    #[test]
    fn delegate_must_be_an_agent() {
        // A hop that delegates authority back to a human is rejected.
        let c = DelegationChain::new(vec![Delegation::new(
            user(),
            Actor::human("u-bob"), // human delegate — authority cannot land back on a human
            scope(vec!["a"]),
            10,
        )]);
        assert_eq!(
            c.verify(t(5)),
            Err(VerifyError::DelegateNotAgent { hop: 0 })
        );
    }

    #[test]
    fn self_delegation_is_rejected() {
        let a = agent();
        let c = DelegationChain::new(vec![
            Delegation::new(user(), a.clone(), scope(vec!["a"]), 10),
            Delegation::new(a.clone(), a, scope(vec!["a"]), 10), // agent -> itself
        ]);
        assert_eq!(c.verify(t(5)), Err(VerifyError::SelfDelegation { hop: 1 }));
    }

    #[test]
    fn cyclic_chain_is_rejected() {
        // user -> A -> B -> A : the reappearance of A at hop 2 is a cycle.
        let a = agent();
        let b = subagent();
        let c = DelegationChain::new(vec![
            Delegation::new(user(), a.clone(), scope(vec!["a"]), 10),
            Delegation::new(a.clone(), b.clone(), scope(vec!["a"]), 10),
            Delegation::new(b, a, scope(vec!["a"]), 10),
        ]);
        assert_eq!(c.verify(t(5)), Err(VerifyError::CyclicChain { hop: 2 }));
    }

    // ------------------------------------------------------------------
    // 9. Expiry-widening (time escalation) is rejected.
    // ------------------------------------------------------------------

    #[test]
    fn sub_delegation_cannot_outlive_its_delegator() {
        let c = DelegationChain::new(vec![
            Delegation::new(user(), agent(), scope(vec!["a"]), 100),
            Delegation::new(agent(), subagent(), scope(vec!["a"]), 200), // outlives the agent
        ]);
        match c.verify(t(5)) {
            Err(VerifyError::ExpiryWidening {
                hop,
                hop_not_after,
                delegator_not_after,
            }) => {
                assert_eq!(hop, 1);
                assert_eq!(hop_not_after, t(200));
                assert_eq!(delegator_not_after, t(100));
            }
            other => panic!("expected ExpiryWidening, got {other:?}"),
        }
    }

    // ------------------------------------------------------------------
    // 10. Empty / single-hop / boundary behaviours.
    // ------------------------------------------------------------------

    #[test]
    fn empty_chain_authorizes_nothing() {
        let c = DelegationChain::empty();
        assert_eq!(c.verify(t(0)), Err(VerifyError::EmptyChain));
        assert!(c.effective_scope().is_empty());
        assert!(!c.can_str("anything", t(0)));
        assert!(c.root().is_none() && c.leaf().is_none());
    }

    #[test]
    fn single_hop_user_to_agent_authorizes_its_scope() {
        let c = DelegationChain::new(vec![Delegation::new(
            user(),
            agent(),
            scope(vec!["repo:read", "repo:write"]),
            10,
        )]);
        assert_eq!(c.verify(t(5)), Ok(()));
        assert_eq!(c.effective_scope(), scope(vec!["repo:read", "repo:write"]));
        assert!(c.can_str("repo:read", t(5)));
        assert!(!c.can_str("repo:delete", t(5)), "never-granted cap denied");
        assert_eq!(c.root(), Some(&user()));
        assert_eq!(c.leaf(), Some(&agent()));
    }

    // ------------------------------------------------------------------
    // 11. verified_effective_scope + from_principal integration.
    // ------------------------------------------------------------------

    #[test]
    fn verified_effective_scope_gates_on_validity() {
        let valid =
            DelegationChain::new(vec![Delegation::new(user(), agent(), scope(vec!["a"]), 10)]);
        assert_eq!(valid.verified_effective_scope(t(5)), Ok(scope(vec!["a"])));
        assert_eq!(
            valid.verified_effective_scope(t(11)),
            Err(VerifyError::Expired {
                hop: 0,
                not_after: t(10),
                now: t(11)
            })
        );
    }

    #[test]
    fn root_actor_from_jwt_principal() {
        let p = ainxt_types::Principal::user("u-carol", &["repo:read"]);
        let root = Actor::from_principal(&p);
        assert_eq!(root, Actor::human("u-carol"));
        let c = DelegationChain::new(vec![Delegation::new(
            root,
            agent(),
            scope(vec!["repo:read"]),
            10,
        )]);
        assert_eq!(c.verify(t(1)), Ok(()));
        assert!(c.can_str("repo:read", t(1)));
    }

    // ------------------------------------------------------------------
    // 12. Determinism of the offending-set + error ordering + serde shape.
    // ------------------------------------------------------------------

    #[test]
    fn structural_error_reported_before_scope_error() {
        // A chain that both breaks the link AND widens scope reports the more fundamental
        // structural defect (broken link) first — deterministic ordering.
        let other = Actor::agent(AgentId::new("role/other@v1", "run-x"));
        let c = DelegationChain::new(vec![
            Delegation::new(user(), agent(), scope(vec!["a"]), 10),
            Delegation::new(other, subagent(), scope(vec!["a", "b"]), 10),
        ]);
        assert_eq!(c.verify(t(5)), Err(VerifyError::BrokenLink { hop: 1 }));
    }

    #[test]
    fn delegation_credential_round_trips_through_serde() {
        // Not a tautology test: we assert the concrete JSON tag shape AND that a chain
        // deserialized from the wire verifies to the same decision as the original.
        let c = DelegationChain::new(vec![
            Delegation::new(user(), agent(), scope(vec!["a", "b"]), 10),
            Delegation::new(agent(), subagent(), scope(vec!["a"]), 9),
        ]);
        let json = serde_json::to_string(&c).unwrap();
        let back: DelegationChain = serde_json::from_str(&json).unwrap();
        assert_eq!(back, c);
        assert_eq!(back.verify(t(5)), Ok(()));
        assert_eq!(back.effective_scope(), scope(vec!["a"]));

        // The error enum serializes with a discriminant tag usable by a non-Rust auditor.
        let err = VerifyError::ScopeWidening {
            hop: 2,
            offending: scope(vec!["admin:all"]),
        };
        let ejson = serde_json::to_value(&err).unwrap();
        assert_eq!(ejson["error"], "scope_widening");
        assert_eq!(ejson["hop"], 2);
    }

    // ------------------------------------------------------------------
    // 13. OBO scope-narrowing helpers: narrow_scope + delegate_to.
    // ------------------------------------------------------------------

    #[test]
    fn narrow_scope_is_intersection_never_widens() {
        let available = scope(vec!["a", "b", "c"]);
        // Request a superset {a,b,c,d,e}: the excess {d,e} is dropped, not granted.
        let requested = scope(vec!["a", "c", "d", "e"]);
        let got = narrow_scope(&available, &requested);
        assert_eq!(got, scope(vec!["a", "c"]));
        assert!(
            got.is_subset(&available),
            "result can never exceed available"
        );
    }

    #[test]
    fn delegate_to_narrows_superset_request_and_clamps_expiry() {
        // A valid single-hop chain user->agent holding {read,write} until t=100.
        let base = DelegationChain::new(vec![Delegation::new(
            user(),
            agent(),
            scope(vec!["read", "write"]),
            100,
        )]);
        // The agent sub-delegates to a tester, REQUESTING more than it holds ({read,write,admin})
        // and a LONGER window (t=500) than it has.
        let sub = base
            .delegate_to(
                subagent(),
                &scope(vec!["read", "write", "admin"]),
                t(500),
                t(10),
            )
            .expect("narrowing delegation must succeed");
        // The produced chain verifies, and the new hop granted only {read,write} (admin dropped)
        // with not_after clamped to the delegator's 100 (not the requested 500).
        assert_eq!(sub.verify(t(10)), Ok(()));
        let leaf_hop = sub.hops.last().unwrap();
        assert_eq!(
            leaf_hop.scope,
            scope(vec!["read", "write"]),
            "admin was narrowed away"
        );
        assert_eq!(
            leaf_hop.not_after,
            t(100),
            "expiry clamped to the delegator's window"
        );
        assert!(
            !sub.can_str("admin", t(10)),
            "the excess capability is never authorized"
        );
        assert!(sub.can_str("read", t(10)));
        // And the produced credential expires with its delegator, not at the requested t=500.
        assert!(!sub.can_str("read", t(101)), "clamped window is enforced");
    }

    #[test]
    fn delegate_to_refuses_from_an_invalid_chain() {
        // An already-expired chain holds no authority to pass on.
        let base = DelegationChain::new(vec![Delegation::new(
            user(),
            agent(),
            scope(vec!["read"]),
            10,
        )]);
        let err = base
            .delegate_to(subagent(), &scope(vec!["read"]), t(20), t(20))
            .unwrap_err();
        assert!(
            matches!(
                err,
                DelegateError::ChainInvalid(VerifyError::Expired { hop: 0, .. })
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn delegate_to_refuses_non_agent_delegate_and_empty_scope() {
        let base = DelegationChain::new(vec![Delegation::new(
            user(),
            agent(),
            scope(vec!["read"]),
            100,
        )]);
        // A human delegate is refused.
        assert_eq!(
            base.delegate_to(Actor::human("u-bob"), &scope(vec!["read"]), t(50), t(10)),
            Err(DelegateError::DelegateNotAgent)
        );
        // Requesting only capabilities the chain does NOT hold narrows to empty -> refused.
        assert_eq!(
            base.delegate_to(subagent(), &scope(vec!["write", "admin"]), t(50), t(10)),
            Err(DelegateError::EmptyScope)
        );
    }

    #[test]
    fn delegate_to_that_would_cycle_is_reported_as_chain_invalid() {
        // Build user -> agent, then try to delegate back to `agent` (already in the chain).
        let base = DelegationChain::new(vec![Delegation::new(
            user(),
            agent(),
            scope(vec!["read"]),
            100,
        )]);
        // Delegating to the SAME identity as the current leaf is a self-delegation from the leaf.
        let err = base
            .delegate_to(agent(), &scope(vec!["read"]), t(50), t(10))
            .unwrap_err();
        assert!(
            matches!(
                err,
                DelegateError::ChainInvalid(VerifyError::SelfDelegation { .. })
                    | DelegateError::ChainInvalid(VerifyError::CyclicChain { .. })
            ),
            "a re-introduced identity must be refused, got {err:?}"
        );
    }

    // ------------------------------------------------------------------
    // 14. IDN-06 — reserved payment-initiation capability is not grantable.
    // ------------------------------------------------------------------

    #[test]
    fn gap_idn_06_reserved_payment_capability_is_not_representable_in_a_grant() {
        // A fully-privileged human tries to delegate `payment:initiate` to an agent. Under the
        // old by-omission model the opaque string was representable and the chain verified; the
        // structural fix rejects it at the grant layer, so `can()` denies it regardless of who
        // rooted the chain (confused-deputy closed for this class).
        for verb in [
            "payment:initiate",
            "SETTLEMENT:COMMIT",
            "mandate:sign",
            "value:move",
        ] {
            let c = DelegationChain::new(vec![Delegation::new(
                user(),
                agent(),
                scope(vec!["repo:read", verb]),
                100,
            )]);
            match c.verify(t(5)) {
                Err(VerifyError::ReservedCapability { hop, reserved }) => {
                    assert_eq!(hop, 0, "the offending hop is named");
                    assert_eq!(reserved.len(), 1, "exactly the reserved verb is reported");
                    assert!(reserved
                        .iter()
                        .next()
                        .unwrap()
                        .is_reserved_payment_initiation());
                }
                other => panic!("expected ReservedCapability for {verb:?}, got {other:?}"),
            }
            // The chain authorizes NOTHING — not even the benign co-granted capability.
            assert!(
                !c.can_str("repo:read", t(5)),
                "an invalid chain grants nothing"
            );
            assert!(
                !c.can_str(verb, t(5)),
                "the reserved verb is never authorized"
            );
        }

        // A reserved verb introduced by a *sub*-delegation hop is caught too (deeper in the chain).
        let deep = DelegationChain::new(vec![
            Delegation::new(user(), agent(), scope(vec!["repo:read"]), 100),
            Delegation::new(agent(), subagent(), scope(vec!["payment:commit"]), 90),
        ]);
        assert!(matches!(
            deep.verify(t(5)),
            Err(VerifyError::ReservedCapability { hop: 1, .. })
        ));

        // A benign, non-reserved capability set is unaffected.
        let ok = DelegationChain::new(vec![Delegation::new(
            user(),
            agent(),
            scope(vec!["payment:read", "settlement-report:view", "repo:read"]),
            100,
        )]);
        assert_eq!(
            ok.verify(t(5)),
            Ok(()),
            "payment:read is adjacent, not reserved"
        );
        assert!(ok.can_str("payment:read", t(5)));
    }

    #[test]
    fn delegate_to_chains_three_deep_monotonically_narrowing() {
        // user{a,b,c} -> agent, then agent narrows to {a,b}, then sub narrows to {a}.
        let c0 = DelegationChain::new(vec![Delegation::new(
            user(),
            agent(),
            scope(vec!["a", "b", "c"]),
            100,
        )]);
        let c1 = c0
            .delegate_to(subagent(), &scope(vec!["a", "b"]), t(90), t(5))
            .unwrap();
        let leaf2 = Actor::agent(AgentId::new("role/linter@v1", "run-3"));
        let c2 = c1
            .delegate_to(leaf2, &scope(vec!["a"]), t(80), t(5))
            .unwrap();
        assert_eq!(c2.verify(t(5)), Ok(()));
        assert_eq!(c2.effective_scope(), scope(vec!["a"]));
        assert!(c2.can_str("a", t(5)));
        assert!(!c2.can_str("b", t(5)), "narrowed away two hops down");
        assert_eq!(c2.len(), 3);
    }
}
