// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! The Payment-Adjacent Mandate (PAM) model (ADR-016 §6) — the fourth dispatch gate for
//! payment-*adjacent* write actions (e.g. simulate a settlement in a sandbox, draft-and-queue a
//! dispute response), AP2-mandate-shaped but **structurally incapable of expressing value movement**.
//!
//! Design: `docs/architecture/AGENT_IDENTITY_AND_PAYMENT_BOUNDARY.md` §6.
//!
//! # The four properties the PAM guarantees
//!
//! 1. **Human-issued, never agent-issued.** [`PaymentAdjacentMandate::issue`] refuses unless the
//!    signer holds `can_approve` and is senior enough (`ad_level <= 3`, the same authority ADR-026
//!    §5 requires for the payment-boundary front-matter class). An agent can *request* a PAM; only a
//!    human can *sign* one.
//! 2. **Scoped, bounded, expiring, single-purpose.** A PAM names exactly one action verb, one
//!    resource, a hard expiry, and a small use-count (default one), and is bound to the requesting
//!    Run's identity — non-repudiable and non-transferable.
//! 3. **Structurally incapable of value movement.** The [`PaymentAdjacentMandate`] struct has **no
//!    field** for an amount, payee, settlement instruction, or payment credential — value movement
//!    is *unrepresentable*, not merely disallowed. Belt-and-suspenders, [`issue`] additionally
//!    rejects any action verb that is itself a value-movement verb, so a PAM cannot even *spell*
//!    "settle batch B".
//! 4. **Verified at dispatch, alongside OBO.** [`MandateRegistry::authorize`] is a *fourth* gate
//!    checked in addition to the three OBO layers — verb + resource + run-binding + expiry + a
//!    consumed use-count — never a substitute for them.
//!
//! # Determinism
//!
//! No clock, no rng, no I/O: logical time is a caller-supplied `u64` tick and every check is a pure
//! function, so a PAM's authority is reproducible and exhaustively testable.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

/// The maximum AD seniority level permitted to sign a PAM (§6): `ad_level <= 3` (lower = more
/// senior), the `can_approve` + `ad_level<=3` authority ADR-026 §5 mandates for the payment class.
pub const PAM_MAX_SIGNER_AD_LEVEL: u8 = 3;

/// The default use-count of a PAM (§6 "a use-count of one (or a small N)").
pub const PAM_DEFAULT_MAX_USES: u32 = 1;

/// Action verbs that themselves express value movement — a PAM may never carry one (§6: value
/// movement is unrepresentable in a PAM). Case-insensitive; deliberately the small set of
/// unambiguous money verbs, so a legitimate adjacent verb like `settlement:simulate` or
/// `dispute:draft` is unaffected.
pub const VALUE_MOVEMENT_ACTION_VERBS: &[&str] = &[
    "settlement:initiate",
    "settlement:commit",
    "settlement:release",
    "settlement:post",
    "payment:initiate",
    "payment:authorize",
    "payment:commit",
    "payment:send",
    "netting:release",
    "mandate:sign",
    "value:transfer",
    "value:move",
];

fn is_value_movement_verb(verb: &str) -> bool {
    let v = verb.to_ascii_lowercase();
    VALUE_MOVEMENT_ACTION_VERBS.iter().any(|r| v == *r)
}

/// An agent's *request* for a PAM (§6 "the agent can request a PAM; only a human can sign one").
/// Carries only verb + resource + the requesting Run binding + desired expiry/uses — and, by
/// construction, no value field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PamRequest {
    /// Exactly one adjacent action verb, e.g. `"settlement:simulate"`, `"dispute:draft"`.
    pub action_verb: String,
    /// Exactly one resource, e.g. `"netting-batch:B-42"`.
    pub resource: String,
    /// The Run this mandate will be bound to (non-transferable).
    pub bound_run_id: String,
    /// Requested hard expiry (logical tick, inclusive).
    pub not_after: u64,
    /// Requested use-count (clamped to `>= 1`).
    pub max_uses: u32,
}

impl PamRequest {
    /// A single-use PAM request for `verb` on `resource`, bound to `run_id`, expiring at `not_after`.
    pub fn single_use(
        action_verb: impl Into<String>,
        resource: impl Into<String>,
        run_id: impl Into<String>,
        not_after: u64,
    ) -> Self {
        PamRequest {
            action_verb: action_verb.into(),
            resource: resource.into(),
            bound_run_id: run_id.into(),
            not_after,
            max_uses: PAM_DEFAULT_MAX_USES,
        }
    }
}

/// Why a PAM could not be issued or did not authorize an action (§6). Fail-closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PamError {
    /// The signer lacks `can_approve` — an agent (or any non-approver) cannot sign a PAM.
    SignerCannotApprove,
    /// The signer is too junior (`ad_level > PAM_MAX_SIGNER_AD_LEVEL`).
    SignerTooJunior { ad_level: u8, max: u8 },
    /// The action verb is a value-movement verb — value is unrepresentable in a PAM.
    ValueMovementNotRepresentable(String),
    /// A required field (verb / resource / run binding) was empty.
    EmptyField(&'static str),
    /// The requested expiry is already in the past at issuance.
    AlreadyExpired { not_after: u64, now: u64 },
    /// The presented action verb does not match the mandate's single verb.
    WrongAction { expected: String, presented: String },
    /// The presented resource does not match the mandate's single resource.
    WrongResource { expected: String, presented: String },
    /// The presenting Run is not the Run the mandate is bound to (non-transferable).
    NotBoundToRun { bound: String, presented: String },
    /// The mandate has expired at the time of use.
    Expired { not_after: u64, now: u64 },
    /// The mandate's use-count is exhausted (single-use / small-N spent).
    Exhausted { max_uses: u32 },
    /// No such mandate is registered.
    UnknownMandate(String),
}

impl fmt::Display for PamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PamError::SignerCannotApprove => {
                write!(
                    f,
                    "PAM signer lacks can_approve (only a human approver may sign)"
                )
            }
            PamError::SignerTooJunior { ad_level, max } => {
                write!(
                    f,
                    "PAM signer ad_level {ad_level} exceeds required <= {max}"
                )
            }
            PamError::ValueMovementNotRepresentable(v) => write!(
                f,
                "action verb {v:?} expresses value movement, which a PAM cannot represent"
            ),
            PamError::EmptyField(name) => write!(f, "PAM field {name:?} is empty"),
            PamError::AlreadyExpired { not_after, now } => {
                write!(
                    f,
                    "PAM expiry {not_after} is already past at issuance {now}"
                )
            }
            PamError::WrongAction {
                expected,
                presented,
            } => {
                write!(
                    f,
                    "PAM action mismatch: expected {expected:?}, got {presented:?}"
                )
            }
            PamError::WrongResource {
                expected,
                presented,
            } => {
                write!(
                    f,
                    "PAM resource mismatch: expected {expected:?}, got {presented:?}"
                )
            }
            PamError::NotBoundToRun { bound, presented } => {
                write!(
                    f,
                    "PAM is bound to run {bound:?}, presented by {presented:?}"
                )
            }
            PamError::Expired { not_after, now } => {
                write!(f, "PAM expired at {not_after} (now {now})")
            }
            PamError::Exhausted { max_uses } => {
                write!(f, "PAM use-count exhausted (max_uses {max_uses})")
            }
            PamError::UnknownMandate(id) => write!(f, "no PAM registered with id {id:?}"),
        }
    }
}

impl std::error::Error for PamError {}

/// A human-signed Payment-Adjacent Mandate (§6). Constructed **only** by [`issue`](PaymentAdjacentMandate::issue)
/// after the human-authority + no-value-verb checks pass. Note the **absence** of any amount / payee
/// / settlement-instruction / credential field — value movement is unrepresentable by construction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentAdjacentMandate {
    /// A unique mandate id (audit correlation; the use-count in [`MandateRegistry`] keys on it).
    pub id: String,
    /// The single authorized adjacent action verb.
    pub action_verb: String,
    /// The single authorized resource.
    pub resource: String,
    /// The Run this mandate is bound to (non-transferable).
    pub bound_run_id: String,
    /// The human approver who signed it (non-repudiable).
    pub signer_id: String,
    pub signer_ad_level: u8,
    pub issued_at: u64,
    /// Hard expiry (inclusive).
    pub not_after: u64,
    pub max_uses: u32,
}

impl PaymentAdjacentMandate {
    /// Issue a PAM from an agent's `request`, signed by a human approver (§6). Fail-closed:
    /// * the signer must hold `can_approve` (an agent cannot self-issue) and be senior enough;
    /// * the action verb must not be a value-movement verb (value is unrepresentable);
    /// * verb/resource/run-binding must be non-empty and the expiry must be in the future.
    pub fn issue(
        id: impl Into<String>,
        request: &PamRequest,
        signer_id: impl Into<String>,
        signer_ad_level: u8,
        signer_can_approve: bool,
        now: u64,
    ) -> Result<Self, PamError> {
        if !signer_can_approve {
            return Err(PamError::SignerCannotApprove);
        }
        if signer_ad_level > PAM_MAX_SIGNER_AD_LEVEL {
            return Err(PamError::SignerTooJunior {
                ad_level: signer_ad_level,
                max: PAM_MAX_SIGNER_AD_LEVEL,
            });
        }
        if request.action_verb.trim().is_empty() {
            return Err(PamError::EmptyField("action_verb"));
        }
        if request.resource.trim().is_empty() {
            return Err(PamError::EmptyField("resource"));
        }
        if request.bound_run_id.trim().is_empty() {
            return Err(PamError::EmptyField("bound_run_id"));
        }
        if is_value_movement_verb(&request.action_verb) {
            return Err(PamError::ValueMovementNotRepresentable(
                request.action_verb.clone(),
            ));
        }
        if request.not_after <= now {
            return Err(PamError::AlreadyExpired {
                not_after: request.not_after,
                now,
            });
        }
        Ok(PaymentAdjacentMandate {
            id: id.into(),
            action_verb: request.action_verb.clone(),
            resource: request.resource.clone(),
            bound_run_id: request.bound_run_id.clone(),
            signer_id: signer_id.into(),
            signer_ad_level,
            issued_at: now,
            not_after: request.not_after.max(now + 1),
            max_uses: request.max_uses.max(1),
        })
    }

    /// Verify the mandate authorizes `action_verb` on `resource` for `run_id` at `now` — the scope,
    /// binding, and expiry half of the fourth gate (the use-count is consumed by
    /// [`MandateRegistry::authorize`]). Pure; does not mutate.
    pub fn verify(
        &self,
        action_verb: &str,
        resource: &str,
        run_id: &str,
        now: u64,
    ) -> Result<(), PamError> {
        if self.action_verb != action_verb {
            return Err(PamError::WrongAction {
                expected: self.action_verb.clone(),
                presented: action_verb.to_string(),
            });
        }
        if self.resource != resource {
            return Err(PamError::WrongResource {
                expected: self.resource.clone(),
                presented: resource.to_string(),
            });
        }
        if self.bound_run_id != run_id {
            return Err(PamError::NotBoundToRun {
                bound: self.bound_run_id.clone(),
                presented: run_id.to_string(),
            });
        }
        if now > self.not_after {
            return Err(PamError::Expired {
                not_after: self.not_after,
                now,
            });
        }
        Ok(())
    }
}

/// Tracks per-mandate use-counts so a single-use / small-N PAM cannot be replayed (§6). The registry
/// is the stateful *fourth gate*: [`authorize`](MandateRegistry::authorize) verifies scope/binding/
/// expiry and consumes one use, refusing an exhausted mandate.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MandateRegistry {
    /// mandate id -> uses already consumed.
    used: BTreeMap<String, u32>,
}

impl MandateRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Uses already consumed for a mandate id.
    pub fn uses_consumed(&self, mandate_id: &str) -> u32 {
        self.used.get(mandate_id).copied().unwrap_or(0)
    }

    /// The fourth gate at dispatch (§6): verify the PAM authorizes this exact `(action_verb,
    /// resource, run_id)` at `now` **and** consume one use. Refuses a scope/binding/expiry mismatch
    /// or an exhausted mandate. On success the use-count is incremented (so a single-use PAM cannot
    /// fire twice). This is checked *in addition to* the three OBO layers, never instead of them.
    pub fn authorize(
        &mut self,
        pam: &PaymentAdjacentMandate,
        action_verb: &str,
        resource: &str,
        run_id: &str,
        now: u64,
    ) -> Result<(), PamError> {
        pam.verify(action_verb, resource, run_id, now)?;
        let consumed = self.used.get(&pam.id).copied().unwrap_or(0);
        if consumed >= pam.max_uses {
            return Err(PamError::Exhausted {
                max_uses: pam.max_uses,
            });
        }
        self.used.insert(pam.id.clone(), consumed + 1);
        Ok(())
    }
}

/// The three on-behalf-of (OBO) layers the Policy Engine evaluates for *every* action (TOOLING
/// §1.6): the acting identity must be authenticated, the delegated authority must cover the action,
/// and RBAC/authz must permit it. For a payment-*adjacent* write these are evaluated by
/// `ainxt-identity`'s delegation/authz core; this crate models their *outcome* as three booleans so
/// the fourth-gate composition below stays pure and does not couple `ainxt-payments` to
/// `ainxt-identity` (acyclic deps).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OboOutcome {
    /// Layer 1 — the acting agent identity is authenticated / non-revoked.
    pub identity_ok: bool,
    /// Layer 2 — the delegation chain grants authority for this action.
    pub delegation_ok: bool,
    /// Layer 3 — RBAC/authz permits it.
    pub authz_ok: bool,
}

impl OboOutcome {
    /// All three OBO layers passed.
    pub fn all_pass(&self) -> bool {
        self.identity_ok && self.delegation_ok && self.authz_ok
    }
}

/// Why a payment-adjacent dispatch was refused by the composed four-gate check (§6). A PAM is a
/// *fourth* gate, **never a substitute** for the first three — so an OBO-layer failure denies even
/// with a perfectly valid PAM, and a valid OBO still requires the PAM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdjacentDispatchDenied {
    /// One or more of the three OBO layers failed (the PAM is not even consulted — a PAM can only
    /// *add* a constraint, never override the OBO gates).
    Obo(OboOutcome),
    /// The three OBO layers passed but the PAM did not authorize the action (scope / binding /
    /// expiry / exhaustion).
    Pam(PamError),
}

impl fmt::Display for AdjacentDispatchDenied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdjacentDispatchDenied::Obo(o) => write!(
                f,
                "OBO gate failed before the PAM gate (identity_ok={}, delegation_ok={}, authz_ok={})",
                o.identity_ok, o.delegation_ok, o.authz_ok
            ),
            AdjacentDispatchDenied::Pam(e) => write!(f, "PAM (fourth) gate failed: {e}"),
        }
    }
}

impl std::error::Error for AdjacentDispatchDenied {}

/// Authorize a payment-**adjacent** write at dispatch as the **fourth gate on top of OBO** (§6). This
/// is the exact ordering the design mandates: the three OBO layers are checked *first*; only if they
/// all pass is the PAM verified-and-consumed. Consequently:
/// * an OBO failure denies with [`AdjacentDispatchDenied::Obo`] and **does not consume a PAM use**
///   (a valid single-use PAM is not burned by a failed OBO — no self-DoS);
/// * an OBO pass with a bad/expired/exhausted PAM denies with [`AdjacentDispatchDenied::Pam`];
/// * only the conjunction of all four authorizes the action.
///
/// The PAM can never *rescue* a failed OBO gate — it is additive-only, discharging §6's
/// "a fourth gate, never a substitute for the first three".
pub fn authorize_adjacent_dispatch(
    reg: &mut MandateRegistry,
    obo: OboOutcome,
    pam: &PaymentAdjacentMandate,
    action_verb: &str,
    resource: &str,
    run_id: &str,
    now: u64,
) -> Result<(), AdjacentDispatchDenied> {
    if !obo.all_pass() {
        return Err(AdjacentDispatchDenied::Obo(obo));
    }
    reg.authorize(pam, action_verb, resource, run_id, now)
        .map_err(AdjacentDispatchDenied::Pam)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req() -> PamRequest {
        PamRequest::single_use(
            "settlement:simulate",
            "netting-batch:B-42",
            "run-analyst-1",
            100,
        )
    }

    // ---- IDN-04: human-issued, scoped, expiring, single-use --------------
    #[test]
    fn gap_idn_04_pam_is_human_issued_only() {
        // An agent (no can_approve) cannot sign a PAM.
        assert_eq!(
            PaymentAdjacentMandate::issue("m1", &req(), "run-agent", 2, false, 1).unwrap_err(),
            PamError::SignerCannotApprove
        );
        // A too-junior human cannot sign.
        assert_eq!(
            PaymentAdjacentMandate::issue("m1", &req(), "u-junior", 5, true, 1).unwrap_err(),
            PamError::SignerTooJunior {
                ad_level: 5,
                max: 3
            }
        );
        // A senior human approver can.
        let pam = PaymentAdjacentMandate::issue("m1", &req(), "u-exec", 2, true, 1).unwrap();
        assert_eq!(pam.signer_id, "u-exec");
        assert_eq!(pam.action_verb, "settlement:simulate");
        assert_eq!(pam.max_uses, 1);
    }

    #[test]
    fn gap_idn_04_pam_cannot_spell_value_movement() {
        // The PAM struct has NO amount/payee/settlement-instruction field (structural — see the
        // type). Belt-and-suspenders: even the action VERB cannot be a value-movement verb.
        for verb in [
            "settlement:commit",
            "payment:initiate",
            "value:move",
            "MANDATE:SIGN",
        ] {
            let r = PamRequest::single_use(verb, "batch:B", "run-1", 100);
            assert_eq!(
                PaymentAdjacentMandate::issue("m", &r, "u-exec", 1, true, 1).unwrap_err(),
                PamError::ValueMovementNotRepresentable(verb.to_string())
            );
        }
    }

    #[test]
    fn gap_idn_04_pam_is_single_use_and_scoped_and_bound() {
        let pam = PaymentAdjacentMandate::issue("m1", &req(), "u-exec", 2, true, 1).unwrap();
        let mut reg = MandateRegistry::new();

        // Wrong action / resource / run are all refused.
        assert!(matches!(
            reg.authorize(
                &pam,
                "settlement:release",
                "netting-batch:B-42",
                "run-analyst-1",
                5
            ),
            Err(PamError::WrongAction { .. })
        ));
        assert!(matches!(
            reg.authorize(
                &pam,
                "settlement:simulate",
                "netting-batch:OTHER",
                "run-analyst-1",
                5
            ),
            Err(PamError::WrongResource { .. })
        ));
        assert!(matches!(
            reg.authorize(
                &pam,
                "settlement:simulate",
                "netting-batch:B-42",
                "run-IMPOSTOR",
                5
            ),
            Err(PamError::NotBoundToRun { .. })
        ));
        // None of the refused attempts consumed a use.
        assert_eq!(reg.uses_consumed("m1"), 0);

        // The correct, in-scope, in-window, bound use succeeds — once.
        assert!(reg
            .authorize(
                &pam,
                "settlement:simulate",
                "netting-batch:B-42",
                "run-analyst-1",
                5
            )
            .is_ok());
        assert_eq!(reg.uses_consumed("m1"), 1);
        // A second use of a single-use PAM is refused (no replay).
        assert_eq!(
            reg.authorize(
                &pam,
                "settlement:simulate",
                "netting-batch:B-42",
                "run-analyst-1",
                6
            )
            .unwrap_err(),
            PamError::Exhausted { max_uses: 1 }
        );
    }

    #[test]
    fn gap_idn_04_pam_expires() {
        let pam = PaymentAdjacentMandate::issue("m1", &req(), "u-exec", 2, true, 1).unwrap();
        let mut reg = MandateRegistry::new();
        // Valid at/through not_after (100), expired after.
        assert!(pam
            .verify(
                "settlement:simulate",
                "netting-batch:B-42",
                "run-analyst-1",
                100
            )
            .is_ok());
        assert_eq!(
            reg.authorize(
                &pam,
                "settlement:simulate",
                "netting-batch:B-42",
                "run-analyst-1",
                101
            )
            .unwrap_err(),
            PamError::Expired {
                not_after: 100,
                now: 101
            }
        );
        // An expired-at-issuance request is refused up-front.
        let past = PamRequest::single_use("settlement:simulate", "b", "run-1", 5);
        assert!(matches!(
            PaymentAdjacentMandate::issue("m2", &past, "u-exec", 2, true, 10),
            Err(PamError::AlreadyExpired { .. })
        ));
    }

    #[test]
    fn gap_idn_04_small_n_uses_allowed() {
        let mut r = req();
        r.max_uses = 3;
        let pam = PaymentAdjacentMandate::issue("m1", &r, "u-exec", 2, true, 1).unwrap();
        let mut reg = MandateRegistry::new();
        for _ in 0..3 {
            assert!(reg
                .authorize(
                    &pam,
                    "settlement:simulate",
                    "netting-batch:B-42",
                    "run-analyst-1",
                    5
                )
                .is_ok());
        }
        assert!(matches!(
            reg.authorize(
                &pam,
                "settlement:simulate",
                "netting-batch:B-42",
                "run-analyst-1",
                5
            ),
            Err(PamError::Exhausted { max_uses: 3 })
        ));
    }
}
