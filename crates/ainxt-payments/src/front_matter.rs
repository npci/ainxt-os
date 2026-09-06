// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! The git-native `payment_boundary` front-matter policy core (ADR-016 §7 / ADR-026 §5) — Layer 4,
//! the *authoring* enforcement of the payment boundary.
//!
//! Design: `docs/architecture/AGENT_IDENTITY_AND_PAYMENT_BOUNDARY.md` §7 (and ADR-026 §5/§8).
//!
//! # What this module is
//!
//! The **pure decision core** the CI check and the pre-receive hook call to enforce the
//! `payment_boundary` front-matter field on a control-plane definition:
//!
//! * [`PaymentBoundaryClass::parse`] — accepts only `none` and `payment-adjacent`; the reserved
//!   value `payment-initiating` is **rejected** ([`FrontMatterError::ReservedValue`]) so a
//!   definition that even *claims* to initiate payment cannot merge (§7).
//! * [`authorize_authoring`] — a `payment-adjacent` definition requires the **payments-council
//!   CODEOWNERS** group *and* an `ad_level <= 3` signed commit (ADR-026 §5/§8); `none` is
//!   unrestricted. This is the authoring catch that sits orthogonally *above* the runtime execution
//!   denial (RBAC-on-author vs RBAC-on-execute, ADR-026 §8).
//!
//! # What this is NOT (the seam)
//!
//! This is not the CI runner, the git pre-receive hook, or the CODEOWNERS file parser — those live
//! in `ainxt-governance` / the CI control plane and call this core. This crate owns the payment-
//! domain *policy* so "what may be authored" is a versioned, testable artifact here, not logic
//! scattered across a CI script. See IDN-07 needs-wiring for the exact integration point.

use serde::{Deserialize, Serialize};
use std::fmt;

/// The permitted values of the `payment_boundary` front-matter field on a control-plane definition
/// (ADR-026 §5). `payment-initiating` is deliberately **not** a variant — it is unrepresentable in
/// the accepted schema (only recognised by [`PaymentBoundaryClass::parse`] in order to *reject* it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PaymentBoundaryClass {
    /// The default: the definition does not touch the payment perimeter at all.
    None,
    /// The definition touches payment systems but moves no value (§2 payment-adjacent). Requires
    /// council authorship authority (§7).
    PaymentAdjacent,
}

impl PaymentBoundaryClass {
    /// The string form written in front-matter.
    pub fn as_str(self) -> &'static str {
        match self {
            PaymentBoundaryClass::None => "none",
            PaymentBoundaryClass::PaymentAdjacent => "payment-adjacent",
        }
    }

    /// Parse a front-matter value (§7 / ADR-026 §5). `none`/`payment-adjacent` parse; the reserved
    /// `payment-initiating` is **rejected** so it can never merge; anything else is unknown. The
    /// missing/empty case defaults to [`PaymentBoundaryClass::None`] (the safe default).
    pub fn parse(raw: &str) -> Result<Self, FrontMatterError> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "" | "none" => Ok(PaymentBoundaryClass::None),
            "payment-adjacent" => Ok(PaymentBoundaryClass::PaymentAdjacent),
            "payment-initiating" => Err(FrontMatterError::ReservedValue(raw.trim().to_string())),
            other => Err(FrontMatterError::UnknownValue(other.to_string())),
        }
    }
}

/// Why a `payment_boundary` front-matter value or its authoring was rejected (§7). Fail-closed: CI
/// and the pre-receive hook block the merge on any of these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrontMatterError {
    /// The reserved `payment-initiating` value — cannot be authored at all (§7).
    ReservedValue(String),
    /// An unrecognised value (typo / unsupported).
    UnknownValue(String),
    /// A `payment-adjacent` definition was not reviewed by the payments-council CODEOWNERS (§7).
    MissingPaymentsCouncilApproval,
    /// The signing committer is not senior enough (`ad_level > 3`) to author a payment-class def.
    InsufficientAuthorAuthority { ad_level: u8, max: u8 },
    /// The commit authorizing a payment-class def was not signed / lacked `can_approve`.
    UnsignedOrUnauthorizedCommit,
}

impl fmt::Display for FrontMatterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrontMatterError::ReservedValue(v) => write!(
                f,
                "payment_boundary {v:?} is reserved and rejected; only none/payment-adjacent may merge"
            ),
            FrontMatterError::UnknownValue(v) => {
                write!(f, "unknown payment_boundary value {v:?}")
            }
            FrontMatterError::MissingPaymentsCouncilApproval => write!(
                f,
                "a payment-adjacent definition requires payments-council CODEOWNERS approval"
            ),
            FrontMatterError::InsufficientAuthorAuthority { ad_level, max } => write!(
                f,
                "author ad_level {ad_level} exceeds required <= {max} for a payment-class definition"
            ),
            FrontMatterError::UnsignedOrUnauthorizedCommit => write!(
                f,
                "a payment-class definition requires a signed, can_approve commit"
            ),
        }
    }
}

impl std::error::Error for FrontMatterError {}

/// The maximum author AD seniority level permitted to author a payment-class definition (§7 /
/// ADR-026 §5): `ad_level <= 3`.
pub const PAYMENT_AUTHOR_MAX_AD_LEVEL: u8 = 3;

/// The evidence a CI check / pre-receive hook presents about the commit authoring a definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthoringContext {
    /// Whether the change was approved by the payments-council CODEOWNERS group.
    pub payments_council_approved: bool,
    /// Whether the commit is cryptographically signed.
    pub commit_signed: bool,
    /// The author's `can_approve` claim.
    pub author_can_approve: bool,
    /// The author's AD seniority level (lower = more senior).
    pub author_ad_level: u8,
}

/// Authorize *authoring* a definition with the given `payment_boundary` class (§7 / ADR-026 §5/§8):
/// `None` is unrestricted; `PaymentAdjacent` requires payments-council CODEOWNERS **and** a signed
/// `ad_level <= 3` `can_approve` commit. This is the Layer-4 authoring catch that sits above the
/// runtime execution denial — a def can be git-approved `payment-adjacent` and *still* be denied a
/// specific value-moving dispatch at runtime.
pub fn authorize_authoring(
    class: PaymentBoundaryClass,
    ctx: &AuthoringContext,
) -> Result<(), FrontMatterError> {
    match class {
        PaymentBoundaryClass::None => Ok(()),
        PaymentBoundaryClass::PaymentAdjacent => {
            if !ctx.payments_council_approved {
                return Err(FrontMatterError::MissingPaymentsCouncilApproval);
            }
            if !ctx.commit_signed || !ctx.author_can_approve {
                return Err(FrontMatterError::UnsignedOrUnauthorizedCommit);
            }
            if ctx.author_ad_level > PAYMENT_AUTHOR_MAX_AD_LEVEL {
                return Err(FrontMatterError::InsufficientAuthorAuthority {
                    ad_level: ctx.author_ad_level,
                    max: PAYMENT_AUTHOR_MAX_AD_LEVEL,
                });
            }
            Ok(())
        }
    }
}

/// The single **Layer-4 authoring-enforcement decision** a CI check / git pre-receive hook calls on
/// every changed control-plane definition (§7 / ADR-026 §5/§8): parse the raw `payment_boundary`
/// front-matter value **and** authorize its authoring in one fail-closed step. Returns the accepted
/// [`PaymentBoundaryClass`] a merge is allowed to carry, or the [`FrontMatterError`] the hook blocks
/// on. This is the clean entrypoint that turns the two pure predicates ([`PaymentBoundaryClass::parse`]
/// [`authorize_authoring`]) into the one call the CI runner / pre-receive hook makes — so the
/// enforcement is a single versioned, testable artifact, never logic re-implemented per CI script.
///
/// Order matters and is fail-closed: the reserved/unknown value is rejected *before* any authority
/// is consulted (a `payment-initiating` claim can never merge regardless of who signed it), then a
/// `payment-adjacent` class is gated on payments-council CODEOWNERS + a signed `ad_level<=3`
/// `can_approve` commit. A `none` class merges with no extra authority (the common case).
pub fn enforce(
    raw: &str,
    ctx: &AuthoringContext,
) -> Result<PaymentBoundaryClass, FrontMatterError> {
    let class = PaymentBoundaryClass::parse(raw)?;
    authorize_authoring(class, ctx)?;
    Ok(class)
}

// ===========================================================================
// Pre-receive / CI changeset gate — Layer 4 (ADR-016 §4 / ADR-026 §5)
// ===========================================================================

/// One changed control-plane definition in a push, as the CI check / git pre-receive hook sees it:
/// the repo path (for the block message), the raw `payment_boundary` front-matter value, and the
/// authoring evidence for the commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangedDefinition {
    pub path: String,
    pub raw_payment_boundary: String,
    pub authoring: AuthoringContext,
}

/// A single definition the pre-receive gate blocked, with the reason (§4 Layer 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockedDefinition {
    pub path: String,
    pub error: FrontMatterError,
}

impl fmt::Display for BlockedDefinition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path, self.error)
    }
}

/// The **Layer-4 pre-receive / CI decision over a whole push** (§4 / ADR-026 §5): run [`enforce`] on
/// every changed control-plane definition and, git-style, **reject the entire push if ANY definition
/// fails** — a `payment-initiating` (or otherwise unauthorized payment-class) definition cannot merge,
/// and cannot be smuggled in alongside good changes. This is the single call the git `pre-receive`
/// hook and the CI job both make so the boundary is enforced identically at both gates from one
/// versioned artifact.
///
/// Returns `Ok(())` iff every definition is authorable; otherwise `Err(blocked)` naming every
/// offending definition (all of them, so an author fixes the push in one pass rather than one reject
/// at a time). Fail-closed: an empty changeset trivially passes; any error blocks the whole push.
///
/// The seam is the git transport itself (the `pre-receive` hook process and the CI runner) — that is
/// infra this crate cannot host; this is the pure decision those hooks call, so "what may merge" is a
/// tested policy artifact, not logic re-implemented in a shell script per gate.
pub fn evaluate_changeset(changes: &[ChangedDefinition]) -> Result<(), Vec<BlockedDefinition>> {
    let blocked: Vec<BlockedDefinition> = changes
        .iter()
        .filter_map(|c| {
            enforce(&c.raw_payment_boundary, &c.authoring)
                .err()
                .map(|error| BlockedDefinition {
                    path: c.path.clone(),
                    error,
                })
        })
        .collect();
    if blocked.is_empty() {
        Ok(())
    } else {
        Err(blocked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- IDN-07: payment-initiating is a rejected reserved value ---------
    #[test]
    fn gap_idn_07_reserved_payment_initiating_cannot_merge() {
        assert_eq!(
            PaymentBoundaryClass::parse("payment-initiating").unwrap_err(),
            FrontMatterError::ReservedValue("payment-initiating".to_string())
        );
        // Case/space-insensitive so it cannot be smuggled past CI.
        assert!(matches!(
            PaymentBoundaryClass::parse("  Payment-Initiating "),
            Err(FrontMatterError::ReservedValue(_))
        ));
        // The two permitted values parse; empty/missing defaults to None.
        assert_eq!(
            PaymentBoundaryClass::parse("none").unwrap(),
            PaymentBoundaryClass::None
        );
        assert_eq!(
            PaymentBoundaryClass::parse("").unwrap(),
            PaymentBoundaryClass::None
        );
        assert_eq!(
            PaymentBoundaryClass::parse("payment-adjacent").unwrap(),
            PaymentBoundaryClass::PaymentAdjacent
        );
        // A typo is an unknown value, also rejected.
        assert!(matches!(
            PaymentBoundaryClass::parse("payment-adjcent"),
            Err(FrontMatterError::UnknownValue(_))
        ));
    }

    #[test]
    fn gap_idn_07_payment_adjacent_requires_council_and_ad_level_3() {
        let full = AuthoringContext {
            payments_council_approved: true,
            commit_signed: true,
            author_can_approve: true,
            author_ad_level: 3,
        };
        // Fully-authorized adjacent authoring passes.
        assert!(authorize_authoring(PaymentBoundaryClass::PaymentAdjacent, &full).is_ok());

        // Missing council approval is rejected.
        let no_council = AuthoringContext {
            payments_council_approved: false,
            ..full.clone()
        };
        assert_eq!(
            authorize_authoring(PaymentBoundaryClass::PaymentAdjacent, &no_council).unwrap_err(),
            FrontMatterError::MissingPaymentsCouncilApproval
        );
        // Unsigned or non-approver commit is rejected.
        let unsigned = AuthoringContext {
            commit_signed: false,
            ..full.clone()
        };
        assert_eq!(
            authorize_authoring(PaymentBoundaryClass::PaymentAdjacent, &unsigned).unwrap_err(),
            FrontMatterError::UnsignedOrUnauthorizedCommit
        );
        // Too-junior author is rejected.
        let junior = AuthoringContext {
            author_ad_level: 4,
            ..full.clone()
        };
        assert_eq!(
            authorize_authoring(PaymentBoundaryClass::PaymentAdjacent, &junior).unwrap_err(),
            FrontMatterError::InsufficientAuthorAuthority {
                ad_level: 4,
                max: 3
            }
        );
    }

    #[test]
    fn gap_idn_07_none_class_is_unrestricted() {
        // A `none` definition needs no council / seniority — the common case is unimpeded.
        let bare = AuthoringContext {
            payments_council_approved: false,
            commit_signed: false,
            author_can_approve: false,
            author_ad_level: 6,
        };
        assert!(authorize_authoring(PaymentBoundaryClass::None, &bare).is_ok());
    }
}
