// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! OBO authorization **decisions** — the bridge from the delegation-chain grant *algebra* (crate
//! root: [`DelegationChain`], [`effective_scope`](DelegationChain::effective_scope),
//! [`can`](DelegationChain::can)) to a per-action **allow/deny** an authz path consumes and the
//! Event Log records.
//!
//! Design: `docs/architecture/AGENT_IDENTITY_AND_PAYMENT_BOUNDARY.md` — ADR-022 §12/§15 (the OBO
//! delegation facet), ADR-003 (the per-turn authz seam that evaluates the AWC), Pass-5 gap **[AI]**
//! (confused-deputy / on-behalf-of authz).
//!
//! # The gap this closes
//!
//! The delegation algebra was fully implemented and tested but was **not usable in a live authz
//! decision**: nothing bound an issued [`AgentWorkloadCredential`] (the per-Run identity) to a
//! [`DelegationChain`] (the grant it acts under), and nothing turned "may this actor do capability
//! X now?" into a structured, auditable decision. [`RunAuthorization`] is that entrypoint: the
//! runtime holds one per Run and calls [`authorize`](RunAuthorization::authorize) before every
//! capability-bearing dispatch. Every decision is derived from the *real* chain (`verify` +
//! `effective_scope`) — a widening/expired/broken chain, a reserved payment verb anywhere in it, or
//! a capability outside the narrowed effective scope each **deny**, with the reason named.

use crate::authority::AgentWorkloadCredential;
use crate::{Actor, AgentId, Capability, Delegation, DelegationChain, LogicalTime, VerifyError};
use ainxt_types::Principal;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Why an OBO authorization was denied. Distinguishes a *structurally invalid grant* (the whole
/// chain does not verify — widening, expiry, broken link, cycle, or a reserved payment-initiation
/// verb, each carrying its offending hop) from a *valid grant that simply does not confer the
/// requested capability* (the capability is outside the chain's narrowed effective scope).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "denial", rename_all = "snake_case")]
pub enum AuthzDenial {
    /// The delegation chain does not verify at `now`; it holds no authority to authorize anything.
    ChainInvalid(VerifyError),
    /// The chain is valid but the requested capability is not in its effective (intersected) scope.
    OutsideEffectiveScope { capability: Capability },
}

impl fmt::Display for AuthzDenial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthzDenial::ChainInvalid(e) => write!(f, "delegation chain invalid: {e}"),
            AuthzDenial::OutsideEffectiveScope { capability } => {
                write!(
                    f,
                    "capability {capability} is outside the chain's effective scope"
                )
            }
        }
    }
}

/// The result of authorizing one action under an OBO chain — the object the authz path branches on
/// and the Event Log records. Serializable so a non-Rust auditor can read the decision + reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum AuthzDecision {
    /// The capability is authorized under a fully-valid, non-widened, unexpired chain.
    Allow { capability: Capability },
    /// The capability is denied; [`AuthzDenial`] carries the exact reason.
    Deny(AuthzDenial),
}

impl AuthzDecision {
    /// True iff the action is authorized.
    pub fn is_allowed(&self) -> bool {
        matches!(self, AuthzDecision::Allow { .. })
    }
    /// The denial reason, if denied.
    pub fn denial(&self) -> Option<&AuthzDenial> {
        match self {
            AuthzDecision::Deny(d) => Some(d),
            AuthzDecision::Allow { .. } => None,
        }
    }
}

impl fmt::Display for AuthzDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthzDecision::Allow { capability } => write!(f, "allow {capability}"),
            AuthzDecision::Deny(d) => write!(f, "deny ({d})"),
        }
    }
}

/// The per-Run OBO authorization context (ADR-022 §12/§15, ADR-003). Binds the delegation chain the
/// Run acts under to a stable `actor_label` (the AWC's composite actor of record, §14) so every
/// [`authorize`](RunAuthorization::authorize) decision is attributable. The runtime constructs one
/// of these per Run — typically via [`root_from_principal`](RunAuthorization::root_from_principal),
/// which roots the chain at the authenticated human and the per-Run agent identity — and consults it
/// before every capability-bearing dispatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunAuthorization {
    chain: DelegationChain,
    actor_label: String,
}

impl RunAuthorization {
    /// Wrap an already-built delegation chain with the actor label to attribute decisions to.
    pub fn new(chain: DelegationChain, actor_label: impl Into<String>) -> Self {
        RunAuthorization {
            chain,
            actor_label: actor_label.into(),
        }
    }

    /// The clean entrypoint the runtime calls to turn *who authenticated* (the JWT [`Principal`])
    /// plus *which Run was minted* (the issued [`AgentWorkloadCredential`]) into a verifiable OBO
    /// chain usable in an authz decision. The human is the accountable root; the AWC's per-Run
    /// agent identity is the delegate; the principal's own capabilities are the widest scope the
    /// agent may ever hold (it can only narrow from here); the grant is valid through `not_after`.
    ///
    /// If the principal itself carries a reserved payment-initiation verb, the produced chain fails
    /// [`verify`](DelegationChain::verify) as `ReservedCapability` — so [`authorize`] denies
    /// **everything**, fail-closed, rather than smuggling value-movement authority to an agent.
    pub fn root_from_principal(
        principal: &Principal,
        awc: &AgentWorkloadCredential,
        not_after: LogicalTime,
    ) -> Self {
        let human = Actor::from_principal(principal);
        let agent = Actor::agent(AgentId::new(
            format!("{}/{}@{}", awc.def_kind, awc.def_id, awc.def_version),
            awc.run_id.clone(),
        ));
        let granted: std::collections::BTreeSet<Capability> = principal
            .caps
            .iter()
            .map(|c| Capability::new(c.clone()))
            .collect();
        let chain = DelegationChain::new(vec![Delegation {
            delegator: human,
            delegate: agent,
            scope: granted,
            not_after,
        }]);
        RunAuthorization {
            chain,
            actor_label: awc.actor_label(),
        }
    }

    /// The delegation chain this Run acts under (for further sub-delegation via
    /// [`DelegationChain::delegate_to`], or for audit).
    pub fn chain(&self) -> &DelegationChain {
        &self.chain
    }

    /// The actor of record decisions are attributed to (§14).
    pub fn actor_label(&self) -> &str {
        &self.actor_label
    }

    /// Authorize one action under the OBO chain at `now` — the live authz decision. Allows **iff**
    /// the chain verifies (root-human, connected, narrowing, unexpired, no reserved payment verb)
    /// **and** the capability is in the narrowed effective scope; otherwise a named [`AuthzDenial`].
    pub fn authorize(&self, capability: &Capability, now: LogicalTime) -> AuthzDecision {
        match self.chain.verify(now) {
            Err(e) => AuthzDecision::Deny(AuthzDenial::ChainInvalid(e)),
            Ok(()) => {
                if self.chain.effective_scope().contains(capability) {
                    AuthzDecision::Allow {
                        capability: capability.clone(),
                    }
                } else {
                    AuthzDecision::Deny(AuthzDenial::OutsideEffectiveScope {
                        capability: capability.clone(),
                    })
                }
            }
        }
    }

    /// [`authorize`](RunAuthorization::authorize) with a `&str` capability — an ergonomic wrapper.
    pub fn authorize_str(&self, capability: &str, now: LogicalTime) -> AuthzDecision {
        self.authorize(&Capability::from(capability), now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::{
        AttestationQuote, ControlPlaneProjection, IdentityAuthority, IssueRequest,
        ReferenceValueVerifier,
    };
    use ainxt_types::DataClass;

    // Mint a REAL AWC through the REAL AIA gate, exactly as the runtime does at run start.
    fn issued_awc(caps_user: &Principal) -> AgentWorkloadCredential {
        let verifier = ReferenceValueVerifier::new().with_measurement("m-coder-ok");
        let projection =
            ControlPlaneProjection::new(["def:role/coder@v3".to_string()], LogicalTime(0), "c1");
        let mut aia = IdentityAuthority::new(verifier, projection, 100, 1000, "key-v1");
        let req = IssueRequest {
            def_kind: "role".into(),
            def_id: "coder".into(),
            def_version: "v3".into(),
            run_id: "run-authz-1".into(),
            data_class: DataClass::Internal,
            requires_tee: false,
            obo_user_id: caps_user.user_id.clone(),
            obo_department: None,
            obo_ad_level: None,
            obo_can_approve: false,
        };
        let quote = AttestationQuote {
            def_content_hash: "h".into(),
            control_commit_sha: "c1".into(),
            measurement: "m-coder-ok".into(),
            tee_quote: None,
        };
        aia.issue(&req, &quote, LogicalTime(1)).unwrap()
    }

    // R3: the OBO chain is usable in a live authz decision on the REAL objects (Principal + AWC +
    // DelegationChain), and the decision fail-closes on an expired chain and a reserved payment verb.
    #[test]
    fn r3_obo_authz_decision_on_real_run_identity() {
        // A human authenticated with {repo:read, repo:write}; a Run was minted for them.
        let principal = Principal::user("u-alice", &["repo:read", "repo:write"]);
        let awc = issued_awc(&principal);

        // The runtime turns Principal + AWC into an OBO authz context valid through t=50.
        let authz = RunAuthorization::root_from_principal(&principal, &awc, LogicalTime(50));
        // The chain roots at the human and delegates to the per-Run agent identity.
        assert!(authz.chain().root().unwrap().is_human());
        assert_eq!(
            authz.chain().leaf().unwrap().label(),
            "ainxt-id://ainxt/agent/role/coder@v3/run/run-authz-1"
        );
        assert!(authz.actor_label().contains("run/run-authz-1"));

        // A granted capability is ALLOWED within the window.
        let d = authz.authorize_str("repo:read", LogicalTime(10));
        assert!(d.is_allowed(), "granted cap authorized: {d}");
        assert_eq!(
            d,
            AuthzDecision::Allow {
                capability: Capability::from("repo:read")
            }
        );

        // A never-granted capability is DENIED as outside the effective scope (not a bare bool).
        let d = authz.authorize_str("repo:delete", LogicalTime(10));
        assert_eq!(
            d,
            AuthzDecision::Deny(AuthzDenial::OutsideEffectiveScope {
                capability: Capability::from("repo:delete")
            })
        );

        // Past the window the chain is expired -> EVERY capability is denied (chain invalid).
        let d = authz.authorize_str("repo:read", LogicalTime(51));
        assert!(matches!(
            d,
            AuthzDecision::Deny(AuthzDenial::ChainInvalid(VerifyError::Expired { .. }))
        ));

        // A sub-delegation NARROWS: the agent hands only {repo:read} to a sub-agent; the decision
        // engine over the extended chain denies the dropped capability but allows the retained one.
        let sub = crate::AgentId::new("role/tester@v2", "run-authz-2");
        let extended = authz
            .chain()
            .delegate_to(
                Actor::agent(sub),
                &crate::scope(vec!["repo:read"]),
                LogicalTime(40),
                LogicalTime(10),
            )
            .expect("narrowing sub-delegation");
        let sub_authz = RunAuthorization::new(extended, "sub-actor");
        assert!(sub_authz
            .authorize_str("repo:read", LogicalTime(10))
            .is_allowed());
        assert!(!sub_authz
            .authorize_str("repo:write", LogicalTime(10))
            .is_allowed());

        // Fail-closed: if the principal itself carries a reserved payment verb, the OBO chain is
        // structurally invalid and authorizes NOTHING (confused-deputy closed at the grant layer).
        let tainted = Principal::user("u-bob", &["repo:read", "payment:initiate"]);
        let awc2 = {
            let mut a = awc.clone();
            a.run_id = "run-authz-3".into();
            a.obo_user_id = "u-bob".into();
            a
        };
        let bad = RunAuthorization::root_from_principal(&tainted, &awc2, LogicalTime(50));
        assert!(matches!(
            bad.authorize_str("repo:read", LogicalTime(10)),
            AuthzDecision::Deny(AuthzDenial::ChainInvalid(
                VerifyError::ReservedCapability { .. }
            ))
        ));
    }
}
