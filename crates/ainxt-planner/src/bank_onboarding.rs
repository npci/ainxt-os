// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-AUDIT data-surfaces-artifacts (bank-onboarding program has no substrate):
//! `STRUCTURED_FEDERATED_RETRIEVAL.md` §6.5 names "onboarding a new bank into the federated network"
//! as a concrete instance of the generic Long-Horizon Program Supervisor (ADR-027) — "a Program, not
//! a Run" — riding "the same Long-Horizon Program Supervisor" every other multi-step migration uses.
//! Before this module, that was a single doc paragraph: no [`crate::program::NodeDecl`] topology, no
//! `ainxt-workforce` Role, no `ainxt-scenario` matrix entry, no data model existed anywhere in code —
//! the generic engine ([`crate::program`], [`crate::driver`], [`crate::supervisor`]) had zero
//! bank-specific instantiation to actually run.
//!
//! This is that substrate: the concrete node topology a deployment onboarding a bank into the
//! federated retrieval network (`ainxt_retrieval::federation`) and the multimodal artifact routing
//! tier (`ainxt_context::artifact`) actually needs — built from the SAME generic
//! [`crate::program::NodeDecl`]/[`crate::driver::drive_program_verified`] engine every other Program
//! uses, never a bespoke onboarding-only state machine.

use crate::program::{CheckpointClass, NodeClass, NodeDecl};

/// The three ordered modules `STRUCTURED_FEDERATED_RETRIEVAL.md` §6.5 names for onboarding `bank_id`
/// into the federated network, each an ADR-027 §3 [`NodeClass::Integration`] node (connecting this
/// program's environment to an external system — exactly what onboarding a bank is):
///
/// 1. **KYC data-class registration** — the new bank's KYC records must be classified
///    ([`ainxt_types::DataClass`]) before anything else touches them; `ainxt_context::artifact`'s
///    regulated-data routing rule (never resolve a regulated artifact to a cloud model) depends on
///    this classification existing first.
/// 2. **Federated-broker credential issuance** — depends on (1): the credential
///    `ainxt_retrieval::federation`'s whitelist + per-tenant isolation checks will authenticate is
///    never issued before the bank's data is classified (issuing credentials for an unclassified
///    bank would let its data cross the federation boundary with no data-class gate yet in place).
/// 3. **Member-bank connectivity check** — depends on (2): the live fan-out probe (a real
///    [`ainxt_retrieval::federation::BankTenant`] round trip in a live deployment) never runs against
///    a bank that does not yet hold valid federation credentials.
///
/// Both compliance/security-sensitive nodes are tagged [`CheckpointClass::CriticalPath`] (ADR-027 §8:
/// a forced human commit gate regardless of score) — KYC classification and credential issuance are
/// exactly the "settlement/ledger/compliance-tagged" steps that checkpoint class exists for. The
/// connectivity check is a read-only probe with no such gate.
pub fn bank_onboarding_program(bank_id: &str) -> Vec<NodeDecl> {
    let kyc = format!("{bank_id}-kyc-data-class-registration");
    let cred = format!("{bank_id}-federated-broker-credential-issuance");
    let conn = format!("{bank_id}-member-bank-connectivity-check");

    vec![
        NodeDecl::new(kyc.clone(), NodeClass::Integration)
            .checkpoint(CheckpointClass::CriticalPath)
            .with_verification(format!("kyc-data-class-registered:{bank_id}")),
        NodeDecl::new(cred.clone(), NodeClass::Integration)
            .depends_on(kyc)
            .checkpoint(CheckpointClass::CriticalPath)
            .with_verification(format!("federated-broker-credential-issued:{bank_id}")),
        NodeDecl::new(conn.clone(), NodeClass::Integration)
            .depends_on(cred)
            .checkpoint(CheckpointClass::None)
            .with_verification(format!("member-bank-connectivity-verified:{bank_id}")),
    ]
}

/// The node id for `bank_onboarding_program`'s KYC registration step, for callers that need to refer
/// to a specific node (e.g. a caller inspecting [`crate::program::ProgramState::schedulable_nodes`]).
pub fn kyc_node_id(bank_id: &str) -> crate::program::NodeId {
    crate::program::NodeId::new(format!("{bank_id}-kyc-data-class-registration"))
}

/// The node id for `bank_onboarding_program`'s credential-issuance step.
pub fn credential_node_id(bank_id: &str) -> crate::program::NodeId {
    crate::program::NodeId::new(format!("{bank_id}-federated-broker-credential-issuance"))
}

/// The node id for `bank_onboarding_program`'s connectivity-check step.
pub fn connectivity_node_id(bank_id: &str) -> crate::program::NodeId {
    crate::program::NodeId::new(format!("{bank_id}-member-bank-connectivity-check"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::NodeState;

    #[test]
    fn bank_onboarding_program_has_the_three_documented_modules_in_dependency_order() {
        let nodes = bank_onboarding_program("newbank");
        assert_eq!(nodes.len(), 3);

        let kyc = &nodes[0];
        let cred = &nodes[1];
        let conn = &nodes[2];

        assert_eq!(kyc.id, kyc_node_id("newbank"));
        assert!(
            kyc.deps.is_empty(),
            "KYC registration is the entry point: no dependencies"
        );
        assert_eq!(kyc.checkpoint_class, CheckpointClass::CriticalPath);

        assert_eq!(cred.id, credential_node_id("newbank"));
        assert!(
            cred.deps.contains(&kyc_node_id("newbank")),
            "credential issuance must depend on KYC classification landing FIRST"
        );
        assert_eq!(cred.checkpoint_class, CheckpointClass::CriticalPath);

        assert_eq!(conn.id, connectivity_node_id("newbank"));
        assert!(
            conn.deps.contains(&credential_node_id("newbank")),
            "the connectivity probe must depend on credentials being issued FIRST"
        );
        assert_eq!(
            conn.checkpoint_class,
            CheckpointClass::None,
            "a read-only probe has no human gate"
        );

        // Every node is Integration (ADR-027 §3: connecting this program's environment to an
        // external system) — never a code-migration class, which would misrepresent what these
        // steps actually do.
        for n in &nodes {
            assert_eq!(n.node_class, NodeClass::Integration);
        }
    }

    #[test]
    fn bank_onboarding_program_initially_schedules_only_kyc_registration() {
        // Project the topology through the REAL generic engine's event log (Created + Decomposed),
        // exactly how every other Program's node set becomes a live ProgramState — never a bespoke
        // reading of the Vec<NodeDecl>.
        let events = vec![
            crate::program::ProgramEvent::Created {
                program_id: crate::program::ProgramId::new("bank-onboard-newbank"),
                goal: "Onboard newbank into the federated retrieval network".into(),
            },
            crate::program::ProgramEvent::Decomposed {
                nodes: bank_onboarding_program("newbank"),
            },
        ];
        let state =
            crate::program::project(&events).expect("a fresh decomposition always projects");

        // Only the dependency-free KYC node is Ready; credential issuance and the connectivity check
        // are NOT schedulable until their dependency chain commits.
        assert_eq!(state.schedulable_nodes(), vec![kyc_node_id("newbank")]);
        assert_eq!(
            state
                .nodes
                .get(&credential_node_id("newbank"))
                .map(|n| n.state),
            Some(NodeState::Pending),
            "credential issuance must not be schedulable before KYC registration commits"
        );
    }
}
