// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Context-Fabric read integration (design §7). Memory has **no separate retrieval code path** — it
//! is *layer 12 of the Context Fabric*, read by the same Context Optimizer that reads the
//! symbol/call/architecture/docs graphs, with the same pre-rank RBAC/data-class discipline. This
//! module provides the two pieces §7 requires, as clean public entrypoints, so the reserved runtime
//! crate wires memory into the turn pipeline **without re-implementing retrieval**:
//!
//! 1. **Query planning by task** ([`plan_query`], design §7.1): a code-gen turn on a repo pulls
//!    `CodingConvention` + `ApprovedLibrary` + `SecurityRule` scoped to that repo; an incident
//!    triage pulls `IncidentPostmortem` + `CommonFix` by error signature; casual chat pulls only
//!    per-user personalization. The Optimizer never guesses which memory sub-types matter.
//! 2. **Per-turn lineage** ([`TurnLineage`], design §7.4/§7.5): [`InMemoryStore::read_for_turn`]
//!    captures the exact `(id, version)` of every injected item so a turn can be *forensically
//!    replayed* — resolving those ids to their versioned content **as of that turn**, even after the
//!    items have since been edited/superseded — via [`InMemoryStore::resolve`](crate::store::InMemoryStore::resolve).
//!    It also marks each injected item *used* (usage-based decay, design §6).

use std::collections::BTreeSet;

use crate::{
    AccessScope, InMemoryStore, MemoryHit, MemoryKind, MemoryQuery, OrgKnowledgeType, Scope,
};

/// The task class the current turn is performing — the input to query planning (design §7.1). Own
/// vocabulary, not a provider's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskKind {
    /// Writing/modifying code for a repo in a language — needs conventions, approved libraries, and
    /// security rules for that repo.
    CodeGen {
        /// Target language (informational; scoping is by repo).
        language: String,
        /// The repository being worked on.
        repo: String,
    },
    /// Diagnosing a failure — needs postmortems and common fixes keyed by error signature.
    IncidentTriage {
        /// The normalized error signature to match.
        error_signature: String,
    },
    /// Ordinary conversation — needs only per-user personalization, never org rules.
    CasualChat,
}

/// A query plan: the ordered set of memory queries whose union the Optimizer should retrieve for a
/// turn. Each query still passes the store's pre-rank RBAC/data-class/identity-scope filter.
#[derive(Debug, Clone)]
pub struct MemoryPlan {
    /// The queries to run (in planning order).
    pub queries: Vec<MemoryQuery>,
}

/// Plan which memory sub-types to retrieve for `task` (design §7.1). Pure and deterministic.
pub fn plan_query(task: &TaskKind) -> MemoryPlan {
    let queries = match task {
        TaskKind::CodeGen { repo, .. } => {
            let scope = Scope::Repo(repo.clone());
            vec![
                MemoryQuery::default()
                    .with_org_type(OrgKnowledgeType::SecurityRule)
                    .with_scope(scope.clone())
                    .by_precedence(),
                MemoryQuery::default()
                    .with_org_type(OrgKnowledgeType::CodingConvention)
                    .with_scope(scope.clone()),
                MemoryQuery::default()
                    .with_org_type(OrgKnowledgeType::ApprovedLibrary)
                    .with_scope(scope),
            ]
        }
        TaskKind::IncidentTriage { error_signature } => {
            let kw: Vec<&str> = vec![error_signature.as_str()];
            vec![
                MemoryQuery::keywords(&kw).with_org_type(OrgKnowledgeType::IncidentPostmortem),
                MemoryQuery::keywords(&kw).with_org_type(OrgKnowledgeType::CommonFix),
            ]
        }
        TaskKind::CasualChat => {
            vec![MemoryQuery::default().with_kind(MemoryKind::UserPreference)]
        }
    };
    MemoryPlan { queries }
}

/// A per-turn memory lineage record (design §7.4/§7.5): the exact `(id, version)` of every memory
/// item injected into a turn, captured alongside the turn's prompt/model snapshot so the turn is
/// forensically replayable.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TurnLineage {
    /// The turn this lineage belongs to (Event-Log turn id).
    pub turn_id: String,
    /// `(item_id, version)` of each injected memory item, in injection order.
    pub injected: Vec<(String, u32)>,
}

impl TurnLineage {
    /// The `(id, version)` refs, ready for [`InMemoryStore::resolve`](crate::store::InMemoryStore::resolve).
    pub fn refs(&self) -> Vec<(String, u32)> {
        self.injected.clone()
    }
}

impl InMemoryStore {
    /// Read memory for a turn the Context-Fabric way (design §7): plan by `task`, run each planned
    /// query under the caller's [`AccessScope`] (pre-rank filtered), de-duplicate by id keeping the
    /// first (highest-planning-priority) hit, mark each returned item *used* at `now` (usage-based
    /// decay, §6), and return the hits together with a [`TurnLineage`] capturing `(id, version)` for
    /// forensic replay. `per_query_limit == 0` means unlimited per planned query.
    pub fn read_for_turn(
        &mut self,
        turn_id: &str,
        task: &TaskKind,
        access: &AccessScope,
        now: u64,
        per_query_limit: usize,
    ) -> (Vec<MemoryHit>, TurnLineage) {
        let plan = plan_query(task);
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut hits: Vec<MemoryHit> = Vec::new();
        for mut q in plan.queries {
            if per_query_limit > 0 {
                q.limit = per_query_limit;
            }
            // Audited read path (design §5): if the caller is an admin exercising break-glass over
            // another user's personal memory, the access is recorded — break-glass is provably
            // audited on *every* read path, including turn-time Context-Fabric injection.
            for h in self.query_audited(&q, access) {
                if seen.insert(h.item.id.clone()) {
                    hits.push(h);
                }
            }
        }
        let injected: Vec<(String, u32)> = hits
            .iter()
            .map(|h| (h.item.id.clone(), h.item.version))
            .collect();
        // Usage-based decay: an injected item was just used this turn.
        for (id, _) in &injected {
            self.touch(id, now);
        }
        (
            hits,
            TurnLineage {
                turn_id: turn_id.to_string(),
                injected,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Enforcement, MemoryItem, MemoryStore, OrgPayload, Principal, Provenance, Severity,
        CAP_APPROVE,
    };
    use ainxt_types::Role;

    fn approver() -> Principal {
        Principal::user("owner", &[CAP_APPROVE])
    }

    fn write_promoted(store: &mut InMemoryStore, item: MemoryItem) {
        let id = item.id.clone();
        store.write(item).unwrap();
        store.promote(&id, &approver()).unwrap();
    }

    #[test]
    fn gap_ainxt_memory_mem_04_context_fabric_planning_and_turn_lineage() {
        let mut store = InMemoryStore::new();
        let repo = Scope::Repo("payments-core".into());

        write_promoted(
            &mut store,
            MemoryItem::org(
                "conv",
                repo.clone(),
                "rust error handling",
                OrgPayload::CodingConvention {
                    rule: "use thiserror".into(),
                    language: "rust".into(),
                    example_do: "?".into(),
                    example_dont: "unwrap".into(),
                    enforcement: Enforcement::Advisory,
                },
                Provenance::ingest(1.0),
            ),
        );
        write_promoted(
            &mut store,
            MemoryItem::org(
                "lib",
                repo.clone(),
                "http client",
                OrgPayload::ApprovedLibrary {
                    name: "reqwest".into(),
                    version_range: ">=0.12".into(),
                    language: "rust".into(),
                    reason: "audited".into(),
                    disallowed_alternatives: vec![],
                    security_review_ref: None,
                },
                Provenance::ingest(1.0),
            ),
        );
        write_promoted(
            &mut store,
            MemoryItem::org(
                "sec",
                repo.clone(),
                "no plaintext secrets",
                OrgPayload::SecurityRule {
                    rule: "never log secrets".into(),
                    applicable_action: "log".into(),
                    applicable_data_class: crate::DataClass::Confidential,
                    severity: Severity::High,
                    enforcement: Enforcement::Blocking,
                    exception_process: None,
                },
                Provenance::ingest(1.0),
            ),
        );
        // An incident postmortem that must NOT surface for a code-gen turn.
        write_promoted(
            &mut store,
            MemoryItem::org(
                "pm",
                repo.clone(),
                "outage",
                OrgPayload::IncidentPostmortem {
                    incident_id: "INC-1".into(),
                    timeline: "t".into(),
                    root_cause: "npe".into(),
                    blast_radius: "b".into(),
                    error_signatures: vec![],
                    remediation: "r".into(),
                    owner: "o".into(),
                },
                Provenance::ingest(1.0),
            ),
        );
        // A per-user preference (personalization) for the casual-chat plan + lineage replay.
        store
            .write(MemoryItem::new(
                "pref",
                MemoryKind::UserPreference,
                Scope::User("alice".into()),
                "verbosity",
                "prefers terse",
                Provenance::human("alice", 1.0),
            ))
            .unwrap();

        let access = AccessScope::from_principal(Principal::user("alice", &[]))
            .with_repos(&["payments-core"]);

        // Query planning: a code-gen turn pulls conventions/libraries/security for the repo — not
        // the postmortem, and not the personal preference.
        let (hits, lineage) = store.read_for_turn(
            "turn-code",
            &TaskKind::CodeGen {
                language: "rust".into(),
                repo: "payments-core".into(),
            },
            &access,
            100,
            0,
        );
        let ids: BTreeSet<&str> = hits.iter().map(|h| h.item.id.as_str()).collect();
        assert!(ids.contains("conv") && ids.contains("lib") && ids.contains("sec"));
        assert!(
            !ids.contains("pm"),
            "postmortem must not surface for code-gen"
        );
        assert!(
            !ids.contains("pref"),
            "personalization must not surface for code-gen"
        );
        assert!(!lineage.injected.is_empty());

        // Incident-triage planning pulls the postmortem (by keyword), not the code conventions.
        let (inc_hits, _) = store.read_for_turn(
            "turn-inc",
            &TaskKind::IncidentTriage {
                error_signature: "npe".into(),
            },
            &access,
            101,
            0,
        );
        let inc_ids: BTreeSet<&str> = inc_hits.iter().map(|h| h.item.id.as_str()).collect();
        assert!(inc_ids.contains("pm"));
        assert!(!inc_ids.contains("conv"));

        // Per-turn lineage + forensic replay: a casual-chat turn injects the preference; capture its
        // (id, version), then EDIT the preference (new version), and prove the turn replays to the
        // exact content injected — not the current, since-edited state (design §7.5).
        let (chat_hits, chat_lineage) =
            store.read_for_turn("turn-chat", &TaskKind::CasualChat, &access, 102, 0);
        assert_eq!(chat_hits.len(), 1);
        assert_eq!(chat_hits[0].item.id, "pref");
        // Edit the preference.
        store
            .write(MemoryItem::new(
                "pref",
                MemoryKind::UserPreference,
                Scope::User("alice".into()),
                "verbosity",
                "prefers verbose now",
                Provenance::human("alice", 1.0),
            ))
            .unwrap();
        assert_eq!(store.get_unchecked("pref").unwrap().version, 2);
        // Replay the turn from its lineage → the ORIGINAL v1 content, not the current v2.
        let replayed = store.resolve(&chat_lineage.refs());
        assert_eq!(replayed.len(), 1);
        let snap = replayed[0].as_ref().unwrap();
        assert_eq!(snap.version, 1);
        assert_eq!(snap.body, "prefers terse");
    }

    #[test]
    fn gap_ainxt_memory_mem_04_planning_respects_identity_scope() {
        // A caller NOT a member of the repo gets nothing from a code-gen plan (pre-rank identity
        // filter still applies through the planned queries — planning is not a scope bypass).
        let mut store = InMemoryStore::new();
        write_promoted(
            &mut store,
            MemoryItem::org(
                "lib",
                Scope::Repo("secret-repo".into()),
                "http",
                OrgPayload::ApprovedLibrary {
                    name: "reqwest".into(),
                    version_range: ">=1".into(),
                    language: "rust".into(),
                    reason: "audited".into(),
                    disallowed_alternatives: vec![],
                    security_review_ref: None,
                },
                Provenance::ingest(1.0),
            ),
        );
        let outsider = AccessScope::from_principal(Principal::user("nobody", &[]));
        let (hits, lineage) = store.read_for_turn(
            "t",
            &TaskKind::CodeGen {
                language: "rust".into(),
                repo: "secret-repo".into(),
            },
            &outsider,
            1,
            0,
        );
        assert!(hits.is_empty());
        assert!(lineage.injected.is_empty());
        // Admins are members of every scope (an admin planner would see it).
        let _ = Role::Admin;
    }
}
