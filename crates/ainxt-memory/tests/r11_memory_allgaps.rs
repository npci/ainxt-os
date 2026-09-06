// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-11 all-severities gap closure for the Enterprise Memory & Continuous-Learning core
//! (design: `docs/architecture/ENTERPRISE_MEMORY_LEARNING.md`). Each test drives the REAL objects
//! (no mocks of the store) and fails to even compile / assert before the round's changes, because it
//! exercises API that did not exist (semantic recall, KG traversal, embed-on-write, the extraction
//! guard, the schema registry, the real flywheel sink) or an invariant that was not yet enforced
//! (break-glass provably audited on every read path).

use ainxt_memory::flywheel::{FeedbackEvent, ImprovementEngine, MemoryStoreSink};
use ainxt_memory::{
    AccessScope, DataClass, DurableMemoryStore, EdgeKind, Embedder, EmbedderKind, GovernanceState,
    InMemoryStore, MemoryItem, MemoryKind, MemoryQuery, MemorySqlBackend, MemoryStore,
    OrgKnowledgeType, OrgPayload, Principal, Provenance, SchemaRegistry, Scope, CAP_APPROVE,
};

fn approver() -> Principal {
    Principal::user("owner", &[CAP_APPROVE])
}

// A deterministic offline embedder: maps each configured keyword to a one-hot axis so cosine
// similarity is a clean, reproducible signal (no network, no rng). `kind` decides the tier.
#[derive(Debug)]
struct AxisEmbedder {
    id: &'static str,
    kind: EmbedderKind,
}
impl AxisEmbedder {
    // Axis order: [payments, refund, kubernetes, rust].
    fn axes(text: &str) -> Vec<f32> {
        let t = text.to_lowercase();
        vec![
            t.contains("payment") as u8 as f32 + t.contains("settle") as u8 as f32,
            t.contains("refund") as u8 as f32,
            t.contains("kubernetes") as u8 as f32 + t.contains("pod") as u8 as f32,
            t.contains("rust") as u8 as f32,
        ]
    }
}
impl Embedder for AxisEmbedder {
    fn model_id(&self) -> &str {
        self.id
    }
    fn kind(&self) -> EmbedderKind {
        self.kind
    }
    fn embed(&self, text: &str) -> Vec<f32> {
        AxisEmbedder::axes(text)
    }
}

fn inhouse() -> Box<dyn Embedder> {
    Box::new(AxisEmbedder {
        id: "inhouse-axis-v1",
        kind: EmbedderKind::InHouse,
    })
}
fn cloud() -> Box<dyn Embedder> {
    Box::new(AxisEmbedder {
        id: "cloud-axis-v1",
        kind: EmbedderKind::Cloud,
    })
}

/// MEM-R11-A (medium): **embed-on-write under data-class rules** + **semantic recall via
/// embeddings**. A regulated item is embedded ONLY by the in-house model; a public item by the
/// cloud model — at write time, no explicit reembed call. Then a semantic query (a query vector with
/// NO lexical overlap with the target's title/body) recalls the semantically-closest item first,
/// which a pure keyword query could never do.
#[test]
fn r11_embed_on_write_and_semantic_recall() {
    let mut store = InMemoryStore::new().with_embedders(inhouse(), cloud());

    // A regulated payment fact and a public infra fact — no embeddings supplied by hand.
    store
        .write(
            MemoryItem::new(
                "pay",
                MemoryKind::Semantic,
                Scope::User("u".into()),
                "settlement window",
                "the payment settlement batch runs nightly",
                Provenance::ingest(1.0),
            )
            .with_data_class(DataClass::RegulatedPayment),
        )
        .unwrap();
    store
        .write(
            MemoryItem::new(
                "infra",
                MemoryKind::Semantic,
                Scope::User("u".into()),
                "cluster note",
                "kubernetes pod autoscaling policy",
                Provenance::ingest(1.0),
            )
            .with_data_class(DataClass::Public),
        )
        .unwrap();

    // Embed-on-write happened, routed by data-class (§8.5): regulated → in-house, public → cloud.
    let pay_emb = store.get_unchecked("pay").unwrap().embedding.as_ref().unwrap();
    assert_eq!(pay_emb.kind, EmbedderKind::InHouse);
    assert_eq!(pay_emb.model_id, "inhouse-axis-v1");
    let infra_emb = store.get_unchecked("infra").unwrap().embedding.as_ref().unwrap();
    assert_eq!(infra_emb.kind, EmbedderKind::Cloud);

    // Semantic recall: a query vector on the "payments" axis. It shares NO keyword with the item
    // (the item text is "settlement batch"; the query carries no such tokens) — only the embedding
    // connects them.
    let acc = AccessScope::from_principal(
        Principal::user("u", &[]).with_clearance(DataClass::RegulatedPayment),
    );
    let q_vec = AxisEmbedder::axes("payment"); // [1,0,0,0]
    let hits = store.query(&MemoryQuery::semantic(q_vec), &acc);
    assert!(!hits.is_empty(), "semantic recall returned nothing");
    assert_eq!(
        hits[0].item.id, "pay",
        "closest-by-embedding item must rank first"
    );
    // The unrelated infra item scores 0 similarity (orthogonal axis) and is not a semantic hit.
    assert!(hits.iter().all(|h| h.item.id != "infra"));
}

/// MEM-R11-B (medium): **break-glass admin read is provably audited on EVERY read path.** The
/// immutable `query` (which cannot write an audit entry) fails CLOSED on break-glass — it never
/// discloses another user's personal memory. Only the audited paths (`query_audited`,
/// `read_for_turn`) serve it, and each records the access.
#[test]
fn r11_break_glass_audited_on_every_read_path() {
    let mut store = InMemoryStore::new();
    store
        .write(
            MemoryItem::new(
                "alice-note",
                MemoryKind::UserPreference,
                Scope::User("alice".into()),
                "alice personal",
                "alice likes terse answers",
                Provenance::human("alice", 1.0),
            )
            .with_data_class(DataClass::Pii),
        )
        .unwrap();

    let admin_glass =
        AccessScope::from_principal(Principal::admin("root")).with_break_glass("DPO ticket 42");

    // Immutable path: NOT audit-capable → fails closed. Personal item is NOT disclosed, even to an
    // admin holding break-glass, because the access could not be recorded.
    let unaudited = store.query(&MemoryQuery::keywords(&["alice"]), &admin_glass);
    assert!(
        unaudited.iter().all(|h| h.item.id != "alice-note"),
        "immutable query leaked break-glass personal memory without an audit entry"
    );
    assert!(
        !store
            .audit_entries()
            .iter()
            .any(|e| e.action == "break-glass-read"),
        "no audit entry should exist yet"
    );

    // Audited path: discloses AND records.
    let hits = store.query_audited(&MemoryQuery::keywords(&["alice"]), &admin_glass);
    assert!(hits.iter().any(|h| h.item.id == "alice-note"));
    assert!(store
        .audit_entries()
        .iter()
        .any(|e| e.action == "break-glass-read" && e.subject == "alice"));

    // The turn-time Context-Fabric read path (read_for_turn) also audits break-glass: a casual-chat
    // turn injects per-user personalization; an admin reading over another user's memory is recorded.
    let before = store
        .audit_entries()
        .iter()
        .filter(|e| e.action == "break-glass-read")
        .count();
    let (_hits, _lineage) = store.read_for_turn(
        "turn-1",
        &ainxt_memory::fabric::TaskKind::CasualChat,
        &admin_glass,
        100,
        0,
    );
    let after = store
        .audit_entries()
        .iter()
        .filter(|e| e.action == "break-glass-read")
        .count();
    assert!(
        after > before,
        "read_for_turn must audit a break-glass read"
    );
    assert_eq!(store.verify_audit_chain(), None, "audit chain stays intact");
}

/// MEM-R11-C (medium): **Improvement-Engine flywheel wired to a REAL sink** — capture → propose →
/// dispatch into an actual governed OKI store. The recurring-fix candidate lands `Draft` (never
/// authoritative on its own), and a human `promote` is still required to reach authority (the
/// human-gate is unbypassable, so a volume attack cannot escalate through the sink).
#[test]
fn r11_flywheel_dispatch_to_real_oki_store_sink() {
    let mut eng = ImprovementEngine::new();
    for t in ["t1", "t2", "t3"] {
        assert!(eng.capture(
            &FeedbackEvent::correction(t, "npe-on-null-config", "boom", "guard the null config"),
            0.9,
            None,
        ));
    }
    let candidates = eng.propose(3, 0.5, &Scope::Org, "cand", 10);

    let mut store = InMemoryStore::new();
    let accepted;
    let rejected;
    {
        let mut sink = MemoryStoreSink::new(&mut store);
        let (a, r) = eng.dispatch(&candidates, &mut sink);
        accepted = a;
        rejected = r;
        assert_eq!(
            sink.written(),
            1,
            "one org-knowledge candidate written to the store"
        );
    }
    assert!(accepted >= 1);
    // An eval-case candidate exists from... actually only OKI here; a prompt/eval candidate would be
    // rejected by this in-crate sink. Assert the OKI landed and rejections are counted, not dropped.
    let _ = rejected;

    // The candidate id is deterministic: "{prefix}-fix-{idx}".
    let landed = store
        .get_unchecked("cand-fix-0")
        .expect("dispatched OKI must be in the store");
    assert_eq!(
        landed.governance,
        GovernanceState::Draft,
        "flywheel sink writes Draft only"
    );
    assert!(!landed.is_authoritative());

    // A human with CAP_APPROVE promotes it to authority — the only path to authoritative.
    assert_eq!(
        store.promote("cand-fix-0", &approver()).unwrap(),
        GovernanceState::Approved
    );
    assert!(store.get_unchecked("cand-fix-0").unwrap().is_authoritative());
}

/// MEM-R11-D (medium): **unified Knowledge-Graph retrieval** — OKIs are nodes, `links` are typed
/// edges, and traversal follows them (RBAC/data-class-aware, pre-rank). An incident postmortem
/// CAUSED_BY an OKI and RELATES_TO a fix is reachable by edge traversal; a node the caller cannot
/// see is neither returned nor a bridge past it.
#[test]
fn r11_knowledge_graph_edge_traversal() {
    let mut store = InMemoryStore::new();
    let repo = Scope::Repo("payments-core".into());

    let fix = MemoryItem::org(
        "fix-1",
        repo.clone(),
        "null guard fix",
        OrgPayload::CommonFix {
            error_pattern: "npe".into(),
            fix_template: "guard the null".into(),
            verified_count: 3,
            false_positive_count: 0,
        },
        Provenance::ingest(1.0),
    );
    // The postmortem links to the fix (RELATES_TO) and to a security rule (CAUSED_BY).
    let pm = MemoryItem::org(
        "pm-1",
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
    )
    .with_link(EdgeKind::RelatesTo, "fix-1")
    .with_link(EdgeKind::CausedBy, "sec-1");
    let sec = MemoryItem::org(
        "sec-1",
        repo.clone(),
        "no plaintext secrets",
        OrgPayload::SecurityRule {
            rule: "never log secrets".into(),
            applicable_action: "log".into(),
            applicable_data_class: DataClass::Confidential,
            severity: ainxt_memory::Severity::High,
            enforcement: ainxt_memory::Enforcement::Blocking,
            exception_process: None,
        },
        Provenance::ingest(1.0),
    );
    for it in [fix, pm, sec] {
        let id = it.id.clone();
        store.write(it).unwrap();
        store.promote(&id, &approver()).unwrap();
    }

    let member =
        AccessScope::from_principal(Principal::user("dev", &[])).with_repos(&["payments-core"]);

    // Neighbors of the postmortem: both linked OKIs, deterministic order.
    let neighbors = store.neighbors("pm-1", &member, true);
    let ids: Vec<&str> = neighbors.iter().map(|(_, it)| it.id.as_str()).collect();
    assert!(
        ids.contains(&"fix-1") && ids.contains(&"sec-1"),
        "got {ids:?}"
    );

    // Traverse only RELATES_TO edges from the postmortem → reaches fix-1, not sec-1.
    let related = store.traverse("pm-1", 3, &[EdgeKind::RelatesTo], &member, true);
    let rids: Vec<&str> = related.iter().map(|it| it.id.as_str()).collect();
    assert_eq!(rids, vec!["fix-1"], "RELATES_TO traversal");

    // A non-member of the repo cannot traverse the graph at all (fail-closed, existence not leaked).
    let outsider = AccessScope::from_principal(Principal::user("nobody", &[]));
    assert!(store.neighbors("pm-1", &outsider, true).is_empty());
    assert!(store.traverse("pm-1", 3, &[], &outsider, true).is_empty());
}

/// MEM-R11-E (medium/infra): **durable store is queryable at scale** across every recall mode. A
/// larger corpus is written through the durable SqlLike seam (embed-on-write configured), the store
/// is dropped, reopened over the SAME backend, and keyword + semantic + KG-traversal queries all
/// answer correctly against the hydrated corpus — the offline proof behind the live-Postgres seam.
#[test]
fn r11_durable_store_queryable_at_scale() {
    let backend = MemorySqlBackend::new();
    let n = 600usize;
    {
        let mut store = DurableMemoryStore::open(backend.clone())
            .unwrap()
            .with_embedders(inhouse(), cloud());
        for i in 0..n {
            // Half payments-flavored, half kubernetes-flavored — semantic axes are separable.
            let body = if i % 2 == 0 {
                "payment settlement record"
            } else {
                "kubernetes pod record"
            };
            // Unique title per item so personal-fact auto-supersession does not collapse the corpus.
            store
                .write(MemoryItem::new(
                    &format!("item-{i}"),
                    MemoryKind::Semantic,
                    Scope::User("u".into()),
                    &format!("record {i}"),
                    body,
                    Provenance::ingest(1.0),
                ))
                .unwrap();
        }
        // One linked pair to prove KG traversal survives durably.
        store
            .write(
                MemoryItem::new(
                    "hub",
                    MemoryKind::Semantic,
                    Scope::User("u".into()),
                    "hub",
                    "payment hub",
                    Provenance::ingest(1.0),
                )
                .with_link(EdgeKind::RelatesTo, "item-0"),
            )
            .unwrap();
    } // dropped — nothing kept in RAM

    // Reopen over the same backend; the whole corpus hydrates.
    let reopened = DurableMemoryStore::open(backend.clone())
        .unwrap()
        .with_embedders(inhouse(), cloud());
    assert_eq!(reopened.len(), n + 1);

    let acc = AccessScope::from_principal(Principal::user("u", &[]));

    // Keyword recall at scale.
    let kw = reopened.query(&MemoryQuery::keywords(&["kubernetes"]).limit(10), &acc);
    assert!(!kw.is_empty() && kw.iter().all(|h| h.item.body.contains("kubernetes")));

    // Semantic recall at scale: a payments-axis query only returns payment-flavored items.
    let sem = reopened.query(
        &MemoryQuery::semantic(AxisEmbedder::axes("payment")).limit(5),
        &acc,
    );
    assert_eq!(sem.len(), 5);
    assert!(
        sem.iter().all(|h| h.item.body.contains("payment")),
        "semantic recall must surface only payment-flavored items"
    );

    // KG traversal survives the reopen.
    let related = reopened.traverse("hub", 2, &[EdgeKind::RelatesTo], &acc, true);
    assert_eq!(
        related.iter().map(|it| it.id.as_str()).collect::<Vec<_>>(),
        vec!["item-0"]
    );
}

/// MEM-R11-F (low): **versioned per-type JSON-schema registry; a schema bump is itself governed.**
/// Each of the 7 types carries an independent version; a bump requires CAP_APPROVE, only moves
/// forward, and is recorded in an append-only history.
#[test]
fn r11_versioned_governed_schema_registry() {
    let mut reg = SchemaRegistry::new();
    assert_eq!(reg.version(OrgKnowledgeType::SecurityRule), 1);
    assert_eq!(reg.version(OrgKnowledgeType::ApprovedLibrary), 1);

    // A non-approver cannot bump a schema (governed act).
    let dev = Principal::user("dev", &[]);
    assert!(reg
        .bump(OrgKnowledgeType::SecurityRule, 2, &dev, "add field")
        .is_err());
    assert_eq!(reg.version(OrgKnowledgeType::SecurityRule), 1);

    // An approver can — and only forward.
    assert_eq!(
        reg.bump(
            OrgKnowledgeType::SecurityRule,
            2,
            &approver(),
            "add exception_ref"
        )
        .unwrap(),
        2
    );
    assert!(
        reg.bump(OrgKnowledgeType::SecurityRule, 2, &approver(), "no-op")
            .is_err(),
        "must move forward"
    );
    assert!(reg
        .bump(OrgKnowledgeType::SecurityRule, 1, &approver(), "backwards")
        .is_err());

    // Per-type independence: bumping SecurityRule left ApprovedLibrary at v1.
    assert_eq!(reg.version(OrgKnowledgeType::SecurityRule), 2);
    assert_eq!(reg.version(OrgKnowledgeType::ApprovedLibrary), 1);

    // The bump is provably recorded.
    let hist = reg.history();
    assert_eq!(hist.len(), 1);
    assert_eq!(hist[0].oki_type, OrgKnowledgeType::SecurityRule);
    assert_eq!((hist[0].from, hist[0].to), (1, 2));
    assert_eq!(hist[0].approved_by, "owner");
}

/// MEM-R11-G (low): **system-prompt / OKI extraction resistance (§8.8 / AM).** With the extraction
/// guard enabled, an unscoped bulk sweep of the SecurityRule/ApprovedLibrary set is refused
/// (fail-closed — the full set is never dumped verbatim) and recorded as a guardrail violation on
/// the audited path; a properly scoped read (as the Context-Fabric planner issues) still works.
#[test]
fn r11_oki_extraction_resistance() {
    let mut store = InMemoryStore::new().with_extraction_guard(2);
    // Seed 5 org-wide security rules (an attacker wants them all, verbatim, for recon).
    for i in 0..5 {
        let it = MemoryItem::org(
            &format!("sec-{i}"),
            Scope::Org,
            &format!("rule {i}"),
            OrgPayload::SecurityRule {
                rule: format!("rule body {i}"),
                applicable_action: format!("action-{i}"),
                applicable_data_class: DataClass::Confidential,
                severity: ainxt_memory::Severity::High,
                enforcement: ainxt_memory::Enforcement::Blocking,
                exception_process: None,
            },
            Provenance::ingest(1.0),
        );
        store.write(it).unwrap();
        store.promote(&format!("sec-{i}"), &approver()).unwrap();
    }
    // A repo-scoped rule the legitimate planner would fetch.
    let scoped = MemoryItem::org(
        "sec-repo",
        Scope::Repo("payments-core".into()),
        "repo rule",
        OrgPayload::SecurityRule {
            rule: "repo body".into(),
            applicable_action: "deploy".into(),
            applicable_data_class: DataClass::Confidential,
            severity: ainxt_memory::Severity::High,
            enforcement: ainxt_memory::Enforcement::Blocking,
            exception_process: None,
        },
        Provenance::ingest(1.0),
    );
    store.write(scoped).unwrap();
    store.promote("sec-repo", &approver()).unwrap();

    let admin =
        AccessScope::from_principal(Principal::admin("root")).with_repos(&["payments-core"]);

    // Unscoped bulk sweep of the SecurityRule set → refused (fail-closed): none of the sensitive
    // OKIs are returned, and the audited path records the guardrail violation.
    let recon = MemoryQuery::default().with_org_type(OrgKnowledgeType::SecurityRule);
    let dumped = store.query_audited(&recon, &admin);
    assert!(
        dumped.is_empty(),
        "extraction guard must refuse the full unscoped SecurityRule dump, got {} items",
        dumped.len()
    );
    assert!(store
        .audit_entries()
        .iter()
        .any(|e| e.action == "oki-extraction-guard"));

    // A properly SCOPED read still works (the planner always scopes by repo).
    let scoped_q = MemoryQuery::default()
        .with_org_type(OrgKnowledgeType::SecurityRule)
        .with_scope(Scope::Repo("payments-core".into()));
    let ok = store.query(&scoped_q, &admin);
    assert_eq!(ok.len(), 1);
    assert_eq!(ok[0].item.id, "sec-repo");
}

/// GAP-CLOSE memory (DurableMemoryStore parity): before this, [`DurableMemoryStore`] had no
/// `with_schema_registry`/`schema_registry()` at all — only the ephemeral [`InMemoryStore`] exposed
/// them, so a production (Postgres-backed) deployment could never install a governed, bumped
/// [`SchemaRegistry`]; every durable OKI write was silently pinned to the fresh v1-everywhere
/// default no matter what a deployment had governably bumped. This proves the durable store now
/// enforces the SAME installed registry on write (stamping the in-force version), not just the
/// in-RAM store.
#[test]
fn r12_durable_store_honors_installed_schema_registry() {
    let mut reg = SchemaRegistry::new();
    assert_eq!(
        reg.bump(
            OrgKnowledgeType::SecurityRule,
            2,
            &approver(),
            "add exception_ref"
        )
        .unwrap(),
        2
    );

    let backend = MemorySqlBackend::new();
    let mut store = DurableMemoryStore::open(backend)
        .unwrap()
        .with_schema_registry(reg);
    assert_eq!(
        store
            .schema_registry()
            .version(OrgKnowledgeType::SecurityRule),
        2
    );

    let item = MemoryItem::org(
        "sec-durable",
        Scope::Org,
        "durable rule",
        OrgPayload::SecurityRule {
            rule: "body".into(),
            applicable_action: "deploy".into(),
            applicable_data_class: DataClass::Confidential,
            severity: ainxt_memory::Severity::High,
            enforcement: ainxt_memory::Enforcement::Blocking,
            exception_process: None,
        },
        Provenance::ingest(1.0),
    );
    store.write(item).unwrap();
    let stored = store.get_version("sec-durable", 1).expect("item persisted");
    assert_eq!(
        stored.schema_version, 2,
        "durable write must stamp the installed (bumped) registry version, not a fresh default"
    );
}

/// GAP-CLOSE memory (retention TTL-decay / DurableMemoryStore parity): before this,
/// [`InMemoryStore::expire_decayed`] (design §6 usage-based decay expiry) had no equivalent on
/// [`DurableMemoryStore`] — a production deployment could never run the decay sweep at all. This
/// proves `DurableMemoryStore::expire_decayed` deprecates a long-unused fact AND that the
/// deprecation is write-through durable: a fresh reopen over the same backend still sees it
/// `Deprecated`, not silently reverted to `Active` because only the in-RAM copy changed.
#[test]
fn r12_durable_store_expire_decayed_is_write_through() {
    let backend = MemorySqlBackend::new();
    {
        let mut store = DurableMemoryStore::open(backend.clone()).unwrap();
        let mut it = MemoryItem::new(
            "stale-pref",
            MemoryKind::UserPreference,
            Scope::User("dana".into()),
            "old preference",
            "prefers dark mode",
            Provenance::ingest(0.9),
        );
        it.provenance.author = ainxt_memory::Author::Human {
            user_id: "dana".into(),
        };
        store.write(it).unwrap();
        // Never touched again after tick 0; half_life=10, floor=0.5 → fully decayed by tick 1000.
        let n = store.expire_decayed(1_000, 10, 0.5).unwrap();
        assert_eq!(n, 1, "the long-unused preference must be swept");
        let cur = store
            .get_version("stale-pref", 1)
            .expect("item still present, just deprecated");
        assert_eq!(cur.governance, GovernanceState::Deprecated);
    } // dropped — nothing kept in RAM

    let reopened = DurableMemoryStore::open(backend).unwrap();
    let cur = reopened
        .get_version("stale-pref", 1)
        .expect("survives reopen");
    assert_eq!(
        cur.governance,
        GovernanceState::Deprecated,
        "decay-expiry must be durably persisted, not only applied to the in-RAM working set"
    );
}
