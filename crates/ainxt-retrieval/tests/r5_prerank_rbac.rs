// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-5 gap closure: **pre-rank node/department/`ad_level`/group RBAC composed with the RLS
//! row-filter** on the REAL production query object ([`ainxt_retrieval::Corpus::hybrid_ctx_rls`]).
//!
//! The served path previously reached retrieval through a bare [`Principal`], which can prove only
//! class clearance + department — so every `ad_level`/group-gated node fail-closed regardless of the
//! caller's real seniority/groups (`CONTEXT_FABRIC.md` §8.3). This exercises the full
//! [`ainxt_retrieval::acl::AccessContext`] carrying the caller's complete OBO claims, in the SAME
//! pre-rank pass as the RLS row-filter, so a node the caller may not see on ANY axis (class,
//! department, seniority, group, or row scope) is never scored, fused, reranked, or counted —
//! existence never leaks.
//!
//! Fails to COMPILE before the closure (`Corpus::hybrid_ctx_rls` did not exist); passes after —
//! fail-before / pass-after on the real object. This is a read-filter, never a turn-admission gate.

use ainxt_retrieval::acl::{AccessContext, NodeAcl};
use ainxt_retrieval::rls::RowFilter;
use ainxt_retrieval::{Chunk, Corpus, LexicalReranker};
use ainxt_types::{DataClass, Principal};

fn corpus() -> Corpus {
    Corpus::new(vec![
        // Owned by settlement-eng, visible at ad_level <= 3, needs the on-call group; row is in the
        // caller's department. A senior on-call settlement engineer may see it.
        Chunk::new(
            "oncall-runbook",
            "settlement failure incident runbook detail",
            DataClass::Internal,
        )
        .with_acl(
            NodeAcl::new()
                .departments(&["settlement-eng"])
                .max_ad_level(3)
                .allow_groups(&["settlement-oncall"]),
        )
        .with_attribute("department", "settlement-eng"),
        // Same content/department but locked to a MORE senior tier (ad_level <= 2). The caller at
        // ad_level 3 must be denied pre-rank — the axis a bare Principal could never even evaluate.
        Chunk::new(
            "exec-only",
            "settlement failure incident runbook detail",
            DataClass::Internal,
        )
        .with_acl(
            NodeAcl::new()
                .departments(&["settlement-eng"])
                .max_ad_level(2),
        )
        .with_attribute("department", "settlement-eng"),
        // Correct class + no node ACL, but the RLS row belongs to another department → row-filter denies.
        Chunk::new(
            "other-dept-row",
            "settlement failure incident runbook detail",
            DataClass::Internal,
        )
        .with_attribute("department", "hr"),
    ])
}

#[test]
fn r5_prerank_rbac() {
    let corpus = corpus();
    // OBO principal → binds the RLS department-isolation session.
    let principal = Principal::user("analyst", &[]).with_department("settlement-eng");
    let row_filter = RowFilter::department_isolation(&principal);

    // Full OBO access claims: Internal clearance, settlement-eng, ad_level 3 (senior enough for
    // the <=3 node but NOT the <=2 node), member of the on-call group.
    let access = AccessContext::new(
        DataClass::Internal,
        Some("settlement-eng"),
        Some(3),
        &["settlement-oncall"],
    );

    let hits = corpus.hybrid_ctx_rls(
        "settlement failure incident runbook",
        None,
        &access,
        &row_filter,
        10,
        &LexicalReranker,
    );
    let ids: Vec<&str> = hits.iter().map(|c| c.id.as_str()).collect();

    assert!(
        ids.contains(&"oncall-runbook"),
        "a caller who satisfies department + ad_level ceiling + allow-group must see the node — \
         claims a bare Principal path could never prove"
    );
    assert!(
        !ids.contains(&"exec-only"),
        "the ad_level<=2 node must be denied PRE-rank for an ad_level-3 caller (existence never leaks)"
    );
    assert!(
        !ids.contains(&"other-dept-row"),
        "RLS composes: a cross-department row is denied in the same pre-rank pass"
    );

    // The seniority axis really gates: bump the caller to a junior tier and the <=3 node vanishes too.
    let junior = AccessContext::new(
        DataClass::Internal,
        Some("settlement-eng"),
        Some(5),
        &["settlement-oncall"],
    );
    let junior_hits = corpus.hybrid_ctx_rls(
        "settlement failure incident runbook",
        None,
        &junior,
        &row_filter,
        10,
        &LexicalReranker,
    );
    assert!(
        junior_hits.iter().all(|c| c.id != "oncall-runbook"),
        "a junior (ad_level 5) is denied the ad_level<=3 node — the RBAC axis is enforced, not ignored"
    );

    // Drop the on-call group and the allow-group axis alone denies the otherwise-permitted node.
    let no_group = AccessContext::new(DataClass::Internal, Some("settlement-eng"), Some(3), &[]);
    let no_group_hits = corpus.hybrid_ctx_rls(
        "settlement failure incident runbook",
        None,
        &no_group,
        &row_filter,
        10,
        &LexicalReranker,
    );
    assert!(
        no_group_hits.iter().all(|c| c.id != "oncall-runbook"),
        "missing the required allow-group denies the node (fail-closed on the group axis)"
    );
}
