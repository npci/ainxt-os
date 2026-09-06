// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-4 gap closure: **row-level-security row-filter contract on the retrieval query**.
//!
//! Exercised on the REAL production query object ([`ainxt_retrieval::Corpus::hybrid_rls`]) exactly
//! as the live serving path calls it: a SET LOCAL-style predicate bound from the OBO principal is
//! applied in the SAME pre-rank pass as the class/node ACL, so a row the caller may not read is
//! never scored, fused, reranked, or counted (existence never leaks). Fail-closed on a missing
//! binding or a row missing the referenced attribute.
//!
//! Fails to COMPILE before the closure (`Corpus::hybrid_rls`, `rls::RowFilter`, `Chunk::with_attribute`
//! did not exist); passes after — fail-before / pass-after on the real object. RLS is a read-filter,
//! not an admission gate: it shapes which rows a turn may read, never whether the turn proceeds.

use ainxt_retrieval::rls::{RlsSession, RowFilter};
use ainxt_retrieval::{Chunk, Corpus, LexicalReranker};
use ainxt_types::{DataClass, Principal};

fn corpus() -> Corpus {
    Corpus::new(vec![
        // Same class + same lexical content; only the row-security department attribute differs.
        Chunk::new(
            "mine",
            "settlement failure postmortem detail",
            DataClass::Internal,
        )
        .with_attribute("department", "settlement-eng"),
        Chunk::new(
            "theirs",
            "settlement failure postmortem detail",
            DataClass::Internal,
        )
        .with_attribute("department", "hr"),
        // A same-department row carrying NO department attribute — must fail-close (be denied).
        Chunk::new(
            "unlabeled",
            "settlement failure postmortem detail",
            DataClass::Internal,
        ),
    ])
}

#[test]
fn r4_rls_row_filter() {
    let corpus = corpus();
    // The caller is in settlement-eng and cleared for Internal (so the class ACL admits all three).
    let principal = Principal::user("analyst", &[]).with_department("settlement-eng");
    let filter = RowFilter::department_isolation(&principal);

    let hits = corpus.hybrid_rls(
        "settlement failure postmortem",
        None,
        &principal,
        &filter,
        10,
        &LexicalReranker,
    );
    let ids: Vec<&str> = hits.iter().map(|c| c.id.as_str()).collect();

    // Only the caller's own department's row survives the pre-rank RLS filter.
    assert!(
        ids.contains(&"mine"),
        "the caller's own-department row must be retrievable"
    );
    assert!(
        !ids.contains(&"theirs"),
        "a cross-department row must never be scored/returned (pre-rank RLS, existence never leaks)"
    );
    assert!(
        !ids.contains(&"unlabeled"),
        "fail-closed: a row lacking the referenced attribute is denied, never permitted by omission"
    );

    // Fail-closed on a missing binding: a principal with no department reads NOTHING even though
    // the class ACL would admit every row.
    let no_dept = Principal::user("nobody", &[]).with_department("");
    let no_dept = Principal {
        department: None,
        ..no_dept
    };
    let no_dept_filter = RowFilter::department_isolation(&no_dept);
    let none = corpus.hybrid_rls(
        "settlement failure postmortem",
        None,
        &no_dept,
        &no_dept_filter,
        10,
        &LexicalReranker,
    );
    assert!(
        none.is_empty(),
        "an unbound department setting must fail-close the whole query (no cross-dept leak)"
    );

    // RLS is strictly ADDITIONAL to the class/node ACL, never a way to widen it: with an empty
    // filter (RLS disabled) the class ACL alone still governs, and a below-clearance query returns
    // all three rows — proving the filter narrows, it does not admit.
    let open = RowFilter::new(RlsSession::bind(&principal));
    assert!(open.is_empty());
    let all = corpus.hybrid_rls(
        "settlement failure postmortem",
        None,
        &principal,
        &open,
        10,
        &LexicalReranker,
    );
    assert_eq!(
        all.len(),
        3,
        "an empty RLS filter reduces to the plain hybrid query"
    );

    // A custom bound setting (tenant isolation) works the same way, proving the contract is general
    // SET LOCAL-style binding, not a hardcoded department special-case.
    let tenant_corpus = Corpus::new(vec![
        Chunk::new("acme-doc", "settlement report", DataClass::Public)
            .with_attribute("tenant", "acme"),
        Chunk::new("globex-doc", "settlement report", DataClass::Public)
            .with_attribute("tenant", "globex"),
    ]);
    let tenant_filter =
        RowFilter::new(RlsSession::new().set("tenant", "acme")).require("tenant", "tenant");
    let tenant_hits = tenant_corpus.hybrid_rls(
        "settlement report",
        None,
        &principal,
        &tenant_filter,
        10,
        &LexicalReranker,
    );
    let tids: Vec<&str> = tenant_hits.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(
        tids,
        vec!["acme-doc"],
        "custom bound setting isolates the caller's tenant only"
    );
}
