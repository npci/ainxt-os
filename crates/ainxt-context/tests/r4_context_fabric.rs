// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-4 context-fabric gap closures, exercised on the REAL public objects the live serving path
//! (`ainxt-chat`/`ainxt-runtimed`) drives.
//!
//! - `r4_numeric_rederive_gate`: the numeric re-derivation gate is reachable on the live
//!   compile/verify path — the SAME `CompiledWindow` that grounded the answer verifies its numbers,
//!   recomputing every sourced figure from source and BLOCKING on a mismatch or an unbacked prose
//!   number (never trust model arithmetic; gap BH). Fails to COMPILE before the closure
//!   (`CompiledWindow::verify_answer`, the `NumericClaim`/`Rederiver` re-exports did not exist).
//! - `r4_compile_rls_composition`: the Context Optimizer composition (plan → cross-graph rank →
//!   freshness → eligible-floor position-aware fit, with full lineage) runs on the `compile_rls`
//!   entrypoint with the OBO principal's RLS row-filter applied PRE-rank, so a row outside the
//!   caller's row scope never enters the window, the citations, OR the lineage (existence never
//!   leaks). Fails to COMPILE before the closure (`compile_rls` / `Retriever::retrieve_scoped` /
//!   `RowFilter` did not exist).
//!
//! Both are fail-before / pass-after on the real objects. RLS and clearance are retrieval
//! read-filters, never turn-admission denials.

use std::collections::BTreeMap;

use ainxt_context::{
    compile, compile_rls, ClaimSource, HybridRetriever, NumericClaim, OptimizerConfig, Rederiver,
    Tolerance, ValueClass,
};
use ainxt_retrieval::rls::{RlsSession, RowFilter};
use ainxt_retrieval::{Chunk as RChunk, Corpus as RCorpus, EligibleModel, WordTokenCounter};
use ainxt_types::{DataClass, Principal};

/// A stub server-side re-executor keyed by the claim's `rederive_key` — models a read-replica
/// query / deterministic tool returning the independently-computed truth (or `None` = cannot
/// reproduce → fail-closed).
struct MapRederiver {
    truth: BTreeMap<String, f64>,
}
impl MapRederiver {
    fn new(pairs: &[(&str, f64)]) -> Self {
        MapRederiver {
            truth: pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
        }
    }
}
impl Rederiver for MapRederiver {
    fn rederive(&self, source: &ClaimSource) -> Option<f64> {
        self.truth.get(&source.rederive_key()?).copied()
    }
}

#[test]
fn r4_numeric_rederive_gate() {
    // A real compiled window over a small grounded corpus.
    let rcorpus = RCorpus::new(vec![RChunk::new(
        "recon",
        "settlement reconciliation produced failed settlements today",
        DataClass::Internal,
    )]);
    let hybrid = HybridRetriever::from_retrieval_corpus(rcorpus);
    let counter = WordTokenCounter;
    let cfg = OptimizerConfig {
        eligible: vec![EligibleModel::new("m", 8000)],
        graph_weight: 0.0,
        ..OptimizerConfig::default()
    };
    let window = compile(
        "failed settlements",
        &hybrid,
        DataClass::Internal,
        &cfg,
        &counter,
        None,
        &BTreeMap::new(),
    );
    assert!(!window.context.is_empty(), "the window grounded the answer");

    // The model's answer states one number, declared as a sourced metric claim.
    let answer = "There were 47 failed settlements.";
    let claims = vec![NumericClaim::metric(
        47.0,
        "count",
        ValueClass::Exact,
        "failed_settlement_count",
        "h1",
    )];

    // Server re-derives the SAME value → the window's verify step ships.
    let good = MapRederiver::new(&[("metric:failed_settlement_count:h1", 47.0)]);
    let ok = window.verify_answer(answer, &claims, &good, &Tolerance::default());
    assert!(ok.ships(), "a re-derived, matching number must ship");
    assert!(!ok.blocked_on_mismatch());

    // Server recomputes a DIFFERENT value → BLOCK, flagged as a mismatch incident. This is the
    // payments-critical case: the model was confidently wrong and the gate caught it.
    let bad = MapRederiver::new(&[("metric:failed_settlement_count:h1", 52.0)]);
    let blocked = window.verify_answer(answer, &claims, &bad, &Tolerance::default());
    assert!(
        !blocked.ships(),
        "a server/model numeric mismatch must block the answer"
    );
    assert!(
        blocked.blocked_on_mismatch(),
        "mismatch is the incident-adjacent signal"
    );

    // A stray number the model computed itself in prose (never put under the contract) blocks the
    // whole answer even though the sourced claim re-derives fine — never trust model arithmetic.
    let answer2 = "There were 47 failed settlements, about 75% of the batch.";
    let stray = window.verify_answer(answer2, &claims, &good, &Tolerance::default());
    assert!(
        !stray.ships(),
        "an unbacked computed ratio in prose must block"
    );
    assert!(
        !stray.blocked_on_mismatch(),
        "it fails the lint, not re-derivation"
    );
}

#[test]
fn r4_compile_rls_composition() {
    // Two equally-relevant rows differing ONLY by their row-security department attribute, plus a
    // fresher own-department row so freshness/positioning are also exercised in the composition.
    let rcorpus = RCorpus::new(vec![
        RChunk::new(
            "mine-old",
            "settlement failure report detail",
            DataClass::Internal,
        )
        .with_attribute("department", "settlement-eng"),
        RChunk::new(
            "theirs",
            "settlement failure report detail",
            DataClass::Internal,
        )
        .with_attribute("department", "hr"),
        RChunk::new(
            "mine-new",
            "settlement failure report detail",
            DataClass::Internal,
        )
        .with_attribute("department", "settlement-eng"),
    ]);
    let hybrid = HybridRetriever::from_retrieval_corpus(rcorpus);
    let counter = WordTokenCounter;

    let principal = Principal::user("analyst", &[]).with_department("settlement-eng");
    let filter = RowFilter::department_isolation(&principal);
    let cfg = OptimizerConfig {
        eligible: vec![EligibleModel::new("m", 8000)],
        graph_weight: 0.0,
        prefer_fresh: false,
        ..OptimizerConfig::default()
    };

    let compiled = compile_rls(
        "settlement failure report",
        &hybrid,
        &principal,
        &filter,
        &cfg,
        &counter,
        None,
        &BTreeMap::new(),
    );

    // The optimizer composition ran: the query was planned and the window is grounded/fitted.
    assert!(
        compiled
            .plan
            .includes(ainxt_context::optimizer::GraphLayer::Conversation),
        "plan → the composition ran plan_query"
    );
    assert!(
        !compiled.context.is_empty(),
        "the composition produced a grounded, fitted window"
    );

    // RLS applied PRE-rank: the cross-department row appears NOWHERE — not the window chunks, not
    // the citations, and not the lineage (existence never leaks through the compile path).
    assert!(
        compiled.context.chunks.iter().all(|c| c.id != "theirs"),
        "a cross-department row must never enter the compiled window"
    );
    assert!(
        compiled
            .context
            .citations
            .iter()
            .all(|c| c.chunk_id != "theirs"),
        "a filtered row must never be cited"
    );
    assert!(
        compiled
            .context
            .lineage
            .iter()
            .all(|n| n.chunk_id != "theirs"),
        "a filtered row must not even appear in lineage — pre-rank, not a post-filter drop"
    );
    assert!(
        compiled.ranked.iter().all(|c| c.id != "theirs"),
        "a filtered row must never be ranked/fused"
    );
    // Both own-department rows survived the filter and composed into the window.
    let ids: Vec<&str> = compiled
        .context
        .chunks
        .iter()
        .map(|c| c.id.as_str())
        .collect();
    assert!(
        ids.contains(&"mine-old") && ids.contains(&"mine-new"),
        "own-department rows compose in"
    );

    // Contrast: an empty RLS filter (no policies) reduces compile_rls to the plain composition —
    // proving the row-filter NARROWS, it never widens visibility.
    let open = RowFilter::new(RlsSession::bind(&principal));
    let all = compile_rls(
        "settlement failure report",
        &hybrid,
        &principal,
        &open,
        &cfg,
        &counter,
        None,
        &BTreeMap::new(),
    );
    assert!(
        all.ranked.iter().any(|c| c.id == "theirs"),
        "with RLS disabled the class ACL alone governs and the cross-dept row is visible"
    );
}
