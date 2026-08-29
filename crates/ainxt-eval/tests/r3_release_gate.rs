// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-3 gap-closing integration tests, exercised on the REAL objects (no `#[cfg(test)]` internals):
//!
//! * `r3_release_gate_ci_merge_block` — the composed keystone [`ainxt_eval::ci::run_release_gate_ci`]
//!   is a callable CI/dogfood entrypoint that runs the real instruments and produces a fail-closed
//!   merge-block + exit code (gap: "Composed release-gate not wired to real infra or CI merge-block").
//! * `r3_stat_gate_not_bypassed` — the drop-in [`ainxt_eval::evaluate_gate_statistical_dropin`] the
//!   first consumers call in place of the naive [`ainxt_eval::evaluate_gate`] gates on statistical
//!   *significance*, not on a coin-flip pass-rate dip (gap: "Statistically-valid gate is bypassed by
//!   its own first consumers").
//!
//! Both are fail-before (the symbols did not exist) / pass-after.

use std::collections::{BTreeMap, BTreeSet};

use ainxt_eval::audit::{EventSink, VerdictRecord};
use ainxt_eval::ci::{run_release_gate_ci, EXIT_BLOCK, EXIT_INDETERMINATE, EXIT_SHIP};
use ainxt_eval::integrity::{
    ContaminationPolicy, EvalCaseContent, HoldoutCase, SealedCorpusStore, SealedManifest,
};
use ainxt_eval::judge::{CalibrationFloors, JudgeSpec};
use ainxt_eval::manifest::{Direction, EvalSetManifest, MetricSpec, PreRegistration};
use ainxt_eval::pipeline::{
    ContaminationScan, GatedCase, JudgeCalibration, ReleaseGateConfig, ReleaseGateRequest,
    RotationInputs, VaultInputs,
};
use ainxt_eval::vault::RegressionVault;
use ainxt_eval::{
    evaluate_gate, evaluate_gate_statistical_dropin, CaseResult, EvalCase, EvalCriteria,
    EvalReport, EvalSystem, GateOutcome, GatePolicy, QualityJudge, QualityScore,
};
use ainxt_types::DataClass;

// =================================================================================================
// Fakes — the seams the parent supplies in production (durable store / Event Log / in-house Judge /
// dogfooded systems). Here they are deterministic stand-ins so the composed gate can be driven end to
// end; the object under test (run_release_gate_ci → run_release_gate) is the real one.
// =================================================================================================

/// A system whose per-case output encodes its arm ("b:<id>" / "c:<id>") for the table judge.
struct ScriptedSystem {
    prefix: String,
}
impl EvalSystem for ScriptedSystem {
    fn respond(&self, input: &str) -> String {
        format!("{}:{input}", self.prefix)
    }
}

/// A judge that reads the intended score from a per-arm table keyed by case id, so a test dials exact
/// per-case diffs.
struct TableJudge {
    base: BTreeMap<String, u8>,
    cand: BTreeMap<String, u8>,
}
impl QualityJudge for TableJudge {
    fn score(&self, _input: &str, output: &str, _c: &EvalCriteria) -> QualityScore {
        let mut it = output.splitn(2, ':');
        let arm = it.next().unwrap_or("");
        let id = it.next().unwrap_or("");
        let table = if arm == "c" { &self.cand } else { &self.base };
        QualityScore {
            score: *table.get(id).unwrap_or(&0),
            rationale: "table".into(),
        }
    }
}

/// Only the declared runner identity may read the sealed gold answers.
struct AllowStore {
    cases: Vec<(String, String, String)>,
    identity: String,
}
impl SealedCorpusStore for AllowStore {
    fn load(
        &self,
        _set_id: &str,
        _v: &str,
        identity: &str,
    ) -> Option<Vec<(String, String, String)>> {
        if identity == self.identity {
            Some(self.cases.clone())
        } else {
            None
        }
    }
}

/// An in-memory Event Log sink (the parent supplies a tamper-evident/WORM one).
struct MemSink(Vec<VerdictRecord>);
impl EventSink for MemSink {
    fn append(&mut self, record: &VerdictRecord) {
        self.0.push(record.clone());
    }
}

fn judge_spec() -> JudgeSpec {
    JudgeSpec {
        judge_id: "correctness-v1".into(),
        base_model: "glm-4".into(),
        model_version: "glm-4-2026-05".into(),
        family: "glm".into(),
        temperature: 0.0,
        seed: 7,
        rubric: "score correctness".into(),
        scoring_scale: "0-100".into(),
        dimension: "correctness".into(),
        in_house_only: true,
    }
}

fn prereg() -> PreRegistration {
    PreRegistration {
        metrics: vec![MetricSpec {
            name: "correctness".into(),
            direction: Direction::HigherIsBetter,
            noninferiority_margin: 2.0,
            mde: 3.0,
            primary: true,
        }],
        power: 0.8,
        alpha: 0.05,
        method: "paired-noninferiority-bh".into(),
    }
}

/// Build N gated cases in one cell; `base`/`cand` fill the judge tables. Returns cases, judge, and the
/// sealed-corpus triples for the manifest content commitment.
fn build(
    n: usize,
    base_fn: impl Fn(usize) -> u8,
    cand_fn: impl Fn(usize) -> u8,
) -> (Vec<GatedCase>, TableJudge, Vec<(String, String, String)>) {
    let mut cases = Vec::new();
    let mut base = BTreeMap::new();
    let mut cand = BTreeMap::new();
    let mut triples = Vec::new();
    for i in 0..n {
        let id = format!("c{i}");
        cases.push(GatedCase::new(
            EvalCase::new(&id, &id, "must be correct", 60),
            "correctness×glm×qa",
            2.0,
            false,
            false,
        ));
        base.insert(id.clone(), base_fn(i));
        cand.insert(id.clone(), cand_fn(i));
        triples.push((id.clone(), id.clone(), "gold".to_string()));
    }
    (cases, TableJudge { base, cand }, triples)
}

fn good_labels() -> (Vec<String>, Vec<String>) {
    let mut gold = vec!["good".to_string(); 8];
    gold.extend(vec!["bad".to_string(); 8]);
    let mut judge = gold.clone();
    judge[0] = "bad".into(); // one mistake — still admitted
    (gold, judge)
}

fn manifest_for(triples: &[(String, String, String)]) -> EvalSetManifest {
    let m = SealedManifest::build("correctness-set", "v1", triples);
    EvalSetManifest {
        set_id: "correctness-set".into(),
        version: "v1".into(),
        dimension: "correctness".into(),
        content_commitment: m.content_commitment,
        pre_registration: prereg(),
    }
}

/// A fully-assembled request that is otherwise a valid, well-powered, in-house-judged, uncontaminated
/// run — only the base/cand score tables differ per test to craft "null" vs "regression".
#[allow(clippy::too_many_arguments)]
fn request<'a>(
    cases: &'a [GatedCase],
    judge: &'a TableJudge,
    manifest: &'a EvalSetManifest,
    store: &'a AllowStore,
    base: &'a ScriptedSystem,
    cand: &'a ScriptedSystem,
    spec: &'a JudgeSpec,
    available: &'a [JudgeSpec],
    gold: &'a [String],
    jlabels: &'a [String],
    current: &'a [String],
    content: &'a [EvalCaseContent],
    cand_texts: &'a [String],
    cand_emb: &'a [Vec<f32>],
    holdout: &'a [HoldoutCase],
    vault: &'a RegressionVault,
    now_passing: &'a BTreeSet<String>,
) -> ReleaseGateRequest<'a> {
    ReleaseGateRequest {
        manifest,
        primary_sds: &[1.0],
        sealed_store: store,
        runner_identity: "eval-runner",
        cases,
        baseline: base,
        candidate: cand,
        judge,
        judge_spec: spec,
        data_class: DataClass::RegulatedPayment,
        available_judges: available,
        calibration: JudgeCalibration {
            gold_labels: gold,
            judge_labels: jlabels,
            admission_kappa: 1.0,
            current_labels: current,
            max_kappa_drop: 0.2,
        },
        floors: CalibrationFloors::default(),
        contamination: ContaminationScan {
            candidate_texts: cand_texts,
            candidate_embeddings: cand_emb,
            eval_case_content: content,
            policy: ContaminationPolicy::default(),
        },
        rotation: RotationInputs {
            holdout,
            now_epoch: 101,
            max_age_epochs: 50,
            max_uses: 100,
        },
        vault: VaultInputs {
            vault,
            previously_tripped: &[],
            now_passing,
            prior_snapshot: None,
        },
        candidate_sha: "deadbeef",
        seed: 42,
        epoch: 1000,
        config: ReleaseGateConfig::default(),
        cancel: None,
        panel: None,
    }
}

// =================================================================================================
// r3_release_gate_ci_merge_block
// =================================================================================================

#[test]
fn r3_release_gate_ci_merge_block() {
    let (gold, jlabels) = good_labels();
    let current = gold.clone();
    let content = vec![EvalCaseContent {
        id: "c0".into(),
        text: "sealed gold".into(),
        embedding: None,
    }];
    let cand_texts = vec!["clean prompt".into()];
    let cand_emb: Vec<Vec<f32>> = vec![];
    let holdout: Vec<HoldoutCase> = vec![];
    let vault = RegressionVault::new();
    let spec = judge_spec();
    let available = vec![judge_spec()];
    let base_sys = ScriptedSystem { prefix: "b".into() };
    let cand_sys = ScriptedSystem { prefix: "c".into() };
    let passing = BTreeSet::new();

    // ---- (1) a null change (candidate == baseline) SHIPS and is mergeable ---------------------
    {
        let (cases, judge, triples) = build(120, |_| 80, |_| 80);
        let manifest = manifest_for(&triples);
        let store = AllowStore {
            cases: triples.clone(),
            identity: "eval-runner".into(),
        };
        let req = request(
            &cases,
            &judge,
            &manifest,
            &store,
            &base_sys,
            &cand_sys,
            &spec,
            &available,
            &gold,
            &jlabels,
            &current,
            &content,
            &cand_texts,
            &cand_emb,
            &holdout,
            &vault,
            &passing,
        );
        let mut sink = MemSink(Vec::new());
        let outcome = run_release_gate_ci(&req, &mut sink);
        assert!(
            outcome.is_mergeable() && !outcome.merge_blocked,
            "a null change must be mergeable: {}",
            outcome.summary
        );
        assert_eq!(outcome.exit_code, EXIT_SHIP, "ship → exit 0");
        assert!(outcome.report.is_ship());
        // The keystone actually ran its real instruments AND audited before returning.
        assert_eq!(
            outcome.report.scored, 120,
            "the statistical gate scored the corpus"
        );
        assert!(outcome.report.statistical.is_some());
        assert_eq!(sink.0.len(), 1, "a verdict was written to the Event Log");
        assert_eq!(sink.0[0].outcome, "pass");
    }

    // ---- (2) a genuine, significant regression BLOCKS the merge (exit 1) ----------------------
    {
        let (cases, judge, triples) = build(120, |_| 80, |_| 72); // 8-point drop everywhere
        let manifest = manifest_for(&triples);
        let store = AllowStore {
            cases: triples.clone(),
            identity: "eval-runner".into(),
        };
        let req = request(
            &cases,
            &judge,
            &manifest,
            &store,
            &base_sys,
            &cand_sys,
            &spec,
            &available,
            &gold,
            &jlabels,
            &current,
            &content,
            &cand_texts,
            &cand_emb,
            &holdout,
            &vault,
            &passing,
        );
        let mut sink = MemSink(Vec::new());
        let outcome = run_release_gate_ci(&req, &mut sink);
        assert!(
            outcome.merge_blocked,
            "a real regression must block the merge"
        );
        assert_eq!(outcome.exit_code, EXIT_BLOCK, "block → exit 1");
        assert!(
            outcome.summary.contains("statistical regression"),
            "the block cites the statistical gate (not aggregate arithmetic): {}",
            outcome.summary
        );
        assert_eq!(sink.0[0].outcome, "block", "even a block is audited");
    }

    // ---- (3) an un-runnable gate (cancelled) is INDETERMINATE → fail-closed, merge blocked -----
    {
        let (cases, judge, triples) = build(120, |_| 80, |_| 80);
        let manifest = manifest_for(&triples);
        let store = AllowStore {
            cases: triples.clone(),
            identity: "eval-runner".into(),
        };
        let mut req = request(
            &cases,
            &judge,
            &manifest,
            &store,
            &base_sys,
            &cand_sys,
            &spec,
            &available,
            &gold,
            &jlabels,
            &current,
            &content,
            &cand_texts,
            &cand_emb,
            &holdout,
            &vault,
            &passing,
        );
        let always_cancel = || true;
        req.cancel = Some(&always_cancel);
        let mut sink = MemSink(Vec::new());
        let outcome = run_release_gate_ci(&req, &mut sink);
        assert!(
            outcome.merge_blocked && !outcome.is_mergeable(),
            "a cancelled/un-run gate must fail closed"
        );
        assert_eq!(
            outcome.exit_code, EXIT_INDETERMINATE,
            "indeterminate → exit 2"
        );
        assert_eq!(
            sink.0[0].outcome, "indeterminate",
            "even a cancelled run is audited"
        );
    }
}

// =================================================================================================
// r3_stat_gate_not_bypassed
// =================================================================================================

/// Build an [`EvalReport`] from per-case (id, score) with threshold 60.
fn report_from(scores: &[(String, u8)]) -> EvalReport {
    let results: Vec<CaseResult> = scores
        .iter()
        .map(|(id, s)| CaseResult {
            id: id.clone(),
            output: String::new(),
            score: *s,
            passed: *s >= 60,
            rationale: String::new(),
        })
        .collect();
    let passed = results.iter().filter(|r| r.passed).count();
    let n = results.len();
    EvalReport {
        mean: (results.iter().map(|r| r.score as u32).sum::<u32>() / n as u32) as u8,
        pass_rate: passed as f64 / n as f64,
        passed,
        n,
        results,
    }
}

#[test]
fn r3_stat_gate_not_bypassed() {
    // Two runs of EQUAL true quality with a tiny non-significant sampling dip (6 of 120 cases slip
    // from 61→59, i.e. one point across the threshold). The NAIVE evaluate_gate blocks it as a
    // pass-rate regression (the coin-flip bug); the drop-in the first consumers must call does NOT.
    let base: Vec<(String, u8)> = (0..120)
        .map(|i| (format!("c{i}"), if i % 20 == 0 { 61 } else { 80 }))
        .collect();
    let cand: Vec<(String, u8)> = (0..120)
        .map(|i| (format!("c{i}"), if i % 20 == 0 { 59 } else { 80 }))
        .collect();
    let base_r = report_from(&base);
    let cand_r = report_from(&cand);

    let lax = GatePolicy {
        min_pass_rate: 0.0,
        min_mean: 0,
        noninferiority_margin: 0.02,
    };

    // The naive aggregate gate flaps on the non-significant dip (this is what the consumers get today).
    assert!(
        !evaluate_gate(&cand_r, &lax, Some(&base_r)).is_pass(),
        "the naive gate blocks the tiny non-significant dip (the coin-flip bug)"
    );

    // The statistically-valid drop-in on the SAME data must NOT block — the diff is not significant.
    assert!(
        evaluate_gate_statistical_dropin(&cand_r, &lax, Some(&base_r)).is_pass(),
        "the drop-in must gate on significance, not a coin-flip pass-rate dip"
    );

    // But a genuine 8-point regression across every case must block the drop-in.
    let reg: Vec<(String, u8)> = (0..120).map(|i| (format!("c{i}"), 72u8)).collect();
    let reg_r = report_from(&reg);
    match evaluate_gate_statistical_dropin(&reg_r, &lax, Some(&base_r)) {
        GateOutcome::Fail(reasons) => assert!(
            reasons.iter().any(|r| r.contains("statistical regression")),
            "a real regression blocks via the statistical branch: {reasons:?}"
        ),
        GateOutcome::Pass => panic!("a real 8-point regression must block the drop-in"),
    }

    // The absolute floors are preserved: a run below the pass-rate floor fails even with no baseline.
    let strict = GatePolicy {
        min_pass_rate: 0.9,
        min_mean: 0,
        noninferiority_margin: 0.02,
    };
    let weak: Vec<(String, u8)> = (0..120)
        .map(|i| (format!("c{i}"), if i % 2 == 0 { 80 } else { 40 }))
        .collect();
    let weak_r = report_from(&weak);
    match evaluate_gate_statistical_dropin(&weak_r, &strict, None) {
        GateOutcome::Fail(reasons) => assert!(
            reasons.iter().any(|r| r.contains("pass-rate")),
            "absolute floors still apply: {reasons:?}"
        ),
        GateOutcome::Pass => panic!("a run below the pass-rate floor must fail the drop-in"),
    }
}
