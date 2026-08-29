// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-5 gap-closing integration test (eval-tester-scenarios):
//!
//! * `r5_release_gate_merge_check` — the offline release gate is now driven by a NON-TEST enforcer
//!   entrypoint [`ainxt_eval::dogfood::run_merge_check`] over a [`ainxt_eval::dogfood::ReleaseGateProvider`]
//!   seam (the dogfood runner / CI job). Before this the composed gate was reachable only by hand-
//!   assembling a `ReleaseGateRequest` inside the crate's own tests — "no enforcer exists". The provider
//!   assembles the real inputs; the enforcer runs the REAL composed gate and returns a fail-closed
//!   merge decision + process exit code a CI status check consumes.
//!
//! Fail-before: `ainxt_eval::dogfood` did not exist. Pass-after: the enforcer ships a null change,
//! blocks a real statistical regression, and fail-closes when the provider cannot assemble inputs.
//!
//! The object under test is the real `run_merge_check` → `run_release_gate_ci` → `run_release_gate`
//! path; only the provider's backends (encrypted store / Event Log / in-house Judge / dogfooded
//! systems) are deterministic stand-ins, exactly as the parent supplies real ones in production.

use std::collections::{BTreeMap, BTreeSet};

use ainxt_eval::audit::{EventSink, VerdictRecord};
use ainxt_eval::ci::{EXIT_BLOCK, EXIT_INDETERMINATE, EXIT_SHIP};
use ainxt_eval::dogfood::{run_merge_check, ReleaseGateProvider};
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
use ainxt_eval::{EvalCase, EvalCriteria, EvalSystem, QualityJudge, QualityScore};
use ainxt_types::DataClass;

// ---- deterministic stand-ins for the provider's production backends -----------------------------

struct ScriptedSystem {
    prefix: String,
}
impl EvalSystem for ScriptedSystem {
    fn respond(&self, input: &str) -> String {
        format!("{}:{input}", self.prefix)
    }
}

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

struct AllowStore {
    cases: Vec<(String, String, String)>,
    identity: String,
}
impl SealedCorpusStore for AllowStore {
    fn load(&self, _s: &str, _v: &str, identity: &str) -> Option<Vec<(String, String, String)>> {
        if identity == self.identity {
            Some(self.cases.clone())
        } else {
            None
        }
    }
}

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
    judge[0] = "bad".into();
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

/// The dogfood runner: owns every borrowed input and assembles a real `ReleaseGateRequest`. `runner`
/// is the identity the sealed store admits; passing a wrong identity models a store that refuses the
/// caller (fail-closed inside the gate). `unavailable` models the store being unreachable entirely.
struct DogfoodRunner {
    base_fn: fn(usize) -> u8,
    cand_fn: fn(usize) -> u8,
    runner: String,
    unavailable: bool,
}

impl ReleaseGateProvider for DogfoodRunner {
    fn with_release_inputs(
        &self,
        run: &mut dyn FnMut(&ReleaseGateRequest<'_>, &mut dyn EventSink),
    ) -> Result<(), String> {
        if self.unavailable {
            return Err("dogfood run failed: candidate build artifact missing".into());
        }
        let (cases, judge, triples) = build(120, self.base_fn, self.cand_fn);
        let manifest = manifest_for(&triples);
        let store = AllowStore {
            cases: triples.clone(),
            identity: "eval-runner".into(),
        };
        let (gold, jlabels) = good_labels();
        let current = gold.clone();
        let content = vec![EvalCaseContent {
            id: "c0".into(),
            text: "sealed gold".into(),
            embedding: None,
        }];
        let cand_texts = vec!["clean prompt".to_string()];
        let cand_emb: Vec<Vec<f32>> = vec![];
        let holdout: Vec<HoldoutCase> = vec![];
        let vault = RegressionVault::new();
        let spec = judge_spec();
        let available = vec![judge_spec()];
        let base_sys = ScriptedSystem { prefix: "b".into() };
        let cand_sys = ScriptedSystem { prefix: "c".into() };
        let passing = BTreeSet::new();

        let req = ReleaseGateRequest {
            manifest: &manifest,
            primary_sds: &[1.0],
            sealed_store: &store,
            runner_identity: &self.runner,
            cases: &cases,
            baseline: &base_sys,
            candidate: &cand_sys,
            judge: &judge,
            judge_spec: &spec,
            data_class: DataClass::RegulatedPayment,
            available_judges: &available,
            calibration: JudgeCalibration {
                gold_labels: &gold,
                judge_labels: &jlabels,
                admission_kappa: 1.0,
                current_labels: &current,
                max_kappa_drop: 0.2,
            },
            floors: CalibrationFloors::default(),
            contamination: ContaminationScan {
                candidate_texts: &cand_texts,
                candidate_embeddings: &cand_emb,
                eval_case_content: &content,
                policy: ContaminationPolicy::default(),
            },
            rotation: RotationInputs {
                holdout: &holdout,
                now_epoch: 101,
                max_age_epochs: 50,
                max_uses: 100,
            },
            vault: VaultInputs {
                vault: &vault,
                previously_tripped: &[],
                now_passing: &passing,
                prior_snapshot: None,
            },
            candidate_sha: "deadbeef",
            seed: 42,
            epoch: 1000,
            config: ReleaseGateConfig::default(),
            cancel: None,
            panel: None,
        };
        let mut sink = MemSink(Vec::new());
        run(&req, &mut sink);
        // A real Event-Log write happened before the decision returned.
        assert_eq!(sink.0.len(), 1, "the gate audited exactly one verdict");
        Ok(())
    }
}

#[test]
fn r5_release_gate_merge_check() {
    // (1) A null change (candidate == baseline) ships and is mergeable via the enforcer.
    let null = DogfoodRunner {
        base_fn: |_| 80,
        cand_fn: |_| 80,
        runner: "eval-runner".into(),
        unavailable: false,
    };
    let check = run_merge_check(&null);
    assert!(
        check.is_mergeable() && !check.merge_blocked(),
        "a null change must merge: {}",
        check.summary()
    );
    assert_eq!(check.exit_code(), EXIT_SHIP, "ship → exit 0");
    let outcome = check.outcome().expect("gate ran");
    assert!(outcome.report.is_ship());
    assert_eq!(
        outcome.report.scored, 120,
        "the composed gate scored the corpus"
    );
    assert!(outcome.report.statistical.is_some());

    // (2) A genuine 8-point regression blocks the merge (exit 1) and cites the statistical gate.
    let regression = DogfoodRunner {
        base_fn: |_| 80,
        cand_fn: |_| 72,
        runner: "eval-runner".into(),
        unavailable: false,
    };
    let check = run_merge_check(&regression);
    assert!(
        check.merge_blocked(),
        "a real regression must block the merge"
    );
    assert_eq!(check.exit_code(), EXIT_BLOCK, "block → exit 1");
    assert!(
        check.summary().contains("statistical regression"),
        "the block cites the statistical gate, not aggregate arithmetic: {}",
        check.summary()
    );

    // (3) A store that refuses this runner identity → the gate blocks fail-closed (still ran + audited).
    let wrong_identity = DogfoodRunner {
        base_fn: |_| 80,
        cand_fn: |_| 80,
        runner: "pr-author".into(),
        unavailable: false,
    };
    let check = run_merge_check(&wrong_identity);
    assert!(
        check.merge_blocked(),
        "an unreadable corpus must fail closed"
    );
    assert_eq!(check.exit_code(), EXIT_BLOCK, "corpus refusal is a block");

    // (4) The provider cannot assemble inputs at all → fail-closed (merge blocked, exit 2), no gate run.
    let unavailable = DogfoodRunner {
        base_fn: |_| 80,
        cand_fn: |_| 80,
        runner: "eval-runner".into(),
        unavailable: true,
    };
    let check = run_merge_check(&unavailable);
    assert!(
        check.merge_blocked() && !check.is_mergeable(),
        "unavailable inputs must fail closed"
    );
    assert_eq!(
        check.exit_code(),
        EXIT_INDETERMINATE,
        "unavailable → exit 2"
    );
    assert!(check.outcome().is_none(), "no gate ran");
    assert!(check.summary().contains("unavailable"));
}
