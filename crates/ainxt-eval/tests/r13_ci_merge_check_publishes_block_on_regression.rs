// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-13 gap-closing integration test (eval-tester-scenarios, HIGH):
//! **"The Eval Gate is not actually wired as a merge-blocking CI status check" (ADR-010 D1 keystone).**
//!
//! Everything before this round *computed* a merge decision (`run_release_gate` → `run_merge_check` →
//! the composite `merge_status_check_required`) but nothing handed it to a CI system: no entrypoint
//! posted the composite status to an SCM's commit-status API so a branch-protection rule could block
//! on it. `ci::run_ci_merge_check` closes that. It is the ONE call a CI job makes — it runs the REAL
//! composed gate through the dogfood provider, composes it with the other required DoD gates into the
//! single named status check, PUBLISHES that check to the `CommitStatusPublisher` seam, and returns a
//! pass/block status + a process exit code the job exits on.
//!
//! Fail-before: `ci::run_ci_merge_check` / `ci::CommitStatusPublisher` / `ci::CommitStatus` did not
//! exist — the gate could compute a block but nothing published it to a CI system. Pass-after: a
//! genuine statistical regression is published to the SCM as a **`failed`** commit status on the PR
//! head, is `merge_blocked`, and exits `EXIT_BLOCK`; a null change is published as `success`, is
//! mergeable, and exits 0.
//!
//! The live GitLab commit-status HTTP call (network + project token + the pipeline that registers the
//! check as a branch-protection requirement) is infra-gated: the real `CommitStatusPublisher` lives in
//! the reserved server/daemon crates. This test drives the whole decision-and-publish path through a
//! deterministic `RecordingStatusPublisher`, so the block-on-regression behaviour that a CI system
//! would enforce is proven offline end-to-end.

use std::collections::{BTreeMap, BTreeSet};

use ainxt_eval::audit::{EventSink, VerdictRecord};
use ainxt_eval::ci::{
    run_ci_merge_check, CheckState, CommitStatusPublisher, RecordingStatusPublisher, RequiredCheck,
    EXIT_BLOCK, EXIT_INDETERMINATE, EXIT_SHIP, RELEASE_GATE_CHECK, SCENARIO_MATRIX_CHECK,
};
use ainxt_eval::dogfood::ReleaseGateProvider;
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

/// The dogfood runner (the CI job's provider): assembles a real `ReleaseGateRequest` and runs the
/// composed gate. `cand_fn` dials the candidate's per-case score so we can craft a null change or a
/// genuine regression. `unavailable` models the provider being unable to assemble inputs at all.
struct DogfoodRunner {
    base_fn: fn(usize) -> u8,
    cand_fn: fn(usize) -> u8,
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
            runner_identity: "eval-runner",
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
        assert_eq!(sink.0.len(), 1, "the gate audited exactly one verdict");
        Ok(())
    }
}

const HEAD_SHA: &str = "0a1b2c3d4e5f60718293a4b5c6d7e8f900112233";

#[test]
fn r13_ci_merge_check_publishes_block_on_regression() {
    let required = [SCENARIO_MATRIX_CHECK];
    let matrix_green = RequiredCheck::new(SCENARIO_MATRIX_CHECK, true, "1300 scenarios green");

    // ---- (1) NULL change: eval ships, matrix green → published `success`, mergeable, exit 0. ----
    {
        let null = DogfoodRunner {
            base_fn: |_| 80,
            cand_fn: |_| 80,
            unavailable: false,
        };
        let mut pub_ = RecordingStatusPublisher::new();
        let result = run_ci_merge_check(
            &null,
            std::slice::from_ref(&matrix_green),
            &required,
            HEAD_SHA,
            &mut pub_,
        );
        assert!(
            result.is_mergeable(),
            "null change must merge: {:?}",
            result.status
        );
        assert!(!result.merge_blocked);
        assert_eq!(result.exit_code, EXIT_SHIP, "ship → exit 0");
        assert_eq!(result.status.state, CheckState::Success);
        assert!(result.published.is_ok());
        // The status was actually POSTED to the SCM commit-status seam, on the PR head.
        let posted = pub_.last().expect("a status was published");
        assert_eq!(
            posted.name, RELEASE_GATE_CHECK,
            "branch protection keys off this name"
        );
        assert_eq!(posted.state, CheckState::Success);
        assert_eq!(
            posted.scm_state(),
            "success",
            "GitLab commit-status vocabulary"
        );
        assert_eq!(
            posted.target_ref, HEAD_SHA,
            "attached to the PR head commit"
        );
    }

    // ---- (2) THE GAP THIS CLOSES: a genuine 8-point regression is PUBLISHED as a merge-blocking ----
    //          `failed` commit status, is merge_blocked, and exits EXIT_BLOCK.
    {
        let regression = DogfoodRunner {
            base_fn: |_| 80,
            cand_fn: |_| 72,
            unavailable: false,
        };
        let mut pub_ = RecordingStatusPublisher::new();
        let result = run_ci_merge_check(
            &regression,
            std::slice::from_ref(&matrix_green),
            &required,
            HEAD_SHA,
            &mut pub_,
        );
        assert!(
            result.merge_blocked,
            "a real statistical regression must block the merge"
        );
        assert!(!result.is_mergeable());
        assert_eq!(
            result.exit_code, EXIT_BLOCK,
            "block → exit 1 (the CI job fails)"
        );
        assert_eq!(result.status.state, CheckState::Failure);
        assert!(
            result.status.description.contains("statistical regression"),
            "the block cites the statistical gate, not aggregate arithmetic: {}",
            result.status.description
        );
        // The FAILED status was posted to the SCM — this is what branch protection blocks the PR on.
        let posted = pub_.last().expect("a status was published even on a block");
        assert_eq!(posted.state, CheckState::Failure);
        assert_eq!(
            posted.scm_state(),
            "failed",
            "posted as a failed commit status"
        );
        assert_eq!(posted.target_ref, HEAD_SHA);
        assert!(
            result.published.is_ok(),
            "the block status published successfully"
        );
    }

    // ---- (3) Eval ships but the Scenario-Matrix DoD gate is ABSENT → composite is published ----
    //          `failed` (fail-closed on a missing gate), exit EXIT_BLOCK.
    {
        let null = DogfoodRunner {
            base_fn: |_| 80,
            cand_fn: |_| 80,
            unavailable: false,
        };
        let mut pub_ = RecordingStatusPublisher::new();
        let result = run_ci_merge_check(&null, &[], &required, HEAD_SHA, &mut pub_);
        assert!(
            result.merge_blocked,
            "a missing required DoD gate must fail closed"
        );
        assert_eq!(result.exit_code, EXIT_BLOCK);
        assert_eq!(pub_.last().unwrap().scm_state(), "failed");
        assert!(result.status.description.contains(SCENARIO_MATRIX_CHECK));
    }

    // ---- (4) Provider cannot assemble inputs → fail-closed: published `failed`, exit INDETERMINATE. ----
    {
        let unavailable = DogfoodRunner {
            base_fn: |_| 80,
            cand_fn: |_| 80,
            unavailable: true,
        };
        let mut pub_ = RecordingStatusPublisher::new();
        let result = run_ci_merge_check(
            &unavailable,
            std::slice::from_ref(&matrix_green),
            &required,
            HEAD_SHA,
            &mut pub_,
        );
        assert!(result.merge_blocked && !result.is_mergeable());
        assert_eq!(
            result.exit_code, EXIT_INDETERMINATE,
            "unavailable gate → exit 2"
        );
        assert_eq!(pub_.last().unwrap().scm_state(), "failed");
        assert!(result.check.outcome().is_none(), "no gate ran");
    }
}

/// A publisher whose network call fails — the merge stays blocked (the required check never turns
/// green), never silently mergeable. Proves the publish-failure fail-closed contract.
struct FailingPublisher;
impl CommitStatusPublisher for FailingPublisher {
    fn publish(&mut self, _status: &ainxt_eval::ci::CommitStatus) -> Result<(), String> {
        Err("GitLab commit-status API unreachable (503)".into())
    }
}

#[test]
fn r13_publish_failure_never_flips_a_ship_into_a_merge() {
    let required = [SCENARIO_MATRIX_CHECK];
    let matrix_green = RequiredCheck::new(SCENARIO_MATRIX_CHECK, true, "green");
    let null = DogfoodRunner {
        base_fn: |_| 80,
        cand_fn: |_| 80,
        unavailable: false,
    };
    let mut pub_ = FailingPublisher;
    let result = run_ci_merge_check(
        &null,
        std::slice::from_ref(&matrix_green),
        &required,
        HEAD_SHA,
        &mut pub_,
    );
    // The gate itself shipped (Success) …
    assert_eq!(result.status.state, CheckState::Success);
    assert!(!result.merge_blocked);
    // … but because the status could not be POSTED, the change is NOT mergeable (fail-closed at the CI
    // layer: branch protection would still see the required check as unresolved).
    assert!(result.published.is_err());
    assert!(
        !result.is_mergeable(),
        "an un-publishable status must not be treated as a green required check"
    );
}
