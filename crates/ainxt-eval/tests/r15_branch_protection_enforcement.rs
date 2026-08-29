// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-15 gap-closing integration test (eval-tester-scenarios, MEDIUM):
//! **"Merge-blocking CI status check / branch-protection ENFORCEMENT."**
//!
//! Round-13 closed "the gate is not wired as a CI status check" (`ci::run_ci_merge_check` publishes
//! a composite [`ainxt_eval::ci::StatusCheck`] to the SCM's commit-status API). That is only half of
//! ADR-010 D1: a posted `failed` commit status only blocks a merge if the branch's protection RULE was
//! actually configured to require that named check. Nothing before this round ever read or wrote that
//! rule — a project whose branch protection was never (or was mis-) configured would post a correct
//! `failed` status and still let the PR merge.
//!
//! [`ainxt_eval::ci::run_ci_merge_check_enforced`] closes that: it enforces (idempotently, additively)
//! that the branch's rule requires [`ainxt_eval::ci::RELEASE_GATE_CHECK`] plus every other required DoD
//! gate name, RE-VERIFIES the rule was actually persisted (never trusting the write call blindly), and
//! only then treats the change as mergeable.
//!
//! Fail-before: `BranchProtectionEnforcer` / `run_ci_merge_check_enforced` did not exist — nothing in
//! the crate ever inspected or configured a branch's protection rule, so a correctly-published
//! `Success` status on an UNPROTECTED branch was indistinguishable from a truly-enforced one.
//! Pass-after: a genuine regression is both published as `failed` AND confirmed unmergeable via an
//! enforced rule; a null change is mergeable ONLY once the rule is confirmed to cover the gate; and an
//! enforcer whose write transport fails leaves the change NOT mergeable even when the gate itself
//! shipped.

use ainxt_eval::audit::EventSink;
use ainxt_eval::audit::VerdictRecord;
use ainxt_eval::ci::{
    branch_protection_covers, run_ci_merge_check_enforced, BranchProtectionEnforcer, CheckState,
    ProtectionRule, RecordingBranchProtectionEnforcer, RecordingStatusPublisher, RequiredCheck,
    EXIT_SHIP, RELEASE_GATE_CHECK, SCENARIO_MATRIX_CHECK,
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
use std::collections::{BTreeMap, BTreeSet};

// ---- the same deterministic dogfood scaffolding r13's test uses --------------------------------

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

struct DogfoodRunner {
    base_fn: fn(usize) -> u8,
    cand_fn: fn(usize) -> u8,
}

impl ReleaseGateProvider for DogfoodRunner {
    fn with_release_inputs(
        &self,
        run: &mut dyn FnMut(&ReleaseGateRequest<'_>, &mut dyn EventSink),
    ) -> Result<(), String> {
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
        Ok(())
    }
}

const HEAD_SHA: &str = "0a1b2c3d4e5f60718293a4b5c6d7e8f900112233";
const BRANCH: &str = "main";

#[test]
fn r15_enforcement_configures_an_unprotected_branch_and_becomes_mergeable() {
    let required = [SCENARIO_MATRIX_CHECK];
    let matrix_green = RequiredCheck::new(SCENARIO_MATRIX_CHECK, true, "1300 scenarios green");
    let null = DogfoodRunner {
        base_fn: |_| 80,
        cand_fn: |_| 80,
    };
    let mut pub_ = RecordingStatusPublisher::new();
    // A BRAND NEW enforcer — the branch has no protection rule at all yet.
    let mut enforcer = RecordingBranchProtectionEnforcer::new();
    assert!(
        enforcer.current_rule(BRANCH).is_none(),
        "starts genuinely unprotected"
    );

    let result = run_ci_merge_check_enforced(
        &null,
        std::slice::from_ref(&matrix_green),
        &required,
        HEAD_SHA,
        BRANCH,
        &mut pub_,
        &mut enforcer,
    );

    assert!(
        result.is_mergeable(),
        "a null change on a NOW-enforced branch must be mergeable: {result:?}"
    );
    assert_eq!(result.inner.status.state, CheckState::Success);
    let rule = result.protection.expect("enforcement succeeded");
    assert!(
        rule.covers(&[RELEASE_GATE_CHECK, SCENARIO_MATRIX_CHECK]),
        "the rule must now require BOTH DoD gates: {rule:?}"
    );
    // Idempotent: re-running enforcement doesn't duplicate or regress the rule.
    let missing = branch_protection_covers(
        &enforcer,
        BRANCH,
        &[RELEASE_GATE_CHECK, SCENARIO_MATRIX_CHECK],
    );
    assert!(missing.is_empty());
}

#[test]
fn r15_a_genuine_regression_is_published_failed_and_confirmed_unmergeable_under_an_enforced_rule() {
    let required = [SCENARIO_MATRIX_CHECK];
    let matrix_green = RequiredCheck::new(SCENARIO_MATRIX_CHECK, true, "green");
    let regression = DogfoodRunner {
        base_fn: |_| 80,
        cand_fn: |_| 72, // an 8-point regression
    };
    let mut pub_ = RecordingStatusPublisher::new();
    let mut enforcer = RecordingBranchProtectionEnforcer::new();

    let result = run_ci_merge_check_enforced(
        &regression,
        std::slice::from_ref(&matrix_green),
        &required,
        HEAD_SHA,
        BRANCH,
        &mut pub_,
        &mut enforcer,
    );

    assert!(
        !result.is_mergeable(),
        "a real regression must not merge: {result:?}"
    );
    assert_eq!(result.inner.status.state, CheckState::Failure);
    assert_ne!(result.inner.exit_code, EXIT_SHIP);
    // The rule IS enforced (this is a genuine block, not a rule-configuration failure).
    assert!(result.protection.is_ok());
    let posted = pub_.last().expect("a status was published even on a block");
    assert_eq!(posted.scm_state(), "failed");
}

#[test]
fn r15_a_pre_existing_rule_missing_our_check_is_strengthened_not_replaced() {
    let required: [&str; 0] = [];
    let no_extra: [RequiredCheck; 0] = [];
    let null = DogfoodRunner {
        base_fn: |_| 80,
        cand_fn: |_| 80,
    };
    let mut pub_ = RecordingStatusPublisher::new();
    let mut enforcer = RecordingBranchProtectionEnforcer::new();
    // Seed a REALISTIC pre-existing rule that requires some unrelated legacy check but not ours.
    enforcer.seed(ProtectionRule {
        branch: BRANCH.to_string(),
        required_checks: vec!["legacy/lint".to_string()],
    });

    let result = run_ci_merge_check_enforced(
        &null,
        &no_extra,
        &required,
        HEAD_SHA,
        BRANCH,
        &mut pub_,
        &mut enforcer,
    );

    let mergeable = result.is_mergeable();
    let rule = result.protection.expect("enforcement succeeded");
    assert!(
        rule.required_checks.iter().any(|c| c == "legacy/lint"),
        "an existing requirement must be PRESERVED, never dropped: {rule:?}"
    );
    assert!(
        rule.covers(&[RELEASE_GATE_CHECK]),
        "the eval gate's own check must be ADDED: {rule:?}"
    );
    assert!(mergeable);
}

#[test]
fn r15_a_failing_enforcer_transport_leaves_the_change_not_mergeable_even_on_a_shipped_gate() {
    /// An enforcer whose write always fails (e.g. GitLab API 403/503) — the merge check itself still
    /// runs and publishes (full audit trail), but the change must NOT be treated as mergeable, because
    /// nothing confirms the SCM will actually block on the posted status.
    struct FailingEnforcer;
    impl BranchProtectionEnforcer for FailingEnforcer {
        fn current_rule(&self, _branch: &str) -> Option<ProtectionRule> {
            None
        }
        fn ensure_required(
            &mut self,
            _branch: &str,
            _required: &[&str],
        ) -> Result<ProtectionRule, String> {
            Err("GitLab protected-branches API unreachable (503)".into())
        }
    }

    let required: [&str; 0] = [];
    let no_extra: [RequiredCheck; 0] = [];
    let null = DogfoodRunner {
        base_fn: |_| 80,
        cand_fn: |_| 80,
    };
    let mut pub_ = RecordingStatusPublisher::new();
    let mut enforcer = FailingEnforcer;

    let result = run_ci_merge_check_enforced(
        &null,
        &no_extra,
        &required,
        HEAD_SHA,
        BRANCH,
        &mut pub_,
        &mut enforcer,
    );

    // The gate itself shipped (published Success) …
    assert_eq!(result.inner.status.state, CheckState::Success);
    assert!(
        result.inner.is_mergeable(),
        "the eval gate half genuinely shipped"
    );
    // … but enforcement failed, so the FULL wiring must not be treated as mergeable.
    assert!(result.protection.is_err());
    assert!(
        !result.is_mergeable(),
        "an un-enforceable branch-protection rule must never be treated as a green light"
    );
}
