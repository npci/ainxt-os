// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! End-to-end Prompt Registry flow across the public API: author four layer artifacts, drive one
//! through the DRAFT→PRODUCTION lifecycle behind the eval-delta merge gate + SoD, pin a release,
//! serve the per-model variant with lock verification, assemble the five layers, record the forensic
//! event, and run the output-side guard rail. This is the "prompts-as-code" spine the audit flagged
//! as missing, exercised as a caller would.

use std::collections::BTreeMap;

use ainxt_eval::{CaseResult, EvalReport, GatePolicy};
use ainxt_prompt::guard::LeakRail;
use ainxt_prompt::layered::{HeuristicTokens, LayeredAssembler, TruncatingCondenser};
use ainxt_prompt::registry::{
    Approval, CanaryResult, Deployment, EvalDelta, EvalSetIndex, EvalSetRef, Layer, LayerArtifact,
    LifecycleEvent, ModelFamily, Registry, Semver, Stage,
};

fn fam(s: &str) -> ModelFamily {
    ModelFamily::new(s)
}

fn report(pass_rate: f64, mean: u8, n: usize) -> EvalReport {
    let passed = (pass_rate * n as f64).round() as usize;
    let results = (0..n)
        .map(|i| CaseResult {
            id: format!("c{i}"),
            output: String::new(),
            score: mean,
            passed: i < passed,
            rationale: String::new(),
        })
        .collect();
    EvalReport {
        results,
        n,
        passed,
        mean,
        pass_rate,
    }
}

fn artifact(id: &str, layer: Layer, v: Semver) -> LayerArtifact {
    let mut variants = BTreeMap::new();
    variants.insert(
        fam("claude"),
        format!("<{}> concise claude body v{v}", layer.code()),
    );
    variants.insert(
        fam("qwen"),
        format!(
            "<{}> explicit qwen body v{v}: restate format, 2 few-shot exemplars",
            layer.code()
        ),
    );
    LayerArtifact {
        id: id.to_string(),
        layer,
        version: v,
        owner: "platform-prompt-eng".to_string(),
        author: "alice".to_string(),
        variables: vec![],
        eval_set: EvalSetRef::new("eval.role.l1_support", "^2.0.0").unwrap(),
        model_variants: vec![fam("claude"), fam("qwen")],
        variants,
    }
}

#[test]
fn prompts_as_code_end_to_end() {
    let mut ix = EvalSetIndex::new();
    ix.insert("eval.role.l1_support", Semver::new(2, 1, 0));
    let mut reg = Registry::new(ix);
    reg.set_owner_group("platform-prompt-eng", ["bob".to_string()]);

    let v = Semver::new(1, 0, 0);
    let layers = [
        ("prompt.persona", Layer::Persona),
        ("prompt.policy", Layer::Policy),
        ("prompt.task", Layer::Task),
        ("prompt.guards", Layer::Guards),
    ];
    for (id, layer) in layers {
        reg.register(artifact(id, layer, v)).unwrap();
    }

    // Drive the task layer through the full lifecycle behind every gate.
    reg.advance("prompt.task", v, LifecycleEvent::OpenPr)
        .unwrap();
    let delta = EvalDelta {
        eval_set: EvalSetRef::new("eval.role.l1_support", "^2.0.0").unwrap(),
        baseline: report(0.90, 80, 20),
        candidate: report(0.96, 88, 20),
        policy: GatePolicy::default(),
    };
    reg.advance("prompt.task", v, LifecycleEvent::SubmitEval(delta))
        .unwrap();
    reg.advance(
        "prompt.task",
        v,
        LifecycleEvent::Approve(Approval {
            approver: "bob".into(),
        }),
    )
    .unwrap();
    let stage = reg
        .advance(
            "prompt.task",
            v,
            LifecycleEvent::Promote(CanaryResult::Healthy),
        )
        .unwrap();
    assert_eq!(stage, Stage::Production);

    // Pin a production release and serve the per-model variant with lock verification.
    let ids: Vec<(&str, Semver)> = layers.iter().map(|(id, _)| (*id, v)).collect();
    let release = reg.pin_release("prompt-v1", &ids).unwrap();
    let deployment = Deployment::new(release);

    let layer_ids = [
        "prompt.persona",
        "prompt.policy",
        "prompt.task",
        "prompt.guards",
    ];
    let resolved_claude = reg
        .serve(&deployment, "turn-100", &fam("claude"), &layer_ids)
        .unwrap();
    let resolved_qwen = reg
        .serve(&deployment, "turn-100", &fam("qwen"), &layer_ids)
        .unwrap();

    // Per-model variants really differ (PE2).
    assert!(resolved_claude[0].body.contains("concise claude"));
    assert!(resolved_qwen[0].body.contains("explicit qwen"));
    assert_ne!(resolved_claude[0].body, resolved_qwen[0].body);

    // Assemble the five layers and produce the forensic event record (PE1/PE11).
    let asm = LayeredAssembler {
        estimator: &HeuristicTokens,
        condenser: &TruncatingCondenser,
        budget_tokens: 10_000,
    };
    let compiled = asm.assemble(
        &resolved_claude,
        "Retrieved: the UPI settlement window closes at 22:00 IST.",
        fam("claude"),
        "control-sha-abc123",
    );
    let tuple = compiled.version_tuple();
    assert_eq!(tuple.len(), 4);
    assert_eq!(tuple[0], "L1@prompt.persona.v1.0.0");
    assert_eq!(tuple[3], "L4@prompt.guards.v1.0.0");

    let rec = compiled.event_record();
    assert_eq!(rec.control_sha, "control-sha-abc123");
    // The recorded hash matches the exact text sent → replayable byte-for-byte.
    assert_eq!(
        rec.prompt_hash,
        ainxt_prompt::registry::content_fingerprint(&compiled.text)
    );

    // The output-side guard rail catches a verbatim leak of the compiled prompt.
    let rail = LeakRail::default();
    let (leak, safe) = rail.redact(&compiled.text, &compiled.text); // model dumps its own prompt
    assert!(leak.leaked);
    assert!(!safe.contains("concise claude body"));
    // A benign answer passes untouched.
    let (ok, passthrough) = rail.redact(&compiled.text, "The window closes at 22:00 IST.");
    assert!(!ok.leaked);
    assert_eq!(passthrough, "The window closes at 22:00 IST.");
}

#[test]
fn a_regressing_task_version_cannot_reach_production() {
    let mut ix = EvalSetIndex::new();
    ix.insert("eval.role.l1_support", Semver::new(2, 1, 0));
    let mut reg = Registry::new(ix);
    let v = Semver::new(2, 0, 0);
    reg.register(artifact("prompt.task", Layer::Task, v))
        .unwrap();
    reg.advance("prompt.task", v, LifecycleEvent::OpenPr)
        .unwrap();

    let regressing = EvalDelta {
        eval_set: EvalSetRef::new("eval.role.l1_support", "^2.0.0").unwrap(),
        baseline: report(0.95, 88, 20),
        candidate: report(0.60, 55, 20),
        policy: GatePolicy::default(),
    };
    let err = reg
        .advance("prompt.task", v, LifecycleEvent::SubmitEval(regressing))
        .unwrap_err();
    // Merge-blocking: it never leaves EVAL.
    assert!(err.to_string().contains("regression"));
    assert_eq!(reg.stage_of("prompt.task", v), Some(Stage::Eval));
}
