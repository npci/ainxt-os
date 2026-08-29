// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! gap5-prompt-governance #1 + #6 — `ainxt_prompt::constrained::StructuredOutputEngine`'s only
//! cross-crate caller was `ainxt_promptopt::constrained_judge::ConstrainedLlmJudge`, which itself had
//! zero callers in `ainxt-runtimed`/`ainxt-server`; and `run_prompt_optimizer_sweep_tick` was reachable
//! only from its own module's unit tests, with no real (non-test) `judge`/`models` construction
//! anywhere and no daemon cadence ever calling it.
//!
//! FAIL-BEFORE: neither `ProviderConstrainedDecoder`/`ProviderModelSeam` nor
//! `spawn_prompt_optimizer_tick` existed — this file would not resolve.
//! PASS-AFTER:
//!   1. [`spawn_prompt_optimizer_tick`] is reachable from a real [`LoadedConfig`] and is genuinely
//!      inert (`None`) on the shipped air-gapped default — exactly matching every other
//!      conditionally-live cadence (`spawn_health_sweep`, `spawn_autoscale_tick`), proven against the
//!      SAME `load_layered`/`LoadedConfig` the real daemon boots from.
//!   2. The REAL constrained-decoding-backed judge + model-seam adapters plug into
//!      [`run_prompt_optimizer_sweep_tick`] — the EXACT function `spawn_prompt_optimizer_tick`'s
//!      spawned loop calls — over a real (if scripted, offline) [`Provider`], driving the actual
//!      `StructuredOutputEngine` bounded-repair loop end-to-end and landing a certified DRAFT via the
//!      crate's pre-existing real Registry-bridge logic. This is not a bespoke duplicate of the tick;
//!      it is the same composition-root entrypoint the daemon's cadence invokes, called here directly
//!      with a network-free `Provider` double (mirrors `ainxt_eval::live`'s own `ScriptedProvider`
//!      test-double discipline — no network, no API key, fully offline and deterministic).

use ainxt_eval::EvalCase;
use ainxt_prompt::registry::{
    EvalSetIndex, EvalSetRef, Layer, ModelFamily, Registry, Semver, Stage,
};
use ainxt_promptopt::constrained_judge::ConstrainedLlmJudge;
use ainxt_promptopt::{ModelSeam, PromptVariant};
use ainxt_protocol::Event;
use ainxt_runtime::provider::Provider;
use ainxt_runtimed::{
    load_layered, run_prompt_optimizer_sweep_tick, spawn_prompt_optimizer_tick, PromptSweepOutcome,
    PromptSweepSpec, ProviderConstrainedDecoder, ProviderModelSeam,
};
use ainxt_types::DataClass;
use std::sync::Arc;
use tokio::sync::mpsc;

/// A network-free `Provider` double: it inspects the incoming prompt exactly like
/// `ainxt_prompt::constrained`'s own `WeakModel` test fixture and `ainxt_promptopt::constrained_judge`'s
/// own `WeakJudgeModel` — invalid JSON (prose) on a first-attempt prompt, a schema-valid
/// `{score,passed,rationale}` object once the repair prompt carries "was invalid". This is the SAME
/// weak-model shape the crate's own tests use to prove the bounded-repair loop, now driven through a
/// real async `Provider::stream()` round trip instead of a hand-rolled sync `ConstrainedDecoder`.
struct WeakScriptedProvider;

impl Provider for WeakScriptedProvider {
    fn id(&self) -> &str {
        "weak-scripted"
    }
    fn eligible(&self, _data_class: DataClass) -> bool {
        true
    }
    fn stream(&self, prompt: &str) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(16);
        let reply = if prompt.contains("was invalid") {
            r#"{"score":85,"passed":true,"rationale":"mentions UPI clearly"}"#.to_string()
        } else {
            "Sure! score=85, here you go (no JSON here)".to_string()
        };
        tokio::spawn(async move {
            let _ = tx.send(Event::TextDelta(reply)).await;
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

#[test]
fn spawn_prompt_optimizer_tick_is_inert_on_the_air_gapped_default() {
    // The SAME LoadedConfig shape the real daemon boots from (no [[models.providers]] declared).
    let loaded = load_layered(&[("t", "version = 1\n")]).expect("load config");
    let handle = spawn_prompt_optimizer_tick(&loaded, std::time::Duration::from_millis(10));
    assert!(
        handle.is_none(),
        "no OpenAI-schema/local provider configured -> no cadence spawned, matching every other \
         conditionally-live cadence on the air-gapped default"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn real_optimizer_tick_drives_the_constrained_decoding_judge_over_a_real_provider_adapter() {
    // The REAL composition-root function `spawn_prompt_optimizer_tick`'s spawned loop calls — exercised
    // here directly with the constrained-decoding judge + model-seam adapters (prompt-governance #1)
    // over a scripted-but-real `Provider`, not a bespoke duplicate of the tick's logic.
    let provider: Arc<dyn Provider> = Arc::new(WeakScriptedProvider);
    let judge = ConstrainedLlmJudge::new(ProviderConstrainedDecoder::new(provider.clone()));
    let seam = ProviderModelSeam::new(provider.clone());
    let family = ModelFamily::new("weak-scripted");
    let models: Vec<(&dyn ModelSeam, ModelFamily)> = vec![(&seam, family)];

    let variants = vec![
        PromptVariant::new("plain", "{input}"),
        PromptVariant::new("guided", "Explain step by step about {input}"),
    ];
    let gold = vec![EvalCase::new(
        "g1",
        "instant transfer",
        "must mention UPI",
        60,
    )];

    let mut ix = EvalSetIndex::new();
    ix.insert("eval.role.optimizer-test", Semver::new(1, 0, 0));
    let mut registry = Registry::new(ix);
    let spec = PromptSweepSpec {
        id: "prompt.task.optimizer-test".into(),
        layer: Layer::Task,
        next_version: Semver::new(1, 0, 0),
        owner: "platform-prompt-eng".into(),
        variables: vec![],
        eval_set: EvalSetRef::new("eval.role.optimizer-test", "^1.0.0").unwrap(),
    };

    let outcomes =
        run_prompt_optimizer_sweep_tick(&mut registry, &variants, &gold, &judge, &models, &spec);
    assert_eq!(outcomes.len(), 1, "one outcome for the one input model");
    match &outcomes[0] {
        PromptSweepOutcome::Drafted { version, .. } => {
            assert_eq!(*version, Semver::new(1, 0, 0));
        }
        PromptSweepOutcome::Skipped { reason, .. } => {
            panic!(
                "expected a draft via the real constrained-decoding judge over a real provider \
                 adapter, got skipped: {reason}"
            )
        }
    }
    assert_eq!(
        registry.stage_of("prompt.task.optimizer-test", Semver::new(1, 0, 0)),
        Some(Stage::Draft),
        "the certified winner (scored through the REAL StructuredOutputEngine bounded-repair loop, \
         via a real async Provider::stream round trip) must land as a real DRAFT in the registry"
    );
}
