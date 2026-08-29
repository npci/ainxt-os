// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! `ainxt-runtimed` — the runtime daemon. A thin shell over [`ainxt_runtimed`]: parse args, load the
//! layered config, assemble the runtime, print an assembly report, then either validate-and-exit
//! (`--check`) or bind the socket and serve the protocol.

use std::io::Write;
use std::sync::{Arc, Mutex};

use ainxt_identity::control::ControlPlane;
use ainxt_runtimed::{
    assemble_full_with_control_plane_and_transparency,
    assemble_selected_fabric_grounded_with_transparency, load_shipped,
};

const HELP: &str = "\
ainxt-runtimed — the AiNxt runtime daemon

USAGE:
    ainxt-runtimed [--config <FILE>]... [--port <N>] [--surface <ID>] [--check]

OPTIONS:
    --config <FILE>       A TOML config layer (repeatable; most-specific last). Defaults to built-ins.
    --port <N>            Override the server port.
    --surface <ID>        Which surface to serve: a profile id from the surface catalog
                          ('chat' (default) / 'code' / 'sdlc' / 'buddy' — profile-enforced,
                          grounded + cited + cached); 'chat_governed' (the SAME grounded chat
                          surface, but every turn first drives the ADR-022 §15 short-TTL JIT
                          renew-and-re-attest + §17/§19 in-flight admission gate against the
                          daemon's shared kill-switch/revocation plane — opt-in, does not change
                          the 'chat' default); 'chat_fabric_grounded' (the SAME grounded chat
                          surface, but every turn is first routed through the populated
                          Context-Fabric multi-graph — cross-graph personalized PageRank,
                          global/sensemaking community summaries, and the multimodal-artifact tier
                          — opt-in, does not change the 'chat' default); 'program' (the
                          long-horizon Program Supervisor / 3-tier Team loop, driven by real Engine
                          turns); or 'engine' (a bare model turn behind the mandatory gates, no
                          profile/grounding).
    --check               Load + assemble the config, print the report, and exit without serving.
    -h, --help            Show this help.

EXIT CODES:
    0 ok   1 config/assembly/bind error   2 usage error
";

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let mut config_paths: Vec<String> = Vec::new();
    let mut check = false;
    let mut port_override: Option<u16> = None;
    let mut surface = String::from("chat");

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print!("{HELP}");
                return;
            }
            "--check" => check = true,
            "--surface" => {
                i += 1;
                match args.get(i) {
                    Some(s) if !s.is_empty() => surface = s.clone(),
                    _ => fail_usage(
                        "--surface requires a surface id (chat/code/sdlc/buddy) or 'engine'",
                    ),
                }
            }
            "--config" => {
                i += 1;
                match args.get(i) {
                    Some(p) => config_paths.push(p.clone()),
                    None => fail_usage("--config requires a FILE"),
                }
            }
            "--port" => {
                i += 1;
                match args.get(i).and_then(|s| s.parse::<u16>().ok()) {
                    Some(p) => port_override = Some(p),
                    None => fail_usage("--port requires a number"),
                }
            }
            other => fail_usage(&format!("unknown argument: {other}")),
        }
        i += 1;
    }

    // Read config layers. The SHIPPED_DEFAULTS base (guardrails + injection ON) is always prepended by
    // `load_shipped`, so the shipped daemon is safety-on-by-default even with no --config; a deployment
    // layer overrides on top.
    let mut layers: Vec<(String, String)> = Vec::new();
    for path in &config_paths {
        match std::fs::read_to_string(path) {
            Ok(src) => layers.push((path.clone(), src)),
            Err(e) => fail(1, &format!("cannot read config '{path}': {e}")),
        }
    }
    let layer_refs: Vec<(&str, &str)> = layers
        .iter()
        .map(|(n, s)| (n.as_str(), s.as_str()))
        .collect();

    let loaded = match load_shipped(&layer_refs) {
        Ok(l) => l,
        Err(e) => fail(1, &format!("{e}")),
    };
    // GAP-FIX identity-payments (ADR-022 §15/§17/§19 "per-turn granularity") — this ONE shared plane is
    // handed to BOTH the surface selector and `assemble_full`'s wiring, so a `--surface chat_governed`
    // daemon's kill-switch/revocation endpoints (below) and its served chat turns consult the SAME live
    // deny-state. `assemble_selected_governed` falls through to the byte-identical `assemble_selected`
    // for every id other than the new opt-in `"chat_governed"`, so the shipped default is unchanged.
    let control_plane = Arc::new(Mutex::new(ControlPlane::new()));

    // One composition-root dispatch (R14): 'engine' / 'program' / 'team' / 'workforce' / 'chat_governed'
    // / the new 'chat_fabric_grounded' each have a match arm; anything else resolves as a profile id
    // from the catalog. GAP-FIX context-fabric (+ data-surfaces-artifacts): `assemble_selected_fabric_grounded`
    // adds the `"chat_fabric_grounded"` arm and falls through to the byte-identical
    // `assemble_selected_governed` for every other id, so both the shipped default and the existing
    // `chat_governed` opt-in are unchanged.
    // GAP-FIX identity-payments (gap6 audit item 1) — the `_with_transparency` sibling additionally
    // returns the live issuance transparency log the selected surface wired (`Some` only for
    // `--surface chat_governed` today), so it can be threaded onto `AssembledFull::transparency`
    // below and served at `GET /v1/transparency/proof/:run_id` — the SAME log
    // `chat_identity.rs::GovernedChatSurface` appends every newly-minted chat-run credential to, not
    // a second, disconnected instance. Every other surface id is unaffected (`None`, unchanged).
    let (assembled, transparency) = match assemble_selected_fabric_grounded_with_transparency(
        &loaded,
        &surface,
        control_plane.clone(),
    ) {
        Ok(a) => a,
        Err(e) => fail(1, &format!("{e}")),
    };

    // Augment the selected surface into the fully-wired served surface: the durable Event Log, the
    // /graph + /v1/query_ledger + /v1/infer governed surfaces, and the live IncidentRegister + the SAME
    // shared ControlPlane the selector above used. Offline-safe (empty corpus/graph/serving-pool still
    // serve).
    let full = match assemble_full_with_control_plane_and_transparency(
        &loaded,
        assembled,
        control_plane,
        transparency,
    ) {
        Ok(f) => f,
        Err(e) => fail(1, &format!("{e}")),
    };

    // Assembly report → stderr.
    eprintln!("ainxt-runtimed: assembled runtime (surface={surface})");
    eprintln!(
        "  gates: compliance={:?}, authz={:?}, audit={:?}",
        loaded.runtime.gates.compliance, loaded.runtime.gates.authz, loaded.runtime.gates.audit
    );
    for line in &full.report {
        eprintln!("  {line}");
    }

    if check {
        eprintln!("config OK (--check) — not serving");
        return;
    }

    let port = port_override.unwrap_or(loaded.server.port);
    let addr = format!("{}:{}", loaded.server.host, port);
    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => fail(1, &format!("cannot bind {addr}: {e}")),
    };
    // Advance the statutory breach clocks even with no request traffic (a paged deadline must fire on
    // wall-clock time, not on the next chat turn). The handle is held for the process lifetime.
    let _breach_clock = full.spawn_breach_clock(std::time::Duration::from_secs(1));
    // GAP-AUDIT regulated-fi #4 — drive the §5.4/§8.1/§8.2 supervisory monitor cadence on real wall-clock
    // time (the store-sweep half; NTP-skew/residency stay due-visible for a deployment with real
    // measurement adapters — see `spawn_supervisory_cadence`'s doc comment).
    let _supervisory_cadence = full.spawn_supervisory_cadence(std::time::Duration::from_secs(60));
    // R10 — start the background ReconcilerSweeper over the served engine's shared exactly-once ledger
    // (§1.8): a lost-ack PENDING capability row is actively reconciled, never passively expired. The
    // handle is held for the process lifetime (dropping it cleanly joins the sweep loop).
    let _reconciler_sweep = full.spawn_reconciler_sweep();
    // GAP-FIX memory — periodic retroactive re-redaction sweep (design §8.6) over the served MEM-10
    // memory backing: `InMemoryStore`/`DurableMemoryStore::re_redact` were fully implemented and
    // tested but had zero callers outside the crate, so a compliance-rule update never reached content
    // already persisted in durable memory. `None` on a surface with no chat engine (nothing to sweep).
    let _memory_re_redact_sweep =
        full.spawn_memory_re_redact_sweep(std::time::Duration::from_secs(300));
    // GAP-FIX memory (embedding-lifecycle no caller) — periodic batch re-embed sweep (design §8.5)
    // over the SAME served MEM-10 memory backing `spawn_memory_re_redact_sweep` sweeps above:
    // `InMemoryStore`/`DurableMemoryStore::reembed_all` were fully implemented and unit-tested, and
    // `spawn_memory_reembed_sweep` itself was already built and tested in this crate — but unlike its
    // sibling re-redact sweep (spawned immediately above), nothing in `main.rs` ever called it, so a
    // platform embedding-model bump never reached already-persisted memory items on any real
    // deployment. `None` on a surface with no chat engine (nothing to sweep), matching every other
    // sweep spawn on this line.
    let _memory_reembed_sweep =
        full.spawn_memory_reembed_sweep(std::time::Duration::from_secs(900));
    // GAP-FIX memory (PromotionPipeline-never-called) — periodic episodic→semantic condensation
    // checkpoint (design §3/§6) over the same served MEM-10 memory backing the two sweeps above
    // share: `PromotionPipeline::condense`/`write_candidates` were fully implemented and unit-tested
    // but had zero callers outside the crate, so an episodic record never actually distilled into a
    // durable semantic fact / user preference on any real deployment. `None` on a surface with no
    // chat engine (nothing to sweep).
    let _memory_promotion_sweep =
        full.spawn_memory_promotion_sweep(std::time::Duration::from_secs(600));
    // GAP-FIX ainxt-retrieval (gap6-retrieval-maintenance, item 1) — periodic KB index-maintenance
    // sweep: `ainxt_retrieval::maintenance`'s `IndexState`/`SourceEvent`/`ReindexTrigger`/
    // `RecallLatencyMonitor` were fully implemented and exhaustively unit-tested but had ZERO callers
    // anywhere in the workspace outside their own crate's tests — the served retrieval corpus was built
    // ONCE at boot (`corpus_for_scope`) with no ongoing freshness/health monitoring at all, so a
    // silently-changed KB document or a degraded vector index (bad `ef_search`, a partial rebuild)
    // would never be noticed by anything. Unconditional (unlike the memory sweeps above): every
    // assembled surface has a `[kb]` config (possibly empty) and the shared maintenance state
    // (`kb_index_state`/`kb_recall_monitor`) is always present — see
    // `AssembledFull::run_kb_maintenance_tick`'s doc for exactly what a tick decides, and its
    // `needs_hot_wiring` note on the still-missing live per-query recall/latency sampler.
    let _kb_maintenance_sweep =
        full.spawn_kb_maintenance_sweep(std::time::Duration::from_secs(300));
    // GAP-FIX ainxt-retrieval (gap6-retrieval-maintenance, item 2) — periodic KB corpus embedding-
    // migration sweep: `governed::run_kb_corpus_reembed` (itself a composition-root wrapper around
    // `ainxt_retrieval::reembed::migrate_to`) was fully implemented and unit-tested but had ZERO
    // callers anywhere in the workspace outside this crate's OWN tests
    // (`r19_embedding_lifecycle_served.rs`) — an audited composition-root wrapper nothing in the served
    // daemon, on any real cadence or route, ever actually drove. Unconditional (mirrors
    // `spawn_kb_maintenance_sweep` immediately above): every assembled surface has a `[kb]` config to
    // migrate. Target version mirrors this codebase's own stated embedding model
    // (`ainxt-retrieval::reembed`'s own doc: "a real deployment implements this with
    // services/embed_svc (Ollama nomic-embed-text)") — see `AssembledFull::run_kb_reembed_tick`'s doc
    // for the `needs_hot_wiring` note on live-corpus propagation.
    let _kb_reembed_sweep = full.spawn_kb_reembed_sweep(
        std::time::Duration::from_secs(3600),
        ainxt_retrieval::EmbeddingVersion::new("nomic-embed-text", 1),
    );
    // GAP-FIX regulated-fi-responsible-lifecycle (gap6, §6.3) — periodic retention/legal-hold sweep over
    // the served `/v1/regfi/*` retention store + the served-turn replay tier: `RetentionSweeper`/
    // `sweep_now` were fully implemented and unit-tested but had zero callers outside `ainxt-lifecycle`'s
    // own tests, and BOTH live erasure call sites mounted an explicitly empty tier slice — a deferred
    // erasure (hold released / floor elapsed) never fired automatically and never reached the real
    // conversational bytes even when it did. Unconditional (unlike the memory sweeps above): `retention`/
    // `replay_store` are mandatory `AssembledFull` fields, not gated on a configured chat engine.
    let _retention_sweep = full.spawn_retention_sweep(std::time::Duration::from_secs(300));
    // GAP-FIX memory (gap6, item 2) — periodic propose->triage->dispatch_gated pass over the SAME LIVE
    // ImprovementEngine `POST /feedback` writes into: the daemon captured feedback forever but nothing
    // ever read it back out. OrgKnowledge candidates route into the SAME MEM-10 memory backing (Draft
    // OKI, human-gated to authority); EvalCase candidates route into a real flywheel staging set.
    // Unconditional (unlike the memory sweeps above): `feedback_engine`/`eval_staging` are mandatory
    // `AssembledFull` fields — a surface with no chat engine simply reports OrgKnowledge `unrouted`
    // each tick (see `AssembledFull::run_feedback_flywheel_tick`'s doc).
    let _feedback_flywheel_sweep =
        full.spawn_feedback_flywheel_sweep(std::time::Duration::from_secs(600));
    // R13 (SRV-03) — spawn the attestation quote-refresh LOOP on daemon start (ADR-021 §8.3). On the
    // air-gapped default (no declared regulated pool) this is a no-op (`None`); a declared pool exposes
    // a refresher and the loop keeps it attested on the shipped served gate. The live-TEE QuoteSource is
    // needs_hot_wiring/infra — the offline StaticQuoteSource default produces no quotes, so a declared-
    // but-un-sourced pool stays honestly fail-closed rather than faking attestation.
    //
    // GAP-FIX serving-ops (ADR-021 §8.3, gap-2) — `[serving] attestation_manifest` is the config-driven
    // way to populate the three seams below for a fixed offline fleet: with no manifest declared, this
    // is byte-identical to before (the empty, honestly-inert trio); a declared manifest is materialized
    // via `AttestationManifest::build` in their place, so a deployment's pre-shared quotes/accepted
    // signatures/approved firmware-driver-binary hashes actually reach the refresh loop instead of the
    // permanently-empty defaults the audit found (which by construction could never admit any node).
    let (quote_source, sig_verifier, ref_values) = match &loaded.serving.attestation_manifest {
        Some(manifest) => {
            let (source, verifier, refs) = manifest.build();
            (
                std::sync::Arc::new(source)
                    as std::sync::Arc<dyn ainxt_serving::attestation::QuoteSource + Send + Sync>,
                std::sync::Arc::new(verifier)
                    as std::sync::Arc<
                        dyn ainxt_serving::attestation::SignatureVerifier + Send + Sync,
                    >,
                refs,
            )
        }
        None => (
            std::sync::Arc::new(ainxt_serving::attestation::StaticQuoteSource::new())
                as std::sync::Arc<dyn ainxt_serving::attestation::QuoteSource + Send + Sync>,
            std::sync::Arc::new(ainxt_serving::attestation::AllowListVerifier::new())
                as std::sync::Arc<dyn ainxt_serving::attestation::SignatureVerifier + Send + Sync>,
            ainxt_serving::attestation::ReferenceValues::new(),
        ),
    };
    let _attest_refresh = full.spawn_attestation_refresh(
        std::time::Duration::from_secs(30),
        quote_source,
        sig_verifier,
        ref_values,
    );
    // GAP-FIX serving-ops (SERVING_OPS.md §4, gap 37) — spawn the shard-group health-sweep LOOP on
    // daemon start, mirroring the attestation-refresh loop above for the analogous §4 gap: the audit
    // found `ShardHealthMonitor`'s poll→act body (`monitor_tick`) and drain-the-group recovery fully
    // implemented and tested, but nothing on the served daemon ever POLLED it on a cadence. On the
    // air-gapped default (no `[[serving.nodes]]` entry declares a `golden_hash`) this is a no-op
    // (`None`); a declared shard group gets a live cadence that keeps its health machine ticking.
    // needs_hot_wiring/infra: the live GPU interconnect-collective counters + canary-correctness probe
    // that would populate real observations are the deployment's fleet-telemetry seam — there is no
    // offline analogue for a live measurement (unlike `attestation_manifest`'s pre-shared quotes), so
    // this loop's sweeps genuinely observe nothing by default, honestly inert rather than faking a
    // health signal.
    let _health_sweep = full.spawn_health_sweep(std::time::Duration::from_secs(30));
    // GAP-FIX serving-ops (SERVING_OPS.md §3, gaps 26/W, round-15 LOW) — spawn the demand-EWMA
    // autoscale-decision LOOP on daemon start, mirroring the health-sweep loop above for the
    // analogous §3 gap: `AutoscaleController::tick` + `AutoscaleCadence` were fully implemented and
    // tested but nothing on the served daemon ever drove either on a cadence. On the default (no
    // `[serving.autoscale]` declared) this is a no-op (`None`); a declared tuning gets a live cadence
    // that keeps the demand-EWMA decision loop ticking. needs_hot_wiring/infra: the live per-model
    // request-rate telemetry that would populate real samples is the deployment's metrics seam — this
    // loop's recomputes genuinely have nothing to fold in by default, honestly inert.
    //
    // GAP-FIX gap6-composition-root (Item 1) — `spawn_autoscale_and_placement_tick` (the fuller
    // observe→decide→actuate sibling that ALSO drives the GPU bin-packing placement actuator over the
    // SAME decisions this tick makes) had ZERO callers anywhere, including this file: only the
    // narrower decision-only tick above was ever started, so a deployment declaring BOTH
    // `[serving.autoscale]` AND `[serving.placement]` never got the placement half converged on a
    // cadence — only a direct hand-driven call to `run_autoscale_and_placement_tick` would have
    // actuated it. Prefer the fuller tick whenever a placement fleet is declared.
    //
    // IMPORTANT (confirmed, not assumed): `spawn_autoscale_and_placement_tick` requires ALL THREE of
    // cadence+controller+actuator to build its loop (`?` on each `clone()`) — it returns `None` (no
    // loop AT ALL, not even the decision half) when `[serving.placement]` is undeclared. It must NOT
    // unconditionally replace `spawn_autoscale_tick` above: a deployment that declares
    // `[serving.autoscale]` alone (no placement — a legitimate, common shape) would silently LOSE its
    // autoscale decision loop entirely, a real regression `spawn_autoscale_tick`'s own None-only-when-
    // unconfigured contract does not have. This branch keeps that deployment shape byte-identical
    // (still calls the narrower `spawn_autoscale_tick`) while giving a deployment that declares BOTH
    // sections the fuller loop. Never spawn both over the SAME shared cadence/controller — each tick
    // would double the effective sweep rate and corrupt `AutoscaleCadence`'s due-or-not timing.
    let _autoscale_tick = if loaded.serving.placement.is_some() {
        full.spawn_autoscale_and_placement_tick(std::time::Duration::from_secs(30))
    } else {
        full.spawn_autoscale_tick(std::time::Duration::from_secs(30))
    };
    // GAP-FIX gap6-composition-root (Item 2) — spawn the chunked-prefill interleaving LOOP on daemon
    // start, mirroring the health-sweep/autoscale-tick pattern above for the analogous §2 gap:
    // `ServingGate::batch_step_tick` (chunked-prefill interleaving over the live `PreemptionScheduler`)
    // was fully implemented and unit-tested (`r_chunked_prefill_wired.rs`), and the assembly report
    // itself named the missing piece outright: a deployment with `[serving] chunked_prefill` declared
    // got the string "needs_hot_wiring: the async cadence timer, via spawn_batch_step_sweep" — the
    // daemon's own boot output confessed this loop was never started. `AssembledFull::
    // spawn_batch_step_sweep` self-gates on `ServingGate::has_chunked_prefill()` (verified: `false` by
    // default, matching every other conditionally-live cadence's absent-is-off shape) — spawning it
    // unconditionally here is the SAME pattern as `spawn_health_sweep`/`spawn_autoscale_tick` above:
    // `None` (no loop) on the default (no `chunked_prefill` declared); a declared value gets a live
    // loop advancing one decode step for every currently-running sequence, interleaved with a fresh
    // prefill-chunk budget, every `period`. NOTE the period here is deliberately much tighter than the
    // monitoring cadences above (health/autoscale, 30s): this loop drives actual per-token decode
    // progress on the live serving path (`PreemptionScheduler::advance(seq_id, 1)` per running sequence
    // per tick) — a 30s period would floor decode throughput to one step per 30s, which is a
    // production-breaking cadence, not a merely-coarse one. A real deployment tunes this to its own
    // decode-latency budget; 50ms is an illustrative, honestly-fast-enough-to-be-usable default.
    let _batch_step_sweep = full.spawn_batch_step_sweep(std::time::Duration::from_millis(50));
    // GAP-FIX prompt-governance (#1 constrained-decoding real served caller + #6 optimizer cadence) —
    // spawn the prompt-optimizer sweep LOOP on daemon start, mirroring every other conditionally-live
    // cadence above: on the air-gapped default (no OpenAI-schema/local provider configured with both
    // an endpoint and, for cloud, an API key) this is a no-op (`None`); a declared provider gets a
    // live cadence that drives a real ConstrainedLlmJudge/ModelSeam pair over the real Provider
    // Gateway. needs_hot_wiring/infra: the shipped illustrative gold-set/variants and the tick's own
    // private Registry (vs the actually-served one) are the deployment's further config/landing wire
    // — see `ainxt_runtimed::spawn_prompt_optimizer_tick`'s doc.
    let _prompt_optimizer_tick =
        ainxt_runtimed::spawn_prompt_optimizer_tick(&loaded, std::time::Duration::from_secs(3600));
    // GAP-FIX prompt (gap5-prompt-round2 Item A) — spawn the CanaryController promote/auto-rollback
    // sweep LOOP on daemon start. `governed::run_prompt_canary_sweep_tick` was already correctly wired
    // to a real `ServedPromptEngine` (see its own test in `governed.rs`), but nothing ever drove it on a
    // schedule — no `spawn_*_tick` wrapper existed at all. This builds ONE shared, config-sourced
    // `ServedPromptEngine` handle and spawns the periodic sweep over it; the SAME handle is passed to
    // the drift-monitor cadence below so both ticks observe/mutate one deployment, never two
    // disconnected engines. needs_hot_wiring/infra: `metrics_source` returns `None` here — there is no
    // live prod/canary-arm traffic sampler wired yet (see `governed::spawn_prompt_canary_tick`'s doc); a
    // deployment supplies a real sampler closure in its place. This engine is intentionally separate
    // from the `/v1/chat` transport's own prompt compile — `assemble_served_prompt_engine`'s own doc
    // already flags that unification as its OWN further wire, not this gap.
    let prompt_served_engine =
        ainxt_runtimed::governed::assemble_shared_served_prompt_engine_from_config(&loaded.runtime);
    let _prompt_canary_tick = ainxt_runtimed::governed::spawn_prompt_canary_tick(
        prompt_served_engine.clone(),
        ainxt_prompt::canary::CanaryController::default(),
        std::time::Duration::from_secs(300),
        || None,
    );
    // GAP-FIX prompt (gap5-prompt-round2 Item B) — spawn the continuous quality-drift monitor LOOP on
    // daemon start, over the SAME shared `ServedPromptEngine` handle the canary cadence above mutates
    // (never a second, disconnected engine). `ainxt_prompt::drift::DriftMonitor`/`DriftKey`/`Baseline`
    // were fully implemented and unit-tested but had zero callers anywhere in `ainxt-runtimed`/
    // `ainxt-server` — this installs every served family's deploy-time baseline once at spawn, then
    // checks each sampled/scored live turn `sampled_turn_source` supplies against it.
    // needs_hot_wiring/infra: `sampled_turn_source` returns `None` here — there is no live sampler/judge
    // wired yet (see `governed::spawn_prompt_drift_tick`'s doc); a deployment supplies a real
    // sampled-and-scored turn source in its place. A confirmed drift event is only logged, never
    // auto-applied — the same deliberate human-in-the-loop posture §8 documents.
    let _prompt_drift_tick = ainxt_runtimed::governed::spawn_prompt_drift_tick(
        prompt_served_engine,
        std::time::Duration::from_secs(300),
        || None,
    );
    // GAP-FIX providers-gemini-quality-tripwire (item 2) — spawn the provider-silent-update tripwire
    // cadence on daemon start, mirroring the prompt-canary/drift ticks above for the analogous gap:
    // `ainxt_quality::monitor::provider_silent_update`/`ProviderVerdict` (a Welch-t-test statistical
    // tripwire distinguishing a silent cloud-provider model-swap from an intentional, deployment-
    // initiated change) was fully implemented and unit-tested but had ZERO callers anywhere outside its
    // own `#[cfg(test)]`. Unlike the prompt canary/drift engine (which always has SOME compiled-in
    // default deployment to observe), there is no default frozen tripwire baseline for a provider that
    // was never registered with one, so `spawn_provider_silent_update_tick` self-gates on `baseline`
    // exactly like `spawn_autoscale_tick` self-gates on undeclared `[serving.autoscale]` tuning: `None`
    // here (the air-gapped default — no tripwire baseline registered) means no task is spawned at all.
    // needs_hot_wiring/infra: (1) `baseline` — there is no live "run the tripwire eval set against a
    // provider once at registration and freeze the scores" step wired yet; a deployment computes that
    // once (e.g. from its own eval harness) and supplies `Some((provider_id, scores))` here instead of
    // `None`; (2) `current_sample_source` returns `None` here — there is no live re-scored-tripwire
    // sampler wired yet (see `governed::spawn_provider_silent_update_tick`'s doc); a deployment supplies
    // a real re-scored-and-checked sample source in its place. A confirmed silent-swap verdict is only
    // logged, never auto-actioned — the same deliberate human-in-the-loop posture the prompt-drift tick
    // above documents for a confirmed drift event.
    let _provider_silent_update_tick = ainxt_runtimed::governed::spawn_provider_silent_update_tick(
        None,
        0.05,
        std::time::Duration::from_secs(300),
        || None,
    );
    eprintln!(
        "ainxt-runtimed: listening on http://{addr} (fully-wired: /healthz /readyz /v1/chat /v1/command /v1/replay \
         /v1/events /v1/observe /graph /v1/query_ledger /v1/infer /v1/harness/* /connectors/* \
         /v1/artifact /v1/replay/step)"
    );
    // serve_full_ext mounts the additive cluster surfaces (connector OAuth + artifact + step-replay)
    // alongside the base FullApp (which now also carries the harness invoke/run surface).
    ainxt_server::serve_full_ext(listener, full.to_full_app(), full.to_full_app_ext()).await;
}

fn fail(code: i32, msg: &str) -> ! {
    let _ = writeln!(std::io::stderr(), "ainxt-runtimed: error: {msg}");
    std::process::exit(code);
}

fn fail_usage(msg: &str) -> ! {
    let _ = writeln!(std::io::stderr(), "ainxt-runtimed: {msg}\n\n{HELP}");
    std::process::exit(2);
}
