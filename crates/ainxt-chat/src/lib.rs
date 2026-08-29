// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-chat — the Chat surface, assembled end-to-end over the runtime.
//!
//! Everything the other crates build in isolation, wired into one flow and proven together:
//!
//! ```text
//! user turn
//!   → response cache (scoping-safe: keyed by clearance + data-class; sensitive classes never cached)
//!   → ConversationManager
//!        → intent cascade (chitchat / QA / doc-gen / …)
//!        → referent/content resolution ("generate this as pdf" ⇒ the PRIOR answer, not the instruction)
//!        → grounded retrieval (ainxt-context, pre-rank clearance filter) + citations
//!        → prompt engine (model-agnostic assembly, reasoning depth, numeric discipline)
//!        → Engine  (StrongRedactor compliance-in/out · RBAC · provider failover · audit)
//!   → cache the fresh answer (cacheable classes only)
//! ```
//!
//! The point of this crate is **depth, not breadth**: an integration test drives a real multi-turn
//! chat through the assembled stack and asserts the cross-cutting behaviors (grounding, referent
//! resolution, streaming PAN redaction, RBAC denial, cache hit, and cache scoping) hold together —
//! the thing per-crate unit tests cannot show.
//!
//! Caching correctness for a regulated multi-tenant system: the cache key encodes the caller's
//! clearance and the turn's data class, and answers at or above [`ChatSurface::cacheable_max`] are
//! never cached. Retrieval is clearance-filtered, so two callers with the SAME clearance legitimately
//! share a cached answer; different clearances get different keys. Any further scoping dimension
//! (tenant / department) MUST be folded into the key by the enterprise layer — documented, not
//! silently assumed.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use ainxt_cache::{normalize, CacheConfig, Clock, Embedder, Partition, PartitionedCache};
use ainxt_compliance::StrongRedactor;
use ainxt_context::optimizer::RankGraph;
use ainxt_context::{hybrid_retriever, Citation, Corpus, EligibleModel, OptimizerConfig};
use ainxt_convo::GuardrailsConfig;
use ainxt_convo::{
    resolve_action, ActionKind, AnswerVerifier, ClarifyPolicy, ContentSource, ConversationManager,
    HeuristicClassifier, IntentClassifier, IntentResult, ManagerOutcome, Message, ModelCaps,
    ModelIntentClassifier, OutputFormat, PromptDeployment, SessionStore,
};
use ainxt_injection::{InjectionConfig, InjectionScanner};
use ainxt_prompt::registry::ModelFamily;
use ainxt_prompt::service::NullSink;
use ainxt_protocol::{Event, Request};
use ainxt_providers::{ConstrainedProvider, ProviderLabelModel};
use ainxt_runtime::router::ModelRouter;
use ainxt_runtime::{
    CancelToken, Engine, InMemoryAudit, RbacAuthorizer, TurnError, TurnHandler, TurnSummary,
};
use ainxt_serving::cache_isolation::PartitionKey;
use ainxt_types::{DataClass, Principal};

/// The engine-consumable **surface capability-scope authorizer** (gap SURF: non-chat surfaces execute
/// their DECLARED capabilities/connectors) — the enforcement that makes a surface actually run only the
/// tools/connectors it declares, on the LIVE served engine.
///
/// A [`SurfaceProfile`](ainxt_profile::SurfaceProfile) *offers* a fixed capability set (e.g. `code`
/// offers `tool.grep`/`tool.read`/`tool.edit`/`tool.bash`; `chat` offers only `chat.send`). The engine
/// consults [`Authorizer::authorize_tool`] before EVERY tool/connector dispatch; this wrapper narrows
/// that decision so a tool/connector capability the surface does **not** declare is refused — *even for
/// an admin principal whose broad RBAC would otherwise allow it*. The surface can never escalate the
/// principal (the base authorizer still runs), and it can only ever *narrow* to its declared set.
///
/// Scope predicate: only `tool.*` / `connector.*` capabilities are surface-scoped (the namespaced tool
/// dispatch caps). Any other capability (`chat.send`, session caps, …) defers to the base authorizer
/// unchanged, so wrapping never breaks non-tool authorization. A scoped `tool.<name>:<resource>` cap is
/// in scope when the surface offers either it or its unscoped base `tool.<name>` (least-privilege
/// composes with the engine's OBO resource check).
///
/// Built from the profile's offered capability list by the composition daemon:
/// `SurfaceScopedAuthorizer::new(Box::new(RbacAuthorizer), profile.capabilities.clone())`, then handed
/// to the surface engine — so the served non-chat surface's tool loop is bounded by its declaration.
/// Kept in `ainxt-chat` (not `ainxt-surface`) because it implements the engine's `Authorizer` trait,
/// and `ainxt-chat` already depends on `ainxt-runtime` (acyclic — `ainxt-surface` does not).
pub struct SurfaceScopedAuthorizer {
    base: Box<dyn ainxt_runtime::authz::Authorizer>,
    offered: std::collections::BTreeSet<String>,
}

impl SurfaceScopedAuthorizer {
    /// Wrap `base`, narrowing tool/connector authorization to the surface's `offered` capability set.
    pub fn new(
        base: Box<dyn ainxt_runtime::authz::Authorizer>,
        offered: impl IntoIterator<Item = String>,
    ) -> Self {
        SurfaceScopedAuthorizer {
            base,
            offered: offered.into_iter().collect(),
        }
    }

    /// Whether `capability` is surface-scoped (a namespaced tool/connector dispatch capability).
    fn is_scoped(capability: &str) -> bool {
        capability.starts_with("tool.") || capability.starts_with("connector.")
    }

    /// Whether the surface's offered set admits `capability` (itself, or its unscoped base for a
    /// `tool.<name>:<resource>` form).
    fn in_scope(&self, capability: &str) -> bool {
        if self.offered.contains(capability) {
            return true;
        }
        let base_cap = capability.split(':').next().unwrap_or(capability);
        self.offered.contains(base_cap)
    }
}

impl ainxt_runtime::authz::Authorizer for SurfaceScopedAuthorizer {
    fn authorize(&self, principal: &Principal, capability: &str) -> ainxt_runtime::authz::Decision {
        if Self::is_scoped(capability) && !self.in_scope(capability) {
            return ainxt_runtime::authz::Decision::Deny(format!(
                "capability '{capability}' is outside this surface's declared capability set"
            ));
        }
        self.base.authorize(principal, capability)
    }
}

/// The intent-classifier the assembled Chat surface runs (gap CONV-01). The runtime — never the
/// model — owns control-flow, so this is just *which* classifier fills the [`IntentClassifier`] seam:
///
/// * [`ChatClassifier::Heuristic`] — the deterministic Stage-1 tier, used when no live model is
///   configured (air-gapped / offline / classifier disabled).
/// * [`ChatClassifier::Model`] — the model-backed Stage-2 cascade
///   ([`ainxt_convo::ModelIntentClassifier`] over a provider-backed [`ainxt_providers::ProviderLabelModel`]),
///   used when a live model *is* configured. Held boxed so the surface is monomorphic regardless of
///   the concrete transport the daemon selected.
///
/// Boxing behind a local enum (rather than `ConversationManager<Box<dyn IntentClassifier>>`) keeps the
/// orphan rules happy — the blanket `Box<dyn _>: IntentClassifier` impl is not ours to add.
pub enum ChatClassifier {
    /// Deterministic Stage-1 tier — no model call.
    Heuristic(HeuristicClassifier),
    /// Model-backed Stage-2 cascade over a live provider.
    Model(Box<dyn IntentClassifier>),
}

impl IntentClassifier for ChatClassifier {
    fn classify(&self, message: &str, history: &[Message]) -> IntentResult {
        match self {
            ChatClassifier::Heuristic(h) => h.classify(message, history),
            ChatClassifier::Model(m) => m.classify(message, history),
        }
    }

    /// GAP-FIX conversation-intelligence "command pipelines never reach a served classifier": without
    /// this override, `ConversationManager<ChatClassifier>` (the type `ChatSurface` actually assembles)
    /// would fall through to `IntentClassifier`'s DEFAULT `classify_with_commands` — which ignores
    /// `commands` and calls `classify()` above — so a real registered registry would never reach
    /// either inner classifier's own `classify_with_commands` override, even though both
    /// `HeuristicClassifier` and `ModelIntentClassifier` implement it correctly. Forwarding here is
    /// what makes the fix reach the SERVED surface, not just the two classifiers in isolation.
    fn classify_with_commands(
        &self,
        message: &str,
        history: &[Message],
        commands: &ainxt_convo::command_pipeline::CommandPipelineRegistry,
    ) -> IntentResult {
        match self {
            ChatClassifier::Heuristic(h) => h.classify_with_commands(message, history, commands),
            ChatClassifier::Model(m) => m.classify_with_commands(message, history, commands),
        }
    }
}

/// The reply from one chat turn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChatReply {
    /// A grounded/answered turn. `from_cache` is true when served from the response cache.
    Answer {
        text: String,
        provider: String,
        citations: Vec<Citation>,
        from_cache: bool,
    },
    /// A generated artifact (doc-gen intent) — content resolved from context, never the instruction.
    /// R16 fix: `document` is the REAL `ainxt_artifact::Document` IR `ConversationManager` built
    /// from `content` — the pre-built structure `ainxt_artifact::ArtifactRuntime::generate` /
    /// `POST /v1/artifact` require, so a caller of this reply can render immediately instead of
    /// having no live path from a chat turn to a real renderer.
    Document {
        format: OutputFormat,
        content: String,
        document: ainxt_artifact::Document,
    },
    /// A content-consuming action ("summarize the above and email it") — gap CONV-08. `content` is the
    /// resolved **referent** (the prior answer / explicit subject), with the instruction verb phrase
    /// EXCLUDED (instruction ≠ content). The surface hands `(action, content)` to the delivery/
    /// transform layer; this is never cached (it depends on live conversation context).
    Action { action: ActionKind, content: String },
    /// A registered git-native command pipeline matched (GAP-FIX conversation-intelligence "command
    /// pipelines never reach a served classifier") — `expanded_steps` are `name`'s ordered prompt
    /// templates with `{args}`/`{step_N}` already resolved (`ainxt_convo::command_pipeline::expand`).
    Command {
        name: String,
        expanded_steps: Vec<String>,
    },
    /// The runtime needs a clarification before it can act.
    Clarify { question: String },
}

/// The default harness/surface id folded into the cache [`PartitionKey`] so a chat entry can never
/// collide with another surface's (SDLC / Buddy / …) entry at the same data-class + scope (SRV-06).
pub const CHAT_HARNESS_ID: &str = "chat";

/// The default model family the served layered Prompt Service compiles the chat Role's per-model
/// variant for (`PROMPT_ENGINEERING.md` §7). [`PromptDeployment::served_default`] guarantees the
/// family has a served variant (adding it if absent), so the served prompt never fails closed on the
/// configured model; a deployment that pins a specific self-hosted family rebuilds with its own.
pub const DEFAULT_CHAT_FAMILY: &str = "claude";

/// The served-default Context-Fabric window config ([`ainxt_context::compile_window`]). Carries one
/// generous eligible-model window so the two-phase budget fit includes retrieved chunks (an EMPTY
/// eligible set floors the window to zero and would ground nothing). A deployment overrides
/// `eligible` from the Model Router's task-type ∩ data-class resolution; this default keeps live
/// grounding active out of the box. PageRank/freshness use [`OptimizerConfig::default`] weights.
///
/// Gap context-fabric (budget-fit fake eligible list): `eligible` now comes from
/// [`ModelRouter::eligible_ids`] — the SAME non-overridable data-class-exclusion +
/// FI-03/FI-07-governance admission test [`ModelRouter::select`] uses — so the two-phase budget fit
/// floors to a model this router would actually route the turn to, not an unrelated hardcoded id.
/// A router with no admissible provider for `data_class` (e.g. an unconfigured test engine) falls
/// back to the single generous placeholder window, preserving the documented safety property: an
/// EMPTY eligible set floors the window to zero and would ground nothing.
fn served_window(router: &ModelRouter, data_class: DataClass) -> OptimizerConfig {
    let ids = router.eligible_ids(data_class);
    let eligible = if ids.is_empty() {
        vec![EligibleModel::new("served-default", 8000)]
    } else {
        ids.iter().map(|id| EligibleModel::new(id, 8000)).collect()
    };
    OptimizerConfig {
        eligible,
        ..OptimizerConfig::default()
    }
}

/// Build the served [`RankGraph`] from the corpus that backs THIS surface (gap context-fabric:
/// `assemble_with_prompt` never called [`ainxt_convo::ConversationManager::with_context_graph`],
/// so `graph: None` reached [`ainxt_context::compile_window`] on every live turn — PageRank never
/// ran, it silently degraded to lexical-only ranking).
///
/// Nodes are the corpus's chunk ids; an edge connects two chunks that share the same `source`
/// document (`CONTEXT_FABRIC.md` §3's "unified graph" reduced to the one structural relation the
/// served [`Corpus`] actually carries pre-KG-ingestion: chunks of the same document co-reference
/// each other). No query seeds are supplied here — [`with_context_graph`](ainxt_convo::ConversationManager::with_context_graph)
/// is a construction-time seam, fixed before any turn's query is known, and
/// [`personalized_pagerank`](ainxt_context::optimizer::personalized_pagerank) documents that an
/// empty seed set falls back cleanly to uniform (ordinary) PageRank rather than grounding nothing.
/// An empty corpus yields an empty graph, which `compile_window` also handles safely (no ranking
/// boost, identical to the pre-wiring behavior) — this never narrows what the flat retriever would
/// have surfaced.
fn build_rank_graph(corpus: &Corpus) -> RankGraph {
    let mut graph = RankGraph::new();
    for chunk in &corpus.chunks {
        graph = graph.with_node(&chunk.id);
    }
    for (i, a) in corpus.chunks.iter().enumerate() {
        for b in corpus.chunks.iter().skip(i + 1) {
            if a.source == b.source {
                graph = graph.with_edge(&a.id, &b.id).with_edge(&b.id, &a.id);
            }
        }
    }
    graph
}

/// The assembled Chat surface.
pub struct ChatSurface {
    manager: ConversationManager<ChatClassifier>,
    /// Partition-isolated response cache (SRV-06): each `{data_class, principal_scope, harness_id}`
    /// partition owns an independent store, so a lookup can only ever reach its own partition — no
    /// cross-tenant / cross-department read path.
    ///
    /// `Arc<Mutex<..>>`, not a bare `Mutex` (R16 CRITICAL, serving-ops): the DPDP right-to-erasure
    /// cascade must purge the SAME cache instance this surface's served turn path reads/writes, never
    /// a second, disconnected copy. [`ChatSurface::answer_cache_handle`] hands the composition root a
    /// clone of this `Arc` so it can build the daemon's `ainxt_serving::erasure::TieredCacheErasure`
    /// organ over it (`TieredCacheErasure::with_shared_answer_cache`) — a genuine shared instance, not
    /// an erasure organ that drains an empty cache while this one keeps serving stale answers.
    cache: Arc<Mutex<PartitionedCache>>,
    clock: Box<dyn Clock>,
    /// Answers at or below this sensitivity may be cached; anything more sensitive is never cached.
    cacheable_max: DataClass,
    /// The harness/surface id that scopes this surface's cache partitions.
    harness_id: String,
    /// The embed-service seam for the SEMANTIC (paraphrase) cache tier (gap I, live-path wiring).
    /// `None` (the default from every existing constructor) degrades safely to exact/normalized-only
    /// lookups — byte-identical to the pre-wiring behavior. [`ChatSurface::with_embedder`] opts a
    /// surface into the paraphrase tier without changing any constructor signature.
    embedder: Option<Arc<dyn Embedder>>,
}

impl ChatSurface {
    /// Assemble the Chat surface: a real [`Engine`] with the [`StrongRedactor`] compliance gate, a
    /// grounded retriever over `corpus`, the prompt engine, and a response cache.
    pub fn new(
        router: ModelRouter,
        corpus: Corpus,
        cache_cfg: CacheConfig,
        clock: Box<dyn Clock>,
    ) -> Self {
        let engine = Engine::new(
            Box::new(StrongRedactor::new()),
            Box::new(RbacAuthorizer),
            Box::new(InMemoryAudit::default()),
            router,
        );
        Self::from_engine(engine, corpus, cache_cfg, clock)
    }

    /// Assemble the Chat surface over an **already-built** [`Engine`] — the daemon-consumable
    /// constructor (gap SURF-02/03). The composition binary ([`ainxt-runtimed`]) selects the
    /// mandatory gates (fail-closed on an enterprise gate), builds the engine + router, and hands it
    /// here; this crate adds the grounded retriever + prompt engine + scoping-safe cache and exposes
    /// the result as a [`TurnHandler`] the `SessionManager` serves. This is what lets the served chat
    /// path GROUND + CITE + CACHE, instead of the bare no-retriever [`ConversationManager::new`].
    ///
    /// Wiring (parent, in `ainxt-runtimed`): the REAL served `/v1/chat` default composes this family
    /// via `assemble_surface` → `build_chat_surface_wired_authz` (which actually calls
    /// `Self::from_engine_classified_numeric_gated_with_prompt`, not the bare constructor below);
    /// `ainxt-runtimed::assemble_chat` builds the same family un-profiled via `build_chat_surface_wired`
    /// but is NOT the served default (see that function's own doc comment). This snippet shows the
    /// simplest constructor for illustration only:
    /// ```ignore
    /// let chat = ainxt_chat::ChatSurface::from_engine(engine, corpus, cache_cfg, clock);
    /// let sm = std::sync::Arc::new(SessionManager::new(std::sync::Arc::new(chat), session_cfg));
    /// ```
    pub fn from_engine(
        engine: Engine,
        corpus: Corpus,
        cache_cfg: CacheConfig,
        clock: Box<dyn Clock>,
    ) -> Self {
        Self::assemble(
            engine,
            corpus,
            cache_cfg,
            clock,
            ChatClassifier::Heuristic(HeuristicClassifier),
            None,
            false,
        )
    }

    /// Assemble the served Chat surface with the **numeric re-derivation hard gate ON** — the served
    /// ledger/answer default (task R7 §2). Every answer runs the numeric gate: a stated figure that
    /// does not survive server-side re-derivation is BLOCKED + escalated (a payment-incident signal
    /// that must never ship), while faithfulness + conflict stay non-blocking presentation caveats
    /// (redact-don't-block mandate). Unlike [`from_engine_verified`](Self::from_engine_verified) (the
    /// full payments gate, which also hard-blocks any unsourced claim), this default does NOT escalate
    /// a legitimate no-number / offline answer — so the numeric gate can be the SERVED default without
    /// degrading ordinary chat. Heuristic classifier (see
    /// [`from_engine_classified_numeric_gated`](Self::from_engine_classified_numeric_gated) for the
    /// model cascade).
    pub fn from_engine_numeric_gated(
        engine: Engine,
        corpus: Corpus,
        cache_cfg: CacheConfig,
        clock: Box<dyn Clock>,
        row_isolation: bool,
    ) -> Self {
        Self::assemble(
            engine,
            corpus,
            cache_cfg,
            clock,
            ChatClassifier::Heuristic(HeuristicClassifier),
            Some(AnswerVerifier::numeric_gate_only()),
            row_isolation,
        )
    }

    /// [`from_engine_numeric_gated`](Self::from_engine_numeric_gated) + the model-backed intent cascade
    /// (gap CONV-01): the served ledger default WITH the Stage-2 constrained classifier when a live
    /// grammar/schema-capable provider is configured, falling back to the deterministic heuristic when
    /// none is (air-gapped). The numeric re-derivation hard gate runs either way.
    pub fn from_engine_classified_numeric_gated<P: ConstrainedProvider + 'static>(
        engine: Engine,
        corpus: Corpus,
        cache_cfg: CacheConfig,
        clock: Box<dyn Clock>,
        live_model: Option<(P, ModelCaps)>,
        row_isolation: bool,
    ) -> Self {
        let classifier = match live_model {
            Some((provider, caps)) => {
                let label_model = ProviderLabelModel::new(provider, caps.grammar_constrained);
                // Chat surface: never clarify — always answer. The default ClarifyPolicy gates on
                // min_confidence 0.7, but plain Q&A grades at 0.5, so normal statements like "My
                // name is Vishnu" triggered a clarify ("I didn't quite catch that") instead of
                // reaching the LLM — breaking multi-turn context (the name was never sent to the
                // model, so "what is my name?" couldn't recall it). Clarify is for agentic surfaces
                // where a wrong dispatch has side effects; chat's job is to answer.
                //
                // fallback_on_parse_failure: when the model-backed classifier's own LLM call returns
                // an unparseable label (or the call fails), the default behavior is to clarify — but
                // that intermittently bounced normal messages like "My Fav color is blue" (the
                // classifier LLM sometimes garbles its label, sometimes doesn't — non-deterministic).
                // For chat, a parse failure must fall back to Q&A and still answer, never clarify.
                ChatClassifier::Model(Box::new(
                    ModelIntentClassifier::new(label_model, caps).with_policy(ClarifyPolicy {
                        min_confidence: 0.0,
                        clarify_on_ambiguous: false,
                        max_attempts: 2,
                        fallback_on_parse_failure: true,
                        fallback_label: "qa",
                    }),
                ))
            }
            None => ChatClassifier::Heuristic(HeuristicClassifier),
        };
        Self::assemble(
            engine,
            corpus,
            cache_cfg,
            clock,
            classifier,
            Some(AnswerVerifier::numeric_gate_only()),
            row_isolation,
        )
    }

    /// [`Self::from_engine_numeric_gated`] but with a caller-supplied [`PromptDeployment`] (R14): the
    /// served ledger/answer default, driven through a Prompt Service whose forensic sink + registry
    /// source the daemon controls — so the served chat compile writes a durable forensic prompt record
    /// BEFORE the provider call (PE11), and (when configured) serves git-native FILE-sourced prompt
    /// bodies (§3). Heuristic classifier.
    pub fn from_engine_numeric_gated_with_prompt(
        engine: Engine,
        corpus: Corpus,
        cache_cfg: CacheConfig,
        clock: Box<dyn Clock>,
        row_isolation: bool,
        prompt: PromptDeployment,
    ) -> Self {
        Self::assemble_with_prompt(
            engine,
            corpus,
            cache_cfg,
            clock,
            ChatClassifier::Heuristic(HeuristicClassifier),
            Some(AnswerVerifier::numeric_gate_only()),
            row_isolation,
            prompt,
        )
    }

    /// [`Self::from_engine_classified_numeric_gated`] but with a caller-supplied [`PromptDeployment`]
    /// (R14) — the served default WITH the model-backed intent cascade AND the daemon's forensic /
    /// git-native prompt deployment.
    pub fn from_engine_classified_numeric_gated_with_prompt<P: ConstrainedProvider + 'static>(
        engine: Engine,
        corpus: Corpus,
        cache_cfg: CacheConfig,
        clock: Box<dyn Clock>,
        live_model: Option<(P, ModelCaps)>,
        row_isolation: bool,
        prompt: PromptDeployment,
    ) -> Self {
        // GAP-FIX conversation-intelligence — `None` (no live grammar/schema-capable provider
        // configured) previously fell back to the bare deterministic-tier `HeuristicClassifier`,
        // leaving `ainxt_convo::ModelIntentClassifier::offline()` (a REAL confidence-graded
        // classify -> clarify decision — Stage-3 "ask third" — over the zero-infra `LexicalLabelModel`)
        // reachable only from `ainxt-convo`'s own tests. This is the exact fix its own doc comment
        // names: still zero infra/network/model calls, but Stage-3 is now genuinely active on the
        // shipped air-gapped default instead of dead code.
        let classifier = match live_model {
            Some((provider, caps)) => {
                let label_model = ProviderLabelModel::new(provider, caps.grammar_constrained);
                ChatClassifier::Model(Box::new(ModelIntentClassifier::new(label_model, caps)))
            }
            None => ChatClassifier::Model(Box::new(ModelIntentClassifier::offline())),
        };
        Self::assemble_with_prompt(
            engine,
            corpus,
            cache_cfg,
            clock,
            classifier,
            Some(AnswerVerifier::numeric_gate_only()),
            row_isolation,
            prompt,
        )
    }

    /// Assemble the served Chat surface with the fail-closed answer-path **verifier** ON (the
    /// compile/verify numeric re-derivation gate + faithfulness/conflict, gap CTX-06/09): a stated
    /// figure not attributable to a retrieved source is BLOCKED and escalated, never shipped. The
    /// payments-surface constructor — everything else matches [`ChatSurface::from_engine`]
    /// (compile_window grounding, layered Prompt Service, answer composition; heuristic classifier).
    pub fn from_engine_verified(
        engine: Engine,
        corpus: Corpus,
        cache_cfg: CacheConfig,
        clock: Box<dyn Clock>,
    ) -> Self {
        Self::assemble(
            engine,
            corpus,
            cache_cfg,
            clock,
            ChatClassifier::Heuristic(HeuristicClassifier),
            Some(AnswerVerifier::new()),
            false,
        )
    }

    /// Assemble the Chat surface, deciding the intent classifier from whether a **live model** is
    /// configured (gap CONV-01, `CONVERSATION_INTELLIGENCE.md` §2 Stage-2 / §5):
    ///
    /// * `Some((provider, caps))` → the model-backed cascade: an [`ainxt_convo::ModelIntentClassifier`]
    ///   over a provider-backed [`ainxt_providers::ProviderLabelModel`], capability-aware
    ///   (`caps.grammar_constrained` selects grammar-pinned vs. prompt-steered extraction, CONV-03).
    /// * `None` → the deterministic [`HeuristicClassifier`] (air-gapped / offline / disabled).
    ///
    /// Either way the runtime — not the model — owns control-flow; the model only classifies.
    pub fn from_engine_classified<P: ConstrainedProvider + 'static>(
        engine: Engine,
        corpus: Corpus,
        cache_cfg: CacheConfig,
        clock: Box<dyn Clock>,
        live_model: Option<(P, ModelCaps)>,
    ) -> Self {
        let classifier = match live_model {
            Some((provider, caps)) => {
                // The adapter's extraction technique must agree with the cascade's prompt strategy:
                // both read the SAME `grammar_constrained` flag.
                let label_model = ProviderLabelModel::new(provider, caps.grammar_constrained);
                ChatClassifier::Model(Box::new(ModelIntentClassifier::new(label_model, caps)))
            }
            None => ChatClassifier::Heuristic(HeuristicClassifier),
        };
        Self::assemble(engine, corpus, cache_cfg, clock, classifier, None, false)
    }

    /// The single assembly site (gap CONV-01/CTX-fabric/PRMT-01): the SERVED RICH defaults, not the
    /// flat placeholders. The grounded [`ConversationManager`] over `classifier` is assembled with:
    ///
    /// * the **Context-Fabric window** ([`ConversationManager::with_context_window`],
    ///   [`ainxt_context::compile_window`]) as the grounding path — full OBO [`AccessContext`]
    ///   pre-rank RBAC (class + department + `ad_level` + groups) + RLS + PageRank + freshness +
    ///   eligible-floor budget-fit — instead of the flat class-only `assemble`. A low-clearance /
    ///   wrong-department caller therefore grounds NOTHING on the served path;
    /// * the **layered per-model Prompt Service** ([`ConversationManager::with_prompt_service`],
    ///   [`PromptDeployment::served_default`]) as the DEFAULT system-prompt assembly — instead of the
    ///   flat single-string prompt engine (PRMT-01/06). Offline + deterministic ([`NullSink`]);
    /// * `ainxt-answer` composition (CONV-10 right-size + citation rendering).
    ///
    /// When `verify` is set, the fail-closed answer-path verifier ([`AnswerVerifier`]) also runs —
    /// the numeric re-derivation gate of the compile/verify path (a stated figure not attributable to
    /// a source is BLOCKED, never shipped). It is OFF by default because a surface whose provider
    /// does not declare sourced numeric claims would otherwise gate every legitimate figure; a
    /// payments surface opts in via [`ChatSurface::from_engine_verified`].
    fn assemble(
        engine: Engine,
        corpus: Corpus,
        cache_cfg: CacheConfig,
        clock: Box<dyn Clock>,
        classifier: ChatClassifier,
        verifier: Option<AnswerVerifier>,
        row_isolation: bool,
    ) -> Self {
        // Default prompt deployment: the shipped canonical served-default over a NullSink (no forensic
        // persistence). The daemon-facing `*_with_prompt` constructors inject a deployment that owns a
        // durable `ForensicFileSink` (PE11) and/or a git-native FILE-sourced registry (§3).
        Self::assemble_with_prompt(
            engine,
            corpus,
            cache_cfg,
            clock,
            classifier,
            verifier,
            row_isolation,
            PromptDeployment::served_default(
                ModelFamily::new(DEFAULT_CHAT_FAMILY),
                Box::new(NullSink),
            ),
        )
    }

    /// [`Self::assemble`] but with a caller-supplied [`PromptDeployment`] — the seam the daemon uses to
    /// inject the durable forensic sink (PE11) and/or the git-native FILE-sourced prompt registry (§3)
    /// into the served chat compile, instead of the constant deployment over a `NullSink`.
    #[allow(clippy::too_many_arguments)]
    fn assemble_with_prompt(
        engine: Engine,
        corpus: Corpus,
        cache_cfg: CacheConfig,
        clock: Box<dyn Clock>,
        classifier: ChatClassifier,
        verifier: Option<AnswerVerifier>,
        row_isolation: bool,
        prompt: PromptDeployment,
    ) -> Self {
        // Gap context-fabric (budget-fit fake eligible list): resolve the real tier-eligible set
        // from the engine's OWN router BEFORE `engine` moves into `with_retriever` below — this is
        // the same admission test the engine's own dispatch uses, so the window floors to a model
        // this surface would actually route to.
        let window_cfg = served_window(engine.router(), DataClass::Internal);
        // Gap CTX-01/CTX-fabric: the served path grounds through the PRODUCTION hybrid
        // (BM25 + RRF + rerank, pre-rank chunk-level ACL) retriever — not the lexical placeholder.
        // `hybrid_retriever` is the single ready drop-in over a populatable [`Corpus`]; the daemon
        // seeds that corpus from the KB before assembly, so live grounding retrieves real documents
        // with real citations. An empty corpus keeps every other behavior valid (grounds nothing).
        let mut manager =
            ConversationManager::with_retriever(engine, classifier, hybrid_retriever(&corpus))
                // Gap CTX-fabric: ground through `compile_window` (full-AccessContext pre-rank RBAC +
                // RLS + PageRank + freshness + eligible-floor fit), not the flat class-only assemble.
                .with_context_window(window_cfg)
                // Gap context-fabric (PageRank dormant): bind a REAL RankGraph built from this
                // surface's own corpus so `compile_window` actually fuses a personalized-PageRank
                // score into ranking instead of silently degrading to lexical-only every turn.
                .with_context_graph(build_rank_graph(&corpus), BTreeMap::new())
                // Gap PRMT-01/06: the layered per-model Prompt Service is the served default. R14: the
                // deployment (its forensic sink + registry source) is injected by the caller.
                .with_prompt_service(prompt)
                // Gap CONV-10: right-size (BM) + structure (BK) + render citations (BN) via ainxt-answer.
                .with_answer_format()
                // R16 CRITICAL (guardrails-injection): scan RETRIEVED content for indirect prompt
                // injection ON THE SERVED PATH. The detector and the `with_injection` seam both
                // existed, but no surface ever set it, so the shipped daemon grounded on unscanned
                // third-party text — the #1 agentic attack vector: the user never typed "wire the
                // funds", a poisoned KB chunk or connector email did.
                //
                // ON BY DEFAULT here, not opt-in: a defense a deployment must remember to enable is
                // a defense that is off in production. `Enforce` taints the turn so the engine gates
                // side-effecting tools; it does NOT block the answer — grounding still proceeds and
                // the user still gets a reply (redact-and-proceed applies to the whole pipeline, not
                // just PII).
                .with_injection(InjectionConfig::recommended());
        // Gap AJ / CTX §8.3: bind the RLS row-filter (department isolation) from the OBO principal on
        // the served window so the row-level pass is ENFORCED pre-rank (fail-closed). Opt-in — a corpus
        // whose rows carry no `department` RLS label grounds unchanged with the flag off.
        if row_isolation {
            manager = manager.with_row_isolation();
        }
        if let Some(v) = verifier {
            manager = manager.with_verifier(v);
        }
        ChatSurface {
            manager,
            cache: Arc::new(Mutex::new(PartitionedCache::new(cache_cfg))),
            clock,
            cacheable_max: DataClass::Internal,
            harness_id: CHAT_HARNESS_ID.to_string(),
            embedder: None,
        }
    }

    /// **R16 CRITICAL fix (serving-ops)**: the live handle to this surface's answer cache — the SAME
    /// `Arc<Mutex<PartitionedCache>>` [`ChatSurface::turn`] and [`TurnHandler::handle_turn`] read and
    /// populate on every served turn. The composition root calls this once, right after building the
    /// surface, and hands the clone to
    /// [`ainxt_serving::erasure::TieredCacheErasure::with_shared_answer_cache`] so the daemon's DSAR/
    /// right-to-erasure organ purges exactly the entries the served chat path actually created — not a
    /// second, never-populated cache (the audit's "erasure ack is vacuous" finding). Cloning an `Arc`
    /// is cheap and never copies cache contents.
    pub fn answer_cache_handle(&self) -> Arc<Mutex<PartitionedCache>> {
        self.cache.clone()
    }

    /// Opt this surface into the **semantic (paraphrase) cache tier** on the live path (gap I): a
    /// query embedded via `embedder` that lands within the configured cosine threshold of a fresh
    /// cached entry hits without a fresh model call, on both [`ChatSurface::turn`] and the served
    /// [`TurnHandler::handle_turn`] path. Every existing constructor defaults to `None` (exact/
    /// normalized-only, the pre-wiring behavior); the daemon composition calls this once with the
    /// real (or offline [`ainxt_cache::HashEmbedder`]) embed seam to make the tier LIVE.
    pub fn with_embedder(mut self, embedder: Arc<dyn Embedder>) -> Self {
        self.embedder = Some(embedder);
        self
    }

    /// GAP-FIX conversation-intelligence "command pipelines never reach a served classifier": register
    /// this deployment's git-native command pipelines
    /// ([`ainxt_convo::command_pipeline::CommandPipelineRegistry`]) so BOTH the served [`Self::turn`]
    /// and [`TurnHandler::handle_turn`] paths recognize a registered `/name` macro (via
    /// [`ainxt_convo::IntentClassifier::classify_with_commands`], which `ConversationManager` now
    /// always calls). Every existing constructor defaults to an empty registry (matches no commands,
    /// byte-for-byte the pre-wiring behavior) — a deployment opts in by calling this once at assembly,
    /// the same posture as [`Self::with_embedder`]/[`Self::with_guardrails`] above.
    pub fn with_command_registry(
        mut self,
        registry: ainxt_convo::command_pipeline::CommandPipelineRegistry,
    ) -> Self {
        self.manager = self.manager.with_command_registry(registry);
        self
    }

    /// GUARD-09/GUARD-07: attach the output-side guardrails config (groundedness/toxicity/topic/
    /// citation) to this surface's `ConversationManager`. Every served-daemon `ChatSurface`
    /// constructor built its manager with NO guardrails config at all (`self.guardrails` stayed
    /// `None` unconditionally) — so `[guardrails] groundedness = "enforce"` in a deployment's config
    /// had no effect on the actual served chat path; the rail existed and was unit-tested purely in
    /// isolation. Every constructor defaults to no-op (`GuardrailsConfig::default()`, all rails Off,
    /// the pre-wiring behavior); the daemon composition calls this once with the real config.
    pub fn with_guardrails(mut self, cfg: GuardrailsConfig) -> Self {
        self.manager = self.manager.with_guardrails(cfg);
        self
    }

    /// GAP-FIX guardrails-injection — swap the RETRIEVED-content injection scanner (ADR-009) this
    /// surface uses to scan RAG chunks for indirect prompt injection. Every constructor builds the
    /// manager over the bare `HeuristicInjectionScanner` (default detector, empty `known_tool_names`),
    /// so the "a retrieved document naming an internal tool is a strong signal" detection category
    /// could never fire on the served path — the registry's real tool names never reached the
    /// detector, only a manually-supplied list in the crate's own tests did. The daemon composition
    /// calls this once with a detector built from the served `ToolRuntime`'s actual registered names
    /// (`ainxt_tools::ToolRuntime::tool_names`).
    pub fn with_injection_scanner(mut self, scanner: Box<dyn InjectionScanner>) -> Self {
        self.manager = self.manager.with_injection_scanner(scanner);
        self
    }

    /// GAP-AUDIT conversation-intelligence #2 — swap this surface's session-history store for a
    /// durable one (e.g. `ainxt_convo::PersistentSessions`). Every constructor builds the manager
    /// over the default `InMemorySessions`, so every served conversation's turn history — and the
    /// referent-resolution fix that depends on reading it back — was lost on daemon restart. Every
    /// constructor is unaffected until this is called; the daemon composition calls it once with a
    /// real durable store to make history restart-survivable.
    pub fn with_session_store(mut self, store: Box<dyn SessionStore>) -> Self {
        self.manager = self.manager.with_session_store(store);
        self
    }

    /// Embed `input` through the configured seam, or `None` when no embedder is wired (safe
    /// degrade to exact-only) or the embedder itself declines (e.g. empty/unembeddable text).
    fn query_embedding(&self, input: &str) -> Option<Vec<f32>> {
        self.embedder.as_ref().and_then(|e| e.embed(input))
    }

    /// Assemble the served Chat surface **for a resolved [`SurfaceProfile`]**, deriving the served
    /// retrieval-isolation decision from the profile's declaration (gap: *profile department scoping
    /// is declared but not wired into served retrieval isolation*).
    ///
    /// A profile's [`rbac.department_scoped`](ainxt_profile::RbacPolicy::department_scoped) says "data
    /// for this surface is scoped by the principal's department". Until now that declaration only
    /// gated *admission* ([`SurfaceBinding::admit`](ainxt_profile) refuses a department-less principal)
    /// — the served retrieval path still had to be told, out-of-band, to bind the RLS department
    /// row-filter. This constructor closes that: it maps `department_scoped` straight onto the served
    /// surface's `row_isolation`, so a department-scoped profile's grounded retrieval ENFORCES
    /// department isolation pre-rank (a row whose `department` attribute is not the caller's own is
    /// never scored — existence never leaks), and a non-department-scoped profile grounds unchanged.
    ///
    /// Everything else matches [`from_engine_numeric_gated`](Self::from_engine_numeric_gated) (the
    /// served ledger/answer default: grounded `compile_window` retrieval, layered Prompt Service,
    /// numeric re-derivation hard gate, scoping-safe cache). The composition daemon calls this with the
    /// catalog-resolved profile so the declared scoping is LIVE on the served path — no separate flag.
    pub fn from_engine_for_profile(
        engine: Engine,
        corpus: Corpus,
        cache_cfg: CacheConfig,
        clock: Box<dyn Clock>,
        profile: &ainxt_profile::SurfaceProfile,
    ) -> Self {
        Self::from_engine_numeric_gated(
            engine,
            corpus,
            cache_cfg,
            clock,
            Self::profile_row_isolation(profile),
        )
    }

    /// The served **row-isolation** decision a profile implies: a surface whose profile declares
    /// `rbac.department_scoped` grounds under the department RLS row-filter. This is the single bridge
    /// from the declarative profile to the served retrieval-isolation flag, exposed so the composition
    /// daemon (and tests) derive it one way — never by re-reading the field ad hoc.
    pub fn profile_row_isolation(profile: &ainxt_profile::SurfaceProfile) -> bool {
        profile.rbac.department_scoped
    }

    /// The highest data-class sensitivity that is eligible for caching (default: `Internal`).
    pub fn cacheable_max(&self) -> DataClass {
        self.cacheable_max
    }

    fn cacheable(&self, dc: DataClass) -> bool {
        dc.sensitivity() <= self.cacheable_max.sensitivity()
    }

    /// The cache **partition** for this caller + data class (SRV-06): `{data_class, principal_scope,
    /// harness_id}`, where `principal_scope` is per-user for confidential+ and per-department for
    /// internal/public (`ainxt_serving::cache_isolation`). A department-less principal degrades to
    /// per-user isolation (fail-safe, never a broader share). Isolation is structural — a lookup can
    /// only ever reach its own partition's store.
    fn partition(&self, principal: &Principal, dc: DataClass) -> Partition {
        let pk = PartitionKey::resolve(
            dc,
            &principal.user_id,
            principal.department.as_deref(),
            &self.harness_id,
        );
        Partition::new(pk.render())
    }

    /// The within-partition entry key. Clearance stays in the key so an answer produced under
    /// clearance-filtered retrieval is NEVER served across clearances — the "never cross clearance"
    /// invariant — even inside a shared department partition.
    fn cache_key(&self, clearance: DataClass, session: &str, input: &str) -> String {
        // Session-scoped: without the session id in the key, two different questions in
        // different conversations could collide on the semantic (paraphrase) tier — the
        // offline HashEmbedder's 64-bucket bag-of-tokens vectors let short, unrelated
        // prompts hash into similar buckets and exceed the cosine threshold, serving one
        // conversation's cached answer to a completely different conversation. Including
        // the session id guarantees a cache hit can only ever serve a prior turn from the
        // SAME conversation.
        format!(
            "{}|{}|{}",
            clearance.sensitivity(),
            session,
            normalize(input)
        )
    }

    /// The retrieved-content injection mode this surface actually runs (`"off"` = unscanned).
    /// A shipped surface must never report `"off"`: see
    /// `tests/r16_served_rag_injection_defense.rs`.
    pub fn injection_mode_label(&self) -> &'static str {
        self.manager.injection_mode_label()
    }

    /// Handle one chat turn end-to-end.
    pub async fn turn(
        &self,
        session: &str,
        principal: &Principal,
        input: &str,
        data_class: DataClass,
    ) -> Result<ChatReply, TurnError> {
        let now = self.clock.now();

        // Gap CONV-08: a content-consuming action ("summarize the above and email it") resolves to
        // the prior answer (referent), with the instruction verb phrase EXCLUDED. Checked BEFORE the
        // cache so an action turn never serves a stale cached Answer, and only surfaced when the
        // content actually resolves — an ambiguous action falls through to normal handling.
        let history = self.manager.history(session);
        if let Some(resolved) = resolve_action(input, &history) {
            match resolved.content {
                ContentSource::Explicit(content) | ContentSource::Referent(content) => {
                    return Ok(ChatReply::Action {
                        action: resolved.action,
                        content,
                    });
                }
                ContentSource::Ambiguous => { /* fall through to normal handling */ }
            }
        }

        let partition = self.partition(principal, data_class);
        let key = self.cache_key(principal.clearance, session, input);

        // Cache is consulted only for cacheable-class turns. (Doc-gen / clarify / action are never
        // cached — they depend on live conversation context — so a hit here can only be a prior
        // Answer.) The lookup can only ever reach this caller's own partition. Tiered (gap I): exact/
        // normalized first, then — only on a miss and only when an embedder is wired — the SEMANTIC
        // (paraphrase) tier, so a re-worded repeat of a cached prompt hits without a fresh model call.
        let query_embedding = if self.cacheable(data_class) {
            self.query_embedding(input)
        } else {
            None
        };
        if self.cacheable(data_class) {
            if let Some(hit) = self.cache.lock().unwrap().get_tiered(
                &partition,
                &key,
                query_embedding.as_deref(),
                now,
            ) {
                // Same §1 step 2 + step 10 as the streaming path: a cache hit must not be the one
                // way to reach an answer without the `chat.send` check and without an audit record.
                // `session` doubles as the turn id here — this entrypoint has no separate turn id.
                self.manager
                    .engine()
                    .authorize_short_circuit(principal, session, session)?;
                self.manager.engine().audit_short_circuit(
                    principal,
                    session,
                    session,
                    "chat-cache",
                    0,
                );
                return Ok(ChatReply::Answer {
                    text: hit.value,
                    provider: "cache".into(),
                    citations: Vec::new(),
                    from_cache: true,
                });
            }
        }

        let outcome = self
            .manager
            .handle(session, principal, input, data_class)
            .await?;
        Ok(match outcome {
            ManagerOutcome::Answer {
                text,
                provider,
                citations,
                ..
            } => {
                if self.cacheable(data_class) {
                    self.cache.lock().unwrap().put(
                        &partition,
                        &key,
                        &text,
                        query_embedding.clone(),
                        now,
                    );
                }
                ChatReply::Answer {
                    text,
                    provider,
                    citations,
                    from_cache: false,
                }
            }
            ManagerOutcome::Document {
                format,
                content,
                document,
            } => ChatReply::Document {
                format,
                content,
                document,
            },
            ManagerOutcome::Action { action, content } => ChatReply::Action { action, content },
            ManagerOutcome::Command {
                name,
                expanded_steps,
            } => ChatReply::Command {
                name,
                expanded_steps,
            },
            ManagerOutcome::Clarify { question } => ChatReply::Clarify { question },
        })
    }
}

/// The served Chat surface AS a [`TurnHandler`] (gap SURF-02/03): this is what the `SessionManager`
/// concurrency spine drives, so the daemon serves the **grounded, cited, cached** chat instead of a
/// bare no-retriever conversation. It:
///
/// 1. consults a **scoping-safe** response cache (keyed by the caller's clearance + the turn's data
///    class + the normalized input) for cacheable-class turns — a hit is streamed straight back;
/// 2. otherwise delegates to the grounded [`ConversationManager`] streaming path (intent cascade →
///    referent resolution → clearance-filtered retrieval → prompt engine → engine with compliance-
///    out redaction), forwarding tokens to the caller as they arrive and teeing the final answer;
/// 3. populates the cache from the **redacted** final answer, for genuine model answers only
///    (doc-gen / clarification outcomes are conversation-dependent and are never cached), and never
///    for above-`cacheable_max` (sensitive) classes.
///
/// Cancellation and back-pressure propagate: the caller's `cancel` token flows into the manager/
/// engine turn, and a dropped `sink` (client gone) stops forwarding.
impl TurnHandler for ChatSurface {
    fn handle_turn<'a>(
        &'a self,
        principal: &'a Principal,
        req: &'a Request,
        sink: tokio::sync::mpsc::Sender<Event>,
        cancel: &'a CancelToken,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<TurnSummary, TurnError>> + Send + 'a>,
    > {
        Box::pin(async move {
            let partition = self.partition(principal, req.data_class);
            // Cache on the RAW user turn, not the composed `req.input` (persona + context + policy +
            // user). The composed prompt's long identical prefix dominates the HashEmbedder's
            // bag-of-tokens vector, so any two questions in the same surface collide above the
            // semantic threshold (cosine ~0.97) and serve each other's cached answer. The raw user
            // turn is what actually differs between turns — keying on it makes the exact tier
            // precise and the semantic tier meaningful.
            let cache_input = req.user_turn.as_deref().unwrap_or(&req.input);
            let key = self.cache_key(principal.clearance, &req.session, cache_input);
            let now = self.clock.now();

            // 1. Scoping-safe, TIERED cache lookup (cacheable classes only) — own partition only.
            //    Exact/normalized first; on a miss, and only when a live-path embedder is wired
            //    (gap I), the SEMANTIC (paraphrase) tier — so a re-worded repeat of a cached prompt
            //    streams straight back without a fresh model call.
            let query_embedding = if self.cacheable(req.data_class) {
                self.query_embedding(cache_input)
            } else {
                None
            };
            if self.cacheable(req.data_class) {
                let hit = self.cache.lock().unwrap().get_tiered(
                    &partition,
                    &key,
                    query_embedding.as_deref(),
                    now,
                );
                if let Some(hit) = hit {
                    // §1 step 2 BEFORE serving: a cache hit answers the turn without entering
                    // `run_turn`, so it was previously the one path to an answer that skipped the
                    // `chat.send` check entirely. The partition is per-DEPARTMENT for
                    // internal/public classes, so a department peer who lacks the capability — or
                    // whose access was revoked after the entry was written — was still served.
                    // Fail-closed: an unauthorized caller gets the denial, never the cached text.
                    self.manager.engine().authorize_short_circuit(
                        principal,
                        &req.session,
                        &req.turn,
                    )?;
                    let text = hit.value;
                    let _ = sink.send(Event::TextDelta(text.clone())).await;
                    let _ = sink.send(Event::Done).await;
                    // §1 step 10: a turn served from cache is still a turn an auditor must be able
                    // to find. `provider="chat-cache"` distinguishes it from a model answer.
                    self.manager.engine().audit_short_circuit(
                        principal,
                        &req.session,
                        &req.turn,
                        "chat-cache",
                        0,
                    );
                    return Ok(TurnSummary {
                        final_text: text,
                        redactions: 0,
                        provider: "cache".into(),
                        ..Default::default()
                    });
                }
            }

            // 2. Delegate to the grounded manager, teeing the stream to the caller's sink.
            let (tx, mut rx) = tokio::sync::mpsc::channel::<Event>(64);
            let manager_fut = self.manager.run_turn_streaming(principal, req, tx, cancel);
            let forward_fut = async {
                while let Some(ev) = rx.recv().await {
                    if sink.send(ev).await.is_err() {
                        break; // client gone — stop forwarding (the manager turn still unwinds)
                    }
                }
            };
            let (summary_res, ()) = tokio::join!(manager_fut, forward_fut);
            let summary = summary_res?;

            // 3. Populate the cache from the REDACTED final answer — model answers only, never a
            //    doc-gen/clarify terminal (provider "chat") or an above-ceiling class.
            if self.cacheable(req.data_class)
                && !summary.final_text.is_empty()
                && summary.provider != "chat"
                && summary.provider != "cache"
            {
                self.cache.lock().unwrap().put(
                    &partition,
                    &key,
                    &summary.final_text,
                    query_embedding.clone(),
                    now,
                );
            }
            Ok(summary)
        })
    }
}

#[cfg(test)]
mod context_fabric_gap_tests {
    //! Proving tests for the two context-fabric gaps closed in this module:
    //! (1) PageRank was dormant — `assemble_with_prompt` never called `with_context_graph`, so
    //!     `graph: None` reached `compile_window` on every live turn.
    //! (2) `served_window` hardcoded a single fake `EligibleModel` instead of resolving the real
    //!     tier-eligible set from the `ModelRouter`.
    use super::*;
    use ainxt_context::Chunk;
    use ainxt_protocol::Event;
    use ainxt_runtime::provider::Provider;

    struct FakeProvider(&'static str);
    impl Provider for FakeProvider {
        fn id(&self) -> &str {
            self.0
        }
        fn eligible(&self, _dc: DataClass) -> bool {
            true
        }
        fn stream(&self, _prompt: &str) -> tokio::sync::mpsc::Receiver<Event> {
            let (_tx, rx) = tokio::sync::mpsc::channel(1);
            rx
        }
    }

    /// Gap (2): `served_window` must resolve `eligible` from the router's OWN admissible-provider
    /// set (the same non-overridable test `ModelRouter::select` uses), not a hardcoded placeholder
    /// id unrelated to any registered provider.
    #[test]
    fn served_window_resolves_real_router_eligible_ids_not_a_placeholder() {
        let mut router = ModelRouter::new();
        router.register(Box::new(FakeProvider("alpha-model")));
        router.register(Box::new(FakeProvider("beta-model")));

        let cfg = served_window(&router, DataClass::Public);
        let ids: Vec<&str> = cfg.eligible.iter().map(|m| m.id.as_str()).collect();

        assert!(
            ids.contains(&"alpha-model"),
            "missing real provider id: {ids:?}"
        );
        assert!(
            ids.contains(&"beta-model"),
            "missing real provider id: {ids:?}"
        );
        assert!(
            !ids.contains(&"served-default"),
            "must not fall back to the hardcoded placeholder when real providers are eligible: {ids:?}"
        );
    }

    /// The documented safety property must survive the fix: a router with NO admissible provider
    /// for the data class (e.g. an unconfigured test engine) still floors to a non-empty window
    /// instead of grounding nothing.
    #[test]
    fn served_window_falls_back_to_placeholder_when_router_has_no_eligible_provider() {
        let router = ModelRouter::new(); // no providers registered
        let cfg = served_window(&router, DataClass::Public);
        assert_eq!(cfg.eligible.len(), 1);
        assert_eq!(cfg.eligible[0].id, "served-default");
    }

    /// Gap (1): `build_rank_graph` must derive a REAL graph from the corpus — chunks that share a
    /// `source` document get an edge (co-reference), chunks from different sources do not.
    #[test]
    fn build_rank_graph_connects_same_source_chunks_only() {
        let corpus = Corpus::new()
            .with(Chunk::new("c1", "doc-a", "alpha text", DataClass::Public))
            .with(Chunk::new(
                "c2",
                "doc-a",
                "alpha continued",
                DataClass::Public,
            ))
            .with(Chunk::new(
                "c3",
                "doc-b",
                "unrelated text",
                DataClass::Public,
            ));

        let graph = build_rank_graph(&corpus);

        assert_eq!(graph.nodes.len(), 3);
        assert!(
            graph.edges.contains(&("c1".to_string(), "c2".to_string())),
            "same-source chunks must be linked: {:?}",
            graph.edges
        );
        assert!(
            graph.edges.contains(&("c2".to_string(), "c1".to_string())),
            "the link must be bidirectional: {:?}",
            graph.edges
        );
        assert!(
            !graph
                .edges
                .iter()
                .any(|(a, b)| (a == "c1" || a == "c2") && b == "c3"
                    || (b == "c1" || b == "c2") && a == "c3"),
            "chunks from a different source must NOT be linked: {:?}",
            graph.edges
        );
    }

    /// End-to-end: `assemble_with_prompt` (via `ChatSurface::new`) must wire a non-empty graph into
    /// the manager instead of leaving `graph: None`, so a live turn actually reaches `compile_window`
    /// with PageRank able to run (not silently degraded to lexical-only ranking every turn).
    #[test]
    fn chat_surface_wires_a_real_context_graph_from_its_corpus() {
        let mut router = ModelRouter::new();
        router.register(Box::new(FakeProvider("mock")));
        let corpus = Corpus::new()
            .with(Chunk::new("c1", "doc-a", "alpha text", DataClass::Public))
            .with(Chunk::new(
                "c2",
                "doc-a",
                "alpha continued",
                DataClass::Public,
            ));
        let cfg = ainxt_cache::CacheConfig {
            capacity: 8,
            ttl_ticks: 100,
            semantic_threshold: 0.99,
        };
        let surface = ChatSurface::new(router, corpus, cfg, Box::new(ainxt_cache::FixedClock(0)));
        assert!(
            surface.manager.has_context_graph(),
            "assemble_with_prompt must call with_context_graph so graph: Some(..) reaches compile_window"
        );
    }
}
