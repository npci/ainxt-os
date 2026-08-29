// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Served-path **governance wiring** — the composition root drives the leaf entrypoints that every
//! phase built but left unreachable from the shipped daemon (R5 gap-closing). Nothing here is a new
//! policy engine; it is the wire that makes the *existing* leaves run on the SERVED path:
//!
//! * **Context Fabric** (`context-fabric`): the single [`ainxt_context::compile_window`] entrypoint —
//!   pre-rank node/department/`ad_level`/group **RBAC**, the RLS **row-filter**, cross-graph
//!   personalized **PageRank**, freshness, and the two-phase **budget-fit** against the eligible-model
//!   set — driven over an ACL/RLS-carrying retrieval [`Corpus`](ainxt_retrieval::Corpus) seeded from
//!   the daemon KB. The `ainxt-context` `Corpus` the chat surface grounds over drops the per-node ACL;
//!   this path preserves it, so a **regulated turn is genuinely department + node-ACL + row filtered**
//!   (existence never leaks — an out-of-scope document is never scored, positioned, cited, or logged).
//! * **Numeric-claim gate** (gap BH): the same [`CompiledWindow`](ainxt_context::CompiledWindow) that
//!   assembled the context also gates the model's numbers via server-side re-derivation — never trust
//!   model arithmetic.
//! * **RBI outsourcing register** (`regulated-fi`): installed as the Model Router's **non-overridable**
//!   eligibility input (an external/outsourced route is excluded BEFORE ranking + failover when the
//!   register says it is ineligible for the request's data-class + residency).
//! * **Online canary → auto-rollback → drift** (`eval-tester-scenarios`): the
//!   [`OnlineReleaseController`](ainxt_quality::OnlineReleaseController) instantiated live on the served
//!   surface so a model/prompt candidate is canaried, auto-rolled-back on established regression, and
//!   drift-watched after promotion — off the live-traffic quality stream.
//!
//! Everything is a retrieval read-filter / eligibility / release-control concern — **never** turn
//! admission. An empty eligible set, a fully-filtered corpus, or an ineligible route yields an empty
//! grounded window / no route, never a denied turn (compliance still redacts-and-proceeds).

use std::collections::BTreeMap;
use std::sync::Arc;

use ainxt_canary::alwaysvalid::{AlwaysValidCanary, AlwaysValidConfig};
use ainxt_context::optimizer::{FabricGraph, GraphLayer, RankGraph};
use ainxt_context::route::{MultiGraphFabric, RoutedWindow};
use ainxt_context::{
    compile_window, AccessContext, Chunk as CtxChunk, CompileRequest, CompiledWindow, NodeAcl,
    OptimizerConfig, RowFilter,
};
use ainxt_quality::controller::OnlineReleaseController;
use ainxt_quality::monitor::{provider_silent_update, Cusum, ProviderVerdict, SampledDriftMonitor};
use ainxt_responsibleai::outsourcing::OutsourcingRegister;
use ainxt_retrieval::{Chunk as RChunk, Corpus as RCorpus, EligibleModel, WordTokenCounter};
use ainxt_runtime::router::RouterClock;
use ainxt_types::Principal;

use crate::{scope_admits, KbConfig, KbDocument};
use ainxt_profile::RetrievalScope;

// ============================ Context Fabric — served governed compile ============================

/// The node-ACL a KB document declares (department / seniority / allow-groups / deny-groups). An
/// all-empty declaration yields `None` (the document is class-gated only, back-compat). `pub(crate)`
/// so the Context-Fabric `corpus_for_scope` (the `ainxt-context` corpus the LIVE `ChatSurface`
/// grounds over) preserves the SAME node-ACL onto its chunks — not just the reserved
/// [`retrieval_corpus_for_scope`] path.
pub(crate) fn node_acl_for(doc: &KbDocument) -> Option<NodeAcl> {
    let has_acl = doc.department.is_some()
        || doc.max_ad_level.is_some()
        || !doc.allow_groups.is_empty()
        || !doc.deny_groups.is_empty();
    if !has_acl {
        return None;
    }
    let mut acl = NodeAcl::new();
    if let Some(dept) = &doc.department {
        acl = acl.departments(&[dept.as_str()]);
    }
    if let Some(max) = doc.max_ad_level {
        acl = acl.max_ad_level(max);
    }
    if !doc.allow_groups.is_empty() {
        let g: Vec<&str> = doc.allow_groups.iter().map(|s| s.as_str()).collect();
        acl = acl.allow_groups(&g);
    }
    if !doc.deny_groups.is_empty() {
        let g: Vec<&str> = doc.deny_groups.iter().map(|s| s.as_str()).collect();
        acl = acl.deny_groups(&g);
    }
    Some(acl)
}

/// Build the **ACL/RLS-carrying** retrieval [`Corpus`](ainxt_retrieval::Corpus) for a surface's
/// [`RetrievalScope`] from the daemon KB — the corpus the served governed compile path retrieves over
/// (gap: the `ainxt-context` `Corpus` seeded by `corpus_for_scope` drops the per-node ACL, so
/// department / seniority / group RBAC was structurally unenforceable on grounding). Scope separation
/// is still enforced structurally (only in-scope documents are ever indexed); on top of it every
/// per-node ACL and every RLS row-attribute is preserved so the pre-rank filter can enforce them.
pub fn retrieval_corpus_for_scope(kb: &KbConfig, scope: RetrievalScope) -> RCorpus {
    let chunks: Vec<RChunk> = kb
        .documents
        .iter()
        .filter(|d| scope_admits(scope, d))
        .map(|d| {
            let mut c = RChunk::new(&d.id, &d.text, d.data_class);
            if let Some(acl) = node_acl_for(d) {
                c = c.with_acl(acl);
            }
            for (k, v) in &d.row_attributes {
                c = c.with_attribute(k, v);
            }
            c
        })
        .collect();
    RCorpus::new(chunks)
}

/// The caller's full OBO [`AccessContext`] for the served governed retrieval turn — clearance +
/// department + seniority + groups. The clearance/department come from the [`Principal`]; the
/// seniority + groups are the JWT/OBO claims the transport resolves (passed in, not reached for).
pub fn access_for(principal: &Principal, ad_level: Option<u8>, groups: &[&str]) -> AccessContext {
    let mut ctx = AccessContext::from_principal(principal);
    if let Some(level) = ad_level {
        ctx = ctx.with_ad_level(level);
    }
    if !groups.is_empty() {
        ctx = ctx.with_groups(groups);
    }
    ctx
}

/// The eligible-model set the two-phase budget-fit targets, as the Model Router resolves it from the
/// request's tier ∩ data-class. The composition supplies the real per-model context windows; the fit
/// targets the narrowest so the assembled window is never wider than the eventual (or failover) model
/// can accept. An empty set ⇒ nothing is fitted (the window is empty, never a denied turn).
pub fn eligible_default() -> Vec<EligibleModel> {
    vec![
        EligibleModel::new("in-house-8k", 8_000),
        EligibleModel::new("in-house-32k", 32_000),
    ]
}

/// The **single** served Context-Fabric compile call (gap: `compile_window` was reachable only from
/// the reserved chat/convo crates + tests, never from the composition root). Drives
/// [`ainxt_context::compile_window`] over the ACL/RLS retrieval corpus with the caller's full
/// [`AccessContext`] + optional [`RowFilter`] + optional cross-graph [`RankGraph`]/seeds for
/// personalized PageRank, fitting to the eligible-model floor. Returns the [`CompiledWindow`] whose
/// `context.citations` / `context.chunks` are exactly the department + node-ACL + row filtered,
/// budget-fitted grounding — and which then gates the answer's numbers via [`verify_numbers`].
#[allow(clippy::too_many_arguments)]
pub fn compile_served_context(
    corpus: &RCorpus,
    query: &str,
    access: &AccessContext,
    row_filter: Option<&RowFilter>,
    graph: Option<&RankGraph>,
    seeds: &BTreeMap<String, f64>,
    eligible: Vec<EligibleModel>,
) -> CompiledWindow {
    let cfg = OptimizerConfig {
        eligible,
        ..OptimizerConfig::default()
    };
    let retriever = ainxt_context::HybridRetriever::from_retrieval_corpus(corpus.clone());
    let req = CompileRequest {
        access,
        row_filter,
        graph,
        seeds,
    };
    compile_window(query, &retriever, &cfg, &WordTokenCounter, &req)
}

// ============================ Context Fabric — served fabric-of-graphs compile ============================

/// Build the **layered multi-graph fabric** (`CONTEXT_FABRIC.md` §2, "the fabric of graphs") the
/// served routed compile draws from, seeded from the daemon KB. Every in-scope KB document becomes a
/// [`GraphLayer::EnterpriseDocs`]-labelled fabric node carrying its full node-ACL + RLS row-attributes
/// (so the pre-rank RBAC/RLS still enforces per node), fed through a *populated* [`FabricGraph`] via
/// [`MultiGraphFabric::from_fabric`].
///
/// `code_graph` overlays the extractor/KG-derived layers (symbol/AST/call/import/git/runtime/test/
/// architecture — `ainxt_context::extract::build_fabric`) with their content chunks, so a repo-indexed
/// deployment routes over 12+ layers. The air-gapped default overlays none, so the served fabric is the
/// honestly-available EnterpriseDocs layer until the indexing job populates the rest
/// (**`needs_hot_wiring`**: the per-namespace repo/KG indexer feeds the code layers + edges).
pub fn served_fabric_from_kb(
    kb: &KbConfig,
    scope: RetrievalScope,
    code_graph: FabricGraph,
    code_contents: Vec<CtxChunk>,
) -> MultiGraphFabric {
    let mut graph = code_graph;
    let mut contents = code_contents;
    for d in kb.documents.iter().filter(|d| scope_admits(scope, d)) {
        graph = graph.with_layer(&d.id, GraphLayer::EnterpriseDocs);
        let mut c = CtxChunk::new(&d.id, &d.source, &d.text, d.data_class);
        if let Some(acl) = node_acl_for(d) {
            c = c.with_acl(acl);
        }
        for (k, v) in &d.row_attributes {
            c = c.with_attribute(k, v);
        }
        contents.push(c);
    }
    MultiGraphFabric::from_fabric(graph, contents)
}

/// The **served fabric-of-graphs compile** for a turn (gap `context-fabric`: 12+ graph layers compiled
/// into the window each turn + budget-fit against the Model-Router eligible set). Drives
/// [`MultiGraphFabric::route_eligible`] over the populated fabric with the caller's full
/// [`AccessContext`] + optional [`RowFilter`], and fits the window to the **eligible-model set the
/// Model Router resolved for THIS turn** (`eligible`, passed explicitly — never a config default), so
/// the assembled window is never wider than the narrowest model that could answer, *including a
/// failover target* (Gap-22, anti-silent-truncation on failover). The returned [`RoutedWindow`]'s
/// [`compiled_layers`](RoutedWindow::compiled_layers) reports which fabric layers were compiled in.
///
/// **`needs_hot_wiring`**: this is the clean, drivable composition-root entrypoint; the remaining hot
/// wire is the transport call-site owning (a) the per-namespace/tenant populated fabric from the KB +
/// repo/KG indexer, and (b) the live per-turn eligible set from [`ainxt_runtime::router::ModelRouter`].
/// It is deliberately NOT yet mounted on `/v1/chat`, so the shipped daemon's air-gapped default path is
/// unchanged (the empty-eligible case grounds an empty window, never a denied turn — no empty-pool 503).
#[allow(clippy::too_many_arguments)]
pub fn compile_served_fabric(
    fabric: &MultiGraphFabric,
    query: &str,
    access: &AccessContext,
    row_filter: Option<&RowFilter>,
    eligible: &[EligibleModel],
    namespace: &str,
) -> RoutedWindow {
    fabric.route_eligible(
        query,
        access,
        row_filter,
        eligible,
        &OptimizerConfig::default(),
        &WordTokenCounter,
        namespace,
    )
}

/// GAP-FIX context-fabric — [`RoutedWindow::two_phase_fit`] was fully implemented and unit-tested but
/// had zero callers outside `ainxt-context`'s own tests, even though [`compile_served_fabric`] above
/// already builds the [`RoutedWindow`] this method re-fits: on model-confirm and on every failover
/// (Gap-22), the window must be re-fit to the ACTUAL model that will answer (never the widest
/// candidate assumed at compile time) — this is that missing second phase. Deterministic offline
/// token counting, same as [`compile_served_fabric`]. `needs_hot_wiring` unchanged: not yet mounted on
/// `/v1/chat`, same as its sibling above.
pub fn refit_served_window(
    routed: &RoutedWindow,
    confirmed: &EligibleModel,
    failovers: &[EligibleModel],
) -> CompiledWindow {
    routed.two_phase_fit(confirmed, failovers, &WordTokenCounter)
}

/// GAP-FIX context-fabric — [`ainxt_context::VerifiedAnswer::to_event_record`] was fully implemented
/// and unit-tested but had zero callers outside `ainxt-context`'s own tests. Its own doc comment names
/// it "the clean entrypoint a composition root calls right before `EventLog::append`" — this is that
/// entrypoint: `window`'s lineage is exactly what [`compile_served_fabric`]/[`refit_served_window`]
/// already produce, so nothing new needs constructing. `federated_epsilon_spent` stays the honest
/// `None` default for the non-federated case; a caller that DID query a federated source passes its
/// actual spend. `needs_hot_wiring` unchanged: not yet mounted on `/v1/chat`, same as its siblings.
pub fn served_turn_event_record(
    verified: &ainxt_context::VerifiedAnswer,
    window: &CompiledWindow,
    control_plane_sha: &str,
    federated_epsilon_spent: Option<f64>,
) -> ainxt_context::TurnEventRecord {
    verified.to_event_record(
        window.context.lineage.clone(),
        control_plane_sha,
        federated_epsilon_spent,
    )
}

/// GAP-FIX data-surfaces-artifacts — [`ainxt_context::artifact::ArtifactStore::erasure_cascade`]
/// (DPDP right-to-erasure / ADR-015: erasing an artifact must ALSO purge every derived embedding
/// produced from it — the modality-isolated vector rows, not just the source blob) was fully
/// implemented and unit-tested but had zero callers outside `ainxt-context`'s own tests. Standalone
/// wrapper mirroring [`served_turn_event_record`]'s shape (a thin call on an already-real object).
/// `needs_hot_wiring`: no composition-root code populates a live `ArtifactStore` from object storage
/// yet, so this is not mounted on any DSAR route — it makes the cascade RULE reachable + testable.
pub fn artifact_erasure_cascade(
    store: &ainxt_context::artifact::ArtifactStore,
    artifact_id: &str,
) -> ainxt_context::artifact::ErasurePlan {
    store.erasure_cascade(artifact_id)
}

/// GAP-FIX surfaces-profiles-skills-config — [`SurfaceCatalog::builtin_with_tenant_overrides`] (ADR-004
/// §the full `defaults → deployment → tenant` chain — a tenant/org layers a MORE-specific override on
/// top of a deployment's cross-cutting one) was fully implemented and unit-tested but had zero callers
/// outside `ainxt-surface`'s own tests: `assemble_surface` only ever calls the 2-layer
/// [`SurfaceCatalog::builtin_with_overrides`] sibling. Standalone wrapper (both override lists are
/// caller-supplied, same shape as [`compile_served_fabric`]'s `eligible`) — makes the tenant layer
/// itself REACHABLE + testable. `needs_hot_wiring`: wiring it into `assemble_surface` for real needs a
/// new `tenant_overrides` field on `SurfacesConfig` (config-schema growth, deliberately out of scope
/// here, same as `compile_served_fabric`'s own `/v1/chat` mount being deferred).
pub fn surface_catalog_with_tenant_overrides(
    deployment_overrides: &[(&str, &str)],
    tenant_overrides: &[(&str, &str)],
) -> Result<ainxt_surface::SurfaceCatalog, ainxt_profile::ProfileError> {
    ainxt_surface::SurfaceCatalog::builtin_with_tenant_overrides(
        deployment_overrides,
        tenant_overrides,
    )
}

/// GAP-FIX data-surfaces-artifacts — [`ainxt_context::artifact::route_model`] (§8 data-class model
/// routing: a regulated/PII multimodal artifact resolves ONLY to an in-house, non-cloud vision/ASR
/// model; refuses rather than leaking it to a cloud API) was fully implemented and unit-tested but had
/// zero callers outside `ainxt-context`'s own tests. Pure/stateless — a standalone wrapper, mirroring
/// [`compile_served_fabric`]'s "params supplied directly by the caller" shape. `needs_hot_wiring`: no
/// composition-root code populates a live `ArtifactModel` fleet or artifact ingestion pipeline yet, so
/// this is not mounted on any route — it makes the routing rule itself REACHABLE + testable, the way
/// `compile_served_fabric`/`refit_served_window` did before their live-hook wiring landed.
pub fn route_artifact_model(
    data_class: ainxt_types::DataClass,
    modality: ainxt_context::artifact::Modality,
    models: &[ainxt_context::artifact::ArtifactModel],
) -> Result<&ainxt_context::artifact::ArtifactModel, ainxt_context::artifact::RoutingError> {
    ainxt_context::artifact::route_model(data_class, modality, models)
}

/// GAP-AUDIT data-surfaces-artifacts (multimodal model-eligibility not wired): the wrapper above made
/// [`route_model`](ainxt_context::artifact::route_model) callable from this crate, but nothing here —
/// or anywhere else — ever called it with the artifacts a served turn's OWN [`compile_served_fabric`]
/// actually assembles. [`RoutedWindow::artifacts`] reached every caller with no eligibility check at
/// all: a regulated cheque-scan artifact and a public marketing image came back identically, so a
/// caller wiring `RoutedWindow` straight into a model dispatch had nothing stopping it from sending
/// regulated data to a cloud vision model. This is the composition-root entrypoint that closes the
/// loop, mirroring [`compile_served_fabric`]'s own "reachable, needs_hot_wiring" posture: it takes the
/// ALREADY-COMPILED [`RoutedWindow`] `compile_served_fabric` produced for this turn plus the caller's
/// real model catalog, and returns only the artifacts each is actually eligible for — artifacts with no
/// eligible model are reported in the second element (never silently forwarded to an ineligible model).
///
/// **`needs_hot_wiring`**: same remaining wire as `compile_served_fabric` — the live model catalog is
/// an infra concern (the fleet of configured vision/ASR provider adapters); offline this is proven
/// against a caller-supplied `models` slice, exactly like `route_artifact_model` already was.
pub fn served_multimodal_turn<'a>(
    routed: &RoutedWindow,
    models: &'a [ainxt_context::artifact::ArtifactModel],
) -> (
    Vec<(
        ainxt_context::artifact::Artifact,
        &'a ainxt_context::artifact::ArtifactModel,
    )>,
    Vec<(
        ainxt_context::artifact::Artifact,
        ainxt_context::artifact::RoutingError,
    )>,
) {
    routed.eligible_artifacts(models)
}

/// GAP-FIX context-fabric (embedding-lifecycle no caller) — [`ainxt_retrieval::reembed::migrate_to`]
/// (`CONTEXT_FABRIC.md` §4: "version-tracked embeddings + a re-embed pipeline so migrations never
/// leave a mixed-version index") was fully implemented and unit-tested but had zero callers outside
/// `ainxt-retrieval`'s own tests: nothing in the served daemon ever ran the migration, so bumping the
/// platform embedding model would leave the KB retrieval corpus permanently mixed-version (some chunks
/// on the old vector space, some on the new — `Corpus::is_embedding_uniform` would stay false forever).
///
/// The explicit **admin-triggered** entrypoint an operator drives after bumping the configured
/// embedding model (mirrors `migrate_to`'s own doc: "the loop an index worker runs after the platform
/// embedding model is bumped"). Pure/stateless — a standalone wrapper, mirroring
/// [`route_artifact_model`]'s "params supplied directly by the caller" shape. Returns the
/// [`ainxt_retrieval::reembed::MigrationReport`]: the rebuilt corpus plus whether it reached a single
/// embedding version (a partial failure is visible via `!uniform` +
/// [`ainxt_retrieval::reembed::ReembedOutcome::failed_ids`], never silently marked migrated).
/// `needs_hot_wiring`: no composition-root code retains the served chat surface's live `Corpus` handle
/// past construction yet (it moves into `hybrid_retriever` at `ChatSurface` assembly) — a deployment
/// that wants this on an automatic cadence instead of an explicit admin trigger re-fetches the corpus
/// via [`corpus_for_scope`] on each tick and re-assembles the chat surface with the migrated result.
pub fn run_kb_corpus_reembed(
    corpus: &ainxt_retrieval::Corpus,
    target: &ainxt_retrieval::EmbeddingVersion,
    embedder: &dyn ainxt_retrieval::reembed::Embedder,
) -> ainxt_retrieval::reembed::MigrationReport {
    ainxt_retrieval::reembed::migrate_to(corpus, target, embedder)
}

// ============================ Multimodal artifact ingestion — served pipeline ============================

/// GAP-FIX data-surfaces-artifacts (multimodal no pipeline) — [`ainxt_context::artifact::route_model`]
/// had real, unit-tested data-class routing logic, but no composition-root code ever populated a live
/// [`ainxt_context::artifact::ArtifactModel`] fleet, ran an [`ainxt_context::artifact::ArtifactEmbedder`],
/// or connected the two to [`ainxt_context::artifact::ArtifactStore`] — a regulated KYC scan or call
/// recording could be ROUTED in a test, but never actually INDEXED anywhere on the served path.
///
/// The deterministic, dependency-free default [`ArtifactEmbedder`](ainxt_context::artifact::ArtifactEmbedder)
/// for the air-gapped default — mirrors this crate's `OfflineTierEmbedder` (the memory embedding-lifecycle
/// sweep's own offline default) FNV-hash technique (id + namespace, since there is no real pixel/waveform
/// payload offline), one instance per modality (§8: modality-isolated by construction). A deployment
/// with a real ONNX vision model or a whisper ASR endpoint swaps this for a client behind the same seam
/// — no caller change.
#[derive(Debug, Clone)]
pub struct OfflineArtifactEmbedder {
    modality: ainxt_context::artifact::Modality,
    dim: usize,
}

impl OfflineArtifactEmbedder {
    pub fn new(modality: ainxt_context::artifact::Modality) -> Self {
        OfflineArtifactEmbedder { modality, dim: 32 }
    }
}

impl ainxt_context::artifact::ArtifactEmbedder for OfflineArtifactEmbedder {
    fn modality(&self) -> ainxt_context::artifact::Modality {
        self.modality
    }
    /// An artifact with no id cannot be embedded (nothing to key the derived vector on) — the ONE
    /// deliberate `None` case, so [`ainxt_context::artifact::IngestError::EmbedFailed`] is genuinely
    /// exercisable, not merely a theoretical arm.
    fn embed(&self, artifact: &ainxt_context::artifact::Artifact) -> Option<Vec<f32>> {
        if artifact.id.is_empty() {
            return None;
        }
        let mut hash: u64 = 0xcbf29ce484222325;
        for b in artifact.id.bytes().chain(artifact.namespace.bytes()) {
            hash ^= b as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
        let mut v = vec![0.0f32; self.dim];
        v[(hash as usize) % self.dim] = 1.0;
        Some(v)
    }
}

/// The default artifact-model fleet (§8): one in-house + one cloud model per modality — the minimal
/// real declaration [`ingest_artifact_batch`] routes against. A deployment with real vision/ASR vendor
/// contracts supplies its own fleet directly to
/// [`ainxt_context::artifact::ingest_artifact`]/[`route_artifact_model`] instead of this default.
pub fn artifact_model_fleet_default() -> Vec<ainxt_context::artifact::ArtifactModel> {
    use ainxt_context::artifact::{ArtifactModel, Modality};
    vec![
        ArtifactModel::new("inhouse-vision-v1", Modality::Image, false),
        ArtifactModel::new("cloud-vision-v1", Modality::Image, true),
        ArtifactModel::new("inhouse-asr-v1", Modality::Audio, false),
        ArtifactModel::new("cloud-asr-v1", Modality::Audio, true),
    ]
}

/// **The composition-root's multimodal ingestion entrypoint.** The explicit admin/connector-triggered
/// call that turns a batch of [`Artifact`](ainxt_context::artifact::Artifact) handles into a populated
/// [`ArtifactStore`](ainxt_context::artifact::ArtifactStore): each artifact is routed
/// ([`route_artifact_model`]'s data-class ceiling — a regulated artifact never reaches a cloud model),
/// embedded via the modality-matching [`OfflineArtifactEmbedder`], and only on full success is it (plus
/// its derived embedding) added to the store. A routing/embed failure is reported per-artifact in the
/// returned outcome vector (same index as `artifacts`) — never a silently-dropped artifact and never a
/// partial store entry (an artifact with no derived embedding, which would break the erasure cascade's
/// completeness guarantee).
///
/// The returned store is the exact shape [`ainxt_context::route::MultiGraphFabric::with_artifacts`]
/// accepts, so a deployment feeds this straight into the same fabric [`served_fabric_from_kb`] builds —
/// closing the "no live ingestion pipeline populates the fleet" gap end-to-end: fleet → ingest → store →
/// fabric → [`compile_served_fabric`]'s routed multimodal-artifact tier
/// ([`ainxt_context::route::MultiGraphFabric::artifacts_for`]).
pub fn ingest_artifact_batch(
    artifacts: Vec<ainxt_context::artifact::Artifact>,
) -> (
    ainxt_context::artifact::ArtifactStore,
    Vec<Result<String, ainxt_context::artifact::IngestError>>,
) {
    use ainxt_context::artifact::{ArtifactStore, Modality};
    let models = artifact_model_fleet_default();
    let image_embedder = OfflineArtifactEmbedder::new(Modality::Image);
    let audio_embedder = OfflineArtifactEmbedder::new(Modality::Audio);
    let embedders: Vec<&dyn ainxt_context::artifact::ArtifactEmbedder> =
        vec![&image_embedder, &audio_embedder];
    let mut store = ArtifactStore::new();
    let mut outcomes = Vec::with_capacity(artifacts.len());
    for artifact in artifacts {
        outcomes.push(ainxt_context::artifact::ingest_artifact(
            &mut store, artifact, &models, &embedders,
        ));
    }
    (store, outcomes)
}

/// GAP-FIX context-fabric — [`ainxt_context::optimizer::FabricGraph`]'s named query methods
/// (`who_calls`/`refs_of`/`deps`/`changed_with`/`tests_covering`/`runtime_errors_for`/
/// `architecture_around` — the design's §5 named vocabulary: `whoCalls`/`refsOf`/`deps`/
/// `changedWith`/`testsCovering`/`runtimeErrorsFor`/`architectureAround`) were fully implemented and
/// unit-tested but had zero callers outside `ainxt-context`'s own tests. Standalone wrapper over the
/// crate's own mount-ready [`ainxt_context::optimizer::named_fabric_query`] dispatcher, mirroring
/// [`route_artifact_model`]'s shape (both graph + query are caller-supplied). `needs_hot_wiring`: no
/// composition-root code populates a live `FabricGraph` from a real repo/KG indexer yet (the same gap
/// `served_fabric_from_kb`'s own doc calls out), so this is not mounted on any route — it makes the
/// named-query vocabulary itself REACHABLE + testable.
pub fn named_fabric_query(
    fabric: &ainxt_context::optimizer::FabricGraph,
    query: &ainxt_context::optimizer::NamedFabricQuery,
) -> Vec<String> {
    ainxt_context::optimizer::named_fabric_query(fabric, query)
}

// ============================ Named Fabric Query — governed capability ============================

/// The **§5 named fabric query vocabulary** (`whoCalls`/`refsOf`/`deps`/`changedWith`/
/// `testsCovering`/`runtimeErrorsFor`/`architectureAround`, `CONTEXT_FABRIC.md` §5) mounted as a
/// governed [`ainxt_tools::Tool`] capability (GAP-AUDIT context-fabric — the plain [`named_fabric_query`]
/// wrapper above was reachable from `ainxt-runtimed`'s own crate, but was never registered as a
/// model-facing capability — unlike [`FederatedQueryTool`]/[`StructuredQueryTool`], which this mirrors
/// exactly, there was no manifest entry a served turn's function-calling loop could ever select). Same
/// posture as those two: the served composition root constructs this over an EMPTY
/// [`FabricGraph`](ainxt_context::optimizer::FabricGraph) (no repo/KG indexed in yet — that's the
/// separate "fabric not mounted" gap), so the capability is reachable and dispatchable but every named
/// query resolves to an empty result set until a deployment feeds it a real indexed fabric via
/// [`NamedFabricQueryTool::new`].
///
/// `Pure`, never `SideEffecting`: every named query is a read-only graph lookup, mirroring
/// `StructuredQueryTool`'s classification.
pub struct NamedFabricQueryTool {
    fabric: ainxt_context::optimizer::FabricGraph,
}

/// The canonical capability name exposed to the model's function-calling manifest.
pub const NAMED_FABRIC_QUERY: &str = "named_fabric_query";

impl NamedFabricQueryTool {
    pub fn new(fabric: ainxt_context::optimizer::FabricGraph) -> Self {
        NamedFabricQueryTool { fabric }
    }

    /// The air-gapped served default: an empty fabric (no nodes/edges), so the capability is
    /// reachable in the manifest without a real repo/KG indexer being wired in yet.
    pub fn empty() -> Self {
        NamedFabricQueryTool {
            fabric: ainxt_context::optimizer::FabricGraph::new(),
        }
    }

    /// THE live handler: dispatch a [`NamedFabricQuery`](ainxt_context::optimizer::NamedFabricQuery)
    /// against this capability's fixed fabric. Not reachable through [`Tool::execute`]'s sync,
    /// argument-string signature: the caller's structured query enum is needed, which the one-shot
    /// capability path doesn't carry — exactly why `StructuredQueryTool::execute` redirects to
    /// `dispatch`.
    pub fn dispatch(&self, query: &ainxt_context::optimizer::NamedFabricQuery) -> Vec<String> {
        named_fabric_query(&self.fabric, query)
    }
}

impl ainxt_tools::Tool for NamedFabricQueryTool {
    fn name(&self) -> &str {
        NAMED_FABRIC_QUERY
    }
    /// Every named query is a read-only graph lookup — no side effect, mirroring
    /// `StructuredQueryTool`'s `Pure` classification.
    fn effect_class(&self) -> ainxt_tools::EffectClass {
        ainxt_tools::EffectClass::Pure
    }
    fn schema(&self) -> ainxt_tools::ToolSchema {
        ainxt_tools::ToolSchema {
            name: NAMED_FABRIC_QUERY.into(),
            description:
                "Query the indexed code/knowledge fabric by the closed §5 named vocabulary: \
                          whoCalls, refsOf, deps, changedWith, testsCovering, runtimeErrorsFor, \
                          architectureAround. Each takes a single symbol/module/file/function \
                          argument and returns the matching node names from the typed fabric graph."
                    .into(),
            parameters: ainxt_tools::ParamSpec::Text,
        }
    }
    fn execute(&self, _args: &str) -> Result<String, ainxt_tools::ToolError> {
        Err(ainxt_tools::ToolError::Execution(
            "named_fabric_query must be invoked through the governed boundary \
             (NamedFabricQueryTool::dispatch): resolving a named query needs the caller's structured \
             NamedFabricQuery enum, which the one-shot capability path doesn't carry"
                .into(),
        ))
    }
}

/// The numeric-claim gate (gap BH) over an already-compiled window: never trust the model's
/// arithmetic — every sourced number is independently re-derived and diffed. A convenience over
/// [`CompiledWindow::verify_answer`] so the served path runs the SAME object's verify half.
pub fn verify_numbers(
    window: &CompiledWindow,
    answer: &str,
    claims: &[ainxt_context::NumericClaim],
    rederiver: &dyn ainxt_context::Rederiver,
    tolerance: &ainxt_context::Tolerance,
) -> ainxt_context::VerifiedAnswer {
    window.verify_answer(answer, claims, rederiver, tolerance)
}

/// A deterministic in-memory [`Rederiver`](ainxt_context::Rederiver) that re-derives a claim's value
/// from a source→value map (the offline analogue of a read-replica query / deterministic tool). A
/// claim whose source key is absent is *not reproducible* → fail-closed (the answer's numbers block).
#[derive(Debug, Default, Clone)]
pub struct MapRederiver {
    values: BTreeMap<String, f64>,
}

impl MapRederiver {
    pub fn new() -> Self {
        Self::default()
    }
    /// Register the authoritative value for a claim source's re-derivation key.
    pub fn with(mut self, key: &str, value: f64) -> Self {
        self.values.insert(key.to_string(), value);
        self
    }
}

impl ainxt_context::Rederiver for MapRederiver {
    fn rederive(&self, source: &ainxt_context::ClaimSource) -> Option<f64> {
        let key = source.rederive_key()?;
        self.values.get(&key).copied()
    }
}

// ============================ Structured retrieval — served point-lookup round trip ============================
//
// Closes three round-15 `context-fabric` gaps as ONE composition-root call: (1) "NL-to-SQL reachable
// from a classified point-lookup chat turn" — the CLASSIFIER (`ainxt_context::optimizer::
// classify_scope`, §7.1) gates entry, so a genuinely global/sensemaking ask never drives a
// single-metric structured round trip; (2) "Stage-A constrained decoding from the catalog" — the
// catalog's `metric_id` is (structurally) drawn from `MetricCatalog::metric_ids()`, the exact closed
// vocabulary `MetricCatalog::constrained_intent_schema` grammar-locks a proposal to; (3) "server-side
// independent numeric re-derivation on the served chat path" — the compiled query's `query_hash` is
// exactly the identity `ServerSideRederiver` re-executes, so the SAME call that answers the turn also
// registers the re-derivation target the numeric gate later checks the model's claim against.

/// The served point-lookup → structured-metric round trip. `None` when `query` does not classify as
/// a [`QueryScope::PointLookup`] (§7.1) — a global/sensemaking ask must route to the GraphRAG
/// map-reduce tier instead, never a single-metric structured query. `Some` carries the compiled,
/// parameterized [`CompiledStructuredQuery`] (never raw SQL) whose `query_hash` the caller feeds to
/// [`register_structured_rederiver`] so the numeric gate can independently re-verify the answer.
///
/// **`needs_hot_wiring`**: this is the clean, drivable composition-root entrypoint; the remaining hot
/// wire is the transport call-site owning (a) the live read-replica [`RlsExecutor`] execution (an
/// infra concern — offline this is proven against the in-memory row-filter oracle) and (b) mounting
/// this ahead of ordinary RAG grounding on `/v1/chat` when the turn classifies as a point lookup. It
/// is deliberately NOT yet mounted, so the shipped daemon's air-gapped default path is unchanged (no
/// empty-pool 503 — an unresolved/ambiguous scope simply falls through to ordinary grounding).
#[allow(clippy::too_many_arguments)]
pub fn served_structured_turn(
    query: &str,
    catalog: &ainxt_retrieval::structured::MetricCatalog,
    metric_id: &str,
    group_by: &[&str],
    filters: &[ainxt_retrieval::structured_pipeline::DimensionFilter],
    aggregation: ainxt_retrieval::structured_pipeline::Aggregation,
    schema: &ainxt_nl2sql::Schema,
    principal: &Principal,
) -> Result<
    Option<ainxt_retrieval::structured_pipeline::CompiledStructuredQuery>,
    ainxt_retrieval::structured_pipeline::PipelineError,
> {
    let scope = ainxt_context::optimizer::classify_scope(query);
    if scope.scope != ainxt_context::optimizer::QueryScope::PointLookup {
        return Ok(None);
    }
    let compiled = ainxt_retrieval::structured_pipeline::compile_structured_query(
        catalog,
        metric_id,
        group_by,
        filters,
        aggregation,
        schema,
        principal,
    )?;
    Ok(Some(compiled))
}

/// Register a [`served_structured_turn`] result's re-derivation target on a
/// [`ServerSideRederiver`](ainxt_retrieval::structured_pipeline::ServerSideRederiver) — the one call
/// that arms the numeric gate to independently re-execute THIS turn's exact compiled query
/// server-side (§5.2), rather than trusting the model's stated figure. `session` is the SAME RLS
/// `SET LOCAL` context the original read used, so re-derivation never runs under a broader scope.
pub fn register_structured_rederiver<'a>(
    rederiver: &mut ainxt_retrieval::structured_pipeline::ServerSideRederiver<'a>,
    compiled: &ainxt_retrieval::structured_pipeline::CompiledStructuredQuery,
    session: ainxt_retrieval::structured::SessionContext,
) {
    rederiver.register(compiled, session);
}

// ============================ Structured Query — governed capability ============================

/// The **catalog-bound structured query** (`STRUCTURED_FEDERATED_RETRIEVAL.md` §4) mounted as a
/// governed [`ainxt_tools::Tool`] capability (GAP-AUDIT context-fabric — [`served_structured_turn`]
/// was a clean, fully-tested composition-root entrypoint with zero callers outside its own test
/// module: no model-facing route to the metric catalog / NL-to-SQL bridge existed at all). Mounting
/// it here — exactly the pattern [`FederatedQueryTool`] already established for the federation
/// broker — makes the capability *reachable* through the SAME unified [`ainxt_tools::ToolRuntime`]
/// dispatch path (same manifest listing, same OBO-authz, same approval gate) without inventing a
/// bespoke structured-query-only surface.
///
/// The catalog + schema are fixed at construction — a startup, git-reviewed control-plane decision
/// exactly like [`ainxt_tools::ledger_query::LedgerQueryTool::default_ledger`]'s fixed allowlist. The
/// air-gapped served default constructs this over an EMPTY [`MetricCatalog`](
/// ainxt_retrieval::structured::MetricCatalog) (no metrics configured), so the capability is
/// reachable but every proposal fails closed with `UnknownMetric` until a deployment loads its own
/// git-native catalog via [`MetricCatalog::load`](ainxt_retrieval::structured::MetricCatalog::load) —
/// the same "declared but excludes everything exotic by default" posture [`FederatedQueryTool`]
/// uses for its empty [`FederationRegistry`](ainxt_retrieval::federation::FederationRegistry).
///
/// `Pure`, never `SideEffecting`: compiling a `SELECT`-only [`CompiledStructuredQuery`](
/// ainxt_retrieval::structured_pipeline::CompiledStructuredQuery) has no side effect — the query is
/// executed by the read-only data path downstream, mirroring `LedgerQueryTool`'s classification.
pub struct StructuredQueryTool {
    catalog: ainxt_retrieval::structured::MetricCatalog,
    schema: ainxt_nl2sql::Schema,
}

/// The canonical capability name exposed to the model's function-calling manifest.
pub const STRUCTURED_QUERY: &str = "structured_query";

impl StructuredQueryTool {
    pub fn new(
        catalog: ainxt_retrieval::structured::MetricCatalog,
        schema: ainxt_nl2sql::Schema,
    ) -> Self {
        StructuredQueryTool { catalog, schema }
    }

    /// The air-gapped served default: an empty catalog (registers nothing exotic by default) over
    /// an empty schema, so the capability is reachable in the manifest without a control-plane
    /// catalog being configured yet.
    pub fn empty() -> Self {
        StructuredQueryTool {
            catalog: ainxt_retrieval::structured::MetricCatalog::new(),
            schema: ainxt_nl2sql::Schema::new(Vec::new()).expect("empty schema is always valid"),
        }
    }

    /// THE live handler: [`served_structured_turn`] gated by the query-scope classifier, then
    /// [`ainxt_retrieval::structured_pipeline::compile_structured_query`] against this capability's
    /// fixed catalog + schema. Not reachable through [`Tool::execute`]'s sync, argument-string
    /// signature: the caller's classified turn text and [`Principal`] clearance are needed, neither
    /// of which the one-shot capability path carries — exactly why `LedgerQueryTool::execute`
    /// redirects to `compile` and `FederatedQueryTool::execute` redirects to `dispatch`.
    #[allow(clippy::too_many_arguments)]
    pub fn dispatch(
        &self,
        query: &str,
        metric_id: &str,
        group_by: &[&str],
        filters: &[ainxt_retrieval::structured_pipeline::DimensionFilter],
        aggregation: ainxt_retrieval::structured_pipeline::Aggregation,
        principal: &Principal,
    ) -> Result<
        Option<ainxt_retrieval::structured_pipeline::CompiledStructuredQuery>,
        ainxt_retrieval::structured_pipeline::PipelineError,
    > {
        served_structured_turn(
            query,
            &self.catalog,
            metric_id,
            group_by,
            filters,
            aggregation,
            &self.schema,
            principal,
        )
    }
}

impl ainxt_tools::Tool for StructuredQueryTool {
    fn name(&self) -> &str {
        STRUCTURED_QUERY
    }
    /// A `SELECT`-only compiled query has no side effect (§4) — the produced query is executed by
    /// the read-only data path downstream, mirroring `LedgerQueryTool`'s classification.
    fn effect_class(&self) -> ainxt_tools::EffectClass {
        ainxt_tools::EffectClass::Pure
    }
    fn schema(&self) -> ainxt_tools::ToolSchema {
        ainxt_tools::ToolSchema {
            name: STRUCTURED_QUERY.into(),
            description: "Query a single governed metric from the git-native catalog by proposing \
                          a closed-vocabulary (metric_id, group_by, filters, aggregation) intent. \
                          Only classified point-lookup turns route here — a global/sensemaking ask \
                          must use ordinary grounded retrieval instead. The model never emits SQL; \
                          a deterministic compiler produces a parameterized, RLS-scoped query and a \
                          stable query_hash the numeric gate independently re-derives against."
                .into(),
            parameters: ainxt_tools::ParamSpec::Text,
        }
    }
    fn execute(&self, _args: &str) -> Result<String, ainxt_tools::ToolError> {
        Err(ainxt_tools::ToolError::Execution(
            "structured_query must be invoked through the governed boundary \
             (StructuredQueryTool::dispatch): compiling a metric query needs the caller's \
             classified turn text and Principal clearance, neither of which the one-shot \
             capability path carries"
                .into(),
        ))
    }
}

/// GAP-AUDIT data-surfaces-artifacts (federated-broker zero callers): [`FederatedQueryTool`] was
/// registered into the live [`ainxt_tools::CapabilityRegistry`] composition root (`build_unified_
/// capability_registry_shared_over`), so it was reachable in the manifest — but unlike
/// [`served_structured_turn`] above, nothing gated WHEN a classified turn should actually attempt a
/// federated cross-bank read: `Tool::execute` always errors (by design, same as `structured_query`),
/// and the only callers of the real `.dispatch()` handler were this crate's own test module. A served
/// turn had no composition-root entrypoint that could decide "this ask needs the federated tier" at
/// all — every `FederatedQueryTool::dispatch` call had to be hand-constructed by a test with args a
/// real request path never assembles.
///
/// This is that missing gate, mirroring `served_structured_turn`'s shape and INVERTING its scope
/// check: a federated cross-bank aggregate ("mule-account velocity across banks") is definitionally a
/// cross-cutting, network-wide ask — [`QueryScope::Global`](ainxt_context::optimizer::QueryScope::Global),
/// never a bounded single-bank [`QueryScope::PointLookup`](ainxt_context::optimizer::QueryScope::PointLookup)
/// (which must route to `served_structured_turn`'s single-metric tier instead, never spend the shared,
/// exhaustible epsilon budget or reach every member bank's boundary for what is actually a one-bank
/// question).
///
/// The served federated cross-bank round trip. `None` when `query` does not classify as
/// [`QueryScope::Global`](ainxt_context::optimizer::QueryScope::Global) — a plain point-lookup ask
/// must never spend the shared epsilon budget or reach every member bank's tenant boundary. `Some`
/// carries the real [`DispatchReport`](ainxt_retrieval::federation::DispatchReport) from a
/// [`FederatedBroker`](ainxt_retrieval::federation::FederatedBroker) dispatch — whitelist gate →
/// ε-budget debit → per-tenant isolation-enforced fan-out → k-anonymity aggregation, unchanged.
///
/// **`needs_hot_wiring`**: same remaining wire as `served_structured_turn` — the transport call-site
/// owning the live per-bank tenant connections (an infra concern; offline this is proven against the
/// in-memory [`BankTenant`](ainxt_retrieval::federation::BankTenant) fakes) and mounting this ahead of
/// ordinary RAG grounding on `/v1/chat` when the turn classifies as global/network-wide. Deliberately
/// NOT yet mounted, so the shipped daemon's air-gapped default path is unchanged.
#[allow(clippy::too_many_arguments)]
pub fn served_federated_turn(
    query: &str,
    registry: &ainxt_retrieval::federation::FederationRegistry,
    k: ainxt_retrieval::federation::KAnonConfig,
    dp: ainxt_retrieval::federation::DpParams,
    metric_id: &str,
    window: &str,
    epsilon: f64,
    budget: f64,
    ledger: &mut ainxt_retrieval::federation::EpsilonLedger,
    tenants: &[&dyn ainxt_retrieval::federation::BankTenant],
    disclose_per_bank: bool,
) -> Result<
    Option<ainxt_retrieval::federation::DispatchReport>,
    ainxt_retrieval::federation::FederationError,
> {
    let scope = ainxt_context::optimizer::classify_scope(query);
    if scope.scope != ainxt_context::optimizer::QueryScope::Global {
        return Ok(None);
    }
    let broker = ainxt_retrieval::federation::FederatedBroker::new(registry, k, dp);
    let report = broker.dispatch(
        metric_id,
        window,
        epsilon,
        budget,
        ledger,
        tenants,
        disclose_per_bank,
    )?;
    Ok(Some(report))
}

// ============================ Federated Query Broker — governed capability ============================

/// The **Federated Query Broker** (`STRUCTURED_FEDERATED_RETRIEVAL.md` §6) mounted as a governed
/// [`ainxt_tools::Tool`] capability (round-15 `context-fabric` gap), so a network-wide cross-bank
/// signal ("mule-account velocity across banks") is reachable through the SAME unified
/// [`ToolRuntime`]/`CapabilityRegistry` dispatch path — same OBO-authz, same approval gate, same
/// manifest listing — every other capability goes through, never a bespoke federation-only
/// surface. The policy (whitelist, k-anonymity floor, and DP calibration)
/// is fixed at construction, a startup, git-reviewed control-plane decision
/// exactly like [`ainxt_tools::ledger_query::LedgerQueryTool::default_ledger`]'s fixed schema allowlist.
///
/// `Elevated`, never `Low`/`Pure`: this capability spends a shared, exhaustible privacy-epsilon
/// budget and reaches every member bank's tenant boundary, so a human/policy approval gate must
/// clear every call. Deliberately NOT `HighRisk`: that tier requires [`Tool::has_reconcile_probe`]
/// (a downstream idempotency-key probe the [`ReconcilerSweeper`] can call to resolve a lost-ack
/// row against the real state) — the epsilon debit here is an in-process ledger operation with no
/// external, independently-queryable state to probe, so CLAIMING a reconcile probe would be exactly
/// the dishonest declaration [`Tool::has_reconcile_probe`]'s own doc warns against. `Elevated` is
/// the tier that is both honest about that limit and still approval-gated.
pub struct FederatedQueryTool {
    registry: ainxt_retrieval::federation::FederationRegistry,
    k: ainxt_retrieval::federation::KAnonConfig,
    dp: ainxt_retrieval::federation::DpParams,
}

/// The canonical capability name exposed to the model's function-calling manifest.
pub const FEDERATED_QUERY: &str = "federated_query";

impl FederatedQueryTool {
    pub fn new(
        registry: ainxt_retrieval::federation::FederationRegistry,
        k: ainxt_retrieval::federation::KAnonConfig,
        dp: ainxt_retrieval::federation::DpParams,
    ) -> Self {
        FederatedQueryTool { registry, k, dp }
    }

    /// THE live handler: [`served_federated_turn`] gated by the query-scope classifier, then a
    /// federated cross-bank query through the [`FederatedBroker`] (whitelist gate → ε-budget debit →
    /// per-tenant isolation-enforced fan-out → k-anonymity aggregation) — the ONLY path that produces
    /// a [`DispatchReport`]. Not reachable through [`Tool::execute`]'s sync, stateless signature: this
    /// call needs the caller's classified turn text (so a bounded single-bank point lookup never
    /// spends the shared budget), the shared, mutable [`EpsilonLedger`] (so the debit is real and
    /// shared across calls), and the live per-bank tenant connections (the infra piece), none of which
    /// a stateless `execute(&self, args)` can carry — exactly the same reason `LedgerQueryTool::execute`
    /// redirects to `compile`.
    #[allow(clippy::too_many_arguments)]
    pub fn dispatch(
        &self,
        query: &str,
        metric_id: &str,
        window: &str,
        epsilon: f64,
        budget: f64,
        ledger: &mut ainxt_retrieval::federation::EpsilonLedger,
        tenants: &[&dyn ainxt_retrieval::federation::BankTenant],
        disclose_per_bank: bool,
    ) -> Result<
        Option<ainxt_retrieval::federation::DispatchReport>,
        ainxt_retrieval::federation::FederationError,
    > {
        served_federated_turn(
            query,
            &self.registry,
            self.k,
            self.dp,
            metric_id,
            window,
            epsilon,
            budget,
            ledger,
            tenants,
            disclose_per_bank,
        )
    }
}

impl ainxt_tools::Tool for FederatedQueryTool {
    fn name(&self) -> &str {
        FEDERATED_QUERY
    }
    /// Spends a shared, exhaustible privacy budget and reaches every member bank's boundary — a
    /// world-changing (ledger-mutating, `EpsilonLedger`) side effect, gated by the `Elevated`
    /// approval requirement (see the type doc).
    fn effect_class(&self) -> ainxt_tools::EffectClass {
        ainxt_tools::EffectClass::SideEffecting
    }
    fn risk_tier(&self) -> ainxt_tools::RiskTier {
        ainxt_tools::RiskTier::Elevated
    }
    fn schema(&self) -> ainxt_tools::ToolSchema {
        ainxt_tools::ToolSchema {
            name: FEDERATED_QUERY.into(),
            description: "Query a network-wide, privacy-preserving cross-member-bank aggregate \
                          (e.g. mule-account velocity across banks). Only whitelisted, \
                          `federated: true` catalog metrics may be queried; every response is a \
                          k-anonymous, DP-noised aggregate — no bank's raw rows ever leave its own \
                          boundary."
                .into(),
            parameters: ainxt_tools::ParamSpec::Text,
        }
    }
    fn execute(&self, _args: &str) -> Result<String, ainxt_tools::ToolError> {
        Err(ainxt_tools::ToolError::Execution(
            "federated_query must be invoked through the governed boundary \
             (FederatedQueryTool::dispatch): a federated cross-bank read needs the shared \
             ε-budget ledger + live per-bank tenant connections, neither of which the one-shot \
             capability path carries"
                .into(),
        ))
    }
}

// ============================ Prompt Engine — served forensic-before-provider compile ============================

/// The composition-root entrypoint that binds the shipped default served-chat prompt deployment to a
/// **durable** forensic Event-Log sink, closing the "Prompt Engine §7/PE11" HIGH: the forensic prompt
/// event record was persisted "before the provider call" only for whatever sink the caller happened to
/// pass — a served daemon could pass a `NullSink` and silently skip forensic persistence. This returns
/// a [`ServedPromptEngine`](ainxt_prompt::service::ServedPromptEngine) that OWNS a mandatory durable
/// [`ForensicFileSink`](ainxt_prompt::service::ForensicFileSink) rooted at `path` (fsync-before-return),
/// so **every** served turn this engine compiles has its exact `(control_sha, layer versions,
/// prompt_hash)` on disk BEFORE the provider is called — byte-for-byte replayable, structurally, with
/// zero infra (the air-gapped default).
///
/// **`needs_hot_wiring`**: the shipped `/v1/chat` compile still uses the flat single-string engine; the
/// remaining wire is the transport call-site swapping in this engine per turn. **infra_gated**: a
/// production deployment injects a Postgres / WORM Event-Log-backed sink behind the same
/// [`EventSink`](ainxt_prompt::service::EventSink) trait via
/// [`ServedPromptEngine::new`](ainxt_prompt::service::ServedPromptEngine::new) in place of the file sink.
pub fn assemble_served_prompt_engine(
    path: impl AsRef<std::path::Path>,
) -> ainxt_prompt::service::ServedPromptEngine {
    ainxt_prompt::service::ServedPromptEngine::with_forensic_file(
        ainxt_prompt::served::default_served_chat_prompts(),
        path,
    )
}

/// The payments-surface variant of [`assemble_served_prompt_engine`] — same mandatory
/// durable-before-provider forensic guarantee, but bound to the payments served-chat deployment
/// (`ToolsOnly` numeric discipline: the model never does payment arithmetic; every sourced number is
/// re-derived server-side).
pub fn assemble_payments_served_prompt_engine(
    path: impl AsRef<std::path::Path>,
) -> ainxt_prompt::service::ServedPromptEngine {
    ainxt_prompt::service::ServedPromptEngine::with_forensic_file(
        ainxt_prompt::served::default_payments_served_chat_prompts(),
        path,
    )
}

/// **Gap closure — `PolicyEngineConfig`'s doc comment promised a config-file-to-served-daemon path
/// that stopped short at `served.rs`'s own seam.** `ainxt_config::RuntimeConfig::policy.l2_body`
/// resolves through the real layered TOML merge (built-in defaults → deployment → tenant/org →
/// surface profile → per-request, `ainxt_config::Loader`) exactly like every other config domain —
/// but nothing in the composition root ever READ it into a served deployment; `layer_specs`'s L2 body
/// stayed whatever the caller's `Option<&str>` happened to be, and no caller here supplied one sourced
/// from config. This is that caller: build a served-chat engine whose L2 body is `config`'s resolved
/// policy, not the compiled-in default, closing the loop from a `[policy]` TOML layer to the exact
/// text a served turn's system prompt contains.
///
/// `config.validate()` is the caller's responsibility (as with every other `RuntimeConfig` consumer in
/// this module) — this function trusts an already-validated config, so an empty `l2_body` cannot reach
/// here (fail-closed at the config layer, per `RuntimeConfig::validate`).
pub fn assemble_served_prompt_engine_from_config(
    config: &ainxt_config::RuntimeConfig,
    path: impl AsRef<std::path::Path>,
) -> ainxt_prompt::service::ServedPromptEngine {
    let served = ainxt_prompt::served::served_chat_prompts_with_l2_policy(
        &ainxt_prompt::served::default_chat_families(),
        Some(&config.policy.l2_body),
    );
    ainxt_prompt::service::ServedPromptEngine::with_forensic_file(served, path)
}

/// The payments-surface variant of [`assemble_served_prompt_engine_from_config`] — same config-sourced
/// L2 body, `ToolsOnly` numeric discipline.
pub fn assemble_payments_served_prompt_engine_from_config(
    config: &ainxt_config::RuntimeConfig,
    path: impl AsRef<std::path::Path>,
) -> ainxt_prompt::service::ServedPromptEngine {
    let served = ainxt_prompt::served::served_chat_prompts_with_l2_policy(
        &ainxt_prompt::served::default_chat_families(),
        Some(&config.policy.l2_body),
    );
    let served = ainxt_prompt::served::ServedChatPrompts {
        numeric: ainxt_prompt::NumericPolicy::ToolsOnly,
        ..served
    };
    ainxt_prompt::service::ServedPromptEngine::with_forensic_file(served, path)
}

/// **Gap closure — `ainxt_prompt::canary::CanaryController` was orphaned** (implemented and
/// unit-tested next to `drift.rs`, but invoked from nowhere outside its own `#[cfg(test)]`). This is
/// the composition-root entrypoint a daemon cadence calls: ONE evaluate-and-apply pass against the
/// live [`ServedPromptEngine`](ainxt_prompt::service::ServedPromptEngine) this crate's own
/// [`assemble_served_prompt_engine`] / [`assemble_payments_served_prompt_engine`] already construct.
/// Mirrors [`crate::run_workforce_nightly_tick`] / [`crate::run_prompt_optimizer_sweep_tick`]'s
/// pattern: a single pure pass per call, drivable by a real cron/timer.
///
/// A `Promote`/`Rollback` decision is applied to `engine`'s bound deployment IN THIS CALL — the next
/// `compile_turn` on the same engine instance immediately reflects it (an instant pointer flip, never
/// a rewrite, `PROMPT_ENGINEERING.md` §3/§8).
///
/// **`needs_hot_wiring`** (honest, matching this module's own convention for every sibling tick):
/// 1. live `prod`/`prod-canary` arm metrics sourced from real sampled traffic (today the caller
///    supplies them — there is no telemetry query against a real data plane here); and
/// 2. a real cron/timer invoking this tick on a schedule, and a rollback NOTIFICATION channel (§8: "a
///    human is notified, not paged") — both orthogonal to the decide-and-apply logic this closes.
pub fn run_prompt_canary_sweep_tick(
    engine: &mut ainxt_prompt::service::ServedPromptEngine,
    controller: &ainxt_prompt::canary::CanaryController,
    prod: &ainxt_prompt::canary::ArmMetrics,
    canary: &ainxt_prompt::canary::ArmMetrics,
) -> ainxt_prompt::canary::CanaryDecision {
    engine.evaluate_canary(controller, prod, canary)
}

/// A [`ainxt_prompt::service::ServedPromptEngine`] shared across every composition-root cadence tick
/// that needs to observe/mutate the SAME bound deployment. [`spawn_prompt_canary_tick`] and
/// [`spawn_prompt_drift_tick`] both take a clone of this `Arc` — never a second, disconnected engine —
/// so a canary pointer-flip the first applies is immediately visible to the second's `.prompts()` reads.
pub type SharedServedPromptEngine =
    std::sync::Arc<std::sync::Mutex<ainxt_prompt::service::ServedPromptEngine>>;

/// Construct the [`SharedServedPromptEngine`] the daemon's canary + drift cadence ticks share, with the
/// SAME config-sourced L2 policy body [`assemble_served_prompt_engine_from_config`] resolves (a
/// `[policy]` TOML layer, not the compiled-in default). Bound to
/// [`NullSink`](ainxt_prompt::service::NullSink) — [`spawn_prompt_canary_tick`]/[`spawn_prompt_drift_tick`]
/// only ever call `evaluate_canary`/`.prompts()` (the deployment/registry fields), never
/// `compile_turn`/`compile_turn_adaptive` (the only methods that touch the sink), so the
/// mandatory-durable-forensic-sink guarantee `with_forensic_file` exists for is moot for this handle.
///
/// **`needs_hot_wiring`**: this is a fresh, private instance — not the SAME `PromptDeployment` object
/// `build_served_chat_prompt` constructs for the real `/v1/chat` transport call-site. Unifying those two
/// is `assemble_served_prompt_engine`'s own already-documented further wire ("the shipped `/v1/chat`
/// compile still uses the flat single-string engine"), not this gap — exactly the same honest posture
/// [`crate::prompt_optimizer_surface::spawn_prompt_optimizer_tick`] already documents for its own
/// private `Registry` ("not the SAME live registry `build_served_chat_prompt` owns for `/v1/chat`").
pub fn assemble_shared_served_prompt_engine_from_config(
    config: &ainxt_config::RuntimeConfig,
) -> SharedServedPromptEngine {
    let served = ainxt_prompt::served::served_chat_prompts_with_l2_policy(
        &ainxt_prompt::served::default_chat_families(),
        Some(&config.policy.l2_body),
    );
    std::sync::Arc::new(std::sync::Mutex::new(
        ainxt_prompt::service::ServedPromptEngine::new(
            served,
            std::sync::Arc::new(ainxt_prompt::service::NullSink),
        ),
    ))
}

/// **Gap closure — the missing periodic driver for [`run_prompt_canary_sweep_tick`].** That one-shot
/// evaluate-and-apply function was already correctly wired to a real `ServedPromptEngine` (its own test
/// above proves the pointer-flip), but nothing ever called it on a schedule — no `spawn_*_tick` wrapper,
/// no boot-time cadence. This closes exactly that, mirroring
/// [`crate::prompt_optimizer_surface::spawn_prompt_optimizer_tick`]'s pattern exactly (this module's own
/// established convention for a spawnable cadence): a `tokio::time::interval`-driven loop that calls the
/// one-shot tick function every `period`, spawned once at daemon boot and held for the process lifetime
/// (aborting/dropping the returned handle stops the loop).
///
/// `engine` is the [`SharedServedPromptEngine`] handle — build it once via
/// [`assemble_shared_served_prompt_engine_from_config`] and clone the `Arc` into this AND
/// [`spawn_prompt_drift_tick`] (never construct a second, disconnected engine for either).
///
/// **`needs_hot_wiring`, honestly** (unchanged from `run_prompt_canary_sweep_tick`'s own doc, now doubly
/// true for the cadence itself):
/// 1. `metrics_source` is the caller-supplied live-traffic seam, polled once per due tick. It returns
///    `None` when there is no fresh prod/canary-arm sample this interval — an honest no-op, exactly like
///    [`crate::spawn_autoscale_tick`]'s permanently-empty `samples` on the air-gapped default — or
///    `Some((prod, canary))` computed by the caller from real sampled live traffic. There is no
///    telemetry query against a real data plane inside this function.
/// 2. a rollback NOTIFICATION channel (§8: "a human is notified, not paged") is a further wire — this
///    loop only logs the applied decision.
pub fn spawn_prompt_canary_tick(
    engine: SharedServedPromptEngine,
    controller: ainxt_prompt::canary::CanaryController,
    period: std::time::Duration,
    metrics_source: impl Fn() -> Option<(
            ainxt_prompt::canary::ArmMetrics,
            ainxt_prompt::canary::ArmMetrics,
        )> + Send
        + 'static,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut iv = tokio::time::interval(period);
        loop {
            iv.tick().await;
            let Some((prod, canary)) = metrics_source() else {
                // No fresh live-traffic-sourced arm metrics this interval — honest no-op (see doc).
                continue;
            };
            let decision = {
                let mut eng = engine.lock().expect("served prompt engine lock");
                run_prompt_canary_sweep_tick(&mut eng, &controller, &prod, &canary)
            };
            eprintln!("ainxt-runtimed: prompt canary sweep tick -> {decision:?}");
        }
    })
}

/// **Gap closure — `ainxt_prompt::drift::DriftMonitor`/`DriftKey`/`Baseline` (next to
/// `ServedChatPrompts`, `PROMPT_ENGINEERING.md` §8/PRMT-08) had ZERO callers anywhere in
/// `ainxt-runtimed`/`ainxt-server`.** Fully implemented and unit-tested
/// (`ainxt-prompt/tests/r11_drift_from_served.rs`, `r12_drift_controller.rs`), but nothing in the
/// composition root ever constructed a `DriftMonitor`, installed baselines from a real served
/// deployment, or checked a live/sampled turn against it — the continuous quality-drift monitor stayed
/// reachable only from `ainxt-prompt`'s own tests.
///
/// NOT to be confused with the unrelated `ainxt_canary::experiment`/[`OnlineReleaseController`]/
/// [`SampledDriftMonitor`]/[`Cusum`] system this module's [`build_release_controller`] already wires —
/// that is the release-controller's OWN CUSUM drift on prod/candidate rollout, a different,
/// already-closed gap. This function is specifically `ainxt_prompt`'s own per-`(role, family, version)`
/// drift stream.
///
/// The composition-root entrypoint a daemon cadence calls: observe ONE already-scored sampled live turn
/// for `family` against `monitor`'s installed baseline, where the drift key is resolved from
/// `engine.prompts().drift_key` — the SAME [`SharedServedPromptEngine`]/`ServedChatPrompts` deployment
/// [`run_prompt_canary_sweep_tick`] mutates, so a canary pointer-flip and a drift baseline always agree
/// on which family/version they track. Returns the confirmed
/// [`DriftEvent`](ainxt_prompt::drift::DriftEvent) exactly once per sustained degradation (never
/// re-alerts every turn after, per [`DriftMonitor::observe_score`](ainxt_prompt::drift::DriftMonitor::observe_score)'s
/// own one-ticket-not-a-paging-storm contract).
///
/// `score` is the caller-supplied, already-scored quality (0-100) for one SAMPLED live turn — the same
/// "daemon computes the online numbers and calls in" seam `run_prompt_canary_sweep_tick`'s `prod`/
/// `canary` [`ArmMetrics`](ainxt_prompt::canary::ArmMetrics) already documents; no live judge/telemetry
/// call happens inside this function.
pub fn run_prompt_drift_sweep_tick(
    engine: &ainxt_prompt::service::ServedPromptEngine,
    monitor: &mut ainxt_prompt::drift::DriftMonitor,
    family: &ainxt_prompt::registry::ModelFamily,
    score: u8,
) -> Option<ainxt_prompt::drift::DriftEvent> {
    let key = engine.prompts().drift_key(family);
    monitor.observe_score(&key, score)
}

/// **Spawn the quality-drift monitor cadence on daemon start** — mirrors [`spawn_prompt_canary_tick`]'s
/// pattern exactly (this module's established convention for a spawnable cadence).
///
/// At spawn time, installs every served family's deploy-time baseline from `engine`'s bound
/// `ServedChatPrompts` via
/// [`ServedChatPrompts::install_drift_baselines`](ainxt_prompt::served::ServedChatPrompts::install_drift_baselines)
/// (called ONCE, not every tick — re-installing on every tick would reset the rolling window every
/// `period`, and the monitor could never accumulate `DriftPolicy::min_samples`). Every `period` after
/// that it polls `sampled_turn_source` for at most one already-sampled, already-scored live turn and
/// drives [`run_prompt_drift_sweep_tick`] against the SAME [`SharedServedPromptEngine`]
/// [`spawn_prompt_canary_tick`] mutates — reused, never a second disconnected engine (this gap's own
/// requirement).
///
/// **`needs_hot_wiring`, honestly**, matching [`spawn_prompt_canary_tick`]'s own admission for
/// consistency:
/// 1. `sampled_turn_source` is the caller-supplied seam, polled once per due tick. It returns `None`
///    when no fresh sampled turn is ready this interval — an honest no-op, exactly like
///    `spawn_prompt_canary_tick`'s `metrics_source` — or `Some((family, score))` when a deployment's own
///    sampling/judge (e.g. [`DriftController`](ainxt_prompt::drift::DriftController)/
///    [`SamplingPolicy`](ainxt_prompt::drift::SamplingPolicy), or a live LLM judge) has already decided
///    to sample AND scored a live turn. There is no live traffic sampler or judge call inside this
///    function.
/// 2. the `DriftAction::OpenTicketAndRollback` a confirmed [`DriftEvent`](ainxt_prompt::drift::DriftEvent)
///    recommends is only LOGGED here — actually applying the rollback (the same pointer-flip
///    [`run_prompt_canary_sweep_tick`] applies for a canary regression) is a further wire, deliberately
///    left to the caller/deployment rather than an unreviewed auto-action on a slower, judge-scored
///    signal.
pub fn spawn_prompt_drift_tick(
    engine: SharedServedPromptEngine,
    period: std::time::Duration,
    sampled_turn_source: impl Fn() -> Option<(ainxt_prompt::registry::ModelFamily, u8)> + Send + 'static,
) -> tokio::task::JoinHandle<()> {
    let mut monitor =
        ainxt_prompt::drift::DriftMonitor::new(ainxt_prompt::drift::DriftPolicy::default());
    {
        let eng = engine.lock().expect("served prompt engine lock");
        eng.prompts().install_drift_baselines(&mut monitor);
    }
    tokio::spawn(async move {
        let mut iv = tokio::time::interval(period);
        loop {
            iv.tick().await;
            let Some((family, score)) = sampled_turn_source() else {
                // No fresh sampled/scored live turn this interval — honest no-op (see doc).
                continue;
            };
            let event = {
                let eng = engine.lock().expect("served prompt engine lock");
                run_prompt_drift_sweep_tick(&eng, &mut monitor, &family, score)
            };
            if let Some(event) = event {
                eprintln!(
                    "ainxt-runtimed: prompt quality-drift CONFIRMED for {:?} -> recommended action={:?} \
                     (baseline_mean={}, window_mean={}, n={})",
                    event.key, event.action, event.baseline_mean, event.window_mean, event.window_n
                );
            }
        }
    })
}

/// **Gap closure — `ainxt_quality::monitor::provider_silent_update`/[`ProviderVerdict`] (the
/// Welch-t-test tripwire distinguishing a silent provider model-swap from an intentional,
/// deployment-initiated change) had ZERO callers anywhere outside its own `#[cfg(test)]`.** Fully
/// implemented and unit-tested, but nothing in the composition root ever re-scored a frozen tripwire
/// set against a live provider and asked whether the observed shift is explained by a recorded
/// control-plane change.
///
/// NOT to be confused with [`SampledDriftMonitor`]/[`Cusum`] (already wired via
/// [`build_release_controller`]) or [`run_prompt_drift_sweep_tick`] above: both of those are drift-on-
/// quality-SCORES-over-time monitors (a streaming CUSUM change-point over a rolling window of live
/// turns). This is a DIFFERENT mechanism — a two-sample significance test (Welch's t-test) between a
/// FROZEN baseline tripwire-score set and a freshly re-scored current set, specifically aimed at the
/// "the cloud vendor silently swapped the model behind the endpoint" failure mode: an abrupt
/// step-change signature, gated on whether a recorded control-plane change explains it (if it does,
/// this is an intentional deployment change, not a silent swap).
///
/// The composition-root entrypoint a daemon cadence calls: one evaluate pass of `baseline_scores`
/// (a provider's frozen tripwire scores, established once at registration) against `current_scores`
/// (a freshly re-scored run of the SAME tripwire set against the live provider). Pure pass-through to
/// [`provider_silent_update`] — kept as a distinct composition-root fn (mirrors
/// [`run_prompt_canary_sweep_tick`]'s thin-wrapper-over-existing-logic shape) so the daemon's own
/// cadence surface names it alongside its `spawn_*` counterpart below.
pub fn run_provider_silent_update_tick(
    baseline_scores: &[f64],
    current_scores: &[f64],
    control_plane_changed: bool,
    alpha: f64,
) -> ProviderVerdict {
    provider_silent_update(
        baseline_scores,
        current_scores,
        control_plane_changed,
        alpha,
    )
}

/// **Spawn the provider-silent-update tripwire cadence on daemon start** — mirrors
/// [`spawn_prompt_drift_tick`]'s pattern exactly (this module's established convention for a
/// spawnable cadence), with ONE difference reflecting a real asymmetry: unlike
/// [`ainxt_prompt::served::ServedChatPrompts`] (which always has *some* deploy-time baseline to
/// install, even on the compiled-in default), there is no default frozen tripwire baseline for a
/// provider that was never registered with one — so this returns `Option<JoinHandle<()>>` and is a
/// clean no-op (`None`, no task spawned at all) when `baseline` is `None`, exactly mirroring
/// [`crate::AssembledFull::spawn_autoscale_tick`]'s "`None` when no tuning declared" gate (this
/// module's OTHER established convention, for a cadence with no meaningful default state to run
/// against — as opposed to [`spawn_prompt_canary_tick`]/[`spawn_prompt_drift_tick`], which always have
/// one).
///
/// `baseline`'s `Vec<f64>` (the frozen tripwire set) is captured ONCE at spawn time — analogous to
/// [`spawn_prompt_drift_tick`] installing its baselines once, not every tick: a tripwire baseline that
/// silently re-froze itself every tick could never detect a *sustained* swap, only ever compare a
/// window to itself. Every `period` after that it polls `current_sample_source` for at most one
/// freshly re-scored tripwire run plus whether a control-plane change is on record for this window,
/// and drives [`run_provider_silent_update_tick`] against the SAME frozen baseline.
///
/// **`needs_hot_wiring`, honestly** (matching [`spawn_prompt_drift_tick`]'s own admission for
/// consistency — this codebase's established bar, not a lower one for this gap):
/// 1. `baseline` itself is caller-established — there is no live "run the tripwire eval set against
///    this provider once at registration and freeze the scores" step inside this function; a
///    deployment computes that once (e.g. from its own eval harness) and supplies `Some((provider_id,
///    scores))` in its place. On the air-gapped default (no such registration), `main.rs` passes
///    `None` and this cadence simply never starts — the identical absent-is-off shape every other
///    optionally-declared cadence in this crate already has.
/// 2. `current_sample_source` is the caller-supplied seam, polled once per due tick. It returns
///    `None` when there is no fresh re-scored tripwire run ready this interval — an honest no-op,
///    exactly like [`spawn_prompt_drift_tick`]'s `sampled_turn_source` — or
///    `Some((current_scores, control_plane_changed))` when a deployment's own scheduler has already
///    re-run the SAME frozen tripwire set against the live provider and checked its own change-log for
///    a recorded control-plane change this window. There is no live judge/telemetry call and no
///    control-plane change-log query inside this function.
///
/// A confirmed [`ProviderVerdict::SilentProviderUpdate`] is only LOGGED here — routing it to a real
/// incident/paging channel is a further wire, the same deliberate human-in-the-loop posture
/// [`spawn_prompt_drift_tick`]'s own doc documents for a confirmed drift event.
pub fn spawn_provider_silent_update_tick(
    baseline: Option<(String, Vec<f64>)>,
    alpha: f64,
    period: std::time::Duration,
    current_sample_source: impl Fn() -> Option<(Vec<f64>, bool)> + Send + 'static,
) -> Option<tokio::task::JoinHandle<()>> {
    let (provider_id, baseline_scores) = baseline?;
    Some(tokio::spawn(async move {
        let mut iv = tokio::time::interval(period);
        loop {
            iv.tick().await;
            let Some((current_scores, control_plane_changed)) = current_sample_source() else {
                // No fresh re-scored tripwire run this interval — honest no-op (see doc).
                continue;
            };
            let verdict = run_provider_silent_update_tick(
                &baseline_scores,
                &current_scores,
                control_plane_changed,
                alpha,
            );
            match &verdict {
                ProviderVerdict::SilentProviderUpdate {
                    p_value,
                    baseline_mean,
                    current_mean,
                } => {
                    eprintln!(
                        "ainxt-runtimed: provider '{provider_id}' SILENT MODEL SWAP suspected — \
                         tripwire shift p={p_value:.4} with NO control-plane change on record \
                         (baseline_mean={baseline_mean:.2}, current_mean={current_mean:.2})"
                    );
                }
                ProviderVerdict::ExplainedByChange { p_value } => {
                    eprintln!(
                        "ainxt-runtimed: provider '{provider_id}' tripwire shift (p={p_value:.4}) \
                         explained by a recorded control-plane change — not flagged"
                    );
                }
                ProviderVerdict::Indeterminate(reason) => {
                    eprintln!(
                        "ainxt-runtimed: provider '{provider_id}' silent-update tripwire \
                         indeterminate: {reason}"
                    );
                }
                ProviderVerdict::Stable { .. } => {}
            }
        }
    }))
}

// ============================ RBI outsourcing register (regulated-fi) ============================

/// The deployment's data-residency label the outsourcing register resolves routes against (RBI
/// localisation). `AINXT_DATA_RESIDENCY`, defaulting to `"in"` (India) — the regulated home region.
pub fn residency() -> String {
    std::env::var("AINXT_DATA_RESIDENCY")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "in".to_string())
        .to_ascii_lowercase()
}

/// The default RBI outsourcing register the shipped daemon installs on the Model Router as its
/// non-overridable eligibility input. The air-gapped default is **empty** — which is the fail-closed
/// posture. The daemon installs it via
/// [`with_outsourcing_register_authoritative`](ainxt_runtime::router::ModelRouter::with_outsourcing_register_authoritative):
/// externality is decided **authoritatively-by-construction**, NOT from a provider adapter's
/// `outsourcing_route()` self-declaration (which was fail-OPEN). Every provider is treated as an
/// external/outsourced route (register route id = `derive_route_id(id)`) and excluded (`NoRegisterEntry`)
/// until a deployment registers a board-approved arrangement for it — UNLESS its id is in the signed
/// on-prem exemption set (`in_house_exemptions`: the `offline` route + any `ProviderKind::Local`
/// provider). `exit_cadence` is the staleness window (seconds) after which a regulated route's
/// exit-rehearsal is stale.
pub fn default_outsourcing_register(exit_cadence: u64) -> OutsourcingRegister {
    OutsourcingRegister::new(exit_cadence)
}

/// A [`RouterClock`] over the wall clock (seconds since the Unix epoch) — what the outsourcing /
/// model-risk guards read for time-dependent checks (exit-rehearsal staleness). The `ainxt-runtime`
/// router is deliberately clock-free; the composition edge supplies the real clock.
pub fn wall_router_clock() -> RouterClock {
    Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    })
}

// ============================ Online canary + auto-rollback + drift (eval-tester) ============================

/// The candidate/champion git-refs the served release controller flips the deploy pointer between,
/// and the anytime-valid + drift tuning. A deployment overrides the refs (the control-repo SHAs); the
/// defaults are honest placeholders so the controller is LIVE on the served surface with zero config.
#[derive(Debug, Clone)]
pub struct ReleaseControllerConfig {
    pub candidate_arm: String,
    pub candidate_ref: String,
    pub champion_ref: String,
    /// Established champion quality (0–100) the candidate is judged non-inferior to.
    pub baseline: f64,
    /// Non-inferiority margin (metric points).
    pub margin: f64,
    /// Confidence-sequence error level (time-uniform coverage 1 − α).
    pub alpha: f64,
    /// Minimum candidate samples before a Promote (a Rollback can fire earlier — safety).
    pub min_samples: u64,
    /// Target sample size the AsympCS ρ is tuned for.
    pub target_n: u64,
    /// Post-promotion drift: sample every Nth turn; auto-roll-back on a confirmed downward change-point.
    pub drift_sample_rate: u64,
    pub drift_auto_rollback: bool,
    /// GAP-FIX eval-tester-scenarios — `ainxt_canary::experiment::TrafficSplit` (the git-ref-pinned
    /// request router feed.rs's own doc names as *the* source of `served_ref`: "the git-ref that
    /// actually served the turn (from the upstream traffic split)") had zero callers anywhere in the
    /// workspace outside its own crate's tests, even though the release controller it feeds
    /// (`ingest_served_turn`) is already live on the served surface. Candidate traffic share in basis
    /// points (10000 = 100%); the remainder routes to `champion_ref`. Default is a conservative 5%
    /// canary.
    pub candidate_traffic_bps: u32,
}

impl Default for ReleaseControllerConfig {
    fn default() -> Self {
        ReleaseControllerConfig {
            candidate_arm: "candidate".to_string(),
            candidate_ref: "env/candidate".to_string(),
            champion_ref: "env/prod".to_string(),
            baseline: 80.0,
            margin: 5.0,
            alpha: 0.05,
            min_samples: 30,
            target_n: 200,
            drift_sample_rate: 1,
            drift_auto_rollback: true,
            candidate_traffic_bps: 500,
        }
    }
}

/// Build the online release controller instantiated live on the served surface: the anytime-valid
/// canary (pre-promotion non-inferiority, no peeking penalty) plus the sampled CUSUM drift monitor
/// (post-promotion erosion → auto-rollback). This is the wire that makes canary + auto-rollback +
/// drift part of the SHIPPED served surface rather than a test-only fixture.
pub fn build_release_controller(cfg: &ReleaseControllerConfig) -> OnlineReleaseController {
    let canary = AlwaysValidCanary::new(AlwaysValidConfig::tuned(
        cfg.baseline,
        cfg.margin,
        cfg.alpha,
        cfg.min_samples,
        cfg.target_n,
    ));
    // CUSUM centered on the established baseline; a modest slack k and threshold h give a responsive
    // but non-jittery downward change-point detector for the promoted candidate.
    let cusum = Cusum::new(cfg.baseline, cfg.margin / 2.0, cfg.margin * 2.0);
    let drift = SampledDriftMonitor::new(
        cusum,
        cfg.drift_sample_rate,
        cfg.drift_auto_rollback,
        &cfg.candidate_ref,
    );
    OnlineReleaseController::new(
        canary,
        drift,
        &cfg.candidate_arm,
        &cfg.candidate_ref,
        &cfg.champion_ref,
    )
}

/// Build the git-ref traffic split that decides which ref (`champion_ref` or `candidate_ref`) serves a
/// given request — the SAME two refs [`build_release_controller`] canaries. This is the wire that makes
/// [`ainxt_canary::experiment::TrafficSplit`] part of the shipped served surface: before this, the
/// controller could be driven with a `served_ref` argument, but nothing anywhere computed that
/// argument from an actual request — the "upstream traffic split" `ainxt_quality::feed`'s doc
/// describes as the source of `served_ref` didn't exist as a caller-reachable seam. Deterministic
/// (stable FNV hash, no RNG): the same request key always routes to the same ref.
pub fn build_traffic_split(
    cfg: &ReleaseControllerConfig,
) -> ainxt_canary::experiment::TrafficSplit {
    let candidate_bps = cfg.candidate_traffic_bps.min(10_000);
    let champion_bps = 10_000 - candidate_bps;
    ainxt_canary::experiment::TrafficSplit::new(vec![
        ainxt_canary::experiment::SplitArm {
            name: "champion".to_string(),
            git_ref: cfg.champion_ref.clone(),
            weight_bps: champion_bps,
        },
        ainxt_canary::experiment::SplitArm {
            name: cfg.candidate_arm.clone(),
            git_ref: cfg.candidate_ref.clone(),
            weight_bps: candidate_bps,
        },
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use ainxt_context::ClaimSource;
    use ainxt_types::DataClass;

    fn kb_two_departments() -> KbConfig {
        // Two Confidential settlement docs, each node-ACL locked to a different department. A
        // platform-scope surface indexes both; the pre-rank RBAC decides who sees which.
        KbConfig {
            documents: vec![
                KbDocument {
                    id: "settle-a".into(),
                    source: "settlement-a.md".into(),
                    text: "settlement reconciliation runbook for department alpha".into(),
                    data_class: DataClass::Confidential,
                    scope: crate::KbScope::Platform,
                    namespace: None,
                    repo: None,
                    department: Some("alpha".into()),
                    max_ad_level: None,
                    allow_groups: vec![],
                    deny_groups: vec![],
                    row_attributes: BTreeMap::new(),
                },
                KbDocument {
                    id: "settle-b".into(),
                    source: "settlement-b.md".into(),
                    text: "settlement reconciliation runbook for department beta".into(),
                    data_class: DataClass::Confidential,
                    scope: crate::KbScope::Platform,
                    namespace: None,
                    repo: None,
                    department: Some("beta".into()),
                    max_ad_level: None,
                    allow_groups: vec![],
                    deny_groups: vec![],
                    row_attributes: BTreeMap::new(),
                },
            ],
            rls_department_isolation: false,
            rag_enabled: true,
        }
    }

    #[test]
    fn served_context_is_department_node_acl_filtered_pre_rank() {
        let kb = kb_two_departments();
        let corpus = retrieval_corpus_for_scope(&kb, RetrievalScope::PlatformAndNamespace);
        assert_eq!(corpus.len(), 2, "both docs are in scope before RBAC");

        // A caller in department alpha (cleared for Confidential) retrieves the settlement runbook.
        let principal = Principal::user("u-alpha", &["chat.send"])
            .with_clearance(DataClass::Confidential)
            .with_department("alpha");
        let access = access_for(&principal, Some(3), &[]);
        let seeds = BTreeMap::new();
        let window = compile_served_context(
            &corpus,
            "settlement reconciliation",
            &access,
            None,
            None,
            &seeds,
            eligible_default(),
        );
        let ids: Vec<&str> = window
            .context
            .citations
            .iter()
            .map(|c| c.chunk_id.as_str())
            .collect();
        assert!(
            ids.contains(&"settle-a"),
            "alpha's own department doc must ground: {ids:?}"
        );
        assert!(
            !ids.contains(&"settle-b"),
            "beta's node-ACL doc must be filtered PRE-RANK for an alpha caller — existence never \
             leaks: {ids:?}"
        );
        // Lineage never records the filtered node either (not scored → not accounted, not leaked).
        assert!(
            !window
                .context
                .lineage
                .iter()
                .any(|n| n.chunk_id == "settle-b"),
            "the out-of-department node must never enter the window lineage"
        );
    }

    #[test]
    fn served_fabric_compiles_layers_and_fits_router_eligible_set() {
        // The composition-root fabric-of-graphs compile: a repo-indexed code fabric (2 layers) overlaid
        // with the KB EnterpriseDocs layer → 3 distinct layers compiled in for a broad code+docs turn.
        let code_graph = FabricGraph::new()
            .with_layer("sym1", GraphLayer::Symbol)
            .with_layer("call1", GraphLayer::Call)
            .with_edge("sym1", ainxt_context::optimizer::EdgeKind::Calls, "call1");
        let code_contents = vec![
            CtxChunk::new(
                "sym1",
                "parser.rs",
                "settlement import dependency signature",
                DataClass::Internal,
            ),
            CtxChunk::new(
                "call1",
                "caller.rs",
                "settlement import dependency call site",
                DataClass::Internal,
            ),
        ];
        let kb = KbConfig {
            documents: vec![KbDocument {
                id: "runbook".into(),
                source: "runbook.md".into(),
                text: "settlement import dependency runbook".into(),
                data_class: DataClass::Internal,
                scope: crate::KbScope::Platform,
                namespace: None,
                repo: None,
                department: None,
                max_ad_level: None,
                allow_groups: vec![],
                deny_groups: vec![],
                row_attributes: BTreeMap::new(),
            }],
            rls_department_isolation: false,
            rag_enabled: true,
        };
        let fabric = served_fabric_from_kb(
            &kb,
            RetrievalScope::PlatformAndNamespace,
            code_graph,
            code_contents,
        );
        assert_eq!(
            fabric.len(),
            3,
            "code layers + KB enterprise-docs layer indexed"
        );

        let principal = Principal::user("u", &["chat.send"]).with_clearance(DataClass::Internal);
        let access = access_for(&principal, None, &[]);
        // A debug+refactor turn routes to code layers (refactor/import/dependency) AND enterprise
        // docs + runtime (why/fail), so both the code-fabric and KB layers are compiled in.
        let query = "why did the settlement import dependency refactor fail";

        // Wide router set → all layers compile in; the window is NOT limited by budget here.
        let wide = compile_served_fabric(&fabric, query, &access, None, &eligible_default(), "");
        assert!(
            wide.layer_count() >= 3,
            "3+ distinct fabric layers compiled into the window: {:?}",
            wide.compiled_layers
        );
        assert!(wide.compiled_layers.contains(&GraphLayer::Symbol));
        assert!(wide.compiled_layers.contains(&GraphLayer::EnterpriseDocs));

        // The Model-Router's per-turn eligible set (a 3-token failover-tight model) binds the fit —
        // proving the explicit set, not a default, resolves the budget floor (Gap-22).
        let router_tiny = [EligibleModel::new("failover-tiny", 3)];
        let tight = compile_served_fabric(&fabric, query, &access, None, &router_tiny, "");
        assert_eq!(
            tight.window.window_tokens, 3,
            "the router eligible set resolves the budget floor"
        );
        assert!(
            tight.window.context.chunks.len() < wide.window.context.chunks.len(),
            "the narrow router floor sheds evidence vs the wide set"
        );
        assert!(
            tight
                .window
                .context
                .lineage
                .iter()
                .any(|n| n.outcome == ainxt_context::LineageOutcome::DroppedByBudget),
            "shed evidence is ACCOUNTED — never a silent truncation on failover"
        );
    }

    #[test]
    fn served_fabric_is_node_acl_filtered_pre_rank() {
        // The served fabric compile still enforces per-node RBAC pre-rank (existence never leaks): a
        // dept-locked KB node is filtered for an out-of-department caller.
        let kb = KbConfig {
            documents: vec![KbDocument {
                id: "beta-only".into(),
                source: "beta.md".into(),
                text: "settlement reconciliation runbook".into(),
                data_class: DataClass::Confidential,
                scope: crate::KbScope::Platform,
                namespace: None,
                repo: None,
                department: Some("beta".into()),
                max_ad_level: None,
                allow_groups: vec![],
                deny_groups: vec![],
                row_attributes: BTreeMap::new(),
            }],
            rls_department_isolation: false,
            rag_enabled: true,
        };
        let fabric = served_fabric_from_kb(
            &kb,
            RetrievalScope::PlatformAndNamespace,
            FabricGraph::new(),
            vec![],
        );
        let principal = Principal::user("u-alpha", &["chat.send"])
            .with_clearance(DataClass::Confidential)
            .with_department("alpha");
        let access = access_for(&principal, Some(3), &[]);
        let routed = compile_served_fabric(
            &fabric,
            "settlement reconciliation",
            &access,
            None,
            &eligible_default(),
            "",
        );
        assert!(
            routed.window.context.chunks.is_empty(),
            "a beta-locked node must be filtered pre-rank for an alpha caller — existence never leaks"
        );
    }

    #[test]
    fn served_context_is_rls_row_filtered_pre_rank() {
        use ainxt_context::{RlsSession, RowFilter};
        // Two same-scope, same-class docs distinguished only by a per-ROW tenant attribute (RLS
        // labels, not node-ACL). The row-filter binds the caller's tenant and requires the match.
        let doc = |id: &str, tenant: &str| {
            let mut attrs = BTreeMap::new();
            attrs.insert("tenant".to_string(), tenant.to_string());
            KbDocument {
                id: id.into(),
                source: format!("{id}.md"),
                text: "ledger row detail".into(),
                data_class: DataClass::Confidential,
                scope: crate::KbScope::Platform,
                namespace: None,
                repo: None,
                department: None,
                max_ad_level: None,
                allow_groups: vec![],
                deny_groups: vec![],
                row_attributes: attrs,
            }
        };
        let kb = KbConfig {
            documents: vec![doc("row-t1", "t1"), doc("row-t2", "t2")],
            rls_department_isolation: false,
            rag_enabled: true,
        };
        let corpus = retrieval_corpus_for_scope(&kb, RetrievalScope::PlatformAndNamespace);

        let principal =
            Principal::user("u", &["chat.send"]).with_clearance(DataClass::Confidential);
        let access = access_for(&principal, None, &[]);
        // SET LOCAL app.tenant = 't1'; USING (tenant = current_setting('app.tenant')).
        let filter =
            RowFilter::new(RlsSession::new().set("tenant", "t1")).require("tenant", "tenant");
        let seeds = BTreeMap::new();
        let window = compile_served_context(
            &corpus,
            "ledger row",
            &access,
            Some(&filter),
            None,
            &seeds,
            eligible_default(),
        );
        let ids: Vec<&str> = window
            .context
            .citations
            .iter()
            .map(|c| c.chunk_id.as_str())
            .collect();
        assert!(
            ids.contains(&"row-t1"),
            "the caller's tenant row grounds: {ids:?}"
        );
        assert!(
            !ids.contains(&"row-t2"),
            "a foreign-tenant row is RLS-filtered PRE-RANK (existence never leaks): {ids:?}"
        );
    }

    #[test]
    fn numeric_gate_blocks_model_arithmetic_that_does_not_re_derive() {
        let kb = kb_two_departments();
        let corpus = retrieval_corpus_for_scope(&kb, RetrievalScope::PlatformAndNamespace);
        let principal = Principal::user("u-alpha", &["chat.send"])
            .with_clearance(DataClass::Confidential)
            .with_department("alpha");
        let access = access_for(&principal, Some(3), &[]);
        let seeds = BTreeMap::new();
        let window = compile_served_context(
            &corpus,
            "reconciliation total",
            &access,
            None,
            None,
            &seeds,
            eligible_default(),
        );

        // The model asserts a total of 100; the authoritative re-derivation says 250 → BLOCK.
        let claim = ainxt_context::NumericClaim::metric(
            100.0,
            "count",
            ainxt_context::ValueClass::Exact,
            "total",
            "qh",
        );
        let rederiver = MapRederiver::new().with(
            &ClaimSource::Metric {
                id: "total".into(),
                query_hash: "qh".into(),
            }
            .rederive_key()
            .unwrap(),
            250.0,
        );
        let verified = verify_numbers(
            &window,
            "the reconciliation total is 100",
            std::slice::from_ref(&claim),
            &rederiver,
            &ainxt_context::Tolerance::default(),
        );
        assert!(
            !verified.ships(),
            "a number the server cannot reproduce must not ship"
        );
        assert!(
            verified.blocked_on_mismatch(),
            "the mismatch is the payment-incident signal"
        );
    }

    // GAP-FIX context-fabric — `VerifiedAnswer::to_event_record` was fully implemented and unit-tested
    // but had zero callers outside `ainxt-context`'s own tests. Proves the composition-root wrapper
    // carries the SAME lineage/rederivation this turn actually produced into the durable event record.
    #[test]
    fn served_turn_event_record_carries_this_turns_lineage_and_rederivation() {
        let kb = kb_two_departments();
        let corpus = retrieval_corpus_for_scope(&kb, RetrievalScope::PlatformAndNamespace);
        let principal = Principal::user("u-alpha", &["chat.send"])
            .with_clearance(DataClass::Confidential)
            .with_department("alpha");
        let access = access_for(&principal, Some(3), &[]);
        let seeds = BTreeMap::new();
        let window = compile_served_context(
            &corpus,
            "reconciliation total",
            &access,
            None,
            None,
            &seeds,
            eligible_default(),
        );
        assert!(
            !window.context.lineage.is_empty(),
            "precondition: this turn actually grounded evidence"
        );

        let claim = ainxt_context::NumericClaim::metric(
            250.0,
            "count",
            ainxt_context::ValueClass::Exact,
            "total",
            "qh",
        );
        let rederiver = MapRederiver::new().with(
            &ClaimSource::Metric {
                id: "total".into(),
                query_hash: "qh".into(),
            }
            .rederive_key()
            .unwrap(),
            250.0,
        );
        let verified = verify_numbers(
            &window,
            "the reconciliation total is 250",
            std::slice::from_ref(&claim),
            &rederiver,
            &ainxt_context::Tolerance::default(),
        );
        assert!(
            verified.ships(),
            "precondition: a reproducible number ships"
        );

        let record = served_turn_event_record(&verified, &window, "sha-abc123", None);
        assert_eq!(record.control_plane_sha, "sha-abc123");
        assert_eq!(
            record.lineage, window.context.lineage,
            "the record's lineage is THIS turn's, not empty/default"
        );
        assert!(
            record.federated_epsilon_spent.is_none(),
            "the honest default for a non-federated turn"
        );
    }

    // GAP-FIX surfaces-profiles-skills-config — `SurfaceCatalog::builtin_with_tenant_overrides` was
    // fully implemented and unit-tested but had zero callers outside `ainxt-surface`'s own tests.
    // Proves the composition-root wrapper resolves the SAME defaults->deployment->tenant chain: the
    // tenant layer (most specific) wins over the deployment layer, and an untouched canonical field
    // survives from the defaults.
    #[test]
    fn surface_catalog_with_tenant_overrides_resolves_the_full_layer_chain() {
        let c = surface_catalog_with_tenant_overrides(
            &[("chat", "[model_policy]\ndefault_tier = \"medium\"")],
            &[("chat", "[model_policy]\ndefault_tier = \"complex\"")],
        )
        .unwrap();
        assert_eq!(
            c.get("chat").unwrap().model_policy.default_tier,
            ainxt_types::Tier::Complex
        );
        assert_eq!(
            c.get("chat").unwrap().autonomy,
            ainxt_profile::Autonomy::ReadOnly
        );
    }

    // GAP-FIX data-surfaces-artifacts — `ArtifactStore::erasure_cascade` was fully implemented and
    // unit-tested but had zero callers outside `ainxt-context`'s own tests. Proves the composition-
    // root wrapper returns the artifact PLUS every derived embedding produced from it, sorted, and
    // scoped only to that artifact — never a sibling's embeddings.
    #[test]
    fn artifact_erasure_cascade_purges_the_artifact_and_only_its_own_derived_embeddings() {
        use ainxt_context::artifact::{Artifact, ArtifactStore, DerivedEmbedding, Modality};

        let mut store = ArtifactStore::new();
        store.add_artifact(Artifact::new(
            "kyc-1",
            "ns",
            Modality::Image,
            DataClass::Confidential,
        ));
        store.add_artifact(Artifact::new(
            "kyc-2",
            "ns",
            Modality::Image,
            DataClass::Confidential,
        ));
        store.add_derived(DerivedEmbedding {
            id: "emb-b".into(),
            artifact_id: "kyc-1".into(),
            vector: vec![],
        });
        store.add_derived(DerivedEmbedding {
            id: "emb-a".into(),
            artifact_id: "kyc-1".into(),
            vector: vec![],
        });
        store.add_derived(DerivedEmbedding {
            id: "emb-x".into(),
            artifact_id: "kyc-2".into(),
            vector: vec![],
        });

        let plan = artifact_erasure_cascade(&store, "kyc-1");
        assert_eq!(plan.artifact_id, "kyc-1");
        assert_eq!(
            plan.derived_embedding_ids,
            vec!["emb-a".to_string(), "emb-b".to_string()],
            "only kyc-1's own derived embeddings, sorted"
        );
    }

    // GAP-FIX data-surfaces-artifacts — `route_model` was fully implemented and unit-tested but had
    // zero callers outside `ainxt-context`'s own tests. Proves the composition-root wrapper enforces
    // the SAME ADR-012 rule: a regulated artifact never routes to a cloud model, even when a cloud
    // model is the only OTHER eligible candidate for the modality.
    #[test]
    fn route_artifact_model_never_routes_a_regulated_artifact_to_a_cloud_model() {
        use ainxt_context::artifact::{ArtifactModel, Modality, RoutingError};

        let models = vec![
            ArtifactModel::new("cloud-vision", Modality::Image, true),
            ArtifactModel::new("in-house-vision", Modality::Image, false),
        ];

        // A regulated artifact resolves to the in-house model, skipping the cloud one entirely.
        let picked = route_artifact_model(DataClass::RegulatedPayment, Modality::Image, &models)
            .expect("an in-house model is eligible");
        assert_eq!(picked.id, "in-house-vision");

        // With ONLY a cloud model available, a regulated artifact is REFUSED, never routed to it.
        let cloud_only = vec![ArtifactModel::new("cloud-vision", Modality::Image, true)];
        let refused =
            route_artifact_model(DataClass::RegulatedPayment, Modality::Image, &cloud_only);
        assert!(
            matches!(refused, Err(RoutingError::NoEligibleModel { .. })),
            "a regulated artifact must fail closed rather than route to a cloud model: {refused:?}"
        );

        // A non-regulated artifact may use the cloud model.
        let ok = route_artifact_model(DataClass::Internal, Modality::Image, &cloud_only)
            .expect("non-regulated data may use the cloud model");
        assert_eq!(ok.id, "cloud-vision");
    }

    // GAP-FIX data-surfaces-artifacts (multimodal no pipeline) — `route_model` had real routing logic
    // but nothing populated a live `ArtifactModel` fleet or ran an `ArtifactEmbedder` end-to-end.
    // Proves `ingest_artifact_batch` is the missing glue: a real fleet + real (offline) embedders
    // route, embed, and index a mixed batch — including a regulated artifact that must be REFUSED
    // (never silently indexed) — and the resulting store is directly consumable by
    // `MultiGraphFabric::with_artifacts`, tying the multimodal tier into the served fabric (gap 1).
    #[test]
    fn ingest_artifact_batch_indexes_eligible_artifacts_and_reports_refusals_never_silently() {
        use ainxt_context::artifact::{Artifact, IngestError, Modality, RoutingError};
        use ainxt_context::route::MultiGraphFabric;

        let artifacts = vec![
            // Public image → routes fine (in-house or cloud both eligible).
            Artifact::new("cheque-1", "kyc:bankA", Modality::Image, DataClass::Public),
            // Regulated audio → the default fleet HAS an in-house ASR model, so this succeeds too.
            Artifact::new(
                "call-1",
                "calls:bankA",
                Modality::Audio,
                DataClass::RegulatedPayment,
            ),
        ];
        let (store, outcomes) = ingest_artifact_batch(artifacts);
        assert_eq!(outcomes.len(), 2);
        assert!(
            outcomes[0].is_ok(),
            "public image must ingest: {:?}",
            outcomes[0]
        );
        assert!(
            outcomes[1].is_ok(),
            "regulated audio must route to the in-house ASR model: {:?}",
            outcomes[1]
        );

        let access =
            ainxt_context::AccessContext::new(DataClass::RegulatedPayment, None, None, &[]);
        assert_eq!(
            store.search("kyc:bankA", &access).len(),
            1,
            "the ingested image must be indexed"
        );
        assert_eq!(
            store.search("calls:bankA", &access).len(),
            1,
            "the ingested audio must be indexed"
        );
        // Each ingested artifact has its own linked derived embedding (the erasure cascade's basis).
        assert_eq!(
            store
                .erasure_cascade("cheque-1")
                .derived_embedding_ids
                .len(),
            1
        );
        assert_eq!(
            store.erasure_cascade("call-1").derived_embedding_ids.len(),
            1
        );

        // The populated store is exactly what `MultiGraphFabric::with_artifacts` accepts — the
        // multimodal tier reaches the served fabric compile_served_fabric routes over (gap 1).
        let fabric = MultiGraphFabric::new().with_artifacts(store);
        assert_eq!(fabric.artifacts_for("kyc:bankA", &access).len(), 1);

        // An empty batch indexes nothing (no panics, no phantom artifacts).
        let (empty_store, empty_outcomes) = ingest_artifact_batch(vec![]);
        assert!(empty_outcomes.is_empty());
        assert!(empty_store.search("ns", &access).is_empty());

        // A regulated artifact whose ONLY eligible model for its modality is cloud-only is refused,
        // never silently indexed — drives the same rule `ingest_artifact_batch` enforces via its
        // default fleet, but with a caller-supplied fleet that has no in-house option at all.
        let refusal_only_models = vec![ainxt_context::artifact::ArtifactModel::new(
            "cloud-only",
            Modality::Image,
            true,
        )];
        let mut refusal_store = ainxt_context::artifact::ArtifactStore::new();
        let vision = OfflineArtifactEmbedder::new(Modality::Image);
        let embedders: Vec<&dyn ainxt_context::artifact::ArtifactEmbedder> = vec![&vision];
        let err = ainxt_context::artifact::ingest_artifact(
            &mut refusal_store,
            Artifact::new(
                "regulated-scan",
                "ns",
                Modality::Image,
                DataClass::RegulatedPayment,
            ),
            &refusal_only_models,
            &embedders,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            IngestError::Routing(RoutingError::NoEligibleModel { .. })
        ));
        assert!(
            refusal_store.search("ns", &access).is_empty(),
            "a refused artifact must never be indexed"
        );
    }

    #[test]
    fn outsourcing_register_gates_external_routes_but_not_in_house() {
        use ainxt_runtime::provider::Provider;
        use ainxt_runtime::router::ModelRouter;

        // A provider that declares itself an EXTERNAL/outsourced route (subject to the register).
        struct ExternalRoute;
        impl Provider for ExternalRoute {
            fn id(&self) -> &str {
                "acme-cloud"
            }
            fn eligible(&self, _dc: DataClass) -> bool {
                true
            }
            fn outsourcing_route(&self) -> Option<&str> {
                Some("outsourcing.cloud.acme.chat")
            }
            fn stream(&self, _p: &str) -> tokio::sync::mpsc::Receiver<ainxt_protocol::Event> {
                let (_tx, rx) = tokio::sync::mpsc::channel(1);
                rx
            }
        }
        // An in-house route (not an outsourcing arrangement) — never gated by the register.
        struct InHouse;
        impl Provider for InHouse {
            fn id(&self) -> &str {
                "in-house"
            }
            fn eligible(&self, _dc: DataClass) -> bool {
                true
            }
            fn stream(&self, _p: &str) -> tokio::sync::mpsc::Receiver<ainxt_protocol::Event> {
                let (_tx, rx) = tokio::sync::mpsc::channel(1);
                rx
            }
        }

        // The register the shipped daemon installs by default (empty) — the fail-closed posture.
        let mut router = ModelRouter::new();
        router.register(Box::new(ExternalRoute));
        let router = router.with_outsourcing_register(
            default_outsourcing_register(3600),
            residency(),
            wall_router_clock(),
        );
        // The only provider is an unregistered external route → excluded before ranking (no route).
        assert!(
            router.select(DataClass::Pii, None).is_err(),
            "an unregistered external/outsourced route must be gated out by the register"
        );

        // With an in-house route added, that route IS selectable (in-house is never register-gated).
        let mut router2 = ModelRouter::new();
        router2.register(Box::new(ExternalRoute));
        router2.register(Box::new(InHouse));
        let router2 = router2.with_outsourcing_register(
            default_outsourcing_register(3600),
            residency(),
            wall_router_clock(),
        );
        let picked = router2
            .select(DataClass::Pii, None)
            .expect("in-house route is admissible");
        assert_eq!(
            picked.id(),
            "in-house",
            "in-house route serves; external route stays gated"
        );
    }

    #[test]
    fn release_controller_rolls_back_an_established_regression() {
        use ainxt_canary::experiment::{Notifier, PointerController};
        use ainxt_quality::monitor::DriftResponder;

        struct MemPointer {
            cur: String,
        }
        impl PointerController for MemPointer {
            fn current(&self) -> String {
                self.cur.clone()
            }
            fn flip(&mut self, to: &str) -> String {
                std::mem::replace(&mut self.cur, to.to_string())
            }
        }
        struct Sink;
        impl Notifier for Sink {
            fn notify(&mut self, _m: &str) {}
        }
        impl DriftResponder for Sink {
            fn open_ticket(&mut self, _s: &str) {}
            fn rollback_last_good(&mut self) -> bool {
                true
            }
        }

        let mut ctrl = build_release_controller(&ReleaseControllerConfig::default());
        let mut ptr = MemPointer {
            cur: "env/prod".into(),
        };
        let mut notif = Sink;
        let mut resp = Sink;
        // A candidate stream far below the baseline (80) must establish a rollback within the budget.
        let mut rolled_back = false;
        for _ in 0..500 {
            let step = ctrl.ingest("env/candidate", 10.0, &mut ptr, &mut notif, &mut resp);
            if step.rolled_back() {
                rolled_back = true;
                break;
            }
        }
        assert!(
            rolled_back,
            "an established regression must auto-roll-back the deploy pointer"
        );
        assert_eq!(
            ptr.current(),
            "env/prod",
            "the pointer returns to the champion ref"
        );
    }

    // ---- structured retrieval: served point-lookup round trip (round-15 `context-fabric`) ----

    fn settlement_catalog() -> ainxt_retrieval::structured::MetricCatalog {
        use ainxt_retrieval::structured::MetricDef;
        use std::collections::BTreeSet;
        let metric = MetricDef::new(
            "failed_settlement_count",
            "v_settlement_failures_curated",
            DataClass::Confidential,
        )
        .dimension("bank_id", DataClass::Internal)
        .rls("rls_settlement_by_dept");
        let mut rls = BTreeSet::new();
        rls.insert("rls_settlement_by_dept".to_string());
        ainxt_retrieval::structured::MetricCatalog::load(vec![metric], &rls).unwrap()
    }

    fn settlement_view_schema() -> ainxt_nl2sql::Schema {
        use ainxt_nl2sql::{Column, Table};
        ainxt_nl2sql::Schema::new(vec![Table::new(
            "v_settlement_failures_curated",
            vec![Column::new("bank_id", DataClass::Internal).unwrap()],
        )
        .unwrap()])
        .unwrap()
    }

    #[test]
    fn r15_served_structured_turn_gated_by_point_lookup_classification() {
        use ainxt_retrieval::structured_pipeline::{Aggregation, DimensionFilter};
        let catalog = settlement_catalog();
        let schema = settlement_view_schema();
        let analyst = Principal::user("analyst", &[]).with_clearance(DataClass::Confidential);

        // A genuine point-lookup ("how many failed settlements did bank X have last Tuesday",
        // §7.1's own worked example) reaches Stage A/B and compiles a real, parameterized query —
        // NL-to-SQL is reachable from the classified turn.
        let point_lookup = "how many failed settlements did bank X have on tuesday";
        let result = served_structured_turn(
            point_lookup,
            &catalog,
            "failed_settlement_count",
            &["bank_id"],
            &[DimensionFilter::eq_text("bank_id", "BANKX")],
            Aggregation::Count,
            &schema,
            &analyst,
        )
        .unwrap();
        let compiled = result.expect("a point-lookup turn must reach the structured pipeline");
        assert!(compiled.query.sql.starts_with("SELECT "));
        assert!(!compiled.query_hash.is_empty());

        // A genuinely global/sensemaking ask must NOT drive a single-metric structured round trip —
        // it belongs to the GraphRAG map-reduce tier instead.
        let global = "what are the recurring root causes of settlement failure this quarter";
        let none = served_structured_turn(
            global,
            &catalog,
            "failed_settlement_count",
            &[],
            &[],
            Aggregation::Count,
            &schema,
            &analyst,
        )
        .unwrap();
        assert!(
            none.is_none(),
            "a global/sensemaking ask must not reach the structured pipeline"
        );
    }

    #[test]
    fn r15_structured_intent_schema_locks_to_the_live_served_catalog() {
        // Stage-A constrained decoding (round-15): the live served catalog's vocabulary IS the
        // grammar the model's proposal is locked to — not a hand-maintained parallel list.
        use ainxt_prompt::constrained::FieldType;
        let catalog = settlement_catalog();
        let schema = catalog.constrained_intent_schema();
        assert_eq!(
            schema.fields.get("metric_id").unwrap().ty,
            FieldType::Enum(vec!["failed_settlement_count".to_string()])
        );
    }

    #[test]
    fn r15_register_structured_rederiver_arms_the_numeric_gate_end_to_end() {
        // The full served round trip: classify → compile (Stage A + B) → register on a
        // ServerSideRederiver → the numeric gate independently re-derives the SAME figure a served
        // answer would state, over the SAME RLS session — never trusting the model's arithmetic.
        use ainxt_context::{
            ClaimSource as CtxClaimSource, NumericClaim, Rederiver as CtxRederiver, Tolerance,
            ValueClass,
        };
        use ainxt_retrieval::structured::RowFilter as RlsRowExecutor;
        use ainxt_retrieval::structured_pipeline::{
            Aggregation, DimensionFilter, ServerSideRederiver,
        };

        let catalog = settlement_catalog();
        let schema = settlement_view_schema();
        let analyst = Principal::user("analyst", &[]).with_clearance(DataClass::Confidential);
        let compiled = served_structured_turn(
            "how many failed settlements did bank X have on tuesday",
            &catalog,
            "failed_settlement_count",
            &["bank_id"],
            &[DimensionFilter::eq_text("bank_id", "BANKX")],
            Aggregation::Count,
            &schema,
            &analyst,
        )
        .unwrap()
        .expect("point lookup reaches the pipeline");

        // The offline read-replica oracle: two rows for BANKX, one for a different bank (which the
        // compiled query's RLS/filter scope must exclude when re-executed).
        let rows = vec![
            vec![("bank_id".to_string(), "BANKX".to_string())],
            vec![("bank_id".to_string(), "BANKX".to_string())],
            vec![("bank_id".to_string(), "BANKY".to_string())],
        ];
        // The session var is a NAMESPACED GUC (`app.bank_id`), not a bare name: Postgres rejects a
        // custom parameter without a namespace ("unrecognized configuration parameter"), and the
        // binding validator enforces that shape because a GUC name cannot be a bound parameter of
        // SET LOCAL and so is allow-listed rather than escaped. A bare name here made the binding
        // refuse and the gate fail closed — correct behaviour, wrong fixture.
        let executor = RlsRowExecutor {
            rows,
            scope_column: "bank_id".to_string(),
            scope_var: "app.bank_id".to_string(),
        };
        let session = ainxt_retrieval::structured::SessionContext {
            settings: vec![("app.bank_id".to_string(), "BANKX".to_string())],
            stale_as_of: None,
        };

        let mut rederiver = ServerSideRederiver::new(&executor);
        register_structured_rederiver(&mut rederiver, &compiled, session);
        assert_eq!(rederiver.len(), 1);

        // The model states the CORRECT count (2) sourced to this exact compiled query: the numeric
        // gate independently re-derives it from the SAME data path and ships.
        let claim = NumericClaim::metric(
            2.0,
            "count",
            ValueClass::Exact,
            "failed_settlement_count",
            &compiled.query_hash,
        );
        let rederived = rederiver.rederive(&CtxClaimSource::Metric {
            id: "failed_settlement_count".to_string(),
            query_hash: compiled.query_hash.clone(),
        });
        assert_eq!(
            rederived,
            Some(2.0),
            "the server independently recomputed the SAME figure"
        );

        // Drive it through the SAME gate the served chat path uses, over the SAME window object.
        let counter = ainxt_retrieval::WordTokenCounter;
        let corpus = ainxt_context::Corpus::new();
        let retriever = ainxt_context::LexicalRetriever::new(corpus);
        let window = ainxt_context::compile(
            "how many failed settlements did bank X have on tuesday",
            &retriever,
            DataClass::Confidential,
            &ainxt_context::OptimizerConfig::default(),
            &counter,
            None,
            &BTreeMap::new(),
        );
        let verified = window.verify_answer(
            "2 failed settlements for bank X",
            &[claim],
            &rederiver,
            &Tolerance::default(),
        );
        assert!(
            verified.ships(),
            "a correctly re-derived, sourced figure must ship"
        );

        // A model that states a WRONG figure for the SAME query is caught, not trusted.
        let wrong_claim = NumericClaim::metric(
            99.0,
            "count",
            ValueClass::Exact,
            "failed_settlement_count",
            &compiled.query_hash,
        );
        let blocked = window.verify_answer(
            "99 failed settlements",
            &[wrong_claim],
            &rederiver,
            &Tolerance::default(),
        );
        assert!(!blocked.ships());
        assert!(
            blocked.blocked_on_mismatch(),
            "the incident-adjacent mismatch signal must fire"
        );
    }

    // ---- Federated Query Broker as a governed capability (round-15 `context-fabric`) ----

    struct FakeBank {
        id: String,
        partials: Vec<ainxt_retrieval::federation::NoisedPartial>,
    }
    impl ainxt_retrieval::federation::BankTenant for FakeBank {
        fn bank_id(&self) -> &str {
            &self.id
        }
        fn local_partials(
            &self,
            _metric_id: &str,
            _window: &str,
        ) -> Option<Vec<ainxt_retrieval::federation::NoisedPartial>> {
            Some(self.partials.clone())
        }
    }

    #[test]
    fn r15_federated_query_registers_into_the_unified_capability_registry() {
        // The SAME `ToolRuntime` every other capability (e.g. `query_ledger`) dispatches through —
        // proving the broker is mounted as a GOVERNED capability, not a bespoke surface.
        let mut runtime = ainxt_tools::ToolRuntime::new(
            Box::new(ainxt_tools::InMemoryLedger::new()),
            Box::new(ainxt_tools::ManualReconciler),
        );
        let tool = FederatedQueryTool::new(
            ainxt_retrieval::federation::FederationRegistry::new().allow("mule_velocity"),
            ainxt_retrieval::federation::KAnonConfig {
                min_banks: 3,
                min_underlying: 5,
            },
            ainxt_retrieval::federation::DpParams {
                epsilon: 1.0,
                sensitivity: 1.0,
            },
        );
        runtime.register(Box::new(tool));

        // Listed in the manifest with the expected name — reachable exactly like every other
        // capability, and correctly marked `Elevated` (approval-gated; see the type doc for why not
        // `HighRisk`).
        assert!(runtime.schemas().iter().any(|s| s.name == FEDERATED_QUERY));
        assert_eq!(
            runtime.risk_tier(FEDERATED_QUERY),
            Some(ainxt_tools::RiskTier::Elevated)
        );

        // The one-shot sync path is refused too — a side-effecting tool with no declared semantic
        // idempotency key is structurally blocked (§1.2) before `execute` ever runs, so the sync
        // signature can never silently run an unscoped federated read off it.
        let outcome = runtime.dispatch(FEDERATED_QUERY, "{}");
        assert!(
            matches!(outcome, ainxt_tools::DispatchResult::Blocked(_)),
            "federated_query must never execute on the one-shot path: {outcome:?}"
        );
    }

    /// A query that unambiguously classifies as [`QueryScope::Global`](ainxt_context::optimizer::QueryScope::Global)
    /// (the `"across all"` phrase carries strong Global evidence in `classify_scope`) — the shape of
    /// a genuine cross-bank ask, never a bounded single-bank point lookup.
    const NETWORK_WIDE_QUERY: &str = "network-wide mule-account velocity across all member banks";

    #[test]
    fn r15_federated_query_tool_dispatch_enforces_whitelist_and_k_anonymity() {
        let tool = FederatedQueryTool::new(
            ainxt_retrieval::federation::FederationRegistry::new().allow("mule_velocity"),
            ainxt_retrieval::federation::KAnonConfig {
                min_banks: 2,
                min_underlying: 1,
            },
            ainxt_retrieval::federation::DpParams {
                epsilon: 1.0,
                sensitivity: 1.0,
            },
        );
        let mut ledger = ainxt_retrieval::federation::EpsilonLedger::new();

        // A non-whitelisted metric is refused before any bank is contacted (the Global-scope gate
        // passes — this call is genuinely network-wide — but the broker's own whitelist still bites).
        let banks: Vec<&dyn ainxt_retrieval::federation::BankTenant> = vec![];
        let refused = tool.dispatch(
            NETWORK_WIDE_QUERY,
            "not_whitelisted",
            "2026-w1",
            0.5,
            5.0,
            &mut ledger,
            &banks,
            false,
        );
        assert!(matches!(
            refused,
            Err(ainxt_retrieval::federation::FederationError::NotFederated { .. })
        ));

        // A whitelisted metric with real (fake-bank) partials dispatches end to end through the
        // SAME governed object the capability registry holds.
        let bank_a = FakeBank {
            id: "bank-a".to_string(),
            partials: vec![ainxt_retrieval::federation::NoisedPartial {
                bank_id: "bank-a".to_string(),
                bucket: "high".to_string(),
                value: 10.0,
                underlying_count: 3,
            }],
        };
        let bank_b = FakeBank {
            id: "bank-b".to_string(),
            partials: vec![ainxt_retrieval::federation::NoisedPartial {
                bank_id: "bank-b".to_string(),
                bucket: "high".to_string(),
                value: 8.0,
                underlying_count: 4,
            }],
        };
        let tenants: Vec<&dyn ainxt_retrieval::federation::BankTenant> = vec![&bank_a, &bank_b];
        let report = tool
            .dispatch(
                NETWORK_WIDE_QUERY,
                "mule_velocity",
                "2026-w1",
                0.5,
                5.0,
                &mut ledger,
                &tenants,
                false,
            )
            .expect("whitelisted metric with 2 banks clears the k=2 floor")
            .expect("a Global-scoped query must actually dispatch, never be gated to None");
        assert_eq!(
            report.contributed,
            vec!["bank-a".to_string(), "bank-b".to_string()]
        );
        // The privacy budget was genuinely debited on the SHARED ledger.
        assert_eq!(ledger.spent("mule_velocity", "2026-w1"), 0.5);
    }

    // GAP-AUDIT data-surfaces-artifacts (federated-broker zero callers) — the actual missing behavior:
    // before `served_federated_turn` existed, NOTHING gated a federated dispatch on the classified turn
    // text at all — `FederatedQueryTool::dispatch` took no `query` param and would happily spend the
    // shared epsilon budget for what might be a bounded single-bank point lookup that should have
    // routed to `served_structured_turn`'s single-metric tier instead. This proves the gate: a
    // classified point-lookup turn is refused BEFORE the broker is even constructed — `Ok(None)`, the
    // ledger is never touched, and no bank tenant is ever contacted (an empty tenant list would panic
    // downstream if the broker ran, so an untouched ledger + `None` is the only honest outcome).
    #[test]
    fn r_federated_query_scope_gate_refuses_a_point_lookup_before_spending_any_budget() {
        let tool = FederatedQueryTool::new(
            ainxt_retrieval::federation::FederationRegistry::new().allow("mule_velocity"),
            ainxt_retrieval::federation::KAnonConfig {
                min_banks: 1,
                min_underlying: 1,
            },
            ainxt_retrieval::federation::DpParams {
                epsilon: 1.0,
                sensitivity: 1.0,
            },
        );
        let mut ledger = ainxt_retrieval::federation::EpsilonLedger::new();
        let bank_a = FakeBank {
            id: "bank-a".to_string(),
            partials: vec![ainxt_retrieval::federation::NoisedPartial {
                bank_id: "bank-a".to_string(),
                bucket: "high".to_string(),
                value: 10.0,
                underlying_count: 3,
            }],
        };
        let tenants: Vec<&dyn ainxt_retrieval::federation::BankTenant> = vec![&bank_a];

        // A bounded, single-bank point lookup — the exact shape `served_structured_turn` exists to
        // serve, never the federated tier.
        let point_lookup = "what is the settlement count for account 12345 today";
        let scope = ainxt_context::optimizer::classify_scope(point_lookup);
        assert_eq!(
            scope.scope,
            ainxt_context::optimizer::QueryScope::PointLookup,
            "test fixture sanity: this query must classify as PointLookup, not Global"
        );

        let result = tool.dispatch(
            point_lookup,
            "mule_velocity",
            "2026-w1",
            0.5,
            5.0,
            &mut ledger,
            &tenants,
            false,
        );
        assert!(
            matches!(result, Ok(None)),
            "a PointLookup-classified turn must be gated to None, never dispatched: {result:?}"
        );
        assert_eq!(
            ledger.spent("mule_velocity", "2026-w1"),
            0.0,
            "the shared epsilon budget must never be touched for a gated-off point lookup"
        );
    }

    /// GAP-FIX prompt — `run_prompt_canary_sweep_tick` is the composition-root entrypoint proving
    /// `CanaryController` is reachable from a real daemon composition function, not merely from
    /// `ainxt-prompt`'s own unit tests. Drives it against a `ServedPromptEngine` built through this
    /// crate's OWN `assemble_served_prompt_engine`-shaped construction (a real forensic-file-backed
    /// engine, not a bespoke fixture).
    #[test]
    fn gap_ainxt_runtimed_prmt_13_canary_sweep_tick_is_reachable_from_the_composition_root() {
        let mut prompts = ainxt_prompt::served::default_served_chat_prompts();
        let canary_release = prompts.deployment.prod.clone();
        prompts.deployment.start_canary(canary_release, 25);

        let path = std::env::temp_dir().join(format!(
            "ainxt_runtimed_prmt13_canary_{}_{}.jsonl",
            std::process::id(),
            "sweep_tick_reachable"
        ));
        let mut engine =
            ainxt_prompt::service::ServedPromptEngine::with_forensic_file(prompts, &path);
        let controller = ainxt_prompt::canary::CanaryController::default();

        // Regressed on both watched signals -> Rollback, applied to the SAME engine instance.
        let decision = run_prompt_canary_sweep_tick(
            &mut engine,
            &controller,
            &ainxt_prompt::canary::ArmMetrics::new(90.0, 500, 0.01),
            &ainxt_prompt::canary::ArmMetrics::new(55.0, 200, 0.08),
        );
        assert_eq!(decision, ainxt_prompt::canary::CanaryDecision::Rollback);
        assert!(
            engine.prompts().deployment.canary.is_none(),
            "the composition-root tick must apply the pointer flip, not just decide"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// gap5-prompt-round2 Item A — `run_prompt_canary_sweep_tick` had NO periodic driver: no
    /// `spawn_*_tick` wrapper, no boot-time cadence. This proves [`spawn_prompt_canary_tick`]'s spawned
    /// loop is a REAL running `tokio` task that, over REAL wall-clock time, drives the one-shot tick
    /// against a REAL shared [`SharedServedPromptEngine`] and applies the pointer flip — observed from
    /// OUTSIDE the spawned task, through the same `Arc<Mutex<_>>` handle, not by calling the tick
    /// function's logic a second time.
    #[tokio::test(flavor = "multi_thread")]
    async fn spawn_prompt_canary_tick_drives_a_real_rollback_through_the_shared_engine() {
        let mut prompts = ainxt_prompt::served::default_served_chat_prompts();
        let canary_release = prompts.deployment.prod.clone();
        prompts.deployment.start_canary(canary_release, 25);
        let engine: SharedServedPromptEngine = std::sync::Arc::new(std::sync::Mutex::new(
            ainxt_prompt::service::ServedPromptEngine::new(
                prompts,
                std::sync::Arc::new(ainxt_prompt::service::NullSink),
            ),
        ));
        let controller = ainxt_prompt::canary::CanaryController::default();

        // Regressed on both watched signals every tick -> every due tick decides Rollback.
        let handle = spawn_prompt_canary_tick(
            engine.clone(),
            controller,
            std::time::Duration::from_millis(5),
            || {
                Some((
                    ainxt_prompt::canary::ArmMetrics::new(90.0, 500, 0.01),
                    ainxt_prompt::canary::ArmMetrics::new(55.0, 200, 0.08),
                ))
            },
        );

        // Real wall-clock wait for several real interval ticks of the REAL spawned loop.
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        assert!(
            !handle.is_finished(),
            "the cadence loop must still be running, not panicked/exited"
        );
        handle.abort();

        let eng = engine.lock().expect("served prompt engine lock");
        assert!(
            eng.prompts().deployment.canary.is_none(),
            "the REAL spawned cadence must have applied the Rollback pointer-flip through the shared \
             engine handle, observed from outside the spawned task"
        );
    }

    /// gap5-prompt-round2 Item A — `spawn_prompt_canary_tick` is reachable from the SAME `LoadedConfig`
    /// shape the real daemon boots from (`load_layered`, no deployment-specific overrides), and a
    /// caller-supplied `metrics_source` that honestly returns `None` (no live-traffic sampler wired on
    /// the air-gapped default) never panics the loop — mirrors
    /// `spawn_prompt_optimizer_tick_is_inert_on_the_air_gapped_default`'s bar for the sibling cadence.
    #[tokio::test(flavor = "multi_thread")]
    async fn spawn_prompt_canary_tick_is_reachable_from_a_real_boot_config() {
        let loaded = crate::load_layered(&[("t", "version = 1\n")]).expect("load config");
        let engine = assemble_shared_served_prompt_engine_from_config(&loaded.runtime);
        let handle = spawn_prompt_canary_tick(
            engine,
            ainxt_prompt::canary::CanaryController::default(),
            std::time::Duration::from_millis(5),
            || None,
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            !handle.is_finished(),
            "an absent live-traffic metrics source must be an honest no-op, never a panic"
        );
        handle.abort();
    }

    /// gap5-prompt-round2 Item B — `ainxt_prompt::drift::DriftMonitor`/`DriftKey`/`Baseline` had zero
    /// callers outside `ainxt-prompt`'s own tests. This proves [`run_prompt_drift_sweep_tick`] — the new
    /// composition-root entrypoint — installs REAL baselines from a REAL `SharedServedPromptEngine`
    /// (built via [`assemble_shared_served_prompt_engine_from_config`], the same constructor
    /// `spawn_prompt_canary_tick` shares), resolves the drift key from `engine.prompts().drift_key`
    /// (never a hand-rolled key), and confirms a sustained degradation on a REAL served family exactly
    /// like `ainxt-prompt/tests/r11_drift_from_served.rs` proves for the raw `DriftMonitor` — but through
    /// this crate's own composition-root tick function, not the bare crate API.
    #[test]
    fn gap_ainxt_runtimed_prompt_drift_sweep_tick_confirms_degradation_on_a_real_served_family() {
        let config = ainxt_config::RuntimeConfig::default();
        let engine = assemble_shared_served_prompt_engine_from_config(&config);
        let mut monitor =
            ainxt_prompt::drift::DriftMonitor::new(ainxt_prompt::drift::DriftPolicy::default());
        let family = {
            let eng = engine.lock().expect("served prompt engine lock");
            eng.prompts().install_drift_baselines(&mut monitor);
            eng.prompts().families[0].clone()
        };

        let mut event = None;
        for i in 0..80 {
            let eng = engine.lock().expect("served prompt engine lock");
            // Baseline is DEFAULT_CHAT_BASELINE_MEAN (~88); feed a stream ~20 points worse.
            let score = if i % 2 == 0 { 66 } else { 70 };
            if let Some(e) = run_prompt_drift_sweep_tick(&eng, &mut monitor, &family, score) {
                event = Some(e);
                break;
            }
        }
        let e = event.expect(
            "a sustained ~20-point drop on a real served family must be confirmed by the composition-root tick",
        );
        assert_eq!(
            e.action,
            ainxt_prompt::drift::DriftAction::OpenTicketAndRollback
        );
        assert!(e.window_mean < e.baseline_mean);
        assert_eq!(
            e.key.model_family, family.0,
            "the confirmed event must key off the REAL served family"
        );
    }

    /// gap5-prompt-round2 Item B — the task's own requirement: the drift cadence must reuse the SAME
    /// engine handle the canary cadence mutates, never build a second, disconnected engine. This proves
    /// it empirically: both [`spawn_prompt_canary_tick`] and [`spawn_prompt_drift_tick`], spawned from
    /// ONE `SharedServedPromptEngine` built off a REAL `LoadedConfig` (the same shape `main.rs` boots
    /// from), each hold a clone of the IDENTICAL `Arc` — not two engines that merely look alike.
    #[tokio::test(flavor = "multi_thread")]
    async fn spawn_prompt_canary_tick_and_spawn_prompt_drift_tick_share_the_same_engine_handle() {
        let loaded = crate::load_layered(&[("t", "version = 1\n")]).expect("load config");
        let engine = assemble_shared_served_prompt_engine_from_config(&loaded.runtime);

        let canary_handle = spawn_prompt_canary_tick(
            engine.clone(),
            ainxt_prompt::canary::CanaryController::default(),
            std::time::Duration::from_secs(3600),
            || None,
        );
        let drift_handle =
            spawn_prompt_drift_tick(engine.clone(), std::time::Duration::from_secs(3600), || {
                None
            });

        // This test's own clone + the canary task's clone + the drift task's clone = 3 — definitive
        // proof both cadences share ONE engine, never a second disconnected instance.
        assert_eq!(
            std::sync::Arc::strong_count(&engine),
            3,
            "the canary and drift cadence ticks must share the SAME served-prompt-engine handle"
        );
        assert!(!canary_handle.is_finished());
        assert!(!drift_handle.is_finished());
        canary_handle.abort();
        drift_handle.abort();
    }

    // --- gap closure: provider-silent-update tripwire (`provider_silent_update`/`ProviderVerdict`) ---

    /// GAP-FIX providers-gemini-quality-tripwire (item 2) — `ainxt_quality::monitor::
    /// provider_silent_update`/`ProviderVerdict` had ZERO callers outside its own `#[cfg(test)]`. This
    /// proves [`run_provider_silent_update_tick`] — the new composition-root entrypoint — through the
    /// SAME shape `gap_ainxt_runtimed_prompt_drift_sweep_tick_confirms_degradation_on_a_real_served_
    /// family` above proves for its sibling: a genuinely step-changed current sample sequence
    /// (simulating a silent provider model-swap, no control-plane change on record) is DETECTED, and a
    /// stable sequence (same distribution as the frozen baseline) is NOT.
    #[test]
    fn provider_silent_update_tick_detects_a_genuine_step_change_but_not_a_stable_sequence() {
        // A frozen tripwire baseline: alternating noise around 90 (mirrors the CUSUM in-control
        // fixture style already used by `cusum_flags_a_sustained_drop_not_single_noise` above).
        let baseline: Vec<f64> = (0..30)
            .map(|i| 90.0 + if i % 2 == 0 { 1.0 } else { -1.0 })
            .collect();

        // Stable: the SAME distribution re-scored (independent noise pattern, same mean) — this is
        // "we re-ran the tripwire and nothing moved", not a swap.
        let stable: Vec<f64> = (0..30)
            .map(|i| 90.0 + if i % 3 == 0 { -1.0 } else { 1.0 })
            .collect();
        let stable_verdict = run_provider_silent_update_tick(&baseline, &stable, false, 0.05);
        assert!(
            !stable_verdict.is_silent_update(),
            "a stable re-score of the SAME tripwire set must never be flagged as a swap: \
             {stable_verdict:?}"
        );
        assert!(
            matches!(stable_verdict, ProviderVerdict::Stable { .. }),
            "expected Stable, got {stable_verdict:?}"
        );

        // Genuinely step-changed: the SAME tripwire set re-scored ~25 points lower — the abrupt
        // step-change signature a silent provider model-swap would produce, with NO control-plane
        // change on record.
        let swapped: Vec<f64> = (0..30)
            .map(|i| 65.0 + if i % 2 == 0 { 1.0 } else { -1.0 })
            .collect();
        let swap_verdict = run_provider_silent_update_tick(&baseline, &swapped, false, 0.05);
        assert!(
            swap_verdict.is_silent_update(),
            "a step-changed tripwire re-score with no control-plane change on record must be flagged \
             as a suspected silent provider swap: {swap_verdict:?}"
        );

        // The SAME step change, but WITH a recorded control-plane change — an intentional deployment
        // change, not a silent swap.
        let explained_verdict = run_provider_silent_update_tick(&baseline, &swapped, true, 0.05);
        assert!(
            !explained_verdict.is_silent_update(),
            "the identical shift must NOT be flagged when a control-plane change explains it: \
             {explained_verdict:?}"
        );
        assert!(
            matches!(explained_verdict, ProviderVerdict::ExplainedByChange { .. }),
            "expected ExplainedByChange, got {explained_verdict:?}"
        );
    }

    /// The spawn gate is `None` (no task spawned at all) when no frozen tripwire baseline has been
    /// established for any provider — mirrors `spawn_autoscale_tick`'s own "`None` when no tuning
    /// declared" bar (`r_gap6_autoscale_placement_tick_spawned.rs`'s
    /// `assert!(full.spawn_autoscale_tick(..).is_none())`), the established convention in this crate
    /// for a cadence with no meaningful default state to run against. This is the composition-root
    /// shape `main.rs` relies on: it always calls this fn at boot, and on the air-gapped default (no
    /// registered tripwire baseline) it is a true no-op — not even a running task.
    #[test]
    fn spawn_provider_silent_update_tick_is_none_on_the_absent_default() {
        let handle = spawn_provider_silent_update_tick(
            None,
            0.05,
            std::time::Duration::from_millis(5),
            || None,
        );
        assert!(
            handle.is_none(),
            "no frozen tripwire baseline registered -> no task spawned at all"
        );
    }

    /// The spawned cadence is a REAL running `tokio` task that, over REAL wall-clock time, drives
    /// [`run_provider_silent_update_tick`] against a genuinely step-changed sample source every due
    /// tick without panicking — mirrors `spawn_prompt_canary_tick_drives_a_real_rollback_through_the_
    /// shared_engine`'s "real wall-clock, still running" bar for the sibling cadence's spawn wrapper.
    #[tokio::test(flavor = "multi_thread")]
    async fn spawn_provider_silent_update_tick_runs_over_real_wall_clock_on_a_step_change() {
        let baseline = vec![90.0, 91.0, 89.0, 90.5, 89.5, 90.0, 91.0, 89.0, 90.5, 89.5];
        let swapped = vec![65.0, 66.0, 64.0, 65.5, 64.5, 65.0, 66.0, 64.0, 65.5, 64.5];
        let handle = spawn_provider_silent_update_tick(
            Some(("cloud-anthropic".to_string(), baseline)),
            0.05,
            std::time::Duration::from_millis(5),
            move || Some((swapped.clone(), false)),
        )
        .expect("a Some baseline must spawn a real task");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(
            !handle.is_finished(),
            "the cadence loop must still be running after repeatedly detecting a suspected silent \
             swap, not panicked/exited"
        );
        handle.abort();
    }

    // --- gap closure: `assemble_served_prompt_engine_from_config` closes the config -> L2 loop ------

    /// The end-to-end path a real deployment relies on: a `[policy]` TOML layer, merged through
    /// `ainxt-config`'s real `Loader`, produces a `RuntimeConfig` whose `policy.l2_body` this
    /// composition root reads into a served engine — and a REAL compiled turn's system prompt
    /// contains that exact text, not the compiled-in shipped default.
    #[test]
    fn gap_ainxt_runtimed_policy_config_flows_from_toml_layer_to_a_compiled_turn() {
        let custom_policy =
            "DEPLOYMENT-WIDE: a new disclosure clause applies to every response on this deployment.";
        let config = ainxt_config::Loader::new()
            .deployment(&format!("[policy]\nl2_body = \"{custom_policy}\"\n"))
            .expect("valid toml layer")
            .resolve_runtime()
            .expect("resolves");
        config
            .validate()
            .expect("a real deployment validates its config before using it");
        assert_eq!(config.policy.l2_body, custom_policy);

        let path = std::env::temp_dir().join(format!(
            "ainxt_runtimed_policy_from_config_{}.jsonl",
            std::process::id()
        ));
        let engine = assemble_served_prompt_engine_from_config(&config, &path);

        // The Registry artifact itself carries the config-sourced text (per family, not just L1 raw).
        let v = ainxt_prompt::registry::Semver::new(1, 0, 0);
        let artifact = engine
            .prompts()
            .registry
            .get("prompt.chat.policy", v)
            .expect("policy layer artifact exists");
        let policy_body = artifact
            .variant(&ainxt_prompt::registry::ModelFamily::new("claude"))
            .expect("policy layer variant exists");
        assert!(policy_body.contains(custom_policy));

        // And it survives all the way to a real compiled turn's system prompt text.
        let svc = ainxt_prompt::service::PromptService::new(
            &ainxt_prompt::layered::HeuristicTokens,
            &ainxt_prompt::layered::TruncatingCondenser,
            10_000,
        );
        let ids: Vec<&str> = engine
            .prompts()
            .layer_ids
            .iter()
            .map(|s| s.as_str())
            .collect();
        let compiled = svc
            .compile_turn(
                &engine.prompts().registry,
                &engine.prompts().deployment,
                &ainxt_prompt::service::NullSink,
                "turn-1",
                &ainxt_prompt::registry::ModelFamily::new("claude"),
                &ids,
                "Retrieved: nothing relevant.",
                &engine.prompts().control_sha,
            )
            .expect("compiles");
        assert!(
            compiled.text.contains(custom_policy),
            "the config-sourced L2 body must reach the compiled turn text"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn gap_ainxt_runtimed_policy_config_payments_variant_keeps_tools_only_numeric_discipline() {
        let config = ainxt_config::RuntimeConfig::default();
        let path = std::env::temp_dir().join(format!(
            "ainxt_runtimed_policy_from_config_payments_{}.jsonl",
            std::process::id()
        ));
        let engine = assemble_payments_served_prompt_engine_from_config(&config, &path);
        assert_eq!(
            engine.prompts().numeric,
            ainxt_prompt::NumericPolicy::ToolsOnly
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn gap_ainxt_runtimed_policy_config_unconfigured_matches_the_shipped_default_engine() {
        let config = ainxt_config::RuntimeConfig::default();
        let path = std::env::temp_dir().join(format!(
            "ainxt_runtimed_policy_from_config_default_{}.jsonl",
            std::process::id()
        ));
        let engine = assemble_served_prompt_engine_from_config(&config, &path);
        let v = ainxt_prompt::registry::Semver::new(1, 0, 0);
        let artifact = engine
            .prompts()
            .registry
            .get("prompt.chat.policy", v)
            .unwrap();
        let body = artifact
            .variant(&ainxt_prompt::registry::ModelFamily::new("claude"))
            .unwrap();
        assert!(body.contains("take precedence over the user message"));
        let _ = std::fs::remove_file(&path);
    }
}
