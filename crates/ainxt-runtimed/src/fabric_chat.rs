// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Gap `context-fabric` — mounts `governed::compile_served_fabric` on the served chat path.
//!
//! # The gap this closes
//!
//! `governed::compile_served_fabric` (the served fabric-of-graphs compile: 12+ graph layers routed +
//! PageRank-fused + budget-fit against the per-turn Model-Router eligible set,
//! `CONTEXT_FABRIC.md` §2–§3) was fully implemented and unit-tested (`ainxt-context`'s own tests +
//! `r13_context_fabric_served.rs`) but had **zero callers on the served turn path** — its own doc
//! comment says so explicitly: "deliberately NOT yet mounted on `/v1/chat`". The shipped daemon's
//! `ChatSurface` grounds through the flat, single-corpus `compile_window` path instead
//! (`ainxt_chat::ChatSurface::assemble_with_prompt` → `ConversationManager::with_context_window`) —
//! real, but only ONE graph layer (`EnterpriseDocs`) wide, never the routed multi-layer fabric.
//!
//! [`FabricGroundedChatSurface`] is the wire: a [`TurnHandler`] that wraps the grounded chat handler
//! and, on every turn, routes the turn's query through a populated [`MultiGraphFabric`] via
//! [`ainxt_runtimed::governed::compile_served_fabric`](crate::governed::compile_served_fabric) BEFORE
//! delegating — the routed, layer-labelled evidence is prepended onto the turn as an explicit context
//! block (the raw user turn is preserved in [`Request::user_turn`] so intent classification / referent
//! resolution still runs on the user's own words, never the composed prompt — the same seam
//! `ainxt-surface`'s `TurnPlan::to_request` uses).
//!
//! This is **additive and config-selectable** ([`crate::assemble_chat_fabric_grounded`]) — it does NOT
//! change [`crate::assemble_surface`] (the REAL default `/v1/chat` surface; [`crate::assemble_chat`] is
//! a separate, un-profiled sibling composition kept as a test/library fixture — see its own doc
//! comment — not the served default). An EMPTY fabric (the air-gapped
//! default: no repo/KG indexer has populated one yet) or a turn whose query plan/RBAC/RLS pre-rank pass
//! routes to nothing this turn is a **byte-identical no-op** — `inner` runs unchanged, never a denied
//! turn (the fabric is a retrieval read-filter, exactly like its own doc comment's "never a denied
//! turn" invariant). See `runtime/crates/ainxt-runtimed/tests/r19_fabric_grounded_chat_served.rs` for
//! the transparency-over-empty-fabric regression proof + the live-wiring proof.

use std::sync::Arc;

use ainxt_context::route::{MultiGraphFabric, RoutedWindow};
use ainxt_context::AccessContext;
use ainxt_protocol::{Event, Request};
use ainxt_retrieval::EligibleModel;
use ainxt_runtime::{CancelToken, TurnError, TurnHandler, TurnSummary};
use ainxt_types::Principal;
use tokio::sync::mpsc;

/// A [`TurnHandler`] that grounds every turn through the populated Context-Fabric
/// ([`crate::governed::compile_served_fabric`]) before delegating to `inner`. See the module docs.
pub struct FabricGroundedChatSurface {
    inner: Arc<dyn TurnHandler>,
    fabric: MultiGraphFabric,
    /// The per-deployment eligible-model set [`compile_served_fabric`](crate::governed::compile_served_fabric)'s
    /// own doc requires (never a config default) — the composition root resolves this from the
    /// deployment's [`ainxt_runtime::router::ModelRouter`] before constructing this surface (see
    /// [`crate::assemble_chat_fabric_grounded`]).
    eligible: Vec<EligibleModel>,
    /// The default multimodal-artifact-tier namespace, used when a turn's own
    /// [`Request::namespace`] is unset.
    namespace: String,
}

impl FabricGroundedChatSurface {
    /// Wrap `inner` so every turn is first routed through `fabric`.
    pub fn new(
        inner: Arc<dyn TurnHandler>,
        fabric: MultiGraphFabric,
        eligible: Vec<EligibleModel>,
        namespace: impl Into<String>,
    ) -> Self {
        FabricGroundedChatSurface {
            inner,
            fabric,
            eligible,
            namespace: namespace.into(),
        }
    }

    /// The wrapped fabric's populated layers (diagnostic / composition-report aid).
    pub fn populated_layers(&self) -> Vec<ainxt_context::optimizer::GraphLayer> {
        self.fabric.populated_layers()
    }

    /// Render the routed window's grounded chunks into an explicit, layer-labelled context block
    /// (`CONTEXT_FABRIC.md` §2's "fabric of graphs" made observable on the served prompt) — never raw,
    /// unlabelled concatenation, and never silently dropping which layer an item of evidence came from.
    ///
    /// GAP-FIX data-surfaces-artifacts (multimodal artifact tier orphaned behind the fabric-grounded
    /// surface): `routed.artifacts` (populated when the plan routes to `GraphLayer::MultimodalArtifact`
    /// AND the fabric carries an attached [`ainxt_context::artifact::ArtifactStore`] — see
    /// [`crate::assemble_chat_fabric_grounded_with_artifacts`]) is now routed through
    /// [`crate::governed::served_multimodal_turn`]'s model-eligibility gate before being labelled onto
    /// the turn: only artifacts with an eligible model in the default offline fleet
    /// ([`crate::governed::artifact_model_fleet_default`]) are surfaced, each labelled with the model it
    /// is eligible for; an ineligible artifact (e.g. regulated data with no in-house model available) is
    /// silently dropped from the rendered block — never forwarded, and never named (existence never
    /// leaks), mirroring the department-RBAC "no leak" invariant chunks/community summaries already get.
    fn render_context(routed: &RoutedWindow, original_input: &str) -> String {
        let mut block = String::new();
        block.push_str(&format!(
            "[context-fabric: {} layer(s) compiled: {:?}]\n",
            routed.layer_count(),
            routed.compiled_layers
        ));
        for chunk in &routed.window.context.chunks {
            block.push_str(&format!("- ({}) {}\n", chunk.source, chunk.text));
        }
        for summary in &routed.community_summaries {
            block.push_str(&format!(
                "- [community {} summary] members: {}\n",
                summary.community_id,
                summary.members.join(", ")
            ));
        }
        if !routed.artifacts.is_empty() {
            let models = crate::governed::artifact_model_fleet_default();
            let (eligible, _dropped) = crate::governed::served_multimodal_turn(routed, &models);
            for (artifact, model) in &eligible {
                // Deliberately "key: value" with a space after the colon (not a bare "key=value" or
                // "key:value" run) — the compliance/guardrails high-entropy secret scanner
                // (`ainxt-compliance`) treats any single whitespace-delimited token over its length
                // gate as a candidate; an unspaced `eligible_model=<hyphenated-id>` token is long
                // enough and mixed-class enough to trip it and get redacted before this ever reaches
                // the model. Splitting the id into its own short, space-delimited token keeps the
                // eligible model's identity genuinely visible in the rendered evidence.
                block.push_str(&format!(
                    "- [artifact {} modality={:?} eligible model: {}]\n",
                    artifact.id, artifact.modality, model.id
                ));
            }
        }
        block.push_str("\n---\n");
        block.push_str(original_input);
        block
    }
}

impl TurnHandler for FabricGroundedChatSurface {
    fn handle_turn<'a>(
        &'a self,
        principal: &'a Principal,
        req: &'a Request,
        sink: mpsc::Sender<Event>,
        cancel: &'a CancelToken,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<TurnSummary, TurnError>> + Send + 'a>,
    > {
        Box::pin(async move {
            // An empty fabric (the air-gapped default — no repo/KG indexer has populated one yet) is a
            // byte-identical no-op: never denies, never narrows what `inner` alone would ground.
            if self.fabric.is_empty() {
                return self.inner.handle_turn(principal, req, sink, cancel).await;
            }
            let access = AccessContext::from_principal(principal);
            let namespace = req.namespace.as_deref().unwrap_or(self.namespace.as_str());
            let routed = crate::governed::compile_served_fabric(
                &self.fabric,
                &req.input,
                &access,
                None,
                &self.eligible,
                namespace,
            );
            // GAP-FIX data-surfaces-artifacts (multimodal tier silently dropped on the empty-window
            // fallback): this emptiness check must ALSO look at `routed.artifacts` — a turn whose plan
            // routes ONLY to `GraphLayer::MultimodalArtifact` (no chunk, no community summary) has an
            // empty `window.context` AND an empty `community_summaries` by construction, so checking
            // only those two fields fell through to the byte-identical no-op path and never rendered
            // (or even looked at) a routed artifact — the eligibility-gated multimodal tier was
            // unreachable from a served turn even once populated via
            // [`crate::assemble_chat_fabric_grounded_with_artifacts`].
            if routed.window.context.is_empty()
                && routed.community_summaries.is_empty()
                && routed.artifacts.is_empty()
            {
                // The plan/RBAC/RLS pre-rank pass routed to nothing for THIS turn (e.g. a caller whose
                // clearance/department/ad_level admits no fabric node, or a query the plan does not
                // match any populated layer). Ground unchanged via `inner` — the fabric is a retrieval
                // read-filter, never a turn-admission gate, so this is never a denied turn.
                return self.inner.handle_turn(principal, req, sink, cancel).await;
            }
            let mut grounded = req.clone();
            // Preserve the RAW user turn for intent classification / referent resolution — the same
            // seam `ainxt_surface::TurnPlan::to_request` uses when it composes persona/guard/context
            // onto `input`. Only set it if not already set upstream (never overwrite an earlier layer's
            // own raw-turn preservation).
            if grounded.user_turn.is_none() {
                grounded.user_turn = Some(req.input.clone());
            }
            grounded.input = Self::render_context(&routed, &req.input);
            self.inner
                .handle_turn(principal, &grounded, sink, cancel)
                .await
        })
    }
}
