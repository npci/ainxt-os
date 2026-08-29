// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Multimodal artifact tier (fabric layer 16).
//!
//! Design: `STRUCTURED_FEDERATED_RETRIEVAL.md` §8 — modality-isolated vision/ASR embedding
//! pipelines with their own namespaces, **data-class model routing** (regulated/PII artifacts may
//! NEVER go to a cloud vision/ASR model), **existence-never-leaks RBAC**, and an **erasure cascade**
//! to derived embeddings (DPDP right-to-erasure, ADR-015).
//!
//! What is real and tested here (pure, deterministic, offline):
//!
//! - [`route_model`] — data-class model routing: a regulated/PII artifact resolves only to an
//!   in-house (`cloud == false`) model for its modality; if none exists the call is **refused**,
//!   never silently sent to a cloud model. This is the multimodal projection of ADR-012.
//! - [`ArtifactStore::search`] — namespace isolation + pre-rank RBAC: a query scoped to one
//!   namespace never sees another's artifacts, and an artifact above the caller's clearance / not
//!   permitted by its [`NodeAcl`] is filtered *before* results form, so its existence never leaks
//!   (same guarantee as text retrieval, §8 "existence-never-leaks").
//! - [`ArtifactStore::erasure_cascade`] — erasing an artifact returns the artifact **and every
//!   derived embedding** produced from it, so a right-to-erasure request purges the modality-
//!   isolated vector rows too, not just the source blob.
//!
//! The actual vision/ASR embedding computation (the ML model, ONNX/whisper) is the [`ArtifactEmbedder`]
//! seam — modality-isolated by construction (one embedder per modality) — and is deferred to infra;
//! everything above it (routing, isolation, RBAC, erasure) is real logic with real tests.

use ainxt_retrieval::acl::{AccessContext, NodeAcl};
use ainxt_types::DataClass;
use serde::{Deserialize, Serialize};

/// A non-text modality. Each has its OWN embedding pipeline + namespace (never mixed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Modality {
    /// Cheque / KYC scan / document image → a vision embedder.
    Image,
    /// Call recording / voice note → an ASR + audio embedder.
    Audio,
}

/// A multimodal artifact (a cheque scan, a KYC image, a call recording). The blob itself lives in
/// object storage; this is its indexed, RBAC-labelled handle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Artifact {
    pub id: String,
    /// The isolated namespace this artifact belongs to (e.g. `kyc:bankA`). Queries never cross it.
    pub namespace: String,
    pub modality: Modality,
    pub data_class: DataClass,
    /// Optional node-level ACL beyond the class scalar (dept/seniority/group), same model as text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acl: Option<NodeAcl>,
}

impl Artifact {
    pub fn new(id: &str, namespace: &str, modality: Modality, data_class: DataClass) -> Self {
        Artifact {
            id: id.to_string(),
            namespace: namespace.to_string(),
            modality,
            data_class,
            acl: None,
        }
    }

    pub fn with_acl(mut self, acl: NodeAcl) -> Self {
        self.acl = Some(acl);
        self
    }

    fn visible_to(&self, ctx: &AccessContext) -> bool {
        if self.data_class.sensitivity() > ctx.clearance.sensitivity() {
            return false;
        }
        match &self.acl {
            None => true,
            Some(a) => a.permits(ctx),
        }
    }
}

/// A vector row derived from an artifact by the modality embedder — a separate, isolated index the
/// erasure cascade must also purge (a regulated artifact's embedding is itself regulated, §8).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DerivedEmbedding {
    pub id: String,
    pub artifact_id: String,
    /// The embedder's computed vector (real ingestion path, [`ingest_artifact`]). Empty for a
    /// hand-constructed [`DerivedEmbedding`] that predates this field (e.g. an erasure-cascade test
    /// fixture that only exercises the id-linkage, never the vector itself) — additive + defaulted, so
    /// existing construction sites are unaffected.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vector: Vec<f32>,
}

/// A vision/ASR model available for artifact embedding. `cloud == true` means the model runs on a
/// third-party cloud API — forbidden for regulated/PII data (ADR-012 / §8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactModel {
    pub id: String,
    pub modality: Modality,
    pub cloud: bool,
}

impl ArtifactModel {
    pub fn new(id: &str, modality: Modality, cloud: bool) -> Self {
        ArtifactModel {
            id: id.to_string(),
            modality,
            cloud,
        }
    }
}

/// Why artifact-model routing was refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RoutingError {
    /// No model of the right modality is eligible — for regulated/PII this means no *in-house*
    /// model exists, and the artifact must NOT be sent to a cloud model. Fail-closed.
    NoEligibleModel {
        modality: Modality,
        data_class: DataClass,
    },
}

/// Route an artifact of `data_class` + `modality` to an eligible model (§8 data-class routing).
/// A regulated/PII artifact resolves ONLY to a non-cloud model; anything else refuses rather than
/// leaking the artifact to a cloud vision/ASR API. Deterministic: candidates are id-sorted and the
/// first eligible one is returned.
pub fn route_model(
    data_class: DataClass,
    modality: Modality,
    models: &[ArtifactModel],
) -> Result<&ArtifactModel, RoutingError> {
    let mut candidates: Vec<&ArtifactModel> = models
        .iter()
        .filter(|m| m.modality == modality)
        .filter(|m| !(data_class.is_regulated() && m.cloud))
        .collect();
    candidates.sort_by(|a, b| a.id.cmp(&b.id));
    candidates
        .into_iter()
        .next()
        .ok_or(RoutingError::NoEligibleModel {
            modality,
            data_class,
        })
}

/// The modality embedder seam (§8) — one implementation per modality, so pipelines are isolated by
/// construction. A real deployment plugs in the in-house vision/ASR model; returning `None` = the
/// artifact could not be embedded (unsupported format, model error) and must surface, not be
/// silently skipped. Deferred to infra; the trait is the contract.
pub trait ArtifactEmbedder {
    fn modality(&self) -> Modality;
    fn embed(&self, artifact: &Artifact) -> Option<Vec<f32>>;
}

/// Why an artifact failed to ingest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IngestError {
    /// [`route_model`] found no eligible model for this artifact's modality + data-class (e.g. a
    /// regulated artifact whose only configured model for its modality is cloud-only).
    Routing(RoutingError),
    /// No [`ArtifactEmbedder`] was supplied for this artifact's modality — the fleet names an
    /// eligible model id but no embedder implementation for that modality is wired into this
    /// ingestion call. Distinct from [`RoutingError`]: the model exists in the fleet, but this
    /// deployment did not hand the ingestion pipeline an executable embedder for it.
    NoEmbedderForModality(Modality),
    /// The embedder ran but could not produce a vector for this artifact (unsupported format, model
    /// error) — fail-visible, never a silently-dropped artifact (mirrors
    /// [`crate::reembed`](crate)'s own `Failed` accounting for text embeddings).
    EmbedFailed { artifact_id: String },
}

/// **The minimal real multimodal ingestion pipeline** (gap `data-surfaces-artifacts`: "no live
/// ingestion pipeline populates an `ArtifactModel` fleet"). Glues the three pieces that already
/// existed in isolation — [`route_model`]'s data-class routing, an [`ArtifactEmbedder`]'s actual
/// vision/ASR compute, and [`ArtifactStore`]'s RBAC-labelled index — into ONE call an indexing
/// worker/connector makes per artifact:
///
/// 1. [`route_model`] resolves an eligible model id for `artifact`'s modality + data-class (§8: a
///    regulated/PII artifact never resolves to a cloud model) — fails closed on
///    [`IngestError::Routing`] if none exists, and the artifact is never indexed.
/// 2. The modality-matching embedder in `embedders` computes the derived vector. No matching
///    embedder → [`IngestError::NoEmbedderForModality`] (the fleet declares a model this deployment
///    has not actually wired an executable embedder for yet) — never silently skipped.
/// 3. An embedder that runs but returns `None` (unsupported format / model error) surfaces as
///    [`IngestError::EmbedFailed`] — the SAME fail-visible discipline
///    [`crate::reembed::run_reembed`](crate::reembed) uses for text embeddings, never a quiet drop.
/// 4. Only on full success are BOTH the artifact and its [`DerivedEmbedding`] added to `store` — a
///    routing/embed failure leaves the store untouched (no half-ingested artifact with no derived
///    embedding, which would silently break the erasure cascade's completeness guarantee).
///
/// Returns the derived embedding's id (`"{artifact.id}::{routed_model.id}"`, deterministic and
/// collision-free per artifact+model pair) on success.
pub fn ingest_artifact(
    store: &mut ArtifactStore,
    artifact: Artifact,
    models: &[ArtifactModel],
    embedders: &[&dyn ArtifactEmbedder],
) -> Result<String, IngestError> {
    let routed = route_model(artifact.data_class, artifact.modality, models)
        .map_err(IngestError::Routing)?;
    let embedder = embedders
        .iter()
        .find(|e| e.modality() == artifact.modality)
        .ok_or(IngestError::NoEmbedderForModality(artifact.modality))?;
    let vector = embedder
        .embed(&artifact)
        .ok_or_else(|| IngestError::EmbedFailed {
            artifact_id: artifact.id.clone(),
        })?;
    let derived_id = format!("{}::{}", artifact.id, routed.id);
    let derived = DerivedEmbedding {
        id: derived_id.clone(),
        artifact_id: artifact.id.clone(),
        vector,
    };
    store.add_artifact(artifact);
    store.add_derived(derived);
    Ok(derived_id)
}

/// What a right-to-erasure request must purge for one artifact: the artifact handle plus every
/// derived embedding row (id-sorted).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErasurePlan {
    pub artifact_id: String,
    pub derived_embedding_ids: Vec<String>,
}

/// The indexed artifact tier: RBAC-labelled artifacts + their derived embeddings, partitioned by
/// namespace. Pure/in-memory here (the reference index behind the object store + vector DB).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ArtifactStore {
    artifacts: Vec<Artifact>,
    derived: Vec<DerivedEmbedding>,
}

impl ArtifactStore {
    pub fn new() -> Self {
        ArtifactStore::default()
    }

    pub fn add_artifact(&mut self, artifact: Artifact) {
        self.artifacts.push(artifact);
    }

    pub fn add_derived(&mut self, derived: DerivedEmbedding) {
        self.derived.push(derived);
    }

    /// Artifacts in `namespace` visible to `ctx` — namespace isolation + pre-rank RBAC. An artifact
    /// in another namespace, above clearance, or not permitted by its ACL is filtered before any
    /// result forms, so its existence never leaks (§8). Results are id-sorted (deterministic).
    pub fn search(&self, namespace: &str, ctx: &AccessContext) -> Vec<&Artifact> {
        let mut hits: Vec<&Artifact> = self
            .artifacts
            .iter()
            .filter(|a| a.namespace == namespace)
            .filter(|a| a.visible_to(ctx))
            .collect();
        hits.sort_by(|a, b| a.id.cmp(&b.id));
        hits
    }

    /// The erasure cascade for an artifact (§8 / ADR-015): the artifact plus every derived
    /// embedding produced from it, so the modality-isolated vector rows are purged too.
    pub fn erasure_cascade(&self, artifact_id: &str) -> ErasurePlan {
        let mut derived_embedding_ids: Vec<String> = self
            .derived
            .iter()
            .filter(|d| d.artifact_id == artifact_id)
            .map(|d| d.id.clone())
            .collect();
        derived_embedding_ids.sort();
        ErasurePlan {
            artifact_id: artifact_id.to_string(),
            derived_embedding_ids,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gap_ctx_13_regulated_artifact_never_routes_to_cloud() {
        let models = vec![
            ArtifactModel::new("cloud-vision", Modality::Image, true),
            ArtifactModel::new("inhouse-vision", Modality::Image, false),
            ArtifactModel::new("cloud-asr", Modality::Audio, true),
        ];
        // A public image may use any image model (deterministic: id-sorted → cloud-vision first).
        let pub_route = route_model(DataClass::Public, Modality::Image, &models).unwrap();
        assert_eq!(pub_route.id, "cloud-vision");
        // A regulated KYC scan resolves ONLY to the in-house model.
        let reg_route = route_model(DataClass::RegulatedPayment, Modality::Image, &models).unwrap();
        assert_eq!(reg_route.id, "inhouse-vision");
        assert!(!reg_route.cloud);
        // A regulated audio artifact with only a CLOUD ASR model is refused — never sent to cloud.
        let err = route_model(DataClass::Pii, Modality::Audio, &models).unwrap_err();
        assert!(matches!(err, RoutingError::NoEligibleModel { .. }));
    }

    #[test]
    fn gap_ctx_13_namespace_isolation_and_existence_never_leaks() {
        let mut store = ArtifactStore::new();
        store.add_artifact(Artifact::new(
            "cheque1",
            "kyc:bankA",
            Modality::Image,
            DataClass::Confidential,
        ));
        store.add_artifact(Artifact::new(
            "cheque2",
            "kyc:bankB",
            Modality::Image,
            DataClass::Confidential,
        ));
        store.add_artifact(
            Artifact::new(
                "locked",
                "kyc:bankA",
                Modality::Image,
                DataClass::Confidential,
            )
            .with_acl(NodeAcl::new().departments(&["kyc-ops"])),
        );

        let ctx = AccessContext::new(DataClass::Confidential, Some("fraud"), None, &[]);
        let hits = store.search("kyc:bankA", &ctx);
        // Only bankA, and NOT the dept-locked one (existence never leaks across department).
        let ids: Vec<&str> = hits.iter().map(|a| a.id.as_str()).collect();
        assert_eq!(ids, vec!["cheque1"]);
        // bankB's artifact is never visible from a bankA-scoped query (namespace isolation).
        assert!(store
            .search("kyc:bankB", &ctx)
            .iter()
            .all(|a| a.id != "cheque1"));
        // The kyc-ops caller CAN see the locked artifact.
        let ops = AccessContext::new(DataClass::Confidential, Some("kyc-ops"), None, &[]);
        assert!(store
            .search("kyc:bankA", &ops)
            .iter()
            .any(|a| a.id == "locked"));
        // A below-clearance caller sees nothing (existence never leaks by class either).
        let low = AccessContext::new(DataClass::Internal, Some("kyc-ops"), None, &[]);
        assert!(store.search("kyc:bankA", &low).is_empty());
    }

    #[test]
    fn gap_ctx_13_erasure_cascades_to_derived_embeddings() {
        let mut store = ArtifactStore::new();
        store.add_artifact(Artifact::new(
            "cheque1",
            "kyc:bankA",
            Modality::Image,
            DataClass::Confidential,
        ));
        store.add_derived(DerivedEmbedding {
            id: "emb_a".into(),
            artifact_id: "cheque1".into(),
            vector: vec![],
        });
        store.add_derived(DerivedEmbedding {
            id: "emb_b".into(),
            artifact_id: "cheque1".into(),
            vector: vec![],
        });
        store.add_derived(DerivedEmbedding {
            id: "other".into(),
            artifact_id: "cheque2".into(),
            vector: vec![],
        });

        let plan = store.erasure_cascade("cheque1");
        assert_eq!(plan.artifact_id, "cheque1");
        // Both derived embeddings of cheque1 are purged; another artifact's is not touched.
        assert_eq!(plan.derived_embedding_ids, vec!["emb_a", "emb_b"]);
    }

    // ---- ingest_artifact: the minimal real ingestion pipeline (gap data-surfaces-artifacts) ----

    struct FixedEmbedder {
        modality: Modality,
        vector: Option<Vec<f32>>,
    }
    impl ArtifactEmbedder for FixedEmbedder {
        fn modality(&self) -> Modality {
            self.modality
        }
        fn embed(&self, _artifact: &Artifact) -> Option<Vec<f32>> {
            self.vector.clone()
        }
    }

    #[test]
    fn ingest_artifact_routes_embeds_and_indexes_both_artifact_and_derived_embedding() {
        let models = vec![ArtifactModel::new("inhouse-vision", Modality::Image, false)];
        let vision = FixedEmbedder {
            modality: Modality::Image,
            vector: Some(vec![0.1, 0.2, 0.3]),
        };
        let embedders: Vec<&dyn ArtifactEmbedder> = vec![&vision];
        let mut store = ArtifactStore::new();

        let id = ingest_artifact(
            &mut store,
            Artifact::new(
                "cheque9",
                "kyc:bankA",
                Modality::Image,
                DataClass::Confidential,
            ),
            &models,
            &embedders,
        )
        .expect("routing + embed must succeed");
        assert_eq!(id, "cheque9::inhouse-vision");

        let ctx = AccessContext::new(DataClass::Confidential, None, None, &[]);
        let hits = store.search("kyc:bankA", &ctx);
        assert_eq!(hits.len(), 1, "the artifact must be indexed");
        assert_eq!(hits[0].id, "cheque9");

        let plan = store.erasure_cascade("cheque9");
        assert_eq!(
            plan.derived_embedding_ids,
            vec![id],
            "the derived embedding must be indexed and linked to the artifact"
        );
    }

    #[test]
    fn ingest_artifact_refuses_a_regulated_artifact_that_only_has_a_cloud_model_never_indexes_it() {
        let models = vec![ArtifactModel::new("cloud-vision", Modality::Image, true)];
        let vision = FixedEmbedder {
            modality: Modality::Image,
            vector: Some(vec![1.0]),
        };
        let embedders: Vec<&dyn ArtifactEmbedder> = vec![&vision];
        let mut store = ArtifactStore::new();

        let err = ingest_artifact(
            &mut store,
            Artifact::new(
                "kyc-scan",
                "kyc:bankA",
                Modality::Image,
                DataClass::RegulatedPayment,
            ),
            &models,
            &embedders,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            IngestError::Routing(RoutingError::NoEligibleModel { .. })
        ));

        // The refused artifact must NEVER be indexed — a routing failure leaves the store untouched.
        let ctx = AccessContext::new(DataClass::RegulatedPayment, None, None, &[]);
        assert!(store.search("kyc:bankA", &ctx).is_empty());
    }

    #[test]
    fn ingest_artifact_surfaces_a_missing_embedder_without_indexing_anything() {
        let models = vec![ArtifactModel::new("inhouse-asr", Modality::Audio, false)];
        // No embedder supplied at all for Audio — the fleet names a model, but this call has no
        // executable embedder for the modality.
        let embedders: Vec<&dyn ArtifactEmbedder> = vec![];
        let mut store = ArtifactStore::new();

        let err = ingest_artifact(
            &mut store,
            Artifact::new(
                "call-1",
                "calls:bankA",
                Modality::Audio,
                DataClass::Internal,
            ),
            &models,
            &embedders,
        )
        .unwrap_err();
        assert_eq!(err, IngestError::NoEmbedderForModality(Modality::Audio));
        assert!(store
            .search(
                "calls:bankA",
                &AccessContext::new(DataClass::Internal, None, None, &[])
            )
            .is_empty());
    }

    #[test]
    fn ingest_artifact_surfaces_an_embed_failure_fail_visibly_never_a_silent_drop() {
        let models = vec![ArtifactModel::new("inhouse-vision", Modality::Image, false)];
        let vision = FixedEmbedder {
            modality: Modality::Image,
            vector: None,
        };
        let embedders: Vec<&dyn ArtifactEmbedder> = vec![&vision];
        let mut store = ArtifactStore::new();

        let err = ingest_artifact(
            &mut store,
            Artifact::new(
                "corrupt-scan",
                "kyc:bankA",
                Modality::Image,
                DataClass::Internal,
            ),
            &models,
            &embedders,
        )
        .unwrap_err();
        assert_eq!(
            err,
            IngestError::EmbedFailed {
                artifact_id: "corrupt-scan".into()
            }
        );
        assert!(store
            .search(
                "kyc:bankA",
                &AccessContext::new(DataClass::Internal, None, None, &[])
            )
            .is_empty());
    }
}
