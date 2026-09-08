// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-AUDIT data-surfaces-artifacts — "Multimodal model-eligibility not wired": [`RoutedWindow`]'s
//! `artifacts` tier (populated when the plan routes to [`GraphLayer::MultimodalArtifact`]) used to
//! reach every caller with no model-eligibility check at all. [`ainxt_context::artifact::route_model`]
//! already encoded the correct rule (modality match + "regulated data never resolves to a cloud
//! model") but had zero callers on this served path — a regulated cheque-scan artifact and a public
//! marketing image came back identically, so nothing in this crate stopped a caller from handing a
//! regulated artifact to a cloud vision model.
//!
//! [`RoutedWindow::eligible_artifacts`] closes the gap: every artifact the window carries is routed
//! through `route_model` against a real model catalog. Fails before: the method did not exist, so this
//! gate could not be exercised at all on the served `route()`/`route_eligible()` path.

use ainxt_context::artifact::{Artifact, ArtifactModel, ArtifactStore, Modality, RoutingError};
use ainxt_context::optimizer::GraphLayer;
use ainxt_context::route::MultiGraphFabric;
use ainxt_context::{AccessContext, Chunk, OptimizerConfig};
use ainxt_retrieval::{EligibleModel, WordTokenCounter};
use ainxt_types::DataClass;

/// A fabric with exactly one node labelled into the multimodal-artifact layer (so the plan routes
/// there) plus a populated [`ArtifactStore`] holding the two artifacts under test.
fn fabric_with_artifacts(store: ArtifactStore) -> MultiGraphFabric {
    let graph = ainxt_context::optimizer::FabricGraph::new()
        .with_layer("art", GraphLayer::MultimodalArtifact);
    let chunk = Chunk::new(
        "art",
        "art.src",
        "kyc scan settlement image",
        DataClass::Internal,
    );
    MultiGraphFabric::from_fabric(graph, vec![chunk]).with_artifacts(store)
}

fn routed(store: ArtifactStore) -> ainxt_context::route::RoutedWindow {
    let fabric = fabric_with_artifacts(store);
    let query = "scan the kyc cheque image for this account";
    let counter = WordTokenCounter;
    // Max clearance: this test isolates MODEL-eligibility routing, not the separate RBAC
    // visibility gate (`Artifact::visible_to`) — a lower clearance would filter the regulated
    // artifact out of `RoutedWindow::artifacts` before routing ever runs, conflating the two gates.
    let access = AccessContext::new(DataClass::Pii, None, None, &[]);
    let eligible = [EligibleModel::new("wide", 1_000_000)];
    let cfg = OptimizerConfig {
        eligible: eligible.to_vec(),
        k: 64,
        ..OptimizerConfig::default()
    };
    fabric.route_eligible(query, &access, None, &eligible, &cfg, &counter, "kyc")
}

#[test]
fn r17_regulated_artifact_is_dropped_from_cloud_only_catalog() {
    let mut store = ArtifactStore::new();
    store.add_artifact(Artifact {
        id: "cheque-1".into(),
        namespace: "kyc".into(),
        modality: Modality::Image,
        data_class: DataClass::RegulatedPayment,
        acl: None,
    });
    let window = routed(store);
    assert_eq!(
        window.artifacts.len(),
        1,
        "the regulated artifact is indexed and namespace-visible"
    );

    // A catalog with ONLY a cloud vision model — no in-house alternative.
    let models = [ArtifactModel::new("cloud-vision", Modality::Image, true)];
    let (eligible, dropped) = window.eligible_artifacts(&models);

    assert!(
        eligible.is_empty(),
        "a RegulatedPayment artifact must never be paired with a cloud model: {eligible:?}"
    );
    assert_eq!(
        dropped.len(),
        1,
        "the regulated artifact is dropped, not silently forwarded"
    );
    assert_eq!(dropped[0].0.id, "cheque-1");
    assert!(matches!(
        dropped[0].1,
        RoutingError::NoEligibleModel {
            modality: Modality::Image,
            data_class: DataClass::RegulatedPayment
        }
    ));
}

#[test]
fn r17_regulated_artifact_is_eligible_against_an_in_house_model() {
    let mut store = ArtifactStore::new();
    store.add_artifact(Artifact {
        id: "cheque-2".into(),
        namespace: "kyc".into(),
        modality: Modality::Image,
        data_class: DataClass::RegulatedPayment,
        acl: None,
    });
    let window = routed(store);

    // Same regulated artifact, but the catalog now ALSO has an in-house (non-cloud) vision model.
    let models = [
        ArtifactModel::new("cloud-vision", Modality::Image, true),
        ArtifactModel::new("in-house-vision", Modality::Image, false),
    ];
    let (eligible, dropped) = window.eligible_artifacts(&models);

    assert!(
        dropped.is_empty(),
        "an in-house model is eligible for regulated data: {dropped:?}"
    );
    assert_eq!(eligible.len(), 1);
    assert_eq!(eligible[0].0.id, "cheque-2");
    assert_eq!(
        eligible[0].1.id, "in-house-vision",
        "must route to the IN-HOUSE model, never cloud"
    );
}

#[test]
fn r17_public_artifact_is_eligible_against_a_cloud_model() {
    let mut store = ArtifactStore::new();
    store.add_artifact(Artifact {
        id: "marketing-1".into(),
        namespace: "kyc".into(),
        modality: Modality::Image,
        data_class: DataClass::Public,
        acl: None,
    });
    let window = routed(store);

    let models = [ArtifactModel::new("cloud-vision", Modality::Image, true)];
    let (eligible, dropped) = window.eligible_artifacts(&models);

    assert!(
        dropped.is_empty(),
        "public data is eligible for a cloud model: {dropped:?}"
    );
    assert_eq!(eligible.len(), 1);
    assert_eq!(eligible[0].1.id, "cloud-vision");
}

#[test]
fn r17_wrong_modality_model_never_matches() {
    let mut store = ArtifactStore::new();
    store.add_artifact(Artifact {
        id: "call-1".into(),
        namespace: "kyc".into(),
        modality: Modality::Audio,
        data_class: DataClass::Public,
        acl: None,
    });
    let window = routed(store);

    // Only an Image-modality model is in the catalog; the artifact is Audio.
    let models = [ArtifactModel::new("cloud-vision", Modality::Image, true)];
    let (eligible, dropped) = window.eligible_artifacts(&models);

    assert!(
        eligible.is_empty(),
        "an Audio artifact must never route to an Image-only model"
    );
    assert_eq!(dropped.len(), 1);
    assert!(matches!(
        dropped[0].1,
        RoutingError::NoEligibleModel {
            modality: Modality::Audio,
            ..
        }
    ));
}
