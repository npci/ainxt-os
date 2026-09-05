// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-AUDIT data-surfaces-artifacts — "Multimodal model-eligibility not wired": a served turn's
//! [`compile_served_fabric`] assembles a [`RoutedWindow`] whose `artifacts` tier used to reach the
//! caller with no model-eligibility check at all: a regulated cheque-scan artifact and a public image
//! came back identically, so a caller wiring the routed window straight into a model dispatch had
//! nothing in the composition root stopping it from sending regulated data to a cloud vision model.
//! `ainxt_context::artifact::route_model` already encoded the correct data-class/modality rule, and
//! `governed::route_artifact_model` made it callable from this crate — but nothing called it with a
//! REAL served window's artifacts.
//!
//! `governed::served_multimodal_turn` closes the loop end-to-end on the composition root: given the
//! `RoutedWindow` `compile_served_fabric` produces for a live turn and a real model catalog, only the
//! eligible (artifact, model) pairs are returned. FAIL-BEFORE: `served_multimodal_turn` did not exist,
//! so this composition-root path could not be exercised at all.

use ainxt_context::artifact::{Artifact, ArtifactModel, ArtifactStore, Modality, RoutingError};
use ainxt_context::optimizer::{FabricGraph, GraphLayer};
use ainxt_context::Chunk as CtxChunk;
use ainxt_profile::RetrievalScope;
use ainxt_runtimed::governed::{
    access_for, compile_served_fabric, eligible_default, served_fabric_from_kb,
    served_multimodal_turn,
};
use ainxt_runtimed::KbConfig;
use ainxt_types::{DataClass, Principal};

/// A fabric with one node labelled into the multimodal-artifact layer (routing the plan there) plus a
/// populated [`ArtifactStore`] holding a regulated cheque scan and a public marketing image, both in
/// the SAME namespace the query targets.
fn fabric_with_two_artifacts() -> ainxt_context::route::MultiGraphFabric {
    let graph = FabricGraph::new().with_layer("art", GraphLayer::MultimodalArtifact);
    let chunk = CtxChunk::new(
        "art",
        "art.src",
        "kyc cheque scan settlement image",
        DataClass::Internal,
    );
    let mut store = ArtifactStore::new();
    store.add_artifact(Artifact {
        id: "cheque-served-1".into(),
        namespace: "kyc".into(),
        modality: Modality::Image,
        data_class: DataClass::RegulatedPayment,
        acl: None,
    });
    store.add_artifact(Artifact {
        id: "marketing-served-1".into(),
        namespace: "kyc".into(),
        modality: Modality::Image,
        data_class: DataClass::Public,
        acl: None,
    });
    let kb = KbConfig {
        documents: vec![],
        rls_department_isolation: false,
        rag_enabled: true,
    };
    served_fabric_from_kb(
        &kb,
        RetrievalScope::PlatformAndNamespace,
        graph,
        vec![chunk],
    )
    .with_artifacts(store)
}

#[test]
fn r_served_multimodal_turn_gates_regulated_artifact_off_cloud_only_catalog() {
    let fabric = fabric_with_two_artifacts();
    // Max clearance: this test isolates model-eligibility routing, not the separate RBAC visibility
    // gate — a lower clearance would filter the regulated artifact out of the window before routing
    // ever ran, conflating the two gates the same way the crate-level unit test guards against.
    let principal = Principal::user("u", &["chat.send"]).with_clearance(DataClass::Pii);
    let access = access_for(&principal, None, &[]);
    let query = "scan the kyc cheque image for this account";

    let routed = compile_served_fabric(&fabric, query, &access, None, &eligible_default(), "kyc");
    assert_eq!(
        routed.artifacts.len(),
        2,
        "both artifacts are indexed and namespace-visible"
    );

    // A model catalog with ONLY a cloud vision model — the honest air-gapped-default shape: no
    // in-house vision model configured yet.
    let models = [ArtifactModel::new("cloud-vision", Modality::Image, true)];
    let (eligible, dropped) = served_multimodal_turn(&routed, &models);

    assert_eq!(
        eligible.len(),
        1,
        "only the PUBLIC artifact is eligible for the cloud-only catalog"
    );
    assert_eq!(eligible[0].0.id, "marketing-served-1");
    assert_eq!(eligible[0].1.id, "cloud-vision");

    assert_eq!(
        dropped.len(),
        1,
        "the REGULATED artifact is dropped, never silently forwarded"
    );
    assert_eq!(dropped[0].0.id, "cheque-served-1");
    assert!(matches!(
        dropped[0].1,
        RoutingError::NoEligibleModel {
            modality: Modality::Image,
            data_class: DataClass::RegulatedPayment
        }
    ));
}

#[test]
fn r_served_multimodal_turn_routes_regulated_artifact_to_in_house_model_when_configured() {
    let fabric = fabric_with_two_artifacts();
    let principal = Principal::user("u", &["chat.send"]).with_clearance(DataClass::Pii);
    let access = access_for(&principal, None, &[]);
    let query = "scan the kyc cheque image for this account";
    let routed = compile_served_fabric(&fabric, query, &access, None, &eligible_default(), "kyc");

    // A deployment that HAS configured an in-house vision model: now the regulated artifact is
    // eligible too, and routes to the in-house model specifically (never the cloud one).
    let models = [
        ArtifactModel::new("cloud-vision", Modality::Image, true),
        ArtifactModel::new("in-house-vision", Modality::Image, false),
    ];
    let (eligible, dropped) = served_multimodal_turn(&routed, &models);

    assert!(
        dropped.is_empty(),
        "both artifacts are now eligible: {dropped:?}"
    );
    assert_eq!(eligible.len(), 2);
    let regulated = eligible
        .iter()
        .find(|(a, _)| a.id == "cheque-served-1")
        .unwrap();
    assert_eq!(
        regulated.1.id, "in-house-vision",
        "regulated data must route to the IN-HOUSE model"
    );
}
