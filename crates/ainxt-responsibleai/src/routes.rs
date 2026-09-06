// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Route-ready shared types for the FI-07 SR-11-7 quality circuit-breaker / model-risk surface
//! (§2.1 / §4.2): [`ModelRiskRouteError`], [`PromotionDecision`], and [`CAP_MODEL_RISK`] are the wire
//! contract the served daemon's own model-risk preview endpoints use
//! (`ainxt_runtimed::AssembledFull::model_risk_breaker_status` /
//! `::model_risk_promotable_status`) — cap-gated, serde-round-trippable projections over the SAME
//! live [`crate::QualityCircuitBreaker`] / [`crate::route_promotable`] engine `AssembledFull::
//! admit_promotion` gates real promotions on.
//!
//! **Removed history (GAP-FIX gap6-responsibleai-cleanup, item 1):** this module used to also define
//! a `QualityBreakerService` that owned its OWN breaker bar / due-diligence config / model-risk
//! inventory (`route_id → ModelRiskRecord`) as a self-contained, route-ready service object, plus
//! `into_router_guard_parts()` meant to hand `ainxt-runtimed::build_router` the exact triple to install
//! via `ModelRouter::with_quality_guard`. It was fully implemented and unit-tested
//! (`r7_quality_breaker_route.rs`, `r12_router_guard_parts.rs`) but never had a real caller: when
//! `build_router` actually wired `with_quality_guard` onto the served router (`ainxt-runtimed/src/
//! lib.rs`'s `build_router`), it built a fresh `QualityCircuitBreaker` + `DueDiligenceConfig` directly
//! via `mounts::build_quality_breaker` instead of going through this service's inventory, and
//! `AssembledFull::admit_promotion` / `model_risk_breaker_status` likewise hold their own single
//! shared `quality_breaker` field rather than standing up a second, divergent inventory here (see
//! their doc comments). With BOTH real served call-sites confirmed to deliberately bypass it, the
//! service was confirmed-dead (not merely unwired) and removed along with its now-unused
//! `BreakerEvaluateRequest` request type and its two tests.

use serde::{Deserialize, Serialize};

/// Capability admitting the model-risk / quality-breaker read surface (DPO / model-risk officer /
/// the router before admitting a route). `role == Admin` implies it, per `Principal::has_cap`.
pub const CAP_MODEL_RISK: &str = "model-risk.read";

/// Why a route-ready model-risk call was refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum ModelRiskRouteError {
    /// The caller does not hold [`CAP_MODEL_RISK`] (checked before any inventory lookup). → 403.
    NotAuthorized,
    /// No model-risk record is inventoried for the route — fail-safe: an un-inventoried route is not
    /// evaluable and must not be admitted (§4.2 "monitored, not certified-once"). → 404.
    UnknownRoute(String),
}

impl std::fmt::Display for ModelRiskRouteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ModelRiskRouteError::NotAuthorized => {
                write!(f, "not authorized to read model-risk / quality-breaker")
            }
            ModelRiskRouteError::UnknownRoute(id) => {
                write!(f, "no model-risk record inventoried for route `{id}`")
            }
        }
    }
}

impl std::error::Error for ModelRiskRouteError {}

/// A serde-friendly promotion decision (the promotable counterpart to `BreakerState`). The engine's
/// `DueDiligenceOutcome` is not serializable, so the route surface projects it to a boolean plus the
/// human-legible defect reasons — enough for a transport to render a `403`/reason page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionDecision {
    pub route_id: String,
    pub promotable: bool,
    /// Every failing due-diligence reason (empty iff `promotable`). Fail-closed: all reasons at once.
    pub defects: Vec<String>,
}
