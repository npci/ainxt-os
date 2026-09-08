// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R12 §4.1 — the Model Router's "exclude what is not allowed, THEN rank what remains" contract,
//! made concrete: cost/latency/quality-graded ranking (§4.1 step 4, §4.3, §4.5) with tier as a HARD
//! filter (§4.1 step 1), on top of the non-overridable data-class gate (§4.2).
//!
//! Fail-before: the router could only stable-sort by a *soft* tier preference (an off-tier model
//! stayed a candidate) and had no cost/latency/quality ranking at all — step 4 and the hard step 1
//! did not exist. Pass-after: `select_chain_graded` hard-excludes off-tier models, ranks the
//! survivors by (quality up, cost down, latency down), and never lets a class-excluded model into
//! the chain regardless of how good its metrics are.

use std::collections::BTreeMap;

use ainxt_protocol::Event;
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::{ModelRouter, RankWeights, RouteMetrics};
use ainxt_types::{DataClass, Tier};
use tokio::sync::mpsc;

/// A test provider with a declared tier and a configurable data-class eligibility floor.
struct P {
    id: &'static str,
    tier: Option<Tier>,
    /// When false, the provider is a cloud route: eligible only up to `Confidential`, never a
    /// regulated/PII class (models the §4.2 in-house-only exclusion).
    in_house: bool,
}
impl Provider for P {
    fn id(&self) -> &str {
        self.id
    }
    fn eligible(&self, dc: DataClass) -> bool {
        if self.in_house {
            true
        } else {
            !dc.is_regulated()
        }
    }
    fn tier(&self) -> Option<Tier> {
        self.tier
    }
    fn stream(&self, _prompt: &str) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(2);
        tokio::spawn(async move {
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

fn m(quality: u32, cost: u64, latency: u64) -> RouteMetrics {
    RouteMetrics {
        quality_score: quality,
        cost,
        latency,
    }
}

fn ids(chain: Vec<&dyn Provider>) -> Vec<String> {
    chain.into_iter().map(|p| p.id().to_string()).collect()
}

#[test]
fn ranks_by_quality_then_cost_then_latency() {
    let mut r = ModelRouter::new();
    // Registration order is deliberately the OPPOSITE of the desired ranking, so a pass only
    // succeeds if real ranking (not registration order) drove it.
    r.register(Box::new(P {
        id: "cheap_lowq",
        tier: None,
        in_house: true,
    }));
    r.register(Box::new(P {
        id: "best_quality",
        tier: None,
        in_house: true,
    }));
    r.register(Box::new(P {
        id: "mid",
        tier: None,
        in_house: true,
    }));

    let mut metrics = BTreeMap::new();
    metrics.insert("cheap_lowq".to_string(), m(40, 1, 1)); // cheapest but low quality
    metrics.insert("best_quality".to_string(), m(95, 50, 50)); // top quality, pricier
    metrics.insert("mid".to_string(), m(70, 10, 10));

    let chain = r
        .select_chain_graded(
            DataClass::Internal,
            None,
            None,
            &metrics,
            &RankWeights::default(),
        )
        .expect("chain");
    // Default weights: quality dominates.
    assert_eq!(ids(chain), vec!["best_quality", "mid", "cheap_lowq"]);
}

#[test]
fn cache_warm_lower_latency_wins_the_tie() {
    // §4.5: a cache-warm candidate reports lower latency/cost; among equal-quality peers it ranks
    // ahead. Both have identical quality + cost; "warm" has lower latency.
    let mut r = ModelRouter::new();
    r.register(Box::new(P {
        id: "cold",
        tier: None,
        in_house: true,
    }));
    r.register(Box::new(P {
        id: "warm",
        tier: None,
        in_house: true,
    }));

    let mut metrics = BTreeMap::new();
    metrics.insert("cold".to_string(), m(80, 10, 100));
    metrics.insert("warm".to_string(), m(80, 10, 5));

    let chain = r
        .select_chain_graded(
            DataClass::Internal,
            None,
            None,
            &metrics,
            &RankWeights::default(),
        )
        .expect("chain");
    assert_eq!(ids(chain), vec!["warm", "cold"]);
}

#[test]
fn tier_is_a_hard_filter_not_a_preference() {
    let mut r = ModelRouter::new();
    r.register(Box::new(P {
        id: "simple_model",
        tier: Some(Tier::Simple),
        in_house: true,
    }));
    r.register(Box::new(P {
        id: "complex_model",
        tier: Some(Tier::Complex),
        in_house: true,
    }));

    // Give the OFF-tier (simple) model the best metrics; the hard tier filter must still exclude it.
    let mut metrics = BTreeMap::new();
    metrics.insert("simple_model".to_string(), m(100, 1, 1));
    metrics.insert("complex_model".to_string(), m(50, 20, 20));

    let chain = r
        .select_chain_graded(
            DataClass::Internal,
            None,
            Some(Tier::Complex),
            &metrics,
            &RankWeights::default(),
        )
        .expect("chain");
    assert_eq!(
        ids(chain),
        vec!["complex_model"],
        "the off-tier simple model is EXCLUDED entirely, not merely deprioritized"
    );
}

#[test]
fn untiered_provider_survives_any_hard_tier_filter() {
    let mut r = ModelRouter::new();
    r.register(Box::new(P {
        id: "anytier",
        tier: None,
        in_house: true,
    }));
    r.register(Box::new(P {
        id: "simple_only",
        tier: Some(Tier::Simple),
        in_house: true,
    }));

    let metrics = BTreeMap::new();
    let chain = r
        .select_chain_graded(
            DataClass::Internal,
            None,
            Some(Tier::Complex),
            &metrics,
            &RankWeights::default(),
        )
        .expect("chain");
    assert_eq!(
        ids(chain),
        vec!["anytier"],
        "an un-tiered provider serves every tier; the simple-only one is filtered out"
    );
}

#[test]
fn class_exclusion_is_non_overridable_even_with_best_metrics() {
    let mut r = ModelRouter::new();
    // A cloud model with unbeatable metrics, and a modest in-house one.
    r.register(Box::new(P {
        id: "cloud_best",
        tier: None,
        in_house: false,
    }));
    r.register(Box::new(P {
        id: "in_house",
        tier: None,
        in_house: true,
    }));

    let mut metrics = BTreeMap::new();
    metrics.insert("cloud_best".to_string(), m(100, 1, 1));
    metrics.insert("in_house".to_string(), m(30, 40, 40));

    // Regulated turn: the cloud model is class-excluded BEFORE ranking — its metrics never count.
    let chain = r
        .select_chain_graded(
            DataClass::RegulatedPayment,
            None,
            None,
            &metrics,
            &RankWeights::default(),
        )
        .expect("chain");
    assert_eq!(
        ids(chain),
        vec!["in_house"],
        "a data-class-excluded model can never be reached, regardless of metrics"
    );

    // And forcing the cloud model on a regulated turn is a hard error, not an override.
    let forced = r.select_chain_graded(
        DataClass::RegulatedPayment,
        Some("cloud_best"),
        None,
        &metrics,
        &RankWeights::default(),
    );
    assert!(
        forced.is_err(),
        "forcing a class-excluded model must fail closed"
    );
}
