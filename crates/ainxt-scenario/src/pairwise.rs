// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! 7-axis pairwise (all-pairs) matrix generation (SCENARIO_MATRIX.md §2).
//!
//! Full cross-product of the seven axes — Surface × Model × DataClass × Locale × Transport ×
//! Concurrency × Fault — is millions of cases and mostly redundant. **Pairwise** coverage (every
//! value-pair of every axis-pair appears in at least one case) catches the overwhelming majority of
//! interaction bugs at a tractable count. This module is the deterministic covering-array planner
//! ([`pairwise_plan`]) plus the axis vocabulary and a category expander that crosses a template with
//! the plan into genuinely-distinct [`Scenario`]s (never padding — each row is a different code path).
//!
//! Pure, deterministic (a greedy AETG-style construction with fixed tie-breaks — no RNG), std-only.

use crate::{Category, Expectation, Scenario};
use std::collections::BTreeSet;

// ============================ the seven axes (SCENARIO_MATRIX.md §2) ============================

/// Surface Profile — each grants different capabilities/autonomy/RBAC.
pub const SURFACES: &[&str] = &[
    "chat",
    "buddy",
    "code",
    "cli-headless",
    "sdlc",
    "custom-role",
];
/// Model family — failover/tokenizer/malformed/injection differ per family.
pub const MODELS: &[&str] = &["claude", "gpt", "gemini", "qwen", "glm", "gemma", "kimi"];
/// Data class — routing/retrieval/Judge eligibility change; hard-safety cells live here.
pub const DATA_CLASSES: &[&str] = &[
    "public",
    "internal",
    "confidential",
    "regulated-payment",
    "pii",
];
/// Locale / script — i18n + India-language quality.
pub const LOCALES: &[&str] = &["en", "hi", "ta", "bn", "ar-rtl", "mixed-smp"];
/// Transport / renderer — cancellation/streaming/backpressure differ per transport.
pub const TRANSPORTS: &[&str] = &["rest", "grpc", "sse", "websocket", "in-proc"];
/// Concurrency level — isolation/backpressure only manifest at scale.
pub const CONCURRENCY: &[&str] = &["1", "100", "2000"];
/// Fault mode — chaos injection (test-env-gated).
pub const FAULTS: &[&str] = &[
    "none",
    "provider-5xx",
    "net-drop",
    "worker-kill",
    "clock-skew",
    "redis-loss",
    "pg-loss",
];

/// The seven axes, in canonical order.
pub fn seven_axes() -> Vec<&'static [&'static str]> {
    vec![
        SURFACES,
        MODELS,
        DATA_CLASSES,
        LOCALES,
        TRANSPORTS,
        CONCURRENCY,
        FAULTS,
    ]
}

/// Names of the seven axes (for tagging), aligned with [`seven_axes`].
pub const AXIS_NAMES: &[&str] = &[
    "surface",
    "model",
    "data_class",
    "locale",
    "transport",
    "concurrency",
    "fault",
];

// ============================ the pairwise covering-array planner ============================

/// An unordered pair of (axis, value) coordinates from two *different* axes.
type PairKey = (usize, usize, usize, usize); // (axis_i, val_i, axis_j, val_j) with axis_i < axis_j

/// Enumerate every cross-axis value pair that must be covered.
fn all_pairs(sizes: &[usize]) -> BTreeSet<PairKey> {
    let mut pairs = BTreeSet::new();
    for i in 0..sizes.len() {
        for j in (i + 1)..sizes.len() {
            for vi in 0..sizes[i] {
                for vj in 0..sizes[j] {
                    pairs.insert((i, vi, j, vj));
                }
            }
        }
    }
    pairs
}

/// How many currently-uncovered pairs a candidate `value` for axis `a` would cover, given the axes
/// already fixed in `row` (`usize::MAX` = unset).
fn new_pairs_for(a: usize, value: usize, row: &[usize], uncovered: &BTreeSet<PairKey>) -> usize {
    let mut count = 0;
    for (b, &bv) in row.iter().enumerate() {
        if b == a || bv == usize::MAX {
            continue;
        }
        let key = if a < b {
            (a, value, b, bv)
        } else {
            (b, bv, a, value)
        };
        if uncovered.contains(&key) {
            count += 1;
        }
    }
    count
}

/// Mark every cross-axis pair present in a fully-assigned `row` as covered.
fn cover_row(row: &[usize], uncovered: &mut BTreeSet<PairKey>) {
    for i in 0..row.len() {
        for j in (i + 1)..row.len() {
            uncovered.remove(&(i, row[i], j, row[j]));
        }
    }
}

/// Build a pairwise (all-pairs) covering array over axes of the given `sizes`. Returns rows of value
/// indices (one per axis). Guarantees every cross-axis value-pair is covered by at least one row.
/// Deterministic greedy construction with lowest-index tie-breaks.
pub fn pairwise_plan(sizes: &[usize]) -> Vec<Vec<usize>> {
    if sizes.is_empty() || sizes.contains(&0) {
        return Vec::new();
    }
    if sizes.len() == 1 {
        return (0..sizes[0]).map(|v| vec![v]).collect();
    }
    let mut uncovered = all_pairs(sizes);
    let mut rows: Vec<Vec<usize>> = Vec::new();

    while let Some(&seed) = uncovered.iter().next() {
        let (ai, avi, bj, bvj) = seed;
        // Seed a new row with the chosen uncovered pair; guarantees progress each iteration.
        let mut row = vec![usize::MAX; sizes.len()];
        row[ai] = avi;
        row[bj] = bvj;
        // Fill remaining axes greedily to cover the most still-uncovered pairs.
        // Fixed axis order for determinism.
        for a in 0..sizes.len() {
            if row[a] != usize::MAX {
                continue;
            }
            let mut best_val = 0usize;
            let mut best_gain = None::<usize>;
            for v in 0..sizes[a] {
                let gain = new_pairs_for(a, v, &row, &uncovered);
                match best_gain {
                    Some(g) if gain <= g => {}
                    _ => {
                        best_gain = Some(gain);
                        best_val = v;
                    }
                }
            }
            row[a] = best_val;
        }
        cover_row(&row, &mut uncovered);
        rows.push(row);
    }
    rows
}

/// Verify a plan actually covers every cross-axis value-pair (used in tests and as a self-check).
pub fn plan_covers_all_pairs(sizes: &[usize], rows: &[Vec<usize>]) -> bool {
    let mut uncovered = all_pairs(sizes);
    for row in rows {
        if row.len() != sizes.len() {
            return false;
        }
        cover_row(row, &mut uncovered);
    }
    uncovered.is_empty()
}

// ============================ crossing the plan into scenarios ============================

/// A pairwise row resolved to concrete axis values (aligned with [`AXIS_NAMES`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AxisTuple {
    pub values: Vec<String>,
}

impl AxisTuple {
    /// The value for a named axis, if present.
    pub fn get(&self, axis: &str) -> Option<&str> {
        AXIS_NAMES
            .iter()
            .position(|&a| a == axis)
            .and_then(|i| self.values.get(i))
            .map(|s| s.as_str())
    }

    /// Tags of the form `axis=value` for attaching to a scenario.
    pub fn tags(&self) -> Vec<String> {
        AXIS_NAMES
            .iter()
            .zip(self.values.iter())
            .map(|(a, v)| format!("{a}={v}"))
            .collect()
    }
}

/// The pairwise plan over the seven axes, resolved to concrete value tuples.
pub fn seven_axis_plan() -> Vec<AxisTuple> {
    let axes = seven_axes();
    let sizes: Vec<usize> = axes.iter().map(|a| a.len()).collect();
    let plan = pairwise_plan(&sizes);
    plan.into_iter()
        .map(|row| AxisTuple {
            values: row
                .iter()
                .enumerate()
                .map(|(axis, &vi)| axes[axis][vi].to_string())
                .collect(),
        })
        .collect()
}

/// Expand a category template across the seven-axis pairwise plan into distinct scenarios. Each
/// scenario is tagged with its axis tuple, and the fault axis drives whether the turn must complete
/// (a chaos fault still requires graceful, non-crashing degradation — `must_complete` stays true;
/// the runtime must survive the fault, not the fault-free happy path only).
pub fn expand_pairwise(
    category: Category,
    id_prefix: &str,
    name: &str,
    input_base: &str,
) -> Vec<Scenario> {
    let plan = seven_axis_plan();
    plan.into_iter()
        .enumerate()
        .map(|(i, tuple)| {
            let mut sc = Scenario::new(
                &format!("{id_prefix}-{i:04}"),
                name,
                category,
                &format!(
                    "{input_base} [surface={} model={} data_class={} locale={} transport={} concurrency={} fault={}]",
                    tuple.get("surface").unwrap_or("?"),
                    tuple.get("model").unwrap_or("?"),
                    tuple.get("data_class").unwrap_or("?"),
                    tuple.get("locale").unwrap_or("?"),
                    tuple.get("transport").unwrap_or("?"),
                    tuple.get("concurrency").unwrap_or("?"),
                    tuple.get("fault").unwrap_or("?"),
                ),
                Expectation {
                    must_complete: true,
                    ..Default::default()
                },
            );
            sc.tags = tuple.tags();
            sc
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn pairwise_covers_all_pairs_small() {
        // 3 axes of sizes 2,3,2 — a classic small covering-array check.
        let sizes = vec![2, 3, 2];
        let plan = pairwise_plan(&sizes);
        assert!(
            plan_covers_all_pairs(&sizes, &plan),
            "every pair must be covered"
        );
        // Pairwise must be far smaller than the full cross-product (2*3*2 = 12).
        assert!(
            plan.len() < 12,
            "pairwise must beat full-cross: {} rows",
            plan.len()
        );
        assert!(
            plan.len() >= 6,
            "must be at least the size of the largest axis-pair product"
        );
    }

    #[test]
    fn pairwise_covers_all_pairs_seven_axes() {
        let axes = seven_axes();
        let sizes: Vec<usize> = axes.iter().map(|a| a.len()).collect();
        let plan = pairwise_plan(&sizes);
        assert!(
            plan_covers_all_pairs(&sizes, &plan),
            "the 7-axis plan must cover every cross-axis pair"
        );
        // Full cross would be 6*7*5*6*5*3*7 = 132300; pairwise must be a tiny fraction.
        let full: usize = sizes.iter().product();
        assert!(
            plan.len() < full / 100,
            "pairwise ({}) must be << full-cross ({full})",
            plan.len()
        );
        // The largest axis-pair product is 7*7... actually max is models(7)*faults(7)=49, so a valid
        // pairwise plan needs at least that many rows.
        assert!(
            plan.len() >= 49,
            "must cover the largest axis-pair (7×7): {} rows",
            plan.len()
        );
    }

    #[test]
    fn rows_are_fully_assigned_and_in_range() {
        let axes = seven_axes();
        let sizes: Vec<usize> = axes.iter().map(|a| a.len()).collect();
        for row in pairwise_plan(&sizes) {
            assert_eq!(row.len(), sizes.len());
            for (a, &v) in row.iter().enumerate() {
                assert!(v < sizes[a], "value {v} out of range for axis {a}");
            }
        }
    }

    #[test]
    fn seven_axis_plan_resolves_and_tags() {
        let plan = seven_axis_plan();
        assert!(!plan.is_empty());
        let t = &plan[0];
        assert_eq!(t.values.len(), 7);
        assert!(SURFACES.contains(&t.get("surface").unwrap()));
        assert!(FAULTS.contains(&t.get("fault").unwrap()));
        let tags = t.tags();
        assert_eq!(tags.len(), 7);
        assert!(tags.iter().any(|s| s.starts_with("surface=")));
    }

    #[test]
    fn expand_pairwise_yields_distinct_ids_and_axis_tags() {
        let scs = expand_pairwise(
            Category::ProviderFailover,
            "AX-FAILOVER",
            "failover holds across the axis matrix",
            "trigger a provider fault and recover",
        );
        assert!(scs.len() >= 49);
        let ids: HashSet<&str> = scs.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(ids.len(), scs.len(), "all ids unique");
        assert!(
            scs.iter().all(|s| s.tags.len() == 7),
            "each carries its 7-axis tuple"
        );
        assert!(scs.iter().all(|s| s.expect.must_complete));
    }

    #[test]
    fn edge_cases_are_handled() {
        assert!(pairwise_plan(&[]).is_empty());
        assert!(
            pairwise_plan(&[3, 0, 2]).is_empty(),
            "a zero-size axis yields no plan"
        );
        // single axis → one row per value.
        assert_eq!(pairwise_plan(&[4]).len(), 4);
    }
}
