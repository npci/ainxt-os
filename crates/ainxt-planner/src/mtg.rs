// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Module Task Graph (MTG) window-sizing — the invariant that makes a 1M-LOC program feasible.
//!
//! Design: `docs/architecture/LONG_HORIZON_PROGRAMS.md` (ADR-027) §3.2 and §5.
//!
//! The load-bearing property of the whole long-horizon subsystem is stated in §3.2: a migration
//! node is *admissible* only if its **working-set estimate** — the module's own source **plus the
//! interface slices (signatures/contracts, not bodies) of its 1-hop neighbors** — fits within a
//! configured fraction (default ≤ 50%) of the target model's measured context budget. A node that
//! exceeds the budget is **automatically split** along sub-package / call-graph-community /
//! change-coupling-cluster boundaries until every leaf fits. The consequence (§5): **no node ever
//! overflows a window by construction; total repo size only affects the *number* of nodes, never
//! any single Run's context.**
//!
//! This module is the **pure, deterministic** core of that invariant. It reads no clock, draws no
//! randomness, does no I/O: [`MtgNode::working_set_estimate`] is a function of the node's declared
//! token costs, and [`MtgNode::auto_split`] is a deterministic recursive descent. Every guarantee
//! is a property a unit test asserts on concrete values.
//!
//! # The interface-not-implementation invariant, made structural
//!
//! An [`MtgNode`] stores `own_tokens` and a map of **neighbor → interface-slice tokens**. It has
//! **no field** for a neighbor's *body*, so a neighbor's implementation size is unrepresentable in
//! the working-set sum by construction — exactly the §5 "neighbor bodies excluded" guarantee. A
//! test pins `working_set_estimate == own + Σ interface` exactly, so any future change that folded
//! a body into the estimate would fail the suite.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Reference to a migration unit (package / bounded context / cohesive file cluster). ADR-027 §3
/// node contract field `module_ref`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ModuleRef(pub String);

impl ModuleRef {
    pub fn new(s: impl Into<String>) -> Self {
        ModuleRef(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for ModuleRef {
    fn from(s: &str) -> Self {
        ModuleRef(s.to_string())
    }
}
impl From<String> for ModuleRef {
    fn from(s: String) -> Self {
        ModuleRef(s)
    }
}
impl fmt::Display for ModuleRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The target model's usable context budget and the fraction of it a single node's working set may
/// occupy. The fraction is an **integer ratio** (num/den) so the ceiling is computed with exact
/// integer arithmetic — no float rounding drift across platforms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowBudget {
    /// The model's measured usable context, in tokens.
    pub context_tokens: u64,
    /// Numerator of the admissible fraction of the window (default 1).
    pub fraction_num: u32,
    /// Denominator of the admissible fraction of the window (default 2 → ≤ 50%, ADR-027 §3.2).
    pub fraction_den: u32,
}

/// Default admissible fraction numerator (1 of 2 → 50%).
pub const DEFAULT_FRACTION_NUM: u32 = 1;
/// Default admissible fraction denominator (1 of 2 → 50%).
pub const DEFAULT_FRACTION_DEN: u32 = 2;

impl WindowBudget {
    /// A budget with the ADR-027 default ≤ 50% fraction.
    pub fn new(context_tokens: u64) -> Self {
        WindowBudget {
            context_tokens,
            fraction_num: DEFAULT_FRACTION_NUM,
            fraction_den: DEFAULT_FRACTION_DEN,
        }
    }

    /// A budget with an explicit fraction. `den` of 0 is coerced to 1 (treated as "whole window")
    /// so the ceiling is always well-defined and this never divides by zero.
    pub fn with_fraction(context_tokens: u64, fraction_num: u32, fraction_den: u32) -> Self {
        WindowBudget {
            context_tokens,
            fraction_num,
            fraction_den: fraction_den.max(1),
        }
    }

    /// The admissible working-set ceiling in tokens = `floor(context_tokens * num / den)`. Computed
    /// in `u128` so the intermediate product cannot overflow for any realistic token count.
    pub fn ceiling(&self) -> u64 {
        let den = self.fraction_den.max(1) as u128;
        let prod = (self.context_tokens as u128) * (self.fraction_num as u128);
        (prod / den) as u64
    }
}

/// A candidate MTG node: a migration unit with a declared working-set cost and, when it is too big
/// for the window, the sub-boundaries it can be split along.
///
/// `children` are the sub-package / community / cluster boundaries the Program Planner discovered
/// for this module (§3.2). They are used **only** when the node itself does not fit; an admissible
/// node is emitted as-is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MtgNode {
    pub module_ref: ModuleRef,
    /// Tokens for this module's own source.
    pub own_tokens: u64,
    /// 1-hop neighbor → the token cost of that neighbor's **interface slice** (signatures/contracts
    /// only). There is deliberately no field for a neighbor's *body* (§5 interface-not-body).
    pub neighbor_interface: BTreeMap<ModuleRef, u64>,
    /// Dependents resolved from the call/import graph — the seam integration (§6) and rollback
    /// cascade (§9) read this. Not part of the working-set estimate.
    #[serde(default)]
    pub blast_radius: BTreeSet<ModuleRef>,
    /// Sub-boundaries this module can be split along if it exceeds the window (§3.2).
    #[serde(default)]
    pub children: Vec<MtgNode>,
}

impl MtgNode {
    /// A leaf node with own source cost and no neighbors or split boundaries.
    pub fn new(module_ref: impl Into<ModuleRef>, own_tokens: u64) -> Self {
        MtgNode {
            module_ref: module_ref.into(),
            own_tokens,
            neighbor_interface: BTreeMap::new(),
            blast_radius: BTreeSet::new(),
            children: Vec::new(),
        }
    }

    /// Builder: record a 1-hop neighbor's interface-slice token cost.
    pub fn with_neighbor(mut self, neighbor: impl Into<ModuleRef>, interface_tokens: u64) -> Self {
        self.neighbor_interface
            .insert(neighbor.into(), interface_tokens);
        self
    }

    /// Builder: record a dependent (blast radius entry).
    pub fn with_dependent(mut self, dependent: impl Into<ModuleRef>) -> Self {
        self.blast_radius.insert(dependent.into());
        self
    }

    /// Builder: add a split boundary (sub-module).
    pub fn with_child(mut self, child: MtgNode) -> Self {
        self.children.push(child);
        self
    }

    /// The working-set estimate (§3.2): the module's own source **plus** the interface slices of
    /// its 1-hop neighbors. Saturating so a pathological sum can never wrap to a small number and
    /// smuggle an over-budget node past [`is_admissible`](Self::is_admissible).
    pub fn working_set_estimate(&self) -> u64 {
        self.neighbor_interface
            .values()
            .copied()
            .fold(self.own_tokens, u64::saturating_add)
    }

    /// True iff this node's working set fits within the window's admissible ceiling (§3.2).
    pub fn is_admissible(&self, window: &WindowBudget) -> bool {
        self.working_set_estimate() <= window.ceiling()
    }

    /// The schedulable leaf form of this node — its own contract without the split-candidate
    /// subtree (a scheduled migration unit carries no `children`).
    fn emit_leaf(&self) -> MtgNode {
        MtgNode {
            module_ref: self.module_ref.clone(),
            own_tokens: self.own_tokens,
            neighbor_interface: self.neighbor_interface.clone(),
            blast_radius: self.blast_radius.clone(),
            children: Vec::new(),
        }
    }

    /// Auto-split this node until every emitted leaf fits the window (§3.2).
    ///
    /// * If the node is already admissible, it is emitted as a single leaf.
    /// * Otherwise it is split along its declared `children` boundaries, each of which is recursively
    ///   auto-split. Emission order is deterministic (the declared child order).
    /// * A node that exceeds the ceiling but has **no** split boundary is [`SplitError::Irreducible`]
    ///   — the honest "this leaf cannot be made to fit; a human must decompose it" outcome, never a
    ///   silent over-budget node.
    pub fn auto_split(&self, window: &WindowBudget) -> Result<Vec<MtgNode>, SplitError> {
        if self.is_admissible(window) {
            return Ok(vec![self.emit_leaf()]);
        }
        if self.children.is_empty() {
            return Err(SplitError::Irreducible {
                module_ref: self.module_ref.clone(),
                working_set: self.working_set_estimate(),
                ceiling: window.ceiling(),
            });
        }
        let mut out = Vec::new();
        for child in &self.children {
            out.extend(child.auto_split(window)?);
        }
        Ok(out)
    }
}

/// Why an over-budget node could not be auto-split down to admissible leaves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SplitError {
    /// A leaf module with no further split boundary still exceeds the admissible ceiling. Carries
    /// the offending module and the numbers, so the anomaly checkpoint (§8) has the evidence.
    Irreducible {
        module_ref: ModuleRef,
        working_set: u64,
        ceiling: u64,
    },
}

impl fmt::Display for SplitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SplitError::Irreducible {
                module_ref,
                working_set,
                ceiling,
            } => write!(
                f,
                "module '{module_ref}' is irreducible: working set {working_set} tokens exceeds \
                 window ceiling {ceiling} and has no split boundary"
            ),
        }
    }
}

impl std::error::Error for SplitError {}

/// Decompose a set of root modules into the flat, admissible MTG leaf set (§3.2/§5), auto-splitting
/// every root as needed. Deterministic: roots are processed in the given order, each split in its
/// declared child order. The **only** thing total repo size changes is the length of the result;
/// every element is guaranteed `working_set_estimate() ≤ window.ceiling()`.
pub fn decompose_modules(
    roots: &[MtgNode],
    window: &WindowBudget,
) -> Result<Vec<MtgNode>, SplitError> {
    let mut leaves = Vec::new();
    for root in roots {
        leaves.extend(root.auto_split(window)?);
    }
    Ok(leaves)
}

/// True iff every node in `nodes` is admissible for `window` — the §3.2 acceptance invariant, used
/// to assert a produced leaf set never contains an over-budget node.
pub fn all_admissible(nodes: &[MtgNode], window: &WindowBudget) -> bool {
    nodes.iter().all(|n| n.is_admissible(window))
}

/// The maximum working-set estimate across `nodes` (0 for an empty set) — the §5 "p100 per-Run
/// context" measurement the acceptance test asserts is bounded regardless of repo size.
pub fn max_working_set(nodes: &[MtgNode]) -> u64 {
    nodes
        .iter()
        .map(MtgNode::working_set_estimate)
        .max()
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mref(s: &str) -> ModuleRef {
        ModuleRef::new(s)
    }

    #[test]
    fn ceiling_is_exact_integer_arithmetic() {
        // 50% of 100_000 = 50_000.
        assert_eq!(WindowBudget::new(100_000).ceiling(), 50_000);
        // 30% of 100 = 30 (floor).
        assert_eq!(WindowBudget::with_fraction(100, 3, 10).ceiling(), 30);
        // Floor behaviour: 1/3 of 100 = 33 (not 34).
        assert_eq!(WindowBudget::with_fraction(100, 1, 3).ceiling(), 33);
        // A zero denominator is coerced to 1 (whole window), never a divide-by-zero.
        assert_eq!(WindowBudget::with_fraction(100, 1, 0).ceiling(), 100);
    }

    #[test]
    fn working_set_is_own_plus_interface_only_never_bodies() {
        // Own 1000 tokens + two neighbors' interface slices (50 + 30) = 1080.
        let node = MtgNode::new("settlement", 1000)
            .with_neighbor("ledger", 50)
            .with_neighbor("audit", 30);
        assert_eq!(node.working_set_estimate(), 1080);

        // A neighbor with a MASSIVE body cannot inflate the working set: only its interface slice
        // (5 tokens) is representable. If the estimate ever folded in a body, this exact-equality
        // assertion would fail — that is the structural interface-not-body guarantee (§5).
        let with_huge_neighbor = MtgNode::new("settlement", 1000).with_neighbor("giant", 5);
        assert_eq!(with_huge_neighbor.working_set_estimate(), 1005);
    }

    #[test]
    fn admissible_node_is_emitted_as_a_single_leaf_not_split() {
        let window = WindowBudget::new(10_000); // ceiling 5_000
        let node = MtgNode::new("m", 4_000)
            .with_neighbor("n", 100)
            .with_child(MtgNode::new("m::a", 2_000))
            .with_child(MtgNode::new("m::b", 2_000));
        assert!(node.is_admissible(&window));
        let leaves = node.auto_split(&window).unwrap();
        assert_eq!(leaves.len(), 1);
        assert_eq!(leaves[0].module_ref, mref("m"));
        // The emitted leaf carries no split subtree.
        assert!(leaves[0].children.is_empty());
    }

    #[test]
    fn oversized_node_splits_until_every_leaf_fits() {
        let window = WindowBudget::new(10_000); // ceiling 5_000
                                                // A 12_000-token module, over budget, with three sub-packages that each fit.
        let node = MtgNode::new("big", 12_000)
            .with_child(MtgNode::new("big::a", 4_000).with_neighbor("x", 100))
            .with_child(MtgNode::new("big::b", 3_000))
            .with_child(MtgNode::new("big::c", 4_500));
        assert!(!node.is_admissible(&window));

        let leaves = node.auto_split(&window).unwrap();
        assert_eq!(leaves.len(), 3);
        // Deterministic order preserved.
        assert_eq!(
            leaves
                .iter()
                .map(|l| l.module_ref.clone())
                .collect::<Vec<_>>(),
            vec![mref("big::a"), mref("big::b"), mref("big::c")]
        );
        // The invariant: every emitted leaf fits the window.
        assert!(all_admissible(&leaves, &window));
        assert!(max_working_set(&leaves) <= window.ceiling());
    }

    #[test]
    fn split_recurses_when_a_child_is_still_too_big() {
        let window = WindowBudget::new(10_000); // ceiling 5_000
        let node = MtgNode::new("root", 20_000).with_child(
            // This child is still over budget but has its own grandchildren.
            MtgNode::new("root::mid", 9_000)
                .with_child(MtgNode::new("root::mid::x", 4_000))
                .with_child(MtgNode::new("root::mid::y", 4_500)),
        );
        let leaves = node.auto_split(&window).unwrap();
        assert_eq!(leaves.len(), 2);
        assert_eq!(
            leaves
                .iter()
                .map(|l| l.module_ref.clone())
                .collect::<Vec<_>>(),
            vec![mref("root::mid::x"), mref("root::mid::y")]
        );
        assert!(all_admissible(&leaves, &window));
    }

    #[test]
    fn irreducible_leaf_is_an_honest_error_not_a_silent_overflow() {
        let window = WindowBudget::new(10_000); // ceiling 5_000
                                                // A single leaf of 6_000 tokens with no split boundary cannot be made to fit.
        let node = MtgNode::new("monolith", 6_000);
        let err = node.auto_split(&window).unwrap_err();
        assert_eq!(
            err,
            SplitError::Irreducible {
                module_ref: mref("monolith"),
                working_set: 6_000,
                ceiling: 5_000,
            }
        );
    }

    #[test]
    fn irreducible_surfaces_even_when_nested_under_splittable_parents() {
        let window = WindowBudget::new(10_000); // ceiling 5_000
        let node = MtgNode::new("big", 12_000)
            .with_child(MtgNode::new("big::ok", 4_000))
            // This grandchild-less child is over budget -> irreducible; the whole split fails honestly.
            .with_child(MtgNode::new("big::bad", 7_000));
        let err = node.auto_split(&window).unwrap_err();
        assert!(
            matches!(err, SplitError::Irreducible { module_ref, .. } if module_ref == mref("big::bad"))
        );
    }

    #[test]
    fn total_repo_size_only_changes_node_count_not_per_node_ceiling() {
        // The §5 property: a 10k-module program and a 100k-module program have the SAME per-node
        // context ceiling; only the leaf COUNT differs.
        let window = WindowBudget::new(8_000); // ceiling 4_000

        let make_repo = |count: usize| -> Vec<MtgNode> {
            (0..count)
                .map(|i| {
                    // Each module is 6_000 tokens (over budget) and splits into two 3_000 halves.
                    MtgNode::new(format!("mod{i}"), 6_000)
                        .with_child(MtgNode::new(format!("mod{i}::a"), 3_000))
                        .with_child(MtgNode::new(format!("mod{i}::b"), 3_000))
                })
                .collect()
        };

        let small = decompose_modules(&make_repo(10), &window).unwrap();
        let large = decompose_modules(&make_repo(100), &window).unwrap();

        // Node count scales with repo size (2 leaves per module).
        assert_eq!(small.len(), 20);
        assert_eq!(large.len(), 200);
        // But the per-node ceiling is identical and respected in both — repo size never enters a
        // single node's context.
        assert!(all_admissible(&small, &window));
        assert!(all_admissible(&large, &window));
        assert_eq!(max_working_set(&small), max_working_set(&large));
        assert!(max_working_set(&large) <= window.ceiling());
    }

    #[test]
    fn decompose_preserves_neighbor_interface_and_blast_radius_on_admissible_nodes() {
        let window = WindowBudget::new(100_000);
        let node = MtgNode::new("m", 100)
            .with_neighbor("n", 10)
            .with_dependent("dep1")
            .with_dependent("dep2");
        let leaves = decompose_modules(std::slice::from_ref(&node), &window).unwrap();
        assert_eq!(leaves.len(), 1);
        assert_eq!(leaves[0].neighbor_interface.get(&mref("n")), Some(&10));
        assert!(leaves[0].blast_radius.contains(&mref("dep1")));
        assert!(leaves[0].blast_radius.contains(&mref("dep2")));
    }
}
