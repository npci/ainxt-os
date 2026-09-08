// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! MTG cycle handling — Tarjan SCC super-nodes, decoupling prerequisites, strangler-fig shims.
//!
//! Design: `docs/architecture/LONG_HORIZON_PROGRAMS.md` (ADR-027) §3.3 (Tarjan SCC → migration
//! super-node or human-checkpointed decoupling prerequisite) and §3.4 (strangler-fig reverse-order
//! inserts a compatibility shim + a shim-cleanup node).
//!
//! [`crate::program`]'s `validate_decomposition`/`detect_cycle` only *reject* a cyclic decomposition.
//! That is correct for the state machine (an unschedulable graph must never silently run a partial
//! subset) but it is **not** how a real legacy monolith is handled — the gap this module closes
//! (`gap_tracker` LOOP-08). Legacy monoliths have mutual imports; §3.3 says circular coupling is
//! **surfaced**, never arbitrarily linearized: an SCC becomes a single migration super-node
//! (migrated together) if it fits a window, or a human-checkpointed decoupling-refactor prerequisite
//! if it does not. §3.4 says a strangler-fig reverse-order edge gets a shim + shim-cleanup node.
//!
//! Everything here is pure and deterministic (sorted iteration, no clock/rng/I/O), so each rule is a
//! property a unit test asserts on concrete graphs.

use crate::mtg::{ModuleRef, WindowBudget};
use std::collections::{BTreeMap, BTreeSet};

/// A module dependency graph: `deps[a]` = the modules `a` depends on (a → b means "a needs b").
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DepGraph {
    deps: BTreeMap<ModuleRef, BTreeSet<ModuleRef>>,
}

impl DepGraph {
    pub fn new() -> Self {
        DepGraph::default()
    }

    /// Register a module (even if it has no edges) so isolated nodes appear as singleton SCCs.
    pub fn add_module(&mut self, m: impl Into<ModuleRef>) {
        self.deps.entry(m.into()).or_default();
    }

    /// Add a dependency edge `from → to` (`from` depends on `to`). Both ends are registered.
    pub fn add_edge(&mut self, from: impl Into<ModuleRef>, to: impl Into<ModuleRef>) {
        let from = from.into();
        let to = to.into();
        self.deps.entry(to.clone()).or_default();
        self.deps.entry(from).or_default().insert(to);
    }

    /// The modules `m` depends on (sorted; empty if none or unknown).
    pub fn deps_of(&self, m: &ModuleRef) -> Vec<ModuleRef> {
        self.deps
            .get(m)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// All modules, sorted.
    pub fn modules(&self) -> Vec<ModuleRef> {
        self.deps.keys().cloned().collect()
    }

    /// Strongly-connected components via **Tarjan's algorithm** (§3.3). Deterministic: nodes and
    /// neighbours are visited in sorted order, each component is returned sorted, and components are
    /// ordered by their smallest member. An acyclic graph yields all singletons; a mutual-import
    /// cluster yields a multi-member component — the circular coupling, *surfaced* not linearized.
    pub fn strongly_connected_components(&self) -> Vec<Vec<ModuleRef>> {
        let mut ctx = Tarjan {
            graph: self,
            index: 0,
            indices: BTreeMap::new(),
            low: BTreeMap::new(),
            on_stack: BTreeSet::new(),
            stack: Vec::new(),
            out: Vec::new(),
        };
        for m in self.modules() {
            if !ctx.indices.contains_key(&m) {
                ctx.strongconnect(&m);
            }
        }
        // Normalise: sort each component, then order components by smallest member.
        for comp in &mut ctx.out {
            comp.sort();
        }
        ctx.out.sort_by(|a, b| a[0].cmp(&b[0]));
        ctx.out
    }

    /// The multi-member SCCs only — the actual circular-coupling clusters (§3.3). Singletons omitted.
    pub fn cyclic_components(&self) -> Vec<Vec<ModuleRef>> {
        self.strongly_connected_components()
            .into_iter()
            .filter(|c| c.len() > 1)
            .collect()
    }
}

/// Internal Tarjan state.
struct Tarjan<'a> {
    graph: &'a DepGraph,
    index: u64,
    indices: BTreeMap<ModuleRef, u64>,
    low: BTreeMap<ModuleRef, u64>,
    on_stack: BTreeSet<ModuleRef>,
    stack: Vec<ModuleRef>,
    out: Vec<Vec<ModuleRef>>,
}

impl Tarjan<'_> {
    fn strongconnect(&mut self, v: &ModuleRef) {
        self.indices.insert(v.clone(), self.index);
        self.low.insert(v.clone(), self.index);
        self.index += 1;
        self.stack.push(v.clone());
        self.on_stack.insert(v.clone());

        for w in self.graph.deps_of(v) {
            if !self.indices.contains_key(&w) {
                self.strongconnect(&w);
                let lw = self.low[&w];
                let lv = self.low.get_mut(v).expect("v present");
                *lv = (*lv).min(lw);
            } else if self.on_stack.contains(&w) {
                let iw = self.indices[&w];
                let lv = self.low.get_mut(v).expect("v present");
                *lv = (*lv).min(iw);
            }
        }

        if self.low[v] == self.indices[v] {
            let mut comp = Vec::new();
            while let Some(w) = self.stack.pop() {
                self.on_stack.remove(&w);
                comp.push(w.clone());
                if &w == v {
                    break;
                }
            }
            self.out.push(comp);
        }
    }
}

/// How an SCC is resolved (§3.3) — never an arbitrary linearization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SccResolution {
    /// The cluster fits a window → migrate it together as one super-node.
    Supernode { members: Vec<ModuleRef> },
    /// The cluster is too big for a window → a decoupling-refactor prerequisite node is inserted
    /// **before** it and the SCC is raised to a human checkpoint (§3.3). `requires_human_checkpoint`
    /// is always `true` for this arm.
    DecouplingPrerequisite {
        members: Vec<ModuleRef>,
        prerequisite: ModuleRef,
        requires_human_checkpoint: bool,
    },
}

/// Resolve one SCC (§3.3): if the cluster's combined working set fits the window, it is a migration
/// super-node; otherwise a decoupling-refactor prerequisite is generated and the cluster is raised to
/// a human checkpoint. `members` is sorted for a deterministic super-node identity / prereq name.
pub fn resolve_scc(
    members: &[ModuleRef],
    combined_working_set: u64,
    window: &WindowBudget,
) -> SccResolution {
    let mut members: Vec<ModuleRef> = members.to_vec();
    members.sort();
    if combined_working_set <= window.ceiling() {
        SccResolution::Supernode { members }
    } else {
        let joined = members
            .iter()
            .map(|m| m.as_str())
            .collect::<Vec<_>>()
            .join("+");
        SccResolution::DecouplingPrerequisite {
            prerequisite: ModuleRef::new(format!("decouple::{joined}")),
            members,
            requires_human_checkpoint: true,
        }
    }
}

/// A strangler-fig compatibility shim pair (§3.4): when a consumer must migrate *before* the provider
/// it depends on, a `shim` lets the consumer compile against the old provider until the provider's
/// node runs, and a `cleanup` node removes the shim afterwards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShimPair {
    /// Inserted so `consumer` compiles against the old `provider` (scheduled with the consumer).
    pub shim: ModuleRef,
    /// Removes the shim; scheduled **after** the provider migrates.
    pub cleanup: ModuleRef,
    pub consumer: ModuleRef,
    pub provider: ModuleRef,
}

/// Plan the strangler-fig shim + shim-cleanup nodes for a reverse-order edge (§3.4) — a consumer that
/// must migrate before the provider it depends on. Pure: returns the node identities the caller then
/// weaves into the MTG (shim before consumer's migration, cleanup after the provider's).
pub fn plan_strangler_shim(
    consumer: impl Into<ModuleRef>,
    provider: impl Into<ModuleRef>,
) -> ShimPair {
    let consumer = consumer.into();
    let provider = provider.into();
    ShimPair {
        shim: ModuleRef::new(format!(
            "shim::{}->{}",
            consumer.as_str(),
            provider.as_str()
        )),
        cleanup: ModuleRef::new(format!(
            "shim-cleanup::{}->{}",
            consumer.as_str(),
            provider.as_str()
        )),
        consumer,
        provider,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(s: &str) -> ModuleRef {
        ModuleRef::new(s)
    }

    // ---- Tarjan SCC -------------------------------------------------------

    #[test]
    fn gap_loop_08_acyclic_graph_yields_only_singletons() {
        // a -> b -> c (a depends on b depends on c): no cycles.
        let mut g = DepGraph::new();
        g.add_edge("a", "b");
        g.add_edge("b", "c");
        let sccs = g.strongly_connected_components();
        assert_eq!(sccs.len(), 3);
        assert!(sccs.iter().all(|c| c.len() == 1));
        assert!(g.cyclic_components().is_empty());
    }

    #[test]
    fn gap_loop_08_mutual_import_cluster_is_surfaced_as_an_scc_not_linearized() {
        // a <-> b (mutual imports) plus an independent c.
        let mut g = DepGraph::new();
        g.add_edge("a", "b");
        g.add_edge("b", "a");
        g.add_module("c");
        let cyclic = g.cyclic_components();
        assert_eq!(cyclic.len(), 1);
        assert_eq!(cyclic[0], vec![m("a"), m("b")]); // sorted, surfaced together
                                                     // c is a singleton, not swept into the cluster.
        assert!(g
            .strongly_connected_components()
            .iter()
            .any(|comp| comp == &vec![m("c")]));
    }

    #[test]
    fn gap_loop_08_three_node_cycle_is_one_component() {
        // a -> b -> c -> a
        let mut g = DepGraph::new();
        g.add_edge("a", "b");
        g.add_edge("b", "c");
        g.add_edge("c", "a");
        let cyclic = g.cyclic_components();
        assert_eq!(cyclic.len(), 1);
        assert_eq!(cyclic[0], vec![m("a"), m("b"), m("c")]);
    }

    // ---- SCC resolution ---------------------------------------------------

    #[test]
    fn gap_loop_08_small_scc_becomes_a_migration_supernode() {
        let window = WindowBudget::new(10_000); // ceiling 5_000
        let members = vec![m("a"), m("b")];
        // Combined 4_000 fits -> super-node (migrate together).
        let res = resolve_scc(&members, 4_000, &window);
        assert_eq!(
            res,
            SccResolution::Supernode {
                members: vec![m("a"), m("b")]
            }
        );
    }

    #[test]
    fn gap_loop_08_oversized_scc_becomes_a_human_checkpointed_decoupling_prerequisite() {
        let window = WindowBudget::new(10_000); // ceiling 5_000
        let members = vec![m("b"), m("a")]; // unsorted input
                                            // Combined 9_000 exceeds the window -> decoupling prerequisite + human checkpoint.
        let res = resolve_scc(&members, 9_000, &window);
        match res {
            SccResolution::DecouplingPrerequisite {
                members,
                prerequisite,
                requires_human_checkpoint,
            } => {
                assert_eq!(members, vec![m("a"), m("b")]); // sorted
                assert_eq!(prerequisite, m("decouple::a+b"));
                assert!(requires_human_checkpoint);
            }
            other => panic!("expected DecouplingPrerequisite, got {other:?}"),
        }
    }

    // ---- strangler-fig shim ----------------------------------------------

    #[test]
    fn gap_loop_08_reverse_order_edge_gets_a_shim_and_cleanup_node() {
        let pair = plan_strangler_shim("consumer", "provider");
        assert_eq!(pair.shim, m("shim::consumer->provider"));
        assert_eq!(pair.cleanup, m("shim-cleanup::consumer->provider"));
        assert_eq!(pair.consumer, m("consumer"));
        assert_eq!(pair.provider, m("provider"));
    }
}
