// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! The Program **composition entrypoint** — the single clean call that turns a repository module
//! model into the validated `Vec<NodeDecl>` a live-drivable [`crate::driver::Program`] is decomposed
//! with.
//!
//! Design: `docs/architecture/LONG_HORIZON_PROGRAMS.md` (ADR-027) §3.2 (window-sizing), §3.3 (SCC
//! super-node / decoupling prerequisite) and §3.4 (strangler-fig shims).
//!
//! # The gap this closes
//!
//! [`crate::mtg`] (window-sizing / auto-split), [`crate::scc`] (Tarjan SCC + resolution + strangler
//! shims) and [`crate::program::NodeDecl`] (the node contract the durable Program consumes) each
//! existed and were unit-tested in isolation — but **nothing composed them into the node graph the
//! served path actually decomposes with**. The live served path therefore hard-coded a single
//! `NodeDecl`, so a real 1M-LOC repository never reached window-sizing, cycle handling, or shim
//! planning at all. [`MigrationBlueprint::compose`] is that missing composition: one deterministic,
//! pure function
//!
//! ```text
//!   modules + dep-graph + window + reverse-order edges  ->  Vec<NodeDecl>
//! ```
//!
//! that runs, in order: (1) §3.2 window-sizing/auto-split over every root module; (2) §3.3 Tarjan SCC
//! detection and per-cluster resolution (fits-window → one migration super-node; too big → a
//! human-checkpointed `DecouplingRefactor` prerequisite that breaks the cycle); (3) §3.4 strangler
//! shims for declared reverse-order edges (a `Shim` scheduled with the consumer + a `ShimCleanup`
//! scheduled after the provider). The result is a node set the durable Program accepts and can
//! schedule — window-sizing, cycle handling and shim planning are now reachable through **one**
//! entrypoint, and the served path only has to build a [`MigrationBlueprint`] and call `compose`.
//!
//! Pure and deterministic: no clock, no rng, no I/O; nodes are emitted in a stable id order, so the
//! same blueprint always yields byte-identical decls (each guarantee below is a unit-test property).

use crate::mtg::{decompose_modules, ModuleRef, MtgNode, SplitError, WindowBudget};
use crate::program::{CheckpointClass, EditRung, NodeClass, NodeDecl, NodeId};
use crate::scc::{plan_strangler_shim, resolve_scc, DepGraph, SccResolution};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// A migration unit surfaced by the Context Fabric (§3.1): a module reference plus the measured token
/// size of its working set (the module body + its 1-hop interface context). This is the unit
/// [`MigrationBlueprint::from_source`] turns into an [`MtgNode`] root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FabricModule {
    pub module: ModuleRef,
    /// Measured working-set tokens (drives the §3.2 window-admissibility check).
    pub working_set_tokens: u64,
}

impl FabricModule {
    pub fn new(module: impl Into<ModuleRef>, working_set_tokens: u64) -> Self {
        FabricModule {
            module: module.into(),
            working_set_tokens,
        }
    }
}

/// The **Context-Fabric module-graph seam** (LONG_HORIZON §3.1): the source of the *real* repository
/// module set + import/call dependency graph a Program is decomposed from. The served path must NOT
/// hard-code a blueprint — it must decompose from the actual codebase structure the Context Fabric
/// surfaced (module bodies, working-set sizes, and the import/call edges between them).
///
/// This is the seam for that. A deployment backs it with the live `ainxt-context` retrieval layer
/// (the real import/call graph over the indexed repository — a live retrieval source, so wiring it is
/// `needs_hot_wiring` / infra-gated); [`StaticModuleGraph`] is the offline, dependency-free default
/// used by tests and fixed shapes. Either way, [`MigrationBlueprint::from_source`] composes the result
/// through the SAME §3.2/§3.3/§3.4 planner, so window-sizing / cycle-resolution / shim-planning run
/// over whatever graph the source provides — never a fabricated single node.
pub trait ModuleGraphSource {
    /// The migration units the Fabric surfaced for this program's scope.
    fn modules(&self) -> Vec<FabricModule>;
    /// The dependency edges (`(a, b)` = "a depends on b / imports b") over those modules. Cycles are
    /// permitted — §3.3 (SCC) resolves them; they are never rejected at this seam.
    fn edges(&self) -> Vec<(ModuleRef, ModuleRef)>;
}

/// The offline, dependency-free [`ModuleGraphSource`] default: an explicitly-provided module set +
/// edge list. This is what a test or a fixed migration shape uses; a deployment substitutes the live
/// `ainxt-context` import/call graph behind the same trait (`needs_hot_wiring`).
#[derive(Debug, Clone, Default)]
pub struct StaticModuleGraph {
    modules: Vec<FabricModule>,
    edges: Vec<(ModuleRef, ModuleRef)>,
}

impl StaticModuleGraph {
    pub fn new() -> Self {
        StaticModuleGraph::default()
    }
    /// Add a migration unit with its measured working-set size.
    pub fn with_module(mut self, module: impl Into<ModuleRef>, working_set_tokens: u64) -> Self {
        self.modules
            .push(FabricModule::new(module, working_set_tokens));
        self
    }
    /// Add a dependency edge `a → b` ("a imports / depends on b").
    pub fn with_edge(mut self, a: impl Into<ModuleRef>, b: impl Into<ModuleRef>) -> Self {
        self.edges.push((a.into(), b.into()));
        self
    }
}

impl ModuleGraphSource for StaticModuleGraph {
    fn modules(&self) -> Vec<FabricModule> {
        self.modules.clone()
    }
    fn edges(&self) -> Vec<(ModuleRef, ModuleRef)> {
        self.edges.clone()
    }
}

/// A strangler-fig **reverse-order edge** (§3.4): a `consumer` that must migrate *before* the
/// `provider` it depends on. The natural `consumer → provider` dependency is therefore replaced by a
/// compatibility shim so the consumer can migrate first and compile against the old provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReverseEdge {
    pub consumer: ModuleRef,
    pub provider: ModuleRef,
}

impl ReverseEdge {
    pub fn new(consumer: impl Into<ModuleRef>, provider: impl Into<ModuleRef>) -> Self {
        ReverseEdge {
            consumer: consumer.into(),
            provider: provider.into(),
        }
    }
}

/// The repository model a Program is composed from — the input to [`MigrationBlueprint::compose`].
#[derive(Debug, Clone)]
pub struct MigrationBlueprint {
    /// Root migration units. Each is auto-split (§3.2) so every emitted leaf fits the window.
    pub roots: Vec<MtgNode>,
    /// The dependency graph over the **final migration-unit refs** (leaf refs after any split):
    /// `a → b` means "a depends on b" (b must migrate first). Cycles here are handled by §3.3, not
    /// rejected.
    pub dep_graph: DepGraph,
    /// The target model's context window budget the working-set admissibility check is against.
    pub window: WindowBudget,
    /// Declared reverse-order edges that get a strangler shim (§3.4).
    pub reverse_edges: Vec<ReverseEdge>,
    /// Modules whose migration is on the settlement/ledger/compliance critical path: they are raised
    /// to a `CriticalPath` human commit gate and their edit-ladder floor is lifted to AST (§8/§10 —
    /// `TextPatch` forbidden on the critical path).
    pub critical_paths: BTreeSet<ModuleRef>,
}

impl MigrationBlueprint {
    /// A blueprint with no cycles, no shims, no critical-path modules — the common acyclic case.
    pub fn new(roots: Vec<MtgNode>, dep_graph: DepGraph, window: WindowBudget) -> Self {
        MigrationBlueprint {
            roots,
            dep_graph,
            window,
            reverse_edges: Vec::new(),
            critical_paths: BTreeSet::new(),
        }
    }

    /// Build a blueprint from a **Context-Fabric-derived module graph** (LONG_HORIZON §3.1): the
    /// dependency structure the served path decomposes from should come from the *real* repository
    /// import/call graph, not a fabricated single node. This is the clean seam for that: the caller
    /// passes `(module_ref, working_set_tokens)` for every migration unit the Context Fabric surfaced,
    /// plus `edges` (`(a, b)` = "a depends on b") from its dependency layer. The Fabric itself is a
    /// live retrieval source (reported `needs_hot_wiring` — the daemon populates these from
    /// `ainxt-context`); this function is the pure composition that turns that structure into a
    /// schedulable [`MigrationBlueprint`], so window-sizing / SCC / shim planning all run over the real
    /// graph. Cycles in `edges` are handled by §3.3 (SCC), never rejected here.
    pub fn from_module_graph(
        modules: impl IntoIterator<Item = (ModuleRef, u64)>,
        edges: impl IntoIterator<Item = (ModuleRef, ModuleRef)>,
        window: WindowBudget,
    ) -> Self {
        let roots: Vec<MtgNode> = modules
            .into_iter()
            .map(|(m, tokens)| MtgNode::new(m, tokens))
            .collect();
        let mut dep_graph = DepGraph::new();
        for (a, b) in edges {
            dep_graph.add_edge(a, b);
        }
        MigrationBlueprint::new(roots, dep_graph, window)
    }

    /// Build a blueprint directly from a [`ModuleGraphSource`] (LONG_HORIZON §3.1) — the clean seam the
    /// served path uses to decompose from the **real** Context-Fabric import/call graph instead of a
    /// fabricated fixed node set. The source supplies the migration units (with measured working-set
    /// sizes) and the dependency edges; this composes them into a schedulable blueprint against
    /// `window`. Window-sizing / SCC / shim planning then run over the real graph via
    /// [`MigrationBlueprint::compose`]. A deployment backs the source with live `ainxt-context`
    /// (`needs_hot_wiring`); [`StaticModuleGraph`] backs it offline.
    pub fn from_source(source: &dyn ModuleGraphSource, window: WindowBudget) -> Self {
        MigrationBlueprint::from_module_graph(
            source
                .modules()
                .into_iter()
                .map(|m| (m.module, m.working_set_tokens)),
            source.edges(),
            window,
        )
    }

    /// Builder: declare a strangler reverse-order edge (§3.4).
    pub fn with_reverse_edge(
        mut self,
        consumer: impl Into<ModuleRef>,
        provider: impl Into<ModuleRef>,
    ) -> Self {
        self.reverse_edges
            .push(ReverseEdge::new(consumer, provider));
        self
    }

    /// Builder: mark a module as critical-path (forces a human commit gate; §8/§10).
    pub fn with_critical_path(mut self, module: impl Into<ModuleRef>) -> Self {
        self.critical_paths.insert(module.into());
        self
    }

    /// Compose the blueprint into the validated node graph the durable Program is decomposed with.
    ///
    /// Runs, deterministically and in order:
    /// 1. **Window-sizing (§3.2)** — [`decompose_modules`] auto-splits every root until every leaf's
    ///    working set fits the window; an irreducible leaf is a hard [`ComposeError::Split`], never a
    ///    silent over-budget node.
    /// 2. **Cycle handling (§3.3)** — Tarjan SCC over the dep graph; each multi-member cluster is
    ///    [`resolve_scc`]d: a cluster that fits the window collapses to one migration super-node
    ///    (members migrate together); one that does not becomes a human-checkpointed
    ///    `DecouplingRefactor` prerequisite that every member depends on, and the intra-cluster edges
    ///    are dropped (the decoupling breaks the cycle) — so the emitted graph is always acyclic.
    /// 3. **Strangler shims (§3.4)** — each declared reverse-order edge drops the consumer→provider
    ///    dependency, adds a `Shim` the consumer depends on, and a `ShimCleanup` scheduled after the
    ///    provider (and consumer) migrate.
    ///
    /// Nodes are returned sorted by id (deterministic). The result is what [`crate::driver::Program`]
    /// / `Program::decompose` validates and schedules.
    pub fn compose(&self) -> Result<Vec<NodeDecl>, ComposeError> {
        // ---- 1. window-sizing ------------------------------------------------------------------
        let leaves = decompose_modules(&self.roots, &self.window).map_err(ComposeError::Split)?;
        let leaf_ids: BTreeSet<ModuleRef> = leaves.iter().map(|l| l.module_ref.clone()).collect();
        let working_set: BTreeMap<ModuleRef, u64> = leaves
            .iter()
            .map(|l| (l.module_ref.clone(), l.working_set_estimate()))
            .collect();
        let blast: BTreeMap<ModuleRef, BTreeSet<ModuleRef>> = leaves
            .iter()
            .map(|l| (l.module_ref.clone(), l.blast_radius.clone()))
            .collect();

        // ---- 2. SCC classification -------------------------------------------------------------
        // `rep[m]` is the id of the emitted node that owns member `m` (identity for a normal leaf, the
        // super-node id for a collapsed cluster). `decouple_of[m]` is the decoupling prerequisite a
        // member must wait on, and `cluster_of[m]` names the members it may no longer depend on
        // directly (the cycle is broken by the prerequisite).
        let mut rep: BTreeMap<ModuleRef, ModuleRef> =
            leaf_ids.iter().map(|m| (m.clone(), m.clone())).collect();
        let mut supernodes: Vec<SuperNode> = Vec::new();
        let mut decouple_of: BTreeMap<ModuleRef, ModuleRef> = BTreeMap::new();
        let mut cluster_of: BTreeMap<ModuleRef, BTreeSet<ModuleRef>> = BTreeMap::new();
        let mut decouple_prereqs: Vec<DecouplePrereq> = Vec::new();

        for comp in self.dep_graph.strongly_connected_components() {
            if comp.len() < 2 {
                continue; // singleton — no cycle to resolve
            }
            // Only resolve clusters whose every member is an emitted leaf; a member that is not a
            // migration unit is left alone and surfaces (if referenced) as an honest dangling dep at
            // Program validation, never silently swept into a super-node.
            if !comp.iter().all(|m| leaf_ids.contains(m)) {
                continue;
            }
            let combined = comp
                .iter()
                .map(|m| working_set.get(m).copied().unwrap_or(0))
                .fold(0u64, u64::saturating_add);
            match resolve_scc(&comp, combined, &self.window) {
                SccResolution::Supernode { members } => {
                    let id = ModuleRef::new(
                        members
                            .iter()
                            .map(|m| m.as_str())
                            .collect::<Vec<_>>()
                            .join("+"),
                    );
                    for m in &members {
                        rep.insert(m.clone(), id.clone());
                    }
                    supernodes.push(SuperNode {
                        id,
                        members: members.into_iter().collect(),
                        working_set: combined,
                    });
                }
                SccResolution::DecouplingPrerequisite {
                    members,
                    prerequisite,
                    ..
                } => {
                    let member_set: BTreeSet<ModuleRef> = members.iter().cloned().collect();
                    for m in &members {
                        decouple_of.insert(m.clone(), prerequisite.clone());
                        cluster_of.insert(m.clone(), member_set.clone());
                    }
                    decouple_prereqs.push(DecouplePrereq {
                        id: prerequisite,
                        members: member_set,
                    });
                }
            }
        }

        // Reverse edges: the consumer→provider dependency is *replaced* by a shim, so it must be
        // dropped from the consumer's normal deps. Keyed by (consumer, provider).
        let reverse: BTreeSet<(ModuleRef, ModuleRef)> = self
            .reverse_edges
            .iter()
            .map(|e| (e.consumer.clone(), e.provider.clone()))
            .collect();

        // Remap a raw dependency onto its emitted owner id (super-node collapse).
        let remap =
            |d: &ModuleRef| -> ModuleRef { rep.get(d).cloned().unwrap_or_else(|| d.clone()) };

        // ---- 3. build the emitted node set -----------------------------------------------------
        let mut out: BTreeMap<NodeId, NodeDecl> = BTreeMap::new();

        // (a) plain migration leaves (everything not collapsed into a super-node) + decoupling members.
        for leaf in &leaves {
            let m = &leaf.module_ref;
            // Skip members collapsed into a super-node — they are emitted as one node below.
            if rep.get(m) != Some(m) {
                continue;
            }
            let mut deps: BTreeSet<NodeId> = BTreeSet::new();
            for d in self.dep_graph.deps_of(m) {
                if reverse.contains(&(m.clone(), d.clone())) {
                    continue; // replaced by a shim (§3.4)
                }
                // A decoupling member may not depend directly on a cluster sibling — the prerequisite
                // is what serialises them (the cycle is broken).
                if let Some(cluster) = cluster_of.get(m) {
                    if cluster.contains(&d) {
                        continue;
                    }
                }
                let mapped = remap(&d);
                if &mapped != m {
                    deps.insert(mapped);
                }
            }
            if let Some(prereq) = decouple_of.get(m) {
                deps.insert(prereq.clone());
            }
            let mut decl = NodeDecl::new(m.clone(), NodeClass::MigrationRun)
                .with_working_set(working_set.get(m).copied().unwrap_or(0));
            for dep in deps {
                decl = decl.depends_on(dep);
            }
            for b in blast.get(m).into_iter().flatten() {
                decl = decl.with_blast(remap(b));
            }
            decl = self.apply_criticality(decl, std::slice::from_ref(m));
            out.insert(m.clone(), decl);
        }

        // (b) migration super-nodes (a fits-window SCC migrated together).
        for sn in &supernodes {
            let mut deps: BTreeSet<NodeId> = BTreeSet::new();
            let mut blast_out: BTreeSet<NodeId> = BTreeSet::new();
            for m in &sn.members {
                for d in self.dep_graph.deps_of(m) {
                    if reverse.contains(&(m.clone(), d.clone())) {
                        continue;
                    }
                    let mapped = remap(&d);
                    if mapped != sn.id {
                        deps.insert(mapped); // external dep only; intra-cluster edges vanish
                    }
                }
                for b in blast.get(m).into_iter().flatten() {
                    let mapped = remap(b);
                    if mapped != sn.id {
                        blast_out.insert(mapped);
                    }
                }
            }
            let mut decl = NodeDecl::new(sn.id.clone(), NodeClass::MigrationRun)
                .with_working_set(sn.working_set);
            for dep in deps {
                decl = decl.depends_on(dep);
            }
            for b in blast_out {
                decl = decl.with_blast(b);
            }
            let members: Vec<ModuleRef> = sn.members.iter().cloned().collect();
            decl = self.apply_criticality(decl, &members);
            out.insert(sn.id.clone(), decl);
        }

        // (c) decoupling-refactor prerequisites (a too-big SCC → human-checkpointed prereq).
        for dp in &decouple_prereqs {
            // The prerequisite inherits the cluster's external dependencies so it is only scheduled
            // once everything the cluster needs from *outside* is in place.
            let mut deps: BTreeSet<NodeId> = BTreeSet::new();
            for m in &dp.members {
                for d in self.dep_graph.deps_of(m) {
                    if dp.members.contains(&d) {
                        continue; // internal edge — the point of decoupling
                    }
                    if reverse.contains(&(m.clone(), d.clone())) {
                        continue;
                    }
                    let mapped = remap(&d);
                    deps.insert(mapped);
                }
            }
            let mut decl = NodeDecl::new(dp.id.clone(), NodeClass::DecouplingRefactor)
                .checkpoint(CheckpointClass::CriticalPath)
                .with_edit_floor(EditRung::Ast);
            for dep in deps {
                decl = decl.depends_on(dep);
            }
            out.insert(dp.id.clone(), decl);
        }

        // (d) strangler shims + shim-cleanup nodes (§3.4).
        for edge in &self.reverse_edges {
            let pair = plan_strangler_shim(edge.consumer.clone(), edge.provider.clone());
            let consumer_id = remap(&edge.consumer);
            let provider_id = remap(&edge.provider);

            // The shim itself: scheduled with the consumer, compiles against the OLD provider, so it
            // has no dependency on the provider's migration.
            out.entry(pair.shim.clone())
                .or_insert_with(|| NodeDecl::new(pair.shim.clone(), NodeClass::Shim));

            // The consumer now depends on the shim instead of the provider.
            if let Some(consumer_decl) = out.get_mut(&consumer_id) {
                *consumer_decl = consumer_decl.clone().depends_on(pair.shim.clone());
            }

            // The cleanup removes the shim only after BOTH the provider and the consumer have migrated.
            let mut cleanup = NodeDecl::new(pair.cleanup.clone(), NodeClass::ShimCleanup)
                .depends_on(provider_id.clone());
            if consumer_id != provider_id {
                cleanup = cleanup.depends_on(consumer_id.clone());
            }
            out.insert(pair.cleanup.clone(), cleanup);
        }

        Ok(out.into_values().collect())
    }

    /// Lift a node to the critical-path human gate + AST edit floor if any of `members` is tagged.
    fn apply_criticality(&self, decl: NodeDecl, members: &[ModuleRef]) -> NodeDecl {
        if members.iter().any(|m| self.critical_paths.contains(m)) {
            decl.checkpoint(CheckpointClass::CriticalPath)
                .with_edit_floor(EditRung::Ast)
        } else {
            decl
        }
    }
}

struct SuperNode {
    id: ModuleRef,
    members: BTreeSet<ModuleRef>,
    working_set: u64,
}

struct DecouplePrereq {
    id: ModuleRef,
    members: BTreeSet<ModuleRef>,
}

/// Why a blueprint could not be composed into a schedulable node set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComposeError {
    /// Window-sizing could not make an over-budget module fit (§3.2) — a human must decompose it.
    Split(SplitError),
}

impl fmt::Display for ComposeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ComposeError::Split(e) => write!(f, "window-sizing failed: {e}"),
        }
    }
}

impl std::error::Error for ComposeError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn mref(s: &str) -> ModuleRef {
        ModuleRef::new(s)
    }

    fn ids(decls: &[NodeDecl]) -> Vec<String> {
        decls.iter().map(|d| d.id.to_string()).collect()
    }

    fn find<'a>(decls: &'a [NodeDecl], id: &str) -> &'a NodeDecl {
        decls
            .iter()
            .find(|d| d.id.as_str() == id)
            .unwrap_or_else(|| panic!("no node {id}"))
    }

    #[test]
    fn window_sizing_expands_a_root_into_admissible_leaf_nodes() {
        // A 12k-token module (over a 5k ceiling) that splits into three sub-packages.
        let window = WindowBudget::new(10_000); // ceiling 5_000
        let root = MtgNode::new("big", 12_000)
            .with_child(MtgNode::new("big::a", 4_000))
            .with_child(MtgNode::new("big::b", 3_000))
            .with_child(MtgNode::new("big::c", 4_500));
        let bp = MigrationBlueprint::new(vec![root], DepGraph::new(), window);
        let decls = bp.compose().unwrap();
        assert_eq!(ids(&decls), vec!["big::a", "big::b", "big::c"]);
        // Every emitted node carries a working set within the window ceiling.
        for d in &decls {
            assert!(d.working_set_estimate <= window.ceiling());
            assert_eq!(d.node_class, NodeClass::MigrationRun);
        }
    }

    #[test]
    fn irreducible_module_is_an_honest_compose_error() {
        let window = WindowBudget::new(10_000); // ceiling 5_000
        let root = MtgNode::new("monolith", 6_000); // no split boundary
        let bp = MigrationBlueprint::new(vec![root], DepGraph::new(), window);
        let err = bp.compose().unwrap_err();
        assert!(matches!(err, ComposeError::Split(_)));
    }

    #[test]
    fn acyclic_deps_are_carried_onto_the_node_decls() {
        let window = WindowBudget::new(100_000);
        let roots = vec![
            MtgNode::new("a", 100),
            MtgNode::new("b", 100),
            MtgNode::new("c", 100),
        ];
        let mut g = DepGraph::new();
        g.add_edge("b", "a"); // b depends on a
        g.add_edge("c", "b"); // c depends on b
        let bp = MigrationBlueprint::new(roots, g, window);
        let decls = bp.compose().unwrap();
        assert_eq!(find(&decls, "a").deps.len(), 0);
        assert!(find(&decls, "b").deps.contains(&mref("a")));
        assert!(find(&decls, "c").deps.contains(&mref("b")));
    }

    #[test]
    fn small_cycle_collapses_to_one_migration_supernode() {
        let window = WindowBudget::new(10_000); // ceiling 5_000
                                                // a <-> b (mutual imports), combined 2_000 fits the window -> super-node.
        let roots = vec![MtgNode::new("a", 1_000), MtgNode::new("b", 1_000)];
        let mut g = DepGraph::new();
        g.add_edge("a", "b");
        g.add_edge("b", "a");
        let bp = MigrationBlueprint::new(roots, g, window);
        let decls = bp.compose().unwrap();
        // The two members are gone; one "a+b" super-node remains, with no self-dependency.
        assert_eq!(ids(&decls), vec!["a+b"]);
        let sn = find(&decls, "a+b");
        assert_eq!(sn.working_set_estimate, 2_000);
        assert!(sn.deps.is_empty());
    }

    #[test]
    fn oversized_cycle_becomes_a_human_checkpointed_decoupling_prerequisite() {
        let window = WindowBudget::new(10_000); // ceiling 5_000
                                                // a <-> b, combined 9_000 exceeds the window -> decoupling prereq + human checkpoint.
        let roots = vec![MtgNode::new("a", 4_500), MtgNode::new("b", 4_500)];
        let mut g = DepGraph::new();
        g.add_edge("a", "b");
        g.add_edge("b", "a");
        let bp = MigrationBlueprint::new(roots, g, window);
        let decls = bp.compose().unwrap();
        // Both members survive, plus a decouple:: prerequisite they each depend on.
        let prereq = find(&decls, "decouple::a+b");
        assert_eq!(prereq.node_class, NodeClass::DecouplingRefactor);
        assert_eq!(prereq.checkpoint_class, CheckpointClass::CriticalPath);
        // The intra-cluster edges are gone; each member now waits on the prerequisite instead.
        let a = find(&decls, "a");
        let b = find(&decls, "b");
        assert!(a.deps.contains(&mref("decouple::a+b")));
        assert!(b.deps.contains(&mref("decouple::a+b")));
        assert!(!a.deps.contains(&mref("b")));
        assert!(!b.deps.contains(&mref("a")));
    }

    #[test]
    fn reverse_order_edge_inserts_shim_and_cleanup_and_rewires_consumer() {
        let window = WindowBudget::new(100_000);
        let roots = vec![MtgNode::new("consumer", 100), MtgNode::new("provider", 100)];
        let mut g = DepGraph::new();
        g.add_edge("consumer", "provider"); // consumer depends on provider
        let bp =
            MigrationBlueprint::new(roots, g, window).with_reverse_edge("consumer", "provider");
        let decls = bp.compose().unwrap();

        let shim = mref("shim::consumer->provider");
        let cleanup = find(&decls, "shim-cleanup::consumer->provider");
        assert_eq!(cleanup.node_class, NodeClass::ShimCleanup);
        // The consumer no longer depends on the provider directly; it depends on the shim.
        let consumer = find(&decls, "consumer");
        assert!(consumer.deps.contains(&shim));
        assert!(!consumer.deps.contains(&mref("provider")));
        // Cleanup runs after both the provider and consumer migrate.
        assert!(cleanup.deps.contains(&mref("provider")));
        assert!(cleanup.deps.contains(&mref("consumer")));
    }

    #[test]
    fn critical_path_module_forces_a_human_gate_and_ast_floor() {
        let window = WindowBudget::new(100_000);
        let roots = vec![MtgNode::new("settlement", 100)];
        let bp = MigrationBlueprint::new(roots, DepGraph::new(), window)
            .with_critical_path("settlement");
        let decls = bp.compose().unwrap();
        let s = find(&decls, "settlement");
        assert_eq!(s.checkpoint_class, CheckpointClass::CriticalPath);
        assert_eq!(s.edit_ladder_floor, EditRung::Ast);
        assert!(s.edit_ladder_floor > EditRung::TextPatch); // TextPatch forbidden on the critical path
    }

    #[test]
    fn output_is_deterministic_and_sorted_by_id() {
        let window = WindowBudget::new(100_000);
        let roots = vec![
            MtgNode::new("z", 10),
            MtgNode::new("a", 10),
            MtgNode::new("m", 10),
        ];
        let bp = MigrationBlueprint::new(roots, DepGraph::new(), window);
        let first = ids(&bp.compose().unwrap());
        let second = ids(&bp.compose().unwrap());
        assert_eq!(first, second);
        assert_eq!(first, vec!["a", "m", "z"]);
    }
}
