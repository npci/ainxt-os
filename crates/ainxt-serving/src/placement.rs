// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GPU bin-packing placement + eviction/model-parking + demand-EWMA autoscale
//! (SERVING_OPS.md §3, gaps 26 + W; audit gap **SRV-04**).
//!
//! The fleet mixes GPU generations/memory sizes and a growing model catalog, each model×quant×TP
//! combination carrying a **footprint** (VRAM per replica) and a **locality** constraint (a TP/PP
//! group's ranks must sit on interconnect-adjacent GPUs, modeled here as "the whole footprint must
//! fit in ONE bin"). The audit found only comments; this module is the real policy core §3 requires:
//!
//! * **Best-fit-decreasing placement** ([`PlacementController::plan`]) — items sorted by footprint
//!   descending, each placed in the *tightest* bin that still fits, subject to (a) locality (single
//!   bin), (b) **attestation-tier match** — a regulated-eligible model may only land in a bin whose
//!   GPUs currently hold a regulated-eligible trust tier (ADR-021 §8.2); a regulated model with no
//!   eligible bin **fails closed** to [`Placement::unplaced`], never silently onto an untrusted bin.
//! * **N+1 standby reservation** ([`BinPool::with_standby_reserve`]) — one bin per pool is held out
//!   of placement so a `drain-the-group` event (§4) has somewhere to promote a replacement without an
//!   emergency cold-start.
//! * **Eviction + model-parking** ([`ParkingRegistry`]) — an evicted replica's weights are *parked*
//!   in a fast local tier (warm), not discarded, so re-warm is a minutes-scale local reload
//!   ([`ReWarmCost::WarmLocal`]) rather than an object-store cold pull ([`ReWarmCost::ColdPull`]) —
//!   the concrete fix for gap W's "cold-start latency". A P0 admission target excludes cold-only
//!   models by policy ([`ParkingRegistry::is_p0_admissible`]).
//! * **Demand-EWMA autoscale** ([`DemandTracker`]) — a per-model exponentially-weighted moving
//!   average of demand drives the target replica count (scale up before saturation, park down when
//!   idle), the elastic signal `LONG_HORIZON_PROGRAMS.md` §7 cites.
//!
//! Deterministic and pure: no GPU, no clock. Placement is a total function of (items, bins); the
//! EWMA takes samples explicitly. Best-fit-decreasing is a heuristic (§12 residual risk — it can
//! strand capacity); [`Placement::unplaced`] reports exactly what did not fit rather than hiding it.

use std::collections::BTreeMap;

use crate::attestation::TrustTier;

/// A GPU bin — one interconnect-adjacent group that a whole model replica must fit within.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bin {
    pub id: String,
    /// Total VRAM (arbitrary units, e.g. GiB) available for placement.
    pub vram_total: u64,
    /// VRAM already consumed by prior placements.
    pub vram_used: u64,
    /// The bin's current hardware trust tier (from the attestation gate, ADR-021 §8.2).
    pub tier: TrustTier,
    /// Fabric domain id — placement prefers pairing same-domain prefill/decode (§1/§3).
    pub fabric_domain: String,
}

impl Bin {
    pub fn new(
        id: impl Into<String>,
        vram_total: u64,
        tier: TrustTier,
        fabric_domain: impl Into<String>,
    ) -> Self {
        Bin {
            id: id.into(),
            vram_total,
            vram_used: 0,
            tier,
            fabric_domain: fabric_domain.into(),
        }
    }
    /// Free VRAM in this bin.
    pub fn free(&self) -> u64 {
        self.vram_total.saturating_sub(self.vram_used)
    }
}

/// A model replica to place — one model×quant×TP item (SERVING_OPS.md §3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelItem {
    pub model_id: String,
    /// VRAM footprint of one replica at its declared TP/PP degree.
    pub footprint: u64,
    /// Whether this model is regulated-eligible and so requires an attestation-eligible bin.
    pub requires_regulated_bin: bool,
}

impl ModelItem {
    pub fn new(model_id: impl Into<String>, footprint: u64, requires_regulated_bin: bool) -> Self {
        ModelItem {
            model_id: model_id.into(),
            footprint,
            requires_regulated_bin,
        }
    }
}

/// A single placement assignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assignment {
    pub model_id: String,
    pub bin_id: String,
}

/// Why an item could not be placed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnplacedReason {
    /// No bin had enough contiguous free VRAM (locality: one bin) — stranded capacity (§12).
    NoFittingBin,
    /// A regulated model had no attestation-eligible bin with room — **fails closed**, never placed
    /// on an untrusted bin (ADR-021 §8.2).
    NoAttestedCapacity,
}

/// An unplaced item and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unplaced {
    pub model_id: String,
    pub reason: UnplacedReason,
}

/// The result of a placement pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placement {
    pub assignments: Vec<Assignment>,
    pub unplaced: Vec<Unplaced>,
}

/// A pool of bins with an optional N+1 standby reservation (SERVING_OPS.md §3).
#[derive(Debug, Clone)]
pub struct BinPool {
    bins: Vec<Bin>,
    /// How many bins are held out of placement as N+1 standby headroom.
    standby_reserve: usize,
}

impl BinPool {
    pub fn new(bins: Vec<Bin>) -> Self {
        BinPool {
            bins,
            standby_reserve: 0,
        }
    }

    /// Reserve `n` bins as N+1 standby headroom — held out of placement so a drain (§4) can promote
    /// a replacement without an emergency cold-start.
    pub fn with_standby_reserve(mut self, n: usize) -> Self {
        self.standby_reserve = n;
        self
    }

    pub fn bins(&self) -> &[Bin] {
        &self.bins
    }

    /// Number of bins currently held in standby reserve.
    pub fn standby_reserve(&self) -> usize {
        self.standby_reserve
    }
}

/// The placement controller (SERVING_OPS.md §3).
#[derive(Debug, Clone)]
pub struct PlacementController;

impl PlacementController {
    /// Compute a placement for `items` over `pool` using **best-fit-decreasing**, honoring locality
    /// (single bin), attestation-tier match, and the N+1 standby reservation. Pure: it does not
    /// mutate the caller's pool; the returned `Placement` is the *target* a rate-limited reconciler
    /// (§3) would then apply one move at a time.
    pub fn plan(pool: &BinPool, items: &[ModelItem]) -> Placement {
        // Working copy of bin free-space; the standby reserve holds out the LAST `reserve` bins
        // (deterministic: bins are considered in declared order, reserve taken from the tail).
        let usable = pool.bins.len().saturating_sub(pool.standby_reserve);
        let mut free: BTreeMap<usize, u64> = pool
            .bins
            .iter()
            .take(usable)
            .enumerate()
            .map(|(i, b)| (i, b.free()))
            .collect();

        // Best-fit-DECREASING: largest footprints first (they are hardest to place late).
        let mut order: Vec<usize> = (0..items.len()).collect();
        order.sort_by(|&a, &b| {
            items[b]
                .footprint
                .cmp(&items[a].footprint)
                .then(items[a].model_id.cmp(&items[b].model_id))
        });

        let mut assignments = Vec::new();
        let mut unplaced = Vec::new();

        for &idx in &order {
            let item = &items[idx];
            // Candidate bins: enough free VRAM AND (if regulated) a regulated-eligible tier.
            let mut best: Option<(usize, u64)> = None; // (bin index, free after)
            let mut saw_regulated_eligible_bin = false;
            for (&bi, &bfree) in free.iter() {
                let bin = &pool.bins[bi];
                let tier_ok = !item.requires_regulated_bin || bin.tier.is_regulated_eligible();
                if item.requires_regulated_bin && bin.tier.is_regulated_eligible() {
                    saw_regulated_eligible_bin = true;
                }
                if !tier_ok || bfree < item.footprint {
                    continue;
                }
                let remaining = bfree - item.footprint;
                // Best-fit: the tightest bin (smallest remaining), ties by bin index for determinism.
                match best {
                    Some((_, br)) if br <= remaining => {}
                    _ => best = Some((bi, remaining)),
                }
            }

            match best {
                Some((bi, remaining)) => {
                    free.insert(bi, remaining);
                    assignments.push(Assignment {
                        model_id: item.model_id.clone(),
                        bin_id: pool.bins[bi].id.clone(),
                    });
                }
                None => {
                    let reason = if item.requires_regulated_bin && !saw_regulated_eligible_bin {
                        UnplacedReason::NoAttestedCapacity
                    } else {
                        UnplacedReason::NoFittingBin
                    };
                    unplaced.push(Unplaced {
                        model_id: item.model_id.clone(),
                        reason,
                    });
                }
            }
        }

        // Assignments in deterministic model-id order for a stable reconciler diff.
        assignments.sort_by(|a, b| a.model_id.cmp(&b.model_id).then(a.bin_id.cmp(&b.bin_id)));
        Placement {
            assignments,
            unplaced,
        }
    }
}

// ---------------------------------------------------------------------------
// Eviction / model-parking (SERVING_OPS.md §3, gap W)
// ---------------------------------------------------------------------------

/// Where an evicted model's weights currently live (SERVING_OPS.md §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParkTier {
    /// Resident in GPU VRAM — servable now, P0-admissible.
    Resident,
    /// Parked warm in a fast local tier (host RAM/NVMe) — re-warm is a minutes-scale local reload.
    Warm,
    /// Only in the origin object store — a cold pull, tens-of-minutes; never a P0 admission target.
    Cold,
}

/// The cost class of bringing a model back to servable (SERVING_OPS.md §3, gap W).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReWarmCost {
    /// Already resident — no reload.
    None,
    /// Warm parked local reload — minutes, not the object-store cold-pull time.
    WarmLocal,
    /// Object-store cold pull — the tens-of-minutes surprise §3/gap W exists to avoid on P0 paths.
    ColdPull,
}

/// Tracks each model's parking tier so re-warm cost and P0-admissibility are explicit, not a surprise.
#[derive(Debug, Clone, Default)]
pub struct ParkingRegistry {
    tiers: BTreeMap<String, ParkTier>,
}

impl ParkingRegistry {
    pub fn new() -> Self {
        ParkingRegistry::default()
    }

    /// Mark a model resident (placed in VRAM).
    pub fn set_resident(&mut self, model_id: &str) {
        self.tiers.insert(model_id.to_string(), ParkTier::Resident);
    }

    /// Evict + **park** a model warm (not discard) so re-warm stays a local reload (§3).
    pub fn park_warm(&mut self, model_id: &str) {
        self.tiers.insert(model_id.to_string(), ParkTier::Warm);
    }

    /// Drop a model past its parking retention window — now only in the object store (cold).
    pub fn evict_cold(&mut self, model_id: &str) {
        self.tiers.insert(model_id.to_string(), ParkTier::Cold);
    }

    pub fn tier_of(&self, model_id: &str) -> ParkTier {
        self.tiers.get(model_id).copied().unwrap_or(ParkTier::Cold)
    }

    /// The re-warm cost to make `model_id` servable from its current tier.
    pub fn rewarm_cost(&self, model_id: &str) -> ReWarmCost {
        match self.tier_of(model_id) {
            ParkTier::Resident => ReWarmCost::None,
            ParkTier::Warm => ReWarmCost::WarmLocal,
            ParkTier::Cold => ReWarmCost::ColdPull,
        }
    }

    /// Whether `model_id` may back a P0 admission target — a P0 request must never be routed to
    /// "wait several minutes for a cold reload" (§3), so only resident/warm models qualify.
    pub fn is_p0_admissible(&self, model_id: &str) -> bool {
        matches!(self.tier_of(model_id), ParkTier::Resident | ParkTier::Warm)
    }
}

// ---------------------------------------------------------------------------
// Demand-EWMA autoscale (SERVING_OPS.md §3)
// ---------------------------------------------------------------------------

/// Per-model demand EWMA driving the target replica count (SERVING_OPS.md §3 autoscale signal).
#[derive(Debug, Clone)]
pub struct DemandTracker {
    /// Smoothing factor in `(0,1]`; higher reacts faster.
    alpha: f64,
    ewma: BTreeMap<String, f64>,
}

impl DemandTracker {
    /// `alpha` is clamped into `(0,1]`.
    pub fn new(alpha: f64) -> Self {
        DemandTracker {
            alpha: alpha.clamp(f64::MIN_POSITIVE, 1.0),
            ewma: BTreeMap::new(),
        }
    }

    /// Feed one demand sample (e.g. requests/sec) for a model, updating its EWMA.
    pub fn observe(&mut self, model_id: &str, demand: f64) {
        let d = demand.max(0.0);
        let e = self.ewma.entry(model_id.to_string()).or_insert(d);
        *e = self.alpha * d + (1.0 - self.alpha) * *e;
    }

    /// The current smoothed demand for a model (0.0 if never observed).
    pub fn demand(&self, model_id: &str) -> f64 {
        self.ewma.get(model_id).copied().unwrap_or(0.0)
    }

    /// Target replica count: `ceil(demand / per_replica_capacity)`, never below `min_replicas`
    /// (so a P0-serving family keeps at least its floor). `per_replica_capacity` must be > 0.
    pub fn target_replicas(
        &self,
        model_id: &str,
        per_replica_capacity: f64,
        min_replicas: u32,
    ) -> u32 {
        if per_replica_capacity <= 0.0 {
            return min_replicas;
        }
        let need = (self.demand(model_id) / per_replica_capacity).ceil();
        let need = if need.is_finite() && need > 0.0 {
            need as u32
        } else {
            0
        };
        need.max(min_replicas)
    }
}

// ---------------------------------------------------------------------------
// Demand-autoscale decision loop (SERVING_OPS.md §3; serving-ops gap-7)
// ---------------------------------------------------------------------------
//
// The audit found bin-packing + parking + the demand EWMA each existed as primitives but nothing
// composed them into the autoscale LOOP §3 describes: observe live demand → recompute target replicas
// → scale a family out, or PARK a family warm (never cold-evict a still-warm model onto a P0 path)
// when its demand falls. This controller is that per-tick decision loop, pure and offline-testable;
// the physical replica provisioning it feeds is the [`PlacementBinder`] infra seam below.

/// Smoothed-demand floor (requests/sec) below which a family is treated as idle and eligible to be
/// parked warm — a decaying EWMA never reaches exactly zero, so an explicit threshold is the honest
/// idle test (SERVING_OPS.md §3).
const AUTOSCALE_IDLE_THRESHOLD: f64 = 1.0;

/// One autoscale decision for a model family on a tick (SERVING_OPS.md §3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScaleAction {
    /// The family's desired resident replica count changed to `replicas` (>= its P0 floor).
    ScaleTo { model_id: String, replicas: u32 },
    /// Demand fell to (near) zero: the family is **parked warm** — a minutes-scale local re-warm, NOT
    /// a cold object-store evict — so a demand rebound never lands a P0 on a cold pull (§3, gap W).
    ParkWarm { model_id: String },
}

/// The per-tick demand-autoscale controller (SERVING_OPS.md §3): composes the demand EWMA + the
/// target-replica formula + the parking registry into the loop the audit found missing.
#[derive(Debug, Clone)]
pub struct AutoscaleController {
    demand: DemandTracker,
    parking: ParkingRegistry,
    /// Serving capacity of one replica (same units as the demand samples).
    per_replica_capacity: f64,
    /// The P0 floor: a family never scales below this many replicas (keeps interactive traffic warm).
    min_replicas: u32,
}

impl AutoscaleController {
    pub fn new(alpha: f64, per_replica_capacity: f64, min_replicas: u32) -> Self {
        AutoscaleController {
            demand: DemandTracker::new(alpha),
            parking: ParkingRegistry::new(),
            per_replica_capacity,
            min_replicas,
        }
    }

    /// Read-only view of the parking tier a family currently sits in.
    pub fn parking(&self) -> &ParkingRegistry {
        &self.parking
    }

    /// Smoothed demand for a family (0.0 if never observed).
    pub fn demand(&self, model_id: &str) -> f64 {
        self.demand.demand(model_id)
    }

    /// **One autoscale tick** (SERVING_OPS.md §3, gap-7): fold this window's `samples` into each
    /// family's demand EWMA, then decide — a family whose smoothed demand rounds to **zero** replicas
    /// (below the P0 floor's need AND effectively idle) is [`ScaleAction::ParkWarm`]'d (never
    /// cold-evicted); every other family is [`ScaleAction::ScaleTo`] its `target_replicas`, marked
    /// resident. Deterministic model-id order. The caller feeds each `ScaleTo` into the placement
    /// reconciler (the physical GPU binding, infra); the DECISION loop is closed here.
    pub fn tick(&mut self, samples: &[(String, f64)]) -> Vec<ScaleAction> {
        for (model, demand) in samples {
            self.demand.observe(model, *demand);
        }
        // Decide for every family we have ever seen (deterministic order), not only this window's
        // samples — a family that dropped to zero demand this window still needs a park decision.
        let mut families: BTreeMap<String, ()> = BTreeMap::new();
        for (m, _) in samples {
            families.insert(m.clone(), ());
        }
        for m in self.parking.tiers.keys() {
            families.insert(m.clone(), ());
        }

        let mut actions = Vec::new();
        for model in families.keys() {
            let d = self.demand.demand(model);
            // "Idle" = effectively no live traffic (sub-1-rps smoothed). A decaying EWMA never reaches
            // exactly 0.0, so a threshold — not `ceil() == 0` — is what distinguishes an idle family
            // (park it) from a lightly-loaded one (keep a replica) honestly.
            let idle = d < AUTOSCALE_IDLE_THRESHOLD;
            if idle && self.min_replicas == 0 {
                // Idle family with no P0 floor → park warm (retain fast re-warm), don't cold-evict.
                self.parking.park_warm(model);
                actions.push(ScaleAction::ParkWarm {
                    model_id: model.clone(),
                });
            } else {
                let need = if self.per_replica_capacity > 0.0 {
                    (d / self.per_replica_capacity).ceil()
                } else {
                    0.0
                };
                let raw = if need.is_finite() && need > 0.0 {
                    need as u32
                } else {
                    0
                };
                let target = raw.max(self.min_replicas);
                self.parking.set_resident(model);
                actions.push(ScaleAction::ScaleTo {
                    model_id: model.clone(),
                    replicas: target,
                });
            }
        }
        actions
    }
}

// ---------------------------------------------------------------------------
// Physical GPU-binding seam + incremental reconciler (SERVING_OPS.md §3, INFRA-GATED)
// ---------------------------------------------------------------------------
//
// [`PlacementController::plan`] above is the pure, exhaustively-tested target algorithm. *Applying*
// that target — allocating VRAM on a bin's GPUs and streaming/warming a replica's weights onto them
// — is the physical GPU binding, which needs a live fleet. That physical action is isolated behind
// the [`PlacementBinder`] seam so the reconciliation LOGIC (diff desired-vs-bound, apply moves one
// at a time under a rate budget, never overflow a bin) stays pure and deterministically testable
// offline via [`InMemoryPlacementBinder`]. The live binder (CUDA/driver allocation) is the only part
// deferred to real infra.

/// Why the physical binding of one replica onto a bin failed (SERVING_OPS.md §3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindError {
    /// The bin has no free VRAM for this footprint (the plan raced a concurrent allocation).
    InsufficientVram { free: u64, needed: u64 },
    /// The target bin id is not known to the binder.
    UnknownBin,
}

/// The outcome of physically binding one replica onto a bin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindOutcome {
    /// Newly materialized resident on the target bin.
    Bound,
    /// Already resident on exactly this bin — an idempotent no-op (safe re-drive).
    AlreadyBound,
    /// Moved from another bin (old freed, new allocated).
    Rebound { from_bin: String },
    /// The bind could not be performed.
    Failed(BindError),
}

/// The physical GPU-binding seam (SERVING_OPS.md §3, INFRA-GATED). Real implementations allocate
/// VRAM on the bin's GPUs and stream/warm the replica's weights onto them; this pure crate only
/// sequences the moves. [`InMemoryPlacementBinder`] is the deterministic offline reference.
pub trait PlacementBinder {
    /// Bind `model_id` (of `footprint` VRAM) onto `bin_id`, materializing it resident.
    fn bind(&mut self, model_id: &str, bin_id: &str, footprint: u64) -> BindOutcome;
    /// Unbind `model_id`, freeing its VRAM. Returns whether it had been bound.
    fn unbind(&mut self, model_id: &str) -> bool;
    /// The bin `model_id` is currently bound to, if any.
    fn bound_bin(&self, model_id: &str) -> Option<String>;
    /// Every model currently bound, in deterministic id order (the reconciler's current-state view).
    fn bound_set(&self) -> Vec<String>;
}

/// A deterministic in-memory [`PlacementBinder`]: tracks per-bin VRAM occupancy and the current
/// model→bin map, with a genuine (non-tautological) free-VRAM check on every bind.
#[derive(Debug, Clone, Default)]
pub struct InMemoryPlacementBinder {
    total: BTreeMap<String, u64>,
    used: BTreeMap<String, u64>,
    bound: BTreeMap<String, (String, u64)>,
}

impl InMemoryPlacementBinder {
    /// Build a binder over `bins` (their total VRAM defines the hard allocation ceiling).
    pub fn from_bins(bins: &[Bin]) -> Self {
        let mut total = BTreeMap::new();
        let mut used = BTreeMap::new();
        for b in bins {
            total.insert(b.id.clone(), b.vram_total);
            used.insert(b.id.clone(), b.vram_used);
        }
        InMemoryPlacementBinder {
            total,
            used,
            bound: BTreeMap::new(),
        }
    }

    /// Currently-bound models in deterministic id order.
    pub fn bound_models(&self) -> Vec<String> {
        self.bound.keys().cloned().collect()
    }

    /// VRAM used on `bin_id` (0 if unknown).
    pub fn used_vram(&self, bin_id: &str) -> u64 {
        self.used.get(bin_id).copied().unwrap_or(0)
    }

    fn free_vram(&self, bin_id: &str) -> Option<u64> {
        let total = *self.total.get(bin_id)?;
        Some(total.saturating_sub(self.used.get(bin_id).copied().unwrap_or(0)))
    }
}

impl PlacementBinder for InMemoryPlacementBinder {
    fn bind(&mut self, model_id: &str, bin_id: &str, footprint: u64) -> BindOutcome {
        // Unknown target bin.
        let Some(free) = self.free_vram(bin_id) else {
            return BindOutcome::Failed(BindError::UnknownBin);
        };
        // Already resident on this exact bin → idempotent no-op.
        if let Some((cur_bin, _)) = self.bound.get(model_id) {
            if cur_bin == bin_id {
                return BindOutcome::AlreadyBound;
            }
        }
        // A move must fit AFTER accounting for the old allocation being freed.
        let from = self.bound.get(model_id).cloned();
        let effective_free = match &from {
            Some((cur_bin, cur_fp)) if cur_bin == bin_id => free + cur_fp, // unreachable (handled above)
            _ => free,
        };
        if effective_free < footprint {
            return BindOutcome::Failed(BindError::InsufficientVram {
                free: effective_free,
                needed: footprint,
            });
        }
        // Free the old allocation (for a move) then allocate on the target.
        if let Some((cur_bin, cur_fp)) = &from {
            let u = self.used.entry(cur_bin.clone()).or_insert(0);
            *u = u.saturating_sub(*cur_fp);
        }
        *self.used.entry(bin_id.to_string()).or_insert(0) += footprint;
        self.bound
            .insert(model_id.to_string(), (bin_id.to_string(), footprint));
        match from {
            Some((cur_bin, _)) => BindOutcome::Rebound { from_bin: cur_bin },
            None => BindOutcome::Bound,
        }
    }

    fn unbind(&mut self, model_id: &str) -> bool {
        match self.bound.remove(model_id) {
            Some((bin, fp)) => {
                let u = self.used.entry(bin).or_insert(0);
                *u = u.saturating_sub(fp);
                true
            }
            None => false,
        }
    }

    fn bound_bin(&self, model_id: &str) -> Option<String> {
        self.bound.get(model_id).map(|(b, _)| b.clone())
    }

    fn bound_set(&self) -> Vec<String> {
        self.bound.keys().cloned().collect()
    }
}

/// One action taken by the reconciler this step (SERVING_OPS.md §3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconcileAction {
    /// Newly bound `model` onto `bin`.
    Bound { model: String, bin: String },
    /// Moved `model` to `bin` (freed its old bin first).
    Rebound { model: String, bin: String },
    /// Unbound `model` (it is no longer in the desired plan).
    Unbound { model: String },
    /// A bind was attempted and physically failed (reported, never hidden).
    Failed { model: String, err: BindError },
}

/// Drives the physical fleet toward a computed [`Placement`] one rate-limited step at a time
/// (SERVING_OPS.md §3). Pure sequencing logic over the [`PlacementBinder`] seam.
#[derive(Debug, Clone)]
pub struct PlacementReconciler;

impl PlacementReconciler {
    /// Apply at most `max_moves` moves toward `plan`, through `binder`. Unbinds models no longer in
    /// the plan first (freeing VRAM so later binds fit), then binds/moves the rest, all in
    /// deterministic model-id order. `items` supplies each model's footprint. Returns the actions
    /// taken this step; call repeatedly until it returns empty (fully converged).
    pub fn reconcile_step(
        binder: &mut dyn PlacementBinder,
        plan: &Placement,
        items: &[ModelItem],
        max_moves: usize,
    ) -> Vec<ReconcileAction> {
        let footprint: BTreeMap<&str, u64> = items
            .iter()
            .map(|i| (i.model_id.as_str(), i.footprint))
            .collect();
        let target: BTreeMap<&str, &str> = plan
            .assignments
            .iter()
            .map(|a| (a.model_id.as_str(), a.bin_id.as_str()))
            .collect();

        let mut actions = Vec::new();

        // 1. Unbind models bound now but absent from the target (frees VRAM first).
        for model in binder.bound_set() {
            if actions.len() >= max_moves {
                return actions;
            }
            if !target.contains_key(model.as_str()) && binder.unbind(&model) {
                actions.push(ReconcileAction::Unbound { model });
            }
        }

        // 2. Bind/move models whose current bin differs from the target (deterministic order).
        for (&model, &bin) in target.iter() {
            if actions.len() >= max_moves {
                return actions;
            }
            if binder.bound_bin(model).as_deref() == Some(bin) {
                continue; // already where it belongs
            }
            let fp = footprint.get(model).copied().unwrap_or(0);
            match binder.bind(model, bin, fp) {
                BindOutcome::Bound => actions.push(ReconcileAction::Bound {
                    model: model.to_string(),
                    bin: bin.to_string(),
                }),
                BindOutcome::Rebound { .. } => actions.push(ReconcileAction::Rebound {
                    model: model.to_string(),
                    bin: bin.to_string(),
                }),
                BindOutcome::AlreadyBound => {}
                BindOutcome::Failed(err) => actions.push(ReconcileAction::Failed {
                    model: model.to_string(),
                    err,
                }),
            }
        }
        actions
    }
}

// ---------------------------------------------------------------------------
// The periodic autoscale-decision DRIVER (SERVING_OPS.md §3, gaps 26/W; serving-ops gap-7, round-15)
// ---------------------------------------------------------------------------
//
// [`AutoscaleController::tick`] (round-11) is the pure per-window decision body: fold demand samples
// into the EWMA, decide scale-to/park-warm per family. The audit found this had no cadence concept —
// every call was assumed due — so "wired into ANY daemon loop" had no honest throttle independent of
// however often the daemon's own timer happened to fire. [`AutoscaleCadence`] closes that the same way
// [`crate::attestation::AttestationRefresher`] and [`crate::health::HealthCadence`] close the
// analogous gaps: it owns the cadence + a next-due cursor, so the daemon's async timer has exactly ONE
// call — [`AutoscaleCadence::tick`] — and the demand-driven recompute only actually runs when due.
// [`PlacementReconciler::reconcile_step`] (the physical-binding half) is already self-throttling via
// its own `max_moves` rate limit and is meant to be called every daemon tick regardless — it needs no
// separate cadence gate.

/// Cadence tuning for [`AutoscaleCadence`] (SERVING_OPS.md §3). A logical-tick duration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AutoscaleCadenceConfig {
    /// Logical ticks between autoscale recomputes. A tick before the next due point is a no-op
    /// ([`AutoscaleCadence::tick`] returns `None`).
    pub interval: u64,
}

impl Default for AutoscaleCadenceConfig {
    fn default() -> Self {
        // Conservative default: recompute demand-driven targets every 30 ticks.
        AutoscaleCadenceConfig { interval: 30 }
    }
}

impl AutoscaleCadenceConfig {
    /// The effective (never-zero) cadence — a `0` interval degrades to "every tick", never a busy-loop.
    fn effective_interval(self) -> u64 {
        self.interval.max(1)
    }
}

/// A stateful, periodic driver for [`AutoscaleController::tick`] (SERVING_OPS.md §3, gaps 26/W;
/// serving-ops gap-7, round-15).
///
/// Holds its own cadence + next-due cursor, mirroring [`crate::attestation::AttestationRefresher`] /
/// [`crate::health::HealthCadence`]'s pattern. On a due [`AutoscaleCadence::tick`] it runs one
/// [`AutoscaleController::tick`] pass over the supplied demand `samples` (folding them into each
/// family's EWMA and deciding scale-to vs. park-warm) and advances the cadence; a tick before the next
/// due point does nothing and returns `None`.
///
/// The async timer + the live demand-sample collection are the daemon's needs_hot_wiring/infra
/// concern; the due-or-not decision gating the decision loop is proven here, offline.
#[derive(Debug, Clone)]
pub struct AutoscaleCadence {
    cfg: AutoscaleCadenceConfig,
    next_due_at: u64,
    ticks: u64,
}

impl AutoscaleCadence {
    /// Build a driver at this cadence. The first [`Self::tick`] at any `now` is due.
    pub fn new(cfg: AutoscaleCadenceConfig) -> Self {
        AutoscaleCadence {
            cfg,
            next_due_at: 0,
            ticks: 0,
        }
    }

    /// The cadence tuning.
    pub fn config(&self) -> AutoscaleCadenceConfig {
        self.cfg
    }

    /// Whether a recompute is due at `now`.
    pub fn is_due(&self, now: u64) -> bool {
        now >= self.next_due_at
    }

    /// How many recomputes have actually run (a `None`-returning tick does not count).
    pub fn ticks_run(&self) -> u64 {
        self.ticks
    }

    /// One driver tick at logical time `now`. Returns `None` when a recompute is not yet due; on a due
    /// tick it runs [`AutoscaleController::tick`] over `samples`, advances the cadence to
    /// `now + interval`, and returns the [`ScaleAction`]s.
    pub fn tick(
        &mut self,
        controller: &mut AutoscaleController,
        now: u64,
        samples: &[(String, f64)],
    ) -> Option<Vec<ScaleAction>> {
        if !self.is_due(now) {
            return None;
        }
        let actions = controller.tick(samples);
        self.next_due_at = now.saturating_add(self.cfg.effective_interval());
        self.ticks = self.ticks.saturating_add(1);
        Some(actions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cc(id: &str, vram: u64, dom: &str) -> Bin {
        Bin::new(id, vram, TrustTier::CcEnclave, dom)
    }
    fn untrusted(id: &str, vram: u64, dom: &str) -> Bin {
        Bin::new(id, vram, TrustTier::Untrusted, dom)
    }

    #[test]
    fn gap_ainxt_serving_srv_04_best_fit_decreasing_places_largest_first_in_tightest_bin() {
        // Two bins: small(10) and large(100). Items 8 and 90.
        let pool = BinPool::new(vec![cc("small", 10, "d0"), cc("large", 100, "d0")]);
        let items = vec![
            ModelItem::new("m8", 8, false),
            ModelItem::new("m90", 90, false),
        ];
        let plan = PlacementController::plan(&pool, &items);
        assert!(plan.unplaced.is_empty());
        // Best-fit: the 8-footprint model takes the tight small bin, 90 takes large.
        assert!(plan.assignments.contains(&Assignment {
            model_id: "m8".into(),
            bin_id: "small".into()
        }));
        assert!(plan.assignments.contains(&Assignment {
            model_id: "m90".into(),
            bin_id: "large".into()
        }));
    }

    #[test]
    fn gap_ainxt_serving_srv_04_regulated_model_never_lands_on_untrusted_bin_fails_closed() {
        // Only an untrusted bin has room; a regulated model must NOT be placed on it.
        let pool = BinPool::new(vec![untrusted("burst", 100, "d0")]);
        let items = vec![ModelItem::new("reg", 10, true)];
        let plan = PlacementController::plan(&pool, &items);
        assert!(plan.assignments.is_empty());
        assert_eq!(
            plan.unplaced,
            vec![Unplaced {
                model_id: "reg".into(),
                reason: UnplacedReason::NoAttestedCapacity
            }]
        );
    }

    #[test]
    fn gap_ainxt_serving_srv_04_regulated_model_lands_on_attested_bin_when_available() {
        let pool = BinPool::new(vec![untrusted("burst", 100, "d0"), cc("secure", 50, "d0")]);
        let items = vec![ModelItem::new("reg", 40, true)];
        let plan = PlacementController::plan(&pool, &items);
        assert_eq!(
            plan.assignments,
            vec![Assignment {
                model_id: "reg".into(),
                bin_id: "secure".into()
            }]
        );
    }

    #[test]
    fn gap_ainxt_serving_srv_04_n_plus_one_standby_is_held_out_of_placement() {
        // Two identical bins, one reserved as N+1 standby → only one is usable for placement.
        let pool =
            BinPool::new(vec![cc("b0", 100, "d0"), cc("b1", 100, "d0")]).with_standby_reserve(1);
        assert_eq!(pool.standby_reserve(), 1);
        // Two 80-footprint items cannot both fit in the single usable bin → one is unplaced.
        let items = vec![
            ModelItem::new("a", 80, false),
            ModelItem::new("b", 80, false),
        ];
        let plan = PlacementController::plan(&pool, &items);
        assert_eq!(plan.assignments.len(), 1);
        assert_eq!(
            plan.unplaced.len(),
            1,
            "the standby bin is not used for placement"
        );
        assert_eq!(plan.unplaced[0].reason, UnplacedReason::NoFittingBin);
    }

    #[test]
    fn oversized_item_is_reported_unplaced_not_silently_dropped() {
        let pool = BinPool::new(vec![cc("b0", 10, "d0")]);
        let plan = PlacementController::plan(&pool, &[ModelItem::new("big", 999, false)]);
        assert_eq!(
            plan.unplaced,
            vec![Unplaced {
                model_id: "big".into(),
                reason: UnplacedReason::NoFittingBin
            }]
        );
    }

    #[test]
    fn gap_ainxt_serving_srv_04_parking_makes_rewarm_warm_not_cold() {
        let mut reg = ParkingRegistry::new();
        reg.set_resident("hot");
        assert_eq!(reg.rewarm_cost("hot"), ReWarmCost::None);
        assert!(reg.is_p0_admissible("hot"));

        // Evict a low-demand model — parked WARM, so re-warm is a minutes-scale local reload.
        reg.park_warm("hot");
        assert_eq!(reg.rewarm_cost("hot"), ReWarmCost::WarmLocal);
        assert!(
            reg.is_p0_admissible("hot"),
            "warm is still fast enough for P0"
        );

        // Past the retention window → cold; now a P0 must never be routed here.
        reg.evict_cold("hot");
        assert_eq!(reg.rewarm_cost("hot"), ReWarmCost::ColdPull);
        assert!(!reg.is_p0_admissible("hot"));
        // An unknown model defaults to cold (conservative — never assume it's warm).
        assert_eq!(reg.rewarm_cost("unknown"), ReWarmCost::ColdPull);
    }

    #[test]
    fn gap_ainxt_serving_srv_04_demand_ewma_drives_target_replicas() {
        let mut d = DemandTracker::new(0.5);
        // No demand → the P0 floor still holds a minimum.
        assert_eq!(d.target_replicas("m", 100.0, 1), 1);
        // Sustained demand of ~400 rps at 100 rps/replica → 4 replicas.
        for _ in 0..20 {
            d.observe("m", 400.0);
        }
        assert!((d.demand("m") - 400.0).abs() < 1.0);
        assert_eq!(d.target_replicas("m", 100.0, 1), 4);
        // A demand spike scales up beyond the floor.
        for _ in 0..20 {
            d.observe("m", 950.0);
        }
        assert_eq!(d.target_replicas("m", 100.0, 1), 10);
    }
}
