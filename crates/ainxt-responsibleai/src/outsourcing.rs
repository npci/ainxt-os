// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! RBI IT/cloud-outsourcing governance register (FI-03; `REGULATED_FI_COMPLIANCE_OPS.md` §3;
//! ADR-017, extends ADR-012).
//!
//! RBI's Master Direction on Outsourcing of IT Services treats **every call that ships context to an
//! external provider as IT outsourcing** — every cloud LLM route, every external connector, every
//! remote MCP server. A spreadsheet register is inert. Here the register **is the model router's
//! eligibility input**: [`OutsourcingRegister::eligibility`] is the non-overridable check the router
//! runs *before ranking and before failover*. A route with **no register entry**, or whose
//! `permitted_data_class` is below the request's class, or whose `data_residency` violates the
//! request's residency label, or whose exit plan is untested, is **excluded** — so no ungoverned
//! outsourcing can ever occur, and it cannot be a "policy violation caught later": it *cannot route*.
//!
//! Every arrangement is a control-plane definition (Q2/ADR-026 — a git file, CODEOWNERS = outsourcing
//! governance + board-delegate). Here it is a pure, serde value. Sub-processors are pinned by hash
//! (TOFU + diff-and-re-approve, §3.3); a silent sub-processor change fails the pin and auto-restricts
//! the arrangement (fail-safe). The register is queryable for concentration risk (§3.5) and exit
//! rehearsal freshness (§3.4). No clock/rng/I/O — logical time is injected.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use ainxt_types::DataClass;

/// The canonical register route-id prefix for a cloud/external provider route (§3.1).
pub const OUTSOURCING_ROUTE_PREFIX: &str = "outsourcing.cloud.";

/// Derive the canonical outsourcing-register route id for a provider id — `outsourcing.cloud.<id>`.
///
/// The FI-03 register only gates a provider that *self-declares* it is an external route (its
/// `outsourcing_route()` returns `Some`). Relying on hand-set self-declaration is fail-OPEN: a genuinely
/// external cloud provider whose adapter forgot to declare a route id is treated as in-house and escapes
/// the register entirely. This deterministic derivation lets the served assembly mark **every** cloud-kind
/// provider external *by construction* — `derive_route_id(provider_id)` — instead of trusting each
/// adapter to remember. Combined with the register's fail-closed default (an unregistered route ⇒
/// [`Eligibility::NoRegisterEntry`] ⇒ excluded), a cloud provider then cannot route until a
/// board-approved arrangement exists under exactly this derived id. (The provider-marking call-site is
/// in the RESERVED served assembly — `needs_hot_wiring`; this is the id both sides agree on.)
pub fn derive_route_id(provider_id: &str) -> String {
    format!("{OUTSOURCING_ROUTE_PREFIX}{provider_id}")
}

/// A declared sub-processor in a provider's chain (RBI chain-outsourcing control, §3.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubProcessor {
    pub name: String,
    pub jurisdiction: String,
}

/// When a route's exit plan was last rehearsed (§3.4). `Never` (or a stale date) ⇒ treated as no exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum ExitRehearsal {
    Never,
    At { tick: u64 },
}

impl ExitRehearsal {
    /// `true` if a rehearsal exists and is no older than `cadence` ticks at `now`.
    pub fn is_fresh(&self, now: u64, cadence: u64) -> bool {
        match self {
            ExitRehearsal::Never => false,
            ExitRehearsal::At { tick } => now.saturating_sub(*tick) <= cadence,
        }
    }
}

/// One outsourcing arrangement — the control-plane definition for a single external route (§3.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutsourcingArrangement {
    /// `outsourcing.cloud.<provider>.<route>` — matches the router's candidate-route id.
    pub id: String,
    pub provider_legal_entity: String,
    pub contract_ref: String,
    pub board_approval_ref: String,
    /// The MAX data class this route may ever carry → the router eligibility ceiling (ADR-012).
    pub permitted_data_class: DataClass,
    /// The route's resolved data-residency region (lowercased on set) — RBI localisation.
    pub data_residency: String,
    /// The declared sub-processor chain, pinned by [`pinned_list_hash`](Self::pinned_list_hash).
    pub sub_processors: Vec<SubProcessor>,
    /// The TOFU pin: SHA-256 over the canonical sub-processor list at last approval. A newly-published
    /// list whose hash differs must be re-approved (§3.3).
    pub pinned_list_hash: String,
    pub right_to_audit_clause: String,
    pub exit_plan_ref: String,
    /// For §3.5 concentration analysis (e.g. "chat-inference", "embeddings").
    pub concentration_tag: String,
    pub last_exit_rehearsal: ExitRehearsal,
}

impl OutsourcingArrangement {
    /// Build an arrangement, computing the sub-processor pin from the supplied list (TOFU: the first
    /// observed list is the trusted baseline).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: &str,
        provider_legal_entity: &str,
        permitted_data_class: DataClass,
        data_residency: &str,
        sub_processors: Vec<SubProcessor>,
        exit_plan_ref: &str,
        concentration_tag: &str,
        last_exit_rehearsal: ExitRehearsal,
    ) -> Self {
        let pinned_list_hash = Self::hash_sub_processors(&sub_processors);
        Self {
            id: id.to_string(),
            provider_legal_entity: provider_legal_entity.to_string(),
            contract_ref: String::new(),
            board_approval_ref: String::new(),
            permitted_data_class,
            data_residency: data_residency.to_ascii_lowercase(),
            sub_processors,
            pinned_list_hash,
            right_to_audit_clause: String::new(),
            exit_plan_ref: exit_plan_ref.to_string(),
            concentration_tag: concentration_tag.to_string(),
            last_exit_rehearsal,
        }
    }

    /// Canonical SHA-256 over the sub-processor list (order-sensitive, length-prefixed fields).
    pub fn hash_sub_processors(subs: &[SubProcessor]) -> String {
        let mut h = Sha256::new();
        h.update((subs.len() as u64).to_le_bytes());
        for s in subs {
            for field in [s.name.as_str(), s.jurisdiction.as_str()] {
                h.update((field.len() as u64).to_le_bytes());
                h.update(field.as_bytes());
            }
        }
        h.finalize().iter().map(|b| format!("{b:02x}")).collect::<String>()
    }

    /// `true` if `published` (a freshly-observed sub-processor list) matches the pinned baseline.
    /// A `false` here is the §3.3 signal that the provider silently changed its chain.
    pub fn sub_processors_match(&self, published: &[SubProcessor]) -> bool {
        Self::hash_sub_processors(published) == self.pinned_list_hash
    }

    /// Adopt a re-approved sub-processor list (the register PR landed) — re-pins the hash.
    pub fn reapprove_sub_processors(&mut self, published: Vec<SubProcessor>) {
        self.pinned_list_hash = Self::hash_sub_processors(&published);
        self.sub_processors = published;
    }
}

/// Why a route is or is not eligible for a request (§3.2). The router excludes any non-`Eligible`
/// route before ranking and before failover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Eligibility {
    Eligible,
    /// No register entry exists — the provider is invisible to the router (no ungoverned outsourcing).
    NoRegisterEntry,
    /// The route's permitted ceiling is below the request's data class.
    DataClassAboveCeiling {
        request: DataClass,
        permitted: DataClass,
    },
    /// The route's residency violates the request's residency label (localisation).
    ResidencyMismatch {
        request: String,
        route: String,
    },
    /// The exit plan is untested (never/stale) → fail-safe exclusion for a regulated-class request.
    ExitUntested,
    /// A pending sub-processor change auto-restricted this route below the request's class.
    SubProcessorDrift,
}

impl Eligibility {
    pub fn is_eligible(&self) -> bool {
        matches!(self, Eligibility::Eligible)
    }
}

/// One candidate route's reason-coded eligibility decision for a request (§3.2) — the auditable form
/// of the router's non-overridable eligibility input. Retained so an *exclusion* carries its reason
/// into the governance evidence trail rather than vanishing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EligibilityDecision {
    pub route_id: String,
    pub eligibility: Eligibility,
}

impl EligibilityDecision {
    /// Whether this route was admitted.
    pub fn is_eligible(&self) -> bool {
        self.eligibility.is_eligible()
    }
}

/// The runtime state of an arrangement in the register: the definition plus any auto-restriction the
/// register applied (a sub-processor drift lowers the effective ceiling until re-approved).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisteredRoute {
    pub arrangement: OutsourcingArrangement,
    /// When a sub-processor drift is detected, the arrangement is auto-restricted (fail-safe): its
    /// *effective* ceiling drops to `Public` until a re-approving PR re-pins the list (§3.3).
    pub restricted: bool,
}

/// A §3.5 concentration-risk escalation: a single `concentration_tag` whose share of dependent traffic
/// breached the board-set `threshold`. The board-delegate (CODEOWNERS = outsourcing governance) acts on
/// it — diversify the arrangement, seek board re-approval, or accept-with-mitigation. The runtime crate
/// stays decoupled from the incident register by returning this typed fact (the same pattern as
/// [`crate::BreakerTrip`]); the parent maps it onto its escalation channel.
#[derive(Debug, Clone, PartialEq)]
pub struct ConcentrationFinding {
    /// The over-relied dependency category (e.g. "chat-inference").
    pub tag: String,
    /// The measured fraction of traffic depending on `tag` (0.0–1.0).
    pub fraction: f64,
    /// The board-set threshold that was breached (`fraction > threshold`).
    pub threshold: f64,
}

/// The RBI outsourcing register (§3). Maps route id → registered route. The router consults
/// [`eligibility`](OutsourcingRegister::eligibility) for every external candidate.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OutsourcingRegister {
    routes: BTreeMap<String, RegisteredRoute>,
    /// The exit-rehearsal cadence (ticks): a rehearsal older than this is stale ⇒ exit untested.
    exit_cadence: u64,
}

impl OutsourcingRegister {
    /// A register with the given exit-rehearsal cadence.
    pub fn new(exit_cadence: u64) -> Self {
        Self {
            routes: BTreeMap::new(),
            exit_cadence,
        }
    }

    /// Register (or replace) an arrangement.
    pub fn upsert(&mut self, arrangement: OutsourcingArrangement) -> &mut Self {
        self.routes.insert(
            arrangement.id.clone(),
            RegisteredRoute {
                arrangement,
                restricted: false,
            },
        );
        self
    }

    pub fn get(&self, route_id: &str) -> Option<&RegisteredRoute> {
        self.routes.get(route_id)
    }

    /// FI-03 core: the router eligibility check. A route is eligible for a request of `request_class`
    /// with residency label `request_residency` (lowercased) at logical time `now` **only if** it is
    /// registered, not auto-restricted below the class, its ceiling covers the class, its residency
    /// matches, and — for a regulated request — its exit plan is tested. Anything else is exclusion.
    pub fn eligibility(
        &self,
        route_id: &str,
        request_class: DataClass,
        request_residency: &str,
        now: u64,
    ) -> Eligibility {
        let Some(route) = self.routes.get(route_id) else {
            return Eligibility::NoRegisterEntry;
        };
        let a = &route.arrangement;

        // Auto-restriction (sub-processor drift) collapses the effective ceiling to Public.
        let effective_ceiling = if route.restricted {
            DataClass::Public
        } else {
            a.permitted_data_class
        };

        if request_class.sensitivity() > effective_ceiling.sensitivity() {
            if route.restricted {
                return Eligibility::SubProcessorDrift;
            }
            return Eligibility::DataClassAboveCeiling {
                request: request_class,
                permitted: a.permitted_data_class,
            };
        }

        if a.data_residency != request_residency.to_ascii_lowercase() {
            return Eligibility::ResidencyMismatch {
                request: request_residency.to_string(),
                route: a.data_residency.clone(),
            };
        }

        // For a regulated request, an untested exit plan is a fail-safe exclusion.
        if request_class.is_regulated() && !a.last_exit_rehearsal.is_fresh(now, self.exit_cadence) {
            return Eligibility::ExitUntested;
        }

        Eligibility::Eligible
    }

    /// One candidate route's eligibility decision — the auditable unit. Pairs the route id with its
    /// reason-coded [`Eligibility`] so an **exclusion is evidence**, not a silent drop.
    ///
    /// The router keeps only [`Eligibility::Eligible`] routes (see [`eligible_routes`](
    /// OutsourcingRegister::eligible_routes)); this form additionally lets the caller record *why*
    /// each excluded route was excluded — the trail a regulator asks for to prove "no ungoverned
    /// outsourcing routed".
    pub fn eligibility_decisions<'a>(
        &self,
        candidates: impl IntoIterator<Item = &'a str>,
        request_class: DataClass,
        request_residency: &str,
        now: u64,
    ) -> Vec<EligibilityDecision> {
        candidates
            .into_iter()
            .map(|c| EligibilityDecision {
                route_id: c.to_string(),
                eligibility: self.eligibility(c, request_class, request_residency, now),
            })
            .collect()
    }

    /// The eligible routes among `candidates` for a request (what the router keeps before ranking).
    pub fn eligible_routes<'a>(
        &self,
        candidates: impl IntoIterator<Item = &'a str>,
        request_class: DataClass,
        request_residency: &str,
        now: u64,
    ) -> Vec<String> {
        candidates
            .into_iter()
            .filter(|c| {
                self.eligibility(c, request_class, request_residency, now)
                    .is_eligible()
            })
            .map(|c| c.to_string())
            .collect()
    }

    /// §3.3: check a route's freshly-published sub-processor list against its pin. On mismatch the
    /// route is **auto-restricted** (fail-safe) and `true` is returned (a diff the register PR must
    /// adopt). On match, nothing changes and `false` is returned.
    pub fn check_sub_processors(&mut self, route_id: &str, published: &[SubProcessor]) -> bool {
        if let Some(route) = self.routes.get_mut(route_id) {
            if !route.arrangement.sub_processors_match(published) {
                route.restricted = true;
                return true;
            }
        }
        false
    }

    /// Adopt a re-approving PR: re-pin the sub-processor list and lift the auto-restriction.
    pub fn reapprove(&mut self, route_id: &str, published: Vec<SubProcessor>) -> bool {
        if let Some(route) = self.routes.get_mut(route_id) {
            route.arrangement.reapprove_sub_processors(published);
            route.restricted = false;
            return true;
        }
        false
    }

    /// §3.4: route ids whose exit plan is untested (never or stale) at `now`.
    ///
    /// `needs_hot_wiring` (GAP-FIX gap6-responsibleai-cleanup, item 3): this has zero served callers —
    /// no admin route or cadence tick in `ainxt-runtimed`/`ainxt-server` surfaces which routes are due
    /// for a rehearsal. See [`crate::exit_plan::ExitPlan::rehearse`]'s doc for the full investigation
    /// (this would be the natural "what's due" read backing either a listing route or a cadence loop).
    pub fn exit_untested(&self, now: u64) -> Vec<String> {
        self.routes
            .values()
            .filter(|r| {
                !r.arrangement
                    .last_exit_rehearsal
                    .is_fresh(now, self.exit_cadence)
            })
            .map(|r| r.arrangement.id.clone())
            .collect()
    }

    /// §3.4 — record the outcome of a **rehearsed** exit plan (a rehearsable Long-Horizon shadow
    /// Program; see [`crate::exit_plan`]). Only an **all-pass** rehearsal freshens the route: on a
    /// passing report the route's `last_exit_rehearsal` advances to the rehearsal tick and the route
    /// leaves [`Eligibility::ExitUntested`]; a failed/partial rehearsal (or a report for an unknown
    /// route) changes nothing — fail-safe: a broken exit cannot dress itself up as tested. Returns
    /// `true` iff a route's freshness was advanced.
    ///
    /// `needs_hot_wiring` (GAP-FIX gap6-responsibleai-cleanup, item 3): zero served callers — the only
    /// served outsourcing route, `POST /admin/outsourcing/register`, lets an operator assert
    /// `last_exit_rehearsal` directly on registration instead of calling this with a real
    /// [`crate::exit_plan::ExitRehearsalReport`]. See [`crate::exit_plan::ExitPlan::rehearse`]'s doc
    /// for the full investigation and why this is a genuine follow-up, not a forced wire.
    pub fn record_exit_rehearsal(
        &mut self,
        report: &crate::exit_plan::ExitRehearsalReport,
    ) -> bool {
        let Some(fresh) = report.as_rehearsal() else {
            return false; // a failed/partial rehearsal never freshens.
        };
        if let Some(route) = self.routes.get_mut(&report.route_id) {
            route.arrangement.last_exit_rehearsal = fresh;
            return true;
        }
        false
    }

    /// §3.5 — every distinct `concentration_tag` present in the register, paired with the fraction of
    /// `traffic` that depends on it (0.0–1.0), in deterministic tag order. The raw signal
    /// [`concentration_findings`](Self::concentration_findings) turns into escalations.
    pub fn concentration_by_tag(&self, traffic: &BTreeMap<String, u64>) -> Vec<(String, f64)> {
        let mut tags: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        for r in self.routes.values() {
            tags.insert(r.arrangement.concentration_tag.as_str());
        }
        tags.into_iter()
            .map(|t| (t.to_string(), self.concentration(t, traffic)))
            .collect()
    }

    /// §3.5 — the **wired threshold→escalation**: scan every concentration tag and emit a
    /// [`ConcentrationFinding`] for each whose dependency fraction **exceeds** `threshold` (a strict
    /// `>` — a tag exactly at the board-set ceiling is acceptable). Each finding is the board-delegate
    /// escalation the parent routes (RBI §3.5 concentration-risk governance): it names the over-relied
    /// tag, its measured fraction, and the breached threshold. Findings are returned worst-first (then
    /// tag-ordered for determinism), so the parent escalates the most concentrated dependency first.
    /// Previously §3.5 was only a query metric ([`concentration`](Self::concentration)); this makes the
    /// threshold an actual control that fires, not a number a human must remember to read.
    pub fn concentration_findings(
        &self,
        traffic: &BTreeMap<String, u64>,
        threshold: f64,
    ) -> Vec<ConcentrationFinding> {
        let mut findings: Vec<ConcentrationFinding> = self
            .concentration_by_tag(traffic)
            .into_iter()
            .filter(|(_, frac)| *frac > threshold)
            .map(|(tag, fraction)| ConcentrationFinding {
                tag,
                fraction,
                threshold,
            })
            .collect();
        // Worst (highest fraction) first; ties broken by tag for a deterministic escalation order.
        findings.sort_by(|a, b| {
            b.fraction
                .partial_cmp(&a.fraction)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(a.tag.cmp(&b.tag))
        });
        findings
    }

    /// §3.5 concentration risk: the fraction (0.0–1.0) of `traffic` (route-id → weight) that depends
    /// on a single `concentration_tag`. A parent raises a board-delegate finding above a threshold.
    pub fn concentration(&self, tag: &str, traffic: &BTreeMap<String, u64>) -> f64 {
        let total: u64 = traffic.values().sum();
        if total == 0 {
            return 0.0;
        }
        let tagged: u64 = traffic
            .iter()
            .filter(|(id, _)| {
                self.routes
                    .get(*id)
                    .is_some_and(|r| r.arrangement.concentration_tag == tag)
            })
            .map(|(_, w)| *w)
            .sum();
        tagged as f64 / total as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arr(
        id: &str,
        ceiling: DataClass,
        residency: &str,
        rehearsal: ExitRehearsal,
    ) -> OutsourcingArrangement {
        OutsourcingArrangement::new(
            id,
            "Provider Ltd, US",
            ceiling,
            residency,
            vec![SubProcessor {
                name: "sub-a".into(),
                jurisdiction: "us".into(),
            }],
            "program.exit.p",
            "chat-inference",
            rehearsal,
        )
    }

    #[test]
    fn gap_ainxt_responsibleai_fi03_route_with_no_register_entry_is_excluded() {
        // §3.6 test 1: a cloud route with no register file is excluded for every request.
        let reg = OutsourcingRegister::new(10_000);
        let e = reg.eligibility("outsourcing.cloud.ghost", DataClass::Internal, "in", 0);
        assert_eq!(e, Eligibility::NoRegisterEntry);
        assert!(!e.is_eligible());
    }

    #[test]
    fn gap_ainxt_responsibleai_fi03_class_above_ceiling_and_residency_are_excluded() {
        // §3.6 test 2+3: permitted_data_class below request class → excluded; residency mismatch →
        // excluded (localisation).
        let mut reg = OutsourcingRegister::new(10_000);
        reg.upsert(arr(
            "r1",
            DataClass::Internal,
            "in",
            ExitRehearsal::At { tick: 100 },
        ));
        // internal-ceiling route asked to carry regulated-payment → excluded before ranking.
        assert_eq!(
            reg.eligibility("r1", DataClass::RegulatedPayment, "in", 200),
            Eligibility::DataClassAboveCeiling {
                request: DataClass::RegulatedPayment,
                permitted: DataClass::Internal,
            }
        );
        // in-country request against a foreign route → excluded.
        reg.upsert(arr(
            "r2",
            DataClass::Confidential,
            "us-east-1",
            ExitRehearsal::At { tick: 100 },
        ));
        assert!(matches!(
            reg.eligibility("r2", DataClass::Internal, "in", 200),
            Eligibility::ResidencyMismatch { .. }
        ));
        // A within-ceiling, in-residency, non-regulated request is eligible.
        assert!(reg
            .eligibility("r1", DataClass::Internal, "in", 200)
            .is_eligible());
    }

    #[test]
    fn gap_ainxt_responsibleai_fi03_untested_exit_excludes_regulated_requests() {
        // §3.6 test 5: a stale/never exit rehearsal ⇒ exit_untested ⇒ a regulated request is excluded.
        let mut reg = OutsourcingRegister::new(1_000);
        reg.upsert(arr(
            "r",
            DataClass::RegulatedPayment,
            "in",
            ExitRehearsal::Never,
        ));
        assert_eq!(
            reg.eligibility("r", DataClass::RegulatedPayment, "in", 5_000),
            Eligibility::ExitUntested
        );
        assert_eq!(reg.exit_untested(5_000), vec!["r".to_string()]);
        // Fresh rehearsal → eligible.
        reg.upsert(arr(
            "r",
            DataClass::RegulatedPayment,
            "in",
            ExitRehearsal::At { tick: 4_900 },
        ));
        assert!(reg
            .eligibility("r", DataClass::RegulatedPayment, "in", 5_000)
            .is_eligible());
    }

    #[test]
    fn gap_ainxt_responsibleai_fi03_sub_processor_drift_auto_restricts_until_reapproved() {
        // §3.6 test 4: a provider changes its sub-processor list → the pin fails; the route is
        // auto-restricted until a re-approving PR re-pins it.
        let mut reg = OutsourcingRegister::new(10_000);
        reg.upsert(arr(
            "r",
            DataClass::Confidential,
            "in",
            ExitRehearsal::At { tick: 100 },
        ));
        // Baseline holds.
        assert!(reg
            .eligibility("r", DataClass::Confidential, "in", 200)
            .is_eligible());

        // Provider silently adds a sub-processor.
        let published = vec![
            SubProcessor {
                name: "sub-a".into(),
                jurisdiction: "us".into(),
            },
            SubProcessor {
                name: "sub-NEW".into(),
                jurisdiction: "eu".into(),
            },
        ];
        let drifted = reg.check_sub_processors("r", &published);
        assert!(drifted, "a changed sub-processor list must be detected");
        // Auto-restricted: effective ceiling collapses to Public, so a Confidential request is excluded.
        assert_eq!(
            reg.eligibility("r", DataClass::Confidential, "in", 200),
            Eligibility::SubProcessorDrift
        );

        // Re-approving PR lands → re-pins and lifts the restriction.
        assert!(reg.reapprove("r", published));
        assert!(reg
            .eligibility("r", DataClass::Confidential, "in", 200)
            .is_eligible());
    }

    #[test]
    fn r5_outsourcing_eligibility_decisions_are_auditable() {
        // Round-5: the eligibility fn exposed as an AUDITABLE, reason-coded per-candidate decision set
        // (the non-overridable router input, in the form that records WHY each route was excluded).
        let mut reg = OutsourcingRegister::new(1_000);
        // r-ok: registered, within ceiling, in-residency, fresh exit → eligible.
        reg.upsert(arr(
            "r-ok",
            DataClass::RegulatedPayment,
            "in",
            ExitRehearsal::At { tick: 4_900 },
        ));
        // r-low: ceiling below the request class → excluded.
        reg.upsert(arr(
            "r-low",
            DataClass::Internal,
            "in",
            ExitRehearsal::At { tick: 4_900 },
        ));
        // r-stale: regulated request but exit plan never rehearsed → excluded.
        reg.upsert(arr(
            "r-stale",
            DataClass::RegulatedPayment,
            "in",
            ExitRehearsal::Never,
        ));

        let candidates = ["r-ok", "r-low", "r-stale", "r-ghost"];
        let decisions =
            reg.eligibility_decisions(candidates, DataClass::RegulatedPayment, "in", 5_000);

        // Order follows the input candidates (deterministic).
        assert_eq!(decisions.len(), 4);
        assert_eq!(decisions[0].route_id, "r-ok");
        assert!(decisions[0].is_eligible());
        // Each exclusion carries its reason code, not a silent drop.
        assert!(matches!(
            decisions[1].eligibility,
            Eligibility::DataClassAboveCeiling { .. }
        ));
        assert_eq!(decisions[2].eligibility, Eligibility::ExitUntested);
        assert_eq!(decisions[3].eligibility, Eligibility::NoRegisterEntry);

        // The admitted subset matches the router's `eligible_routes` exactly (same non-overridable
        // eligibility, just with the exclusion evidence retained).
        let admitted: Vec<String> = decisions
            .iter()
            .filter(|d| d.is_eligible())
            .map(|d| d.route_id.clone())
            .collect();
        assert_eq!(
            admitted,
            reg.eligible_routes(candidates, DataClass::RegulatedPayment, "in", 5_000)
        );
        assert_eq!(admitted, vec!["r-ok".to_string()]);
    }

    #[test]
    fn gap_ainxt_responsibleai_fi03_concentration_fraction() {
        // §3.5: the register answers "what fraction of traffic depends on one tag".
        let mut reg = OutsourcingRegister::new(10_000);
        reg.upsert(arr(
            "a",
            DataClass::Internal,
            "in",
            ExitRehearsal::At { tick: 1 },
        ));
        reg.upsert(arr(
            "b",
            DataClass::Internal,
            "in",
            ExitRehearsal::At { tick: 1 },
        ));
        let mut traffic = BTreeMap::new();
        traffic.insert("a".to_string(), 70);
        traffic.insert("b".to_string(), 30);
        // Both are tag "chat-inference" → 100% concentration.
        assert!((reg.concentration("chat-inference", &traffic) - 1.0).abs() < 1e-9);
        assert!(reg.concentration("embeddings", &traffic).abs() < 1e-9);
    }
}
