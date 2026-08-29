// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! **Role Studio** — the conversational factory (AINXT_OS §4 Steps 0–10) as a typed state machine.
//!
//! The design's authoring flow is *describe the job → structured Role Spec → auto-assemble → grant &
//! govern → per-task autonomy → knowledge + retrieval-quality check → KPI/eval auto-gen → Breaker
//! publish gate → shadow run → governed publish → monitor*. Here each step is an explicit
//! [`StudioStage`] and each transition is a method that (a) refuses to run out of order and (b)
//! carries the artifact forward. The Breaker gate is load-bearing: [`RoleStudio::run_breaker`] only
//! advances the machine when the report passes, and [`RoleStudio::publish`] can only be reached from
//! the post-Breaker stages — so the state machine *cannot* walk to `Published` without a passing
//! Breaker report. This mirrors, at the workflow level, the type-level guarantee in [`crate::breaker`].

use crate::author::{Factory, IntentExtractor, JobDescription};
use crate::breaker::{
    AdversarialCase, Breaker, BreakerPass, BreakerReport, Expectation, GateError,
    GovernedPublishRequest, ProbeCategory, PublishError, ResponseAction, RoleExecutor,
};
use crate::role::{Charter, Governance, PublishedRole, RoleSpec, ValidatedRole};

/// A pre-vetted golden-path template (Step 0) — kills the blank-page adoption problem (gap AZ).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Template {
    Developer,
    Tester,
    Ops,
    Support,
    Analyst,
    Blank,
}

/// The Studio's step, 0–10. Advancing is strictly sequential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StudioStage {
    /// Step 0 — pick a template / blank.
    Start,
    /// Step 1 — the job is described and turned into a structured spec.
    Described,
    /// Step 2 — an auto-assembled draft RoleSpec exists for review.
    Drafted,
    /// Step 3 — grant & govern reviewed (least-privilege).
    Governed,
    /// Step 4 — per-task autonomy dial set.
    AutonomySet,
    /// Step 5 — knowledge attached + retrieval-quality checked.
    KnowledgeChecked,
    /// Step 6 — KPIs / eval set defined.
    Kpis,
    /// Step 7 — the Breaker gate PASSED (only reachable on a passing report).
    BreakerPassed,
    /// Step 8 — shadow run recorded.
    Shadow,
    /// Step 9 — governed publish (PublishedRole minted).
    Published,
    /// Step 10 — live, monitored.
    Monitoring,
}

/// The outcome of a Step-8 shadow run beside the human team.
#[derive(Debug, Clone, PartialEq)]
pub struct ShadowResult {
    /// How many shadowed decisions matched the human's (evidence, not a claim).
    pub observed: u32,
    pub agreed_with_human: u32,
}

impl ShadowResult {
    pub fn new(observed: u32, agreed_with_human: u32) -> Self {
        ShadowResult {
            observed,
            agreed_with_human,
        }
    }
    pub fn agreement(&self) -> f64 {
        if self.observed == 0 {
            0.0
        } else {
            self.agreed_with_human as f64 / self.observed as f64
        }
    }
}

/// The outcome of a Step-10 monitoring evaluation ([`RoleStudio::evaluate_monitoring`]): whether a
/// live, published role should keep running, be paused for human review, or rolled back.
#[derive(Debug, Clone, PartialEq)]
pub enum MonitorDecision {
    /// KPIs and cost are within bounds — no action.
    Continue,
    /// A soft signal (KPI drifting below target, or over cost budget) — pause for human review.
    PauseForReview(Vec<String>),
    /// A hard signal (a KPI collapsed, or cost blew past 2x budget) — roll the role back.
    Rollback(Vec<String>),
}

/// A Studio flow error.
#[derive(Debug, Clone, PartialEq)]
pub enum StudioError {
    /// A transition was attempted from the wrong stage.
    OutOfOrder {
        expected: StudioStage,
        actual: StudioStage,
    },
    /// The assembled spec failed validation.
    Invalid(Vec<String>),
    /// The Breaker gate rejected the role (static battery or the actual adversarial run) — the
    /// machine does NOT advance.
    BreakerFailed(Vec<String>),
    /// Publish was refused by the gate.
    Publish(PublishError),
    /// A retrieval-quality check flagged knowledge below the floor.
    RetrievalQualityGap {
        namespace: String,
        score: f64,
        floor: f64,
    },
    /// Step 3 (grant & govern): the draft carries one or more capabilities marked
    /// `requires_approval` that were not in the caller's approved-capability list — least-privilege
    /// sign-off is not a rubber stamp, so `govern()` refuses to advance until every sensitive grant is
    /// explicitly approved (see [`RoleStudio::govern_with_approvals`]).
    SensitiveCapabilityNeedsApproval(Vec<String>),
    /// Step 8 (shadow run): the observed evidence does not clear the trust-before-publish bar — either
    /// too few shadowed decisions to be statistically meaningful, or the human-agreement rate is below
    /// the floor. Trust must be EARNED with evidence, not merely recorded.
    InsufficientShadowEvidence {
        observed: u32,
        required_observed: u32,
        agreement: f64,
        required_agreement: f64,
    },
}

impl std::fmt::Display for StudioError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StudioError::OutOfOrder { expected, actual } => {
                write!(
                    f,
                    "out-of-order Studio step: expected {expected:?}, at {actual:?}"
                )
            }
            StudioError::Invalid(e) => write!(f, "invalid role spec: {}", e.join("; ")),
            StudioError::BreakerFailed(p) => write!(f, "Breaker gate failed: {}", p.join(", ")),
            StudioError::Publish(e) => write!(f, "publish refused: {e}"),
            StudioError::RetrievalQualityGap {
                namespace,
                score,
                floor,
            } => write!(
                f,
                "knowledge '{namespace}' retrieval quality {score} below floor {floor}"
            ),
            StudioError::SensitiveCapabilityNeedsApproval(caps) => write!(
                f,
                "sensitive capabilities need human sign-off before Step 3 can complete: {}",
                caps.join(", ")
            ),
            StudioError::InsufficientShadowEvidence {
                observed,
                required_observed,
                agreement,
                required_agreement,
            } => {
                write!(
                    f,
                    "shadow-run evidence insufficient: observed={observed} (need >= {required_observed}), \
                     agreement={agreement:.2} (need >= {required_agreement:.2})"
                )
            }
        }
    }
}
impl std::error::Error for StudioError {}

/// Step 8's minimum evidence bar (§4 Step 8: "trust is earned with evidence before publish"). A
/// shadow run with too few observed decisions is not statistically meaningful; one below the
/// agreement floor means the role is not yet trustworthy enough to publish. Both are hard-fail —
/// `shadow_run` does NOT advance the machine when either is unmet.
pub const MIN_SHADOW_OBSERVATIONS: u32 = 20;
pub const MIN_SHADOW_AGREEMENT: f64 = 0.85;

/// Step 5's minimum retrieval-quality bar (§4 Step 5: "knowledge + retrieval-quality check"). A FIXED
/// constant, not a caller-suppliable parameter — a floor a caller can pick is a floor a caller can pick
/// as `0.0`, which would make the gate decorative. `0.75` mirrors the same "clearly acceptable, not yet
/// excellent" convention `ainxt-runtimed`'s `EVAL_BATTERY_PASS_THRESHOLD` documents for the analogous
/// Step-6 eval-battery bar (scaled to this field's own `[0.0, 1.0]` range instead of `0-100`).
pub const KNOWLEDGE_RETRIEVAL_QUALITY_FLOOR: f64 = 0.75;

/// The conversational Role factory as a driven state machine.
#[derive(Debug)]
pub struct RoleStudio {
    stage: StudioStage,
    template: Template,
    job: Option<JobDescription>,
    charter: Option<Charter>,
    spec: Option<RoleSpec>,
    validated: Option<ValidatedRole>,
    report: Option<BreakerReport>,
    /// The sealed pass from the Step-7 gate (static battery + actual adversarial run). Publishing
    /// requires it, so the machine cannot reach Published without an actual Breaker gate having run.
    pass: Option<BreakerPass>,
    shadow: Option<ShadowResult>,
    published: Option<PublishedRole>,
}

impl RoleStudio {
    /// Step 0 — Start.
    pub fn start(template: Template) -> Self {
        RoleStudio {
            stage: StudioStage::Start,
            template,
            job: None,
            charter: None,
            spec: None,
            validated: None,
            report: None,
            pass: None,
            shadow: None,
            published: None,
        }
    }

    pub fn stage(&self) -> StudioStage {
        self.stage
    }
    pub fn template(&self) -> Template {
        self.template
    }

    fn require(&self, expected: StudioStage) -> Result<(), StudioError> {
        if self.stage == expected {
            Ok(())
        } else {
            Err(StudioError::OutOfOrder {
                expected,
                actual: self.stage,
            })
        }
    }

    /// **Step 1** — the creator's plain-language job description is turned into a structured
    /// [`Charter`] by the [`Factory`]'s intent seam (conversational authoring; AINXT_OS §4 Step 1).
    /// This is a *distinct* step from the Step-2 auto-assembly, giving the state machine 1:1 fidelity
    /// with the design's ten steps (the intermediate [`StudioStage::Described`] is real, not folded).
    pub fn describe<E: IntentExtractor>(
        &mut self,
        job: JobDescription,
        factory: &Factory<E>,
    ) -> Result<&mut Self, StudioError> {
        self.require(StudioStage::Start)?;
        self.charter = Some(factory.describe(&job));
        self.job = Some(job);
        self.stage = StudioStage::Described;
        Ok(self)
    }

    /// **Step 2** — the Factory auto-assembles the draft [`RoleSpec`] (capabilities, skills, model
    /// policy, connectors, knowledge, per-task autonomy) from the chosen template + the Step-1 charter
    /// + the governance block, and pre-seeds the Step-6 quality-eval [`Kpi`] set. The creator reviews
    /// (doesn't build); `define_kpis` later confirms the auto-generated evals.
    #[allow(clippy::doc_lazy_continuation)]
    pub fn auto_assemble<E: IntentExtractor>(
        &mut self,
        factory: &Factory<E>,
        governance: Governance,
    ) -> Result<&mut Self, StudioError> {
        self.require(StudioStage::Described)?;
        let charter = self
            .charter
            .clone()
            .expect("charter present after describe");
        let job = self.job.clone().expect("job present after describe");
        let mut spec = factory.auto_assemble(&job, charter, governance);
        // Step 6 auto-generation (proposed now; confirmed at `define_kpis`).
        spec.kpis = factory.auto_generate_kpis(job.template);
        self.spec = Some(spec);
        self.stage = StudioStage::Drafted;
        Ok(self)
    }

    /// The Steps-1–2 folded convenience: the caller already holds an assembled [`RoleSpec`] (e.g. from
    /// an external authoring client) and hands it in as the reviewed draft. Reaches the same
    /// [`StudioStage::Drafted`] as `describe` + `auto_assemble`.
    pub fn describe_and_draft(&mut self, spec: RoleSpec) -> Result<&mut Self, StudioError> {
        self.require(StudioStage::Start)?;
        self.spec = Some(spec);
        self.stage = StudioStage::Drafted;
        Ok(self)
    }

    /// The structured charter produced at Step 1 (before auto-assembly), if the finer path was used.
    pub fn charter(&self) -> Option<&Charter> {
        self.charter.as_ref()
    }
    /// The draft spec after Step 2 (for the review canvas).
    pub fn spec(&self) -> Option<&RoleSpec> {
        self.spec.as_ref()
    }

    /// Step 3 — grant & govern (least-privilege sign-off). Sugar for
    /// `govern_with_approvals(&[])`: succeeds only when the draft carries NO capability marked
    /// `requires_approval` (`Capability::requiring_approval`). A draft with any sensitive grant must
    /// go through [`RoleStudio::govern_with_approvals`] instead — this is what turns Step 3 from a
    /// rubber-stamp stage transition into a real least-privilege gate.
    pub fn govern(&mut self) -> Result<&mut Self, StudioError> {
        self.govern_with_approvals(&[])
    }

    /// Step 3 — grant & govern, with an explicit list of capability names a human has signed off on.
    /// Every capability across every agent that is marked `requires_approval` MUST appear in
    /// `approved_capabilities`, or the step is refused with
    /// [`StudioError::SensitiveCapabilityNeedsApproval`] naming exactly the ungranted ones — sensitive
    /// capabilities need human approval, not a default-yes.
    pub fn govern_with_approvals(
        &mut self,
        approved_capabilities: &[String],
    ) -> Result<&mut Self, StudioError> {
        self.require(StudioStage::Drafted)?;
        let spec = self.spec.as_ref().expect("spec present after draft");
        let unapproved: Vec<String> = spec
            .all_capabilities()
            .into_iter()
            .filter(|c| c.requires_approval)
            .filter(|c| !approved_capabilities.iter().any(|a| a == &c.name))
            .map(|c| c.name.clone())
            .collect();
        if !unapproved.is_empty() {
            return Err(StudioError::SensitiveCapabilityNeedsApproval(unapproved));
        }
        self.stage = StudioStage::Governed;
        Ok(self)
    }

    /// Step 4 — per-task autonomy dial confirmed. Runs [`crate::autonomy::AutonomyModel::validate`]
    /// on the draft's dial NOW (rather than deferring every coherence check to the Step-7 Breaker), so
    /// an incoherent dial (a regulated task pinned to `Auto`, an out-of-range escalation threshold) is
    /// caught at the step that actually sets it, not seven steps later — the real substance behind
    /// "confirmed", not a no-op flag flip.
    pub fn set_autonomy(&mut self) -> Result<&mut Self, StudioError> {
        self.require(StudioStage::Governed)?;
        let spec = self.spec.as_ref().expect("spec present after draft");
        let errs = spec.autonomy.validate();
        if !errs.is_empty() {
            return Err(StudioError::Invalid(errs));
        }
        self.stage = StudioStage::AutonomySet;
        Ok(self)
    }

    /// Step 5 — attach knowledge + run the retrieval-quality check. `scores` maps each knowledge
    /// namespace to its measured retrieval quality; any below `floor` is a gap that blocks the step
    /// (RAG quality, gap G). On success the scores are written back onto the spec's knowledge scopes.
    pub fn check_knowledge(
        &mut self,
        scores: &[(&str, f64)],
        floor: f64,
    ) -> Result<&mut Self, StudioError> {
        self.require(StudioStage::AutonomySet)?;
        let spec = self.spec.as_mut().expect("spec present after draft");
        for (ns, score) in scores {
            if *score < floor {
                return Err(StudioError::RetrievalQualityGap {
                    namespace: (*ns).to_string(),
                    score: *score,
                    floor,
                });
            }
        }
        for k in &mut spec.knowledge {
            if let Some((_, score)) = scores.iter().find(|(ns, _)| *ns == k.namespace) {
                k.retrieval_quality = Some(*score);
            }
        }
        self.stage = StudioStage::KnowledgeChecked;
        Ok(self)
    }

    /// Step 5 convenience — derive each knowledge scope's score from the spec's OWN pre-populated
    /// [`crate::role::KnowledgeScope::retrieval_quality`] instead of requiring a caller to pass a
    /// disconnected out-of-band `scores` slice. A namespace that was never actually measured
    /// (`retrieval_quality: None`) is treated as `0.0` — fail-closed, never silently skipped or treated
    /// as a pass — so a role cannot clear this step by simply never running the (real, external)
    /// retrieval-quality check that is supposed to populate the field before this call. Gates against
    /// [`KNOWLEDGE_RETRIEVAL_QUALITY_FLOOR`], the fixed, non-caller-suppliable bar.
    pub fn check_knowledge_from_spec(&mut self) -> Result<&mut Self, StudioError> {
        self.require(StudioStage::AutonomySet)?;
        let scores: Vec<(String, f64)> = self
            .spec
            .as_ref()
            .expect("spec present after draft")
            .knowledge
            .iter()
            .map(|k| (k.namespace.clone(), k.retrieval_quality.unwrap_or(0.0)))
            .collect();
        let score_refs: Vec<(&str, f64)> = scores.iter().map(|(n, s)| (n.as_str(), *s)).collect();
        self.check_knowledge(&score_refs, KNOWLEDGE_RETRIEVAL_QUALITY_FLOOR)
    }

    /// Step 6 — KPIs / eval set defined (auto-generated then confirmed). Requires the spec to carry
    /// at least one KPI, else the role would be unmeasurable.
    pub fn define_kpis(&mut self) -> Result<&mut Self, StudioError> {
        self.require(StudioStage::KnowledgeChecked)?;
        let spec = self.spec.as_ref().expect("spec present");
        if spec.kpis.is_empty() {
            return Err(StudioError::Invalid(
                vec!["no KPIs defined (Step 6)".into()],
            ));
        }
        self.stage = StudioStage::Kpis;
        Ok(self)
    }

    /// Step 7 — **the Breaker gate (cannot skip)**. Validates the composition and runs the FULL
    /// Breaker gate ([`Breaker::gate`]): the static spec battery AND an ACTUAL adversarial run of the
    /// role through the injected [`RoleExecutor`] (a live deployment supplies a model-backed executor;
    /// offline the crate's [`crate::breaker::CompliantExecutor`] / [`crate::breaker::ScriptedExecutor`]
    /// stand in). The machine advances *only* when both halves pass, minting a sealed
    /// [`BreakerPass`] that `publish` later consumes — so the machine cannot reach `Published` on the
    /// static battery alone, nor with a forged report. A failure leaves the machine at `Kpis` and
    /// returns [`StudioError::BreakerFailed`].
    pub fn run_breaker<E: RoleExecutor>(
        &mut self,
        executor: &E,
    ) -> Result<&BreakerReport, StudioError> {
        self.require(StudioStage::Kpis)?;
        let spec = self.spec.clone().expect("spec present");
        let validated = spec.validate().map_err(StudioError::Invalid)?;
        // Keep the static report for the review canvas regardless of outcome.
        self.report = Some(Breaker::run(&validated));
        match Breaker::gate(&validated, executor) {
            Ok(pass) => {
                self.validated = Some(validated);
                self.pass = Some(pass);
                self.stage = StudioStage::BreakerPassed;
                Ok(self.report.as_ref().unwrap())
            }
            Err(GateError::StaticBatteryFailed { failed_probes })
            | Err(GateError::AdversarialRunFailed { failed_probes }) => {
                // Do NOT advance — stay at Kpis.
                Err(StudioError::BreakerFailed(failed_probes))
            }
        }
    }

    /// Step 8 — shadow run beside the human team (observe, do not act). Only reachable once the
    /// Breaker has passed. **Trust is earned with evidence before publish**: a shadow run with fewer
    /// than [`MIN_SHADOW_OBSERVATIONS`] decisions is not statistically meaningful, and one whose
    /// human-agreement rate falls below [`MIN_SHADOW_AGREEMENT`] means the role is not yet trustworthy
    /// — either way `shadow_run` refuses with [`StudioError::InsufficientShadowEvidence`] and the
    /// machine stays at `BreakerPassed`, so Step 9's publish can never be reached on thin or bad
    /// evidence.
    pub fn shadow_run(&mut self, result: ShadowResult) -> Result<&mut Self, StudioError> {
        self.require(StudioStage::BreakerPassed)?;
        let agreement = result.agreement();
        if result.observed < MIN_SHADOW_OBSERVATIONS || agreement < MIN_SHADOW_AGREEMENT {
            return Err(StudioError::InsufficientShadowEvidence {
                observed: result.observed,
                required_observed: MIN_SHADOW_OBSERVATIONS,
                agreement,
                required_agreement: MIN_SHADOW_AGREEMENT,
            });
        }
        self.shadow = Some(result);
        self.stage = StudioStage::Shadow;
        Ok(self)
    }

    /// Step 9 — **governed publish** (git-native, ADR-026). Mints the [`PublishedRole`] through the
    /// publish gate using the sealed [`BreakerPass`] captured at Step 7 and the supplied
    /// [`GovernedPublishRequest`] — which routes the mint through `ainxt-governance` (emit a PR → CI /
    /// pre-receive gate → CODEOWNERS-approved signed merge → signed production tag). Unreachable
    /// before `Shadow`, which is unreachable before `BreakerPassed` — so this can never mint a role
    /// that skipped the Breaker, and it never flips a DB flag: publishing walks the git lifecycle.
    pub fn publish(&mut self, gov: &GovernedPublishRequest) -> Result<&PublishedRole, StudioError> {
        self.require(StudioStage::Shadow)?;
        let validated = self
            .validated
            .take()
            .expect("validated present after Breaker pass");
        let pass = self.pass.as_ref().expect("pass present after Breaker gate");
        let published =
            crate::breaker::publish(validated, pass, gov).map_err(StudioError::Publish)?;
        self.published = Some(published);
        self.stage = StudioStage::Published;
        Ok(self.published.as_ref().unwrap())
    }

    /// Step 10 — live & monitored. The stage flip itself is a one-time transition (Published →
    /// Monitoring); the CONTINUOUS half — KPI/quality-drift + cost tracking and the pause/rollback
    /// decision — is [`RoleStudio::evaluate_monitoring`], called repeatedly for the life of the role.
    pub fn monitor(&mut self) -> Result<&mut Self, StudioError> {
        self.require(StudioStage::Published)?;
        self.stage = StudioStage::Monitoring;
        Ok(self)
    }

    /// **Step 10's continuous substance**: evaluate a monitoring snapshot for a published role against
    /// its own declared KPIs and a cost budget, and derive the pause/rollback decision (AINXT_OS §4
    /// Step 10). Pure and deterministic — the live telemetry feed that produces `kpi_observations` /
    /// `cost_actual` is a downstream, infra-gated seam; this is the decision logic a monitoring loop
    /// (nightly sweep or a live dashboard) calls every period.
    ///
    /// - Any KPI observed at or below half its target, or cost at/above 2x budget, is a hard signal —
    ///   [`MonitorDecision::Rollback`].
    /// - Any KPI observed below (but above half) its target, or cost over budget but under 2x, is a
    ///   soft signal — [`MonitorDecision::PauseForReview`].
    /// - Otherwise [`MonitorDecision::Continue`].
    pub fn evaluate_monitoring(
        spec: &RoleSpec,
        kpi_observations: &[(&str, f64)],
        cost_actual: f64,
        cost_budget: f64,
    ) -> MonitorDecision {
        let mut hard = Vec::new();
        let mut soft = Vec::new();

        for kpi in &spec.kpis {
            if let Some((_, observed)) = kpi_observations.iter().find(|(n, _)| *n == kpi.name) {
                if kpi.target > 0.0 && *observed <= kpi.target * 0.5 {
                    hard.push(format!(
                        "KPI '{}' collapsed: observed {observed} vs target {}",
                        kpi.name, kpi.target
                    ));
                } else if *observed < kpi.target {
                    soft.push(format!(
                        "KPI '{}' drifting: observed {observed} vs target {}",
                        kpi.name, kpi.target
                    ));
                }
            }
        }

        if cost_budget > 0.0 && cost_actual >= cost_budget * 2.0 {
            hard.push(format!(
                "cost {cost_actual} is at/above 2x budget {cost_budget}"
            ));
        } else if cost_budget > 0.0 && cost_actual > cost_budget {
            soft.push(format!("cost {cost_actual} exceeds budget {cost_budget}"));
        }

        if !hard.is_empty() {
            MonitorDecision::Rollback(hard)
        } else if !soft.is_empty() {
            MonitorDecision::PauseForReview(soft)
        } else {
            MonitorDecision::Continue
        }
    }

    // ---- Accessors ----
    /// The validated role after a passing Step-7 Breaker gate — for a caller that needs to run an
    /// ADDITIONAL check against the SAME validated composition the gate just cleared (e.g. a real
    /// Step-8 shadow-run observation via [`run_shadow_observation`]) rather than re-deriving a second,
    /// independent [`ValidatedRole`] by re-calling [`RoleSpec::validate`] itself.
    pub fn validated(&self) -> Option<&ValidatedRole> {
        self.validated.as_ref()
    }
    pub fn report(&self) -> Option<&BreakerReport> {
        self.report.as_ref()
    }
    pub fn shadow(&self) -> Option<&ShadowResult> {
        self.shadow.as_ref()
    }
    pub fn published(&self) -> Option<&PublishedRole> {
        self.published.as_ref()
    }
    pub fn into_published(self) -> Option<PublishedRole> {
        self.published
    }
}

/// **GAP-CLOSE os-workforce (gap6-workforce-governance-gate) — real Step-8 shadow-run evidence.** One
/// real historical decision the role is shadow-run against: what a real user actually asked, and what a
/// human on the team actually decided about it. Both fields are genuine ground truth the caller
/// supplies (from wherever shadow tickets actually live) — [`run_shadow_observation`] does not invent
/// either one; it only runs the model and compares. Moved here (from the composition-root crate that
/// originally defined it) because neither this type nor `run_shadow_observation` has any dependency on
/// that crate — both are pure over `ainxt-workforce`'s own [`RoleExecutor`]/[`ValidatedRole`], so they
/// belong in the dependency-free crate that owns [`RoleStudio::shadow_run`] itself, reusable by ANY
/// caller (a served composition root, a CLI, or a test) without needing the heavier crate.
#[derive(Debug, Clone)]
pub struct ShadowCase {
    pub id: String,
    pub input: String,
    /// What a human on the team actually decided for this real case.
    pub human_action: ResponseAction,
}

/// Run `role` through `executor` — the SAME live seam the Step-7 Breaker uses — against REAL
/// historical `cases`, and compare each actual model decision to what the human actually did. Returns
/// a genuine [`ShadowResult`] computed from that comparison: `observed` is the real case count,
/// `agreed_with_human` is the real count of matching decisions. This is the whole gap-close — no
/// fabricated evidence reaches [`RoleStudio::shadow_run`]'s trust-before-publish gate. Generic over
/// `E: RoleExecutor` (rather than a fixed concrete executor type) so both a composition root's live
/// model-backed executor AND the crate's own offline `CompliantExecutor`/`ScriptedExecutor` — or an
/// `Arc<dyn RoleExecutor + Send + Sync>` trait-object handle, via the blanket `RoleExecutor` impls for
/// `&E`/`Arc<E>`/`Box<E>` in `breaker.rs` — can drive this same real observation.
pub fn run_shadow_observation<E: RoleExecutor>(
    executor: &E,
    role: &ValidatedRole,
    cases: &[ShadowCase],
) -> ShadowResult {
    let mut agreed = 0u32;
    for c in cases {
        // `MustAnswerWithQuality` is only the calling convention `RoleExecutor::execute` requires
        // (an `AdversarialCase` shape) — a shadow case is not judged by the Breaker's rubric; only
        // the resulting `action` is compared to the real human decision below.
        let probe = AdversarialCase {
            id: c.id.clone(),
            category: ProbeCategory::EdgeCase,
            input: c.input.clone(),
            expect: Expectation::MustAnswerWithQuality,
        };
        let out = executor.execute(role, &probe);
        if out.action == c.human_action {
            agreed += 1;
        }
    }
    ShadowResult::new(cases.len() as u32, agreed)
}

/// **A minimal, cross-crate-safe seam** (gap6-workforce-governance-gate) so the network-transport crate
/// (`ainxt-server`, which cannot depend on the composition root that builds the real, model-backed
/// [`RoleExecutor`] — that would be a circular crate dependency) can still drive a REAL governed role
/// publish / team assembly without needing that root's own types. The composition root's real workforce
/// surface implements this trait; the transport crate holds only `Arc<dyn GovernedWorkforce>` — the
/// exact same "type-adapter at the crate boundary" pattern this workspace already uses for
/// `ainxt-admission::StepExecutor` / `ainxt-client::CapabilityInvoker` / `ainxt-mcp::AuthProvider` /
/// `ainxt-mcp::PinStore`. The error type is a plain `String` (not the composition root's own rich error
/// enum) deliberately — a transport-crate HTTP handler only ever turns a failure into a response body,
/// so sharing the rich enum across the boundary would buy nothing but a second, disjoint copy of it.
pub trait GovernedWorkforce: Send + Sync {
    /// Drive a role through the REAL, non-skippable governance pipeline (Steps 3–9: grant & govern,
    /// autonomy, knowledge-quality, KPIs, the Breaker, shadow-run evidence, governed publish) and
    /// return the minted [`PublishedRole`], or a fail-closed refusal message.
    fn publish_role(
        &self,
        spec: RoleSpec,
        approved_capabilities: &[String],
        shadow_cases: &[ShadowCase],
        gov: &GovernedPublishRequest,
    ) -> Result<PublishedRole, String>;

    /// Assemble a [`crate::team::DigitalTeam`] from roles this SAME surface has actually published
    /// (never an arbitrary caller-constructed [`PublishedRole`]).
    fn assemble_team(
        &self,
        id: &str,
        department: &str,
        owner: &str,
        role_ids: &[String],
        collaborations: Vec<crate::team::Collaboration>,
    ) -> Result<crate::team::DigitalTeam, String>;
}
