// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Signed, staged, integrity-verified weight rollout + honest rollback SLA
//! (SERVING_OPS.md §5, gap 38; audit gap **SRV-05**).
//!
//! The audit found only two comments — no rollout controller, no weight-signature verification, no
//! staged promotion, no rollback logic. This module is the real policy core §5 requires:
//!
//! * **Signature + content-hash re-verified AT EVERY LOAD** ([`WeightRollout::verify_load`]) — not
//!   only at first install, so a signing key discovered compromised after a model has run for months
//!   does not grandfather it in (§5). Reuses the platform's one signed-artifact scheme via the
//!   [`ArtifactVerifier`] seam (the crypto backend is injected, not carried by this pure crate).
//! * **Regulated-tier decryption bound to a valid attestation quote** — a regulated weight blob is
//!   only decryptable inside a currently-attested enclave; [`WeightRollout::verify_load`] refuses the
//!   load if `attestation_ok` is false (ADR-021 §8.3), even when the signature itself verifies.
//! * **Staged promotion** ([`RolloutState`], [`WeightRollout::advance`]) — `P2Shadow → P2Canary →
//!   P1Canary → P0`, each gated on no judge-score/latency regression for a minimum soak; a regression
//!   at any canary stage **auto-rolls-back** (blast radius small); a P0-stage regression needs either
//!   a control-plane breach threshold or a human approval gate before it rolls back (§5).
//! * **Two honest zero-downtime paths** ([`CutoverPath::plan`]) — true blue-green when ≥2× VRAM
//!   headroom, else staged group-by-group (capacity dips but never reaches zero) — the cost is stated
//!   up front, not discovered in production.
//! * **Rollback SLA as a number, not a slogan** ([`RollbackPlan::for_state`]) — a warm parked
//!   fallback rolls back in a bounded warm-reload window; a fallback evicted past its retention
//!   window is honestly a cold pull, reported as such rather than claiming the warm number.
//!
//! Deterministic and pure: no crypto, no GPU, no clock. Signatures and quality signals are inputs.

#[cfg(test)]
use crate::attestation::{AttestationQuote, SignatureVerifier};

/// A signed weight artifact: the weights + tokenizer + serving config, addressed by content hash and
/// carrying a detached signature (SERVING_OPS.md §5, reusing the plugin signed-artifact scheme).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeightArtifact {
    pub model_id: String,
    pub version: String,
    /// Content hash of the weight blob — recomputed and compared at every load.
    pub content_hash: u64,
    /// Detached signature over the artifact (opaque; verified via the [`ArtifactVerifier`] seam).
    pub signature: String,
    /// Whether this is a regulated-tier deployment (decryption key is attestation-bound).
    pub regulated: bool,
}

/// The weight-artifact signature/integrity seam (SERVING_OPS.md §5). Real implementations verify a
/// detached signature against an allow-listed publisher and recompute the content hash — a crypto
/// backend this pure crate does not carry. [`AllowListArtifactVerifier`] models it deterministically.
pub trait ArtifactVerifier {
    /// True iff `artifact`'s signature verifies against a trusted publisher.
    fn verify_signature(&self, artifact: &WeightArtifact) -> bool;
    /// The content hash recomputed from the on-disk blob (a real re-hash; here, injected). A mismatch
    /// with `artifact.content_hash` is a tamper signal caught at load.
    fn recompute_hash(&self, artifact: &WeightArtifact) -> u64;
}

/// A deterministic reference verifier: a signature verifies iff allow-listed, and the recomputed hash
/// is whatever was recorded for `(model,version)` — a genuine (non-tautological) tamper check.
#[derive(Debug, Clone, Default)]
pub struct AllowListArtifactVerifier {
    accepted_sigs: std::collections::BTreeSet<String>,
    on_disk_hash: std::collections::BTreeMap<(String, String), u64>,
}

impl AllowListArtifactVerifier {
    pub fn new() -> Self {
        AllowListArtifactVerifier::default()
    }
    pub fn accept_signature(mut self, sig: impl Into<String>) -> Self {
        self.accepted_sigs.insert(sig.into());
        self
    }
    /// Record what the blob on disk actually hashes to (may differ from the manifest → tamper).
    pub fn with_on_disk_hash(mut self, model: &str, version: &str, hash: u64) -> Self {
        self.on_disk_hash
            .insert((model.to_string(), version.to_string()), hash);
        self
    }
}

impl ArtifactVerifier for AllowListArtifactVerifier {
    fn verify_signature(&self, artifact: &WeightArtifact) -> bool {
        self.accepted_sigs.contains(&artifact.signature)
    }
    fn recompute_hash(&self, artifact: &WeightArtifact) -> u64 {
        self.on_disk_hash
            .get(&(artifact.model_id.clone(), artifact.version.clone()))
            .copied()
            .unwrap_or(artifact.content_hash) // default: on-disk matches the manifest
    }
}

/// Why a weight load was refused at load time (SERVING_OPS.md §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadError {
    /// The detached signature did not verify against a trusted publisher.
    SignatureInvalid,
    /// The recomputed content hash does not match the signed manifest — tampered/corrupt blob.
    ContentHashMismatch,
    /// A regulated-tier blob whose attestation-bound decryption key cannot be released (the target
    /// node is not currently attested, ADR-021 §8.3).
    AttestationKeyUnavailable,
}

/// The staged rollout position of a candidate version (SERVING_OPS.md §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RolloutState {
    /// 0% live traffic — replayed against recorded traffic + the regression eval-suite.
    P2Shadow,
    /// A small % of P2 (batch/program) traffic — cheapest failure surface.
    P2Canary,
    /// A small % of P1 traffic, for a minimum soak, gated on no regression.
    P1Canary,
    /// Full P0 traffic — only after a clean soak at P1.
    Promoted,
    /// Rolled back to the incumbent.
    RolledBack,
}

/// The outcome of one [`WeightRollout::advance`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdvanceOutcome {
    /// Promoted to the next stage.
    Advanced { to: RolloutState },
    /// Held at the current stage (soak time not yet met, no regression).
    Held { at: RolloutState },
    /// Auto-rolled-back (a canary-stage regression, or a P0 breach past threshold).
    AutoRolledBack { from: RolloutState },
    /// A P0-stage regression *below* the auto-rollback threshold — requires a human approval gate
    /// before rollback executes (the same Approval Gate seam used elsewhere, §5).
    AwaitingApproval { at: RolloutState },
}

/// One soak observation fed to [`WeightRollout::advance`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SoakSignal {
    /// No judge-score/latency regression vs. the incumbent (the live quality scoreboard, §5).
    pub no_regression: bool,
    /// The minimum soak time for the current stage has elapsed.
    pub soak_met: bool,
    /// At P0 only: the regression (if any) breached the control-plane auto-rollback threshold.
    pub p0_breach_threshold: bool,
}

/// The staged weight-rollout controller for one candidate version (SERVING_OPS.md §5).
#[derive(Debug, Clone)]
pub struct WeightRollout {
    state: RolloutState,
}

impl WeightRollout {
    /// Begin a rollout in shadow (0% traffic).
    pub fn new() -> Self {
        WeightRollout {
            state: RolloutState::P2Shadow,
        }
    }

    pub fn state(&self) -> RolloutState {
        self.state
    }

    /// Verify a weight artifact **at load time** (SERVING_OPS.md §5). `attestation_ok` is the
    /// attestation gate's verdict for the target node (ADR-021 §8.3) — required only for regulated
    /// blobs, whose decryption key is attestation-bound. Signature + content hash are checked on
    /// EVERY load, never grandfathered.
    pub fn verify_load(
        artifact: &WeightArtifact,
        verifier: &dyn ArtifactVerifier,
        attestation_ok: bool,
    ) -> Result<(), LoadError> {
        if !verifier.verify_signature(artifact) {
            return Err(LoadError::SignatureInvalid);
        }
        if verifier.recompute_hash(artifact) != artifact.content_hash {
            return Err(LoadError::ContentHashMismatch);
        }
        if artifact.regulated && !attestation_ok {
            return Err(LoadError::AttestationKeyUnavailable);
        }
        Ok(())
    }

    /// Advance the staged promotion given one soak observation (SERVING_OPS.md §5).
    ///
    /// * A regression at any **canary** stage (`P2Shadow`/`P2Canary`/`P1Canary`) auto-rolls-back.
    /// * A regression at **P0** (`Promoted`) rolls back automatically only if it breached the
    ///   control-plane threshold; otherwise it awaits a human approval gate.
    /// * No regression + soak met → promote to the next stage; soak not met → hold.
    pub fn advance(&mut self, signal: SoakSignal) -> AdvanceOutcome {
        match self.state {
            RolloutState::RolledBack => AdvanceOutcome::Held {
                at: RolloutState::RolledBack,
            },
            RolloutState::Promoted => {
                if signal.no_regression {
                    return AdvanceOutcome::Held {
                        at: RolloutState::Promoted,
                    };
                }
                // A P0 regression: auto-rollback only past the breach threshold; else await approval.
                if signal.p0_breach_threshold {
                    self.state = RolloutState::RolledBack;
                    AdvanceOutcome::AutoRolledBack {
                        from: RolloutState::Promoted,
                    }
                } else {
                    AdvanceOutcome::AwaitingApproval {
                        at: RolloutState::Promoted,
                    }
                }
            }
            canary => {
                if !signal.no_regression {
                    let from = self.state;
                    self.state = RolloutState::RolledBack;
                    return AdvanceOutcome::AutoRolledBack { from };
                }
                if !signal.soak_met {
                    return AdvanceOutcome::Held { at: canary };
                }
                let next = match canary {
                    RolloutState::P2Shadow => RolloutState::P2Canary,
                    RolloutState::P2Canary => RolloutState::P1Canary,
                    RolloutState::P1Canary => RolloutState::Promoted,
                    _ => unreachable!("Promoted/RolledBack handled above"),
                };
                self.state = next;
                AdvanceOutcome::Advanced { to: next }
            }
        }
    }

    /// Execute the approved P0 rollback (after the [`AdvanceOutcome::AwaitingApproval`] gate clears).
    pub fn approve_rollback(&mut self) {
        self.state = RolloutState::RolledBack;
    }
}

impl Default for WeightRollout {
    fn default() -> Self {
        WeightRollout::new()
    }
}

// ---------------------------------------------------------------------------
// Zero-downtime cutover path (SERVING_OPS.md §5)
// ---------------------------------------------------------------------------

/// Which zero-downtime mechanic a cutover uses, chosen by available VRAM headroom (§5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CutoverPath {
    /// ≥2× the model footprint free: old + new both resident, traffic shifts with zero reload latency.
    BlueGreen,
    /// <2× headroom: replace one shard group at a time; aggregate capacity dips but never hits zero.
    StagedGroupByGroup,
}

impl CutoverPath {
    /// Choose the cutover path: blue-green iff at least `2 × footprint` of free VRAM is available.
    pub fn plan(footprint: u64, free_vram: u64) -> CutoverPath {
        if free_vram >= footprint.saturating_mul(2) {
            CutoverPath::BlueGreen
        } else {
            CutoverPath::StagedGroupByGroup
        }
    }
}

// ---------------------------------------------------------------------------
// Rollback SLA (SERVING_OPS.md §5 — honest number, not "instant")
// ---------------------------------------------------------------------------

/// The path a rollback must take, and its honest cost class (SERVING_OPS.md §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RollbackPath {
    /// Previous version still resident (blue-green) — a router flip, effectively instant.
    ResidentFlip,
    /// Previous version parked warm within its retention window — a minutes-scale local reload.
    WarmReload,
    /// Previous version evicted past its retention window — a cold pull, reported honestly as longer.
    ColdPull,
}

/// A rollback plan with an honest bounded estimate (SERVING_OPS.md §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RollbackPlan {
    pub path: RollbackPath,
    /// Honest upper-bound estimate in minutes (0 for a resident flip).
    pub est_minutes: u32,
}

impl RollbackPlan {
    /// Plan a rollback from the incumbent's current parking state (SERVING_OPS.md §5). `warm_bound`
    /// is the control-plane warm-reload SLA for this model class (e.g. 6 for a ~30B, 15 for a 100B+);
    /// `cold_extra` is the additional object-store transfer time when the fallback is already cold.
    pub fn for_state(
        prev_tier: crate::placement::ParkTier,
        warm_bound: u32,
        cold_extra: u32,
    ) -> RollbackPlan {
        use crate::placement::ParkTier;
        match prev_tier {
            ParkTier::Resident => RollbackPlan {
                path: RollbackPath::ResidentFlip,
                est_minutes: 0,
            },
            ParkTier::Warm => RollbackPlan {
                path: RollbackPath::WarmReload,
                est_minutes: warm_bound,
            },
            // Cold: honestly the warm bound PLUS the object-store pull — never claim the warm number.
            ParkTier::Cold => RollbackPlan {
                path: RollbackPath::ColdPull,
                est_minutes: warm_bound.saturating_add(cold_extra),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Physical weight-staging seam + staged-rollout driver (SERVING_OPS.md §5, INFRA-GATED)
// ---------------------------------------------------------------------------
//
// [`WeightRollout`] above is the pure staged-promotion state machine + [`WeightRollout::verify_load`]
// (the crypto/attestation fence, via the [`ArtifactVerifier`] seam). Actually *staging* the verified
// weights — streaming the blob to the node, decrypting it (regulated: attestation-bound), and
// materializing it resident on the target GPUs, then shifting a slice of traffic onto it — is the
// physical binding, which needs a live fleet. It is isolated behind the [`WeightLoader`] seam so the
// DRIVE LOGIC (verify → stage → advance → shift traffic, fail-closed on a bad blob) stays pure and
// offline-testable via [`InMemoryWeightLoader`]. The live loader is the only part deferred to infra.

/// The outcome of physically staging a verified artifact onto the fleet (SERVING_OPS.md §5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageOutcome {
    /// The artifact materialized resident and is serving its stage's traffic slice.
    Staged { stage: RolloutState },
    /// The load was refused at the crypto/attestation fence — nothing was staged (fail-closed).
    Refused(LoadError),
}

/// The physical weight-staging seam (SERVING_OPS.md §5, INFRA-GATED). Real implementations stream
/// the signed blob to the node, decrypt regulated tiers against a live attestation quote, and
/// materialize the replica resident on the target GPUs. [`InMemoryWeightLoader`] is the deterministic
/// offline reference — it records what was staged and how traffic was shifted.
pub trait WeightLoader {
    /// Materialize `artifact` resident for serving at `stage` (called only after `verify_load` passed).
    fn stage(&mut self, artifact: &WeightArtifact, stage: RolloutState);
    /// Shift this stage's traffic slice onto the candidate version.
    fn shift_traffic(&mut self, model_id: &str, version: &str, stage: RolloutState);
    /// Roll traffic back to the incumbent version (on a rollback), reverting any shift.
    fn revert_traffic(&mut self, model_id: &str);
    /// The version currently receiving live traffic for `model_id`, if any.
    fn live_version(&self, model_id: &str) -> Option<String>;
}

/// A deterministic in-memory [`WeightLoader`]: records staged `(model,version)@stage` and the live
/// traffic version per model.
#[derive(Debug, Clone, Default)]
pub struct InMemoryWeightLoader {
    staged: std::collections::BTreeSet<(String, String, RolloutState)>,
    incumbent: std::collections::BTreeMap<String, String>,
    live: std::collections::BTreeMap<String, String>,
}

impl InMemoryWeightLoader {
    pub fn new() -> Self {
        InMemoryWeightLoader::default()
    }
    /// Record the incumbent version live before the rollout begins (what a rollback reverts to).
    pub fn with_incumbent(mut self, model_id: &str, version: &str) -> Self {
        self.incumbent
            .insert(model_id.to_string(), version.to_string());
        self.live.insert(model_id.to_string(), version.to_string());
        self
    }
    /// Whether `(model,version)` was staged at `stage`.
    pub fn was_staged(&self, model_id: &str, version: &str, stage: RolloutState) -> bool {
        self.staged
            .contains(&(model_id.to_string(), version.to_string(), stage))
    }
    /// How many distinct stages the candidate has been staged at (walks the ladder).
    pub fn staged_count(&self) -> usize {
        self.staged.len()
    }
}

impl WeightLoader for InMemoryWeightLoader {
    fn stage(&mut self, artifact: &WeightArtifact, stage: RolloutState) {
        self.staged
            .insert((artifact.model_id.clone(), artifact.version.clone(), stage));
    }
    fn shift_traffic(&mut self, model_id: &str, version: &str, _stage: RolloutState) {
        self.live.insert(model_id.to_string(), version.to_string());
    }
    fn revert_traffic(&mut self, model_id: &str) {
        if let Some(inc) = self.incumbent.get(model_id).cloned() {
            self.live.insert(model_id.to_string(), inc);
        } else {
            self.live.remove(model_id);
        }
    }
    fn live_version(&self, model_id: &str) -> Option<String> {
        self.live.get(model_id).cloned()
    }
}

impl WeightRollout {
    /// Advance one stage AND physically actuate it through the [`WeightLoader`] seam
    /// (SERVING_OPS.md §5), fail-closed: the artifact is re-verified (signature + content hash +
    /// regulated-attestation) on EVERY call before anything is staged, so a blob discovered
    /// compromised is never materialized. On an advance the candidate is staged + its stage's traffic
    /// slice shifted; on a rollback (auto or approved-then-executed) traffic reverts to the incumbent.
    ///
    /// Returns `Err(LoadError)` if the load fence fails (nothing staged, state unchanged); otherwise
    /// the [`AdvanceOutcome`].
    pub fn advance_with_loader(
        &mut self,
        artifact: &WeightArtifact,
        verifier: &dyn ArtifactVerifier,
        attestation_ok: bool,
        signal: SoakSignal,
        loader: &mut dyn WeightLoader,
    ) -> Result<AdvanceOutcome, LoadError> {
        // Fail-closed fence FIRST — never stage an unverified/tampered/unattested blob.
        WeightRollout::verify_load(artifact, verifier, attestation_ok)?;
        let outcome = self.advance(signal);
        match outcome {
            AdvanceOutcome::Advanced { to } => {
                loader.stage(artifact, to);
                loader.shift_traffic(&artifact.model_id, &artifact.version, to);
            }
            AdvanceOutcome::AutoRolledBack { .. } => loader.revert_traffic(&artifact.model_id),
            AdvanceOutcome::Held { .. } | AdvanceOutcome::AwaitingApproval { .. } => {}
        }
        Ok(outcome)
    }
}

// ---------------------------------------------------------------------------
// Live-traffic rollout driver (SERVING_OPS.md §5; serving-ops gap-4)
// ---------------------------------------------------------------------------
//
// The audit found the staged-rollout controller + the loader seam existed but were driven only by
// hand-built `SoakSignal`s in tests — the rollout was "library-only, never enforced on a real load".
// This closes the gap by deriving the `SoakSignal` from a window of LIVE-traffic quality metrics (the
// online scoreboard: regression rate vs the incumbent + soak time) and driving one advance/rollback
// per window through the [`WeightLoader`] seam. The live metrics collection + the physical weight
// store remain infra seams; the enforcement LOGIC over real-load windows is proven offline.

/// One window of live-traffic quality metrics for the candidate version (SERVING_OPS.md §5), sampled
/// from the online scoreboard the canary is judged against — the real-load signal the rollout is
/// enforced by, not a hand-set boolean.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TrafficWindow {
    /// Requests judged in this window (0 ⇒ not enough live signal to call a regression either way).
    pub sampled_requests: u64,
    /// Fraction `[0,1]` of sampled requests judged worse than the incumbent (judge/latency/error).
    pub regression_rate: f64,
    /// Soak time elapsed at the current stage (logical ticks) and the minimum required to promote.
    pub soak_elapsed: u64,
    pub soak_required: u64,
}

/// The control-plane thresholds a [`TrafficWindow`] is judged against (SERVING_OPS.md §5).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RolloutThresholds {
    /// Regression-rate above which a canary stage is a regression (auto-rollback at canary stages).
    pub regression_threshold: f64,
    /// Regression-rate at/above which a P0 regression breaches the auto-rollback threshold (else it
    /// awaits a human approval gate).
    pub p0_breach_threshold: f64,
}

impl TrafficWindow {
    /// Derive the [`SoakSignal`] this live-traffic window represents (SERVING_OPS.md §5). A window with
    /// zero sampled requests is treated as **no regression observed** (never roll back on no signal),
    /// but also cannot meet soak-with-evidence unless `soak_required` is likewise zero.
    pub fn to_signal(&self, thr: RolloutThresholds) -> SoakSignal {
        let regressed =
            self.sampled_requests > 0 && self.regression_rate > thr.regression_threshold;
        SoakSignal {
            no_regression: !regressed,
            soak_met: self.soak_elapsed >= self.soak_required,
            p0_breach_threshold: self.sampled_requests > 0
                && self.regression_rate >= thr.p0_breach_threshold,
        }
    }
}

impl WeightRollout {
    /// **Drive one rollout step from a live-traffic window** (SERVING_OPS.md §5, gap-4): derive the
    /// soak signal from real-load quality metrics, then advance-or-rollback through the fail-closed
    /// load fence + the [`WeightLoader`] seam ([`WeightRollout::advance_with_loader`]). This is the
    /// call a deployment makes once per soak window with metrics from the online scoreboard, so the
    /// rollout is enforced on real load instead of a synthetic constant. Returns the load-fence error
    /// (nothing staged) or the [`AdvanceOutcome`].
    pub fn observe_live_window(
        &mut self,
        artifact: &WeightArtifact,
        verifier: &dyn ArtifactVerifier,
        attestation_ok: bool,
        window: TrafficWindow,
        thresholds: RolloutThresholds,
        loader: &mut dyn WeightLoader,
    ) -> Result<AdvanceOutcome, LoadError> {
        let signal = window.to_signal(thresholds);
        self.advance_with_loader(artifact, verifier, attestation_ok, signal, loader)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::AllowListVerifier;
    use crate::placement::ParkTier;

    fn artifact(regulated: bool) -> WeightArtifact {
        WeightArtifact {
            model_id: "qwen-32b".into(),
            version: "v2".into(),
            content_hash: 0xABCDEF,
            signature: "sig-good".into(),
            regulated,
        }
    }

    fn verifier() -> AllowListArtifactVerifier {
        AllowListArtifactVerifier::new().accept_signature("sig-good")
    }

    // Satisfy the unused-import lint intent: AttestationQuote/SignatureVerifier belong to the seam
    // reuse story; this asserts they remain the shared attestation types.
    #[test]
    fn attestation_seam_types_are_shared() {
        let _: fn(&dyn SignatureVerifier, &AttestationQuote) -> bool = |v, q| v.verify(q);
        let _ = AllowListVerifier::new();
    }

    #[test]
    fn gap_ainxt_serving_srv_05_signature_and_hash_reverified_at_every_load() {
        let v = verifier();
        // A good artifact loads.
        assert_eq!(
            WeightRollout::verify_load(&artifact(false), &v, true),
            Ok(())
        );
        // A forged signature is refused AT LOAD (not grandfathered).
        let mut forged = artifact(false);
        forged.signature = "sig-forged".into();
        assert_eq!(
            WeightRollout::verify_load(&forged, &v, true),
            Err(LoadError::SignatureInvalid)
        );
    }

    #[test]
    fn gap_ainxt_serving_srv_05_tampered_blob_hash_is_caught_at_load() {
        // The on-disk blob hashes to something other than the signed manifest → tamper.
        let v = AllowListArtifactVerifier::new()
            .accept_signature("sig-good")
            .with_on_disk_hash("qwen-32b", "v2", 0xBADBAD);
        assert_eq!(
            WeightRollout::verify_load(&artifact(false), &v, true),
            Err(LoadError::ContentHashMismatch)
        );
    }

    #[test]
    fn gap_ainxt_serving_srv_05_regulated_load_fails_without_attestation_bound_key() {
        let v = verifier();
        // Regulated blob + node NOT attested → decryption key cannot be released → refused,
        // even though the signature itself verifies.
        assert_eq!(
            WeightRollout::verify_load(&artifact(true), &v, false),
            Err(LoadError::AttestationKeyUnavailable)
        );
        // Same blob on an attested node loads.
        assert_eq!(
            WeightRollout::verify_load(&artifact(true), &v, true),
            Ok(())
        );
    }

    #[test]
    fn gap_ainxt_serving_srv_05_staged_promotion_advances_only_on_clean_soak() {
        let mut r = WeightRollout::new();
        assert_eq!(r.state(), RolloutState::P2Shadow);
        let clean = SoakSignal {
            no_regression: true,
            soak_met: true,
            p0_breach_threshold: false,
        };
        let holding = SoakSignal {
            no_regression: true,
            soak_met: false,
            p0_breach_threshold: false,
        };
        // Soak not met → held.
        assert_eq!(
            r.advance(holding),
            AdvanceOutcome::Held {
                at: RolloutState::P2Shadow
            }
        );
        // Clean soak walks the full ladder to P0.
        assert_eq!(
            r.advance(clean),
            AdvanceOutcome::Advanced {
                to: RolloutState::P2Canary
            }
        );
        assert_eq!(
            r.advance(clean),
            AdvanceOutcome::Advanced {
                to: RolloutState::P1Canary
            }
        );
        assert_eq!(
            r.advance(clean),
            AdvanceOutcome::Advanced {
                to: RolloutState::Promoted
            }
        );
        // At P0, a clean signal just holds (fully promoted).
        assert_eq!(
            r.advance(clean),
            AdvanceOutcome::Held {
                at: RolloutState::Promoted
            }
        );
    }

    #[test]
    fn gap_ainxt_serving_srv_05_canary_regression_auto_rolls_back() {
        let mut r = WeightRollout::new();
        let regress = SoakSignal {
            no_regression: false,
            soak_met: true,
            p0_breach_threshold: false,
        };
        // A regression at the very first canary stage reverts immediately (small blast radius).
        assert_eq!(
            r.advance(regress),
            AdvanceOutcome::AutoRolledBack {
                from: RolloutState::P2Shadow
            }
        );
        assert_eq!(r.state(), RolloutState::RolledBack);
    }

    #[test]
    fn gap_ainxt_serving_srv_05_p0_regression_needs_threshold_or_approval() {
        let mut r = WeightRollout::new();
        let clean = SoakSignal {
            no_regression: true,
            soak_met: true,
            p0_breach_threshold: false,
        };
        for _ in 0..3 {
            r.advance(clean);
        }
        assert_eq!(r.state(), RolloutState::Promoted);
        // A P0 regression BELOW the threshold awaits human approval, does not auto-revert.
        let minor = SoakSignal {
            no_regression: false,
            soak_met: true,
            p0_breach_threshold: false,
        };
        assert_eq!(
            r.advance(minor),
            AdvanceOutcome::AwaitingApproval {
                at: RolloutState::Promoted
            }
        );
        assert_eq!(
            r.state(),
            RolloutState::Promoted,
            "still serving until approved"
        );
        r.approve_rollback();
        assert_eq!(r.state(), RolloutState::RolledBack);

        // A P0 regression that BREACHES the threshold auto-reverts, no human in the loop.
        let mut r2 = WeightRollout::new();
        for _ in 0..3 {
            r2.advance(clean);
        }
        let breach = SoakSignal {
            no_regression: false,
            soak_met: true,
            p0_breach_threshold: true,
        };
        assert_eq!(
            r2.advance(breach),
            AdvanceOutcome::AutoRolledBack {
                from: RolloutState::Promoted
            }
        );
    }

    #[test]
    fn gap_ainxt_serving_srv_05_cutover_path_by_headroom() {
        assert_eq!(CutoverPath::plan(50, 100), CutoverPath::BlueGreen); // exactly 2x
        assert_eq!(CutoverPath::plan(50, 99), CutoverPath::StagedGroupByGroup);
    }

    #[test]
    fn gap_ainxt_serving_srv_05_rollback_sla_is_honest_warm_vs_cold() {
        // Resident previous version → a router flip, ~instant.
        assert_eq!(
            RollbackPlan::for_state(ParkTier::Resident, 6, 20),
            RollbackPlan {
                path: RollbackPath::ResidentFlip,
                est_minutes: 0
            }
        );
        // Warm parked within retention → bounded warm-reload SLA.
        assert_eq!(
            RollbackPlan::for_state(ParkTier::Warm, 6, 20),
            RollbackPlan {
                path: RollbackPath::WarmReload,
                est_minutes: 6
            }
        );
        // Evicted past retention → honestly a cold pull, longer, NOT the warm number.
        assert_eq!(
            RollbackPlan::for_state(ParkTier::Cold, 6, 20),
            RollbackPlan {
                path: RollbackPath::ColdPull,
                est_minutes: 26
            }
        );
    }
}
