// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! §15 short-TTL JIT **renew-and-re-attest** made drivable on a **chat run** (ADR-022 §15 + §17/§19).
//!
//! # The gap this closes
//!
//! The identity crate already implements the §15 short-TTL renew-and-re-attest and the fused
//! per-dispatch [`ControlPlane::authorize_dispatch`] entrypoint (JIT renew → in-flight admission), and
//! the **Program** served path drives credential renewal per module (`run_program_verified`). But the
//! **chat** served path (`ChatSurface` over the `SessionManager` spine) minted no per-Run credential
//! and never drove §15 — a long multi-turn chat run was, from the identity plane's view, a single
//! standing (un-renewed, un-re-attested) grant, and a mid-run kill-switch / revocation would not reach
//! its next turn.
//!
//! [`GovernedChatSurface`] is the wire: a [`TurnHandler`] that wraps the grounded chat handler and, on
//! **every turn of a chat run**, drives [`ControlPlane::authorize_dispatch`] for that session's
//! short-TTL credential:
//!
//! 1. **JIT renew-and-re-attest (§15).** As the run's logical clock advances past the renew-ahead
//!    margin, a fresh short-TTL credential is minted — re-attested against the reference values and
//!    re-checked against the *shared* deny-state — so a long chat run is a chain of re-authorized
//!    identities, never one standing token.
//! 2. **In-flight admission (§17/§19).** A kill-switch / run-revocation / OBO-revocation pulled on the
//!    shared control plane mid-run **denies the next turn immediately** (fail-closed: the model turn
//!    never starts), not merely at the next renewal.
//! 3. **OBO confused-deputy authorization (Pass-5 [AI], ADR-022 §12, `ainxt_identity::authz`).** Once
//!    admitted, the turn's [`RunAuthorization`] is rooted at the REAL authenticated principal (its
//!    actual JWT capability set) and the just-(re)admitted credential, then checked for `chat.send`.
//!    [`RunAuthorization`]/`authorize_str` were fully implemented and unit-tested in `ainxt-identity`
//!    but had ZERO callers anywhere in the served daemon — nothing turned the delegation-chain algebra
//!    into a live per-dispatch decision, so a human whose own JWT happened to carry a reserved
//!    payment-initiation verb (any of [`ainxt_identity::RESERVED_PAYMENT_INITIATION_CAPABILITIES`])
//!    could still have an agent run turns "on their behalf" with the grant-layer confused-deputy check
//!    never actually exercised. A structurally invalid chain (reserved verb / expiry / cycle) denies
//!    the turn fail-closed, exactly the same posture as the §17/§19 admission gate above.
//!
//! This is **additive and config-selectable** (`assemble_chat_governed`) — it does NOT change the
//! default `/v1/chat` surface or the default authenticator. The identity crate reads no wall clock;
//! logical time is supplied by the surface (a per-session turn clock), so the renewal cadence is
//! deterministic and testable.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ainxt_identity::authority::{
    AgentWorkloadCredential, AttestationQuote, ControlPlaneProjection, IdentityAuthority,
    IssueError, IssueRequest, ReferenceValueVerifier,
};
use ainxt_identity::authz::{AuthzDecision, RunAuthorization};
use ainxt_identity::control::{ControlPlane, DispatchOutcome, RunLease};
use ainxt_identity::transparency::{IssuanceEntry, Sha256Hasher, TransparencyLog};
use ainxt_identity::LogicalTime;
use ainxt_protocol::{Event, Request};
use ainxt_runtime::{CancelToken, TurnError, TurnHandler, TurnSummary};
use tokio::sync::mpsc;

use ainxt_types::Principal;

/// The composition-local attested measurement the chat run's short-TTL credential is minted against.
const CHAT_MEASUREMENT: &str = "runtimed-attested-chat-workload";
/// The control-plane commit the composition-local projection pins (reproducibility anchor).
const CHAT_COMMIT: &str = "runtimed-composition";

/// The renew cadence knobs for a chat run's short-TTL credential (§15). Small logical values so a
/// multi-turn chat run exercises the renew-and-re-attest chain; a deployment tunes them to the
/// deployed AWC TTL. The crate reads no clock — the surface advances a per-session logical turn clock.
#[derive(Debug, Clone, Copy)]
pub struct ChatIdentityPolicy {
    /// Short TTL (logical ticks) of each minted credential.
    pub ttl: u64,
    /// Renew when `now` is within this many ticks of expiry (§15 renew-ahead).
    pub renew_ahead: u64,
    /// Logical ticks the run clock advances per turn.
    pub ticks_per_turn: u64,
}

impl Default for ChatIdentityPolicy {
    fn default() -> Self {
        ChatIdentityPolicy {
            ttl: 3,
            renew_ahead: 1,
            ticks_per_turn: 1,
        }
    }
}

/// Per-session identity state for a chat run: the minting authority, the attestation quote (re-used
/// for re-attestation on each renewal), the current credential, the renew lease, the run's logical
/// turn clock, and observability counters.
struct SessionIdentity {
    aia: IdentityAuthority<ReferenceValueVerifier>,
    quote: AttestationQuote,
    cred: AgentWorkloadCredential,
    lease: RunLease,
    clock: u64,
    renewals: u64,
    denied: bool,
}

/// A [`TurnHandler`] that drives §15 short-TTL JIT renew-and-re-attest + §17/§19 in-flight admission
/// on every turn of a chat run, then delegates to an inner grounded chat handler. See the module docs.
pub struct GovernedChatSurface {
    inner: Arc<dyn TurnHandler>,
    control: Arc<Mutex<ControlPlane>>,
    def_kind: String,
    def_id: String,
    def_version: String,
    policy: ChatIdentityPolicy,
    sessions: Mutex<HashMap<String, SessionIdentity>>,
    /// GAP-FIX identity-payments (ADR-022 §13) — the append-only, HMAC-signed issuance transparency
    /// log `assemble_program_surface_with_transparency`/`assemble_team_surface_with_transparency`
    /// already wire for the Program/Team surfaces. `GovernedChatSurface` mints/renews AWCs (§15) on
    /// every chat turn but, before this fix, never appended to any transparency log — a chat run's
    /// credential issuance had zero external-auditor inclusion-proof-verifiable record, unlike the
    /// SAME class of event on Program/Team. `None` (the composition's air-gapped default, no HMAC key
    /// provisioned) keeps this a no-op — byte-identical pre-wire behavior for `assemble_chat_governed`
    /// callers that never reach for [`Self::with_transparency_log`].
    transparency: Option<Arc<Mutex<TransparencyLog<Sha256Hasher>>>>,
}

impl GovernedChatSurface {
    /// Wrap `inner` so every chat turn is identity-governed against the shared `control` plane. The
    /// per-Run credential is minted for definition `def:<def_kind>/chat@v1`.
    pub fn new(
        inner: Arc<dyn TurnHandler>,
        control: Arc<Mutex<ControlPlane>>,
        def_kind: impl Into<String>,
    ) -> Self {
        GovernedChatSurface {
            inner,
            control,
            def_kind: def_kind.into(),
            def_id: "chat".into(),
            def_version: "v1".into(),
            policy: ChatIdentityPolicy::default(),
            sessions: Mutex::new(HashMap::new()),
            transparency: None,
        }
    }

    /// Override the default renew cadence (§15) — e.g. to match a deployed AWC TTL.
    pub fn with_policy(mut self, policy: ChatIdentityPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// GAP-FIX identity-payments (ADR-022 §13) — wire the SAME append-only issuance transparency log
    /// the Program/Team surfaces use (`ProgramSurface::with_transparency_log`/
    /// `TeamSurface::with_transparency_log`) into this chat surface's AWC issuance path. Every
    /// NEWLY-MINTED chat-run credential (`mint_session`, at run start) is appended — mirroring
    /// exactly what the Program/Team surfaces log (the initial issuance, not each §15 renewal).
    pub fn with_transparency_log(mut self, log: Arc<Mutex<TransparencyLog<Sha256Hasher>>>) -> Self {
        self.transparency = Some(log);
        self
    }

    fn def_ref(&self) -> String {
        format!("def:{}/{}@{}", self.def_kind, self.def_id, self.def_version)
    }

    /// Mint the chat run's FIRST short-TTL credential JIT at run start, gated on the SHARED control
    /// plane (`issue_jit`): an en-masse kill-switch or a revoked OBO human refuses a brand-new chat
    /// run, exactly as it refuses a renewal.
    fn mint_session(
        &self,
        principal: &Principal,
        req: &Request,
    ) -> Result<SessionIdentity, IssueError> {
        let verifier = ReferenceValueVerifier::new().with_measurement(CHAT_MEASUREMENT);
        let projection = ControlPlaneProjection::new([self.def_ref()], LogicalTime(0), CHAT_COMMIT);
        let mut aia = IdentityAuthority::new(
            verifier,
            projection,
            self.policy.ttl,
            u64::MAX,
            "runtimed-chat-key-v1",
        );
        let quote = AttestationQuote {
            def_content_hash: format!("hash-{}-{}", self.def_id, self.def_version),
            control_commit_sha: CHAT_COMMIT.into(),
            measurement: CHAT_MEASUREMENT.into(),
            tee_quote: None,
        };
        let issue_req = IssueRequest {
            def_kind: self.def_kind.clone(),
            def_id: self.def_id.clone(),
            def_version: self.def_version.clone(),
            run_id: req.session.clone(),
            data_class: req.data_class,
            requires_tee: false,
            obo_user_id: principal.user_id.clone(),
            obo_department: principal.department.clone(),
            obo_ad_level: None,
            obo_can_approve: false,
        };
        // JIT mint at the run's first logical tick, gated on the shared deny-state.
        let cred = {
            let cp = self.control.lock().expect("control plane lock");
            cp.issue_jit(&mut aia, &issue_req, &quote, LogicalTime(1))?
        };
        Ok(SessionIdentity {
            aia,
            quote,
            cred,
            lease: RunLease::new(self.policy.renew_ahead),
            clock: 1,
            renewals: 0,
            denied: false,
        })
    }

    /// Total §15 renewals performed across all chat runs this surface has governed (observability).
    pub fn total_renewals(&self) -> u64 {
        self.sessions
            .lock()
            .expect("sessions lock")
            .values()
            .map(|s| s.renewals)
            .sum()
    }

    /// §15 renewals performed on one chat run so far (observability / tests).
    pub fn renewals_for(&self, session: &str) -> u64 {
        self.sessions
            .lock()
            .expect("sessions lock")
            .get(session)
            .map(|s| s.renewals)
            .unwrap_or(0)
    }

    /// The current per-Run credential for a chat run (its `issued_at` advances on each re-attestation).
    pub fn credential_for(&self, session: &str) -> Option<AgentWorkloadCredential> {
        self.sessions
            .lock()
            .expect("sessions lock")
            .get(session)
            .map(|s| s.cred.clone())
    }
}

impl TurnHandler for GovernedChatSurface {
    fn handle_turn<'a>(
        &'a self,
        principal: &'a Principal,
        req: &'a Request,
        sink: mpsc::Sender<Event>,
        cancel: &'a CancelToken,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<TurnSummary, TurnError>> + Send + 'a>,
    > {
        Box::pin(async move {
            // Stage A — §15 renew-and-re-attest + §17/§19 admission, computed under the locks and then
            // RELEASED before any await (std Mutex guards must never be held across `.await`).
            let gate: Result<(), String> = {
                let mut sessions = self.sessions.lock().expect("sessions lock");
                // JIT-mint this chat run's first credential if new (gated on the shared plane).
                let mint_err = if sessions.contains_key(&req.session) {
                    None
                } else {
                    match self.mint_session(principal, req) {
                        Ok(sid) => {
                            // GAP-FIX identity-payments (ADR-022 §13) — append the newly-minted
                            // chat-run credential to the SAME transparency log Program/Team already
                            // feed, so an external auditor's inclusion-proof-verifiable record
                            // covers chat-run issuance too, not only Program/Team.
                            if let Some(log) = &self.transparency {
                                log.lock()
                                    .expect("transparency log mutex poisoned")
                                    .append(IssuanceEntry::from_awc(&sid.cred));
                            }
                            sessions.insert(req.session.clone(), sid);
                            None
                        }
                        Err(e) => Some(format!("chat run identity refused at issuance: {e}")),
                    }
                };
                match mint_err {
                    Some(msg) => Err(msg),
                    None => {
                        let sid = sessions.get_mut(&req.session).expect("session present");
                        // Advance the run's logical turn clock and drive the fused §15+§17/§19 entrypoint.
                        sid.clock = sid.clock.saturating_add(self.policy.ticks_per_turn);
                        let now = LogicalTime(sid.clock);
                        let outcome = {
                            let cp = self.control.lock().expect("control plane lock");
                            cp.authorize_dispatch(
                                &sid.aia,
                                &sid.cred,
                                &sid.lease,
                                Some(&sid.quote),
                                now,
                            )
                        };
                        match outcome {
                            DispatchOutcome::Proceed {
                                credential,
                                renewed,
                            } => {
                                if renewed {
                                    sid.renewals = sid.renewals.saturating_add(1);
                                }
                                // Act under the (possibly freshly re-attested) credential — the actor of record.
                                sid.cred = credential;
                                // GAP-FIX regulated-fi-responsible-lifecycle (Pass-5 [AI] confused-deputy,
                                // `ainxt_identity::authz::RunAuthorization`) — see the module doc. Root the
                                // OBO chain at the turn's REAL principal (its actual granted capabilities,
                                // not a derived/narrowed one) and the just-(re)admitted credential; the
                                // grant window is the credential's own short TTL, so it can never outlive
                                // the identity it is attached to. A reserved payment-initiation verb
                                // anywhere in the principal's own capabilities makes the chain structurally
                                // invalid, denying EVERY turn fail-closed (confused-deputy closed at the
                                // grant layer, not merely by a downstream dispatch arm's absence).
                                let authz = RunAuthorization::root_from_principal(
                                    principal,
                                    &sid.cred,
                                    sid.cred.expires_at,
                                );
                                match authz.authorize_str("chat.send", now) {
                                    AuthzDecision::Allow { .. } => Ok(()),
                                    AuthzDecision::Deny(denial) => {
                                        sid.denied = true;
                                        Err(format!(
                                            "chat turn denied by OBO authorization: {denial}"
                                        ))
                                    }
                                }
                            }
                            DispatchOutcome::Deny(d) => {
                                sid.denied = true;
                                Err(format!("chat turn denied by control plane: {d}"))
                            }
                        }
                    }
                }
            };

            if let Err(msg) = gate {
                // Fail-closed: the model turn never starts (a mid-run kill-switch/revocation, or a
                // refused issuance/renewal). Compliance redact-and-proceed is unrelated — this is an
                // identity admission denial, not a content decision.
                let _ = sink.send(Event::Error(msg.clone())).await;
                let _ = sink.send(Event::Done).await;
                return Err(TurnError::Denied(msg));
            }

            // Stage B — the identity is valid & admitted: run the real grounded chat turn.
            self.inner.handle_turn(principal, req, sink, cancel).await
        })
    }
}
