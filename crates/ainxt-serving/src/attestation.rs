// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Node-level hardware attestation gate (SERVING_OPS.md §8, ADR-021).
//!
//! A **second, node-level admission gate underneath** the Model Router's model-identity gate
//! (ADR-012). The Router decides *which model* may see regulated data; this gate decides *whether
//! the physical node the model is loaded on is trusted enough to be shown that data at all*.
//! Plaintext prompts/activations/KV for a regulated turn sit in GPU memory during inference, and
//! GPU memory is by default visible to the hypervisor/operator — "it's an in-house model" says
//! nothing about that exposure (ADR-021 §8.1). This gate closes exactly that.
//!
//! What is real here (pure, deterministic — no clock, no crypto lib, no network):
//!
//! * **Trust tiers** ([`TrustTier`]): `cc-enclave` / `bare-metal-attested` (regulated-eligible) and
//!   `untrusted` (public/internal only).
//! * **Reference-value allow-list** ([`ReferenceValues`]): git-native golden hashes for approved
//!   firmware / driver / serving-binary versions. A quote whose measurements are validly *signed*
//!   but not allow-listed **still fails** — this is what catches an unauthorized *downgrade* to an
//!   old-but-validly-signed firmware, not just an outright forgery (ADR-021 §8.3).
//! * **Firmware provenance → whole-node quarantine** (ADR-021 §8.4): an unrecognized firmware hash
//!   is a whole-node integrity question, so it quarantines the node from the *entire* fleet, not
//!   just the regulated pool.
//! * **Grace-TTL** ([`AttestationConfig::grace_ttl`], ADR-021 §8.3): if the Attestation Verifier is
//!   unreachable, a node keeps its last valid quote for a short, bounded window — long enough to
//!   ride out a verifier blip, short enough that stale trust cannot silently drift for hours. Past
//!   the grace window, and *immediately* if the verifier is reachable but the quote is simply
//!   overdue, the node auto-drains from the regulated pool — **fail-closed, never fail-open**.
//!
//! The signature-verification crypto itself is a **seam** ([`SignatureVerifier`]) — real quote
//! signatures chain to a hardware root key, which needs a crypto backend this pure crate does not
//! carry. A deterministic, non-tautological [`AllowListVerifier`] models it for tests and for a
//! deployment that injects its own.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use ainxt_types::DataClass;

// ---------------------------------------------------------------------------
// Trust tiers (ADR-021 §8.2)
// ---------------------------------------------------------------------------

/// The trust tier a GPU node is tagged with. Regulated data classes are only ever admitted to the
/// top two; `untrusted` is public/internal only, *regardless of which model is loaded on it*.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TrustTier {
    /// Generic burst/cloud capacity, no attestation. Public/internal only.
    Untrusted,
    /// operator-owned physical hardware, measured boot + TPM-backed quote, no hypervisor to trust.
    BareMetalAttested,
    /// GPU confidential-computing mode: hardware memory encryption + hypervisor isolation, quote
    /// chained to the manufacturer's hardware root key.
    CcEnclave,
}

impl TrustTier {
    /// Whether this tier may ever be admitted for a regulated (confidential+) data class.
    pub fn is_regulated_eligible(self) -> bool {
        matches!(self, TrustTier::CcEnclave | TrustTier::BareMetalAttested)
    }
}

// ---------------------------------------------------------------------------
// Measurements + reference-value allow-list (ADR-021 §8.2/§8.3)
// ---------------------------------------------------------------------------

/// The measured state a quote attests to. Golden values for each field live in an allow-list.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct Measurements {
    /// Firmware/BIOS measurement hash (also the §8.4 supply-chain provenance signal).
    pub firmware_hash: String,
    /// GPU/driver version measurement.
    pub driver_version: String,
    /// Loaded serving-binary hash.
    pub binary_hash: String,
}

/// A signed attestation quote produced by a node's attestation agent (ADR-021 §8.3).
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct AttestationQuote {
    pub node_id: String,
    pub tier: TrustTier,
    pub measurements: Measurements,
    /// The detached signature over the quote (opaque here; the crypto is the [`SignatureVerifier`]
    /// seam).
    pub signature: String,
}

/// The git-native, PR-reviewed reference-value allow-list (ADR-026 §2 / ADR-021 §8.3): golden
/// hashes for approved firmware / driver / serving-binary versions. Verification requires **all
/// three** to be allow-listed; a valid signature over a non-allow-listed measurement still fails.
#[derive(Debug, Clone, Default)]
pub struct ReferenceValues {
    approved_firmware: BTreeSet<String>,
    approved_drivers: BTreeSet<String>,
    approved_binaries: BTreeSet<String>,
}

impl ReferenceValues {
    pub fn new() -> Self {
        ReferenceValues::default()
    }

    pub fn allow_firmware(mut self, hash: impl Into<String>) -> Self {
        self.approved_firmware.insert(hash.into());
        self
    }
    pub fn allow_driver(mut self, ver: impl Into<String>) -> Self {
        self.approved_drivers.insert(ver.into());
        self
    }
    pub fn allow_binary(mut self, hash: impl Into<String>) -> Self {
        self.approved_binaries.insert(hash.into());
        self
    }

    pub fn firmware_ok(&self, hash: &str) -> bool {
        self.approved_firmware.contains(hash)
    }
    pub fn driver_ok(&self, ver: &str) -> bool {
        self.approved_drivers.contains(ver)
    }
    pub fn binary_ok(&self, hash: &str) -> bool {
        self.approved_binaries.contains(hash)
    }
}

// ---------------------------------------------------------------------------
// Signature-verification seam
// ---------------------------------------------------------------------------

/// The quote-signature verification seam (ADR-021 §8.3 step 2). Real verification chains the
/// signature to the hardware manufacturer's root key — a crypto backend this pure crate does not
/// carry. Implementations are injected by the deployment; [`AllowListVerifier`] models it
/// deterministically for tests.
pub trait SignatureVerifier {
    /// True iff `quote`'s signature verifies against a trusted hardware root.
    fn verify(&self, quote: &AttestationQuote) -> bool;
}

/// A deterministic reference verifier: a signature verifies iff it is in the injected set of
/// accepted signatures. Real set-membership (not a tautology) — an unaccepted signature is
/// genuinely rejected — while keeping the real hardware-root crypto as the seam.
#[derive(Debug, Clone, Default)]
pub struct AllowListVerifier {
    accepted: BTreeSet<String>,
}

impl AllowListVerifier {
    pub fn new() -> Self {
        AllowListVerifier::default()
    }
    pub fn accept(mut self, signature: impl Into<String>) -> Self {
        self.accepted.insert(signature.into());
        self
    }
}

impl SignatureVerifier for AllowListVerifier {
    fn verify(&self, quote: &AttestationQuote) -> bool {
        self.accepted.contains(&quote.signature)
    }
}

// ---------------------------------------------------------------------------
// Errors / verdicts
// ---------------------------------------------------------------------------

/// Why a submitted quote was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmitError {
    /// The signature did not verify against a trusted root.
    SignatureInvalid,
    /// The firmware hash is not on the allow-list — a whole-node integrity failure that
    /// **quarantines the entire node** (ADR-021 §8.4), not just its regulated eligibility.
    FirmwareNotAllowListed,
    /// Driver or binary measurement is not on the allow-list (regulated eligibility denied, but no
    /// full quarantine).
    MeasurementNotAllowListed,
    /// The quote claims the `untrusted` tier — that tier is never regulated-eligible, so recording
    /// it as an attested quote would be meaningless.
    UntrustedTierQuote,
}

impl fmt::Display for SubmitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SubmitError::SignatureInvalid => f.write_str("attestation signature did not verify"),
            SubmitError::FirmwareNotAllowListed => {
                f.write_str("firmware hash not allow-listed — node quarantined")
            }
            SubmitError::MeasurementNotAllowListed => {
                f.write_str("driver/binary measurement not allow-listed")
            }
            SubmitError::UntrustedTierQuote => {
                f.write_str("untrusted-tier node cannot present an attested quote")
            }
        }
    }
}

impl std::error::Error for SubmitError {}

/// The node-admission decision for one `(node, data_class)` at a logical time (ADR-021 §8.2/§8.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeVerdict {
    /// Admitted on a currently-fresh quote (or the class needs no attestation).
    Admitted { tier: TrustTier },
    /// Admitted on the bounded grace-TTL because the verifier is unreachable and the quote,
    /// though past its normal freshness window, is still within grace (ADR-021 §8.3 step 4).
    AdmittedOnGrace {
        tier: TrustTier,
        grace_expires_at: u64,
    },
    /// Denied — regulated traffic is fenced off this node. The node may still serve
    /// public/internal traffic unless the reason is [`DenyReason::Quarantined`].
    Denied { reason: DenyReason },
}

impl NodeVerdict {
    pub fn is_admitted(&self) -> bool {
        matches!(
            self,
            NodeVerdict::Admitted { .. } | NodeVerdict::AdmittedOnGrace { .. }
        )
    }
}

/// Why regulated admission to a node was denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    /// The whole node is quarantined (firmware provenance failure) — denied for ALL classes.
    Quarantined,
    /// The node's tier is `untrusted` — never regulated-eligible.
    UntrustedTier,
    /// No attested quote has ever been recorded for this node.
    NoValidQuote,
    /// The last quote is past its freshness window and either the verifier is reachable (an
    /// overdue re-attestation) or the grace-TTL has also elapsed.
    QuoteExpired,
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

/// Attestation gate configuration (ADR-021 §8.3). Both are logical-tick durations (deterministic).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttestationConfig {
    /// How long a verified quote is considered fresh before re-attestation is required.
    pub quote_ttl: u64,
    /// The extra window a node may keep serving regulated traffic on a stale quote **while the
    /// verifier is unreachable** (ADR-021 §8.3 step 4). Zero disables grace (strict fail-closed).
    pub grace_ttl: u64,
}

#[derive(Debug, Clone)]
struct VerifiedQuote {
    tier: TrustTier,
    verified_at: u64,
}

/// The node attestation gate (ADR-021 §8). Holds the last verified quote per node and the set of
/// quarantined nodes; answers [`AttestationGate::evaluate`] for a `(node, data_class, now,
/// verifier_reachable)` — the node-level admission precondition that sits underneath the Router.
#[derive(Debug, Clone)]
pub struct AttestationGate {
    cfg: AttestationConfig,
    verified: BTreeMap<String, VerifiedQuote>,
    quarantined: BTreeSet<String>,
}

impl AttestationGate {
    pub fn new(cfg: AttestationConfig) -> Self {
        AttestationGate {
            cfg,
            verified: BTreeMap::new(),
            quarantined: BTreeSet::new(),
        }
    }

    /// Submit a quote for verification (ADR-021 §8.3). On success the node's fresh-quote timestamp
    /// is updated to `now`. Ordering of checks is deliberate: signature first (a forgery is the
    /// cheapest reject), then firmware provenance (a whole-node quarantine short-circuits
    /// everything), then driver/binary allow-list.
    pub fn submit_quote(
        &mut self,
        quote: &AttestationQuote,
        now: u64,
        verifier: &dyn SignatureVerifier,
        refs: &ReferenceValues,
    ) -> Result<(), SubmitError> {
        if quote.tier == TrustTier::Untrusted {
            return Err(SubmitError::UntrustedTierQuote);
        }
        if !verifier.verify(quote) {
            return Err(SubmitError::SignatureInvalid);
        }
        // §8.4: unrecognized firmware is a whole-node integrity failure → quarantine the node.
        if !refs.firmware_ok(&quote.measurements.firmware_hash) {
            self.quarantined.insert(quote.node_id.clone());
            self.verified.remove(&quote.node_id);
            return Err(SubmitError::FirmwareNotAllowListed);
        }
        if !refs.driver_ok(&quote.measurements.driver_version)
            || !refs.binary_ok(&quote.measurements.binary_hash)
        {
            return Err(SubmitError::MeasurementNotAllowListed);
        }
        self.verified.insert(
            quote.node_id.clone(),
            VerifiedQuote {
                tier: quote.tier,
                verified_at: now,
            },
        );
        Ok(())
    }

    /// Manually clear a node's quarantine after out-of-band review (ADR-021 §8.4 — quarantine is
    /// "pending manual review", never auto-cleared by a fresh quote). Returns whether it was set.
    pub fn clear_quarantine(&mut self, node_id: &str) -> bool {
        self.quarantined.remove(node_id)
    }

    pub fn is_quarantined(&self, node_id: &str) -> bool {
        self.quarantined.contains(node_id)
    }

    /// The node-admission decision (ADR-021 §8.2/§8.3).
    ///
    /// * A quarantined node is denied for **every** class.
    /// * A class that needs no attestation (`public`/`internal`) is admitted on any node.
    /// * A regulated class (`confidential`+) requires a regulated-eligible tier **and** a quote
    ///   that is either fresh, or within grace while the verifier is unreachable. Otherwise it
    ///   **fails closed** — the node is drained from the regulated pool, never fallen back to.
    pub fn evaluate(
        &self,
        node_id: &str,
        data_class: DataClass,
        now: u64,
        verifier_reachable: bool,
    ) -> NodeVerdict {
        if self.quarantined.contains(node_id) {
            return NodeVerdict::Denied {
                reason: DenyReason::Quarantined,
            };
        }

        if !Self::needs_attestation(data_class) {
            // Non-regulated traffic runs on any non-quarantined node; report the tier if known.
            let tier = self
                .verified
                .get(node_id)
                .map(|q| q.tier)
                .unwrap_or(TrustTier::Untrusted);
            return NodeVerdict::Admitted { tier };
        }

        let Some(q) = self.verified.get(node_id) else {
            return NodeVerdict::Denied {
                reason: DenyReason::NoValidQuote,
            };
        };
        if !q.tier.is_regulated_eligible() {
            return NodeVerdict::Denied {
                reason: DenyReason::UntrustedTier,
            };
        }

        let fresh_until = q.verified_at.saturating_add(self.cfg.quote_ttl);
        if now <= fresh_until {
            return NodeVerdict::Admitted { tier: q.tier };
        }
        // Past normal freshness. Only the bounded grace path (verifier down) can save it.
        let grace_expires_at = fresh_until.saturating_add(self.cfg.grace_ttl);
        if !verifier_reachable && now <= grace_expires_at {
            return NodeVerdict::AdmittedOnGrace {
                tier: q.tier,
                grace_expires_at,
            };
        }
        NodeVerdict::Denied {
            reason: DenyReason::QuoteExpired,
        }
    }

    /// Whether a data class requires node attestation. `confidential` and everything more sensitive
    /// (`regulated-payment`, `pii`) do; `public`/`internal` do not (ADR-021 §8.2).
    pub fn needs_attestation(data_class: DataClass) -> bool {
        data_class.sensitivity() >= DataClass::Confidential.sensitivity()
    }

    /// Logical ticks until `node_id`'s verified quote expires, or `None` if it holds no quote
    /// (ADR-021 §8.3). Zero means it expires exactly now; a value <= a lead window means it is due for
    /// proactive re-attestation before the fence starts failing closed.
    pub fn ttl_remaining(&self, node_id: &str, now: u64) -> Option<u64> {
        let q = self.verified.get(node_id)?;
        Some(
            q.verified_at
                .saturating_add(self.cfg.quote_ttl)
                .saturating_sub(now),
        )
    }

    /// Whether `node_id` must be (re-)attested on this refresh tick (ADR-021 §8.3): it is not under
    /// manual-review quarantine AND either holds no quote or its quote expires within `lead` ticks.
    /// A quarantined node is never auto-refreshed — it awaits [`AttestationGate::clear_quarantine`].
    pub fn needs_refresh(&self, node_id: &str, now: u64, lead: u64) -> bool {
        if self.quarantined.contains(node_id) {
            return false;
        }
        match self.ttl_remaining(node_id, now) {
            None => true,
            Some(rem) => rem <= lead,
        }
    }
}

// ---------------------------------------------------------------------------
// Declarative attestation manifest — git-native config for the offline seams
// (ADR-021 §8.3 / ADR-026 §2; serving-ops gap-2, round-15)
// ---------------------------------------------------------------------------
//
// The audit found the shipped daemon's default wiring constructs an EMPTY `StaticQuoteSource`,
// EMPTY `AllowListVerifier`, and EMPTY `ReferenceValues` (see `ainxt-runtimed/src/main.rs`) — correct
// for the air-gapped default (nothing to attest ⇒ nothing IS attested, matching the empty serving
// pool), but there was no DECLARATIVE way for a deployment that DOES want to attest a fixed, offline
// fleet (pre-shared TEE quotes for a known set of on-prem nodes, no live quote-fetch network call) to
// populate the three seams without hand-writing Rust `with_quote`/`accept`/`allow_*` calls. This
// closes that: [`AttestationManifest`] is a plain-data, git-native-config-shaped (ADR-026 §2)
// declaration a deployment's config loader deserializes, and [`AttestationManifest::build`] is the
// ONE call that materializes it into the exact trio [`refresh_regulated_nodes`] /
// [`AttestationRefresher`] consume — replacing the three empty defaults with one line, still entirely
// offline (no live TEE, no crypto backend; the same seams as before).

/// A declarative, git-native attestation manifest (ADR-021 §8.3 / ADR-026 §2, serving-ops gap-2): the
/// reference-value allow-list, the accepted quote signatures, and — for a fixed offline fleet with no
/// live TEE network call — pre-shared static quotes, expressed as plain data instead of a sequence of
/// builder calls. A deployment's config loader deserializes this from its manifest (TOML/YAML, the
/// same git-native surface every other Serving-Ops policy uses) and calls [`Self::build`] once at
/// startup in place of the shipped default's three empty constructors.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(default)]
pub struct AttestationManifest {
    /// Firmware hashes approved for regulated eligibility (ADR-021 §8.3/§8.4).
    pub approved_firmware: Vec<String>,
    /// Driver versions approved for regulated eligibility.
    pub approved_drivers: Vec<String>,
    /// Serving-binary hashes approved for regulated eligibility.
    pub approved_binaries: Vec<String>,
    /// Quote signatures this deployment's [`AllowListVerifier`] accepts (the offline reference model
    /// of "chains to a trusted hardware root" — a real deployment injects a crypto-backed
    /// [`SignatureVerifier`] instead and may leave this empty).
    pub accepted_signatures: Vec<String>,
    /// Pre-shared quotes for a fixed, known node set — the offline reference model of a live TEE
    /// quote-fetch. A deployment with a real [`QuoteSource`] leaves this empty.
    pub quotes: Vec<AttestationQuote>,
}

impl AttestationManifest {
    pub fn new() -> Self {
        AttestationManifest::default()
    }

    /// Materialize this manifest into the three offline seams [`refresh_regulated_nodes`] /
    /// [`AttestationRefresher::tick`] consume (serving-ops gap-2): a [`StaticQuoteSource`] pre-loaded
    /// with every declared quote, an [`AllowListVerifier`] that accepts every declared signature, and
    /// [`ReferenceValues`] allow-listing every declared firmware/driver/binary. This is the single call
    /// a deployment's config loader makes in place of the shipped default's
    /// `StaticQuoteSource::new()` + `AllowListVerifier::new()` + `ReferenceValues::new()` (which
    /// together can never admit any node, by construction — the audit's "shipped inert, not merely
    /// deployed inert" finding).
    pub fn build(&self) -> (StaticQuoteSource, AllowListVerifier, ReferenceValues) {
        let mut source = StaticQuoteSource::new();
        for q in &self.quotes {
            source = source.with_quote(q.clone());
        }
        let mut verifier = AllowListVerifier::new();
        for sig in &self.accepted_signatures {
            verifier = verifier.accept(sig.clone());
        }
        let mut refs = ReferenceValues::new();
        for fw in &self.approved_firmware {
            refs = refs.allow_firmware(fw.clone());
        }
        for drv in &self.approved_drivers {
            refs = refs.allow_driver(drv.clone());
        }
        for bin in &self.approved_binaries {
            refs = refs.allow_binary(bin.clone());
        }
        (source, verifier, refs)
    }

    /// Whether this manifest can ever admit anything — the honest "still air-gapped-inert" signal a
    /// deployment's startup log can check (the same "empty ⇒ inert" pattern the serving-pool config
    /// uses): a manifest with no quotes AND no accepted signatures can never attest a single node, so
    /// building it is equivalent to (and just as inert as) the shipped default.
    pub fn is_empty(&self) -> bool {
        self.quotes.is_empty() && self.accepted_signatures.is_empty()
    }
}

// ---------------------------------------------------------------------------
// The §8.3 attestation quote-refresh loop (ADR-021 §8.3; serving-ops gap-3)
// ---------------------------------------------------------------------------
//
// The audit found the daemon declared a regulated node pool but never re-attested it: a live TEE
// quote had to be submitted by hand through `submit_quote`, so declared nodes stayed UNattested and
// regulated traffic fenced off the whole fleet forever. The pure *scheduling* of that loop — which
// declared nodes are due, and driving each through the verifier fence — is offline-testable here; only
// obtaining a hardware quote from a live TEE ([`QuoteSource::fetch_quote`]) is the infra seam.

/// The live-TEE quote-acquisition seam (ADR-021 §8.3, INFRA-GATED). A real implementation asks the
/// node's confidential-compute stack for a fresh signed attestation quote (SEV-SNP/TDX report);
/// [`StaticQuoteSource`] is the deterministic offline reference. `None` models a node that cannot
/// currently produce a quote (TEE unavailable) — the loop leaves it unattested, fail-closed.
pub trait QuoteSource {
    fn fetch_quote(&self, node_id: &str) -> Option<AttestationQuote>;
}

/// A deterministic offline [`QuoteSource`] — a fixed `node_id → quote` map for tests / replay.
#[derive(Debug, Clone, Default)]
pub struct StaticQuoteSource {
    quotes: BTreeMap<String, AttestationQuote>,
}

impl StaticQuoteSource {
    pub fn new() -> Self {
        StaticQuoteSource::default()
    }
    pub fn with_quote(mut self, quote: AttestationQuote) -> Self {
        self.quotes.insert(quote.node_id.clone(), quote);
        self
    }
}

impl QuoteSource for StaticQuoteSource {
    fn fetch_quote(&self, node_id: &str) -> Option<AttestationQuote> {
        self.quotes.get(node_id).cloned()
    }
}

/// What happened to one declared node on a refresh tick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshOutcome {
    /// A fresh quote was fetched + verified; the node is (re-)attested until `quote_ttl` elapses.
    Refreshed { node_id: String },
    /// The node's quote is still fresh (not within the lead window) — nothing to do.
    StillFresh { node_id: String },
    /// The TEE could not produce a quote this tick — the node stays unattested (fail-closed).
    NoQuoteAvailable { node_id: String },
    /// A fetched quote FAILED the verifier fence (bad signature / measurement / firmware quarantine).
    VerificationFailed {
        node_id: String,
        reason: SubmitError,
    },
    /// The node is under manual-review quarantine — never auto-refreshed (ADR-021 §8.4).
    Quarantined { node_id: String },
}

/// The report of one [`refresh_regulated_nodes`] tick — one [`RefreshOutcome`] per declared node,
/// in deterministic node-id order.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RefreshReport {
    pub outcomes: Vec<RefreshOutcome>,
}

impl RefreshReport {
    /// Count of nodes actually (re-)attested this tick.
    pub fn refreshed_count(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|o| matches!(o, RefreshOutcome::Refreshed { .. }))
            .count()
    }
}

/// One tick of the ADR-021 §8.3 quote-refresh loop over `declared_nodes` (serving-ops gap-3): for each
/// node due for (re-)attestation ([`AttestationGate::needs_refresh`]) within `lead` ticks, fetch a
/// fresh quote from the live-TEE `source` seam and drive it through the verifier fence, updating the
/// gate. Pure scheduling + fence sequencing — the only deferred part is the hardware quote acquisition.
/// The daemon calls this on a cadence (needs_hot_wiring: the async timer + the live `QuoteSource`); the
/// WHICH-nodes-are-due decision and the fence it drives them through are proven offline here.
pub fn refresh_regulated_nodes(
    gate: &mut AttestationGate,
    declared_nodes: &[String],
    now: u64,
    lead: u64,
    source: &dyn QuoteSource,
    verifier: &dyn SignatureVerifier,
    refs: &ReferenceValues,
) -> RefreshReport {
    let mut report = RefreshReport::default();
    for node_id in declared_nodes {
        if gate.is_quarantined(node_id) {
            report.outcomes.push(RefreshOutcome::Quarantined {
                node_id: node_id.clone(),
            });
            continue;
        }
        if !gate.needs_refresh(node_id, now, lead) {
            report.outcomes.push(RefreshOutcome::StillFresh {
                node_id: node_id.clone(),
            });
            continue;
        }
        match source.fetch_quote(node_id) {
            None => report.outcomes.push(RefreshOutcome::NoQuoteAvailable {
                node_id: node_id.clone(),
            }),
            Some(quote) => match gate.submit_quote(&quote, now, verifier, refs) {
                Ok(()) => report.outcomes.push(RefreshOutcome::Refreshed {
                    node_id: node_id.clone(),
                }),
                Err(reason) => report.outcomes.push(RefreshOutcome::VerificationFailed {
                    node_id: node_id.clone(),
                    reason,
                }),
            },
        }
    }
    report
}

// ---------------------------------------------------------------------------
// The stateful, periodic quote-refresh DRIVER (ADR-021 §8.3; serving-ops gap-3, round-13)
// ---------------------------------------------------------------------------
//
// Round-12 shipped the pure single-tick [`refresh_regulated_nodes`], but on its own it still had to be
// hand-called — so the shipped daemon declared a regulated pool and then never re-attested it, leaving
// every declared node UNattested and regulated traffic fenced off the whole fleet forever (the HIGH).
// [`AttestationRefresher`] is the DRIVER that closes that: it owns the declared node list + a cadence,
// decides on each logical tick whether a sweep is DUE, and on a due tick drives every expiring/
// unattested node through the verifier fence via the live-TEE [`QuoteSource`] seam. Periodic re-fetch
// + expiry-driven re-admit — still pure and deterministic (logical time is the `now` parameter; the
// async timer + the live TEE are the daemon's needs_hot_wiring/infra concern).

/// Cadence + lead-window tuning for the [`AttestationRefresher`] (ADR-021 §8.3). Both are logical-tick
/// durations, so the driver stays deterministic and exhaustively testable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefreshConfig {
    /// Logical ticks between refresh sweeps (the periodic cadence). A tick before the next due point is
    /// a no-op ([`AttestationRefresher::tick`] returns `None`). Treated as `1` if configured `0`, so a
    /// sweep can never be scheduled "in the past forever" and busy-loop.
    pub interval: u64,
    /// Re-attest a node when its verified quote expires within this many ticks (proactive lead), so the
    /// fence never flickers to fail-closed on an expiry the sweep could have prevented. Should be `>=`
    /// the interval, or a quote can lapse between two sweeps.
    pub lead: u64,
}

impl Default for RefreshConfig {
    fn default() -> Self {
        // Conservative defaults: sweep every 30 ticks, re-attest anything within 60 ticks of expiry
        // (lead > interval so a quote is always renewed at least one sweep before it can lapse).
        RefreshConfig {
            interval: 30,
            lead: 60,
        }
    }
}

impl RefreshConfig {
    /// The effective (never-zero) cadence — a `0` interval degrades to "every tick", never a busy-loop.
    fn effective_interval(self) -> u64 {
        self.interval.max(1)
    }
}

/// A stateful, periodic driver for the ADR-021 §8.3 quote-refresh loop (serving-ops gap-3, round-13).
///
/// Holds the declared regulated node pool + the [`RefreshConfig`] cadence and its own next-due cursor.
/// On each [`AttestationRefresher::tick`] it decides whether a sweep is due; on a due sweep it drives
/// one [`refresh_regulated_nodes`] pass over the pool through the live-TEE [`QuoteSource`] seam and the
/// verifier fence, then advances the cadence. This is exactly the loop the audit found missing: it
/// re-admits a node the TEE can freshly quote, and — because a failed/absent fetch never fabricates a
/// quote — leaves an expired-and-unrenewable node fail-closed.
///
/// The daemon owns the async timer and the live [`QuoteSource`] (needs_hot_wiring / infra); this struct
/// is the clean, offline-testable core it calls on a cadence.
#[derive(Debug, Clone)]
pub struct AttestationRefresher {
    declared_nodes: Vec<String>,
    cfg: RefreshConfig,
    next_due_at: u64,
    sweeps: u64,
}

impl AttestationRefresher {
    /// Build a refresher over the deployment's declared regulated node pool. The first [`tick`] at any
    /// `now` is due (the pool must be attested as early as possible after boot).
    ///
    /// [`tick`]: AttestationRefresher::tick
    pub fn new(declared_nodes: Vec<String>, cfg: RefreshConfig) -> Self {
        AttestationRefresher {
            declared_nodes,
            cfg,
            next_due_at: 0,
            sweeps: 0,
        }
    }

    /// The declared regulated node pool this driver keeps attested.
    pub fn declared_nodes(&self) -> &[String] {
        &self.declared_nodes
    }

    /// The cadence/lead tuning.
    pub fn config(&self) -> RefreshConfig {
        self.cfg
    }

    /// How many sweeps have actually run (a `None`-returning tick does not count).
    pub fn sweeps_run(&self) -> u64 {
        self.sweeps
    }

    /// Whether a refresh sweep is due at `now` (the periodic cadence gate).
    pub fn is_due(&self, now: u64) -> bool {
        now >= self.next_due_at
    }

    /// One driver tick at logical time `now`.
    ///
    /// Returns `None` when a sweep is not yet due (between cadence points) — the caller does nothing.
    /// On a due tick it runs one [`refresh_regulated_nodes`] sweep over the declared pool (fetch a
    /// fresh quote for every unattested / expiring-within-`lead` node from the live-TEE `source`, drive
    /// it through `verifier` + `refs`, update `gate`), advances the cadence to `now + interval`, and
    /// returns the [`RefreshReport`]. A node the TEE cannot quote this sweep, or whose fetched quote
    /// fails the fence, is NOT admitted — an expired node with no valid fresh quote stays fail-closed
    /// (the gate never falls back to a stale quote past its window).
    pub fn tick(
        &mut self,
        gate: &mut AttestationGate,
        now: u64,
        source: &dyn QuoteSource,
        verifier: &dyn SignatureVerifier,
        refs: &ReferenceValues,
    ) -> Option<RefreshReport> {
        if !self.is_due(now) {
            return None;
        }
        let report = refresh_regulated_nodes(
            gate,
            &self.declared_nodes,
            now,
            self.cfg.lead,
            source,
            verifier,
            refs,
        );
        self.next_due_at = now.saturating_add(self.cfg.effective_interval());
        self.sweeps = self.sweeps.saturating_add(1);
        Some(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIG: &str = "sig-good";

    fn cfg() -> AttestationConfig {
        AttestationConfig {
            quote_ttl: 100,
            grace_ttl: 15,
        }
    }

    fn good_measurements() -> Measurements {
        Measurements {
            firmware_hash: "fw-1".into(),
            driver_version: "drv-1".into(),
            binary_hash: "bin-1".into(),
        }
    }

    fn refs() -> ReferenceValues {
        ReferenceValues::new()
            .allow_firmware("fw-1")
            .allow_driver("drv-1")
            .allow_binary("bin-1")
    }

    fn verifier() -> AllowListVerifier {
        AllowListVerifier::new().accept(SIG)
    }

    fn quote(node: &str, tier: TrustTier) -> AttestationQuote {
        AttestationQuote {
            node_id: node.into(),
            tier,
            measurements: good_measurements(),
            signature: SIG.into(),
        }
    }

    #[test]
    fn fresh_attested_node_admits_regulated_traffic() {
        let mut gate = AttestationGate::new(cfg());
        gate.submit_quote(&quote("n1", TrustTier::CcEnclave), 0, &verifier(), &refs())
            .unwrap();
        let v = gate.evaluate("n1", DataClass::RegulatedPayment, 50, true);
        assert_eq!(
            v,
            NodeVerdict::Admitted {
                tier: TrustTier::CcEnclave
            }
        );
        assert!(v.is_admitted());
    }

    #[test]
    fn unattested_node_is_denied_regulated_but_serves_public() {
        let gate = AttestationGate::new(cfg());
        assert_eq!(
            gate.evaluate("n1", DataClass::Pii, 0, true),
            NodeVerdict::Denied {
                reason: DenyReason::NoValidQuote
            }
        );
        // Same node happily serves public traffic.
        assert!(gate
            .evaluate("n1", DataClass::Public, 0, true)
            .is_admitted());
    }

    #[test]
    fn forged_signature_is_rejected() {
        let mut gate = AttestationGate::new(cfg());
        let mut q = quote("n1", TrustTier::CcEnclave);
        q.signature = "sig-forged".into();
        assert_eq!(
            gate.submit_quote(&q, 0, &verifier(), &refs()),
            Err(SubmitError::SignatureInvalid)
        );
        // Nothing recorded → still denied for regulated.
        assert!(!gate.evaluate("n1", DataClass::Pii, 0, true).is_admitted());
    }

    #[test]
    fn validly_signed_but_downgraded_firmware_quarantines_the_whole_node() {
        let mut gate = AttestationGate::new(cfg());
        let mut q = quote("n1", TrustTier::CcEnclave);
        q.measurements.firmware_hash = "fw-OLD-vulnerable".into(); // validly signed, not allow-listed
        let v = AllowListVerifier::new().accept(SIG); // signature DOES verify
        assert_eq!(
            gate.submit_quote(&q, 0, &v, &refs()),
            Err(SubmitError::FirmwareNotAllowListed)
        );
        assert!(gate.is_quarantined("n1"));
        // Quarantine denies EVEN public traffic (whole-node integrity, §8.4).
        assert_eq!(
            gate.evaluate("n1", DataClass::Public, 0, true),
            NodeVerdict::Denied {
                reason: DenyReason::Quarantined
            }
        );
    }

    #[test]
    fn downgraded_driver_denies_regulated_without_full_quarantine() {
        let mut gate = AttestationGate::new(cfg());
        let mut q = quote("n1", TrustTier::CcEnclave);
        q.measurements.driver_version = "drv-OLD".into();
        assert_eq!(
            gate.submit_quote(&q, 0, &verifier(), &refs()),
            Err(SubmitError::MeasurementNotAllowListed)
        );
        assert!(
            !gate.is_quarantined("n1"),
            "driver mismatch is not a whole-node quarantine"
        );
        // Not admitted for regulated (no valid quote recorded)...
        assert!(!gate.evaluate("n1", DataClass::Pii, 0, true).is_admitted());
        // ...but still fine for public.
        assert!(gate
            .evaluate("n1", DataClass::Public, 0, true)
            .is_admitted());
    }

    #[test]
    fn quarantine_is_not_auto_cleared_by_a_fresh_quote() {
        let mut gate = AttestationGate::new(cfg());
        let mut bad = quote("n1", TrustTier::CcEnclave);
        bad.measurements.firmware_hash = "fw-bad".into();
        let _ = gate.submit_quote(&bad, 0, &verifier(), &refs());
        assert!(gate.is_quarantined("n1"));
        // A subsequent good quote does NOT silently un-quarantine — needs manual review.
        // (evaluate still denies because quarantine short-circuits before the quote check.)
        gate.submit_quote(&quote("n1", TrustTier::CcEnclave), 1, &verifier(), &refs())
            .unwrap();
        assert_eq!(
            gate.evaluate("n1", DataClass::Pii, 1, true),
            NodeVerdict::Denied {
                reason: DenyReason::Quarantined
            }
        );
        // Explicit review clears it; now the recorded good quote lets it through.
        assert!(gate.clear_quarantine("n1"));
        assert!(gate.evaluate("n1", DataClass::Pii, 1, true).is_admitted());
    }

    #[test]
    fn untrusted_tier_quote_is_refused_at_submit() {
        let mut gate = AttestationGate::new(cfg());
        assert_eq!(
            gate.submit_quote(&quote("n1", TrustTier::Untrusted), 0, &verifier(), &refs()),
            Err(SubmitError::UntrustedTierQuote)
        );
    }

    #[test]
    fn stale_quote_with_verifier_reachable_fails_closed_immediately() {
        // Overdue re-attestation while the verifier is UP is a lapse → drain now, no grace.
        let mut gate = AttestationGate::new(cfg());
        gate.submit_quote(&quote("n1", TrustTier::CcEnclave), 0, &verifier(), &refs())
            .unwrap();
        // now = 101 > quote_ttl(100); verifier reachable.
        assert_eq!(
            gate.evaluate("n1", DataClass::RegulatedPayment, 101, true),
            NodeVerdict::Denied {
                reason: DenyReason::QuoteExpired
            }
        );
    }

    #[test]
    fn stale_quote_within_grace_and_verifier_down_admits_on_grace() {
        // ADR-021 §8.3 scenario 18: verifier blip within grace → keep serving on last quote.
        let mut gate = AttestationGate::new(cfg());
        gate.submit_quote(
            &quote("n1", TrustTier::BareMetalAttested),
            0,
            &verifier(),
            &refs(),
        )
        .unwrap();
        // fresh_until = 100, grace_expires_at = 115. now = 110, verifier DOWN.
        assert_eq!(
            gate.evaluate("n1", DataClass::Pii, 110, false),
            NodeVerdict::AdmittedOnGrace {
                tier: TrustTier::BareMetalAttested,
                grace_expires_at: 115
            }
        );
    }

    #[test]
    fn past_grace_ttl_fails_closed_even_with_verifier_down() {
        // ADR-021 §8.3 scenario 19: stale trust must not drift silently past the grace window.
        let mut gate = AttestationGate::new(cfg());
        gate.submit_quote(&quote("n1", TrustTier::CcEnclave), 0, &verifier(), &refs())
            .unwrap();
        // grace_expires_at = 115; now = 116, verifier still down → fail closed.
        assert_eq!(
            gate.evaluate("n1", DataClass::RegulatedPayment, 116, false),
            NodeVerdict::Denied {
                reason: DenyReason::QuoteExpired
            }
        );
    }

    #[test]
    fn at_freshness_boundary_is_still_fresh() {
        let mut gate = AttestationGate::new(cfg());
        gate.submit_quote(&quote("n1", TrustTier::CcEnclave), 10, &verifier(), &refs())
            .unwrap();
        // verified_at=10, quote_ttl=100 → fresh through 110 inclusive.
        assert!(gate.evaluate("n1", DataClass::Pii, 110, true).is_admitted());
        assert!(!gate.evaluate("n1", DataClass::Pii, 111, true).is_admitted());
    }

    #[test]
    fn needs_attestation_threshold_is_confidential_and_above() {
        assert!(!AttestationGate::needs_attestation(DataClass::Public));
        assert!(!AttestationGate::needs_attestation(DataClass::Internal));
        assert!(AttestationGate::needs_attestation(DataClass::Confidential));
        assert!(AttestationGate::needs_attestation(
            DataClass::RegulatedPayment
        ));
        assert!(AttestationGate::needs_attestation(DataClass::Pii));
    }

    #[test]
    fn re_attestation_refreshes_the_window() {
        let mut gate = AttestationGate::new(cfg());
        gate.submit_quote(&quote("n1", TrustTier::CcEnclave), 0, &verifier(), &refs())
            .unwrap();
        // Would be stale at 101...
        assert!(!gate.evaluate("n1", DataClass::Pii, 101, true).is_admitted());
        // ...but a re-attestation at 90 pushes freshness out to 190.
        gate.submit_quote(&quote("n1", TrustTier::CcEnclave), 90, &verifier(), &refs())
            .unwrap();
        assert!(gate.evaluate("n1", DataClass::Pii, 150, true).is_admitted());
    }
}
