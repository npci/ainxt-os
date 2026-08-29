// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! r4_data_class_tri_signal — §4.2: the effective data-class of a tool call is fused from THREE
//! independent, agreeing signals — the tool's DECLARED capability class, a COMPLIANCE SCAN of the
//! args, and the DESTINATION/EGRESS class — and on disagreement it ESCALATES to the most sensitive.
//!
//! These run against the REAL objects: [`ToolRuntime::classify_data_class`], the [`Tool`] trait's
//! `declared_data_class`/`destination_data_class` signals, and the default [`MarkerArgScanner`]
//! compliance-scan seam. The classification is proven to be a *routing/approval* verdict, never a
//! turn denial (no admission gate is introduced).

use ainxt_tools::{
    ArgClassScanner, ClassSignal, EffectClass, EffectiveDataClass, InMemoryLedger,
    MarkerArgScanner, RiskTier, Tool, ToolError, ToolRuntime,
};
use ainxt_types::DataClass;

/// A configurable native tool: declares a data-class, an egress flag, and (optionally) an explicit
/// destination class — so a single type exercises every signal permutation.
struct ConfigurableTool {
    name: String,
    declared: DataClass,
    egress: bool,
    dest_override: Option<DataClass>,
}

impl ConfigurableTool {
    fn new(name: &str, declared: DataClass) -> Self {
        ConfigurableTool {
            name: name.into(),
            declared,
            egress: false,
            dest_override: None,
        }
    }
    fn egressing(mut self) -> Self {
        self.egress = true;
        self
    }
    fn dest(mut self, c: DataClass) -> Self {
        self.dest_override = Some(c);
        self
    }
}

impl Tool for ConfigurableTool {
    fn name(&self) -> &str {
        &self.name
    }
    fn effect_class(&self) -> EffectClass {
        EffectClass::Pure
    }
    fn risk_tier(&self) -> RiskTier {
        RiskTier::Low
    }
    fn egress(&self) -> bool {
        self.egress
    }
    fn declared_data_class(&self) -> DataClass {
        self.declared
    }
    fn destination_data_class(&self, _args: &str) -> Option<DataClass> {
        // Explicit override wins; else fall back to the trait's egress-derived default.
        match self.dest_override {
            Some(c) => Some(c),
            None => {
                if self.egress {
                    Some(DataClass::Confidential)
                } else {
                    None
                }
            }
        }
    }
    fn execute(&self, _args: &str) -> Result<String, ToolError> {
        Ok("ok".into())
    }
}

fn runtime_with(tool: ConfigurableTool) -> ToolRuntime {
    let mut rt = ToolRuntime::new(
        Box::new(InMemoryLedger::new()),
        Box::new(ainxt_tools::ManualReconciler),
    );
    rt.register(Box::new(tool));
    rt
}

// ---- Signal 2 (compliance scan of args) is a real, deterministic classifier ----

#[test]
fn r4_data_class_tri_signal_marker_scanner_classifies_by_content() {
    let s = MarkerArgScanner;
    // Nothing sensitive → no class contributed.
    assert_eq!(s.classify_args("{\"path\":\"README.md\"}"), None);
    // A Luhn-valid card (Visa test PAN) → RegulatedPayment.
    assert_eq!(
        s.classify_args("{\"pan\":\"4111111111111111\"}"),
        Some(DataClass::RegulatedPayment)
    );
    // A long account-like digit run (13+) → RegulatedPayment.
    assert_eq!(
        s.classify_args("account 1234567890123456789"),
        Some(DataClass::RegulatedPayment)
    );
    // An email → Pii.
    assert_eq!(
        s.classify_args("notify jane.doe@example.com"),
        Some(DataClass::Pii)
    );
    // A marked secret → Confidential.
    assert_eq!(
        s.classify_args("api_key=AKIAABCDEF"),
        Some(DataClass::Confidential)
    );
}

// ---- GAP-FIX tooling-mcp-plugins-routing: `re2_detectors::is_secret_assignment` is wired into the
// SAME `MarkerArgScanner::classify_args` [`default_hardened_scanner`] installs on the served engine
// (`ainxt-runtime`'s `Engine::new`, the composition root) — proving a real detection gap the literal
// substring marker list cannot close (whitespace before the `:`/`=`, and hyphenated key spellings)
// is now caught by the exact function the shipped daemon's default `ArgClassScanner` runs. ----
#[test]
fn r_gap_secret_assignment_whitespace_and_hyphen_variants_now_classify_as_confidential() {
    let s = MarkerArgScanner;

    // Before this fix: the literal substring "password:" is not present (there's a space before the
    // colon), so the marker list misses it entirely, and neither the digit scan nor the email check
    // finds anything else sensitive — `classify_args` returned `None`, waving a plainly-labelled
    // secret through unclassified.
    assert_eq!(
        s.classify_args("Password : mySecretValue123"),
        Some(DataClass::Confidential),
        "whitespace-tolerant secret-assignment detection must reach the served scanner"
    );

    // A genuine negative stays negative (the regex requires a real key=value shape, not just the
    // bare word) — proving this isn't an over-broad match that would flag ordinary prose.
    assert_eq!(
        s.classify_args("the api provides a key metric for latency"),
        None,
        "ordinary prose mentioning 'api'/'key' must not be misclassified as a secret"
    );

    // The exact served entrypoint (`ainxt-runtime`'s composition root installs THIS function, not
    // the bare `MarkerArgScanner`) must classify identically — the DoS-hardening wrapper changes
    // availability posture only, never detection behavior for in-budget input.
    let hardened = ainxt_tools::default_hardened_scanner();
    assert_eq!(
        hardened.classify_args("Password : mySecretValue123"),
        Some(DataClass::Confidential),
        "the served default_hardened_scanner() must classify identically to the bare scanner"
    );
}

// ---- The core §4.2 property: disagreement escalates to the MOST sensitive ----

#[test]
fn r4_data_class_tri_signal_three_disagreeing_signals_escalate_to_most_sensitive() {
    // Tool DECLARES Internal, but its args carry a PAN (scan ⇒ RegulatedPayment) and it egresses
    // off-box (destination ⇒ Confidential). Three signals, all different. The effective class must
    // be the MOST sensitive of the three (RegulatedPayment), not the declared (Internal), not the
    // destination floor (Confidential), and certainly not an average.
    let rt = runtime_with(ConfigurableTool::new("send", DataClass::Internal).egressing());
    let eff = rt
        .classify_data_class("send", "{\"pan\":\"4111111111111111\"}", &MarkerArgScanner)
        .expect("tool is registered");

    assert_eq!(
        eff.class,
        DataClass::RegulatedPayment,
        "escalate to most sensitive"
    );
    assert!(eff.escalated, "signals disagreed → escalated flag set");
    assert_eq!(
        eff.drivers,
        vec![ClassSignal::ArgScan],
        "arg-scan drove the verdict"
    );
    // The raw readings are preserved for audit.
    assert_eq!(eff.signals.declared, DataClass::Internal);
    assert_eq!(eff.signals.scanned, Some(DataClass::RegulatedPayment));
    assert_eq!(eff.signals.destination, Some(DataClass::Confidential));
    // Routing consequence (ADR-012): a regulated class must stay in-house.
    assert!(eff.must_stay_in_house());
}

#[test]
fn r4_data_class_tri_signal_declared_alone_cannot_downgrade_a_pan_in_args() {
    // The adversarial case that motivates §4.2: a tool that LIES about its class (declares Public)
    // still cannot launder a PAN-bearing call down to Public — the arg scan overrides it.
    let rt = runtime_with(ConfigurableTool::new("read", DataClass::Public));
    let eff = rt
        .classify_data_class("read", "card 4111 1111 1111 1111", &MarkerArgScanner)
        .unwrap();
    assert_eq!(eff.class, DataClass::RegulatedPayment);
    assert!(eff.escalated);
}

#[test]
fn r4_data_class_tri_signal_email_in_args_escalates_above_declared_and_destination() {
    // Declared Internal, egress→Confidential, but an email in args ⇒ Pii (the most sensitive class).
    let rt = runtime_with(ConfigurableTool::new("mail", DataClass::Internal).egressing());
    let eff = rt
        .classify_data_class("mail", "to: ops@example.org.in", &MarkerArgScanner)
        .unwrap();
    assert_eq!(eff.class, DataClass::Pii);
    assert!(eff.escalated);
    assert_eq!(eff.drivers, vec![ClassSignal::ArgScan]);
}

#[test]
fn r4_data_class_tri_signal_destination_egress_raises_the_floor_over_a_clean_declared_internal() {
    // No sensitive args, declared Internal, but the call egresses off-box: the destination signal
    // floors the effective class at Confidential — disagreement between declared and destination
    // still escalates upward.
    let rt = runtime_with(ConfigurableTool::new("push", DataClass::Internal).egressing());
    let eff = rt
        .classify_data_class("push", "{\"note\":\"status ok\"}", &MarkerArgScanner)
        .unwrap();
    assert_eq!(eff.class, DataClass::Confidential);
    assert!(eff.escalated);
    assert_eq!(eff.drivers, vec![ClassSignal::Destination]);
}

#[test]
fn r4_data_class_tri_signal_all_signals_agree_no_escalation() {
    // Declared Confidential, args clean, and an explicit Confidential destination → all present
    // signals agree, so escalated is FALSE and all present signals are drivers.
    let rt = runtime_with(
        ConfigurableTool::new("sync", DataClass::Confidential)
            .egressing()
            .dest(DataClass::Confidential),
    );
    let eff = rt
        .classify_data_class("sync", "{\"ok\":true}", &MarkerArgScanner)
        .unwrap();
    assert_eq!(eff.class, DataClass::Confidential);
    assert!(!eff.escalated, "all signals agreed");
    assert_eq!(
        eff.drivers,
        vec![ClassSignal::Declared, ClassSignal::Destination]
    );
    assert!(!eff.must_stay_in_house());
}

#[test]
fn r4_data_class_tri_signal_clean_on_box_internal_tool_is_not_escalated() {
    // The trivial baseline: on-box, clean args, declared Internal → only signal 1 present, no
    // disagreement, effective == declared.
    let rt = runtime_with(ConfigurableTool::new("calc", DataClass::Internal));
    let eff = rt
        .classify_data_class("calc", "{\"a\":1,\"b\":2}", &MarkerArgScanner)
        .unwrap();
    assert_eq!(eff.class, DataClass::Internal);
    assert!(!eff.escalated);
    assert_eq!(eff.drivers, vec![ClassSignal::Declared]);
    assert_eq!(eff.signals.scanned, None);
    assert_eq!(eff.signals.destination, None);
}

#[test]
fn r4_data_class_tri_signal_unknown_tool_returns_none() {
    let rt = runtime_with(ConfigurableTool::new("known", DataClass::Internal));
    assert!(rt
        .classify_data_class("nope", "{}", &MarkerArgScanner)
        .is_none());
}

// ---- The fuse function's escalation invariant holds for ALL signal combinations ----

#[test]
fn r4_data_class_tri_signal_fuse_is_always_the_maximum_present_signal() {
    let classes = [
        DataClass::Public,
        DataClass::Internal,
        DataClass::Confidential,
        DataClass::RegulatedPayment,
        DataClass::Pii,
    ];
    let opts: [Option<DataClass>; 6] = [
        None,
        Some(DataClass::Public),
        Some(DataClass::Internal),
        Some(DataClass::Confidential),
        Some(DataClass::RegulatedPayment),
        Some(DataClass::Pii),
    ];
    for &declared in &classes {
        for &scanned in &opts {
            for &destination in &opts {
                let eff = EffectiveDataClass::fuse(declared, scanned, destination);
                // The effective class is the maximum of every PRESENT signal (declared always is).
                let expected = [Some(declared), scanned, destination]
                    .into_iter()
                    .flatten()
                    .max()
                    .unwrap();
                assert_eq!(eff.class, expected, "effective = most sensitive present");
                // Never below any present signal — escalation, never de-classification.
                for present in [Some(declared), scanned, destination].into_iter().flatten() {
                    assert!(eff.class >= present, "never below a present signal");
                }
                // escalated iff some present signal differs from the effective class.
                let disagree = [Some(declared), scanned, destination]
                    .into_iter()
                    .flatten()
                    .any(|c| c != eff.class);
                assert_eq!(eff.escalated, disagree);
                // Determinism: drivers are in a fixed order and every driver reads at `class`.
                assert!(eff.drivers.windows(2).all(|w| {
                    let idx = |s: &ClassSignal| match s {
                        ClassSignal::Declared => 0,
                        ClassSignal::ArgScan => 1,
                        ClassSignal::Destination => 2,
                    };
                    idx(&w[0]) < idx(&w[1])
                }));
                assert!(!eff.drivers.is_empty());
            }
        }
    }
}

/// A scanner that always returns Pii — proves the seam is honored (production PCI/DSS classifier
/// plugs in the same way) and that a scan reading escalates the verdict.
struct AlwaysPii;
impl ArgClassScanner for AlwaysPii {
    fn classify_args(&self, _args: &str) -> Option<DataClass> {
        Some(DataClass::Pii)
    }
}

#[test]
fn r4_data_class_tri_signal_pluggable_scanner_seam_drives_escalation() {
    let rt = runtime_with(ConfigurableTool::new("plain", DataClass::Internal));
    // With the marker scanner and clean args, nothing escalates.
    let base = rt
        .classify_data_class("plain", "{\"x\":1}", &MarkerArgScanner)
        .unwrap();
    assert_eq!(base.class, DataClass::Internal);
    // Swap in a stricter scanner behind the SAME seam → the scan signal escalates to Pii.
    let strict = rt
        .classify_data_class("plain", "{\"x\":1}", &AlwaysPii)
        .unwrap();
    assert_eq!(strict.class, DataClass::Pii);
    assert!(strict.escalated);
    assert_eq!(strict.drivers, vec![ClassSignal::ArgScan]);
}
