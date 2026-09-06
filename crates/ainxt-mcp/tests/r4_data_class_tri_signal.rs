// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! r4_data_class_tri_signal (MCP side) — §4.2 signal 1 (declared capability class) for a REMOTE
//! tool is carried on the [`ToolManifest`] and is TAMPER-EVIDENT: it is folded into the TOFU content
//! hash, so a server that silently DOWNGRADES its declared data-class on reconnect (e.g. a payments
//! tool relabelling itself `internal`) produces a diff that forces re-approval — a stealth
//! de-classification cannot slip past the pin. Also proves the field defaults conservatively
//! (omitted ⇒ Confidential) and survives the serde wire.

use ainxt_mcp::{diff_manifest, tool_content_hash, ManifestPin, ToolManifest};
use ainxt_types::DataClass;

#[test]
fn r4_data_class_tri_signal_omitted_declaration_defaults_conservative() {
    // A manifest built without an explicit class must NOT be Public/Internal — an absent
    // declaration can never under-classify a remote tool.
    let m = ToolManifest::new("query", "read the ledger");
    assert_eq!(m.declared_data_class, DataClass::Confidential);

    // Legacy wire payload with no `declared_data_class` field deserializes to the same floor.
    let legacy = r#"{"name":"query","description":"read the ledger","schema":""}"#;
    let parsed: ToolManifest = serde_json::from_str(legacy).unwrap();
    assert_eq!(parsed.declared_data_class, DataClass::Confidential);
}

#[test]
fn r4_data_class_tri_signal_declared_class_survives_serde_roundtrip() {
    let m = ToolManifest::new("settle", "post a settlement entry")
        .with_data_class(DataClass::RegulatedPayment);
    let json = serde_json::to_string(&m).unwrap();
    assert!(
        json.contains("regulated-payment"),
        "kebab-case on the wire: {json}"
    );
    let back: ToolManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(back, m);
    assert_eq!(back.declared_data_class, DataClass::RegulatedPayment);
}

#[test]
fn r4_data_class_tri_signal_declared_class_is_folded_into_tofu_hash() {
    // Two manifests identical in name/description/schema but differing ONLY in declared class must
    // hash differently — otherwise a downgrade would be invisible to the pin.
    let base = "post a settlement entry";
    let regulated = ToolManifest::new("settle", base).with_data_class(DataClass::RegulatedPayment);
    let downgraded = ToolManifest::new("settle", base).with_data_class(DataClass::Internal);
    assert_ne!(
        tool_content_hash(&regulated),
        tool_content_hash(&downgraded),
        "declared data-class must be part of the content hash"
    );
    // Same class ⇒ same hash (the hash is a pure function of declared content).
    let regulated2 = ToolManifest::new("settle", base).with_data_class(DataClass::RegulatedPayment);
    assert_eq!(
        tool_content_hash(&regulated),
        tool_content_hash(&regulated2)
    );
}

#[test]
fn r4_data_class_tri_signal_stealth_downgrade_on_reconnect_forces_reapproval() {
    // Approve a payments tool declared RegulatedPayment.
    let approved = [ToolManifest::new("settle", "post a settlement entry")
        .with_data_class(DataClass::RegulatedPayment)];
    let pin = ManifestPin::approve("https://mcp.acme.test", &approved, "risk-officer", 100);

    // Reconnect with the SAME name/description/schema but a silently DOWNGRADED class.
    let reconnect =
        [ToolManifest::new("settle", "post a settlement entry")
            .with_data_class(DataClass::Internal)];

    // The pin no longer matches, and the diff flags the tool as changed → re-approval required.
    assert!(
        !pin.matches(&reconnect),
        "downgraded class must break the pin match"
    );
    let diff = diff_manifest(&pin, &reconnect);
    assert!(diff.requires_reapproval());
    assert_eq!(diff.changed, vec!["settle".to_string()]);
    assert_eq!(diff.quarantined_names(), vec!["settle".to_string()]);

    // Reconnecting with the ORIGINAL declared class proceeds silently.
    assert!(pin.matches(&approved));
    assert!(diff_manifest(&pin, &approved).is_identical());
}
