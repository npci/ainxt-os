// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-11 — **populating** the two Context-Fabric graphs the Code-Review Pipeline consumes
//! (`CODE_REVIEW_PIPELINE.md` §4 stages 7 & 8), rather than hand-wiring them:
//!   * the **architecture-graph contract** from a declarative, git-controlled `LayerManifest`
//!     (round-trips serde, so amending a boundary rule is a reviewable diff);
//!   * the **git-history co-change graph** from a list of per-commit file sets
//!     (`CochangeGraph::from_commits`), the offline core of `git log --name-only`.
//!
//! Both then drive the *existing* analyses (`new_violations`, `analyze`) unchanged — proving the
//! populated graphs are real inputs, not decoration. Fail-before: `LayerContract::from_manifest`,
//! `LayerManifest`, and `CochangeGraph::from_commits` did not exist.

use ainxt_semantic::arch::{LayerContract, LayerManifest};
use ainxt_semantic::graph::SourceFile;
use ainxt_semantic::regression::{analyze, CochangeGraph};
use ainxt_semantic::Language;

fn rs(path: &str, src: &str) -> SourceFile {
    SourceFile::new(path, Language::Rust, src)
}

#[test]
fn r11_layer_contract_built_from_a_declarative_manifest_catches_a_boundary_break() {
    // A deployment checks in this contract as JSON; the pipeline loads it.
    let json = r#"{
        "layers": {
            "ui":  ["ui/"],
            "api": ["api_client"],
            "db":  ["db::"]
        },
        "allowed": [["ui", "api"], ["api", "db"]]
    }"#;
    let manifest: LayerManifest = serde_json::from_str(json).expect("manifest parses");
    let contract = LayerContract::from_manifest(&manifest);

    // ui -> db is NOT an allowed edge → the populated contract flags it, identically to the fluent form.
    let before = vec![rs("src/ui/screen.rs", "fn render() {}\n")];
    let after = vec![rs(
        "src/ui/screen.rs",
        "use crate::db::conn;\nfn render() {}\n",
    )];
    let v = contract.new_violations(&before, &after);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].from_layer, "ui");
    assert_eq!(v[0].to_layer, "db");

    // ui -> api IS allowed → no violation. Same populated contract.
    let after_ok = vec![rs(
        "src/ui/screen.rs",
        "use crate::api_client::Client;\nfn render() {}\n",
    )];
    assert!(contract.new_violations(&before, &after_ok).is_empty());
}

#[test]
fn r11_cochange_graph_populated_from_commit_history_drives_the_advisory() {
    // Three past commits: schema.rs + migration.rs changed together twice; schema.rs + notes.md once.
    let commits: Vec<Vec<&str>> = vec![
        vec!["schema.rs", "migration.rs"],
        vec!["schema.rs", "migration.rs", "notes.md"],
        vec!["schema.rs", "notes.md"],
    ];
    let cc = CochangeGraph::from_commits(&commits);

    // schema.rs<->migration.rs co-changed in 2 commits; schema.rs<->notes.md in 2 as well.
    assert_eq!(
        cc.coupled_with("schema.rs", 1)
            .into_iter()
            .collect::<std::collections::BTreeMap<_, _>>()["migration.rs"],
        2
    );

    // Editing only schema.rs, threshold 2 → both partners flagged as change-coupling advisories.
    let lib = rs("schema.rs", "pub fn f() {}\n");
    let report = analyze(&[lib], &["f"], &["schema.rs"], &cc, 2);
    let flagged: std::collections::BTreeSet<&str> = report
        .coupling_advisories
        .iter()
        .map(|a| a.coupled_file.as_str())
        .collect();
    assert!(flagged.contains("migration.rs"));
    assert!(flagged.contains("notes.md"));

    // A partner that co-changed only once falls below the threshold and is not flagged.
    let onceish = CochangeGraph::from_commits(&[vec!["a.rs", "b.rs"]]);
    let a = rs("a.rs", "pub fn f() {}\n");
    let r = analyze(&[a], &["f"], &["a.rs"], &onceish, 2);
    assert!(r.coupling_advisories.is_empty());
}

#[test]
fn r11_manifest_round_trips_serde() {
    let mut layers = std::collections::BTreeMap::new();
    layers.insert("core".to_string(), vec!["core/".to_string()]);
    let manifest = LayerManifest {
        layers,
        allowed: vec![("core".to_string(), "util".to_string())],
    };
    let json = serde_json::to_string(&manifest).unwrap();
    let back: LayerManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(back.allowed, manifest.allowed);
    assert!(back.layers.contains_key("core"));
}
