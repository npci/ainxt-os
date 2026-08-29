// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R11 (Prompt Engineering, §3) — the RUNTIME END of the git-native control plane enforces the pinned
//! content-address before any prompt reaches a model: a production load requires `control.lock`, a
//! swapped/drifted body fails closed against it, and hot-reload builds a fresh Registry. This is the
//! consumer of the git-host primitives (branch protection / signed tags / CODEOWNERS / merge-block CI)
//! — those live in the git host + CI and are reported infra_gated; this test proves the runtime side.
//!
//! FAIL-BEFORE: exercises the public control-plane API from OUTSIDE the crate. Offline + deterministic.

use ainxt_prompt::control::{ControlLock, ControlPlane, LoadError};
use ainxt_prompt::registry::{EvalSetIndex, Semver};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static CTR: AtomicU64 = AtomicU64::new(0);

struct TmpDir(PathBuf);
impl TmpDir {
    fn new(tag: &str) -> Self {
        let n = CTR.fetch_add(1, Ordering::SeqCst);
        let p =
            std::env::temp_dir().join(format!("ainxt-r11-ctrl-{tag}-{}-{n}", std::process::id()));
        fs::create_dir_all(&p).unwrap();
        TmpDir(p)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn write_artifact(root: &Path, id: &str, layer: &str, claude: &str, qwen: &str) {
    let dir = root.join(id);
    fs::create_dir_all(&dir).unwrap();
    let manifest = format!(
        r#"{{
            "kind": "prompt", "id": "{id}", "layer": "{layer}", "version": "1.0.0",
            "owner": "platform-prompt-eng", "author": "alice",
            "model_variants": ["claude", "qwen"],
            "eval_set": {{ "id": "eval.role.chat", "version": "^2.0.0" }}
        }}"#
    );
    fs::write(dir.join("definition.json"), manifest).unwrap();
    fs::write(dir.join("variant.claude.md"), claude).unwrap();
    fs::write(dir.join("variant.qwen.md"), qwen).unwrap();
}

fn index() -> EvalSetIndex {
    let mut ix = EvalSetIndex::new();
    ix.insert("eval.role.chat", Semver::new(2, 1, 0));
    ix
}

#[test]
fn r11_production_load_requires_lock_and_fails_closed_on_a_tampered_body() {
    let tmp = TmpDir::new("enforce");
    write_artifact(
        tmp.path(),
        "prompt.persona",
        "persona",
        "concise persona",
        "explicit persona",
    );
    write_artifact(
        tmp.path(),
        "prompt.guards",
        "guards",
        "claude guards",
        "qwen guards",
    );

    // Production posture (require_lock = true) with NO lock present → hard error.
    let err = ControlPlane::new(tmp.path(), index()).load().unwrap_err();
    assert_eq!(err, LoadError::MissingLock);

    // Bootstrap once (unlocked), pin the clean content-address.
    let boot = ControlPlane::new(tmp.path(), index())
        .allow_unlocked()
        .load()
        .unwrap();
    ainxt_prompt::control::write_lock(tmp.path(), &ControlLock::of(&boot.artifacts)).unwrap();

    // Now a production load verifies against the lock.
    let loaded = ControlPlane::new(tmp.path(), index()).load().unwrap();
    assert!(loaded.lock_verified);
    assert_eq!(loaded.artifacts.len(), 2);

    // Tamper a body AFTER locking → the load fails closed (the body never reaches the Registry).
    fs::write(
        tmp.path().join("prompt.guards").join("variant.claude.md"),
        "SWAPPED malicious guards",
    )
    .unwrap();
    let err = ControlPlane::new(tmp.path(), index()).load().unwrap_err();
    assert!(
        matches!(err, LoadError::LockHashMismatch { .. }),
        "a swapped body must fail closed against control.lock, got {err:?}"
    );
}

#[test]
fn r11_hot_reload_builds_a_fresh_registry_from_the_files() {
    let tmp = TmpDir::new("reload");
    write_artifact(
        tmp.path(),
        "prompt.persona",
        "persona",
        "v1 claude persona",
        "v1 qwen persona",
    );
    let cp = ControlPlane::new(tmp.path(), index()).allow_unlocked();

    let first = cp.load().unwrap();
    let fam = ainxt_prompt::registry::ModelFamily::new("claude");
    assert!(first
        .registry
        .get("prompt.persona", Semver::new(1, 0, 0))
        .unwrap()
        .variant(&fam)
        .unwrap()
        .contains("v1 claude persona"));

    // An author edits the file on disk; a reload reflects it in a fresh Registry (caller Arc-swaps).
    fs::write(
        tmp.path().join("prompt.persona").join("variant.claude.md"),
        "v2 claude persona",
    )
    .unwrap();
    let second = cp.load().unwrap();
    assert!(second
        .registry
        .get("prompt.persona", Semver::new(1, 0, 0))
        .unwrap()
        .variant(&fam)
        .unwrap()
        .contains("v2 claude persona"));
}
