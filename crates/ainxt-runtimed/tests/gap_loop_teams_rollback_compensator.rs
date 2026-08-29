// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! gap loop-teams-longhorizon (item 4, rollback mock-only): proves [`GitRevertingProgramVerifier`]
//! performs a REAL git-level rollback side effect, not a mock.
//!
//! Before this gap closed, the only `compensate`-shaped abstraction anywhere in the codebase
//! (`ainxt_planner::program::Compensator`) had exactly ONE implementor in existence — a test fake
//! (`HalfBrokenComp`) inside `ainxt-planner`'s own unit tests — and no driver ever called it: a
//! "rolled back" node was only ever a durable STATE transition (`NodeState::RolledBack`); the actual
//! git commit it represented was never reverted in any real repository. This test drives
//! `GitRevertingProgramVerifier::compensate` against a REAL temporary git repository and asserts the
//! offending commit is genuinely undone — a new revert commit exists and the file content is back to
//! its pre-bad-commit state — never a fabricated success.

use ainxt_planner::program::NodeId;
use ainxt_planner::supervisor::ProgramVerifier;
use ainxt_runtimed::{GitRevertingProgramVerifier, PermissiveProgramVerifier};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

/// A fresh, unique scratch directory under the OS temp dir — avoids pulling in a `tempfile`
/// dependency for a handful of tests. Deliberately NOT auto-removed (best-effort `rm -rf` on drop via
/// [`ScratchDir`]) so a failed assertion leaves the repo inspectable.
struct ScratchDir(PathBuf);

impl ScratchDir {
    fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "ainxt-rollback-compensator-test-{}-{}-{n}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).expect("create scratch dir");
        ScratchDir(path)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Run a git command in `dir`, panicking with full output on failure — test setup must be reliable.
fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .expect("spawn git");
    assert!(
        out.status.success(),
        "git {:?} failed: stdout={} stderr={}",
        args,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// A real temp git repo with one good commit, then one "bad" commit whose SHA the test will
/// compensate away. Returns `(repo_dir, bad_commit_sha)`.
fn repo_with_a_bad_commit() -> (ScratchDir, String) {
    let dir = ScratchDir::new();
    let path = dir.path();
    git(path, &["init", "-q"]);
    git(path, &["config", "user.email", "test@ainxt.local"]);
    git(path, &["config", "user.name", "ainxt-test"]);

    std::fs::write(path.join("module.txt"), "good state\n").unwrap();
    git(path, &["add", "."]);
    git(path, &["commit", "-q", "-m", "good: initial module"]);

    // The "bad" commit — this is the one the program node produced and later needs undone.
    std::fs::write(path.join("module.txt"), "BROKEN state\n").unwrap();
    git(path, &["add", "."]);
    git(path, &["commit", "-q", "-m", "bad: node's broken commit"]);
    let bad_sha = git(path, &["rev-parse", "HEAD"]);

    (dir, bad_sha)
}

#[test]
fn git_reverting_verifier_actually_undoes_the_commit_in_a_real_repo() {
    let (dir, bad_sha) = repo_with_a_bad_commit();
    let path = dir.path().to_path_buf();

    // Sanity: the working tree currently reflects the BAD commit.
    assert_eq!(
        std::fs::read_to_string(path.join("module.txt")).unwrap(),
        "BROKEN state\n"
    );

    let mut verifier = GitRevertingProgramVerifier::new(PermissiveProgramVerifier, path.clone());
    let node = NodeId::new("bad-module");
    let result = verifier.compensate(&node, &[bad_sha.clone()]);
    assert!(result.is_ok(), "compensate must succeed: {result:?}");

    // The REAL git history now contains a revert commit undoing the bad SHA.
    let log = git(&path, &["log", "--oneline"]);
    assert!(
        log.to_lowercase().contains("revert"),
        "git log must show a real revert commit, got: {log}"
    );

    // The REAL working tree content is restored to the pre-bad-commit state — not a state-machine
    // fiction, an actual file on disk.
    assert_eq!(
        std::fs::read_to_string(path.join("module.txt")).unwrap(),
        "good state\n",
        "the working tree must be genuinely restored by the real git revert"
    );
}

/// A node with no real commits ever recorded has nothing to undo — vacuously compensated, never an
/// error (a node that never produced a committable artifact should not block an honest rollback).
#[test]
fn git_reverting_verifier_is_vacuously_ok_with_no_commit_shas() {
    let dir = ScratchDir::new();
    let mut verifier =
        GitRevertingProgramVerifier::new(PermissiveProgramVerifier, dir.path().to_path_buf());
    let node = NodeId::new("never-committed");
    assert_eq!(verifier.compensate(&node, &[]), Ok(()));
}

/// A SHA that does not exist in the repo is a real, honest failure — never silently swallowed as a
/// success (the FAILED_PARTIAL case the design's §9 rollback discipline requires).
#[test]
fn git_reverting_verifier_reports_a_real_failure_for_an_unknown_sha() {
    let dir = ScratchDir::new();
    let path = dir.path().to_path_buf();
    git(&path, &["init", "-q"]);
    git(&path, &["config", "user.email", "test@ainxt.local"]);
    git(&path, &["config", "user.name", "ainxt-test"]);
    std::fs::write(path.join("f.txt"), "x\n").unwrap();
    git(&path, &["add", "."]);
    git(&path, &["commit", "-q", "-m", "init"]);

    let mut verifier = GitRevertingProgramVerifier::new(PermissiveProgramVerifier, path);
    let node = NodeId::new("bad-module");
    let result = verifier.compensate(
        &node,
        &["0000000000000000000000000000000000000000".to_string()],
    );
    assert!(
        result.is_err(),
        "an unknown SHA must be an honest failure, never a fabricated success"
    );
}

/// The wrapper delegates every OTHER `ProgramVerifier` seam unchanged — it overrides `compensate`
/// ONLY, so wrapping an existing verifier never silently changes edge/sweep/judge behavior.
#[test]
fn git_reverting_verifier_delegates_every_other_seam_unchanged() {
    let dir = ScratchDir::new();
    let mut verifier =
        GitRevertingProgramVerifier::new(PermissiveProgramVerifier, dir.path().to_path_buf());
    let a = NodeId::new("a");
    let b = NodeId::new("b");
    assert!(verifier.verify_edge(&a, &b).is_complete());
    assert!(verifier
        .regression_sweep(&[a.clone(), b.clone()])
        .is_complete());
    let judge = verifier.program_judge();
    assert!(judge.completed && judge.score >= judge.threshold);
}
