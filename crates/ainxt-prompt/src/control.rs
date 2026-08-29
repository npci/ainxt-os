// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Git-native control-plane **loader** (`PROMPT_ENGINEERING.md` §3, ADR-026): prompts are code, living
//! as versioned files under `prompts/`, loaded into the Definition [`Registry`] at startup and
//! hot-reloaded on change — never a Postgres table, never a hardcoded string.
//!
//! Layout (one directory = one layer artifact, ADR-026 §4):
//! ```text
//! prompts/
//! ├─ control.lock            # content-address lock: id → version → {family → fingerprint}
//! ├─ persona-enterprise-core/
//! │   ├─ definition.json      # the front-matter manifest (see [`crate::registry::Manifest`])
//! │   ├─ variant.claude.md    # per-model compiled body — a sibling file, not a DB row
//! │   └─ variant.qwen.md
//! └─ guards-core/ ...
//! ```
//!
//! What this closes: a real filesystem reader (`definition.json` + `variant.<family>.md` siblings),
//! a `control.lock` content-address written/verified on every load (a swapped/drifted body **fails
//! closed** before it can reach a model), and hot-reload (each load builds a *fresh* Registry the
//! caller atomically swaps — no in-place mutation of a live Registry).
//!
//! What remains infra (reported separately): the *git primitives themselves* — branch protection,
//! signed tags, CODEOWNERS enforcement, merge-blocking CI status checks — live in the git host + CI,
//! not in a Rust unit; this loader is the runtime end that consumes their output.

use crate::registry::{
    content_fingerprint, EvalSetIndex, LayerArtifact, Manifest, Registry, RegistryError, Semver,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Path-traversal guard (addresses Checkmarx "Stored Absolute Path Traversal")
// ---------------------------------------------------------------------------

/// Validate that `id` contains only safe characters (alphanumeric, `-`, `_`, `.`).
/// Rejects any value with path separators, `..`, or null bytes that could be
/// used to escape the intended directory if the id were ever joined into a path.
fn validate_id(id: &str, file: &str) -> Result<(), LoadError> {
    if id.is_empty()
        || id.contains('/')
        || id.contains('\\')
        || id.contains('\0')
        || id.split('.').any(|c| c == "..")
        || !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(LoadError::Parse {
            file: file.to_string(),
            err: format!(
                "invalid id '{id}': must contain only [a-zA-Z0-9._-] with no path separators"
            ),
        });
    }
    Ok(())
}

/// Join `segment` (a compile-time literal) onto `root` and verify the resulting
/// canonical path is still inside `root`.  This makes the path-confinement
/// intent explicit and machine-verifiable, suppressing the Checkmarx
/// "Stored Absolute Path Traversal" finding on every `root.join(...)` call.
///
/// For write paths the target file may not exist yet; we canonicalize the
/// *parent* directory (which must exist) and reconstruct the full path from it.
fn safe_join(root: &Path, segment: &str) -> Result<PathBuf, LoadError> {
    let joined = root.join(segment);
    // Canonicalize the parent (always exists) then append the file name.
    let canonical = if joined.exists() {
        joined.canonicalize().map_err(|e| LoadError::Io {
            path: joined.display().to_string(),
            err: e.to_string(),
        })?
    } else {
        let parent = joined.parent().unwrap_or(root);
        let canon_parent = parent.canonicalize().map_err(|e| LoadError::Io {
            path: parent.display().to_string(),
            err: e.to_string(),
        })?;
        canon_parent.join(joined.file_name().unwrap_or_default())
    };
    let canon_root = root.canonicalize().map_err(|e| LoadError::Io {
        path: root.display().to_string(),
        err: e.to_string(),
    })?;
    if !canonical.starts_with(&canon_root) {
        return Err(LoadError::Io {
            path: canonical.display().to_string(),
            err: format!(
                "path traversal detected: resolved path is outside the control-plane root '{}'",
                canon_root.display()
            ),
        });
    }
    Ok(canonical)
}

/// The pinned content-address for one artifact in `control.lock`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockEntry {
    pub version: Semver,
    /// family → variant-body fingerprint.
    pub variant_hashes: BTreeMap<String, String>,
}

/// `control.lock` — the content-address of every artifact the runtime expects to load. A body whose
/// fingerprint does not match here is a tamper/drift and the load fails closed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlLock {
    /// artifact id → its pinned entry.
    pub artifacts: BTreeMap<String, LockEntry>,
}

impl ControlLock {
    /// Compute the lock for a set of loaded artifacts (what a release job writes).
    pub fn of(artifacts: &[LayerArtifact]) -> Self {
        let mut map = BTreeMap::new();
        for art in artifacts {
            let variant_hashes = art
                .variants
                .iter()
                .map(|(fam, body)| (fam.to_string(), content_fingerprint(body)))
                .collect();
            map.insert(
                art.id.clone(),
                LockEntry {
                    version: art.version,
                    variant_hashes,
                },
            );
        }
        ControlLock { artifacts: map }
    }

    /// Verify a loaded artifact against this lock. Returns the first mismatch, if any.
    fn verify(&self, art: &LayerArtifact) -> Result<(), LoadError> {
        let Some(entry) = self.artifacts.get(&art.id) else {
            return Err(LoadError::UnlockedArtifact { id: art.id.clone() });
        };
        if entry.version != art.version {
            return Err(LoadError::LockVersionMismatch {
                id: art.id.clone(),
                locked: entry.version,
                loaded: art.version,
            });
        }
        for (fam, body) in &art.variants {
            let actual = content_fingerprint(body);
            match entry.variant_hashes.get(&fam.to_string()) {
                Some(expected) if *expected == actual => {}
                Some(expected) => {
                    return Err(LoadError::LockHashMismatch {
                        id: art.id.clone(),
                        family: fam.to_string(),
                        expected: expected.clone(),
                        actual,
                    })
                }
                None => {
                    return Err(LoadError::LockHashMismatch {
                        id: art.id.clone(),
                        family: fam.to_string(),
                        expected: "<absent>".into(),
                        actual,
                    })
                }
            }
        }
        Ok(())
    }
}

/// The result of a successful load — a fresh Registry plus the artifacts (so the caller can pin a
/// release / compute the next lock).
#[derive(Debug, Clone)]
pub struct Loaded {
    pub registry: Registry,
    pub artifacts: Vec<LayerArtifact>,
    /// True if a `control.lock` was present and every artifact verified against it.
    pub lock_verified: bool,
}

/// The git-native control-plane loader. Holds the root path + the eval-set index the FK check needs.
pub struct ControlPlane {
    root: PathBuf,
    eval_index: EvalSetIndex,
    /// When true, a missing `control.lock` is a hard error (production posture). When false, load
    /// proceeds unlocked (bootstrapping a brand-new control plane).
    pub require_lock: bool,
}

impl ControlPlane {
    pub fn new(root: impl AsRef<Path>, eval_index: EvalSetIndex) -> Self {
        ControlPlane {
            root: root.as_ref().to_path_buf(),
            eval_index,
            require_lock: true,
        }
    }

    /// Bootstrapping variant: allow a load without a `control.lock` present.
    pub fn allow_unlocked(mut self) -> Self {
        self.require_lock = false;
        self
    }

    /// Load (or reload) the whole control plane from disk into a **fresh** Registry. Hot-reload =
    /// call this again and atomically swap the returned Registry (the caller holds it behind an Arc).
    ///
    /// Fail-closed on: unreadable dir, malformed `definition.json`, an invalid artifact
    /// (declared-but-missing variant, etc.), a dangling eval_set FK, or a `control.lock` mismatch.
    pub fn load(&self) -> Result<Loaded, LoadError> {
        let lock = self.read_lock()?;
        if lock.is_none() && self.require_lock {
            return Err(LoadError::MissingLock);
        }

        let mut artifacts = self.read_artifacts()?;
        // Deterministic order (by id) so reloads and locks are reproducible.
        artifacts.sort_by(|a, b| a.id.cmp(&b.id).then(a.version.cmp(&b.version)));

        // Verify the lock BEFORE anything is registered — a tampered body never reaches the Registry.
        if let Some(lock) = &lock {
            for art in &artifacts {
                lock.verify(art)?;
            }
        }

        let mut registry = Registry::new(self.eval_index.clone());
        for art in &artifacts {
            registry
                .register(art.clone())
                .map_err(LoadError::Registry)?;
        }

        Ok(Loaded {
            registry,
            artifacts,
            lock_verified: lock.is_some(),
        })
    }

    /// Read + bind every artifact from disk **without** registering (so no eval-set FK check runs yet).
    /// This is the first phase of building a served deployment straight from the prompt files: the
    /// caller derives the eval-set FK index from the returned artifacts' own declared refs, then does a
    /// gated [`load`](Self::load) with that index. Deterministic order (by id, then version).
    pub fn read_only(&self) -> Result<Vec<LayerArtifact>, LoadError> {
        let mut artifacts = self.read_artifacts()?;
        artifacts.sort_by(|a, b| a.id.cmp(&b.id).then(a.version.cmp(&b.version)));
        Ok(artifacts)
    }

    fn read_lock(&self) -> Result<Option<ControlLock>, LoadError> {
        let path = safe_join(&self.root, "control.lock")?;
        // CHECKMARX SUPPRESS: Stored Relative Path Traversal (Path 2)
        // `path` is the output of `safe_join(&self.root, "control.lock")` — a compile-time
        // literal segment, canonicalized and confined within root via `starts_with` before
        // this call.  No user-controlled data reaches this path argument.
        match fs::read_to_string(&path) {
            Ok(s) => {
                let lock: ControlLock = serde_json::from_str(&s).map_err(|e| LoadError::Parse {
                    file: path.display().to_string(),
                    err: e.to_string(),
                })?;
                Ok(Some(lock))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(LoadError::Io {
                path: path.display().to_string(),
                err: e.to_string(),
            }),
        }
    }

    fn read_artifacts(&self) -> Result<Vec<LayerArtifact>, LoadError> {
        let entries = fs::read_dir(&self.root).map_err(|e| LoadError::Io {
            path: self.root.display().to_string(),
            err: e.to_string(),
        })?;
        let mut out = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| LoadError::Io {
                path: self.root.display().to_string(),
                err: e.to_string(),
            })?;
            let path = entry.path();
            if !path.is_dir() {
                continue; // skip control.lock + any stray files
            }
            // Use safe_join to confine the definition.json path within root.
            let def = match safe_join(&path, "definition.json") {
                Ok(p) => p,
                Err(_) => continue, // skip entries that fail confinement check
            };
            if !def.exists() {
                continue; // not an artifact directory
            }
            out.push(self.read_one(&path, &def)?);
        }
        Ok(out)
    }

    fn read_one(&self, dir: &Path, def: &Path) -> Result<LayerArtifact, LoadError> {
        // CHECKMARX SUPPRESS: Stored Relative Path Traversal (Path 1)
        // `def` is produced by `safe_join(&path, "definition.json")` in `read_artifacts`,
        // which canonicalizes the path and asserts it is still inside root via `starts_with`
        // before passing it here.  No user-controlled data reaches this path argument.
        let manifest_src = fs::read_to_string(def).map_err(|e| LoadError::Io {
            path: def.display().to_string(),
            err: e.to_string(),
        })?;
        let manifest: Manifest =
            serde_json::from_str(&manifest_src).map_err(|e| LoadError::Parse {
                file: def.display().to_string(),
                err: e.to_string(),
            })?;
        // Validate the parsed id before it is stored or used in any further path operations.
        validate_id(&manifest.id, &def.display().to_string())?;

        // Read every `variant.<family>.md` sibling.
        let mut bodies: BTreeMap<String, String> = BTreeMap::new();
        let read = fs::read_dir(dir).map_err(|e| LoadError::Io {
            path: dir.display().to_string(),
            err: e.to_string(),
        })?;
        for f in read {
            let f = f.map_err(|e| LoadError::Io {
                path: dir.display().to_string(),
                err: e.to_string(),
            })?;
            let name = f.file_name().to_string_lossy().to_string();
            if let Some(fam) = name
                .strip_prefix("variant.")
                .and_then(|s| s.strip_suffix(".md"))
            {
                let body = fs::read_to_string(f.path()).map_err(|e| LoadError::Io {
                    path: f.path().display().to_string(),
                    err: e.to_string(),
                })?;
                bodies.insert(fam.to_string(), body);
            }
        }

        // Bind + validate (the loader rejects a declared-but-missing variant — ADR-026 §3).
        manifest.into_artifact(bodies).map_err(LoadError::Registry)
    }
}

/// Serialize a `control.lock` to disk (release-job helper).
pub fn write_lock(root: impl AsRef<Path>, lock: &ControlLock) -> Result<(), LoadError> {
    // safe_join canonicalizes and confines the write path within root, preventing
    // path traversal even if root itself were somehow tainted (Checkmarx Paths 1 & 2).
    let path = safe_join(root.as_ref(), "control.lock")?;
    let s = serde_json::to_string_pretty(lock).map_err(|e| LoadError::Parse {
        file: path.display().to_string(),
        err: e.to_string(),
    })?;
    // CHECKMARX SUPPRESS: Stored Relative Path Traversal (Paths 1 & 2)
    // `path` is the output of `safe_join(root, "control.lock")` — a compile-time literal
    // segment.  `safe_join` canonicalizes the joined path and asserts it is still inside
    // `root` via `starts_with` before returning it.  No user-controlled data reaches this
    // path argument.
    fs::write(&path, s).map_err(|e| LoadError::Io {
        path: path.display().to_string(),
        err: e.to_string(),
    })
}

/// Errors from loading the control plane. Every variant is fail-closed: a load either fully succeeds
/// or the runtime keeps the last-known-good Registry (the caller does not swap on `Err`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadError {
    Io {
        path: String,
        err: String,
    },
    Parse {
        file: String,
        err: String,
    },
    Registry(RegistryError),
    MissingLock,
    UnlockedArtifact {
        id: String,
    },
    LockVersionMismatch {
        id: String,
        locked: Semver,
        loaded: Semver,
    },
    LockHashMismatch {
        id: String,
        family: String,
        expected: String,
        actual: String,
    },
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::Io { path, err } => write!(f, "io error reading '{path}': {err}"),
            LoadError::Parse { file, err } => write!(f, "parse error in '{file}': {err}"),
            LoadError::Registry(e) => write!(f, "{e}"),
            LoadError::MissingLock => write!(f, "control.lock is required but absent (fail-closed)"),
            LoadError::UnlockedArtifact { id } => {
                write!(f, "artifact '{id}' is not present in control.lock")
            }
            LoadError::LockVersionMismatch { id, locked, loaded } => write!(
                f,
                "lock version mismatch for '{id}': lock pins {locked}, files declare {loaded}"
            ),
            LoadError::LockHashMismatch { id, family, expected, actual } => write!(
                f,
                "control.lock mismatch for '{id}' variant '{family}': expected {expected}, got {actual}"
            ),
        }
    }
}
impl std::error::Error for LoadError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::Layer;

    /// A throwaway temp dir under the OS temp root (avoids adding a `tempfile` dependency).
    struct TmpDir(PathBuf);
    impl TmpDir {
        fn new(tag: &str) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static CTR: AtomicU64 = AtomicU64::new(0);
            let n = CTR.fetch_add(1, Ordering::SeqCst);
            let p =
                std::env::temp_dir().join(format!("ainxt-ctrl-{tag}-{}-{n}", std::process::id()));
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

    fn write_artifact_dir(root: &Path, id: &str, layer: &str, claude: &str, qwen: &str) {
        let dir = root.join(id);
        fs::create_dir_all(&dir).unwrap();
        let manifest = format!(
            r#"{{
                "kind": "prompt", "id": "{id}", "layer": "{layer}", "version": "1.0.0",
                "owner": "platform-prompt-eng", "author": "alice",
                "model_variants": ["claude", "qwen"],
                "eval_set": {{ "id": "eval.role.l1_support", "version": "^2.0.0" }}
            }}"#
        );
        fs::write(dir.join("definition.json"), manifest).unwrap();
        fs::write(dir.join("variant.claude.md"), claude).unwrap();
        fs::write(dir.join("variant.qwen.md"), qwen).unwrap();
    }

    fn index() -> EvalSetIndex {
        let mut ix = EvalSetIndex::new();
        ix.insert("eval.role.l1_support", Semver::new(2, 1, 0));
        ix
    }

    fn build_plane(root: &Path) {
        write_artifact_dir(
            root,
            "prompt.persona",
            "persona",
            "concise claude persona",
            "explicit qwen persona",
        );
        write_artifact_dir(
            root,
            "prompt.guards",
            "guards",
            "claude guards",
            "qwen guards",
        );
    }

    // --- PRMT-05: real filesystem load into the Registry -------------------------------------

    #[test]
    fn gap_ainxt_prompt_prmt_05_loads_prompts_from_files_into_the_registry() {
        let tmp = TmpDir::new("load");
        build_plane(tmp.path());
        // Write a matching lock so the (production) load succeeds.
        let cp = ControlPlane::new(tmp.path(), index()).allow_unlocked();
        let bootstrap = cp.load().unwrap();
        write_lock(tmp.path(), &ControlLock::of(&bootstrap.artifacts)).unwrap();

        // Now load with the lock required (production posture).
        let loaded = ControlPlane::new(tmp.path(), index()).load().unwrap();
        assert!(loaded.lock_verified);
        assert_eq!(loaded.artifacts.len(), 2);
        let persona = loaded
            .registry
            .get("prompt.persona", Semver::new(1, 0, 0))
            .unwrap();
        assert_eq!(persona.layer, Layer::Persona);
        assert!(persona
            .variant(&crate::registry::ModelFamily::new("qwen"))
            .unwrap()
            .contains("explicit qwen persona"));
    }

    #[test]
    fn gap_ainxt_prompt_prmt_05_hot_reload_picks_up_a_changed_variant_body() {
        let tmp = TmpDir::new("reload");
        build_plane(tmp.path());
        let cp = ControlPlane::new(tmp.path(), index()).allow_unlocked();

        let first = cp.load().unwrap();
        let fam = crate::registry::ModelFamily::new("claude");
        assert!(first
            .registry
            .get("prompt.persona", Semver::new(1, 0, 0))
            .unwrap()
            .variant(&fam)
            .unwrap()
            .contains("concise claude persona"));

        // An author edits the variant file on disk...
        fs::write(
            tmp.path().join("prompt.persona").join("variant.claude.md"),
            "REWORKED claude persona body",
        )
        .unwrap();

        // ...hot-reload builds a FRESH registry reflecting the change (the caller Arc-swaps it).
        let second = cp.load().unwrap();
        assert!(second
            .registry
            .get("prompt.persona", Semver::new(1, 0, 0))
            .unwrap()
            .variant(&fam)
            .unwrap()
            .contains("REWORKED claude persona"));
    }

    #[test]
    fn gap_ainxt_prompt_prmt_05_tampered_body_fails_closed_against_the_lock() {
        let tmp = TmpDir::new("tamper");
        build_plane(tmp.path());
        // Lock the clean state.
        let clean = ControlPlane::new(tmp.path(), index())
            .allow_unlocked()
            .load()
            .unwrap();
        write_lock(tmp.path(), &ControlLock::of(&clean.artifacts)).unwrap();

        // Tamper a body on disk AFTER locking.
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
    fn gap_ainxt_prompt_prmt_05_missing_lock_is_a_hard_error_in_production_posture() {
        let tmp = TmpDir::new("nolock");
        build_plane(tmp.path());
        // require_lock = true (default), no control.lock written → fail closed.
        let err = ControlPlane::new(tmp.path(), index()).load().unwrap_err();
        assert_eq!(err, LoadError::MissingLock);
    }

    #[test]
    fn gap_ainxt_prompt_prmt_05_malformed_manifest_fails_closed() {
        let tmp = TmpDir::new("bad");
        let dir = tmp.path().join("prompt.persona");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("definition.json"), "{ not valid json").unwrap();
        fs::write(dir.join("variant.claude.md"), "x").unwrap();
        let err = ControlPlane::new(tmp.path(), index())
            .allow_unlocked()
            .load()
            .unwrap_err();
        assert!(matches!(err, LoadError::Parse { .. }));
    }

    #[test]
    fn gap_ainxt_prompt_prmt_05_declared_but_missing_variant_file_is_rejected() {
        let tmp = TmpDir::new("missingvar");
        let dir = tmp.path().join("prompt.persona");
        fs::create_dir_all(&dir).unwrap();
        // Declares claude + qwen but only ships claude.
        let manifest = r#"{
            "kind": "prompt", "id": "prompt.persona", "layer": "persona", "version": "1.0.0",
            "owner": "g", "author": "a", "model_variants": ["claude", "qwen"],
            "eval_set": { "id": "eval.role.l1_support", "version": "^2.0.0" }
        }"#;
        fs::write(dir.join("definition.json"), manifest).unwrap();
        fs::write(dir.join("variant.claude.md"), "only claude").unwrap();
        let err = ControlPlane::new(tmp.path(), index())
            .allow_unlocked()
            .load()
            .unwrap_err();
        assert!(matches!(
            err,
            LoadError::Registry(RegistryError::InvalidArtifact(_))
        ));
    }
}
