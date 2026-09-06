// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Git-native skill control-plane **loader** (ADR-026), mirroring
//! [`ainxt_prompt::control::ControlPlane`]'s pattern: skills are code, living as versioned files under
//! a `skills/` root, loaded into a fresh [`SkillRegistry`] at startup and hot-reloadable on change —
//! never a Postgres table, never a compiled-in Rust constant.
//!
//! GAP-FIX surfaces-profiles-skills-config (ADR-026) — before this module existed, the ONLY way a
//! served [`crate::SkillRuntime`] got populated was [`crate::SkillRuntime::with_builtins`] /
//! [`with_builtins_and_wasm`](crate::SkillRuntime::with_builtins_and_wasm): the eight compiled-in
//! [`crate::builtin`] manifests. `ainxt-prompt` already had a real file-native loader
//! ([`ainxt_prompt::control::ControlPlane`]) wired to the daemon via `[server] prompt_dir`
//! (`ainxt-runtimed/src/lib.rs`'s `build_served_chat_prompt`); the skill side had no analogous loader
//! at all — a deployment could not add or edit a skill without recompiling the binary. This module is
//! that missing loader; `ainxt-runtimed` wires it behind a new `[server] skill_dir` key.
//!
//! Layout (one directory = one skill, deliberately simpler than the prompt tree's per-family variant
//! siblings — a skill has exactly one body, never a per-model variant):
//! ```text
//! skills/
//! ├─ control.lock                  # content-address lock: id\t<fingerprint>, one per line
//! ├─ rca-procedure/
//! │   └─ definition.md             # front matter (id/type/description) + the skill body
//! └─ turn-header/
//!     └─ definition.md
//! ```
//!
//! `definition.md` front matter is a minimal `key: value` block delimited by `---` lines (no YAML/JSON
//! parser dependency — this crate ships with zero new dependencies):
//! ```text
//! ---
//! id: rca-procedure
//! type: behavioral
//! description: Root-cause-analysis procedure for a production incident.
//! ---
//! Follow the Root-Cause-Analysis procedure: ...
//! ```
//! Everything after the closing `---` line is the skill body verbatim (trimmed of leading/trailing
//! blank lines), matching [`SkillManifest::body`] — the SOP text for a behavioral skill, or the runner
//! template/instruction for an execution skill.
//!
//! What this closes: a real filesystem reader (`definition.md` per skill directory), a `control.lock`
//! content-address verified on every load (a swapped/drifted body **fails closed** before it can reach
//! a served turn), and hot-reload (each [`SkillControlPlane::load`] call builds a *fresh*
//! [`SkillRegistry`] the caller atomically swaps — no in-place mutation of a live registry).
//!
//! What remains infra (reported separately, exactly like the prompt loader's own doc): the git
//! primitives themselves — branch protection, signed tags, CODEOWNERS enforcement, merge-blocking CI —
//! live in the git host + CI, not in this Rust unit; this loader is the runtime end that consumes their
//! output.

use crate::{
    builtin, DispatchingSkillExecutor, NativeSkillExecutor, SkillExecutor, SkillManifest,
    SkillRegistry, SkillRuntime, SkillType, WasmSkillExecutor,
};
use std::collections::BTreeMap;
use std::fmt;
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

/// A dependency-free 128-bit content fingerprint (same FNV-style construction
/// `ainxt_prompt::registry::content_fingerprint` uses) — deliberately duplicated rather than adding an
/// inter-crate dependency just for one pure hash function; `ainxt-skill` has no other reason to depend
/// on `ainxt-prompt` and the two loaders are otherwise independent.
fn content_fingerprint(s: &str) -> String {
    const OFF1: u64 = 0xcbf2_9ce4_8422_2325;
    const OFF2: u64 = 0x8422_2325_cbf2_9ce4;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h1 = OFF1;
    let mut h2 = OFF2;
    for b in s.bytes() {
        h1 = (h1 ^ b as u64).wrapping_mul(PRIME);
        h2 = (h2 ^ (b as u64).rotate_left(5)).wrapping_mul(PRIME);
    }
    format!("{h1:016x}{h2:016x}")
}

/// The content-address of one loaded [`SkillManifest`]: every field (id/type/description/body) folds
/// into the fingerprint, NUL-separated so no field boundary can be confused with in-field content — a
/// tamper to ANY field (not just the body) is detected.
fn manifest_fingerprint(m: &SkillManifest) -> String {
    let ty = match m.skill_type {
        SkillType::Behavioral => "behavioral",
        SkillType::Execution => "execution",
    };
    content_fingerprint(&format!("{}\0{}\0{}\0{}", m.id, ty, m.description, m.body))
}

/// `control.lock` — the content-address of every skill the runtime expects to load. A skill whose
/// fingerprint does not match here is a tamper/drift and the load fails closed. Plain text (one
/// `<id>\t<fingerprint>` line per skill) rather than JSON/YAML — this crate ships with zero new
/// dependencies for the loader.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ControlLock {
    /// skill id → its pinned fingerprint.
    pub skills: BTreeMap<String, String>,
}

impl ControlLock {
    /// Compute the lock for a set of loaded manifests (what a release job writes).
    pub fn of(manifests: &[SkillManifest]) -> Self {
        let skills = manifests
            .iter()
            .map(|m| (m.id.clone(), manifest_fingerprint(m)))
            .collect();
        ControlLock { skills }
    }

    fn verify(&self, m: &SkillManifest) -> Result<(), LoadError> {
        match self.skills.get(&m.id) {
            None => Err(LoadError::UnlockedSkill { id: m.id.clone() }),
            Some(expected) => {
                let actual = manifest_fingerprint(m);
                if *expected == actual {
                    Ok(())
                } else {
                    Err(LoadError::LockHashMismatch {
                        id: m.id.clone(),
                        expected: expected.clone(),
                        actual,
                    })
                }
            }
        }
    }

    fn to_lock_text(&self) -> String {
        let mut out = String::new();
        for (id, fp) in &self.skills {
            out.push_str(id);
            out.push('\t');
            out.push_str(fp);
            out.push('\n');
        }
        out
    }

    fn parse_lock_text(s: &str) -> Result<Self, LoadError> {
        let mut skills = BTreeMap::new();
        for (n, line) in s.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let Some((id, fp)) = line.split_once('\t') else {
                return Err(LoadError::Parse {
                    file: "control.lock".to_string(),
                    err: format!("line {}: expected '<id>\\t<fingerprint>'", n + 1),
                });
            };
            skills.insert(id.to_string(), fp.to_string());
        }
        Ok(ControlLock { skills })
    }
}

/// The result of a successful load — a fresh [`SkillRegistry`] plus the manifests (so the caller can
/// pin a release / compute the next lock).
#[derive(Debug, Clone)]
pub struct Loaded {
    pub registry: SkillRegistry,
    pub manifests: Vec<SkillManifest>,
    /// True if a `control.lock` was present and every manifest verified against it.
    pub lock_verified: bool,
}

/// The git-native skill control-plane loader. Holds the root path the manifests are read from.
pub struct SkillControlPlane {
    root: PathBuf,
    /// When true, a missing `control.lock` is a hard error (production posture). When false, load
    /// proceeds unlocked (bootstrapping a brand-new control plane).
    pub require_lock: bool,
}

impl SkillControlPlane {
    pub fn new(root: impl AsRef<Path>) -> Self {
        SkillControlPlane {
            root: root.as_ref().to_path_buf(),
            require_lock: true,
        }
    }

    /// Bootstrapping variant: allow a load without a `control.lock` present.
    pub fn allow_unlocked(mut self) -> Self {
        self.require_lock = false;
        self
    }

    /// Load (or reload) the whole skill tree from disk into a **fresh** [`SkillRegistry`]. Hot-reload =
    /// call this again and atomically swap the returned registry (the caller holds it behind an Arc).
    ///
    /// Fail-closed on: unreadable dir, malformed/incomplete `definition.md` front matter, a duplicate
    /// skill id across two directories, or a `control.lock` mismatch.
    pub fn load(&self) -> Result<Loaded, LoadError> {
        let lock = self.read_lock()?;
        if lock.is_none() && self.require_lock {
            return Err(LoadError::MissingLock);
        }

        let mut manifests = self.read_manifests()?;
        // Deterministic order (by id) so reloads and locks are reproducible.
        manifests.sort_by(|a, b| a.id.cmp(&b.id));

        // Verify the lock BEFORE anything is registered — a tampered body never reaches the registry.
        if let Some(lock) = &lock {
            for m in &manifests {
                lock.verify(m)?;
            }
        }

        let mut registry = SkillRegistry::new();
        for m in &manifests {
            if registry.register(m.clone()).is_some() {
                return Err(LoadError::DuplicateId(m.id.clone()));
            }
        }

        Ok(Loaded {
            registry,
            manifests,
            lock_verified: lock.is_some(),
        })
    }

    /// Read every manifest from disk **without** registering (first phase of a served build that needs
    /// to inspect the manifests — e.g. to compute a fresh lock — before a gated [`load`](Self::load)).
    pub fn read_only(&self) -> Result<Vec<SkillManifest>, LoadError> {
        let mut manifests = self.read_manifests()?;
        manifests.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(manifests)
    }

    fn read_lock(&self) -> Result<Option<ControlLock>, LoadError> {
        let path = safe_join(&self.root, "control.lock")?;
        // CHECKMARX SUPPRESS: Stored Relative Path Traversal (Path 3)
        // `path` is the output of `safe_join(&self.root, "control.lock")` — a compile-time
        // literal segment, canonicalized and confined within root via `starts_with` before
        // this call.  No user-controlled data reaches this path argument.
        match fs::read_to_string(&path) {
            Ok(s) => ControlLock::parse_lock_text(&s).map(Some),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(LoadError::Io {
                path: path.display().to_string(),
                err: e.to_string(),
            }),
        }
    }

    fn read_manifests(&self) -> Result<Vec<SkillManifest>, LoadError> {
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
            // Use safe_join to confine the definition.md path within the skill directory.
            let def = match safe_join(&path, "definition.md") {
                Ok(p) => p,
                Err(_) => continue, // skip entries that fail confinement check
            };
            if !def.exists() {
                continue; // not a skill directory
            }
            out.push(self.read_one(&def)?);
        }
        Ok(out)
    }

    fn read_one(&self, def: &Path) -> Result<SkillManifest, LoadError> {
        let src = fs::read_to_string(def).map_err(|e| LoadError::Io {
            path: def.display().to_string(),
            err: e.to_string(),
        })?;
        let (front, body) = split_front_matter(&src).ok_or_else(|| LoadError::Parse {
            file: def.display().to_string(),
            err: "missing front matter ('---' ... '---' block) at the top of definition.md".into(),
        })?;

        let mut id: Option<String> = None;
        let mut skill_type: Option<SkillType> = None;
        let mut description = String::new();
        for (n, line) in front.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let Some((k, v)) = line.split_once(':') else {
                return Err(LoadError::Parse {
                    file: def.display().to_string(),
                    err: format!("front matter line {}: expected 'key: value'", n + 1),
                });
            };
            let k = k.trim();
            let v = v.trim().to_string();
            match k {
                "id" if id.is_none() => id = Some(v),
                "id" => {
                    return Err(LoadError::Parse {
                        file: def.display().to_string(),
                        err: "duplicate 'id' in front matter".into(),
                    })
                }
                "type" if skill_type.is_none() => {
                    skill_type = Some(match v.as_str() {
                        "behavioral" => SkillType::Behavioral,
                        "execution" => SkillType::Execution,
                        other => {
                            return Err(LoadError::Parse {
                                file: def.display().to_string(),
                                err: format!(
                                "invalid 'type': '{other}' (expected 'behavioral' or 'execution')"
                            ),
                            })
                        }
                    });
                }
                "type" => {
                    return Err(LoadError::Parse {
                        file: def.display().to_string(),
                        err: "duplicate 'type' in front matter".into(),
                    })
                }
                "description" => description = v,
                other => {
                    return Err(LoadError::Parse {
                        file: def.display().to_string(),
                        err: format!("unknown front-matter field '{other}'"),
                    })
                }
            }
        }
        let id = id.ok_or_else(|| LoadError::Parse {
            file: def.display().to_string(),
            err: "missing required 'id' in front matter".into(),
        })?;
        // Validate the parsed id before it is stored or used in any further path operations.
        // This closes the theoretical path-traversal risk if the id were ever joined into a
        // filesystem path (Checkmarx "Stored Absolute Path Traversal" — Path 3).
        validate_id(&id, &def.display().to_string())?;
        let skill_type = skill_type.ok_or_else(|| LoadError::Parse {
            file: def.display().to_string(),
            err: "missing required 'type' in front matter".into(),
        })?;

        Ok(SkillManifest {
            id,
            skill_type,
            description,
            body: body.trim().to_string(),
        })
    }
}

/// Split `src` into its front-matter block and body, given `src` opens with a `---` delimiter line and
/// closes with a bare `---` line. Returns `None` if `src` does not open with `---` or no closing
/// delimiter line is found.
fn split_front_matter(src: &str) -> Option<(&str, &str)> {
    let src = src.strip_prefix('\u{feff}').unwrap_or(src); // tolerate a UTF-8 BOM
    let after_open = src.strip_prefix("---")?;
    let after_open = match after_open.strip_prefix("\r\n") {
        Some(r) => r,
        None => after_open.strip_prefix('\n')?,
    };
    let mut offset = 0usize;
    for line in after_open.split_inclusive('\n') {
        let trimmed = line.trim_end_matches(['\n', '\r']);
        if trimmed == "---" {
            let front = &after_open[..offset];
            let body = &after_open[offset + line.len()..];
            return Some((front, body));
        }
        offset += line.len();
    }
    None
}

/// Build the merged [`SkillRegistry`] (compiled-in [`builtin`] floor + git-native file-declared skills
/// from `root`, file wins on a matching id) WITHOUT constructing a new executor. This is the piece
/// [`SkillRuntime::reload`] needs (ADR-026 §6.2 hot-reload, `ainxt-server`'s `POST /admin/reload`): a
/// fresh registry published onto an EXISTING `SkillRuntime` via one atomic swap, leaving its executor
/// (native, or dispatching-to-WASM) completely undisturbed across the reload. [`skill_runtime_from_dir`]
/// is built on top of this for the (rarer) case of constructing a whole fresh runtime.
///
/// Fails closed on any load error from [`SkillControlPlane::load`] — never a silent partial/builtin-
/// only registry, and (per [`SkillControlPlane::load`]'s own contract) a caller that gets `Err` here
/// must NOT swap anything: the existing registry stays the last-known-good one.
pub fn merged_registry_from_dir(
    root: impl AsRef<Path>,
) -> Result<(SkillRegistry, Loaded), LoadError> {
    let cp = SkillControlPlane::new(root);
    let loaded = cp.load()?;

    let mut registry = SkillRegistry::new();
    for m in builtin::manifests() {
        registry.register(m);
    }
    // File-declared skills are registered AFTER the builtin floor, so a same-id file overrides the
    // compiled-in default (`SkillRegistry::register` replaces on a matching id).
    for m in &loaded.manifests {
        registry.register(m.clone());
    }
    Ok((registry, loaded))
}

/// Build a served [`SkillRuntime`] whose registry is the git-native skill tree at `root`
/// ([`SkillControlPlane::load`]) LAYERED OVER the compiled-in [`builtin`] skills: a file-declared skill
/// whose id matches a builtin's OVERRIDES it (a deployment can redefine `citation-discipline` without
/// a recompile); every builtin id the tree does NOT redeclare stays available, so a profile written
/// before a `skill_dir` existed keeps resolving unchanged. This is the file-backed analogue of
/// [`SkillRuntime::with_builtins`]/[`SkillRuntime::with_builtins_and_wasm`] — the bridge the audit
/// flagged as missing (no loader ever populated `SkillManifest` from a real git-native source).
///
/// `wasm`, when `Some`, dispatches execution skills through the sandboxed [`WasmSkillExecutor`] first
/// (any id with a registered module runs sandboxed), falling back to the trusted native handlers —
/// including every builtin — for everything else, mirroring `with_builtins_and_wasm`. `None` uses the
/// native executor alone, mirroring `with_builtins`.
///
/// Fails closed on any load error from [`SkillControlPlane::load`] (unreadable dir, malformed
/// `definition.md`, a `control.lock` mismatch, a duplicate id across two directories) — never a silent
/// partial/builtin-only registry.
pub fn skill_runtime_from_dir(
    root: impl AsRef<Path>,
    wasm: Option<WasmSkillExecutor>,
) -> Result<(SkillRuntime, Loaded), LoadError> {
    let (registry, loaded) = merged_registry_from_dir(root)?;

    let mut native = NativeSkillExecutor::new();
    builtin::register_handlers(&mut native);
    let executor: Box<dyn SkillExecutor> = match wasm {
        Some(w) => Box::new(DispatchingSkillExecutor::new(native, w)),
        None => Box::new(native),
    };

    let runtime = SkillRuntime::new(registry, executor);
    Ok((runtime, loaded))
}

/// Serialize a `control.lock` to disk (release-job helper).
pub fn write_lock(root: impl AsRef<Path>, lock: &ControlLock) -> Result<(), LoadError> {
    // safe_join canonicalizes and confines the write path within root, preventing
    // path traversal even if root itself were somehow tainted (Checkmarx Path 3).
    let path = safe_join(root.as_ref(), "control.lock")?;
    // CHECKMARX SUPPRESS: Stored Relative Path Traversal (Path 3)
    // `path` is the output of `safe_join(root, "control.lock")` — a compile-time literal
    // segment.  `safe_join` canonicalizes the joined path and asserts it is still inside
    // `root` via `starts_with` before returning it.  No user-controlled data reaches this
    // path argument.
    fs::write(&path, lock.to_lock_text()).map_err(|e| LoadError::Io {
        path: path.display().to_string(),
        err: e.to_string(),
    })
}

/// Errors from loading the skill control plane. Every variant is fail-closed: a load either fully
/// succeeds or the runtime keeps the last-known-good registry (the caller does not swap on `Err`).
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
    MissingLock,
    UnlockedSkill {
        id: String,
    },
    LockHashMismatch {
        id: String,
        expected: String,
        actual: String,
    },
    /// Two skill directories declared the SAME `id` in their front matter — never silently let the
    /// later one win (that would be a config drift a caller cannot observe).
    DuplicateId(String),
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoadError::Io { path, err } => write!(f, "io error reading '{path}': {err}"),
            LoadError::Parse { file, err } => write!(f, "parse error in '{file}': {err}"),
            LoadError::MissingLock => {
                write!(f, "control.lock is required but absent (fail-closed)")
            }
            LoadError::UnlockedSkill { id } => {
                write!(f, "skill '{id}' is not present in control.lock")
            }
            LoadError::LockHashMismatch {
                id,
                expected,
                actual,
            } => write!(
                f,
                "control.lock mismatch for skill '{id}': expected {expected}, got {actual}"
            ),
            LoadError::DuplicateId(id) => {
                write!(
                    f,
                    "duplicate skill id '{id}' declared by more than one directory"
                )
            }
        }
    }
}
impl std::error::Error for LoadError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// A throwaway temp dir under the OS temp root (avoids adding a `tempfile` dependency).
    struct TmpDir(PathBuf);
    impl TmpDir {
        fn new(tag: &str) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static CTR: AtomicU64 = AtomicU64::new(0);
            let n = CTR.fetch_add(1, Ordering::SeqCst);
            let p = std::env::temp_dir()
                .join(format!("ainxt-skill-ctrl-{tag}-{}-{n}", std::process::id()));
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

    fn write_skill_dir(root: &Path, id: &str, kind: &str, description: &str, body: &str) {
        let dir = root.join(id);
        fs::create_dir_all(&dir).unwrap();
        let content =
            format!("---\nid: {id}\ntype: {kind}\ndescription: {description}\n---\n{body}\n");
        fs::write(dir.join("definition.md"), content).unwrap();
    }

    fn build_plane(root: &Path) {
        write_skill_dir(
            root,
            "rca-procedure",
            "behavioral",
            "Root-cause-analysis SOP",
            "Follow the RCA procedure.",
        );
        write_skill_dir(
            root,
            "turn-header",
            "execution",
            "Deterministic turn-context header",
            "Request under consideration: {input}",
        );
    }

    #[test]
    fn gap_ainxt_skill_loads_skills_from_files_into_the_registry() {
        let tmp = TmpDir::new("load");
        build_plane(tmp.path());
        let cp = SkillControlPlane::new(tmp.path()).allow_unlocked();
        let bootstrap = cp.load().unwrap();
        write_lock(tmp.path(), &ControlLock::of(&bootstrap.manifests)).unwrap();

        // Now load with the lock required (production posture).
        let loaded = SkillControlPlane::new(tmp.path()).load().unwrap();
        assert!(loaded.lock_verified);
        assert_eq!(loaded.manifests.len(), 2);
        let rca = loaded.registry.get("rca-procedure").unwrap();
        assert_eq!(rca.skill_type, SkillType::Behavioral);
        assert!(rca.body.contains("RCA procedure"));
        let header = loaded.registry.get("turn-header").unwrap();
        assert_eq!(header.skill_type, SkillType::Execution);
    }

    #[test]
    fn gap_ainxt_skill_hot_reload_picks_up_a_changed_body() {
        let tmp = TmpDir::new("reload");
        build_plane(tmp.path());
        let cp = SkillControlPlane::new(tmp.path()).allow_unlocked();

        let first = cp.load().unwrap();
        assert!(first
            .registry
            .get("rca-procedure")
            .unwrap()
            .body
            .contains("Follow the RCA procedure."));

        // An author edits the skill body on disk...
        write_skill_dir(
            tmp.path(),
            "rca-procedure",
            "behavioral",
            "Root-cause-analysis SOP",
            "REWORKED rca body.",
        );

        // ...hot-reload builds a FRESH registry reflecting the change (the caller Arc-swaps it).
        let second = cp.load().unwrap();
        assert!(second
            .registry
            .get("rca-procedure")
            .unwrap()
            .body
            .contains("REWORKED rca body."));
    }

    #[test]
    fn gap_ainxt_skill_tampered_body_fails_closed_against_the_lock() {
        let tmp = TmpDir::new("tamper");
        build_plane(tmp.path());
        let clean = SkillControlPlane::new(tmp.path())
            .allow_unlocked()
            .load()
            .unwrap();
        write_lock(tmp.path(), &ControlLock::of(&clean.manifests)).unwrap();

        // Tamper a body on disk AFTER locking.
        write_skill_dir(
            tmp.path(),
            "turn-header",
            "execution",
            "Deterministic turn-context header",
            "SWAPPED malicious template {input}",
        );

        let err = SkillControlPlane::new(tmp.path()).load().unwrap_err();
        assert!(
            matches!(err, LoadError::LockHashMismatch { .. }),
            "a swapped body must fail closed against control.lock, got {err:?}"
        );
    }

    #[test]
    fn gap_ainxt_skill_missing_lock_is_a_hard_error_in_production_posture() {
        let tmp = TmpDir::new("nolock");
        build_plane(tmp.path());
        // require_lock = true (default), no control.lock written → fail closed.
        let err = SkillControlPlane::new(tmp.path()).load().unwrap_err();
        assert_eq!(err, LoadError::MissingLock);
    }

    #[test]
    fn gap_ainxt_skill_malformed_front_matter_fails_closed() {
        let tmp = TmpDir::new("bad");
        let dir = tmp.path().join("broken-skill");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("definition.md"), "no front matter here at all").unwrap();
        let err = SkillControlPlane::new(tmp.path())
            .allow_unlocked()
            .load()
            .unwrap_err();
        assert!(matches!(err, LoadError::Parse { .. }));
    }

    #[test]
    fn gap_ainxt_skill_unknown_front_matter_field_is_rejected() {
        let tmp = TmpDir::new("unknown");
        let dir = tmp.path().join("weird-skill");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("definition.md"),
            "---\nid: weird-skill\ntype: behavioral\nauthor: someone\n---\nbody text\n",
        )
        .unwrap();
        let err = SkillControlPlane::new(tmp.path())
            .allow_unlocked()
            .load()
            .unwrap_err();
        assert!(matches!(err, LoadError::Parse { .. }));
    }

    #[test]
    fn gap_ainxt_skill_invalid_type_is_rejected() {
        let tmp = TmpDir::new("invalidtype");
        let dir = tmp.path().join("bogus-skill");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("definition.md"),
            "---\nid: bogus-skill\ntype: mystical\n---\nbody text\n",
        )
        .unwrap();
        let err = SkillControlPlane::new(tmp.path())
            .allow_unlocked()
            .load()
            .unwrap_err();
        assert!(matches!(err, LoadError::Parse { .. }));
    }

    #[test]
    fn gap_ainxt_skill_duplicate_id_across_directories_fails_closed() {
        let tmp = TmpDir::new("dup");
        write_skill_dir(tmp.path(), "same-id", "behavioral", "first", "first body");
        // A second directory with a DIFFERENT dir name but the SAME declared id.
        let dir2 = tmp.path().join("same-id-again");
        fs::create_dir_all(&dir2).unwrap();
        fs::write(
            dir2.join("definition.md"),
            "---\nid: same-id\ntype: behavioral\ndescription: second\n---\nsecond body\n",
        )
        .unwrap();
        let err = SkillControlPlane::new(tmp.path())
            .allow_unlocked()
            .load()
            .unwrap_err();
        assert_eq!(err, LoadError::DuplicateId("same-id".to_string()));
    }

    #[test]
    fn gap_ainxt_skill_read_only_does_not_require_a_lock_or_register() {
        let tmp = TmpDir::new("readonly");
        build_plane(tmp.path());
        // No control.lock at all, no `allow_unlocked()` needed — `read_only` never checks the lock.
        let manifests = SkillControlPlane::new(tmp.path()).read_only().unwrap();
        assert_eq!(manifests.len(), 2);
        assert!(manifests.iter().any(|m| m.id == "rca-procedure"));
    }
}
