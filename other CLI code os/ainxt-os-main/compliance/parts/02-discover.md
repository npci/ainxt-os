# discover

_Inventory roots, languages, manifests, archives, binaries, nested repos._

**1 finding(s)** — WARN 1

## What this module did

- **archives**: `0`
- **binaries**: `0`
- **files**: `849`
- **lockfiles**: `1`
- **manifests**: `65`
- **nested_roots**: `0`
- **roots**: `1`
- **total_mib**: `13.6`

## Findings

### [WARN] Target is not a git repository

- **Rule**: `DISCOVER.NOT_A_GIT_REPOSITORY`
- **Where**: `(repository)`
- **Classification**: SCOPE_INTEGRITY
- **Finding id**: `4b1e68e3fcbd05dd`
- **Evidence**: `/Users/admin/ainxt-oss-suite/ainxt-suite-oss/ainxt-os-main`

**Why this matters.** Without git metadata the auditor cannot distinguish tracked from untracked files, and cannot examine history for secrets or removed files.  The scan falls back to walking the filesystem, which includes local build output.

**What to do.** Run the audit against a git checkout of what will be published.

## What this module could NOT verify

- Only git-tracked files were examined.  Untracked working-tree files -- including any local .env holding live credentials -- were not scanned.  Re-run with scan.include_untracked=true to cover them.

## Coverage

| Capability | State | Detail |
|---|---|---|
| `repository_inventory` | COVERED | 849 files across 1 root(s); 6 language(s), 1 ecosystem(s) |
