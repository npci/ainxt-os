# OSS Compliance Audit — ainxt

| | |
|---|---|
| **Result** | **YELLOW** (warnings) |
| Repository | `/Users/admin/ainxt-oss-suite/ainxt-suite-oss/ainxt-os-main` |
| Commit | `not a git repository` |
| Intended license | `Apache-2.0` |
| Scanned | 2026-08-27 12:34:06Z |
| Policy | `ainxt-oss-baseline` fingerprint `43189e46f04c1e3a` |
| Exit code | `1` |

## Why this verdict

- 98 findings require human legal review; these are not questions an automated scan can close.

## Compliance matrix

| Category | Status | Basis |
|---|---|---|
| Project license | **PASS** | no open findings; capability `license_detection` exercised |
| License headers | **PASS** | no open findings; capability `header_review` exercised |
| Third-party licenses | **WARN** | 46 finding(s) for review |
| NOTICE / attribution | **PASS** | no open findings; capability `license_detection` exercised |
| Copyright | **PASS** | no open findings; capability `provenance_review` exercised |
| Provenance | **PASS** | no open findings; capability `provenance_review` exercised |
| SBOM | **PASS** | no open findings; capability `sbom_generation` exercised |
| Vulnerabilities | **PASS** | no open findings; capability `vulnerability_scan` exercised |
| Secrets | **PASS** | no open findings; capability `secret_detection` exercised |
| Organisation branding | **PASS** | no open findings; capability `branding_detection` exercised |
| Internal data | **PASS** | no open findings; capability `internal_data_detection` exercised |
| Model hardcoding | **PASS** | no open findings; capability `model_hardcoding_detection` exercised |
| Vendor lock-in | **PASS** | no open findings; capability `model_hardcoding_detection` exercised |
| Configuration | **PASS** | no open findings; capability `configuration_review` exercised |
| Organisation coupling | **PASS** | no open findings; capability `portability_coupling_detection` exercised |
| Contributor governance | **PASS** | no open findings; capability `governance_review` exercised |
| Trademark | **PASS** | no open findings; capability `branding_detection` exercised |
| Patent review | **PASS** | no open findings; capability `legal_marker_detection` exercised |
| Crypto / export review | **WARN** | 52 finding(s) for review |
| Supply chain | **PASS** | no open findings; capability `supply_chain_review` exercised |
| Build reproducibility | **PASS** | no open findings; capability `build_reproducibility` exercised |
| Committed artifacts | **PASS** | no open findings; capability `artifact_inventory` exercised |
| Telemetry | **PASS** | no open findings; capability `configuration_review` exercised |
| Documentation | **PASS** | no open findings; capability `governance_review` exercised |
| Git history | **NOT CHECKED** | capability `history_review` was not exercised, so this row is unassessed |

## Coverage: what was checked, and what was not

A capability that could not be exercised is listed here as a gap.  A gap is not a pass: it means this audit says nothing about that dimension.

| Capability | State | Tool | Detail |
|---|---|---|---|
| `ai_artifact_review` | COVERED | ossaudit (builtin) | 0 weight, 0 tokenizer, 0 dataset file(s) found |
| `artifact_inventory` | COVERED | ossaudit (builtin) | 0 artifact(s) totalling 0.0 MiB inventoried and hashed |
| `branding_detection` | COVERED | ossaudit (builtin) | 10 rule(s) from policy/patterns/branding.yaml applied to 849 files |
| `build_reproducibility` | COVERED | ossaudit (builtin) | verdict: PASS |
| `configuration_review` | COVERED | ossaudit (builtin) | 7 rule(s) from policy/patterns/endpoints.yaml applied to 849 files |
| `dependency_enumeration` | COVERED | ossaudit (builtin) | 328 components across 1 ecosystem(s) from 1 manifest/lockfile(s) |
| `governance_review` | COVERED | ossaudit (builtin) | 6 required file(s) present |
| `header_review` | COVERED | ossaudit (builtin) | 247 source files checked for SPDX headers |
| `internal_data_detection` | COVERED | ossaudit (builtin) | 9 rule(s) from policy/patterns/internal_data.yaml applied to 849 files |
| `legal_marker_detection` | COVERED | ossaudit (builtin) | 6 rule(s) from policy/patterns/legal_markers.yaml applied to 849 files |
| `license_detection` | COVERED | ossaudit (builtin) | 2 license file(s) found, 2 identified, 0 unidentified; bundled SPDX snapshot 2026-08-14 |
| `model_hardcoding_detection` | COVERED | ossaudit (builtin) | 7 rule(s) from policy/patterns/models.yaml applied to 849 files |
| `portability_coupling_detection` | COVERED | ossaudit (builtin) | 1 rule(s) from policy/patterns/coupling.yaml applied to 849 files |
| `provenance_review` | COVERED | ossaudit (builtin) | 0 vendored tree(s) covering 0 file(s) assessed |
| `provenance_review` | COVERED | ossaudit (builtin) | 7 rule(s) from policy/patterns/provenance_markers.yaml applied to 849 files |
| `repository_inventory` | COVERED | ossaudit (builtin) | 849 files across 1 root(s); 6 language(s), 1 ecosystem(s) |
| `sbom_generation` | COVERED | ossaudit (builtin) | 328 component(s) and 0 artifact(s) in: sbom.cdx.json, sbom.spdx.json |
| `secret_detection` | COVERED | ossaudit (builtin) | 15 rule(s) from policy/patterns/secrets.yaml applied to 849 files |
| `self_verification` | COVERED | ossaudit (builtin) | 35 engine source files checked against 10 forbidden literals; policy coherence validated |
| `supply_chain_review` | COVERED | ossaudit (builtin) | 0 build/install/CI file(s) scanned with 11 supply-chain rule(s) |
| `transitive_license_review` | COVERED | ossaudit (builtin) | lockfiles present for: cargo |
| `vendored_tree_review` | COVERED | ossaudit (builtin) | 0 vendored tree(s) |
| `vulnerability_scan` | COVERED | trivy | trivy scanned an SBOM of 328 enumerated component(s) using a local database from 2026-08-26 13:02:19.845522405 +0000 UTC (1.2 days old) |
| `git_history_secret_scan` | MISSING | gitleaks | gitleaks 8.30.1 is installed but every invocation failed: no git root to scan |
| `history_review` | MISSING | ossaudit (builtin) | 0 commit(s) across 0 git root(s) examined |

## Findings

| Severity | Open | Total |
|---|---|---|
| BLOCK | 0 | 0 |
| HIGH | 0 | 0 |
| REVIEW | 52 | 70 |
| WARN | 0 | 30 |
| INFO | 46 | 101 |
| _cleared by triage_ | - | 103 |

### Blocking

_These prevent release under the configured policy._

None.

### Legal review required

_An automated tool cannot close these.  They need a named human decision, recorded in the triage ledger with a rationale._

#### `DEP.LICENSE_REVIEW` — 46 occurrence(s)

**cranelift-assembler-x64 0.133.3 is review (Apache-2.0 WITH LLVM-exception)**

*Why this matters.* Apache-2.0 is permissive, but the exception clause 'LLVM-exception' is not on the reviewed exception list, so its effect is unverified.

*What to do.* Have the licence assessed against the intended distribution.  If it is acceptable, record the decision in the triage ledger with the rationale, so the conclusion survives to the next audit.

| Location | Evidence | Finding id |
|---|---|---|
| `Cargo.lock` | `cranelift-assembler-x64 0.133.3 [cargo] license=Apache-2.0 WITH LLVM-exception (source: cargo registry cache)` | `002f3ed6166f3eda` |
| `Cargo.lock` | `zerovec-derive 0.11.6 [cargo] license=Unicode-3.0 (source: cargo registry cache)` | `00ac7f30e2602e94` |
| `Cargo.lock` | `cranelift-frontend 0.133.3 [cargo] license=Apache-2.0 WITH LLVM-exception (source: cargo registry cache)` | `0f0a7a40cc96ea63` |
| `Cargo.lock` | `wasmtime-internal-fiber 46.0.3 [cargo] license=Apache-2.0 WITH LLVM-exception (source: cargo registry cache)` | `12b611c951d6ca11` |
| `Cargo.lock` | `icu_locale_core 2.3.0 [cargo] license=Unicode-3.0 (source: cargo registry cache)` | `276531f644372c70` |
| `Cargo.lock` | `litemap 0.8.3 [cargo] license=Unicode-3.0 (source: cargo registry cache)` | `2dabf8a91c10e765` |
| `Cargo.lock` | `wasmtime-internal-jit-debug 46.0.3 [cargo] license=Apache-2.0 WITH LLVM-exception (source: cargo registry cach` | `3058c7677d608295` |
| `Cargo.lock` | `wasmtime-environ 46.0.3 [cargo] license=Apache-2.0 WITH LLVM-exception (source: cargo registry cache)` | `32ce34f5deb68cc9` |
| `Cargo.lock` | `wasmtime 46.0.3 [cargo] license=Apache-2.0 WITH LLVM-exception (source: cargo registry cache)` | `38a9fe78dd6512f4` |
| `Cargo.lock` | `target-lexicon 0.13.5 [cargo] license=Apache-2.0 WITH LLVM-exception (source: cargo registry cache)` | `3c9dd358031aad0b` |
| `Cargo.lock` | `icu_properties_data 2.3.0 [cargo] license=Unicode-3.0 (source: cargo registry cache)` | `3ff7b9a7861d4588` |
| `Cargo.lock` | `icu_collections 2.3.0 [cargo] license=Unicode-3.0 (source: cargo registry cache)` | `460bd3371e7b4998` |
| `Cargo.lock` | `wasmtime-internal-unwinder 46.0.3 [cargo] license=Apache-2.0 WITH LLVM-exception (source: cargo registry cache` | `4a0ac7f715e35f9d` |
| `Cargo.lock` | `cranelift-control 0.133.3 [cargo] license=Apache-2.0 WITH LLVM-exception (source: cargo registry cache)` | `4ff6e7459e7d1974` |
| `Cargo.lock` | `pulley-interpreter 46.0.3 [cargo] license=Apache-2.0 WITH LLVM-exception (source: cargo registry cache)` | `559830691fa7981c` |
| _... and 31 more_ | | |

#### `LEGAL.CRYPTO_LIBRARY_DEPENDENCY` — 29 occurrence(s)

**Cryptography or TLS library dependency**

*Why this matters.* Recorded so the export-control review has a complete list of cryptographic dependencies.  Informational: depending on a TLS library is normal and not a defect.

*What to do.* Include in the cryptography inventory supplied to legal review.

| Location | Evidence | Finding id |
|---|---|---|
| `Cargo.lock:1561` | `name = "hyper-rustls"` | `9efc7249696a93ce` |
| `Cargo.lock:2165` | `name = "ring"` | `69cf7fcd133f2501` |
| `Cargo.lock:2204` | `name = "rustls"` | `95f9115283f2a3ad` |
| `Cargo.lock:2218` | `name = "rustls-pki-types"` | `5e768ebf8b2bce2c` |
| `Cargo.lock:2228` | `name = "rustls-webpki"` | `22ddffc631945d4b` |
| `Cargo.lock:2567` | `name = "tokio-rustls"` | `605409633dc29486` |
| `THIRD_PARTY_INVENTORY.yaml:260` | `- name: hyper-rustls` | `ee690780d12eb4ad` |
| `THIRD_PARTY_INVENTORY.yaml:263` | `repo: https://crates.io/crates/hyper-rustls` | `f937d409f6238285` |
| `THIRD_PARTY_INVENTORY.yaml:507` | `- name: ring` | `468b1db20e3e0ce5` |
| `THIRD_PARTY_INVENTORY.yaml:510` | `repo: https://crates.io/crates/ring` | `66838ceac1536eff` |
| `THIRD_PARTY_INVENTORY.yaml:519` | `- name: rustls` | `b64235e7155bd89c` |
| `THIRD_PARTY_INVENTORY.yaml:522` | `repo: https://crates.io/crates/rustls` | `16da22329d080210` |
| `THIRD_PARTY_INVENTORY.yaml:525` | `- name: rustls-pki-types` | `ff6f07c6bea1cf6a` |
| `THIRD_PARTY_INVENTORY.yaml:528` | `repo: https://crates.io/crates/rustls-pki-types` | `99d0de9641ee68d9` |
| `THIRD_PARTY_INVENTORY.yaml:531` | `- name: rustls-webpki` | `238727c34a049161` |
| _... and 14 more_ | | |

#### `LEGAL.CRYPTO_IMPLEMENTATION` — 23 occurrence(s)

**Cryptographic implementation or key management in source**

*Why this matters.* Cryptographic functionality can bring a distribution within the scope of export-control regimes.  Whether an exemption or notification applies is a legal determination about the specific distribution, not something a scanner can decide.

*What to do.* Inventory the cryptographic capabilities of the release and refer them for export-control review.  Many open-source distributions qualify for published-source exemptions, but that conclusion must come from counsel.

| Location | Evidence | Finding id |
|---|---|---|
| `THIRD_PARTY_INVENTORY.yaml:86` | `- name: chacha20` | `e8e9e201e914e7df` |
| `THIRD_PARTY_INVENTORY.yaml:89` | `repo: https://crates.io/crates/chacha20` | `7d49a4c4501cd5bc` |
| `THIRD_PARTY_INVENTORY.yaml:428` | `- name: poly1305` | `f2be4ddc48a30f8d` |
| `THIRD_PARTY_INVENTORY.yaml:431` | `repo: https://crates.io/crates/poly1305` | `287876620130c2e3` |
| `crates/ainxt-token/src/lib.rs:41` | `/// Length of an XChaCha20-Poly1305 key (256-bit) and nonce (192-bit).` | `e307b54bec315446` |
| `crates/ainxt-token/src/lib.rs:82` | `/// Ciphertext with the appended Poly1305 authentication tag.` | `3abe0130352bbcc1` |
| `crates/ainxt-cryptoagility/src/lib.rs:431` | `Algorithm::deprecated("ed25519", 100, false),` | `acdff255a3f132cf` |
| `crates/ainxt-cryptoagility/src/lib.rs:435` | `Algorithm::forbidden("rsa-1024-sha1", false),` | `473a3b0f87bfcaf4` |
| `crates/ainxt-cryptoagility/src/lib.rs:456` | `r.register(Purpose::Signing, Algorithm::forbidden("rsa-1024", false))` | `2c53b2effedaa8f1` |
| `crates/ainxt-cryptoagility/src/lib.rs:462` | `assert_eq!(r.resolve(Purpose::Signing, 50).unwrap().name, "ed25519");` | `28621a709b409ebd` |
| `crates/ainxt-cryptoagility/src/lib.rs:463` | `assert_eq!(r.resolve(Purpose::Signing, 100).unwrap().name, "ed25519");` | `6daac2dcd85ea527` |
| `crates/ainxt-cryptoagility/src/lib.rs:498` | `Algorithm::deprecated("x25519", 10, true),` | `3d704eda67e062b0` |
| `crates/ainxt-cryptoagility/src/lib.rs:539` | `.register(Purpose::KeyExchange, Algorithm::approved("x25519", false));` | `6b3b3b4e9150dce3` |
| `crates/ainxt-cryptoagility/src/lib.rs:554` | `let forbidden = Algorithm::forbidden("rsa-1024", false);` | `95f15b0e97e28b3f` |
| `crates/ainxt-cryptoagility/src/lib.rs:555` | `let deprecated = Algorithm::deprecated("ed25519", 100, false);` | `15d8a07ae1bc34d6` |
| _... and 8 more_ | | |

### Warnings

_These degrade the verdict but do not block._

#### `DEP.LICENSE_REVIEW` — 46 occurrence(s)

**cranelift-assembler-x64 0.133.3 is review (Apache-2.0 WITH LLVM-exception)**

*Why this matters.* Apache-2.0 is permissive, but the exception clause 'LLVM-exception' is not on the reviewed exception list, so its effect is unverified.

*What to do.* Have the licence assessed against the intended distribution.  If it is acceptable, record the decision in the triage ledger with the rationale, so the conclusion survives to the next audit.

| Location | Evidence | Finding id |
|---|---|---|
| `Cargo.lock` | `cranelift-assembler-x64 0.133.3 [cargo] license=Apache-2.0 WITH LLVM-exception (source: cargo registry cache)` | `002f3ed6166f3eda` |
| `Cargo.lock` | `zerovec-derive 0.11.6 [cargo] license=Unicode-3.0 (source: cargo registry cache)` | `00ac7f30e2602e94` |
| `Cargo.lock` | `cranelift-frontend 0.133.3 [cargo] license=Apache-2.0 WITH LLVM-exception (source: cargo registry cache)` | `0f0a7a40cc96ea63` |
| `Cargo.lock` | `wasmtime-internal-fiber 46.0.3 [cargo] license=Apache-2.0 WITH LLVM-exception (source: cargo registry cache)` | `12b611c951d6ca11` |
| `Cargo.lock` | `icu_locale_core 2.3.0 [cargo] license=Unicode-3.0 (source: cargo registry cache)` | `276531f644372c70` |
| `Cargo.lock` | `litemap 0.8.3 [cargo] license=Unicode-3.0 (source: cargo registry cache)` | `2dabf8a91c10e765` |
| `Cargo.lock` | `wasmtime-internal-jit-debug 46.0.3 [cargo] license=Apache-2.0 WITH LLVM-exception (source: cargo registry cach` | `3058c7677d608295` |
| `Cargo.lock` | `wasmtime-environ 46.0.3 [cargo] license=Apache-2.0 WITH LLVM-exception (source: cargo registry cache)` | `32ce34f5deb68cc9` |
| `Cargo.lock` | `wasmtime 46.0.3 [cargo] license=Apache-2.0 WITH LLVM-exception (source: cargo registry cache)` | `38a9fe78dd6512f4` |
| `Cargo.lock` | `target-lexicon 0.13.5 [cargo] license=Apache-2.0 WITH LLVM-exception (source: cargo registry cache)` | `3c9dd358031aad0b` |
| `Cargo.lock` | `icu_properties_data 2.3.0 [cargo] license=Unicode-3.0 (source: cargo registry cache)` | `3ff7b9a7861d4588` |
| `Cargo.lock` | `icu_collections 2.3.0 [cargo] license=Unicode-3.0 (source: cargo registry cache)` | `460bd3371e7b4998` |
| `Cargo.lock` | `wasmtime-internal-unwinder 46.0.3 [cargo] license=Apache-2.0 WITH LLVM-exception (source: cargo registry cache` | `4a0ac7f715e35f9d` |
| `Cargo.lock` | `cranelift-control 0.133.3 [cargo] license=Apache-2.0 WITH LLVM-exception (source: cargo registry cache)` | `4ff6e7459e7d1974` |
| `Cargo.lock` | `pulley-interpreter 46.0.3 [cargo] license=Apache-2.0 WITH LLVM-exception (source: cargo registry cache)` | `559830691fa7981c` |
| _... and 31 more_ | | |

#### `LEGAL.CRYPTO_IMPLEMENTATION` — 6 occurrence(s)

**Cryptographic implementation or key management in source**

*Why this matters.* Cryptographic functionality can bring a distribution within the scope of export-control regimes.  Whether an exemption or notification applies is a legal determination about the specific distribution, not something a scanner can decide.

*What to do.* Inventory the cryptographic capabilities of the release and refer them for export-control review.  Many open-source distributions qualify for published-source exemptions, but that conclusion must come from counsel.

| Location | Evidence | Finding id |
|---|---|---|
| `THIRD_PARTY_INVENTORY.yaml:86` | `- name: chacha20` | `e8e9e201e914e7df` |
| `THIRD_PARTY_INVENTORY.yaml:89` | `repo: https://crates.io/crates/chacha20` | `7d49a4c4501cd5bc` |
| `THIRD_PARTY_INVENTORY.yaml:428` | `- name: poly1305` | `f2be4ddc48a30f8d` |
| `THIRD_PARTY_INVENTORY.yaml:431` | `repo: https://crates.io/crates/poly1305` | `287876620130c2e3` |
| `crates/ainxt-token/src/lib.rs:41` | `/// Length of an XChaCha20-Poly1305 key (256-bit) and nonce (192-bit).` | `e307b54bec315446` |
| `crates/ainxt-token/src/lib.rs:82` | `/// Ciphertext with the appended Poly1305 authentication tag.` | `3abe0130352bbcc1` |

## Triage ledger

| | |
|---|---|
| ledger path | `/Users/admin/ainxt-oss-suite/ainxt-suite-oss/ainxt-os-main/compliance/triage.yaml` |
| decisions in ledger | `103` |
| decisions applied | `103` |
| decisions rejected | `0` |
| decisions invalidated by change | `0` |
| decisions expired | `0` |

## Module execution

| Module | Findings | Notes |
|---|---|---|
| `ai_artifacts` | 0 |  |
| `artifacts` | 0 |  |
| `buildscripts` | 0 |  |
| `deps` | 46 |  |
| `discover` | 1 |  |
| `git_history` | 0 |  |
| `governance` | 0 |  |
| `licenses` | 0 |  |
| `provenance` | 0 |  |
| `selfcheck` | 4 |  |
| `textscan` | 310 | rule COUPLING.OPTIONAL_SERVICE_HARDCODED not applied: inert: coupling.optional_capability_services is empty in configura |
| `vulns` | 0 |  |

## What this audit could NOT verify

Every scanner has limits.  These are stated so that a clean result in a category is read with the right confidence.

- **ai_artifacts** — Model artifacts are identified by file extension and name.  Weights stored under an unconventional extension, or fetched at runtime, are not detected here -- runtime downloads are covered by the endpoint inventory instead.
- **artifacts** — Binary contents are assessed from magic bytes and embedded strings only.  The auditor does not disassemble, and cannot enumerate the libraries statically linked into a binary.  A committed binary's true third-party composition can only be established from its build.
- **buildscripts** — Reproducibility is assessed from configuration -- lockfiles, pinned toolchains, pinned images -- not by performing two builds and comparing them.  A genuine bit-for-bit reproducibility claim requires actually building twice.
- **deps** — Maven and Gradle dependencies are read from build files only.  Neither transitive closure nor license data is resolved, because that requires the build tool and a repository connection.  Treat those counts as a floor.
- **deps** — Dependency licenses come from local metadata, a vendored copy, or the project's own declaration -- in that order.  A declaration is the package author's claim, not a verified fact; where redistribution turns on it, read the component's actual license file.
- **discover** — Only git-tracked files were examined.  Untracked working-tree files -- including any local .env holding live credentials -- were not scanned.  Re-run with scan.include_untracked=true to cover them.
- **git_history** — History review examines commit metadata and the set of paths that ever existed.  It does NOT read the content of every historical revision: that requires walking every blob in the object database, which is prohibitively slow on a large repository.  A secret committed inside a normal source file and later edited out will therefore NOT be found here.  Install gitleaks to get content-level history scanning.
- **licenses** — License identification uses distinctive marker phrases from a bundled snapshot, not full text comparison.  A license text modified in a region not covered by a marker phrase will still be identified as the base license; the length check above is a partial mitigation, not a guarantee.
- **licenses** — The bundled SPDX snapshot (2026-08-14) covers 116 identifiers, not the complete SPDX list.  An identifier outside it is treated as unrecognised.
- **provenance** — Provenance is established from what is in the tree: license files, copyright headers, derivation comments and byte-identical matches against other copies in the same repository.  Without network access the auditor cannot compare against real upstream releases, so a file copied from a project that is not also vendored here will only be caught if it carries a marker or a foreign copyright line.
- **textscan** — These rules hit their configured max_findings cap and stopped reporting, so their true count is higher than shown: PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE
- **textscan** — Content rules are regular expressions over single lines.  A value split across lines, assembled at runtime, base64-encoded or otherwise obfuscated will not match.  Absence of a finding is not proof of absence.
- **vulns** — Vulnerability results are only as current as the advisory database used, and its timestamp is recorded above.  Absence of findings from a stale or missing database is not evidence of absence of vulnerabilities.

## Status of this report

Automated open-source compliance checks were executed against the configured policy and the results are above.  **This is an engineering release gate, not a legal opinion.** It does not establish that the repository is legally compliant, and it cannot: questions of copyright ownership, provenance of incorporated code, patent exposure, trademark use, export control and the interpretation of unusual licences all require a qualified human decision.  Every finding marked for legal review is such a question.

