# License migration — Apache-2.0 → MIT

| | |
|---|---|
| **Repository** | `ainxt-os` (AiNxt OS) |
| **Previous project license** | Apache-2.0 |
| **New project license** | **MIT** |
| **Migration date** | 2026-09-01 |
| **Commit SHA** | *unavailable — this tree contains no `.git` directory* |
| **Copyright holder** | National Payments Corporation of India — taken verbatim from the previous `LICENSE` appendix and `NOTICE`; not invented |

MIT applies to **AiNxt's own code**. Third-party components retain their original licenses,
attribution and notices. That separation is the point of this document.

---

## 1. Audit performed before any modification

Every place the project license is declared, referenced or embedded was enumerated first.

There is **no** `package.json`, `pyproject.toml`, `pom.xml` or `build.gradle` in this repository —
the only package metadata is Cargo, and 65 of the 66 crates inherit through
`license.workspace = true`, so a single field governs the whole workspace.

---

## 2. Files changed — AiNxt-owned

| File(s) | Change |
|---|---|
| `LICENSE` | Apache-2.0 (201 lines) replaced with the official MIT text (21 lines). |
| `Cargo.toml` | `license = "Apache-2.0"` → `"MIT"`. `cargo metadata` now reports **all 65 workspace crates as MIT**. |
| **763 files** under `crates/` (`*.rs` and crate `Cargo.toml`) | **765** SPDX header identifiers changed from `Apache-2.0` to `MIT`. |
| `crates/ainxt-client/src/sdk_contract.rs` | Two of those occurrences are string literals the SDK generator **emits into the generated Python and TypeScript SDKs**. That output is AiNxt-owned, so the generator now emits MIT headers. |
| `crates/ainxt-mcp/src/lib.rs` | "independent clean-room work licensed under Apache-2.0" → MIT. The adjacent note that the MCP **specification** belongs to Anthropic (MIT) is unchanged. |
| `README.md` | Five passages: open-source scope, the licensing bullet, the contribution posture, the Disclaimer (reworded from MIT's own warranty language), and the editorial comment explaining why GPL boilerplate is deliberately avoided. |
| `CONTRIBUTING.md` | Three references: the project-license sentence, the SPDX header template contributors copy into new files, and the inbound-contribution clause. |
| `NOTICE` | Apache-specific framing rewritten — see §4. |
| `THIRD_PARTY_NOTICES.md` | Two project-framing statements: the Apache §4(d) justification for the file, and the `ainxt-mcp` license statement. |

### SPDX result

```
crates/  SPDX headers declaring Apache-2.0  → 0
crates/  SPDX headers declaring MIT         → 765
```

---

## 3. Third-party licenses preserved — deliberately NOT changed

| Item | Apache refs | Why it stays |
|---|---:|---|
| `deny.toml` | 12 | Dependency license **allow-list**. `Apache-2.0` and `Apache-2.0 WITH LLVM-exception` must remain — a large part of the dependency tree is Apache-licensed. Removing them would break the gate, not tighten it. |
| `THIRD_PARTY_LICENSES.md` | 121 | Machine-generated dependency inventory. |
| `THIRD_PARTY_INVENTORY.yaml` | 124 | Dependency inventory. |
| `docs/vendor/` | — | `marked` 11.0.0 (MIT), `mermaid` 11.9.0 (MIT), `purify.min.js` — **DOMPurify 3.2.6 (Apache-2.0 / MPL-2.0)**. All redistributed unmodified with their license headers intact. |
| `THIRD_PARTY_NOTICES.md` | 3 | DOMPurify (×2) and `ring` (Apache-2.0 AND ISC). |
| `CONTRIBUTING.md` | 2 | The permissive-dependency policy list. |
| `crates/**/*.rs` | 6 | Dependency commentary only: `sha2` (MIT/Apache-2.0), `wasmtime` (Apache-2.0 WITH LLVM-exception). |

**No third-party license, copyright notice, SPDX identifier or attribution was modified.**

### Defect repaired en route

`THIRD_PARTY_NOTICES.md` contained two MIT reproductions (for `marked` and `mermaid`) with the grant
clause mangled — *"and to permit substantial portions of the Software."* — which dropped both
"to permit persons to whom the Software is furnished to do so" **and** the entire notice-retention
paragraph. An inaccurate reproduction of a third-party license is itself a compliance defect. Both
are now verbatim; all three MIT texts in the file are complete.

---

## 4. NOTICE — retained, reframed

MIT imposes **no** NOTICE obligation. Apache-2.0 §4(d) did. The file was **not** deleted, because it
carries material that remains required or remains true:

* attribution for the three bundled JavaScript components, and
* the trademark reservation for the AiNxt name, marks, and the logos under `AINxt_logo_icon/`.

A new **ABOUT THIS FILE** section states exactly that.

The trademark section required real rewording rather than a find-and-replace. It previously rested on
Apache-2.0 **§6**, which reserves trade names and trademarks explicitly. **MIT is silent on
trademarks.** The section now says so plainly and asserts the reservation on its own footing instead
of citing a clause that no longer applies.

Two Apache references remain in `NOTICE` by design: both are *historical*, explaining why the file
still exists and why the trademark wording changed. Neither is a claim about the current license.

---

## 5. Validation

| Check | Result |
|---|---|
| `cargo metadata` license for all 65 crates | **MIT** |
| Locked + offline release build (`ainxt-runtimed`, `ainxt-cli`, `ainxt-console`) | **pass** |
| `cargo test -p ainxt-client` (the SPDX-emitting generator) | **pass** |
| `cargo test -p ainxt-console` | **pass** |
| `cargo deny check` — advisories / bans / sources | **pass** |
| `cargo deny check licenses` | **fails** — `notify` 6.1.1 is CC0-1.0 (pre-existing, see §6) |
| CI workflow + `THIRD_PARTY_INVENTORY.yaml` YAML | **valid** |
| Repo-wide re-search for project-license residue | **0 incorrect project-license references** |

No behavioural change was made: the migration touched comments, package metadata and prose only.

---

## 6. Remaining legal questions — for counsel, not engineering

1. **Patents.** Apache-2.0 §3 granted an express patent license with a retaliation clause. **MIT
   contains no express patent grant.** Downstream recipients receive materially less than before.
   This is the most consequential effect of the change and needs explicit sign-off.
2. **Trademarks.** Apache §6 reserved them explicitly; MIT does not address them at all. `NOTICE` now
   asserts the reservation independently — confirm the wording is sufficient given this repository
   ships brand imagery.
3. **Inbound contributions.** `CONTRIBUTING.md` now binds future contributions to MIT. Anything
   already contributed under Apache-2.0 was licensed on those terms; relicensing existing third-party
   contributions needs their authors' consent. The repository states contributions are not yet open,
   which likely makes this moot — confirm.
4. **Already-distributed copies.** An Apache-2.0 grant already made is irrevocable for those copies.
   If any release was published earlier, both licenses will exist in the wild.
5. **Copyright year inconsistency (pre-existing, preserved).** `LICENSE` and `NOTICE` assert **2026**;
   the 758 source headers assert **2024-2026**. Left exactly as found rather than silently
   harmonised — choose one and apply it deliberately.
6. **`notify` v6.1.1 is `CC0-1.0`**, which is not in the `deny.toml` allow-list, so
   `cargo deny check licenses` fails. It is a **normal, redistributed** dependency of
   `ainxt-injection-svc` — not dev-only. Pre-existing and unrelated to this migration, but note that
   CC0-1.0 expressly declines to grant patent rights, which is why some organisations disallow it.
   Adding it to the allow-list is a policy decision and was left alone.

---

## 7. Pre-existing problems found during validation — now resolved

These were **not** caused by the licence migration. They were found while validating it and have
since been fixed in a follow-up pass.

### `docs/` was duplicated (239 broken links, mermaid entity bug)

The tree held 502 Markdown files: 252 flat at `docs/` root plus 250 in the subject folders. The two
copies were not identical — the flat copies still linked to files that do not exist
(`ainxt-types.md`, `eval.md`, …), which was the entire source of the 239 broken links, and they still
carried the `&#59;`/`&#58;` entities that break mermaid rendering. The organised copies had already
had the dangling links removed and the real cross-folder links repathed, and `index.html`'s
`DOC_PATHS` map resolves every one of the 250 documents to its **folder** path — so the viewer never
loaded the flat copies at all.

The 250 flat duplicates were deleted; `README.md` and `overview.md` legitimately stay at the root
(the latter is the one non-foldered entry in `DOC_PATHS`). One further broken link was fixed in the
root `README.md`, which still pointed a dark-mode `<picture>` source at `AINxt_logo_icon/AINxt_CTC-02.png`
— a folder removed in an earlier cleanup. The navy-plate `-02` asset is not present anywhere in this
drop, so the dangling source was dropped rather than substituting a different mark; the approved
`assets/AINxt_CTC-01.png` lockup is used on both themes.

**Result:** 5070 links checked, **0 broken**. 1268 mermaid blocks scanned, **0 offending lines**.

### The test suite did not compile, then did not pass

28 compile errors, then 14 runtime failures. Root causes, all of them drift between the tests and
deliberate product changes:

| Cause | Tests | Resolution |
|---|---:|---|
| `MemoryStore::get` was renamed `get_unchecked` so the absence of an authorization check is visible at every call site. Tests still called `get`. | 28 (compile) | Call sites updated to `get_unchecked`. The rename was **not** reverted — re-adding `get` would have quietly undone the hardening. |
| The OSS default arming policy is now `Generic` (no pre-armed clocks); it also switches the report templates and cadence scheduler. Tests assert India-regulated behaviour. | 6 | Tests opt in explicitly via `[incident] arming_policy = "india-regulatory"`, exercising the real config path. |
| `ConnectorCallError::sanitized_client_message` deliberately withholds connector names from client-facing text (Checkmarx: Secret Leak in Error Messages). Tests asserted the message names the connector. | 2 | Tests now assert the connector-pipeline error *vocabulary*. Reaching that match arm already proves the pipeline ran — an unregistered tool is a different variant (`Blocked("unknown tool: …")`). |
| `InjectionConfig::default()` is now `Enforce` (secure-by-default). A test asserted a stale "defaults OFF" baseline. | 1 | Baseline updated to assert secure-by-default. |
| The chat surface deliberately wires the deterministic heuristic intent classifier (`LATENCY FIX`: the model-backed one costs a separate LLM call per turn). Two tests asserted the model-backed Stage-2/Stage-3 classifier. | 2 | Rewritten to pin the current contract, so re-introducing a per-turn classification call has to be a conscious decision. **See the flag below.** |
| A panicking or timed-out turn dropped the caller's sink, producing a `200 OK` SSE stream with zero events — indistinguishable from a successful empty answer, and not retryable or reportable. | 2 | **Product fix**, not a test change: the session supervisor keeps a clone of the sink and emits `Event::Error` + `Event::Done` itself, preserving the panic payload. |

**Result:** `cargo test --workspace` — **3929 passed, 0 failed**, 6 ignored.

> **Flag for a human:** the classifier change is the one item here that removes a capability rather
> than renaming or re-defaulting one. The served chat default no longer asks for clarification on a
> genuinely ambiguous turn; it answers. That is deliberate and documented at the wiring site, but the
> tests that guarded the behaviour were written on purpose, so someone should confirm the trade is
> intended. Stage-3 clarify remains covered at the unit level in `ainxt-chat` / `ainxt-convo`.

## 8. Third-party attribution defect found and corrected

`THIRD_PARTY_NOTICES.md` described the components embedded in the mermaid bundle as
"further MIT-licensed components" and listed **DOMPurify** among them. DOMPurify is
**Apache-2.0 / MPL-2.0**. The other embedded components (lodash, a Promises/A+ thenable
© Ralf S. Engelschall, a jQuery-derived event object, a Bezier generator © Gaetan Renaudeau) are
genuinely MIT — DOMPurify was the sole exception, and MPL-2.0 is weak copyleft, so mislabelling it
as MIT is materially wrong rather than cosmetic. Corrected, and the embedded version (3.2.5, versus
3.2.6 for the separately vendored `docs/vendor/purify.min.js`) is now recorded.

This is the second such defect in this file, after the two malformed MIT reproductions in §3.

## 9. Final licence audit

A sweep of all **1137** files in the repository (excluding `target/`, `.git/`, `node_modules`):

| Check | Result |
|---|---|
| SPDX identifiers declaring Apache, in our code | **0** |
| Cargo `license =` declaring Apache | **0** (root `MIT`; 65 crates `license.workspace = true`) |
| Apache licence **text** or `apache.org/licenses` URL in our files | **0** |
| Apache licence files (`LICENSE-APACHE`, `COPYING`, …) | **none exist** |
| `README.md` Apache claims | **0** |
| Dependency inventories attributing Apache to an `ainxt-*` crate | **0** |

37 files still contain the string "apache". Every one was classified: dependency allow-list
(`deny.toml`), generated dependency inventories, genuine third-party notices (DOMPurify, ring),
in-code dependency commentary (`sha2`, `wasmtime`), the permissive-dependency policy in
`CONTRIBUTING.md`, the two vendored JavaScript bundles, and two historical sentences in `NOTICE`
explaining the migration itself. **No file declares, implies or reproduces Apache-2.0 as the licence
of AiNxt code.**
