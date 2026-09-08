# Changelog

All notable changes to AiNxt OS are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project has not yet cut a
versioned release (see `GATE_0_CHECKLIST.md`), so everything below is `Unreleased`.

## [Unreleased]

### Changed
- Project license migrated from Apache-2.0 to MIT (see
  `docs/release-readiness/LICENSE-MIGRATION.md` for the full record, including the open legal
  questions it raised).

### Fixed
- Multiple release-readiness documentation defects identified by the 2026-09-05 OSS compliance
  audit (`final_audit_response_os.md`): stale trademark-asset path and third-party license
  mislabelling in `NOTICE`, incorrect crate-count and workspace-membership claims in
  `CONTRIBUTING.md`, a dangling `deploy/.env.example` reference, a missing `GATE_0_CHECKLIST.md`,
  and several dangling internal-path references in source comments. See that report for the
  complete list, including the items intentionally left open pending legal or product review.

---

Nothing has shipped as a tagged release yet. Once a release is cut, add a dated version section
above this line following Keep a Changelog conventions, and keep the newest release at the top.
