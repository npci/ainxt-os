# Governance — AiNxt OS

This project is governed on **git primitives** (ADR-026), not a database status field.

## Roles
- **Maintainers** — merge rights + release authority (see `MAINTAINERS.md`).
- **Security reviewers** — required reviewers on safety-critical paths (see `CODEOWNERS`).
- **Legal** — required reviewer on licensing/release paths; owns the Gate #0 clearance.
- **Contributors** — anyone submitting a PR under `CONTRIBUTING.md` (DCO required).

## Decision-making
- **Architectural decisions** are recorded as **ADRs**. The ADR corpus is maintained by NPCI and is
  **not published in this repository**; the per-subsystem reference under [`docs/`](docs/) cites the
  relevant ADR numbers. A change that alters an ADR-level decision requires a new/amended ADR and
  maintainer consensus.
- **Non-trivial changes** start as an **issue/RFC** before code (see `CONTRIBUTING.md`).
- **Rough consensus** of maintainers decides; a maintainer may block a change on a safety/legal
  invariant (compliance/RBAC/audit unbypassable, data-residency, exactly-once, clean-room, no
  copyleft) — these are non-negotiable and cannot be waived by consensus.

## Lifecycle
`DRAFT` (branch) → `PENDING_APPROVAL` (open PR + CI: schema, clippy `-D warnings`, `cargo test`,
`cargo deny`, the pre-receive PII/secret gate) → `APPROVED` (CODEOWNERS-approved, signed merge to
`main`) → `PRODUCTION` (signed semver tag promoted onto the `env/prod` ref). Git history is the audit
trail; a tag/SHA is the rollback point.

## Releases
- Semantic versioning; releases are **signed tags** (verified on the prod ref).
- No release ships until **Gate #0** (`GATE_0_CHECKLIST.md`) is green.

## Core / enterprise split (non-negotiable)
This OSS tree contains the runtime + gates-as-traits + generic defaults + protocol + SDK **only**.
Jurisdiction-specific PCI/DSS rule packs, directory-backed RBAC, and IP-bearing connectors live in a **separate private repository**
and are never merged here. A PR that introduces such IP into this tree is rejected on sight.

## Contact

Governance questions, maintainer nominations and licence decisions:
**`opensource@npci.org.in`** — the NPCI Open Source Programme, a monitored group address rather
than an individual mailbox. Security vulnerabilities must instead follow
[`SECURITY.md`](SECURITY.md); Code of Conduct reports follow
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
