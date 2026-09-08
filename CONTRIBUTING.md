# Contributing to AiNxt OS

Thank you for your interest. This project is an **independently engineered, clean-room** codebase
licensed under the **MIT License**. It is a Rust workspace (65 crates) that ships a network runtime, so
contributions carry both an engineering bar and a legal bar. Both are described below.

---

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [How to Report a Bug](#how-to-report-a-bug)
3. [How to Request a Feature](#how-to-request-a-feature)
4. [Development Setup](#development-setup)
5. [Running the Tests](#running-the-tests)
6. [Where Does My Change Belong?](#where-does-my-change-belong)
7. [Making a Pull Request](#making-a-pull-request)
8. [Coding Standards](#coding-standards)
9. [Commit Message Convention](#commit-message-convention)
10. [DCO Sign-Off](#dco-sign-off)
11. [Clean-Room Rules](#clean-room-rules)
12. [Dependency Policy](#dependency-policy)
13. [Core / Enterprise Split](#core--enterprise-split)
14. [Review and Merge](#review-and-merge)

---

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By
participating you agree to abide by its terms. Report unacceptable behaviour to the contact listed
in that document.

---

## How to Report a Bug

Open an issue. There are no issue templates in this repository yet, so please include:

- Rust toolchain version (`rustc --version`) and OS / architecture
- The commit SHA you built from
- The command you ran (`cargo build`, `ainxt-runtimed --config …`, a `curl` against `/v1/chat`, …)
- Your configuration with secrets removed — and which `authenticator` you selected
- Expected vs actual behaviour, including the full error text and any SSE frames you received
- For a runtime failure: the relevant lines from the event log (`event_log_dir`, default `logs/`)

**Security vulnerabilities must not be filed as public issues** — see [SECURITY.md](SECURITY.md)
for the private reporting channel.

Before filing a test failure, check the known-failing suites in
[Running the Tests](#running-the-tests) — some assertions are stale rather than broken.

---

## How to Request a Feature

Open an issue describing the **problem**, not only the solution you have in mind: who is blocked,
what they cannot do today, and what a correct outcome looks like. Anything non-trivial starts as an
issue/RFC before code — the OS/runtime is a shared spine and an
API change ripples through every docked client.

If your proposal changes an architectural decision, it needs a new or amended **ADR**. The ADR set
is maintained outside this tree; reference the ADR number in the issue and record the decision in
your PR description so the independent-implementation evidence stays intact.

---

## Development Setup

### Prerequisites

| Requirement | Notes |
|---|---|
| **Rust ≥ 1.94** | The workspace sets `rust-version = "1.94"`. Install via [rustup](https://rustup.rs). |
| **C toolchain** | `ring`, `wasmtime` and `tree-sitter` build native code. macOS: Xcode command-line tools. Debian/Ubuntu: `build-essential`. |
| **Network** | The first build fetches ~328 crates from crates.io; there is no vendored tree. |
| **Disk** | ~3 GB for `target/` after a debug **and** release build. |
| **cargo-deny** | Required before opening a PR: `cargo install cargo-deny`. |

No database, broker, model provider or API key is needed. With no provider configured the runtime
serves an **offline** provider, so the socket always answers.

### Build and run

```sh
cargo build --release -p ainxt-runtimed

# Layered config — pass --config more than once and each file deep-merges over the previous.
cp crates/ainxt-runtimed/config/runtimed.example.toml runtimed.toml

# Assemble everything and exit without serving. Read the report it prints:
# it names each subsystem that is live versus deployment-owned.
AINXT_TRUSTED_GATEWAY=1 ./target/release/ainxt-runtimed --config runtimed.toml --check

AINXT_TRUSTED_GATEWAY=1 ./target/release/ainxt-runtimed --config runtimed.toml
```

The daemon **refuses to boot** until you choose an identity posture: either set
`AINXT_TRUSTED_GATEWAY=1` (only when the listener is unreachable except through a gateway that has
already validated the caller) or configure `authenticator = "jwt-sso"`. That is by design — do not
"fix" it in a PR.

Smoke-test a turn:

```sh
curl -N http://127.0.0.1:8080/v1/chat \
  -H 'content-type: application/json' \
  -d '{"session":"c1","turn":"t1","input":"hello","data_class":"public"}'
```

`offline mode: no model configured` is the expected first-run reply — it proves transport, session,
gate and streaming all work without a credential. The wire contract, event vocabulary and docking
examples are in [DOCKING.md](DOCKING.md); the [README](README.md) has a troubleshooting table.

---

## Running the Tests

```sh
cargo test --workspace                 # everything
cargo test -p ainxt-runtime            # one crate — much faster while iterating
cargo test -p ainxt-runtime --test guardrails_test
```

Two things to know before you triage a failure:

- **The suite is not currently green.** A workspace run reports roughly 3,800 passing and ~18
  failing across 634 suites, concentrated in the `ainxt-runtimed` composition-root integration
  tests and one `ainxt-payments` perimeter test. These are stale assertions, not new breakage — no
  CI has been enforcing them. Compare against a clean checkout before assuming your change caused
  it, and do not treat a red workspace run as permission to leave *your* crate red.
House bar for new work: **mechanism test + acceptance test**. The mechanism test pins the unit's
behaviour; the acceptance test proves the behaviour through the assembled runtime. Conformance
work that must drive the fully-wired runtime belongs in `ainxt-conformance`, which is what the
scenario-matrix gate exercises — `ainxt-scenario` is deliberately zero-dependency and cannot reach
a real `Engine`.

---

## Where Does My Change Belong?

The workspace is layered; putting a change in the wrong crate is the most common review rejection.

| Crate | Owns |
|---|---|
| `ainxt-types` | Core domain types. Pure, **no I/O**. |
| `ainxt-protocol` | The versioned command/event contract. Changing it is a breaking change for every docked client. |
| `ainxt-runtime` | The turn pipeline, the mandatory gates, the data-class-aware model router. |
| `ainxt-runtimed` | The composition binary — assembles the runtime from a layered `RuntimeConfig`. Wiring only; no policy. |
| `ainxt-config` | Layered, schema-validated configuration. |
| `ainxt-server` | HTTP + SSE transport (axum). |
| `ainxt-client` | The Rust protocol client / SDK over the `Transport` seam. |
| `ainxt-providers` | Vendor adapters normalising wire formats to the event-enum seam. |
| `ainxt-compliance` / `ainxt-guardrails` | The generic DLP/redaction default, and opt-in input/output rails. |
| `ainxt-tools` | Tool runtime, side-effect ledger, saga/compensation. |
| `ainxt-session` / `ainxt-eventlog` | Actor-per-session lifecycle; the tamper-evident append-only log. |
| `ainxt-conformance` | Definition-of-Done harness against the fully-assembled runtime. |

Read the `description` field in a crate's `Cargo.toml` before adding to it — each one states its
scope and the ADR it implements. The README also lists which subsystems are **placeholder or
design-only** (eval, RAG, memory, agent teams, MCP, WASM sandbox, non-Rust SDKs); building on one
means finishing it, not assuming it works.

---

## Making a Pull Request

1. Open an issue / RFC first for anything non-trivial.
2. Branch from `main` (the only supported branch until the first tagged release):
   ```sh
   git checkout -b feat/session-idle-reaping main
   ```
3. Implement, keeping commits focused — one logical change per commit.
4. Add tests (mechanism + acceptance).
5. Run the full local gate:
   ```sh
   cargo fmt --all
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test -p <crates-you-touched>
   cargo deny check
   ```
6. Update `CHANGELOG.md` under `## [Unreleased]` for anything user-visible
   ([Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format).
7. Sign off every commit (`git commit -s` — see [DCO Sign-Off](#dco-sign-off)).
8. Open the PR against `main`. In the description: what changed and why, the issue/ADR it
   implements, any external project you consulted as a reference, and any new dependency with its
   license.

> **Note:** `.github/workflows/ci.yml` enforces only some of these gates today — the locked release
> build, a type-check of every test target, `cargo deny`, and a documentation link check. The rest
> (schema, clippy `-D warnings`, a green `cargo test`, the pre-receive PII/secret gate, DCO) is not
> yet enforced: the `test` and `lint` jobs are deliberately non-blocking while known failures are
> outstanding, and standing the remainder up is Gate 9 / Go-Public work. Until then the gates above
> are enforced by you locally and by the reviewer. Do not treat "CI did not complain" as a
> passing gate.

### Branch naming

| Type | Pattern | Example |
|---|---|---|
| Feature | `feat/<short-description>` | `feat/session-idle-reaping` |
| Bug fix | `fix/<short-description>` | `fix/sse-frame-ordering` |
| Documentation | `docs/<short-description>` | `docs/docking-examples` |
| Chore | `chore/<short-description>` | `chore/bump-tokio` |

---

## Coding Standards

- **SPDX header on every new source file**, matching the existing files:
  ```rust
  // SPDX-License-Identifier: MIT
  // Copyright 2024-2026 National Payments Corporation of India
  ```
- `cargo fmt --all` (default rustfmt) and `cargo clippy --all-targets -- -D warnings` must be clean
  for the crates you touch.
- **No `unsafe`.** Crates forbid it via `[lints.rust] unsafe_code = "forbid"`; keep that in any new
  crate.
- Respect the layering: `ainxt-types` stays I/O-free, `ainxt-runtimed` stays wiring-only, and
  policy lives in the crate that owns it.
- **The mandatory gates are unbypassable.** Compliance/redaction, RBAC/authorization and audit run
  on every governed path. A change that lets a caller skip one, or that makes a gate silently
  no-op, is rejected regardless of how convenient the escape hatch is.
- Fail closed. Missing or ambiguous configuration must refuse to assemble rather than degrade to a
  permissive default — the daemon's boot refusal is the reference behaviour.
- Errors are typed and actionable; the message should tell the operator what to change.
- No hardcoded secrets, internal URLs, tenant names, or organisation-specific defaults. Domain data
  that genuinely affects behaviour (such as `SettlementPerimeter::default_reserved()`) must be
  documented and overridable.
- Document new public items with `///`, and add a crate-level `//!` doc explaining the crate's
  scope and its ADR.
- All user-visible strings in English, authored originally for AiNxt.

---

## Commit Message Convention

We use [Conventional Commits](https://www.conventionalcommits.org/), with the crate as the scope:

```
<type>(<scope>): <short summary>

[optional body]

Signed-off-by: Your Name <your.email@example.com>
```

**Types:** `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`, `ci`

```
feat(session): reap idle sessions under the global cap
fix(server): preserve SSE frame ordering across reconnect
docs: document the identity-posture boot refusal
chore(deps): bump tokio to 1.48
```

---

## DCO Sign-Off

Every commit must be signed off, certifying you have the right to submit it under the project
license. Use `git commit -s`, which appends:

```
Signed-off-by: Your Name <your.email@example.com>
```

By signing off you agree to the Developer Certificate of Origin 1.1:

> By making a contribution to this project, I certify that:
> (a) The contribution was created in whole or in part by me and I have the right to submit it under the open source license indicated in the file; or
> (b) The contribution is based upon previous work that, to the best of my knowledge, is covered under an appropriate open source license and I have the right under that license to submit that work with modifications, whether created in whole or in part by me, under the same open source license (unless I am permitted to submit under a different license), as indicated in the file; or
> (c) The contribution was provided directly to me by some other person who certified (a), (b) or (c) and I have not modified it.
> (d) I understand and agree that this project and the contribution are public and that a record of the contribution (including all personal information I submit with it, including my sign-off) is maintained indefinitely and may be redistributed consistent with this project and the open source license(s) involved.

PRs with unsigned commits will not be merged; DCO enforcement moves into CI at Gate 9. (A CLA may
be adopted later at the maintainers' discretion; DCO is the default.) Full text:
[developercertificate.org](https://developercertificate.org/).

---

## Clean-Room Rules

Non-negotiable — the project's IP integrity depends on this.

- **Never copy** source code, identifiers, class/function/variable names, constants, enums, error
  messages, comments, prompts, documentation, tests, folder layouts, branding, or project-specific
  terminology from any other project.
- External projects may be **studied as references only**. If you consulted one, say so in the PR
  description — do not reproduce its expression.
- All prompts, system messages and error text must be authored originally for AiNxt.
- Every substantive design decision gets an **ADR**, referenced from the PR. This is our evidence of
  independent implementation.

---

## Dependency Policy

The license gate is a legal-clearance gate, not a style preference.

- New dependencies must be **permissive-licensed**: Apache-2.0, MIT, BSD-2/3-Clause, ISC,
  Unicode-DFS-2016, Unicode-3.0, Zlib, CDLA-Permissive-2.0, or Apache-2.0 WITH LLVM-exception.
  The allow-list in [`deny.toml`](deny.toml) is **exhaustive** — anything else, including unknown
  or unclear licenses, is denied.
- **Copyleft (GPL/LGPL/AGPL/MPL/EPL/CDDL) and source-available (BUSL/SSPL) are not allowed** in the
  OSS tree. Shell out to an installed binary instead of vendoring.
- For a dual-licensed crate, elect the permissive option and record the election in `deny.toml`
  alongside the existing entries.
- Wildcard/unpinned versions are denied. Prefer adding shared deps to `[workspace.dependencies]`.
- Add every new dependency to [`THIRD_PARTY_INVENTORY.yaml`](THIRD_PARTY_INVENTORY.yaml), then run
  `cargo deny check` locally — it checks licenses, bans and security advisories. A PR that has not
  passed it will be sent back.
- `Cargo.lock` is committed on purpose: this is an application workspace and a reproducible
  dependency set is part of the licence and supply-chain posture. Include lockfile changes in your
  PR; never delete it.
- Bundling model weights or datasets requires a documented licence and origin record for each
  artifact, plus legal review, before it is proposed. No weights or datasets are distributed in
  this tree today.

---

## Core / Enterprise Split

Enterprise-specific compliance rule packs, directory/AD-RBAC integration and IP-bearing connectors
do **not** belong in this OSS tree (ADR-028); they live in a separate private repository. This tree
contains the runtime, gates-as-traits, generic defaults, protocol and SDK only. A PR that
introduces such IP here is rejected on sight.

---

## Review and Merge

Review ownership is defined in [CODEOWNERS](CODEOWNERS): `opensource@npci.org.in`, and
`@ainxt-legal` on `LICENSE`, `NOTICE`, `THIRD_PARTY_LICENSES.md`, `deny.toml` and the root
`Cargo.toml`. Expect a legal reviewer on any dependency change.

The lifecycle is `DRAFT` (branch) → `PENDING_APPROVAL` (open PR + gates) → `APPROVED`
(CODEOWNERS-approved, signed merge to `main`) → `PRODUCTION` (signed semver tag on the release
ref). Git history is the audit trail. A maintainer may block a change on a safety or legal
invariant — unbypassable compliance/RBAC/audit, data residency, exactly-once semantics,
clean-room, no copyleft. Those cannot be waived by consensus. See [MAINTAINERS.md](MAINTAINERS.md).

By contributing, you agree your contributions are licensed under the MIT License and that you have
followed the clean-room and dependency rules above.
