# Maintainers — AiNxt OS

Contributions are **not open** at this time (see [`CONTRIBUTING.md`](CONTRIBUTING.md)),
so this file records who is accountable for the repository rather than a
contributor roster.

## Accountable contacts

| Role | Scope | Contact |
|---|---|---|
| Repository owner | Merge rights, releases, licence decisions | NPCI Open Source Programme — opensource@npci.org.in |
| Security contact | Vulnerability triage (see [`SECURITY.md`](SECURITY.md)) | opensource@npci.org.in, or a [private GitHub advisory](https://github.com/npci/ainxt-os/security/advisories/new) |
| Conduct contact | Code of Conduct reports (see [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)) | opensource@npci.org.in |

### Review teams

`CODEOWNERS` refers to three teams. Until they exist on the git host and are
populated, **CODEOWNERS review is advisory only** — it will not block a merge.

| Team handle | Scope |
|---|---|
| `@ainxt-maintainers` | Runtime spine and engine — merge rights, release authority |
| `@ainxt-security` | Safety-critical paths — gates, injection, egress, payment invariants |
| `@ainxt-legal` | Licensing and the release gate — `LICENSE`, `deny.toml` |

Create and populate them before the repository is made public. This is a git-host
configuration step, not a change to this file.

`opensource@npci.org.in` is a monitored group address, not an individual mailbox. It is used in
preference to a personal name so that reports survive staff changes and so that
no single person's address is published on a repository that may outlive their
involvement.

## Becoming a maintainer

External contributions are not being accepted or triaged at present, so there is
no nomination process yet. If that changes, it will be described in
[`CONTRIBUTING.md`](CONTRIBUTING.md).
