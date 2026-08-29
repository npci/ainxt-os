# Security Policy

## Reporting a vulnerability
**Do not open a public issue for a security vulnerability.** Report privately to the security contact:

**Preferred: this repository's private security advisory.** Open the **Security** tab
and click **"Report a vulnerability"**, or go straight to
<https://github.com/npci/ainxt-os/security/advisories/new>. The report stays confidential between you and the
maintainers until a fix is published, and GitHub handles CVE assignment if one is
warranted.

**By email:** `opensource@npci.org.in` — the NPCI Open Source Programme, a monitored
group address rather than an individual mailbox. Use this if you cannot or prefer not
to use GitHub. For sensitive reports the GitHub advisory is still preferred, because it
keeps the disclosure timeline and the fix in one auditable place.

Please include: affected component/version, a description, reproduction steps or PoC, and impact. We follow **coordinated disclosure**.

## Our commitments
- Acknowledge receipt within **2 business days**.
- Provide an initial assessment within **7 business days**.
- Agree a remediation timeline based on severity; credit reporters who wish to be named.

## Scope
This policy covers the AiNxt OS OSS project in this repository. Vulnerabilities in any separately-developed enterprise plugins are out of scope for this policy and should be reported through the deploying organisation's own security channels.

## Enterprise / regulated note
As infrastructure intended for a regulated payment context, security-relevant incidents may also trigger **statutory reporting obligations** (e.g., CERT-In, DPDP breach notification, RBI) once deployed. Those obligations belong to the deploying organisation and are separate from, and additional to, this OSS disclosure policy.

## Security model — what AiNxt OS does and does not isolate

AiNxt OS executes AI-directed work, so the trust boundaries matter more than usual. Stated
plainly, because a researcher should not have to infer them from source:

**Identity is never self-asserted in a safe deployment.** The default `trusted-gateway`
authenticator derives role, capabilities and clearance from client-supplied `X-AInxt-*`
headers, and the daemon **refuses to start** until you accept that posture explicitly or
choose `jwt-sso`. Under `trusted-gateway` the listener must be unreachable except through a
gateway that has already authenticated the caller. **Never expose that listener to a
browser.** The shipped Console (`ainxt-os`) exists partly for this reason: it acts as the
authenticating gateway and runs the daemon in `jwt-sso` mode, so a browser never asserts
an identity.

**A refusal arrives inside the stream, not as an HTTP status.** Governed refusals are
`error` frames on a `200` response. Treating `200` as success is the most common integration
mistake and can silently defeat a gate — see [`DOCKING.md`](DOCKING.md).

**Subprocess execution is operator-configured, not model-directed.** The runtime spawns
child processes for MCP servers, skill interpreters, an optional LSP, and `git`. In every
case the executable and its arguments come from **deployment configuration**, not from model
output. MCP servers are additionally pinned trust-on-first-use with an admin re-approval
route. The skill runner clears the child environment (`env_clear`) and grants only `PATH`
plus an explicit allowlist. **A model cannot introduce a new executable.**

**What is NOT sandboxed today.** A configured skill interpreter or MCP server runs with the
privileges of the daemon process. There is no filesystem jail, no seccomp/AppArmor profile,
and no network namespace applied by AiNxt OS. The WASM sandbox seam exists but is listed as
design-only in the README. **Treat any skill, plugin or MCP server you configure as trusted
code, and run the daemon as an unprivileged user with only the filesystem access it needs.**

**Prompt injection is mitigated, not solved.** Untrusted retrieved or connector content is
scanned and fenced, and a tainted turn gates side-effecting tools (`[injection] mode`,
shipped as `enforce`). This raises the cost of an attack; it is not a guarantee. Do not grant
a surface capabilities whose misuse you could not tolerate.

**Reports we particularly want:** authentication or capability bypass; a governed refusal
that can be turned into an answer; escape from the configured skill/MCP boundary; a path
that persists unredacted cardholder data or secrets to the durable event log; tampering with
the hash-chained audit log that `verify` does not detect.

## Supported versions
Until the first tagged release, `main` is the only supported branch. A version-support matrix will be published at GA.
