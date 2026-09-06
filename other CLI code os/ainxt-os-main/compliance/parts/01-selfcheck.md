# selfcheck

_Verify the auditor itself hardcodes nothing that belongs in policy._

**4 finding(s)** — INFO 4

## What this module did

- **engine_files_scanned**: `35`
- **policy_checks**: `4`

## Findings

### [INFO] The auditor's own source contains a literal that belongs in policy

- **Rule**: `SELFCHECK.HARDCODED_LITERAL`
- **Where**: `skills/oss-compliance-auditor/ossaudit/evidence.py:60`
- **Classification**: SELF_AUDIT
- **Finding id**: `e0002d199f9f3690`
- **Evidence**: `(''sk-a'', ''ghp_'', ''AKIA'') and reports the length plus digest so the real`

**Why this matters.** 'AKIA' appears in the engine source.  Brand names, model identifiers, provider hostnames and credential prefixes must live in policy/ so that the same auditor works for a different organisation by changing configuration.  A tool that embeds them is not reusable and cannot be trusted to report on them neutrally.

**What to do.** Move the value into policy/patterns/ or policy/policy.yaml and read it through Config.

### [INFO] The auditor's own source contains a literal that belongs in policy

- **Rule**: `SELFCHECK.HARDCODED_LITERAL`
- **Where**: `skills/oss-compliance-auditor/ossaudit/scanpass.py:656`
- **Classification**: SELF_AUDIT
- **Finding id**: `431d99a76b7b51d4`
- **Evidence**: `"OpenAI Responses API -- routes gpt-5.4 and deep-research models."`

**Why this matters.** 'gpt-5' appears in the engine source.  Brand names, model identifiers, provider hostnames and credential prefixes must live in policy/ so that the same auditor works for a different organisation by changing configuration.  A tool that embeds them is not reusable and cannot be trusted to report on them neutrally.

**What to do.** Move the value into policy/patterns/ or policy/policy.yaml and read it through Config.

### [INFO] The auditor's own source contains a literal that belongs in policy

- **Rule**: `SELFCHECK.HARDCODED_LITERAL`
- **Where**: `skills/oss-compliance-auditor/ossaudit/scanpass.py:657`
- **Classification**: SELF_AUDIT
- **Finding id**: `435fe10400c35b3b`
- **Evidence**: `"defaults to gemini-3.5-flash; env-overridable via GEMINI_VISION_MODEL"`

**Why this matters.** 'gemini-' appears in the engine source.  Brand names, model identifiers, provider hostnames and credential prefixes must live in policy/ so that the same auditor works for a different organisation by changing configuration.  A tool that embeds them is not reusable and cannot be trusted to report on them neutrally.

**What to do.** Move the value into policy/patterns/ or policy/policy.yaml and read it through Config.

### [INFO] The auditor's own source contains a literal that belongs in policy

- **Rule**: `SELFCHECK.HARDCODED_LITERAL`
- **Where**: `skills/oss-compliance-auditor/ossaudit/scanpass.py:1032`
- **Classification**: SELF_AUDIT
- **Finding id**: `8ee33d85999914b4`
- **Evidence**: `#     MODEL = 'claude-sonnet-4-6'`

**Why this matters.** 'claude-' appears in the engine source.  Brand names, model identifiers, provider hostnames and credential prefixes must live in policy/ so that the same auditor works for a different organisation by changing configuration.  A tool that embeds them is not reusable and cannot be trusted to report on them neutrally.

**What to do.** Move the value into policy/patterns/ or policy/policy.yaml and read it through Config.

## Coverage

| Capability | State | Detail |
|---|---|---|
| `self_verification` | COVERED | 35 engine source files checked against 10 forbidden literals; policy coherence validated |
