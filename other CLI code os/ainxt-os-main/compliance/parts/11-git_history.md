# git_history

_Secrets, deleted sensitive files and binaries in history._

**0 finding(s)**

## What this module did

- **commits**: `0`
- **gitleaks_findings**: `0`
- **roots**: `0`
- **sensitive_in_history**: `0`

No findings from this module.

## What this module could NOT verify

- History review examines commit metadata and the set of paths that ever existed.  It does NOT read the content of every historical revision: that requires walking every blob in the object database, which is prohibitively slow on a large repository.  A secret committed inside a normal source file and later edited out will therefore NOT be found here.  Install gitleaks to get content-level history scanning.

## Coverage

| Capability | State | Detail |
|---|---|---|
| `history_review` | MISSING | 0 commit(s) across 0 git root(s) examined |
| `git_history_secret_scan` | MISSING | gitleaks 8.30.1 is installed but every invocation failed: no git root to scan |
