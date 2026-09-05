<!--
External pull requests are NOT currently accepted or triaged (see CONTRIBUTING.md). This
template is the workflow the maintaining team follows.
-->

**What changed and why**

**Linked issue / ADR**

**Checks run locally**
- [ ] `cargo build --locked --release -p ainxt-runtimed -p ainxt-console`
- [ ] `cargo check --locked --tests --workspace`
- [ ] `cargo test -p <crates touched>`
- [ ] `cargo deny check`
- [ ] `cargo fmt --all --check` and `cargo clippy`
- [ ] `./.github/scripts/check-doc-links.sh`

**Governance impact**
- [ ] No mandatory gate (compliance / authz / audit) can be weakened or bypassed by this change
- [ ] No new path persists unredacted cardholder data or secrets to the durable event log
- [ ] Any new refusal is a typed `error` frame with the correct `category` and `retryable`

**Third-party code**
- [ ] No new dependency, **or** it is added to `THIRD_PARTY_INVENTORY.yaml` **and**
      `THIRD_PARTY_NOTICES.md`, and `cargo deny check` passes
- [ ] Lockfile changes are included in this PR

**Documentation**
- [ ] Docs updated for any changed command, path, environment variable, config key or route

**Sign-off**
- [ ] Every commit is signed off (`git commit -s`) per the DCO in CONTRIBUTING.md
