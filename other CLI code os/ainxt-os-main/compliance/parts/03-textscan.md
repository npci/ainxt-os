# textscan

_Single content pass applying all text rule groups._

**310 finding(s)** — REVIEW 175, WARN 31, INFO 104

## What this module did

- **groups**: `['branding', 'coupling', 'endpoints', 'internal_data', 'legal_markers', 'models', 'provenance_markers', 'secrets', 'supply_chain']`
- **rules_applied**: `62`
- **scan**:
    - bytes_read: `14256702`
    - files_binary_skipped: `0`
    - files_considered: `849`
    - files_read: `849`
    - files_too_large_skipped: `0`
    - files_truncated: `0`
    - files_unreadable: `0`
    - findings_kept: `310`
    - lines_scanned: `335515`
    - lines_truncated: `0`
    - raw_matches: `2682`
    - rules_hitting_cap: `['PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE']`
    - suppressed_by_reason: `{'allow-listed by the enclosing statement': 66, 'allow-listed line': 459, 'copyright notice naming a holder this repository attributes to itself in LICENSE/NOTICE; Apache-2.0 s4(c) requires the notice to be retained': 756, 'detector or example line': 2, 'entropy 0.45 below 4.20': 1, 'entropy 3.64 below 4.20': 1, 'entropy 3.67 below 4.20': 1, 'entropy 3.73 below 4.20': 1, 'entropy 3.75 below 4.20': 1, 'entropy 3.76 below 4.20': 1, 'entropy 3.80 below 4.20': 1, 'entropy 3.88 below 4.20': 1, 'entropy 3.89 below 4.20': 1, 'entropy 3.92 below 4.20': 2, 'entropy 3.95 below 4.20': 1, 'entropy 3.98 below 4.20': 1, 'entropy 4.07 below 4.20': 3, 'failed luhn check digit': 1, 'failed verhoeff check digit': 14, 'holder is declared by this project itself': 756, 'repository states its third-party trademark position in NOTICE (nominative use, marks belong to their owners)': 95, 'required context absent from line': 17, 'rule vocabulary or data table, not a notice': 51, 'value is a placeholder': 20}`

## Findings

### [REVIEW] Organisation acronym appears in source

- **Rule**: `BRAND.ORG_ACRONYM`
- **Where**: `crates/ainxt-payments/src/boundary.rs:72`
- **Classification**: TRADEMARK_BRAND
- **Finding id**: `5cffefd5c5cc2ef7`
- **Evidence**: `"nach.npci",`

**Why this matters.** The open-source distribution must be organisation-neutral.  A brand acronym in shipped source either leaks an internal deployment assumption or asserts a trademark the OSS project cannot license to downstream users.

**What to do.** Replace with a generic product or configuration name.  Where the reference is legitimate legal attribution (LICENSE, NOTICE, copyright headers), classify it PUBLIC_ATTRIBUTION and keep it -- do not strip attribution required by law or by an upstream license.  Suggested: use the configured product name, or a neutral term such as "enterprise"

### [REVIEW] Organisation acronym appears in source

- **Rule**: `BRAND.ORG_ACRONYM`
- **Where**: `crates/ainxt-payments/src/boundary.rs:75`
- **Classification**: TRADEMARK_BRAND
- **Finding id**: `d6fe4825b76bbb74`
- **Evidence**: `"settlement.npci",`

**Why this matters.** The open-source distribution must be organisation-neutral.  A brand acronym in shipped source either leaks an internal deployment assumption or asserts a trademark the OSS project cannot license to downstream users.

**What to do.** Replace with a generic product or configuration name.  Where the reference is legitimate legal attribution (LICENSE, NOTICE, copyright headers), classify it PUBLIC_ATTRIBUTION and keep it -- do not strip attribution required by law or by an upstream license.  Suggested: use the configured product name, or a neutral term such as "enterprise"

### [REVIEW] Organisation acronym appears in source

- **Rule**: `BRAND.ORG_ACRONYM`
- **Where**: `crates/ainxt-payments/src/boundary.rs:76`
- **Classification**: TRADEMARK_BRAND
- **Finding id**: `8828c4db81bbf23b`
- **Evidence**: `"netting.npci",`

**Why this matters.** The open-source distribution must be organisation-neutral.  A brand acronym in shipped source either leaks an internal deployment assumption or asserts a trademark the OSS project cannot license to downstream users.

**What to do.** Replace with a generic product or configuration name.  Where the reference is legitimate legal attribution (LICENSE, NOTICE, copyright headers), classify it PUBLIC_ATTRIBUTION and keep it -- do not strip attribution required by law or by an upstream license.  Suggested: use the configured product name, or a neutral term such as "enterprise"

### [REVIEW] Organisation acronym appears in source

- **Rule**: `BRAND.ORG_ACRONYM`
- **Where**: `crates/ainxt-runtimed/src/lib.rs:1474`
- **Classification**: TRADEMARK_BRAND
- **Finding id**: `a2d81e3a3d6e50fd`
- **Evidence**: `/// inside the reserved settlement perimeter (e.g. '"x402.pay"', '"nach.npci.execute"') matches`

**Why this matters.** The open-source distribution must be organisation-neutral.  A brand acronym in shipped source either leaks an internal deployment assumption or asserts a trademark the OSS project cannot license to downstream users.

**What to do.** Replace with a generic product or configuration name.  Where the reference is legitimate legal attribution (LICENSE, NOTICE, copyright headers), classify it PUBLIC_ATTRIBUTION and keep it -- do not strip attribution required by law or by an upstream license.  Suggested: use the configured product name, or a neutral term such as "enterprise"

### [REVIEW] External HTTP endpoint hardcoded in source

- **Rule**: `CONFIG.HARDCODED_HTTP_ENDPOINT`
- **Where**: `crates/ainxt-runtimed/src/lib.rs:1366`
- **Classification**: HARDCODED_REQUIRED
- **Finding id**: `cbbb6ffeae5a5f7e`
- **Evidence**: `.unwrap_or_else(|| "https://api.anthropic.com".into());`

**Why this matters.** An endpoint compiled into source cannot be redirected to a proxy, a mirror or an internal equivalent, which is precisely what a restricted-network deployment requires.

**What to do.** Read the URL from configuration with the public value as its default, and list the setting in .env.example.  Suggested: settings.<name>_url, defaulted from an environment variable

### [REVIEW] Cryptographic implementation or key management in source

- **Rule**: `LEGAL.CRYPTO_IMPLEMENTATION`
- **Where**: `THIRD_PARTY_INVENTORY.yaml:86`
- **Classification**: CRYPTO_IMPLEMENTATION
- **Legal review required**: yes
- **Finding id**: `e8e9e201e914e7df`
- **Evidence**: `- name: chacha20`

**Why this matters.** Cryptographic functionality can bring a distribution within the scope of export-control regimes.  Whether an exemption or notification applies is a legal determination about the specific distribution, not something a scanner can decide.

**What to do.** Inventory the cryptographic capabilities of the release and refer them for export-control review.  Many open-source distributions qualify for published-source exemptions, but that conclusion must come from counsel.

### [REVIEW] Cryptographic implementation or key management in source

- **Rule**: `LEGAL.CRYPTO_IMPLEMENTATION`
- **Where**: `THIRD_PARTY_INVENTORY.yaml:89`
- **Classification**: CRYPTO_IMPLEMENTATION
- **Legal review required**: yes
- **Finding id**: `7d49a4c4501cd5bc`
- **Evidence**: `repo: https://crates.io/crates/chacha20`

**Why this matters.** Cryptographic functionality can bring a distribution within the scope of export-control regimes.  Whether an exemption or notification applies is a legal determination about the specific distribution, not something a scanner can decide.

**What to do.** Inventory the cryptographic capabilities of the release and refer them for export-control review.  Many open-source distributions qualify for published-source exemptions, but that conclusion must come from counsel.

### [REVIEW] Cryptographic implementation or key management in source

- **Rule**: `LEGAL.CRYPTO_IMPLEMENTATION`
- **Where**: `THIRD_PARTY_INVENTORY.yaml:92`
- **Classification**: CRYPTO_IMPLEMENTATION
- **Legal review required**: yes
- **Finding id**: `e8e9e201e914e7df`
- **Evidence**: `- name: chacha20`

**Why this matters.** Cryptographic functionality can bring a distribution within the scope of export-control regimes.  Whether an exemption or notification applies is a legal determination about the specific distribution, not something a scanner can decide.

**What to do.** Inventory the cryptographic capabilities of the release and refer them for export-control review.  Many open-source distributions qualify for published-source exemptions, but that conclusion must come from counsel.

### [REVIEW] Cryptographic implementation or key management in source

- **Rule**: `LEGAL.CRYPTO_IMPLEMENTATION`
- **Where**: `THIRD_PARTY_INVENTORY.yaml:95`
- **Classification**: CRYPTO_IMPLEMENTATION
- **Legal review required**: yes
- **Finding id**: `7d49a4c4501cd5bc`
- **Evidence**: `repo: https://crates.io/crates/chacha20`

**Why this matters.** Cryptographic functionality can bring a distribution within the scope of export-control regimes.  Whether an exemption or notification applies is a legal determination about the specific distribution, not something a scanner can decide.

**What to do.** Inventory the cryptographic capabilities of the release and refer them for export-control review.  Many open-source distributions qualify for published-source exemptions, but that conclusion must come from counsel.

### [REVIEW] Cryptographic implementation or key management in source

- **Rule**: `LEGAL.CRYPTO_IMPLEMENTATION`
- **Where**: `THIRD_PARTY_INVENTORY.yaml:428`
- **Classification**: CRYPTO_IMPLEMENTATION
- **Legal review required**: yes
- **Finding id**: `f2be4ddc48a30f8d`
- **Evidence**: `- name: poly1305`

**Why this matters.** Cryptographic functionality can bring a distribution within the scope of export-control regimes.  Whether an exemption or notification applies is a legal determination about the specific distribution, not something a scanner can decide.

**What to do.** Inventory the cryptographic capabilities of the release and refer them for export-control review.  Many open-source distributions qualify for published-source exemptions, but that conclusion must come from counsel.

### [REVIEW] Cryptographic implementation or key management in source

- **Rule**: `LEGAL.CRYPTO_IMPLEMENTATION`
- **Where**: `THIRD_PARTY_INVENTORY.yaml:431`
- **Classification**: CRYPTO_IMPLEMENTATION
- **Legal review required**: yes
- **Finding id**: `287876620130c2e3`
- **Evidence**: `repo: https://crates.io/crates/poly1305`

**Why this matters.** Cryptographic functionality can bring a distribution within the scope of export-control regimes.  Whether an exemption or notification applies is a legal determination about the specific distribution, not something a scanner can decide.

**What to do.** Inventory the cryptographic capabilities of the release and refer them for export-control review.  Many open-source distributions qualify for published-source exemptions, but that conclusion must come from counsel.

### [REVIEW] Cryptographic implementation or key management in source

- **Rule**: `LEGAL.CRYPTO_IMPLEMENTATION`
- **Where**: `crates/ainxt-token/src/lib.rs:41`
- **Classification**: CRYPTO_IMPLEMENTATION
- **Legal review required**: yes
- **Finding id**: `e307b54bec315446`
- **Evidence**: `/// Length of an XChaCha20-Poly1305 key (256-bit) and nonce (192-bit).`

**Why this matters.** Cryptographic functionality can bring a distribution within the scope of export-control regimes.  Whether an exemption or notification applies is a legal determination about the specific distribution, not something a scanner can decide.

**What to do.** Inventory the cryptographic capabilities of the release and refer them for export-control review.  Many open-source distributions qualify for published-source exemptions, but that conclusion must come from counsel.

### [REVIEW] Cryptographic implementation or key management in source

- **Rule**: `LEGAL.CRYPTO_IMPLEMENTATION`
- **Where**: `crates/ainxt-token/src/lib.rs:82`
- **Classification**: CRYPTO_IMPLEMENTATION
- **Legal review required**: yes
- **Finding id**: `3abe0130352bbcc1`
- **Evidence**: `/// Ciphertext with the appended Poly1305 authentication tag.`

**Why this matters.** Cryptographic functionality can bring a distribution within the scope of export-control regimes.  Whether an exemption or notification applies is a legal determination about the specific distribution, not something a scanner can decide.

**What to do.** Inventory the cryptographic capabilities of the release and refer them for export-control review.  Many open-source distributions qualify for published-source exemptions, but that conclusion must come from counsel.

### [REVIEW] Provider-specific authentication header in shared code

- **Rule**: `MODEL.PROVIDER_AUTH_SCHEME`
- **Where**: `crates/ainxt-compliance/src/lib.rs:372`
- **Classification**: BUSINESS_LOGIC_COUPLING
- **Finding id**: `8bcbc3b7e56f35df`
- **Evidence**: `"api-key",`

**Why this matters.** A vendor-specific header name in shared code means the transport layer knows which vendor it is talking to, which is the coupling an adapter boundary is supposed to absorb.

**What to do.** Let the adapter own its headers; keep shared transport code vendor-neutral.

### [REVIEW] Provider-specific authentication header in shared code

- **Rule**: `MODEL.PROVIDER_AUTH_SCHEME`
- **Where**: `crates/ainxt-injection/src/egress.rs:493`
- **Classification**: BUSINESS_LOGIC_COUPLING
- **Finding id**: `c6dd8e557071db76`
- **Evidence**: `"api-key" => 6,`

**Why this matters.** A vendor-specific header name in shared code means the transport layer knows which vendor it is talking to, which is the coupling an adapter boundary is supposed to absorb.

**What to do.** Let the adapter own its headers; keep shared transport code vendor-neutral.

### [REVIEW] Provider-specific authentication header in shared code

- **Rule**: `MODEL.PROVIDER_AUTH_SCHEME`
- **Where**: `crates/ainxt-injection/src/egress.rs:540`
- **Classification**: BUSINESS_LOGIC_COUPLING
- **Finding id**: `0d591cf653cabfd6`
- **Evidence**: `("sk-", 20, "api-key"),`

**Why this matters.** A vendor-specific header name in shared code means the transport layer knows which vendor it is talking to, which is the coupling an adapter boundary is supposed to absorb.

**What to do.** Let the adapter own its headers; keep shared transport code vendor-neutral.

### [REVIEW] Provider-specific authentication header in shared code

- **Rule**: `MODEL.PROVIDER_AUTH_SCHEME`
- **Where**: `crates/ainxt-providers/src/anthropic.rs:73`
- **Classification**: BUSINESS_LOGIC_COUPLING
- **Finding id**: `ddc6d2876485c45a`
- **Evidence**: `.header("x-api-key", &self.api_key)`

**Why this matters.** A vendor-specific header name in shared code means the transport layer knows which vendor it is talking to, which is the coupling an adapter boundary is supposed to absorb.

**What to do.** Let the adapter own its headers; keep shared transport code vendor-neutral.

### [REVIEW] Provider-specific authentication header in shared code

- **Rule**: `MODEL.PROVIDER_AUTH_SCHEME`
- **Where**: `crates/ainxt-providers/src/anthropic.rs:74`
- **Classification**: BUSINESS_LOGIC_COUPLING
- **Finding id**: `5ce5786c533ee1eb`
- **Evidence**: `.header("anthropic-version", ANTHROPIC_VERSION)`

**Why this matters.** A vendor-specific header name in shared code means the transport layer knows which vendor it is talking to, which is the coupling an adapter boundary is supposed to absorb.

**What to do.** Let the adapter own its headers; keep shared transport code vendor-neutral.

### [REVIEW] Provider-specific authentication header in shared code

- **Rule**: `MODEL.PROVIDER_AUTH_SCHEME`
- **Where**: `crates/ainxt-providers/src/gemini.rs:79`
- **Classification**: BUSINESS_LOGIC_COUPLING
- **Finding id**: `e9002110f574a964`
- **Evidence**: `rb = rb.header("x-goog-api-key", &self.api_key);`

**Why this matters.** A vendor-specific header name in shared code means the transport layer knows which vendor it is talking to, which is the coupling an adapter boundary is supposed to absorb.

**What to do.** Let the adapter own its headers; keep shared transport code vendor-neutral.

### [REVIEW] Provider-specific credential variable referenced in business logic

- **Rule**: `MODEL.PROVIDER_CREDENTIAL_ENV`
- **Where**: `crates/ainxt-runtimed/src/lib.rs:1360`
- **Classification**: BUSINESS_LOGIC_COUPLING
- **Finding id**: `6dd9edea5d0026e6`
- **Evidence**: `let key = std::env::var("ANTHROPIC_API_KEY")`

**Why this matters.** Reading a named vendor credential outside its adapter means every deployment must supply that specific vendor's key, whichever provider it actually uses.

**What to do.** Have the adapter resolve its own credential from a provider-scoped setting, so the core requires only "a configured provider".

### [REVIEW] Provider-specific credential variable referenced in business logic

- **Rule**: `MODEL.PROVIDER_CREDENTIAL_ENV`
- **Where**: `crates/ainxt-runtimed/src/lib.rs:1375`
- **Classification**: BUSINESS_LOGIC_COUPLING
- **Finding id**: `b10b71b93502387d`
- **Evidence**: `let key = std::env::var("OPENAI_API_KEY")`

**Why this matters.** Reading a named vendor credential outside its adapter means every deployment must supply that specific vendor's key, whichever provider it actually uses.

**What to do.** Have the adapter resolve its own credential from a provider-scoped setting, so the core requires only "a configured provider".

### [REVIEW] Provider-specific credential variable referenced in business logic

- **Rule**: `MODEL.PROVIDER_CREDENTIAL_ENV`
- **Where**: `crates/ainxt-runtimed/src/lib.rs:1391`
- **Classification**: BUSINESS_LOGIC_COUPLING
- **Finding id**: `fc85af009532d532`
- **Evidence**: `// present-key-or-no-op convention as 'Anthropic'/'OpenAiSchema' above: 'GOOGLE_API_KEY'`

**Why this matters.** Reading a named vendor credential outside its adapter means every deployment must supply that specific vendor's key, whichever provider it actually uses.

**What to do.** Have the adapter resolve its own credential from a provider-scoped setting, so the core requires only "a configured provider".

### [REVIEW] Provider-specific credential variable referenced in business logic

- **Rule**: `MODEL.PROVIDER_CREDENTIAL_ENV`
- **Where**: `crates/ainxt-runtimed/src/lib.rs:1393`
- **Classification**: BUSINESS_LOGIC_COUPLING
- **Finding id**: `eb75f0f7404536a6`
- **Evidence**: `// 'ANTHROPIC_API_KEY'/'OPENAI_API_KEY' exactly rather than inventing a Gemini-specific`

**Why this matters.** Reading a named vendor credential outside its adapter means every deployment must supply that specific vendor's key, whichever provider it actually uses.

**What to do.** Have the adapter resolve its own credential from a provider-scoped setting, so the core requires only "a configured provider".

### [REVIEW] Provider-specific credential variable referenced in business logic

- **Rule**: `MODEL.PROVIDER_CREDENTIAL_ENV`
- **Where**: `crates/ainxt-runtimed/src/lib.rs:1395`
- **Classification**: BUSINESS_LOGIC_COUPLING
- **Finding id**: `195c0b3bac2db87c`
- **Evidence**: `let key = std::env::var("GOOGLE_API_KEY")`

**Why this matters.** Reading a named vendor credential outside its adapter means every deployment must supply that specific vendor's key, whichever provider it actually uses.

**What to do.** Have the adapter resolve its own credential from a provider-scoped setting, so the core requires only "a configured provider".

### [REVIEW] Provider-specific credential variable referenced in business logic

- **Rule**: `MODEL.PROVIDER_CREDENTIAL_ENV`
- **Where**: `crates/ainxt-runtimed/src/lib.rs:4301`
- **Classification**: BUSINESS_LOGIC_COUPLING
- **Finding id**: `80a641c2c1757cfe`
- **Evidence**: `ProviderKind::OpenAiSchema => std::env::var("OPENAI_API_KEY")`

**Why this matters.** Reading a named vendor credential outside its adapter means every deployment must supply that specific vendor's key, whichever provider it actually uses.

**What to do.** Have the adapter resolve its own credential from a provider-scoped setting, so the core requires only "a configured provider".

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:8`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:17`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:27`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:837`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:843`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:849`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:855`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:864`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:875`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:881`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:918`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:939`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:945`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:951`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:960`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:969`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:975`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:981`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:991`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:997`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1003`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1014`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1025`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1038`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1049`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1058`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1067`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1076`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1085`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1094`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1103`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1113`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1124`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1155`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1168`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1174`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1183`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1195`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1208`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1214`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1225`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1231`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1240`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1251`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1257`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1268`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1279`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1285`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1291`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1297`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1303`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1313`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1319`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1325`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1331`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1340`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1354`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1364`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1370`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1376`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1387`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1393`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1399`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1416`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1426`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1439`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1453`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1465`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1471`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1482`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1488`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1497`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1507`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1517`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1530`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1536`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1542`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1563`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1579`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1602`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1616`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1629`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1643`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1649`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1664`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1670`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1685`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1696`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1706`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1718`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1727`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1733`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1742`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1748`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1759`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1765`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1771`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1777`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1783`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1789`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1795`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1801`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1807`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1813`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1819`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1828`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1834`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1845`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1857`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1863`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1869`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1875`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1881`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1892`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1904`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1913`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1922`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1931`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1943`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1954`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1974`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:1996`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:2010`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:2019`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:2025`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:2036`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:2047`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:2057`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:2066`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:2072`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:2081`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:2096`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:2108`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:2119`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:2125`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:2167`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:2181`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:2187`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:2193`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:2206`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:2220`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:2230`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:2241`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:2247`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:2253`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:2263`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:2273`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:2282`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:2293`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [REVIEW] Upstream repository URL referenced in source

- **Rule**: `PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE`
- **Where**: `Cargo.lock:2307`
- **Classification**: UPSTREAM_ATTRIBUTION
- **Finding id**: `a10ab3ef3327668e`
- **Evidence**: `source = "registry+https://github.com/rust-lang/crates.io-index"`

**Why this matters.** A repository URL in a source comment is frequently the only surviving record of where a snippet came from, and is worth resolving into a documented provenance entry while the trail is still warm.

**What to do.** Determine whether code was actually incorporated from this repository.  If it was, record the license and version; if it is only a reference, classify it as such so it stops being flagged.

### [WARN] Organisation acronym appears in source

- **Rule**: `BRAND.ORG_ACRONYM`
- **Where**: `crates/ainxt-payments/src/boundary.rs:1196`
- **Classification**: TRADEMARK_BRAND
- **Finding id**: `efc82e8206f28184`
- **Evidence**: `// The shipped NACH pattern is '"nach.npci"' (see 'default_reserved'), so the host has to`

**Why this matters.** The open-source distribution must be organisation-neutral.  A brand acronym in shipped source either leaks an internal deployment assumption or asserts a trademark the OSS project cannot license to downstream users.

**What to do.** Replace with a generic product or configuration name.  Where the reference is legitimate legal attribution (LICENSE, NOTICE, copyright headers), classify it PUBLIC_ATTRIBUTION and keep it -- do not strip attribution required by law or by an upstream license.  Suggested: use the configured product name, or a neutral term such as "enterprise"

### [WARN] Organisation acronym appears in source

- **Rule**: `BRAND.ORG_ACRONYM`
- **Where**: `crates/ainxt-payments/src/boundary.rs:1200`
- **Classification**: TRADEMARK_BRAND
- **Finding id**: `56294eef8c5b050f`
- **Evidence**: `assert!(p.contains("https://nach.npci.example.internal/mandate"));`

**Why this matters.** The open-source distribution must be organisation-neutral.  A brand acronym in shipped source either leaks an internal deployment assumption or asserts a trademark the OSS project cannot license to downstream users.

**What to do.** Replace with a generic product or configuration name.  Where the reference is legitimate legal attribution (LICENSE, NOTICE, copyright headers), classify it PUBLIC_ATTRIBUTION and keep it -- do not strip attribution required by law or by an upstream license.  Suggested: use the configured product name, or a neutral term such as "enterprise"

### [WARN] Service port hardcoded rather than configured

- **Rule**: `CONFIG.HARDCODED_PORT_BINDING`
- **Where**: `config.toml:5`
- **Classification**: HARDCODED_OPTIONAL
- **Finding id**: `e0e9912b15572486`
- **Evidence**: `port = 8080`

**Why this matters.** A fixed port collides with whatever else the adopter runs, and prevents running two instances on one host.

**What to do.** Default the port from configuration.

### [WARN] Service port hardcoded rather than configured

- **Rule**: `CONFIG.HARDCODED_PORT_BINDING`
- **Where**: `crates/ainxt-runtimed/config/runtimed.example.toml:15`
- **Classification**: HARDCODED_OPTIONAL
- **Finding id**: `2d1fd294a5164838`
- **Evidence**: `port = 8080`

**Why this matters.** A fixed port collides with whatever else the adopter runs, and prevents running two instances on one host.

**What to do.** Default the port from configuration.

### [WARN] Service port hardcoded rather than configured

- **Rule**: `CONFIG.HARDCODED_PORT_BINDING`
- **Where**: `crates/ainxt-runtimed/src/lib.rs:325`
- **Classification**: HARDCODED_OPTIONAL
- **Finding id**: `c1d6ee5215452184`
- **Evidence**: `port: 8080,`

**Why this matters.** A fixed port collides with whatever else the adopter runs, and prevents running two instances on one host.

**What to do.** Default the port from configuration.

### [WARN] Service port hardcoded rather than configured

- **Rule**: `CONFIG.HARDCODED_PORT_BINDING`
- **Where**: `crates/ainxt-runtimed/src/lib.rs:10978`
- **Classification**: HARDCODED_OPTIONAL
- **Finding id**: `c2dd0bd71fc51ca9`
- **Evidence**: `port = 9000`

**Why this matters.** A fixed port collides with whatever else the adopter runs, and prevents running two instances on one host.

**What to do.** Default the port from configuration.

### [WARN] Service port hardcoded rather than configured

- **Rule**: `CONFIG.HARDCODED_PORT_BINDING`
- **Where**: `crates/ainxt-runtimed/src/lib.rs:10995`
- **Classification**: HARDCODED_OPTIONAL
- **Finding id**: `dfacdda5ba5786cb`
- **Evidence**: `port = 8080"#;`

**Why this matters.** A fixed port collides with whatever else the adopter runs, and prevents running two instances on one host.

**What to do.** Default the port from configuration.

### [WARN] Service port hardcoded rather than configured

- **Rule**: `CONFIG.HARDCODED_PORT_BINDING`
- **Where**: `crates/ainxt-runtimed/src/lib.rs:10997`
- **Classification**: HARDCODED_OPTIONAL
- **Finding id**: `ea9da68993037409`
- **Evidence**: `port = 9999"#;`

**Why this matters.** A fixed port collides with whatever else the adopter runs, and prevents running two instances on one host.

**What to do.** Default the port from configuration.

### [WARN] Feature or capability switch hardcoded rather than read from configuration

- **Rule**: `COUPLING.HARDCODED_FEATURE_TOGGLE`
- **Where**: `config.toml:24`
- **Classification**: CONFIGURABLE_TOGGLE
- **Finding id**: `bd9fc8f4da678440`
- **Evidence**: `rag_enabled = false`

**Why this matters.** A capability switch fixed to one value at the source level cannot be toggled by whoever deploys the software; it is not a setting, it only looks like one.  A downstream adopter who needs the opposite behaviour has no way to get it without patching source, which is precisely what "configurable toggle on/off" rules out.

**What to do.** Default the flag from configuration (environment variable or settings object) with the current literal as its default value, so behaviour is unchanged until an operator deliberately changes the setting.  Suggested: read from configuration, e.g. ${FEATURE_X_ENABLED}, defaulting to the current value

### [WARN] Model identifier hardcoded outside the model registry

- **Rule**: `MODEL.HARDCODED_IDENTIFIER`
- **Where**: `crates/ainxt-client/src/lib.rs:1749`
- **Classification**: BUSINESS_LOGIC_COUPLING
- **Finding id**: `bf3e384587a69328`
- **Evidence**: `ainxt_admission::resolve_model_policy("claude-sonnet-4-6"),`

**Why this matters.** A model identifier compiled into business logic makes the model a code dependency rather than a deployment choice.  Downstream users cannot point the software at their own model without patching source, and a retired model becomes a code change instead of a config change.

**What to do.** Resolve the identifier from configuration through the model registry.  A literal is acceptable only as a documented default inside the registry itself, read from an environment variable.  Suggested: read from configuration, e.g. ${LLM_MODEL}

### [WARN] Model identifier hardcoded outside the model registry

- **Rule**: `MODEL.HARDCODED_IDENTIFIER`
- **Where**: `crates/ainxt-client/src/lib.rs:1750`
- **Classification**: BUSINESS_LOGIC_COUPLING
- **Finding id**: `56f4c0da2ba65ba7`
- **Evidence**: `(Tier::Complex, Some("claude-sonnet-4-6".to_string()))`

**Why this matters.** A model identifier compiled into business logic makes the model a code dependency rather than a deployment choice.  Downstream users cannot point the software at their own model without patching source, and a retired model becomes a code change instead of a config change.

**What to do.** Resolve the identifier from configuration through the model registry.  A literal is acceptable only as a documented default inside the registry itself, read from an environment variable.  Suggested: read from configuration, e.g. ${LLM_MODEL}

### [WARN] Model identifier hardcoded outside the model registry

- **Rule**: `MODEL.HARDCODED_IDENTIFIER`
- **Where**: `crates/ainxt-eval/src/judge.rs:1021`
- **Classification**: BUSINESS_LOGIC_COUPLING
- **Finding id**: `bcf2b7d81a0e434b`
- **Evidence**: `model_version: "glm-4-2026-05".into(),`

**Why this matters.** A model identifier compiled into business logic makes the model a code dependency rather than a deployment choice.  Downstream users cannot point the software at their own model without patching source, and a retired model becomes a code change instead of a config change.

**What to do.** Resolve the identifier from configuration through the model registry.  A literal is acceptable only as a documented default inside the registry itself, read from an environment variable.  Suggested: read from configuration, e.g. ${LLM_MODEL}

### [WARN] Model identifier hardcoded outside the model registry

- **Rule**: `MODEL.HARDCODED_IDENTIFIER`
- **Where**: `crates/ainxt-eval/src/pipeline.rs:778`
- **Classification**: BUSINESS_LOGIC_COUPLING
- **Finding id**: `406840eae27a8cfa`
- **Evidence**: `model_version: "glm-4-2026-05".into(),`

**Why this matters.** A model identifier compiled into business logic makes the model a code dependency rather than a deployment choice.  Downstream users cannot point the software at their own model without patching source, and a retired model becomes a code change instead of a config change.

**What to do.** Resolve the identifier from configuration through the model registry.  A literal is acceptable only as a documented default inside the registry itself, read from an environment variable.  Suggested: read from configuration, e.g. ${LLM_MODEL}

### [WARN] Model identifier hardcoded outside the model registry

- **Rule**: `MODEL.HARDCODED_IDENTIFIER`
- **Where**: `crates/ainxt-planner/src/program.rs:1550`
- **Classification**: BUSINESS_LOGIC_COUPLING
- **Finding id**: `b544afc6f9beb436`
- **Evidence**: `let s1 = build("qwen-v1", "qwen-v1");`

**Why this matters.** A model identifier compiled into business logic makes the model a code dependency rather than a deployment choice.  Downstream users cannot point the software at their own model without patching source, and a retired model becomes a code change instead of a config change.

**What to do.** Resolve the identifier from configuration through the model registry.  A literal is acceptable only as a documented default inside the registry itself, read from an environment variable.  Suggested: read from configuration, e.g. ${LLM_MODEL}

### [WARN] Model identifier hardcoded outside the model registry

- **Rule**: `MODEL.HARDCODED_IDENTIFIER`
- **Where**: `crates/ainxt-planner/src/program.rs:1551`
- **Classification**: BUSINESS_LOGIC_COUPLING
- **Finding id**: `1eaf9de75c580786`
- **Evidence**: `let s2 = build("qwen-v1", "glm-v2"); // coder model retired mid-program`

**Why this matters.** A model identifier compiled into business logic makes the model a code dependency rather than a deployment choice.  Downstream users cannot point the software at their own model without patching source, and a retired model becomes a code change instead of a config change.

**What to do.** Resolve the identifier from configuration through the model registry.  A literal is acceptable only as a documented default inside the registry itself, read from an environment variable.  Suggested: read from configuration, e.g. ${LLM_MODEL}

### [WARN] Model identifier hardcoded outside the model registry

- **Rule**: `MODEL.HARDCODED_IDENTIFIER`
- **Where**: `crates/ainxt-protocol/src/lib.rs:1433`
- **Classification**: BUSINESS_LOGIC_COUPLING
- **Finding id**: `9958f670ef79d619`
- **Evidence**: `forced_model: Some("gpt-5.4".into()),`

**Why this matters.** A model identifier compiled into business logic makes the model a code dependency rather than a deployment choice.  Downstream users cannot point the software at their own model without patching source, and a retired model becomes a code change instead of a config change.

**What to do.** Resolve the identifier from configuration through the model registry.  A literal is acceptable only as a documented default inside the registry itself, read from an environment variable.  Suggested: read from configuration, e.g. ${LLM_MODEL}

### [WARN] Model identifier hardcoded outside the model registry

- **Rule**: `MODEL.HARDCODED_IDENTIFIER`
- **Where**: `crates/ainxt-protocol/src/lib.rs:1594`
- **Classification**: BUSINESS_LOGIC_COUPLING
- **Finding id**: `e9f884f95c776af3`
- **Evidence**: `model: "gpt-5.4".into(),`

**Why this matters.** A model identifier compiled into business logic makes the model a code dependency rather than a deployment choice.  Downstream users cannot point the software at their own model without patching source, and a retired model becomes a code change instead of a config change.

**What to do.** Resolve the identifier from configuration through the model registry.  A literal is acceptable only as a documented default inside the registry itself, read from an environment variable.  Suggested: read from configuration, e.g. ${LLM_MODEL}

### [WARN] Model identifier hardcoded outside the model registry

- **Rule**: `MODEL.HARDCODED_IDENTIFIER`
- **Where**: `crates/ainxt-protocol/src/lib.rs:1624`
- **Classification**: BUSINESS_LOGIC_COUPLING
- **Finding id**: `e9f884f95c776af3`
- **Evidence**: `model: "gpt-5.4".into(),`

**Why this matters.** A model identifier compiled into business logic makes the model a code dependency rather than a deployment choice.  Downstream users cannot point the software at their own model without patching source, and a retired model becomes a code change instead of a config change.

**What to do.** Resolve the identifier from configuration through the model registry.  A literal is acceptable only as a documented default inside the registry itself, read from an environment variable.  Suggested: read from configuration, e.g. ${LLM_MODEL}

### [WARN] Model identifier hardcoded outside the model registry

- **Rule**: `MODEL.HARDCODED_IDENTIFIER`
- **Where**: `crates/ainxt-replay/src/lib.rs:2556`
- **Classification**: BUSINESS_LOGIC_COUPLING
- **Finding id**: `38164121a8952eaf`
- **Evidence**: `model: "claude-sonnet-4-6".into(),`

**Why this matters.** A model identifier compiled into business logic makes the model a code dependency rather than a deployment choice.  Downstream users cannot point the software at their own model without patching source, and a retired model becomes a code change instead of a config change.

**What to do.** Resolve the identifier from configuration through the model registry.  A literal is acceptable only as a documented default inside the registry itself, read from an environment variable.  Suggested: read from configuration, e.g. ${LLM_MODEL}

### [WARN] Model identifier hardcoded outside the model registry

- **Rule**: `MODEL.HARDCODED_IDENTIFIER`
- **Where**: `crates/ainxt-replay/src/lib.rs:3115`
- **Classification**: BUSINESS_LOGIC_COUPLING
- **Finding id**: `38164121a8952eaf`
- **Evidence**: `model: "claude-sonnet-4-6".into(),`

**Why this matters.** A model identifier compiled into business logic makes the model a code dependency rather than a deployment choice.  Downstream users cannot point the software at their own model without patching source, and a retired model becomes a code change instead of a config change.

**What to do.** Resolve the identifier from configuration through the model registry.  A literal is acceptable only as a documented default inside the registry itself, read from an environment variable.  Suggested: read from configuration, e.g. ${LLM_MODEL}

### [WARN] Model identifier hardcoded outside the model registry

- **Rule**: `MODEL.HARDCODED_IDENTIFIER`
- **Where**: `crates/ainxt-runtimed/src/lib.rs:10589`
- **Classification**: BUSINESS_LOGIC_COUPLING
- **Finding id**: `c990dd2ff1402ce0`
- **Evidence**: `provider: "claude-sonnet-4-6".into(),`

**Why this matters.** A model identifier compiled into business logic makes the model a code dependency rather than a deployment choice.  Downstream users cannot point the software at their own model without patching source, and a retired model becomes a code change instead of a config change.

**What to do.** Resolve the identifier from configuration through the model registry.  A literal is acceptable only as a documented default inside the registry itself, read from an environment variable.  Suggested: read from configuration, e.g. ${LLM_MODEL}

### [WARN] Model identifier hardcoded outside the model registry

- **Rule**: `MODEL.HARDCODED_IDENTIFIER`
- **Where**: `crates/ainxt-runtimed/src/lib.rs:11182`
- **Classification**: BUSINESS_LOGIC_COUPLING
- **Finding id**: `f8edf418cc8b7185`
- **Evidence**: `id = "gemini-2.5-flash"`

**Why this matters.** A model identifier compiled into business logic makes the model a code dependency rather than a deployment choice.  Downstream users cannot point the software at their own model without patching source, and a retired model becomes a code change instead of a config change.

**What to do.** Resolve the identifier from configuration through the model registry.  A literal is acceptable only as a documented default inside the registry itself, read from an environment variable.  Suggested: read from configuration, e.g. ${LLM_MODEL}

### [WARN] Model identifier hardcoded outside the model registry

- **Rule**: `MODEL.HARDCODED_IDENTIFIER`
- **Where**: `crates/ainxt-runtimed/src/lib.rs:11197`
- **Classification**: BUSINESS_LOGIC_COUPLING
- **Finding id**: `4f7eaaca12206ace`
- **Evidence**: `.any(|r| r.contains("gemini-2.5-flash") && r.contains("skipped")),`

**Why this matters.** A model identifier compiled into business logic makes the model a code dependency rather than a deployment choice.  Downstream users cannot point the software at their own model without patching source, and a retired model becomes a code change instead of a config change.

**What to do.** Resolve the identifier from configuration through the model registry.  A literal is acceptable only as a documented default inside the registry itself, read from an environment variable.  Suggested: read from configuration, e.g. ${LLM_MODEL}

### [WARN] Model identifier hardcoded outside the model registry

- **Rule**: `MODEL.HARDCODED_IDENTIFIER`
- **Where**: `crates/ainxt-runtimed/src/lib.rs:11213`
- **Classification**: BUSINESS_LOGIC_COUPLING
- **Finding id**: `d5512e9b8a727f67`
- **Evidence**: `.any(|r| r.contains("gemini-2.5-flash") && r.contains("wired")),`

**Why this matters.** A model identifier compiled into business logic makes the model a code dependency rather than a deployment choice.  Downstream users cannot point the software at their own model without patching source, and a retired model becomes a code change instead of a config change.

**What to do.** Resolve the identifier from configuration through the model registry.  A literal is acceptable only as a documented default inside the registry itself, read from an environment variable.  Suggested: read from configuration, e.g. ${LLM_MODEL}

### [WARN] Model identifier hardcoded outside the model registry

- **Rule**: `MODEL.HARDCODED_IDENTIFIER`
- **Where**: `crates/ainxt-server/src/lib.rs:12649`
- **Classification**: BUSINESS_LOGIC_COUPLING
- **Finding id**: `6854a9afcbcd2158`
- **Evidence**: `"seq_id": seq, "model_id": "qwen-32b", "priority": "interactive",`

**Why this matters.** A model identifier compiled into business logic makes the model a code dependency rather than a deployment choice.  Downstream users cannot point the software at their own model without patching source, and a retired model becomes a code change instead of a config change.

**What to do.** Resolve the identifier from configuration through the model registry.  A literal is acceptable only as a documented default inside the registry itself, read from an environment variable.  Suggested: read from configuration, e.g. ${LLM_MODEL}

### [WARN] Model identifier hardcoded outside the model registry

- **Rule**: `MODEL.HARDCODED_IDENTIFIER`
- **Where**: `crates/ainxt-server/src/lib.rs:12932`
- **Classification**: BUSINESS_LOGIC_COUPLING
- **Finding id**: `70d75146caf955e9`
- **Evidence**: `"seq_id": 7, "model_id": "qwen-32b", "priority": "interactive",`

**Why this matters.** A model identifier compiled into business logic makes the model a code dependency rather than a deployment choice.  Downstream users cannot point the software at their own model without patching source, and a retired model becomes a code change instead of a config change.

**What to do.** Resolve the identifier from configuration through the model registry.  A literal is acceptable only as a documented default inside the registry itself, read from an environment variable.  Suggested: read from configuration, e.g. ${LLM_MODEL}

### [WARN] Model identifier hardcoded outside the model registry

- **Rule**: `MODEL.HARDCODED_IDENTIFIER`
- **Where**: `crates/ainxt-server/src/lib.rs:12959`
- **Classification**: BUSINESS_LOGIC_COUPLING
- **Finding id**: `f132c79dec5fc5e7`
- **Evidence**: `model_id: "qwen-32b".into(),`

**Why this matters.** A model identifier compiled into business logic makes the model a code dependency rather than a deployment choice.  Downstream users cannot point the software at their own model without patching source, and a retired model becomes a code change instead of a config change.

**What to do.** Resolve the identifier from configuration through the model registry.  A literal is acceptable only as a documented default inside the registry itself, read from an environment variable.  Suggested: read from configuration, e.g. ${LLM_MODEL}

### [WARN] Model identifier hardcoded outside the model registry

- **Rule**: `MODEL.HARDCODED_IDENTIFIER`
- **Where**: `crates/ainxt-serving/src/disagg.rs:174`
- **Classification**: BUSINESS_LOGIC_COUPLING
- **Finding id**: `717c4cad50c87494`
- **Evidence**: `model_id: "qwen-32b".into(),`

**Why this matters.** A model identifier compiled into business logic makes the model a code dependency rather than a deployment choice.  Downstream users cannot point the software at their own model without patching source, and a retired model becomes a code change instead of a config change.

**What to do.** Resolve the identifier from configuration through the model registry.  A literal is acceptable only as a documented default inside the registry itself, read from an environment variable.  Suggested: read from configuration, e.g. ${LLM_MODEL}

### [WARN] Model identifier hardcoded outside the model registry

- **Rule**: `MODEL.HARDCODED_IDENTIFIER`
- **Where**: `crates/ainxt-serving/src/gate.rs:808`
- **Classification**: BUSINESS_LOGIC_COUPLING
- **Finding id**: `81f4fe2deb70489e`
- **Evidence**: `model_id: "qwen-32b".into(),`

**Why this matters.** A model identifier compiled into business logic makes the model a code dependency rather than a deployment choice.  Downstream users cannot point the software at their own model without patching source, and a retired model becomes a code change instead of a config change.

**What to do.** Resolve the identifier from configuration through the model registry.  A literal is acceptable only as a documented default inside the registry itself, read from an environment variable.  Suggested: read from configuration, e.g. ${LLM_MODEL}

### [WARN] Model identifier hardcoded outside the model registry

- **Rule**: `MODEL.HARDCODED_IDENTIFIER`
- **Where**: `crates/ainxt-serving/src/rollout.rs:520`
- **Classification**: BUSINESS_LOGIC_COUPLING
- **Finding id**: `90030355887cc2c7`
- **Evidence**: `model_id: "qwen-32b".into(),`

**Why this matters.** A model identifier compiled into business logic makes the model a code dependency rather than a deployment choice.  Downstream users cannot point the software at their own model without patching source, and a retired model becomes a code change instead of a config change.

**What to do.** Resolve the identifier from configuration through the model registry.  A literal is acceptable only as a documented default inside the registry itself, read from an environment variable.  Suggested: read from configuration, e.g. ${LLM_MODEL}

### [WARN] Model identifier hardcoded outside the model registry

- **Rule**: `MODEL.HARDCODED_IDENTIFIER`
- **Where**: `crates/ainxt-serving/src/rollout.rs:562`
- **Classification**: BUSINESS_LOGIC_COUPLING
- **Finding id**: `52079e0d5f567d63`
- **Evidence**: `.with_on_disk_hash("qwen-32b", "v2", 0xBADBAD);`

**Why this matters.** A model identifier compiled into business logic makes the model a code dependency rather than a deployment choice.  Downstream users cannot point the software at their own model without patching source, and a retired model becomes a code change instead of a config change.

**What to do.** Resolve the identifier from configuration through the model registry.  A literal is acceptable only as a documented default inside the registry itself, read from an environment variable.  Suggested: read from configuration, e.g. ${LLM_MODEL}

### [INFO] External HTTP endpoint hardcoded in source

- **Rule**: `CONFIG.HARDCODED_HTTP_ENDPOINT`
- **Where**: `crates/ainxt-connector-http/src/lib.rs:2139`
- **Classification**: HARDCODED_REQUIRED
- **Finding id**: `d6f22d94d89afc51`
- **Evidence**: `GitLab::new("https://gl.internal").get_project("g/r"),`

**Why this matters.** An endpoint compiled into source cannot be redirected to a proxy, a mirror or an internal equivalent, which is precisely what a restricted-network deployment requires.

**What to do.** Read the URL from configuration with the public value as its default, and list the setting in .env.example.  Suggested: settings.<name>_url, defaulted from an environment variable

### [INFO] External HTTP endpoint hardcoded in source

- **Rule**: `CONFIG.HARDCODED_HTTP_ENDPOINT`
- **Where**: `crates/ainxt-connector-http/src/lib.rs:2180`
- **Classification**: HARDCODED_REQUIRED
- **Finding id**: `beaab2e7bd6f2ba5`
- **Evidence**: `GitLab::new("https://benign.internal").get_project("settlement-account:HDFC0001");`

**Why this matters.** An endpoint compiled into source cannot be redirected to a proxy, a mirror or an internal equivalent, which is precisely what a restricted-network deployment requires.

**What to do.** Read the URL from configuration with the public value as its default, and list the setting in .env.example.  Suggested: settings.<name>_url, defaulted from an environment variable

### [INFO] External HTTP endpoint hardcoded in source

- **Rule**: `CONFIG.HARDCODED_HTTP_ENDPOINT`
- **Where**: `crates/ainxt-connector-http/src/lib.rs:2214`
- **Classification**: HARDCODED_REQUIRED
- **Finding id**: `d6f22d94d89afc51`
- **Evidence**: `GitLab::new("https://gl.internal").get_project("g/r"),`

**Why this matters.** An endpoint compiled into source cannot be redirected to a proxy, a mirror or an internal equivalent, which is precisely what a restricted-network deployment requires.

**What to do.** Read the URL from configuration with the public value as its default, and list the setting in .env.example.  Suggested: settings.<name>_url, defaulted from an environment variable

### [INFO] External HTTP endpoint hardcoded in source

- **Rule**: `CONFIG.HARDCODED_HTTP_ENDPOINT`
- **Where**: `crates/ainxt-mcp/src/lib.rs:2505`
- **Classification**: HARDCODED_REQUIRED
- **Finding id**: `99c52dfca5e1c279`
- **Evidence**: `"https://prod.jira/mcp",`

**Why this matters.** An endpoint compiled into source cannot be redirected to a proxy, a mirror or an internal equivalent, which is precisely what a restricted-network deployment requires.

**What to do.** Read the URL from configuration with the public value as its default, and list the setting in .env.example.  Suggested: settings.<name>_url, defaulted from an environment variable

### [INFO] External HTTP endpoint hardcoded in source

- **Rule**: `CONFIG.HARDCODED_HTTP_ENDPOINT`
- **Where**: `crates/ainxt-mcp/src/lib.rs:2514`
- **Classification**: HARDCODED_REQUIRED
- **Finding id**: `61dda2510889f004`
- **Evidence**: `"https://staging.jira/mcp",`

**Why this matters.** An endpoint compiled into source cannot be redirected to a proxy, a mirror or an internal equivalent, which is precisely what a restricted-network deployment requires.

**What to do.** Read the URL from configuration with the public value as its default, and list the setting in .env.example.  Suggested: settings.<name>_url, defaulted from an environment variable

### [INFO] External HTTP endpoint hardcoded in source

- **Rule**: `CONFIG.HARDCODED_HTTP_ENDPOINT`
- **Where**: `crates/ainxt-mcp/src/lib.rs:2516`
- **Classification**: HARDCODED_REQUIRED
- **Finding id**: `de62d76b449fed51`
- **Evidence**: `pins.get("https://staging.jira/mcp").as_ref(),`

**Why this matters.** An endpoint compiled into source cannot be redirected to a proxy, a mirror or an internal equivalent, which is precisely what a restricted-network deployment requires.

**What to do.** Read the URL from configuration with the public value as its default, and list the setting in .env.example.  Suggested: settings.<name>_url, defaulted from an environment variable

### [INFO] External HTTP endpoint hardcoded in source

- **Rule**: `CONFIG.HARDCODED_HTTP_ENDPOINT`
- **Where**: `crates/ainxt-mcp/src/lib.rs:2524`
- **Classification**: HARDCODED_REQUIRED
- **Finding id**: `99c52dfca5e1c279`
- **Evidence**: `"https://prod.jira/mcp",`

**Why this matters.** An endpoint compiled into source cannot be redirected to a proxy, a mirror or an internal equivalent, which is precisely what a restricted-network deployment requires.

**What to do.** Read the URL from configuration with the public value as its default, and list the setting in .env.example.  Suggested: settings.<name>_url, defaulted from an environment variable

### [INFO] External HTTP endpoint hardcoded in source

- **Rule**: `CONFIG.HARDCODED_HTTP_ENDPOINT`
- **Where**: `crates/ainxt-mcp/src/lib.rs:2526`
- **Classification**: HARDCODED_REQUIRED
- **Finding id**: `13ca439d98d3b67b`
- **Evidence**: `pins.get("https://prod.jira/mcp").as_ref(),`

**Why this matters.** An endpoint compiled into source cannot be redirected to a proxy, a mirror or an internal equivalent, which is precisely what a restricted-network deployment requires.

**What to do.** Read the URL from configuration with the public value as its default, and list the setting in .env.example.  Suggested: settings.<name>_url, defaulted from an environment variable

### [INFO] External HTTP endpoint hardcoded in source

- **Rule**: `CONFIG.HARDCODED_HTTP_ENDPOINT`
- **Where**: `crates/ainxt-payments/src/boundary.rs:1180`
- **Classification**: HARDCODED_REQUIRED
- **Finding id**: `f22f06c610658e68`
- **Evidence**: `destination: "https://not-allow-listed.internal/x".into(),`

**Why this matters.** An endpoint compiled into source cannot be redirected to a proxy, a mirror or an internal equivalent, which is precisely what a restricted-network deployment requires.

**What to do.** Read the URL from configuration with the public value as its default, and list the setting in .env.example.  Suggested: settings.<name>_url, defaulted from an environment variable

### [INFO] External HTTP endpoint hardcoded in source

- **Rule**: `CONFIG.HARDCODED_HTTP_ENDPOINT`
- **Where**: `crates/ainxt-payments/src/boundary.rs:1271`
- **Classification**: HARDCODED_REQUIRED
- **Finding id**: `136e2621d9de791f`
- **Evidence**: `let write = OutboundCall::read("https://internal.svc/api", "settlement-account:HDFC0001");`

**Why this matters.** An endpoint compiled into source cannot be redirected to a proxy, a mirror or an internal equivalent, which is precisely what a restricted-network deployment requires.

**What to do.** Read the URL from configuration with the public value as its default, and list the setting in .env.example.  Suggested: settings.<name>_url, defaulted from an environment variable

### [INFO] External HTTP endpoint hardcoded in source

- **Rule**: `CONFIG.HARDCODED_HTTP_ENDPOINT`
- **Where**: `crates/ainxt-payments/src/boundary.rs:1274`
- **Classification**: HARDCODED_REQUIRED
- **Finding id**: `5d003b83dc580f61`
- **Evidence**: `let report = OutboundCall::read("https://internal.svc/api", "settlement-report:2026-07");`

**Why this matters.** An endpoint compiled into source cannot be redirected to a proxy, a mirror or an internal equivalent, which is precisely what a restricted-network deployment requires.

**What to do.** Read the URL from configuration with the public value as its default, and list the setting in .env.example.  Suggested: settings.<name>_url, defaulted from an environment variable

### [INFO] External HTTP endpoint hardcoded in source

- **Rule**: `CONFIG.HARDCODED_HTTP_ENDPOINT`
- **Where**: `crates/ainxt-payments/src/boundary.rs:1283`
- **Classification**: HARDCODED_REQUIRED
- **Finding id**: `fc96490697810835`
- **Evidence**: `destination: "https://internal.svc/iso".to_string(),`

**Why this matters.** An endpoint compiled into source cannot be redirected to a proxy, a mirror or an internal equivalent, which is precisely what a restricted-network deployment requires.

**What to do.** Read the URL from configuration with the public value as its default, and list the setting in .env.example.  Suggested: settings.<name>_url, defaulted from an environment variable

### [INFO] External HTTP endpoint hardcoded in source

- **Rule**: `CONFIG.HARDCODED_HTTP_ENDPOINT`
- **Where**: `crates/ainxt-payments/src/boundary.rs:1321`
- **Classification**: HARDCODED_REQUIRED
- **Finding id**: `76e901ea58d67f5a`
- **Evidence**: `destination: "https://internal.svc/upi".to_string(),`

**Why this matters.** An endpoint compiled into source cannot be redirected to a proxy, a mirror or an internal equivalent, which is precisely what a restricted-network deployment requires.

**What to do.** Read the URL from configuration with the public value as its default, and list the setting in .env.example.  Suggested: settings.<name>_url, defaulted from an environment variable

### [INFO] External HTTP endpoint hardcoded in source

- **Rule**: `CONFIG.HARDCODED_HTTP_ENDPOINT`
- **Where**: `crates/ainxt-payments/src/boundary.rs:1329`
- **Classification**: HARDCODED_REQUIRED
- **Finding id**: `76e901ea58d67f5a`
- **Evidence**: `destination: "https://internal.svc/upi".to_string(),`

**Why this matters.** An endpoint compiled into source cannot be redirected to a proxy, a mirror or an internal equivalent, which is precisely what a restricted-network deployment requires.

**What to do.** Read the URL from configuration with the public value as its default, and list the setting in .env.example.  Suggested: settings.<name>_url, defaulted from an environment variable

### [INFO] External HTTP endpoint hardcoded in source

- **Rule**: `CONFIG.HARDCODED_HTTP_ENDPOINT`
- **Where**: `crates/ainxt-payments/src/boundary.rs:1345`
- **Classification**: HARDCODED_REQUIRED
- **Finding id**: `113bb62579fc9536`
- **Evidence**: `destination: "https://internal.svc/nach".to_string(),`

**Why this matters.** An endpoint compiled into source cannot be redirected to a proxy, a mirror or an internal equivalent, which is precisely what a restricted-network deployment requires.

**What to do.** Read the URL from configuration with the public value as its default, and list the setting in .env.example.  Suggested: settings.<name>_url, defaulted from an environment variable

### [INFO] External HTTP endpoint hardcoded in source

- **Rule**: `CONFIG.HARDCODED_HTTP_ENDPOINT`
- **Where**: `crates/ainxt-payments/src/boundary.rs:1352`
- **Classification**: HARDCODED_REQUIRED
- **Finding id**: `fc71c6439fe821c0`
- **Evidence**: `destination: "https://internal.svc/relay".to_string(),`

**Why this matters.** An endpoint compiled into source cannot be redirected to a proxy, a mirror or an internal equivalent, which is precisely what a restricted-network deployment requires.

**What to do.** Read the URL from configuration with the public value as its default, and list the setting in .env.example.  Suggested: settings.<name>_url, defaulted from an environment variable

### [INFO] External HTTP endpoint hardcoded in source

- **Rule**: `CONFIG.HARDCODED_HTTP_ENDPOINT`
- **Where**: `crates/ainxt-payments/src/boundary.rs:1359`
- **Classification**: HARDCODED_REQUIRED
- **Finding id**: `a276b6263480b2c5`
- **Evidence**: `destination: "https://internal.svc/2pc".to_string(),`

**Why this matters.** An endpoint compiled into source cannot be redirected to a proxy, a mirror or an internal equivalent, which is precisely what a restricted-network deployment requires.

**What to do.** Read the URL from configuration with the public value as its default, and list the setting in .env.example.  Suggested: settings.<name>_url, defaulted from an environment variable

### [INFO] External HTTP endpoint hardcoded in source

- **Rule**: `CONFIG.HARDCODED_HTTP_ENDPOINT`
- **Where**: `crates/ainxt-payments/src/boundary.rs:1372`
- **Classification**: HARDCODED_REQUIRED
- **Finding id**: `37d25f3e961c24aa`
- **Evidence**: `destination: "https://ledger-settlement.core.internal/post".to_string(),`

**Why this matters.** An endpoint compiled into source cannot be redirected to a proxy, a mirror or an internal equivalent, which is precisely what a restricted-network deployment requires.

**What to do.** Read the URL from configuration with the public value as its default, and list the setting in .env.example.  Suggested: settings.<name>_url, defaulted from an environment variable

### [INFO] External HTTP endpoint hardcoded in source

- **Rule**: `CONFIG.HARDCODED_HTTP_ENDPOINT`
- **Where**: `crates/ainxt-payments/src/boundary.rs:1399`
- **Classification**: HARDCODED_REQUIRED
- **Finding id**: `b8b5c4ef5cec2523`
- **Evidence**: `let call = OutboundCall::read("https://reports.internal/api", "settlement-report:2026-07");`

**Why this matters.** An endpoint compiled into source cannot be redirected to a proxy, a mirror or an internal equivalent, which is precisely what a restricted-network deployment requires.

**What to do.** Read the URL from configuration with the public value as its default, and list the setting in .env.example.  Suggested: settings.<name>_url, defaulted from an environment variable

### [INFO] External HTTP endpoint hardcoded in source

- **Rule**: `CONFIG.HARDCODED_HTTP_ENDPOINT`
- **Where**: `crates/ainxt-payments/src/boundary.rs:1424`
- **Classification**: HARDCODED_REQUIRED
- **Finding id**: `f539829d0f8d7355`
- **Evidence**: `allow.allow("https://reports.internal/api").unwrap();`

**Why this matters.** An endpoint compiled into source cannot be redirected to a proxy, a mirror or an internal equivalent, which is precisely what a restricted-network deployment requires.

**What to do.** Read the URL from configuration with the public value as its default, and list the setting in .env.example.  Suggested: settings.<name>_url, defaulted from an environment variable

### [INFO] External HTTP endpoint hardcoded in source

- **Rule**: `CONFIG.HARDCODED_HTTP_ENDPOINT`
- **Where**: `crates/ainxt-payments/src/boundary.rs:1426`
- **Classification**: HARDCODED_REQUIRED
- **Finding id**: `648aa89dba076976`
- **Evidence**: `let ok = OutboundCall::read("https://reports.internal/api", "settlement-report:2026-07");`

**Why this matters.** An endpoint compiled into source cannot be redirected to a proxy, a mirror or an internal equivalent, which is precisely what a restricted-network deployment requires.

**What to do.** Read the URL from configuration with the public value as its default, and list the setting in .env.example.  Suggested: settings.<name>_url, defaulted from an environment variable

### [INFO] External HTTP endpoint hardcoded in source

- **Rule**: `CONFIG.HARDCODED_HTTP_ENDPOINT`
- **Where**: `crates/ainxt-payments/src/boundary.rs:1462`
- **Classification**: HARDCODED_REQUIRED
- **Finding id**: `e32bf887a3a4a9d1`
- **Evidence**: `let call = OutboundCall::read("https://unknown.internal/api", "doc:1");`

**Why this matters.** An endpoint compiled into source cannot be redirected to a proxy, a mirror or an internal equivalent, which is precisely what a restricted-network deployment requires.

**What to do.** Read the URL from configuration with the public value as its default, and list the setting in .env.example.  Suggested: settings.<name>_url, defaulted from an environment variable

### [INFO] External HTTP endpoint hardcoded in source

- **Rule**: `CONFIG.HARDCODED_HTTP_ENDPOINT`
- **Where**: `crates/ainxt-payments/src/boundary.rs:1468`
- **Classification**: HARDCODED_REQUIRED
- **Finding id**: `10753a0df3f20fc9`
- **Evidence**: `destination: "https://unknown.internal/api".to_string(),`

**Why this matters.** An endpoint compiled into source cannot be redirected to a proxy, a mirror or an internal equivalent, which is precisely what a restricted-network deployment requires.

**What to do.** Read the URL from configuration with the public value as its default, and list the setting in .env.example.  Suggested: settings.<name>_url, defaulted from an environment variable

### [INFO] External HTTP endpoint hardcoded in source

- **Rule**: `CONFIG.HARDCODED_HTTP_ENDPOINT`
- **Where**: `crates/ainxt-payments/src/boundary.rs:1479`
- **Classification**: HARDCODED_REQUIRED
- **Finding id**: `51dec2b63b8b7fd7`
- **Evidence**: `allow.allow("https://internal.svc/iso").unwrap();`

**Why this matters.** An endpoint compiled into source cannot be redirected to a proxy, a mirror or an internal equivalent, which is precisely what a restricted-network deployment requires.

**What to do.** Read the URL from configuration with the public value as its default, and list the setting in .env.example.  Suggested: settings.<name>_url, defaulted from an environment variable

### [INFO] External HTTP endpoint hardcoded in source

- **Rule**: `CONFIG.HARDCODED_HTTP_ENDPOINT`
- **Where**: `crates/ainxt-payments/src/boundary.rs:1481`
- **Classification**: HARDCODED_REQUIRED
- **Finding id**: `fc96490697810835`
- **Evidence**: `destination: "https://internal.svc/iso".to_string(),`

**Why this matters.** An endpoint compiled into source cannot be redirected to a proxy, a mirror or an internal equivalent, which is precisely what a restricted-network deployment requires.

**What to do.** Read the URL from configuration with the public value as its default, and list the setting in .env.example.  Suggested: settings.<name>_url, defaulted from an environment variable

### [INFO] Email address in source

- **Rule**: `INTERNAL.EMAIL_ADDRESS`
- **Where**: `crates/ainxt-injection/tests/gap_egress_closure_test.rs:57`
- **Classification**: PERSONAL_DATA
- **Finding id**: `b6fdc7b55076de5d`
- **Evidence**: `let decision = guard_egress("mail to anyone@wherever.com", &EgressPolicy::default());`

**Why this matters.** A real personal address in a public repository is personal data and a durable spam and phishing target.  Published role addresses are acceptable when the project intends them to be contactable.

**What to do.** Replace individual addresses with a documented role address, or with a reserved example domain in samples and tests.

### [INFO] Email address in source

- **Rule**: `INTERNAL.EMAIL_ADDRESS`
- **Where**: `crates/ainxt-prompt/src/layered.rs:302`
- **Classification**: PERSONAL_DATA
- **Finding id**: `bf5920118ee7aa03`
- **Evidence**: `assert_eq!(tuple[0], "L1@prompt.persona.v1.0.0");`

**Why this matters.** A real personal address in a public repository is personal data and a durable spam and phishing target.  Published role addresses are acceptable when the project intends them to be contactable.

**What to do.** Replace individual addresses with a documented role address, or with a reserved example domain in samples and tests.

### [INFO] Email address in source

- **Rule**: `INTERNAL.EMAIL_ADDRESS`
- **Where**: `crates/ainxt-prompt/src/layered.rs:303`
- **Classification**: PERSONAL_DATA
- **Finding id**: `565544db1fee0dc6`
- **Evidence**: `assert_eq!(tuple[3], "L4@prompt.guards.v1.0.0");`

**Why this matters.** A real personal address in a public repository is personal data and a durable spam and phishing target.  Published role addresses are acceptable when the project intends them to be contactable.

**What to do.** Replace individual addresses with a documented role address, or with a reserved example domain in samples and tests.

### [INFO] Email address in source

- **Rule**: `INTERNAL.EMAIL_ADDRESS`
- **Where**: `crates/ainxt-prompt/src/service.rs:572`
- **Classification**: PERSONAL_DATA
- **Finding id**: `2d1eccbd19b38594`
- **Evidence**: `assert_eq!(compiled.version_tuple()[0], "L1@prompt.persona.v1.0.0");`

**Why this matters.** A real personal address in a public repository is personal data and a durable spam and phishing target.  Published role addresses are acceptable when the project intends them to be contactable.

**What to do.** Replace individual addresses with a documented role address, or with a reserved example domain in samples and tests.

### [INFO] Email address in source

- **Rule**: `INTERNAL.EMAIL_ADDRESS`
- **Where**: `crates/ainxt-prompt/tests/registry_test.rs:152`
- **Classification**: PERSONAL_DATA
- **Finding id**: `5869c9cdb70766ca`
- **Evidence**: `assert_eq!(tuple[0], "L1@prompt.persona.v1.0.0");`

**Why this matters.** A real personal address in a public repository is personal data and a durable spam and phishing target.  Published role addresses are acceptable when the project intends them to be contactable.

**What to do.** Replace individual addresses with a documented role address, or with a reserved example domain in samples and tests.

### [INFO] Email address in source

- **Rule**: `INTERNAL.EMAIL_ADDRESS`
- **Where**: `crates/ainxt-prompt/tests/registry_test.rs:153`
- **Classification**: PERSONAL_DATA
- **Finding id**: `cd76fd2a5a3959d3`
- **Evidence**: `assert_eq!(tuple[3], "L4@prompt.guards.v1.0.0");`

**Why this matters.** A real personal address in a public repository is personal data and a durable spam and phishing target.  Published role addresses are acceptable when the project intends them to be contactable.

**What to do.** Replace individual addresses with a documented role address, or with a reserved example domain in samples and tests.

### [INFO] Telephone number in source

- **Rule**: `INTERNAL.PHONE_NUMBER`
- **Where**: `crates/ainxt-artifact/src/lib.rs:1118`
- **Classification**: PERSONAL_DATA
- **Finding id**: `2ef731ff7708b36f`
- **Evidence**: `.scan("4111 1111 1111 1111")`

**Why this matters.** A contact number in shipped source is personal data.  This rule is deliberately noisy-then-filtered because numeric formats overlap heavily with identifiers and timestamps.

**What to do.** Remove, or replace with a documented reserved test number.

### [INFO] Telephone number in source

- **Rule**: `INTERNAL.PHONE_NUMBER`
- **Where**: `crates/ainxt-compliance/src/lib.rs:930`
- **Classification**: PERSONAL_DATA
- **Finding id**: `896dbcd5c89c9810`
- **Evidence**: `.persist(&mut sink, "charge 4111 1111 1111 1111 now")`

**Why this matters.** A contact number in shipped source is personal data.  This rule is deliberately noisy-then-filtered because numeric formats overlap heavily with identifiers and timestamps.

**What to do.** Remove, or replace with a documented reserved test number.

### [INFO] Telephone number in source

- **Rule**: `INTERNAL.PHONE_NUMBER`
- **Where**: `crates/ainxt-compliance/src/lib.rs:1045`
- **Classification**: PERSONAL_DATA
- **Finding id**: `5f9822742fefdd56`
- **Evidence**: `"settle 4111 1111 1111 1111 and 5500005555555559 password=hunter2 acct 123456789012";`

**Why this matters.** A contact number in shipped source is personal data.  This rule is deliberately noisy-then-filtered because numeric formats overlap heavily with identifiers and timestamps.

**What to do.** Remove, or replace with a documented reserved test number.

### [INFO] Telephone number in source

- **Rule**: `INTERNAL.PHONE_NUMBER`
- **Where**: `crates/ainxt-compliance/src/lib.rs:1143`
- **Classification**: PERSONAL_DATA
- **Finding id**: `2e1280583b428d11`
- **Evidence**: `let (out, _) = red("PAN 4111-1111-1111-1111 end");`

**Why this matters.** A contact number in shipped source is personal data.  This rule is deliberately noisy-then-filtered because numeric formats overlap heavily with identifiers and timestamps.

**What to do.** Remove, or replace with a documented reserved test number.

### [INFO] Telephone number in source

- **Rule**: `INTERNAL.PHONE_NUMBER`
- **Where**: `crates/ainxt-compliance/tests/r12_composite_detector_seam.rs:69`
- **Classification**: PERSONAL_DATA
- **Finding id**: `99caa4e9a02f2e1a`
- **Evidence**: `const SAMPLE: &str = "pay ravi@okhdfcbank now, card 4111 1111 1111 1111, mail a@b.com";`

**Why this matters.** A contact number in shipped source is personal data.  This rule is deliberately noisy-then-filtered because numeric formats overlap heavily with identifiers and timestamps.

**What to do.** Remove, or replace with a documented reserved test number.

### [INFO] Telephone number in source

- **Rule**: `INTERNAL.PHONE_NUMBER`
- **Where**: `crates/ainxt-connector/src/lib.rs:1339`
- **Classification**: PERSONAL_DATA
- **Finding id**: `f55aa03bbdcb1e38`
- **Evidence**: `"4111 1111 1111 1111", // Visa, space-grouped`

**Why this matters.** A contact number in shipped source is personal data.  This rule is deliberately noisy-then-filtered because numeric formats overlap heavily with identifiers and timestamps.

**What to do.** Remove, or replace with a documented reserved test number.

### [INFO] Telephone number in source

- **Rule**: `INTERNAL.PHONE_NUMBER`
- **Where**: `crates/ainxt-connector/src/lib.rs:1340`
- **Classification**: PERSONAL_DATA
- **Finding id**: `34a6ea103c460eec`
- **Evidence**: `"4111-1111-1111-1111", // Visa, hyphen-grouped`

**Why this matters.** A contact number in shipped source is personal data.  This rule is deliberately noisy-then-filtered because numeric formats overlap heavily with identifiers and timestamps.

**What to do.** Remove, or replace with a documented reserved test number.

### [INFO] Telephone number in source

- **Rule**: `INTERNAL.PHONE_NUMBER`
- **Where**: `crates/ainxt-connector/src/lib.rs:1369`
- **Classification**: PERSONAL_DATA
- **Finding id**: `dbfdf701600c5312`
- **Evidence**: `let out = g.filter_egress(&cid, "ref 1111 1111 1111 1111 end");`

**Why this matters.** A contact number in shipped source is personal data.  This rule is deliberately noisy-then-filtered because numeric formats overlap heavily with identifiers and timestamps.

**What to do.** Remove, or replace with a documented reserved test number.

### [INFO] Telephone number in source

- **Rule**: `INTERNAL.PHONE_NUMBER`
- **Where**: `crates/ainxt-connector/src/lib.rs:1375`
- **Classification**: PERSONAL_DATA
- **Finding id**: `cfda9ccbbe1fee78`
- **Evidence**: `assert!(out.payload.contains("1111 1111 1111 1111"));`

**Why this matters.** A contact number in shipped source is personal data.  This rule is deliberately noisy-then-filtered because numeric formats overlap heavily with identifiers and timestamps.

**What to do.** Remove, or replace with a documented reserved test number.

### [INFO] Telephone number in source

- **Rule**: `INTERNAL.PHONE_NUMBER`
- **Where**: `crates/ainxt-pipeline/src/sast.rs:303`
- **Classification**: PERSONAL_DATA
- **Finding id**: `c786822d8ac9e251`
- **Evidence**: `let src = "fn f() { log::info!(\"charging card 4111 1111 1111 1111\"); }\n";`

**Why this matters.** A contact number in shipped source is personal data.  This rule is deliberately noisy-then-filtered because numeric formats overlap heavily with identifiers and timestamps.

**What to do.** Remove, or replace with a documented reserved test number.

### [INFO] Telephone number in source

- **Rule**: `INTERNAL.PHONE_NUMBER`
- **Where**: `crates/ainxt-planner/src/assurance.rs:422`
- **Classification**: PERSONAL_DATA
- **Finding id**: `d38c212093618869`
- **Evidence**: `"let card = \"4111 1111 1111 1111\";",`

**Why this matters.** A contact number in shipped source is personal data.  This rule is deliberately noisy-then-filtered because numeric formats overlap heavily with identifiers and timestamps.

**What to do.** Remove, or replace with a documented reserved test number.

### [INFO] Telephone number in source

- **Rule**: `INTERNAL.PHONE_NUMBER`
- **Where**: `crates/ainxt-planner/tests/r12_assurance_nonsynthetic_proofs.rs:83`
- **Classification**: PERSONAL_DATA
- **Finding id**: `54924d84b757ef05`
- **Evidence**: `"let card = \"4111 1111 1111 1111\"; save(card);",`

**Why this matters.** A contact number in shipped source is personal data.  This rule is deliberately noisy-then-filtered because numeric formats overlap heavily with identifiers and timestamps.

**What to do.** Remove, or replace with a documented reserved test number.

### [INFO] Telephone number in source

- **Rule**: `INTERNAL.PHONE_NUMBER`
- **Where**: `crates/ainxt-runtime/tests/r8_compliance_out_stream.rs:203`
- **Classification**: PERSONAL_DATA
- **Finding id**: `ae968a36981f4459`
- **Evidence**: `Event::TextDelta("4111 1111 1111 ".into()),`

**Why this matters.** A contact number in shipped source is personal data.  This rule is deliberately noisy-then-filtered because numeric formats overlap heavily with identifiers and timestamps.

**What to do.** Remove, or replace with a documented reserved test number.

### [INFO] Telephone number in source

- **Rule**: `INTERNAL.PHONE_NUMBER`
- **Where**: `crates/ainxt-runtime/tests/r8_compliance_out_stream.rs:236`
- **Classification**: PERSONAL_DATA
- **Finding id**: `9a9f1b550ac82ff6`
- **Evidence**: `let pan = "4111 1111 1111 1111";`

**Why this matters.** A contact number in shipped source is personal data.  This rule is deliberately noisy-then-filtered because numeric formats overlap heavily with identifiers and timestamps.

**What to do.** Remove, or replace with a documented reserved test number.

### [INFO] Telephone number in source

- **Rule**: `INTERNAL.PHONE_NUMBER`
- **Where**: `crates/ainxt-tools/tests/r15_detector_engine_re2_ci_mandate.rs:53`
- **Classification**: PERSONAL_DATA
- **Finding id**: `361aea8cd54e3662`
- **Evidence**: `assert!(re2_detectors::is_pan_like("4111 1111 1111 1111"));`

**Why this matters.** A contact number in shipped source is personal data.  This rule is deliberately noisy-then-filtered because numeric formats overlap heavily with identifiers and timestamps.

**What to do.** Remove, or replace with a documented reserved test number.

### [INFO] Telephone number in source

- **Rule**: `INTERNAL.PHONE_NUMBER`
- **Where**: `crates/ainxt-tools/tests/r15_detector_engine_re2_ci_mandate.rs:63`
- **Classification**: PERSONAL_DATA
- **Finding id**: `071bb807a317a6ab`
- **Evidence**: `assert!(re2_detectors::is_aadhaar_like("1234 5678 9012"));`

**Why this matters.** A contact number in shipped source is personal data.  This rule is deliberately noisy-then-filtered because numeric formats overlap heavily with identifiers and timestamps.

**What to do.** Remove, or replace with a documented reserved test number.

### [INFO] Telephone number in source

- **Rule**: `INTERNAL.PHONE_NUMBER`
- **Where**: `crates/ainxt-tools/tests/r4_data_class_tri_signal.rs:194`
- **Classification**: PERSONAL_DATA
- **Finding id**: `eb111db146d0588c`
- **Evidence**: `.classify_data_class("read", "card 4111 1111 1111 1111", &MarkerArgScanner)`

**Why this matters.** A contact number in shipped source is personal data.  This rule is deliberately noisy-then-filtered because numeric formats overlap heavily with identifiers and timestamps.

**What to do.** Remove, or replace with a documented reserved test number.

### [INFO] Cryptographic implementation or key management in source

- **Rule**: `LEGAL.CRYPTO_IMPLEMENTATION`
- **Where**: `crates/ainxt-cryptoagility/src/lib.rs:431`
- **Classification**: CRYPTO_IMPLEMENTATION
- **Legal review required**: yes
- **Finding id**: `acdff255a3f132cf`
- **Evidence**: `Algorithm::deprecated("ed25519", 100, false),`

**Why this matters.** Cryptographic functionality can bring a distribution within the scope of export-control regimes.  Whether an exemption or notification applies is a legal determination about the specific distribution, not something a scanner can decide.

**What to do.** Inventory the cryptographic capabilities of the release and refer them for export-control review.  Many open-source distributions qualify for published-source exemptions, but that conclusion must come from counsel.

### [INFO] Cryptographic implementation or key management in source

- **Rule**: `LEGAL.CRYPTO_IMPLEMENTATION`
- **Where**: `crates/ainxt-cryptoagility/src/lib.rs:435`
- **Classification**: CRYPTO_IMPLEMENTATION
- **Legal review required**: yes
- **Finding id**: `473a3b0f87bfcaf4`
- **Evidence**: `Algorithm::forbidden("rsa-1024-sha1", false),`

**Why this matters.** Cryptographic functionality can bring a distribution within the scope of export-control regimes.  Whether an exemption or notification applies is a legal determination about the specific distribution, not something a scanner can decide.

**What to do.** Inventory the cryptographic capabilities of the release and refer them for export-control review.  Many open-source distributions qualify for published-source exemptions, but that conclusion must come from counsel.

### [INFO] Cryptographic implementation or key management in source

- **Rule**: `LEGAL.CRYPTO_IMPLEMENTATION`
- **Where**: `crates/ainxt-cryptoagility/src/lib.rs:456`
- **Classification**: CRYPTO_IMPLEMENTATION
- **Legal review required**: yes
- **Finding id**: `2c53b2effedaa8f1`
- **Evidence**: `r.register(Purpose::Signing, Algorithm::forbidden("rsa-1024", false))`

**Why this matters.** Cryptographic functionality can bring a distribution within the scope of export-control regimes.  Whether an exemption or notification applies is a legal determination about the specific distribution, not something a scanner can decide.

**What to do.** Inventory the cryptographic capabilities of the release and refer them for export-control review.  Many open-source distributions qualify for published-source exemptions, but that conclusion must come from counsel.

### [INFO] Cryptographic implementation or key management in source

- **Rule**: `LEGAL.CRYPTO_IMPLEMENTATION`
- **Where**: `crates/ainxt-cryptoagility/src/lib.rs:459`
- **Classification**: CRYPTO_IMPLEMENTATION
- **Legal review required**: yes
- **Finding id**: `acdff255a3f132cf`
- **Evidence**: `Algorithm::deprecated("ed25519", 100, false),`

**Why this matters.** Cryptographic functionality can bring a distribution within the scope of export-control regimes.  Whether an exemption or notification applies is a legal determination about the specific distribution, not something a scanner can decide.

**What to do.** Inventory the cryptographic capabilities of the release and refer them for export-control review.  Many open-source distributions qualify for published-source exemptions, but that conclusion must come from counsel.

### [INFO] Cryptographic implementation or key management in source

- **Rule**: `LEGAL.CRYPTO_IMPLEMENTATION`
- **Where**: `crates/ainxt-cryptoagility/src/lib.rs:462`
- **Classification**: CRYPTO_IMPLEMENTATION
- **Legal review required**: yes
- **Finding id**: `28621a709b409ebd`
- **Evidence**: `assert_eq!(r.resolve(Purpose::Signing, 50).unwrap().name, "ed25519");`

**Why this matters.** Cryptographic functionality can bring a distribution within the scope of export-control regimes.  Whether an exemption or notification applies is a legal determination about the specific distribution, not something a scanner can decide.

**What to do.** Inventory the cryptographic capabilities of the release and refer them for export-control review.  Many open-source distributions qualify for published-source exemptions, but that conclusion must come from counsel.

### [INFO] Cryptographic implementation or key management in source

- **Rule**: `LEGAL.CRYPTO_IMPLEMENTATION`
- **Where**: `crates/ainxt-cryptoagility/src/lib.rs:463`
- **Classification**: CRYPTO_IMPLEMENTATION
- **Legal review required**: yes
- **Finding id**: `6daac2dcd85ea527`
- **Evidence**: `assert_eq!(r.resolve(Purpose::Signing, 100).unwrap().name, "ed25519");`

**Why this matters.** Cryptographic functionality can bring a distribution within the scope of export-control regimes.  Whether an exemption or notification applies is a legal determination about the specific distribution, not something a scanner can decide.

**What to do.** Inventory the cryptographic capabilities of the release and refer them for export-control review.  Many open-source distributions qualify for published-source exemptions, but that conclusion must come from counsel.

### [INFO] Cryptographic implementation or key management in source

- **Rule**: `LEGAL.CRYPTO_IMPLEMENTATION`
- **Where**: `crates/ainxt-cryptoagility/src/lib.rs:473`
- **Classification**: CRYPTO_IMPLEMENTATION
- **Legal review required**: yes
- **Finding id**: `acdff255a3f132cf`
- **Evidence**: `Algorithm::deprecated("ed25519", 100, false),`

**Why this matters.** Cryptographic functionality can bring a distribution within the scope of export-control regimes.  Whether an exemption or notification applies is a legal determination about the specific distribution, not something a scanner can decide.

**What to do.** Inventory the cryptographic capabilities of the release and refer them for export-control review.  Many open-source distributions qualify for published-source exemptions, but that conclusion must come from counsel.

### [INFO] Cryptographic implementation or key management in source

- **Rule**: `LEGAL.CRYPTO_IMPLEMENTATION`
- **Where**: `crates/ainxt-cryptoagility/src/lib.rs:477`
- **Classification**: CRYPTO_IMPLEMENTATION
- **Legal review required**: yes
- **Finding id**: `6daac2dcd85ea527`
- **Evidence**: `assert_eq!(r.resolve(Purpose::Signing, 100).unwrap().name, "ed25519");`

**Why this matters.** Cryptographic functionality can bring a distribution within the scope of export-control regimes.  Whether an exemption or notification applies is a legal determination about the specific distribution, not something a scanner can decide.

**What to do.** Inventory the cryptographic capabilities of the release and refer them for export-control review.  Many open-source distributions qualify for published-source exemptions, but that conclusion must come from counsel.

### [INFO] Cryptographic implementation or key management in source

- **Rule**: `LEGAL.CRYPTO_IMPLEMENTATION`
- **Where**: `crates/ainxt-cryptoagility/src/lib.rs:498`
- **Classification**: CRYPTO_IMPLEMENTATION
- **Legal review required**: yes
- **Finding id**: `3d704eda67e062b0`
- **Evidence**: `Algorithm::deprecated("x25519", 10, true),`

**Why this matters.** Cryptographic functionality can bring a distribution within the scope of export-control regimes.  Whether an exemption or notification applies is a legal determination about the specific distribution, not something a scanner can decide.

**What to do.** Inventory the cryptographic capabilities of the release and refer them for export-control review.  Many open-source distributions qualify for published-source exemptions, but that conclusion must come from counsel.

### [INFO] Cryptographic implementation or key management in source

- **Rule**: `LEGAL.CRYPTO_IMPLEMENTATION`
- **Where**: `crates/ainxt-cryptoagility/src/lib.rs:539`
- **Classification**: CRYPTO_IMPLEMENTATION
- **Legal review required**: yes
- **Finding id**: `6b3b3b4e9150dce3`
- **Evidence**: `.register(Purpose::KeyExchange, Algorithm::approved("x25519", false));`

**Why this matters.** Cryptographic functionality can bring a distribution within the scope of export-control regimes.  Whether an exemption or notification applies is a legal determination about the specific distribution, not something a scanner can decide.

**What to do.** Inventory the cryptographic capabilities of the release and refer them for export-control review.  Many open-source distributions qualify for published-source exemptions, but that conclusion must come from counsel.

### [INFO] Cryptographic implementation or key management in source

- **Rule**: `LEGAL.CRYPTO_IMPLEMENTATION`
- **Where**: `crates/ainxt-cryptoagility/src/lib.rs:554`
- **Classification**: CRYPTO_IMPLEMENTATION
- **Legal review required**: yes
- **Finding id**: `95f15b0e97e28b3f`
- **Evidence**: `let forbidden = Algorithm::forbidden("rsa-1024", false);`

**Why this matters.** Cryptographic functionality can bring a distribution within the scope of export-control regimes.  Whether an exemption or notification applies is a legal determination about the specific distribution, not something a scanner can decide.

**What to do.** Inventory the cryptographic capabilities of the release and refer them for export-control review.  Many open-source distributions qualify for published-source exemptions, but that conclusion must come from counsel.

### [INFO] Cryptographic implementation or key management in source

- **Rule**: `LEGAL.CRYPTO_IMPLEMENTATION`
- **Where**: `crates/ainxt-cryptoagility/src/lib.rs:555`
- **Classification**: CRYPTO_IMPLEMENTATION
- **Legal review required**: yes
- **Finding id**: `15d8a07ae1bc34d6`
- **Evidence**: `let deprecated = Algorithm::deprecated("ed25519", 100, false);`

**Why this matters.** Cryptographic functionality can bring a distribution within the scope of export-control regimes.  Whether an exemption or notification applies is a legal determination about the specific distribution, not something a scanner can decide.

**What to do.** Inventory the cryptographic capabilities of the release and refer them for export-control review.  Many open-source distributions qualify for published-source exemptions, but that conclusion must come from counsel.

### [INFO] Cryptographic implementation or key management in source

- **Rule**: `LEGAL.CRYPTO_IMPLEMENTATION`
- **Where**: `crates/ainxt-cryptoagility/src/lib.rs:575`
- **Classification**: CRYPTO_IMPLEMENTATION
- **Legal review required**: yes
- **Finding id**: `1bc42c83622dcf6e`
- **Evidence**: `let dep = Algorithm::deprecated("x25519", 50, true);`

**Why this matters.** Cryptographic functionality can bring a distribution within the scope of export-control regimes.  Whether an exemption or notification applies is a legal determination about the specific distribution, not something a scanner can decide.

**What to do.** Inventory the cryptographic capabilities of the release and refer them for export-control review.  Many open-source distributions qualify for published-source exemptions, but that conclusion must come from counsel.

### [INFO] Cryptographic implementation or key management in source

- **Rule**: `LEGAL.CRYPTO_IMPLEMENTATION`
- **Where**: `crates/ainxt-cryptoagility/src/lib.rs:589`
- **Classification**: CRYPTO_IMPLEMENTATION
- **Legal review required**: yes
- **Finding id**: `393b8b2f8dcd2f41`
- **Evidence**: `assert_eq!(names, ["ml-dsa-65", "ed25519", "rsa-1024-sha1"]);`

**Why this matters.** Cryptographic functionality can bring a distribution within the scope of export-control regimes.  Whether an exemption or notification applies is a legal determination about the specific distribution, not something a scanner can decide.

**What to do.** Inventory the cryptographic capabilities of the release and refer them for export-control review.  Many open-source distributions qualify for published-source exemptions, but that conclusion must come from counsel.

### [INFO] Cryptographic implementation or key management in source

- **Rule**: `LEGAL.CRYPTO_IMPLEMENTATION`
- **Where**: `crates/ainxt-prompt/src/control.rs:348`
- **Classification**: CRYPTO_IMPLEMENTATION
- **Legal review required**: yes
- **Finding id**: `85460ab776c18068`
- **Evidence**: `static CTR: AtomicU64 = AtomicU64::new(0);`

**Why this matters.** Cryptographic functionality can bring a distribution within the scope of export-control regimes.  Whether an exemption or notification applies is a legal determination about the specific distribution, not something a scanner can decide.

**What to do.** Inventory the cryptographic capabilities of the release and refer them for export-control review.  Many open-source distributions qualify for published-source exemptions, but that conclusion must come from counsel.

### [INFO] Cryptographic implementation or key management in source

- **Rule**: `LEGAL.CRYPTO_IMPLEMENTATION`
- **Where**: `crates/ainxt-prompt/src/control.rs:349`
- **Classification**: CRYPTO_IMPLEMENTATION
- **Legal review required**: yes
- **Finding id**: `a900e170fe43ab0b`
- **Evidence**: `let n = CTR.fetch_add(1, Ordering::SeqCst);`

**Why this matters.** Cryptographic functionality can bring a distribution within the scope of export-control regimes.  Whether an exemption or notification applies is a legal determination about the specific distribution, not something a scanner can decide.

**What to do.** Inventory the cryptographic capabilities of the release and refer them for export-control review.  Many open-source distributions qualify for published-source exemptions, but that conclusion must come from counsel.

### [INFO] Cryptographic implementation or key management in source

- **Rule**: `LEGAL.CRYPTO_IMPLEMENTATION`
- **Where**: `crates/ainxt-skill/src/control.rs:508`
- **Classification**: CRYPTO_IMPLEMENTATION
- **Legal review required**: yes
- **Finding id**: `7028e60757a7fb3d`
- **Evidence**: `static CTR: AtomicU64 = AtomicU64::new(0);`

**Why this matters.** Cryptographic functionality can bring a distribution within the scope of export-control regimes.  Whether an exemption or notification applies is a legal determination about the specific distribution, not something a scanner can decide.

**What to do.** Inventory the cryptographic capabilities of the release and refer them for export-control review.  Many open-source distributions qualify for published-source exemptions, but that conclusion must come from counsel.

### [INFO] Cryptographic implementation or key management in source

- **Rule**: `LEGAL.CRYPTO_IMPLEMENTATION`
- **Where**: `crates/ainxt-skill/src/control.rs:509`
- **Classification**: CRYPTO_IMPLEMENTATION
- **Legal review required**: yes
- **Finding id**: `9124661ff373a545`
- **Evidence**: `let n = CTR.fetch_add(1, Ordering::SeqCst);`

**Why this matters.** Cryptographic functionality can bring a distribution within the scope of export-control regimes.  Whether an exemption or notification applies is a legal determination about the specific distribution, not something a scanner can decide.

**What to do.** Inventory the cryptographic capabilities of the release and refer them for export-control review.  Many open-source distributions qualify for published-source exemptions, but that conclusion must come from counsel.

### [INFO] Cryptographic implementation or key management in source

- **Rule**: `LEGAL.CRYPTO_IMPLEMENTATION`
- **Where**: `crates/ainxt-token/src/lib.rs:1560`
- **Classification**: CRYPTO_IMPLEMENTATION
- **Legal review required**: yes
- **Finding id**: `17285b1e4d6c1e61`
- **Evidence**: `// The design names FERNET/MultiFernet. AiNxt deliberately diverges to XChaCha20-Poly1305 over`

**Why this matters.** Cryptographic functionality can bring a distribution within the scope of export-control regimes.  Whether an exemption or notification applies is a legal determination about the specific distribution, not something a scanner can decide.

**What to do.** Inventory the cryptographic capabilities of the release and refer them for export-control review.  Many open-source distributions qualify for published-source exemptions, but that conclusion must come from counsel.

### [INFO] Cryptographic implementation or key management in source

- **Rule**: `LEGAL.CRYPTO_IMPLEMENTATION`
- **Where**: `crates/ainxt-token/src/lib.rs:1901`
- **Classification**: CRYPTO_IMPLEMENTATION
- **Legal review required**: yes
- **Finding id**: `864cfa493c4eeb49`
- **Evidence**: `// The design names FERNET/MultiFernet. AiNxt ships XChaCha20-Poly1305 over a versioned KeyRing`

**Why this matters.** Cryptographic functionality can bring a distribution within the scope of export-control regimes.  Whether an exemption or notification applies is a legal determination about the specific distribution, not something a scanner can decide.

**What to do.** Inventory the cryptographic capabilities of the release and refer them for export-control review.  Many open-source distributions qualify for published-source exemptions, but that conclusion must come from counsel.

### [INFO] Cryptography or TLS library dependency

- **Rule**: `LEGAL.CRYPTO_LIBRARY_DEPENDENCY`
- **Where**: `Cargo.lock:1561`
- **Classification**: CRYPTO_DEPENDENCY
- **Legal review required**: yes
- **Finding id**: `9efc7249696a93ce`
- **Evidence**: `name = "hyper-rustls"`

**Why this matters.** Recorded so the export-control review has a complete list of cryptographic dependencies.  Informational: depending on a TLS library is normal and not a defect.

**What to do.** Include in the cryptography inventory supplied to legal review.

### [INFO] Cryptography or TLS library dependency

- **Rule**: `LEGAL.CRYPTO_LIBRARY_DEPENDENCY`
- **Where**: `Cargo.lock:2165`
- **Classification**: CRYPTO_DEPENDENCY
- **Legal review required**: yes
- **Finding id**: `69cf7fcd133f2501`
- **Evidence**: `name = "ring"`

**Why this matters.** Recorded so the export-control review has a complete list of cryptographic dependencies.  Informational: depending on a TLS library is normal and not a defect.

**What to do.** Include in the cryptography inventory supplied to legal review.

### [INFO] Cryptography or TLS library dependency

- **Rule**: `LEGAL.CRYPTO_LIBRARY_DEPENDENCY`
- **Where**: `Cargo.lock:2204`
- **Classification**: CRYPTO_DEPENDENCY
- **Legal review required**: yes
- **Finding id**: `95f9115283f2a3ad`
- **Evidence**: `name = "rustls"`

**Why this matters.** Recorded so the export-control review has a complete list of cryptographic dependencies.  Informational: depending on a TLS library is normal and not a defect.

**What to do.** Include in the cryptography inventory supplied to legal review.

### [INFO] Cryptography or TLS library dependency

- **Rule**: `LEGAL.CRYPTO_LIBRARY_DEPENDENCY`
- **Where**: `Cargo.lock:2218`
- **Classification**: CRYPTO_DEPENDENCY
- **Legal review required**: yes
- **Finding id**: `5e768ebf8b2bce2c`
- **Evidence**: `name = "rustls-pki-types"`

**Why this matters.** Recorded so the export-control review has a complete list of cryptographic dependencies.  Informational: depending on a TLS library is normal and not a defect.

**What to do.** Include in the cryptography inventory supplied to legal review.

### [INFO] Cryptography or TLS library dependency

- **Rule**: `LEGAL.CRYPTO_LIBRARY_DEPENDENCY`
- **Where**: `Cargo.lock:2228`
- **Classification**: CRYPTO_DEPENDENCY
- **Legal review required**: yes
- **Finding id**: `22ddffc631945d4b`
- **Evidence**: `name = "rustls-webpki"`

**Why this matters.** Recorded so the export-control review has a complete list of cryptographic dependencies.  Informational: depending on a TLS library is normal and not a defect.

**What to do.** Include in the cryptography inventory supplied to legal review.

### [INFO] Cryptography or TLS library dependency

- **Rule**: `LEGAL.CRYPTO_LIBRARY_DEPENDENCY`
- **Where**: `Cargo.lock:2567`
- **Classification**: CRYPTO_DEPENDENCY
- **Legal review required**: yes
- **Finding id**: `605409633dc29486`
- **Evidence**: `name = "tokio-rustls"`

**Why this matters.** Recorded so the export-control review has a complete list of cryptographic dependencies.  Informational: depending on a TLS library is normal and not a defect.

**What to do.** Include in the cryptography inventory supplied to legal review.

### [INFO] Cryptography or TLS library dependency

- **Rule**: `LEGAL.CRYPTO_LIBRARY_DEPENDENCY`
- **Where**: `THIRD_PARTY_INVENTORY.yaml:260`
- **Classification**: CRYPTO_DEPENDENCY
- **Legal review required**: yes
- **Finding id**: `ee690780d12eb4ad`
- **Evidence**: `- name: hyper-rustls`

**Why this matters.** Recorded so the export-control review has a complete list of cryptographic dependencies.  Informational: depending on a TLS library is normal and not a defect.

**What to do.** Include in the cryptography inventory supplied to legal review.

### [INFO] Cryptography or TLS library dependency

- **Rule**: `LEGAL.CRYPTO_LIBRARY_DEPENDENCY`
- **Where**: `THIRD_PARTY_INVENTORY.yaml:263`
- **Classification**: CRYPTO_DEPENDENCY
- **Legal review required**: yes
- **Finding id**: `f937d409f6238285`
- **Evidence**: `repo: https://crates.io/crates/hyper-rustls`

**Why this matters.** Recorded so the export-control review has a complete list of cryptographic dependencies.  Informational: depending on a TLS library is normal and not a defect.

**What to do.** Include in the cryptography inventory supplied to legal review.

### [INFO] Cryptography or TLS library dependency

- **Rule**: `LEGAL.CRYPTO_LIBRARY_DEPENDENCY`
- **Where**: `THIRD_PARTY_INVENTORY.yaml:507`
- **Classification**: CRYPTO_DEPENDENCY
- **Legal review required**: yes
- **Finding id**: `468b1db20e3e0ce5`
- **Evidence**: `- name: ring`

**Why this matters.** Recorded so the export-control review has a complete list of cryptographic dependencies.  Informational: depending on a TLS library is normal and not a defect.

**What to do.** Include in the cryptography inventory supplied to legal review.

### [INFO] Cryptography or TLS library dependency

- **Rule**: `LEGAL.CRYPTO_LIBRARY_DEPENDENCY`
- **Where**: `THIRD_PARTY_INVENTORY.yaml:510`
- **Classification**: CRYPTO_DEPENDENCY
- **Legal review required**: yes
- **Finding id**: `66838ceac1536eff`
- **Evidence**: `repo: https://crates.io/crates/ring`

**Why this matters.** Recorded so the export-control review has a complete list of cryptographic dependencies.  Informational: depending on a TLS library is normal and not a defect.

**What to do.** Include in the cryptography inventory supplied to legal review.

### [INFO] Cryptography or TLS library dependency

- **Rule**: `LEGAL.CRYPTO_LIBRARY_DEPENDENCY`
- **Where**: `THIRD_PARTY_INVENTORY.yaml:519`
- **Classification**: CRYPTO_DEPENDENCY
- **Legal review required**: yes
- **Finding id**: `b64235e7155bd89c`
- **Evidence**: `- name: rustls`

**Why this matters.** Recorded so the export-control review has a complete list of cryptographic dependencies.  Informational: depending on a TLS library is normal and not a defect.

**What to do.** Include in the cryptography inventory supplied to legal review.

### [INFO] Cryptography or TLS library dependency

- **Rule**: `LEGAL.CRYPTO_LIBRARY_DEPENDENCY`
- **Where**: `THIRD_PARTY_INVENTORY.yaml:522`
- **Classification**: CRYPTO_DEPENDENCY
- **Legal review required**: yes
- **Finding id**: `16da22329d080210`
- **Evidence**: `repo: https://crates.io/crates/rustls`

**Why this matters.** Recorded so the export-control review has a complete list of cryptographic dependencies.  Informational: depending on a TLS library is normal and not a defect.

**What to do.** Include in the cryptography inventory supplied to legal review.

### [INFO] Cryptography or TLS library dependency

- **Rule**: `LEGAL.CRYPTO_LIBRARY_DEPENDENCY`
- **Where**: `THIRD_PARTY_INVENTORY.yaml:525`
- **Classification**: CRYPTO_DEPENDENCY
- **Legal review required**: yes
- **Finding id**: `ff6f07c6bea1cf6a`
- **Evidence**: `- name: rustls-pki-types`

**Why this matters.** Recorded so the export-control review has a complete list of cryptographic dependencies.  Informational: depending on a TLS library is normal and not a defect.

**What to do.** Include in the cryptography inventory supplied to legal review.

### [INFO] Cryptography or TLS library dependency

- **Rule**: `LEGAL.CRYPTO_LIBRARY_DEPENDENCY`
- **Where**: `THIRD_PARTY_INVENTORY.yaml:528`
- **Classification**: CRYPTO_DEPENDENCY
- **Legal review required**: yes
- **Finding id**: `99d0de9641ee68d9`
- **Evidence**: `repo: https://crates.io/crates/rustls-pki-types`

**Why this matters.** Recorded so the export-control review has a complete list of cryptographic dependencies.  Informational: depending on a TLS library is normal and not a defect.

**What to do.** Include in the cryptography inventory supplied to legal review.

### [INFO] Cryptography or TLS library dependency

- **Rule**: `LEGAL.CRYPTO_LIBRARY_DEPENDENCY`
- **Where**: `THIRD_PARTY_INVENTORY.yaml:531`
- **Classification**: CRYPTO_DEPENDENCY
- **Legal review required**: yes
- **Finding id**: `238727c34a049161`
- **Evidence**: `- name: rustls-webpki`

**Why this matters.** Recorded so the export-control review has a complete list of cryptographic dependencies.  Informational: depending on a TLS library is normal and not a defect.

**What to do.** Include in the cryptography inventory supplied to legal review.

### [INFO] Cryptography or TLS library dependency

- **Rule**: `LEGAL.CRYPTO_LIBRARY_DEPENDENCY`
- **Where**: `THIRD_PARTY_INVENTORY.yaml:534`
- **Classification**: CRYPTO_DEPENDENCY
- **Legal review required**: yes
- **Finding id**: `1bda5755c3aceafa`
- **Evidence**: `repo: https://crates.io/crates/rustls-webpki`

**Why this matters.** Recorded so the export-control review has a complete list of cryptographic dependencies.  Informational: depending on a TLS library is normal and not a defect.

**What to do.** Include in the cryptography inventory supplied to legal review.

### [INFO] Cryptography or TLS library dependency

- **Rule**: `LEGAL.CRYPTO_LIBRARY_DEPENDENCY`
- **Where**: `THIRD_PARTY_INVENTORY.yaml:694`
- **Classification**: CRYPTO_DEPENDENCY
- **Legal review required**: yes
- **Finding id**: `f69e110f8541d1ef`
- **Evidence**: `- name: tokio-rustls`

**Why this matters.** Recorded so the export-control review has a complete list of cryptographic dependencies.  Informational: depending on a TLS library is normal and not a defect.

**What to do.** Include in the cryptography inventory supplied to legal review.

### [INFO] Cryptography or TLS library dependency

- **Rule**: `LEGAL.CRYPTO_LIBRARY_DEPENDENCY`
- **Where**: `THIRD_PARTY_INVENTORY.yaml:697`
- **Classification**: CRYPTO_DEPENDENCY
- **Legal review required**: yes
- **Finding id**: `f52d53a34f75fd23`
- **Evidence**: `repo: https://crates.io/crates/tokio-rustls`

**Why this matters.** Recorded so the export-control review has a complete list of cryptographic dependencies.  Informational: depending on a TLS library is normal and not a defect.

**What to do.** Include in the cryptography inventory supplied to legal review.

### [INFO] Cryptography or TLS library dependency

- **Rule**: `LEGAL.CRYPTO_LIBRARY_DEPENDENCY`
- **Where**: `crates/ainxt-connector-http/Cargo.toml:13`
- **Classification**: CRYPTO_DEPENDENCY
- **Legal review required**: yes
- **Finding id**: `7cc8d2e4677d5167`
- **Evidence**: `# The real HTTP transport (reqwest + rustls, honoring the air-gap forward proxy). OFF by default so`

**Why this matters.** Recorded so the export-control review has a complete list of cryptographic dependencies.  Informational: depending on a TLS library is normal and not a defect.

**What to do.** Include in the cryptography inventory supplied to legal review.

### [INFO] Cryptography or TLS library dependency

- **Rule**: `LEGAL.CRYPTO_LIBRARY_DEPENDENCY`
- **Where**: `crates/ainxt-connector-http/Cargo.toml:37`
- **Classification**: CRYPTO_DEPENDENCY
- **Legal review required**: yes
- **Finding id**: `febfb272aaf3b232`
- **Evidence**: `# Real transport (optional). rustls-tls (no OpenSSL); already cleared by the deny license gate.`

**Why this matters.** Recorded so the export-control review has a complete list of cryptographic dependencies.  Informational: depending on a TLS library is normal and not a defect.

**What to do.** Include in the cryptography inventory supplied to legal review.

### [INFO] Cryptography or TLS library dependency

- **Rule**: `LEGAL.CRYPTO_LIBRARY_DEPENDENCY`
- **Where**: `crates/ainxt-connector-http/Cargo.toml:38`
- **Classification**: CRYPTO_DEPENDENCY
- **Legal review required**: yes
- **Finding id**: `430d7b02262b12ec`
- **Evidence**: `reqwest = { version = "0.12", default-features = false, features = ["blocking", "rustls-tls"], optional = true }`

**Why this matters.** Recorded so the export-control review has a complete list of cryptographic dependencies.  Informational: depending on a TLS library is normal and not a defect.

**What to do.** Include in the cryptography inventory supplied to legal review.

### [INFO] Cryptography or TLS library dependency

- **Rule**: `LEGAL.CRYPTO_LIBRARY_DEPENDENCY`
- **Where**: `crates/ainxt-connector-http/src/lib.rs:1615`
- **Classification**: CRYPTO_DEPENDENCY
- **Legal review required**: yes
- **Finding id**: `fb564b186377e2de`
- **Evidence**: `/// Production HTTP transport: reqwest (blocking) + rustls, honoring the air-gap forward proxy.`

**Why this matters.** Recorded so the export-control review has a complete list of cryptographic dependencies.  Informational: depending on a TLS library is normal and not a defect.

**What to do.** Include in the cryptography inventory supplied to legal review.

### [INFO] Cryptography or TLS library dependency

- **Rule**: `LEGAL.CRYPTO_LIBRARY_DEPENDENCY`
- **Where**: `crates/ainxt-providers/Cargo.toml:18`
- **Classification**: CRYPTO_DEPENDENCY
- **Legal review required**: yes
- **Finding id**: `d3c78b60a99e6b43`
- **Evidence**: `reqwest = { version = "0.12", default-features = false, features = ["rustls-tls", "stream", "json"] }`

**Why this matters.** Recorded so the export-control review has a complete list of cryptographic dependencies.  Informational: depending on a TLS library is normal and not a defect.

**What to do.** Include in the cryptography inventory supplied to legal review.

### [INFO] Cryptography or TLS library dependency

- **Rule**: `LEGAL.CRYPTO_LIBRARY_DEPENDENCY`
- **Where**: `crates/ainxt-runtimed/Cargo.toml:170`
- **Classification**: CRYPTO_DEPENDENCY
- **Legal review required**: yes
- **Finding id**: `72603a3d62102c1d`
- **Evidence**: `reqwest = { version = "0.12", default-features = false, features = ["rustls-tls"] }`

**Why this matters.** Recorded so the export-control review has a complete list of cryptographic dependencies.  Informational: depending on a TLS library is normal and not a defect.

**What to do.** Include in the cryptography inventory supplied to legal review.

### [INFO] Cryptography or TLS library dependency

- **Rule**: `LEGAL.CRYPTO_LIBRARY_DEPENDENCY`
- **Where**: `crates/ainxt-server/Cargo.toml:119`
- **Classification**: CRYPTO_DEPENDENCY
- **Legal review required**: yes
- **Finding id**: `afb664e922b76a1c`
- **Evidence**: `reqwest = { version = "0.12", default-features = false, features = ["rustls-tls", "stream", "json"] }`

**Why this matters.** Recorded so the export-control review has a complete list of cryptographic dependencies.  Informational: depending on a TLS library is normal and not a defect.

**What to do.** Include in the cryptography inventory supplied to legal review.

### [INFO] Cryptography or TLS library dependency

- **Rule**: `LEGAL.CRYPTO_LIBRARY_DEPENDENCY`
- **Where**: `crates/ainxt-token/Cargo.toml:26`
- **Classification**: CRYPTO_DEPENDENCY
- **Legal review required**: yes
- **Finding id**: `42a14c43e1231efc`
- **Evidence**: `# RustCrypto — dual MIT/Apache-2.0, pure Rust (no OpenSSL). Default features give alloc + OsRng`

**Why this matters.** Recorded so the export-control review has a complete list of cryptographic dependencies.  Informational: depending on a TLS library is normal and not a defect.

**What to do.** Include in the cryptography inventory supplied to legal review.

### [INFO] Cryptography or TLS library dependency

- **Rule**: `LEGAL.CRYPTO_LIBRARY_DEPENDENCY`
- **Where**: `crates/ainxt-token/src/lib.rs:1561`
- **Classification**: CRYPTO_DEPENDENCY
- **Legal review required**: yes
- **Finding id**: `c2d521e940eabdc5`
- **Evidence**: `// a versioned KeyRing (clean-room Rust, no OpenSSL). This test pins that the *invariant*`

**Why this matters.** Recorded so the export-control review has a complete list of cryptographic dependencies.  Informational: depending on a TLS library is normal and not a defect.

**What to do.** Include in the cryptography inventory supplied to legal review.

### [INFO] Cryptography or TLS library dependency

- **Rule**: `LEGAL.CRYPTO_LIBRARY_DEPENDENCY`
- **Where**: `crates/ainxt-token/src/lib.rs:1902`
- **Classification**: CRYPTO_DEPENDENCY
- **Legal review required**: yes
- **Finding id**: `97ad18a4e402d856`
- **Evidence**: `// (clean-room Rust, no OpenSSL). This test pins that the DEFAULT vault codec — the one the`

**Why this matters.** Recorded so the export-control review has a complete list of cryptographic dependencies.  Informational: depending on a TLS library is normal and not a defect.

**What to do.** Include in the cryptography inventory supplied to legal review.

### [INFO] Cryptography or TLS library dependency

- **Rule**: `LEGAL.CRYPTO_LIBRARY_DEPENDENCY`
- **Where**: `deny.toml:63`
- **Classification**: CRYPTO_DEPENDENCY
- **Legal review required**: yes
- **Finding id**: `6d773e1a6ed4d7da`
- **Evidence**: `# { name = "openssl-src" },   # example: prefer rustls; add real bans as the tree grows`

**Why this matters.** Recorded so the export-control review has a complete list of cryptographic dependencies.  Informational: depending on a TLS library is normal and not a defect.

**What to do.** Include in the cryptography inventory supplied to legal review.

### [INFO] Provider-specific credential variable referenced in business logic

- **Rule**: `MODEL.PROVIDER_CREDENTIAL_ENV`
- **Where**: `crates/ainxt-runtimed/src/lib.rs:11190`
- **Classification**: BUSINESS_LOGIC_COUPLING
- **Finding id**: `ff2240c42c6b69e4`
- **Evidence**: `let saved = std::env::var("GOOGLE_API_KEY").ok();`

**Why this matters.** Reading a named vendor credential outside its adapter means every deployment must supply that specific vendor's key, whichever provider it actually uses.

**What to do.** Have the adapter resolve its own credential from a provider-scoped setting, so the core requires only "a configured provider".

### [INFO] Provider-specific credential variable referenced in business logic

- **Rule**: `MODEL.PROVIDER_CREDENTIAL_ENV`
- **Where**: `crates/ainxt-runtimed/src/lib.rs:11192`
- **Classification**: BUSINESS_LOGIC_COUPLING
- **Finding id**: `4deb41f7f991f544`
- **Evidence**: `std::env::remove_var("GOOGLE_API_KEY");`

**Why this matters.** Reading a named vendor credential outside its adapter means every deployment must supply that specific vendor's key, whichever provider it actually uses.

**What to do.** Have the adapter resolve its own credential from a provider-scoped setting, so the core requires only "a configured provider".

### [INFO] Provider-specific credential variable referenced in business logic

- **Rule**: `MODEL.PROVIDER_CREDENTIAL_ENV`
- **Where**: `crates/ainxt-runtimed/src/lib.rs:11198`
- **Classification**: BUSINESS_LOGIC_COUPLING
- **Finding id**: `c938ca2d6913fd72`
- **Evidence**: `"gemini provider must be skipped (no-op) with no GOOGLE_API_KEY, byte-identical to \`

**Why this matters.** Reading a named vendor credential outside its adapter means every deployment must supply that specific vendor's key, whichever provider it actually uses.

**What to do.** Have the adapter resolve its own credential from a provider-scoped setting, so the core requires only "a configured provider".

### [INFO] Provider-specific credential variable referenced in business logic

- **Rule**: `MODEL.PROVIDER_CREDENTIAL_ENV`
- **Where**: `crates/ainxt-runtimed/src/lib.rs:11208`
- **Classification**: BUSINESS_LOGIC_COUPLING
- **Finding id**: `cf5a1122147062b1`
- **Evidence**: `std::env::set_var("GOOGLE_API_KEY", "test-key-not-real");`

**Why this matters.** Reading a named vendor credential outside its adapter means every deployment must supply that specific vendor's key, whichever provider it actually uses.

**What to do.** Have the adapter resolve its own credential from a provider-scoped setting, so the core requires only "a configured provider".

### [INFO] Provider-specific credential variable referenced in business logic

- **Rule**: `MODEL.PROVIDER_CREDENTIAL_ENV`
- **Where**: `crates/ainxt-runtimed/src/lib.rs:11214`
- **Classification**: BUSINESS_LOGIC_COUPLING
- **Finding id**: `909d96eccaa9a802`
- **Evidence**: `"gemini provider must be wired into the real router when GOOGLE_API_KEY is present: \`

**Why this matters.** Reading a named vendor credential outside its adapter means every deployment must supply that specific vendor's key, whichever provider it actually uses.

**What to do.** Have the adapter resolve its own credential from a provider-scoped setting, so the core requires only "a configured provider".

### [INFO] Provider-specific credential variable referenced in business logic

- **Rule**: `MODEL.PROVIDER_CREDENTIAL_ENV`
- **Where**: `crates/ainxt-runtimed/src/lib.rs:11219`
- **Classification**: BUSINESS_LOGIC_COUPLING
- **Finding id**: `006fe8b4f91d144a`
- **Evidence**: `Some(v) => std::env::set_var("GOOGLE_API_KEY", v),`

**Why this matters.** Reading a named vendor credential outside its adapter means every deployment must supply that specific vendor's key, whichever provider it actually uses.

**What to do.** Have the adapter resolve its own credential from a provider-scoped setting, so the core requires only "a configured provider".

### [INFO] Provider-specific credential variable referenced in business logic

- **Rule**: `MODEL.PROVIDER_CREDENTIAL_ENV`
- **Where**: `crates/ainxt-runtimed/src/lib.rs:11220`
- **Classification**: BUSINESS_LOGIC_COUPLING
- **Finding id**: `21284293f2a660a7`
- **Evidence**: `None => std::env::remove_var("GOOGLE_API_KEY"),`

**Why this matters.** Reading a named vendor credential outside its adapter means every deployment must supply that specific vendor's key, whichever provider it actually uses.

**What to do.** Have the adapter resolve its own credential from a provider-scoped setting, so the core requires only "a configured provider".

## What this module could NOT verify

- These rules hit their configured max_findings cap and stopped reporting, so their true count is higher than shown: PROVENANCE.UPSTREAM_REPOSITORY_REFERENCE
- Content rules are regular expressions over single lines.  A value split across lines, assembled at runtime, base64-encoded or otherwise obfuscated will not match.  Absence of a finding is not proof of absence.

## Coverage

| Capability | State | Detail |
|---|---|---|
| `branding_detection` | COVERED | 10 rule(s) from policy/patterns/branding.yaml applied to 849 files |
| `portability_coupling_detection` | COVERED | 1 rule(s) from policy/patterns/coupling.yaml applied to 849 files |
| `configuration_review` | COVERED | 7 rule(s) from policy/patterns/endpoints.yaml applied to 849 files |
| `internal_data_detection` | COVERED | 9 rule(s) from policy/patterns/internal_data.yaml applied to 849 files |
| `legal_marker_detection` | COVERED | 6 rule(s) from policy/patterns/legal_markers.yaml applied to 849 files |
| `model_hardcoding_detection` | COVERED | 7 rule(s) from policy/patterns/models.yaml applied to 849 files |
| `provenance_review` | COVERED | 7 rule(s) from policy/patterns/provenance_markers.yaml applied to 849 files |
| `secret_detection` | COVERED | 15 rule(s) from policy/patterns/secrets.yaml applied to 849 files |

## Notes

- rule COUPLING.OPTIONAL_SERVICE_HARDCODED not applied: inert: coupling.optional_capability_services is empty in configuration
- rule MODEL.RETIRED_IDENTIFIER_REFERENCE not applied: inert: models.blocked_model_identifiers is empty in configuration
