# Third-Party Licenses — AiNxt OS

**Project:** AiNxt OS  
**Copyright:** Copyright 2026 National Payments Corporation of India  
**Project License:** MIT  
**Last reviewed:** 2026-09-02 (see note below — this count was not re-derived from a fresh
`cargo metadata` run on that date)  

Machine-generated from `cargo metadata --all-features` (2026-07-19). Enforced by `deny.toml`
(the cargo-deny license gate) in CI: any non-permissive or unknown license fails the build.

**2026-09-05 remediation note:** an OSS-release audit (`final_audit_response_os.md` F-08/F-34)
found this file's "170 external crates" count covered only about half of what the committed
Cargo.lock actually resolves (323 unique external crate names / 417 total packages). The
machine-readable `THIRD_PARTY_INVENTORY.yaml` has been regenerated to list all 323; this
narrative document has not yet had the same full-graph regeneration applied (a straight data dump
is mechanical, but this file's per-license narrative/legal-flag prose is not, and should not be
bulk-generated without review). Treat `THIRD_PARTY_INVENTORY.yaml` as the current source of truth
for the complete crate list until this file is regenerated to match.

Total external crates: 170 (see 2026-09-05 note above — incomplete; `THIRD_PARTY_INVENTORY.yaml`
now lists the full 323)  
License spread: (MIT OR Apache-2.0) AND Unicode-3.0=1; Apache-2.0=1; Apache-2.0 AND ISC=1;
Apache-2.0 OR BSL-1.0=1; Apache-2.0 OR ISC OR MIT=2; Apache-2.0 OR MIT=12;
Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT=1; BSD-3-Clause=1; CDLA-Permissive-2.0=1;
ISC=2; MIT=26; MIT AND BSD-3-Clause=1; MIT OR Apache-2.0=95; MIT OR Apache-2.0 OR LGPL-2.1-or-later=1;
MIT OR Apache-2.0 OR Zlib=2; MIT/Apache-2.0=2; Unicode-3.0=18; Unlicense OR MIT=1; Zlib OR Apache-2.0 OR MIT=1

---

## Legal Flags

| # | Issue | Severity | Status |
|---|---|---|---|
| LIC-001 | **CDLA-Permissive-2.0** — `webpki-roots`. Non-standard permissive license; no copyleft. Confirm with counsel. | 🟢 LOW | Documented |
| LIC-002 | **Apache-2.0 AND ISC** — `ring`. Incorporates BoringSSL (ISC) and OpenSSL-derived code. NOTICE preservation required. | 🟡 REVIEW | Documented in THIRD_PARTY_NOTICES.md |
| LIC-003 | **BSD-3-Clause** — `subtle`. Constant-time crypto utility. Standard permissive. | 🟢 LOW | Documented |
| LIC-004 | **MIT OR Apache-2.0 OR LGPL-2.1-or-later** — `r-efi`. MIT/Apache-2.0 elected (deny.toml). | 🟢 LOW | Documented |
| LIC-005 | **Unicode-3.0** — 18 ICU crates. Permissive; retain Unicode copyright notice. | 🟢 LOW | Documented |

---

## Dependency Table (Legal Team Format)

| Dependency | Version | License | Source |
|---|---|---|---|
| aead | 0.5.2 | MIT OR Apache-2.0 | https://github.com/RustCrypto/traits |
| async-trait | 0.1.89 | MIT OR Apache-2.0 | https://github.com/dtolnay/async-trait |
| atomic-waker | 1.1.2 | Apache-2.0 OR MIT | https://github.com/tokio-rs/atomic-waker |
| axum | 0.7.9 | MIT | https://github.com/tokio-rs/axum |
| axum-core | 0.4.5 | MIT | https://github.com/tokio-rs/axum |
| base64 | 0.22.1 | MIT OR Apache-2.0 | https://github.com/marshallpierce/rust-base64 |
| bitflags | 2.13.1 | MIT OR Apache-2.0 | https://github.com/bitflags/bitflags |
| block-buffer | 0.10.4 | MIT OR Apache-2.0 | https://github.com/RustCrypto/utils |
| bumpalo | 3.20.3 | MIT OR Apache-2.0 | https://github.com/fitzgen/bumpalo |
| bytes | 1.12.1 | MIT | https://github.com/tokio-rs/bytes |
| cc | 1.3.0 | MIT OR Apache-2.0 | https://github.com/rust-lang/cc-rs |
| cfg-if | 1.0.4 | MIT OR Apache-2.0 | https://github.com/alexcrichton/cfg-if |
| cfg_aliases | 0.2.2 | MIT | https://github.com/katharostech/cfg_aliases |
| chacha20 | 0.10.1 / 0.9.1 | MIT OR Apache-2.0 | https://github.com/RustCrypto/stream-ciphers |
| chacha20poly1305 | 0.10.1 | Apache-2.0 OR MIT | https://github.com/RustCrypto/AEADs |
| cipher | 0.4.4 | MIT OR Apache-2.0 | https://github.com/RustCrypto/traits |
| cpufeatures | 0.2.17 / 0.3.0 | MIT OR Apache-2.0 | https://github.com/RustCrypto/utils |
| crypto-common | 0.1.7 | MIT OR Apache-2.0 | https://github.com/RustCrypto/traits |
| digest | 0.10.7 | MIT OR Apache-2.0 | https://github.com/RustCrypto/traits |
| displaydoc | 0.2.6 | MIT OR Apache-2.0 | https://github.com/yaahc/displaydoc |
| equivalent | 1.0.2 | Apache-2.0 OR MIT | https://github.com/indexmap-rs/equivalent |
| find-msvc-tools | 0.1.9 | MIT OR Apache-2.0 | https://github.com/nicowillis/find-msvc-tools |
| form_urlencoded | 1.2.2 | MIT OR Apache-2.0 | https://github.com/servo/rust-url |
| futures-channel | 0.3.33 | MIT OR Apache-2.0 | https://github.com/rust-lang/futures-rs |
| futures-core | 0.3.33 | MIT OR Apache-2.0 | https://github.com/rust-lang/futures-rs |
| futures-io | 0.3.33 | MIT OR Apache-2.0 | https://github.com/rust-lang/futures-rs |
| futures-macro | 0.3.33 | MIT OR Apache-2.0 | https://github.com/rust-lang/futures-rs |
| futures-sink | 0.3.33 | MIT OR Apache-2.0 | https://github.com/rust-lang/futures-rs |
| futures-task | 0.3.33 | MIT OR Apache-2.0 | https://github.com/rust-lang/futures-rs |
| futures-util | 0.3.33 | MIT OR Apache-2.0 | https://github.com/rust-lang/futures-rs |
| generic-array | 0.14.7 | MIT | https://github.com/fizyk20/generic-array |
| getrandom | 0.2.17 / 0.4.3 | MIT OR Apache-2.0 | https://github.com/rust-random/getrandom |
| hashbrown | 0.17.1 | MIT OR Apache-2.0 | https://github.com/rust-lang/hashbrown |
| http | 1.4.2 | MIT OR Apache-2.0 | https://github.com/hyperium/http |
| http-body | 1.1.0 | MIT | https://github.com/hyperium/http-body |
| http-body-util | 0.1.4 | MIT | https://github.com/hyperium/http-body |
| httparse | 1.10.1 | MIT OR Apache-2.0 | https://github.com/seanmonstar/httparse |
| httpdate | 1.0.3 | MIT OR Apache-2.0 | https://github.com/pyfisch/httpdate |
| hyper | 1.10.1 | MIT | https://github.com/hyperium/hyper |
| hyper-rustls | 0.27.9 | Apache-2.0 OR ISC OR MIT | https://github.com/rustls/hyper-rustls |
| hyper-util | 0.1.20 | MIT | https://github.com/hyperium/hyper |
| icu_collections | 2.2.0 | Unicode-3.0 | https://github.com/unicode-org/icu4x |
| icu_locale_core | 2.2.0 | Unicode-3.0 | https://github.com/unicode-org/icu4x |
| icu_normalizer | 2.2.0 | Unicode-3.0 | https://github.com/unicode-org/icu4x |
| icu_normalizer_data | 2.2.0 | Unicode-3.0 | https://github.com/unicode-org/icu4x |
| icu_properties | 2.2.0 | Unicode-3.0 | https://github.com/unicode-org/icu4x |
| icu_properties_data | 2.2.0 | Unicode-3.0 | https://github.com/unicode-org/icu4x |
| icu_provider | 2.2.0 | Unicode-3.0 | https://github.com/unicode-org/icu4x |
| idna | 1.1.0 | MIT OR Apache-2.0 | https://github.com/servo/rust-url |
| idna_adapter | 1.2.2 | Apache-2.0 OR MIT | https://github.com/hsivonen/idna_adapter |
| indexmap | 2.14.0 | Apache-2.0 OR MIT | https://github.com/indexmap-rs/indexmap |
| inout | 0.1.4 | MIT OR Apache-2.0 | https://github.com/RustCrypto/utils |
| ipnet | 2.12.0 | MIT OR Apache-2.0 | https://github.com/krisprice/ipnet |
| itoa | 1.0.18 | MIT OR Apache-2.0 | https://github.com/dtolnay/itoa |
| js-sys | 0.3.103 | MIT OR Apache-2.0 | https://github.com/rustwasm/wasm-bindgen |
| libc | 0.2.186 | MIT OR Apache-2.0 | https://github.com/rust-lang/libc |
| litemap | 0.8.2 | Unicode-3.0 | https://github.com/unicode-org/icu4x |
| log | 0.4.33 | MIT OR Apache-2.0 | https://github.com/rust-lang/log |
| lru-slab | 0.1.2 | MIT OR Apache-2.0 OR Zlib | https://github.com/nicowillis/lru-slab |
| matchit | 0.7.3 | MIT AND BSD-3-Clause | https://github.com/ibraheemdev/matchit |
| memchr | 2.8.3 | Unlicense OR MIT | https://github.com/BurntSushi/memchr |
| mime | 0.3.17 | MIT OR Apache-2.0 | https://github.com/hyperium/mime |
| mio | 1.2.2 | MIT | https://github.com/tokio-rs/mio |
| once_cell | 1.21.4 | MIT OR Apache-2.0 | https://github.com/matklad/once_cell |
| opaque-debug | 0.3.1 | MIT OR Apache-2.0 | https://github.com/RustCrypto/utils |
| percent-encoding | 2.3.2 | MIT OR Apache-2.0 | https://github.com/servo/rust-url |
| pin-project-lite | 0.2.17 | Apache-2.0 OR MIT | https://github.com/taiki-e/pin-project-lite |
| poly1305 | 0.8.0 | Apache-2.0 OR MIT | https://github.com/RustCrypto/MACs |
| potential_utf | 0.1.5 | Unicode-3.0 | https://github.com/unicode-org/icu4x |
| proc-macro2 | 1.0.106 | MIT OR Apache-2.0 | https://github.com/dtolnay/proc-macro2 |
| quinn | 0.11.11 | MIT OR Apache-2.0 | https://github.com/quinn-rs/quinn |
| quinn-proto | 0.11.16 | MIT OR Apache-2.0 | https://github.com/quinn-rs/quinn |
| quinn-udp | 0.5.15 | MIT OR Apache-2.0 | https://github.com/quinn-rs/quinn |
| quote | 1.0.46 | MIT OR Apache-2.0 | https://github.com/dtolnay/quote |
| r-efi | 6.0.0 | MIT OR Apache-2.0 OR LGPL-2.1-or-later | https://github.com/r-efi/r-efi |
| rand | 0.10.2 | MIT OR Apache-2.0 | https://github.com/rust-random/rand |
| rand_core | 0.10.1 / 0.6.4 | MIT OR Apache-2.0 | https://github.com/rust-random/rand |
| rand_pcg | 0.10.2 | MIT OR Apache-2.0 | https://github.com/rust-random/rngs |
| reqwest | 0.12.28 | MIT OR Apache-2.0 | https://github.com/seanmonstar/reqwest |
| ring | 0.17.14 | Apache-2.0 AND ISC | https://github.com/briansmith/ring |
| rustc-hash | 2.1.3 | Apache-2.0 OR MIT | https://github.com/rust-lang/rustc-hash |
| rustls | 0.23.42 | Apache-2.0 OR ISC OR MIT | https://github.com/rustls/rustls |
| rustls-pki-types | 1.15.0 | MIT OR Apache-2.0 | https://github.com/rustls/pki-types |
| rustls-webpki | 0.103.13 | ISC | https://github.com/rustls/webpki |
| rustversion | 1.0.23 | MIT OR Apache-2.0 | https://github.com/dtolnay/rustversion |
| ryu | 1.0.23 | Apache-2.0 OR BSL-1.0 | https://github.com/dtolnay/ryu |
| serde | 1.0.228 | MIT OR Apache-2.0 | https://github.com/serde-rs/serde |
| serde_core | 1.0.228 | MIT OR Apache-2.0 | https://github.com/serde-rs/serde |
| serde_derive | 1.0.228 | MIT OR Apache-2.0 | https://github.com/serde-rs/serde |
| serde_json | 1.0.150 | MIT OR Apache-2.0 | https://github.com/serde-rs/json |
| serde_path_to_error | 0.1.20 | MIT OR Apache-2.0 | https://github.com/dtolnay/serde-path-to-error |
| serde_spanned | 0.6.9 | MIT OR Apache-2.0 | https://github.com/toml-rs/toml |
| serde_urlencoded | 0.7.1 | MIT OR Apache-2.0 | https://github.com/nox/serde_urlencoded |
| sha2 | 0.10.9 | MIT OR Apache-2.0 | https://github.com/RustCrypto/hashes |
| shlex | 2.0.1 | MIT OR Apache-2.0 | https://github.com/comex/rust-shlex |
| slab | 0.4.12 | MIT | https://github.com/tokio-rs/slab |
| smallvec | 1.15.2 | MIT OR Apache-2.0 | https://github.com/servo/rust-smallvec |
| socket2 | 0.6.5 | MIT OR Apache-2.0 | https://github.com/rust-lang/socket2 |
| stable_deref_trait | 1.2.1 | MIT OR Apache-2.0 | https://github.com/storyyeller/stable_deref_trait |
| subtle | 2.6.1 | BSD-3-Clause | https://github.com/dalek-cryptography/subtle |
| syn | 2.0.119 | MIT OR Apache-2.0 | https://github.com/dtolnay/syn |
| sync_wrapper | 1.0.2 | Apache-2.0 | https://github.com/Actyx/sync_wrapper |
| synstructure | 0.13.2 | MIT | https://github.com/mystor/synstructure |
| thiserror | 2.0.18 | MIT OR Apache-2.0 | https://github.com/dtolnay/thiserror |
| thiserror-impl | 2.0.18 | MIT OR Apache-2.0 | https://github.com/dtolnay/thiserror |
| tinystr | 0.8.3 | Unicode-3.0 | https://github.com/unicode-org/icu4x |
| tinyvec | 1.12.0 | Zlib OR Apache-2.0 OR MIT | https://github.com/Lokathor/tinyvec |
| tinyvec_macros | 0.1.1 | MIT OR Apache-2.0 OR Zlib | https://github.com/Lokathor/tinyvec |
| tokio | 1.53.0 | MIT | https://github.com/tokio-rs/tokio |
| tokio-macros | 2.7.1 | MIT | https://github.com/tokio-rs/tokio |
| tokio-rustls | 0.26.4 | MIT OR Apache-2.0 | https://github.com/rustls/tokio-rustls |
| tokio-stream | 0.1.18 | MIT | https://github.com/tokio-rs/tokio |
| tokio-util | 0.7.18 | MIT | https://github.com/tokio-rs/tokio |
| toml | 0.8.23 | MIT OR Apache-2.0 | https://github.com/toml-rs/toml |
| toml_datetime | 0.6.11 | MIT OR Apache-2.0 | https://github.com/toml-rs/toml |
| toml_edit | 0.22.27 | MIT OR Apache-2.0 | https://github.com/toml-rs/toml |
| toml_write | 0.1.2 | MIT OR Apache-2.0 | https://github.com/toml-rs/toml |
| tower | 0.5.3 | MIT | https://github.com/tower-rs/tower |
| tower-http | 0.6.11 | MIT | https://github.com/tower-rs/tower-http |
| tower-layer | 0.3.3 | MIT | https://github.com/tower-rs/tower |
| tower-service | 0.3.3 | MIT | https://github.com/tower-rs/tower |
| tracing | 0.1.44 | MIT | https://github.com/tokio-rs/tracing |
| tracing-core | 0.1.36 | MIT | https://github.com/tokio-rs/tracing |
| try-lock | 0.2.5 | MIT | https://github.com/seanmonstar/try-lock |
| typenum | 1.20.1 | MIT OR Apache-2.0 | https://github.com/paholg/typenum |
| unicode-ident | 1.0.24 | (MIT OR Apache-2.0) AND Unicode-3.0 | https://github.com/dtolnay/unicode-ident |
| universal-hash | 0.5.1 | MIT OR Apache-2.0 | https://github.com/RustCrypto/traits |
| untrusted | 0.9.0 | ISC | https://github.com/briansmith/untrusted |
| url | 2.5.8 | MIT OR Apache-2.0 | https://github.com/servo/rust-url |
| utf8_iter | 1.0.4 | Apache-2.0 OR MIT | https://github.com/hsivonen/utf8_iter |
| version_check | 0.9.5 | MIT OR Apache-2.0 | https://github.com/SergioBenitez/version_check |
| want | 0.3.1 | MIT | https://github.com/seanmonstar/want |
| wasi | 0.11.1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | https://github.com/bytecodealliance/wasi |
| wasm-bindgen | 0.2.126 | MIT OR Apache-2.0 | https://github.com/rustwasm/wasm-bindgen |
| wasm-bindgen-futures | 0.4.76 | MIT OR Apache-2.0 | https://github.com/rustwasm/wasm-bindgen |
| wasm-bindgen-macro | 0.2.126 | MIT OR Apache-2.0 | https://github.com/rustwasm/wasm-bindgen |
| wasm-bindgen-macro-support | 0.2.126 | MIT OR Apache-2.0 | https://github.com/rustwasm/wasm-bindgen |
| wasm-bindgen-shared | 0.2.126 | MIT OR Apache-2.0 | https://github.com/rustwasm/wasm-bindgen |
| wasm-streams | 0.4.2 | MIT OR Apache-2.0 | https://github.com/nicowillis/wasm-streams |
| web-sys | 0.3.103 | MIT OR Apache-2.0 | https://github.com/rustwasm/wasm-bindgen |
| web-time | 1.1.0 | MIT OR Apache-2.0 | https://github.com/nicowillis/web-time |
| webpki-roots | 1.0.9 | CDLA-Permissive-2.0 | https://github.com/rustls/webpki-roots |
| windows-link | 0.2.1 | MIT OR Apache-2.0 | https://github.com/microsoft/windows-rs |
| windows-sys | 0.52.0 / 0.61.2 | MIT OR Apache-2.0 | https://github.com/microsoft/windows-rs |
| windows-targets | 0.52.6 | MIT OR Apache-2.0 | https://github.com/microsoft/windows-rs |
| windows_aarch64_gnullvm | 0.52.6 | MIT OR Apache-2.0 | https://github.com/microsoft/windows-rs |
| windows_aarch64_msvc | 0.52.6 | MIT OR Apache-2.0 | https://github.com/microsoft/windows-rs |
| windows_i686_gnu | 0.52.6 | MIT OR Apache-2.0 | https://github.com/microsoft/windows-rs |
| windows_i686_gnullvm | 0.52.6 | MIT OR Apache-2.0 | https://github.com/microsoft/windows-rs |
| windows_i686_msvc | 0.52.6 | MIT OR Apache-2.0 | https://github.com/microsoft/windows-rs |
| windows_x86_64_gnu | 0.52.6 | MIT OR Apache-2.0 | https://github.com/microsoft/windows-rs |
| windows_x86_64_gnullvm | 0.52.6 | MIT OR Apache-2.0 | https://github.com/microsoft/windows-rs |
| windows_x86_64_msvc | 0.52.6 | MIT OR Apache-2.0 | https://github.com/microsoft/windows-rs |
| winnow | 0.7.15 | MIT | https://github.com/winnow-rs/winnow |
| writeable | 0.6.3 | Unicode-3.0 | https://github.com/unicode-org/icu4x |
| yoke | 0.8.3 | Unicode-3.0 | https://github.com/unicode-org/icu4x |
| yoke-derive | 0.8.2 | Unicode-3.0 | https://github.com/unicode-org/icu4x |
| zerofrom | 0.1.8 | Unicode-3.0 | https://github.com/unicode-org/icu4x |
| zerofrom-derive | 0.1.7 | Unicode-3.0 | https://github.com/unicode-org/icu4x |
| zeroize | 1.9.0 | Apache-2.0 OR MIT | https://github.com/RustCrypto/utils |
| zeroize_derive | 1.5.0 | Apache-2.0 OR MIT | https://github.com/RustCrypto/utils |
| zerotrie | 0.2.4 | Unicode-3.0 | https://github.com/unicode-org/icu4x |
| zerovec | 0.11.6 | Unicode-3.0 | https://github.com/unicode-org/icu4x |
| zerovec-derive | 0.11.3 | Unicode-3.0 | https://github.com/unicode-org/icu4x |
| zmij | 1.0.23 | MIT | (see crates.io) |

---

## Bundled JavaScript Components

| Component | Version | License | Location | Source |
|---|---|---|---|---|
| DOMPurify | 3.2.6 | Apache-2.0 OR MPL-2.0 | `docs/vendor/purify.min.js` | https://github.com/cure53/DOMPurify |
| marked | 11.0.0 | MIT | `docs/vendor/marked.min.js` | https://github.com/markedjs/marked |
| mermaid | 11.9.0 | MIT | `docs/vendor/mermaid.min.js` | https://github.com/mermaid-js/mermaid |

> **DOMPurify note:** Apache-2.0 OR MPL-2.0 dual-licensed. Apache-2.0 elected.
> DOMPurify is also embedded inside `mermaid.min.js` (version 3.2.5 in that bundle).
> Both instances are unmodified; their license headers are intact inside the files.

---

## License Elections for Dual-Licensed Crates

| Crate | Available Licenses | Elected License | Reason |
|---|---|---|---|
| ryu | Apache-2.0 OR BSL-1.0 | Apache-2.0 | BSL-1.0 has production-use restrictions; Apache-2.0 is fully permissive |
| r-efi | MIT OR Apache-2.0 OR LGPL-2.1-or-later | MIT / Apache-2.0 | Avoid LGPL |
| wasi | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | Apache-2.0 | Consistent with project license |
| memchr | Unlicense OR MIT | MIT | Consistent with project license |
| DOMPurify | Apache-2.0 OR MPL-2.0 | Apache-2.0 | Avoid MPL-2.0 file-level copyleft |

---

## Full inventory (raw — name, version, license)
```
aead	0.5.2	MIT OR Apache-2.0
async-trait	0.1.89	MIT OR Apache-2.0
atomic-waker	1.1.2	Apache-2.0 OR MIT
axum	0.7.9	MIT
axum-core	0.4.5	MIT
base64	0.22.1	MIT OR Apache-2.0
bitflags	2.13.1	MIT OR Apache-2.0
block-buffer	0.10.4	MIT OR Apache-2.0
bumpalo	3.20.3	MIT OR Apache-2.0
bytes	1.12.1	MIT
cc	1.3.0	MIT OR Apache-2.0
cfg-if	1.0.4	MIT OR Apache-2.0
cfg_aliases	0.2.2	MIT
chacha20	0.10.1	MIT OR Apache-2.0
chacha20	0.9.1	Apache-2.0 OR MIT
chacha20poly1305	0.10.1	Apache-2.0 OR MIT
cipher	0.4.4	MIT OR Apache-2.0
cpufeatures	0.2.17	MIT OR Apache-2.0
cpufeatures	0.3.0	MIT OR Apache-2.0
crypto-common	0.1.7	MIT OR Apache-2.0
digest	0.10.7	MIT OR Apache-2.0
displaydoc	0.2.6	MIT OR Apache-2.0
equivalent	1.0.2	Apache-2.0 OR MIT
find-msvc-tools	0.1.9	MIT OR Apache-2.0
form_urlencoded	1.2.2	MIT OR Apache-2.0
futures-channel	0.3.33	MIT OR Apache-2.0
futures-core	0.3.33	MIT OR Apache-2.0
futures-io	0.3.33	MIT OR Apache-2.0
futures-macro	0.3.33	MIT OR Apache-2.0
futures-sink	0.3.33	MIT OR Apache-2.0
futures-task	0.3.33	MIT OR Apache-2.0
futures-util	0.3.33	MIT OR Apache-2.0
generic-array	0.14.7	MIT
getrandom	0.2.17	MIT OR Apache-2.0
getrandom	0.4.3	MIT OR Apache-2.0
hashbrown	0.17.1	MIT OR Apache-2.0
http	1.4.2	MIT OR Apache-2.0
http-body	1.1.0	MIT
http-body-util	0.1.4	MIT
httparse	1.10.1	MIT OR Apache-2.0
httpdate	1.0.3	MIT OR Apache-2.0
hyper	1.10.1	MIT
hyper-rustls	0.27.9	Apache-2.0 OR ISC OR MIT
hyper-util	0.1.20	MIT
icu_collections	2.2.0	Unicode-3.0
icu_locale_core	2.2.0	Unicode-3.0
icu_normalizer	2.2.0	Unicode-3.0
icu_normalizer_data	2.2.0	Unicode-3.0
icu_properties	2.2.0	Unicode-3.0
icu_properties_data	2.2.0	Unicode-3.0
icu_provider	2.2.0	Unicode-3.0
idna	1.1.0	MIT OR Apache-2.0
idna_adapter	1.2.2	Apache-2.0 OR MIT
indexmap	2.14.0	Apache-2.0 OR MIT
inout	0.1.4	MIT OR Apache-2.0
ipnet	2.12.0	MIT OR Apache-2.0
itoa	1.0.18	MIT OR Apache-2.0
js-sys	0.3.103	MIT OR Apache-2.0
libc	0.2.186	MIT OR Apache-2.0
litemap	0.8.2	Unicode-3.0
log	0.4.33	MIT OR Apache-2.0
lru-slab	0.1.2	MIT OR Apache-2.0 OR Zlib
matchit	0.7.3	MIT AND BSD-3-Clause
memchr	2.8.3	Unlicense OR MIT
mime	0.3.17	MIT OR Apache-2.0
mio	1.2.2	MIT
once_cell	1.21.4	MIT OR Apache-2.0
opaque-debug	0.3.1	MIT OR Apache-2.0
percent-encoding	2.3.2	MIT OR Apache-2.0
pin-project-lite	0.2.17	Apache-2.0 OR MIT
poly1305	0.8.0	Apache-2.0 OR MIT
potential_utf	0.1.5	Unicode-3.0
proc-macro2	1.0.106	MIT OR Apache-2.0
quinn	0.11.11	MIT OR Apache-2.0
quinn-proto	0.11.16	MIT OR Apache-2.0
quinn-udp	0.5.15	MIT OR Apache-2.0
quote	1.0.46	MIT OR Apache-2.0
r-efi	6.0.0	MIT OR Apache-2.0 OR LGPL-2.1-or-later
rand	0.10.2	MIT OR Apache-2.0
rand_core	0.10.1	MIT OR Apache-2.0
rand_core	0.6.4	MIT OR Apache-2.0
rand_pcg	0.10.2	MIT OR Apache-2.0
reqwest	0.12.28	MIT OR Apache-2.0
ring	0.17.14	Apache-2.0 AND ISC
rustc-hash	2.1.3	Apache-2.0 OR MIT
rustls	0.23.42	Apache-2.0 OR ISC OR MIT
rustls-pki-types	1.15.0	MIT OR Apache-2.0
rustls-webpki	0.103.13	ISC
rustversion	1.0.23	MIT OR Apache-2.0
ryu	1.0.23	Apache-2.0 OR BSL-1.0
serde	1.0.228	MIT OR Apache-2.0
serde_core	1.0.228	MIT OR Apache-2.0
serde_derive	1.0.228	MIT OR Apache-2.0
serde_json	1.0.150	MIT OR Apache-2.0
serde_path_to_error	0.1.20	MIT OR Apache-2.0
serde_spanned	0.6.9	MIT OR Apache-2.0
serde_urlencoded	0.7.1	MIT/Apache-2.0
sha2	0.10.9	MIT OR Apache-2.0
shlex	2.0.1	MIT OR Apache-2.0
slab	0.4.12	MIT
smallvec	1.15.2	MIT OR Apache-2.0
socket2	0.6.5	MIT OR Apache-2.0
stable_deref_trait	1.2.1	MIT OR Apache-2.0
subtle	2.6.1	BSD-3-Clause
syn	2.0.119	MIT OR Apache-2.0
sync_wrapper	1.0.2	Apache-2.0
synstructure	0.13.2	MIT
thiserror	2.0.18	MIT OR Apache-2.0
thiserror-impl	2.0.18	MIT OR Apache-2.0
tinystr	0.8.3	Unicode-3.0
tinyvec	1.12.0	Zlib OR Apache-2.0 OR MIT
tinyvec_macros	0.1.1	MIT OR Apache-2.0 OR Zlib
tokio	1.53.0	MIT
tokio-macros	2.7.1	MIT
tokio-rustls	0.26.4	MIT OR Apache-2.0
tokio-stream	0.1.18	MIT
tokio-util	0.7.18	MIT
toml	0.8.23	MIT OR Apache-2.0
toml_datetime	0.6.11	MIT OR Apache-2.0
toml_edit	0.22.27	MIT OR Apache-2.0
toml_write	0.1.2	MIT OR Apache-2.0
tower	0.5.3	MIT
tower-http	0.6.11	MIT
tower-layer	0.3.3	MIT
tower-service	0.3.3	MIT
tracing	0.1.44	MIT
tracing-core	0.1.36	MIT
try-lock	0.2.5	MIT
typenum	1.20.1	MIT OR Apache-2.0
unicode-ident	1.0.24	(MIT OR Apache-2.0) AND Unicode-3.0
universal-hash	0.5.1	MIT OR Apache-2.0
untrusted	0.9.0	ISC
url	2.5.8	MIT OR Apache-2.0
utf8_iter	1.0.4	Apache-2.0 OR MIT
version_check	0.9.5	MIT/Apache-2.0
want	0.3.1	MIT
wasi	0.11.1+wasi-snapshot-preview1	Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT
wasm-bindgen	0.2.126	MIT OR Apache-2.0
wasm-bindgen-futures	0.4.76	MIT OR Apache-2.0
wasm-bindgen-macro	0.2.126	MIT OR Apache-2.0
wasm-bindgen-macro-support	0.2.126	MIT OR Apache-2.0
wasm-bindgen-shared	0.2.126	MIT OR Apache-2.0
wasm-streams	0.4.2	MIT OR Apache-2.0
web-sys	0.3.103	MIT OR Apache-2.0
web-time	1.1.0	MIT OR Apache-2.0
webpki-roots	1.0.9	CDLA-Permissive-2.0
windows-link	0.2.1	MIT OR Apache-2.0
windows-sys	0.52.0	MIT OR Apache-2.0
windows-sys	0.61.2	MIT OR Apache-2.0
windows-targets	0.52.6	MIT OR Apache-2.0
windows_aarch64_gnullvm	0.52.6	MIT OR Apache-2.0
windows_aarch64_msvc	0.52.6	MIT OR Apache-2.0
windows_i686_gnu	0.52.6	MIT OR Apache-2.0
windows_i686_gnullvm	0.52.6	MIT OR Apache-2.0
windows_i686_msvc	0.52.6	MIT OR Apache-2.0
windows_x86_64_gnu	0.52.6	MIT OR Apache-2.0
windows_x86_64_gnullvm	0.52.6	MIT OR Apache-2.0
windows_x86_64_msvc	0.52.6	MIT OR Apache-2.0
winnow	0.7.15	MIT
writeable	0.6.3	Unicode-3.0
yoke	0.8.3	Unicode-3.0
yoke-derive	0.8.2	Unicode-3.0
zerofrom	0.1.8	Unicode-3.0
zerofrom-derive	0.1.7	Unicode-3.0
zeroize	1.9.0	Apache-2.0 OR MIT
zeroize_derive	1.5.0	Apache-2.0 OR MIT
zerotrie	0.2.4	Unicode-3.0
zerovec	0.11.6	Unicode-3.0
zerovec-derive	0.11.3	Unicode-3.0
zmij	1.0.23	MIT
```
