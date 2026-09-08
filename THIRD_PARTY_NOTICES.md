# Third-Party Notices — AiNxt OS

**Project:** AiNxt OS  
**Copyright:** Copyright 2026 National Payments Corporation of India  
**Project License:** MIT  
**Last reviewed:** 2026-09-02  

The AiNxt OS includes third-party open-source components. This file, together with the
machine-readable `THIRD_PARTY_INVENTORY.yaml`, records them and their license notices.
The project itself is MIT-licensed, and MIT imposes no NOTICE obligation of its own —
but the third-party components below carry their OWN attribution and notice-retention
conditions, which are unaffected by this project's licence and are met here.

For the complete dependency table with versions and license elections, see
`THIRD_PARTY_LICENSES.md`.

---

## Legal Flags Summary

| # | Component | License | Risk | Status |
|---|---|---|---|---|
| LIC-001 | `ring` 0.17.x | Apache-2.0 AND ISC (BoringSSL-derived) | 🟡 NOTICE required | Documented below |
| LIC-002 | `subtle` 2.x | BSD-3-Clause | 🟢 LOW | Documented below |
| LIC-003 | `webpki-roots` 1.x | CDLA-Permissive-2.0 | 🟢 LOW | Documented in THIRD_PARTY_LICENSES.md |
| LIC-004 | `DOMPurify` 3.2.6 | Apache-2.0 OR MPL-2.0 | 🟢 LOW (Apache-2.0 elected) | Documented below |
| LIC-005 | `marked` 11.0.0 | MIT | 🟢 LOW | Documented below |
| LIC-006 | `mermaid` 11.9.0 | MIT (embeds DOMPurify Apache-2.0/MPL-2.0) | 🟢 LOW | Documented below |
| LIC-007 | MCP Specification | MIT (Anthropic, Inc.) | 🟢 LOW | Documented below |
| LIC-008 | `ryu` 1.x | Apache-2.0 OR BSL-1.0 | 🟡 BSL period check | Apache-2.0 elected in deny.toml |

---

> **Status: in use.** Two third-party components are bundled **as source** in this tree — the
> documentation viewer's JavaScript under `docs/vendor/` (below). Rust dependencies are **not**
> vendored: they resolve from crates.io against the committed `Cargo.lock` and are gated by
> `deny.toml` (`cargo deny check` covers licences, advisories, bans and sources). As dependencies
> are added, each MUST appear both here (with its required copyright/licence notice) and in
> `THIRD_PARTY_INVENTORY.yaml`.

## How this file is maintained
- Adding a dependency ⇒ add its entry to `THIRD_PARTY_INVENTORY.yaml` **and** append its required NOTICE/copyright text here.
- Removing a dependency ⇒ remove both entries.
- Generation may be automated (e.g., `cargo about`) but the file is committed and reviewed — it is a legal artifact, not a build output to be trusted blindly.

## Components

### DOMPurify — Cure53 and other contributors

**Bundled at:** `docs/vendor/purify.min.js` · **Version:** 3.2.6 · **License:** Apache-2.0 / MPL-2.0
**Used by:** `docs/index.html` — sanitizes all HTML produced by `marked` before it is written to
the DOM, preventing Cross-Site Scripting (XSS) vulnerabilities (Checkmarx: Client Potential XSS;
OWASP A3 / PCI DSS 6.5.7). Redistributed **unmodified**; its licence header is intact inside the file.
**Project:** https://github.com/cure53/DOMPurify

```
DOMPurify 3.2.6 | (c) Cure53 and other contributors | Released under the Apache license 2.0
and Mozilla Public License 2.0 | github.com/cure53/DOMPurify/blob/3.2.6/LICENSE
```

---

### marked — Christopher Jeffrey and contributors

**Bundled at:** `docs/vendor/marked.min.js` · **Version:** 11.0.0 · **License:** MIT
**Used by:** `docs/index.html` — parses the Markdown of the documentation site in the browser.
**Why vendored:** it was previously loaded from a CDN, which left the documentation site
non-functional without internet access. Redistributed **unmodified**; its licence header is intact.
**Project:** https://github.com/markedjs/marked

```
marked v11.0.0 - a markdown parser
Copyright (c) 2011-2023, Christopher Jeffrey. (MIT Licensed)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### mermaid — Knut Sveidqvist and contributors

**Bundled at:** `docs/vendor/mermaid.min.js` · **Version:** 11.9.0 · **License:** MIT
**Used by:** `docs/index.html` — renders the diagrams present in every document under `docs/`.
**Why vendored:** as above. Redistributed **unmodified**.
**Project:** https://github.com/mermaid-js/mermaid

The distributed bundle embeds further components whose notices are retained inside the file
itself. Those observed in this build are MIT-licensed — lodash, a Promises/A+ thenable
(© 2013-2014 Ralf S. Engelschall), a jQuery-derived event object, and a Bezier curve generator
(© Gaetan Renaudeau) — with ONE exception: it also embeds **DOMPurify** (© Cure53 and other
contributors), which is released under the **Apache License 2.0 and Mozilla Public License 2.0**,
not MIT. DOMPurify is also vendored separately at `docs/vendor/purify.min.js`; see its own entry
above. The version embedded in this mermaid build reports itself as 3.2.5.

```
Copyright (c) 2014 - 2022 Knut Sveidqvist

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```


### Model Context Protocol (MCP) Specification — Anthropic, Inc.

**Used by:** `crates/ainxt-mcp/`  
**Nature:** Protocol specification (wire method names, version string, transport taxonomy) — not bundled code.  
**Specification URL:** https://modelcontextprotocol.io  
**License:** MIT License  

```
MIT License

Copyright (c) 2024 Anthropic, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

**Note:** The `ainxt-mcp` crate is an independent clean-room implementation of the MCP wire protocol under the MIT License. The wire method names (`initialize`, `tools/list`, `tools/call`), protocol version (`mcp/1.0`), and transport taxonomy (stdio / streamable-http / sse) are identifiers defined by the MCP specification and are reproduced here for interoperability.

---

### `ring` — Cryptographic library

**Used by:** `crates/ainxt-identity/`, `crates/ainxt-cryptoagility/`, and transitive dependencies  
**Version:** 0.17.x  
**License:** Apache-2.0 AND ISC (with BoringSSL/OpenSSL-derived components)  
**Repository:** https://github.com/briansmith/ring  

`ring` incorporates code from BoringSSL, which is derived from OpenSSL. The following notices apply:

```
Copyright 2015-2024 Brian Smith.

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
```

BoringSSL (incorporated in `ring`):
```
Copyright (c) 2015, Google Inc.
ISC License — see https://boringssl.googlesource.com/boringssl/+/refs/heads/master/LICENSE
```

---

### `subtle` — Constant-time cryptographic utilities

**Used by:** transitive dependency of `ring`, `rustls`  
**Version:** 2.x  
**License:** BSD-3-Clause  
**Repository:** https://github.com/dalek-cryptography/subtle  

```
Copyright (c) 2016-2024 Isis Agora Lovecruft, Henry de Valence

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
3. Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
```

## Excluded by policy (not bundled)
- **Copyleft components** (GPL/LGPL/AGPL/MPL/EPL/CDDL): never vendored. Where their functionality is needed (e.g., a sandbox helper), the runtime **shells out to a separately-installed binary** — the copyleft component is not linked or distributed with this source.
- **Model weights** (Qwen/GLM/Gemma/Kimi/etc.): not distributed here; tracked in `MODEL_WEIGHTS_REGISTER.md`.

## Reference-only projects
Projects listed under `reference_only` in `THIRD_PARTY_INVENTORY.yaml` were **studied for architecture only**; no code from them is incorporated, so they impose no redistribution obligation. They are listed for provenance/transparency, not attribution of included code.
