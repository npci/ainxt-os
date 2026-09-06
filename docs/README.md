# AiNxt OS — architecture reference

251 documents covering every crate in the workspace. Open **[`index.html`](index.html)** in a browser
for the rendered, navigable version (diagrams, search, cross-links); the Markdown here is readable
directly if you prefer.

The viewer is self-contained — `marked` and `mermaid` are vendored under `vendor/`, so it works with
no internet access. See [`../THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md) for their licences.

## Layout

Folders mirror the navigation tree in the viewer, so a document's location tells you which layer it
belongs to.

| Folder | Docs | Covers |
|---|---:|---|
| [`core_infrastructure/`](core_infrastructure/) | 24 | Core interaction protocol, security/config, connectors, application runtime, plugin/WASM, skill execution, surface conversation |
| [`ai_engine/`](ai_engine/) | 81 | Answer artifacts, quality verification, safety guardrails, prompt engineering, knowledge retrieval, memory, evaluation/testing |
| [`governance_compliance/`](governance_compliance/) | 49 | Admission, compliance, governance, identity, incident, lifecycle, payments, responsible AI, teams, workforce |
| [`pipeline_runtime/`](pipeline_runtime/) | 80 | Semantic edit, pipeline orchestration, planning/program execution, runtime engine, server/serving |
| [`tools_cli/`](tools_cli/) | 6 | Headless CLI, client SDK, tool runtime, surface profiles, integration tests |
| [`injection_service/`](injection_service/) | 5 | Prompt-injection sidecar service |
| [`scenario_service/`](scenario_service/) | 5 | Scenario matrix runner and conformance harness |

[`overview.md`](overview.md) is the entry point and stays at this level.
`module_tree.json` is the same subject tree the viewer's navigation is built from, kept as a
machine-readable index; `metadata.json` records how this corpus was generated.

## Scope

These are **architecture** documents: what each subsystem is, how it is composed, and which
invariants it holds. They are not operational instructions — for installing, configuring and running
AiNxt OS, see the [root README](../README.md), and for integrating a front end see
[`../DOCKING.md`](../DOCKING.md).

## Editing a diagram

Every document contains at least one mermaid diagram. One rule is easy to get wrong: inside a
```` ```mermaid ```` block, **never use an HTML entity** such as `&#58;`. The viewer renders Markdown
with `marked` first, which decodes the entity back into a raw `:` or `;` — and mermaid treats those
as grammar delimiters, so the diagram fails to render in the browser while looking correct in the
source. Use mermaid's own numeric escape instead:

| Character in a label | Write |
|---|---|
| `:` | `#58;` |
| `;` | `#59;` |

`.github/scripts/check-mermaid.sh` enforces this in CI.
