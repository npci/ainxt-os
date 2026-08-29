# Context Retrieval & Routing

## Purpose

The **Context Retrieval & Routing** module is the *Context Fabric* of the system: it turns a user query into a secured, grounded, citable, and auditable context window that downstream model calls can safely consume. It sits in the `knowledge_retrieval` subsystem and is responsible for:

1. **Retrieving** relevant knowledge chunks from a corpus while enforcing clearance, node-level RBAC, and row-level security **before** ranking.
2. **Routing** retrieval across a multi-layer fabric graph (code, docs, runtime, structured, federated, multimodal, etc.) based on a deterministic query plan.
3. **Ranking** candidates with a fused lexical + dense + cross-graph personalized PageRank score, plus freshness and authority signals.
4. **Assembling** a token-budget-fitted context window with citations and full lineage (every included, dropped, or superseded node is accounted for).
5. **Verifying** numeric answers via server-side re-derivation and producing a single event-log record for audit.

The module is designed around a single seam â€” the `Retriever` trait â€” so the lexical placeholder used in tests can be swapped for the production hybrid engine without changing any caller code.

## Architecture Overview

```mermaid
flowchart TB
    subgraph Query["Query Input"]
        Q[User Query]
        AC[AccessContext<br/>class + dept + ad_level + groups]
        RF[RowFilter<br/>RLS]
        EM[Eligible Models]
    end

    subgraph Plan["Query Planning"]
        QP[plan_query<br/>GraphLayer selection]
        SC[classify_scope<br/>PointLookup vs Global]
    end

    subgraph Fabric["Multi-Graph Fabric"]
        MG[MultiGraphFabric]
        FG[FabricGraph<br/>typed edges]
        AS[ArtifactStore<br/>multimodal]
    end

    subgraph Retrieve["Retrieval & Ranking"]
        HR[HybridRetriever]
        LEX[LexicalRetriever]
        RER[Reranker]
        PPR[personalized_pagerank]
    end

    subgraph Assemble["Context Assembly"]
        CW[compile_window]
        CR[compile_ranked]
        FIT[budget_fit_eligible]
        CA[conflict arbitration]
    end

    subgraph Verify["Verification & Audit"]
        VA[verify_answer<br/>numeric re-derivation]
        VG[verify_ledger_answer<br/>ledger-class gate]
        TER[TurnEventRecord]
    end

    Q --> QP
    QP --> MG
    MG --> HR
    AC --> HR
    RF --> HR
    FG --> PPR
    PPR --> CR
    HR --> CR
    EM --> FIT
    CR --> FIT
    FIT --> CA
    CA --> CW
    CW --> VA
    CW --> VG
    VA --> TER
    VG --> TER
```

### Key Design Principles

- **Pre-rank security**: Data-class, node-ACL (department, seniority, groups), and RLS row-filters are applied *before* scoring, fusion, reranking, and fitting. A node the caller may not see never enters the candidate set â€” its existence never leaks.
- **Same seam, different engines**: The `Retriever` trait abstracts both the in-memory `LexicalRetriever` and the production `HybridRetriever` (BM25 + dense HNSW â†’ RRF â†’ rerank).
- **Determinism**: No RNG, no wall-clock, no hash-map iteration order. Results are reproducible for audit and testing.
- **Accountability**: Every retrieved node is recorded in `LineageNode` with `Included`, `DroppedByBudget`, or `SupersededByConflict` outcome.
- **Two-phase budget fit**: The window is first fit to the narrowest eligible model floor, then re-fit on model-confirm and every failover without silent truncation.

## Sub-Modules

The module is split into three sub-modules:

| Sub-module | File | Responsibility |
|------------|------|----------------|
| [Context Retrieval & Routing Core](context_retrieval_routing_core.md) | `src/lib.rs` | `Retriever` trait, `Corpus`, `Chunk`, `Context`, `HybridRetriever`, `LexicalRetriever`, `CompiledWindow`, assembly, verification, and event-log record. |
| [Context Retrieval & Routing Optimizer](context_retrieval_routing_optimizer.md) | `src/optimizer.rs` | Query planning (`plan_query`, `classify_scope`), cross-graph personalized PageRank, typed `FabricGraph`, named fabric queries, and community detection/summarization. |
| [Context Retrieval & Routing Router](context_retrieval_routing_router.md) | `src/route.rs` | Served routing layer: `MultiGraphFabric`, `FabricNode`, `RoutedWindow`, plan-routed retrieval, global-summary/multimodal tiers, and two-phase model fit. |

> **Cross-reference guide**: The retrieval seam, corpus model, context assembly, and verification gates are documented in [Context Retrieval & Routing Core](context_retrieval_routing_core.md); the query planner, cross-graph ranker, and community layer are documented in [Context Retrieval & Routing Optimizer](context_retrieval_routing_optimizer.md); the served multi-graph fabric, routed window, and two-phase fit are documented in [Context Retrieval & Routing Router](context_retrieval_routing_router.md).

## Data Flow

```mermaid
sequenceDiagram
    participant Caller as Chat/Convo Surface
    participant Router as MultiGraphFabric::route
    participant Planner as plan_query
    participant Retriever as HybridRetriever
    participant Ranker as personalized_pagerank
    participant Compiler as compile_window
    participant Verifier as CompiledWindow::verify_answer

    Caller->>Router: query + AccessContext + RowFilter + eligible models
    Router->>Planner: classify scope, select GraphLayers
    Planner-->>Router: QueryPlan
    Router->>Retriever: retriever_for_plan(plan)
    Router->>Ranker: rank_graph() + seeds_for(query)
    Ranker-->>Router: PageRank scores
    Router->>Compiler: compile_window(query, retriever, cfg, counter, request)
    Compiler->>Retriever: retrieve_ctx(query, access, filter, k)
    Retriever-->>Compiler: scored candidates (pre-rank ACL/RLS)
    Compiler->>Compiler: fuse retrieval + PageRank + freshness
    Compiler->>Compiler: arbitrate conflicts by authority/recency
    Compiler->>Compiler: budget fit to eligible floor
    Compiler-->>Router: CompiledWindow
    Router->>Router: attach global summaries / artifacts if planned
    Router-->>Caller: RoutedWindow
    Caller->>Verifier: verify_answer(answer, claims, rederiver)
    Verifier-->>Caller: VerifiedAnswer + TurnEventRecord
```

## Integration with the Rest of the System

- **Upstream callers**: `ainxt-convo`, `ainxt-chat`, and `ainxt-runtimed` drive `compile_window` / `MultiGraphFabric::route` on the served path.
- **Retrieval engine**: Delegates heavy lifting to `ainxt-retrieval` (`Corpus::hybrid`, `hybrid_ctx_rls`, `budget_fit_eligible`, `EligibleModel`, `TokenCounter`, `Reranker`). See [retrieval_core](retrieval_core.md) and [retrieval_advanced](retrieval_advanced.md).
- **Security / ACL / RLS**: Re-exports `AccessContext`, `NodeAcl`, `RowFilter`, `RlsSession`, `RlsPolicy` from `ainxt-retrieval`. See [security_config](security_config.md).
- **Numeric verification**: Re-exports and uses `ainxt-synthesis` re-derivation gates (`numeric_gate`, `LedgerAnswerGate`, `Rederiver`). See [quality_verification](quality_verification.md).
- **Prompt injection defense**: Uses `ainxt_injection::wrap_untrusted` to fence retrieved context as untrusted data. See [safety_guardrails](safety_guardrails.md).
- **Multimodal artifacts**: Routes artifact models through `crate::artifact::route_model` to ensure regulated data never reaches a cloud vision model. See [context_sources](context_sources.md).
- **Event log**: `TurnEventRecord` is the payload handed to `ainxt_eventlog`. See [core_interaction](core_interaction.md).

## Security Model

| Control | Where enforced | Guarantee |
|---------|---------------|-----------|
| Data-class clearance | `Retriever::retrieve` / `retrieve_ctx` | Above-clearance chunks are filtered pre-rank. |
| Node ACL (dept / seniority / groups) | `HybridRetriever::retrieve_ctx` â†’ `ainxt_retrieval::Corpus::hybrid_ctx_rls` | Unauthorized nodes never scored. |
| RLS row-filter | `compile_rls` / `compile_window` â†’ `retrieve_scoped` / `retrieve_ctx` | Rows outside caller scope never scored. |
| Conflict arbitration | `arbitrate_conflicts` | Contradictory claims are resolved by authority/recency; losers recorded as superseded. |
| Ledger numeric gate | `CompiledWindow::verify_ledger_answer` | Server-side re-derivation blocks mismatched figures for ledger-class sources. |
| Artifact model routing | `RoutedWindow::eligible_artifacts` | Regulated artifacts are never sent to cloud models. |

## Mermaid: Component Relationships

```mermaid
classDiagram
    class Retriever {
        <<trait>>
        +retrieve(query, clearance, k)
        +retrieve_scoped(query, principal, filter, k)
        +retrieve_ctx(query, access, filter, k)
    }

    class LexicalRetriever {
        +new(corpus)
    }

    class HybridRetriever {
        +new(corpus)
        +with_embedder(embedder)
        +with_reranker(reranker)
        +from_corpus(corpus)
    }

    class Corpus {
        +chunks
        +load(chunks)
        +to_retrieval_corpus()
    }

    class Chunk {
        +id
        +source
        +text
        +data_class
        +timestamp
        +acl
        +attributes
        +authority
        +topic
    }

    class Context {
        +chunks
        +citations
        +lineage
        +to_prompt(query)
        +erasure_targets(ids)
    }

    class CompiledWindow {
        +plan
        +context
        +fitted
        +ranked
        +refit_to(model, counter)
        +verify_answer(...)
        +verify_ledger_answer(...)
    }

    class MultiGraphFabric {
        +nodes
        +graph
        +artifacts
        +route(...)
        +route_eligible(...)
    }

    class FabricGraph {
        +edges
        +layers
        +who_calls(sym)
        +refs_of(sym)
        +deps(module)
        +to_rank_graph()
    }

    Retriever <|-- LexicalRetriever
    Retriever <|-- HybridRetriever
    HybridRetriever --> Corpus
    Corpus --> Chunk
    CompiledWindow --> Context
    MultiGraphFabric --> FabricGraph
    MultiGraphFabric --> CompiledWindow
```

## See Also

- [context_sources](context_sources.md) â€” artifact and source extraction that feeds the fabric.
- [retrieval_core](retrieval_core.md) â€” the underlying retrieval engine (BM25, dense, rerank).
- [retrieval_advanced](retrieval_advanced.md) â€” federation, RLS, and structured retrieval.
- [quality_verification](quality_verification.md) â€” numeric re-derivation and answer verification.
- [safety_guardrails](safety_guardrails.md) â€” prompt injection and guardrail defenses.
- [core_interaction](core_interaction.md) â€” event log and session infrastructure.
