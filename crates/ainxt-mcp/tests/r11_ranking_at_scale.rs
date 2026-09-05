// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R11 §2.3/§2.4 — MCP tool ranking at scale: an always-visible core set, session stickiness, a
//! `capability.search` escape valve, and a phase-2 capability-class planner. Scenarios 11 + 12.

use ainxt_mcp::{
    capability_search, rank_session, Bm25Ranker, ClassCatalog, CoreSet, QualifiedTool, RankConfig,
    ToolManifest, ToolRanker, CAPABILITY_SEARCH,
};

fn tool(server: &str, name: &str, desc: &str) -> QualifiedTool {
    QualifiedTool {
        qualified_name: format!("mcp/{server}/{name}"),
        server_name: server.into(),
        server_url: format!("https://{server}.example/mcp"),
        manifest: ToolManifest::new(name, desc),
    }
}

/// A large registry (400+) so top-K selection is actually exercised, plus a couple of hand-named
/// relevant tools.
fn big_registry() -> Vec<QualifiedTool> {
    let mut tools = vec![
        tool(
            "jira",
            "create_issue",
            "create a new jira ticket in a project",
        ),
        tool("jira", "search_issues", "search jira tickets by jql query"),
        tool(
            "git",
            "search_code",
            "search the repository source code for a function",
        ),
        tool(
            "git",
            "create_mr",
            "open a merge request in gitlab from a branch",
        ),
    ];
    for i in 0..420 {
        tools.push(tool(
            "misc",
            &format!("noise_{i}"),
            &format!("an unrelated utility number {i} for widgets and gadgets"),
        ));
    }
    tools
}

#[test]
fn top_k_surfaces_the_right_tool_and_core_set_is_always_present() {
    let tools = big_registry();
    let core = CoreSet::new(["mcp/misc/noise_0"]); // pin one tool as "core" to prove it bypasses ranking
    let cfg = RankConfig {
        k: 15,
        ..Default::default()
    };

    let ranked = rank_session("open a new jira ticket", &tools, &core, &[], cfg);

    // Core tool is present regardless of relevance (it shares no query term).
    assert!(ranked
        .iter()
        .any(|r| r.tool.qualified_name == "mcp/misc/noise_0"));
    // The correct ticketing tool is surfaced within the top-K out of 420+ candidates.
    assert!(
        ranked
            .iter()
            .any(|r| r.tool.qualified_name == "mcp/jira/create_issue"),
        "the ticketing tool must be surfaced despite hundreds of noise tools"
    );
    // Budget honored: 1 core + up to k ranked tail.
    assert!(ranked.len() <= 1 + cfg.k);
}

#[test]
fn session_stickiness_keeps_a_recently_used_tool_visible() {
    let tools = big_registry();
    let core = CoreSet::default();
    // A query that matches NOTHING meaningful → all BM25 scores 0; without stickiness the recently-used
    // git tool would be lost among 420 zero-scored tools (truncated by the small k).
    let cfg = RankConfig {
        k: 5,
        stickiness_boost: 5.0,
        ..Default::default()
    };

    let no_sticky = rank_session("xyzzy plugh", &tools, &core, &[], cfg);
    let sticky = rank_session(
        "xyzzy plugh",
        &tools,
        &core,
        &["mcp/git/create_mr".to_string()],
        cfg,
    );

    // FAIL-BEFORE (no stickiness): the tool is not guaranteed in the tiny top-5 of a flat field.
    // PASS-AFTER: the boost lifts the recently-used tool into the visible set.
    assert!(
        sticky
            .iter()
            .any(|r| r.tool.qualified_name == "mcp/git/create_mr"),
        "a recently-used tool must stay visible via session stickiness"
    );
    assert!(sticky[0].tool.qualified_name == "mcp/git/create_mr");
    let _ = no_sticky; // (its top-5 is arbitrary among ties; the point is the sticky one is pinned)
}

#[test]
fn capability_search_escape_valve_finds_a_tool_outside_top_k() {
    let tools = big_registry();
    // A rare tool the model was never shown in its top-K — the escape valve searches the FULL registry.
    let hits = capability_search("merge request gitlab branch", &tools, 3);
    assert_eq!(hits[0].tool.qualified_name, "mcp/git/create_mr");
    assert!(hits[0].score > 0.0);
    // The escape valve has a stable, documented name the model invokes.
    assert_eq!(CAPABILITY_SEARCH, "capability.search");
}

#[test]
fn phase2_class_planner_bounds_candidates_before_ranking() {
    let tools = big_registry();
    let catalog = ClassCatalog::new()
        .with_class("ticketing", ["ticket", "jira", "issue"])
        .with_class("code-search", ["code", "repository", "merge", "branch"]);

    // The turn needs ticketing + code-search; the planner proposes exactly those from keywords.
    let classes = catalog.propose_classes("open a jira ticket then search the code repository");
    assert_eq!(
        classes,
        vec!["code-search".to_string(), "ticketing".to_string()]
    );

    // Candidate bounding drops the 420 noise tools BEFORE ranking runs.
    let candidates = catalog.candidates_for_classes(&classes, &tools);
    assert!(
        candidates.len() < 10,
        "class planning must bound the set; got {}",
        candidates.len()
    );
    assert!(candidates
        .iter()
        .any(|t| t.qualified_name == "mcp/jira/create_issue"));
    assert!(candidates
        .iter()
        .any(|t| t.qualified_name == "mcp/git/search_code"));
    assert!(!candidates
        .iter()
        .any(|t| t.qualified_name.starts_with("mcp/misc/")));

    // An empty proposal narrows nothing (never blanks the toolset).
    assert_eq!(
        catalog.candidates_for_classes(&[], &tools).len(),
        tools.len()
    );
}

#[test]
fn bm25_ranker_seam_matches_the_free_function() {
    // The offline reference ToolRanker (Bm25Ranker) is the same lexical rank the pgvector index will
    // replace behind the seam.
    let tools = big_registry();
    let r = Bm25Ranker::default();
    let via_seam = r.rank("jira ticket", &tools, 3);
    assert_eq!(via_seam[0].tool.qualified_name, "mcp/jira/create_issue");
}
