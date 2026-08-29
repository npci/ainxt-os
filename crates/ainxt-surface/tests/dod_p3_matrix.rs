// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! P3-EXIT DoD acceptance matrix — drive the assembled Phase-3 subsystems (profiles, skill runtime,
//! binding, edit engine, judge loop, artifact runtime) through the scenario harness across the P3
//! acceptance categories, with layered oracles + JUnit for CI. Each scenario proves one P3 exit
//! criterion end-to-end; scenarios fail-red if the invariant they name breaks.

use ainxt_artifact::{audit_document, Block, Document, MarkdownRenderer, MarkerScanner, Renderer};
use ainxt_edit::{apply, restore_missing_imports, Edit, EditError, Language};
use ainxt_judge::{
    Generator, Judge, JudgeCriteria, JudgeLoop, JudgePanel, JudgeVerdict, LoopConfig, NoVerifier,
};
use ainxt_profile::{RetrievalScope, SurfaceProfile};
use ainxt_scenario::{Category, Expectation, Observation, Runner, Scenario, Target};
use ainxt_skill::{NoExecutor, SkillManifest, SkillRegistry, SkillRuntime};
use ainxt_surface::{BindingError, SurfaceBinding};
use ainxt_types::{DataClass, Principal};

fn ok(output: String) -> Observation {
    Observation {
        output,
        error: None,
        side_effects: Vec::new(),
        latency_ms: 0,
    }
}
fn err(message: String) -> Observation {
    Observation {
        output: String::new(),
        error: Some(message),
        side_effects: Vec::new(),
        latency_ms: 0,
    }
}

fn skills() -> SkillRuntime {
    let mut r = SkillRegistry::new();
    r.register(SkillManifest::behavioral(
        "sop",
        "Follow the RCA procedure.",
    ));
    SkillRuntime::new(r, Box::new(NoExecutor))
}

// A minimal judge that passes iff the candidate contains a token.
struct TokenJudge {
    id: String,
    token: String,
}
impl Judge for TokenJudge {
    fn id(&self) -> &str {
        &self.id
    }
    fn score(&self, candidate: &str, _c: &JudgeCriteria) -> JudgeVerdict {
        let passed = candidate.contains(&self.token);
        JudgeVerdict {
            judge: self.id.clone(),
            score: if passed { 90 } else { 20 },
            passed,
            notes: String::new(),
        }
    }
}

struct FixedGen(String);
impl Generator for FixedGen {
    fn generate(&self, _attempt: usize, _feedback: &[String]) -> String {
        self.0.clone()
    }
}

struct P3DodTarget;

impl Target for P3DodTarget {
    fn run(&self, s: &Scenario) -> Observation {
        match s.id.as_str() {
            "PROFILE-MERGE-001" => run_profile_merge(),
            "SKILL-ORDER-001" => run_skill_order(),
            "RBAC-SCOPE-001" => run_rbac_scope(),
            "EDIT-SAFETY-001" => run_edit_safety(),
            "IMPORT-RESTORE-001" => run_import_restore(),
            "JUDGE-INDEP-001" => run_judge_independence(),
            "JUDGE-CAPPED-001" => run_judge_capped(),
            "DOCGEN-001" => run_docgen(),
            "CEILING-001" => run_ceiling(),
            "ADMIT-DENY-001" => run_admit_deny(),
            other => err(format!("unknown scenario {other}")),
        }
    }
}

fn run_profile_merge() -> Observation {
    // Deep layered merge: defaults set a nested tier; profile sets id; request overrides autonomy.
    let p = SurfaceProfile::resolve(&[
        ("defaults", "[model_policy]\ndefault_tier=\"complex\""),
        ("profile", "id=\"sdlc\""),
        ("request", "autonomy=\"autonomous\""),
    ]);
    match p {
        Ok(p) => ok(format!(
            "merge id={} tier={:?} autonomy={:?} default_retrieval={:?}",
            p.id, p.model_policy.default_tier, p.autonomy, p.context.retrieval
        )),
        Err(e) => err(format!("resolve failed: {e}")),
    }
}

fn run_skill_order() -> Observation {
    let sk = skills();
    let p = SurfaceProfile::from_toml("id=\"sdlc\"\npersona=\"PERSONA_MARK\"\nskills=[\"sop\"]")
        .unwrap();
    match SurfaceBinding::new(&p, &sk).plan(
        &Principal::user("u", &[]),
        "x",
        DataClass::Public,
        &["GUARD_MARK".to_string()],
    ) {
        Ok(plan) => {
            let sp = &plan.system_prompt;
            let (a, b, c) = (
                sp.find("PERSONA_MARK"),
                sp.find("RCA procedure"),
                sp.find("GUARD_MARK"),
            );
            match (a, b, c) {
                (Some(a), Some(b), Some(c)) if a < b && b < c => {
                    ok("order persona<behavioral<guard".into())
                }
                _ => err(format!("wrong skill-injection order: {sp:?}")),
            }
        }
        Err(e) => err(format!("plan failed: {e}")),
    }
}

fn run_rbac_scope() -> Observation {
    // A repo-scoped surface must resolve to RepoScoped (no cross-repo reach); a chat surface to
    // PlatformAndNamespace. Scope separation is a payment-org non-negotiable.
    let code =
        SurfaceProfile::from_toml("id=\"code\"\n[context]\nretrieval=\"repo-scoped\"").unwrap();
    let chat = SurfaceProfile::from_toml("id=\"chat\"").unwrap();
    let repo = code.context.retrieval == RetrievalScope::RepoScoped;
    let platform = chat.context.retrieval == RetrievalScope::PlatformAndNamespace;
    ok(format!("scope code-repo={repo} chat-platform={platform}"))
}

fn run_edit_safety() -> Observation {
    // Ambiguous anchor must be refused (dry-run safety), and nothing applied (all-or-nothing).
    let src = "x;\nx;\n";
    match apply(
        src,
        &[Edit::Replace {
            anchor: "x;".into(),
            replacement: "y;".into(),
        }],
    ) {
        Ok(_) => err("ambiguous anchor was wrongly applied".into()),
        Err(errs) => {
            let ambiguous = errs
                .iter()
                .any(|e| matches!(e, EditError::AmbiguousAnchor { .. }));
            ok(format!("edit-safety ambiguous-refused={ambiguous}"))
        }
    }
}

fn run_import_restore() -> Observation {
    let original = "use std::fmt;\nuse std::io::Read;\n\nfn main() {}\n";
    let generated = "use std::fmt;\n\nfn main() { /* changed */ }\n"; // dropped io::Read
    let r = restore_missing_imports(original, generated, Language::Rust);
    ok(format!(
        "restored={} content-has-import={}",
        r.restored.len(),
        r.content.contains("use std::io::Read;")
    ))
}

fn run_judge_independence() -> Observation {
    // 3 judges; the candidate satisfies only 1 → a minority cannot pass it (independence + majority).
    let panel = JudgePanel::new(vec![
        Box::new(TokenJudge {
            id: "j0".into(),
            token: "ALPHA".into(),
        }),
        Box::new(TokenJudge {
            id: "j1".into(),
            token: "BETA".into(),
        }),
        Box::new(TokenJudge {
            id: "j2".into(),
            token: "GAMMA".into(),
        }),
    ]);
    let v = panel.evaluate(
        "has ALPHA only",
        &JudgeCriteria {
            goal: "g".into(),
            threshold: 60,
        },
    );
    ok(format!(
        "independence consensus={} passed={}",
        v.consensus_pass,
        v.verdicts.iter().filter(|x| x.passed).count()
    ))
}

fn run_judge_capped() -> Observation {
    // A candidate that never satisfies the panel → honest capped (never reported as success).
    let panel = JudgePanel::new(vec![
        Box::new(TokenJudge {
            id: "j0".into(),
            token: "ALPHA".into(),
        }),
        Box::new(TokenJudge {
            id: "j1".into(),
            token: "BETA".into(),
        }),
    ]);
    let lp = JudgeLoop::new(
        panel,
        Box::new(NoVerifier),
        LoopConfig {
            max_iters: 3,
            stuck: None,
        },
    );
    let out = lp.run(
        &FixedGen("nope".into()),
        &JudgeCriteria {
            goal: "g".into(),
            threshold: 60,
        },
    );
    ok(format!(
        "capped={} succeeded={} iterations={}",
        out.capped, out.succeeded, out.iterations
    ))
}

fn run_docgen() -> Observation {
    // Fidelity: all block types render; audit-and-proceed: a PAN is flagged but NOT redacted.
    let mut d = Document::new("Report");
    d.push(Block::Heading {
        level: 2,
        text: "H".into(),
    })
    .push(Block::Paragraph {
        text: "Card 4111111111111111 on file.".into(),
    })
    .push(Block::Code {
        language: "sh".into(),
        code: "run".into(),
    });
    let md = MarkdownRenderer.render(&d);
    let findings = audit_document(&d, &MarkerScanner);
    ok(format!(
        "docgen has-heading={} has-code-fence={} flagged={} pan-intact={}",
        md.contains("## H"),
        md.contains("```sh"),
        !findings.is_empty(),
        md.contains("4111111111111111")
    ))
}

fn run_ceiling() -> Observation {
    let sk = skills();
    let p = SurfaceProfile::from_toml("id=\"chat\"\n[model_policy]\nmax_data_class=\"internal\"")
        .unwrap();
    match SurfaceBinding::new(&p, &sk).plan(
        &Principal::user("u", &[]),
        "x",
        DataClass::RegulatedPayment,
        &[],
    ) {
        Err(e @ BindingError::DataClassExceeded { .. }) => err(e.to_string()),
        other => err(format!("expected ceiling refusal, got {other:?}")),
    }
}

fn run_admit_deny() -> Observation {
    let sk = skills();
    let p = SurfaceProfile::from_toml("id=\"s\"\n[rbac]\nmin_role=\"admin\"").unwrap();
    match SurfaceBinding::new(&p, &sk).admit(&Principal::user("u", &[])) {
        Err(e @ BindingError::RoleTooLow { .. }) => err(e.to_string()),
        other => err(format!("expected role denial, got {other:?}")),
    }
}

fn contains(cs: &[&str]) -> Expectation {
    Expectation {
        must_contain: cs.iter().map(|s| s.to_string()).collect(),
        must_complete: true,
        ..Default::default()
    }
}
fn expect_err(cs: &[&str]) -> Expectation {
    Expectation {
        must_complete: false,
        must_error_contains: cs.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    }
}

fn matrix() -> Vec<Scenario> {
    vec![
        Scenario::new(
            "PROFILE-MERGE-001",
            "layered profile merge is deep + safe-defaulted",
            Category::Custom,
            "merge",
            contains(&["id=sdlc", "Complex", "Autonomous", "PlatformAndNamespace"]),
        ),
        Scenario::new(
            "SKILL-ORDER-001",
            "skills inject as persona → behavioral → guard",
            Category::Custom,
            "order",
            contains(&["persona<behavioral<guard"]),
        ),
        Scenario::new(
            "RBAC-SCOPE-001",
            "retrieval scope separates repo from platform",
            Category::Custom,
            "scope",
            contains(&["code-repo=true", "chat-platform=true"]),
        ),
        Scenario::new(
            "EDIT-SAFETY-001",
            "ambiguous edit anchor is refused, nothing applied",
            Category::Custom,
            "edit",
            contains(&["ambiguous-refused=true"]),
        ),
        Scenario::new(
            "IMPORT-RESTORE-001",
            "full-file regen restores dropped imports",
            Category::Custom,
            "imports",
            contains(&["restored=1", "content-has-import=true"]),
        ),
        Scenario::new(
            "JUDGE-INDEP-001",
            "an independent panel needs a majority (minority can't pass)",
            Category::Custom,
            "judge",
            contains(&["consensus=false", "passed=1"]),
        ),
        Scenario::new(
            "JUDGE-CAPPED-001",
            "the judge loop caps honestly (never fakes success)",
            Category::Custom,
            "capped",
            contains(&["capped=true", "succeeded=false", "iterations=3"]),
        ),
        Scenario::new(
            "DOCGEN-001",
            "doc-gen renders faithfully + audit-and-proceed (no redaction)",
            Category::Custom,
            "doc",
            contains(&["has-code-fence=true", "flagged=true", "pan-intact=true"]),
        ),
        Scenario::new(
            "CEILING-001",
            "a surface refuses data above its class ceiling",
            Category::DataClassLeak,
            "ceiling",
            expect_err(&["exceeds", "ceiling"]),
        ),
        Scenario::new(
            "ADMIT-DENY-001",
            "a principal below the role floor is denied",
            Category::RbacDeny,
            "admit",
            expect_err(&["below", "floor"]),
        ),
    ]
}

#[test]
fn p3_exit_acceptance_matrix_is_green() {
    let report = Runner::with_default_oracles().run(&matrix(), &P3DodTarget);
    eprintln!("{}", report.summary());
    assert!(
        report.junit_xml().contains("<testsuite"),
        "JUnit report is produced for CI"
    );
    assert!(
        report.all_passed(),
        "P3 acceptance matrix must be green:\n{}",
        report.summary()
    );
    assert!(
        report.coverage().len() >= 3,
        "matrix must cover >= 3 P3 categories (got {})",
        report.coverage().len()
    );
}
