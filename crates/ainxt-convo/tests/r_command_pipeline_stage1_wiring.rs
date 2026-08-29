// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-AUDIT data-surfaces-artifacts — "Command-pipelines unbuilt": `stage1_signal` only recognized
//! the fixed built-in slash commands (`/pdf`, `/doc`, `/ppt`, `/xlsx`); a deployment's own registered,
//! git-native command pipeline was never even checked. `stage1_signal_with_commands` closes that: a
//! registered command takes priority, and an unregistered slash command falls through unchanged to
//! the existing `stage1_signal` behavior. FAIL-BEFORE: `stage1_signal_with_commands` /
//! `command_pipeline` did not exist, so this file would not compile.

use ainxt_convo::command_pipeline::{CommandPipelineDef, CommandPipelineRegistry, CommandStep};
use ainxt_convo::{stage1_signal_with_commands, Intent, OutputFormat, Stage1Signal};

fn registry_with_incident_report() -> CommandPipelineRegistry {
    let mut reg = CommandPipelineRegistry::new();
    reg.register(CommandPipelineDef::new(
        "incident-report",
        vec![
            CommandStep::new("Summarize the incident: {args}"),
            CommandStep::new("From this summary:\n{step_1}\nDraft the postmortem timeline"),
        ],
    ));
    reg
}

#[test]
fn a_registered_command_is_matched_and_expanded_ahead_of_any_built_in() {
    let reg = registry_with_incident_report();
    let signal = stage1_signal_with_commands("/incident-report db outage 03:12 UTC", &reg)
        .expect("a registered command must produce a signal");
    match signal {
        Stage1Signal::Command(m) => {
            assert_eq!(m.name, "incident-report");
            assert_eq!(m.expanded_steps.len(), 2);
            assert_eq!(
                m.expanded_steps[0],
                "Summarize the incident: db outage 03:12 UTC"
            );
            assert!(
                m.expanded_steps[1].contains("db outage 03:12 UTC"),
                "step 2 chains off step 1's already-substituted text: {:?}",
                m.expanded_steps
            );
        }
        Stage1Signal::Intent(_) => panic!("a registered command must never fall through to Intent"),
    }
}

#[test]
fn an_unregistered_slash_command_falls_through_to_the_existing_fixed_built_ins_unchanged() {
    let reg = registry_with_incident_report();
    // `/pdf` is NOT registered as a custom command — this must behave EXACTLY like plain
    // `stage1_signal` (byte-identical fallback), proving the extension is additive, not a divergence.
    let signal = stage1_signal_with_commands("/pdf generate the settlement report", &reg)
        .expect("the fixed built-in must still fire");
    match signal {
        Stage1Signal::Intent(result) => {
            assert!(matches!(
                result.intent,
                Intent::DocGeneration(OutputFormat::Pdf)
            ));
            assert_eq!(result.confidence, 1.0);
        }
        Stage1Signal::Command(_) => panic!("/pdf is not a registered command"),
    }
}

#[test]
fn a_deployment_can_shadow_a_built_in_name_with_its_own_registered_command() {
    // If a deployment deliberately registers a command under a name that collides with a built-in
    // (e.g. "doc"), its own definition wins — a more specific, deliberately-authored match always
    // takes priority over the platform's generic fallback.
    let mut reg = CommandPipelineRegistry::new();
    reg.register(CommandPipelineDef::new(
        "doc",
        vec![CommandStep::new("Custom doc macro: {args}")],
    ));
    let signal = stage1_signal_with_commands("/doc quarterly summary", &reg).unwrap();
    match signal {
        Stage1Signal::Command(m) => {
            assert_eq!(
                m.expanded_steps,
                vec!["Custom doc macro: quarterly summary".to_string()]
            );
        }
        Stage1Signal::Intent(_) => panic!("the deployment's own registered `doc` command must win"),
    }
}

#[test]
fn plain_prose_with_no_slash_and_no_registered_command_yields_no_signal() {
    let reg = registry_with_incident_report();
    assert!(stage1_signal_with_commands("what happened last night", &reg).is_none());
}
