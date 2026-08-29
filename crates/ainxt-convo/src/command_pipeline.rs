// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-AUDIT data-surfaces-artifacts (command-pipelines unbuilt): `IMPLEMENTATION_GAP_AUDIT.md`
//! "Command Pipelines (slash-command macros as git-native definitions) are absent" — no
//! `CommandPipeline`/`command_pipeline` symbol existed anywhere in the workspace before this module.
//! [`stage1_signal`](crate::stage1_signal) recognized only the FIXED built-in slash commands baked
//! directly into [`slash_command_format`](crate::slash_command_format) (`/pdf`, `/doc`, `/ppt`,
//! `/xlsx`) — there was no parameterized, reusable, git-native step-sequence concept a deployment
//! could define its OWN slash-command macro with (e.g. `/standup`, `/incident-report`) without a code
//! change to this crate.
//!
//! [`CommandPipelineDef`] is the resolved, in-memory struct the runtime reasons about — in production
//! this is the front-matter + body of a git-native `commands/<name>/definition.md` (ADR-026), the SAME
//! posture `ainxt_skill::SkillManifest`'s own doc comment describes ("in production this is the
//! front-matter of a git-native `definition.md`; here it is the resolved struct the runtime reasons
//! about"): the git-file→struct parse is a control-plane concern this crate does not own. What this
//! crate owns — and what was genuinely missing — is the resolved manifest, the registry, RECOGNIZING a
//! message as invoking one ahead of the fixed built-ins, and EXPANDING its ordered steps with the
//! caller's arguments (and prior steps' output) substituted in.

use std::collections::BTreeMap;

/// One step of a command pipeline: a prompt template. `{args}` is substituted with the raw text after
/// the slash trigger; `{step_N}` (1-indexed) is substituted with the Nth PRIOR step's own expanded
/// text — so a later step can chain off an earlier one's prompt, the same `{step_id}` output-chaining
/// discipline the platform's DAG workflow engine uses for its own step references.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandStep {
    pub prompt_template: String,
}

impl CommandStep {
    pub fn new(prompt_template: impl Into<String>) -> Self {
        CommandStep {
            prompt_template: prompt_template.into(),
        }
    }
}

/// A named, reusable, git-native slash-command macro (ADR-026): an ordered sequence of steps a single
/// `/name <args>` invocation expands into.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandPipelineDef {
    pub name: String,
    #[allow(dead_code)]
    pub description: String,
    pub steps: Vec<CommandStep>,
}

impl CommandPipelineDef {
    pub fn new(name: impl Into<String>, steps: Vec<CommandStep>) -> Self {
        CommandPipelineDef {
            name: name.into(),
            description: String::new(),
            steps,
        }
    }
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }
}

/// The catalog of registered command pipelines. Source of truth is the git-native control plane
/// (ADR-026); this is the in-memory projection the runtime consults — mirroring
/// `ainxt_skill::SkillRegistry`'s own "in-memory projection of the git-native control plane" posture.
#[derive(Debug, Default, Clone)]
pub struct CommandPipelineRegistry {
    commands: BTreeMap<String, CommandPipelineDef>,
}

impl CommandPipelineRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a command pipeline. Names are matched case-insensitively (slash commands are
    /// conventionally typed lowercase, but a deployment's manifest should not have to enforce that).
    pub fn register(&mut self, def: CommandPipelineDef) {
        self.commands.insert(def.name.to_lowercase(), def);
    }

    pub fn get(&self, name: &str) -> Option<&CommandPipelineDef> {
        self.commands.get(&name.to_lowercase())
    }

    pub fn len(&self) -> usize {
        self.commands.len()
    }

    pub fn is_empty(&self) -> bool {
        self.commands.is_empty()
    }
}

/// A message matched a registered command pipeline: the definition it matched and its steps, fully
/// expanded (arguments + prior-step chaining already resolved) — ready for a caller to drive each
/// entry through a model turn in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandMatch {
    pub name: String,
    pub expanded_steps: Vec<String>,
}

/// Expand a matched pipeline's steps against `args` (the raw text after the slash trigger), resolving
/// `{args}` and `{step_N}` (1-indexed, PRIOR steps only — a template can never reference itself or a
/// later step, so expansion is always a single deterministic left-to-right pass with no cycles
/// possible by construction) placeholders.
///
/// This is real, tested expansion, not a stub — but it stops at producing the ordered prompt text: the
/// multi-turn LLM execution loop that actually drives each expanded prompt through a model call and
/// feeds its REAL response back in as `{step_N}` for the next step is a live-wiring concern (the same
/// `needs_hot_wiring` posture `ainxt_runtimed::governed::compile_served_fabric` itself declares for its
/// own deferred `/v1/chat` mount) — a step's own text is all this offline, deterministic layer can
/// resolve `{step_N}` to; feeding back a step's actual MODEL OUTPUT instead is that composition root's
/// job once it exists.
pub fn expand(def: &CommandPipelineDef, args: &str) -> Vec<String> {
    let mut expanded: Vec<String> = Vec::with_capacity(def.steps.len());
    for step in &def.steps {
        let mut text = step.prompt_template.replace("{args}", args);
        for (i, prior) in expanded.iter().enumerate() {
            text = text.replace(&format!("{{step_{}}}", i + 1), prior);
        }
        expanded.push(text);
    }
    expanded
}

/// Recognize `message` as invoking a REGISTERED command pipeline: a leading `/name` whose `name`
/// matches an entry in `registry`. Matches only the first whitespace-delimited token (mirroring
/// [`crate::slash_command_format`]'s own "a `/pdf` mentioned mid-sentence is not a command" rule), so
/// a stray slash in prose never misfires. Returns `None` (never a partial/best-effort match) when no
/// registered command's name matches — the caller falls through to the platform's fixed built-ins.
pub fn match_command(message: &str, registry: &CommandPipelineRegistry) -> Option<CommandMatch> {
    let trimmed = message.trim_start();
    let first = trimmed.split_whitespace().next()?;
    let name = first.strip_prefix('/')?;
    let def = registry.get(name)?;
    let args = trimmed[first.len()..].trim();
    Some(CommandMatch {
        name: def.name.clone(),
        expanded_steps: expand(def, args),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn standup_registry() -> CommandPipelineRegistry {
        let mut reg = CommandPipelineRegistry::new();
        reg.register(
            CommandPipelineDef::new(
                "standup",
                vec![
                    CommandStep::new("Summarize yesterday's commits for {args}"),
                    CommandStep::new(
                        "Given this summary:\n{step_1}\nDraft a 3-bullet standup update",
                    ),
                ],
            )
            .with_description("Generate a standup update from recent commits"),
        );
        reg
    }

    #[test]
    fn match_command_recognizes_a_registered_slash_trigger_and_extracts_args() {
        let reg = standup_registry();
        let m =
            match_command("/standup team-payments", &reg).expect("registered command must match");
        assert_eq!(m.name, "standup");
        assert_eq!(m.expanded_steps.len(), 2);
        assert_eq!(
            m.expanded_steps[0],
            "Summarize yesterday's commits for team-payments"
        );
    }

    #[test]
    fn match_command_chains_a_later_step_off_an_earlier_steps_expanded_text() {
        let reg = standup_registry();
        let m = match_command("/standup team-payments", &reg).unwrap();
        // Step 2's {step_1} placeholder resolved to step 1's OWN expanded text (which itself already
        // had {args} substituted) — proving real chaining, not just independent per-step substitution.
        assert_eq!(
            m.expanded_steps[1],
            "Given this summary:\nSummarize yesterday's commits for team-payments\nDraft a 3-bullet standup update"
        );
    }

    #[test]
    fn match_command_is_case_insensitive_and_ignores_a_mid_sentence_slash() {
        let reg = standup_registry();
        assert!(
            match_command("/STANDUP eng", &reg).is_some(),
            "trigger matching is case-insensitive"
        );
        assert!(
            match_command("please run /standup later", &reg).is_none(),
            "a slash mentioned mid-sentence is not a command, mirroring slash_command_format's own rule"
        );
    }

    #[test]
    fn match_command_returns_none_for_an_unregistered_trigger() {
        let reg = standup_registry();
        assert!(match_command("/incident-report db-outage", &reg).is_none());
        assert!(match_command("hello there", &reg).is_none());
    }

    #[test]
    fn expand_with_no_args_and_no_chaining_placeholders_is_a_pure_pass_through() {
        let def = CommandPipelineDef::new("ping", vec![CommandStep::new("Reply with pong")]);
        assert_eq!(expand(&def, ""), vec!["Reply with pong".to_string()]);
    }
}
