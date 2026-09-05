// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-cli — the headless CLI (Phase 4), library half.
//!
//! `ainxt` is a **headless** binary — for SSH boxes, air-gapped hosts and CI, not an interactive TUI
//! (the desktop app is the rich surface). It docks into the runtime over HTTP/SSE and runs a single
//! turn per invocation. This library holds the pure, testable logic — argument parsing,
//! input/session resolution, event rendering, exit codes — plus [`run_cli`], the async
//! orchestrator; `main.rs` is a thin shell around it.
//!
//! Output modes: `--print` (the final text, default) and `--json` (NDJSON — one protocol event per
//! line, for pipelines). Exit codes are deterministic so CI can branch on them.
//!
//! Clean-room: the flag set, output framing, and exit-code contract are original to AiNxt.

use std::io::Write;
use std::sync::Arc;

use ainxt_client::{Client, ClientConfig};
use ainxt_protocol::{Event, WireEvent};
use ainxt_runtime::engine_with_defaults;
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_session::{SessionConfig, SessionManager};
use ainxt_types::{DataClass, Principal};
use futures_util::StreamExt;
use tokio::sync::mpsc;

/// Exit codes (a stable contract CI can branch on).
pub const EXIT_OK: i32 = 0;
pub const EXIT_TURN_ERROR: i32 = 1;
pub const EXIT_USAGE: i32 = 2;
pub const EXIT_BACKPRESSURE: i32 = 3;

const DEFAULT_SESSION: &str = "ainxt-cli";

/// How output is rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMode {
    /// Print only the final answer text (default).
    Print,
    /// Emit every protocol event as one JSON object per line (NDJSON).
    Json,
}

/// A parsed `run` invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliCommand {
    /// The prompt, or `None`/`Some("-")` to read stdin.
    pub prompt: Option<String>,
    pub mode: OutputMode,
    /// Resume the previous session (its id is read from the session state file).
    pub continue_session: bool,
    /// An explicit session id (overrides `--continue`).
    pub session: Option<String>,
    pub data_class: DataClass,
}

/// A harness authoring subcommand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HarnessSub {
    /// Validate a manifest against the ADR-026 schema/consistency rules (CI `manifest-lint`).
    Lint,
    /// Lint, run the pre-receive PII/secret gate, and emit the publish Pull Request descriptor.
    Publish,
    /// Run the harness locally against the embedded (offline) runtime — the dev loop.
    Dev,
    /// Local acceptance smoke: lint + run against the embedded runtime and assert the run reaches a
    /// Completed outcome, emitting a deterministic PASS/FAIL + exit code for CI/dev without a server.
    Test,
}

/// A parsed `harness` invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessCommand {
    pub sub: HarnessSub,
    /// Path to the harness manifest (JSON).
    pub path: String,
    pub mode: OutputMode,
    pub data_class: DataClass,
    /// `harness dev --watch`: re-run the harness whenever the manifest file changes (the local
    /// hot-reload loop). Ignored by `lint`/`publish`/`test`.
    pub watch: bool,
}

/// The target of an `sdk` invocation: emit a language binding, or the raw contract descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdkTarget {
    /// Generate the Python SDK binding source (Python ships first — the platform's primary ecosystem).
    Python,
    /// Generate the TypeScript SDK binding source (IDE extension + web tooling).
    Typescript,
    /// Emit the machine-readable contract descriptor as JSON (the codegen input artifact).
    Contract,
}

/// A parsed `sdk` invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SdkCommand {
    pub target: SdkTarget,
}

/// The result of parsing argv.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parsed {
    Run(CliCommand),
    Harness(HarnessCommand),
    Sdk(SdkCommand),
    Help,
    Version,
}

/// A usage error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliError(pub String);

pub const HELP: &str = "\
ainxt — headless AiNxt runtime CLI

USAGE:
    ainxt run [PROMPT] [OPTIONS]
    echo \"prompt\" | ainxt run [OPTIONS]
    ainxt harness <lint|publish|dev|test> <MANIFEST.json> [OPTIONS]
    ainxt sdk <emit <python|typescript> | contract>

OPTIONS:
    --print              Print the final answer text (default)
    --json               Emit each event as JSON, one per line
    --continue           Resume the previous session
    --session <ID>       Use an explicit session id
    --data-class <CLASS> public | internal | confidential | regulated-payment | pii
    AINXT_RUNTIME_URL    Runtime chat endpoint (default http://127.0.0.1:8080/v1/chat)
    AINXT_USER           Trusted-gateway user (default cli)
    AINXT_ROLE           Trusted-gateway role (default engineer)
    AINXT_DEPARTMENT     Trusted-gateway department (default engineering)
    AINXT_CAPS           Trusted-gateway caps, comma-separated (default chat.send)
    AINXT_CLEARANCE      Trusted-gateway clearance (default public)
    -h, --help           Show this help
    -V, --version        Show version

HARNESS:
    ainxt harness lint <MANIFEST.json>      Validate a manifest (ADR-026 manifest-lint)
    ainxt harness publish <MANIFEST.json>   Lint + pre-receive gate + emit the publish PR descriptor
    ainxt harness dev <MANIFEST.json>       Run the harness locally against the offline runtime
    ainxt harness dev <MANIFEST.json> --watch  Hot-reload: re-run on every manifest change
    ainxt harness test <MANIFEST.json>      Local acceptance smoke (PASS/FAIL + exit code)

SDK (the Python + TypeScript SDKs mirror this same wire contract):
    ainxt sdk emit python                   Generate the Python SDK binding source
    ainxt sdk emit typescript               Generate the TypeScript SDK binding source
    ainxt sdk contract                      Emit the machine-readable contract descriptor (JSON)

EXIT CODES:
    0 ok   1 turn error / lint failure   2 usage error   3 runtime at capacity
";

fn parse_data_class(s: &str) -> Result<DataClass, CliError> {
    match s {
        "public" => Ok(DataClass::Public),
        "internal" => Ok(DataClass::Internal),
        "confidential" => Ok(DataClass::Confidential),
        "regulated-payment" => Ok(DataClass::RegulatedPayment),
        "pii" => Ok(DataClass::Pii),
        other => Err(CliError(format!("unknown data class '{other}'"))),
    }
}

/// Parse CLI arguments (excluding the program name). Empty argv, or flags with no `run`/prompt, yield
/// [`Parsed::Help`].
pub fn parse_args(argv: &[String]) -> Result<Parsed, CliError> {
    if argv.is_empty() {
        return Ok(Parsed::Help);
    }

    if argv[0] == "harness" {
        return parse_harness(&argv[1..]);
    }

    if argv[0] == "sdk" {
        return parse_sdk(&argv[1..]);
    }

    let mut mode = OutputMode::Print;
    let mut continue_session = false;
    let mut session = None;
    let mut data_class = DataClass::Internal;
    let mut prompt: Option<String> = None;
    let mut saw_run = false;

    let mut i = 0;

    while i < argv.len() {
        let a = argv[i].as_str();

        match a {
            "-h" | "--help" => return Ok(Parsed::Help),
            "-V" | "--version" => return Ok(Parsed::Version),

            "run" if !saw_run && prompt.is_none() => {
                saw_run = true;
            }

            "--print" => {
                mode = OutputMode::Print;
            }

            "--json" => {
                mode = OutputMode::Json;
            }

            "--continue" => {
                continue_session = true;
            }

            "--session" => {
                i += 1;
                session = Some(
                    argv.get(i)
                        .ok_or_else(|| CliError("--session requires a value".into()))?
                        .clone(),
                );
            }

            "--data-class" => {
                i += 1;

                let v = argv
                    .get(i)
                    .ok_or_else(|| CliError("--data-class requires a value".into()))?;

                data_class = parse_data_class(v)?;
            }

            "-" => {
                prompt = Some("-".to_string());
            }

            s if s.starts_with("--") => {
                return Err(CliError(format!("unknown flag: {s}")));
            }

            s => {
                if prompt.is_some() {
                    return Err(CliError("more than one prompt given".into()));
                }

                prompt = Some(s.to_string());
            }
        }

        i += 1;
    }

    if !saw_run && prompt.is_none() {
        return Ok(Parsed::Help);
    }

    Ok(Parsed::Run(CliCommand {
        prompt,
        mode,
        continue_session,
        session,
        data_class,
    }))
}

/// Parse a `harness` invocation (argv after the `harness` word).
fn parse_harness(rest: &[String]) -> Result<Parsed, CliError> {
    let sub = match rest.first().map(String::as_str) {
        Some("lint") => HarnessSub::Lint,
        Some("publish") => HarnessSub::Publish,
        Some("dev") => HarnessSub::Dev,
        Some("test") => HarnessSub::Test,
        Some("-h") | Some("--help") | None => return Ok(Parsed::Help),
        Some(other) => return Err(CliError(format!("unknown harness subcommand '{other}'"))),
    };

    let mut mode = OutputMode::Print;
    let mut data_class = DataClass::Internal;
    let mut path: Option<String> = None;
    let mut watch = false;

    let mut i = 1;

    while i < rest.len() {
        let a = rest[i].as_str();

        match a {
            "--print" => {
                mode = OutputMode::Print;
            }

            "--json" => {
                mode = OutputMode::Json;
            }

            "--watch" => {
                watch = true;
            }

            "--data-class" => {
                i += 1;

                let v = rest
                    .get(i)
                    .ok_or_else(|| CliError("--data-class requires a value".into()))?;

                data_class = parse_data_class(v)?;
            }

            s if s.starts_with("--") => {
                return Err(CliError(format!("unknown flag: {s}")));
            }

            s => {
                if path.is_some() {
                    return Err(CliError("more than one manifest path given".into()));
                }

                path = Some(s.to_string());
            }
        }

        i += 1;
    }

    let path = path.ok_or_else(|| CliError("a manifest path is required".into()))?;

    Ok(Parsed::Harness(HarnessCommand {
        sub,
        path,
        mode,
        data_class,
        watch,
    }))
}

/// Parse an `sdk` invocation (argv after the `sdk` word):
///   `ainxt sdk emit <python|typescript>` · `ainxt sdk contract`
fn parse_sdk(rest: &[String]) -> Result<Parsed, CliError> {
    match rest.first().map(String::as_str) {
        Some("emit") => {
            let target = match rest.get(1).map(String::as_str) {
                Some("python") | Some("py") => SdkTarget::Python,

                Some("typescript") | Some("ts") => SdkTarget::Typescript,

                Some(other) => {
                    return Err(CliError(format!(
                        "unknown sdk language '{other}' (expected python|typescript)"
                    )))
                }

                None => return Err(CliError("sdk emit requires a language".into())),
            };

            Ok(Parsed::Sdk(SdkCommand { target }))
        }

        Some("contract") => Ok(Parsed::Sdk(SdkCommand {
            target: SdkTarget::Contract,
        })),

        Some("-h") | Some("--help") | None => Ok(Parsed::Help),

        Some(other) => Err(CliError(format!("unknown sdk subcommand '{other}'"))),
    }
}

/// Emit the generated SDK binding (or the contract descriptor JSON) to `out`.
/// Pure codegen over the contract — fully offline, no network or model.
/// Returns the deterministic exit code.
fn run_sdk_cmd<W: Write>(cmd: &SdkCommand, out: &mut W) -> i32 {
    let desc = ainxt_client::sdk_contract::contract_descriptor();

    let text = match cmd.target {
        SdkTarget::Python => ainxt_client::sdk_contract::emit_python_sdk(&desc),

        SdkTarget::Typescript => ainxt_client::sdk_contract::emit_typescript_sdk(&desc),

        SdkTarget::Contract => match serde_json::to_string_pretty(&desc) {
            Ok(j) => j,

            Err(e) => {
                let _ = writeln!(out, "error: contract serialize failed: {e}");

                return EXIT_TURN_ERROR;
            }
        },
    };

    let _ = writeln!(out, "{text}");

    EXIT_OK
}

/// Resolve the turn input: the prompt, or stdin when the prompt is absent or `-`.
pub fn resolve_input(cmd: &CliCommand, stdin: &str) -> String {
    match &cmd.prompt {
        Some(p) if p != "-" => p.clone(),
        _ => stdin.trim_end_matches('\n').to_string(),
    }
}

/// Resolve the session id: explicit `--session` wins; else `--continue` reuses `last`; else the
/// default session.
pub fn resolve_session(cmd: &CliCommand, last: Option<&str>) -> String {
    if let Some(s) = &cmd.session {
        return s.clone();
    }

    if cmd.continue_session {
        if let Some(l) = last {
            return l.to_string();
        }
    }

    DEFAULT_SESSION.to_string()
}

/// One NDJSON line for a protocol event.
pub fn render_event_json(event: &Event) -> String {
    serde_json::to_string(event).unwrap_or_else(|e| format!("{{\"Error\":\"serialize: {e}\"}}"))
}

// ---- offline provider (harness / air-gap / no model configured) ----

/// A deterministic provider that runs with no network.
///
/// This remains available for the harness `dev`/`test` paths, which intentionally
/// execute against the embedded offline runtime.
pub struct OfflineProvider;

impl Provider for OfflineProvider {
    fn id(&self) -> &str {
        "offline"
    }

    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }

    fn stream(&self, _prompt: &str) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(8);

        tokio::spawn(async move {
            let _ = tx
                .send(Event::TextDelta(
                    "offline mode: no model is configured.".into(),
                ))
                .await;

            let _ = tx
                .send(Event::Usage {
                    input_tokens: 0,
                    output_tokens: 8,
                })
                .await;

            let _ = tx.send(Event::Done).await;
        });

        rx
    }
}

fn build_offline_client_with_caps(data_class: DataClass, caps: &[&str]) -> Client {
    let mut router = ModelRouter::new();

    router.register(Box::new(OfflineProvider));

    let manager = Arc::new(SessionManager::new(
        Arc::new(engine_with_defaults(router)),
        SessionConfig::default(),
    ));

    let config = ClientConfig {
        default_data_class: data_class,
        ..Default::default()
    };

    Client::in_process(manager, Principal::user("cli", caps), config)
}

// ---- session state persistence (for --continue) ----

fn session_state_path() -> Option<String> {
    std::env::var("AINXT_SESSION_FILE")
        .ok()
        .filter(|s| !s.is_empty())
}

fn load_last_session() -> Option<String> {
    session_state_path()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn save_last_session(id: &str) {
    if let Some(p) = session_state_path() {
        let _ = std::fs::write(p, id);
    }
}

/// Run the CLI end-to-end.
pub async fn run_cli<W: Write>(argv: &[String], stdin: &str, out: &mut W) -> i32 {
    match parse_args(argv) {
        Err(CliError(msg)) => {
            let _ = writeln!(out, "error: {msg}\n\n{HELP}");
            EXIT_USAGE
        }

        Ok(Parsed::Help) => {
            let _ = write!(out, "{HELP}");
            EXIT_OK
        }

        Ok(Parsed::Version) => {
            let _ = writeln!(
                out,
                "ainxt {} (protocol v{})",
                env!("CARGO_PKG_VERSION"),
                ainxt_protocol::VERSION
            );

            EXIT_OK
        }

        Ok(Parsed::Run(cmd)) => run_turn(&cmd, stdin, out).await,

        Ok(Parsed::Harness(cmd)) => run_harness_cmd(&cmd, out).await,

        Ok(Parsed::Sdk(cmd)) => run_sdk_cmd(&cmd, out),
    }
}

// ---- harness authoring subcommand ----

/// Parse + lint a manifest from its JSON source.
/// Returns the manifest, or a rendered error listing.
pub fn parse_and_lint(json: &str) -> Result<ainxt_admission::HarnessManifest, String> {
    let manifest: ainxt_admission::HarnessManifest =
        serde_json::from_str(json).map_err(|e| format!("manifest parse error: {e}"))?;

    match ainxt_admission::lint_manifest(&manifest) {
        Ok(()) => Ok(manifest),

        Err(findings) => {
            let mut msg = String::from("lint failed:");

            for f in &findings {
                msg.push_str(&format!("\n  {f}"));
            }

            Err(msg)
        }
    }
}

async fn run_harness_cmd<W: Write>(cmd: &HarnessCommand, out: &mut W) -> i32 {
    let json = match std::fs::read_to_string(&cmd.path) {
        Ok(s) => s,

        Err(e) => {
            let _ = writeln!(out, "error: cannot read '{}': {e}", cmd.path);

            return EXIT_TURN_ERROR;
        }
    };

    match cmd.sub {
        HarnessSub::Lint => match parse_and_lint(&json) {
            Ok(m) => {
                let _ = writeln!(out, "lint: ok ({} v{})", m.id, m.version);

                EXIT_OK
            }

            Err(msg) => {
                let _ = writeln!(out, "error: {msg}");
                EXIT_TURN_ERROR
            }
        },

        HarnessSub::Publish => {
            let manifest = match parse_and_lint(&json) {
                Ok(m) => m,

                Err(msg) => {
                    let _ = writeln!(out, "error: {msg}");
                    return EXIT_TURN_ERROR;
                }
            };

            let pr = ainxt_governance::publish(ainxt_governance::PublishRequest {
                definition_id: manifest.id.clone(),
                branch: format!("publish/{}", manifest.id),
                path: cmd.path.clone(),
                content: json.clone(),
            });

            if let Err(findings) =
                ainxt_governance::gate_push(&pr, &ainxt_governance::MarkerPrereceiveGate)
            {
                let _ = writeln!(
                    out,
                    "error: pre-receive gate blocked publish (git history is permanent):"
                );

                for f in &findings {
                    let _ = writeln!(out, "  {f}");
                }

                return EXIT_TURN_ERROR;
            }

            match cmd.mode {
                OutputMode::Json => {
                    let _ = writeln!(
                        out,
                        "{}",
                        serde_json::to_string(&pr)
                            .unwrap_or_else(|e| { format!("{{\"error\":\"{e}\"}}") })
                    );
                }

                OutputMode::Print => {
                    let _ = writeln!(
                        out,
                        "publish: opened PR '{}' ({} -> {}), {} file(s). PENDING_APPROVAL: CI + CODEOWNERS review.",
                        pr.title,
                        pr.branch,
                        pr.target,
                        pr.files.len()
                    );
                }
            }

            EXIT_OK
        }

        HarnessSub::Dev => {
            if cmd.watch {
                run_harness_dev_watch(cmd, out, real_file_poller(&cmd.path)).await
            } else {
                let (report, exit) = match run_harness_offline(&json, cmd.data_class).await {
                    Ok(r) => r,

                    Err(msg) => {
                        let _ = writeln!(out, "error: {msg}");
                        return EXIT_TURN_ERROR;
                    }
                };

                let _ = writeln!(out, "dev: {}", report.outcome);

                for (i, step_out) in report.step_outputs.iter().enumerate() {
                    let _ = writeln!(out, "  step {}: {}", i + 1, step_out.trim());
                }

                exit
            }
        }

        HarnessSub::Test => {
            let (report, _exit) = match run_harness_offline(&json, cmd.data_class).await {
                Ok(r) => r,

                Err(msg) => {
                    let _ = writeln!(out, "test: FAIL ({msg})");

                    return EXIT_TURN_ERROR;
                }
            };

            if report.outcome.is_completed() {
                let _ = writeln!(
                    out,
                    "test: PASS ({} step(s) ran, outcome={})",
                    report.step_outputs.len(),
                    report.outcome
                );

                EXIT_OK
            } else {
                let _ = writeln!(out, "test: FAIL (outcome={})", report.outcome);

                EXIT_TURN_ERROR
            }
        }
    }
}

/// Run a harness manifest once against the embedded offline runtime.
pub async fn run_harness_offline(
    json: &str,
    data_class: DataClass,
) -> Result<(ainxt_client::HarnessRunReport, i32), String> {
    let manifest = parse_and_lint(json)?;

    let mut caps: Vec<&str> = vec!["chat.send"];

    caps.extend(manifest.requested_capabilities.iter().map(String::as_str));

    let client = build_offline_client_with_caps(data_class, &caps);

    let runtime = ainxt_admission::HarnessRuntime::new(
        Box::new(ainxt_admission::CapabilityAuthorizer),
        Box::new(ainxt_admission::InMemoryHarnessAudit::new()),
    );

    let grant = ainxt_admission::CapabilityGrant::new(manifest.requested_capabilities.clone());

    let report = client
        .run_harness(
            &runtime,
            &manifest,
            &grant,
            &ainxt_admission::RunContext::new(data_class),
            "ainxt-admission-dev",
        )
        .await;

    let exit = if report.outcome.is_completed() {
        EXIT_OK
    } else {
        EXIT_TURN_ERROR
    };

    Ok((report, exit))
}

/// The reload DECISION for one hot-reload iteration.
pub fn dev_should_reload(prev: Option<&str>, current: &str) -> bool {
    prev != Some(current)
}

/// One poll of the manifest source.
pub type DevPoll<'a> = Box<dyn FnMut() -> Option<String> + Send + 'a>;

/// A real file poller for `harness dev --watch`.
fn real_file_poller(path: &str) -> DevPoll<'static> {
    let path = path.to_string();
    let mut started = false;

    Box::new(move || {
        if started {
            std::thread::sleep(std::time::Duration::from_millis(500));
        }

        started = true;

        std::fs::read_to_string(&path).ok()
    })
}

/// The hot-reload loop.
pub async fn run_harness_dev_watch<W: Write>(
    cmd: &HarnessCommand,
    out: &mut W,
    mut poll: DevPoll<'_>,
) -> i32 {
    let _ = writeln!(out, "dev --watch: hot-reload loop for '{}'", cmd.path);

    let mut prev: Option<String> = None;
    let mut last_exit = EXIT_TURN_ERROR;
    let mut runs = 0u32;

    while let Some(current) = poll() {
        if !dev_should_reload(prev.as_deref(), &current) {
            continue;
        }

        runs += 1;

        let _ = writeln!(out, "dev --watch: change #{runs} — re-running");

        match run_harness_offline(&current, cmd.data_class).await {
            Ok((report, exit)) => {
                let _ = writeln!(out, "dev: {}", report.outcome);

                last_exit = exit;
            }

            Err(msg) => {
                let _ = writeln!(out, "error: {msg}");

                last_exit = EXIT_TURN_ERROR;
            }
        }

        prev = Some(current);
    }

    last_exit
}

// ---- HTTP/SSE runtime client ----

fn runtime_chat_url() -> String {
    std::env::var("AINXT_RUNTIME_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "http://127.0.0.1:8080/v1/chat".to_string())
}

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name)
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| default.to_string())
}

/// Map the wire protocol used by the runtime to the legacy client Event
/// representation used by the CLI renderer.
fn wire_event_to_legacy(event: WireEvent) -> Option<Event> {
    match event {
        WireEvent::TextDelta { text } => Some(Event::TextDelta(text)),

        WireEvent::ReasoningDelta { text } => Some(Event::ReasoningDelta(text)),

        WireEvent::ToolCallStart { call_id, name, .. } => Some(Event::ToolCallStart {
            id: call_id,
            name,
            args: String::new(),
        }),

        WireEvent::ToolCallStop { call_id, args } => Some(Event::ToolCallStart {
            id: call_id,
            name: String::new(),
            args,
        }),

        WireEvent::ToolResult {
            call_id, blocks, ..
        } => Some(Event::ToolResult {
            id: call_id,
            output: serde_json::to_string(&blocks).unwrap_or_default(),
        }),

        WireEvent::ApprovalRequest {
            approval_id,
            action,
            scope,
            ..
        } => Some(Event::ApprovalRequest {
            id: approval_id,
            summary: format!("{action}: {scope}"),
        }),

        WireEvent::Usage {
            input_tokens,
            output_tokens,
            ..
        } => Some(Event::Usage {
            input_tokens,
            output_tokens,
        }),

        WireEvent::TurnFailed { error, .. } => Some(Event::Error(format!(
            "{}: {}",
            serde_json::to_string(&error.category).unwrap_or_else(|_| "error".into()),
            error.message
        ))),

        WireEvent::Error(error) => Some(Event::Error(error.message)),

        WireEvent::TurnCompleted { .. } => Some(Event::Done),

        _ => None,
    }
}

/// Execute a single turn against the running AiNxt runtime.
///
/// The CLI is a headless frontend, so production `run` requests are sent to
/// `/v1/chat` over HTTP and consumed as an SSE stream.
async fn run_turn<W: Write>(cmd: &CliCommand, stdin: &str, out: &mut W) -> i32 {
    let input = resolve_input(cmd, stdin);

    if input.trim().is_empty() {
        let _ = writeln!(out, "error: no input (give a PROMPT or pipe one on stdin)");

        return EXIT_USAGE;
    }

    let session = resolve_session(cmd, load_last_session().as_deref());

    let turn = format!("t-{}", std::process::id());

    let url = runtime_chat_url();

    let user = env_or("AINXT_USER", "cli");
    let role = env_or("AINXT_ROLE", "engineer");
    let department = env_or("AINXT_DEPARTMENT", "engineering");
    let caps = env_or("AINXT_CAPS", "chat.send");
    let clearance = env_or("AINXT_CLEARANCE", "public");

    let caps_json: Vec<&str> = caps
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();

    let payload = serde_json::json!({
        "session": &session,
        "turn": &turn,
        "input": &input,
        "data_class": cmd.data_class,
        "caps": caps_json,
    });

    let client = reqwest::Client::new();

    let response = match client
        .post(&url)
        .header("content-type", "application/json")
        .header("X-AInxt-User", &user)
        .header("X-AInxt-Role", &role)
        .header("X-AInxt-Department", &department)
        .header("X-AInxt-Caps", &caps)
        .header("X-AInxt-Clearance", &clearance)
        .json(&payload)
        .send()
        .await
    {
        Ok(r) => r,

        Err(e) => {
            let _ = writeln!(out, "error: runtime transport failed: {e}");

            return EXIT_TURN_ERROR;
        }
    };

    if response.status() == reqwest::StatusCode::SERVICE_UNAVAILABLE {
        let body = response.text().await.unwrap_or_default();

        let _ = writeln!(out, "error: runtime at capacity: {body}");

        return EXIT_BACKPRESSURE;
    }

    if !response.status().is_success() {
        let status = response.status();

        let body = response.text().await.unwrap_or_default();

        let _ = writeln!(out, "error: runtime returned HTTP {status}: {body}");

        return EXIT_TURN_ERROR;
    }

    let mut bytes = response.bytes_stream();

    let mut buffer = String::new();
    let mut error: Option<String> = None;
    let mut final_text = String::new();

    while let Some(chunk) = bytes.next().await {
        let chunk = match chunk {
            Ok(c) => c,

            Err(e) => {
                let _ = writeln!(out, "error: SSE stream failed: {e}");

                return EXIT_TURN_ERROR;
            }
        };

        buffer.push_str(&String::from_utf8_lossy(&chunk));

        while let Some(pos) = buffer.find('\n') {
            let line = buffer[..pos].trim_end_matches('\r').to_string();

            buffer.drain(..=pos);

            if !line.starts_with("data: ") {
                continue;
            }

            let json = &line[6..];

            // First parse into Value rather than directly into EventEnvelope.
            //
            // The runtime currently emits some events with duplicate `turn_id`
            // fields because EventEnvelope flattens WireEvent variants that
            // themselves contain turn_id. serde_json::Value accepts the JSON
            // object and retains the final duplicate value, allowing us to
            // continue decoding the envelope.
            let value: serde_json::Value = match serde_json::from_str(json) {
                Ok(v) => v,

                Err(e) => {
                    let _ = writeln!(out, "error: invalid runtime event JSON: {e}");

                    return EXIT_TURN_ERROR;
                }
            };

            // Own the event type before moving `value` into
            // serde_json::from_value(). This avoids borrowing `value`
            // across the move.
            let event_type = value
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("<unknown>")
                .to_string();

            // Decode directly into WireEvent. The runtime event JSON may contain
            // duplicate turn_id keys on the wire, but serde_json::Value has already
            // normalized the object and retained a single turn_id for the variant.
            let wire_event: WireEvent = match serde_json::from_value(value) {
                Ok(v) => v,

                Err(e) => {
                    let _ = writeln!(out, "error: invalid runtime event type={event_type}: {e}");

                    return EXIT_TURN_ERROR;
                }
            };

            let Some(ev) = wire_event_to_legacy(wire_event) else {
                continue;
            };

            if let Event::TextDelta(text) = &ev {
                final_text.push_str(text);
            }

            if let Event::Error(e) = &ev {
                error = Some(e.clone());
            }

            match cmd.mode {
                OutputMode::Json => {
                    let _ = writeln!(out, "{}", render_event_json(&ev));
                }

                OutputMode::Print => {}
            }
        }
    }

    save_last_session(&session);

    if cmd.mode == OutputMode::Print {
        let _ = writeln!(out, "{}", final_text);
    }

    if error.is_some() {
        EXIT_TURN_ERROR
    } else {
        EXIT_OK
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    // ---- parsing ----

    #[test]
    fn parses_run_with_prompt_and_flags() {
        let p = parse_args(&args(&[
            "run",
            "--json",
            "--data-class",
            "confidential",
            "hello",
        ]))
        .unwrap();

        match p {
            Parsed::Run(c) => {
                assert_eq!(c.prompt.as_deref(), Some("hello"));

                assert_eq!(c.mode, OutputMode::Json);

                assert_eq!(c.data_class, DataClass::Confidential);
            }

            other => {
                panic!("expected Run, got {other:?}")
            }
        }
    }

    #[test]
    fn implicit_run_from_bare_prompt() {
        assert!(matches!(
            parse_args(&args(&["hi"])).unwrap(),
            Parsed::Run(_)
        ));
    }

    #[test]
    fn help_version_and_empty() {
        assert_eq!(parse_args(&args(&[])).unwrap(), Parsed::Help);

        assert_eq!(parse_args(&args(&["-h"])).unwrap(), Parsed::Help);

        assert_eq!(parse_args(&args(&["--help"])).unwrap(), Parsed::Help);

        assert_eq!(parse_args(&args(&["-V"])).unwrap(), Parsed::Version);

        assert_eq!(parse_args(&args(&["--json"])).unwrap(), Parsed::Help);
    }

    #[test]
    fn parse_errors() {
        assert!(parse_args(&args(&["run", "--bogus"])).is_err());

        assert!(parse_args(&args(&["run", "--data-class", "nope"])).is_err());

        assert!(parse_args(&args(&["run", "--session"])).is_err());

        assert!(parse_args(&args(&["run", "a", "b"])).is_err());
    }

    #[test]
    fn continue_and_session_flags() {
        let c = match parse_args(&args(&["run", "--continue"])).unwrap() {
            Parsed::Run(c) => c,
            _ => panic!(),
        };

        assert!(c.continue_session);

        let c2 = match parse_args(&args(&["run", "--session", "abc"])).unwrap() {
            Parsed::Run(c) => c,
            _ => panic!(),
        };

        assert_eq!(c2.session.as_deref(), Some("abc"));
    }

    // ---- input / session resolution ----

    #[test]
    fn resolves_input_from_prompt_or_stdin() {
        let cmd = |p: Option<&str>| CliCommand {
            prompt: p.map(str::to_string),
            mode: OutputMode::Print,
            continue_session: false,
            session: None,
            data_class: DataClass::Internal,
        };

        assert_eq!(resolve_input(&cmd(Some("hi")), "IGNORED"), "hi");

        assert_eq!(resolve_input(&cmd(None), "from stdin\n"), "from stdin");

        assert_eq!(resolve_input(&cmd(Some("-")), "piped\n"), "piped");
    }

    #[test]
    fn resolves_session() {
        let base = CliCommand {
            prompt: None,
            mode: OutputMode::Print,
            continue_session: false,
            session: None,
            data_class: DataClass::Internal,
        };

        assert_eq!(resolve_session(&base, Some("prev")), DEFAULT_SESSION);

        let cont = CliCommand {
            continue_session: true,
            ..base.clone()
        };

        assert_eq!(resolve_session(&cont, Some("prev")), "prev");

        assert_eq!(resolve_session(&cont, None), DEFAULT_SESSION);

        let explicit = CliCommand {
            session: Some("x".into()),
            continue_session: true,
            ..base
        };

        assert_eq!(resolve_session(&explicit, Some("prev")), "x");
    }

    #[test]
    fn renders_event_json() {
        let line = render_event_json(&Event::TextDelta("hi".into()));

        assert!(line.contains("\"TextDelta\":\"hi\""));

        let done = render_event_json(&Event::Done);

        assert_eq!(done, "\"Done\"");
    }

    // ---- harness subcommand ----

    use std::sync::atomic::{AtomicU64, Ordering};

    static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn write_temp(content: &str) -> String {
        let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);

        let tmp_base = std::env::var("AINXT_SCRATCH_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| std::env::temp_dir());

        let path = tmp_base.join(format!("ainxt_cli_harness_{}_{n}.json", std::process::id()));

        std::fs::write(&path, content).expect("write temp manifest");

        path.to_string_lossy().into_owned()
    }

    const VALID_MANIFEST: &str = r#"{
        "id":"rca","version":"1.0.0","owner":"settlement-ops",
        "requested_capabilities":["llm.call"],
        "steps":[{"id":"s1","kind":"llm","capability":"llm.call"}]
    }"#;

    #[test]
    fn parses_harness_subcommands() {
        match parse_args(&args(&["harness", "lint", "m.json"])).unwrap() {
            Parsed::Harness(h) => {
                assert_eq!(h.sub, HarnessSub::Lint);

                assert_eq!(h.path, "m.json");
            }

            other => {
                panic!("expected Harness, got {other:?}")
            }
        }

        assert!(matches!(
            parse_args(&args(&["harness", "publish", "m.json", "--json"])).unwrap(),
            Parsed::Harness(HarnessCommand {
                sub: HarnessSub::Publish,
                mode: OutputMode::Json,
                ..
            })
        ));

        assert!(parse_args(&args(&["harness", "lint"])).is_err());

        assert!(parse_args(&args(&["harness", "frobnicate", "m.json"])).is_err());
    }

    #[test]
    fn parse_and_lint_accepts_valid_rejects_invalid() {
        assert!(parse_and_lint(VALID_MANIFEST).is_ok());

        let bad = r#"{"id":"x","version":"latest","requested_capabilities":["c"],"steps":[{"id":"s","kind":"llm","capability":"c"}]}"#;

        let err = parse_and_lint(bad).unwrap_err();

        assert!(err.contains("owner"), "{err}");

        assert!(err.contains("version"), "{err}");

        let undeclared = r#"{"id":"x","version":"1.0.0","owner":"o","requested_capabilities":[],"steps":[{"id":"s","kind":"tool","capability":"tool.delete"}]}"#;

        assert!(parse_and_lint(undeclared)
            .unwrap_err()
            .contains("undeclared-capability"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn harness_lint_command_ok_and_fail() {
        let path = write_temp(VALID_MANIFEST);

        let mut out = Vec::new();

        assert_eq!(
            run_cli(&args(&["harness", "lint", &path]), "", &mut out).await,
            EXIT_OK
        );

        assert!(String::from_utf8(out).unwrap().contains("lint: ok"));

        let bad = write_temp(
            r#"{"id":"x","version":"1.0.0","requested_capabilities":["c"],"steps":[{"id":"s","kind":"llm","capability":"c"}]}"#,
        );

        let mut out2 = Vec::new();

        assert_eq!(
            run_cli(&args(&["harness", "lint", &bad]), "", &mut out2).await,
            EXIT_TURN_ERROR
        );

        assert!(String::from_utf8(out2).unwrap().contains("owner"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn harness_publish_emits_pr_and_pregate_blocks_pii() {
        let path = write_temp(VALID_MANIFEST);

        let mut out = Vec::new();

        assert_eq!(
            run_cli(&args(&["harness", "publish", &path]), "", &mut out).await,
            EXIT_OK
        );

        assert!(String::from_utf8(out).unwrap().contains("PENDING_APPROVAL"));

        let with_pan = r#"{"id":"rca","version":"1.0.0","owner":"o","description":"card 4111111111111111","requested_capabilities":["llm.call"],"steps":[{"id":"s1","kind":"llm","capability":"llm.call"}]}"#;

        let pan_path = write_temp(with_pan);

        let mut out2 = Vec::new();

        assert_eq!(
            run_cli(&args(&["harness", "publish", &pan_path]), "", &mut out2).await,
            EXIT_TURN_ERROR
        );

        assert!(String::from_utf8(out2)
            .unwrap()
            .contains("pre-receive gate blocked"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn harness_dev_runs_offline_and_completes() {
        let path = write_temp(VALID_MANIFEST);

        let mut out = Vec::new();

        let code = run_cli(&args(&["harness", "dev", &path]), "", &mut out).await;

        let s = String::from_utf8(out).unwrap();

        assert_eq!(code, EXIT_OK, "dev output: {s}");

        assert!(s.contains("completed"), "dev output: {s}");

        assert!(
            s.contains("offline mode"),
            "step output should be the engine turn: {s}"
        );
    }
}
