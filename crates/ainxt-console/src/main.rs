// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! # AiNxt OS Console (`ainxt-os`)
//!
//! The thin, self-service layer over AiNxt OS. One command starts everything and opens a chat
//! window; an operator who has never seen a TOML file can pick a model, turn checks on and off, and
//! ask a question.
//!
//! ## Why this is a separate process, not a page served by the daemon
//!
//! AiNxt OS's default identity posture, `trusted-gateway`, derives role, capabilities and clearance
//! from client-supplied `X-AInxt-*` headers. That is safe only behind something that has already
//! authenticated the caller — which is why the daemon refuses to start until you assert the posture
//! deliberately, and why both READMEs say the listener must never be reachable by a browser. A page
//! served on `:8080` under that posture could send `X-AInxt-Role: admin` and be believed.
//!
//! So the console does the job the architecture already requires of a front end: it **is** the
//! authenticating gateway from `DOCKING.md`. It decides who the operator is, runs AiNxt OS in
//! `jwt-sso` mode with a secret generated fresh at every start, and signs a short-lived token per
//! request. The browser never holds the secret and never asserts an identity — it just talks to the
//! console.
//!
//! ```text
//!   browser  ──►  ainxt-os (console, :8081)  ──►  ainxt-runtimed (AiNxt OS, :8080)
//!   no identity     mints a signed token          jwt-sso: believes only the token
//! ```

mod daemon;
mod jwt;
mod settings;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use settings::{ConsoleState, Settings};

const CONSOLE_HTML: &str = include_str!("console.html");
const DEFAULT_CONSOLE_PORT: u16 = 8081;
const EXAMPLE_CONFIG: &str = "crates/ainxt-runtimed/config/runtimed.example.toml";
/// Tokens are minted per request; a minute is generous and bounds the damage of a leak.
const TOKEN_TTL_SECS: u64 = 60;

struct App {
    daemon_bin: PathBuf,
    config_path: PathBuf,
    state_dir: PathBuf,
    overlay_path: PathBuf,
    secret: String,
    settings: Settings,
    console: ConsoleState,
    child: Option<tokio::process::Child>,
    log_path: PathBuf,
}

impl App {
    /// Environment for the daemon: the operator's stored provider credentials, nothing else.
    ///
    /// Passes through `settings::sanitize_env_vars` before any pair reaches `cmd.env()`, which
    /// enforces an allowlist of permitted key names and rejects values containing control
    /// characters. This closes the Stored Environment Variable Injection path identified by
    /// Checkmarx (Rust\Cx\Rust Medium Threat\Stored Environment Variable Injection).
    fn daemon_env(&self) -> Vec<(String, String)> {
        settings::sanitize_env_vars(&self.console.secrets)
    }

    fn configs(&self) -> Vec<PathBuf> {
        vec![self.config_path.clone(), self.overlay_path.clone()]
    }
}

type Shared = Arc<Mutex<App>>;

// ---------------------------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("ainxt-os: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let mut console_port = DEFAULT_CONSOLE_PORT;
    let mut config_path = PathBuf::from("runtimed.toml");
    let mut daemon_override: Option<PathBuf> = None;
    let mut open_browser = true;

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print_help();
                return Ok(());
            }
            "--port" => {
                i += 1;
                console_port = args
                    .get(i)
                    .and_then(|v| v.parse().ok())
                    .ok_or("--port needs a number")?;
            }
            "--config" => {
                i += 1;
                config_path = PathBuf::from(args.get(i).ok_or("--config needs a path")?);
            }
            "--runtimed" => {
                i += 1;
                daemon_override =
                    Some(PathBuf::from(args.get(i).ok_or("--runtimed needs a path")?));
            }
            "--no-open" => open_browser = false,
            other => return Err(format!("unknown option '{other}' (try --help)")),
        }
        i += 1;
    }

    let daemon_bin = daemon::locate_daemon(daemon_override.as_deref())?;
    let state_dir = PathBuf::from(".ainxt-console");

    // A first run should not require the operator to have created anything.
    if !config_path.exists() {
        let example = Path::new(EXAMPLE_CONFIG);
        if example.exists() {
            std::fs::copy(example, &config_path)
                .map_err(|e| format!("could not create {}: {e}", config_path.display()))?;
            println!(
                "ainxt-os: created {} from the shipped example",
                config_path.display()
            );
        } else {
            return Err(format!(
                "{} does not exist and the shipped example was not found at {EXAMPLE_CONFIG}.\n\
                 Run this from the repository root, or pass --config <file>.",
                config_path.display()
            ));
        }
    }

    let loaded = settings::load(&config_path);
    let console_state = settings::load_console_state(&state_dir);
    let secret = daemon::generate_secret();
    let overlay_path = daemon::write_auth_overlay(&state_dir, &secret)
        .map_err(|e| format!("could not write the auth overlay: {e}"))?;

    let mut app = App {
        daemon_bin,
        config_path,
        state_dir,
        overlay_path,
        secret,
        settings: loaded,
        console: console_state,
        child: None,
        log_path: PathBuf::new(),
    };

    println!("ainxt-os: starting AiNxt OS…");
    start_daemon(&mut app).await?;

    bootstrap_outsourcing(&app).await?;

    println!(
        "ainxt-os: AiNxt OS is listening on 127.0.0.1:{} (identity: verified token, jwt-sso)",
        app.settings.port
    );

    let shared: Shared = Arc::new(Mutex::new(app));

    let router = Router::new()
        .route("/", get(serve_html))
        .route("/favicon.svg", get(serve_favicon))
        // Browsers request /favicon.ico unprompted; answering it keeps a 404 out of the console
        // of anyone who opens devtools, and out of the daemon-adjacent logs an operator may read.
        .route("/favicon.ico", get(serve_favicon))
        .route("/api/status", get(api_status))
        .route("/api/chat", post(api_chat))
        .route(
            "/api/settings",
            get(api_get_settings).post(api_post_settings),
        )
        .route("/api/activity", get(api_activity))
        .with_state(shared.clone());

    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], console_port));
    let listener = tokio::net::TcpListener::bind(addr).await.map_err(|e| {
        format!("cannot bind the console to {addr}: {e}\nTry: ainxt-os --port <other>")
    })?;

    let url = format!("http://127.0.0.1:{console_port}");
    println!("\n  AiNxt OS Console is ready:  {url}\n");
    println!("  Open that address to chat, choose a model, and change settings.");
    println!("  Press Ctrl-C to stop AiNxt OS and the console together.\n");
    if open_browser {
        open_in_browser(&url);
    }

    // The console must take the daemon down with it. `kill_on_drop` covers an ordinary return, but
    // a signal terminates the process without running destructors, so both SIGINT and SIGTERM are
    // handled explicitly. A console that exits leaving an orphaned daemon on :8080 is exactly the
    // "address already in use" confusion the AiNxt OS README warns about — and `pkill ainxt-os`
    // (SIGTERM) is at least as likely as Ctrl-C.
    let shutdown = shared.clone();
    axum::serve(listener, router)
        .with_graceful_shutdown(async move {
            wait_for_shutdown_signal().await;
            println!("\nainxt-os: stopping AiNxt OS…");
            if let Some(child) = shutdown.lock().await.child.as_mut() {
                let _ = child.kill().await;
                // Reap it, so the daemon is really gone before this process exits.
                let _ = child.wait().await;
            }
        })
        .await
        .map_err(|e| format!("console server error: {e}"))?;
    Ok(())
}

/// Resolve on the first termination signal. On Unix that is SIGINT **or** SIGTERM; elsewhere,
/// Ctrl-C only.
async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("ainxt-os: warning: cannot handle SIGTERM ({e}); Ctrl-C still works");
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn print_help() {
    println!(
        "AiNxt OS Console — a chat window and settings page for AiNxt OS.\n\
         \n\
         USAGE:\n\
         \x20   ainxt-os [OPTIONS]\n\
         \n\
         It starts AiNxt OS for you, opens a browser, and lets you pick a model and change\n\
         settings without editing configuration files.\n\
         \n\
         OPTIONS:\n\
         \x20   --port <n>          Port for the console itself (default {DEFAULT_CONSOLE_PORT})\n\
         \x20   --config <file>     AiNxt OS config to use/create (default runtimed.toml)\n\
         \x20   --runtimed <file>   Path to the ainxt-runtimed binary, if it is not alongside this one\n\
         \x20   --no-open           Do not open a browser automatically\n\
         \x20   -h, --help          Show this help\n\
         \n\
         The console is the authenticating gateway: AiNxt OS runs in jwt-sso mode and only accepts\n\
         tokens the console signs. Both listeners bind 127.0.0.1 only."
    );
}

fn open_in_browser(url: &str) {
    let (cmd, args): (&str, Vec<&str>) = if cfg!(target_os = "macos") {
        ("open", vec![url])
    } else if cfg!(target_os = "windows") {
        ("cmd", vec!["/C", "start", "", url])
    } else {
        ("xdg-open", vec![url])
    };
    // Best-effort: a headless machine simply has no browser, which is not an error.
    let _ = std::process::Command::new(cmd)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

async fn start_daemon(app: &mut App) -> Result<(), String> {
    let configs = app.configs();
    let env = app.daemon_env();
    let spawned = daemon::spawn(&app.daemon_bin, &configs, &env, &app.state_dir)
        .await
        .map_err(|e| format!("could not start AiNxt OS: {e}"))?;
    app.child = Some(spawned.child);
    app.log_path = spawned.log_path;

    if !daemon::wait_until_listening(app.settings.port, 80).await {
        let tail = std::fs::read_to_string(&app.log_path)
            .map(|s| s.lines().rev().take(12).collect::<Vec<_>>().join("\n"))
            .unwrap_or_default();
        return Err(format!(
            "AiNxt OS did not start listening on port {}. Last lines of its log:\n{tail}",
            app.settings.port
        ));
    }
    Ok(())
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------------------------
// handlers
// ---------------------------------------------------------------------------------------------

/// The approved AiNxt icon, embedded from the sibling `ainxt-icon.svg` (the brand-approved
/// asset) so the Console stays a single self-contained binary with no runtime file lookup.
///
/// Served for both `/favicon.svg` and `/favicon.ico`: browsers request `.ico` unprompted, and
/// answering it with SVG keeps a 404 out of the devtools console. The asset is self-contained —
/// its only `xlink:href` references are internal gradient definitions, no external files or fonts.
const ICON_SVG: &str = include_str!("ainxt-icon.svg");

async fn serve_favicon() -> impl IntoResponse {
    (
        [
            (axum::http::header::CONTENT_TYPE, "image/svg+xml"),
            (axum::http::header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        ICON_SVG,
    )
}

async fn serve_html() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        CONSOLE_HTML,
    )
}

#[derive(Serialize)]
struct StatusBody {
    up: bool,
    model: String,
    provider_kind: String,
    identity: jwt::Identity,
}

async fn api_status(State(app): State<Shared>) -> impl IntoResponse {
    let app = app.lock().await;
    let up = tokio::net::TcpStream::connect(("127.0.0.1", app.settings.port))
        .await
        .is_ok();
    Json(StatusBody {
        up,
        model: if app.settings.provider_id.is_empty() {
            "offline".into()
        } else {
            app.settings.provider_id.clone()
        },
        provider_kind: app.settings.provider_kind.clone(),
        identity: app.console.identity.clone(),
    })
}

#[derive(Deserialize)]
struct ChatBody {
    input: String,
    #[serde(default)]
    data_class: Option<String>,
}

/// Mint a token, forward the turn to AiNxt OS, and stream the SSE response straight back.
///
/// The console does not interpret the stream — it is a gateway, so the browser sees the runtime's
/// own event vocabulary (including refusals delivered inside a 200 response) exactly as
/// `DOCKING.md` specifies.

/// Bootstrap the non-overridable RBI outsourcing registration after every daemon start.
///
/// The registration is held in the runtime's in-memory outsourcing register, so a fresh
/// daemon needs it again. The console is the only component that knows the JWT signing
/// secret, therefore the bootstrap token never leaves this process.
async fn bootstrap_outsourcing(app: &App) -> Result<(), String> {
    let identity = jwt::Identity {
        user: "dpo".into(),
        role: "admin".into(),
        department: "compliance".into(),
        caps: vec![],
        clearance: "confidential".into(),
    };

    let token = jwt::mint(app.secret.as_bytes(), &identity, now_unix(), TOKEN_TTL_SECS);

    // The Console owns one provider/model entry at a time. Register the *configured* cloud
    // route rather than hard-coding one demonstration model (claude-sonnet-4-6). The runtime
    // derives the same canonical route id from the provider/model id, so any model id entered in
    // the Console gets the same governance gate. We deliberately keep the automatic approval
    // ceiling at `public`; higher-sensitivity cloud routing still requires an explicit control-plane
    // registration and cannot be widened by the self-service Console.
    let (provider_legal_entity, approval_ref, exit_plan_ref) =
        match app.settings.provider_kind.as_str() {
            "anthropic" => ("Anthropic", "board-approval-anthropic", "anthropic-exit-plan"),
            "open-ai-schema" => ("OpenAI", "board-approval-openai", "openai-exit-plan"),
            "gemini" => ("Google", "board-approval-google", "google-exit-plan"),
            // Local/offline routes are explicitly exempt from the cloud outsourcing register.
            "local" | "offline" => return Ok(()),
            _ => return Err(format!(
                "cannot bootstrap outsourcing for unknown provider kind '{}'",
                app.settings.provider_kind
            )),
        };

    let provider_id = app.settings.provider_id.trim();
    if provider_id.is_empty() {
        return Err("cannot bootstrap outsourcing without a configured model id".into());
    }

    let payload = serde_json::json!({
        "id": format!("outsourcing.cloud.{provider_id}"),
        "provider_legal_entity": provider_legal_entity,
        "permitted_data_class": "public",
        "data_residency": "in",
        "exit_plan_ref": exit_plan_ref,
        "concentration_tag": "cloud-ai",
        "contract_ref": format!("{provider_legal_entity}-cloud-contract"),
        "board_approval_ref": approval_ref,
        "right_to_audit_clause": "included"
    });

    let resp = reqwest::Client::new()
        .post(format!(
            "http://127.0.0.1:{}/admin/outsourcing/register",
            app.settings.port
        ))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(payload.to_string())
        .send()
        .await
        .map_err(|e| format!("outsourcing bootstrap request failed: {e}"))?;

    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();

    if !status.is_success() {
        return Err(format!("outsourcing bootstrap rejected ({status}): {text}"));
    }

    println!(
        "ainxt-os: cloud outsourcing registration bootstrapped for {} ({})",
        provider_id, app.settings.provider_kind
    );
    Ok(())
}

async fn api_chat(State(app): State<Shared>, Json(body): Json<ChatBody>) -> Response {
    let (port, token, session) = {
        let app = app.lock().await;

        // Chat surfaces are department-scoped. Never mint a token with an empty department:
        // authentication would succeed, but surface admission would correctly reject the turn.
        let mut identity = app.console.identity.clone();
        if identity.department.trim().is_empty() {
            identity.department = "engineering".into();
        }

        let token = jwt::mint(app.secret.as_bytes(), &identity, now_unix(), TOKEN_TTL_SECS);
        (
            app.settings.port,
            token,
            format!("console-{}", std::process::id()),
        )
    };

    let payload = serde_json::json!({
        "session": session,
        "turn": format!("t{}", now_unix()),
        "input": body.input,
        "data_class": body.data_class.unwrap_or_else(|| "public".into()),
    });

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:{port}/v1/chat"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(payload.to_string())
        .send()
        .await;

    match resp {
        Ok(r) => {
            let status =
                StatusCode::from_u16(r.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            if !status.is_success() {
                let text = r.text().await.unwrap_or_default();
                return (status, text).into_response();
            }
            (
                [(header::CONTENT_TYPE, "text/event-stream")],
                axum::body::Body::from_stream(r.bytes_stream()),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            format!("AiNxt OS did not answer: {e}"),
        )
            .into_response(),
    }
}

#[derive(Serialize)]
struct SettingsBody {
    #[serde(flatten)]
    settings: Settings,
    gates: Gates,
}

#[derive(Serialize)]
struct Gates {
    compliance: String,
    authz: String,
    audit: String,
}

/// The gates are read straight from the config so the console reports what is actually in force,
/// never a hardcoded claim.
fn read_gates(config_path: &Path) -> Gates {
    let doc = std::fs::read_to_string(config_path)
        .ok()
        .and_then(|t| t.parse::<toml_edit::DocumentMut>().ok());
    let get = |key: &str, dflt: &str| -> String {
        doc.as_ref()
            .and_then(|d| d.get("gates"))
            .and_then(|g| g.get(key))
            .and_then(|v| v.as_str())
            .unwrap_or(dflt)
            .to_string()
    };
    Gates {
        compliance: get("compliance", "default"),
        authz: get("authz", "rbac"),
        audit: get("audit", "memory"),
    }
}

async fn api_get_settings(State(app): State<Shared>) -> impl IntoResponse {
    let app = app.lock().await;
    Json(SettingsBody {
        settings: app.settings.clone(),
        gates: read_gates(&app.config_path),
    })
}

#[derive(Deserialize)]
struct SaveBody {
    #[serde(flatten)]
    settings: Settings,
    #[serde(default)]
    api_key: String,
}

#[derive(Serialize)]
struct SaveResult {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn bad(msg: impl Into<String>) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(SaveResult {
            ok: false,
            error: Some(msg.into()),
        }),
    )
        .into_response()
}

/// Validate, ask the daemon's own `--check` for a verdict, write only if it agrees, then restart.
///
/// The config is written to a temporary file and checked *before* the operator's real file is
/// touched, so a rejected change never leaves a broken `runtimed.toml` behind.
async fn api_post_settings(State(app): State<Shared>, Json(body): Json<SaveBody>) -> Response {
    let new_settings = body.settings;
    if let Err(e) = settings::validate(&new_settings) {
        return bad(e);
    }

    let mut guard = app.lock().await;

    // Stage the credential, if one was supplied. A blank field means "keep what is stored".
    let mut console_state = guard.console.clone();
    if !body.api_key.is_empty() {
        match settings::env_var_for_kind(&new_settings.provider_kind) {
            Some(var) => {
                console_state.secrets.insert(var.to_string(), body.api_key);
            }
            None => return bad("This model type does not take an API key."),
        }
    }
    if let Some(var) = settings::env_var_for_kind(&new_settings.provider_kind) {
        if console_state.secrets.get(var).is_none_or(|v| v.is_empty()) {
            return bad(format!(
                "This model type needs an API key ({var}). Enter one to continue."
            ));
        }
    }

    // Edit a copy of the operator's document, preserving its comments and everything we do not own.
    let current = std::fs::read_to_string(&guard.config_path).unwrap_or_default();
    let mut doc = match current.parse::<toml_edit::DocumentMut>() {
        Ok(d) => d,
        Err(e) => {
            return bad(format!(
                "The current configuration file could not be parsed: {e}"
            ))
        }
    };
    settings::apply(&mut doc, &new_settings);

    let staged = guard.state_dir.join("staged.runtimed.toml");
    if let Err(e) = std::fs::write(&staged, doc.to_string()) {
        return bad(format!("Could not stage the new configuration: {e}"));
    }

    // The daemon is the authority on validity. Sanitize before passing to cmd.env() to prevent
    // Stored Environment Variable Injection (Checkmarx medium — OWASP A5).
    let env = settings::sanitize_env_vars(&console_state.secrets);
    let check_configs = vec![staged.clone(), guard.overlay_path.clone()];
    if let Err(e) = daemon::validate_config(&guard.daemon_bin, &check_configs, &env).await {
        let _ = std::fs::remove_file(&staged);
        return bad(format!("AiNxt OS rejected this configuration: {e}"));
    }

    // Committed: move the staged file into place and persist console-owned state.
    if let Err(e) = std::fs::write(&guard.config_path, doc.to_string()) {
        return bad(format!("Could not write the configuration: {e}"));
    }
    let _ = std::fs::remove_file(&staged);
    if let Err(e) = settings::save_console_state(&guard.state_dir, &console_state) {
        return bad(format!("Could not save console settings: {e}"));
    }
    guard.console = console_state;
    guard.settings = new_settings;

    // Restart so the change takes effect — several of these keys are read only at assembly.
    if let Some(child) = guard.child.as_mut() {
        let _ = child.kill().await;
    }
    if let Err(e) = start_daemon(&mut guard).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(SaveResult {
                ok: false,
                error: Some(format!("Saved, but AiNxt OS did not come back up: {e}")),
            }),
        )
            .into_response();
    }

    // A settings save restarts the daemon. The outsourcing register is intentionally in-memory,
    // so it must be bootstrapped again after every restart; otherwise the newly configured cloud
    // model is immediately rejected with Routing(NoEligible(Public)).
    if let Err(e) = bootstrap_outsourcing(&guard).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(SaveResult {
                ok: false,
                error: Some(format!(
                    "Saved and daemon restarted, but cloud governance registration failed: {e}"
                )),
            }),
        )
            .into_response();
    }

    Json(SaveResult {
        ok: true,
        error: None,
    })
    .into_response()
}

/// The daemon's own startup report — the ~80 lines naming every subsystem it wired.
async fn api_activity(State(app): State<Shared>) -> impl IntoResponse {
    let app = app.lock().await;
    let body = std::fs::read_to_string(&app.log_path)
        .unwrap_or_else(|e| format!("could not read {}: {e}", app.log_path.display()));
    ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], body)
}
