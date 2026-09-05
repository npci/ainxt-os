// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! The safe subset of AiNxt OS configuration a non-technical operator may change from the console,
//! plus the console's own local state (operator identity and provider credentials).
//!
//! Two deliberate boundaries:
//!
//! * **The mandatory gates are not editable here.** `[gates] compliance/authz/audit` are the
//!   product's fail-closed guarantee; a Settings form that let someone weaken them would defeat the
//!   thing they are buying. The console renders them read-only instead.
//! * **Credentials never enter `runtimed.toml`.** AiNxt OS reads provider keys from the environment,
//!   so the console keeps them in its own `0600` file and injects them when it spawns the daemon.
//!   That keeps secrets out of the file an operator is most likely to paste into a support ticket.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use toml_edit::{value, ArrayOfTables, DocumentMut, Item, Table};

use crate::jwt::Identity;

/// The five guardrail rails the daemon reads, in the order the console renders them.
pub const GUARDRAILS: [&str; 5] = [
    "jailbreak",
    "groundedness",
    "toxicity",
    "system_prompt_leak",
    "citation",
];

/// Provider kinds the console offers. `offline` is not a daemon provider kind — selecting it means
/// "declare no providers", which is what makes AiNxt OS register its offline provider.
pub const PROVIDER_KINDS: [&str; 5] = [
    "offline",
    "local",
    "anthropic",
    "open-ai-schema",
    "gemini",
];

/// The environment variable each cloud kind's credential is read from, per the shipped example config.
pub fn env_var_for_kind(kind: &str) -> Option<&'static str> {
    match kind {
        "anthropic" => Some("ANTHROPIC_API_KEY"),
        "open-ai-schema" => Some("OPENAI_API_KEY"),
        "gemini" => Some("GOOGLE_API_KEY"),
        _ => None, // "local" is normally keyless; "offline" needs nothing.
    }
}

/// The complete set of environment variable names the console is permitted to inject into the
/// daemon process. This is an explicit allowlist — any key not in this set is silently dropped
/// before the pair ever reaches `cmd.env()`.
///
/// Keeping the list here (next to `env_var_for_kind`) means there is exactly one place to update
/// when a new provider is added.
const ALLOWED_ENV_KEYS: &[&str] = &["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GOOGLE_API_KEY"];

/// Validate and filter a raw secrets map before it is passed to the daemon as environment
/// variables. This is the single choke-point that prevents Stored Environment Variable Injection
/// (Checkmarx: Rust\Cx\Rust Medium Threat\Stored Environment Variable Injection).
///
/// Rules applied to every `(key, value)` pair:
/// 1. **Allowlist** – the key must be one of [`ALLOWED_ENV_KEYS`]. Any other key is dropped and a
///    warning is printed to stderr so operators can see if `console.toml` has been tampered with.
/// 2. **Key format** – the key must match `^[A-Z][A-Z0-9_]{0,127}$` (POSIX uppercase env-var
///    naming). This is a defence-in-depth check; the allowlist already guarantees the shape of
///    every legitimate key.
/// 3. **Value safety** – the value must be non-empty and must not contain ASCII control characters
///    (bytes 0x00–0x1F or 0x7F). A null byte in an env-var value is undefined behaviour on most
///    platforms; other control characters are a common injection vector.
///
/// Returns a `Vec` of the pairs that passed all checks, ready to hand to `cmd.env()`.
pub fn sanitize_env_vars(secrets: &std::collections::BTreeMap<String, String>) -> Vec<(String, String)> {
    secrets
        .iter()
        .filter_map(|(k, v)| {
            // 1. Allowlist check.
            if !ALLOWED_ENV_KEYS.contains(&k.as_str()) {
                eprintln!(
                    "ainxt-os: security: dropping env var '{k}' — not in the permitted key list"
                );
                return None;
            }
            // 2. Key format check (defence-in-depth; allowlist already guarantees this for
            //    legitimate keys, but we check anyway in case ALLOWED_ENV_KEYS is ever extended
            //    carelessly).
            if !is_safe_env_key(k) {
                eprintln!(
                    "ainxt-os: security: dropping env var '{k}' — key contains disallowed characters"
                );
                return None;
            }
            // 3. Value safety check.
            if v.is_empty() {
                return None; // silently skip blank credentials (existing behaviour)
            }
            if v.bytes().any(|b| b < 0x20 || b == 0x7f) {
                eprintln!(
                    "ainxt-os: security: dropping env var '{k}' — value contains control characters"
                );
                return None;
            }
            Some((k.clone(), v.clone()))
        })
        .collect()
}

/// Returns `true` if `key` is a well-formed POSIX environment variable name consisting only of
/// uppercase ASCII letters, digits, and underscores, starting with a letter, and no longer than
/// 128 characters.
fn is_safe_env_key(key: &str) -> bool {
    if key.is_empty() || key.len() > 128 {
        return false;
    }
    let mut chars = key.chars();
    // First character must be an uppercase ASCII letter.
    match chars.next() {
        Some(c) if c.is_ascii_uppercase() => {}
        _ => return false,
    }
    // Remaining characters: uppercase letters, digits, or underscores only.
    chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub port: u16,
    /// One of [`PROVIDER_KINDS`].
    pub provider_kind: String,
    /// The model id, which is also the provider id the daemon prices and reports in `turn.rationale`.
    pub provider_id: String,
    /// Only meaningful for `local` / `open-ai-schema`.
    pub provider_base_url: String,
    pub rag_enabled: bool,
    /// Maps to `[server] chat_sessions_dir`. When on, a conversation survives a daemon restart.
    pub persist_sessions: bool,
    pub guardrails: BTreeMap<String, String>,
    pub injection_mode: String,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            port: 8080,
            provider_kind: "offline".into(),
            provider_id: String::new(),
            provider_base_url: String::new(),
            rag_enabled: false,
            persist_sessions: true,
            guardrails: GUARDRAILS
                .iter()
                .map(|g| ((*g).to_string(), "audit".to_string()))
                .collect(),
            injection_mode: "enforce".into(),
        }
    }
}

/// Read the safe subset out of a `runtimed.toml`. Unknown/absent keys fall back to the daemon's own
/// documented defaults rather than erroring — the console must open even against a hand-edited file.
pub fn load(config_path: &Path) -> Settings {
    let mut s = Settings::default();
    let Ok(text) = std::fs::read_to_string(config_path) else {
        return s;
    };
    let Ok(doc) = text.parse::<DocumentMut>() else {
        return s;
    };

    if let Some(p) = doc
        .get("server")
        .and_then(|t| t.get("port"))
        .and_then(|v| v.as_integer())
    {
        s.port = p as u16;
    }
    s.persist_sessions = doc
        .get("server")
        .and_then(|t| t.get("chat_sessions_dir"))
        .and_then(|v| v.as_str())
        .is_some_and(|v| !v.is_empty());

    if let Some(r) = doc
        .get("kb")
        .and_then(|t| t.get("rag_enabled"))
        .and_then(|v| v.as_bool())
    {
        s.rag_enabled = r;
    }
    if let Some(m) = doc
        .get("injection")
        .and_then(|t| t.get("mode"))
        .and_then(|v| v.as_str())
    {
        s.injection_mode = m.to_string();
    }
    if let Some(g) = doc.get("guardrails") {
        for rail in GUARDRAILS {
            if let Some(v) = g.get(rail).and_then(|v| v.as_str()) {
                s.guardrails.insert(rail.to_string(), v.to_string());
            }
        }
    }

    // The console manages a single provider entry; read the first one if present.
    if let Some(first) = doc
        .get("models")
        .and_then(|m| m.get("providers"))
        .and_then(|p| p.as_array_of_tables())
        .and_then(|a| a.get(0))
    {
        s.provider_kind = first
            .get("kind")
            .and_then(|v| v.as_str())
            .unwrap_or("local")
            .to_string();
        s.provider_id = first
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        s.provider_base_url = first
            .get("base_url")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
    }
    s
}

/// Reject anything the daemon would refuse, before a file is written. Returns a message the console
/// shows verbatim, so it has to read well to a non-technical operator.
pub fn validate(s: &Settings) -> Result<(), String> {
    if !PROVIDER_KINDS.contains(&s.provider_kind.as_str()) {
        return Err(format!("Unknown model type '{}'.", s.provider_kind));
    }
    if s.port < 1024 {
        return Err(format!(
            "Port {} is reserved. Choose a port of 1024 or above.",
            s.port
        ));
    }
    for (rail, mode) in &s.guardrails {
        if !["off", "audit", "enforce"].contains(&mode.as_str()) {
            return Err(format!(
                "Guardrail '{rail}' must be off, audit or enforce — got '{mode}'."
            ));
        }
    }
    if !["off", "audit", "enforce"].contains(&s.injection_mode.as_str()) {
        return Err(format!(
            "Prompt-injection defence must be off, audit or enforce — got '{}'.",
            s.injection_mode
        ));
    }
    if s.provider_kind != "offline" && s.provider_id.trim().is_empty() {
        return Err("Give the model a name (for example llama3.1:8b).".into());
    }
    if matches!(s.provider_kind.as_str(), "local" | "open-ai-schema")
        && s.provider_base_url.trim().is_empty()
    {
        return Err(
            "This model type needs an endpoint address (for example http://localhost:11434/v1)."
                .into(),
        );
    }
    if !s.provider_base_url.is_empty()
        && !(s.provider_base_url.starts_with("http://") || s.provider_base_url.starts_with("https://"))
    {
        return Err("The endpoint address must start with http:// or https://".into());
    }
    Ok(())
}

/// Apply the subset onto an existing document **without disturbing anything else in it**, including
/// comments. Everything the console does not own is left byte-identical.
pub fn apply(doc: &mut DocumentMut, s: &Settings) {
    ensure_table(doc, "server");
    doc["server"]["port"] = value(s.port as i64);
    if s.persist_sessions {
        doc["server"]["chat_sessions_dir"] = value("sessions");
    } else if doc["server"].as_table_like().is_some() {
        if let Some(t) = doc["server"].as_table_mut() {
            t.remove("chat_sessions_dir");
        }
    }

    ensure_table(doc, "kb");
    doc["kb"]["rag_enabled"] = value(s.rag_enabled);

    ensure_table(doc, "injection");
    doc["injection"]["mode"] = value(s.injection_mode.as_str());

    ensure_table(doc, "guardrails");
    for rail in GUARDRAILS {
        if let Some(mode) = s.guardrails.get(rail) {
            doc["guardrails"][rail] = value(mode.as_str());
        }
    }

    // Providers: the console owns this array entirely. "offline" means declare none, which is what
    // makes the daemon register its offline provider — never a silent cloud fallback.
    if let Some(models) = doc.get_mut("models").and_then(|m| m.as_table_mut()) {
        models.remove("providers");
    }
    if s.provider_kind != "offline" {
        let mut t = Table::new();
        t["id"] = value(s.provider_id.as_str());
        t["kind"] = value(s.provider_kind.as_str());
        if !s.provider_base_url.is_empty() {
            t["base_url"] = value(s.provider_base_url.as_str());
        }
        let mut elig = toml_edit::Array::new();
        for c in ["public", "internal", "confidential"] {
            elig.push(c);
        }
        t["eligible"] = value(elig);

        let mut aot = ArrayOfTables::new();
        aot.push(t);
        ensure_table(doc, "models");
        doc["models"]["providers"] = Item::ArrayOfTables(aot);
    }
}

fn ensure_table(doc: &mut DocumentMut, key: &str) {
    if doc.get(key).is_none() {
        doc[key] = Item::Table(Table::new());
    }
}

// ---------------------------------------------------------------------------------------------
// Console-local state: the operator identity the gateway asserts, and provider credentials.
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConsoleState {
    #[serde(default)]
    pub identity: Identity,
    /// Keyed by environment variable name, e.g. `ANTHROPIC_API_KEY`.
    #[serde(default)]
    pub secrets: BTreeMap<String, String>,
}

pub fn console_state_path(dir: &Path) -> PathBuf {
    dir.join("console.toml")
}

pub fn load_console_state(dir: &Path) -> ConsoleState {
    let path = console_state_path(dir);
    std::fs::read_to_string(path)
        .ok()
        .and_then(|t| toml::from_str(&t).ok())
        .unwrap_or_default()
}

/// Persist console state at `0600`. It holds API keys, so the permission is part of the contract.
pub fn save_console_state(dir: &Path, state: &ConsoleState) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let path = console_state_path(dir);
    let body = toml::to_string_pretty(state)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(&path, body)?;
    restrict(&path)
}

/// Owner-read/write only. A no-op with a warning on platforms without Unix permissions.
pub fn restrict(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = r#"
# a comment that must survive
version = 1

[server]
host = "127.0.0.1"
port = 8080

# ---- gates: never editable from the console ----
[gates]
compliance = "default"
authz = "rbac"
audit = "memory"
"#;

    #[test]
    fn apply_preserves_comments_and_untouched_sections() {
        let mut doc = EXAMPLE.parse::<DocumentMut>().expect("parse");
        let mut s = Settings::default();
        s.port = 9090;
        apply(&mut doc, &s);
        let out = doc.to_string();
        assert!(
            out.contains("# a comment that must survive"),
            "console edits must not strip the config's comments: {out}"
        );
        assert!(out.contains("# ---- gates: never editable from the console ----"));
        // The gates section is untouched — the console never writes it.
        assert!(out.contains(r#"compliance = "default""#));
        assert!(out.contains("port = 9090"));
    }

    #[test]
    fn offline_declares_no_providers_so_the_daemon_serves_offline() {
        let mut doc = EXAMPLE.parse::<DocumentMut>().expect("parse");
        let mut s = Settings::default();
        s.provider_kind = "local".into();
        s.provider_id = "llama3.1:8b".into();
        s.provider_base_url = "http://localhost:11434/v1".into();
        apply(&mut doc, &s);
        assert!(doc.to_string().contains("[[models.providers]]"));

        // Switching back to offline must REMOVE the provider, not leave it declared.
        s.provider_kind = "offline".into();
        apply(&mut doc, &s);
        let out = doc.to_string();
        assert!(
            !out.contains("[[models.providers]]"),
            "offline must declare no provider, or the daemon would keep routing to it: {out}"
        );
    }

    #[test]
    fn round_trip_through_load_preserves_the_subset() {
        let mut doc = EXAMPLE.parse::<DocumentMut>().expect("parse");
        let mut s = Settings::default();
        s.port = 8123;
        s.provider_kind = "local".into();
        s.provider_id = "qwen".into();
        s.provider_base_url = "http://localhost:8000/v1".into();
        s.rag_enabled = true;
        s.persist_sessions = false;
        s.injection_mode = "audit".into();
        s.guardrails.insert("toxicity".into(), "enforce".into());
        apply(&mut doc, &s);

        let dir = std::env::temp_dir().join(format!("ainxt-console-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("runtimed.toml");
        std::fs::write(&path, doc.to_string()).expect("write");

        let back = load(&path);
        assert_eq!(back.port, 8123);
        assert_eq!(back.provider_kind, "local");
        assert_eq!(back.provider_id, "qwen");
        assert_eq!(back.provider_base_url, "http://localhost:8000/v1");
        assert!(back.rag_enabled);
        assert!(!back.persist_sessions, "persistence off must round-trip as off");
        assert_eq!(back.injection_mode, "audit");
        assert_eq!(back.guardrails["toxicity"], "enforce");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn persistence_toggle_writes_and_removes_the_directory_key() {
        let mut doc = EXAMPLE.parse::<DocumentMut>().expect("parse");
        let mut s = Settings::default();
        s.persist_sessions = true;
        apply(&mut doc, &s);
        assert!(doc.to_string().contains(r#"chat_sessions_dir = "sessions""#));
        s.persist_sessions = false;
        apply(&mut doc, &s);
        assert!(!doc.to_string().contains("chat_sessions_dir"));
    }

    #[test]
    fn validate_rejects_what_the_daemon_would_refuse() {
        let mut s = Settings::default();
        s.provider_kind = "local".into();
        s.provider_id = "m".into();
        assert!(validate(&s).is_err(), "local without a base_url must be rejected");
        s.provider_base_url = "localhost:11434".into();
        assert!(validate(&s).is_err(), "a scheme-less endpoint must be rejected");
        s.provider_base_url = "http://localhost:11434/v1".into();
        assert!(validate(&s).is_ok());

        s.guardrails.insert("toxicity".into(), "maybe".into());
        assert!(validate(&s).is_err(), "an invalid guardrail mode must be rejected");
    }

    #[test]
    fn cloud_kinds_map_to_their_documented_env_vars() {
        assert_eq!(env_var_for_kind("anthropic"), Some("ANTHROPIC_API_KEY"));
        assert_eq!(env_var_for_kind("open-ai-schema"), Some("OPENAI_API_KEY"));
        assert_eq!(env_var_for_kind("gemini"), Some("GOOGLE_API_KEY"));
        assert_eq!(env_var_for_kind("local"), None);
        assert_eq!(env_var_for_kind("offline"), None);
    }

    // -----------------------------------------------------------------------------------------
    // sanitize_env_vars — Stored Environment Variable Injection fix (Checkmarx medium)
    // -----------------------------------------------------------------------------------------

    fn make_secrets(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn sanitize_passes_known_good_keys_with_clean_values() {
        let secrets = make_secrets(&[
            ("ANTHROPIC_API_KEY", "sk-ant-abc123"),
            ("OPENAI_API_KEY", "sk-openai-xyz"),
            ("GOOGLE_API_KEY", "AIzaSy_example"),
        ]);
        let result = sanitize_env_vars(&secrets);
        assert_eq!(result.len(), 3, "all three known-good keys should pass");
        let keys: Vec<&str> = result.iter().map(|(k, _)| k.as_str()).collect();
        assert!(keys.contains(&"ANTHROPIC_API_KEY"));
        assert!(keys.contains(&"OPENAI_API_KEY"));
        assert!(keys.contains(&"GOOGLE_API_KEY"));
    }

    #[test]
    fn sanitize_drops_unknown_key_names() {
        let secrets = make_secrets(&[
            ("ANTHROPIC_API_KEY", "sk-ant-abc123"),
            ("LD_PRELOAD", "/tmp/evil.so"),          // injection attempt
            ("PATH", "/tmp:/usr/bin"),                // injection attempt
            ("DYLD_INSERT_LIBRARIES", "/tmp/x.dylib"), // macOS injection
            ("CUSTOM_SECRET", "value"),               // not in allowlist
        ]);
        let result = sanitize_env_vars(&secrets);
        assert_eq!(result.len(), 1, "only the allowlisted key should survive");
        assert_eq!(result[0].0, "ANTHROPIC_API_KEY");
    }

    #[test]
    fn sanitize_drops_keys_with_lowercase_letters() {
        // Even if somehow a lowercase variant slipped into ALLOWED_ENV_KEYS in the future,
        // is_safe_env_key provides a second line of defence.
        let secrets = make_secrets(&[("anthropic_api_key", "sk-ant-abc123")]);
        let result = sanitize_env_vars(&secrets);
        assert!(result.is_empty(), "lowercase key must be rejected");
    }

    #[test]
    fn sanitize_drops_empty_values() {
        let secrets = make_secrets(&[("ANTHROPIC_API_KEY", "")]);
        let result = sanitize_env_vars(&secrets);
        assert!(result.is_empty(), "blank credential must be silently dropped");
    }

    #[test]
    fn sanitize_drops_values_with_null_bytes() {
        let secrets = make_secrets(&[("OPENAI_API_KEY", "sk-good\x00injected")]);
        let result = sanitize_env_vars(&secrets);
        assert!(result.is_empty(), "null byte in value must be rejected");
    }

    #[test]
    fn sanitize_drops_values_with_control_characters() {
        // Newline, carriage return, tab — all control characters.
        for bad_val in &["sk-\ninjected", "sk-\rinjected", "sk-\x01injected"] {
            let secrets = make_secrets(&[("GOOGLE_API_KEY", bad_val)]);
            let result = sanitize_env_vars(&secrets);
            assert!(
                result.is_empty(),
                "control character in value must be rejected: {:?}",
                bad_val
            );
        }
    }

    #[test]
    fn sanitize_accepts_values_with_printable_special_chars() {
        // API keys legitimately contain hyphens, underscores, dots, slashes, etc.
        let secrets = make_secrets(&[("ANTHROPIC_API_KEY", "sk-ant-abc123-XYZ_./+==")]);
        let result = sanitize_env_vars(&secrets);
        assert_eq!(result.len(), 1, "printable non-control chars in value must be accepted");
    }

    #[test]
    fn is_safe_env_key_rejects_empty_and_overlong() {
        assert!(!is_safe_env_key(""));
        assert!(!is_safe_env_key(&"A".repeat(129)));
        assert!(is_safe_env_key(&"A".repeat(128)));
    }

    #[test]
    fn is_safe_env_key_rejects_leading_digit_or_underscore() {
        assert!(!is_safe_env_key("1KEY"));
        assert!(!is_safe_env_key("_KEY"));
    }

    #[test]
    fn is_safe_env_key_rejects_shell_metacharacters() {
        for bad in &["KEY=VALUE", "KEY;rm", "KEY$(cmd)", "KEY`cmd`", "KEY\nLD_PRELOAD"] {
            assert!(!is_safe_env_key(bad), "should reject: {bad}");
        }
    }
}
