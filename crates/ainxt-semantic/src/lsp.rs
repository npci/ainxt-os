// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! **Rung 1 of the edit ladder — a real Language Server Protocol driver** (`SEMANTIC_EDITING.md` §2).
//!
//! Rung 1 (`ladder::Rung::Lsp`) is the highest-fidelity edit: a *toolchain-guaranteed* refactor
//! computed by the same language server the developer's IDE trusts (rust-analyzer / gopls / pyright /
//! tsserver / jdtls). Until now the rung was a bare seam ([`crate::ladder::LspRefactor`]) with only a
//! scripted stand-in ([`crate::ladder::ScriptedLspRefactor`]) behind it — no code actually *spoke* the
//! protocol, so the ladder could never truly resolve at rung 1; it always fell to the AST rung.
//!
//! This module is the real driver. It speaks **JSON-RPC 2.0 over the LSP base protocol** — messages
//! framed with a `Content-Length` header, the `initialize`/`initialized` handshake, `textDocument/
//! didOpen`, then `textDocument/rename`, and it applies the returned `WorkspaceEdit` byte-precisely to
//! the source. The wire codec, the request/response correlation, and the edit application are **real,
//! deterministic, and offline-testable**.
//!
//! ## The infra boundary (honest `infra_gated`)
//! A *live* refactor needs a language-server **process** with a warm workspace index — that is infra
//! (a real binary on `PATH`, a project it has indexed, filesystem + spawn permissions). That single
//! concern is isolated behind the [`LspTransport`] seam:
//! - [`StdioLspTransport::spawn`] is the **live** transport — it launches a server and pipes JSON-RPC
//!   over its stdio. This is the part that cannot run in the air-gapped/CI default and is left for a
//!   deployment to enable (it is never exercised by the offline test — no server is faked).
//! - [`ScriptedLspTransport`] is the **offline** transport — it replays the exact framed JSON-RPC the
//!   server *would* emit, so the entire client (framing, handshake, rename, `WorkspaceEdit`
//!   application) is proven end-to-end without a live process, and a missing server can never
//!   masquerade as a completed refactor (it degrades to `Unavailable`, so the ladder falls to AST).
//!
//! Everything except the process spawn is genuine protocol code with a real test.

use crate::ladder::{CodeLanguage, LspEditTarget, LspOutcome, LspRefactor, SemanticOp};
use serde_json::{json, Value};
use std::io::{self, BufRead, BufReader, Cursor, Write};

/// An error from the LSP driver, separating the *transport is not there* case (→ fall to AST) from a
/// *server rejected the op* case (→ a recorded rung failure).
#[derive(Debug)]
pub enum LspError {
    /// Transport-level failure: no server, broken pipe, EOF. The ladder treats this as "rung
    /// unavailable" and falls *down* — a missing server is never a refactor failure.
    Transport(String),
    /// A malformed or unexpected protocol message.
    Protocol(String),
    /// The server was consulted and returned a JSON-RPC `error`, or rejected the refactor.
    Server(String),
}

impl std::fmt::Display for LspError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LspError::Transport(s) => write!(f, "lsp transport: {s}"),
            LspError::Protocol(s) => write!(f, "lsp protocol: {s}"),
            LspError::Server(s) => write!(f, "lsp server: {s}"),
        }
    }
}

impl std::error::Error for LspError {}

impl From<io::Error> for LspError {
    fn from(e: io::Error) -> Self {
        LspError::Transport(e.to_string())
    }
}

impl From<serde_json::Error> for LspError {
    fn from(e: serde_json::Error) -> Self {
        LspError::Protocol(e.to_string())
    }
}

/// Encode a JSON payload into an LSP base-protocol frame: `Content-Length: N\r\n\r\n<payload>`.
#[must_use]
pub fn encode_frame(payload: &[u8]) -> Vec<u8> {
    let mut out = format!("Content-Length: {}\r\n\r\n", payload.len()).into_bytes();
    out.extend_from_slice(payload);
    out
}

/// Read exactly one LSP base-protocol frame from `r`, returning its JSON payload bytes. Parses the
/// `Content-Length` header (case-insensitive, per the spec), skips any other headers, consumes the
/// blank separator line, then reads exactly that many payload bytes.
///
/// # Errors
/// [`LspError::Transport`] on EOF/IO; [`LspError::Protocol`] on a missing/invalid `Content-Length`.
pub fn read_frame<R: BufRead>(r: &mut R) -> Result<Vec<u8>, LspError> {
    let mut content_length: Option<usize> = None;
    loop {
        let mut line = String::new();
        let n = r.read_line(&mut line)?;
        if n == 0 {
            return Err(LspError::Transport("EOF before frame body".to_string()));
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break; // end of headers
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                content_length = Some(
                    v.trim()
                        .parse::<usize>()
                        .map_err(|_| LspError::Protocol(format!("bad Content-Length: {v:?}")))?,
                );
            }
        }
    }
    let len = content_length
        .ok_or_else(|| LspError::Protocol("frame had no Content-Length".to_string()))?;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

/// The **only infra-shaped seam** of the LSP rung: a duplex JSON-RPC frame channel to a language
/// server. The live impl pipes a spawned process's stdio; the offline impl replays scripted frames.
pub trait LspTransport {
    /// Write one framed message (the driver hands raw JSON payload bytes; framing is the transport's).
    ///
    /// # Errors
    /// Transport failure (broken pipe, no server).
    fn write_frame(&mut self, payload: &[u8]) -> Result<(), LspError>;
    /// Block until one framed message is available and return its JSON payload bytes.
    ///
    /// # Errors
    /// Transport failure or EOF.
    fn read_frame(&mut self) -> Result<Vec<u8>, LspError>;
}

/// A boxed transport is itself a transport, so [`LspClient`] can hold `Box<dyn LspTransport>` (the
/// per-invocation factory type the driver uses).
impl LspTransport for Box<dyn LspTransport> {
    fn write_frame(&mut self, payload: &[u8]) -> Result<(), LspError> {
        (**self).write_frame(payload)
    }
    fn read_frame(&mut self) -> Result<Vec<u8>, LspError> {
        (**self).read_frame()
    }
}

/// **Live transport (infra):** a language server launched as a child process, JSON-RPC over its stdio.
///
/// This is the piece that genuinely needs infra — a real server binary on `PATH`, a workspace it has
/// permission to read and time to index. It is never used by the offline test; a deployment enables it
/// by pointing at the right server for the language (`rust-analyzer`, `gopls`, `pyright-langserver
/// --stdio`, `typescript-language-server --stdio`, `jdtls`).
pub struct StdioLspTransport {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    stdout: BufReader<std::process::ChildStdout>,
}

impl StdioLspTransport {
    /// Spawn `program args…` as a language server and pipe JSON-RPC over its stdio.
    ///
    /// # Errors
    /// [`LspError::Transport`] if the process cannot be spawned or its pipes cannot be captured.
    pub fn spawn(program: &str, args: &[&str]) -> Result<Self, LspError> {
        use std::process::{Command, Stdio};
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| LspError::Transport(format!("spawn {program}: {e}")))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| LspError::Transport("no child stdin".to_string()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| LspError::Transport("no child stdout".to_string()))?;
        Ok(Self {
            child,
            stdin,
            stdout: BufReader::new(stdout),
        })
    }
}

impl Drop for StdioLspTransport {
    fn drop(&mut self) {
        // Best-effort reap so a driver drop does not leak a server process.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl LspTransport for StdioLspTransport {
    fn write_frame(&mut self, payload: &[u8]) -> Result<(), LspError> {
        self.stdin.write_all(&encode_frame(payload))?;
        self.stdin.flush()?;
        Ok(())
    }
    fn read_frame(&mut self) -> Result<Vec<u8>, LspError> {
        read_frame(&mut self.stdout)
    }
}

/// **Offline transport (deterministic):** replays the exact framed JSON-RPC a server *would* emit, in
/// order, and records every frame the client wrote (for assertions). It uses the *same* [`encode_frame`]
/// / [`read_frame`] codec as the live transport, so the offline test exercises the real wire format.
pub struct ScriptedLspTransport {
    incoming: Cursor<Vec<u8>>,
    /// Raw payload bytes of every frame the client wrote, in order.
    sent: Vec<Vec<u8>>,
}

impl ScriptedLspTransport {
    /// Build a transport that will emit `server_messages` (as framed JSON) in order.
    #[must_use]
    pub fn new(server_messages: &[Value]) -> Self {
        let mut buf = Vec::new();
        for m in server_messages {
            buf.extend_from_slice(&encode_frame(&serde_json::to_vec(m).unwrap_or_default()));
        }
        Self {
            incoming: Cursor::new(buf),
            sent: Vec::new(),
        }
    }

    /// The decoded JSON of every request/notification the client sent (for test assertions).
    #[must_use]
    pub fn sent_messages(&self) -> Vec<Value> {
        self.sent
            .iter()
            .filter_map(|b| serde_json::from_slice(b).ok())
            .collect()
    }
}

impl LspTransport for ScriptedLspTransport {
    fn write_frame(&mut self, payload: &[u8]) -> Result<(), LspError> {
        self.sent.push(payload.to_vec());
        Ok(())
    }
    fn read_frame(&mut self) -> Result<Vec<u8>, LspError> {
        if self.incoming.position() as usize >= self.incoming.get_ref().len() {
            return Err(LspError::Transport(
                "no more scripted server frames".to_string(),
            ));
        }
        read_frame(&mut self.incoming)
    }
}

/// A JSON-RPC 2.0 LSP client over any [`LspTransport`]. Correlates responses to requests by `id` and
/// skips server-initiated notifications/requests it does not need (e.g. `window/logMessage`).
pub struct LspClient<T: LspTransport> {
    transport: T,
    next_id: i64,
}

impl<T: LspTransport> LspClient<T> {
    /// Wrap a transport.
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            next_id: 1,
        }
    }

    /// Send a request and return its `result`, correlating by `id` (skipping unrelated messages).
    ///
    /// # Errors
    /// Transport/protocol failure, or a JSON-RPC `error` from the server.
    pub fn request(&mut self, method: &str, params: Value) -> Result<Value, LspError> {
        let id = self.next_id;
        self.next_id += 1;
        let msg = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        self.transport.write_frame(&serde_json::to_vec(&msg)?)?;
        // Read until the response with our id arrives; skip notifications/other-id messages.
        loop {
            let raw = self.transport.read_frame()?;
            let v: Value = serde_json::from_slice(&raw)?;
            if v.get("id").and_then(Value::as_i64) != Some(id) {
                // A server notification or a server→client request; not our answer.
                continue;
            }
            if let Some(err) = v.get("error") {
                let m = err
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown error");
                return Err(LspError::Server(format!("{method}: {m}")));
            }
            return Ok(v.get("result").cloned().unwrap_or(Value::Null));
        }
    }

    /// Send a notification (no response expected).
    ///
    /// # Errors
    /// Transport failure.
    pub fn notify(&mut self, method: &str, params: Value) -> Result<(), LspError> {
        let msg = json!({"jsonrpc": "2.0", "method": method, "params": params});
        self.transport.write_frame(&serde_json::to_vec(&msg)?)
    }

    /// Perform the LSP `initialize` handshake for a workspace `root_uri`, then `initialized`.
    ///
    /// # Errors
    /// Any transport/protocol/server failure in the handshake.
    pub fn initialize(&mut self, root_uri: &str) -> Result<(), LspError> {
        let _server_caps = self.request(
            "initialize",
            json!({
                "processId": std::process::id(),
                "rootUri": root_uri,
                "capabilities": { "textDocument": { "rename": { "dynamicRegistration": false } } },
            }),
        )?;
        self.notify("initialized", json!({}))?;
        Ok(())
    }

    /// Open a document so the server has its text before a rename (`textDocument/didOpen`).
    ///
    /// # Errors
    /// Transport failure.
    pub fn did_open(&mut self, uri: &str, language_id: &str, text: &str) -> Result<(), LspError> {
        self.notify(
            "textDocument/didOpen",
            json!({
                "textDocument": {
                    "uri": uri,
                    "languageId": language_id,
                    "version": 1,
                    "text": text,
                }
            }),
        )
    }

    /// Request `textDocument/rename` at a symbol position and return the raw `WorkspaceEdit`.
    ///
    /// # Errors
    /// Transport/protocol failure or a server-side rejection.
    pub fn rename(
        &mut self,
        uri: &str,
        line: u32,
        character: u32,
        new_name: &str,
    ) -> Result<Value, LspError> {
        self.request(
            "textDocument/rename",
            json!({
                "textDocument": { "uri": uri },
                "position": { "line": line, "character": character },
                "newName": new_name,
            }),
        )
    }

    /// Politely shut the server down (`shutdown` request then `exit` notification). Best-effort.
    ///
    /// # Errors
    /// Transport/server failure of the `shutdown` request.
    pub fn shutdown(&mut self) -> Result<(), LspError> {
        let _ = self.request("shutdown", Value::Null)?;
        self.notify("exit", Value::Null)
    }
}

/// One `TextEdit` from a `WorkspaceEdit`: replace `[start, end)` with `new_text`. Positions are
/// 0-based `(line, character)`; `character` is a UTF-16 code-unit offset per the spec (equal to the
/// byte offset for ASCII/BMP source, which is what the offline codec test asserts).
#[derive(Debug, Clone, PartialEq, Eq)]
struct TextEdit {
    start_line: usize,
    start_char: usize,
    end_line: usize,
    end_char: usize,
    new_text: String,
}

/// Convert a 0-based `(line, character)` LSP position into a byte offset into `source`. Uses UTF-8
/// byte length per line including its terminator; `character` is treated as a byte offset within the
/// line (exact for ASCII, the honest limitation documented on [`TextEdit`]). Out-of-range positions
/// clamp to the end of the source so a malformed edit can never index out of bounds.
fn position_to_offset(source: &str, line: usize, character: usize) -> usize {
    let mut offset = 0usize;
    for (i, seg) in source.split_inclusive('\n').enumerate() {
        if i == line {
            // Clamp within this line's content (excluding a trailing '\n').
            let line_len = seg.strip_suffix('\n').unwrap_or(seg).len();
            let mut byte = offset + character.min(line_len);
            // Snap to a char boundary defensively.
            while byte < source.len() && !source.is_char_boundary(byte) {
                byte += 1;
            }
            return byte;
        }
        offset += seg.len();
    }
    source.len()
}

/// Apply a set of [`TextEdit`]s to `source`, highest-offset-first so earlier offsets stay valid.
fn apply_text_edits(source: &str, mut edits: Vec<TextEdit>) -> String {
    // Sort by start offset descending; ties broken by end offset descending.
    edits.sort_by(|a, b| {
        let sa = (a.start_line, a.start_char);
        let sb = (b.start_line, b.start_char);
        sb.cmp(&sa)
    });
    let mut out = source.to_string();
    for e in edits {
        let start = position_to_offset(&out, e.start_line, e.start_char);
        let end = position_to_offset(&out, e.end_line, e.end_char).max(start);
        out.replace_range(start..end, &e.new_text);
    }
    out
}

/// Parse the `TextEdit`s a `WorkspaceEdit` carries for `uri` (only the `changes` form; the versioned
/// `documentChanges` form is not needed for a single-file offline rename and is left for the live
/// path to extend). Returns an empty vec if the edit touched no other file.
fn text_edits_for(workspace_edit: &Value, uri: &str) -> Result<Vec<TextEdit>, LspError> {
    let changes = match workspace_edit.get("changes") {
        Some(c) => c,
        None => return Ok(Vec::new()),
    };
    let arr = match changes.get(uri).and_then(Value::as_array) {
        Some(a) => a,
        None => return Ok(Vec::new()),
    };
    let mut edits = Vec::with_capacity(arr.len());
    for te in arr {
        let range = te
            .get("range")
            .ok_or_else(|| LspError::Protocol("TextEdit missing range".to_string()))?;
        let get = |k1: &str, k2: &str| -> Result<usize, LspError> {
            range
                .get(k1)
                .and_then(|p| p.get(k2))
                .and_then(Value::as_u64)
                .map(|n| n as usize)
                .ok_or_else(|| LspError::Protocol(format!("TextEdit range missing {k1}.{k2}")))
        };
        edits.push(TextEdit {
            start_line: get("start", "line")?,
            start_char: get("start", "character")?,
            end_line: get("end", "line")?,
            end_char: get("end", "character")?,
            new_text: te
                .get("newText")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        });
    }
    Ok(edits)
}

/// The LSP `languageId` string a server expects for a [`CodeLanguage`].
#[must_use]
pub fn language_id(lang: CodeLanguage) -> &'static str {
    match lang {
        CodeLanguage::Rust => "rust",
        CodeLanguage::Python => "python",
        CodeLanguage::JavaScript => "javascript",
        CodeLanguage::TypeScript => "typescript",
        CodeLanguage::Go => "go",
        CodeLanguage::Java => "java",
        CodeLanguage::Cobol => "cobol",
        CodeLanguage::Other => "plaintext",
    }
}

/// The symbol-rename target a live `textDocument/rename` request needs: which document, the symbol's
/// 0-based position, and the new name.
///
/// Round `gap3-semantic-editing` item 1: this used to be baked into [`ServerLspRefactor`] at
/// *construction* time, which meant one driver instance could only ever answer the single rename it
/// was built for — an architectural mismatch with [`LspRefactor::apply`], whose original signature
/// carried no symbol/position and which [`crate::ladder::EditLadder`] is designed to call *repeatedly*
/// against one long-lived driver. Now it is computed **per call** inside [`ServerLspRefactor::apply`]
/// from the [`LspEditTarget`] the trait passes in, via [`resolve_rename_plan`] — so one driver instance
/// (one `open` factory + `root_uri`) genuinely serves arbitrary renames.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenamePlan {
    /// The document URI the server knows the buffer by (e.g. `file:///repo/src/a.rs`).
    pub uri: String,
    /// 0-based line of the symbol occurrence to rename.
    pub line: u32,
    /// 0-based (UTF-16) character offset of the symbol occurrence.
    pub character: u32,
    /// The new symbol name.
    pub new_name: String,
}

/// Whether `b` can be part of an identifier (ASCII alphanumeric or `_`) — used to bound a symbol match
/// to whole-word occurrences so a rename of `foo` never matches inside `foobar`/`barfoo`.
fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Find the byte offset of the first **whole-word** occurrence of `name` in `source`: the byte
/// immediately before and after the match (if any) must not itself be an identifier byte.
#[must_use]
fn find_symbol_offset(source: &str, name: &str) -> Option<usize> {
    if name.is_empty() {
        return None;
    }
    let bytes = source.as_bytes();
    let mut start = 0usize;
    while start <= source.len() {
        let rel = source.get(start..)?.find(name)?;
        let idx = start + rel;
        let before_ok = idx == 0 || !is_ident_byte(bytes[idx - 1]);
        let end = idx + name.len();
        let after_ok = end >= bytes.len() || !is_ident_byte(bytes[end]);
        if before_ok && after_ok {
            return Some(idx);
        }
        start = idx + 1;
    }
    None
}

/// Convert a byte offset into `source` to a 0-based `(line, character)` LSP position. `character` is
/// the byte offset within the line — exact for ASCII/ the honest limitation already documented on
/// [`position_to_offset`], which this is the inverse of.
#[must_use]
fn offset_to_line_char(source: &str, offset: usize) -> (u32, u32) {
    let mut line = 0u32;
    let mut line_start = 0usize;
    for (i, b) in source.as_bytes().iter().enumerate() {
        if i >= offset {
            break;
        }
        if *b == b'\n' {
            line += 1;
            line_start = i + 1;
        }
    }
    (line, (offset - line_start) as u32)
}

/// Resolve a [`RenamePlan`] from an [`LspEditTarget`] against `source`: locates the target's `symbol`
/// as a whole-word match and converts its byte offset to an LSP `(line, character)` position.
///
/// # Errors
/// [`LspError::Protocol`] if the target is missing `symbol`/`new_name`, or the symbol is not found in
/// `source` — both are honest "cannot even ask the server" states, not a server-side rejection.
pub fn resolve_rename_plan(target: &LspEditTarget, source: &str) -> Result<RenamePlan, LspError> {
    let symbol = target
        .symbol
        .as_deref()
        .ok_or_else(|| LspError::Protocol("rename target has no symbol name".to_string()))?;
    let new_name = target
        .new_name
        .as_deref()
        .ok_or_else(|| LspError::Protocol("rename target has no new_name".to_string()))?;
    let offset = find_symbol_offset(source, symbol)
        .ok_or_else(|| LspError::Protocol(format!("symbol {symbol:?} not found in source")))?;
    let (line, character) = offset_to_line_char(source, offset);
    Ok(RenamePlan {
        uri: target.uri.clone(),
        line,
        character,
        new_name: new_name.to_string(),
    })
}

/// A **real** [`LspRefactor`] that drives a live-or-scripted language server for a `RenameSymbol`
/// operation and applies the server's `WorkspaceEdit` to the source byte-precisely.
///
/// `open` yields a fresh [`LspTransport`] per invocation (a live driver spawns/attaches a server; the
/// offline test injects a [`ScriptedLspTransport`]). Only `RenameSymbol` is wired to the protocol; any
/// other op returns [`LspOutcome::Unavailable`] so the ladder falls to the AST rung — the driver never
/// claims a rung-1 result it did not compute. A transport error also degrades to `Unavailable` (a
/// missing server is not a refactor failure); a server-side rejection is a recorded [`LspOutcome::Failed`].
///
/// One instance is constructed **once** per language-server connection policy (just `open` +
/// `root_uri`) and reused across arbitrary renames — the rename's identity (symbol/position/new name)
/// comes from the [`LspEditTarget`] `apply()` receives per call, not from construction-time state (the
/// `gap3-semantic-editing` item-1 fix; see [`RenamePlan`]'s docs for the mismatch this replaced).
pub struct ServerLspRefactor<F>
where
    F: Fn() -> Result<Box<dyn LspTransport>, LspError>,
{
    open: F,
    root_uri: String,
}

impl<F> ServerLspRefactor<F>
where
    F: Fn() -> Result<Box<dyn LspTransport>, LspError>,
{
    /// Build a driver bound to a connection policy (`open` a transport, against `root_uri`). No
    /// specific rename is baked in — `apply()` resolves each call's [`RenamePlan`] fresh from the
    /// [`LspEditTarget`] it is given.
    pub fn new(open: F, root_uri: impl Into<String>) -> Self {
        Self {
            open,
            root_uri: root_uri.into(),
        }
    }

    /// Run the full rename round trip against a fresh transport and return the edited source.
    fn run_rename(
        &self,
        lang: CodeLanguage,
        source: &str,
        plan: &RenamePlan,
    ) -> Result<String, LspError> {
        let transport = (self.open)()?;
        let mut client = LspClient::new(transport);
        client.initialize(&self.root_uri)?;
        client.did_open(&plan.uri, language_id(lang), source)?;
        let ws_edit = client.rename(&plan.uri, plan.line, plan.character, &plan.new_name)?;
        if ws_edit.is_null() {
            return Err(LspError::Server(
                "server declined the rename (null WorkspaceEdit)".to_string(),
            ));
        }
        let edits = text_edits_for(&ws_edit, &plan.uri)?;
        if edits.is_empty() {
            return Err(LspError::Server(
                "WorkspaceEdit touched no edits for the target document".to_string(),
            ));
        }
        let edited = apply_text_edits(source, edits);
        let _ = client.shutdown();
        Ok(edited)
    }
}

impl<F> LspRefactor for ServerLspRefactor<F>
where
    F: Fn() -> Result<Box<dyn LspTransport>, LspError>,
{
    fn apply(
        &self,
        lang: CodeLanguage,
        op: SemanticOp,
        source: &str,
        target: &LspEditTarget,
    ) -> LspOutcome {
        if op != SemanticOp::RenameSymbol {
            return LspOutcome::Unavailable(format!(
                "lsp driver wires only RenameSymbol; {op:?} falls to AST"
            ));
        }
        let plan = match resolve_rename_plan(target, source) {
            Ok(p) => p,
            // Cannot even form the request (no symbol/position resolvable) → unavailable, not a
            // server-side failure; the ladder falls to AST without a confidence penalty for "no server".
            Err(e) => return LspOutcome::Unavailable(e.to_string()),
        };
        match self.run_rename(lang, source, &plan) {
            Ok(edited) => LspOutcome::Applied(edited),
            // No server / broken transport → fall down without penalty (not a failure).
            Err(LspError::Transport(why)) => {
                LspOutcome::Unavailable(format!("no live server: {why}"))
            }
            Err(e) => LspOutcome::Failed(e.to_string()),
        }
    }
}

/// A concrete factory for the offline transport, usable by tests and deployments that want to inject a
/// scripted server. Kept out of `cfg(test)` so a deployment can also record/replay real sessions.
pub fn scripted_transport_factory(
    server_messages: Vec<Value>,
) -> impl Fn() -> Result<Box<dyn LspTransport>, LspError> {
    move || Ok(Box::new(ScriptedLspTransport::new(&server_messages)) as Box<dyn LspTransport>)
}

/// **Boot-time availability probe** for a configured LSP binary (GAP-FIX
/// gap6-semantic-lsp-signature-layermanifest item 1) — a config-gate check, NOT a live protocol
/// handshake. A real language server run bare speaks LSP over stdio and blocks forever waiting for an
/// `initialize` request, so "does it start and answer" cannot be probed by spawning it plain and
/// waiting for exit; instead this runs `program args…` (a composition root passes `["--version"]` — a
/// flag every mainstream server this crate names, rust-analyzer/gopls/pyright/tsserver/jdtls, answers
/// immediately and exits on) bounded by `timeout`, so a deployment can decide WHETHER to wire
/// [`ServerLspRefactor`] without ever risking a hang on daemon boot.
///
/// Mirrors the sandboxing discipline `ainxt-pipeline::cargo_tools` already established for a real
/// subprocess call: a cleared environment (`PATH` only — a third-party binary never sees the
/// deployment's other env/secrets), no stdin (`Stdio::null()`), and a bounded poll loop that kills the
/// child the moment it outlives `timeout` — so a missing binary (fails to spawn → instant `false`), a
/// broken one (non-zero exit → `false`), and a hung one (killed at the deadline → `false`) are all
/// handled without ever blocking the caller past `timeout`. Returns `true` only on a clean, in-time
/// exit success.
#[must_use]
pub fn probe_stdio_lsp_available(
    program: &str,
    args: &[&str],
    timeout: std::time::Duration,
) -> bool {
    use std::process::{Command, Stdio};
    use std::time::Instant;

    let mut cmd = Command::new(program);
    cmd.args(args);
    cmd.env_clear();
    if let Ok(path) = std::env::var("PATH") {
        cmd.env("PATH", path);
    }
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::null());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        // Missing / non-executable / permission-denied binary — fails fast, never hangs boot.
        Err(_) => return false,
    };

    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return false; // hung past the deadline — never let a bad binary hang the daemon
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Err(_) => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_codec_round_trips() {
        let payload = br#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#;
        let framed = encode_frame(payload);
        let text = String::from_utf8(framed.clone()).unwrap();
        assert!(text.starts_with("Content-Length: 46\r\n\r\n"));
        let mut cur = Cursor::new(framed);
        let decoded = read_frame(&mut cur).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn read_frame_is_case_insensitive_and_skips_extra_headers() {
        let mut raw = b"content-length: 2\r\nX-Extra: y\r\n\r\n{}".to_vec();
        // trailing bytes after the body must not be consumed
        raw.extend_from_slice(b"leftover");
        let mut cur = Cursor::new(raw);
        let decoded = read_frame(&mut cur).unwrap();
        assert_eq!(decoded, b"{}");
    }

    #[test]
    fn position_offset_and_edit_application() {
        let src = "fn a() {}\nfn b() {}\n";
        // line 1 char 3 is the 'b' in `fn b`.
        let off = position_to_offset(src, 1, 3);
        assert_eq!(&src[off..off + 1], "b");
        let edited = apply_text_edits(
            src,
            vec![TextEdit {
                start_line: 1,
                start_char: 3,
                end_line: 1,
                end_char: 4,
                new_text: "renamed".to_string(),
            }],
        );
        assert_eq!(edited, "fn a() {}\nfn renamed() {}\n");
    }

    #[test]
    fn client_correlates_response_and_skips_notifications() {
        // Server emits a log notification BEFORE the initialize response — the client must skip it.
        let transport = ScriptedLspTransport::new(&[
            json!({"jsonrpc":"2.0","method":"window/logMessage","params":{"type":3,"message":"indexing"}}),
            json!({"jsonrpc":"2.0","id":1,"result":{"capabilities":{}}}),
        ]);
        let mut client = LspClient::new(transport);
        client.initialize("file:///repo").unwrap();
        let sent = client.transport.sent_messages();
        assert_eq!(sent[0]["method"], "initialize");
        assert_eq!(sent[1]["method"], "initialized");
    }

    #[test]
    fn server_error_becomes_lsp_error() {
        let transport = ScriptedLspTransport::new(&[
            json!({"jsonrpc":"2.0","id":1,"result":{"capabilities":{}}}),
            json!({"jsonrpc":"2.0","id":2,"error":{"code":-32603,"message":"boom"}}),
        ]);
        let mut client = LspClient::new(transport);
        client.initialize("file:///repo").unwrap();
        let err = client.rename("file:///repo/a.rs", 0, 3, "x").unwrap_err();
        assert!(matches!(err, LspError::Server(_)));
    }

    // ---- gap3-semantic-editing item 1: RenamePlan is resolved per call from an `LspEditTarget`, not
    // baked into `ServerLspRefactor` at construction (`ladder.rs`'s `LspEditTarget` doc explains why). ----

    #[test]
    fn find_symbol_offset_matches_whole_words_only() {
        // "charge" must not match inside "discharge" or "chargeback".
        let src = "fn discharge() {}\nfn chargeback() {}\nfn charge() {}\n";
        let off = find_symbol_offset(src, "charge").expect("whole-word match");
        assert_eq!(&src[off..off + "charge".len()], "charge");
        assert_eq!(off, src.rfind("fn charge()").unwrap() + 3);
    }

    #[test]
    fn find_symbol_offset_returns_none_when_absent() {
        assert_eq!(find_symbol_offset("fn a() {}", "nope"), None);
        assert_eq!(find_symbol_offset("fn a() {}", ""), None);
    }

    #[test]
    fn offset_to_line_char_is_the_inverse_of_position_to_offset() {
        let src = "fn a() {}\nfn b() {}\n";
        let off = position_to_offset(src, 1, 3); // the 'b' in `fn b`
        assert_eq!(offset_to_line_char(src, off), (1, 3));
    }

    #[test]
    fn resolve_rename_plan_finds_symbol_position_and_carries_new_name() {
        let src = "fn caller() {\n    old_name();\n}\n";
        let target = LspEditTarget::rename("file:///a.rs", "old_name", "renamed");
        let plan = resolve_rename_plan(&target, src).expect("resolves");
        assert_eq!(plan.uri, "file:///a.rs");
        assert_eq!(plan.new_name, "renamed");
        assert_eq!((plan.line, plan.character), (1, 4));
    }

    #[test]
    fn resolve_rename_plan_fails_honestly_when_symbol_absent() {
        let target = LspEditTarget::rename("file:///a.rs", "not_here", "x");
        let err = resolve_rename_plan(&target, "fn a() {}").unwrap_err();
        assert!(matches!(err, LspError::Protocol(_)));
    }

    /// The core architectural proof: ONE `ServerLspRefactor` instance (built once via `new(open,
    /// root_uri)`, no rename baked in) correctly services TWO DIFFERENT renames via sequential `apply()`
    /// calls, each carrying its own symbol/new_name in the `LspEditTarget`. Before the fix this was
    /// structurally impossible — `RenamePlan` was fixed at construction, so the trait's `apply(lang, op,
    /// source)` had no way to tell the driver which symbol/position a given call was even about.
    #[test]
    fn one_driver_instance_serves_two_different_renames_by_target() {
        use std::cell::Cell;

        fn scripted_rename_result(
            new: &str,
            line: u32,
            character: u32,
            match_len: u32,
        ) -> Vec<Value> {
            vec![
                json!({"jsonrpc":"2.0","id":1,"result":{"capabilities":{}}}),
                json!({
                    "jsonrpc":"2.0","id":2,
                    "result":{"changes":{"file:///a.rs":[
                        {"range":{"start":{"line":line,"character":character},
                                  "end":{"line":line,"character":character + match_len}},
                         "newText": new}
                    ]}}
                }),
            ]
        }

        // The transport factory alternates between two distinct canned server scripts per `open()`
        // call, standing in for a real server that would answer each request on its own merits.
        let scripts = [
            scripted_rename_result("one", 0, 3, "alpha".len() as u32),
            scripted_rename_result("two", 0, 3, "beta".len() as u32),
        ];
        let call = Cell::new(0usize);
        let open = move || {
            let i = call.get();
            call.set(i + 1);
            Ok(Box::new(ScriptedLspTransport::new(&scripts[i])) as Box<dyn LspTransport>)
        };
        let driver = ServerLspRefactor::new(open, "file:///repo");

        // First rename through the driver: "alpha" -> "one".
        let out1 = driver.apply(
            CodeLanguage::Rust,
            SemanticOp::RenameSymbol,
            "fn alpha() {}\n",
            &LspEditTarget::rename("file:///a.rs", "alpha", "one"),
        );
        assert_eq!(out1, LspOutcome::Applied("fn one() {}\n".to_string()));

        // Second rename through the SAME driver instance: a completely different symbol/new_name/
        // source — proving `apply()` resolved this call's plan from ITS target, not a stale one.
        let out2 = driver.apply(
            CodeLanguage::Rust,
            SemanticOp::RenameSymbol,
            "fn beta() {}\n",
            &LspEditTarget::rename("file:///a.rs", "beta", "two"),
        );
        assert_eq!(out2, LspOutcome::Applied("fn two() {}\n".to_string()));
    }

    // ---- GAP-FIX gap6-semantic-lsp-signature-layermanifest item 1: the config-gated boot-time
    // availability probe never hangs the daemon on a missing/broken/hung binary. ----

    #[test]
    fn probe_reports_false_fast_for_a_missing_binary() {
        let start = std::time::Instant::now();
        let ok = probe_stdio_lsp_available(
            "ainxt-definitely-not-a-real-lsp-binary-xyz",
            &["--version"],
            std::time::Duration::from_secs(5),
        );
        assert!(!ok);
        assert!(
            start.elapsed() < std::time::Duration::from_secs(1),
            "a missing binary must fail fast at spawn, never wait out the timeout"
        );
    }

    #[test]
    fn probe_reports_true_for_a_binary_that_exits_cleanly_within_the_timeout() {
        // `true` ignores its arguments and exits 0 immediately on every Unix this crate ships for —
        // stands in for a real LSP server answering `--version` quickly.
        let ok =
            probe_stdio_lsp_available("true", &["--version"], std::time::Duration::from_secs(5));
        assert!(
            ok,
            "a binary that exits 0 within the timeout must probe available"
        );
    }

    #[test]
    fn probe_reports_false_for_a_binary_that_exits_nonzero() {
        let ok = probe_stdio_lsp_available("false", &[], std::time::Duration::from_secs(5));
        assert!(!ok, "a nonzero exit must never probe as available");
    }

    #[test]
    fn probe_kills_and_reports_false_for_a_binary_that_hangs_past_the_deadline() {
        // A real bare language server behaves exactly like this (blocks forever on stdin) — the probe
        // must kill it and return false, never block the caller past the deadline.
        let start = std::time::Instant::now();
        let ok = probe_stdio_lsp_available(
            "sh",
            &["-c", "sleep 5"],
            std::time::Duration::from_millis(300),
        );
        assert!(!ok);
        assert!(
            start.elapsed() < std::time::Duration::from_secs(2),
            "a hung binary must be killed at the deadline, never waited out to completion"
        );
    }
}
