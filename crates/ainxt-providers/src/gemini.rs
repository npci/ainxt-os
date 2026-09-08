// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Google Gemini `:streamGenerateContent` adapter.
//!
//! Completes the model-agnostic trio (OpenAI-schema, Anthropic, Gemini) mandated by the
//! multi-model policy — every feature must work irrespective of vendor. Gemini's streaming wire
//! format differs from the other two: requested with `?alt=sse`, it emits `data: {json}` lines
//! whose JSON is a `GenerateContentResponse` (`candidates[].content.parts[].text`), carries usage
//! in a cumulative `usageMetadata`, uses a `{code,message,status}` error shape, and — unlike
//! OpenAI — sends **no `[DONE]` sentinel** (the stream simply ends; [`crate::sse::drive`] supplies
//! the single terminal [`Event::Done`]).
//!
//! As with the sibling adapters, the SSE→[`Event`] mapping is a pure [`GeminiNormalizer`] the unit
//! tests drive with recorded fixture bytes — no network, no key. Usage is emitted **once**, gated on
//! the terminal chunk (the one bearing a `finishReason`), so Gemini's per-chunk cumulative
//! `usageMetadata` is not double-counted.

use ainxt_protocol::Event;
use ainxt_runtime::provider::Provider;
use ainxt_types::DataClass;
use serde::Deserialize;
use tokio::sync::mpsc;

use crate::sse::{drive, LineBuf, SseNormalizer};

const CHANNEL_CAP: usize = 64;

/// Provider for the Google Gemini generative-language API.
pub struct GeminiProvider {
    client: reqwest::Client,
    base_url: String,
    api_key: String,
    model: String,
    eligible: Vec<DataClass>,
}

impl GeminiProvider {
    /// Construct an adapter. `base_url` is the API root (e.g.
    /// `https://generativelanguage.googleapis.com/v1beta`); `model` (e.g. `gemini-2.5-flash`)
    /// doubles as this provider's routing [`id`](Provider::id). `eligible` is the set of data
    /// classes this endpoint may serve (ADR-012) — a cloud vendor is typically `Public`/`Internal`
    /// only, never regulated/PII, which the router enforces non-overridably.
    pub fn new(
        base_url: impl Into<String>,
        api_key: impl Into<String>,
        model: impl Into<String>,
        eligible: Vec<DataClass>,
    ) -> Self {
        Self {
            // Same stall-bounding as the sibling adapters: a hung upstream becomes a retryable
            // error rather than an indefinitely-parked task. `read_timeout` is per-chunk inactivity,
            // so it never cuts off a legitimately long streaming answer.
            client: reqwest::Client::builder()
                .connect_timeout(std::time::Duration::from_secs(10))
                .read_timeout(std::time::Duration::from_secs(60))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            base_url: base_url.into(),
            api_key: api_key.into(),
            model: model.into(),
            eligible,
        }
    }

    fn build_request(&self, prompt: &str) -> reqwest::RequestBuilder {
        // `?alt=sse` selects the line-delimited SSE transport (vs the default streamed JSON array),
        // so the shared LineBuf/`data:` plumbing applies unchanged.
        let url = format!(
            "{}/models/{}:streamGenerateContent?alt=sse",
            self.base_url.trim_end_matches('/'),
            self.model
        );
        let body = serde_json::json!({
            "contents": [ { "role": "user", "parts": [ { "text": prompt } ] } ],
        });
        let mut rb = self.client.post(url).json(&body);
        if !self.api_key.is_empty() {
            // Header auth keeps the key out of request URLs / proxy logs (vs the `?key=` form).
            rb = rb.header("x-goog-api-key", &self.api_key);
        }
        rb
    }
}

impl Provider for GeminiProvider {
    fn id(&self) -> &str {
        &self.model
    }

    fn eligible(&self, data_class: DataClass) -> bool {
        self.eligible.contains(&data_class)
    }

    fn stream(&self, prompt: &str) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(CHANNEL_CAP);
        let request = self.build_request(prompt);
        tokio::spawn(drive(request, GeminiNormalizer::new(), tx));
        rx
    }
}

// ============================ Wire types ============================

#[derive(Deserialize)]
struct GeminiChunk {
    #[serde(default)]
    error: Option<GeminiError>,
    #[serde(default)]
    candidates: Vec<GeminiCandidate>,
    #[serde(default, rename = "usageMetadata")]
    usage: Option<GeminiUsage>,
}

#[derive(Deserialize)]
struct GeminiCandidate {
    #[serde(default)]
    content: Option<GeminiContent>,
    /// Present only on the terminal chunk for this candidate (e.g. `"STOP"`, `"MAX_TOKENS"`,
    /// `"SAFETY"`). Used to gate one-shot usage emission.
    #[serde(default, rename = "finishReason")]
    finish_reason: Option<String>,
}

#[derive(Deserialize, Default)]
struct GeminiContent {
    #[serde(default)]
    parts: Vec<GeminiPart>,
}

#[derive(Deserialize, Default)]
struct GeminiPart {
    #[serde(default)]
    text: Option<String>,
}

#[derive(Deserialize)]
struct GeminiUsage {
    #[serde(default, rename = "promptTokenCount")]
    prompt_token_count: u64,
    #[serde(default, rename = "candidatesTokenCount")]
    candidates_token_count: u64,
}

/// Gemini's error object shape: `{"error":{"code":429,"message":"...","status":"RESOURCE_EXHAUSTED"}}`.
#[derive(Deserialize)]
struct GeminiError {
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    status: Option<String>,
}

impl GeminiError {
    fn describe(&self) -> String {
        match (self.status.as_deref(), self.message.as_deref()) {
            (Some(s), Some(m)) => format!("{s}: {m}"),
            (None, Some(m)) => m.to_string(),
            (Some(s), None) => s.to_string(),
            (None, None) => "gemini error".to_string(),
        }
    }
}

impl GeminiChunk {
    fn into_events(self) -> Vec<Event> {
        if let Some(err) = self.error {
            return vec![Event::Error(err.describe())];
        }
        let mut out = Vec::new();
        let mut terminal = false;
        for cand in self.candidates {
            if cand.finish_reason.is_some() {
                terminal = true;
            }
            if let Some(content) = cand.content {
                for part in content.parts {
                    if let Some(text) = part.text {
                        if !text.is_empty() {
                            out.push(Event::TextDelta(text));
                        }
                    }
                }
            }
        }
        // `usageMetadata` is cumulative and repeats across chunks; emit it once, on the terminal
        // chunk, so tokens are counted exactly once.
        if terminal {
            if let Some(u) = self.usage {
                out.push(Event::Usage {
                    input_tokens: u.prompt_token_count,
                    output_tokens: u.candidates_token_count,
                });
            }
        }
        out
    }
}

// ============================ Normalizer ============================

/// Pure SSE→[`Event`] translator for the Gemini `:streamGenerateContent?alt=sse` schema.
pub(crate) struct GeminiNormalizer {
    lines: LineBuf,
}

impl GeminiNormalizer {
    pub(crate) fn new() -> Self {
        Self {
            lines: LineBuf::default(),
        }
    }

    fn handle_line(&mut self, line: &str) -> Vec<Event> {
        let line = line.trim();
        // Skip blank lines, SSE comments (":"), and non-data fields ("event:").
        let Some(payload) = line.strip_prefix("data:") else {
            return Vec::new();
        };
        let payload = payload.trim();
        if payload.is_empty() {
            return Vec::new();
        }
        // Gemini sends no `[DONE]` sentinel; the terminal `Event::Done` is `drive`'s job.
        match serde_json::from_str::<GeminiChunk>(payload) {
            Ok(chunk) => chunk.into_events(),
            Err(e) => vec![Event::Error(format!("gemini: malformed SSE chunk: {e}"))],
        }
    }
}

impl SseNormalizer for GeminiNormalizer {
    fn push_bytes(&mut self, bytes: &[u8]) -> Vec<Event> {
        let mut out = Vec::new();
        for line in self.lines.push(bytes) {
            out.extend(self.handle_line(&line));
        }
        out
    }

    fn finish(&mut self) -> Vec<Event> {
        match self.lines.take_remainder() {
            Some(rem) => self.handle_line(&rem),
            None => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A realistic Gemini SSE stream: two text deltas, then a terminal chunk carrying an empty
    /// part, a `finishReason`, and the cumulative `usageMetadata`.
    fn fixture() -> String {
        [
            r#"data: {"candidates":[{"content":{"parts":[{"text":"Hello"}],"role":"model"},"index":0}]}"#,
            r#"data: {"candidates":[{"content":{"parts":[{"text":" world"}],"role":"model"},"index":0}]}"#,
            r#"data: {"candidates":[{"content":{"parts":[{"text":""}],"role":"model"},"finishReason":"STOP","index":0}],"usageMetadata":{"promptTokenCount":9,"candidatesTokenCount":2,"totalTokenCount":11}}"#,
        ]
        .join("\n\n")
            + "\n"
    }

    fn run(bytes: &[u8]) -> Vec<Event> {
        let mut n = GeminiNormalizer::new();
        let mut out = n.push_bytes(bytes);
        out.extend(n.finish());
        out
    }

    /// The normalizer's own contract (Done is added by `drive`, not the normalizer — Gemini has no
    /// `[DONE]` sentinel — so it is intentionally absent here).
    fn expected() -> Vec<Event> {
        vec![
            Event::TextDelta("Hello".into()),
            Event::TextDelta(" world".into()),
            Event::Usage {
                input_tokens: 9,
                output_tokens: 2,
            },
        ]
    }

    #[test]
    fn parses_full_stream() {
        assert_eq!(run(fixture().as_bytes()), expected());
    }

    #[test]
    fn reassembles_when_split_byte_by_byte() {
        // Prove the line buffer stitches chunks that break mid-line (and mid-multibyte).
        let f = fixture();
        let mut n = GeminiNormalizer::new();
        let mut out = Vec::new();
        for b in f.as_bytes() {
            out.extend(n.push_bytes(std::slice::from_ref(b)));
        }
        out.extend(n.finish());
        assert_eq!(out, expected());
    }

    #[test]
    fn usage_is_emitted_once_only_on_the_terminal_chunk() {
        // A non-terminal chunk that (as Gemini sometimes does) already carries cumulative usage must
        // NOT emit a Usage event — only the finishReason-bearing chunk does. Otherwise tokens would
        // be counted several times over a long stream.
        let non_terminal = r#"data: {"candidates":[{"content":{"parts":[{"text":"Hi"}],"role":"model"},"index":0}],"usageMetadata":{"promptTokenCount":5,"candidatesTokenCount":1,"totalTokenCount":6}}"#;
        let out = run(format!("{non_terminal}\n\n").as_bytes());
        assert_eq!(
            out,
            vec![Event::TextDelta("Hi".into())],
            "usage leaked from a non-terminal chunk"
        );
    }

    #[test]
    fn maps_error_payload() {
        let bytes = br#"data: {"error":{"code":429,"message":"Resource has been exhausted","status":"RESOURCE_EXHAUSTED"}}
"#;
        assert_eq!(
            run(bytes),
            vec![Event::Error(
                "RESOURCE_EXHAUSTED: Resource has been exhausted".into()
            )]
        );
    }

    #[test]
    fn malformed_json_becomes_error_event() {
        let out = run(b"data: {not json}\n\n");
        assert_eq!(out.len(), 1);
        assert!(matches!(&out[0], Event::Error(m) if m.contains("malformed")));
    }

    #[test]
    fn multibyte_text_survives_byte_split() {
        // A UTF-8 multibyte grapheme ("₹" = 3 bytes) split across chunks must reassemble intact.
        let chunk = r#"data: {"candidates":[{"content":{"parts":[{"text":"₹100"}],"role":"model"},"index":0}]}"#;
        let f = format!("{chunk}\n\n");
        let mut n = GeminiNormalizer::new();
        let mut out = Vec::new();
        for b in f.as_bytes() {
            out.extend(n.push_bytes(std::slice::from_ref(b)));
        }
        out.extend(n.finish());
        assert_eq!(out, vec![Event::TextDelta("₹100".into())]);
    }

    // Live smoke test — skipped unless AX_GEMINI_API_KEY is exported.
    #[tokio::test]
    #[ignore]
    async fn live_stream_reaches_text() {
        let Ok(api_key) = std::env::var("AX_GEMINI_API_KEY") else {
            eprintln!("AX_GEMINI_API_KEY unset; skipping");
            return;
        };
        let base_url = std::env::var("AX_GEMINI_BASE_URL")
            .unwrap_or_else(|_| "https://generativelanguage.googleapis.com/v1beta".into());
        let model = std::env::var("AX_GEMINI_MODEL").unwrap_or_else(|_| "gemini-2.5-flash".into());

        let provider = GeminiProvider::new(base_url, api_key, model, vec![DataClass::Public]);
        let mut rx = provider.stream("Reply with the single word: hello.");

        let mut saw_text = false;
        let mut saw_done = false;
        while let Some(ev) = rx.recv().await {
            match ev {
                Event::TextDelta(_) => saw_text = true,
                Event::Done => {
                    saw_done = true;
                    break;
                }
                Event::Error(e) => panic!("provider error: {e}"),
                _ => {}
            }
        }
        assert!(saw_done, "stream ended without Done");
        assert!(saw_text, "stream produced no text");
    }
}
