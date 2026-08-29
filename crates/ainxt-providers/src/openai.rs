// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! OpenAI `/chat/completions` schema adapter.
//!
//! One code path covers OpenAI, vLLM, Groq, and local servers — they share the
//! `/chat/completions` streaming schema; only `base_url` and the API key differ.
//! The SSE→[`Event`] mapping lives in [`OpenAiNormalizer`], a pure component the
//! unit tests exercise with recorded fixture bytes (no network, no key).

use ainxt_protocol::Event;
use ainxt_runtime::provider::Provider;
use ainxt_types::DataClass;
use serde::Deserialize;
use tokio::sync::mpsc;

use crate::label_model::{ConstrainedProvider, LabelGrammar};
use crate::sse::{drive, ApiError, LineBuf, SseNormalizer};

const CHANNEL_CAP: usize = 64;

/// Provider for any endpoint speaking the OpenAI `/chat/completions` schema.
pub struct OpenAiSchemaProvider {
    client: reqwest::Client,
    base_url: String,
    api_key: String,
    model: String,
    eligible: Vec<DataClass>,
}

impl OpenAiSchemaProvider {
    /// Construct an adapter. `base_url` is the API root (e.g.
    /// `https://api.openai.com/v1` or a local/Groq/vLLM root); `model` doubles
    /// as this provider's routing [`id`](Provider::id). `eligible` is the set of
    /// data classes this endpoint is permitted to serve (ADR-012).
    pub fn new(
        base_url: impl Into<String>,
        api_key: impl Into<String>,
        model: impl Into<String>,
        eligible: Vec<DataClass>,
    ) -> Self {
        Self {
            // Bound a stalled upstream: a connect/read timeout turns a hung stream into a
            // (retryable) error instead of an indefinitely-parked task, so cancellation and
            // failover can free the connection. `read_timeout` is per-chunk inactivity, so it
            // does not cut off a legitimately long streaming response.
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
        self.build_request_with(prompt, None)
    }

    /// Build the `/chat/completions` request, optionally pinning decoding to a label
    /// grammar (CONV-03). When `grammar` is `Some`, we emit both `guided_choice` (the
    /// vLLM knob for "exactly one of these strings") and `guided_grammar` (GBNF for
    /// llama.cpp), plus a `response_format` json-schema mirror — every OpenAI-schema
    /// OSS server that supports constrained decoding honors at least one of these, and
    /// servers that don't fall back to the human-readable constraint line in `prompt`.
    fn build_request_with(
        &self,
        prompt: &str,
        grammar: Option<&LabelGrammar>,
    ) -> reqwest::RequestBuilder {
        let url = format!("{}/chat/completions", self.base_url.trim_end_matches('/'));
        let mut body = serde_json::json!({
            "model": self.model,
            "stream": true,
            // Ask the server to emit a final usage-only chunk.
            "stream_options": { "include_usage": true },
            "messages": [{ "role": "user", "content": prompt }],
        });
        if let Some(g) = grammar.filter(|g| !g.is_empty()) {
            if let Some(obj) = body.as_object_mut() {
                obj.insert(
                    "guided_choice".into(),
                    serde_json::Value::from(g.alternatives().to_vec()),
                );
                obj.insert(
                    "guided_grammar".into(),
                    serde_json::Value::from(g.to_gbnf()),
                );
                obj.insert(
                    "response_format".into(),
                    serde_json::json!({
                        "type": "json_schema",
                        "json_schema": {
                            "name": "intent_label",
                            "strict": true,
                            "schema": g.to_json_schema(),
                        }
                    }),
                );
            }
        }
        let mut rb = self.client.post(url).json(&body);
        if !self.api_key.is_empty() {
            rb = rb.bearer_auth(&self.api_key);
        }
        rb
    }
}

impl ConstrainedProvider for OpenAiSchemaProvider {
    fn stream_constrained(
        &self,
        prompt: &str,
        grammar: Option<&LabelGrammar>,
    ) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(CHANNEL_CAP);
        let request = self.build_request_with(prompt, grammar);
        tokio::spawn(drive(request, OpenAiNormalizer::new(), tx));
        rx
    }
}

impl Provider for OpenAiSchemaProvider {
    fn id(&self) -> &str {
        &self.model
    }

    fn eligible(&self, data_class: DataClass) -> bool {
        self.eligible.contains(&data_class)
    }

    fn stream(&self, prompt: &str) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(CHANNEL_CAP);
        let request = self.build_request(prompt);
        tokio::spawn(drive(request, OpenAiNormalizer::new(), tx));
        rx
    }
}

// ============================ Wire types ============================

#[derive(Deserialize)]
struct OpenAiChunk {
    #[serde(default)]
    error: Option<ApiError>,
    #[serde(default)]
    choices: Vec<OpenAiChoice>,
    #[serde(default)]
    usage: Option<OpenAiUsage>,
}

#[derive(Deserialize)]
struct OpenAiChoice {
    #[serde(default)]
    delta: OpenAiDelta,
}

#[derive(Deserialize, Default)]
struct OpenAiDelta {
    #[serde(default)]
    content: Option<String>,
}

#[derive(Deserialize)]
struct OpenAiUsage {
    #[serde(default)]
    prompt_tokens: u64,
    #[serde(default)]
    completion_tokens: u64,
}

impl OpenAiChunk {
    fn into_events(self) -> Vec<Event> {
        if let Some(err) = self.error {
            return vec![Event::Error(err.describe("openai"))];
        }
        let mut out = Vec::new();
        for choice in self.choices {
            if let Some(text) = choice.delta.content {
                if !text.is_empty() {
                    out.push(Event::TextDelta(text));
                }
            }
        }
        if let Some(u) = self.usage {
            out.push(Event::Usage {
                input_tokens: u.prompt_tokens,
                output_tokens: u.completion_tokens,
            });
        }
        out
    }
}

// ============================ Normalizer ============================

/// Pure SSE→[`Event`] translator for the OpenAI `/chat/completions` schema.
pub(crate) struct OpenAiNormalizer {
    lines: LineBuf,
}

impl OpenAiNormalizer {
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
        if payload == "[DONE]" {
            return vec![Event::Done];
        }
        match serde_json::from_str::<OpenAiChunk>(payload) {
            Ok(chunk) => chunk.into_events(),
            Err(e) => vec![Event::Error(format!("openai: malformed SSE chunk: {e}"))],
        }
    }
}

impl SseNormalizer for OpenAiNormalizer {
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

    /// A realistic OpenAI stream: role priming, two content deltas, a stop
    /// chunk, a usage-only trailer, and the `[DONE]` sentinel.
    fn fixture() -> String {
        [
            r#"data: {"id":"chatcmpl-1","object":"chat.completion.chunk","model":"gpt-x","choices":[{"index":0,"delta":{"role":"assistant","content":""},"finish_reason":null}]}"#,
            r#"data: {"id":"chatcmpl-1","object":"chat.completion.chunk","model":"gpt-x","choices":[{"index":0,"delta":{"content":"Hello"},"finish_reason":null}]}"#,
            r#"data: {"id":"chatcmpl-1","object":"chat.completion.chunk","model":"gpt-x","choices":[{"index":0,"delta":{"content":" world"},"finish_reason":null}]}"#,
            r#"data: {"id":"chatcmpl-1","object":"chat.completion.chunk","model":"gpt-x","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#,
            r#"data: {"id":"chatcmpl-1","object":"chat.completion.chunk","model":"gpt-x","choices":[],"usage":{"prompt_tokens":9,"completion_tokens":2,"total_tokens":11}}"#,
            "data: [DONE]",
        ]
        .join("\n\n")
            + "\n"
    }

    fn run(bytes: &[u8]) -> Vec<Event> {
        let mut n = OpenAiNormalizer::new();
        let mut out = n.push_bytes(bytes);
        out.extend(n.finish());
        out
    }

    fn expected() -> Vec<Event> {
        vec![
            Event::TextDelta("Hello".into()),
            Event::TextDelta(" world".into()),
            Event::Usage {
                input_tokens: 9,
                output_tokens: 2,
            },
            Event::Done,
        ]
    }

    #[test]
    fn parses_full_stream() {
        assert_eq!(run(fixture().as_bytes()), expected());
    }

    #[test]
    fn reassembles_when_split_byte_by_byte() {
        // Prove the line buffer stitches chunks that break mid-line.
        let f = fixture();
        let mut n = OpenAiNormalizer::new();
        let mut out = Vec::new();
        for b in f.as_bytes() {
            out.extend(n.push_bytes(std::slice::from_ref(b)));
        }
        out.extend(n.finish());
        assert_eq!(out, expected());
    }

    #[test]
    fn maps_error_payload() {
        let bytes =
            b"data: {\"error\":{\"type\":\"invalid_request_error\",\"message\":\"Invalid API key\"}}\n\n";
        assert_eq!(
            run(bytes),
            vec![Event::Error(
                "invalid_request_error: Invalid API key".into()
            )]
        );
    }

    #[test]
    fn malformed_json_becomes_error_event() {
        let out = run(b"data: {not json}\n\n");
        assert_eq!(out.len(), 1);
        assert!(matches!(&out[0], Event::Error(m) if m.contains("malformed")));
    }

    // Live smoke test — skipped unless AX_OPENAI_BASE_URL is exported.
    #[tokio::test]
    #[ignore]
    async fn live_stream_reaches_done() {
        let Ok(base_url) = std::env::var("AX_OPENAI_BASE_URL") else {
            eprintln!("AX_OPENAI_BASE_URL unset; skipping");
            return;
        };
        let api_key = std::env::var("AX_OPENAI_API_KEY").unwrap_or_default();
        let model = std::env::var("AX_OPENAI_MODEL").unwrap_or_else(|_| "gpt-4o-mini".into());

        let provider = OpenAiSchemaProvider::new(base_url, api_key, model, vec![DataClass::Public]);
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
