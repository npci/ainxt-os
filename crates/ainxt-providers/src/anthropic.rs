// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Anthropic Messages API (`/v1/messages`) adapter.
//!
//! The SSE→[`Event`] mapping lives in [`AnthropicNormalizer`], a pure component
//! the unit tests exercise with recorded fixture bytes (no network, no key).
//! Anthropic splits token usage across events — `input_tokens` arrives on
//! `message_start`, cumulative `output_tokens` on `message_delta` — so the
//! normalizer carries the input count forward and emits a single combined
//! [`Event::Usage`] when the delta lands.

use ainxt_protocol::Event;
use ainxt_runtime::provider::Provider;
use ainxt_types::DataClass;
use serde::Deserialize;
use tokio::sync::mpsc;

use crate::sse::{drive, ApiError, LineBuf, SseNormalizer};

const CHANNEL_CAP: usize = 64;
/// Anthropic requires `max_tokens`; the constructor is fixed to the frozen
/// signature, so we apply a sane default per request.
const DEFAULT_MAX_TOKENS: u32 = 4096;
const ANTHROPIC_VERSION: &str = "2023-06-01";

/// Provider for the Anthropic Messages streaming API.
pub struct AnthropicProvider {
    client: reqwest::Client,
    base_url: String,
    api_key: String,
    model: String,
    eligible: Vec<DataClass>,
}

impl AnthropicProvider {
    /// Construct an adapter. `base_url` is the API root (e.g.
    /// `https://api.anthropic.com`); `model` doubles as this provider's routing
    /// [`id`](Provider::id). `eligible` is the set of data classes this endpoint
    /// is permitted to serve (ADR-012).
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
        let url = format!("{}/v1/messages", self.base_url.trim_end_matches('/'));
        let body = serde_json::json!({
            "model": self.model,
            "max_tokens": DEFAULT_MAX_TOKENS,
            "stream": true,
            "messages": [{ "role": "user", "content": prompt }],
        });
        self.client
            .post(url)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", ANTHROPIC_VERSION)
            .json(&body)
    }
}

impl Provider for AnthropicProvider {
    fn id(&self) -> &str {
        &self.model
    }

    fn eligible(&self, data_class: DataClass) -> bool {
        self.eligible.contains(&data_class)
    }

    fn stream(&self, prompt: &str) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(CHANNEL_CAP);
        let request = self.build_request(prompt);
        tokio::spawn(drive(request, AnthropicNormalizer::new(), tx));
        rx
    }
}

// ============================ Wire types ============================

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum AnthropicEvent {
    MessageStart {
        message: AnthropicMessage,
    },
    ContentBlockDelta {
        delta: AnthropicContentDelta,
    },
    MessageDelta {
        #[serde(default)]
        usage: Option<AnthropicUsage>,
    },
    MessageStop,
    Error {
        error: ApiError,
    },
    /// `ping`, `content_block_start`, `content_block_stop`, and any future type.
    #[serde(other)]
    Other,
}

#[derive(Deserialize)]
struct AnthropicMessage {
    #[serde(default)]
    usage: Option<AnthropicUsage>,
}

#[derive(Deserialize, Default, Clone, Copy)]
struct AnthropicUsage {
    #[serde(default)]
    input_tokens: u64,
    #[serde(default)]
    output_tokens: u64,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum AnthropicContentDelta {
    TextDelta {
        text: String,
    },
    /// `input_json_delta`, `thinking_delta`, etc. — not surfaced as text.
    #[serde(other)]
    Other,
}

// ============================ Normalizer ============================

/// Pure SSE→[`Event`] translator for the Anthropic Messages wire format.
pub(crate) struct AnthropicNormalizer {
    lines: LineBuf,
    /// `input_tokens` captured from `message_start`, carried to `message_delta`.
    input_tokens: u64,
}

impl AnthropicNormalizer {
    pub(crate) fn new() -> Self {
        Self {
            lines: LineBuf::default(),
            input_tokens: 0,
        }
    }

    fn handle_line(&mut self, line: &str) -> Vec<Event> {
        let line = line.trim();
        // Only `data:` fields carry the JSON payload; `event:` lines are
        // redundant because the payload itself carries a `type` field.
        let Some(payload) = line.strip_prefix("data:") else {
            return Vec::new();
        };
        let payload = payload.trim();
        if payload.is_empty() {
            return Vec::new();
        }

        match serde_json::from_str::<AnthropicEvent>(payload) {
            Ok(AnthropicEvent::MessageStart { message }) => {
                if let Some(u) = message.usage {
                    self.input_tokens = u.input_tokens;
                }
                Vec::new()
            }
            Ok(AnthropicEvent::ContentBlockDelta { delta }) => match delta {
                AnthropicContentDelta::TextDelta { text } if !text.is_empty() => {
                    vec![Event::TextDelta(text)]
                }
                _ => Vec::new(),
            },
            Ok(AnthropicEvent::MessageDelta { usage }) => match usage {
                Some(u) => vec![Event::Usage {
                    input_tokens: self.input_tokens,
                    output_tokens: u.output_tokens,
                }],
                None => Vec::new(),
            },
            Ok(AnthropicEvent::MessageStop) => vec![Event::Done],
            Ok(AnthropicEvent::Error { error }) => {
                vec![Event::Error(error.describe("anthropic"))]
            }
            Ok(AnthropicEvent::Other) => Vec::new(),
            Err(e) => vec![Event::Error(format!("anthropic: malformed SSE data: {e}"))],
        }
    }
}

impl SseNormalizer for AnthropicNormalizer {
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

    /// A realistic Anthropic stream: message_start (with input usage), an empty
    /// text block start, a ping, two text deltas, block stop, message_delta
    /// (output usage), and message_stop.
    fn fixture() -> String {
        [
            "event: message_start\n\
data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-x\",\"content\":[],\"stop_reason\":null,\"usage\":{\"input_tokens\":12,\"output_tokens\":1}}}",
            "event: content_block_start\n\
data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}",
            "event: ping\n\
data: {\"type\":\"ping\"}",
            "event: content_block_delta\n\
data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}",
            "event: content_block_delta\n\
data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\", world\"}}",
            "event: content_block_stop\n\
data: {\"type\":\"content_block_stop\",\"index\":0}",
            "event: message_delta\n\
data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":7}}",
            "event: message_stop\n\
data: {\"type\":\"message_stop\"}",
        ]
        .join("\n\n")
            + "\n"
    }

    fn run(bytes: &[u8]) -> Vec<Event> {
        let mut n = AnthropicNormalizer::new();
        let mut out = n.push_bytes(bytes);
        out.extend(n.finish());
        out
    }

    fn expected() -> Vec<Event> {
        vec![
            Event::TextDelta("Hello".into()),
            Event::TextDelta(", world".into()),
            Event::Usage {
                input_tokens: 12,
                output_tokens: 7,
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
        let f = fixture();
        let mut n = AnthropicNormalizer::new();
        let mut out = Vec::new();
        for b in f.as_bytes() {
            out.extend(n.push_bytes(std::slice::from_ref(b)));
        }
        out.extend(n.finish());
        assert_eq!(out, expected());
    }

    #[test]
    fn maps_error_event() {
        let bytes = b"event: error\n\
data: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"Overloaded\"}}\n\n";
        assert_eq!(
            run(bytes),
            vec![Event::Error("overloaded_error: Overloaded".into())]
        );
    }

    #[test]
    fn usage_defaults_to_zero_input_when_message_start_missing() {
        // A message_delta with no preceding message_start still emits Usage.
        let bytes = b"data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":5}}\n\n";
        assert_eq!(
            run(bytes),
            vec![Event::Usage {
                input_tokens: 0,
                output_tokens: 5
            }]
        );
    }

    #[test]
    fn malformed_json_becomes_error_event() {
        let out = run(b"data: {\"type\":\"message_delta\",\n\n");
        assert_eq!(out.len(), 1);
        assert!(matches!(&out[0], Event::Error(m) if m.contains("malformed")));
    }

    // Live smoke test — skipped unless AX_ANTHROPIC_BASE_URL is exported.
    #[tokio::test]
    #[ignore]
    async fn live_stream_reaches_done() {
        let Ok(base_url) = std::env::var("AX_ANTHROPIC_BASE_URL") else {
            eprintln!("AX_ANTHROPIC_BASE_URL unset; skipping");
            return;
        };
        let api_key = std::env::var("AX_ANTHROPIC_API_KEY").unwrap_or_default();
        let model =
            std::env::var("AX_ANTHROPIC_MODEL").unwrap_or_else(|_| "claude-haiku-4-5".into());

        let provider = AnthropicProvider::new(base_url, api_key, model, vec![DataClass::Public]);
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
