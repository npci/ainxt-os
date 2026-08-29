// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Shared Server-Sent-Events plumbing for the vendor adapters.
//!
//! The wire→[`Event`] normalization is factored into a pure, per-vendor
//! [`SseNormalizer`] so it can be unit-tested against recorded fixture bytes
//! with **no network and no credentials**. The live HTTP path ([`drive`]) is a
//! thin driver: it performs the streaming request, feeds raw bytes to the
//! normalizer, and forwards the resulting events to the caller's channel.

use ainxt_protocol::Event;
use futures_util::StreamExt;
use serde::Deserialize;
use tokio::sync::mpsc::Sender;

/// A pure, stateful SSE→event translator for one vendor wire format.
///
/// It owns a byte buffer so it tolerates chunk boundaries falling anywhere —
/// including mid-line and mid-multibyte-character. Implementations must be pure
/// (no I/O): the same byte sequence always yields the same events.
pub(crate) trait SseNormalizer: Send + 'static {
    /// Feed the next raw chunk from the transport; returns any events that
    /// became complete as a result.
    fn push_bytes(&mut self, bytes: &[u8]) -> Vec<Event>;
    /// Flush any buffered trailing line that was not newline-terminated.
    fn finish(&mut self) -> Vec<Event>;
}

/// Accumulates raw bytes and yields complete `\n`-delimited lines, buffering the
/// partial trailing segment across calls. A trailing `\r` (CRLF) is stripped.
#[derive(Default)]
pub(crate) struct LineBuf {
    buf: Vec<u8>,
}

impl LineBuf {
    /// Append `bytes` and return every complete line now available.
    pub(crate) fn push(&mut self, bytes: &[u8]) -> Vec<String> {
        self.buf.extend_from_slice(bytes);
        let mut lines = Vec::new();
        while let Some(pos) = self.buf.iter().position(|&b| b == b'\n') {
            let mut line: Vec<u8> = self.buf.drain(..=pos).collect();
            line.pop(); // drop the '\n'
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            lines.push(String::from_utf8_lossy(&line).into_owned());
        }
        lines
    }

    /// Take any buffered bytes that were never newline-terminated.
    pub(crate) fn take_remainder(&mut self) -> Option<String> {
        if self.buf.is_empty() {
            return None;
        }
        let s = String::from_utf8_lossy(&self.buf).into_owned();
        self.buf.clear();
        Some(s)
    }
}

/// A vendor error object (`{"type":..,"message":..}`), shared by both wire
/// formats — OpenAI-schema and Anthropic use the same shape here.
#[derive(Deserialize)]
pub(crate) struct ApiError {
    #[serde(default)]
    pub r#type: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
}

impl ApiError {
    /// Render a human-readable, single-line description for [`Event::Error`].
    pub(crate) fn describe(&self, vendor: &str) -> String {
        match (self.r#type.as_deref(), self.message.as_deref()) {
            (Some(t), Some(m)) => format!("{t}: {m}"),
            (None, Some(m)) => m.to_string(),
            (Some(t), None) => t.to_string(),
            (None, None) => format!("{vendor} error"),
        }
    }
}

/// Truncate on a char boundary, appending an ellipsis when clipped.
pub(crate) fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

/// Send `ev` to the sink, tracking whether a terminal [`Event::Done`] has gone
/// out. Returns `false` once the receiver is gone so the caller can stop early.
async fn forward(tx: &Sender<Event>, done_sent: &mut bool, ev: Event) -> bool {
    if matches!(ev, Event::Done) {
        *done_sent = true;
    }
    tx.send(ev).await.is_ok()
}

/// Drive a streaming request end-to-end: issue it, stream the body through
/// `normalizer`, and forward every event to `tx`.
///
/// Invariants held here (independent of the vendor):
/// * Any transport/HTTP failure becomes an [`Event::Error`].
/// * Exactly one terminal [`Event::Done`] is emitted, last — whether the stream
///   ended cleanly, errored, or the vendor never sent an explicit terminator.
pub(crate) async fn drive<N: SseNormalizer>(
    request: reqwest::RequestBuilder,
    mut normalizer: N,
    tx: Sender<Event>,
) {
    let mut done_sent = false;

    match request.send().await {
        Err(e) => {
            let _ = forward(
                &tx,
                &mut done_sent,
                Event::Error(format!("request failed: {e}")),
            )
            .await;
        }
        Ok(resp) => {
            let status = resp.status();
            if !status.is_success() {
                let body = resp.text().await.unwrap_or_default();
                let msg = format!("http {}: {}", status.as_u16(), truncate(body.trim(), 500));
                let _ = forward(&tx, &mut done_sent, Event::Error(msg)).await;
            } else {
                let byte_stream = resp.bytes_stream();
                let mut byte_stream = std::pin::pin!(byte_stream);
                'outer: loop {
                    match byte_stream.next().await {
                        Some(Ok(chunk)) => {
                            for ev in normalizer.push_bytes(&chunk) {
                                if !forward(&tx, &mut done_sent, ev).await {
                                    break 'outer;
                                }
                            }
                        }
                        Some(Err(e)) => {
                            let _ = forward(
                                &tx,
                                &mut done_sent,
                                Event::Error(format!("stream read error: {e}")),
                            )
                            .await;
                            break;
                        }
                        None => {
                            for ev in normalizer.finish() {
                                if !forward(&tx, &mut done_sent, ev).await {
                                    break 'outer;
                                }
                            }
                            break;
                        }
                    }
                }
            }
        }
    }

    if !done_sent {
        let _ = tx.send(Event::Done).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linebuf_splits_and_buffers_partial() {
        let mut lb = LineBuf::default();
        assert_eq!(lb.push(b"hel"), Vec::<String>::new());
        assert_eq!(lb.push(b"lo\nwor"), vec!["hello".to_string()]);
        assert_eq!(lb.push(b"ld\n"), vec!["world".to_string()]);
        assert_eq!(lb.take_remainder(), None);
    }

    #[test]
    fn linebuf_strips_crlf_and_keeps_remainder() {
        let mut lb = LineBuf::default();
        assert_eq!(lb.push(b"a\r\nb"), vec!["a".to_string()]);
        assert_eq!(lb.take_remainder(), Some("b".to_string()));
    }

    #[test]
    fn api_error_describe_variants() {
        let full = ApiError {
            r#type: Some("rate_limit".into()),
            message: Some("slow down".into()),
        };
        assert_eq!(full.describe("v"), "rate_limit: slow down");
        let msg_only = ApiError {
            r#type: None,
            message: Some("boom".into()),
        };
        assert_eq!(msg_only.describe("v"), "boom");
        let empty = ApiError {
            r#type: None,
            message: None,
        };
        assert_eq!(empty.describe("openai"), "openai error");
    }

    #[test]
    fn truncate_respects_char_boundaries() {
        assert_eq!(truncate("short", 100), "short");
        // "é" is two bytes; truncating at byte 3 must not split it.
        let out = truncate("aéb", 3);
        assert!(out.ends_with('…'));
        assert!(out.starts_with('a'));
    }
}
