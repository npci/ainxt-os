// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! r12 — the network HTTP/SSE transport for remote SDK clients (gap "Network HTTP/SSE transport").
//!
//! The pure wire codec (submit encode + SSE-frame decode) and the [`NetworkTransport`] wiring are
//! exercised fully offline here against an in-memory [`WireChannel`]: a remote client encodes its
//! turn, the "server" streams SSE `data:` frames back, and the transport reconstructs the identical
//! [`Event`] stream a client would see over a live socket. Only the socket itself
//! ([`WireChannel::open`] against a real TCP endpoint) is the infra follow-up — this proves the
//! drift-prone codec + streaming reassembly are correct without a running server.

use ainxt_client::net::{
    decode_event_frame, encode_submit, sse_data_payload, NetworkTransport, WireChannel,
};
use ainxt_client::{ClientError, Transport};
use ainxt_protocol::{Event, Request};
use ainxt_types::{DataClass, Principal};
use std::sync::{Arc, Mutex};

/// An in-memory channel standing in for the socket: it records the submit body it was handed, and
/// replays a canned sequence of SSE `data:` payloads back to the transport.
struct CannedChannel {
    frames: Vec<String>,
    seen_body: Arc<Mutex<Option<String>>>,
}
impl WireChannel for CannedChannel {
    fn open(&self, body: String) -> Result<Box<dyn Iterator<Item = String> + Send>, ClientError> {
        *self.seen_body.lock().unwrap() = Some(body);
        Ok(Box::new(self.frames.clone().into_iter()))
    }
}

#[test]
fn r12_encode_submit_carries_principal_and_request() {
    let principal = Principal::user("analyst", &["chat.send"]);
    let req = Request::chat("s1", "t1", "hello", DataClass::Internal);
    let body = encode_submit(&principal, &req).expect("encode");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["principal"]["user_id"], "analyst");
    assert_eq!(v["request"]["session"], "s1");
    assert_eq!(v["request"]["input"], "hello");
    assert_eq!(v["request"]["data_class"], "internal");
}

#[test]
fn r12_sse_framing_and_frame_decode() {
    // A `data:` line yields its payload; a comment/keep-alive line does not.
    assert_eq!(sse_data_payload("data: {\"x\":1}"), Some("{\"x\":1}"));
    assert_eq!(sse_data_payload(": keep-alive"), None);
    assert_eq!(sse_data_payload("event: usage"), None);

    // A real event payload round-trips; the [DONE] sentinel is the terminal None; junk is an Err.
    let ev = decode_event_frame("{\"TextDelta\":\"hi\"}")
        .expect("decode")
        .expect("some");
    assert_eq!(ev, Event::TextDelta("hi".into()));
    assert!(decode_event_frame("[DONE]").expect("decode").is_none());
    assert!(decode_event_frame("{not json").is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn r12_network_transport_reconstructs_the_event_stream() {
    // The "server" streams: a text delta, a usage frame, then [DONE].
    let frames = vec![
        serde_json::to_string(&Event::TextDelta("settle".into())).unwrap(),
        serde_json::to_string(&Event::TextDelta("ment".into())).unwrap(),
        serde_json::to_string(&Event::Usage {
            input_tokens: 5,
            output_tokens: 2,
        })
        .unwrap(),
        "[DONE]".to_string(),
    ];
    let seen = Arc::new(Mutex::new(None));
    let channel = Arc::new(CannedChannel {
        frames,
        seen_body: seen.clone(),
    });
    let transport = NetworkTransport::new(channel, 16);

    let principal = Principal::user("analyst", &["chat.send"]);
    let req = Request::chat("s1", "t1", "settle it", DataClass::Internal);
    let stream = transport.submit(principal, req).expect("submit");
    let collected = stream.collect().await;

    // The transport reassembled the streamed answer + usage + terminal Done — exactly what an
    // in-process client would have seen.
    assert_eq!(collected.text, "settlement");
    assert_eq!(
        collected.usage.map(|u| (u.input_tokens, u.output_tokens)),
        Some((5, 2))
    );
    assert!(
        collected.completed,
        "the [DONE] frame must terminate the stream"
    );

    // The channel was handed the encoded submit body (principal + request).
    let body = seen.lock().unwrap().clone().expect("submit body sent");
    assert!(
        body.contains("\"analyst\"") && body.contains("settle it"),
        "body: {body}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn r12_malformed_frame_surfaces_as_a_transport_error_event() {
    let frames = vec![
        serde_json::to_string(&Event::TextDelta("ok".into())).unwrap(),
        "{ this is not valid json".to_string(),
    ];
    let channel = Arc::new(CannedChannel {
        frames,
        seen_body: Arc::new(Mutex::new(None)),
    });
    let transport = NetworkTransport::new(channel, 16);
    let stream = transport
        .submit(
            Principal::user("u", &["chat.send"]),
            Request::chat("s", "t", "hi", DataClass::Internal),
        )
        .expect("submit");
    let collected = stream.collect().await;
    assert_eq!(collected.text, "ok");
    assert!(
        collected.error.is_some(),
        "a malformed SSE frame must surface as a transport Error event, not a silent hang"
    );
}
