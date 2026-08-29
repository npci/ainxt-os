// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-providers — real model-provider adapters (increment 2b).
//!
//! Three vendor adapters plug into the [`ainxt_runtime::provider::Provider`] seam
//! (ADR-006), normalizing each vendor's streaming SSE wire format into the
//! shared [`ainxt_protocol::Event`] enum — so every runtime feature works
//! irrespective of vendor (the multi-model policy):
//!
//! * [`OpenAiSchemaProvider`] — the OpenAI `/chat/completions` schema, which
//!   also covers vLLM, Groq, and local servers (they differ only by base URL
//!   and key).
//! * [`AnthropicProvider`] — the Anthropic Messages API (`/v1/messages`).
//! * [`GeminiProvider`] — the Google Gemini `:streamGenerateContent?alt=sse`
//!   generative-language API.
//!
//! The wire→event normalization is factored into pure, per-vendor components
//! (`crate::sse::SseNormalizer`) so it is unit-testable against recorded fixture
//! bytes with no network and no credentials. The live HTTP path is a thin
//! driver over `reqwest`'s byte stream (`crate::sse::drive`) and is covered only
//! by `#[ignore]`d integration tests that read connection details from the
//! environment.

mod anthropic;
mod gemini;
mod label_model;
mod openai;
mod sse;

pub use anthropic::AnthropicProvider;
pub use gemini::GeminiProvider;
pub use label_model::{parse_alternatives, ConstrainedProvider, LabelGrammar, ProviderLabelModel};
pub use openai::OpenAiSchemaProvider;
