// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-telemetry — the observability seam: per-turn metrics + cost attribution (gap J/V).
//!
//! One [`TurnMetrics`] is emitted per turn to a pluggable [`TelemetrySink`]. The defaults are
//! dependency-light ([`NullTelemetry`] no-op, [`InMemoryTelemetry`] for dev/tests); a production
//! OTLP/OpenTelemetry exporter implements the SAME trait as an adapter, so the OSS core never
//! pulls the heavy OTel/gRPC dependency tree (consistent with every other seam here).
//!
//! **Cost is integer money** — micro-currency units, never floats — so FinOps/chargeback figures
//! are exact (a payments platform must not accrue floating-point rounding in cost ledgers).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ainxt_types::DataClass;
use serde::Deserialize;

/// How a turn ended — for observability + SLO/error-budget accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnOutcome {
    Completed,
    GuardrailsBlocked,
    Cancelled,
    ProvidersFailed,
    /// Rejected before any provider ran (turn-level authz deny / routing error).
    Rejected,
}

/// The per-turn observability + cost record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnMetrics {
    pub session: String,
    pub turn: String,
    /// The principal the turn ran on behalf of — the cost/attribution key.
    pub actor: String,
    /// The provider that served the turn (or "cancelled"/"guardrails-blocked"/"none").
    pub provider: String,
    pub data_class: DataClass,
    pub input_tokens: u64,
    pub output_tokens: u64,
    /// Attributed cost in micro-currency units (integer; 1 unit = 1e-6 of the currency).
    pub cost_micros: u64,
    pub latency_ms: u64,
    pub redactions: usize,
    pub tool_calls: usize,
    pub outcome: TurnOutcome,
}

/// R15 COMPOSE — the concurrent tool-dispatch observability snapshot, sampled alongside a turn record
/// (gap: parallel tool dispatch, "observable on the shipped daemon, not just inside the engine's own
/// tests"). `ainxt_runtime`'s `DispatchProbe` is attached ONCE per engine (not per turn), so this is a
/// fleet-wide serving-ops gauge riding the existing per-turn emission path, not a per-turn-scoped
/// figure: `peak_concurrency` is the maximum number of tool dispatches ever observed running at once,
/// and `total_dispatched` is the cumulative count — both as of the moment this snapshot was taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DispatchMetrics {
    pub peak_concurrency: usize,
    pub total_dispatched: usize,
}

/// The observability seam. Production plugs an OTLP/OTel exporter in here.
pub trait TelemetrySink: Send + Sync {
    fn record_turn(&self, metrics: &TurnMetrics);

    /// R15 COMPOSE — an optional concurrent-dispatch gauge reading, sampled by the transport alongside
    /// a turn record. Default no-op so every existing [`TelemetrySink`] implementor keeps compiling
    /// unchanged; [`InMemoryTelemetry`] and [`OtlpExporter`] override it to actually capture/export the
    /// reading, making parallel-dispatch concurrency observable on the shipped daemon.
    fn record_dispatch(&self, _stats: DispatchMetrics) {}

    /// GAP6 telemetry-cost-rollup — the in-process FinOps/chargeback breakdown over every turn this
    /// sink has recorded so far, if it retains one. Default `None` so every existing [`TelemetrySink`]
    /// implementor keeps compiling unchanged (and a sink that only ever EXPORTS turns out of process —
    /// [`OtlpExporter`], [`NullTelemetry`] — honestly reports "nothing to roll up" rather than
    /// fabricating a breakdown it cannot actually hold). [`InMemoryTelemetry`] overrides this to return
    /// `Some(self.rollup())`, so a served route can expose the SAME [`CostRollup`] a test would build by
    /// hand, over the daemon's real accumulated turns — not a second, disconnected aggregation.
    fn cost_rollup(&self) -> Option<CostRollup> {
        None
    }
}

/// Discards everything — the default (telemetry is opt-in, per A1).
pub struct NullTelemetry;
impl TelemetrySink for NullTelemetry {
    fn record_turn(&self, _metrics: &TurnMetrics) {}
}

/// Collects turns in memory (dev / tests).
#[derive(Default)]
pub struct InMemoryTelemetry {
    turns: Mutex<Vec<TurnMetrics>>,
    /// R15 COMPOSE — the dispatch-concurrency gauge readings recorded via [`record_dispatch`](TelemetrySink::record_dispatch).
    dispatch: Mutex<Vec<DispatchMetrics>>,
}
impl InMemoryTelemetry {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn turns(&self) -> Vec<TurnMetrics> {
        self.turns.lock().expect("telemetry lock").clone()
    }
    pub fn len(&self) -> usize {
        self.turns.lock().expect("telemetry lock").len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// R15 COMPOSE — every dispatch-concurrency gauge reading recorded so far (dev/test inspection).
    pub fn dispatch_snapshots(&self) -> Vec<DispatchMetrics> {
        self.dispatch
            .lock()
            .expect("dispatch telemetry lock")
            .clone()
    }
    /// R15 COMPOSE — the most recently recorded dispatch-concurrency gauge reading, if any.
    pub fn last_dispatch(&self) -> Option<DispatchMetrics> {
        self.dispatch
            .lock()
            .expect("dispatch telemetry lock")
            .last()
            .copied()
    }
}
impl InMemoryTelemetry {
    /// Aggregate the collected turns into a [`CostRollup`] (chargeback / FinOps, gap V).
    pub fn rollup(&self) -> CostRollup {
        CostRollup::from_turns(&self.turns.lock().expect("telemetry lock"))
    }
}
impl TelemetrySink for InMemoryTelemetry {
    fn record_turn(&self, metrics: &TurnMetrics) {
        self.turns
            .lock()
            .expect("telemetry lock")
            .push(metrics.clone());
    }
    fn record_dispatch(&self, stats: DispatchMetrics) {
        self.dispatch
            .lock()
            .expect("dispatch telemetry lock")
            .push(stats);
    }
    /// GAP6 telemetry-cost-rollup — the real, live chargeback breakdown over every turn recorded so
    /// far (never a stub): the SAME [`CostRollup::from_turns`] aggregation [`InMemoryTelemetry::rollup`]
    /// already provides, reachable through the ONE generic [`TelemetrySink`] seam a served route (or any
    /// other caller that only holds `Arc<dyn TelemetrySink>`) consults.
    fn cost_rollup(&self) -> Option<CostRollup> {
        Some(self.rollup())
    }
}

// ============================ cost attribution / chargeback (gap V) ============================

/// Aggregated cost + usage for one attribution key (an actor or a provider). Integer money only
/// — a payments platform must not accrue floating-point drift in a chargeback ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CostBucket {
    pub turns: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost_micros: u64,
    /// Turns that completed successfully.
    pub completed: u64,
    /// Turns stopped by guardrails/compliance (blocked or cancelled or rejected or failed).
    pub not_completed: u64,
}

impl CostBucket {
    fn add(&mut self, m: &TurnMetrics) {
        self.turns = self.turns.saturating_add(1);
        self.input_tokens = self.input_tokens.saturating_add(m.input_tokens);
        self.output_tokens = self.output_tokens.saturating_add(m.output_tokens);
        self.cost_micros = self.cost_micros.saturating_add(m.cost_micros);
        match m.outcome {
            TurnOutcome::Completed => self.completed = self.completed.saturating_add(1),
            _ => self.not_completed = self.not_completed.saturating_add(1),
        }
    }
}

/// A cost-attribution rollup over a set of [`TurnMetrics`]: totals plus per-actor (chargeback
/// key) and per-provider (FinOps / anomaly) breakdowns. Deterministic integer aggregation so the
/// same turns always produce the same ledger.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CostRollup {
    pub total: CostBucket,
    by_actor: HashMap<String, CostBucket>,
    by_provider: HashMap<String, CostBucket>,
}

impl CostRollup {
    /// Fold a slice of turns into a rollup.
    pub fn from_turns(turns: &[TurnMetrics]) -> Self {
        let mut r = CostRollup::default();
        for m in turns {
            r.total.add(m);
            r.by_actor.entry(m.actor.clone()).or_default().add(m);
            r.by_provider.entry(m.provider.clone()).or_default().add(m);
        }
        r
    }

    /// Chargeback bucket for one principal (`actor`); zero if the actor had no turns.
    pub fn actor(&self, actor: &str) -> CostBucket {
        self.by_actor.get(actor).copied().unwrap_or_default()
    }

    /// FinOps bucket for one provider; zero if the provider served no turns.
    pub fn provider(&self, provider: &str) -> CostBucket {
        self.by_provider.get(provider).copied().unwrap_or_default()
    }

    /// All actor buckets, sorted by descending cost then actor id (stable, deterministic) — the
    /// "top spenders" chargeback report.
    pub fn actors_by_cost(&self) -> Vec<(String, CostBucket)> {
        let mut v: Vec<(String, CostBucket)> =
            self.by_actor.iter().map(|(k, b)| (k.clone(), *b)).collect();
        v.sort_by(|a, b| b.1.cost_micros.cmp(&a.1.cost_micros).then(a.0.cmp(&b.0)));
        v
    }

    /// All provider buckets, sorted by descending cost then provider id (deterministic).
    pub fn providers_by_cost(&self) -> Vec<(String, CostBucket)> {
        let mut v: Vec<(String, CostBucket)> = self
            .by_provider
            .iter()
            .map(|(k, b)| (k.clone(), *b))
            .collect();
        v.sort_by(|a, b| b.1.cost_micros.cmp(&a.1.cost_micros).then(a.0.cmp(&b.0)));
        v
    }
}

// ============================ OTLP / OpenTelemetry export (gap J — low) ============================

/// The **egress transport** an [`OtlpExporter`] hands each encoded OTLP/HTTP JSON payload to. Splitting
/// the encoding (offline, pure, testable here) from the wire send (a live network POST to an OTLP
/// collector, which is genuine infra) keeps the OSS core dependency-light: production plugs a
/// reqwest/tonic-backed transport that POSTs to `${endpoint}/v1/logs`, while the OSS default buffers /
/// drops so the daemon serves with zero external infra. `export` is best-effort — a collector outage
/// must never fail a served turn.
pub trait OtlpTransport: Send + Sync {
    /// Send one already-encoded OTLP/HTTP JSON body (an `ExportLogsServiceRequest`). Best-effort.
    fn export(&self, body: &[u8]);
}

/// The OSS-default OTLP transport: buffers every encoded payload in memory (so a test — or a dev
/// inspecting the daemon — can read back exactly what WOULD be POSTed to the collector) instead of
/// opening a live network connection. The production HTTP/gRPC transport is the infra swap behind the
/// SAME [`OtlpTransport`] seam; this never touches the network, so the air-gapped daemon still serves.
#[derive(Default)]
pub struct BufferingOtlpTransport {
    payloads: Mutex<Vec<Vec<u8>>>,
}
impl BufferingOtlpTransport {
    pub fn new() -> Self {
        Self::default()
    }
    /// The raw encoded OTLP payloads captured so far (one per exported turn).
    pub fn payloads(&self) -> Vec<Vec<u8>> {
        self.payloads.lock().expect("otlp buffer lock").clone()
    }
    /// The captured payloads decoded as JSON (convenience for assertions).
    pub fn json_payloads(&self) -> Vec<serde_json::Value> {
        self.payloads()
            .iter()
            .filter_map(|b| serde_json::from_slice(b).ok())
            .collect()
    }
    pub fn len(&self) -> usize {
        self.payloads.lock().expect("otlp buffer lock").len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
impl OtlpTransport for BufferingOtlpTransport {
    fn export(&self, body: &[u8]) {
        self.payloads
            .lock()
            .expect("otlp buffer lock")
            .push(body.to_vec());
    }
}

/// A [`TelemetrySink`] that projects each [`TurnMetrics`] onto an OTLP/HTTP **LogRecord** (the
/// OpenTelemetry `ExportLogsServiceRequest` JSON shape) and hands the encoded body to a pluggable
/// [`OtlpTransport`]. This is the config-selected production observability sink
/// ([`TelemetrySinkKind::Otlp`]) behind the same trait as [`NullTelemetry`]/[`InMemoryTelemetry`], so
/// selecting it never pulls the heavy OTel/gRPC tree into the OSS core — the encoding is pure
/// `serde_json`, and only the (infra) transport carries the network dependency.
///
/// Encoding is faithful OTLP: a single `resourceLogs[0].scopeLogs[0].logRecords[0]` per turn, with the
/// turn's cost/tokens/latency/outcome as typed `attributes` (`key` + typed `value`), a
/// `timeUnixNano`, a `severityNumber`/`severityText`, and a human `body`. A consumer that speaks OTLP
/// ingests it unchanged; the `service.name` resource attribute is the configured service id.
pub struct OtlpExporter {
    transport: Arc<dyn OtlpTransport>,
    /// The `resource.service.name` stamped on every export (OTLP resource attribute).
    service_name: String,
    /// The collector endpoint this exporter is configured for (recorded on the resource for
    /// provenance; the live send is the transport's job).
    endpoint: String,
    /// Injectable wall-clock (Unix nanos) so a test can pin `timeUnixNano` deterministically.
    now_nanos: Box<dyn Fn() -> u128 + Send + Sync>,
}

impl OtlpExporter {
    /// Build an exporter over `transport`, tagging exports with `service_name` and recording the
    /// configured `endpoint`. The clock is the real wall clock.
    pub fn new(
        transport: Arc<dyn OtlpTransport>,
        service_name: impl Into<String>,
        endpoint: impl Into<String>,
    ) -> Self {
        OtlpExporter {
            transport,
            service_name: service_name.into(),
            endpoint: endpoint.into(),
            now_nanos: Box::new(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            }),
        }
    }

    /// Test hook: pin the `timeUnixNano` clock.
    pub fn with_clock(mut self, now_nanos: impl Fn() -> u128 + Send + Sync + 'static) -> Self {
        self.now_nanos = Box::new(now_nanos);
        self
    }

    /// The collector endpoint this exporter targets.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Encode one turn as the OTLP/HTTP `ExportLogsServiceRequest` JSON body (pure; no I/O).
    pub fn encode(&self, m: &TurnMetrics) -> serde_json::Value {
        let outcome = format!("{:?}", m.outcome);
        // Completed = INFO(9); anything else (blocked/failed/cancelled/rejected) = WARN(13).
        let (sev_num, sev_text) = match m.outcome {
            TurnOutcome::Completed => (9, "INFO"),
            _ => (13, "WARN"),
        };
        let attr_str =
            |k: &str, v: &str| serde_json::json!({"key": k, "value": {"stringValue": v}});
        let attr_int =
            |k: &str, v: u64| serde_json::json!({"key": k, "value": {"intValue": v.to_string()}});
        serde_json::json!({
            "resourceLogs": [{
                "resource": {
                    "attributes": [
                        attr_str("service.name", &self.service_name),
                        attr_str("telemetry.sdk.name", "ainxt-telemetry"),
                        attr_str("otlp.endpoint", &self.endpoint),
                    ]
                },
                "scopeLogs": [{
                    "scope": {"name": "ainxt.turn", "version": "1"},
                    "logRecords": [{
                        "timeUnixNano": (self.now_nanos)().to_string(),
                        "severityNumber": sev_num,
                        "severityText": sev_text,
                        "body": {"stringValue": format!(
                            "turn {}::{} actor={} provider={} outcome={}",
                            m.session, m.turn, m.actor, m.provider, outcome
                        )},
                        "attributes": [
                            attr_str("session.id", &m.session),
                            attr_str("turn.id", &m.turn),
                            attr_str("actor", &m.actor),
                            attr_str("provider", &m.provider),
                            attr_str("data.class", &format!("{:?}", m.data_class)),
                            attr_str("turn.outcome", &outcome),
                            attr_int("input.tokens", m.input_tokens),
                            attr_int("output.tokens", m.output_tokens),
                            attr_int("cost.micros", m.cost_micros),
                            attr_int("latency.ms", m.latency_ms),
                            attr_int("redactions", m.redactions as u64),
                            attr_int("tool.calls", m.tool_calls as u64),
                        ]
                    }]
                }]
            }]
        })
    }

    /// R15 COMPOSE — encode one [`DispatchMetrics`] gauge reading as an OTLP/HTTP `ExportLogsServiceRequest`
    /// JSON body (pure; no I/O), mirroring [`encode`](Self::encode) so the same collector ingests both
    /// per-turn cost records and the concurrent-dispatch gauge over one exporter.
    pub fn encode_dispatch(&self, m: &DispatchMetrics) -> serde_json::Value {
        let attr_str =
            |k: &str, v: &str| serde_json::json!({"key": k, "value": {"stringValue": v}});
        let attr_int =
            |k: &str, v: u64| serde_json::json!({"key": k, "value": {"intValue": v.to_string()}});
        serde_json::json!({
            "resourceLogs": [{
                "resource": {
                    "attributes": [
                        attr_str("service.name", &self.service_name),
                        attr_str("telemetry.sdk.name", "ainxt-telemetry"),
                        attr_str("otlp.endpoint", &self.endpoint),
                    ]
                },
                "scopeLogs": [{
                    "scope": {"name": "ainxt.dispatch", "version": "1"},
                    "logRecords": [{
                        "timeUnixNano": (self.now_nanos)().to_string(),
                        "severityNumber": 9,
                        "severityText": "INFO",
                        "body": {"stringValue": format!(
                            "dispatch peak_concurrency={} total_dispatched={}",
                            m.peak_concurrency, m.total_dispatched
                        )},
                        "attributes": [
                            attr_int("dispatch.peak_concurrency", m.peak_concurrency as u64),
                            attr_int("dispatch.total_dispatched", m.total_dispatched as u64),
                        ]
                    }]
                }]
            }]
        })
    }
}

impl TelemetrySink for OtlpExporter {
    fn record_turn(&self, metrics: &TurnMetrics) {
        let body = serde_json::to_vec(&self.encode(metrics)).unwrap_or_default();
        if !body.is_empty() {
            self.transport.export(&body);
        }
    }
    fn record_dispatch(&self, stats: DispatchMetrics) {
        let body = serde_json::to_vec(&self.encode_dispatch(&stats)).unwrap_or_default();
        if !body.is_empty() {
            self.transport.export(&body);
        }
    }
}

// ============================ cost model ============================

/// Per-provider token prices, in micro-currency per MILLION tokens (integer money).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelPrice {
    #[serde(default)]
    pub input_micros_per_million: u64,
    #[serde(default)]
    pub output_micros_per_million: u64,
}

/// Maps a provider id → its token prices. An unpriced provider costs 0 (unknown), never a panic.
#[derive(Debug, Clone, Default)]
pub struct PriceTable {
    prices: HashMap<String, ModelPrice>,
}

impl PriceTable {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn from_map(prices: HashMap<String, ModelPrice>) -> Self {
        PriceTable { prices }
    }
    pub fn set(&mut self, provider: &str, price: ModelPrice) {
        self.prices.insert(provider.to_string(), price);
    }
    pub fn is_empty(&self) -> bool {
        self.prices.is_empty()
    }

    /// Cost of a turn in micro-currency units. Integer math throughout (no float money);
    /// `saturating_mul` guards against overflow at absurd token counts.
    pub fn cost_micros(&self, provider: &str, input_tokens: u64, output_tokens: u64) -> u64 {
        match self.prices.get(provider) {
            Some(p) => {
                let inp = input_tokens.saturating_mul(p.input_micros_per_million) / 1_000_000;
                let out = output_tokens.saturating_mul(p.output_micros_per_million) / 1_000_000;
                inp.saturating_add(out)
            }
            None => 0,
        }
    }
}

// ============================ config ============================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TelemetrySinkKind {
    /// No-op (default).
    #[default]
    Null,
    /// In-memory collection (dev/tests).
    Memory,
    /// OTLP/OpenTelemetry exporter (adapter; selected here, wired at composition).
    Otlp,
}

/// Telemetry config: which sink, plus the price table for cost attribution.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(default)]
pub struct TelemetryConfig {
    pub sink: TelemetrySinkKind,
    /// provider id → prices.
    pub pricing: HashMap<String, ModelPrice>,
    /// OTLP collector endpoint (used only when `sink = "otlp"`). Empty ⇒ the default local collector
    /// address; the live network POST is the infra transport's concern (the OSS default buffers).
    pub otlp_endpoint: String,
    /// The `service.name` resource attribute stamped on OTLP exports. Empty ⇒ `"ainxt-runtime"`.
    pub service_name: String,
}

impl TelemetryConfig {
    pub fn price_table(&self) -> PriceTable {
        PriceTable::from_map(self.pricing.clone())
    }

    /// The configured OTLP endpoint, or the conventional local-collector default.
    pub fn otlp_endpoint_or_default(&self) -> &str {
        if self.otlp_endpoint.is_empty() {
            "http://localhost:4318"
        } else {
            &self.otlp_endpoint
        }
    }

    /// The configured `service.name`, or the platform default.
    pub fn service_name_or_default(&self) -> &str {
        if self.service_name.is_empty() {
            "ainxt-runtime"
        } else {
            &self.service_name
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ainxt_types::DataClass;

    fn turn(outcome: TurnOutcome) -> TurnMetrics {
        TurnMetrics {
            session: "s-1".into(),
            turn: "t-1".into(),
            actor: "alice".into(),
            provider: "mock".into(),
            data_class: DataClass::Internal,
            input_tokens: 12,
            output_tokens: 34,
            cost_micros: 5_600,
            latency_ms: 42,
            redactions: 1,
            tool_calls: 2,
            outcome,
        }
    }

    /// The OTLP exporter encodes a turn as a faithful `ExportLogsServiceRequest` and hands it to the
    /// pluggable transport (the live network POST is the infra seam; the offline buffer captures it).
    #[test]
    fn r11_otlp_exporter_encodes_turn_as_logrecord_and_exports() {
        let buf = Arc::new(BufferingOtlpTransport::new());
        let exporter = OtlpExporter::new(buf.clone(), "ainxt-runtime", "http://collector:4318")
            .with_clock(|| 1_000);

        // A completed turn is recorded through the SAME TelemetrySink seam as the other sinks.
        let sink: &dyn TelemetrySink = &exporter;
        sink.record_turn(&turn(TurnOutcome::Completed));

        assert_eq!(
            buf.len(),
            1,
            "the exporter must hand the encoded body to the transport"
        );
        let v = &buf.json_payloads()[0];
        // OTLP/HTTP logs shape.
        let rec = &v["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0];
        assert_eq!(rec["timeUnixNano"], "1000", "pinned clock");
        assert_eq!(rec["severityText"], "INFO", "a completed turn is INFO");
        // The cost/token/latency facts land as typed OTLP attributes (integer money, string int).
        let attrs = rec["attributes"].as_array().expect("attributes array");
        let find = |k: &str| {
            attrs
                .iter()
                .find(|a| a["key"] == k)
                .unwrap_or_else(|| panic!("missing attribute {k}"))
        };
        assert_eq!(find("cost.micros")["value"]["intValue"], "5600");
        assert_eq!(find("actor")["value"]["stringValue"], "alice");
        assert_eq!(find("turn.outcome")["value"]["stringValue"], "Completed");
        // The service.name resource attribute is the configured id.
        let res = &v["resourceLogs"][0]["resource"]["attributes"];
        assert!(
            res.as_array()
                .unwrap()
                .iter()
                .any(|a| a["key"] == "service.name" && a["value"]["stringValue"] == "ainxt-runtime"),
            "service.name resource attribute must be stamped: {res}"
        );
    }

    /// A non-completed outcome is exported at WARN severity (SLO/error-budget observability).
    #[test]
    fn r11_otlp_non_completed_turn_is_warn_severity() {
        let buf = Arc::new(BufferingOtlpTransport::new());
        let exporter = OtlpExporter::new(buf.clone(), "svc", "");
        exporter.record_turn(&turn(TurnOutcome::ProvidersFailed));
        let v = &buf.json_payloads()[0];
        let rec = &v["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0];
        assert_eq!(rec["severityText"], "WARN");
        assert_eq!(rec["severityNumber"], 13);
    }

    /// GAP6 telemetry-cost-rollup — `TelemetrySink::cost_rollup` is `None` for a sink that does not
    /// retain turns in-process (the trait default; `NullTelemetry`/`OtlpExporter` never override it),
    /// and `Some(real rollup)` for `InMemoryTelemetry` — reachable through the ONE generic trait object
    /// a served route would hold, not just `InMemoryTelemetry`'s own inherent `rollup()` method.
    #[test]
    fn gap6_cost_rollup_via_telemetry_sink_trait_object() {
        let null_sink: &dyn TelemetrySink = &NullTelemetry;
        assert!(
            null_sink.cost_rollup().is_none(),
            "a sink with no in-process retention must not fabricate a rollup"
        );

        let mem = InMemoryTelemetry::new();
        mem.record_turn(&turn(TurnOutcome::Completed));
        let sink: &dyn TelemetrySink = &mem;
        let rollup = sink
            .cost_rollup()
            .expect("InMemoryTelemetry must expose a real rollup through the trait object");
        assert_eq!(rollup.total.turns, 1);
        assert_eq!(rollup.actor("alice").cost_micros, 5_600);
    }
}
