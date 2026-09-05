# Docking a frontend into the AiNxt runtime

The runtime is a **network service**: any frontend (React UI, the AiNxt Python gateway, a CLI, an IDE plugin) docks in by POSTing a chat turn and reading a Server-Sent-Events (SSE) token stream back.
You build a product *on* it; you do not embed it.

## 1. Run the daemon

Run from the repository root (this repository *is* the runtime — there is no `runtime/`
subdirectory):

```bash
# The daemon refuses to start until you have answered "how is identity established?".
# For a local first run, assert the trusted-gateway posture explicitly:
AINXT_TRUSTED_GATEWAY=1 cargo run --release -p ainxt-runtimed

# → ainxt-runtimed: listening on http://127.0.0.1:8080 (fully-wired: /v1/chat …)
```

**Why the environment variable.** The default authenticator is `trusted-gateway`, which
derives role, capabilities and clearance from client-supplied `X-AInxt-*` headers. That is
only safe when the runtime is unreachable except through a gateway that has already
validated the caller's token, so the daemon **refuses to boot** rather than silently
trusting the client. You have two honest options:

| | |
|---|---|
| Front the runtime with your own authenticating gateway | `AINXT_TRUSTED_GATEWAY=1` — assert that the listener is unreachable except through it |
| Let the runtime verify identity itself | `server.authenticator = "jwt-sso"` plus `server.jwt_hs256_secret` in your config |

Do not set `AINXT_TRUSTED_GATEWAY=1` on a listener that is reachable directly by a browser:
any caller could then assert its own role and capabilities.

Flags: `--config <file>` (layered TOML, repeatable), `--port <n>`, `--surface chat|engine`,
`--check` (validate the assembled config, print the report, exit without serving). `chat` serves the full conversation intelligence (intent cascade, referent resolution,
prompt engine) with the StrongRedactor compliance gate; `engine` serves a bare model turn behind the
same mandatory gates. With no provider key configured it runs an **offline** provider so the socket
always answers; set `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` (or a `[[models.providers]]` config layer)
for a real model.

### Knowing when it is up

```sh
curl -sf http://127.0.0.1:8080/healthz     # → 200  {"status":"ok"}
```

Poll this rather than the TCP port before you send a first turn. The socket binds before composition
finishes; `/healthz` only answers on a fully assembled router. It is one of two routes with no
identity requirement, so your gateway can probe it before it has minted anything.

`GET /readyz` is the companion: `200` when the runtime should receive traffic, `503` when its
mandatory audit sink cannot write and every turn would therefore fail closed. If your gateway
load-balances across several AiNxt OS instances, poll `/readyz` for pool membership and `/healthz`
only to decide whether to restart one.

## 2. The wire contract — `POST /v1/chat`

Request body (JSON):
```json
{
  "session": "conv-42",        // conversation id — turns in the same session share history/referents
  "turn": "t-1",               // turn id within the session
  "input": "How did UPI grow?",// the user's message
  "data_class": "public",      // public | internal | confidential | pii | regulated_payment (drives routing)
  "caps": ["chat.send"],       // optional; the principal's capabilities (the gateway sets these post-auth)
  "forced_provider": null      // optional provider pin (still subject to data-class routing)
}
```

Response: `text/event-stream` — an SSE `id:` line and one `data: <json>` frame per event,
streamed as the model produces it. Every frame is an **envelope** carrying routing/audit
fields, with the event's own fields flattened onto it and discriminated by `type`:

```
id: 1
data: {"v":"1.0","session_id":"c1","turn_id":"t1","seq":1,"ts":"1787730564951","control_plane_sha":"unpinned","type":"turn.started","participant_id":"c1"}

id: 2
data: {"v":"1.0","session_id":"c1","turn_id":"t1","seq":2,"ts":"1787730564953","control_plane_sha":"unpinned","type":"text.delta","text":"offline mode: no model configured."}

id: 3
data: {"v":"1.0","session_id":"c1","turn_id":"t1","seq":3,"ts":"1787730564953","control_plane_sha":"unpinned","type":"turn.rationale","model_tier":"complex","model":"offline"}

id: 4
data: {"v":"1.0","session_id":"c1","turn_id":"t1","seq":4,"ts":"1787730564953","control_plane_sha":"unpinned","type":"turn.completed","outcome":"complete"}
```

Envelope fields on every frame: `v` (body schema version), `session_id`, `seq` (per-session
strictly monotonic — use it for gap detection and resume), `ts`, `control_plane_sha`, and
`turn_id` on turn-scoped events. **Dispatch on `type`**, not on object shape.

The `type` vocabulary is namespaced: `turn.*` (`turn.started`, `turn.rationale`,
`turn.completed`), `text.delta`, `tool.*`, `approval.*`, `session.*`. Treat an unrecognised
`type` as ignorable rather than an error — the vocabulary grows.

> **Known wire defect.** On `turn.started`, `turn.rationale` and `turn.completed` the
> `turn_id` key is currently emitted **twice** in the same JSON object (once from the
> envelope, once from the flattened event body — `#[serde(flatten)]` over a variant that
> re-declares the field). Both copies always hold the same value, so any last-key-wins
> parser — `JSON.parse`, Python `json`, Go `encoding/json`, `serde_json` — is unaffected.
> A parser configured to reject duplicate keys (for example Jackson with
> `STRICT_DUPLICATE_DETECTION`) will fail. Do not enable strict duplicate detection on
> this stream until it is fixed.

A full session inbox or the global session cap returns **HTTP 503** (back-pressure, never a
hang); a client disconnect **cancels** the in-flight turn.

```bash
curl -N http://127.0.0.1:8080/v1/chat \
  -H 'content-type: application/json' \
  -d '{"session":"c1","turn":"t1","input":"How did UPI grow?","data_class":"public"}'
```

## 3. Dock the AiNxt Python gateway (strangler-fig / sidecar)

Run the runtime as a sidecar and forward the gateway's chat endpoint to it. Drop this into `gateway.py`
(uses `httpx`, which the platform already has):

```python
import json, httpx
from fastapi import Request
from fastapi.responses import StreamingResponse

RUNTIME_URL = "http://127.0.0.1:8080/v1/chat"   # the ainxt-runtimed sidecar

@app.post("/ask/runtime")            # or wire behind your existing /ask, gated by a feature flag
async def ask_runtime(req: Request, user=Depends(current_user)):   # your existing SSO/JWT dep
    body = await req.json()
    payload = {
        "session": body["session"],
        "turn": body.get("turn", "t-1"),
        "input": body["message"],
        "data_class": body.get("data_class", "internal"),
        # The gateway has ALREADY authenticated the user — pass the caps it authorized. The runtime
        # trusts these because they arrive from the trusted gateway, not the browser.
        "caps": user.capabilities,   # e.g. ["chat.send", ...]
    }

    async def stream():
        async with httpx.AsyncClient(timeout=None) as client:
            async with client.stream("POST", RUNTIME_URL, json=payload) as r:
                if r.status_code == 503:
                    yield b'data: {"Error":"runtime busy (backpressure)"}\n\n'
                    return
                async for line in r.aiter_lines():
                    if line.startswith("data: "):
                        yield (line + "\n\n").encode()   # pass the SSE frame straight through to the browser

    return StreamingResponse(stream(), media_type="text/event-stream")
```

That's the whole dock: the gateway keeps owning SSO/session persistence/UI; the runtime owns the
safety + intelligence + streaming. Migrate one endpoint at a time behind a feature flag (the Python
compliance/gateway path stays untouched until you're ready to cut over).

**Auth boundary (important):** today the runtime accepts the principal's `caps` from the request body
and uses the `session` id as the actor for authz/audit. That is correct for a **trusted-gateway
sidecar** (the gateway authenticates, then tells the runtime what the user may do). Do **not** expose
`/v1/chat` directly to browsers without the gateway in front until a JWT/SSO auth layer is added to
the transport (a designed, not-yet-built increment).

## 4. Point the React UI at it (optional, direct)

Behind the gateway is the supported path. If you want the UI to hit the runtime directly in dev, it's
a normal SSE `fetch` against `/v1/chat` with the JSON body above — parse each `data:` line's JSON and
append `TextDelta`s until `Done`.

## What's proven vs. what's next

- **Proven (tested over real HTTP, `crates/ainxt-runtimed/tests/dock_chat_http.rs`):** streamed QA
  answer, referent resolution ("generate this as pdf" → the prior answer), streaming PAN redaction,
  RBAC refusal, plus 503 back-pressure and disconnect-cancel (`ainxt-server` tests).
- **Next (designed, not built):** a JWT/SSO auth layer on the transport (so the runtime can be
  exposed beyond a trusted gateway), grounded retrieval wired from a configured knowledge base, and a
  gRPC transport + Python/TypeScript SDKs so non-HTTP clients dock without hand-rolling the contract.
