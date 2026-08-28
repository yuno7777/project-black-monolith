"""TraceAudit FastAPI service — reasoning-layer defense for Project Black
Monolith.

WHAT THIS FILE IS
-----------------
The web server / entry point of the TraceAudit module. It exposes ONE main
endpoint — POST /generate — that an agent's generation framework calls INSTEAD
of the model API directly. The response is a Server-Sent Events (SSE) stream of
tokens, each one already checked for reasoning divergence and PII.

WHY IT EXISTS
-------------
A model's raw stream can (a) drift off-distribution when pushed to evade
guardrails, and (b) echo secrets from its context (credentials, emails, card
numbers) into the output BEFORE any final-answer filter could see them. By
intercepting the stream token-by-token, TraceAudit can terminate a divergent
trace early and redact secrets before they are released.

WHO CALLS WHAT (the flow this file anchors)
------------------------------------------
  Agent runtime
    -> POST /generate {prompt, max_tokens?} + X-Monolith-* headers (this file)
    -> StreamAuditor.audit()          (stream_proxy.py)
    -> DivergenceMonitor + PiiStreamBuffer (divergence_monitor.py, pii_scanner.py)
    -> model backend (mock or Ollama)
    -> events via EventEmitter         (events.py -> python-common outbox)
    -> dashboard POST /api/ingest

  docker-compose: entrypoint runs fixtures/baseline_capture.py BEFORE uvicorn
  starts, so baseline_distribution.json exists by the time this file loads it.
"""

from __future__ import annotations

import json
import os
from contextlib import asynccontextmanager
from secrets import compare_digest

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .config import MODULE_NAME, load_config            # env -> validated Config
from .events import context_from_headers, make_emitter  # event delivery (shared
                                                        # outbox, python-common/)
from .stream_proxy import StreamAuditor                  # the streaming auditor

# Input bounds. The prompt is untrusted input; the baseline file is a
# deployment artifact that must not be able to blow up memory.
MAX_PROMPT_BYTES = 64 * 1024
MAX_BASELINE_TOKEN_COUNT = 2_147_483_647
MAX_BASELINE_TOTAL = 100_000_000_000_000


class GenerateRequest(BaseModel):
    """Body of POST /generate. Pydantic rejects extra fields (extra="forbid")
    and bounds the prompt so a hostile caller cannot send megabytes of text."""

    model_config = ConfigDict(extra="forbid")

    prompt: str = Field(min_length=1)
    max_tokens: int | None = Field(default=None, ge=1, le=4096)

    @field_validator("prompt")
    @classmethod
    def prompt_must_be_bounded(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("prompt must not be blank")
        if len(value.encode("utf-8")) > MAX_PROMPT_BYTES:
            raise ValueError(f"prompt must be at most {MAX_PROMPT_BYTES} UTF-8 bytes")
        return value


def _load_baseline(path: str) -> dict[str, int]:
    """Load and validate the baseline token distribution.

    The baseline is a JSON file: {"counts": {"the": 120, "think": 40, ...}}
    produced by fixtures/baseline_capture.py (the Docker entrypoint runs it
    before uvicorn starts). The DivergenceMonitor turns these counts into
    probabilities and compares every live token against them.

    Validation is strict because this file is a deployment artifact:
      - size <= 16 MiB, tokens 1-512 chars, counts positive integers,
      - unique after trimming, vocabulary <= 100k, total count bounded.
    Returns {} if the file does not exist — divergence detection is then
    DISABLED (the lifespan emits a "baseline_missing" warning event so the
    dashboard tells the operator).
    """
    if not os.path.exists(path):
        return {}
    if os.path.getsize(path) > 16 * 1024 * 1024:
        raise ValueError("baseline distribution exceeds 16 MiB")
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict) or not isinstance(data.get("counts"), dict):
        raise ValueError("baseline distribution must contain a counts object")
    counts: dict[str, int] = {}
    for raw_token, raw_count in data["counts"].items():
        token = str(raw_token).strip()
        if not token or len(token) > 512:
            raise ValueError("baseline tokens must be between 1 and 512 characters")
        if (
            isinstance(raw_count, bool)
            or not isinstance(raw_count, int)
            or not 0 < raw_count <= MAX_BASELINE_TOKEN_COUNT
        ):
            raise ValueError(
                f"baseline counts must be positive integers no greater than {MAX_BASELINE_TOKEN_COUNT}"
            )
        if token in counts:
            raise ValueError("baseline tokens must be unique after trimming")
        counts[token] = raw_count
    if len(counts) > 100_000:
        raise ValueError("baseline vocabulary exceeds 100000 tokens")
    if sum(counts.values()) > MAX_BASELINE_TOTAL:
        raise ValueError("baseline total count exceeds the supported limit")
    return counts


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown hook (runs when uvicorn starts and stops).

    Startup: load config -> build the event emitter (starts the outbox thread)
    -> load the baseline distribution -> build the StreamAuditor (one per
    process, reused by every request) -> emit "service_start". If there is no
    baseline, emit a "baseline_missing" warning.
    Shutdown: emit "service_stop" and close the outbox.
    """
    cfg = load_config()
    emit = make_emitter(
        MODULE_NAME,
        cfg.dashboard_url,
        cfg.event_token,
        cfg.event_outbox_path,
        tenant_id=cfg.tenant_id,
        agent_id=cfg.agent_id,
        session_id=cfg.session_id,
    )
    baseline_counts = _load_baseline(cfg.baseline_path)
    app.state.cfg = cfg
    app.state.emit = emit
    app.state.baseline_counts = baseline_counts
    app.state.auditor = StreamAuditor(cfg, baseline_counts, emit)
    emit(
        "service_start",
        "info",
        {
            "message": "TraceAudit reasoning-layer defense online",
            "backend": cfg.model_backend,
            "baseline_tokens": sum(baseline_counts.values()),
            "baseline_vocab": len(baseline_counts),
        },
    )
    if not baseline_counts:
        emit(
            "baseline_missing",
            "warning",
            {"message": "no baseline distribution loaded; divergence detection disabled until one is captured"},
        )
    try:
        yield
    finally:
        emit("service_stop", "info", {"message": "TraceAudit shutting down"})
        emit.close()


# The FastAPI application object, served by uvicorn (Docker entrypoint /
# run_local_demo.sh).
app = FastAPI(title="Project Black Monolith — TraceAudit", lifespan=lifespan)


def _admin_credential_valid(expected: str | None, authorization: str) -> bool:
    """Constant-time comparison of the bearer token against MONOLITH_ADMIN_TOKEN
    (same pattern as vector-anchor/src/main.py)."""
    if not expected or len(expected) < 16 or not authorization.startswith("Bearer "):
        return False
    supplied = authorization[len("Bearer ") :]
    return bool(supplied) and compare_digest(supplied, expected)


def _require_admin(request: Request) -> None:
    """Authenticate the /stats route with the admin token. Fail-closed: if the
    token is not configured, answer 503 (never pretend auth passed)."""
    expected = app.state.cfg.admin_token
    if not expected or len(expected) < 16:
        raise HTTPException(
            status_code=503,
            detail="administrative authentication is unavailable",
        )
    if not _admin_credential_valid(expected, request.headers.get("authorization", "")):
        raise HTTPException(status_code=401, detail="invalid administrative credential")


@app.get("/health")
def health() -> dict:
    """Docker healthcheck target (docker-compose.yml)."""
    return {
        "status": "ok",
        "module": MODULE_NAME,
    }


@app.get("/stats")
def stats(request: Request) -> dict:
    """Admin: module health. The dashboard Operations page calls this
    (dashboard/app/api/operations/route.ts) to show the backend in use, the
    divergence thresholds, baseline size, and outbox delivery health."""
    _require_admin(request)
    cfg = app.state.cfg
    return {
        "module": MODULE_NAME,
        "backend": cfg.model_backend,
        "kl_threshold": cfg.kl_threshold,
        "window_size": cfg.window_size,
        "min_tokens_before_check": cfg.min_tokens_before_check,
        "baseline_vocab": len(app.state.baseline_counts),
        "delivery": app.state.emit.delivery_stats(),
    }


@app.post("/generate")
async def generate(req: GenerateRequest, request: Request) -> StreamingResponse:
    """THE main endpoint: generate a defended token stream.

    Input:  body {prompt, max_tokens?} + X-Monolith-* correlation headers.
    Output: an SSE stream. Each frame is JSON:
              {"type":"token","token":"...","kl":0.31,"threshold":1.0}
              {"type":"pii","label":"email_address","redacted":"[REDACTED:...]"}
              {"type":"terminated","reason":"reasoning_divergence",...}
              {"type":"done","peak_kl":...,"tokens":...}

    How it works:
      1. Read the correlation headers into an EventContext BEFORE returning —
         the generator body runs after the handler returns, at which point the
         request object is no longer guaranteed to be readable.
      2. Build an async generator that pulls frames from
         StreamAuditor.audit(prompt, max_tokens, ctx) and wraps each in SSE
         "data: ..." framing.
      3. Return a StreamingResponse over that generator; FastAPI/uvicorn
         streams it to the client, so tokens appear as the model produces them.
    """
    auditor: StreamAuditor = app.state.auditor
    # Read the headers before the response starts streaming: the generator body
    # runs after the handler returns, and reaching for the request from inside
    # it would be reading state that is no longer guaranteed to be there.
    ctx = context_from_headers(request.headers)

    async def event_stream():
        async for evt in auditor.audit(req.prompt, req.max_tokens, ctx):
            yield f"data: {json.dumps(evt)}\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream")
