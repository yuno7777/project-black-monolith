"""TraceAudit FastAPI service — reasoning-layer defense for Project Black
Monolith.

Exposes a streaming POST /generate endpoint (Server-Sent Events). Each token
is checked in real time against a baseline reasoning distribution (KL
divergence) and a PII/credential scanner; the stream is terminated early on
divergence, and secrets are redacted before they are forwarded or logged.
"""

from __future__ import annotations

import json
import os
from contextlib import asynccontextmanager
from secrets import compare_digest

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .config import MODULE_NAME, load_config
from .events import context_from_headers, make_emitter
from .stream_proxy import StreamAuditor


MAX_PROMPT_BYTES = 64 * 1024
MAX_BASELINE_TOKEN_COUNT = 2_147_483_647
MAX_BASELINE_TOTAL = 100_000_000_000_000


class GenerateRequest(BaseModel):
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


app = FastAPI(title="Project Black Monolith — TraceAudit", lifespan=lifespan)


def _admin_credential_valid(expected: str | None, authorization: str) -> bool:
    if not expected or len(expected) < 16 or not authorization.startswith("Bearer "):
        return False
    supplied = authorization[len("Bearer ") :]
    return bool(supplied) and compare_digest(supplied, expected)


def _require_admin(request: Request) -> None:
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
    return {
        "status": "ok",
        "module": MODULE_NAME,
    }


@app.get("/stats")
def stats(request: Request) -> dict:
    _require_admin(request)
    cfg = app.state.cfg
    return {
        "module": MODULE_NAME,
        "backend": cfg.model_backend,
        "kl_threshold": cfg.kl_threshold,
        "window_size": cfg.window_size,
        "min_tokens_before_check": cfg.min_tokens_before_check,
        "baseline_vocab": len(app.state.baseline_counts),
    }


@app.post("/generate")
async def generate(req: GenerateRequest, request: Request) -> StreamingResponse:
    auditor: StreamAuditor = app.state.auditor
    # Read the headers before the response starts streaming: the generator body
    # runs after the handler returns, and reaching for the request from inside
    # it would be reading state that is no longer guaranteed to be there.
    ctx = context_from_headers(request.headers)

    async def event_stream():
        async for evt in auditor.audit(req.prompt, req.max_tokens, ctx):
            yield f"data: {json.dumps(evt)}\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream")
