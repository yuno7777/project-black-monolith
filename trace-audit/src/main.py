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

from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from .config import MODULE_NAME, load_config
from .events import context_from_headers, make_emitter
from .stream_proxy import StreamAuditor


class GenerateRequest(BaseModel):
    prompt: str
    max_tokens: int | None = None


def _load_baseline(path: str) -> dict[str, int]:
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return {str(k): int(v) for k, v in data.get("counts", {}).items()}


@asynccontextmanager
async def lifespan(app: FastAPI):
    cfg = load_config()
    emit = make_emitter(
        MODULE_NAME,
        cfg.dashboard_url,
        cfg.event_token,
        cfg.event_outbox_path,
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
    yield


app = FastAPI(title="Project Black Monolith — TraceAudit", lifespan=lifespan)


@app.get("/health")
def health() -> dict:
    cfg = app.state.cfg
    baseline: dict = app.state.baseline_counts
    return {
        "status": "ok",
        "module": MODULE_NAME,
        "backend": cfg.model_backend,
        "baseline_loaded": bool(baseline),
        "baseline_vocab": len(baseline),
        "kl_threshold": cfg.kl_threshold,
    }


@app.get("/stats")
def stats() -> dict:
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
