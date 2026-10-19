"""TraceAudit FastAPI service — reasoning-layer defense for Project Black
Monolith.

Exposes a streaming POST /generate endpoint (Server-Sent Events). Each token
is checked in real time against a baseline reasoning distribution (KL
divergence) and a PII/credential scanner; the stream is terminated early on
divergence, and secrets are redacted before they are forwarded or logged.
"""

from __future__ import annotations

import json
import math
import os
import time
import uuid
from contextlib import asynccontextmanager
from secrets import compare_digest
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .config import MODULE_NAME, load_config
from .events import context_from_headers, make_emitter, now_ms
from .stream_proxy import SAFE_REFUSAL, StreamAuditor

MAX_PROMPT_BYTES = 64 * 1024
MAX_BASELINE_TOKEN_BYTES = 512
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


def _messages_to_prompt(messages: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for msg in messages:
        if not isinstance(msg, dict):
            raise ValueError("each message must be an object")
        content = msg.get("content")
        if isinstance(content, str):
            if content.strip():
                parts.append(content)
        elif isinstance(content, list):
            for item in content:
                if isinstance(item, dict) and isinstance(item.get("text"), str):
                    if item["text"].strip():
                        parts.append(item["text"])
    prompt = "\n".join(parts)
    if not prompt.strip():
        raise ValueError("messages must contain non-blank content")
    if len(prompt.encode("utf-8")) > MAX_PROMPT_BYTES:
        raise ValueError(f"combined messages must be at most {MAX_PROMPT_BYTES} UTF-8 bytes")
    return prompt


class ChatCompletionRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    model: str = Field(default="default", min_length=1, max_length=128)
    messages: list[dict[str, Any]] = Field(min_length=1)
    stream: bool = False
    max_tokens: int | None = Field(default=120, ge=1, le=4096)
    temperature: float | None = Field(default=None, ge=0.0, le=2.0)

    @field_validator("messages")
    @classmethod
    def messages_must_be_valid(cls, value: list[dict[str, Any]]) -> list[dict[str, Any]]:
        _messages_to_prompt(value)
        return value


def _validate_distribution_mapping(
    mapping: dict[str, Any], *, allow_floats: bool
) -> dict[str, int]:
    if not isinstance(mapping, dict) or not mapping:
        raise ValueError("baseline distribution must be a non-empty object")
    validated_raw: dict[str, int | float] = {}
    has_non_int_float = False
    for raw_token, raw_val in mapping.items():
        token = str(raw_token).strip()
        if not token or len(token.encode("utf-8")) > MAX_BASELINE_TOKEN_BYTES:
            raise ValueError("baseline tokens must be between 1 and 512 UTF-8 bytes")
        if isinstance(raw_val, bool) or not isinstance(
            raw_val, (int, float) if allow_floats else int
        ):
            raise ValueError(
                f"baseline counts must be positive numbers no greater than {MAX_BASELINE_TOKEN_COUNT}"
            )
        if not math.isfinite(float(raw_val)) or not 0 < raw_val <= MAX_BASELINE_TOKEN_COUNT:
            raise ValueError(
                f"baseline counts must be positive numbers no greater than {MAX_BASELINE_TOKEN_COUNT}"
            )
        if token in validated_raw:
            raise ValueError("baseline tokens must be unique after trimming")
        if isinstance(raw_val, float) and (not raw_val.is_integer() or raw_val < 1):
            has_non_int_float = True
        validated_raw[token] = raw_val

    if len(validated_raw) > 100_000:
        raise ValueError("baseline vocabulary exceeds 100000 tokens")

    if has_non_int_float:
        counts = {
            tok: max(1, min(MAX_BASELINE_TOKEN_COUNT, int(round(float(val) * 1000))))
            for tok, val in validated_raw.items()
        }
    else:
        counts = {tok: int(val) for tok, val in validated_raw.items()}

    if sum(counts.values()) > MAX_BASELINE_TOTAL:
        raise ValueError("baseline total count exceeds the supported limit")
    return counts


def _write_baseline_atomic(
    path: str, counts: dict[str, int], distribution: dict[str, Any] | None = None
) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    tmp_path = f"{path}.tmp"
    payload: dict[str, Any] = {
        "counts": counts,
        "total": sum(counts.values()),
        "vocab": len(counts),
    }
    if distribution is not None:
        payload["distribution"] = distribution
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    os.replace(tmp_path, path)


def _load_baseline(path: str) -> dict[str, int]:
    if not os.path.exists(path):
        return {}
    if os.path.getsize(path) > 16 * 1024 * 1024:
        raise ValueError("baseline distribution exceeds 16 MiB")
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("baseline distribution must contain a counts object")
    if "counts" in data:
        if not isinstance(data.get("counts"), dict):
            raise ValueError("baseline distribution must contain a counts object")
        counts: dict[str, int] = {}
        for raw_token, raw_count in data["counts"].items():
            token = str(raw_token).strip()
            if not token or len(token.encode("utf-8")) > MAX_BASELINE_TOKEN_BYTES:
                raise ValueError("baseline tokens must be between 1 and 512 UTF-8 bytes")
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
    if isinstance(data.get("distribution"), dict):
        return _validate_distribution_mapping(data["distribution"], allow_floats=True)
    raise ValueError("baseline distribution must contain a counts object")


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
        allow_insecure_http=cfg.allow_insecure_dashboard,
    )
    baseline_counts = _load_baseline(cfg.baseline_path)
    auditor = StreamAuditor(cfg, baseline_counts, emit)
    app.state.cfg = cfg
    app.state.emit = emit
    app.state.baseline_counts = baseline_counts
    app.state.baseline = baseline_counts
    app.state.auditor = auditor
    app.state.proxy = auditor
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


_require_admin_token = _require_admin


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
        "delivery": app.state.emit.delivery_stats(),
    }


@app.post("/admin/reload-baseline")
async def reload_baseline(request: Request) -> dict:
    _require_admin_token(request)
    cfg = app.state.cfg
    raw_body = await request.body()
    if raw_body and raw_body.strip():
        try:
            body = json.loads(raw_body)
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=400, detail="invalid JSON body") from exc
        if not isinstance(body, dict):
            raise HTTPException(status_code=400, detail="request body must be a JSON object")
        dist = body.get("distribution") if "distribution" in body else body.get("counts")
        if dist is not None:
            try:
                counts = _validate_distribution_mapping(dist, allow_floats=True)
                _write_baseline_atomic(
                    cfg.baseline_path,
                    counts,
                    distribution=dist if "distribution" in body else None,
                )
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        baseline_counts = _load_baseline(cfg.baseline_path)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    app.state.baseline_counts = baseline_counts
    app.state.baseline = baseline_counts
    emit = getattr(app.state, "emit", lambda *_a, **_kw: None)
    auditor = StreamAuditor(cfg, baseline_counts, emit)
    app.state.auditor = auditor
    app.state.proxy = auditor
    emit(
        "baseline_reloaded",
        "info",
        {
            "baseline_tokens": sum(baseline_counts.values()),
            "baseline_vocab": len(baseline_counts),
        },
    )
    return {
        "reloaded": True,
        "vocab_size": len(baseline_counts),
    }


@app.post("/admin/replay-dead-letters")
async def replay_dead_letters(request: Request) -> dict:
    _require_admin_token(request)
    emit = getattr(app.state, "emit", None)
    replayed = 0
    if emit is not None:
        if hasattr(emit, "replay_dead_letters") and callable(emit.replay_dead_letters):
            replayed = int(emit.replay_dead_letters())
        else:
            outbox = getattr(emit, "outbox", None)
            if outbox is not None:
                if hasattr(outbox, "replay_dead_letters") and callable(outbox.replay_dead_letters):
                    replayed = int(outbox.replay_dead_letters())
                elif hasattr(outbox, "_connection") and hasattr(outbox, "_lock"):
                    timestamp = now_ms()
                    with outbox._lock, outbox._connection:
                        cursor = outbox._connection.execute(
                            """update event_outbox
                               set status = 'pending', attempts = 0,
                                   next_attempt_ms = ?, updated_ms = ?
                               where status = 'dead'""",
                            (timestamp, timestamp),
                        )
                        replayed = int(
                            cursor.rowcount
                            if cursor.rowcount is not None and cursor.rowcount >= 0
                            else 0
                        )
                    if hasattr(outbox, "_wake"):
                        outbox._wake.set()
    return {"replayed": replayed}


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


@app.post("/v1/chat/completions")
async def chat_completions(req: ChatCompletionRequest, request: Request):
    auditor: StreamAuditor = app.state.auditor
    ctx = context_from_headers(request.headers)
    prompt = _messages_to_prompt(req.messages)
    completion_id = f"chatcmpl-{uuid.uuid4().hex[:24]}"
    created_ts = int(time.time())
    max_tokens = req.max_tokens if req.max_tokens is not None else 120

    if req.stream:
        async def sse_stream():
            redactions: list[str] = []
            async for evt in auditor.audit(
                prompt,
                max_tokens,
                ctx,
                messages=req.messages,
                model=req.model,
                temperature=req.temperature,
            ):
                evt_type = evt.get("type")
                if evt_type == "token":
                    chunk = {
                        "id": completion_id,
                        "object": "chat.completion.chunk",
                        "created": created_ts,
                        "model": req.model,
                        "choices": [
                            {
                                "index": 0,
                                "delta": {"content": evt["token"]},
                                "finish_reason": None,
                            }
                        ],
                    }
                    yield f"data: {json.dumps(chunk)}\n\n"
                elif evt_type == "pii":
                    redactions.append(evt["label"])
                elif evt_type == "terminated":
                    refusal = evt.get("safe_refusal", SAFE_REFUSAL)
                    chunk = {
                        "id": completion_id,
                        "object": "chat.completion.chunk",
                        "created": created_ts,
                        "model": req.model,
                        "choices": [
                            {
                                "index": 0,
                                "delta": {"content": refusal},
                                "finish_reason": "content_filter",
                            }
                        ],
                        "monolith_audit": {
                            "terminated": True,
                            "redactions": redactions,
                            "peak_kl": evt.get("kl", 0.0),
                        },
                    }
                    yield f"data: {json.dumps(chunk)}\n\n"
                    yield "data: [DONE]\n\n"
                    return
                elif evt_type == "error" or "error" in evt:
                    chunk = {
                        "id": completion_id,
                        "object": "chat.completion.chunk",
                        "created": created_ts,
                        "model": req.model,
                        "error": evt.get("error", "upstream_stream_error"),
                        "choices": [
                            {
                                "index": 0,
                                "delta": {},
                                "finish_reason": "error",
                            }
                        ],
                    }
                    yield f"data: {json.dumps(chunk)}\n\n"
                    yield "data: [DONE]\n\n"
                    return
                elif evt_type == "done":
                    chunk = {
                        "id": completion_id,
                        "object": "chat.completion.chunk",
                        "created": created_ts,
                        "model": req.model,
                        "choices": [
                            {
                                "index": 0,
                                "delta": {},
                                "finish_reason": "stop",
                            }
                        ],
                        "monolith_audit": {
                            "terminated": False,
                            "redactions": redactions,
                            "peak_kl": evt.get("peak_kl", 0.0),
                        },
                    }
                    yield f"data: {json.dumps(chunk)}\n\n"
                    yield "data: [DONE]\n\n"
                    return

        return StreamingResponse(sse_stream(), media_type="text/event-stream")

    tokens: list[str] = []
    redactions: list[str] = []
    terminated = False
    finish_reason = "stop"
    peak_kl = 0.0
    tokens_seen = 0
    refusal_text = SAFE_REFUSAL
    upstream_error: str | None = None

    async for evt in auditor.audit(
        prompt,
        max_tokens,
        ctx,
        messages=req.messages,
        model=req.model,
        temperature=req.temperature,
    ):
        evt_type = evt.get("type")
        if evt_type == "token":
            tokens.append(evt["token"])
            if evt.get("kl") is not None:
                peak_kl = max(peak_kl, float(evt["kl"]))
        elif evt_type == "pii":
            redactions.append(evt["label"])
        elif evt_type == "terminated":
            terminated = True
            finish_reason = "content_filter"
            refusal_text = evt.get("safe_refusal", SAFE_REFUSAL)
            if evt.get("kl") is not None:
                peak_kl = max(peak_kl, float(evt["kl"]))
        elif evt_type == "error" or "error" in evt:
            upstream_error = evt.get("error", "upstream_stream_error")
            finish_reason = "error"
        elif evt_type == "done":
            peak_kl = max(peak_kl, float(evt.get("peak_kl", 0.0)))
            tokens_seen = int(evt.get("tokens", len(tokens)))

    content = refusal_text if terminated else "".join(tokens)
    prompt_tokens = len(prompt.split())
    if not tokens_seen:
        tokens_seen = len(tokens)
    result: dict[str, Any] = {
        "id": completion_id,
        "object": "chat.completion",
        "created": created_ts,
        "model": req.model,
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": content,
                },
                "finish_reason": finish_reason,
            }
        ],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": tokens_seen,
            "total_tokens": prompt_tokens + tokens_seen,
        },
        "monolith_audit": {
            "terminated": terminated,
            "redactions": redactions,
            "redaction_count": len(redactions),
            "peak_kl": round(peak_kl, 4),
        },
    }
    if upstream_error is not None:
        result["error"] = upstream_error
    return result
