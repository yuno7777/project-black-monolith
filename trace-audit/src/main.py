"""TraceAudit FastAPI service — reasoning-layer defense for Project Black
Monolith.

Exposes a streaming POST /generate endpoint (Server-Sent Events). Each token
is checked in real time against a baseline reasoning distribution (KL
divergence) and a PII/credential scanner; the stream is terminated early on
divergence, and secrets are redacted before they are forwarded or logged.
"""

from __future__ import annotations

import inspect
import json
import math
import os
import threading
import time
import uuid
from collections.abc import Sequence
from contextlib import asynccontextmanager
from secrets import compare_digest
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .anthropic_gateway import (
    AnthropicRelay,
    UpstreamStreamError,
    build_upstream_request,
    collect_message,
    iter_sse_events,
    relay_sse,
    standalone_refusal_message,
    standalone_refusal_sse,
    upstream_timeout,
)
from .config import MODULE_NAME, load_config
from .events import (
    EventContext,
    context_from_headers,
    is_session_revoked,
    make_emitter,
    now_ms,
    tenant_scope,
)
from .pii_scanner import scan
from .redaction import redact
from .stream_proxy import POLICY_VERSION, SAFE_REFUSAL, StreamAuditor

# Sessions this process already refused, so the refusal event fires once per
# session instead of once per request from a retrying agent.
_REFUSED_SESSIONS: set[str] = set()
_REFUSED_LOCK = threading.Lock()


def _session_is_revoked(ctx: EventContext | None) -> bool:
    """Whether the cross-layer circuit breaker revoked this session.

    The registry is fed by the outbox's ingest responses and by the periodic
    revocation poll, so the refusal survives even when this module has emitted
    nothing recently.
    """
    return bool(ctx and ctx.session_id and is_session_revoked(ctx.session_id))


def _report_revoked_session(ctx: EventContext | None) -> None:
    session_id = ctx.session_id if ctx else None
    if not session_id:
        return
    with _REFUSED_LOCK:
        first = session_id not in _REFUSED_SESSIONS
        _REFUSED_SESSIONS.add(session_id)
    if not first:
        return
    emit = getattr(app.state, "emit", None)
    if emit is None:
        return
    emit(
        "session_quarantined",
        "critical",
        {"session_id": session_id, "refusal": "generation"},
        ctx,
        resource_type="reasoning_trace",
        resource_id=ctx.trace_id if ctx else None,
        outcome="refused",
        policy_version=POLICY_VERSION,
    )


def _revoked_chat_completion(
    completion_id: str, created_ts: int, model: str
) -> dict[str, Any]:
    return {
        "id": completion_id,
        "object": "chat.completion",
        "created": created_ts,
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": SAFE_REFUSAL},
                "finish_reason": "content_filter",
            }
        ],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        "monolith_audit": {
            "terminated": True,
            "redactions": [],
            "redaction_count": 0,
            "peak_kl": 0.0,
            "session_revoked": True,
        },
    }


def _revoked_completion_chunk(
    completion_id: str, created_ts: int, model: str
) -> dict[str, Any]:
    return {
        "id": completion_id,
        "object": "chat.completion.chunk",
        "created": created_ts,
        "model": model,
        "choices": [
            {
                "index": 0,
                "delta": {"content": SAFE_REFUSAL},
                "finish_reason": "content_filter",
            }
        ],
        "monolith_audit": {
            "terminated": True,
            "redactions": [],
            "peak_kl": 0.0,
            "session_revoked": True,
        },
    }

MAX_PROMPT_BYTES = 64 * 1024
MAX_BASELINE_TOKEN_BYTES = 512
MAX_BASELINE_TOKEN_COUNT = 2_147_483_647
MAX_BASELINE_TOTAL = 100_000_000_000_000

# The shortest credential the literal redaction pass will substitute. Below
# this a "credential" is a word, and pulling a word out of an upstream error
# message would mangle it without protecting anything.
MIN_REDACTED_SECRET_LENGTH = 8


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
                if (
                    isinstance(item, dict)
                    and isinstance(item.get("text"), str)
                    and item["text"].strip()
                ):
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


def _load_baseline_model(path: str) -> str | None:
    """Which model the loaded baseline was captured from, if it says.

    A KL divergence score is only meaningful against a baseline from the
    same model: the token distribution of one model says nothing about
    another's. A baseline with no recorded model is treated as
    model-agnostic, and the gateway refuses to use it for termination.
    """
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    model = data.get("model")
    if isinstance(model, str) and model.strip():
        return model.strip()
    return None


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
    baseline_model = _load_baseline_model(cfg.baseline_path)
    auditor = StreamAuditor(cfg, baseline_counts, emit)
    app.state.cfg = cfg
    app.state.emit = emit
    app.state.baseline_counts = baseline_counts
    app.state.baseline = baseline_counts
    app.state.baseline_model = baseline_model
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
            "baseline_model": baseline_model,
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
    app.state.baseline_model = _load_baseline_model(cfg.baseline_path)
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


def _accepts_tenant_scope(replay: object) -> bool:
    """Whether a replay callable can be scoped to one tenant."""
    try:
        parameters = inspect.signature(replay).parameters  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return False
    if "tenant_id" in parameters:
        return True
    return any(
        parameter.kind is inspect.Parameter.VAR_KEYWORD
        for parameter in parameters.values()
    )


def _replay_through(replay: object, tenant: str | None) -> int:
    """Requeue dead letters through a replay callable, honouring the scope.

    A scope the callable cannot honour is refused rather than dropped:
    replaying the whole spool on behalf of one tenant is exactly the mistake
    the scope exists to prevent.
    """
    if tenant is None:
        return int(replay())  # type: ignore[operator]
    if not _accepts_tenant_scope(replay):
        raise HTTPException(
            status_code=409,
            detail="this outbox cannot scope a replay to one tenant",
        )
    return int(replay(tenant_id=tenant))  # type: ignore[operator]


def _replay_dead_rows(outbox: object, tenant: str | None) -> int:
    """Requeue dead rows for an outbox that does not expose the helper.

    Kept for an outbox that is not this package's `EventOutbox`: it reaches
    into the table directly, and it honours the tenant scope the same way,
    because an unscoped replay would requeue another tenant's evidence.
    """
    timestamp = now_ms()
    with outbox._lock, outbox._connection:  # type: ignore[attr-defined]
        if tenant is None:
            cursor = outbox._connection.execute(  # type: ignore[attr-defined]
                """update event_outbox
                   set status = 'pending', attempts = 0,
                       next_attempt_ms = ?, updated_ms = ?
                   where status = 'dead'""",
                (timestamp, timestamp),
            )
        else:
            cursor = outbox._connection.execute(  # type: ignore[attr-defined]
                """update event_outbox
                   set status = 'pending', attempts = 0,
                       next_attempt_ms = ?, updated_ms = ?
                   where status = 'dead' and tenant_id = ?""",
                (timestamp, timestamp, tenant),
            )
        replayed = int(
            cursor.rowcount
            if cursor.rowcount is not None and cursor.rowcount >= 0
            else 0
        )
    if hasattr(outbox, "_wake"):
        outbox._wake.set()
    return replayed


@app.post("/admin/replay-dead-letters")
async def replay_dead_letters(request: Request) -> dict:
    """Requeue dead-lettered outbox events, optionally for one tenant.

    `?tenant=` narrows the replay to one tenant. The outbox is shared by every
    tenant this module serves, so an unscoped replay requeues another tenant's
    evidence too. A tenant that cannot be read is refused rather than ignored:
    a typo must never widen the replay to the whole spool.
    """
    _require_admin_token(request)
    try:
        tenant = tenant_scope(request.query_params.get("tenant"))
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    emit = getattr(app.state, "emit", None)
    replayed = 0
    if emit is not None:
        replay = getattr(emit, "replay_dead_letters", None)
        if callable(replay):
            replayed = _replay_through(replay, tenant)
        else:
            outbox = getattr(emit, "outbox", None)
            if outbox is not None:
                replay = getattr(outbox, "replay_dead_letters", None)
                if callable(replay):
                    replayed = _replay_through(replay, tenant)
                elif hasattr(outbox, "_connection") and hasattr(outbox, "_lock"):
                    replayed = _replay_dead_rows(outbox, tenant)
    return {"replayed": replayed}


@app.post("/generate")
async def generate(req: GenerateRequest, request: Request) -> StreamingResponse:
    auditor: StreamAuditor = app.state.auditor
    # Read the headers before the response starts streaming: the generator body
    # runs after the handler returns, and reaching for the request from inside
    # it would be reading state that is no longer guaranteed to be there.
    ctx = context_from_headers(request.headers)

    if _session_is_revoked(ctx):
        _report_revoked_session(ctx)
        refusal = {
            "type": "terminated",
            "reason": "session_revoked",
            "kl": 0.0,
            "threshold": auditor.cfg.kl_threshold,
            "safe_refusal": SAFE_REFUSAL,
        }

        async def revoked_stream():
            yield f"data: {json.dumps(refusal)}\n\n"

        return StreamingResponse(revoked_stream(), media_type="text/event-stream")

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

    if _session_is_revoked(ctx):
        _report_revoked_session(ctx)
        if req.stream:
            chunk = _revoked_completion_chunk(completion_id, created_ts, req.model)

            async def revoked_sse():
                yield f"data: {json.dumps(chunk)}\n\n"
                yield "data: [DONE]\n\n"

            return StreamingResponse(revoked_sse(), media_type="text/event-stream")
        return _revoked_chat_completion(completion_id, created_ts, req.model)

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


# --- Anthropic Messages gateway -------------------------------------------
#
# Claude Code and every other Anthropic client speak this endpoint. The
# request is forwarded upstream unchanged and the answer comes back through
# the auditor, so a credential the model emits is redacted before the agent
# reads it. The wire format is preserved exactly: a client that cannot tell
# the difference is the point.

MAX_MESSAGES_BODY_BYTES = 4 * 1024 * 1024

# How much of an oversized body is read and thrown away so the 413 reaches
# the client instead of a connection torn down mid-upload. The bytes are
# dropped, never buffered.
MAX_OVERSIZED_DRAIN_BYTES = 4 * 1024 * 1024


async def _read_capped_body(request: Request, limit: int) -> bytes:
    """Read the request body, never buffering more than `limit` bytes.

    ``request.body()`` accumulates every chunk with no ceiling of its own, so
    a size check afterwards only measures a body that is already in memory:
    the guard protects nothing. Counting the bytes as they arrive is what
    makes the limit real.
    """
    chunks: list[bytes] = []
    total = 0
    oversized = False
    discarded = 0
    async for chunk in request.stream():
        if oversized:
            # Keep draining (without keeping the bytes) so the client can
            # finish its upload and read the 413 we are about to send.
            discarded += len(chunk)
            if discarded > MAX_OVERSIZED_DRAIN_BYTES:
                break
            continue
        total += len(chunk)
        if total > limit:
            oversized = True
            chunks.clear()
            continue
        chunks.append(chunk)
    if oversized:
        raise HTTPException(status_code=413, detail="request body is too large")
    return b"".join(chunks)

# One notice per (baseline model, requested model) pair, so a busy gateway
# does not write a ledger row for every request it declines to score.
_DIVERGENCE_NOTICES: set[tuple[str | None, str]] = set()
_DIVERGENCE_NOTICE_LOCK = threading.Lock()

# How many distinct (baseline, requested) model pairs to remember.
#
# The requested model is client-controlled, so an unauthenticated caller
# could otherwise grow this set without bound for the life of the
# container — and, past the cap, could make the gateway write a fresh
# ledger row for every request by naming a model the registry has not
# seen. So the cap bounds the notices as well as the memory: past it the
# notice is dropped, and the first few hundred already say what it says.
MAX_DIVERGENCE_NOTICES = 256


def _divergence_notice_once(
    baseline_model: str | None, requested_model: str, reason: str
) -> None:
    key = (baseline_model, requested_model)
    with _DIVERGENCE_NOTICE_LOCK:
        if key in _DIVERGENCE_NOTICES:
            return
        if len(_DIVERGENCE_NOTICES) >= MAX_DIVERGENCE_NOTICES:
            # The registry is full. Emitting anyway would let a caller
            # choose a fresh model name per request and write a ledger row
            # every time; the notice is a courtesy, not a control.
            return
        _DIVERGENCE_NOTICES.add(key)
    emit = getattr(app.state, "emit", None)
    if emit is None:
        return
    emit(
        "divergence_disabled",
        "info",
        {
            "requested_model": requested_model,
            "baseline_model": baseline_model,
            "reason": reason,
            "message": (
                "divergence detection is off for this model: the loaded baseline "
                "was captured from a different model, so its KL scores would not "
                "mean anything. Credential redaction still applies."
            ),
        },
        resource_type="reasoning_trace",
        outcome="divergence_disabled",
        policy_version=POLICY_VERSION,
    )


def _redact_upstream_error(
    error_body: bytes,
    ctx: EventContext | None,
    secrets: Sequence[str] = (),
) -> bytes:
    """Redact credential-shaped spans in an upstream error body.

    The success path is audited, so every byte of a model's answer is scanned
    before the client sees it. The error path was not: an upstream error body
    is upstream-controlled text and this was the one place where it reached
    the client verbatim. A provider that echoes a key back in its error
    message would hand that key to the agent.

    Two passes, because they catch different things. The scanner finds the
    *shapes* it was written for. The literal pass finds the exact credential
    this gateway holds — the operator's fallback key — whatever shape it
    happens to have: Anthropic keys are hyphenated ("sk-ant-..."), and the
    openai-style pattern stops at the first hyphen, so a pattern-only pass
    would let the operator's own key straight through to the client that
    never had it.
    """
    text = error_body.decode("utf-8", errors="replace")
    matches = scan(text)
    # The pattern redaction runs first: it replaces spans by offset, and
    # substituting a literal afterwards would move those offsets out from
    # under it.
    redacted = redact(text, matches)
    literal_hits = 0
    for secret in secrets:
        # A short "credential" is a word, and redacting a word out of an
        # error message helps nobody.
        if not secret or len(secret) < MIN_REDACTED_SECRET_LENGTH:
            continue
        if secret in redacted:
            redacted = redacted.replace(secret, "[REDACTED:anthropic_api_key]")
            literal_hits += 1
    if not matches and not literal_hits:
        return error_body
    emit = getattr(app.state, "emit", None)
    if emit is not None:
        for match in matches:
            emit(
                "pii_redacted",
                "warning",
                {
                    "label": match.label,
                    "redacted_as": f"[REDACTED:{match.label}]",
                    "position_tokens": 0,
                    "source": "upstream_error_body",
                },
                ctx,
                resource_type="reasoning_trace",
                resource_id=ctx.trace_id if ctx else None,
                outcome="redacted",
                policy_version=POLICY_VERSION,
            )
        if literal_hits:
            emit(
                "pii_redacted",
                "warning",
                {
                    "label": "anthropic_api_key",
                    "redacted_as": "[REDACTED:anthropic_api_key]",
                    "position_tokens": 0,
                    "source": "upstream_error_body",
                },
                ctx,
                resource_type="reasoning_trace",
                resource_id=ctx.trace_id if ctx else None,
                outcome="redacted",
                policy_version=POLICY_VERSION,
            )
    return redacted.encode("utf-8")


def _report_truncated_answer(ctx: EventContext | None, summary: dict[str, Any]) -> None:
    """Record an answer the upstream cut short.

    The auditor emits ``generation_completed`` when a stream ends cleanly, so
    a run whose answer was truncated used to leave the ledger saying the
    generation completed — and the session report read as a run in which
    nothing happened, for an answer the client never received. The truncation
    is an operational failure rather than a security finding, so it is
    recorded with a warning severity; the outcome says what it did to the
    agent, which is the part that matters.
    """
    if not summary.get("truncated"):
        return
    emit = getattr(app.state, "emit", None)
    if emit is None:
        return
    emit(
        "generation_truncated",
        "warning",
        {
            "reason": "upstream ended the answer before message_stop",
            "stop_reason": summary.get("stop_reason"),
            "blocks": summary.get("blocks"),
        },
        ctx,
        resource_type="reasoning_trace",
        resource_id=ctx.trace_id if ctx else None,
        outcome="terminated",
        policy_version=POLICY_VERSION,
    )


@app.post("/v1/messages")
async def messages(request: Request):
    """The Anthropic Messages API, guarded.

    The client's own credential is forwarded upstream untouched; the gateway
    holds no key of its own unless the operator configured one as a fallback.
    """
    cfg = app.state.cfg
    auditor: StreamAuditor = app.state.auditor
    ctx = context_from_headers(request.headers)

    raw = await _read_capped_body(request, MAX_MESSAGES_BODY_BYTES)
    try:
        body = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="invalid JSON body") from exc
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="request body must be a JSON object")
    model = body.get("model")
    if not isinstance(model, str) or not model.strip() or len(model) > 128:
        raise HTTPException(status_code=400, detail="model must be a string of 1-128 characters")
    request_messages = body.get("messages")
    if not isinstance(request_messages, list) or not request_messages:
        raise HTTPException(status_code=400, detail="messages must be a non-empty array")
    max_tokens = body.get("max_tokens")
    if max_tokens is not None:
        if isinstance(max_tokens, bool) or not isinstance(max_tokens, int) or max_tokens < 1:
            raise HTTPException(status_code=400, detail="max_tokens must be a positive integer")
        if max_tokens > cfg.anthropic_max_tokens:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"max_tokens exceeds the operator ceiling of "
                    f"{cfg.anthropic_max_tokens}"
                ),
            )

    # The gateway holds no credential of its own unless the operator
    # configured one as a fallback. A request that carries neither a key nor
    # an authorization header is therefore forwarded with no credential at
    # all, which is an unauthenticated request to the model API wearing the
    # gateway's address. Reject it here rather than let it leave.
    client_key = request.headers.get("x-api-key")
    client_auth = request.headers.get("authorization")
    if not client_key and not client_auth and not cfg.anthropic_api_key:
        raise HTTPException(
            status_code=401,
            detail=(
                "no credential: send x-api-key or authorization, or configure "
                "a gateway fallback key"
            ),
        )

    effective_model = cfg.anthropic_model or model
    # The Messages API streams only when asked to; the default is one
    # document. A client that omits the flag asked for a document, and the
    # upstream would send one — which the auditor cannot read, because it
    # inspects the answer as it arrives. So the upstream is always asked to
    # stream, and the document is assembled here when the client wanted one.
    wants_json = body.get("stream") is not True
    if wants_json:
        # The audit needs the stream: the answer is inspected as it arrives,
        # so the upstream is always asked to stream and the single document
        # is assembled here.
        body["stream"] = True
    if cfg.anthropic_model and cfg.anthropic_model != model:
        # The operator pinned a model. Say so by asking for that one.
        body["model"] = cfg.anthropic_model
    if wants_json or (cfg.anthropic_model and cfg.anthropic_model != model):
        raw = json.dumps(body, separators=(",", ":")).encode("utf-8")

    if _session_is_revoked(ctx):
        _report_revoked_session(ctx)
        message_id = f"msg_{uuid.uuid4().hex[:24]}"
        if wants_json:
            # A client that asked for one document gets one document: an
            # event stream here would be a body it cannot parse, and a
            # parse failure is read as a transport error and retried.
            return Response(
                content=json.dumps(
                    standalone_refusal_message(effective_model, message_id),
                    separators=(",", ":"),
                ),
                media_type="application/json",
            )
        return Response(
            content=standalone_refusal_sse(effective_model, message_id),
            media_type="text/event-stream",
        )

    baseline_model = getattr(app.state, "baseline_model", None)
    divergence_enabled = bool(baseline_model) and baseline_model == effective_model
    if not divergence_enabled:
        _divergence_notice_once(
            baseline_model,
            effective_model,
            "baseline_model_mismatch" if baseline_model else "baseline_records_no_model",
        )

    url, headers, payload = build_upstream_request(
        raw,
        cfg,
        {key.lower(): value for key, value in request.headers.items()},
    )
    client = httpx.AsyncClient(timeout=upstream_timeout())
    upstream_request = client.build_request("POST", url, content=payload, headers=headers)
    try:
        response = await client.send(upstream_request, stream=True)
    except httpx.HTTPError as exc:
        await client.aclose()
        raise HTTPException(status_code=502, detail="upstream model is unreachable") from exc

    if response.status_code != 200:
        # Forward the upstream's own error: the client asked a question the
        # model refused, and inventing a different error would hide the
        # reason. It is still upstream-controlled text, so it gets the same
        # redaction every byte of the success stream gets.
        error_body = await response.aread()
        await response.aclose()
        await client.aclose()
        return Response(
            content=_redact_upstream_error(
                error_body,
                ctx,
                # The credentials this request could have carried. The
                # operator's fallback key is the dangerous one: the client
                # never had it, and an upstream that echoes it would hand it
                # to a party that never owned it.
                secrets=(cfg.anthropic_api_key or "", client_key or "", client_auth or ""),
            ),
            status_code=response.status_code,
            media_type="application/json",
        )

    relay = AnthropicRelay(auditor, ctx, divergence_enabled=divergence_enabled)

    if wants_json:
        async def collect():
            try:
                return await collect_message(relay, iter_sse_events(response.aiter_lines()))
            finally:
                await response.aclose()
                await client.aclose()

        try:
            message = await collect()
        except UpstreamStreamError as exc:
            # The upstream broke mid-answer. A partial answer delivered as a
            # complete one is worse than an error: the agent would act on it
            # and never learn that it was truncated. The truncation is
            # recorded first, so the ledger says what happened even though
            # the client only ever sees a 502.
            _report_truncated_answer(ctx, relay.summary())
            raise HTTPException(
                status_code=502,
                detail="upstream model stream ended before the answer was complete",
            ) from exc
        return Response(
            content=json.dumps(message, separators=(",", ":")),
            media_type="application/json",
        )

    async def stream():
        try:
            async for chunk in relay_sse(relay, response):
                yield chunk
        finally:
            # An answer the upstream cut short has to reach the ledger: the
            # auditor emits generation_completed when a stream ends cleanly,
            # so without this the run reads as a completed one for an answer
            # the client never received.
            _report_truncated_answer(ctx, relay.summary())
            await response.aclose()
            await client.aclose()

    return StreamingResponse(stream(), media_type="text/event-stream")
