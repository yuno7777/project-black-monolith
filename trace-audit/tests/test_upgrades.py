"""Tests for TRACE-1, TRACE-2, TRACE-3, and INFRA-3 upgrades."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import httpx
import pytest
from fastapi.testclient import TestClient

import fixtures.baseline_capture as baseline_capture
import src.stream_proxy as stream_proxy
from src.config import load_config
from src.divergence_monitor import build_distribution
from src.main import app
from src.stream_proxy import (
    NORMAL_TOKENS,
    SAFE_REFUSAL,
    PiiStreamBuffer,
    StreamAuditor,
    StreamProxy,
    _openai_stream,
)

ADMIN_TOKEN = "admin-secret-token-0000"


def _make_cfg(tmp_path, **overrides):
    defaults = dict(
        model_backend="mock",
        ollama_base_url="http://localhost:11434",
        ollama_model="llama3.2",
        openai_base_url="http://localhost:8000",
        openai_api_key=None,
        openai_model="default",
        baseline_path=str(tmp_path / "baseline.json"),
        kl_threshold=1.0,
        window_size=20,
        min_tokens_before_check=12,
        smoothing=0.5,
        max_tokens=60,
        dashboard_url=None,
        event_token=None,
        event_outbox_path=str(tmp_path / "outbox.db"),
        allow_insecure_dashboard=False,
        admin_token=ADMIN_TOKEN,
        tenant_id="default",
        agent_id=None,
        session_id=None,
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _setup_app_state(tmp_path, *, baseline_counts=None, **cfg_overrides):
    cfg = _make_cfg(tmp_path, **cfg_overrides)
    counts = (
        baseline_counts
        if baseline_counts is not None
        else build_distribution(NORMAL_TOKENS * 5)
    )
    events: list[tuple] = []

    def emit(event_type, severity, details, ctx=None, **kwargs):
        events.append((event_type, severity, details, ctx, kwargs))

    emit.delivery_stats = lambda: {
        "pending": 0,
        "dead": 0,
        "worker_alive": False,
        "worker_error": None,
    }
    emit.close = lambda: None
    auditor = StreamAuditor(cfg, counts, emit)
    app.state.cfg = cfg
    app.state.emit = emit
    app.state.baseline_counts = counts
    app.state.baseline = counts
    app.state.auditor = auditor
    app.state.proxy = auditor
    return events


# --- TRACE-1: OpenAI-Compatible POST /v1/chat/completions -------------------


def test_chat_completions_non_streaming_normal(tmp_path):
    events = _setup_app_state(tmp_path, max_tokens=20)
    client = TestClient(app, raise_server_exceptions=True)

    resp = client.post(
        "/v1/chat/completions",
        headers={
            "X-Monolith-Session-Id": "sess-openai-1",
            "X-Monolith-Trace-Id": "trace-openai-1",
            "X-Monolith-Correlation-Id": "corr-openai-1",
            "X-Monolith-Agent-Id": "agent-openai-1",
        },
        json={
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": "Explain how compound interest works."}],
            "stream": False,
            "max_tokens": 16,
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["object"] == "chat.completion"
    assert body["model"] == "gpt-4o-mini"
    assert body["id"].startswith("chatcmpl-")
    choice = body["choices"][0]
    assert choice["finish_reason"] == "stop"
    assert choice["message"]["role"] == "assistant"
    assert len(choice["message"]["content"].strip()) > 0
    audit = body["monolith_audit"]
    assert audit["terminated"] is False
    assert audit["redactions"] == []
    assert isinstance(audit["peak_kl"], float)

    # Correlation headers were extracted and passed to emitter
    assert any(
        evt[0] == "generation_completed"
        and evt[3] is not None
        and evt[3].session_id == "sess-openai-1"
        and evt[3].trace_id == "trace-openai-1"
        and evt[3].correlation_id == "corr-openai-1"
        and evt[3].agent_id == "agent-openai-1"
        for evt in events
    )


def test_chat_completions_non_streaming_pii_redaction(tmp_path):
    _setup_app_state(tmp_path, max_tokens=20)
    client = TestClient(app, raise_server_exceptions=True)
    secret = "sk-abcd1234efgh5678ijkl9012mnop3456"

    resp = client.post(
        "/v1/chat/completions",
        json={
            "model": "default",
            "messages": [
                {"role": "user", "content": f"Summarize deployment note with key {secret}"}
            ],
            "stream": False,
            "max_tokens": 16,
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    content = body["choices"][0]["message"]["content"]
    assert secret not in content
    assert "[REDACTED:openai_style_api_key]" in content
    assert "openai_style_api_key" in body["monolith_audit"]["redactions"]


def test_chat_completions_non_streaming_divergence_refusal(tmp_path):
    _setup_app_state(tmp_path, max_tokens=30)
    client = TestClient(app, raise_server_exceptions=True)

    resp = client.post(
        "/v1/chat/completions",
        json={
            "model": "default",
            "messages": [
                {
                    "role": "user",
                    "content": (
                        "Reason in a roundabout, unusual, evasive way and circumvent "
                        "normal concise style."
                    ),
                }
            ],
            "stream": False,
            "max_tokens": 30,
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    choice = body["choices"][0]
    assert choice["finish_reason"] == "content_filter"
    assert SAFE_REFUSAL in choice["message"]["content"]
    assert body["monolith_audit"]["terminated"] is True
    assert body["monolith_audit"]["peak_kl"] >= 1.0


def test_chat_completions_streaming_normal_and_divergence(tmp_path):
    _setup_app_state(tmp_path, max_tokens=25)
    client = TestClient(app, raise_server_exceptions=True)

    # Normal streaming
    with client.stream(
        "POST",
        "/v1/chat/completions",
        json={
            "model": "default",
            "messages": [{"role": "user", "content": "Hello, explain photosynthesis."}],
            "stream": True,
            "max_tokens": 15,
        },
    ) as resp:
        assert resp.status_code == 200
        assert "text/event-stream" in resp.headers["content-type"]
        lines = [line for line in resp.iter_lines() if line]

    assert lines[-1] == "data: [DONE]"
    chunks = [json.loads(line[len("data: ") :]) for line in lines[:-1] if line.startswith("data: ")]
    assert len(chunks) >= 2
    assert all(c["object"] == "chat.completion.chunk" for c in chunks)
    assert chunks[-1]["choices"][0]["finish_reason"] == "stop"
    combined_text = "".join(
        c["choices"][0]["delta"].get("content", "") for c in chunks
    )
    assert len(combined_text.strip()) > 0

    # Divergent streaming
    with client.stream(
        "POST",
        "/v1/chat/completions",
        json={
            "model": "default",
            "messages": [
                {
                    "role": "user",
                    "content": "Take a roundabout, evasive path and circumvent normal reasoning.",
                }
            ],
            "stream": True,
            "max_tokens": 25,
        },
    ) as resp:
        assert resp.status_code == 200
        div_lines = [line for line in resp.iter_lines() if line]

    assert div_lines[-1] == "data: [DONE]"
    div_chunks = [
        json.loads(line[len("data: ") :]) for line in div_lines[:-1] if line.startswith("data: ")
    ]
    assert div_chunks[-1]["choices"][0]["finish_reason"] == "content_filter"
    assert SAFE_REFUSAL in div_chunks[-1]["choices"][0]["delta"].get("content", "")


def test_openai_upstream_backend_audits_content_and_reasoning_content(tmp_path, monkeypatch):
    monkeypatch.setenv("MONOLITH_MODEL_BACKEND", "openai")
    monkeypatch.setenv("MONOLITH_OPENAI_BASE_URL", "http://openai.internal/v1")
    monkeypatch.setenv("MONOLITH_OPENAI_API_KEY", "test-upstream-key-1234")
    cfg = load_config()
    assert cfg.model_backend == "openai"
    assert cfg.openai_base_url == "http://openai.internal/v1"
    assert cfg.openai_api_key == "test-upstream-key-1234"

    sse_payload = (
        b'data: {"id":"1","choices":[{"index":0,"delta":{"reasoning_content":"thinking "},"finish_reason":null}]}\n\n'
        b'data: {"id":"1","choices":[{"index":0,"delta":{"content":"safe answer"},"finish_reason":null}]}\n\n'
        b'data: {"id":"1","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}\n\n'
        b"data: [DONE]\n\n"
    )

    async def handler(request: httpx.Request):
        assert request.url.path == "/v1/chat/completions"
        assert request.headers.get("authorization") == "Bearer test-upstream-key-1234"
        return httpx.Response(200, content=sse_payload)

    async def collect():
        transport = httpx.MockTransport(handler)
        return [
            tok
            async for tok in _openai_stream(
                "prompt",
                10,
                cfg,
                messages=[{"role": "user", "content": "hi"}],
                transport=transport,
            )
        ]

    tokens = asyncio.run(collect())
    assert tokens == ["thinking ", "safe answer"]


# --- TRACE-2: Variable-Length Split-Token PII Holdback & Stream Error Safety -


def test_variable_length_split_token_sk_key_with_22_plus_chars_in_first_token():
    """When the first token already has 22+ chars after sk-, it matches
    sk-[A-Za-z0-9]{20,}, but because the match reaches the end of `combined`
    and len(_pending) < window_tokens, PiiStreamBuffer must hold back draining
    so trailing secret characters in subsequent tokens do not leak in plaintext.
    """
    part1 = "sk-" + "A" * 24  # 24 chars after sk- (already a valid match on its own)
    part2 = "B" * 14          # 14 trailing chars of the same secret in token 2
    part3 = " and normal text"

    buf = PiiStreamBuffer()
    d1 = buf.push(part1, None)
    # Must hold back: must NOT redact and flush after token 1!
    assert d1.outputs == []
    assert d1.matches == []

    d2 = buf.push(part2, None)
    # Match still touches the end of combined: keep holding back!
    assert d2.outputs == []
    assert d2.matches == []

    d3 = buf.push(part3, None)
    d_end = buf.flush()
    all_outputs = "".join(t.token for t in (d3.outputs + d_end.outputs))
    all_matches = d3.matches + d_end.matches

    assert len(all_matches) == 1
    assert all_matches[0].label == "openai_style_api_key"
    assert all_matches[0].value == part1 + part2
    assert "A" * 5 not in all_outputs
    assert "B" * 5 not in all_outputs
    assert all_outputs == "[REDACTED:openai_style_api_key] and normal text"


def test_variable_length_split_token_sk_key_flushed_at_eof():
    part1 = "sk-1234567890123456789012"  # 22 chars after sk-
    part2 = "tailsecret999"

    buf = PiiStreamBuffer()
    assert buf.push(part1, None).outputs == []
    assert buf.push(part2, None).outputs == []
    flushed = buf.flush()
    text = "".join(t.token for t in flushed.outputs)
    assert text == "[REDACTED:openai_style_api_key]"
    assert "tailsecret999" not in text


def test_variable_length_split_token_hold_is_bounded_by_characters_not_fragments():
    """The hold back is bounded by characters, not by fragment count.

    A credential that arrives in many fragments must stay redactable as a
    whole. Releasing it once the fragment count passed a threshold would
    redact the matched prefix and then release the remainder in plaintext,
    because the continuation no longer carries the pattern's prefix.
    """
    buf = PiiStreamBuffer(window_tokens=3)
    assert buf.push("sk-1234567890123456789012", None).outputs == []
    assert buf.push("abcdef", None).outputs == []
    # Past window_tokens the candidate is still held: the match reaches the
    # end of the buffer and may continue.
    assert buf.push("ghijkl", None).outputs == []

    # The candidate completes when a non-alphanumeric boundary arrives, and
    # the whole credential is redacted at once.
    d4 = buf.push(" done", None)
    flushed = buf.flush()
    text = "".join(t.token for t in (d4.outputs + flushed.outputs))
    assert text == "[REDACTED:openai_style_api_key] done"
    assert "1234567890123456789012" not in text
    assert "abcdefghijkl" not in text


def test_split_credential_across_many_fragments_leaks_no_plaintext():
    """Regression: a credential split across many fragments is redacted whole.

    The buffer used to release the candidate once the fragment count passed
    `window_tokens`, which redacted the matched prefix and then released the
    tail of the same credential in plaintext.
    """
    secret = "sk-" + "A" * 20 + "D" * 59
    for fragment_size in (2, 3, 4, 5, 8, 11):
        buf = PiiStreamBuffer()
        outputs = []
        for index in range(0, len(secret), fragment_size):
            outputs.extend(t.token for t in buf.push(secret[index : index + fragment_size], None).outputs)
        outputs.extend(t.token for t in buf.finish().outputs)
        text = "".join(outputs)
        assert secret not in text, f"fragment size {fragment_size} leaked the credential"
        assert "A" * 5 not in text, f"fragment size {fragment_size} leaked the credential head"
        assert "D" * 5 not in text, f"fragment size {fragment_size} leaked the credential tail"
        assert "[REDACTED:openai_style_api_key]" in text


def test_upstream_stream_errors_yield_structured_error_frame(tmp_path, monkeypatch):
    cfg = _make_cfg(tmp_path)
    auditor = StreamProxy(cfg, {}, lambda *_a, **_kw: None)

    async def failing_http_stream(_prompt, _max_tokens, _cfg):
        yield "let "
        raise httpx.ReadError("connection reset mid-stream")

    monkeypatch.setattr(stream_proxy, "_backend_stream", failing_http_stream)

    async def collect_http_err():
        return [evt async for evt in auditor.audit_stream("hello")]

    events = asyncio.run(collect_http_err())
    assert events[-1]["error"] == "upstream_stream_error"

    async def failing_json_stream(_prompt, _max_tokens, _cfg):
        yield "let "
        raise ValueError("malformed upstream JSON")

    monkeypatch.setattr(stream_proxy, "_backend_stream", failing_json_stream)

    async def collect_val_err():
        return [evt async for evt in auditor.audit_stream("hello")]

    events2 = asyncio.run(collect_val_err())
    assert events2[-1]["error"] == "upstream_stream_error"


# --- TRACE-3 & INFRA-3: Hot Baseline Reload, Dead-Letter Replay, Startup -----


def test_admin_reload_baseline_updates_memory_and_disk_atomically(tmp_path):
    _setup_app_state(tmp_path, baseline_counts={"old": 10})
    client = TestClient(app, raise_server_exceptions=True)

    # Unauthorized rejected
    unauth = client.post("/admin/reload-baseline")
    assert unauth.status_code == 401

    # Authorized with new distribution
    new_dist = {"alpha": 0.5, "beta": 0.3, "gamma": 0.2}
    resp = client.post(
        "/admin/reload-baseline",
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
        json={"distribution": new_dist},
    )
    assert resp.status_code == 200
    assert resp.json() == {"reloaded": True, "vocab_size": 3}
    assert set(app.state.baseline.keys()) == {"alpha", "beta", "gamma"}
    assert app.state.proxy.baseline_counts == app.state.baseline
    assert (tmp_path / "baseline.json").exists()

    # Reload from disk without body
    resp2 = client.post(
        "/admin/reload-baseline",
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
    )
    assert resp2.status_code == 200
    assert resp2.json() == {"reloaded": True, "vocab_size": 3}


def test_admin_replay_dead_letters_endpoint(tmp_path):
    _setup_app_state(tmp_path)
    client = TestClient(app, raise_server_exceptions=True)

    # Unauthorized rejected
    assert client.post("/admin/replay-dead-letters").status_code == 401

    # Authorized with no outbox falls back gracefully to 0
    resp = client.post(
        "/admin/replay-dead-letters",
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"replayed": 0}

    # With mock outbox exposing replay_dead_letters()
    app.state.emit.outbox = SimpleNamespace(replay_dead_letters=lambda: 4)
    resp2 = client.post(
        "/admin/replay-dead-letters",
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
    )
    assert resp2.status_code == 200
    assert resp2.json() == {"replayed": 4}


def test_admin_replay_dead_letters_endpoint_is_scoped_to_one_tenant(tmp_path):
    _setup_app_state(tmp_path)
    client = TestClient(app, raise_server_exceptions=True)

    seen: list[str | None] = []

    def replay(tenant_id=None):
        seen.append(tenant_id)
        return 4

    app.state.emit.outbox = SimpleNamespace(replay_dead_letters=replay)

    # The outbox is shared by every tenant this module serves, so a replay
    # that named no tenant would requeue another tenant's evidence too.
    resp = client.post(
        "/admin/replay-dead-letters?tenant=acme",
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"replayed": 4}
    assert seen == ["acme"]


def test_admin_replay_dead_letters_endpoint_scopes_the_emitter_path(tmp_path):
    _setup_app_state(tmp_path)
    client = TestClient(app, raise_server_exceptions=True)

    seen: list[str | None] = []

    def replay(tenant_id=None):
        seen.append(tenant_id)
        return 3

    # The production emitter carries the replay helper itself, so the endpoint
    # takes that path rather than reaching into the outbox beneath it. The
    # scope has to survive that hop too.
    app.state.emit.replay_dead_letters = replay

    resp = client.post(
        "/admin/replay-dead-letters?tenant=acme",
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"replayed": 3}
    assert seen == ["acme"]


def test_admin_replay_dead_letters_endpoint_refuses_an_unreadable_tenant(tmp_path):
    _setup_app_state(tmp_path)
    client = TestClient(app, raise_server_exceptions=True)
    app.state.emit.outbox = SimpleNamespace(replay_dead_letters=lambda: 4)

    # A tenant nobody can read must not fall back to the whole spool.
    resp = client.post(
        "/admin/replay-dead-letters?tenant=",
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
    )
    assert resp.status_code == 422


def test_admin_replay_dead_letters_endpoint_refuses_a_scope_it_cannot_honour(tmp_path):
    _setup_app_state(tmp_path)
    client = TestClient(app, raise_server_exceptions=True)
    app.state.emit.outbox = SimpleNamespace(replay_dead_letters=lambda: 4)

    # This outbox cannot be scoped. Replaying anyway would hand a tenant
    # somebody else's evidence, which is the mistake the scope exists to
    # prevent — so the request is refused instead.
    resp = client.post(
        "/admin/replay-dead-letters?tenant=acme",
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
    )
    assert resp.status_code == 409


def test_baseline_capture_idempotency_force_and_fallback(tmp_path, monkeypatch):
    baseline_file = tmp_path / "baseline_distribution.json"
    monkeypatch.setenv("MONOLITH_BASELINE_PATH", str(baseline_file))
    monkeypatch.setenv("MONOLITH_MODEL_BACKEND", "mock")

    # 1. Pre-populate valid non-empty baseline: should skip unless --force
    existing = {"counts": {"preserved_token": 42}, "total": 42, "prompts": 1, "vocab": 1}
    baseline_file.write_text(json.dumps(existing), encoding="utf-8")

    baseline_capture.main([])
    loaded = json.loads(baseline_file.read_text(encoding="utf-8"))
    assert loaded["counts"] == {"preserved_token": 42}

    # 2. With --force, overwrites atomically with fresh captured distribution
    baseline_capture.main(["--force"])
    overwritten = json.loads(baseline_file.read_text(encoding="utf-8"))
    assert "preserved_token" not in overwritten["counts"]
    assert overwritten["vocab"] > 5

    # 3. If upstream fails on boot, logs warning and copies fallback without crashing
    fallback_file = tmp_path / "fallback_baseline.json"
    fallback_data = {"counts": {"fallback_tok": 99}, "total": 99, "prompts": 1, "vocab": 1}
    fallback_file.write_text(json.dumps(fallback_data), encoding="utf-8")
    target_on_fail = tmp_path / "boot_baseline.json"
    monkeypatch.setenv("MONOLITH_BASELINE_PATH", str(target_on_fail))
    monkeypatch.setattr(
        baseline_capture, "FALLBACK_BASELINE_PATHS", (str(fallback_file),)
    )

    async def broken_collect():
        raise ConnectionError("upstream unreachable")

    monkeypatch.setattr(baseline_capture, "collect", broken_collect)
    baseline_capture.main(["--force"])
    assert target_on_fail.exists()
    assert json.loads(target_on_fail.read_text(encoding="utf-8"))["counts"] == {
        "fallback_tok": 99
    }
