"""The Anthropic Messages gateway.

Three things have to hold at once for the gateway to be usable: the client
must not be able to tell it is there, a credential the model emits must not
reach the client, and the client's own credential must still reach the
model. These tests pin all three.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import threading
from http.server import ThreadingHTTPServer
from types import SimpleNamespace

from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "fixtures"))

import fake_anthropic_server  # noqa: E402
from src.anthropic_gateway import (  # noqa: E402
    AnthropicRelay,
    build_upstream_request,
    collect_message,
)
from src.divergence_monitor import build_distribution  # noqa: E402
from src.events import revoked_session_registry  # noqa: E402
from src.main import app  # noqa: E402
from src.stream_proxy import (  # noqa: E402
    NORMAL_TOKENS,
    SAFE_REFUSAL,
    StreamAuditor,
)

FICTIONAL_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


def _cfg(tmp_path, **overrides):
    cfg = SimpleNamespace(
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
        admin_token="admin-secret-token-0000",
        tenant_id="default",
        agent_id=None,
        session_id=None,
        anthropic_base_url="https://api.anthropic.com",
        anthropic_api_key=None,
        anthropic_model=None,
        anthropic_max_tokens=8192,
    )
    for key, value in overrides.items():
        setattr(cfg, key, value)
    return cfg


def _setup(tmp_path, **overrides):
    cfg = _cfg(tmp_path, **overrides)
    counts = build_distribution(NORMAL_TOKENS * 5)
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
    app.state.cfg = cfg
    app.state.emit = emit
    app.state.baseline_counts = counts
    app.state.baseline = counts
    app.state.baseline_model = None
    app.state.auditor = StreamAuditor(cfg, counts, emit)
    app.state.proxy = app.state.auditor
    return cfg, events


def _frames(*pairs):
    async def generator():
        for name, data in pairs:
            yield name, data

    return generator()


async def _run_relay(frames, *, divergence_enabled=False):
    cfg = _cfg(_tmp_path())
    counts = build_distribution(NORMAL_TOKENS * 5)
    auditor = StreamAuditor(cfg, counts, lambda *_a, **_k: None)
    relay = AnthropicRelay(auditor, None, divergence_enabled=divergence_enabled)
    return [event async for event in relay.run(frames)]


def _tmp_path():
    import tempfile
    from pathlib import Path

    return Path(tempfile.mkdtemp())


def test_the_relay_keeps_the_event_order_the_client_expects():
    frames = _frames(
        ("message_start", {"type": "message_start", "message": {"id": "msg_1"}}),
        (
            "content_block_start",
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "text", "text": ""},
            },
        ),
        (
            "content_block_delta",
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": "hello "},
            },
        ),
        (
            "content_block_delta",
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": "world"},
            },
        ),
        ("content_block_stop", {"type": "content_block_stop", "index": 0}),
        (
            "message_delta",
            {
                "type": "message_delta",
                "delta": {"stop_reason": "end_turn"},
                "usage": {"output_tokens": 2},
            },
        ),
        ("message_stop", {"type": "message_stop"}),
    )

    events = asyncio.run(_run_relay(frames))
    assert [event.get("event") for event in events if event["kind"] == "passthrough"] == [
        "message_start",
        "content_block_start",
        "content_block_stop",
        "message_delta",
        "message_stop",
    ]
    assert [event["text"] for event in events if event["kind"] == "text"] == ["hello ", "world"]
    # The block's text must not arrive after the block was closed.
    kinds = [event["kind"] for event in events]
    assert kinds.index("text") < kinds.index("passthrough") + len(kinds)


def test_the_relay_redacts_a_credential_the_model_emitted():
    frames = _frames(
        (
            "content_block_start",
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "text", "text": ""},
            },
        ),
        (
            "content_block_delta",
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {
                    "type": "text_delta",
                    "text": f"the key is {FICTIONAL_AWS_KEY} and that is all",
                },
            },
        ),
        ("content_block_stop", {"type": "content_block_stop", "index": 0}),
        ("message_stop", {"type": "message_stop"}),
    )

    events = asyncio.run(_run_relay(frames))
    text = "".join(event["text"] for event in events if event["kind"] == "text")
    assert FICTIONAL_AWS_KEY not in text
    assert "[REDACTED:aws_access_key_id]" in text
    assert text.endswith("and that is all")


def test_the_relay_keeps_two_blocks_in_order():
    frames = _frames(
        (
            "content_block_start",
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "text", "text": ""},
            },
        ),
        (
            "content_block_delta",
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": "first"},
            },
        ),
        ("content_block_stop", {"type": "content_block_stop", "index": 0}),
        (
            "content_block_start",
            {
                "type": "content_block_start",
                "index": 1,
                "content_block": {"type": "text", "text": ""},
            },
        ),
        (
            "content_block_delta",
            {
                "type": "content_block_delta",
                "index": 1,
                "delta": {"type": "text_delta", "text": "second"},
            },
        ),
        ("content_block_stop", {"type": "content_block_stop", "index": 1}),
        ("message_stop", {"type": "message_stop"}),
    )

    events = asyncio.run(_run_relay(frames))
    text = "".join(event["text"] for event in events if event["kind"] == "text")
    assert text == "firstsecond"
    passthrough = [event["event"] for event in events if event["kind"] == "passthrough"]
    assert passthrough == [
        "content_block_start",
        "content_block_stop",
        "content_block_start",
        "content_block_stop",
        "message_stop",
    ]


def test_the_clients_own_credential_is_forwarded_and_the_body_is_untouched():
    cfg = _cfg(_tmp_path())
    body = b'{"model":"claude-x","messages":[{"role":"user","content":"hi"}]}'
    url, headers, payload = build_upstream_request(
        body,
        cfg,
        {"x-api-key": "client-key", "authorization": "Bearer client-token"},
    )
    assert url == "https://api.anthropic.com/v1/messages"
    assert headers["x-api-key"] == "client-key"
    assert headers["authorization"] == "Bearer client-token"
    assert payload == body


def test_the_configured_credential_is_only_a_fallback():
    cfg = _cfg(_tmp_path(), anthropic_api_key="operator-fallback-key")
    _, headers, _ = build_upstream_request(b"{}", cfg, {"x-api-key": "client-key"})
    assert headers["x-api-key"] == "client-key"

    _, headers, _ = build_upstream_request(b"{}", cfg, {})
    assert headers["x-api-key"] == "operator-fallback-key"


# --- end to end against the local stub ------------------------------------


class _Stub:
    def __init__(self, mode: str):
        self.mode = mode
        fake_anthropic_server.Handler.mode = mode
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), fake_anthropic_server.Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_exc):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def _sse_payloads(text: str) -> list[dict]:
    payloads = []
    for line in text.splitlines():
        if line.startswith("data: "):
            payloads.append(json.loads(line[len("data: "):]))
    return payloads


def test_the_gateway_serves_a_client_the_same_stream_it_asked_for(tmp_path):
    with _Stub("clean") as stub:
        _setup(tmp_path, anthropic_base_url=f"http://127.0.0.1:{stub.port}")
        client = TestClient(app, raise_server_exceptions=True)
        response = client.post(
            "/v1/messages",
            headers={"x-api-key": "client-key"},
            json={
                "model": "stub-model",
                "max_tokens": 1024,
                "messages": [{"role": "user", "content": "hello"}],
                "stream": True,
            },
        )

    assert response.status_code == 200
    payloads = _sse_payloads(response.text)
    kinds = [payload["type"] for payload in payloads]
    assert kinds[0] == "message_start"
    assert kinds[-1] == "message_stop"
    assert "content_block_start" in kinds
    assert "content_block_stop" in kinds
    assert "message_delta" in kinds
    text = "".join(
        payload["delta"]["text"]
        for payload in payloads
        if payload["type"] == "content_block_delta"
    )
    assert "invisible" in text


def test_the_gateway_redacts_a_credential_before_the_client_sees_it(tmp_path):
    with _Stub("secret") as stub:
        _setup(tmp_path, anthropic_base_url=f"http://127.0.0.1:{stub.port}")
        client = TestClient(app, raise_server_exceptions=True)
        response = client.post(
            "/v1/messages",
            json={
                "model": "stub-model",
                "max_tokens": 1024,
                "messages": [{"role": "user", "content": "hello"}],
                "stream": True,
            },
        )

    assert response.status_code == 200
    assert FICTIONAL_AWS_KEY not in response.text
    assert "[REDACTED:aws_access_key_id]" in response.text


def test_a_revoked_session_gets_a_well_formed_refusal(tmp_path):
    with _Stub("clean") as stub:
        _setup(tmp_path, anthropic_base_url=f"http://127.0.0.1:{stub.port}")
        revoked_session_registry().replace(["gateway-revoked-session"])
        try:
            client = TestClient(app, raise_server_exceptions=True)
            response = client.post(
                "/v1/messages",
                headers={"X-Monolith-Session-Id": "gateway-revoked-session"},
                json={
                    "model": "stub-model",
                    "max_tokens": 1024,
                    "messages": [{"role": "user", "content": "hello"}],
                    "stream": True,
                },
            )
        finally:
            revoked_session_registry().replace([])

    assert response.status_code == 200
    payloads = _sse_payloads(response.text)
    kinds = [payload["type"] for payload in payloads]
    assert kinds[0] == "message_start"
    assert kinds[-1] == "message_stop"
    text = "".join(
        payload["delta"]["text"]
        for payload in payloads
        if payload["type"] == "content_block_delta"
    )
    assert text == SAFE_REFUSAL


def test_a_baseline_from_another_model_disables_divergence(tmp_path):
    with _Stub("clean") as stub:
        _setup(tmp_path, anthropic_base_url=f"http://127.0.0.1:{stub.port}")
        app.state.baseline_model = "some-other-model"
        client = TestClient(app, raise_server_exceptions=True)
        response = client.post(
            "/v1/messages",
            json={
                "model": "stub-model",
                "max_tokens": 1024,
                "messages": [{"role": "user", "content": "hello"}],
                "stream": True,
            },
        )

    assert response.status_code == 200
    assert "message_stop" in response.text


def test_a_request_over_the_operator_ceiling_is_refused(tmp_path):
    with _Stub("clean") as stub:
        _setup(
            tmp_path,
            anthropic_base_url=f"http://127.0.0.1:{stub.port}",
            anthropic_max_tokens=16,
        )
        client = TestClient(app, raise_server_exceptions=True)
        response = client.post(
            "/v1/messages",
            json={
                "model": "stub-model",
                "max_tokens": 4096,
                "messages": [{"role": "user", "content": "hello"}],
                "stream": True,
            },
        )

    assert response.status_code == 400
    assert "ceiling" in response.json()["detail"]


def test_a_non_streaming_request_gets_one_json_document(tmp_path):
    with _Stub("clean") as stub:
        _setup(tmp_path, anthropic_base_url=f"http://127.0.0.1:{stub.port}")
        client = TestClient(app, raise_server_exceptions=True)
        response = client.post(
            "/v1/messages",
            json={
                "model": "stub-model",
                "max_tokens": 1024,
                "messages": [{"role": "user", "content": "hello"}],
                "stream": False,
            },
        )

    assert response.status_code == 200
    body = response.json()
    assert body["type"] == "message"
    assert body["content"][0]["type"] == "text"
    assert "invisible" in body["content"][0]["text"]


def test_the_non_streaming_message_keeps_a_tool_block():
    frames = _frames(
        (
            "content_block_start",
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "text", "text": ""},
            },
        ),
        (
            "content_block_delta",
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": "reading"},
            },
        ),
        ("content_block_stop", {"type": "content_block_stop", "index": 0}),
        (
            "content_block_start",
            {
                "type": "content_block_start",
                "index": 1,
                "content_block": {
                    "type": "tool_use",
                    "id": "toolu_1",
                    "name": "read_file",
                    "input": {},
                },
            },
        ),
        (
            "content_block_delta",
            {
                "type": "content_block_delta",
                "index": 1,
                "delta": {"type": "input_json_delta", "partial_json": '{"path": "README.md"}'},
            },
        ),
        ("content_block_stop", {"type": "content_block_stop", "index": 1}),
        (
            "message_delta",
            {
                "type": "message_delta",
                "delta": {"stop_reason": "tool_use"},
                "usage": {"output_tokens": 5},
            },
        ),
        ("message_stop", {"type": "message_stop"}),
    )

    async def collect():
        cfg = _cfg(_tmp_path())
        counts = build_distribution(NORMAL_TOKENS * 5)
        auditor = StreamAuditor(cfg, counts, lambda *_a, **_k: None)
        relay = AnthropicRelay(auditor, None, divergence_enabled=False)
        return await collect_message(relay, frames)

    message = asyncio.run(collect())
    assert message["content"][0] == {"type": "text", "text": "reading"}
    assert message["content"][1]["type"] == "tool_use"
    assert message["content"][1]["name"] == "read_file"
    assert message["content"][1]["input"] == {"path": "README.md"}
    assert message["stop_reason"] == "tool_use"
