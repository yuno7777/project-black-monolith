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

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "fixtures"))

import fake_anthropic_server  # noqa: E402
from src import main  # noqa: E402
from src.anthropic_gateway import (  # noqa: E402
    AnthropicRelay,
    build_upstream_request,
    collect_message,
)
from src.divergence_monitor import build_distribution  # noqa: E402
from src.events import revoked_session_registry  # noqa: E402
from src.main import _read_capped_body, app  # noqa: E402
from src.stream_proxy import (  # noqa: E402
    DIVERGENT_TOKENS,
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


async def _run_relay_with_auditor(frames, relay):
    """Drive a relay the test built itself, so it can configure the audit."""
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
    # The block's text must arrive between the block's start and its stop.
    # The whole sequence is pinned, because the ordering is the invariant:
    # a client that receives a block's text after the block was closed
    # assembles an empty answer, and an assertion that only compares kinds
    # cannot tell the two orders apart.
    assert [
        event["event"] if event["kind"] == "passthrough" else "text" for event in events
    ] == [
        "message_start",
        "content_block_start",
        "text",
        "text",
        "content_block_stop",
        "message_delta",
        "message_stop",
    ]


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


def test_the_relay_audits_the_passage_a_citation_quotes():
    """A citation carries model-authored text, and it reaches the client.

    The audited delta kinds are the ones whose payload is a string field. A
    citation's payload is a nested object — the quoted passage sits inside
    a `citation` object, beside the document title and the offsets — so it
    was relayed verbatim: the one place in the answer path where text the
    model produced was never scanned.
    """
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
                    "type": "citations_delta",
                    "citation": {
                        "type": "char_location",
                        "document_title": "notes.md",
                        "document_index": 0,
                        "start_char_index": 10,
                        "end_char_index": 60,
                        "cited_text": f"the key is {FICTIONAL_AWS_KEY} and that is all",
                    },
                },
            },
        ),
        ("content_block_stop", {"type": "content_block_stop", "index": 0}),
        ("message_stop", {"type": "message_stop"}),
    )
    emitted: list[tuple] = []

    async def run():
        cfg = _cfg(_tmp_path())
        counts = build_distribution(NORMAL_TOKENS * 5)
        auditor = StreamAuditor(
            cfg,
            counts,
            lambda event_type, severity, details, ctx=None, **kwargs: emitted.append(
                (event_type, severity, details)
            ),
        )
        relay = AnthropicRelay(auditor, None, divergence_enabled=False)
        return [event async for event in relay.run(frames)]

    events = asyncio.run(run())
    citations = [
        event["data"]["delta"]["citation"]
        for event in events
        if event["kind"] == "passthrough"
        and event["data"].get("type") == "content_block_delta"
    ]
    assert len(citations) == 1
    assert FICTIONAL_AWS_KEY not in citations[0]["cited_text"]
    assert "[REDACTED:aws_access_key_id]" in citations[0]["cited_text"]
    # The rest of the citation is untouched: the client still knows what was
    # cited and where.
    assert citations[0]["document_title"] == "notes.md"
    assert citations[0]["start_char_index"] == 10
    assert citations[0]["end_char_index"] == 60
    # And the redaction is in the ledger, like every other one.
    assert "pii_redacted" in [event_type for event_type, _severity, _details in emitted]
    redaction = next(
        details for event_type, _severity, details in emitted if event_type == "pii_redacted"
    )
    assert redaction["label"] == "aws_access_key_id"


def test_a_citation_with_nothing_to_audit_is_relayed_unchanged():
    """A citation is not a credential, and must not be mangled into one."""
    frames = _frames(
        (
            "content_block_delta",
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {
                    "type": "citations_delta",
                    "citation": {
                        "type": "char_location",
                        "document_title": "notes.md",
                        "cited_text": "an ordinary quoted passage",
                    },
                },
            },
        ),
        ("message_stop", {"type": "message_stop"}),
    )

    events = asyncio.run(_run_relay(frames))
    citations = [
        event["data"]["delta"]["citation"]
        for event in events
        if event["kind"] == "passthrough"
        and event["data"].get("type") == "content_block_delta"
    ]
    assert len(citations) == 1
    assert citations[0]["cited_text"] == "an ordinary quoted passage"


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
            headers={"x-api-key": "client-key"},
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
                headers={
                    "x-api-key": "client-key",
                    "X-Monolith-Session-Id": "gateway-revoked-session",
                },
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


def test_a_revoked_session_gets_a_document_when_the_client_asked_for_one(tmp_path):
    """A client that asked for one JSON document must not get an event stream.

    An event stream is not a document: a client that cannot parse the body
    reads it as a transport failure and retries, which is the wrong reaction
    to a session the circuit breaker has already revoked.
    """
    with _Stub("clean") as stub:
        _setup(tmp_path, anthropic_base_url=f"http://127.0.0.1:{stub.port}")
        revoked_session_registry().replace(["gateway-revoked-document"])
        try:
            client = TestClient(app, raise_server_exceptions=True)
            response = client.post(
                "/v1/messages",
                headers={
                    "x-api-key": "client-key",
                    "X-Monolith-Session-Id": "gateway-revoked-document",
                },
                json={
                    "model": "stub-model",
                    "max_tokens": 1024,
                    "messages": [{"role": "user", "content": "hello"}],
                    "stream": False,
                },
            )
        finally:
            revoked_session_registry().replace([])

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    body = response.json()
    assert body["type"] == "message"
    assert body["role"] == "assistant"
    assert body["stop_reason"] == "refusal"
    assert body["content"][0]["type"] == "text"
    assert body["content"][0]["text"] == SAFE_REFUSAL


def test_a_baseline_from_another_model_disables_divergence(tmp_path):
    with _Stub("clean") as stub:
        _setup(tmp_path, anthropic_base_url=f"http://127.0.0.1:{stub.port}")
        app.state.baseline_model = "some-other-model"
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
            headers={"x-api-key": "client-key"},
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


def test_a_request_with_no_credential_is_refused(tmp_path):
    """The gateway holds no key of its own, so a request that carries no
    credential would leave it unauthenticated. It is rejected here rather
    than sent."""
    with _Stub("clean") as stub:
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

    assert response.status_code == 401
    assert "credential" in response.json()["detail"]


def test_the_operator_fallback_credential_is_used_when_the_client_has_none(tmp_path):
    # The stub records the last credential it saw, and it is a class
    # attribute: a value left over from an earlier test would satisfy the
    # assertion below without this request ever reaching the upstream.
    fake_anthropic_server.Handler.last_api_key = None
    with _Stub("clean") as stub:
        _setup(
            tmp_path,
            anthropic_base_url=f"http://127.0.0.1:{stub.port}",
            anthropic_api_key="operator-fallback-key",
        )
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
    # The status code alone proves nothing: the request would succeed with
    # no credential at all if the upstream did not check. The key the
    # upstream actually received is the assertion.
    assert fake_anthropic_server.Handler.last_api_key == "operator-fallback-key"


def test_a_tool_call_reaches_the_client_with_its_arguments_intact(tmp_path):
    """A tool_use block's arguments have to arrive as input_json_delta.

    An audited delta is re-framed for the client, and if the re-framing
    loses the kind the arguments arrive as prose: the client assembles a
    tool call with no input and calls the tool with nothing.
    """
    with _Stub("tool") as stub:
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
    deltas = [p for p in payloads if p["type"] == "content_block_delta"]
    tool_deltas = [p for p in deltas if p["index"] == 1]
    assert tool_deltas, "the stub's tool block produced no delta"
    for delta in tool_deltas:
        assert delta["delta"]["type"] == "input_json_delta"
        assert "partial_json" in delta["delta"]
    assert "".join(d["delta"]["partial_json"] for d in tool_deltas) == '{"path": "README.md"}'


def test_a_truncated_upstream_answer_is_not_handed_over_as_a_complete_one(tmp_path):
    """An upstream that stops mid-answer leaves a stream with no message_stop.

    Returning that partial answer with a 200 would tell the agent it has a
    complete answer, which it would then act on.
    """

    class Truncated(fake_anthropic_server.Handler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("content-length") or 0))
            self.send_response(200)
            self.send_header("content-type", "text/event-stream")
            self.end_headers()
            frame = (
                'event: message_start\ndata: {"type":"message_start","message":'
                '{"id":"msg_x","type":"message","role":"assistant","content":[],'
                '"model":"stub-model","stop_reason":null,"usage":{}}}\n\n'
                'event: content_block_start\ndata: {"type":"content_block_start",'
                '"index":0,"content_block":{"type":"text","text":""}}\n\n'
                'event: content_block_delta\ndata: {"type":"content_block_delta",'
                '"index":0,"delta":{"type":"text_delta","text":"the answer is 42"}}\n\n'
            )
            self.wfile.write(frame.encode("utf-8"))
            self.wfile.flush()
            self.close_connection = True

    server = ThreadingHTTPServer(("127.0.0.1", 0), Truncated)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        _, events = _setup(tmp_path, anthropic_base_url=f"http://127.0.0.1:{port}")
        client = TestClient(app, raise_server_exceptions=True)
        response = client.post(
            "/v1/messages",
            headers={"x-api-key": "client-key"},
            json={
                "model": "stub-model",
                "max_tokens": 1024,
                "messages": [{"role": "user", "content": "hello"}],
                "stream": False,
            },
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert response.status_code == 502
    assert "complete" in response.json()["detail"]
    # The ledger has to say what happened. The auditor emits
    # generation_completed when a stream ends cleanly, so without a row for
    # the truncation this run reads as a completed one — and the session
    # report shows nothing at all for an answer the client never received.
    assert "generation_truncated" in [event[0] for event in events]


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


def test_an_upstream_error_is_redacted_before_it_reaches_the_client(tmp_path):
    """The success path is audited; the error path was not.

    An upstream error body is upstream-controlled text, and it reached the
    client verbatim. A provider that echoes a key back in its error message
    would have handed that key to the agent, through the one path where the
    auditor was not watching.
    """

    class ErrorBody(fake_anthropic_server.Handler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("content-length") or 0))
            payload = json.dumps(
                {
                    "type": "error",
                    "error": {
                        "type": "invalid_request_error",
                        "message": f"the key {FICTIONAL_AWS_KEY} is not valid",
                    },
                }
            ).encode("utf-8")
            self.send_response(400)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    server = ThreadingHTTPServer(("127.0.0.1", 0), ErrorBody)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        _, events = _setup(tmp_path, anthropic_base_url=f"http://127.0.0.1:{port}")
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
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    # The upstream's own error is still relayed: the reason for the refusal
    # must not be replaced with an invented one.
    assert response.status_code == 400
    assert "invalid_request_error" in response.text
    assert FICTIONAL_AWS_KEY not in response.text
    assert "[REDACTED:aws_access_key_id]" in response.text
    # And the ledger says so, exactly as it does for the success path.
    assert "pii_redacted" in [event[0] for event in events]


def test_an_oversized_body_is_refused(tmp_path, monkeypatch):
    """A body over the cap is refused, and refused while it is being read."""
    with _Stub("clean") as stub:
        _setup(tmp_path, anthropic_base_url=f"http://127.0.0.1:{stub.port}")
        monkeypatch.setattr(main, "MAX_MESSAGES_BODY_BYTES", 128)
        client = TestClient(app, raise_server_exceptions=True)
        response = client.post(
            "/v1/messages",
            headers={"x-api-key": "client-key"},
            json={
                "model": "stub-model",
                "max_tokens": 1024,
                "messages": [{"role": "user", "content": "x" * 4096}],
                "stream": True,
            },
        )

    assert response.status_code == 413
    assert "too large" in response.json()["detail"]


class _CountingRequest:
    """A request whose body arrives in chunks, counting what was read."""

    def __init__(self, chunks):
        self._chunks = chunks
        self.consumed = 0

    async def stream(self):
        for chunk in self._chunks:
            self.consumed += len(chunk)
            yield chunk


def test_the_body_is_refused_before_the_whole_body_is_read():
    """The cap has to hold while the body arrives, not after it has landed.

    ``request.body()`` buffers every chunk with no ceiling of its own, so a
    size check afterwards measures a body that is already in memory and
    protects nothing: one oversized request still takes the whole allocation.
    """
    chunk = b"x" * 1024
    chunks = [chunk] * 8192  # 8 MiB
    request = _CountingRequest(chunks)

    with pytest.raises(HTTPException) as caught:
        asyncio.run(_read_capped_body(request, 4096))

    assert caught.value.status_code == 413
    # The reader stopped well short of the whole body.
    assert request.consumed < len(chunk) * len(chunks)
    # And it kept nothing.
    assert caught.value.detail == "request body is too large"


def _relay_and_events(frames, *, divergence_enabled=False, **kwargs):
    """Run the relay and hand back the relay itself, so a test can ask it
    for the refusal it would frame a terminated answer with."""

    async def run():
        cfg = _cfg(_tmp_path())
        counts = build_distribution(NORMAL_TOKENS * 5)
        auditor = StreamAuditor(cfg, counts, lambda *_a, **_k: None)
        relay = AnthropicRelay(
            auditor, None, divergence_enabled=divergence_enabled, **kwargs
        )
        return relay, [event async for event in relay.run(frames)]

    return asyncio.run(run())


def _block_start(index: int) -> tuple[str, dict]:
    return (
        "content_block_start",
        {
            "type": "content_block_start",
            "index": index,
            "content_block": {"type": "text", "text": ""},
        },
    )


def _block_delta(index: int, text: str) -> tuple[str, dict]:
    return (
        "content_block_delta",
        {
            "type": "content_block_delta",
            "index": index,
            "delta": {"type": "text_delta", "text": text},
        },
    )


def _refusal_starts(refusal):
    return [
        event["data"]["index"]
        for event in refusal
        if event["kind"] == "passthrough" and event["event"] == "content_block_start"
    ]


def test_a_truncated_stream_does_not_reopen_a_block_the_client_already_saw_closed():
    """A stream that ends without message_stop is a truncated answer.

    The refusal that says so has to be a well-formed message: it must not
    announce a second content block under an index the client has already
    been given and closed. A client that tracks blocks by index reads the
    second start as the beginning of an answer that is already finished.
    """
    frames = _frames(
        ("message_start", {"type": "message_start", "message": {"id": "msg_1"}}),
        _block_start(0),
        _block_delta(0, "the answer is 42"),
        ("content_block_stop", {"type": "content_block_stop", "index": 0}),
        # The upstream died here: no message_stop.
    )

    relay, events = _relay_and_events(frames)

    terminated = [event for event in events if event["kind"] == "terminated"]
    assert terminated and terminated[0]["reason"] == "upstream_stream_error"

    # The client was given block 0, and it was closed.
    delivered = [event["event"] for event in events if event["kind"] == "passthrough"]
    assert "content_block_start" in delivered
    assert "content_block_stop" in delivered

    refusal = relay.refusal_events("upstream_stream_error")
    assert _refusal_starts(refusal) == [1]
    # And the refusal text arrives in that new block.
    assert [event["index"] for event in refusal if event["kind"] == "text"] == [1]


def test_a_refusal_for_an_open_block_does_not_announce_it_twice():
    """The block was announced upstream and the client saw the announcement.

    A refusal that writes into that block must not announce it again: the
    client would be told the same block starts twice, and the second start
    is a malformed stream that a client reads as a transport failure.
    """
    frames = _frames(
        _block_start(0),
        _block_delta(0, "the answer is"),
        # The upstream died mid-block: no stop, no message_stop.
    )

    relay, events = _relay_and_events(frames)

    delivered = [event["event"] for event in events if event["kind"] == "passthrough"]
    assert delivered.count("content_block_start") == 1

    refusal = relay.refusal_events("upstream_stream_error")
    assert _refusal_starts(refusal) == []
    # The refusal text goes into the block that is still open.
    assert [event["index"] for event in refusal if event["kind"] == "text"] == [0]
    # And the block is closed for the client.
    stops = [
        event["data"]["index"]
        for event in refusal
        if event["kind"] == "passthrough" and event["event"] == "content_block_stop"
    ]
    assert stops == [0]


def test_the_divergence_notice_cannot_be_flooded(tmp_path):
    """The requested model is client-controlled.

    A caller that names a fresh model on every request would otherwise
    write a ledger row per request, because the notice is keyed by the
    model it is about. The registry that keeps the notices to one per
    model is bounded, and past the bound the notice stops: the first few
    hundred already say what it says.
    """
    _cfg_out, events = _setup(tmp_path)
    main._DIVERGENCE_NOTICES.clear()
    try:
        for index in range(main.MAX_DIVERGENCE_NOTICES + 5):
            main._divergence_notice_once(
                "baseline-model", f"model-{index}", "model-mismatch"
            )
        notices = [event for event in events if event[0] == "divergence_disabled"]
        assert len(notices) == main.MAX_DIVERGENCE_NOTICES
    finally:
        main._DIVERGENCE_NOTICES.clear()


def test_an_auditor_failure_drains_the_queue_before_the_refusal():
    """A stream that breaks mid-answer still has to start properly.

    The error path did not release the queued events, so the client's
    stream began with the refusal's content_block_start and no
    message_start before it. A client that tracks the message envelope
    reads that as a malformed stream, and a malformed stream is a transport
    failure the agent retries — which is the wrong reaction to an upstream
    that has already broken.
    """

    class _FailingAuditor:
        """An auditor whose read of the upstream fails part-way through."""

        async def audit_tokens(
            self,
            source,
            ctx,
            divergence_enabled=False,
            emit_sync=False,
            literals=(),
            reported_secrets=None,
        ):
            async for _ in source:
                pass
            yield {"type": "error", "error": "upstream_stream_error"}

    frames = _frames(
        ("message_start", {"type": "message_start", "message": {"id": "msg_1"}}),
        _block_start(0),
        _block_delta(0, "the answer is 42"),
        ("content_block_stop", {"type": "content_block_stop", "index": 0}),
    )

    async def run():
        relay = AnthropicRelay(_FailingAuditor(), None, divergence_enabled=False)
        return relay, [event async for event in relay.run(frames)]

    relay, events = asyncio.run(run())

    # The events the upstream queued before it broke reach the client.
    delivered = [event["event"] for event in events if event["kind"] == "passthrough"]
    assert "message_start" in delivered
    assert "content_block_start" in delivered
    assert "content_block_stop" in delivered
    # And the refusal follows them.
    terminated = [event for event in events if event["kind"] == "terminated"]
    assert terminated and terminated[0]["reason"] == "upstream_stream_error"
    # The refusal opens a fresh block: the client already saw block 0
    # closed, and re-opening it would be a malformed stream.
    assert _refusal_starts(relay.refusal_events("upstream_stream_error")) == [1]


def _client_stream(relay, events):
    """The events a client actually receives, in order.

    The relay's own events, minus the marker that says "a refusal follows",
    plus the refusal the relay frames. This is the stream the client sees.
    """
    stream = [event for event in events if event.get("kind") != "terminated"]
    terminated = [event for event in events if event.get("kind") == "terminated"]
    if terminated:
        stream += relay.refusal_events(terminated[0].get("reason", "terminated"))
    return stream


def _block_lifecycle(stream):
    """The blocks a client was told about, and whether each one was closed."""
    opened: list[int] = []
    closed: list[int] = []
    for event in stream:
        if event.get("kind") != "passthrough":
            continue
        data = event.get("data", {})
        if data.get("type") == "content_block_start":
            opened.append(data["index"])
        elif data.get("type") == "content_block_stop":
            closed.append(data["index"])
    return opened, closed


def test_the_divergence_refusal_closes_every_block_it_announced():
    """A refused answer still has to be a well-formed message.

    The divergence fires in the middle of an answer, so the block that was
    open when it fired is open on the client — and its stop event is sitting
    in the relay's queue, waiting for the text before it to be released. The
    terminated path did not release the queue, so the stop never reached the
    client: the client was left holding a block it never saw the end of, and
    the refusal opened a second block for an answer it could not assemble.

    The gate is armed here for the first time: a baseline of ordinary
    reasoning tokens, and a stream that leaves that distribution.
    """
    frames = _frames(
        ("message_start", {"type": "message_start", "message": {"id": "msg_1"}}),
        _block_start(0),
        *[_block_delta(0, token) for token in NORMAL_TOKENS[:15]],
        ("content_block_stop", {"type": "content_block_stop", "index": 0}),
        _block_start(1),
        *[_block_delta(1, token) for token in DIVERGENT_TOKENS[:12]],
        ("content_block_stop", {"type": "content_block_stop", "index": 1}),
        ("message_stop", {"type": "message_stop"}),
    )

    relay, events = _relay_and_events(frames, divergence_enabled=True)

    terminated = [event for event in events if event["kind"] == "terminated"]
    assert terminated, "the divergence did not fire"
    assert terminated[0]["reason"] == "reasoning_divergence"

    stream = _client_stream(relay, events)
    opened, closed = _block_lifecycle(stream)
    assert opened, "the client was given no content block at all"
    # Every block the client was told about is closed. A block that is
    # opened and never closed is a malformed stream, and a malformed stream
    # is a transport failure the agent retries.
    assert closed == opened

    # And the text of a block arrives before that block's stop: a client
    # that assembles an answer from the events cannot lose the text of a
    # block it was told was closed.
    closed_at: dict[int, int] = {}
    for position, event in enumerate(stream):
        if event.get("kind") == "passthrough" and event["data"].get("type") == "content_block_stop":
            closed_at[event["data"]["index"]] = position
    for position, event in enumerate(stream):
        if event.get("kind") != "text":
            continue
        index = event["index"]
        if index in closed_at:
            assert position < closed_at[index], (
                f"the text of block {index} arrived after its stop"
            )


def test_a_truncated_stream_is_recorded_in_the_ledger(tmp_path):
    """A stream that ends mid-answer has to be in the ledger.

    The auditor emits generation_completed when a stream ends cleanly, so
    without a row for the truncation the run reads as a completed one --
    and the session report shows nothing for an answer the client never
    received.
    """

    class Truncated(fake_anthropic_server.Handler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("content-length") or 0))
            self.send_response(200)
            self.send_header("content-type", "text/event-stream")
            self.end_headers()
            frame = (
                'event: message_start\ndata: {"type":"message_start","message":'
                '{"id":"msg_x","type":"message","role":"assistant","content":[],'
                '"model":"stub-model","stop_reason":null,"usage":{}}}\n\n'
                'event: content_block_start\ndata: {"type":"content_block_start",'
                '"index":0,"content_block":{"type":"text","text":""}}\n\n'
                'event: content_block_delta\ndata: {"type":"content_block_delta",'
                '"index":0,"delta":{"type":"text_delta","text":"the answer is 42"}}\n\n'
            )
            self.wfile.write(frame.encode("utf-8"))
            self.wfile.flush()
            self.close_connection = True

    server = ThreadingHTTPServer(("127.0.0.1", 0), Truncated)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        _, events = _setup(tmp_path, anthropic_base_url=f"http://127.0.0.1:{port}")
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
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert response.status_code == 200
    # The client is told the answer was cut short.
    assert "ended before the answer was complete" in response.text
    # And the ledger says so, with the outcome that says what it did to the
    # agent: the answer was terminated, not delivered.
    types = [event[0] for event in events]
    assert "generation_truncated" in types
    truncated = next(event for event in events if event[0] == "generation_truncated")
    assert truncated[1] == "warning"
    assert truncated[4]["outcome"] == "terminated"


def test_the_operators_fallback_key_is_not_relayed_to_the_client(tmp_path):
    """The gateway's own key must never reach a client that never had it.

    The scanner finds the shapes it was written for, and the openai-style
    pattern stops at the first hyphen — which an Anthropic key has
    several of. A pattern-only pass therefore let the operator's fallback
    key straight through to the client, in the one path the auditor was
    not watching.
    """
    operator_key = "sk-ant-api03-operator-fallback-key-0123456789"

    class EchoKey(fake_anthropic_server.Handler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("content-length") or 0))
            payload = json.dumps(
                {
                    "type": "error",
                    "error": {
                        "type": "authentication_error",
                        "message": f"the key {operator_key} was rejected",
                    },
                }
            ).encode("utf-8")
            self.send_response(401)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    server = ThreadingHTTPServer(("127.0.0.1", 0), EchoKey)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        _, events = _setup(
            tmp_path,
            anthropic_base_url=f"http://127.0.0.1:{port}",
            anthropic_api_key=operator_key,
        )
        client = TestClient(app, raise_server_exceptions=True)
        # The client sends no credential of its own, so the gateway uses
        # the operator's fallback — the key the client never had.
        response = client.post(
            "/v1/messages",
            json={
                "model": "stub-model",
                "max_tokens": 1024,
                "messages": [{"role": "user", "content": "hello"}],
                "stream": True,
            },
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    # The upstream's own error is still relayed: the reason for the refusal
    # must not be replaced with an invented one.
    assert response.status_code == 401
    assert "authentication_error" in response.text
    # But the key is not.
    assert operator_key not in response.text
    assert "[REDACTED:anthropic_api_key]" in response.text
    # And the ledger records the redaction.
    labels = [event[2].get("label") for event in events if event[0] == "pii_redacted"]
    assert "anthropic_api_key" in labels


def test_a_base_url_that_already_ends_in_v1_is_not_doubled(tmp_path):
    """An operator who configures the versioned root gets a working call.

    Appending the path blindly asks for /v1/v1/messages, and every audited
    call 404s — which looks exactly like the gateway being broken.
    """
    for configured, expected in (
        ("https://api.anthropic.com", "https://api.anthropic.com/v1/messages"),
        ("https://api.anthropic.com/v1", "https://api.anthropic.com/v1/messages"),
        ("https://api.anthropic.com/v1/", "https://api.anthropic.com/v1/messages"),
        (
            "https://api.anthropic.com/v1/messages",
            "https://api.anthropic.com/v1/messages",
        ),
    ):
        cfg = _cfg(tmp_path, anthropic_base_url=configured)
        url, _headers, _payload = build_upstream_request(
            b"{}", cfg, {"x-api-key": "client-key"}
        )
        assert url == expected, configured


# --- a credential that comes back inside a normal answer ------------------


# An Anthropic key is hyphenated, and the openai-style pattern stops at the
# first hyphen, so no pattern in the scanner can match this shape. Only
# knowing the exact credential finds it.
OPERATOR_KEY = "sk-ant-api03-operator-fallback-key-0123456789"


def test_the_relay_redacts_the_operator_key_echoed_in_an_answer():
    """The operator's own key must not reach the client through the answer.

    The error path already redacted it. The success path did not, and the
    pattern scanner cannot catch a hyphenated Anthropic key, so a normal
    200 answer that happened to contain the operator's fallback key handed
    that key to a client that never had it.
    """
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
                    "text": f"the key is {OPERATOR_KEY} and that is all",
                },
            },
        ),
        ("content_block_stop", {"type": "content_block_stop", "index": 0}),
        ("message_stop", {"type": "message_stop"}),
    )

    cfg = _cfg(_tmp_path(), anthropic_api_key=OPERATOR_KEY)
    counts = build_distribution(NORMAL_TOKENS * 5)
    auditor = StreamAuditor(cfg, counts, lambda *_a, **_k: None)
    relay = AnthropicRelay(auditor, None, divergence_enabled=False)
    events = asyncio.run(_run_relay_with_auditor(frames, relay))

    text = "".join(event["text"] for event in events if event["kind"] == "text")
    assert OPERATOR_KEY not in text
    assert "[REDACTED:anthropic_api_key]" in text
    assert text.endswith("and that is all")


def test_the_relay_redacts_the_clients_own_key_echoed_in_an_answer():
    """A client's own credential is redacted when the upstream repeats it."""
    client_key = "sk-ant-api03-client-supplied-key-9876543210"
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
                    "text": f"I have {client_key} on file",
                },
            },
        ),
        ("content_block_stop", {"type": "content_block_stop", "index": 0}),
        ("message_stop", {"type": "message_stop"}),
    )

    cfg = _cfg(_tmp_path())
    counts = build_distribution(NORMAL_TOKENS * 5)
    auditor = StreamAuditor(cfg, counts, lambda *_a, **_k: None)
    relay = AnthropicRelay(
        auditor, None, divergence_enabled=False, literals=(client_key,)
    )
    events = asyncio.run(_run_relay_with_auditor(frames, relay))

    text = "".join(event["text"] for event in events if event["kind"] == "text")
    assert client_key not in text
    assert "[REDACTED:anthropic_api_key]" in text


def test_a_credential_split_across_fragments_is_still_caught():
    """The literal is matched on the whole buffer, not on one fragment.

    The upstream splits its answer into word-sized fragments, so a key
    lands across two of them. The look-behind that catches a pattern split
    across fragments has to catch a literal split the same way.
    """
    client_key = "sk-ant-api03-client-supplied-key-9876543210"
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
                "delta": {"type": "text_delta", "text": "the key is sk-ant-api03-"},
            },
        ),
        (
            "content_block_delta",
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": "client-supplied-key-9876543210 ok"},
            },
        ),
        ("content_block_stop", {"type": "content_block_stop", "index": 0}),
        ("message_stop", {"type": "message_stop"}),
    )

    cfg = _cfg(_tmp_path())
    counts = build_distribution(NORMAL_TOKENS * 5)
    auditor = StreamAuditor(cfg, counts, lambda *_a, **_k: None)
    relay = AnthropicRelay(
        auditor, None, divergence_enabled=False, literals=(client_key,)
    )
    events = asyncio.run(_run_relay_with_auditor(frames, relay))

    text = "".join(event["text"] for event in events if event["kind"] == "text")
    assert client_key not in text
    assert "[REDACTED:anthropic_api_key]" in text
    assert "ok" in text


def test_the_gateway_redacts_the_operator_key_echoed_in_a_200_answer(tmp_path):
    """End to end: the operator's key never reaches the client.

    The upstream repeats the key back inside a normal answer. The client
    gets a 200, and the answer it gets must not contain the credential the
    gateway held on its behalf.
    """
    fake_anthropic_server.Handler.echo_key = OPERATOR_KEY
    try:
        with _Stub("echo") as stub:
            _setup(
                tmp_path,
                anthropic_base_url=f"http://127.0.0.1:{stub.port}",
                anthropic_api_key=OPERATOR_KEY,
            )
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
    finally:
        fake_anthropic_server.Handler.echo_key = ""

    assert response.status_code == 200
    assert OPERATOR_KEY not in response.text
    assert "[REDACTED:anthropic_api_key]" in response.text
