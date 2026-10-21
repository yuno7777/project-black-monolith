"""The backend's deadlines: a cold model is not a dead backend, but a stalled
stream still is.

The reasoning layer proxies a local model. When that model is not resident,
the server has to load it from disk and prefill the prompt before it emits
anything, and on a two-core machine that takes longer than one inter-token
gap. A single read timeout cannot tell "the model is still loading" from
"the server has stopped answering", so the two are budgeted separately here:
generously for the first byte, tightly for every byte after it.

The stub is a real local HTTP server rather than a mock transport. The
deadlines under test are enforced by the HTTP stack, and a mock transport
never enforces one — a test built on a mock would pass whatever the
transport-level timeout was set to.
"""

import asyncio
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import httpx
import pytest
from src import stream_proxy
from src.stream_proxy import (
    OLLAMA_FIRST_BYTE_TIMEOUT_SECONDS,
    OLLAMA_READ_TIMEOUT_SECONDS,
    _backend_timeout,
    _ollama_stream,
    _openai_stream,
)

NDJSON_BODY = b'{"response":"safe answer","done":false}\n{"done":true}\n'
SSE_BODY = b'data: {"choices":[{"delta":{"content":"late"}}]}\n\ndata: [DONE]\n\n'


class _Handler(BaseHTTPRequestHandler):
    """Answers a POST with a body, on a schedule the test sets."""

    protocol_version = "HTTP/1.1"

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        plan = self.server.plan
        try:
            if plan.get("silent"):
                # Accept the connection and then say nothing at all.
                time.sleep(plan["silent"])
                return
            body = plan["body"]
            self.send_response(200)
            self.send_header("Content-Type", plan.get("content_type", "application/x-ndjson"))
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            if plan.get("first_delay"):
                # The model is still loading: the headers are out, the
                # first token is not.
                time.sleep(plan["first_delay"])
            if plan.get("gap_delay") and len(body) > 1:
                self.wfile.write(body[:1])
                self.wfile.flush()
                time.sleep(plan["gap_delay"])
                self.wfile.write(body[1:])
            else:
                self.wfile.write(body)
            self.wfile.flush()
        except OSError:
            # The client gave up and closed the connection. That is the
            # behaviour under test, not a failure of the stub.
            pass

    def log_message(self, *_args):
        pass


class _Stub:
    """A local HTTP server that hands its body over on a schedule."""

    def __init__(self, **plan):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.server.plan = plan
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_exc):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def _config(port: int) -> SimpleNamespace:
    return SimpleNamespace(
        ollama_base_url=f"http://127.0.0.1:{port}",
        ollama_model="test-model",
    )


def _collect_ollama(port: int) -> list[str]:
    async def collect():
        return [token async for token in _ollama_stream("prompt", 4, _config(port))]

    return asyncio.run(collect())


def _collect_openai(port: int) -> list[str]:
    async def collect():
        return [token async for token in _openai_stream("prompt", 4, _config(port))]

    return asyncio.run(collect())


def test_the_first_byte_budget_is_the_generous_one():
    assert OLLAMA_FIRST_BYTE_TIMEOUT_SECONDS > OLLAMA_READ_TIMEOUT_SECONDS
    assert OLLAMA_FIRST_BYTE_TIMEOUT_SECONDS > 0
    assert OLLAMA_READ_TIMEOUT_SECONDS > 0


def test_the_transport_read_budget_is_the_first_byte_one():
    # The transport-level read budget also bounds the wait for the response
    # headers, so it has to be the generous one: a server that accepts the
    # connection and then takes a long time to answer is not dead.
    assert _backend_timeout().read == OLLAMA_FIRST_BYTE_TIMEOUT_SECONDS


def test_an_ordinary_stream_still_arrives():
    with _Stub(body=NDJSON_BODY) as stub:
        assert _collect_ollama(stub.port) == ["safe answer"]


def test_a_cold_model_is_not_mistaken_for_a_dead_backend(monkeypatch):
    monkeypatch.setattr(stream_proxy, "OLLAMA_FIRST_BYTE_TIMEOUT_SECONDS", 2.0)
    monkeypatch.setattr(stream_proxy, "OLLAMA_READ_TIMEOUT_SECONDS", 0.2)

    # The headers arrive at once; the first token takes longer than the
    # inter-token gap, because the model is still being loaded.
    with _Stub(body=NDJSON_BODY, first_delay=0.6) as stub:
        assert _collect_ollama(stub.port) == ["safe answer"]


def test_the_openai_compatible_path_also_tolerates_a_cold_model(monkeypatch):
    monkeypatch.setattr(stream_proxy, "OLLAMA_FIRST_BYTE_TIMEOUT_SECONDS", 2.0)
    monkeypatch.setattr(stream_proxy, "OLLAMA_READ_TIMEOUT_SECONDS", 0.2)

    with _Stub(body=SSE_BODY, first_delay=0.6, content_type="text/event-stream") as stub:
        assert _collect_openai(stub.port) == ["late"]


def test_a_stalled_stream_is_still_caught_quickly(monkeypatch):
    monkeypatch.setattr(stream_proxy, "OLLAMA_FIRST_BYTE_TIMEOUT_SECONDS", 30.0)
    monkeypatch.setattr(stream_proxy, "OLLAMA_READ_TIMEOUT_SECONDS", 0.2)

    started = time.monotonic()
    with (
        _Stub(body=NDJSON_BODY, gap_delay=5.0) as stub,
        pytest.raises(httpx.ReadTimeout),
    ):
        _collect_ollama(stub.port)
    # The first byte arrived promptly; the stream then stopped. That is
    # caught on the inter-token budget, not on the generous first-byte one.
    assert time.monotonic() - started < 3.0


def test_a_server_that_never_answers_is_bounded(monkeypatch):
    monkeypatch.setattr(stream_proxy, "OLLAMA_FIRST_BYTE_TIMEOUT_SECONDS", 0.5)
    monkeypatch.setattr(stream_proxy, "OLLAMA_READ_TIMEOUT_SECONDS", 0.2)

    started = time.monotonic()
    with _Stub(silent=2.0) as stub, pytest.raises(httpx.ReadTimeout):
        _collect_ollama(stub.port)
    # The wait for the response headers is bounded rather than endless.
    assert time.monotonic() - started < 3.0
