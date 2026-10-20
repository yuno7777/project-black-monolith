"""The VectorAnchor MCP server: the memory layer's door into an agent.

The server is spawned as a child process and driven over stdio with
line-delimited JSON-RPC, exactly as an MCP client would drive it. A small
fake VectorAnchor service stands in for the real one, so the test needs
neither ChromaDB nor FastAPI.

Run from the module root: python -m pytest tests/
"""

import json
import os
import queue
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

SERVER_PATH = Path(__file__).resolve().parent.parent / "src" / "mcp_server.py"


class _FakeVectorAnchor(BaseHTTPRequestHandler):
    """Answers POST /retrieve with whatever the test told it to answer."""

    payload = {"results": [], "withheld": []}
    status = 200
    received = []
    # When set, these exact bytes are sent instead of the JSON payload.
    raw = None
    # When set, the declared content-length is this much larger than the
    # body actually written, so the client reads a response that stops
    # mid-stream.
    truncate_by = 0

    def do_POST(self):  # noqa: N802 - stdlib signature
        length = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(length) if length else b""
        type(self).received.append(
            {
                "path": self.path,
                "body": json.loads(body.decode("utf-8")) if body else None,
                "headers": {key.lower(): value for key, value in self.headers.items()},
            }
        )
        if type(self).raw is not None:
            payload = type(self).raw
        else:
            payload = json.dumps(type(self).payload).encode("utf-8")
        self.send_response(type(self).status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload) + type(self).truncate_by))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_args):
        return


@pytest.fixture()
def fake_service():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FakeVectorAnchor)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    _FakeVectorAnchor.payload = {"results": [], "withheld": []}
    _FakeVectorAnchor.status = 200
    _FakeVectorAnchor.received = []
    _FakeVectorAnchor.raw = None
    _FakeVectorAnchor.truncate_by = 0
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


class _Client:
    """Drives the MCP server over stdio."""

    def __init__(self, url: str, env_overrides: dict | None = None):
        env = dict(os.environ)
        env["MONOLITH_VECTOR_ANCHOR_URL"] = url
        # Pinned, not defaulted: an ambient value from the host shell would
        # otherwise win and the test would assert on somebody else's session.
        env["MONOLITH_TENANT_ID"] = "tenant-under-test"
        env["MONOLITH_AGENT_ID"] = "agent-under-test"
        env["MONOLITH_SESSION_ID"] = "session-under-test"
        env.update(env_overrides or {})
        self.process = subprocess.Popen(
            [sys.executable, str(SERVER_PATH)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            text=True,
            encoding="utf-8",
            bufsize=1,
        )
        self.messages: "queue.Queue[dict]" = queue.Queue()
        self.stderr: list[str] = []
        threading.Thread(target=self._drain_stdout, daemon=True).start()
        threading.Thread(target=self._drain_stderr, daemon=True).start()

    def _drain_stdout(self):
        assert self.process.stdout is not None
        for line in self.process.stdout:
            line = line.strip()
            if line:
                self.messages.put(json.loads(line))

    def _drain_stderr(self):
        assert self.process.stderr is not None
        for line in self.process.stderr:
            self.stderr.append(line.rstrip())

    def send(self, method: str, params: dict | None = None, request_id=1) -> None:
        payload = {"jsonrpc": "2.0", "method": method}
        if request_id is not None:
            payload["id"] = request_id
        if params is not None:
            payload["params"] = params
        assert self.process.stdin is not None
        self.process.stdin.write(json.dumps(payload) + "\n")
        self.process.stdin.flush()

    def receive(self, timeout: float = 15.0) -> dict:
        return self.messages.get(timeout=timeout)

    def call(self, method: str, params: dict | None = None, request_id=1) -> dict:
        self.send(method, params, request_id)
        return self.receive()

    def close(self) -> None:
        try:
            if self.process.stdin is not None:
                self.process.stdin.close()
        except OSError:
            pass
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)


@pytest.fixture()
def client(fake_service):
    url = f"http://127.0.0.1:{fake_service.server_address[1]}"
    handle = _Client(url)
    try:
        yield handle
    finally:
        handle.close()


def test_the_handshake_advertises_one_retrieve_tool(client):
    response = client.call(
        "initialize",
        {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}},
    )
    result = response["result"]
    assert result["protocolVersion"] == "2025-06-18"
    assert result["serverInfo"]["name"] == "vector-anchor"
    assert "tools" in result["capabilities"]

    # A protocol version the server does not know falls back to the latest
    # version it supports rather than failing the handshake: a client that
    # has dropped the oldest version but would happily have used the
    # newest still connects.
    fallback = client.call("initialize", {"protocolVersion": "1999-01-01"}, request_id=2)
    assert fallback["result"]["protocolVersion"] == "2025-06-18"

    listed = client.call("tools/list", {}, request_id=3)
    tools = listed["result"]["tools"]
    assert [tool["name"] for tool in tools] == ["retrieve"]
    assert tools[0]["inputSchema"]["required"] == ["query"]


def test_a_notification_gets_no_reply(client):
    client.send("notifications/initialized", None, request_id=None)
    # The next request must still be answered, and nothing else may be
    # interleaved on the wire.
    response = client.call("ping", {}, request_id=7)
    assert response["id"] == 7
    assert response["result"] == {}


def test_no_method_answers_a_notification(client):
    """A JSON-RPC notification carries no id, and the server must not reply
    to one: an unsolicited frame on the wire is a response to a request
    that was never made."""
    for method, params in (
        ("initialize", {"protocolVersion": "2025-06-18"}),
        ("ping", {}),
        ("tools/list", {}),
        ("tools/call", {"name": "retrieve", "arguments": {"query": "x"}}),
    ):
        client.send(method, params, request_id=None)

    # The next request is answered, and it is the only thing on the wire:
    # a server that replied to a notification would have put an
    # unsolicited frame ahead of it.
    response = client.call("ping", {}, request_id=11)
    assert response["id"] == 11
    time.sleep(0.2)
    assert client.messages.qsize() == 0


def test_a_call_is_forwarded_to_the_service_with_the_session_stamped_on_it(client, fake_service):
    _FakeVectorAnchor.payload = {
        "results": [{"id": "doc-1", "document": "the deployment guide"}],
        "withheld": [],
    }
    client.call(
        "initialize",
        {"protocolVersion": "2024-11-05"},
        request_id=1,
    )
    response = client.call(
        "tools/call",
        {"name": "retrieve", "arguments": {"query": "how do I deploy", "k": 3}},
        request_id=2,
    )
    assert "error" not in response
    text = response["result"]["content"][0]["text"]
    assert "the deployment guide" in text
    assert "doc-1" in text
    assert response["result"]["isError"] is False

    assert len(_FakeVectorAnchor.received) == 1
    request = _FakeVectorAnchor.received[0]
    assert request["path"] == "/retrieve"
    assert request["body"] == {"query": "how do I deploy", "k": 3}
    # The correlation ids are what make the retrieval attributable to the
    # same session as the tool calls around it.
    assert request["headers"]["x-monolith-session-id"] == "session-under-test"
    assert request["headers"]["x-monolith-agent-id"] == "agent-under-test"
    assert request["headers"]["x-monolith-tenant-id"] == "tenant-under-test"


def test_a_withheld_document_is_reported_to_the_agent(client, fake_service):
    # The agent has to know its context is incomplete. A short answer that
    # looks complete is worse than no answer, because the agent cannot tell
    # the difference.
    _FakeVectorAnchor.payload = {
        "results": [{"id": "doc-2", "document": "a clean passage"}],
        "withheld": [{"id": "doc-bait", "reason": "frequency_anomaly"}],
    }
    response = client.call(
        "tools/call",
        {"name": "retrieve", "arguments": {"query": "anything"}},
        request_id=1,
    )
    text = response["result"]["content"][0]["text"]
    assert "a clean passage" in text
    assert "1 document(s) were withheld" in text
    # The withheld document itself must not be in the answer.
    assert "doc-bait" not in text


def test_a_revoked_session_is_refused_without_retrieving(client, fake_service):
    # The service is the authority on revocations, so it is asked first and
    # answers with the refusal; the server renders it and returns nothing
    # else, so the agent cannot mistake it for an empty result set.
    _FakeVectorAnchor.payload = {"session_quarantined": True}
    response = client.call(
        "tools/call",
        {"name": "retrieve", "arguments": {"query": "anything"}},
        request_id=1,
    )
    text = response["result"]["content"][0]["text"]
    assert "revoked" in text
    assert "No passages matched" not in text
    assert len(_FakeVectorAnchor.received) == 1
    # A refusal has to be an error on the wire. An agent that reads it as a
    # successful retrieval of zero documents has no reason to stop, and its
    # next tool call lands in the same revoked session.
    assert response["result"]["isError"] is True


def test_a_response_that_stops_mid_stream_is_an_error_result_not_a_crash(
    client, fake_service
):
    # The service declares a body it never finishes sending. The client
    # sees http.client.IncompleteRead, which is an HTTPException and *not*
    # an OSError, so a server that only catches OSError lets it escape and
    # dies mid-session, taking the agent's retrieve tool with it.
    _FakeVectorAnchor.raw = b'{"results": [{"text": "half an answer'
    _FakeVectorAnchor.truncate_by = 40
    try:
        response = client.call(
            "tools/call",
            {"name": "retrieve", "arguments": {"query": "anything"}},
            request_id=1,
        )
        assert response["result"]["isError"] is True
        # The server is still alive and still serving the protocol.
        assert client.call("ping", {}, request_id=2)["result"] == {}
    finally:
        _FakeVectorAnchor.raw = None
        _FakeVectorAnchor.truncate_by = 0


def test_a_truncated_error_body_is_an_error_result_not_a_crash(client, fake_service):
    # The service answers 500 and then stops mid-body. urllib raises
    # HTTPError for the status, and reading the error body raises
    # http.client.IncompleteRead — inside the handler that is supposed to
    # catch it. An exception raised inside an `except` block is not caught
    # by the sibling clause, so it escapes the call and kills the server
    # mid-session, taking the agent's retrieve tool with it.
    _FakeVectorAnchor.raw = b'{"error": "the service is unwell"'
    _FakeVectorAnchor.truncate_by = 40
    _FakeVectorAnchor.status = 500
    try:
        response = client.call(
            "tools/call",
            {"name": "retrieve", "arguments": {"query": "anything"}},
            request_id=1,
        )
        assert response["result"]["isError"] is True
        assert "HTTP 500" in response["result"]["content"][0]["text"]
        # The server is still alive and still serving the protocol.
        assert client.call("ping", {}, request_id=2)["result"] == {}
    finally:
        _FakeVectorAnchor.raw = None
        _FakeVectorAnchor.truncate_by = 0
        _FakeVectorAnchor.status = 200


def test_a_response_that_is_not_utf8_is_an_error_result_not_a_crash(
    client, fake_service
):
    # Bytes that are not valid UTF-8 are not valid JSON either, but
    # json.loads raises UnicodeDecodeError for them, and json.JSONDecodeError
    # does not catch it.
    _FakeVectorAnchor.raw = b"\x80\x81\x82"
    try:
        response = client.call(
            "tools/call",
            {"name": "retrieve", "arguments": {"query": "anything"}},
            request_id=1,
        )
        assert response["result"]["isError"] is True
        assert "not JSON" in response["result"]["content"][0]["text"]
        assert client.call("ping", {}, request_id=2)["result"] == {}
    finally:
        _FakeVectorAnchor.raw = None


def test_a_malformed_service_url_is_an_error_result_not_a_crash():
    # A typo in MONOLITH_VECTOR_ANCHOR_URL is an operator error, and it is
    # raised while the request is being built — before anything is sent.
    # Unhandled it takes the whole server down for a configuration mistake.
    handle = _Client("not-a-url")
    try:
        response = handle.call(
            "tools/call",
            {"name": "retrieve", "arguments": {"query": "anything"}},
            request_id=1,
        )
        assert response["result"]["isError"] is True
        assert "not usable" in response["result"]["content"][0]["text"]
        # The server is still alive and still serving the protocol.
        assert handle.call("ping", {}, request_id=2)["result"] == {}
    finally:
        handle.close()


def test_a_bad_call_is_reported_to_the_agent_rather_than_crashing(client):
    unknown = client.call(
        "tools/call",
        {"name": "not_a_tool", "arguments": {"query": "x"}},
        request_id=1,
    )
    assert unknown["error"]["code"] == -32602

    empty = client.call(
        "tools/call",
        {"name": "retrieve", "arguments": {"query": "   "}},
        request_id=2,
    )
    assert empty["result"]["isError"] is True
    assert "non-empty" in empty["result"]["content"][0]["text"]


def test_an_unreachable_service_is_an_error_result_not_a_crash():
    # Port 1 is not going to be listening.
    handle = _Client("http://127.0.0.1:1")
    try:
        response = handle.call(
            "tools/call",
            {"name": "retrieve", "arguments": {"query": "anything"}},
            request_id=1,
        )
        assert response["result"]["isError"] is True
        assert "unreachable" in response["result"]["content"][0]["text"]
        # The server is still alive and still serving the protocol.
        assert handle.call("ping", {}, request_id=2)["result"] == {}
    finally:
        handle.close()
