"""The revoked-session mirror is fail-closed and refreshable over HTTP.

The cross-layer circuit breaker lives in the dashboard; these tests pin the
module-side contract: an authoritative snapshot replaces the set (including
an empty one), a missing or broken snapshot leaves it alone, and the poller
refreshes it without any event traffic.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from monolith_events.events import (
    RevokedSessionPoller,
    RevokedSessionRegistry,
    is_session_revoked,
    revocation_poll_url,
    revoked_session_registry,
    update_revoked_sessions_from_ingest,
)


def test_registry_replaces_wholesale_and_rejects_junk():
    registry = RevokedSessionRegistry()
    assert registry.replace(["sess-1", "", None, "sess-2", 7, "sess" * 100]) == 2
    assert registry.is_revoked("sess-1")
    assert registry.is_revoked("sess-2")
    assert not registry.is_revoked("")
    assert not registry.is_revoked(None)

    assert registry.replace(["sess-3"]) == 1
    assert not registry.is_revoked("sess-1")
    assert registry.is_revoked("sess-3")

    assert registry.add("sess-4")
    assert not registry.add("sess-4")
    assert registry.is_revoked("sess-3") and registry.is_revoked("sess-4")


def test_ingest_snapshot_updates_global_registry():
    body = json.dumps({"accepted": 1, "revoked_sessions": ["snapshot-session"]}).encode()
    assert update_revoked_sessions_from_ingest(body) == 1
    assert is_session_revoked("snapshot-session")

    # No snapshot — previous state stands; this must not read as "nothing".
    assert update_revoked_sessions_from_ingest(b"not json") == -1
    assert update_revoked_sessions_from_ingest(b"{}") == -1
    assert update_revoked_sessions_from_ingest({"accepted": 1}) == -1
    assert is_session_revoked("snapshot-session")

    # An authoritative empty snapshot lifts the revocation.
    assert update_revoked_sessions_from_ingest({"revoked_sessions": []}) == 0
    assert not is_session_revoked("snapshot-session")


def test_poll_url_is_only_derived_from_the_ingest_endpoint():
    assert (
        revocation_poll_url("https://dashboard.example/api/ingest")
        == "https://dashboard.example/api/sessions/revoked"
    )
    assert revocation_poll_url("https://dashboard.example/events") is None


class _RevocationHandler(BaseHTTPRequestHandler):
    payload: dict = {"revoked_sessions": []}
    status = 200
    seen_headers: dict = {}

    def do_GET(self):  # noqa: N802 — BaseHTTPRequestHandler API
        type(self).seen_headers = {key.lower(): value for key, value in self.headers.items()}
        body = json.dumps(type(self).payload).encode()
        self.send_response(type(self).status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):  # silence test output
        pass


def _start_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _RevocationHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def test_poller_refreshes_from_the_dashboard_endpoint():
    _RevocationHandler.payload = {"revoked_sessions": ["polled-session"]}
    _RevocationHandler.status = 200
    server, thread = _start_server()
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}/api/sessions/revoked"
        poller = RevokedSessionPoller(
            url,
            "test-token-value",
            tenant_id="tenant-poll",
            module="vector-anchor",
            interval_ms=60_000,
        )
        assert poller.refresh_once() == 1
        assert is_session_revoked("polled-session")
        assert _RevocationHandler.seen_headers["x-monolith-tenant-id"] == "tenant-poll"
        assert _RevocationHandler.seen_headers["x-monolith-module"] == "vector-anchor"
        assert _RevocationHandler.seen_headers["authorization"] == "Bearer test-token-value"

        # An error response must not clear the set.
        _RevocationHandler.status = 503
        assert poller.refresh_once() == -1
        assert is_session_revoked("polled-session")
        assert poller.last_error == "http 503"

        # A later healthy snapshot lifts it.
        _RevocationHandler.status = 200
        _RevocationHandler.payload = {"revoked_sessions": []}
        assert poller.refresh_once() == 0
        assert not is_session_revoked("polled-session")
    finally:
        server.shutdown()
        thread.join(timeout=5)
        revoked_session_registry().replace([])
