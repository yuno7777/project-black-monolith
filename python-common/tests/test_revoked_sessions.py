"""The revoked-session mirror is fail-closed and refreshable over HTTP.

The cross-layer circuit breaker lives in the dashboard; these tests pin the
module-side contract: an authoritative snapshot replaces the set (including
an empty one), a missing or broken snapshot leaves it alone, and the poller
refreshes it without any event traffic.
"""

from __future__ import annotations

import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from monolith_events.events import (
    DEFAULT_POLL_INTERVAL_MS,
    MIN_POLL_INTERVAL_MS,
    RevokedSessionPoller,
    RevokedSessionRegistry,
    _poll_interval_ms,
    is_session_revoked,
    make_emitter,
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


def test_a_mistyped_poll_interval_falls_back_to_the_default(monkeypatch, capsys):
    """A cadence the module cannot read must not switch the poll off.

    The poll is the only way an idle module learns that its session was
    revoked, so an unreadable value falls back to the default cadence and
    says so, rather than stopping the poll.
    """
    monkeypatch.setenv("MONOLITH_SESSION_POLL_MS", "500")
    assert _poll_interval_ms() == DEFAULT_POLL_INTERVAL_MS
    assert "MONOLITH_SESSION_POLL_MS" in capsys.readouterr().err

    monkeypatch.setenv("MONOLITH_SESSION_POLL_MS", "not-a-number")
    assert _poll_interval_ms() == DEFAULT_POLL_INTERVAL_MS

    monkeypatch.setenv("MONOLITH_SESSION_POLL_MS", "15000ms")
    assert _poll_interval_ms() == DEFAULT_POLL_INTERVAL_MS

    monkeypatch.setenv("MONOLITH_SESSION_POLL_MS", "-1")
    assert _poll_interval_ms() == DEFAULT_POLL_INTERVAL_MS


def test_a_readable_poll_interval_is_taken_as_written(monkeypatch):
    monkeypatch.setenv("MONOLITH_SESSION_POLL_MS", "30000")
    assert _poll_interval_ms() == 30_000

    monkeypatch.setenv("MONOLITH_SESSION_POLL_MS", str(MIN_POLL_INTERVAL_MS))
    assert _poll_interval_ms() == MIN_POLL_INTERVAL_MS


def test_zero_is_the_only_way_to_switch_the_poll_off(monkeypatch, capsys):
    monkeypatch.setenv("MONOLITH_SESSION_POLL_MS", "0")
    assert _poll_interval_ms() == 0
    assert "disabled" in capsys.readouterr().err


def test_the_emitter_keeps_polling_when_the_cadence_cannot_be_read(monkeypatch, tmp_path):
    """The fallback has to reach the emitter, not just the helper.

    This is the difference between a default cadence and a control that is
    off with nothing to show for it.
    """
    monkeypatch.setenv("MONOLITH_SESSION_POLL_MS", "not-a-number")
    emitter = make_emitter(
        "vector-anchor",
        "https://dashboard.invalid/api/ingest",
        "test-token-value",
        str(tmp_path / "outbox.db"),
    )
    try:
        assert emitter.revocation_poller is not None, (
            "an unreadable cadence must not switch the revocation poll off"
        )
    finally:
        if emitter.outbox is not None:
            emitter.outbox.close()


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


class _PagedRevocationHandler(BaseHTTPRequestHandler):
    """A dashboard whose revocation snapshot does not fit in one response.

    A module reads a response body under a hard byte cap, and a snapshot
    larger than that cap cannot be parsed at all: the module keeps the set it
    already had, and that set is stale. Past a certain number of live
    revocations every snapshot is too large, so the staleness never ends and
    the circuit breaker fails open for exactly the sessions it was meant to
    quarantine.
    """

    pages: dict = {}
    seen_targets: list = []

    def do_GET(self):  # noqa: N802 — BaseHTTPRequestHandler API
        type(self).seen_targets.append(self.path)
        parts = urllib.parse.urlsplit(self.path)
        cursor = urllib.parse.parse_qs(parts.query).get("cursor", [""])[0]
        body = json.dumps(type(self).pages.get(cursor, {"error": "no such page"})).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):  # silence test output
        pass


def _start_paged_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _PagedRevocationHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def test_poller_follows_the_pages_of_a_snapshot_too_large_to_send_at_once():
    _PagedRevocationHandler.pages = {
        "": {
            "revoked_sessions": ["page-1-session"],
            "revoked_sessions_complete": False,
            "next_cursor": "cursor-1",
        },
        "cursor-1": {
            "revoked_sessions": ["page-2-session"],
            "revoked_sessions_complete": False,
            "next_cursor": "cursor-2",
        },
        "cursor-2": {
            "revoked_sessions": ["page-3-session"],
            "revoked_sessions_complete": False,
            "next_cursor": None,
        },
    }
    _PagedRevocationHandler.seen_targets = []
    server, thread = _start_paged_server()
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}/api/sessions/revoked"
        poller = RevokedSessionPoller(
            url,
            "test-token-value",
            tenant_id="tenant-poll",
            module="vector-anchor",
            interval_ms=60_000,
        )
        assert poller.refresh_once() == 3, "every page of the snapshot must be read"
        assert is_session_revoked("page-1-session")
        assert is_session_revoked("page-2-session")
        assert is_session_revoked("page-3-session")
        assert _PagedRevocationHandler.seen_targets == [
            "/api/sessions/revoked",
            "/api/sessions/revoked?cursor=cursor-1",
            "/api/sessions/revoked?cursor=cursor-2",
        ]
    finally:
        server.shutdown()
        thread.join(timeout=5)
        revoked_session_registry().replace([])


def test_a_snapshot_that_cannot_be_read_to_the_end_installs_nothing():
    """A half-read snapshot would forget every revocation that is not on it."""
    _PagedRevocationHandler.pages = {
        "": {
            "revoked_sessions": ["page-1-session"],
            "revoked_sessions_complete": False,
            "next_cursor": "cursor-1",
        },
        # The page after the first one is missing, so the snapshot cannot be
        # read to the end.
    }
    _PagedRevocationHandler.seen_targets = []
    server, thread = _start_paged_server()
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}/api/sessions/revoked"
        poller = RevokedSessionPoller(
            url,
            "test-token-value",
            tenant_id="tenant-poll",
            module="vector-anchor",
            interval_ms=60_000,
        )
        assert poller.refresh_once() == -1
        assert not is_session_revoked("page-1-session"), (
            "a partial set must not be installed"
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)
        revoked_session_registry().replace([])


def test_an_incomplete_ingest_snapshot_is_refused():
    """An ingest response that says its set is not whole is not a set."""
    body = json.dumps(
        {
            "revoked_sessions": ["half-a-set"],
            "revoked_sessions_complete": False,
            "revoked_sessions_total": 2,
        }
    ).encode()
    assert update_revoked_sessions_from_ingest(body) == -1
    assert not is_session_revoked("half-a-set")

    # A complete one is still adopted.
    body = json.dumps(
        {"revoked_sessions": ["whole-set"], "revoked_sessions_complete": True}
    ).encode()
    assert update_revoked_sessions_from_ingest(body) == 1
    assert is_session_revoked("whole-set")
    revoked_session_registry().replace([])
