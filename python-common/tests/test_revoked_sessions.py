"""The revoked-session mirror is fail-closed and refreshable over HTTP.

The cross-layer circuit breaker lives in the dashboard; these tests pin the
module-side contract: an authoritative snapshot replaces the set (including
an empty one), a missing or broken snapshot leaves it alone, and the poller
refreshes it without any event traffic.

They also pin the difference between "the dashboard says nothing is revoked"
and "I could not read what the dashboard said". A body that could not be read
must be loud, and the local set must stand.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from monolith_events.events import (
    DEFAULT_POLL_INTERVAL_MS,
    MAX_SNAPSHOT_BYTES,
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


@pytest.fixture(autouse=True)
def _clean_registry():
    """The registry is process-wide, so no test may inherit another's set."""
    revoked_session_registry().replace([])
    yield
    revoked_session_registry().replace([])


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
    #: A raw body, used to serve one that is over the module's byte cap.
    raw: bytes | None = None

    def do_GET(self):  # noqa: N802 — BaseHTTPRequestHandler API
        type(self).seen_headers = {key.lower(): value for key, value in self.headers.items()}
        body = (
            type(self).raw
            if type(self).raw is not None
            else json.dumps(type(self).payload).encode()
        )
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


def test_a_truncated_body_keeps_the_previous_set_and_records_the_error():
    """A body that could not be read is not a snapshot that says nothing.

    The cap is there to stop a misconfigured target from making the module
    buffer an unbounded body. What must not happen is a cut-short body
    standing in for an authoritative one: the previous set stays, and the
    reason is recorded where an operator will see it.
    """
    assert update_revoked_sessions_from_ingest({"revoked_sessions": ["kept-session"]}) == 1

    _RevocationHandler.status = 200
    _RevocationHandler.raw = b"x" * (MAX_SNAPSHOT_BYTES + 1)
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
        assert poller.refresh_once() == -1
        assert poller.last_error is not None
        assert "cap" in poller.last_error
        assert is_session_revoked("kept-session"), (
            "a snapshot that could not be read must not clear the set"
        )
    finally:
        _RevocationHandler.raw = None
        server.shutdown()
        thread.join(timeout=5)


def test_an_empty_but_complete_body_lifts_the_revocations():
    """An empty list is a snapshot, and an authoritative one.

    A restored session has to come back. A body that is empty because the
    publisher says nothing is revoked is not the same thing as a body that
    could not be read, and the two must not look alike.
    """
    registry = RevokedSessionRegistry()
    registry.replace(["restored-session"])
    assert registry.is_revoked("restored-session")

    assert update_revoked_sessions_from_ingest({"revoked_sessions": []}) == 0
    assert not is_session_revoked("restored-session")
    assert revoked_session_registry().snapshot() == frozenset()


def test_a_body_with_no_snapshot_field_leaves_the_set_alone():
    """No snapshot field is not "nothing is revoked"."""
    assert update_revoked_sessions_from_ingest({"revoked_sessions": ["kept-session"]}) == 1

    assert update_revoked_sessions_from_ingest({"accepted": 1, "duplicates": 0}) == -1
    assert update_revoked_sessions_from_ingest({"revoked_sessions": "not-a-list"}) == -1
    assert is_session_revoked("kept-session")


def test_a_complete_snapshot_replaces_and_a_bounded_one_adds():
    """The publisher's bound decides whether the local set is replaced.

    A bounded snapshot is all the module can see, so it must not drop what it
    already knows: dropping a revocation the dashboard did not mention is the
    unsafe direction, and over-blocking is the safe one.
    """
    registry = RevokedSessionRegistry()
    registry.replace(["session-a", "session-b"])
    assert registry.apply_snapshot(["session-c"], complete=False) == 3
    assert registry.is_revoked("session-a")
    assert registry.is_revoked("session-c")

    assert registry.apply_snapshot(["session-d"], complete=True) == 1
    assert not registry.is_revoked("session-a")
    assert registry.is_revoked("session-d")

    # The same rule through the shared snapshot reader.
    assert update_revoked_sessions_from_ingest(
        {"revoked_sessions": ["session-e"], "complete": False}
    ) == 1
    assert update_revoked_sessions_from_ingest(
        {"revoked_sessions": ["session-f"], "complete": True}
    ) == 1
    assert is_session_revoked("session-f")
    assert not is_session_revoked("session-e")

    # A publisher that reports the bound the other way is believed too.
    assert update_revoked_sessions_from_ingest(
        {"revoked_sessions": ["session-g"], "truncated": True}
    ) == 2
    assert is_session_revoked("session-f")
    assert is_session_revoked("session-g")


def test_the_ingest_response_states_its_bound_under_its_own_names():
    """The ingest body is a different document from the poll body.

    Its bound is stated as `revoked_sessions_complete`, because a bare
    `complete` on a body that is mostly about an ingest would say nothing
    about which part of it is complete. A module that ignored those names
    would read the absence of a statement as "this is the whole set" and
    replace its local set with a bounded list — dropping every revocation
    past the bound, and serving the session revoked a moment ago.
    """
    assert update_revoked_sessions_from_ingest(
        {
            "revoked_sessions": ["session-h"],
            "revoked_sessions_complete": True,
            "revoked_sessions_truncated": False,
        }
    ) == 1
    assert is_session_revoked("session-h")

    # A bounded list is added to the local set, not substituted for it.
    assert update_revoked_sessions_from_ingest(
        {
            "revoked_sessions": ["session-i"],
            "revoked_sessions_complete": False,
            "revoked_sessions_truncated": True,
        }
    ) == 2
    assert is_session_revoked("session-h"), "a bounded list must not drop what is known"
    assert is_session_revoked("session-i")

    # `truncated` alone says the same thing from the other side.
    assert update_revoked_sessions_from_ingest(
        {"revoked_sessions": ["session-j"], "revoked_sessions_truncated": True}
    ) == 3
    assert is_session_revoked("session-h")
    assert is_session_revoked("session-j")

    # Each name is read on its own, so a publisher that states the bound
    # either way is believed. `complete` alone says the set is whole and
    # replaces the local set; `truncated` alone says it is bounded and does
    # not.
    assert update_revoked_sessions_from_ingest(
        {"revoked_sessions": ["session-k"], "revoked_sessions_complete": True}
    ) == 1
    assert not is_session_revoked("session-h"), "a whole set replaces the local set"
    assert is_session_revoked("session-k")

    assert update_revoked_sessions_from_ingest(
        {"revoked_sessions": ["session-l"], "revoked_sessions_complete": False}
    ) == 2
    assert is_session_revoked("session-k"), "a bounded list must not drop what is known"
    assert is_session_revoked("session-l")


def test_an_oversized_event_is_dead_lettered_instead_of_raising(tmp_path, capsys):
    """An event too large to deliver is recorded, not raised.

    The event is evidence. Raising out of the emitter would lose the
    detection along with the event, so the rejection goes to the same
    dead-letter spool a permanent rejection uses.
    """
    emitter = make_emitter(
        "vector-anchor",
        "https://dashboard.invalid/api/ingest",
        "test-token-value",
        str(tmp_path / "outbox.db"),
    )
    try:
        emitter(
            "corpus_poison_quarantine",
            "critical",
            {"blob": "x" * (300 * 1024)},
        )
        emitted = json.loads(capsys.readouterr().err.strip().splitlines()[-1])
        event_id = emitted["event_id"]

        assert emitter.outbox is not None
        assert emitter.outbox.stats()["dead"] == 1
        rows = emitter.outbox._connection.execute(
            "select event_id, last_error from event_outbox where status = 'dead'"
        ).fetchall()
        assert rows == [(event_id, rows[0][1])]
        assert "cap" in rows[0][1]
        assert "over the" in rows[0][1]
    finally:
        emitter.close()
