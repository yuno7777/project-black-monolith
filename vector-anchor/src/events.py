"""Durable, non-blocking security-event delivery for VectorAnchor."""

from __future__ import annotations

import json
import random
import sqlite3
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Mapping

Severity = Literal["info", "warning", "critical"]

# An id longer than this is a caller error, not a correlation key. The dashboard
# silently drops over-long text fields, so clamping here keeps a nonsense header
# from quietly costing a detection its correlation.
MAX_ID_LENGTH = 128


def _clean_id(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    trimmed = value.strip()[:MAX_ID_LENGTH]
    return trimmed or None


@dataclass(frozen=True)
class EventContext:
    """Who and what an event belongs to.

    This is what makes three independent modules one system: detections that
    share a `session_id` are the same agent session, so a rug pull at the tool
    layer and a poisoned retrieval at the memory layer stop being two unrelated
    blips and become one compromised agent.

    Each field is only set when it is actually known — an invented id would be
    worse than a missing one, because it would group unrelated activity and the
    grouping is the whole point.
    """

    # One operation within a session (a single /retrieve, /generate, tools/list).
    trace_id: str | None = None
    # One agent session. The cross-layer key.
    session_id: str | None = None
    # Caller-supplied: ties an operation together across several modules.
    correlation_id: str | None = None
    # Which agent, stable across sessions.
    agent_id: str | None = None


# Header names a caller (an agent framework) uses to propagate identity into the
# long-running HTTP services. Short-lived processes take theirs from the
# environment instead — see the Rust module.
AGENT_HEADER = "x-monolith-agent-id"
SESSION_HEADER = "x-monolith-session-id"
TRACE_HEADER = "x-monolith-trace-id"
CORRELATION_HEADER = "x-monolith-correlation-id"


def context_from_headers(headers: Mapping[str, str]) -> EventContext:
    """Build a context from request headers, minting a trace id if the caller
    did not supply one (every operation gets one; only the caller can know the
    session it belongs to)."""
    return EventContext(
        trace_id=_clean_id(headers.get(TRACE_HEADER)) or str(uuid.uuid4()),
        session_id=_clean_id(headers.get(SESSION_HEADER)),
        correlation_id=_clean_id(headers.get(CORRELATION_HEADER)),
        agent_id=_clean_id(headers.get(AGENT_HEADER)),
    )


class EventOutbox:
    """A small WAL-backed spool. Enqueue is local and delivery is asynchronous."""

    def __init__(self, path: str, url: str, token: str) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(path, check_same_thread=False, timeout=0.05)
        self._connection.execute("pragma journal_mode = wal")
        self._connection.execute("pragma synchronous = normal")
        self._connection.execute(
            """create table if not exists event_outbox (
                event_id text primary key,
                payload blob not null,
                attempts integer not null default 0,
                next_attempt_ms integer not null,
                status text not null default 'pending',
                last_error text
            )"""
        )
        self._connection.commit()
        self._lock = threading.Lock()
        self._url = url
        self._token = token
        self._wake = threading.Event()
        self._worker = threading.Thread(target=self._run, name="event-outbox", daemon=True)
        self._worker.start()

    def enqueue(self, event_id: str, payload: bytes) -> None:
        with self._lock:
            self._connection.execute(
                "insert or ignore into event_outbox (event_id, payload, next_attempt_ms) values (?, ?, ?)",
                (event_id, payload, int(time.time() * 1000)),
            )
            self._connection.commit()
        self._wake.set()

    def _run(self) -> None:
        while True:
            self._flush_due()
            self._wake.wait(timeout=1.0)
            self._wake.clear()

    def _flush_due(self) -> None:
        now = int(time.time() * 1000)
        with self._lock:
            rows = self._connection.execute(
                "select event_id, payload, attempts from event_outbox where status = 'pending' and next_attempt_ms <= ? order by next_attempt_ms limit 16",
                (now,),
            ).fetchall()
        for event_id, payload, attempts in rows:
            status, error = self._post(payload)
            with self._lock:
                if 200 <= status < 300:
                    self._connection.execute("delete from event_outbox where event_id = ?", (event_id,))
                elif status in {400, 401, 403, 413, 422}:
                    self._connection.execute(
                        "update event_outbox set status = 'dead', last_error = ? where event_id = ?",
                        (error, event_id),
                    )
                else:
                    delay_ms = min(300_000, (2 ** min(attempts + 1, 8)) * 1_000)
                    delay_ms += int(random.random() * 1_000)
                    self._connection.execute(
                        "update event_outbox set attempts = attempts + 1, next_attempt_ms = ?, last_error = ? where event_id = ?",
                        (now + delay_ms, error, event_id),
                    )
                self._connection.commit()

    def _post(self, payload: bytes) -> tuple[int, str]:
        try:
            request = urllib.request.Request(
                self._url,
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self._token}",
                },
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=2) as response:
                return response.status, ""
        except urllib.error.HTTPError as error:
            return error.code, f"http {error.code}"
        except Exception as error:
            return 0, type(error).__name__


def now_ms() -> int:
    return int(time.time() * 1000)


def make_emitter(
    module: str,
    dashboard_url: str | None,
    event_token: str | None,
    outbox_path: str,
    agent_id: str | None = None,
    session_id: str | None = None,
):
    """Build the emit function.

    `agent_id`/`session_id` are the process-level defaults (from the
    environment). A per-request `EventContext` overrides them, which is how a
    long-running service serving many agents attributes each detection to the
    right one.
    """
    outbox = EventOutbox(outbox_path, dashboard_url, event_token) if dashboard_url and event_token else None
    default_agent = _clean_id(agent_id)
    default_session = _clean_id(session_id)

    def emit(
        event_type: str,
        severity: Severity,
        details: dict[str, Any],
        ctx: EventContext | None = None,
    ) -> None:
        event = {
            "event_id": str(uuid.uuid4()),
            "schema_version": 2,
            "timestamp_ms": now_ms(),
            "module": module,
            "event_type": event_type,
            "severity": severity,
            "details": details,
            "source": "module",
        }
        # Correlation fields are omitted when unknown rather than sent as null:
        # the contract treats them as optional, and a null would claim we looked
        # and found nothing rather than that nobody told us.
        correlation = {
            "agent_id": (ctx.agent_id if ctx else None) or default_agent,
            "session_id": (ctx.session_id if ctx else None) or default_session,
            "trace_id": ctx.trace_id if ctx else None,
            "correlation_id": ctx.correlation_id if ctx else None,
        }
        for key, value in correlation.items():
            if value:
                event[key] = value

        line = json.dumps(event, separators=(",", ":"))
        print(line, file=sys.stderr, flush=True)
        if outbox:
            try:
                outbox.enqueue(event["event_id"], line.encode("utf-8"))
            except sqlite3.Error as error:
                print(f"event outbox enqueue failed: {error}", file=sys.stderr, flush=True)

    return emit
