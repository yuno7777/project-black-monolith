"""Shared event envelopes and bounded SQLite delivery for Python modules."""

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
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

Severity = Literal["info", "warning", "critical"]
MAX_ID_LENGTH = 128
AGENT_HEADER = "x-monolith-agent-id"
TENANT_HEADER = "x-monolith-tenant-id"
SESSION_HEADER = "x-monolith-session-id"
TRACE_HEADER = "x-monolith-trace-id"
CORRELATION_HEADER = "x-monolith-correlation-id"
PERMANENT_HTTP_STATUSES = {400, 401, 403, 413, 422}


def now_ms() -> int:
    return int(time.time() * 1000)


def _clean_id(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    trimmed = value.strip()[:MAX_ID_LENGTH]
    return trimmed or None


@dataclass(frozen=True)
class EventContext:
    tenant_id: str | None = None
    trace_id: str | None = None
    session_id: str | None = None
    correlation_id: str | None = None
    agent_id: str | None = None


def context_from_headers(headers: Mapping[str, str]) -> EventContext:
    return EventContext(
        tenant_id=_clean_id(headers.get(TENANT_HEADER)),
        trace_id=_clean_id(headers.get(TRACE_HEADER)) or str(uuid.uuid4()),
        session_id=_clean_id(headers.get(SESSION_HEADER)),
        correlation_id=_clean_id(headers.get(CORRELATION_HEADER)),
        agent_id=_clean_id(headers.get(AGENT_HEADER)),
    )


class EventOutbox:
    """WAL-backed asynchronous delivery with bounded retry and retention."""

    def __init__(
        self,
        path: str,
        url: str,
        token: str,
        *,
        max_attempts: int = 12,
        max_pending: int = 10_000,
        max_dead: int = 2_000,
        dead_retention_ms: int = 7 * 24 * 60 * 60 * 1000,
        start_worker: bool = True,
    ) -> None:
        if min(max_attempts, max_pending, max_dead, dead_retention_ms) < 1:
            raise ValueError("outbox limits must be positive")
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(path, check_same_thread=False, timeout=1.0)
        self._connection.execute("pragma journal_mode = wal")
        self._connection.execute("pragma synchronous = normal")
        self._connection.execute("pragma busy_timeout = 1000")
        self._connection.execute(
            """create table if not exists event_outbox (
                event_id text primary key,
                payload blob not null,
                attempts integer not null default 0,
                next_attempt_ms integer not null,
                status text not null default 'pending',
                last_error text,
                created_ms integer not null,
                updated_ms integer not null
            )"""
        )
        self._migrate_legacy_table()
        self._connection.commit()
        self._lock = threading.Lock()
        self._url = url
        self._token = token
        self._max_attempts = max_attempts
        self._max_pending = max_pending
        self._max_dead = max_dead
        self._dead_retention_ms = dead_retention_ms
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._worker_error: str | None = None
        self._worker: threading.Thread | None = None
        if start_worker:
            self._worker = threading.Thread(
                target=self._run,
                name="event-outbox",
                daemon=True,
            )
            self._worker.start()

    def _migrate_legacy_table(self) -> None:
        columns = {
            row[1] for row in self._connection.execute("pragma table_info(event_outbox)")
        }
        timestamp = now_ms()
        for name in ("created_ms", "updated_ms"):
            if name not in columns:
                self._connection.execute(
                    f"alter table event_outbox add column {name} integer"
                )
                self._connection.execute(
                    f"update event_outbox set {name} = ? where {name} is null",
                    (timestamp,),
                )

    def enqueue(self, event_id: str, payload: bytes) -> None:
        timestamp = now_ms()
        with self._lock:
            self._connection.execute(
                """insert or ignore into event_outbox
                   (event_id, payload, next_attempt_ms, created_ms, updated_ms)
                   values (?, ?, ?, ?, ?)""",
                (event_id, payload, timestamp, timestamp, timestamp),
            )
            self._enforce_limits_locked(timestamp)
            self._connection.commit()
        self._wake.set()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.flush_once()
                self._worker_error = None
            except Exception as error:  # the delivery worker must self-heal
                self._worker_error = type(error).__name__
                print(
                    f"event outbox worker recovered from {type(error).__name__}",
                    file=sys.stderr,
                    flush=True,
                )
            self._wake.wait(timeout=1.0)
            self._wake.clear()

    def flush_once(self) -> None:
        timestamp = now_ms()
        with self._lock:
            rows = self._connection.execute(
                """select event_id, payload, attempts from event_outbox
                   where status = 'pending' and next_attempt_ms <= ?
                   order by next_attempt_ms limit 16""",
                (timestamp,),
            ).fetchall()
        for event_id, payload, attempts in rows:
            status, error = self._post(payload)
            with self._lock:
                next_attempt = attempts + 1
                if 200 <= status < 300:
                    self._connection.execute(
                        "delete from event_outbox where event_id = ?", (event_id,)
                    )
                elif status in PERMANENT_HTTP_STATUSES or next_attempt >= self._max_attempts:
                    reason = error or f"delivery attempts exhausted ({next_attempt})"
                    self._connection.execute(
                        """update event_outbox set status = 'dead', attempts = ?,
                           last_error = ?, updated_ms = ? where event_id = ?""",
                        (next_attempt, reason, timestamp, event_id),
                    )
                else:
                    delay_ms = min(300_000, (2 ** min(next_attempt, 8)) * 1_000)
                    delay_ms += int(random.random() * 1_000)
                    self._connection.execute(
                        """update event_outbox set attempts = ?, next_attempt_ms = ?,
                           last_error = ?, updated_ms = ? where event_id = ?""",
                        (next_attempt, timestamp + delay_ms, error, timestamp, event_id),
                    )
                self._enforce_limits_locked(timestamp)
                self._connection.commit()

    def _enforce_limits_locked(self, timestamp: int) -> None:
        self._connection.execute(
            "delete from event_outbox where status = 'dead' and updated_ms < ?",
            (timestamp - self._dead_retention_ms,),
        )
        pending = self._connection.execute(
            "select count(*) from event_outbox where status = 'pending'"
        ).fetchone()[0]
        overflow = max(0, pending - self._max_pending)
        if overflow:
            self._connection.execute(
                """update event_outbox set status = 'dead', last_error = 'outbox_capacity',
                   updated_ms = ? where event_id in (
                     select event_id from event_outbox where status = 'pending'
                     order by created_ms limit ?
                   )""",
                (timestamp, overflow),
            )
        dead = self._connection.execute(
            "select count(*) from event_outbox where status = 'dead'"
        ).fetchone()[0]
        dead_overflow = max(0, dead - self._max_dead)
        if dead_overflow:
            self._connection.execute(
                """delete from event_outbox where event_id in (
                     select event_id from event_outbox where status = 'dead'
                     order by updated_ms limit ?
                   )""",
                (dead_overflow,),
            )

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

    def stats(self) -> dict[str, int | bool | str | None]:
        with self._lock:
            counts = dict(
                self._connection.execute(
                    "select status, count(*) from event_outbox group by status"
                ).fetchall()
            )
        return {
            "pending": int(counts.get("pending", 0)),
            "dead": int(counts.get("dead", 0)),
            "worker_alive": bool(self._worker and self._worker.is_alive()),
            "worker_error": self._worker_error,
        }

    def close(self, timeout: float = 5.0) -> None:
        self._stop.set()
        self._wake.set()
        if self._worker:
            self._worker.join(timeout=timeout)
            if self._worker.is_alive():
                raise TimeoutError("event outbox worker did not stop")
        with self._lock:
            self._connection.close()


class EventEmitter:
    def __init__(
        self,
        module: str,
        dashboard_url: str | None,
        event_token: str | None,
        outbox_path: str,
        *,
        tenant_id: str | None = "default",
        agent_id: str | None = None,
        session_id: str | None = None,
    ) -> None:
        self.module = module
        self.default_agent = _clean_id(agent_id)
        self.default_session = _clean_id(session_id)
        self.default_tenant = _clean_id(tenant_id) or "default"
        self.outbox = (
            EventOutbox(outbox_path, dashboard_url, event_token)
            if dashboard_url and event_token
            else None
        )

    def __call__(
        self,
        event_type: str,
        severity: Severity,
        details: dict[str, Any],
        ctx: EventContext | None = None,
        *,
        resource_type: str | None = None,
        resource_id: str | None = None,
        outcome: str | None = None,
        policy_version: str | None = None,
    ) -> None:
        event: dict[str, Any] = {
            "event_id": str(uuid.uuid4()),
            "schema_version": 2,
            "timestamp_ms": now_ms(),
            "module": self.module,
            "event_type": event_type,
            "severity": severity,
            "details": details,
            "source": "module",
            "tenant_id": (ctx.tenant_id if ctx else None) or self.default_tenant,
        }
        optional = {
            "agent_id": (ctx.agent_id if ctx else None) or self.default_agent,
            "session_id": (ctx.session_id if ctx else None) or self.default_session,
            "trace_id": ctx.trace_id if ctx else None,
            "correlation_id": ctx.correlation_id if ctx else None,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "outcome": outcome,
            "policy_version": policy_version,
        }
        event.update({key: value for key, value in optional.items() if value})
        line = json.dumps(event, separators=(",", ":"))
        print(line, file=sys.stderr, flush=True)
        if self.outbox:
            try:
                self.outbox.enqueue(event["event_id"], line.encode("utf-8"))
            except sqlite3.Error as error:
                print(
                    f"event outbox enqueue failed: {type(error).__name__}",
                    file=sys.stderr,
                    flush=True,
                )

    def close(self) -> None:
        if self.outbox:
            self.outbox.close()

    def delivery_stats(self) -> dict[str, int | bool | str | None]:
        if not self.outbox:
            return {"pending": 0, "dead": 0, "worker_alive": False, "worker_error": None}
        return self.outbox.stats()


def make_emitter(
    module: str,
    dashboard_url: str | None,
    event_token: str | None,
    outbox_path: str,
    tenant_id: str | None = "default",
    agent_id: str | None = None,
    session_id: str | None = None,
) -> EventEmitter:
    return EventEmitter(
        module,
        dashboard_url,
        event_token,
        outbox_path,
        tenant_id=tenant_id,
        agent_id=agent_id,
        session_id=session_id,
    )
