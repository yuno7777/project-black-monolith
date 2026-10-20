"""Shared event envelopes and bounded SQLite delivery for Python modules."""

from __future__ import annotations

import ipaddress
import json
import os
import random
import sqlite3
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections.abc import Iterable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

Severity = Literal["info", "warning", "critical"]
MAX_ID_LENGTH = 128
MAX_EVENT_PAYLOAD_BYTES = 256 * 1024
MIN_BEARER_TOKEN_LENGTH = 16
MAX_BEARER_TOKEN_LENGTH = 512
AGENT_HEADER = "x-monolith-agent-id"
TENANT_HEADER = "x-monolith-tenant-id"
SESSION_HEADER = "x-monolith-session-id"
TRACE_HEADER = "x-monolith-trace-id"
CORRELATION_HEADER = "x-monolith-correlation-id"
PERMANENT_HTTP_STATUSES = {400, 401, 403, 413, 422}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Keep bearer credentials pinned to the configured ingest origin."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def now_ms() -> int:
    return int(time.time() * 1000)


def _poll_interval_ms() -> int:
    """Revocation poll cadence; 0 (or a bad value) disables polling."""
    raw = os.environ.get("MONOLITH_SESSION_POLL_MS", "15000")
    try:
        value = int(raw)
    except ValueError:
        return 0
    return value if value > 0 else 0


def _clean_id(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    trimmed = value.strip()
    if (
        not trimmed
        or len(trimmed.encode("utf-8")) > MAX_ID_LENGTH
        or any(not character.isprintable() for character in trimmed)
    ):
        return None
    return trimmed


def _tenant_of_payload(payload: bytes) -> str | None:
    """The tenant a stored event belongs to, or None when it says nothing.

    The payload is the event envelope, so the tenant is in it. Reading it
    back is what lets a spooled row be attributed to a tenant without a
    second source of truth that could disagree with what gets delivered.
    """
    try:
        decoded = json.loads(payload)
    except (ValueError, TypeError):
        return None
    if not isinstance(decoded, dict):
        return None
    return _clean_id(decoded.get("tenant_id"))


def tenant_scope(value: str | None) -> str | None:
    """The tenant a scoped operation applies to.

    `None` means no scope was asked for. A value that cannot be a tenant id
    raises `ValueError` rather than returning `None`, because the two mean
    different things: no scope replays everything, and a scope nobody can
    read must be rejected instead of quietly becoming everything.
    """
    if value is None:
        return None
    cleaned = _clean_id(value)
    if not cleaned:
        raise ValueError("tenant must be 1-128 printable characters")
    return cleaned


def _safe_delivery_url(value: str, *, allow_insecure_http: bool = False) -> bool:
    try:
        parsed = urllib.parse.urlsplit(value)
        host = parsed.hostname
    except ValueError:
        return False
    loopback = host == "localhost"
    if host and not loopback:
        with suppress(ValueError):
            loopback = ipaddress.ip_address(host).is_loopback
    return bool(
        host
        and not parsed.username
        and not parsed.password
        and not parsed.fragment
        and (
            parsed.scheme == "https"
            or (parsed.scheme == "http" and (loopback or allow_insecure_http))
        )
    )


def _valid_bearer_token(value: str) -> bool:
    return MIN_BEARER_TOKEN_LENGTH <= len(value) <= MAX_BEARER_TOKEN_LENGTH and all(
        character.isascii() and (character.isalnum() or character in "-._~+/=")
        for character in value
    )


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


class RevokedSessionRegistry:
    """Thread-safe mirror of the dashboard's revoked-session set.

    A revocation does **not** expire locally: the dashboard is the authority,
    and a module-local TTL would silently re-admit a quarantined session after
    a fixed delay. The set is replaced wholesale by each authoritative update
    (an ingest response or a poll of `/api/sessions/revoked`), and a failed
    refresh leaves the previous set in place — fail closed, not open.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sessions: frozenset[str] = frozenset()

    def replace(self, session_ids: Iterable[Any]) -> int:
        cleaned = frozenset(
            value for value in (_clean_id(item) for item in session_ids) if value
        )
        with self._lock:
            self._sessions = cleaned
        return len(cleaned)

    def add(self, session_id: Any) -> bool:
        cleaned = _clean_id(session_id)
        if not cleaned:
            return False
        with self._lock:
            if cleaned in self._sessions:
                return False
            self._sessions = self._sessions | {cleaned}
        return True

    def is_revoked(self, session_id: Any) -> bool:
        cleaned = _clean_id(session_id)
        if not cleaned:
            return False
        with self._lock:
            return cleaned in self._sessions

    def snapshot(self) -> frozenset[str]:
        with self._lock:
            return self._sessions


_REVOKED_SESSIONS = RevokedSessionRegistry()


def revoked_session_registry() -> RevokedSessionRegistry:
    return _REVOKED_SESSIONS


def is_session_revoked(session_id: Any) -> bool:
    return _REVOKED_SESSIONS.is_revoked(session_id)


def update_revoked_sessions_from_ingest(body: bytes | str | Mapping[str, Any]) -> int:
    """Adopt the `revoked_sessions` snapshot of an ingest response.

    Only a payload that actually carries the field updates the registry; an
    unparseable or empty body must not be read as "nothing is revoked".
    Returns the number of revoked sessions now known, or -1 when the payload
    carried no usable snapshot.
    """
    if isinstance(body, (bytes, bytearray)):
        try:
            payload: Any = json.loads(bytes(body).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return -1
    elif isinstance(body, str):
        try:
            payload = json.loads(body)
        except ValueError:
            return -1
    else:
        payload = body
    if not isinstance(payload, Mapping):
        return -1
    raw = payload.get("revoked_sessions")
    if not isinstance(raw, (list, tuple)):
        return -1
    return _REVOKED_SESSIONS.replace(raw)


def revocation_poll_url(dashboard_url: str) -> str | None:
    """Derive the revocation-poll endpoint from the configured ingest URL."""
    parsed = urllib.parse.urlsplit(dashboard_url)
    path = parsed.path.rstrip("/")
    if not path.endswith("/api/ingest"):
        return None
    poll_path = path[: -len("/api/ingest")] + "/api/sessions/revoked"
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, poll_path, "", ""))


class RevokedSessionPoller:
    """Periodically refresh the revoked-session set when no events flow."""

    def __init__(
        self,
        url: str,
        token: str,
        *,
        tenant_id: str,
        module: str,
        interval_ms: int = 15_000,
        allow_insecure_http: bool = False,
    ) -> None:
        if interval_ms < 1_000:
            raise ValueError("poll interval must be at least one second")
        if not _safe_delivery_url(url, allow_insecure_http=allow_insecure_http):
            raise ValueError("poll URL must use HTTPS (HTTP is loopback-only)")
        if not _valid_bearer_token(token):
            raise ValueError("poll token must be 16-512 header-safe characters")
        clean_tenant = _clean_id(tenant_id)
        clean_module = _clean_id(module)
        if not clean_tenant or not clean_module:
            raise ValueError("poll tenant and module must be printable")
        self._url = url
        self._token = token
        self._tenant = clean_tenant
        self._module = clean_module
        self._interval_s = interval_ms / 1000.0
        self._stop = threading.Event()
        self._worker: threading.Thread | None = None
        self.last_error: str | None = None

    def start(self) -> None:
        if self._worker is not None:
            return
        self._worker = threading.Thread(
            target=self._run,
            name="revoked-session-poller",
            daemon=True,
        )
        self._worker.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            self.refresh_once()
            self._stop.wait(self._interval_s)

    def refresh_once(self) -> int:
        try:
            request = urllib.request.Request(
                self._url,
                headers={
                    "Authorization": f"Bearer {self._token}",
                    TENANT_HEADER: self._tenant,
                    "x-monolith-module": self._module,
                },
                method="GET",
            )
            opener = urllib.request.build_opener(_NoRedirect)
            with opener.open(request, timeout=2) as response:
                body = response.read(64 * 1024)
            self.last_error = None
            return update_revoked_sessions_from_ingest(body)
        except urllib.error.HTTPError as error:
            self.last_error = f"http {error.code}"
        except Exception as error:  # a poll failure must never kill the thread
            self.last_error = type(error).__name__
        return -1

    def close(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._worker:
            self._worker.join(timeout=timeout)


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
        allow_insecure_http: bool = False,
    ) -> None:
        if min(max_attempts, max_pending, max_dead, dead_retention_ms) < 1:
            raise ValueError("outbox limits must be positive")
        if not _safe_delivery_url(url, allow_insecure_http=allow_insecure_http):
            raise ValueError("outbox URL must use HTTPS (HTTP is loopback-only)")
        if not _valid_bearer_token(token):
            raise ValueError("outbox token must be 16-512 header-safe characters")
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(path, check_same_thread=False, timeout=1.0)
        self._connection.execute("pragma journal_mode = wal")
        self._connection.execute("pragma synchronous = normal")
        self._connection.execute("pragma busy_timeout = 1000")
        self._init_schema()
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

    def _init_schema(self) -> None:
        self._connection.execute(
            """create table if not exists event_outbox (
                event_id text primary key,
                payload blob not null,
                attempts integer not null default 0,
                next_attempt_ms integer not null,
                status text not null default 'pending',
                last_error text,
                created_ms integer not null,
                updated_ms integer not null,
                tenant_id text
            )"""
        )
        self._migrate_legacy_table()
        self._connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_event_outbox_status_next ON event_outbox (status, next_attempt_ms, created_ms)"
        )
        self._connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_event_outbox_status_updated ON event_outbox (status, updated_ms)"
        )
        self._connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_event_outbox_tenant_status ON event_outbox (tenant_id, status)"
        )

    def _migrate_legacy_table(self) -> None:
        columns = {row[1] for row in self._connection.execute("pragma table_info(event_outbox)")}
        timestamp = now_ms()
        for name in ("created_ms", "updated_ms"):
            if name not in columns:
                self._connection.execute(f"alter table event_outbox add column {name} integer")
                self._connection.execute(
                    f"update event_outbox set {name} = ? where {name} is null",
                    (timestamp,),
                )
        if "tenant_id" not in columns:
            self._connection.execute("alter table event_outbox add column tenant_id text")
            self._backfill_tenant_ids()

    def _backfill_tenant_ids(self) -> None:
        """Give every row already in the spool the tenant it belongs to.

        The tenant lives inside the stored payload, so a row that predates the
        column can still be attributed. Leaving it unattributed would be the
        one way to lose evidence: a tenant-scoped replay skips rows it cannot
        place, and the skipped rows are the ones an operator asked about.
        """
        rows = self._connection.execute(
            "select event_id, payload from event_outbox where tenant_id is null"
        ).fetchall()
        for event_id, payload in rows:
            tenant = _tenant_of_payload(payload)
            if tenant:
                self._connection.execute(
                    "update event_outbox set tenant_id = ? where event_id = ?",
                    (tenant, event_id),
                )

    def enqueue(self, event_id: str, payload: bytes, tenant_id: str | None = None) -> None:
        if (
            not event_id
            or len(event_id.encode("utf-8")) > MAX_ID_LENGTH
            or any(not character.isprintable() for character in event_id)
        ):
            raise ValueError(f"event_id must be 1-{MAX_ID_LENGTH} printable characters")
        if not payload or len(payload) > MAX_EVENT_PAYLOAD_BYTES:
            raise ValueError(f"event payload must be 1-{MAX_EVENT_PAYLOAD_BYTES} bytes")
        clean_tenant = _clean_id(tenant_id) if tenant_id is not None else None
        if clean_tenant is None:
            clean_tenant = _tenant_of_payload(payload)
        timestamp = now_ms()
        with self._lock, self._connection:
            self._connection.execute(
                """insert or ignore into event_outbox
                   (event_id, payload, tenant_id, next_attempt_ms, created_ms, updated_ms)
                   values (?, ?, ?, ?, ?, ?)""",
                (event_id, payload, clean_tenant, timestamp, timestamp, timestamp),
            )
            self._enforce_limits_locked(timestamp)
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
            opener = urllib.request.build_opener(_NoRedirect)
            with opener.open(request, timeout=2) as response:
                status = response.status
                try:
                    body = response.read(64 * 1024)
                except Exception:
                    # A delivered event is delivered; never retry it because
                    # the revocation snapshot could not be read back.
                    body = b""
        except urllib.error.HTTPError as error:
            return error.code, f"http {error.code}"
        except Exception as error:
            return 0, type(error).__name__
        update_revoked_sessions_from_ingest(body)
        return status, ""

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

    def replay_dead_letters(self, tenant_id: str | None = None) -> int:
        """Move dead-lettered events back to pending so they are retried.

        A tenant-scoped replay touches only that tenant's events. The outbox
        is shared by every tenant a module serves, so an unscoped replay
        requeues another tenant's evidence and reports it in a count the
        operator then reads as their own.
        """
        timestamp = now_ms()
        clean_tenant: str | None = None
        if tenant_id is not None:
            clean_tenant = _clean_id(tenant_id)
            if clean_tenant is None:
                # A scope that cannot be read must never widen to "everything".
                raise ValueError("tenant must be 1-128 printable characters")
        with self._lock, self._connection:
            if clean_tenant is not None:
                cursor = self._connection.execute(
                    """update event_outbox
                       set status = 'pending',
                           attempts = 0,
                           next_attempt_ms = 0,
                           last_error = null,
                           updated_ms = ?
                       where status = 'dead' and tenant_id = ?""",
                    (timestamp, clean_tenant),
                )
            else:
                cursor = self._connection.execute(
                    """update event_outbox
                       set status = 'pending',
                           attempts = 0,
                           next_attempt_ms = 0,
                           last_error = null,
                           updated_ms = ?
                       where status = 'dead'""",
                    (timestamp,),
                )
            replayed = int(
                cursor.rowcount
                if cursor.rowcount is not None and cursor.rowcount >= 0
                else 0
            )
        self._wake.set()
        return replayed

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
        allow_insecure_http: bool = False,
    ) -> None:
        self.module = module
        self.default_agent = _clean_id(agent_id)
        self.default_session = _clean_id(session_id)
        self.default_tenant = _clean_id(tenant_id) or "default"
        self.outbox = (
            EventOutbox(
                outbox_path,
                dashboard_url,
                event_token,
                allow_insecure_http=allow_insecure_http,
            )
            if dashboard_url and event_token
            else None
        )
        self.revocation_poller: RevokedSessionPoller | None = None
        if (
            self.outbox
            and dashboard_url
            and event_token
            and _poll_interval_ms()
            and (
                (poll_url := os.environ.get("MONOLITH_SESSION_POLL_URL"))
                or (poll_url := revocation_poll_url(dashboard_url))
            )
        ):
                try:
                    self.revocation_poller = RevokedSessionPoller(
                        poll_url,
                        event_token,
                        tenant_id=self.default_tenant,
                        module=module,
                        interval_ms=_poll_interval_ms(),
                        allow_insecure_http=allow_insecure_http,
                    )
                    self.revocation_poller.start()
                except ValueError as error:
                    print(
                        f"revoked-session polling disabled: {error}",
                        file=sys.stderr,
                        flush=True,
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
                self.outbox.enqueue(
                    event["event_id"],
                    line.encode("utf-8"),
                    tenant_id=event["tenant_id"],
                )
            except sqlite3.Error as error:
                print(
                    f"event outbox enqueue failed: {type(error).__name__}",
                    file=sys.stderr,
                    flush=True,
                )

    def close(self) -> None:
        if self.revocation_poller:
            self.revocation_poller.close()
        if self.outbox:
            self.outbox.close()

    def delivery_stats(self) -> dict[str, int | bool | str | None]:
        if not self.outbox:
            return {"pending": 0, "dead": 0, "worker_alive": False, "worker_error": None}
        return self.outbox.stats()

    def replay_dead_letters(self, tenant_id: str | None = None) -> int:
        if not self.outbox:
            return 0
        return self.outbox.replay_dead_letters(tenant_id=tenant_id)


def replay_dead_letters(
    outbox: EventOutbox | EventEmitter | None = None,
    tenant_id: str | None = None,
) -> int:
    if outbox is None:
        return 0
    return outbox.replay_dead_letters(tenant_id=tenant_id)


def make_emitter(
    module: str,
    dashboard_url: str | None,
    event_token: str | None,
    outbox_path: str,
    tenant_id: str | None = "default",
    agent_id: str | None = None,
    session_id: str | None = None,
    allow_insecure_http: bool = False,
) -> EventEmitter:
    return EventEmitter(
        module,
        dashboard_url,
        event_token,
        outbox_path,
        tenant_id=tenant_id,
        agent_id=agent_id,
        session_id=session_id,
        allow_insecure_http=allow_insecure_http,
    )
