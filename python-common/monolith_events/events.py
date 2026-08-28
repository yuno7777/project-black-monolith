"""Shared event envelopes and bounded SQLite delivery for Python modules.

================================================================================
WHAT THIS FILE IS (THE DELIVERY SPINE OF THE PYTHON MODULES)
================================================================================

Project Black Monolith has three detection modules (mcp-shield, vector-anchor,
trace-audit) that each detect a different kind of attack. They are independent
services, but they all need to send "security events" to the same dashboard so
an operator sees one unified threat feed.

This file is the shared piece of that plumbing for the two Python modules
(VectorAnchor and TraceAudit). It defines:

1. The EXACT JSON shape of a security event (the "envelope") that every module
   emits, so the dashboard can treat all modules uniformly.
2. The durable OUTBOX: a small on-disk queue (SQLite) inside each module. When a
   module detects something, it does NOT send the event to the dashboard
   directly. It writes the event to this local queue first, then a background
   thread delivers queued events to the dashboard with retries.

WHY THE OUTBOX EXISTS (the most important design idea in the project)
----------------------------------------------------------------------
If a module detected an attack but the dashboard happened to be down or
restarting, a direct send would fail and the evidence would be LOST forever.
An attack that produced no record might as well not have been detected.

The outbox makes delivery "durable, at-least-once":

- "durable": the event is written to disk (SQLite, WAL mode) BEFORE the
  detection code continues, so even a crash right after detection does not lose
  it.
- "at-least-once": the event will be delivered at least once. The dashboard
  deduplicates on the event's `event_id` (a UUID), so a redelivery after a
  timeout does not create a duplicate row.

HOW THIS FILE IS USED ACROSS THE PROJECT
----------------------------------------
- vector-anchor/src/events.py  is a COPY of this file (vendored so the module
  can run standalone).  VectorAnchor's retriever_proxy.py calls make_emitter()
  at startup and emits events like "corpus_poison_quarantine".
- trace-audit/src/events.py   is the same COPY.  TraceAudit's main.py calls
  make_emitter() at startup; stream_proxy.py emits "reasoning_divergence_terminate"
  and "pii_redacted".
- The dashboard's /api/ingest route (dashboard/app/api/ingest/route.ts) receives
  the POST this outbox sends. It validates the envelope and stores it in
  Postgres, so events that pass through here end up on the live SSE feed.

This file is the "sender side" of the delivery contract. The matching
"receiver side" is the dashboard ingest route. The matching contract document is
contracts/schemas/event-envelope.v2.schema.json, and
contracts/check_contracts.py verifies the shape stays in sync.
"""

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

# The three allowed severities. "critical" is what triggers dashboard alerts.
Severity = Literal["info", "warning", "critical"]

# Correlation ids (tenant/agent/session/...) are clamped to this length so a
# hostile or buggy caller cannot stuff megabytes of text into the ledger.
MAX_ID_LENGTH = 128

# The HTTP header names the AGENT runtime uses to tell the module which agent /
# tenant / session a request belongs to. VectorAnchor and TraceAudit read these
# from the incoming request so each detection can be attributed to the right
# agent session. The dashboard documents these headers in contracts/openapi.yaml.
AGENT_HEADER = "x-monolith-agent-id"
TENANT_HEADER = "x-monolith-tenant-id"
SESSION_HEADER = "x-monolith-session-id"
TRACE_HEADER = "x-monolith-trace-id"
CORRELATION_HEADER = "x-monolith-correlation-id"

# HTTP statuses that mean "the dashboard will NEVER accept this event, retrying
# is pointless": bad request, bad credential, forbidden, too large, unprocessable.
# These events are dead-lettered (moved aside, not silently dropped) so a human
# can see them. Everything else (5xx, timeouts, 429) is transient and retried.
PERMANENT_HTTP_STATUSES = {400, 401, 403, 413, 422}


def now_ms() -> int:
    """Current wall-clock time in milliseconds since the Unix epoch.

    Used as the event's timestamp_ms and for retry scheduling. Simple, but it is
    the module's shared clock: every event and every outbox delay uses this.
    """
    return int(time.time() * 1000)


def _clean_id(value: Any) -> str | None:
    """Trim a correlation id, clamp it to 128 chars, and drop blanks.

    Correlation ids arrive from the agent via headers and are treated as
    untrusted input: a 5000-char session id must not reach the database. Returns
    None for anything that is not a usable string, which means "caller didn't
    tell us", which the envelope then treats as "unknown" (the field is omitted
    rather than sent as an empty string).
    """
    if not isinstance(value, str):
        return None
    trimmed = value.strip()[:MAX_ID_LENGTH]
    return trimmed or None


@dataclass(frozen=True)
class EventContext:
    """The correlation identity of ONE request, read from its headers.

    This is the "who is this detection about" bundle. It is passed along when a
    module emits an event so the event can be tied to the correct agent session.

    Fields:
      tenant_id:      which customer/tenant. Always set (defaults to "default").
      trace_id:       one logical operation (e.g. one retrieval). Auto-generated
                      as a UUID when the caller did not send one, so every
                      detection can be grouped even if the agent was sloppy.
      session_id:     one agent session. THE key field for cross-layer
                      correlation (the dashboard groups events by
                      tenant+agent+session).
      correlation_id: optional broader workflow id that spans sessions.
      agent_id:       which agent process.

    This object is created by context_from_headers() and consumed by
    EventEmitter.__call__(), which stamps it onto outgoing events.
    """

    tenant_id: str | None = None
    trace_id: str | None = None
    session_id: str | None = None
    correlation_id: str | None = None
    agent_id: str | None = None


def context_from_headers(headers: Mapping[str, str]) -> EventContext:
    """Build an EventContext from an incoming HTTP request's headers.

    Called from:
      - vector-anchor/src/main.py       -> retrieve() endpoint, for every /retrieve
      - trace-audit/src/main.py         -> generate() endpoint, for every /generate

    The agent framework that calls these endpoints is expected to send
    X-Monolith-Tenant-Id, X-Monolith-Agent-Id, X-Monolith-Session-Id, etc. Those
    headers are the ONLY link between a detection and the agent session it
    belongs to — which is the whole point of the correlation system.

    Data flow: agent headers -> this function -> EventContext -> EventEmitter ->
    event JSON -> dashboard Postgres -> session view in the UI.

    Note on trace_id: if the caller did not supply one, a fresh UUID is minted
    here, because "every detection should be groupable into some operation" is
    more useful than "this one belongs to no operation". session_id is NOT
    auto-generated: an invented session id would wrongly group unrelated agents
    together, and the grouping is the entire point of having one.
    """
    return EventContext(
        tenant_id=_clean_id(headers.get(TENANT_HEADER)),
        trace_id=_clean_id(headers.get(TRACE_HEADER)) or str(uuid.uuid4()),
        session_id=_clean_id(headers.get(SESSION_HEADER)),
        correlation_id=_clean_id(headers.get(CORRELATION_HEADER)),
        agent_id=_clean_id(headers.get(AGENT_HEADER)),
    )


class EventOutbox:
    """The durable local queue + background delivery thread.

    THIS IS THE HEART OF THE "NO LOST EVIDENCE" GUARANTEE.

    How it works, step by step:

    1. On startup the module creates one EventOutbox pointing at an on-disk
       SQLite file (e.g. /var/lib/monolith/outbox.db) and the dashboard's
       ingest URL + the module's bearer token.
    2. enqueue() is called whenever a detection happens. It INSERTs the event
       into SQLite (journal_mode=wal, so writes are crash-safe) and commits.
       Only then does the detection code continue.
    3. A daemon background thread (self._worker) loops forever calling
       flush_once(): it picks up to 16 due events, POSTs each to the dashboard,
       and classifies the result:
         - 2xx        -> event delivered, row deleted.
         - 4xx/413/422 -> the dashboard will never accept it -> status='dead'
                          (a "dead letter": kept for inspection, never retried).
         - anything else (5xx, timeout) -> schedule a retry with exponential
                          backoff (2^n seconds, capped at 5 min, plus jitter so
                          retrying modules don't all hit the dashboard at once).
       After 12 attempts an event is marked dead rather than retried forever.
    4. Bounds keep disk from filling: max 10,000 pending, 2,000 dead, dead
       entries pruned after 7 days. Overflowing pending events are dead-lettered
       with reason "outbox_capacity".

    The queue is NOT a message broker. It is a crash-safety buffer in front of
    the dashboard. The dashboard deduplicates redeliveries by event_id.
    """

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
        """Set up the SQLite queue and (by default) start the delivery thread.

        Args:
          path:      filesystem path of the SQLite file. Lives on a Docker volume
                     so it survives container restarts.
          url:       dashboard ingest URL, e.g. http://dashboard:3000/api/ingest
          token:     this module's bearer token (MONOLITH_EVENT_TOKEN). The
                     dashboard uses it to verify this module is who it claims.
          start_worker: False is used only in tests that want to drive
                     flush_once() manually.
        """
        if min(max_attempts, max_pending, max_dead, dead_retention_ms) < 1:
            raise ValueError("outbox limits must be positive")
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False: the main thread writes (enqueue) while the
        # background thread reads/delivers. SQLite is fine with this as long as
        # we serialize access with our own lock, which we do (self._lock).
        self._connection = sqlite3.connect(path, check_same_thread=False, timeout=1.0)
        # WAL journaling: readers don't block writers and a crash mid-write
        # cannot corrupt the DB. This is what makes the outbox "durable".
        self._connection.execute("pragma journal_mode = wal")
        # synchronous=normal still fsyncs at WAL checkpoints; fast enough here.
        self._connection.execute("pragma synchronous = normal")
        self._connection.execute("pragma busy_timeout = 1000")
        self._connection.execute(
            """create table if not exists event_outbox (
                event_id text primary key,      -- the event UUID; PK prevents dup rows
                payload blob not null,          -- the serialized event JSON
                attempts integer not null default 0,
                next_attempt_ms integer not null, -- when this row is allowed to be retried
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
                daemon=True,  # daemon: won't block module shutdown
            )
            self._worker.start()

    def _migrate_legacy_table(self) -> None:
        """Add created_ms/updated_ms to queues created by an older version.

        This is a tiny schema-upgrade shim: older outbox files predate these
        two columns, and the prune logic reads them. ALTER TABLE ADD COLUMN is
        cheap and idempotent.
        """
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
        """Durably store one event so the background thread can deliver it.

        Called from: EventEmitter.__call__() (below), which is in turn called by
        the detection code in retriever_proxy.py / stream_proxy.py.

        Insert-or-ignore: if the same event_id is somehow enqueued twice (e.g.
        a detection re-fired), we keep the first copy. The commit happens BEFORE
        enqueue() returns, which is the "fsynced before the detection path
        continues" guarantee. self._wake.set() pokes the delivery thread so it
        checks immediately instead of waiting for its 1-second poll.
        """
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
        """The delivery thread's main loop: flush, then sleep up to 1s.

        Runs forever as a daemon thread. If flush_once() throws for any reason,
        the worker records the error and keeps going — a delivery bug must never
        kill the detection module that owns the outbox.
        """
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
        """Deliver up to 16 due events to the dashboard in one pass.

        The 16-row batch keeps a single flush short (each POST has a 2s timeout)
        so a large backlog is worked through over several passes without
        blocking enqueue() for long.

        For each row: POST the payload with the bearer token. Then classify:
          - 2xx        -> delete the row (delivered).
          - permanent status (400/401/403/413/422) OR attempts exhausted
                         -> status='dead' with the reason.
          - otherwise  -> exponential backoff: delay = min(300s, 2^attempts s)
                          plus 0-1s of random jitter. Attempts persist across
                          module restarts because they live in the row.
        """
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
        """Keep the queue bounded: prune old dead rows, cap pending and dead.

        Runs after every write (enqueue and flush). If pending exceeds
        max_pending, the OLDEST pending events are marked dead with reason
        'outbox_capacity' (newest detections are the most actionable). If dead
        exceeds max_dead, the oldest dead rows are deleted outright.
        """
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
        """POST one event to the dashboard's /api/ingest endpoint.

        Uses Python's stdlib urllib (no extra dependency). The Authorization
        header carries this module's bearer token, which the dashboard checks
        via timing-safe comparison in dashboard/lib/ingest-auth.ts.

        Returns (http_status, error_text). HTTPError (4xx/5xx) is captured as a
        status code; network failures (dashboard unreachable) return status 0
        with the exception name — the caller treats 0 as transient and retries.
        """
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
        """Count pending/dead events and worker health.

        Called from: VectorAnchor/TraceAudit /stats routes -> surfaced in the
        dashboard's Operations page (dashboard/app/api/operations/route.ts reads
        the module /stats endpoints and shows delivery backlog / dead letters).
        """
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
        """Stop the delivery thread and close the database.

        Called from: EventEmitter.close() -> module shutdown (FastAPI lifespan
        finally block in main.py of both Python modules). The timeout means
        "wait up to 5s for the worker to finish its current flush"; if it is
        still alive after that, the caller knows delivery may be mid-flight
        (which is safe — the dashboard dedupes redeliveries).
        """
        self._stop.set()
        self._wake.set()
        if self._worker:
            self._worker.join(timeout=timeout)
            if self._worker.is_alive():
                raise TimeoutError("event outbox worker did not stop")
        with self._lock:
            self._connection.close()


class EventEmitter:
    """The object a module calls to emit a security event.

    This is the module's public interface to the whole delivery system. The
    module builds ONE emitter at startup (via make_emitter) and then calls it
    like a function:  emit("corpus_poison_quarantine", "critical", {...details}).

    Calling the emitter does three things:
      1. Builds the event JSON envelope (event_id, timestamp, module name,
         severity, details, tenant + correlation fields from the EventContext).
      2. Prints the JSON to stderr (so it is visible in container logs and
         testable without any dashboard).
      3. Enqueues it to the durable outbox for delivery to the dashboard.

    Emission NEVER blocks or throws: a full outbox degrades delivery, not
    detection. The detection path must never be able to fail because the
    dashboard is broken.
    """

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
        """Create the emitter. Called once per module at startup:
          - vector-anchor/src/main.py   -> make_emitter(MODULE_NAME, ...)
          - trace-audit/src/main.py     -> make_emitter(MODULE_NAME, ...)

        The tenant_id/agent_id/session_id here are the module's DEFAULTS (from
        environment: MONOLITH_TENANT_ID, MONOLITH_AGENT_ID, MONOLITH_SESSION_ID).
        A per-request EventContext (from headers) overrides them, which is how
        one long-running service serving many agents attributes each detection
        correctly. MCP-Shield (Rust) has no per-request context — one proxy
        invocation IS one session — so its equivalent lives in its env only.
        """
        self.module = module
        self.default_agent = _clean_id(agent_id)
        self.default_session = _clean_id(session_id)
        self.default_tenant = _clean_id(tenant_id) or "default"
        # If no dashboard URL+token are configured (e.g. pure-local module use),
        # the outbox is None and events only go to stderr.
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
        """Build + emit one event. This is what detection code actually calls.

        Callers (all via the module's `emit` object):
          - vector-anchor/src/retriever_proxy.py: "corpus_poison_quarantine"
            (critical, when a doc is quarantined), "retrieval" (info, every
            request, with query_sha256 instead of the raw query), "service_start".
          - trace-audit/src/stream_proxy.py: "reasoning_divergence_terminate"
            (critical), "pii_redacted" (warning), "service_start"/"service_stop".

        Envelope construction, field by field:
          event_id:       fresh UUIDv4 — the idempotency key for the dashboard's
                          `on conflict (event_id) do nothing` insert.
          schema_version: 2 (the current contract; the dashboard accepts 1 and 2).
          timestamp_ms:   module clock at detection time.
          module:         "vector-anchor" | "trace-audit" (set at construction).
          severity:       info | warning | critical.
          details:        arbitrary JSON the detector wants to record. NOTE: the
                          modules deliberately put SHA-256 hashes of query/doc
                          text here, never the raw text (PII hygiene).
          source:         "module" (as opposed to an operator action).
          tenant_id:      per-request ctx override, else module default.
          agent/session:  per-request ctx override, else module default; omitted
                          entirely if unknown (a null would falsely claim we
                          looked and found nothing).
          trace_id:       per-request ctx (auto-generated if absent).
          correlation_id: per-request ctx, omitted if unknown.

        Then the event is (1) printed to stderr as one JSON line and (2)
        enqueued. Any sqlite error is logged, never raised.
        """
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
        """Stop the delivery thread. Called during module shutdown (lifespan
        finally blocks in both Python modules' main.py)."""
        if self.outbox:
            self.outbox.close()

    def delivery_stats(self) -> dict[str, int | bool | str | None]:
        """Expose outbox health (pending/dead counts) to the /stats routes."""
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
    """Factory function: build an EventEmitter from environment-derived values.

    Called exactly once per Python module at startup:
      - vector-anchor/src/main.py  (lifespan, via load_config())
      - trace-audit/src/main.py    (lifespan, via load_config())

    This indirection exists so the module's main.py stays tidy: it passes config
    values straight through. The returned emitter is stored as `emit` on the
    module's app state / proxy and used for every event in that process.
    """
    return EventEmitter(
        module,
        dashboard_url,
        event_token,
        outbox_path,
        tenant_id=tenant_id,
        agent_id=agent_id,
        session_id=session_id,
    )
