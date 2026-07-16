"""Durable, non-blocking security-event delivery for TraceAudit."""

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
from pathlib import Path
from typing import Any, Literal

Severity = Literal["info", "warning", "critical"]


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
):
    outbox = EventOutbox(outbox_path, dashboard_url, event_token) if dashboard_url and event_token else None

    def emit(event_type: str, severity: Severity, details: dict[str, Any]) -> None:
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
        line = json.dumps(event, separators=(",", ":"))
        print(line, file=sys.stderr, flush=True)
        if outbox:
            try:
                outbox.enqueue(event["event_id"], line.encode("utf-8"))
            except sqlite3.Error as error:
                print(f"event outbox enqueue failed: {error}", file=sys.stderr, flush=True)

    return emit
