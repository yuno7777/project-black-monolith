"""Structured security-event emission for VectorAnchor.

Emits the SAME event shape used by every Project Black Monolith module
(mcp-shield, VectorAnchor, TraceAudit), so the unified dashboard consumes all
three feeds uniformly:

    {
      "timestamp_ms": 1770000000000,
      "module": "vector-anchor",
      "event_type": "corpus_poison_quarantine",
      "severity": "critical",
      "details": { ... }
    }

Each event is written as a single JSON line to stderr and, if
MONOLITH_DASHBOARD_URL is set, additionally POSTed to the dashboard ingest
endpoint on a best-effort, fire-and-forget basis (a down dashboard never
affects retrieval).
"""

from __future__ import annotations

import json
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Literal

Severity = Literal["info", "warning", "critical"]

# Small pool so event forwarding never blocks the request path and never
# spawns unbounded threads under load.
_forwarder = ThreadPoolExecutor(max_workers=2, thread_name_prefix="event-forward")


def now_ms() -> int:
    return int(time.time() * 1000)


def _post(url: str, payload: bytes) -> None:
    try:
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=2).close()
    except Exception:
        # Best-effort only: the dashboard being unreachable is not an error.
        pass


def make_emitter(module: str, dashboard_url: str | None):
    """Return an ``emit(event_type, severity, details)`` function bound to a
    module name and optional dashboard endpoint."""

    def emit(event_type: str, severity: Severity, details: dict[str, Any]) -> None:
        event = {
            "timestamp_ms": now_ms(),
            "module": module,
            "event_type": event_type,
            "severity": severity,
            "details": details,
        }
        line = json.dumps(event)
        print(line, file=sys.stderr, flush=True)
        if dashboard_url:
            _forwarder.submit(_post, dashboard_url, line.encode("utf-8"))

    return emit
