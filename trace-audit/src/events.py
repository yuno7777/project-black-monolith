"""Structured security-event emission for TraceAudit.

Emits the SAME event shape used by every Project Black Monolith module
(mcp-shield, VectorAnchor, TraceAudit), so the unified dashboard consumes all
three feeds uniformly:

    {
      "timestamp_ms": 1770000000000,
      "module": "trace-audit",
      "event_type": "reasoning_divergence_terminate",
      "severity": "critical",
      "details": { ... }
    }

Each event is written as a single JSON line to stderr and, if
MONOLITH_DASHBOARD_URL is set, additionally POSTed to the dashboard ingest
endpoint on a best-effort, fire-and-forget basis.

IMPORTANT: callers must redact PII/credentials BEFORE passing anything into
`details` — this module does not scrub payloads.
"""

from __future__ import annotations

import json
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Literal

Severity = Literal["info", "warning", "critical"]

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
        pass


def make_emitter(module: str, dashboard_url: str | None):
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
