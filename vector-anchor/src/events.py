"""Compatibility import for the shared monolith-events package."""

from __future__ import annotations

import sys
from pathlib import Path

try:
    from monolith_events.events import (
        AGENT_HEADER,
        CORRELATION_HEADER,
        MAX_ID_LENGTH,
        SESSION_HEADER,
        TENANT_HEADER,
        TRACE_HEADER,
        EventContext,
        EventEmitter,
        EventOutbox,
        Severity,
        _clean_id,
        context_from_headers,
        make_emitter,
        now_ms,
    )
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "python-common"))
    from monolith_events.events import (  # type: ignore[no-redef]
        AGENT_HEADER,
        CORRELATION_HEADER,
        MAX_ID_LENGTH,
        SESSION_HEADER,
        TENANT_HEADER,
        TRACE_HEADER,
        EventContext,
        EventEmitter,
        EventOutbox,
        Severity,
        _clean_id,
        context_from_headers,
        make_emitter,
        now_ms,
    )

__all__ = [
    "AGENT_HEADER",
    "CORRELATION_HEADER",
    "MAX_ID_LENGTH",
    "SESSION_HEADER",
    "TENANT_HEADER",
    "TRACE_HEADER",
    "EventContext",
    "EventEmitter",
    "EventOutbox",
    "Severity",
    "_clean_id",
    "context_from_headers",
    "make_emitter",
    "now_ms",
]
