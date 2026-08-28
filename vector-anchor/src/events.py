"""Compatibility import for the shared monolith-events package.

WHAT THIS FILE IS
-----------------
A thin re-export shim, NOT a copy of the outbox. The real event delivery code
lives in python-common/monolith_events/events.py (one shared implementation for
both Python modules). This file lets VectorAnchor's source code write
`from .events import make_emitter` and get that shared implementation:

  - If the `monolith_events` package is installed/importable (e.g. the CI job
    for this module, which installs python-common), it imports straight from it.
  - Otherwise (e.g. running the module standalone from its own directory) it
    temporarily adds python-common/ to sys.path and imports from there. Either
    way, the SAME single implementation is used — there is no duplicated code
    to drift.

WHY THE SHIM EXISTS
-------------------
The module's imports (main.py, retriever_proxy.py) were written against
`from .events import ...`, so this file keeps that import path working without
forcing a package install step on a bare module checkout.

Everything this file exports is the API of python-common/monolith_events/
events.py — see that file for the full explanation of each symbol.
"""

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
