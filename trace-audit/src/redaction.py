"""Redaction of matched PII/credential spans.

Redaction happens before any logging or event emission so a secret that
appeared in the model's reasoning trace is never persisted in the clear.
"""

from __future__ import annotations

from .pii_scanner import PiiMatch


def redact(text: str, matches: list[PiiMatch]) -> str:
    """Replace each matched span with a typed placeholder, e.g.
    ``[REDACTED:aws_access_key_id]``. Non-overlapping matches are applied
    right-to-left so earlier offsets stay valid."""
    if not matches:
        return text
    ordered = sorted(matches, key=lambda m: m.start, reverse=True)
    out = text
    last_start = len(text) + 1
    for m in ordered:
        # Skip a match that overlaps one already applied (defensive).
        if m.end > last_start:
            continue
        out = out[: m.start] + f"[REDACTED:{m.label}]" + out[m.end :]
        last_start = m.start
    return out


def redact_all(text: str) -> str:
    """Convenience: scan and redact in one call."""
    from .pii_scanner import scan

    return redact(text, scan(text))
