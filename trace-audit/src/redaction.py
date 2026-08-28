"""Redaction of matched PII/credential spans.

WHAT THIS FILE IS
-----------------
The "replace with placeholder" step of the PII pipeline. Given a text and a
list of matches (from pii_scanner.scan), it replaces each matched span with a
typed placeholder like [REDACTED:aws_access_key_id] — so the reader knows WHAT
was redacted without seeing the secret.

WHY IT EXISTS / WHY "BEFORE ANYTHING IS LOGGED"
-----------------------------------------------
The whole point is that a secret must never be persisted in the clear. The
redaction happens on the token stream BEFORE the token is forwarded to the
agent, before the event emitter writes anything, and before any logging. That
ordering is the guarantee: the only place the plaintext exists is transiently
inside the PiiStreamBuffer.

Note: stream_proxy.py implements its own inline redaction
(PiiStreamBuffer._redact_matches) that operates on the buffered token
fragments. This file is the simpler whole-string version — it is used by tests
and by redact_all(), and it is the reference implementation of the
right-to-left splice logic.
"""

from __future__ import annotations

from .pii_scanner import PiiMatch


def redact(text: str, matches: list[PiiMatch]) -> str:
    """Replace each matched span with a typed placeholder, e.g.
    ``[REDACTED:aws_access_key_id]``. Non-overlapping matches are applied
    right-to-left so earlier offsets stay valid.

    Step by step:
      1. No matches -> return the text unchanged.
      2. Sort matches by start position DESCENDING (rightmost first). If we
         replaced left-to-right, each replacement would shift the offsets of
         every match to its right.
      3. For each match (skipping any that overlaps one already applied —
         defensive), splice the placeholder into the string at [start, end).
      4. Track last_start so overlapping matches are skipped.
    """
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
    """Convenience: scan and redact in one call. Used by tests and the
    fixtures; the live streaming path uses the buffer + inline redaction in
    stream_proxy.py instead."""
    from .pii_scanner import scan

    return redact(text, scan(text))
