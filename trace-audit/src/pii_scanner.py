"""Regex scanner for credential / PII-like patterns in streamed reasoning
tokens.

On a match, the caller redacts the matched span (see redaction.py) *before*
anything is logged, and emits an event. Patterns are intentionally conservative
to keep false positives low in a demo.

**Scope — read this before trusting it.** `stream_proxy` calls `scan()` on each
token in isolation, not on a rolling buffer, so a secret a tokenizer splits
across two tokens matches neither half and is missed. That is a real gap, it is
ordinary tokenizer behaviour rather than an attack, and it is measured in
`tests/test_evasion.py`. Closing it means scanning a sliding character window
with overlap; the patterns themselves are not the limitation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# (label, compiled pattern). Order matters only for reporting.
_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("openai_style_api_key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("generic_bearer_token", re.compile(r"\b[A-Za-z0-9_\-]{32,}\.[A-Za-z0-9_\-]{6,}\b")),
    ("email_address", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
    ("us_ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("credit_card", re.compile(r"\b(?:\d[ \-]?){13,16}\b")),
]


@dataclass
class PiiMatch:
    label: str
    start: int
    end: int
    value: str


def scan(text: str) -> list[PiiMatch]:
    """Return all PII/credential matches in ``text``."""
    matches: list[PiiMatch] = []
    for label, pattern in _PATTERNS:
        for m in pattern.finditer(text):
            matches.append(PiiMatch(label=label, start=m.start(), end=m.end(), value=m.group()))
    return matches
