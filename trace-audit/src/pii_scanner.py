"""Regex scanner for credential / PII-like patterns in streamed reasoning
tokens.

On a match, the caller redacts the matched span (see redaction.py) *before*
anything is logged, and emits an event. Patterns are intentionally conservative
to keep false positives low in a demo.

**Scope — read this before trusting it.** `scan()` operates on one supplied
string. `stream_proxy.PiiStreamBuffer` concatenates and delays up to 16 output
tokens before calling it, so ordinary two- or few-token credential splits are
redacted before any fragment is released. More than 16 adversarial fragments
can still outlive that bounded window; the measured boundary is pinned in
`tests/test_evasion.py`.
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
    ("credit_card", re.compile(r"\b(?:\d[ \-]?){13,19}\b")),
]


@dataclass
class PiiMatch:
    label: str
    start: int
    end: int
    value: str


def _valid_card_number(value: str) -> bool:
    digits = [int(character) for character in value if character.isdigit()]
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def scan(text: str) -> list[PiiMatch]:
    """Return all PII/credential matches in ``text``."""
    matches: list[PiiMatch] = []
    for label, pattern in _PATTERNS:
        for m in pattern.finditer(text):
            if label == "credit_card" and not _valid_card_number(m.group()):
                continue
            matches.append(PiiMatch(label=label, start=m.start(), end=m.end(), value=m.group()))
    return matches
