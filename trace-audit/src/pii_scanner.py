"""Regex scanner for credential / PII-like patterns in streamed reasoning
tokens.

WHAT THIS FILE IS
-----------------
TraceAudit's second detector: a pattern scanner that recognizes things that
look like credentials or personal data — AWS keys, API keys, bearer tokens,
emails, US SSNs, credit card numbers — inside the model's raw output stream.

WHY THE "SCOPE" WARNING MATTERS
-------------------------------
`scan()` operates on ONE supplied string. By itself it would miss a credential
the tokenizer split across two tokens. That is why stream_proxy.PiiStreamBuffer
concatenates and delays up to 16 output tokens before calling scan() — so
ordinary two- or few-token credential splits are redacted before any fragment
is released. More than 16 adversarial fragments can still outlive that bounded
window; the measured boundary is pinned in tests/test_evasion.py. Say this
honestly in an interview: the scanner is pattern-based and window-bounded, not
an omnipotent secret filter.

WHY THE Luhn CHECK EXISTS (precision)
------------------------------------
The credit-card pattern is intentionally broad (13-19 digits), so a 16-digit
shipment tracking number would false-positive. The Luhn checksum is a
standard last-digit validation that real card numbers pass and random digit
strings usually fail — it is what keeps the PII corpus's card-shaped tracking
number from being over-matched (EVALUATION.md reports this).

Called from: stream_proxy.py PiiStreamBuffer._matches_ending_in_latest()
(per buffered suffix) and _leaked_secrets() (prompt scanning for the mock).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# (label, compiled pattern). Order matters only for reporting.
# Patterns are intentionally conservative to keep false positives low.
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
    """One finding: which pattern (label), where in the scanned text
    (start/end, used by the redaction logic), and the matched value (used only
    transiently for the redaction placeholder / dedupe fingerprint — the
    plaintext is never logged or persisted)."""

    label: str
    start: int
    end: int
    value: str


def _valid_card_number(value: str) -> bool:
    """Luhn checksum: the standard last-digit validation for card numbers.

    Step by step:
      1. Keep only digits; reject unless 13-19 of them (and not all identical
         — "1111..." would trivially pass the checksum).
      2. From the rightmost digit, double every second digit; if doubling
         exceeds 9, subtract 9.
      3. Sum everything; valid iff the sum ends in 0.
    """
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
    """Return all PII/credential matches in ``text``.

    Called from:
      - stream_proxy.py PiiStreamBuffer (per candidate suffix) — the real
        detection path,
      - stream_proxy.py _leaked_secrets (on the prompt, to seed the mock),
      - tests.

    Iterates every pattern over the text; the credit-card pattern is filtered
    through the Luhn check before it counts as a match.
    """
    matches: list[PiiMatch] = []
    for label, pattern in _PATTERNS:
        for m in pattern.finditer(text):
            if label == "credit_card" and not _valid_card_number(m.group()):
                continue
            matches.append(PiiMatch(label=label, start=m.start(), end=m.end(), value=m.group()))
    return matches
