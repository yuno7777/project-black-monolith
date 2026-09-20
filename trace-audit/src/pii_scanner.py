"""Regex scanner for credential / PII-like patterns in streamed reasoning
tokens.

On a match, the caller redacts the matched span (see redaction.py) *before*
anything is logged, and emits an event. Patterns are intentionally conservative
to keep false positives low in a demo.

**Scope — read this before trusting it.** `scan()` operates on one supplied
string. `stream_proxy.PiiStreamBuffer` uses a 256-character look-behind
independent of fragment count and retains incomplete candidate matches.
Overlong unbroken candidates are withheld, which can redact benign long IDs.
This is a pattern detector, not a guarantee against arbitrary encodings.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass

# (label, compiled pattern). Order matters only for reporting.
_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("aws_access_key_id", re.compile(r"AKIA[0-9A-Z]{16}\b")),
    ("openai_style_api_key", re.compile(r"sk-[A-Za-z0-9]{20,}\b")),
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


def _scan_plain(text: str) -> list[PiiMatch]:
    """Return all PII/credential matches in ``text``."""
    # Normalize compatibility glyphs and remove format-control obfuscation,
    # retaining a mapping so redaction always removes the original characters.
    normalized = []
    offsets = []
    for index, character in enumerate(text):
        if unicodedata.category(character) == "Cf":
            continue
        for value in unicodedata.normalize("NFKC", character):
            normalized.append(value)
            offsets.append(index)
    candidate = "".join(normalized)
    matches: list[PiiMatch] = []
    patterns = _PATTERNS + [
        ("aws_access_key_id", re.compile(r"A\s{0,3}K\s{0,3}I\s{0,3}A(?:\s{0,3}[0-9A-Z]){16}\b"))
    ]
    seen = set()
    for label, pattern in patterns:
        for m in pattern.finditer(candidate):
            if label == "credit_card" and not _valid_card_number(m.group()):
                continue
            start, end = offsets[m.start()], offsets[m.end() - 1] + 1
            if (label, start, end) in seen:
                continue
            seen.add((label, start, end))
            matches.append(PiiMatch(label=label, start=start, end=end, value=text[start:end]))
    return matches


# Decode one bounded layer only. Never recursively expand attacker-controlled
# text, and redact the entire original atom instead of leaking encoded tails.
_MAX_ENCODED_CHARS = 4096
_ENCODED_ATOMS = (
    ("percent", re.compile(r"(?:%[0-9A-Fa-f]{2}|[A-Za-z0-9_.~-]){12,}")),
    ("hex", re.compile(r"(?<![A-Za-z0-9])(?:0x)?[0-9a-fA-F]{20,}(?![A-Za-z0-9])")),
    ("base64", re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")),
)


def scan(text: str) -> list[PiiMatch]:
    """Scan plain text and bounded, single-layer encoded credential atoms."""
    matches = _scan_plain(text)
    for encoding, pattern in _ENCODED_ATOMS:
        for atom in pattern.finditer(text):
            value = atom.group()
            if len(value) > _MAX_ENCODED_CHARS:
                continue  # The streaming buffer separately withholds long runs.
            try:
                if encoding == "percent":
                    if "%" not in value:
                        continue
                    decoded = urllib.parse.unquote_to_bytes(value).decode("utf-8")
                elif encoding == "hex":
                    decoded = bytes.fromhex(value.removeprefix("0x")).decode("utf-8")
                else:
                    decoded = base64.b64decode(
                        value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
                    ).decode("utf-8")
            except (ValueError, UnicodeError, binascii.Error):
                continue
            findings = _scan_plain(decoded)
            if findings:
                matches.append(
                    PiiMatch(
                        label=f"encoded_{encoding}_{findings[0].label}",
                        start=atom.start(),
                        end=atom.end(),
                        value=value,
                    )
                )
    return matches
