"""Conservative first-hit indicators for instructions embedded in retrieved data.

This supplements frequency evidence; it is not a semantic injection classifier.
Quoted examples can trigger it. No text is copied into telemetry.
"""
from __future__ import annotations

import re
import unicodedata

_RULES = {
    "instruction_override": re.compile(
        r"\b(?:ignore|disregard|override|forget)\b.{0,60}\b(?:previous|prior|system|user|above)\b"
        r".{0,40}\b(?:instructions?|prompts?|rules?|requests?)\b", re.I),
    "credential_exfiltration": re.compile(
        r"\b(?:reveal|expose|exfiltrate|leak|upload|send)\b.{0,60}"
        r"\b(?:credentials?|secrets?|api[ _-]?keys?|passwords?|access[ _-]?tokens?)\b", re.I),
    "role_spoofing": re.compile(r"(?:<\|(?:im_start|start_header_id)\|>\s*system|\[SYSTEM\])", re.I),
}


def inspect_document(text: str) -> list[str]:
    # The API bounds document input. Bound scanning independently for callers
    # using the proxy directly, and withhold instead of silently ignoring tails.
    if len(text) > 100_000:
        return ["document_scan_limit"]
    normalized = "".join(c for c in unicodedata.normalize("NFKC", text)
                         if unicodedata.category(c) != "Cf")
    normalized = " ".join(normalized.split())
    return [name for name, pattern in _RULES.items() if pattern.search(normalized)]
