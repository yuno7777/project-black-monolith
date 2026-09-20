"""Conservative first-hit indicators for instructions embedded in retrieved data.

Rules are designed against a pinned development split. The separate pinned test
split is never used to change them. Matches supplement frequency evidence and
quoted examples can trigger them. No source text is copied into telemetry.
"""

from __future__ import annotations

import re
import unicodedata

_OVERRIDE = (
    r"ignore|disregard|override|forget|abandon|drop|leave|erase|change|"
    r"ignoriere|ignorieren|vergiss|vergessen|verlassen|stopp|abweichend|"
    r"olvida|olvide|olvidar|oubliez|zaboravi|забудьте"
)
_PRIOR = (
    r"previous|preceding|prior|above|before|earlier|all|system|user|instructions?|rules?|orders?|tasks?|"
    r"vorherigen|vorangehenden|bisherigen|obigen|alles|aufträge|aufgaben|informationen|"
    r"anteriores|antes|instrucciones|todas|tous|toutes|précédentes|instruktionen|instrukcije"
)
_ACTION = (
    r"say|output|print|write|repeat|show|reveal|copy|answer|respond|"
    r"sag|sage|schreib|schreibe|zeige|ausgeben|antwort|"
    r"di|decir|imprime|escribe|dites|écrivez"
)

_RULES = {
    "instruction_override": re.compile(rf"\b(?:{_OVERRIDE})\b.{{0,90}}\b(?:{_PRIOR})\b", re.I),
    "forced_response": re.compile(
        rf"\b(?:just|only|instead|stattdessen|nur|einfach|solo|sólo)\b.{{0,60}}\b(?:{_ACTION})\b|"
        rf"\b(?:{_ACTION})\b.{{0,45}}(?:exact(?:ly)?|folgend(?:e|es)|the following|nur|only)",
        re.I,
    ),
    "prompt_disclosure": re.compile(
        r"\b(?:show|reveal|copy|display|repeat|zeige|zeig|vorzeigen)\b.{0,60}"
        r"\b(?:full|entire|all|complete|gesamten?|sämtlichen?)?\s*"
        r"(?:system\s+)?(?:prompts?|instructions?|prompt[- ]?texte?|anweisungen)\b",
        re.I,
    ),
    "credential_exfiltration": re.compile(
        r"\b(?:reveal|expose|exfiltrate|leak|upload|send)\b.{0,60}"
        r"\b(?:credentials?|secrets?|api[ _-]?keys?|passwords?|access[ _-]?tokens?)\b",
        re.I,
    ),
    "role_spoofing": re.compile(
        r"(?:<\|(?:im_start|start_header_id)\|>\s*system|\[SYSTEM\])", re.I
    ),
}


def inspect_document(text: str) -> list[str]:
    if len(text) > 100_000:
        return ["document_scan_limit"]
    normalized = "".join(
        c for c in unicodedata.normalize("NFKC", text) if unicodedata.category(c) != "Cf"
    )
    normalized = " ".join(normalized.split())
    return [name for name, pattern in _RULES.items() if pattern.search(normalized)]
