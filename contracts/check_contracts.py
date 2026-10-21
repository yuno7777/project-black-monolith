"""Validate canonical fixtures and cross-service contract invariants."""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent
SCHEMAS = ROOT / "schemas"
FIXTURES = ROOT / "fixtures"


def load_json(path: Path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def validator(name: str) -> Draft202012Validator:
    schema = load_json(SCHEMAS / name)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def validate() -> None:
    event = validator("event-envelope.v2.schema.json")
    vector = validator("vector-anchor-api.v1.schema.json")
    trace = validator("trace-audit-api.v1.schema.json")
    benchmark = validator("benchmark-run.v1.schema.json")

    event.validate(load_json(FIXTURES / "event-envelope.valid.json"))
    # The Secret Boundary emits the same envelope under a different
    # event_type, with a `details.subsystem` discriminator. It must satisfy
    # the same contract: a new event type is not a new envelope.
    event.validate(load_json(FIXTURES / "event-envelope.secret-boundary.valid.json"))
    # Same rule for event types added by the production upgrades: the
    # envelope schema is intentionally open on `event_type`, so each new
    # detection gets a fixture to prove its real shape still conforms.
    event.validate(load_json(FIXTURES / "event-envelope.tool-call-argument-flagged.valid.json"))
    event.validate(load_json(FIXTURES / "event-envelope.upstream-stream-error.valid.json"))
    vector.evolve(schema={"$ref": "#/$defs/retrieveRequest"}).validate(
        load_json(FIXTURES / "vector-retrieve-request.valid.json")
    )
    retrieve_response = vector.evolve(schema={"$ref": "#/$defs/retrieveResponse"})
    retrieve_response.validate(load_json(FIXTURES / "vector-retrieve-response.valid.json"))
    retrieve_response.validate(
        load_json(FIXTURES / "vector-retrieve-response.session-quarantined.valid.json")
    )
    vector.evolve(schema={"$ref": "#/$defs/quarantineResponse"}).validate(
        load_json(FIXTURES / "vector-quarantine-response.valid.json")
    )
    trace.evolve(schema={"$ref": "#/$defs/generateRequest"}).validate(
        load_json(FIXTURES / "trace-generate-request.valid.json")
    )
    trace.evolve(schema={"$ref": "#/$defs/chatCompletionRequest"}).validate(
        load_json(FIXTURES / "trace-chat-completion-request.valid.json")
    )
    trace.evolve(schema={"$ref": "#/$defs/chatCompletionResponse"}).validate(
        load_json(FIXTURES / "trace-chat-completion-response.valid.json")
    )
    trace.evolve(schema={"$ref": "#/$defs/chatCompletionChunk"}).validate(
        load_json(FIXTURES / "trace-chat-completion-chunk.valid.json")
    )
    stream_validator = trace.evolve(schema={"$ref": "#/$defs/streamEvent"})
    for stream_event in load_json(FIXTURES / "trace-stream-events.valid.json"):
        stream_validator.validate(stream_event)
    benchmark.validate(load_json(FIXTURES / "benchmark-run.valid.json"))

    # Public input is deliberately named `k`; ChromaDB's internal
    # `n_results` parameter must never leak into the API contract.
    retrieve = load_json(FIXTURES / "vector-retrieve-request.valid.json")
    legacy = {"query": retrieve["query"], "n_results": retrieve["k"]}
    if vector.evolve(schema={"$ref": "#/$defs/retrieveRequest"}).is_valid(legacy):
        raise AssertionError("VectorAnchor contract unexpectedly accepts n_results")

    with (ROOT / "openapi.yaml").open(encoding="utf-8") as handle:
        openapi = yaml.safe_load(handle)
    if openapi.get("openapi") != "3.1.0":
        raise AssertionError("OpenAPI document must use 3.1.0 for JSON Schema 2020-12")
    required_headers = {
        "x-monolith-tenant-id",
        "x-monolith-agent-id",
        "x-monolith-session-id",
        "x-monolith-trace-id",
        "x-monolith-correlation-id",
    }
    declared_headers = {
        parameter["name"]
        for parameter in openapi["components"]["parameters"].values()
    }
    if declared_headers != required_headers:
        raise AssertionError("OpenAPI correlation headers drifted")
    # The security surface is the endpoint list: a new analyzer endpoint that
    # never reaches the contract is one nobody can review from one place.
    required_paths = {
        "/retrieve",
        "/admin/add-documents",
        "/quarantine",
        "/quarantine/{doc_id}",
        "/generate",
        "/v1/chat/completions",
        "/admin/reload-baseline",
        "/admin/replay-dead-letters",
        "/api/ingest",
        "/api/benchmarks",
        "/api/operations",
        "/api/incidents/{eventId}/session",
    }
    missing_paths = required_paths - set(openapi.get("paths", {}))
    if missing_paths:
        raise AssertionError(f"OpenAPI is missing documented endpoints: {sorted(missing_paths)}")

    check_event_vocabulary()


# ---------------------------------------------------------------------------
# The event vocabulary
#
# The envelope schema is deliberately open on `event_type`: a new detection
# must not need a schema change, so there is no enumeration to check against.
# That leaves the list of event types themselves unchecked, and the
# dashboard's headline number is only as good as that list — a type nobody
# classified is a finding the console does not count, which is the defect
# this check exists to stop.
#
# So the list is checked here, against the layers that emit. A layer that
# starts emitting a type the dashboard has not classified fails the build.

#: The source trees that emit events, and the dashboard's classification of
#: them. The dashboard's file is TypeScript because the dashboard is what
#: counts by it, and the dashboard's container holds nothing outside its own
#: directory.
LAYER_TREES = (
    "mcp-shield/src",
    "crates/pbm-secret-boundary/src",
    "trace-audit/src",
    "vector-anchor/src",
)
VOCABULARY_PATH = REPO / "dashboard" / "lib" / "event-classification.ts"
DOC_PATH = REPO / "docs" / "EVENT_TYPES.md"

# A literal event type in an emission position. Rust has three forms — the
# emitter call, the struct field, and the secret boundary's
# (type, severity, outcome) tuple — and Python has the emitter call.
_RUST_TYPE = r'"([a-z][a-z0-9_]*)"'
RUST_PATTERNS = (
    re.compile(r"\b(?:events::)?emit(?:_traced)?\(\s*" + _RUST_TYPE),
    re.compile(r"\bevent_type:\s*" + _RUST_TYPE),
    re.compile(r"\(\s*" + _RUST_TYPE + r"\s*,\s*Severity::"),
)
PYTHON_PATTERNS = (re.compile(r"\bemit\(\s*" + _RUST_TYPE),)

# The emission sites whose event type has to be a literal, so that the scan
# above can see it. A call that names its type through some other variable
# is invisible to the scan, and an invisible type is an uncounted detection.
# A type named `event_type` is the one exception: it is a type the layer
# built earlier and is only handing on, and the scan saw it when it was
# built.
RUST_CALL_SITES = re.compile(r"\b(?:crate::)?events::emit(?:_traced)?\(\s*([^,)]*)")
PYTHON_CALL_SITES = re.compile(r"\bemit\(\s*([^,)]*)")

#: One line of the dashboard's classification list.
VOCABULARY_ENTRY = re.compile(r'^"([a-z][a-z0-9_]*)":\s*"(detection|operational|lifecycle)",?$')


def strip_comments(text: str, line_comment: str) -> str:
    """Remove comments, cheaply and in the safe direction.

    A comment marker inside a string literal cuts the rest of its line, so a
    real emission site can be hidden. It can never invent one, and inventing
    one is the direction that would fail the build for the wrong reason.
    """
    out = []
    for line in text.splitlines():
        index = line.find(line_comment)
        out.append(line if index < 0 else line[:index])
    return "\n".join(out)


def read_vocabulary(path: Path) -> dict[str, str]:
    """Read the event types the dashboard classifies, and their class.

    The list is TypeScript, so it is read out of a single object literal
    with a strict line shape. A change the reader cannot parse fails the
    build rather than passing it silently.
    """
    if not path.is_file():
        raise AssertionError(f"the event vocabulary is missing: {path}")
    text = path.read_text(encoding="utf-8")
    start = text.find("export const EVENT_CLASSES")
    if start < 0:
        raise AssertionError(f"{path} has no EVENT_CLASSES list")
    open_brace = text.find("{", start)
    depth = 0
    end = -1
    for index in range(open_brace, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                end = index
                break
    if end < 0:
        raise AssertionError(f"{path}: the EVENT_CLASSES list is not closed")
    vocabulary: dict[str, str] = {}
    for raw in text[open_brace + 1 : end].splitlines():
        line = raw.strip()
        if not line or line.startswith("//"):
            continue
        match = VOCABULARY_ENTRY.match(line)
        if not match:
            raise AssertionError(f"{path}: unreadable line in EVENT_CLASSES: {line!r}")
        vocabulary[match.group(1)] = match.group(2)
    if not vocabulary:
        raise AssertionError(f"{path}: the EVENT_CLASSES list is empty")
    return vocabulary


def scan_layer_event_types() -> tuple[dict[str, set[str]], list[str]]:
    """Every event type the layers can emit, and the sites that hide one.

    The second return value is the emission sites whose type is not a
    literal. A site the scan cannot read is a type the scan cannot check,
    so it is reported rather than ignored.
    """
    found: dict[str, set[str]] = {}
    unverifiable: list[str] = []
    for tree in LAYER_TREES:
        base = REPO / tree
        if not base.is_dir():
            raise AssertionError(f"the layer tree {tree} is missing")
        for path in sorted(base.rglob("*")):
            if path.suffix not in (".rs", ".py"):
                continue
            relative = str(path.relative_to(REPO))
            raw = path.read_text(encoding="utf-8", errors="replace")
            if path.suffix == ".rs":
                text = strip_comments(re.sub(r"/\*.*?\*/", " ", raw, flags=re.S), "//")
                patterns = RUST_PATTERNS
                call_sites = RUST_CALL_SITES
            else:
                text = strip_comments(raw, "#")
                patterns = PYTHON_PATTERNS
                call_sites = PYTHON_CALL_SITES
            for pattern in patterns:
                for match in pattern.finditer(text):
                    found.setdefault(match.group(1), set()).add(relative)
            for match in call_sites.finditer(text):
                argument = match.group(1).strip()
                if argument.startswith('"') or argument.endswith("event_type"):
                    continue
                unverifiable.append(f"{relative}: {match.group(0).strip()[:60]}")
    return found, unverifiable


def check_event_vocabulary() -> None:
    """Every event type a layer emits must be classified, and documented."""
    vocabulary = read_vocabulary(VOCABULARY_PATH)
    emitted, unverifiable = scan_layer_event_types()

    unclassified = sorted(set(emitted) - set(vocabulary))
    if unclassified:
        raise AssertionError(
            "these event types are emitted but not classified, so the console "
            "will not count them as detections: "
            + ", ".join(unclassified)
            + f" -- add each to EVENT_CLASSES in {VOCABULARY_PATH.relative_to(REPO)}"
        )

    if unverifiable:
        raise AssertionError(
            "these emission sites do not name their event type literally, so "
            "the vocabulary cannot be checked against them: "
            + "; ".join(sorted(unverifiable))
        )

    if not DOC_PATH.is_file():
        raise AssertionError(f"the event vocabulary is not documented: {DOC_PATH}")
    documented = read_documented_types(DOC_PATH)
    missing = sorted(set(vocabulary) - set(documented))
    if missing:
        raise AssertionError(
            "these event types are classified but not documented: "
            + ", ".join(missing)
            + f" -- add each to {DOC_PATH.relative_to(REPO)}"
        )
    wrong = sorted(
        f"{name} (documented as {documented[name]}, classified as {vocabulary[name]})"
        for name in vocabulary
        if name in documented and documented[name] != vocabulary[name]
    )
    if wrong:
        raise AssertionError(
            "these event types are documented with a different class: " + "; ".join(wrong)
        )


def read_documented_types(path: Path) -> dict[str, str]:
    """Read the documented event types and their class out of the table.

    The table's shape is the contract with the check: one row per event
    type, the type in the first column, the class in the second.
    """
    documented: dict[str, str] = {}
    row = re.compile(r"^\|\s*`([a-z][a-z0-9_]*)`\s*\|\s*(detection|operational|lifecycle)\s*\|")
    for line in path.read_text(encoding="utf-8").splitlines():
        match = row.match(line)
        if match:
            documented[match.group(1)] = match.group(2)
    return documented


if __name__ == "__main__":
    validate()
    print("contract schemas, fixtures and event vocabulary: ok")
