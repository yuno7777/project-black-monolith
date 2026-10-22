"""Validate canonical fixtures and cross-service contract invariants."""

from __future__ import annotations

import json
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parent
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
    snapshot = validator("revocation-snapshot.v1.schema.json")

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

    # The revocation snapshot is the one body a module polls on a timer and
    # reads under a hard byte cap. Its contract is therefore not only "these
    # fields exist" but "the body stays inside what the reader can take", and
    # the two halves of that have to be checked here rather than trusted: a
    # snapshot that grew past the cap would reach a module truncated, fail to
    # parse, and leave it serving a session that was revoked a moment ago.
    snapshot.validate(load_json(FIXTURES / "revocation-snapshot.valid.json"))
    snapshot_fixture = load_json(FIXTURES / "revocation-snapshot.valid.json")

    # `revision` and `complete` are the two fields a module cannot do without:
    # the first says whether the set changed, the second says whether the body
    # is the whole set or a bounded prefix of it. A body missing either is one
    # a module would have to guess about, and a module that guesses is the
    # failure this snapshot exists to prevent.
    for required_field in ("revision", "complete"):
        without = {k: v for k, v in snapshot_fixture.items() if k != required_field}
        if snapshot.is_valid(without):
            raise AssertionError(
                f"revocation snapshot contract unexpectedly accepts a body without {required_field}"
            )

    # The bound is part of the contract, not an implementation detail: the
    # module's reader is what enforces it, and a body past the cap is a body
    # the reader cannot take.
    over_capacity = dict(snapshot_fixture)
    over_capacity["revoked_sessions"] = [f"session-{index}" for index in range(129)]
    if snapshot.is_valid(over_capacity):
        raise AssertionError("revocation snapshot contract unexpectedly accepts 129 entries")

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


if __name__ == "__main__":
    validate()
    print("contract schemas and fixtures: ok")
