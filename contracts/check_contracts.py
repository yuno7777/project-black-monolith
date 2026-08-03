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

    event.validate(load_json(FIXTURES / "event-envelope.valid.json"))
    vector.evolve(schema={"$ref": "#/$defs/retrieveRequest"}).validate(
        load_json(FIXTURES / "vector-retrieve-request.valid.json")
    )
    vector.evolve(schema={"$ref": "#/$defs/retrieveResponse"}).validate(
        load_json(FIXTURES / "vector-retrieve-response.valid.json")
    )
    trace.evolve(schema={"$ref": "#/$defs/generateRequest"}).validate(
        load_json(FIXTURES / "trace-generate-request.valid.json")
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


if __name__ == "__main__":
    validate()
    print("contract schemas and fixtures: ok")
