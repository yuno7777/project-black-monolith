"""Validate canonical fixtures and cross-service contract invariants.

WHAT THIS FILE IS
-----------------
The CI "contract gate". The whole project stands on the promise that all four
sides of the shared event contract agree: the JSON Schema (contracts/schemas/),
the Python emitter (python-common/), the Rust emitter (mcp-shield/src/events.rs),
and the TypeScript types (dashboard/lib/types.ts). This script can't read code,
but it CAN check the two things that are machine-checkable:

  1. Every schema is valid JSON Schema (2020-12) and every canonical fixture
     payload validates against it — so the shapes the modules are tested
     against are the shapes the dashboard accepts.
  2. The OpenAPI document's correlation headers have not drifted — the five
     X-Monolith-* headers the modules read (python-common header constants)
     must be exactly the five declared in contracts/openapi.yaml.

It also pins two API-surface decisions:
  - the VectorAnchor /retrieve input field is named `k` (public), and
    ChromaDB's internal `n_results` must NEVER leak into the contract
    (an assertion actively rejects a legacy payload using n_results);
  - the OpenAPI document must be 3.1.0 (needed for JSON Schema 2020-12).

Called from: CI (contracts job in .github/workflows/ci.yml) and locally:
  python contracts/check_contracts.py
"""

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
    """Load a schema file and construct a validating object. FormatChecker
    enables format keywords (e.g. "uuid")."""
    schema = load_json(SCHEMAS / name)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def validate() -> None:
    # Load all four schemas.
    event = validator("event-envelope.v2.schema.json")
    vector = validator("vector-anchor-api.v1.schema.json")
    trace = validator("trace-audit-api.v1.schema.json")
    benchmark = validator("benchmark-run.v1.schema.json")

    # Validate the canonical fixtures against the relevant subschemas.
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

    # OpenAPI checks: version and exact correlation-header set.
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
