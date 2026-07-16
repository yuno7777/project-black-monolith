"""Correlation identity on the shared event envelope.

Imports only src.events, which is stdlib-only — no ChromaDB or FastAPI needed.
Run from the module root: python -m pytest tests/
"""

import json

from src.events import (
    MAX_ID_LENGTH,
    EventContext,
    _clean_id,
    context_from_headers,
    make_emitter,
)


def emit_once(capsys, ctx=None, **kwargs):
    """Emit one event with delivery disabled and return the parsed envelope.

    With no dashboard URL the emitter builds no outbox, so this exercises the
    envelope without a spool or a network.
    """
    emit = make_emitter("vector-anchor", None, None, "unused.db", **kwargs)
    emit("retrieval", "info", {"query": "x"}, ctx)
    return json.loads(capsys.readouterr().err.strip())


def test_unknown_correlation_fields_are_omitted_not_nulled(capsys):
    # Absence means "nobody told us"; a null would assert "belongs to no
    # session". The dashboard groups by session, so the difference matters.
    event = emit_once(capsys)
    for field in ("agent_id", "session_id", "trace_id", "correlation_id"):
        assert field not in event


def test_process_defaults_are_stamped_on_every_event(capsys):
    event = emit_once(capsys, agent_id="demo-agent", session_id="session-1")
    assert event["agent_id"] == "demo-agent"
    assert event["session_id"] == "session-1"


def test_request_context_overrides_process_defaults(capsys):
    # One service serves many agents: whoever is calling right now wins over
    # whatever the process was configured with.
    event = emit_once(
        capsys,
        ctx=EventContext(session_id="caller-session", agent_id="caller-agent"),
        agent_id="demo-agent",
        session_id="session-1",
    )
    assert event["session_id"] == "caller-session"
    assert event["agent_id"] == "caller-agent"


def test_context_falls_back_per_field(capsys):
    # A caller that supplies only a trace must still inherit the configured
    # session, or the event drops out of its own session's grouping.
    event = emit_once(
        capsys,
        ctx=EventContext(trace_id="trace-9"),
        session_id="session-1",
    )
    assert event["trace_id"] == "trace-9"
    assert event["session_id"] == "session-1"


def test_the_envelope_still_matches_the_shared_contract(capsys):
    event = emit_once(capsys, session_id="session-1")
    assert event["module"] == "vector-anchor"
    assert event["schema_version"] == 2
    assert event["severity"] == "info"
    assert event["source"] == "module"
    assert event["details"] == {"query": "x"}
    assert isinstance(event["timestamp_ms"], int)


def test_headers_are_read_case_insensitively_by_the_caller_contract():
    ctx = context_from_headers(
        {
            "x-monolith-agent-id": "agent-7",
            "x-monolith-session-id": "session-7",
            "x-monolith-trace-id": "trace-7",
            "x-monolith-correlation-id": "corr-7",
        }
    )
    assert ctx.agent_id == "agent-7"
    assert ctx.session_id == "session-7"
    assert ctx.trace_id == "trace-7"
    assert ctx.correlation_id == "corr-7"


def test_a_trace_id_is_minted_when_the_caller_omits_one():
    # Every operation gets a trace; only the caller can know its session.
    ctx = context_from_headers({})
    assert ctx.trace_id
    assert context_from_headers({}).trace_id != ctx.trace_id
    assert ctx.session_id is None
    assert ctx.agent_id is None


def test_ids_are_trimmed_clamped_and_blanks_dropped():
    assert _clean_id("  session-1  ") == "session-1"
    assert _clean_id("   ") is None
    assert _clean_id("") is None
    assert _clean_id(None) is None
    assert _clean_id(123) is None
    # The dashboard silently drops over-long text, so a nonsense header must be
    # clamped rather than cost the detection its correlation.
    assert len(_clean_id("x" * 500)) == MAX_ID_LENGTH


def test_an_absurd_header_cannot_strip_correlation(capsys):
    event = emit_once(capsys, ctx=context_from_headers({"x-monolith-session-id": "s" * 900}))
    assert len(event["session_id"]) == MAX_ID_LENGTH
