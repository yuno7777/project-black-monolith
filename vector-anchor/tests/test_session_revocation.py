"""A revoked agent session gets no corpus text, regardless of query.

The cross-layer circuit breaker revokes a session when the tool, memory, and
reasoning layers agree it is compromised. Serving retrieval results into that
agent's context is exactly how a poisoned document would reach it, so the
refusal happens before embedding, before detector state, and before the
corpus is touched.
"""

from types import SimpleNamespace

from src.events import revoked_session_registry
from src.quarantine import Quarantine
from src.retriever_proxy import RetrieverProxy


class Collection:
    def __init__(self):
        self.queried = False

    def query(self, **_kwargs):
        self.queried = True
        return {"ids": [["doc-1"]], "documents": [["corpus text"]], "distances": [[0.1]]}


class Tracker:
    def __init__(self):
        self.recorded = False

    def record_query(self, _ids, _embedding):
        self.recorded = True

    def is_anomalous(self, _doc_id):
        return False


def _proxy(events: list) -> RetrieverProxy:
    cfg = SimpleNamespace(
        top_k=1,
        candidate_buffer=0,
        top_rank_threshold=1,
        min_distinct_topics=4,
        state_flush_interval_ms=0,
        log_clean_retrievals=True,
    )
    return RetrieverProxy(
        collection=Collection(),
        embed_fn=lambda _queries: [[1.0]],
        tracker=Tracker(),
        quarantine=Quarantine(),
        cfg=cfg,
        emit=lambda event_type, severity, details, _ctx, **_evidence: events.append(
            (event_type, severity, details)
        ),
    )


def test_revoked_session_gets_an_empty_refusal_and_one_event():
    from src.events import EventContext

    events: list = []
    proxy = _proxy(events)
    revoked_session_registry().replace(["revoked-session-1"])
    try:
        ctx = EventContext(session_id="revoked-session-1", agent_id="agent-1")
        response = proxy.retrieve("incident response procedure", 1, ctx)

        assert response["results"] == []
        assert response["withheld"] == []
        assert response["session_quarantined"] is True
        assert proxy.collection.queried is False, "no corpus query for a revoked session"
        assert proxy.tracker.recorded is False

        refusals = [event for event in events if event[0] == "session_quarantined"]
        assert len(refusals) == 1
        assert refusals[0][1] == "critical"
        assert refusals[0][2]["session_id"] == "revoked-session-1"

        # A retry is still refused but does not re-emit the event.
        assert proxy.retrieve("another query", 1, ctx)["session_quarantined"] is True
        assert len([e for e in events if e[0] == "session_quarantined"]) == 1
    finally:
        revoked_session_registry().replace([])


def test_clean_session_retrieves_normally():
    from src.events import EventContext

    events: list = []
    proxy = _proxy(events)
    response = proxy.retrieve(
        "incident response procedure", 1, EventContext(session_id="clean-session")
    )
    assert response["results"][0]["id"] == "doc-1"
    assert "session_quarantined" not in response
    assert events[-1][0] == "retrieval"


def test_a_retrieval_with_no_session_identity_is_refused():
    """A retrieval that cannot be attributed to a session is refused.

    The circuit breaker revokes a session, and the revocation registry
    works on a session id. A retrieval with no session id has no session
    to revoke, so the check that stands between the corpus and a
    compromised agent does not run at all — the check was skipped
    silently, and a caller that reached the corpus without an identity
    was a caller the breaker could not act on.
    """
    from src.events import EventContext

    events: list = []
    proxy = _proxy(events)
    response = proxy.retrieve("ordinary query", 1, None)

    assert response["results"] == []
    assert response["withheld"] == []
    assert response["session_quarantined"] is True
    # Nothing from the corpus was touched.
    assert proxy.collection.queried is False
    assert proxy.tracker.recorded is False

    refusals = [event for event in events if event[0] == "session_quarantined"]
    assert len(refusals) == 1
    assert refusals[0][1] == "critical"
    # The reason tells a misconfiguration apart from a compromise.
    assert refusals[0][2]["refusal"] == "unattributed_retrieval"
    assert refusals[0][2]["session_id"] == ""


def test_an_unattributed_refusal_is_reported_once_per_identity():
    """A caller that retries must not be able to flood the ledger."""
    from src.events import EventContext

    events: list = []
    proxy = _proxy(events)
    ctx = EventContext(session_id=None, agent_id="agent-without-a-session")

    assert proxy.retrieve("one", 1, ctx)["session_quarantined"] is True
    assert proxy.retrieve("two", 1, ctx)["session_quarantined"] is True
    assert len([event for event in events if event[0] == "session_quarantined"]) == 1

    # A different caller is a different misconfiguration, and says so.
    other = EventContext(session_id=None, agent_id="another-agent")
    assert proxy.retrieve("three", 1, other)["session_quarantined"] is True
    assert len([event for event in events if event[0] == "session_quarantined"]) == 2


def test_a_revoked_session_and_an_unattributed_one_are_told_apart():
    """The two refusals look the same to the caller, and are not the same."""
    from src.events import EventContext

    events: list = []
    proxy = _proxy(events)
    revoked_session_registry().replace(["revoked-session-2"])
    try:
        proxy.retrieve("ordinary query", 1, EventContext(session_id="revoked-session-2"))
        proxy.retrieve("ordinary query", 1, None)
    finally:
        revoked_session_registry().replace([])

    reasons = [
        event[2]["refusal"] for event in events if event[0] == "session_quarantined"
    ]
    assert reasons == ["retrieval", "unattributed_retrieval"]
