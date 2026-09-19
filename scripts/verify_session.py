"""Verify persisted three-layer findings for one exact agent session."""

import json
import time
import urllib.parse
import urllib.request

EXPECTED = {
    "mcp-shield": "schema_mismatch",
    "vector-anchor": "corpus_poison_quarantine",
    "trace-audit": "pii_redacted",
}


def get(url, token):
    req = urllib.request.Request(url, headers={"Authorization": "Bearer " + token})
    with urllib.request.urlopen(req, timeout=5) as response:
        return json.load(response)


def verify_session(base, token, session, agent, timeout=30):
    deadline = time.monotonic() + timeout
    query = urllib.parse.urlencode(
        {"session": session, "agent": agent, "status": "all", "limit": 500}
    )
    while time.monotonic() < deadline:
        events = get(base + "/api/incidents?" + query, token)["incidents"]
        seen = {(event["module"], event["event_type"]) for event in events}
        if all((module, kind) in seen for module, kind in EXPECTED.items()):
            event_id = urllib.parse.quote(events[0]["event_id"], safe="")
            view = get(base + "/api/incidents/" + event_id + "/session", token)["session"]
            if not view["cross_layer"] or len(view["layers"]) != 3:
                raise RuntimeError("Ledger did not correlate all three defense layers")
            return {
                "session_id": session,
                "agent_id": agent,
                "events": len(events),
                "verified_layers": sorted(EXPECTED),
                "cross_layer": True,
            }
        time.sleep(0.2)
    raise RuntimeError("Timed out waiting for the three-layer session in PostgreSQL")
