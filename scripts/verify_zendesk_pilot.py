"""Queue synthetic support drafts and verify their Zendesk sandbox outcomes."""

import argparse
import json
import os
import re
import sys
import urllib.parse
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from business_practice_connector import RequestError, canonical_uuid
from business_zendesk_connector import Zendesk, audit_reference, matches_decision, reply_digest
from monolith_wrap import credential_transport_is_trusted
from verify_github_pilot import VerificationError, request, require, write_evidence

SCENARIOS = {"approved": "Approved sandbox reply.", "denied": "Denied sandbox reply."}


def reply(subdomain: str, ticket: int, marker: str, scenario: str) -> dict:
    return {"kind": "customer_reply", "recipient": f"zendesk:{subdomain}:{ticket}",
            "body": f"{marker} {SCENARIOS[scenario]}"}


def prepare(api, state_path, zendesk, ticket, workload):
    result = zendesk.request(f"/api/v2/tickets/{ticket}.json").get("ticket")
    require(isinstance(result, dict) and result.get("id") == ticket, "The Zendesk test ticket could not be read.")
    marker = "Monolith support pilot " + str(uuid4())
    state = {"subdomain": zendesk.subdomain, "ticket": ticket, "marker": marker, "decisions": {}}
    descriptor = os.open(state_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        try:
            for scenario in SCENARIOS:
                action = reply(zendesk.subdomain, ticket, marker, scenario)
                payload = {"requestId": str(uuid4()), "caseId": f"zendesk-pilot-{ticket}", "templateId": "support",
                           "action": action}
                decision = request(api + "/proposals", workload, expected=202, payload=payload)["decision"]
                require(decision.get("action") == action and decision.get("status") == "pending"
                        and decision.get("template_id") == "support" and canonical_uuid(decision.get("id"))
                        and re.fullmatch(r"[a-f0-9]{64}", decision.get("digest", "")),
                        "Dashboard did not return the exact pending proposal.")
                state["decisions"][scenario] = {"id": decision["id"], "digest": decision["digest"]}
        finally:
            json.dump(state, output, indent=2)
            output.write("\n")
    return state


def verify(api, state, zendesk, ticket, operator):
    require((state.get("subdomain"), state.get("ticket")) == (zendesk.subdomain, ticket),
            "This state file belongs to a different sandbox or ticket.")
    require(set(state["decisions"]) == SCENARIOS.keys(), "The state file is incomplete.")
    marker = state["marker"]
    require(marker.startswith("Monolith support pilot ") and canonical_uuid(marker.removeprefix("Monolith support pilot ")),
            "The state file has an invalid test marker.")
    decisions = {}
    for scenario, expected_status in (("approved", "succeeded"), ("denied", "denied")):
        saved = state["decisions"][scenario]
        require(canonical_uuid(saved["id"]), "The state file has an invalid decision ID.")
        url = api + "?" + urllib.parse.urlencode({"id": saved["id"]})
        rows = request(url, operator)["decisions"]
        require(len(rows) == 1 and rows[0].get("id") == saved["id"], "Could not locate the requested decision.")
        row = rows[0]
        require(row.get("status") == expected_status and row.get("digest") == saved["digest"]
                and row.get("template_id") == "support" and row.get("case_id") == f"zendesk-pilot-{ticket}"
                and row.get("action") == reply(zendesk.subdomain, ticket, marker, scenario),
                f"Dashboard outcome or exact action does not match the {scenario} draft.")
        decisions[scenario] = row

    approved, denied = decisions["approved"], decisions["denied"]
    approved_digest, denied_digest = (reply_digest(row["action"]) for row in (approved, denied))
    matching_audits = []
    marker_count = 0
    for audit in zendesk.audits(ticket):
        require(isinstance(audit, dict) and audit.get("ticket_id") == ticket, "Zendesk returned an audit for a different ticket.")
        if matches_decision(audit, ticket, approved["id"], approved_digest):
            matching_audits.append(audit)
        require(not matches_decision(audit, ticket, denied["id"], denied_digest), "The denied decision reached Zendesk.")
        for event in audit.get("events", []):
            body = event.get("body")
            if event.get("type") == "Comment" and isinstance(body, str) and marker in body:
                marker_count += 1
    require(len(matching_audits) == 1 and marker_count == 1,
            "Expected exactly one exact approved audit and one synthetic reply on the ticket.")
    reference = audit_reference(matching_audits[0], ticket, approved["action"]["recipient"], approved["id"], approved_digest)
    require(reference is not None and reference == approved.get("reference"),
            "Zendesk did not return the exact approved reply or the dashboard receipt differs.")
    return {
        "format_version": 1, "verified_at": datetime.now(UTC).isoformat(), "sandbox_subdomain": zendesk.subdomain,
        "ticket": ticket, "checks": ["exact_approved_reply_once", "denied_reply_absent"],
        "decisions": {scenario: {key: row.get(key) for key in ("id", "digest", "status", "reference", "reviewed_at")}
                      for scenario, row in decisions.items()},
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("prepare", "check"))
    parser.add_argument("--sandbox-subdomain", required=True)
    parser.add_argument("--ticket", required=True, type=int)
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args(argv)
    dashboard = os.environ.get("MONOLITH_DASHBOARD_API_URL", "")
    try:
        require(1 <= args.ticket < 10**18, "Supply a dedicated synthetic test ticket ID.")
        require(credential_transport_is_trusted(dashboard, False) and "?" not in dashboard and "#" not in dashboard,
                "Set MONOLITH_DASHBOARD_API_URL to an HTTPS or loopback dashboard URL.")
        zendesk = Zendesk(args.sandbox_subdomain, os.environ.get("MONOLITH_VERIFY_ZENDESK_TOKEN", ""), {args.ticket})
        api = dashboard.rstrip("/") + "/api/business"
        if args.phase == "prepare":
            credential = os.environ.get("MONOLITH_WORKLOAD_TOKEN")
            require(credential and args.evidence is None, "Prepare needs a workload credential and a new state path.")
            state = prepare(api, args.state, zendesk, args.ticket, {"X-Monolith-Workload-Token": credential})
            for scenario, decision in state["decisions"].items():
                print(f"{scenario}: {decision['id']}")
            print("Review the two proposed actions in the dashboard.")
        else:
            credential = os.environ.get("MONOLITH_OPERATOR_TOKEN")
            require(credential, "Set MONOLITH_OPERATOR_TOKEN to a test reviewer or viewer credential.")
            if args.evidence is not None:
                require(args.evidence.parent.is_dir() and not (args.evidence.exists() or args.evidence.is_symlink()),
                        "Choose a new evidence path in an existing directory.")
            state = json.loads(args.state.read_text(encoding="utf-8"))
            report = verify(api, state, zendesk, args.ticket, {"Authorization": f"Bearer {credential}"})
            if args.evidence is not None:
                write_evidence(args.evidence, report)
            print("PASS: Zendesk contains exactly one approved synthetic reply and zero denied replies.")
    except VerificationError as error:
        print(error, file=sys.stderr)
        return 1
    except (OSError, ValueError, LookupError, TypeError, AttributeError, RequestError):
        print("Could not check the sandbox or read and write verification files. Check access and arguments.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
