"""Prepare test drafts and verify human-approved writes in a dedicated GitHub repository."""

import argparse
import json
import os
import re
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from monolith_wrap import _opener, credential_transport_is_trusted


class VerificationError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise VerificationError(message)


def request(url, headers, *, expected=200, payload=None):
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, body, {"Content-Type": "application/json", **headers})
    try:
        response = _opener(use_proxy=False).open(req, timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        require(response.status == expected, f"Expected HTTP {expected}, received {response.status} on {req.get_method()} {req.selector}.")
        return json.load(response)


class Pilot:
    def __init__(self, dashboard, repo, issue, github_token, workload_token, operator_token):
        self.api = dashboard.rstrip("/") + "/api/github"
        self.repository = repo
        self.issue = issue
        self.github = f"https://api.github.com/repos/{repo}/issues/{issue}"
        self.workload = {"X-Monolith-Workload-Token": workload_token}
        self.operator = {"Authorization": f"Bearer {operator_token}"}
        self.github_read = {"Authorization": f"Bearer {github_token}", "Accept": "application/vnd.github+json"}

    def issue_labels(self):
        result = request(self.github, self.github_read)
        require("pull_request" not in result, "Choose a dedicated test issue, not a pull request.")
        return {label["name"] for label in result["labels"]}

    def proposal(self, draft, *, expected=202):
        return request(self.api + "/triage", self.workload, expected=expected, payload={
            "request_id": draft["request_id"], "issue": self.issue,
            "action": {"kind": draft["kind"], "value": draft["value"]},
        })

    def review(self, row, *, expected=200):
        result = request(self.api + "/triage/" + row["id"], self.operator, expected=expected, payload={
            "decision": "approve", "digest": row["digest"],
        })
        return result.get("action", {})

    def audit(self, state):
        drafts = state["drafts"]
        found = {}
        cursor = None
        for _ in range(20):
            url = self.api + "/triage"
            if cursor:
                url += "?" + urllib.parse.urlencode({"before": cursor})
            page = request(url, self.operator)
            rows = {row["id"]: row for row in page["actions"]}
            for name, draft in drafts.items():
                if draft["id"] in rows:
                    row = rows[draft["id"]]
                    assert_matches(row, draft, self.repository, self.issue)
                    found[name] = row
            cursor = page.get("next")
            if not cursor or len(found) == len(drafts):
                break
        require(found.keys() == drafts.keys(), "Could not find every test proposal in the dashboard audit history.")
        return found

    def github_outcome(self, state, reply):
        comments = []
        for page in range(1, 11):
            batch = request(f"{self.github}/comments?per_page=100&page={page}", self.github_read)
            comments.extend(item for item in batch if str(item.get("body", "")).startswith(state["marker"]))
            if len(batch) < 100:
                break
        else:
            raise VerificationError("Choose a fixture issue with fewer than 1,000 comments.")
        require(len(comments) == 1, f"Expected exactly one fixture reply on GitHub, found {len(comments)}.")
        require(comments[0]["body"] == reply["value"] and str(comments[0]["id"]) == reply["github_comment_id"],
                "GitHub reply content or comment ID differs from the audit record.")
        labels = self.issue_labels()
        require(state["drafts"]["add_label"]["value"] in labels, "GitHub did not retain the added label.")
        require(state["drafts"]["remove_label"]["value"] not in labels, "GitHub still has the removed label.")


def assert_matches(row, draft, repository, issue):
    require(row.get("repository", "").casefold() == repository.casefold() and row.get("issue") == issue,
            "The draft or audit record points at a different GitHub target.")
    require(all(row.get(key) == value for key, value in draft.items()), "The recorded action differs from the exact fixture.")


def prepare(pilot, path, add_label, remove_label):
    require(add_label and remove_label and add_label.casefold() != remove_label.casefold(),
            "Supply distinct labels for addition and removal.")
    issue = request(f"{pilot.api}/issues/{pilot.issue}", pilot.workload)
    require(issue.get("repository", "").casefold() == pilot.repository.casefold() and issue.get("number") == pilot.issue,
            "The dashboard returned a different test repository or issue.")
    labels = pilot.issue_labels()
    require(add_label.casefold() not in {label.casefold() for label in labels} and remove_label in labels,
            "Start with the exact removal label attached and the addition label absent.")
    marker = f"[monolith-pilot:{uuid4()}]"
    scenarios = {
        "reply": ("reply", f"{marker} Approved test reply."),
        "add_label": ("add_label", add_label),
        "remove_label": ("remove_label", remove_label),
        **{name: ("reply", f"{marker} {name} fixture.") for name in ("denied", "expired", "revoked")},
    }
    state = {"repository": pilot.repository, "issue": pilot.issue, "marker": marker, "drafts": {}}
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as output:
        try:
            for name, (kind, value) in scenarios.items():
                draft = {"request_id": str(uuid4()), "kind": kind, "value": value}
                state["drafts"][name] = draft
                row = pilot.proposal(draft)["action"]
                assert_matches(row, draft, pilot.repository, pilot.issue)
                require(re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", row["id"])
                        and re.fullmatch(r"[a-f0-9]{64}", row["digest"]), "The gateway must return an action ID and digest.")
                draft.update(id=row["id"], digest=row["digest"])
            denied = state["drafts"]["denied"]
            pilot.proposal({**denied, "value": denied["value"] + " Changed payload."}, expected=409)
            state["changed_rejected"] = True
        finally:
            json.dump(state, output, indent=2)
            output.write("\n")
    for name, row in state["drafts"].items():
        print(f"{name}: {row['id']}")
    print("Changed draft replay returned HTTP 409. Review the prepared actions in the dashboard.")


def verify(pilot, state, phase):
    require(state.get("changed_rejected") is True, "The changed-draft check was not recorded during preparation.")
    rows = pilot.audit(state)
    for name in ("reply", "add_label", "remove_label"):
        require(rows[name]["status"] == "succeeded", f"The reviewer must successfully approve {name} first.")
    require(rows["denied"]["status"] == "denied", "Deny the denied fixture from the dashboard first.")
    target = rows["revoked" if phase == "check-now" else "expired"]
    if phase == "check-now":
        require(target.get("session_revoked_at"), "Revoke the test workload from the dashboard first.")
        require(target["status"] in {"pending", "revoked"}, "Run the revocation check before the revoked draft expires.")
        for name in ("reply", "add_label", "remove_label", "denied"):
            pilot.review(rows[name], expected=409)
        if target["status"] == "pending":
            recorded = pilot.review(target)
            require(recorded["status"] == "revoked", "The revoked proposal did not record a revoked outcome.")
            rows["revoked"] = {**target, **recorded}
    else:
        require(rows["revoked"]["status"] == "revoked", "Complete check-now first.")
        require(target["status"] == "expired", "Wait until the expired draft passes its deadline.")
        if not target.get("reviewed_at"):
            recorded = pilot.review(target)
            require(recorded["status"] == "expired", "The expired proposal did not record an expired outcome.")
            rows["expired"] = {**target, **recorded}
    pilot.github_outcome(state, rows["reply"])
    checks = (
        ["approved_actions", "changed_draft_refused", "approval_replays_refused", "denied_action_refused", "revoked_action_refused"]
        if phase == "check-now" else ["expired_action_refused"]
    )
    fields = ("id", "digest", "status", "reviewed_at", "github_status", "github_comment_id")
    return {
        "format_version": 1,
        "phase": phase,
        "verified_at": datetime.now(UTC).isoformat(),
        "repository": state["repository"],
        "issue": state["issue"],
        "checks": [*checks, "exact_github_reply_and_labels"],
        "actions": {
            name: {field: row.get(field) for field in fields}
            for name, row in rows.items() if phase == "check-expired" or name != "expired"
        },
    }


def write_evidence(path, report):
    # Publish a complete report without overwriting evidence from another run.
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as output:
            temporary = Path(output.name)
            json.dump(report, output, indent=2)
            output.write("\n")
        os.link(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("prepare", "check-now", "check-expired"))
    parser.add_argument("--test-repository", required=True, metavar="OWNER/REPO")
    parser.add_argument("--issue", required=True, type=int)
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--evidence", type=Path, help="write a new JSON evidence file after a successful check")
    parser.add_argument("--label-to-add")
    parser.add_argument("--label-to-remove")
    args = parser.parse_args()
    dashboard = os.environ.get("MONOLITH_DASHBOARD_API_URL", "")
    github = os.environ.get("MONOLITH_VERIFY_GITHUB_TOKEN", "")
    workload = os.environ.get("MONOLITH_WORKLOAD_TOKEN", "")
    operator = os.environ.get("MONOLITH_OPERATOR_TOKEN", "")
    try:
        require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}", args.test_repository)
                and not args.test_repository.endswith(("/.", "/..")) and args.issue > 0, "Supply a dedicated test repository and issue.")
        require(credential_transport_is_trusted(dashboard, False) and "?" not in dashboard and github,
                "Set a trusted dashboard URL and a read-only GitHub verifier token.")
        require(workload if args.phase == "prepare" else operator, "Set the credential for the selected phase.")
        if args.evidence is not None:
            require(args.phase != "prepare", "Use --evidence with check-now or check-expired.")
            require(args.evidence.parent.is_dir(), "The evidence directory must already exist.")
            require(not (args.evidence.exists() or args.evidence.is_symlink()), "Choose a new evidence file.")
        pilot = Pilot(dashboard, args.test_repository, args.issue, github, workload, operator)
        if args.phase == "prepare":
            prepare(pilot, args.state, args.label_to_add, args.label_to_remove)
        else:
            state = json.loads(args.state.read_text(encoding="utf-8"))
            require((state["repository"], state["issue"]) == (pilot.repository, pilot.issue), "The state file belongs to a different test target.")
            require(set(state["drafts"]) == {"reply", "add_label", "remove_label", "denied", "expired", "revoked"}, "The state file is incomplete.")
            report = verify(pilot, state, args.phase)
            if args.evidence is not None:
                write_evidence(args.evidence, report)
            print(f"PASS {args.phase}: audit decisions and exact GitHub reply and labels match.")
    except VerificationError as error:
        print(error, file=sys.stderr)
        return 1
    except (OSError, ValueError, LookupError, TypeError, AttributeError):
        print("Could not read a fixture response or write verification state or evidence.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
