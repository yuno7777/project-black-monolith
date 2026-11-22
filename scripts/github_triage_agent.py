"""Read a GitHub issue and optionally submit an exact draft for review."""

import argparse
import json
import sys
import urllib.error
import urllib.request
import uuid
from pathlib import Path

from monolith_wrap import (
    DEFAULT_DASHBOARD_URL,
    REPO_ROOT,
    _opener,
    credential_transport_is_trusted,
    load_dotenv,
    resolve_setting,
)


def request(url: str, token: str, payload: dict | None = None) -> dict:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers={
        "X-Monolith-Workload-Token": token,
        "Content-Type": "application/json",
    })
    with _opener(use_proxy=False).open(req, timeout=15) as response:
        return json.load(response)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("issue", type=int)
    parser.add_argument("--request-id", type=uuid.UUID, help="reuse the same UUID when retrying a draft")
    drafts = parser.add_mutually_exclusive_group()
    drafts.add_argument("--reply-file", type=Path)
    drafts.add_argument("--add-label")
    drafts.add_argument("--remove-label")
    args = parser.parse_args()
    dotenv = load_dotenv(REPO_ROOT / ".env")
    token = resolve_setting("MONOLITH_WORKLOAD_TOKEN", dotenv)
    url = resolve_setting("MONOLITH_DASHBOARD_API_URL", dotenv) or DEFAULT_DASHBOARD_URL
    if not token or not credential_transport_is_trusted(url, False):
        parser.error("a workload token and HTTPS or loopback dashboard URL are required")
    if args.issue < 1:
        parser.error("issue must be positive")

    try:
        base = url.rstrip("/") + "/api/github"
        issue = request(f"{base}/issues/{args.issue}", token)
        print(json.dumps({"issue": issue}, ensure_ascii=False))
        if args.reply_file is not None:
            with args.reply_file.open("rb") as draft:
                content = draft.read(12001)
            if len(content) > 12000:
                parser.error("reply exceeds 12000 bytes")
            action = {"kind": "reply", "value": content.decode("utf-8")}
        elif args.add_label is not None:
            action = {"kind": "add_label", "value": args.add_label}
        elif args.remove_label is not None:
            action = {"kind": "remove_label", "value": args.remove_label}
        else:
            return 0
        request_id = str(args.request_id or uuid.uuid4())
        print(f"Draft request ID {request_id}", file=sys.stderr, flush=True)
        result = request(f"{base}/triage", token, {"request_id": request_id, "issue": args.issue, "action": action})
        print(json.dumps(result, ensure_ascii=False))
    except urllib.error.HTTPError as error:
        print(f"Triage gateway returned HTTP {error.code}.", file=sys.stderr)
        return 1
    except (OSError, ValueError):
        print("Could not send or read the triage request.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
