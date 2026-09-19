"""Reset live demo detector history without deleting corpus or incident evidence."""

import argparse
import json
import os
from pathlib import Path

from run_local_demo import ROOT, load_env, post


def reset_detection(url, token):
    return post(url.rstrip("/") + "/admin/reset-detection", {}, token)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vector-url", default="http://127.0.0.1:8001")
    parser.add_argument(
        "--state-dir", type=Path, help="inspect a previous native demo state directory"
    )
    args = parser.parse_args()
    if args.state_dir:
        marker = args.state_dir / "demo-state.json"
        data = json.loads(marker.read_text(encoding="utf-8"))
        if data.get("kind") != "monolith-local-demo":
            raise ValueError("Not a marked native demo directory")
        print("State retained at", args.state_dir.resolve())
        print("Start a new native demo for fresh MCP/TraceAudit baselines and a fresh corpus.")
        print("Remove this directory manually only after stopping its services.")
        return
    env = load_env(ROOT / ".env", dict(os.environ))
    token = env.get("MONOLITH_ADMIN_TOKEN")
    if not token:
        raise ValueError("MONOLITH_ADMIN_TOKEN is required")
    result = reset_detection(args.vector_url, token)
    print(json.dumps(result))
    print(
        "VectorAnchor frequency history and quarantine reset. Corpus and PostgreSQL incident history retained."
    )
    print(
        "For new MCP/TraceAudit baselines, stop and restart the native demo; each run uses isolated state."
    )


if __name__ == "__main__":
    main()
