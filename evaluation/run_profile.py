#!/usr/bin/env python3
"""Run a versioned evaluation profile and preserve its provenance.

WHAT THIS FILE IS
-----------------
The reproducibility wrapper for the evaluation harness. It runs a named
profile (from evaluation/profiles.json) step by step and writes EVERYTHING
needed to defend the numbers later into a timestamped results directory:

    evaluation/results/<profile>-<timestamp>/
      run-manifest.json      git commit, command, env overrides, python
                             version, per-step source SHA-256s, duration,
                             exit code
      <step-name>.json       the detector reports each step produced

WHY PROVENANCE MATTERS (the project's honesty rule)
---------------------------------------------------
"75% detection" is only a claim if you can say WHICH code produced it. The
manifest records the exact git revision and the SHA-256 of every source file
involved, so a stale or edited detector cannot quietly reuse an old number.

THE TWO PROFILES (implemented vs implied)
-----------------------------------------
  deterministic — VectorAnchor's hash embedder + TraceAudit's seeded mock.
                  Offline, reproducible — the CI/demo claim.
  real          — Chroma's default semantic embedder + an Ollama model. May
                  download model assets and depends on installed backends; a
                  step that fails records its exit code and the manifest is
                  still written, so the run is honestly reported as
                  NOT MEASURED rather than inferred from the deterministic
                  fixture (see EVALUATION.md).

Called from: evaluation/profiles.json steps -> python evaluation/run_profile.py
deterministic|real.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROFILES = Path(__file__).with_name("profiles.json")


def digest(path: Path) -> str:
    """SHA-256 of a source file, for the manifest's source_sha256 entries."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("profile", choices=("deterministic", "real"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    profiles = json.loads(PROFILES.read_text(encoding="utf-8"))
    profile = profiles[args.profile]
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    output = (args.output or ROOT / "evaluation" / "results" / f"{args.profile}-{stamp}").resolve()
    output.mkdir(parents=True, exist_ok=False)
    # The manifest starts with the static provenance (profile, description,
    # python version, git commit); steps are appended as they run.
    manifest: dict[str, object] = {
        "profile": args.profile,
        "description": profile["description"],
        "started_at_ms": int(time.time() * 1000),
        "python": sys.version,
        "git_commit": subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, check=True, capture_output=True, text=True
        ).stdout.strip(),
        "steps": [],
    }

    for step in profile["steps"]:
        cwd = ROOT / step["cwd"]
        environment = os.environ.copy()
        environment.update(step.get("environment", {}))
        command = [part.format(python=sys.executable) for part in step["command"]]
        # Hash the sources BEFORE running the step, so the hashes describe the
        # code that actually ran.
        source_hashes = {name: digest(cwd / name) for name in step["sources"]}
        started = time.perf_counter()
        completed = subprocess.run(command, cwd=cwd, env=environment, check=False)
        record = {
            "name": step["name"],
            "command": command,
            "environment": step.get("environment", {}),
            "source_sha256": source_hashes,
            "duration_ms": round((time.perf_counter() - started) * 1000),
            "exit_code": completed.returncode,
        }
        manifest["steps"].append(record)
        # A failed step still writes the partial manifest (the run is honestly
        # NOT MEASURED) and exits with the step's code.
        if completed.returncode:
            (output / "run-manifest.json").write_text(
                json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
            )
            raise SystemExit(completed.returncode)
        shutil.copy2(cwd / step["result"], output / f"{step['name']}.json")

    manifest["completed_at_ms"] = int(time.time() * 1000)
    (output / "run-manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    print(f"evaluation artifacts: {output}")


if __name__ == "__main__":
    main()
