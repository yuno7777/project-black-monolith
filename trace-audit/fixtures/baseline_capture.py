#!/usr/bin/env python3
"""Build the baseline reasoning-token distribution from several NORMAL prompts.

Runs the ordinary prompts through the model backend, tallies the resulting
token counts, and writes them to the baseline file the TraceAudit service
loads at startup. This is what "normal" looks like; the divergence monitor
scores live streams against it.

Run this before starting the service (the demo script does so automatically
if no baseline exists).
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.config import load_config  # noqa: E402
from src.divergence_monitor import build_distribution  # noqa: E402
from src.stream_proxy import _backend_stream  # noqa: E402

FALLBACK_BASELINE_PATHS = (
    "/app/fixtures/baseline_distribution.json",
    os.path.join(os.path.dirname(__file__), "baseline_distribution.json"),
)

# Ordinary, benign reasoning prompts spanning a mix of styles — factual Q&A,
# short creative writing, step-by-step reasoning, and casual conversation — so
# the baseline distribution is not biased toward one prompt shape. None contain
# divergence markers or credentials, so they exercise the normal token
# distribution. (See fixtures/calibrate.py for how the threshold is derived
# from held-out prompts drawn from these same four categories.)
NORMAL_PROMPTS = [
    # factual Q&A
    "What is the capital of France and why is it historically significant?",
    "Explain in simple terms how vaccines help the immune system.",
    "How does compound interest grow savings over time?",
    # short creative writing
    "Write a short, cheerful paragraph about a walk in an autumn park.",
    "Describe a cozy cabin in the mountains during a light snowfall.",
    # step-by-step reasoning
    "Explain how to reset a forgotten password step by step.",
    "Walk through how to compare two job offers clearly.",
    "Describe how to back up important files safely.",
    # casual conversation
    "Any tips for staying focused while working from home?",
    "What is a fun, easy hobby to pick up on the weekend?",
]


def _has_valid_baseline(path: str) -> bool:
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return False
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict) or not data:
            return False
        if "counts" in data:
            return isinstance(data["counts"], dict) and len(data["counts"]) > 0
        if "distribution" in data:
            return isinstance(data["distribution"], dict) and len(data["distribution"]) > 0
        return all(
            isinstance(k, str)
            and k.strip()
            and isinstance(v, (int, float))
            and not isinstance(v, bool)
            and v > 0
            for k, v in data.items()
        )
    except Exception:
        return False


def _write_atomic(path: str, payload: dict) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    os.replace(tmp_path, path)


async def collect() -> list[str]:
    cfg = load_config()
    tokens: list[str] = []
    for prompt in NORMAL_PROMPTS:
        async for tok in _backend_stream(prompt, 80, cfg):
            tokens.append(tok)
    return tokens


def main(argv: list[str] | None = None, *, force: bool = False) -> None:
    cfg = load_config()
    args = argv if argv is not None else sys.argv[1:]
    force_overwrite = force or ("--force" in args) or ("--force" in sys.argv)
    if not force_overwrite and _has_valid_baseline(cfg.baseline_path):
        print(
            f"[baseline] existing valid baseline found at {cfg.baseline_path}; "
            "skipping capture (pass --force to overwrite)"
        )
        return

    try:
        tokens = asyncio.run(collect())
        counts = build_distribution(tokens)
        if not counts:
            raise RuntimeError("no tokens collected from upstream backend")
        out = {
            "counts": counts,
            "total": sum(counts.values()),
            "prompts": len(NORMAL_PROMPTS),
            "vocab": len(counts),
        }
        _write_atomic(cfg.baseline_path, out)
        print(
            f"[baseline] captured {out['total']} tokens across {out['prompts']} normal "
            f"prompts ({out['vocab']} distinct) -> {cfg.baseline_path}"
        )
    except Exception as exc:
        print(
            f"[baseline] warning: failed to capture baseline from upstream ({exc}); "
            "falling back to static baseline if available",
            file=sys.stderr,
        )
        target_abs = os.path.abspath(cfg.baseline_path)
        for fallback in FALLBACK_BASELINE_PATHS:
            if os.path.exists(fallback) and os.path.abspath(fallback) != target_abs:
                parent = os.path.dirname(target_abs)
                if parent:
                    os.makedirs(parent, exist_ok=True)
                tmp_path = f"{cfg.baseline_path}.tmp"
                shutil.copyfile(fallback, tmp_path)
                os.replace(tmp_path, cfg.baseline_path)
                print(
                    f"[baseline] copied fallback baseline from {fallback} -> {cfg.baseline_path}",
                    file=sys.stderr,
                )
                break


if __name__ == "__main__":
    main()
