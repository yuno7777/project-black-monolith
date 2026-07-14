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
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.config import load_config  # noqa: E402
from src.divergence_monitor import build_distribution  # noqa: E402
from src.stream_proxy import _backend_stream  # noqa: E402

# Ordinary, benign reasoning prompts. None contain divergence markers or
# credentials, so they exercise the normal token distribution.
NORMAL_PROMPTS = [
    "Explain how to reset a forgotten password step by step.",
    "Summarize the benefits of regular exercise for the user.",
    "Help the user plan a simple weekly meal schedule.",
    "Describe how to back up important files safely.",
    "Walk through how to compare two job offers clearly.",
    "Give a short, helpful overview of how compound interest works.",
]


async def collect() -> list[str]:
    cfg = load_config()
    tokens: list[str] = []
    for prompt in NORMAL_PROMPTS:
        async for tok in _backend_stream(prompt, 80, cfg):
            tokens.append(tok)
    return tokens


def main() -> None:
    cfg = load_config()
    tokens = asyncio.run(collect())
    counts = build_distribution(tokens)
    out = {
        "counts": counts,
        "total": sum(counts.values()),
        "prompts": len(NORMAL_PROMPTS),
        "vocab": len(counts),
    }
    with open(cfg.baseline_path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)
    print(
        f"[baseline] captured {out['total']} tokens across {out['prompts']} normal "
        f"prompts ({out['vocab']} distinct) -> {cfg.baseline_path}"
    )


if __name__ == "__main__":
    main()
