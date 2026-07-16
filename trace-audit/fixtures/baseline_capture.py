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
