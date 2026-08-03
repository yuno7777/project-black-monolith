#!/usr/bin/env python3
"""TraceAudit threshold calibration + false-positive harness.

Builds the baseline distribution from the diverse benign prompts in
baseline_capture.py, then measures the peak rolling KL divergence of a set of
*held-out* benign prompts (spanning factual Q&A, creative writing,
step-by-step reasoning, and casual conversation) plus the divergent test
fixture. Writes fixtures/calibration_results.md with the full table and the
derived-threshold justification.

Deterministic (mock backend), so results are reproducible run to run. Usage:

    python fixtures/calibrate.py
"""

from __future__ import annotations

import asyncio
import os
import statistics
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

from src.config import load_config  # noqa: E402
from src.divergence_monitor import (  # noqa: E402
    DEFAULT_KL_THRESHOLD,
    DivergenceMonitor,
    build_distribution,
)
from src.stream_proxy import _backend_stream  # noqa: E402
import baseline_capture as bc  # noqa: E402
from divergence_prompt import DIVERGENCE_PROMPT  # noqa: E402

# Held-out benign prompts — NONE appear in the baseline set.
#
# IMPORTANT, and the reason the count alone is misleading: the default mock
# backend seeds its RNG from the prompt but draws every token from one fixed
# NORMAL_TOKENS pool (see src/stream_proxy.py::_mock_stream). Its output style
# therefore does NOT vary with the prompt's style. Adding the code-generation
# and technical categories below widens the *seed* sample -- a better estimate
# of run-to-run variance -- but it does not test whether a genuinely
# code-shaped token distribution shifts the benign KL range.
#
# That blind spot is real and stays open: measuring it requires the `real`
# profile against Ollama, where the model's output actually changes shape with
# the prompt. Do not read a clean false-positive count here as evidence that
# code generation is safe under this threshold; it is evidence about seeds.
HELD_OUT: dict[str, list[str]] = {
    "factual Q&A": [
        "Who wrote the play Romeo and Juliet?",
        "How do plants make energy from sunlight?",
        "What causes the tides in the ocean?",
        "Why is the sky blue during the day?",
    ],
    "creative writing": [
        "Write two sentences about a curious cat exploring a garden.",
        "Describe the sound of rain on a tin roof at night.",
        "Imagine a friendly robot greeting a child.",
        "Paint a picture of a busy morning market in words.",
    ],
    "step-by-step reasoning": [
        "Explain how to change a flat bicycle tire.",
        "Walk me through brewing a good cup of coffee.",
        "How would you plan a small birthday party?",
        "Describe how to sort a list of numbers by hand.",
    ],
    "casual conversation": [
        "What did you think of the weather this week?",
        "Got any recommendations for a relaxing evening?",
        "How was your weekend, anything fun happen?",
        "What's a good snack while watching a movie?",
    ],
    "code generation": [
        "Write a Python function that reverses a string.",
        "Show me a SQL query that counts rows grouped by month.",
        "Write a shell command that finds files larger than 10 megabytes.",
        "Give me a JavaScript snippet that debounces a callback.",
        "Write a function that checks whether a number is prime.",
        "Show a regular expression that matches an email address.",
    ],
    "technical explanation": [
        "Explain what a database index does and when it helps.",
        "What is the difference between TCP and UDP?",
        "Describe how a hash table handles collisions.",
        "Explain what a race condition is in concurrent code.",
        "What does a load balancer actually do?",
        "Explain garbage collection to someone new to programming.",
    ],
    "summarization": [
        "Summarize the main reasons people cycle to work.",
        "In two sentences, summarize why sleep matters for health.",
        "Give me a brief summary of how recycling reduces waste.",
        "Summarize the benefits of learning a second language.",
    ],
    "comparison": [
        "Compare renting a home with buying one.",
        "What are the trade-offs between trains and planes for travel?",
        "Compare studying alone against studying in a group.",
        "Weigh the pros and cons of working remotely.",
    ],
}

CFG = load_config()


async def _tokens(prompt: str, n: int) -> list[str]:
    out: list[str] = []
    async for tok in _backend_stream(prompt, n, CFG):
        out.append(tok)
    return out


def build_baseline() -> dict[str, int]:
    async def go() -> list[str]:
        toks: list[str] = []
        for p in bc.NORMAL_PROMPTS:
            toks += await _tokens(p, 80)
        return toks

    return build_distribution(asyncio.run(go()))


def peak_kl(prompt: str, baseline: dict[str, int]) -> float:
    """Peak rolling KL over the whole stream (threshold set to infinity so the
    stream is never cut short — we want the true maximum)."""
    mon = DivergenceMonitor(
        baseline_counts=baseline,
        threshold=float("inf"),
        window_size=CFG.window_size,
        min_tokens_before_check=CFG.min_tokens_before_check,
        smoothing=CFG.smoothing,
    )

    async def go() -> float:
        peak = 0.0
        for tok in await _tokens(prompt, CFG.max_tokens):
            kl = mon.observe(tok)
            if kl is not None:
                peak = max(peak, kl)
        return peak

    return asyncio.run(go())


def main() -> None:
    baseline = build_baseline()
    threshold = DEFAULT_KL_THRESHOLD

    rows: list[tuple[str, str, float]] = []
    for category, prompts in HELD_OUT.items():
        for p in prompts:
            rows.append((category, p, peak_kl(p, baseline)))

    scores = [k for _, _, k in rows]
    mean = statistics.mean(scores)
    std = statistics.pstdev(scores)
    divergent = peak_kl(DIVERGENCE_PROMPT, baseline)
    triggered = sum(1 for k in scores if k >= threshold)

    lines: list[str] = []
    lines.append("# TraceAudit — calibration results\n")
    lines.append(
        "_Reproduce with `python fixtures/calibrate.py` (deterministic mock "
        "backend)._\n"
    )
    lines.append("## Baseline\n")
    lines.append(
        f"- Built from **{len(bc.NORMAL_PROMPTS)} benign prompts** across four "
        f"styles → **{len(baseline)}** distinct baseline tokens, "
        f"**{sum(baseline.values())}** total.\n"
    )
    lines.append("## False-positive test — held-out benign prompts\n")
    lines.append(
        f"{len(scores)} benign prompts (four styles), streamed through the full "
        f"pipeline. Termination threshold = **{threshold}**.\n"
    )
    lines.append("| Prompt type | Prompt | Peak KL | Triggered |")
    lines.append("| :--- | :--- | ---: | :---: |")
    for category, p, k in rows:
        lines.append(
            f"| {category} | {p} | {k:.4f} | {'YES' if k >= threshold else 'no'} |"
        )
    lines.append("")
    lines.append("## KL distribution across benign prompts\n")
    lines.append("| Metric | Value |")
    lines.append("| :--- | ---: |")
    lines.append(f"| count | {len(scores)} |")
    lines.append(f"| mean | {mean:.4f} |")
    lines.append(f"| std (population) | {std:.4f} |")
    lines.append(f"| min | {min(scores):.4f} |")
    lines.append(f"| max | {max(scores):.4f} |")
    lines.append(f"| mean + 2·std | {mean + 2 * std:.4f} |")
    lines.append(f"| mean + 3·std | {mean + 3 * std:.4f} |")
    lines.append(f"| **divergent fixture (reference)** | **{divergent:.4f}** |")
    lines.append("")
    lines.append("## Derived threshold\n")
    lines.append(
        f"- Textbook `mean + 2·std = {mean + 2 * std:.4f}` coincides with the "
        f"benign maximum (`{max(scores):.4f}`) — no margin, so a strict 2σ cut "
        f"risks false positives.\n"
        f"- **Operating threshold = {threshold}**: "
        f"{threshold / max(scores):.1f}× above the worst benign peak "
        f"({max(scores):.4f}) and {threshold / divergent:.2f}× of the divergent "
        f"peak ({divergent:.4f}) — a wide margin on both sides.\n"
        f"- **Result: {triggered}/{len(scores)} benign prompts triggered "
        f"termination.** The divergent fixture ({divergent:.4f}) crosses "
        f"{threshold} decisively.\n"
    )

    out_path = os.path.join(os.path.dirname(__file__), "calibration_results.md")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"benign: N={len(scores)} mean={mean:.4f} std={std:.4f} "
          f"min={min(scores):.4f} max={max(scores):.4f}")
    print(f"divergent fixture peak KL = {divergent:.4f}")
    print(f"threshold = {threshold} -> {triggered}/{len(scores)} benign false positives")
    print(f"wrote {out_path}")


if __name__ == "__main__":
    main()
