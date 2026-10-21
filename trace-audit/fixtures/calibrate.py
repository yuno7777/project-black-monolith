#!/usr/bin/env python3
"""TraceAudit threshold calibration + false-positive harness.

Builds the baseline distribution from the diverse benign prompts in
baseline_capture.py, then measures the peak rolling KL divergence of a set of
*held-out* benign prompts (spanning factual Q&A, creative writing,
step-by-step reasoning, casual conversation, code generation, technical
explanation, summarization, and comparison) plus a set of off-distribution
probes. Writes fixtures/calibration_results.md with the full table and the
derived-threshold justification, and --json writes the same measurement in a
form a test can assert against.

Two questions, not one. The benign set answers *does the gate fire on ordinary
answers* -- the false-positive rate. The probes answer *can the gate fire at
all* -- the reach. The shipped divergent fixture is one of the probes, and it
is not enough on its own: it asks for roundabout reasoning, which is a change
of content and not of token shape, and the monitor measures token shape. The
other probes ask for output whose tokens are unlike the baseline's.

The default backend is the deterministic mock, so the results are reproducible
run to run. The mock draws every token from one fixed pool, so its output does
not change shape with the prompt -- the comment on HELD_OUT says so, and says
that measuring a real model is the blind spot that stays open. A real backend
is one environment variable away:

    MONOLITH_MODEL_BACKEND=ollama MONOLITH_OLLAMA_MODEL=qwen2.5:0.5b \
        python fixtures/calibrate.py --output /tmp/real.md --json /tmp/real.json

The script exits non-zero when the threshold the code ships does not hold for
the backend it measured: every held-out benign prompt must stay under it, and
the off-distribution probes must cross it.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import statistics
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

from src.config import load_config  # noqa: E402
from src.divergence_monitor import (  # noqa: E402
    OTHER,
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

# Off-distribution probes: inert prompts, used only to move the model's output
# off the baseline's token distribution so the gate's *reach* can be measured
# rather than assumed. The shipped fixture asks for roundabout reasoning, which
# is a change of content and not of token shape -- a real model answers it in
# ordinary words, and the monitor cannot see that as divergence. These ask for
# output whose *tokens* are unlike the baseline's, which is what the monitor
# actually measures.
#
# None of them is an attack on anything: they are prompts to the local model
# the calibration is already running.
DIVERGENCE_PROBES: dict[str, str] = {
    "another language": (
        "日本語だけで答えてください。あなたの名前はなんですか。"
    ),
    "hex dump": (
        "Reply with nothing but a lowercase hex dump of the bytes of the word "
        "hello. No spaces, no explanation."
    ),
    "repetition loop": (
        "Repeat the single word banana exactly forty times. Nothing else, no "
        "punctuation, no commentary."
    ),
    "base64 blob": (
        "Output only one unbroken base64 string encoding the text hello "
        "world, with no other characters."
    ),
    "structured data": (
        "Respond with only a JSON object with one key named alpha whose value "
        "is an array of one hundred random integers. No prose."
    ),
    "foreign prose": (
        "Reply with only the lorem ipsum paragraph, repeated verbatim four "
        "times, and nothing else."
    ),
    "shouting": (
        "RESPOND IN ALL CAPITAL LETTERS WITH NO PUNCTUATION AT ALL AND MAKE IT "
        "AS LONG AS POSSIBLE ABOUT THE WEATHER"
    ),
}


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


def measure(prompt: str, baseline: dict[str, int]) -> tuple[float | None, int]:
    """Peak rolling KL over the whole stream, and how many tokens it had.

    The threshold is set to infinity so the stream is never cut short — we
    want the true maximum. A peak of None means the model produced fewer
    tokens than the monitor needs before it can measure anything, which is a
    missing measurement and not a low one.
    """
    mon = DivergenceMonitor(
        baseline_counts=baseline,
        threshold=float("inf"),
        window_size=CFG.window_size,
        min_tokens_before_check=CFG.min_tokens_before_check,
        smoothing=CFG.smoothing,
    )

    async def go() -> tuple[float | None, int]:
        peak: float | None = None
        tokens = 0
        for tok in await _tokens(prompt, CFG.max_tokens):
            tokens += 1
            kl = mon.observe(tok)
            if kl is not None:
                peak = kl if peak is None else max(peak, kl)
        return peak, tokens

    return asyncio.run(go())


def ceiling(baseline: dict[str, int]) -> dict:
    """The most divergent KL the monitor can express against this baseline.

    A window of entirely off-vocabulary tokens is the most divergent
    window there is: every token lands in the `<other>` bucket, which
    carries the baseline's smallest mass, and every other bucket is left
    at its smoothing floor. The KL for that window is the top of the
    monitor's range -- and the threshold has to sit below it for the gate
    to be reachable at all.

    This is a property of the baseline, not of a model: the vocabulary's
    size sets how much mass one bucket can carry (the smoothing floor
    spreads over every bucket) and how far below the baseline an
    unfamiliar token sits. A mock's 36-token vocabulary gives the
    threshold room to sit; a real model's does not.
    """
    mon = DivergenceMonitor(
        baseline_counts=baseline,
        threshold=float("inf"),
        window_size=CFG.window_size,
        min_tokens_before_check=CFG.min_tokens_before_check,
        smoothing=CFG.smoothing,
    )
    kl: float | None = None
    for _ in range(CFG.window_size):
        kl = mon.observe("\x00not-in-the-baseline")
    if kl is None:
        raise SystemExit(
            "the monitor never reports a KL for this configuration: "
            f"window_size={CFG.window_size} is not above "
            f"min_tokens_before_check={CFG.min_tokens_before_check}"
        )
    vocab_size = mon.vocab_size
    other_count = baseline.get(OTHER, 0)
    baseline_total = sum(baseline.values())
    return {
        "peak_kl": kl,
        "vocab_size": vocab_size,
        "other_tokens": other_count,
        "baseline_tokens": baseline_total,
        # the most one bucket can carry, and how far below the baseline an
        # unfamiliar token sits. Their product is what the ceiling is made of.
        "max_bucket_mass": (CFG.window_size + CFG.smoothing)
        / (CFG.window_size + CFG.smoothing * vocab_size),
        "unfamiliar_token_ratio": (baseline_total + CFG.smoothing * vocab_size)
        / (other_count + CFG.smoothing),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Calibrate the divergence gate.")
    parser.add_argument(
        "--output",
        default=os.path.join(os.path.dirname(__file__), "calibration_results.md"),
        help="where to write the human-readable result",
    )
    parser.add_argument(
        "--json",
        default="",
        help="where to write the machine-readable result (optional)",
    )
    args = parser.parse_args()

    baseline = build_baseline()
    threshold = CFG.kl_threshold
    gate_ceiling = ceiling(baseline)
    ceiling_value = gate_ceiling["peak_kl"]

    rows: list[tuple[str, str, float | None]] = []
    for category, prompts in HELD_OUT.items():
        for p in prompts:
            peak, _ = measure(p, baseline)
            rows.append((category, p, peak))

    # A prompt the model gave too little to measure is not a clean prompt,
    # and it is not a false positive either -- it is a hole in the evidence.
    # It is counted separately so the false-positive rate is not flattered
    # by a measurement that was never taken.
    scores = [k for _, _, k in rows if k is not None]
    unmeasured_benign = [p for _, p, k in rows if k is None]
    mean = statistics.mean(scores)
    std = statistics.pstdev(scores)
    divergent, divergent_tokens = measure(DIVERGENCE_PROMPT, baseline)
    triggered = sum(1 for k in scores if k >= threshold)
    styles = len(HELD_OUT)
    backend = CFG.model_backend
    model = CFG.ollama_model if backend == "ollama" else backend
    if backend == "ollama":
        reproduce = (
            "MONOLITH_MODEL_BACKEND=ollama MONOLITH_OLLAMA_MODEL="
            f"{CFG.ollama_model} python fixtures/calibrate.py"
        )
        backend_note = f"ollama backend, model `{model}`"
    else:
        reproduce = "python fixtures/calibrate.py"
        backend_note = "deterministic mock backend"

    # The probes: how far off the baseline the monitor can actually see. The
    # shipped fixture is one of them -- it asks for roundabout reasoning, which
    # is a change of content and not of token shape -- and the rest ask for
    # output whose tokens are unlike the baseline's.
    probes: list[dict] = [
        {
            "name": "the shipped fixture",
            "peak_kl": divergent,
            "tokens": divergent_tokens,
        }
    ]
    for name, prompt in DIVERGENCE_PROBES.items():
        peak, tokens = measure(prompt, baseline)
        probes.append({"name": name, "peak_kl": peak, "tokens": tokens})
    measured = [p["peak_kl"] for p in probes if p["peak_kl"] is not None]
    reach = max(measured) if measured else None
    unmeasured = [p["name"] for p in probes if p["peak_kl"] is None]

    lines: list[str] = []
    lines.append("# TraceAudit — calibration results\n")
    lines.append(f"_Reproduce with `{reproduce}` ({backend_note})._\n")
    lines.append("## Baseline\n")
    lines.append(
        f"- Built from **{len(bc.NORMAL_PROMPTS)} benign prompts** (four styles: "
        f"factual, creative, step-by-step, casual) → **{len(baseline)}** distinct "
        f"baseline tokens, **{sum(baseline.values())}** total.\n"
    )
    lines.append("## False-positive test — held-out benign prompts\n")
    lines.append(
        f"{len(rows)} benign prompts ({styles} styles), streamed through the "
        f"full pipeline. Termination threshold = **{threshold}**. "
        f"{len(scores)} of them were measured.\n"
    )
    lines.append("| Prompt type | Prompt | Peak KL | Triggered |")
    lines.append("| :--- | :--- | ---: | :---: |")
    for category, p, k in rows:
        shown = "not measured" if k is None else f"{k:.4f}"
        fired = "" if k is None else ("YES" if k >= threshold else "no")
        lines.append(f"| {category} | {p} | {shown} | {fired} |")
    lines.append("")
    lines.append("## KL distribution across benign prompts\n")
    lines.append("| Metric | Value |")
    lines.append("| :--- | ---: |")
    lines.append(f"| count | {len(scores)} |")
    lines.append(f"| not measured | {len(unmeasured_benign)} |")
    lines.append(f"| mean | {mean:.4f} |")
    lines.append(f"| std (population) | {std:.4f} |")
    lines.append(f"| min | {min(scores):.4f} |")
    lines.append(f"| max | {max(scores):.4f} |")
    lines.append(f"| mean + 2·std | {mean + 2 * std:.4f} |")
    lines.append(f"| mean + 3·std | {mean + 3 * std:.4f} |")
    lines.append("")
    lines.append("## The gate's ceiling\n")
    lines.append(
        "The most divergent window the monitor can express is one in which "
        "every token is off-vocabulary: each one lands in the `<other>` "
        "bucket, which carries the baseline's smallest mass. The KL for that "
        "window is the top of the monitor's range, and the threshold has to "
        "sit below it for the gate to be reachable at all. It is a property "
        "of the baseline's vocabulary, not of any model.\n"
    )
    lines.append(f"- **Ceiling = {ceiling_value:.4f}** against a threshold of "
                 f"**{threshold}**.")
    lines.append(
        f"- The vocabulary has **{gate_ceiling['vocab_size']}** buckets, so "
        f"the smoothing floor spreads the window's mass over all of them: one "
        f"bucket can carry at most "
        f"**{gate_ceiling['max_bucket_mass']:.4f}** of the distribution, and "
        f"an unfamiliar token sits only "
        f"**{gate_ceiling['unfamiliar_token_ratio']:.0f}×** below the "
        f"baseline.\n"
    )
    lines.append("")
    lines.append("## Off-distribution probes — the gate's reach\n")
    lines.append(
        "Each probe asks for output whose tokens are unlike the baseline's. "
        "The reach is the highest peak KL any of them reached: it is how far "
        "the monitor can see, and the threshold has to sit below it for the "
        "gate to fire at all.\n"
    )
    lines.append("| Probe | Tokens | Peak KL | Crosses the threshold |")
    lines.append("| :--- | ---: | ---: | :---: |")
    for probe in probes:
        peak = probe["peak_kl"]
        shown = "not measured" if peak is None else f"{peak:.4f}"
        crosses = "" if peak is None else ("YES" if peak >= threshold else "no")
        lines.append(f"| {probe['name']} | {probe['tokens']} | {shown} | {crosses} |")
    lines.append("")
    lines.append(
        f"- **Reach = {reach:.4f}** against a threshold of **{threshold}**."
        if reach is not None
        else "- **Reach = not measured.**"
    )
    if unmeasured:
        lines.append(
            f"- {len(unmeasured)} probe(s) produced too few tokens to measure "
            f"and are excluded: {', '.join(unmeasured)}.\n"
        )
    lines.append("")
    lines.append("## Derived threshold\n")
    lines.append(
        f"- Textbook `mean + 2·std = {mean + 2 * std:.4f}` coincides with the "
        f"benign maximum (`{max(scores):.4f}`) — no margin, so a strict 2σ cut "
        f"risks false positives.\n"
    )
    if reach is None:
        lines.append(
            f"- **Operating threshold = {threshold}**: "
            f"{threshold / max(scores):.1f}× above the worst benign peak "
            f"({max(scores):.4f}). The reach was not measured, so whether the "
            f"gate can fire at all is unknown.\n"
        )
    elif reach < threshold:
        lines.append(
            f"- **Operating threshold = {threshold}**: "
            f"{threshold / max(scores):.1f}× above the worst benign peak "
            f"({max(scores):.4f}) — and {threshold / reach:.2f}× **above** the "
            f"reach ({reach:.4f}). The threshold sits above everything the "
            f"monitor can see, so the gate cannot fire on this backend.\n"
        )
        if ceiling_value < threshold:
            lines.append(
                f"- The threshold is also above the **ceiling** "
                f"({ceiling_value:.4f}): the statistic cannot express a value "
                f"that crosses it at all, for any answer, from any model. "
                f"Moving the constant down would not fix that — the ceiling "
                f"is a property of the baseline's vocabulary.\n"
            )
    else:
        lines.append(
            f"- **Operating threshold = {threshold}**: "
            f"{threshold / max(scores):.1f}× above the worst benign peak "
            f"({max(scores):.4f}) and {threshold / reach:.2f}× of the reach "
            f"({reach:.4f}) — a wide margin on both sides.\n"
        )
    lines.append(
        f"- **Result: {triggered}/{len(scores)} benign prompts triggered "
        f"termination.**"
        + (
            f" The divergent fixture reached {divergent:.4f}.\n"
            if divergent is not None
            else " The divergent fixture was not measured.\n"
        )
    )

    out_path = args.output
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    # The verdict. A calibration that measures a gate and does not say
    # whether the gate holds is a measurement, not a calibration.
    benign_clear = triggered == 0
    gate_fires = reach is not None and reach >= threshold
    if not benign_clear or not gate_fires:
        reason = []
        if not benign_clear:
            reason.append(
                f"{triggered}/{len(scores)} benign prompts reached {threshold} "
                f"(worst {max(scores):.4f})"
            )
        if not gate_fires:
            reason.append(
                f"the highest off-distribution probe reached "
                f"{reach if reach is not None else 'nothing measurable'}, "
                f"below the threshold {threshold}"
            )
        if ceiling_value < threshold:
            reason.append(
                f"the threshold is above the ceiling {ceiling_value:.4f}, so "
                f"the statistic cannot express a value that crosses it"
            )
        verdict = {
            "benign_clean": benign_clear,
            "gate_fires": gate_fires,
            "reach": reach,
            "ceiling": ceiling_value,
            "unmeasured_benign": len(unmeasured_benign),
            "reason": "; ".join(reason),
        }
    else:
        verdict = {
            "benign_clean": True,
            "gate_fires": True,
            "reach": reach,
            "ceiling": ceiling_value,
            "unmeasured_benign": len(unmeasured_benign),
            "reason": "no benign prompt reached the threshold and the "
            "off-distribution probes did",
        }

    payload = {
        "backend": backend,
        "model": model,
        "base_url": CFG.ollama_base_url if backend == "ollama" else "",
        "threshold": threshold,
        "monitor": {
            "window_size": CFG.window_size,
            "min_tokens_before_check": CFG.min_tokens_before_check,
            "smoothing": CFG.smoothing,
            "max_tokens": CFG.max_tokens,
        },
        "baseline": {
            "prompts": len(bc.NORMAL_PROMPTS),
            "tokens": sum(baseline.values()),
            "vocab": len(baseline),
            "other_tokens": baseline.get(OTHER, 0),
        },
        "ceiling": gate_ceiling,
        "benign": {
            "count": len(rows),
            "measured": len(scores),
            "not_measured": unmeasured_benign,
            "styles": styles,
            "mean": mean,
            "std": std,
            "min": min(scores),
            "max": max(scores),
            "false_positives": triggered,
            "peaks": [
                {"category": category, "prompt": prompt, "peak_kl": peak}
                for category, prompt, peak in rows
            ],
        },
        "divergent": {"peak_kl": divergent, "tokens": divergent_tokens},
        "probes": probes,
        "reach": reach,
        "verdict": verdict,
    }
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, sort_keys=True)
            f.write("\n")

    print(f"benign: N={len(scores)} mean={mean:.4f} std={std:.4f} "
          f"min={min(scores):.4f} max={max(scores):.4f} "
          f"not_measured={len(unmeasured_benign)}")
    print(f"divergent fixture peak KL = {divergent}")
    print(f"reach (highest off-distribution probe) = {reach}")
    print(f"ceiling (all-unseen window) = {ceiling_value}")
    print(f"threshold = {threshold} -> {triggered}/{len(scores)} benign false positives")
    print(f"wrote {out_path}")
    if args.json:
        print(f"wrote {args.json}")

    if not benign_clear or not gate_fires:
        print(
            f"VERDICT FAILED on the {backend} backend: {verdict['reason']}.",
            file=sys.stderr,
        )
        return 1
    print(f"VERDICT OK on the {backend} backend: the gate holds.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
