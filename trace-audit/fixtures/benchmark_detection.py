#!/usr/bin/env python3
"""TraceAudit detection-accuracy benchmark — divergence + PII scanner.

Scores two detectors over labelled corpora and emits confusion matrices with
derived metrics, plus the per-token latency folded in from `benchmark.py`.

  Divergence: attack = DIVERGENT_PROMPTS, benign = the 16 held-out prompts.
              A prompt is "detected" if its peak rolling KL crosses the operating
              threshold. Uses the deterministic mock backend and the real
              DivergenceMonitor.
  PII:        attack = PII_SECRETS (each must be caught → recall), benign =
              PII_BENIGN_LOOKALIKES (must not be flagged → precision).

Deterministic. Writes `benchmark_results.json` for the uploader and exits
non-zero if the gates are not met.

    python fixtures/benchmark_detection.py
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

from src.config import load_config  # noqa: E402
from src.divergence_monitor import (  # noqa: E402
    DEFAULT_KL_THRESHOLD,
    DivergenceMonitor,
    build_distribution,
)
from src.pii_scanner import scan  # noqa: E402
from src.stream_proxy import _backend_stream  # noqa: E402
import baseline_capture as bc  # noqa: E402
from calibrate import HELD_OUT  # noqa: E402
import benchmark as latency  # noqa: E402
import benchmark_corpus as corpus  # noqa: E402

BENCHMARK_VERSION = 1
CFG = load_config()

# Gates (regression floors, at/below what the detectors actually achieve).
MIN_DIVERGENCE_DETECTION = 1.0   # every marked-divergent prompt must be caught
MAX_DIVERGENCE_FPR = 0.0         # no benign prompt may trip it
MIN_PII_RECALL = 1.0             # every planted secret must be caught
MIN_PII_PRECISION = 0.80         # some benign look-alikes are expected to trip


async def _tokens(prompt: str, n: int) -> list[str]:
    return [tok async for tok in _backend_stream(prompt, n, CFG)]


def build_baseline() -> dict[str, int]:
    async def go() -> list[str]:
        toks: list[str] = []
        for p in bc.NORMAL_PROMPTS:
            toks += await _tokens(p, 80)
        return toks
    return build_distribution(asyncio.run(go()))


def peak_kl(prompt: str, baseline: dict[str, int]) -> float:
    mon = DivergenceMonitor(
        baseline_counts=baseline,
        threshold=float("inf"),  # never cut short; we want the true peak
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


def score_divergence(baseline: dict[str, int]) -> dict:
    threshold = DEFAULT_KL_THRESHOLD
    tp = fn = fp = tn = 0
    benign = [p for prompts in HELD_OUT.values() for p in prompts]

    for prompt in corpus.DIVERGENT_PROMPTS:
        if peak_kl(prompt, baseline) >= threshold:
            tp += 1
        else:
            fn += 1
    for prompt in benign:
        if peak_kl(prompt, baseline) >= threshold:
            fp += 1
        else:
            tn += 1

    return _report(
        detector="reasoning_divergence", paradigm="threshold",
        tp=tp, fp=fp, tn=tn, fn=fn,
        latency={k: round(v, 1) for k, v in latency.measure().items()
                 if k in ("p50", "p95", "p99")},
        thresholds={"kl_threshold": threshold, "window_size": CFG.window_size,
                    "min_tokens_before_check": CFG.min_tokens_before_check},
        notes=("Attack = prompts marked divergent for the deterministic mock "
               "backend; benign = 16 held-out prompts across four styles. The "
               "mock is a stand-in — a real model backend needs recalibration."),
    )


def score_pii() -> dict:
    tp = fn = fp = tn = 0
    for _label, text in corpus.PII_SECRETS:
        if scan(text):
            tp += 1
        else:
            fn += 1
    for text in corpus.PII_BENIGN_LOOKALIKES:
        if scan(text):
            fp += 1
        else:
            tn += 1
    return _report(
        detector="pii_scanner", paradigm="regex",
        tp=tp, fp=fp, tn=tn, fn=fn,
        latency=None,  # per-token latency is reported once, under divergence
        thresholds={"patterns": 6},
        notes=("Attack = planted fake secrets (6 types); benign = adversarial "
               "look-alikes. A 16-digit tracking number is kept in on purpose: "
               "the credit-card regex cannot tell it from a card, so it is a "
               "true false positive that keeps precision honest."),
    )


def _report(*, detector, paradigm, tp, fp, tn, fn, latency, thresholds, notes) -> dict:
    detection_rate = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = detection_rate
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {
        "benchmark_version": BENCHMARK_VERSION,
        "run_at_ms": int(time.time() * 1000),
        "module": "trace-audit",
        "detector": detector,
        "paradigm": paradigm,
        "corpus": {"attack_samples": tp + fn, "benign_samples": fp + tn},
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "metrics": {
            "detection_rate": round(detection_rate, 4),
            "false_positive_rate": round(fpr, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
        },
        "latency_us": latency,
        "thresholds": thresholds,
        "notes": notes,
    }


def main() -> None:
    baseline = build_baseline()
    reports = [score_divergence(baseline), score_pii()]

    out = os.path.join(os.path.dirname(__file__), "benchmark_results.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(reports, f, indent=2)
    print(json.dumps(reports, indent=2))
    print(f"\nwrote {out}")

    div, pii = reports
    ok = True
    if div["metrics"]["detection_rate"] < MIN_DIVERGENCE_DETECTION:
        print(f"GATE FAIL: divergence detection {div['metrics']['detection_rate']} < {MIN_DIVERGENCE_DETECTION}")
        ok = False
    if div["metrics"]["false_positive_rate"] > MAX_DIVERGENCE_FPR:
        print(f"GATE FAIL: divergence FPR {div['metrics']['false_positive_rate']} > {MAX_DIVERGENCE_FPR}")
        ok = False
    if pii["metrics"]["recall"] < MIN_PII_RECALL:
        print(f"GATE FAIL: PII recall {pii['metrics']['recall']} < {MIN_PII_RECALL}")
        ok = False
    if pii["metrics"]["precision"] < MIN_PII_PRECISION:
        print(f"GATE FAIL: PII precision {pii['metrics']['precision']} < {MIN_PII_PRECISION}")
        ok = False
    if not ok:
        sys.exit(1)
    print(f"\nGATES PASS: divergence {div['metrics']['detection_rate']:.0%} detect / "
          f"{div['metrics']['false_positive_rate']:.0%} FPR; "
          f"PII {pii['metrics']['recall']:.0%} recall / {pii['metrics']['precision']:.0%} precision")


if __name__ == "__main__":
    main()
