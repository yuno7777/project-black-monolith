"""What does TraceAudit's auditing cost per token?

This is the overhead that matters most in the project: it is paid on every token
of every stream, so it lands directly in the latency a user feels. The model's
own generation is excluded — it happens with or without this defense, and
charging it to the defense would flatter it. What is timed is exactly what
`stream_proxy` adds per token: the PII scan and the rolling KL update.

The monitor is warmed past `min_tokens_before_check` first, so the KL is
actually being computed rather than skipped — the cheap path is not the one
worth reporting.

Run from the module root:  python fixtures/benchmark.py
"""

from __future__ import annotations

import random
import statistics
import sys
import time

sys.path.insert(0, ".")

from src.divergence_monitor import DEFAULT_KL_THRESHOLD, DivergenceMonitor  # noqa: E402
from src.pii_scanner import scan  # noqa: E402

WINDOW = 20
MIN_TOKENS = 12
SMOOTHING = 0.5
ITERATIONS = 5_000

# A baseline of realistic size (the shipped one is captured from 10 prompts).
VOCAB = (
    "let us think about this the user wants a clear answer first we consider "
    "the context then we provide a helpful response step by step because it "
    "is correct and safe so the answer follows from the facts we explain "
    "plainly and stay on topic"
).split()


def main() -> None:
    rng = random.Random(20260717)  # fixed seed: reproducible run to run
    baseline = {token: rng.randint(1, 40) for token in set(VOCAB)}
    monitor = DivergenceMonitor(
        baseline_counts=baseline,
        threshold=DEFAULT_KL_THRESHOLD,
        window_size=WINDOW,
        min_tokens_before_check=MIN_TOKENS,
        smoothing=SMOOTHING,
    )

    # Warm past min_tokens_before_check so KL is genuinely computed below.
    for _ in range(MIN_TOKENS + WINDOW):
        monitor.observe(rng.choice(VOCAB))

    samples: list[float] = []
    for _ in range(ITERATIONS):
        token = rng.choice(VOCAB)
        start = time.perf_counter()
        # Exactly what stream_proxy does per token.
        scan(token)
        kl = monitor.observe(token)
        monitor.is_divergent(kl)
        samples.append((time.perf_counter() - start) * 1_000_000)

    samples.sort()
    print(f"TraceAudit — auditing overhead per token (N={ITERATIONS})")
    print(f"  window={WINDOW}  baseline_vocab={len(baseline)}  threshold={DEFAULT_KL_THRESHOLD}")
    print()
    print(f"  mean    {statistics.mean(samples):8.1f} us")
    print(f"  median  {statistics.median(samples):8.1f} us")
    print(f"  p95     {samples[int(len(samples) * 0.95)]:8.1f} us")
    print(f"  p99     {samples[int(len(samples) * 0.99)]:8.1f} us")
    print(f"  max     {samples[-1]:8.1f} us")
    print()
    print(f"  a 60-token response costs ~{statistics.mean(samples) * 60 / 1000:.2f} ms of auditing")


if __name__ == "__main__":
    main()
