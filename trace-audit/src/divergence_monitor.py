"""Rolling KL-divergence monitor over a streaming reasoning trace.

A baseline token distribution is captured from several "normal" prompts (see
fixtures/baseline_capture.py). As tokens stream during a live request, the
monitor maintains the distribution over a rolling window and computes

    KL(live || baseline) = sum_x  P_live(x) * ln( P_live(x) / P_baseline(x) )

over a fixed vocabulary. Tokens not in the baseline vocabulary collapse into
an ``<other>`` bucket whose baseline mass is tiny — so a trace that wanders
into off-distribution reasoning (lots of unfamiliar tokens) drives KL up
sharply. Crossing ``threshold`` signals divergence and lets the proxy
terminate the stream and return a safe refusal.

This module is pure Python and unit-testable without any model backend.
"""

from __future__ import annotations

import math
from collections import Counter, deque

OTHER = "<other>"

# --- Derived termination threshold -----------------------------------------
# Calibrated empirically (see fixtures/calibrate.py and
# fixtures/calibration_results.md), NOT guessed. Method: capture the baseline
# from 10 benign prompts spanning four styles (factual Q&A, creative writing,
# step-by-step reasoning, casual conversation), then measure the peak rolling
# KL of 16 *held-out* benign prompts drawn from those same four styles.
#
# Measured benign peak-KL distribution (N=16):
#     mean = 0.343   std = 0.064   min = 0.247   max = 0.481
# Divergent test fixture, for reference: peak KL = 3.29.
#
# The textbook mean + 2*std = 0.47 sits right at the benign maximum (0.481),
# leaving no margin — so a strict 2-sigma cut would risk false positives. We
# therefore set the operating threshold in the wide gap between the two
# populations:
#
#     DEFAULT_KL_THRESHOLD = 1.0
#
#   * ~2.1x above the highest observed benign peak (0.481)  -> 0/16 benign FP
#   * ~0.30x of the divergent fixture peak (3.29)           -> fires decisively
#
# The extra headroom over 2-sigma is deliberate: this benign distribution is
# unusually tight because the default backend is a deterministic mock; a real
# model backend would show wider benign spread, and 1.0 absorbs that drift.
DEFAULT_KL_THRESHOLD = 1.0


def normalize_token(token: str) -> str:
    """Canonical token key: lowercased, stripped. Empty tokens are ignored by
    the caller; here they map to OTHER defensively."""
    t = token.strip().lower()
    return t or OTHER


def build_distribution(tokens: list[str]) -> dict[str, int]:
    """Raw token counts, used by baseline capture."""
    return dict(Counter(normalize_token(t) for t in tokens))


class DivergenceMonitor:
    def __init__(
        self,
        *,
        baseline_counts: dict[str, int],
        threshold: float,
        window_size: int,
        min_tokens_before_check: int,
        smoothing: float,
    ):
        self.threshold = threshold
        self.window_size = window_size
        self.min_tokens_before_check = min_tokens_before_check
        self.smoothing = smoothing

        # Fixed vocabulary = baseline tokens + OTHER catch-all.
        self.vocab: list[str] = sorted(set(baseline_counts) | {OTHER})
        self.vocab_size = len(self.vocab)

        baseline_total = sum(baseline_counts.values())
        denom = baseline_total + smoothing * self.vocab_size
        # Smoothed baseline probabilities Q(x).
        self.q: dict[str, float] = {
            tok: (baseline_counts.get(tok, 0) + smoothing) / denom for tok in self.vocab
        }

        self._window: deque[str] = deque(maxlen=window_size)
        self._counts: Counter[str] = Counter()
        self.tokens_seen = 0

    def _bucket(self, token: str) -> str:
        tok = normalize_token(token)
        return tok if tok in self.q else OTHER

    def observe(self, token: str) -> float | None:
        """Record one token; return the current KL divergence, or None if not
        enough tokens have streamed yet to evaluate."""
        if len(self._window) == self.window_size:
            evicted = self._window[0]  # about to be pushed out by maxlen
            self._counts[evicted] -= 1
            if self._counts[evicted] <= 0:
                del self._counts[evicted]
        bucket = self._bucket(token)
        self._window.append(bucket)
        self._counts[bucket] += 1
        self.tokens_seen += 1

        if self.tokens_seen < self.min_tokens_before_check:
            return None
        return self._kl()

    def _kl(self) -> float:
        n = len(self._window)
        denom = n + self.smoothing * self.vocab_size
        kl = 0.0
        for tok in self.vocab:
            p = (self._counts.get(tok, 0) + self.smoothing) / denom
            q = self.q[tok]
            if p > 0.0:
                kl += p * math.log(p / q)
        return kl

    def is_divergent(self, kl: float | None) -> bool:
        return kl is not None and kl >= self.threshold
