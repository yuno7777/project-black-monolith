"""Rolling KL-divergence monitor over a streaming reasoning trace.

WHAT THIS FILE IS
-----------------
TraceAudit's first detector: it watches the STREAMING token distribution of a
model's output and notices when it drifts away from a captured "normal
reasoning" baseline. This is a statistical anomaly detector — no training, no
ML — built on KL divergence (a standard information-theory distance between
two probability distributions).

THE SIMPLE VERSION
------------------
Think of it as a dialect check. Before deployment, TraceAudit captures the
typical "vocabulary" of normal reasoning (baseline_capture.py -> counts of
tokens like "think", "the", "step", "because"). During a generation, it keeps
a rolling window of the last 20 tokens and asks: "does this window look like
normal reasoning, or has it drifted to words that never appear in normal
reasoning?" If the window drifts far enough, the stream is terminated.

THE TECHNICAL MECHANISM
-----------------------
  KL(live || baseline) = sum_x  P_live(x) * ln( P_live(x) / P_baseline(x) )

over a FIXED vocabulary = the baseline tokens PLUS a catch-all bucket called
"<other>". Tokens not in the baseline vocabulary collapse into <other>, whose
baseline mass is tiny — so a trace that wanders into off-distribution
reasoning (lots of unfamiliar tokens) drives KL up sharply. Crossing
`threshold` signals divergence; stream_proxy.py then terminates the stream
with a safe refusal.

WHY THE THRESHOLD IS 1.0 (the honest calibration story)
-------------------------------------------------------
Not guessed, not textbook: fixtures/calibrate.py measured the peak rolling KL
of 16 held-out benign prompts (mean 0.343, max 0.481) and of the divergent
fixture (3.29). The textbook mean+2*std = 0.47 sits RIGHT AT the benign max —
a strict 2-sigma cut would false-positive. The operating threshold sits in the
wide gap between the two populations: 1.0 is ~2.1x the worst benign peak and
~0.30x the divergent fixture. Headroom is deliberate because the benign
distribution is unusually tight (deterministic mock backend); a real model
would spread wider, and 1.0 absorbs that drift. See EVALUATION.md.

WHY THIS FILE HAS NO MODEL DEPENDENCY
-------------------------------------
It operates on token strings only, which makes it unit-testable in isolation
(tests/test_detection.py) and lets the calibration harness run offline.
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
    """Raw token counts, used by baseline capture (fixtures/baseline_capture.py
    streams benign prompts and feeds their tokens here)."""
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
        """Constructed PER REQUEST by StreamAuditor.audit() (stream_proxy.py)
        with config from trace-audit/src/config.py.

        At construction:
          - The fixed vocabulary = sorted baseline tokens + OTHER.
          - The baseline probabilities Q(x) are computed ONCE with Laplace
            (additive) smoothing: (count + smoothing) / (total + smoothing *
            vocab_size). Smoothing stops unseen tokens from producing infinite
            KL terms and gives every token a small nonzero baseline mass.
        """
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

        # The rolling window and its counts, both capped at window_size.
        self._window: deque[str] = deque(maxlen=window_size)
        self._counts: Counter[str] = Counter()
        self.tokens_seen = 0

    def _bucket(self, token: str) -> str:
        """Map a live token to a vocabulary key: its normalized form if the
        baseline knows it, otherwise the OTHER catch-all."""
        tok = normalize_token(token)
        return tok if tok in self.q else OTHER

    def observe(self, token: str) -> float | None:
        """Record one token; return the current KL divergence, or None if not
        enough tokens have streamed yet to evaluate.

        Called from: stream_proxy.py StreamAuditor.audit() for EVERY token.

        Step by step:
          1. If the window is full, the oldest token is pushed out — decrement
             its count (delete at zero).
          2. Bucket the new token, append it, increment its count.
          3. Before min_tokens_before_check (12) tokens, return None — a
             window that small is statistically noisy, so no termination
             decision is made yet.
          4. Otherwise return the KL of the current window vs the baseline.
        """
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
        """Compute KL(live || baseline) over the fixed vocabulary.

        The live distribution P(x) is the smoothed window counts;
        the baseline Q(x) was precomputed in __init__. Both are smoothed with
        the same `smoothing` so zero-count tokens contribute nothing (p = 0
        skips the term) instead of dividing by zero.
        """
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
        """THE decision: has the live window crossed the threshold?

        Called from stream_proxy.py; True means "terminate the stream".
        """
        return kl is not None and kl >= self.threshold
