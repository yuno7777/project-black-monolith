"""TraceAudit configuration, sourced from environment variables.

TraceAudit is the reasoning-layer defense of Project Black Monolith. It sits
in front of a model's generation endpoint, watches the token stream in real
time, and (a) terminates the stream if the reasoning trace diverges too far
from an established baseline distribution, and (b) redacts credential/PII-like
patterns before anything is logged or persisted.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

MODULE_NAME = "trace-audit"


@dataclass(frozen=True)
class Config:
    # --- model backend -------------------------------------------------
    # "mock" (default): a deterministic, offline stand-in model so the demo
    # runs with no model download. "ollama": proxy a local Ollama server (or
    # any OpenAI-compatible completion endpoint at the same base URL).
    model_backend: str
    ollama_base_url: str
    ollama_model: str

    # --- divergence monitor --------------------------------------------
    baseline_path: str
    kl_threshold: float
    # Rolling window of most-recent tokens the live distribution is built from.
    window_size: int
    # Don't evaluate/terminate until at least this many tokens have streamed
    # (a short window is statistically noisy).
    min_tokens_before_check: int
    # Additive (Laplace) smoothing so unseen tokens don't blow up the KL term.
    smoothing: float

    # --- generation ----------------------------------------------------
    max_tokens: int

    # --- dashboard integration -----------------------------------------
    dashboard_url: str | None


def load_config() -> Config:
    return Config(
        model_backend=os.environ.get("MONOLITH_MODEL_BACKEND", "mock").strip().lower(),
        ollama_base_url=os.environ.get("MONOLITH_OLLAMA_URL", "http://localhost:11434"),
        ollama_model=os.environ.get("MONOLITH_OLLAMA_MODEL", "llama3.2"),
        baseline_path=os.environ.get("MONOLITH_BASELINE_PATH", "./baseline_distribution.json"),
        kl_threshold=float(os.environ.get("MONOLITH_KL_THRESHOLD", "1.5")),
        window_size=int(os.environ.get("MONOLITH_TA_WINDOW", "20")),
        min_tokens_before_check=int(os.environ.get("MONOLITH_MIN_TOKENS", "12")),
        smoothing=float(os.environ.get("MONOLITH_SMOOTHING", "0.5")),
        max_tokens=int(os.environ.get("MONOLITH_MAX_TOKENS", "60")),
        dashboard_url=os.environ.get("MONOLITH_DASHBOARD_URL") or None,
    )
