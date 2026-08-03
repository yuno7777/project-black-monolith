"""TraceAudit configuration, sourced from environment variables.

TraceAudit is the reasoning-layer defense of Project Black Monolith. It sits
in front of a model's generation endpoint, watches the token stream in real
time, and (a) terminates the stream if the reasoning trace diverges too far
from an established baseline distribution, and (b) redacts credential/PII-like
patterns before anything is logged or persisted.
"""

from __future__ import annotations

import math
import os
from dataclasses import dataclass

from .divergence_monitor import DEFAULT_KL_THRESHOLD

MODULE_NAME = "trace-audit"
MAX_ID_LENGTH = 128


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
    event_token: str | None
    event_outbox_path: str
    admin_token: str | None

    # --- correlation ----------------------------------------------------
    # Process-level defaults for who the detections belong to. A per-request
    # X-Monolith-* header overrides them, which is how one service serving many
    # agents attributes each detection correctly. Both are None unless
    # configured: an invented session id would group unrelated agents together,
    # and the grouping is the entire point of having one.
    tenant_id: str
    agent_id: str | None
    session_id: str | None


def _valid_bearer_token(value: str) -> bool:
    return len(value) >= 16 and all(
        char.isascii() and (char.isalnum() or char in "-._~+/=")
        for char in value
    )


def _validate_id(name: str, value: str | None, *, required: bool = False) -> None:
    if value is None and not required:
        return
    if value is None or not value.strip() or len(value.strip()) > MAX_ID_LENGTH:
        raise ValueError(f"{name} must be between 1 and {MAX_ID_LENGTH} characters")


def _validate_config(cfg: Config) -> Config:
    if cfg.model_backend not in {"mock", "ollama"}:
        raise ValueError("MONOLITH_MODEL_BACKEND must be 'mock' or 'ollama'")
    if not cfg.ollama_base_url.startswith(("http://", "https://")):
        raise ValueError("MONOLITH_OLLAMA_URL must use http:// or https://")
    if not cfg.ollama_model.strip() or len(cfg.ollama_model) > 128:
        raise ValueError("MONOLITH_OLLAMA_MODEL must be between 1 and 128 characters")
    if not cfg.baseline_path.strip():
        raise ValueError("MONOLITH_BASELINE_PATH must not be blank")
    if not math.isfinite(cfg.kl_threshold) or not 0 < cfg.kl_threshold <= 100:
        raise ValueError("MONOLITH_KL_THRESHOLD must be greater than 0 and at most 100")
    if not 1 <= cfg.window_size <= 10_000:
        raise ValueError("MONOLITH_TA_WINDOW must be between 1 and 10000")
    if not 1 <= cfg.min_tokens_before_check <= cfg.window_size:
        raise ValueError(
            "MONOLITH_MIN_TOKENS must be between 1 and the divergence window size"
        )
    if not math.isfinite(cfg.smoothing) or not 0 < cfg.smoothing <= 100:
        raise ValueError("MONOLITH_SMOOTHING must be greater than 0 and at most 100")
    if not 1 <= cfg.max_tokens <= 4096:
        raise ValueError("MONOLITH_MAX_TOKENS must be between 1 and 4096")
    if bool(cfg.dashboard_url) != bool(cfg.event_token):
        raise ValueError(
            "MONOLITH_DASHBOARD_URL and MONOLITH_EVENT_TOKEN must be configured together"
        )
    if cfg.dashboard_url and not cfg.dashboard_url.startswith(("http://", "https://")):
        raise ValueError("MONOLITH_DASHBOARD_URL must use http:// or https://")
    if cfg.event_token and not _valid_bearer_token(cfg.event_token):
        raise ValueError("MONOLITH_EVENT_TOKEN must be a header-safe token of at least 16 characters")
    if cfg.admin_token and not _valid_bearer_token(cfg.admin_token):
        raise ValueError("MONOLITH_ADMIN_TOKEN must be a header-safe token of at least 16 characters")
    _validate_id("MONOLITH_TENANT_ID", cfg.tenant_id, required=True)
    _validate_id("MONOLITH_AGENT_ID", cfg.agent_id)
    _validate_id("MONOLITH_SESSION_ID", cfg.session_id)
    return cfg


def load_config() -> Config:
    cfg = Config(
        model_backend=os.environ.get("MONOLITH_MODEL_BACKEND", "mock").strip().lower(),
        ollama_base_url=os.environ.get("MONOLITH_OLLAMA_URL", "http://localhost:11434"),
        ollama_model=os.environ.get("MONOLITH_OLLAMA_MODEL", "llama3.2"),
        baseline_path=os.environ.get("MONOLITH_BASELINE_PATH", "./baseline_distribution.json"),
        kl_threshold=float(
            os.environ.get("MONOLITH_KL_THRESHOLD", str(DEFAULT_KL_THRESHOLD))
        ),
        window_size=int(os.environ.get("MONOLITH_TA_WINDOW", "20")),
        min_tokens_before_check=int(os.environ.get("MONOLITH_MIN_TOKENS", "12")),
        smoothing=float(os.environ.get("MONOLITH_SMOOTHING", "0.5")),
        max_tokens=int(os.environ.get("MONOLITH_MAX_TOKENS", "60")),
        dashboard_url=os.environ.get("MONOLITH_DASHBOARD_URL") or None,
        event_token=os.environ.get("MONOLITH_EVENT_TOKEN") or None,
        event_outbox_path=os.environ.get("MONOLITH_EVENT_OUTBOX_PATH", "./event_outbox.db"),
        admin_token=os.environ.get("MONOLITH_ADMIN_TOKEN") or None,
        tenant_id=os.environ.get("MONOLITH_TENANT_ID", "default"),
        agent_id=os.environ.get("MONOLITH_AGENT_ID") or None,
        session_id=os.environ.get("MONOLITH_SESSION_ID") or None,
    )
    return _validate_config(cfg)
