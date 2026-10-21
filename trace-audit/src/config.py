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
    allow_insecure_dashboard: bool
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
    openai_base_url: str = "http://localhost:8000"
    openai_api_key: str | None = None
    openai_model: str = "default"

    # --- Anthropic gateway ---------------------------------------------
    # The Messages API endpoint Claude Code and every other Anthropic client
    # speaks. The gateway is transparent: it forwards the request upstream and
    # pipes the answer back through the auditor.
    anthropic_base_url: str = "https://api.anthropic.com"
    # Credential used when the incoming request carries none. When it is
    # unset the client's own credential is forwarded instead, so the gateway
    # can sit in front of a normal Anthropic client without holding a key.
    anthropic_api_key: str | None = None
    # Override the model the upstream request names. Empty means "use the
    # model the client asked for".
    anthropic_model: str | None = None
    # Ceiling on the tokens a single upstream request may ask for. Unlike
    # MONOLITH_MAX_TOKENS (which truncates a generated stream) this one
    # rejects the request, because truncating an answer mid-way would leave
    # the client with a half-message it cannot parse.
    anthropic_max_tokens: int = 8192
    # Whether the model upstream may be plain HTTP to a host that is not
    # loopback. The default is no: the gateway forwards the client's own
    # credential upstream, and a credential in cleartext is a credential on
    # the wire. The escape hatch exists for an operator whose model service
    # is genuinely on a trusted network, and it has to be asked for by name.
    anthropic_allow_insecure: bool = False


def _valid_bearer_token(value: str) -> bool:
    return len(value) >= 16 and all(
        char.isascii() and (char.isalnum() or char in "-._~+/=")
        for char in value
    )


def _validate_id(name: str, value: str | None, *, required: bool = False) -> None:
    if value is None and not required:
        return
    trimmed = value.strip() if value is not None else ""
    if (
        not trimmed
        or len(trimmed) > MAX_ID_LENGTH
        or any(not character.isprintable() for character in trimmed)
    ):
        raise ValueError(f"{name} must be between 1 and {MAX_ID_LENGTH} characters")


def _validate_config(cfg: Config) -> Config:
    if cfg.model_backend not in {"mock", "ollama", "openai", "anthropic"}:
        raise ValueError(
            "MONOLITH_MODEL_BACKEND must be 'mock', 'ollama', 'openai', or 'anthropic'"
        )
    if not cfg.ollama_base_url.startswith(("http://", "https://")):
        raise ValueError("MONOLITH_OLLAMA_URL must use http:// or https://")
    ollama_model = cfg.ollama_model.strip()
    if (
        not ollama_model
        or len(ollama_model.encode("utf-8")) > 128
        or any(not character.isprintable() for character in ollama_model)
    ):
        raise ValueError("MONOLITH_OLLAMA_MODEL must be 1-128 printable UTF-8 bytes")
    if not cfg.openai_base_url.startswith(("http://", "https://")):
        raise ValueError("MONOLITH_OPENAI_BASE_URL must use http:// or https://")
    openai_model = cfg.openai_model.strip()
    if (
        not openai_model
        or len(openai_model.encode("utf-8")) > 128
        or any(not character.isprintable() for character in openai_model)
    ):
        raise ValueError("MONOLITH_OPENAI_MODEL must be 1-128 printable UTF-8 bytes")
    if cfg.openai_api_key is not None and (
        not cfg.openai_api_key.strip()
        or any(
            not character.isprintable() or character in "\r\n"
            for character in cfg.openai_api_key
        )
    ):
        raise ValueError("MONOLITH_OPENAI_API_KEY must be printable header-safe characters")
    if not cfg.baseline_path.strip():
        raise ValueError("MONOLITH_BASELINE_PATH must not be blank")
    if not cfg.anthropic_base_url.startswith(("http://", "https://")):
        raise ValueError("MONOLITH_ANTHROPIC_BASE_URL must use http:// or https://")
    if cfg.anthropic_api_key is not None and (
        not cfg.anthropic_api_key.strip()
        or any(
            not character.isprintable() or character in "\r\n"
            for character in cfg.anthropic_api_key
        )
    ):
        raise ValueError("MONOLITH_ANTHROPIC_API_KEY must be printable header-safe characters")
    if cfg.anthropic_model is not None:
        anthropic_model = cfg.anthropic_model.strip()
        if (
            not anthropic_model
            or len(anthropic_model.encode("utf-8")) > 128
            or any(not character.isprintable() for character in anthropic_model)
        ):
            raise ValueError("MONOLITH_ANTHROPIC_MODEL must be 1-128 printable UTF-8 bytes")
    if not 1 <= cfg.anthropic_max_tokens <= 1_000_000:
        raise ValueError("MONOLITH_ANTHROPIC_MAX_TOKENS must be between 1 and 1000000")
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
        allow_insecure_dashboard=os.environ.get("MONOLITH_ALLOW_INSECURE_DASHBOARD") == "true",
        admin_token=os.environ.get("MONOLITH_ADMIN_TOKEN") or None,
        tenant_id=os.environ.get("MONOLITH_TENANT_ID", "default"),
        agent_id=os.environ.get("MONOLITH_AGENT_ID") or None,
        session_id=os.environ.get("MONOLITH_SESSION_ID") or None,
        openai_base_url=(
            os.environ.get("MONOLITH_OPENAI_BASE_URL")
            or os.environ.get("MONOLITH_OPENAI_URL")
            or "http://localhost:8000"
        ),
        openai_api_key=os.environ.get("MONOLITH_OPENAI_API_KEY") or None,
        openai_model=os.environ.get("MONOLITH_OPENAI_MODEL", "default"),
        anthropic_base_url=os.environ.get(
            "MONOLITH_ANTHROPIC_BASE_URL", "https://api.anthropic.com"
        ).rstrip("/"),
        anthropic_api_key=os.environ.get("MONOLITH_ANTHROPIC_API_KEY") or None,
        anthropic_model=os.environ.get("MONOLITH_ANTHROPIC_MODEL") or None,
        anthropic_max_tokens=int(
            os.environ.get("MONOLITH_ANTHROPIC_MAX_TOKENS", "8192")
        ),
        anthropic_allow_insecure=(
            os.environ.get("MONOLITH_ALLOW_INSECURE_ANTHROPIC") == "true"
        ),
    )
    return _validate_config(cfg)
