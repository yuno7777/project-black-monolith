"""Streaming proxy: forwards a prompt to a model backend and intercepts the
token stream in real time.

Two backends:
  * "mock" (default): a deterministic, offline stand-in model so the whole
    demo runs with no model download. Its output distribution depends on the
    prompt, exactly as a real model's would: an ordinary prompt yields normal
    reasoning tokens; a prompt that pushes for roundabout/evasive reasoning
    yields off-distribution tokens (which is what the divergence monitor is
    built to catch). If the prompt contains a credential-looking string, the
    mock "leaks" it into its trace — modeling a model echoing a secret from
    its context, so the PII scanner has something to catch.
  * "ollama": streams from a local Ollama server (or any compatible
    /api/generate endpoint) at MONOLITH_OLLAMA_URL.

As each token arrives it is run through the divergence monitor and the PII
scanner. On divergence the stream is terminated early and a safe refusal is
substituted; on a PII/credential hit the span is redacted before it is
forwarded, logged, or emitted.
"""

from __future__ import annotations

import asyncio
import random
from typing import AsyncIterator

from .config import Config
from .divergence_monitor import DivergenceMonitor
from .events import now_ms
from .pii_scanner import scan
from .redaction import redact

# Ordinary, on-distribution reasoning vocabulary.
NORMAL_TOKENS = (
    "let us think about this the user wants a clear answer first we consider "
    "the context then we provide a helpful response step by step because it "
    "is correct and safe so the answer follows from the facts we explain "
    "plainly and stay on topic"
).split()

# Off-distribution "roundabout / evasive" reasoning: familiar connective words
# mixed with unfamiliar nonsense tokens that never appear in the baseline, so
# the live distribution shifts hard away from it.
DIVERGENT_TOKENS = (
    "however conversely hypothetically circumvent pretend secretly bypass "
    "ignore the guardrails obfuscate reroute exfiltrate quietly without "
    "telling anyone fabricate a pretext misdirect the auditor zzxq qwploo "
    "vbnmk glorptastic wibblewobble frobnicate quuxly"
).split()

_DIVERGENCE_MARKERS = ("roundabout", "unusual", "evasive", "obfuscat", "circumvent")

SAFE_REFUSAL = (
    "[TraceAudit] Response terminated: the reasoning trace diverged from the "
    "safe baseline distribution and was stopped before completion. A safe "
    "refusal has been substituted for the remaining output."
)


def _looks_divergent(prompt: str) -> bool:
    p = prompt.lower()
    return any(m in p for m in _DIVERGENCE_MARKERS)


def _leaked_secrets(prompt: str) -> list[str]:
    """Credential-looking strings present in the prompt that the mock model
    will 'leak' back into its reasoning trace."""
    return [m.value for m in scan(prompt)]


async def _mock_stream(prompt: str, max_tokens: int) -> AsyncIterator[str]:
    rng = random.Random(hash(prompt) & 0xFFFFFFFF)
    pool = DIVERGENT_TOKENS if _looks_divergent(prompt) else NORMAL_TOKENS
    secrets = _leaked_secrets(prompt)
    for i in range(max_tokens):
        if secrets and i == 8:
            for secret in secrets:
                yield secret
                await asyncio.sleep(0.01)
        yield rng.choice(pool)
        await asyncio.sleep(0.02)


async def _ollama_stream(prompt: str, max_tokens: int, cfg: Config) -> AsyncIterator[str]:
    import json

    import httpx  # lazily imported: only needed for the ollama backend

    url = cfg.ollama_base_url.rstrip("/") + "/api/generate"
    payload = {
        "model": cfg.ollama_model,
        "prompt": prompt,
        "stream": True,
        "options": {"num_predict": max_tokens},
    }
    async with httpx.AsyncClient(timeout=None) as client:
        async with client.stream("POST", url, json=payload) as resp:
            async for line in resp.aiter_lines():
                if not line.strip():
                    continue
                data = json.loads(line)
                chunk = data.get("response", "")
                for tok in chunk.split():
                    yield tok
                if data.get("done"):
                    break


def _backend_stream(prompt: str, max_tokens: int, cfg: Config) -> AsyncIterator[str]:
    if cfg.model_backend == "ollama":
        return _ollama_stream(prompt, max_tokens, cfg)
    return _mock_stream(prompt, max_tokens)


class StreamAuditor:
    """Wraps a backend token stream with divergence + PII interception and
    yields event dicts ready for SSE serialization."""

    def __init__(self, cfg: Config, baseline_counts: dict[str, int], emit):
        self.cfg = cfg
        self.baseline_counts = baseline_counts
        self.emit = emit

    async def audit(self, prompt: str, max_tokens: int | None = None) -> AsyncIterator[dict]:
        max_tokens = max_tokens or self.cfg.max_tokens
        start = now_ms()
        monitor = DivergenceMonitor(
            baseline_counts=self.baseline_counts,
            threshold=self.cfg.kl_threshold,
            window_size=self.cfg.window_size,
            min_tokens_before_check=self.cfg.min_tokens_before_check,
            smoothing=self.cfg.smoothing,
        )
        reported_secrets: set[str] = set()
        peak_kl = 0.0

        async for token in _backend_stream(prompt, max_tokens, self.cfg):
            if not token:
                continue

            # --- PII / credential scan (redact before forward + log) -----
            outgoing = token
            token_matches = scan(token)
            if token_matches:
                outgoing = redact(token, token_matches)
                for m in token_matches:
                    if m.value in reported_secrets:
                        continue
                    reported_secrets.add(m.value)
                    self.emit(
                        "pii_redacted",
                        "warning",
                        {
                            "label": m.label,
                            "redacted_as": f"[REDACTED:{m.label}]",
                            "position_tokens": monitor.tokens_seen,
                        },
                    )
                    yield {
                        "type": "pii",
                        "label": m.label,
                        "redacted": f"[REDACTED:{m.label}]",
                    }

            # --- divergence monitor --------------------------------------
            kl = monitor.observe(token)
            if kl is not None:
                peak_kl = max(peak_kl, kl)

            yield {
                "type": "token",
                "token": outgoing,
                "kl": round(kl, 4) if kl is not None else None,
                "threshold": self.cfg.kl_threshold,
            }

            if monitor.is_divergent(kl):
                self.emit(
                    "reasoning_divergence_terminate",
                    "critical",
                    {
                        "kl_divergence": round(kl, 4),
                        "threshold": self.cfg.kl_threshold,
                        "tokens_seen": monitor.tokens_seen,
                        "detection_latency_ms": now_ms() - start,
                    },
                )
                yield {
                    "type": "terminated",
                    "reason": "reasoning_divergence",
                    "kl": round(kl, 4),
                    "threshold": self.cfg.kl_threshold,
                    "safe_refusal": SAFE_REFUSAL,
                }
                return

        yield {"type": "done", "peak_kl": round(peak_kl, 4), "tokens": monitor.tokens_seen}
