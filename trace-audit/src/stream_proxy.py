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
import hashlib
import random
from dataclasses import dataclass
from typing import AsyncIterator

from .config import Config
from .divergence_monitor import DivergenceMonitor
from .events import EventContext, now_ms
from .pii_scanner import PiiMatch, scan

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

# Delay a small number of output fragments so a credential split by a
# tokenizer can be recognized and redacted before any fragment is released.
# The bound keeps streaming latency and memory finite.
PII_TOKEN_WINDOW = 16


@dataclass
class _BufferedToken:
    token: str
    kl: float | None


@dataclass
class _BufferDrain:
    outputs: list[_BufferedToken]
    matches: list[PiiMatch]


class PiiStreamBuffer:
    """Bounded look-behind that redacts matches spanning token boundaries."""

    def __init__(self, window_tokens: int = PII_TOKEN_WINDOW):
        if window_tokens < 2:
            raise ValueError("PII token window must be at least 2")
        self.window_tokens = window_tokens
        self._pending: list[_BufferedToken] = []

    def push(self, token: str, kl: float | None) -> _BufferDrain:
        self._pending.append(_BufferedToken(token, kl))
        return self._drain(force=False)

    def finish(self) -> _BufferDrain:
        return self._drain(force=True)

    def clear(self) -> None:
        self._pending.clear()

    def _drain(self, *, force: bool) -> _BufferDrain:
        matches = self._matches_ending_in_latest()
        if matches:
            outputs, applied = self._redact_matches(matches)
            self._pending.clear()
            return _BufferDrain(outputs, applied)
        if force:
            outputs, self._pending = self._pending, []
            return _BufferDrain(outputs, [])
        if len(self._pending) > self.window_tokens:
            return _BufferDrain([self._pending.pop(0)], [])
        return _BufferDrain([], [])

    def _matches_ending_in_latest(self) -> list[PiiMatch]:
        """Scan every contiguous suffix so both whole and split tokens match.

        Joining the entire window alone would erase real token boundaries:
        ``normal`` followed by ``AKIA...`` would lose the word boundary before
        the key. Suffixes include the final token by itself and every possible
        cross-token reconstruction ending at it.
        """
        if not self._pending:
            return []
        full_starts: list[int] = []
        cursor = 0
        for item in self._pending:
            full_starts.append(cursor)
            cursor += len(item.token)

        latest_length = len(self._pending[-1].token)
        found: dict[tuple[str, int, int], PiiMatch] = {}
        for start_index in range(len(self._pending)):
            candidate = "".join(
                item.token for item in self._pending[start_index:]
            )
            latest_start = len(candidate) - latest_length
            for match in scan(candidate):
                if match.end <= latest_start:
                    continue
                offset = full_starts[start_index]
                adjusted = PiiMatch(
                    label=match.label,
                    start=match.start + offset,
                    end=match.end + offset,
                    value=match.value,
                )
                found[(adjusted.label, adjusted.start, adjusted.end)] = adjusted
        return list(found.values())

    def _redact_matches(
        self, matches: list[PiiMatch]
    ) -> tuple[list[_BufferedToken], list[PiiMatch]]:
        """Apply combined-buffer offsets while retaining token boundaries."""
        starts: list[int] = []
        ends: list[int] = []
        cursor = 0
        fragments = [item.token for item in self._pending]
        for fragment in fragments:
            starts.append(cursor)
            cursor += len(fragment)
            ends.append(cursor)

        applied: list[PiiMatch] = []
        last_start = cursor + 1
        for match in sorted(matches, key=lambda candidate: candidate.start, reverse=True):
            if match.end > last_start:
                continue
            start_index = next(
                index for index, end in enumerate(ends) if match.start < end
            )
            end_index = next(
                index for index, end in enumerate(ends) if match.end <= end
            )
            start_offset = match.start - starts[start_index]
            end_offset = match.end - starts[end_index]
            placeholder = f"[REDACTED:{match.label}]"
            if start_index == end_index:
                fragment = fragments[start_index]
                fragments[start_index] = (
                    fragment[:start_offset] + placeholder + fragment[end_offset:]
                )
            else:
                fragments[start_index] = (
                    fragments[start_index][:start_offset] + placeholder
                )
                for index in range(start_index + 1, end_index):
                    fragments[index] = ""
                fragments[end_index] = fragments[end_index][end_offset:]
            applied.append(match)
            last_start = match.start

        outputs = [
            _BufferedToken(fragment, item.kl)
            for fragment, item in zip(fragments, self._pending)
            if fragment
        ]
        applied.reverse()
        return outputs, applied


def _looks_divergent(prompt: str) -> bool:
    p = prompt.lower()
    return any(m in p for m in _DIVERGENCE_MARKERS)


def _leaked_secrets(prompt: str) -> list[str]:
    """Credential-looking strings present in the prompt that the mock model
    will 'leak' back into its reasoning trace."""
    return [m.value for m in scan(prompt)]


def _stable_seed(prompt: str) -> int:
    """Process-independent seed. Python's built-in ``hash()`` is salted per
    process (PYTHONHASHSEED), so use a stable digest instead — this makes the
    mock backend genuinely deterministic across restarts, which the demo and
    the calibration harness rely on."""
    return int.from_bytes(hashlib.sha256(prompt.encode("utf-8")).digest()[:8], "big")


async def _mock_stream(prompt: str, max_tokens: int) -> AsyncIterator[str]:
    rng = random.Random(_stable_seed(prompt))
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

    async def audit(
        self,
        prompt: str,
        max_tokens: int | None = None,
        ctx: EventContext | None = None,
    ) -> AsyncIterator[dict]:
        """`ctx` carries the caller's correlation identity for this one
        generation, so a leaked credential or a terminated trace can be tied to
        detections the other layers made in the same agent session."""
        if max_tokens is not None and max_tokens < 1:
            raise ValueError("max_tokens must be positive")
        # MONOLITH_MAX_TOKENS is an operator-owned ceiling, not merely a
        # default that an untrusted request may override upward.
        max_tokens = min(max_tokens or self.cfg.max_tokens, self.cfg.max_tokens)
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
        pii_buffer = PiiStreamBuffer()

        async for token in _backend_stream(prompt, max_tokens, self.cfg):
            if not token:
                continue

            # Observe the reasoning token immediately; only client delivery is
            # delayed by the bounded PII look-behind.
            kl = monitor.observe(token)
            if kl is not None:
                peak_kl = max(peak_kl, kl)

            drain = pii_buffer.push(token, kl)
            if drain.matches:
                for m in drain.matches:
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
                        ctx,
                    )
                    yield {
                        "type": "pii",
                        "label": m.label,
                        "redacted": f"[REDACTED:{m.label}]",
                    }

            for outgoing in drain.outputs:
                yield {
                    "type": "token",
                    "token": outgoing.token,
                    "kl": round(outgoing.kl, 4) if outgoing.kl is not None else None,
                    "threshold": self.cfg.kl_threshold,
                }

            if monitor.is_divergent(kl):
                # Never release look-behind fragments after a terminated trace.
                pii_buffer.clear()
                self.emit(
                    "reasoning_divergence_terminate",
                    "critical",
                    {
                        "kl_divergence": round(kl, 4),
                        "threshold": self.cfg.kl_threshold,
                        "tokens_seen": monitor.tokens_seen,
                        "detection_latency_ms": now_ms() - start,
                    },
                    ctx,
                )
                yield {
                    "type": "terminated",
                    "reason": "reasoning_divergence",
                    "kl": round(kl, 4),
                    "threshold": self.cfg.kl_threshold,
                    "safe_refusal": SAFE_REFUSAL,
                }
                return

        drain = pii_buffer.finish()
        if drain.matches:
            for m in drain.matches:
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
                    ctx,
                )
                yield {
                    "type": "pii",
                    "label": m.label,
                    "redacted": f"[REDACTED:{m.label}]",
                }
        for outgoing in drain.outputs:
            yield {
                "type": "token",
                "token": outgoing.token,
                "kl": round(outgoing.kl, 4) if outgoing.kl is not None else None,
                "threshold": self.cfg.kl_threshold,
            }

        yield {"type": "done", "peak_kl": round(peak_kl, 4), "tokens": monitor.tokens_seen}
