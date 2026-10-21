#!/usr/bin/env python3
"""Build the baseline reasoning-token distribution from several NORMAL prompts.

Runs the ordinary prompts through the model backend, tallies the resulting
token counts, and writes them to the baseline file the TraceAudit service
loads at startup. This is what "normal" looks like; the divergence monitor
scores live streams against it.

The file also records *which model* the baseline was captured from. That
key is what opens the divergence gate: a KL score against a distribution
from another model means nothing, so the gateway refuses to score a live
stream against a baseline whose model is not the model answering. A
baseline captured from the mock backend records the mock backend's
identity, and the gate stays closed for every real model.

Run this before starting the service (the demo script does so automatically
if no baseline exists).

  python fixtures/baseline_capture.py                    # the configured backend
  python fixtures/baseline_capture.py --force            # replace an existing one
  python fixtures/baseline_capture.py --anthropic --model claude-sonnet-4-5
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.config import load_config  # noqa: E402
from src.divergence_monitor import build_distribution  # noqa: E402
from src.stream_proxy import _backend_stream  # noqa: E402

FALLBACK_BASELINE_PATHS = (
    "/app/fixtures/baseline_distribution.json",
    os.path.join(os.path.dirname(__file__), "baseline_distribution.json"),
)

# The model name recorded for the deterministic offline backend. It is not
# a model at all, and recording it as one is the point: the divergence gate
# compares the recorded model against the model answering a request, and
# "mock" is not a model any client will ask for.
MOCK_MODEL_NAME = "mock"

# Ordinary, benign reasoning prompts spanning a mix of styles — factual Q&A,
# short creative writing, step-by-step reasoning, and casual conversation — so
# the baseline distribution is not biased toward one prompt shape. None contain
# divergence markers or credentials, so they exercise the normal token
# distribution. (See fixtures/calibrate.py for how the threshold is derived
# from held-out prompts drawn from these same four categories.)
NORMAL_PROMPTS = [
    # factual Q&A
    "What is the capital of France and why is it historically significant?",
    "Explain in simple terms how vaccines help the immune system.",
    "How does compound interest grow savings over time?",
    # short creative writing
    "Write a short, cheerful paragraph about a walk in an autumn park.",
    "Describe a cozy cabin in the mountains during a light snowfall.",
    # step-by-step reasoning
    "Explain how to reset a forgotten password step by step.",
    "Walk through how to compare two job offers clearly.",
    "Describe how to back up important files safely.",
    # casual conversation
    "Any tips for staying focused while working from home?",
    "What is a fun, easy hobby to pick up on the weekend?",
]


def _has_valid_baseline(path: str) -> bool:
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return False
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict) or not data:
            return False
        if "counts" in data:
            return isinstance(data["counts"], dict) and len(data["counts"]) > 0
        if "distribution" in data:
            return isinstance(data["distribution"], dict) and len(data["distribution"]) > 0
        return all(
            isinstance(k, str)
            and k.strip()
            and isinstance(v, (int, float))
            and not isinstance(v, bool)
            and v > 0
            for k, v in data.items()
        )
    except Exception:
        return False


def _recorded_model(path: str) -> str | None:
    """The model an existing baseline was captured from, if it says."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    model = data.get("model")
    if isinstance(model, str) and model.strip():
        return model.strip()
    return None


def _write_atomic(path: str, payload: dict) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    os.replace(tmp_path, path)


def _option_value(args: list[str], name: str) -> str | None:
    """The value of ``--name value`` or ``--name=value``, if it is there."""
    prefix = name + "="
    for index, item in enumerate(args):
        if item == name and index + 1 < len(args):
            return args[index + 1]
        if item.startswith(prefix):
            return item[len(prefix) :]
    return None


def _backend_model(cfg) -> str:
    """The model the configured backend answers with."""
    if cfg.model_backend == "ollama":
        return cfg.ollama_model
    if cfg.model_backend == "openai":
        return cfg.openai_model
    return MOCK_MODEL_NAME


async def collect() -> list[str]:
    cfg = load_config()
    tokens: list[str] = []
    for prompt in NORMAL_PROMPTS:
        async for tok in _backend_stream(prompt, 80, cfg):
            tokens.append(tok)
    return tokens


async def collect_anthropic(cfg, model: str) -> list[str]:
    """The fragments one Anthropic answer produced, as the auditor sees them.

    The baseline has to be captured at the granularity the auditor
    actually scores. The Anthropic relay feeds the divergence monitor the
    model's text deltas as they arrive, so a baseline of whole words
    would score every answer against a distribution it can never match:
    the gate would open and then fire on ordinary traffic.

    So the capture reuses the relay's own request builder and its own SSE
    parser, and counts the deltas exactly where the relay counts them.
    """
    import httpx

    from src.anthropic_gateway import (
        AUDITED_DELTA_KINDS,
        audited_delta_text,
        build_upstream_request,
        iter_sse_events,
    )

    if not cfg.anthropic_api_key:
        raise RuntimeError(
            "no Anthropic credential is configured: set MONOLITH_ANTHROPIC_API_KEY"
        )

    fragments: list[str] = []
    timeout = httpx.Timeout(connect=5.0, read=300.0, write=30.0, pool=5.0)
    async with httpx.AsyncClient(timeout=timeout) as client:
        for prompt in NORMAL_PROMPTS:
            body = json.dumps(
                {
                    "model": model,
                    "max_tokens": 80,
                    "stream": True,
                    "messages": [{"role": "user", "content": prompt}],
                }
            ).encode("utf-8")
            # The operator's own key is the credential: the capture talks to
            # the API directly, not through the gateway.
            url, headers, payload = build_upstream_request(body, cfg, {})
            request = client.build_request("POST", url, content=payload, headers=headers)
            response = await client.send(request, stream=True)
            try:
                if response.status_code != 200:
                    detail = (await response.aread()).decode("utf-8", "replace")[:200]
                    raise RuntimeError(
                        f"the Anthropic API answered {response.status_code}: {detail}"
                    )
                async for _name, data in iter_sse_events(response.aiter_lines()):
                    if data.get("type") != "content_block_delta":
                        continue
                    delta = data.get("delta")
                    if not isinstance(delta, dict):
                        continue
                    if delta.get("type") not in AUDITED_DELTA_KINDS:
                        continue
                    text = audited_delta_text(delta)
                    if text:
                        fragments.append(text)
            finally:
                await response.aclose()
    return fragments


def main(argv: list[str] | None = None, *, force: bool = False) -> None:
    cfg = load_config()
    args = argv if argv is not None else sys.argv[1:]
    force_overwrite = force or ("--force" in args) or ("--force" in sys.argv)
    from_anthropic = "--anthropic" in args
    model_option = _option_value(args, "--model")

    if not force_overwrite and _has_valid_baseline(cfg.baseline_path):
        recorded = _recorded_model(cfg.baseline_path)
        print(
            f"[baseline] existing valid baseline found at {cfg.baseline_path}; "
            f"skipping capture (pass --force to overwrite)"
        )
        if recorded:
            print(f"[baseline] the existing baseline was captured from model {recorded}")
        return

    try:
        if from_anthropic:
            model = model_option or cfg.anthropic_model
            if not model:
                raise RuntimeError(
                    "the Anthropic capture needs a model: pass --model, or pin "
                    "MONOLITH_ANTHROPIC_MODEL so the gateway asks for the same one"
                )
            tokens = asyncio.run(collect_anthropic(cfg, model))
        else:
            model = model_option or _backend_model(cfg)
            tokens = asyncio.run(collect())
        counts = build_distribution(tokens)
        if not counts:
            raise RuntimeError("no tokens collected from upstream backend")
        out = {
            "counts": counts,
            "total": sum(counts.values()),
            "prompts": len(NORMAL_PROMPTS),
            "vocab": len(counts),
            # The model the baseline was captured from. The divergence gate
            # compares it against the model that answers a request, so
            # without this key the gate can never open.
            "model": model,
        }
        _write_atomic(cfg.baseline_path, out)
        print(
            f"[baseline] captured {out['total']} tokens across {out['prompts']} normal "
            f"prompts ({out['vocab']} distinct) from model {out['model']} -> "
            f"{cfg.baseline_path}"
        )
        if out["model"] == MOCK_MODEL_NAME:
            print(
                "[baseline] the divergence gate stays closed for every real model "
                "against this baseline: capture one from the model that answers "
                "(--anthropic --model <name>) to open it"
            )
    except Exception as exc:
        print(
            f"[baseline] warning: failed to capture baseline from upstream ({exc}); "
            "falling back to static baseline if available",
            file=sys.stderr,
        )
        target_abs = os.path.abspath(cfg.baseline_path)
        for fallback in FALLBACK_BASELINE_PATHS:
            if os.path.exists(fallback) and os.path.abspath(fallback) != target_abs:
                parent = os.path.dirname(target_abs)
                if parent:
                    os.makedirs(parent, exist_ok=True)
                tmp_path = f"{cfg.baseline_path}.tmp"
                shutil.copyfile(fallback, tmp_path)
                os.replace(tmp_path, cfg.baseline_path)
                print(
                    f"[baseline] copied fallback baseline from {fallback} -> {cfg.baseline_path}",
                    file=sys.stderr,
                )
                break


if __name__ == "__main__":
    main()
