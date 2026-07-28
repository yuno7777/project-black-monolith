"""Generation inputs are bounded and cannot override the operator token cap."""

import asyncio
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from src.main import MAX_PROMPT_BYTES, GenerateRequest
from src.stream_proxy import StreamAuditor


@pytest.mark.parametrize(
    "payload",
    [
        {"prompt": ""},
        {"prompt": "   "},
        {"prompt": "x", "max_tokens": 0},
        {"prompt": "x", "max_tokens": 4097},
        {"prompt": "x" * (MAX_PROMPT_BYTES + 1)},
        {"prompt": "x", "unexpected": True},
    ],
)
def test_generation_inputs_are_bounded(payload):
    with pytest.raises(ValidationError):
        GenerateRequest.model_validate(payload)


def test_operator_max_tokens_is_a_hard_ceiling():
    cfg = SimpleNamespace(
        max_tokens=3,
        model_backend="mock",
        kl_threshold=100.0,
        window_size=20,
        min_tokens_before_check=12,
        smoothing=0.5,
    )
    auditor = StreamAuditor(cfg, {}, lambda *_args: None)

    async def collect():
        return [event async for event in auditor.audit("ordinary prompt", max_tokens=100)]

    events = asyncio.run(collect())
    assert events[-1] == {"type": "done", "peak_kl": 0.0, "tokens": 3}


def test_direct_auditor_call_rejects_non_positive_token_count():
    cfg = SimpleNamespace(
        max_tokens=3,
        model_backend="mock",
        kl_threshold=100.0,
        window_size=20,
        min_tokens_before_check=12,
        smoothing=0.5,
    )
    auditor = StreamAuditor(cfg, {}, lambda *_args: None)

    async def collect():
        return [event async for event in auditor.audit("ordinary prompt", max_tokens=0)]

    with pytest.raises(ValueError, match="positive"):
        asyncio.run(collect())
