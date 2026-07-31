import asyncio
from types import SimpleNamespace

import httpx
import pytest

from src.stream_proxy import _ollama_stream


def config():
    return SimpleNamespace(
        ollama_base_url="http://model.internal",
        ollama_model="test-model",
    )


def test_ollama_backend_rejects_http_errors_before_streaming():
    async def handler(_request):
        return httpx.Response(503, json={"error": "unavailable"})

    async def collect():
        transport = httpx.MockTransport(handler)
        return [
            token
            async for token in _ollama_stream(
                "prompt",
                2,
                config(),
                transport=transport,
            )
        ]

    with pytest.raises(httpx.HTTPStatusError):
        asyncio.run(collect())


def test_ollama_backend_parses_successful_ndjson_stream():
    async def handler(request):
        assert request.url.path == "/api/generate"
        return httpx.Response(
            200,
            content=b'{"response":"safe answer","done":false}\n{"done":true}\n',
        )

    async def collect():
        transport = httpx.MockTransport(handler)
        return [
            token
            async for token in _ollama_stream(
                "prompt",
                2,
                config(),
                transport=transport,
            )
        ]

    assert asyncio.run(collect()) == ["safe", "answer"]
