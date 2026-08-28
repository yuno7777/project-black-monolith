import asyncio
from types import SimpleNamespace

import httpx
import pytest
from src.stream_proxy import MAX_OLLAMA_LINE_BYTES, _ollama_stream


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


def test_ollama_backend_cannot_exceed_the_requested_token_budget():
    async def handler(_request):
        return httpx.Response(
            200,
            content=b'{"response":"one two three four","done":false}\n',
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

    assert asyncio.run(collect()) == ["one", "two"]


def test_ollama_backend_rejects_pathologically_large_tokens():
    content = b'{"response":"' + b"x" * (8 * 1024 + 1) + b'","done":false}\n'

    async def handler(_request):
        return httpx.Response(200, content=content)

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

    with pytest.raises(ValueError, match="token exceeds"):
        asyncio.run(collect())


@pytest.mark.parametrize(
    "content",
    [
        b'[]\n',
        b'{"response":42,"done":false}\n',
        b'{"response":"safe","done":"yes"}\n',
    ],
)
def test_ollama_backend_rejects_malformed_or_oversized_records(content):
    async def handler(_request):
        return httpx.Response(200, content=content)

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

    with pytest.raises(ValueError):
        asyncio.run(collect())


def test_ollama_backend_rejects_oversized_records():
    content = b'{"response":"' + b"x" * MAX_OLLAMA_LINE_BYTES + b'"}\n'

    async def handler(_request):
        return httpx.Response(200, content=content)

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

    with pytest.raises(ValueError):
        asyncio.run(collect())
