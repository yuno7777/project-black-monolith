"""The OpenAI-compatible endpoint's prompt projection.

The endpoint speaks text: it projects the client's messages into one string
and hands that to a text backend, and the auditor scans that string. A
content block carrying something else — an image, a tool result — cannot be
projected into it and cannot be audited, and dropping such a block in
silence would answer a question the client did not ask. These tests pin the
refusal, and pin the shapes that are accepted.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from src.divergence_monitor import build_distribution
from src.main import _messages_to_prompt, app
from src.stream_proxy import NORMAL_TOKENS, StreamAuditor


def _setup_app_state(tmp_path, **cfg_overrides):
    defaults = dict(
        model_backend="mock",
        ollama_base_url="http://localhost:11434",
        ollama_model="llama3.2",
        openai_base_url="http://localhost:8000",
        openai_api_key=None,
        openai_model="default",
        baseline_path=str(tmp_path / "baseline.json"),
        kl_threshold=1.0,
        window_size=20,
        min_tokens_before_check=12,
        smoothing=0.5,
        max_tokens=60,
        dashboard_url=None,
        event_token=None,
        event_outbox_path=str(tmp_path / "outbox.db"),
        allow_insecure_dashboard=False,
        admin_token="admin-secret-token-0000",
        tenant_id="default",
        agent_id=None,
        session_id=None,
    )
    defaults.update(cfg_overrides)
    cfg = SimpleNamespace(**defaults)
    counts = build_distribution(NORMAL_TOKENS * 5)
    events: list[tuple] = []

    def emit(event_type, severity, details, ctx=None, **kwargs):
        events.append((event_type, severity, details, ctx, kwargs))

    emit.delivery_stats = lambda: {
        "pending": 0,
        "dead": 0,
        "worker_alive": False,
        "worker_error": None,
    }
    emit.close = lambda: None
    auditor = StreamAuditor(cfg, counts, emit)
    app.state.cfg = cfg
    app.state.emit = emit
    app.state.baseline_counts = counts
    app.state.baseline = counts
    app.state.auditor = auditor
    app.state.proxy = auditor
    return events


# -- what is accepted -------------------------------------------------------


def test_a_text_block_becomes_the_prompt():
    prompt = _messages_to_prompt(
        [{"role": "user", "content": [{"type": "text", "text": "hello there"}]}]
    )
    assert prompt == "hello there"


def test_a_string_content_becomes_the_prompt():
    prompt = _messages_to_prompt([{"role": "user", "content": "hello there"}])
    assert prompt == "hello there"


def test_the_messages_are_joined_in_order():
    prompt = _messages_to_prompt(
        [
            {"role": "user", "content": "first"},
            {"role": "assistant", "content": "second"},
            {"role": "user", "content": [{"type": "text", "text": "third"}]},
        ]
    )
    assert prompt == "first\nsecond\nthird"


def test_a_blank_text_block_contributes_nothing():
    # A text block with nothing in it carries nothing, so it is not a loss.
    prompt = _messages_to_prompt(
        [
            {"role": "user", "content": [{"type": "text", "text": "   "}]},
            {"role": "user", "content": "the real question"},
        ]
    )
    assert prompt == "the real question"


def test_a_message_with_no_content_contributes_nothing():
    # An assistant turn that carries tool calls rather than text has a null
    # content field. That is not a content block and there is nothing to
    # drop, so it is not refused — but on its own it leaves nothing to audit.
    prompt = _messages_to_prompt(
        [
            {"role": "assistant", "content": None},
            {"role": "user", "content": "the real question"},
        ]
    )
    assert prompt == "the real question"


# -- what is refused --------------------------------------------------------


def test_a_non_text_block_is_refused_rather_than_dropped():
    # The point of the refusal: the backend is text-only, so an image that
    # was dropped in silence would leave the model answering a question it
    # was never asked, with no record that anything was lost.
    with pytest.raises(ValueError, match="image_url"):
        _messages_to_prompt(
            [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "what is in this picture?"},
                        {"type": "image_url", "image_url": {"url": "data:..."}},
                    ],
                }
            ]
        )


def test_a_block_that_carries_no_text_is_refused():
    # A tool result holds its answer under its own key, not under "text".
    # Projecting it would silently lose the answer.
    with pytest.raises(ValueError, match="tool_result"):
        _messages_to_prompt(
            [
                {
                    "role": "user",
                    "content": [
                        {"type": "tool_result", "content": [{"type": "text", "text": "42"}]}
                    ],
                }
            ]
        )


def test_a_block_whose_text_is_not_a_string_is_refused():
    with pytest.raises(ValueError, match="text"):
        _messages_to_prompt(
            [{"role": "user", "content": [{"type": "text", "text": 42}]}]
        )


def test_a_block_that_is_not_an_object_is_refused():
    with pytest.raises(ValueError, match="object"):
        _messages_to_prompt([{"role": "user", "content": ["just a string"]}])


def test_a_message_whose_content_is_neither_text_nor_blocks_is_refused():
    # A null content means "this turn carries no text". A number means the
    # request is malformed, and a malformed request is not answered in
    # silence.
    with pytest.raises(ValueError, match="string or a list"):
        _messages_to_prompt([{"role": "user", "content": 42}])


def test_a_refused_block_names_the_type_it_could_not_audit():
    # The client is told which block was the problem, not merely that
    # something was.
    with pytest.raises(ValueError) as caught:
        _messages_to_prompt(
            [{"role": "user", "content": [{"type": "input_audio", "input_audio": {}}]}]
        )
    assert "input_audio" in str(caught.value)
    assert "cannot be audited" in str(caught.value)


def test_a_prompt_with_nothing_in_it_is_still_refused():
    with pytest.raises(ValueError, match="non-blank"):
        _messages_to_prompt([{"role": "user", "content": [{"type": "text", "text": " "}]}])


# -- end to end -------------------------------------------------------------


def test_the_endpoint_refuses_a_prompt_it_cannot_audit(tmp_path):
    _setup_app_state(tmp_path, max_tokens=20)
    client = TestClient(app, raise_server_exceptions=True)

    response = client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-4o-mini",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "what is in this picture?"},
                        {"type": "image_url", "image_url": {"url": "data:..."}},
                    ],
                }
            ],
            "stream": False,
            "max_tokens": 16,
        },
    )

    assert response.status_code == 422
    assert "image_url" in response.text


def test_the_endpoint_still_answers_a_text_prompt(tmp_path):
    _setup_app_state(tmp_path, max_tokens=20)
    client = TestClient(app, raise_server_exceptions=True)

    response = client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-4o-mini",
            "messages": [
                {"role": "user", "content": [{"type": "text", "text": "hello there"}]}
            ],
            "stream": False,
            "max_tokens": 16,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["object"] == "chat.completion"
    assert body["choices"][0]["message"]["content"].strip()
