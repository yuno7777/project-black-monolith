"""Adversarial evaluation of the bounded cross-token PII look-behind."""

import asyncio
from types import SimpleNamespace

import src.stream_proxy as stream_proxy
from src.pii_scanner import scan
from src.stream_proxy import PII_TOKEN_WINDOW, PiiStreamBuffer, StreamAuditor

# Fake AWS example credential — the same inert value the fixtures use. Never a
# real key.
SECRET = "AKIAIOSFODNN7EXAMPLE"


def labels(text: str) -> list[str]:
    return [match.label for match in scan(text)]


def test_the_secret_is_caught_when_it_arrives_whole():
    assert labels(SECRET) == ["aws_access_key_id"]
    assert labels(f"the key is {SECRET} ok") == ["aws_access_key_id"]


def test_raw_fragments_do_not_match_without_stream_context():
    for cut in range(1, len(SECRET)):
        head, tail = SECRET[:cut], SECRET[cut:]
        assert labels(head) == [], f"unexpected match on {head!r}"
        assert labels(tail) == [], f"unexpected match on {tail!r}"


def test_all_two_token_splits_are_redacted_before_release():
    for cut in range(1, len(SECRET)):
        buffer = PiiStreamBuffer()
        first = buffer.push(SECRET[:cut], None)
        second = buffer.push(SECRET[cut:], None)
        assert first.outputs == []
        assert [match.label for match in second.matches] == ["aws_access_key_id"]
        output = "".join(item.token for item in second.outputs)
        assert SECRET not in output
        assert output == "[REDACTED:aws_access_key_id]"


def test_split_secret_is_caught_across_the_full_buffer_window():
    fragments = list(SECRET[: PII_TOKEN_WINDOW - 1])
    fragments.append(SECRET[PII_TOKEN_WINDOW - 1 :])
    buffer = PiiStreamBuffer()
    outputs = []
    matches = []
    for fragment in fragments:
        drained = buffer.push(fragment, None)
        outputs.extend(drained.outputs)
        matches.extend(drained.matches)
    assert [match.label for match in matches] == ["aws_access_key_id"]
    assert SECRET not in "".join(item.token for item in outputs)


def test_redaction_preserves_unrelated_token_boundaries():
    buffer = PiiStreamBuffer()
    buffer.push("normal-one", None)
    buffer.push("normal-two", None)
    drained = buffer.push(SECRET, None)

    assert [item.token for item in drained.outputs] == [
        "normal-one",
        "normal-two",
        "[REDACTED:aws_access_key_id]",
    ]


def test_known_boundary_more_fragments_than_the_window_can_evade():
    buffer = PiiStreamBuffer()
    outputs = []
    matches = []
    fragments = list(SECRET[: PII_TOKEN_WINDOW + 1])
    fragments.append(SECRET[PII_TOKEN_WINDOW + 1 :])
    for fragment in fragments:
        drained = buffer.push(fragment, None)
        outputs.extend(drained.outputs)
        matches.extend(drained.matches)
    drained = buffer.finish()
    outputs.extend(drained.outputs)
    matches.extend(drained.matches)

    assert matches == []
    assert "".join(item.token for item in outputs) == SECRET


def test_stream_auditor_never_releases_a_split_secret(monkeypatch):
    async def split_stream():
        for fragment in ("AKIAIOSF", "ODNN7EXA", "MPLE"):
            yield fragment

    monkeypatch.setattr(
        stream_proxy,
        "_backend_stream",
        lambda _prompt, _max_tokens, _cfg: split_stream(),
    )
    cfg = SimpleNamespace(
        max_tokens=3,
        model_backend="mock",
        kl_threshold=100.0,
        window_size=20,
        min_tokens_before_check=12,
        smoothing=0.5,
    )
    emitted = []
    auditor = StreamAuditor(cfg, {}, lambda *args: emitted.append(args))

    async def collect():
        return [event async for event in auditor.audit("ordinary prompt")]

    events = asyncio.run(collect())
    output = "".join(
        event["token"] for event in events if event["type"] == "token"
    )
    assert SECRET not in output
    assert output == "[REDACTED:aws_access_key_id]"
    assert any(event["type"] == "pii" for event in events)
    assert emitted[0][0] == "pii_redacted"
