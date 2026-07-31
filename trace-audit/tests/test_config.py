"""TraceAudit fails startup on unsafe configuration or baseline data."""

import json

import pytest

from src.config import load_config
from src.main import MAX_BASELINE_TOKEN_COUNT, _load_baseline


@pytest.mark.parametrize(
    ("name", "value", "message"),
    [
        ("MONOLITH_MODEL_BACKEND", "mystery", "mock"),
        ("MONOLITH_OLLAMA_URL", "file:///tmp/model", "http"),
        ("MONOLITH_KL_THRESHOLD", "0", "greater than 0"),
        ("MONOLITH_TA_WINDOW", "0", "between 1 and 10000"),
        ("MONOLITH_MIN_TOKENS", "0", "divergence window"),
        ("MONOLITH_SMOOTHING", "nan", "greater than 0"),
        ("MONOLITH_MAX_TOKENS", "4097", "between 1 and 4096"),
        ("MONOLITH_TENANT_ID", " ", "between 1 and 128"),
    ],
)
def test_invalid_runtime_configuration_fails_at_startup(
    monkeypatch, name, value, message
):
    monkeypatch.setenv(name, value)
    with pytest.raises(ValueError, match=message):
        load_config()


def test_minimum_token_count_must_fit_the_window(monkeypatch):
    monkeypatch.setenv("MONOLITH_TA_WINDOW", "10")
    monkeypatch.setenv("MONOLITH_MIN_TOKENS", "11")
    with pytest.raises(ValueError, match="window size"):
        load_config()


def test_dashboard_credentials_are_paired_and_header_safe(monkeypatch):
    monkeypatch.setenv("MONOLITH_DASHBOARD_URL", "http://dashboard:3000/api/ingest")
    monkeypatch.delenv("MONOLITH_EVENT_TOKEN", raising=False)
    with pytest.raises(ValueError, match="configured together"):
        load_config()

    monkeypatch.setenv("MONOLITH_EVENT_TOKEN", "valid-length-token\r\nInjected: yes")
    with pytest.raises(ValueError, match="header-safe"):
        load_config()


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"counts": []},
        {"counts": {"": 1}},
        {"counts": {"token": 0}},
        {"counts": {"token": -1}},
        {"counts": {"token": 1.5}},
        {"counts": {"token": True}},
        {"counts": {"token": MAX_BASELINE_TOKEN_COUNT + 1}},
        {"counts": {" token ": 1, "token": 2}},
    ],
)
def test_invalid_baseline_distributions_fail_closed(tmp_path, payload):
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError):
        _load_baseline(str(path))


def test_valid_baseline_distribution_loads_exact_counts(tmp_path):
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps({"counts": {"safe": 3, "answer": 2}}), encoding="utf-8")
    assert _load_baseline(str(path)) == {"safe": 3, "answer": 2}
