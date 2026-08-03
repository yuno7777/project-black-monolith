"""Startup configuration must fail early on unsafe or nonsensical values."""

import pytest

from src.config import load_config


@pytest.mark.parametrize(
    ("name", "value", "message"),
    [
        ("MONOLITH_EMBEDDING", "mystery", "hash"),
        ("MONOLITH_EMBEDDING_DIM", "0", "between 1 and 4096"),
        ("MONOLITH_TOP_K", "0", "between 1 and 100"),
        ("MONOLITH_CANDIDATE_BUFFER", "-1", "between 0 and 1000"),
        ("MONOLITH_RETENTION_HORIZON", "0", "between 1 and 1000000"),
        ("MONOLITH_MAX_QUERIES_PER_DOC", "0", "between 1 and 4096"),
        ("MONOLITH_TOPIC_SIMILARITY", "1.1", "between -1 and 1"),
        ("MONOLITH_TENANT_ID", " ", "between 1 and 128"),
    ],
)
def test_invalid_detector_configuration_fails_at_startup(
    monkeypatch, name, value, message
):
    monkeypatch.setenv(name, value)
    with pytest.raises(ValueError, match=message):
        load_config()


def test_related_thresholds_must_be_internally_consistent(monkeypatch):
    monkeypatch.setenv("MONOLITH_TOP_K", "2")
    monkeypatch.setenv("MONOLITH_CANDIDATE_BUFFER", "0")
    monkeypatch.setenv("MONOLITH_TOP_RANK_THRESHOLD", "3")
    with pytest.raises(ValueError, match="candidate set"):
        load_config()

    monkeypatch.setenv("MONOLITH_TOP_RANK_THRESHOLD", "2")
    monkeypatch.setenv("MONOLITH_MAX_QUERIES_PER_DOC", "3")
    monkeypatch.setenv("MONOLITH_MIN_DISTINCT_TOPICS", "4")
    with pytest.raises(ValueError, match="max queries per document"):
        load_config()


def test_dashboard_credentials_are_paired_and_header_safe(monkeypatch):
    monkeypatch.setenv("MONOLITH_DASHBOARD_URL", "http://dashboard:3000/api/ingest")
    monkeypatch.delenv("MONOLITH_EVENT_TOKEN", raising=False)
    with pytest.raises(ValueError, match="configured together"):
        load_config()

    monkeypatch.setenv("MONOLITH_EVENT_TOKEN", "valid-length-token\r\nInjected: yes")
    with pytest.raises(ValueError, match="header-safe"):
        load_config()


def test_default_configuration_is_valid(monkeypatch):
    for name in (
        "MONOLITH_EMBEDDING",
        "MONOLITH_EMBEDDING_DIM",
        "MONOLITH_TOP_K",
        "MONOLITH_CANDIDATE_BUFFER",
        "MONOLITH_TOP_RANK_THRESHOLD",
        "MONOLITH_MIN_DISTINCT_TOPICS",
        "MONOLITH_TOPIC_SIMILARITY",
        "MONOLITH_WINDOW_SIZE",
        "MONOLITH_DASHBOARD_URL",
        "MONOLITH_EVENT_TOKEN",
        "MONOLITH_ADMIN_TOKEN",
        "MONOLITH_TENANT_ID",
        "MONOLITH_AGENT_ID",
        "MONOLITH_SESSION_ID",
    ):
        monkeypatch.delenv(name, raising=False)
    cfg = load_config()
    assert cfg.embedding == "hash"
    assert cfg.top_k == 3
