"""Unit tests for TraceAudit divergence + PII detection (no model backend)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.divergence_monitor import DivergenceMonitor, build_distribution  # noqa: E402
from src.pii_scanner import scan  # noqa: E402
from src.redaction import redact  # noqa: E402

# A small normal baseline: ordinary reasoning words.
BASELINE = build_distribution(
    "let us think about this the user wants a clear answer we consider the "
    "context then provide a helpful response step by step".split()
    * 5
)


def monitor(threshold=1.5):
    return DivergenceMonitor(
        baseline_counts=BASELINE,
        threshold=threshold,
        window_size=20,
        min_tokens_before_check=12,
        smoothing=0.5,
    )


def test_normal_stream_stays_below_threshold():
    m = monitor()
    normal = "let us think about this the user wants a clear helpful answer step by step".split()
    diverged = False
    for tok in normal * 3:
        kl = m.observe(tok)
        diverged = diverged or m.is_divergent(kl)
    assert not diverged


def test_off_distribution_stream_crosses_threshold():
    m = monitor()
    weird = "zzxq qwploo vbnmk glorptastic wibblewobble frobnicate quuxly circumvent obfuscate".split()
    crossed = False
    for tok in weird * 3:
        kl = m.observe(tok)
        if m.is_divergent(kl):
            crossed = True
            break
    assert crossed


def test_pii_scanner_detects_and_redacts():
    text = "the key is AKIAIOSFODNN7EXAMPLE and email ops@example.com and ssn 123-45-6789"
    matches = scan(text)
    labels = {m.label for m in matches}
    assert "aws_access_key_id" in labels
    assert "email_address" in labels
    assert "us_ssn" in labels
    redacted = redact(text, matches)
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "ops@example.com" not in redacted
    assert "123-45-6789" not in redacted
    assert "[REDACTED:aws_access_key_id]" in redacted


def test_clean_text_has_no_pii():
    assert scan("let us think about this step by step and give a helpful answer") == []
