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


def test_card_detection_requires_a_valid_luhn_checksum():
    matches = scan("valid test card 4111 1111 1111 1111")
    assert [match.label for match in matches] == ["credit_card"]
    assert scan("ordinary reference 1234 5678 9012 3456") == []
    assert scan("placeholder 0000-0000-0000-0000") == []


def test_a_literal_credential_is_matched_whatever_its_shape():
    """A credential we hold exactly needs no pattern to be recognised.

    The openai-style pattern stops at the first hyphen, so an Anthropic key
    passes straight through it. The literal match finds it because it is the
    exact string, not a shape.
    """
    key = "sk-ant-api03-operator-fallback-key-0123456789"
    text = f"the key is {key} and that is all"

    assert not scan(text), "no pattern should match a hyphenated Anthropic key"

    matches = scan(text, [key])
    assert len(matches) == 1
    assert matches[0].label == "anthropic_api_key"
    assert matches[0].value == key
    assert text[matches[0].start : matches[0].end] == key


def test_a_literal_credential_too_short_to_be_one_is_ignored():
    # A short "credential" is a word, and redacting a word out of ordinary
    # text mangles it without protecting anything.
    assert scan("the word hunter2 appears here", ["hunter2"]) == []


def test_a_literal_credential_overrides_a_pattern_that_overlaps_it():
    """The known credential is the more specific match.

    The pattern covers the start of the key, the literal covers all of it.
    Redacting the literal means the whole credential goes, not the part the
    pattern happened to see.
    """
    key = "sk-ant-api03-operator-fallback-key-0123456789"
    matches = scan(f"value {key} end", [key])
    assert [match.label for match in matches] == ["anthropic_api_key"]
    assert matches[0].value == key
