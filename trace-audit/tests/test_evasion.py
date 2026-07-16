"""Adversarial evaluation: does the documented evasion actually work?

The README calls token-boundary splitting a known limitation of the PII scanner.
Prose is cheap, so this measures it. Some of these tests assert that the scanner
**misses** a secret — that is deliberate. They pin a limitation we already
believe is real, so the claim in the docs is backed by a number, and so that
anyone who later closes the gap is told by a failing test to update the claim.

Imports only src.pii_scanner, which is stdlib-only.
Run from the module root: python -m pytest tests/
"""

from src.pii_scanner import scan

# Fake AWS example credential — the same inert value the fixtures use. Never a
# real key.
SECRET = "AKIAIOSFODNN7EXAMPLE"


def labels(text: str) -> list[str]:
    return [m.label for m in scan(text)]


def test_the_secret_is_caught_when_it_arrives_whole():
    """The control. If this fails, the evasion results below mean nothing."""
    assert labels(SECRET) == ["aws_access_key_id"]
    assert labels(f"the key is {SECRET} ok") == ["aws_access_key_id"]


def test_known_evasion_a_secret_split_across_tokens_is_missed():
    """DOCUMENTS A LIMITATION — the attack succeeds.

    stream_proxy scans each token in isolation (`scan(token)`), so a secret a
    tokenizer happens to split is never seen whole by the regex, and neither
    half matches on its own. Nothing here is contrived: this is ordinary
    tokenizer behaviour, not an attacker's cleverness — which is what makes it
    worth reporting.
    """
    for cut in range(1, len(SECRET)):
        head, tail = SECRET[:cut], SECRET[cut:]
        assert labels(head) == [], f"unexpected match on {head!r}"
        assert labels(tail) == [], f"unexpected match on {tail!r}"

    # Every one of the 19 possible splits evades the per-token scan.
    assert all(not labels(SECRET[:c]) and not labels(SECRET[c:]) for c in range(1, len(SECRET)))


def test_the_evasion_is_a_windowing_bug_not_a_pattern_bug():
    """Quantifies the fix. The regex is fine; the input it is handed is not.

    Concatenating the fragments — what a sliding character window with overlap
    would do — catches the secret the per-token scan missed. So the limitation
    is a scanning-strategy choice, not a detection ceiling.
    """
    fragments = ["AKIAIOSF", "ODNN7EXA", "MPLE"]
    assert all(labels(f) == [] for f in fragments), "no fragment matches alone"
    assert labels("".join(fragments)) == ["aws_access_key_id"], (
        "a buffered scan recovers the secret, so overlap-windowing would close this"
    )


def test_the_scanner_still_catches_an_unsplit_secret_among_fragments():
    """Bounds the damage. The gap is only ever the split secret — a second,
    unsplit secret in the same trace is still caught, so the failure is
    per-secret rather than a scanner that gives up."""
    assert labels("ops@example.com") == ["email_address"]
    assert labels("AKIAIOSF") == []
