"""Unit tests for the embedding functions the memory layer's hot path uses.

``normalize`` and ``unit_dot`` are the two functions every comparison in the
detector goes through. ``unit_dot`` is deliberately unvalidated — it is the
fast path — so the contract that makes that safe has to live somewhere, and
this file is where it lives: what ``normalize`` guarantees, and therefore
what ``unit_dot`` is allowed to assume about its inputs.

The performance claim that motivates the split (the validating ``cosine``
costs several times as much per call) is deliberately NOT asserted here. A
timing assertion in a unit test fails on a noisy machine, and a benchmark
that fails teaches people to ignore failures — the same reason the
MCP-Shield benchmark is ``#[ignore]``d. The measurement lives in
``EVALUATION.md``; what is asserted here is the *reason* the fast path is
safe, which is a property of the code and not of the machine it runs on.
"""

import math

import pytest

from src.embedding import HashingEmbeddingFunction, cosine, normalize, unit_dot


def test_cosine_rejects_mismatched_or_nonfinite_vectors():
    with pytest.raises(ValueError, match="equal dimensions"):
        cosine([1.0], [1.0, 0.0])
    with pytest.raises(ValueError, match="finite"):
        cosine([float("nan")], [1.0])


# -- normalize --------------------------------------------------------------


def test_normalize_makes_a_unit_vector():
    result = normalize([3.0, 4.0])
    assert math.isclose(math.sqrt(sum(v * v for v in result)), 1.0, rel_tol=1e-12)


def test_normalize_leaves_a_zero_vector_alone():
    # A zero vector has no direction to preserve. Dividing by its norm would
    # raise, so it is returned as it came in.
    zero = [0.0, 0.0, 0.0]
    assert normalize(zero) == zero


def test_normalize_does_not_touch_its_input():
    vector = [3.0, 4.0]
    before = list(vector)
    normalize(vector)
    assert vector == before


def test_normalize_returns_a_copy_of_its_input():
    # The zero vector is the only case where the result could alias the
    # input, and an aliased result would let a caller mutate detector state
    # by accident.
    zero = [0.0, 0.0]
    result = normalize(zero)
    assert result is not zero
    result[0] = 1.0
    assert zero == [0.0, 0.0]


def test_normalize_preserves_the_direction_of_the_vector():
    a = [1.0, 2.0, 3.0]
    b = [4.0, 5.0, 6.0]
    assert unit_dot(normalize(a), normalize(b)) == pytest.approx(
        cosine(a, b), rel=1e-12
    )


@pytest.mark.parametrize("scale", [0.001, 1.0, 1000.0])
def test_normalize_agrees_with_cosine_at_every_scale(scale):
    # This is the claim the whole design rests on: cosine similarity is
    # scale-invariant, so a vector can be normalized once on admission and
    # compared with a plain dot product afterwards.
    a = [1.0, -2.0, 0.5]
    b = [3.0, 1.0, -1.0]
    assert unit_dot(
        normalize([value * scale for value in a]),
        normalize([value * scale for value in b]),
    ) == pytest.approx(cosine(a, b), rel=1e-9)


def test_normalize_is_idempotent():
    vector = [1.0, 2.0, 2.0]
    once = normalize(vector)
    assert normalize(once) == pytest.approx(once)


# -- unit_dot ---------------------------------------------------------------


def test_unit_dot_equals_cosine_for_normalized_vectors():
    a = normalize([1.0, 2.0, 3.0])
    b = normalize([-1.0, 0.5, 2.0])
    assert unit_dot(a, b) == pytest.approx(cosine(a, b), rel=1e-12)
    assert unit_dot(a, a) == pytest.approx(1.0, rel=1e-12)


def test_unit_dot_is_not_scale_invariant():
    # The precondition, stated as a test: unit_dot is a plain dot product,
    # so it is NOT a drop-in for cosine. The caller has to normalize first.
    # If this ever stops being true, the fast path is no longer equivalent
    # to the validated one and the detector's threshold means something
    # different.
    assert unit_dot([1.0, 0.0], [1.0, 0.0]) == 1.0
    assert unit_dot([2.0, 0.0], [1.0, 0.0]) == 2.0
    assert unit_dot([2.0, 0.0], [1.0, 0.0]) != pytest.approx(
        cosine([2.0, 0.0], [1.0, 0.0])
    )


def test_unit_dot_refuses_vectors_of_different_lengths():
    # The validating cosine raises on this. The hot path has to as well, or a
    # dimension mismatch would silently compare a prefix of one vector with
    # the other and report a similarity that was never computed.
    with pytest.raises(ValueError):
        unit_dot([1.0], [1.0, 0.0])


def test_unit_dot_does_not_validate_its_inputs():
    # Why the two functions are not interchangeable: the hot path accepts
    # values the validating one rejects, because its inputs were checked
    # where they entered the detector. A change that routed unit_dot through
    # cosine would silently reintroduce the per-call validation the split
    # exists to avoid.
    with pytest.raises(ValueError):
        cosine([float("nan")], [1.0])
    assert math.isnan(unit_dot([float("nan")], [1.0]))


def test_unit_dot_of_a_zero_vector_is_zero():
    assert unit_dot([0.0, 0.0], [1.0, 1.0]) == 0.0
    assert unit_dot([0.0, 0.0], [0.0, 0.0]) == 0.0


def test_the_whole_chain_agrees_with_cosine():
    # The chain the detector actually runs: the embedder produces a vector,
    # normalize is applied once, and unit_dot compares. The answer must be
    # the one the validated function would have given.
    embedder = HashingEmbeddingFunction(dim=256)
    a = embedder(["red giant star galaxy nebula"])[0]
    b = embedder(["boil pasta noodles simmer sauce"])[0]
    assert unit_dot(normalize(a), normalize(b)) == pytest.approx(
        cosine(a, b), rel=1e-9
    )
