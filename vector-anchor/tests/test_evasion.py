"""Adversarial evaluation: does the documented evasion actually work?

The README calls slow-drip evasion a known limitation. Prose is cheap, so this
measures it. Some of these tests assert that the detector **misses** an attack —
that is deliberate. They pin a limitation we already believe is real, so that
the claim in the docs is backed by a number, and so that anyone who later closes
the gap is told by a failing test to update the claim.

Imports only src.frequency_tracker, which is pure Python — no ChromaDB needed.
Run from the module root: python -m pytest tests/
"""

from src.frequency_tracker import FrequencyTracker

# The shipped defaults (see src/config.py and the calibration in
# fixtures/calibration_results.md).
MIN_DISTINCT_TOPICS = 4
TOPIC_SIMILARITY = 0.20
WINDOW = 50

BAIT = "poison-1"


def orthogonal(index: int, dim: int = 8) -> list[float]:
    """A one-hot vector: cosine 0 against every other index.

    Deliberately extreme — these stand for queries with nothing in common, which
    is the *easiest* case for the detector. If it misses the attack even here,
    it misses it in general.
    """
    vec = [0.0] * dim
    vec[index % dim] = 1.0
    return vec


def tracker() -> FrequencyTracker:
    return FrequencyTracker(
        min_distinct_topics=MIN_DISTINCT_TOPICS,
        topic_similarity=TOPIC_SIMILARITY,
        window_size=WINDOW,
    )


def test_the_burst_attack_is_caught():
    """The control. A bait doc ranking across unrelated topics in quick
    succession is exactly what the detector is for — if this ever fails, the
    evasion results below mean nothing."""
    t = tracker()
    for topic in range(MIN_DISTINCT_TOPICS):
        t.record_query([BAIT], orthogonal(topic))
    assert t.is_anomalous(BAIT)
    assert t.evaluate(BAIT).distinct_topics == MIN_DISTINCT_TOPICS


def test_known_evasion_slow_drip_defeats_the_rolling_window():
    """DOCUMENTS A LIMITATION — the attack succeeds.

    Detection counts distinct topics within a bounded rolling window. An
    attacker who surfaces the bait for one unrelated topic per window, and lets
    the window fill with unrelated traffic before the next, never has more than
    one topic counted at once.
    """
    t = tracker()
    topics_surfaced = 0
    peak_score = 0

    # Far more distinct topics than the threshold — 3x — spread thin.
    for topic in range(MIN_DISTINCT_TOPICS * 3):
        t.record_query([BAIT], orthogonal(topic))
        topics_surfaced += 1
        peak_score = max(peak_score, t.evaluate(BAIT).distinct_topics)
        assert not t.is_anomalous(BAIT), (
            f"unexpectedly caught after {topics_surfaced} topics — if the "
            f"detector improved, update this test and the README's limitation"
        )
        # Cover traffic ages the bait's hit out of the window before the next.
        for filler in range(WINDOW):
            t.record_query([f"clean-{filler}"], orthogonal(filler + 100))

    assert peak_score == 1, f"the bait never accumulated past {peak_score} topic(s)"
    assert not t.is_anomalous(BAIT)


def test_the_evasion_boundary_is_the_window_not_the_threshold():
    """Quantifies the edge: the attack works only if the gap outlives the
    window. Drip fast enough that two hits coexist and the count climbs again,
    which is what makes `window_size` the real security parameter."""
    t = tracker()
    # Hits spaced so that all MIN_DISTINCT_TOPICS stay inside one window.
    spacing = (WINDOW // MIN_DISTINCT_TOPICS) - 1
    for topic in range(MIN_DISTINCT_TOPICS):
        t.record_query([BAIT], orthogonal(topic))
        for filler in range(spacing):
            t.record_query([f"clean-{filler}"], orthogonal(filler + 100))
    assert t.is_anomalous(BAIT), "spacing inside one window must still be caught"


def test_the_cost_of_evading_is_measurable():
    """The evasion is not free, and the price is the useful finding.

    Each topic must be separated by a full window of cover traffic, so an
    attacker needs roughly window_size retrievals per topic they want to hide.
    That is the number an operator would tune against.
    """
    t = tracker()
    queries_used = 0
    for topic in range(MIN_DISTINCT_TOPICS):
        t.record_query([BAIT], orthogonal(topic))
        queries_used += 1
        for filler in range(WINDOW):
            t.record_query([f"clean-{filler}"], orthogonal(filler + 100))
            queries_used += 1
    assert not t.is_anomalous(BAIT)
    # ~50 covering queries per hidden topic at the shipped window size.
    cost_per_topic = queries_used // MIN_DISTINCT_TOPICS
    assert cost_per_topic >= WINDOW, (
        f"evasion cost {cost_per_topic} queries per topic; the window is {WINDOW}"
    )
