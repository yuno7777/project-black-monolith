"""Adversarial evaluation: does the documented evasion actually work?

Some of these tests assert that the detector **misses** an attack — that is
deliberate. They pin a limitation we believe is real, so that the claim in the
docs is backed by a number, and so that anyone who later closes the gap is told
by a failing test to update the claim.

History worth keeping: the slow drip used to succeed here. Detection counted
distinct topics inside a *global* rolling window of 50 queries, so surfacing the
bait once per window let each hit age out before the next arrived — peak score
1 against a threshold of 4, while covering 12 distinct topics. The window is
gone. Retention is now per document, with the detection horizon
(``retention_horizon``) separated from the memory/cost bound
(``max_queries_per_doc``), so the horizon can be widened without paying the
quadratic clustering cost that previously made widening it impractical.

The evasion did not disappear; it got roughly 10x more expensive, and the tests
below pin both the closure and the new boundary.

Imports only src.frequency_tracker, which is pure Python — no ChromaDB needed.
Run from the module root: python -m pytest tests/
"""

import pytest

from src.frequency_tracker import FrequencyTracker

# The shipped defaults (see src/config.py and the calibration in
# fixtures/calibration_results.md).
MIN_DISTINCT_TOPICS = 4
TOPIC_SIMILARITY = 0.20
RETENTION_HORIZON = 500
MAX_QUERIES_PER_DOC = 8

BAIT = "poison-1"


def orthogonal(index: int, dim: int = 64) -> list[float]:
    """A one-hot vector: cosine 0 against every other index.

    Deliberately extreme — these stand for queries with nothing in common, which
    is the *easiest* case for the detector. If it misses the attack even here,
    it misses it in general.
    """
    vec = [0.0] * dim
    vec[index % dim] = 1.0
    return vec


def tracker(**overrides) -> FrequencyTracker:
    params = dict(
        min_distinct_topics=MIN_DISTINCT_TOPICS,
        topic_similarity=TOPIC_SIMILARITY,
        retention_horizon=RETENTION_HORIZON,
        max_queries_per_doc=MAX_QUERIES_PER_DOC,
    )
    params.update(overrides)
    return FrequencyTracker(**params)


def cover(t: FrequencyTracker, count: int, offset: int = 1000) -> None:
    """Unrelated traffic that does not involve the bait."""
    for filler in range(count):
        t.record_query([f"clean-{filler}"], orthogonal(offset + filler))


def test_the_burst_attack_is_caught():
    """The control. A bait doc ranking across unrelated topics in quick
    succession is exactly what the detector is for — if this ever fails, the
    evasion results below mean nothing."""
    t = tracker()
    for topic in range(MIN_DISTINCT_TOPICS):
        t.record_query([BAIT], orthogonal(topic))
    assert t.is_anomalous(BAIT)
    assert t.evaluate(BAIT).distinct_topics == MIN_DISTINCT_TOPICS


def test_the_slow_drip_that_used_to_evade_is_now_caught():
    """CLOSES A PREVIOUSLY DOCUMENTED LIMITATION.

    The historical attack: one topic per 50-query window, letting each hit age
    out. Against the old global window that never accumulated past a score of 1.
    The retention horizon is now 500, so hits spaced 50 apart coexist and the
    count climbs to the threshold.
    """
    t = tracker()
    old_window = 50
    for topic in range(MIN_DISTINCT_TOPICS):
        t.record_query([BAIT], orthogonal(topic))
        cover(t, old_window)

    assert t.is_anomalous(BAIT), "the slow drip must no longer evade"
    assert t.evaluate(BAIT).distinct_topics >= MIN_DISTINCT_TOPICS


def test_a_drip_slower_than_the_horizon_still_evades():
    """DOCUMENTS THE REMAINING LIMITATION — the attack still succeeds.

    Detection reaches back `retention_horizon` queries and no further. An
    attacker patient enough to leave a full horizon between hits still never has
    two topics counted at once. The gap is not closed; it is repriced.
    """
    t = tracker()
    peak = 0
    for topic in range(MIN_DISTINCT_TOPICS * 3):
        t.record_query([BAIT], orthogonal(topic))
        peak = max(peak, t.evaluate(BAIT).distinct_topics)
        assert not t.is_anomalous(BAIT), (
            f"unexpectedly caught at topic {topic} — if the detector improved, "
            f"update this test and the README's limitation"
        )
        cover(t, RETENTION_HORIZON)

    assert peak == 1, f"the bait never accumulated past {peak} topic(s)"


def test_the_cost_of_evading_rose_with_the_horizon():
    """The evasion is not free, and the price is the useful finding.

    Each topic must now be separated by a full *horizon* of cover traffic
    rather than a 50-query window, so the attacker pays ~10x what they used to
    for every topic they want to hide.
    """
    t = tracker()
    queries_used = 0
    for topic in range(MIN_DISTINCT_TOPICS):
        t.record_query([BAIT], orthogonal(topic))
        queries_used += 1
        cover(t, RETENTION_HORIZON)
        queries_used += RETENTION_HORIZON

    assert not t.is_anomalous(BAIT)
    cost_per_topic = queries_used // MIN_DISTINCT_TOPICS
    assert cost_per_topic >= RETENTION_HORIZON, (
        f"evasion cost {cost_per_topic} queries per topic; "
        f"the horizon is {RETENTION_HORIZON}"
    )
    # The number that actually changed: it used to be ~50.
    assert cost_per_topic >= 10 * 50


def test_the_boundary_is_the_horizon_not_the_threshold():
    """Quantifies the edge: the attack works only if the gap outlives the
    horizon. Drip fast enough that the hits coexist and the count climbs, which
    is what makes `retention_horizon` the real security parameter."""
    t = tracker()
    spacing = (RETENTION_HORIZON // MIN_DISTINCT_TOPICS) - 1
    for topic in range(MIN_DISTINCT_TOPICS):
        t.record_query([BAIT], orthogonal(topic))
        cover(t, spacing)
    assert t.is_anomalous(BAIT), "spacing inside one horizon must still be caught"


def test_flooding_the_retention_cap_cannot_flush_earned_topics():
    """A cap on retained hits per document is what keeps the horizon affordable,
    but a naive cap creates a new evasion: fill it with cheap, merely-varied
    queries in a single topic and the bait's earlier distinct topics are pushed
    out, resetting the score for free.

    Eviction drops the most redundant retained hit rather than the oldest, so
    flooding evicts the flood.
    """
    t = tracker()
    for topic in range(MIN_DISTINCT_TOPICS - 1):
        t.record_query([BAIT], orthogonal(topic))
    earned = t.evaluate(BAIT).distinct_topics
    assert earned == MIN_DISTINCT_TOPICS - 1

    # Flood: many hits that all sit in one narrow region of the space.
    flood = [0.0] * 64
    flood[MIN_DISTINCT_TOPICS + 1] = 1.0
    for nudge in range(MAX_QUERIES_PER_DOC * 2):
        variant = list(flood)
        variant[(nudge % 8) + 20] = 0.05  # varied, but same topic
        t.record_query([BAIT], variant)

    assert t.evaluate(BAIT).distinct_topics >= earned, (
        "flooding the retention cap must not erase topics the bait already "
        "ranked for"
    )


def test_retention_cap_is_enforced():
    """The memory bound is real: no document retains more than the cap, no
    matter how much traffic it attracts. This is what lets the horizon grow
    without the clustering cost growing with it."""
    t = tracker(max_queries_per_doc=8)
    for topic in range(200):
        t.record_query([BAIT], orthogonal(topic))
    assert len(t._docs[BAIT].queries) <= 8


@pytest.mark.parametrize("horizon", [50, 200, 500])
def test_horizon_sets_how_far_back_detection_reaches(horizon):
    """The horizon is a dial, and this pins what turning it buys: hits spaced
    just inside it are caught, the same hits spaced just outside are not."""
    inside = tracker(retention_horizon=horizon)
    for topic in range(MIN_DISTINCT_TOPICS):
        inside.record_query([BAIT], orthogonal(topic))
        cover(inside, (horizon // MIN_DISTINCT_TOPICS) - 1)
    assert inside.is_anomalous(BAIT)

    outside = tracker(retention_horizon=horizon)
    for topic in range(MIN_DISTINCT_TOPICS):
        outside.record_query([BAIT], orthogonal(topic))
        cover(outside, horizon)
    assert not outside.is_anomalous(BAIT)
