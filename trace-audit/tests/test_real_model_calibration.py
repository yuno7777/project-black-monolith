"""The divergence gate, measured against a real model.

The threshold in `src/divergence_monitor.py` is derived from the mock
backend's numbers, and the comment that justifies it says the rest:

    The extra headroom over 2-sigma is deliberate: this benign
    distribution is unusually tight because the default backend is a
    deterministic mock; a real model backend would show wider benign
    spread, and 1.0 absorbs that drift.

Nothing asserted that the drift was absorbed. The mock's own calibrator
says the same thing and calls it a blind spot that stays open.

The measurement is committed -- `fixtures/real_model_calibration.json` --
and this test is what asserts it. Two things are asserted, and they are
not the same thing:

  * **No false positives.** A real model's ordinary answers stay under
    the threshold the code ships. This holds, and it has to keep holding:
    a benign prompt that reaches the threshold is a refusal, and the
    agent is told the model had gone off the rails.

  * **The gate can fire.** An off-distribution answer crosses the
    threshold. This does *not* hold, and the measurement says why: the
    monitor's whole range against a real model is 0.29 to 0.49, and the
    threshold is 1.0. The gate is unreachable. That is a known failure,
    recorded as a finding in `docs/FINDINGS.md`; the test below is
    marked as expected-to-fail until the statistic is replaced or the
    threshold is re-derived, and it is marked *strictly*, so a fix that
    makes the gate fire has to come back here and remove the marker.

The test reads the committed copy, so it needs no model and no network.
A branch that does not carry the artifact skips rather than fails.
"""

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.divergence_monitor import DEFAULT_KL_THRESHOLD  # noqa: E402

ARTIFACT = Path(__file__).resolve().parents[1] / "fixtures" / "real_model_calibration.json"

# The monitor's shipped defaults, as `load_config()` applies them. They are
# spelled out here rather than read from the config, because the config reads
# the environment: a developer with MONOLITH_TA_WINDOW exported would
# otherwise get a different answer from the same repository. These are the
# numbers the committed calibration was measured with, and a change to any of
# them makes that calibration stale.
SHIPPED_MONITOR = {
    "window_size": 20,
    "min_tokens_before_check": 12,
    "smoothing": 0.5,
    "max_tokens": 60,
}


@pytest.fixture(scope="module")
def result():
    if not ARTIFACT.is_file():
        pytest.skip(f"{ARTIFACT.name} is not committed; the real-model workflow produces it")
    with ARTIFACT.open(encoding="utf-8") as handle:
        return json.load(handle)


def test_the_committed_result_measures_a_real_model(result):
    """The mock's calibration is already committed; this is the other one."""
    assert result["backend"] != "mock", (
        "the committed result was measured against the mock backend, which is "
        "the blind spot this result exists to close"
    )
    assert str(result.get("model", "")).strip()


def test_the_committed_result_is_for_the_threshold_the_code_ships(result):
    assert result["threshold"] == DEFAULT_KL_THRESHOLD, (
        "the calibration was measured against a different threshold; the "
        "shipped one has to be re-measured"
    )


def test_the_committed_result_used_the_shipped_monitor(result):
    """A different window or smoothing is a different measurement."""
    assert result["monitor"] == SHIPPED_MONITOR


def test_a_real_models_ordinary_answers_do_not_trip_the_gate(result):
    """The guarantee that holds, and has to keep holding.

    A benign prompt that reaches the threshold is a refusal: the
    reasoning layer would end an ordinary answer and tell the agent the
    model had gone off the rails.
    """
    benign = result["benign"]
    assert benign["false_positives"] == 0
    assert benign["max"] < result["threshold"], (
        f"the worst benign prompt reached {benign['max']}, which is the "
        f"threshold ({result['threshold']})"
    )


def test_the_committed_result_records_the_gates_reach(result):
    """How far the monitor can see is a measured fact, not an assumption.

    The reach is the highest peak KL any off-distribution probe reached.
    It is what the threshold has to sit below for the gate to fire at
    all, so it is recorded and pinned here.
    """
    probes = result["probes"]
    assert len(probes) >= 5
    measured = [p["peak_kl"] for p in probes if p["peak_kl"] is not None]
    assert measured, "no probe produced a measurement"
    assert result["reach"] == max(measured)
    assert any("shipped" in p["name"] for p in probes), (
        "the shipped fixture is a probe: the gate has to be measured against "
        "the prompt the demo actually uses"
    )


def test_the_committed_result_says_whether_the_gate_holds(result):
    """The verdict has to agree with the numbers it is a verdict about."""
    verdict = result["verdict"]
    reach = result["reach"]
    assert verdict["benign_clean"] == (result["benign"]["false_positives"] == 0)
    assert verdict["gate_fires"] == (reach is not None and reach >= result["threshold"])
    assert verdict["reason"].strip()


def test_the_committed_result_covers_the_held_out_prompts(result):
    """A verdict over one prompt is not a verdict over the set."""
    benign = result["benign"]
    assert benign["count"] >= 30
    assert len(benign["peaks"]) == benign["count"]
    categories = {peak["category"] for peak in benign["peaks"]}
    assert len(categories) >= 4, "the held-out set is meant to span several styles, not one"
    for peak in benign["peaks"]:
        assert peak["prompt"].strip()
        assert peak["peak_kl"] >= 0.0


@pytest.mark.xfail(
    strict=True,
    reason=(
        "the divergence gate cannot fire against a real model: the monitor's "
        "whole range is 0.29-0.49 and the threshold is 1.0 (FINDINGS.md, the "
        "reasoning layer's divergence gate). Strict, so a fix has to come "
        "back and remove this marker."
    ),
)
def test_the_gate_fires_on_an_off_distribution_answer(result):
    """The other half of the gate's promise, and the half that is broken.

    An off-distribution answer -- another language, a hex dump, a
    repetition loop -- has to cross the threshold. Against the mock it
    did, and that is the only evidence the threshold ever had.
    """
    assert result["reach"] >= result["threshold"], (
        f"the highest off-distribution probe reached {result['reach']}, "
        f"below the threshold ({result['threshold']})"
    )
