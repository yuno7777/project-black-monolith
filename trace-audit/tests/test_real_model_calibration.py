"""The divergence gate, measured against a real model.

The threshold in `src/divergence_monitor.py` is derived from the mock
backend's numbers, and the comment that justifies it says the rest:

    The extra headroom over 2-sigma is deliberate: this benign
    distribution is unusually tight because the default backend is a
    deterministic mock; a real model backend would show wider benign
    spread, and 1.0 absorbs that drift.

Nothing asserted that the drift was absorbed. The mock's own calibrator
says so as well: its benign prompts are drawn from one fixed token pool,
so the mock's output does not change shape with the prompt, and
"measuring it requires the `real` profile against Ollama".

The measurement is committed -- `fixtures/real_model_calibration.json` --
and this test is what asserts it: a real model's ordinary answers stay
under the threshold the code ships, and the divergent fixture crosses it.

The artifact is produced by the "Real model evidence" workflow, which runs
the same calibration against Ollama whenever the reasoning layer is
touched. This test reads the committed copy, so it needs no model and no
network; the skip below is for a branch that does not carry the artifact.
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
    """The guarantee the threshold's own comment only hopes for.

    A benign prompt that reaches the threshold is a refusal: the reasoning
    layer would end an ordinary answer and tell the agent the model had
    gone off the rails.
    """
    benign = result["benign"]
    assert benign["false_positives"] == 0
    assert benign["max"] < result["threshold"], (
        f"the worst benign prompt reached {benign['max']}, which is the "
        f"threshold ({result['threshold']})"
    )


def test_the_gate_still_fires_on_the_divergent_fixture(result):
    assert result["divergent"]["peak_kl"] >= result["threshold"], (
        "the divergent fixture did not reach the threshold on this backend, "
        "so the gate would not have fired on it"
    )


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
