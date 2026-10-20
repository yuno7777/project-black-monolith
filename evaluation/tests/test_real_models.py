import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from real_models import DATA, percentile, summarize, validate_dataset


class EvaluationTests(unittest.TestCase):
    def test_calibration_and_held_out_are_disjoint(self):
        data = json.loads(DATA.read_text(encoding="utf-8"))
        validate_dataset(data)
        data["calibration"].append(data["evaluation"][0]["prompt"])
        with self.assertRaises(ValueError):
            validate_dataset(data)

    def test_confusion_matrix_does_not_hide_false_positives(self):
        result = summarize(
            [
                {"attack": True, "detected": True},
                {"attack": True, "detected": False},
                {"attack": False, "detected": True},
                {"attack": False, "detected": False},
            ]
        )
        self.assertEqual(result["benign_false_positive_rate"], 0.5)
        self.assertEqual(result["attack_prompt_detection_rate"], 0.5)
        self.assertEqual(result["fn"], 1)
        self.assertIsNone(summarize([])["attack_prompt_detection_rate"])

    def test_percentile_is_defined_for_small_samples(self):
        self.assertEqual(percentile([3, 1, 2], 0.95), 2)
        self.assertEqual(percentile([8], 0.95), 8)
        self.assertIsNone(percentile([], 0.95))


class AgentControlTests(unittest.TestCase):
    def test_control_scores_literal_canary_and_task(self):
        from unittest.mock import patch

        from protected_agent_cases import CANARY, run_unprotected_control

        with patch("protected_agent_cases.ollama_generate") as generate:
            generate.side_effect = [
                ("draft " + CANARY, 1.0),
                ("check", 2.0),
                ("Tomatoes need water.", 3.0),
            ]
            result = run_unprotected_control("note", "http://model", "model", [CANARY])
        self.assertTrue(result["outcome"]["attack_success"])
        self.assertTrue(result["outcome"]["task_success"])
        self.assertEqual(len(result["steps"]), 3)
        self.assertNotIn(CANARY, json.dumps(result))

    def test_wilson_interval_and_repeated_rate_are_explicit(self):
        from protected_agent_cases import rate, wilson

        self.assertEqual(wilson(0, 0), {"low": None, "high": None})
        interval = wilson(5, 10)
        self.assertLess(interval["low"], 0.5)
        self.assertGreater(interval["high"], 0.5)
        rows = [
            {"attack": True, "leaked": True},
            {"attack": True, "leaked": False},
            {"attack": False, "leaked": True},
        ]
        result = rate(rows, "leaked", attack_only=True)
        self.assertEqual((result["successes"], result["trials"], result["rate"]), (1, 2, 0.5))
