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
