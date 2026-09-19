import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from reset_demo_state import reset_detection
from verify_session import EXPECTED, verify_session


class OperationTests(unittest.TestCase):
    def test_reset_targets_only_authenticated_detector_endpoint(self):
        with patch("reset_demo_state.post") as post:
            reset_detection("http://127.0.0.1:8001/", "admin-token")
            post.assert_called_once_with(
                "http://127.0.0.1:8001/admin/reset-detection", {}, "admin-token"
            )

    def test_ledger_verification_requires_three_actual_finding_types(self):
        events = [
            {"module": module, "event_type": kind, "event_id": "id"}
            for module, kind in EXPECTED.items()
        ]
        with patch(
            "verify_session.get",
            side_effect=[
                {"incidents": events},
                {"session": {"cross_layer": True, "layers": [1, 2, 3]}},
            ],
        ) as get:
            result = verify_session("http://local", "token", "session", "agent")
            self.assertTrue(result["cross_layer"])
            self.assertIn("session=session&agent=agent", get.call_args_list[0].args[0])
        with (
            patch("verify_session.get", return_value={"incidents": []}),
            self.assertRaises(RuntimeError),
        ):
            verify_session("http://local", "token", "session", "agent", timeout=0)
