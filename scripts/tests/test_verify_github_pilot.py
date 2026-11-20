import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from verify_github_pilot import Pilot, VerificationError, prepare, verify


class PilotVerificationTests(unittest.TestCase):
    def test_different_dashboard_target_is_refused_before_any_draft(self):
        pilot = Pilot("http://localhost:3000", "fixtures/dedicated", 2, "github", "agent", "operator")
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state.json"
            with patch("verify_github_pilot.request", return_value={"repository": "other/repo", "number": 2}) as request:
                with self.assertRaisesRegex(VerificationError, "different test repository"):
                    prepare(pilot, state, "add", "remove")
                self.assertEqual(request.call_count, 1)
                self.assertFalse(state.exists())

    def test_verifier_will_not_approve_a_pending_success_fixture(self):
        pilot = Mock()
        pilot.audit.return_value = {"reply": {"status": "pending"}}
        with self.assertRaisesRegex(VerificationError, "reviewer must successfully approve reply"):
            verify(pilot, {"changed_rejected": True}, "check-now")
        pilot.review.assert_not_called()

    def test_verifier_detects_duplicate_matching_replies_across_pages(self):
        pilot = Pilot("http://localhost:3000", "fixtures/dedicated", 2, "github", "agent", "operator")
        reply = {"id": 42, "body": "[fixture] Exact reply"}
        first_page = [{"body": "unrelated"}] * 99 + [reply]
        with (
            patch("verify_github_pilot.request", side_effect=[first_page, [reply]]),
            self.assertRaisesRegex(VerificationError, "exactly one fixture reply.*found 2"),
        ):
            pilot.github_outcome({"marker": "[fixture]"}, {"value": reply["body"], "github_comment_id": "42"})
