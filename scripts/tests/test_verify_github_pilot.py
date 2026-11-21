import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from verify_github_pilot import Pilot, VerificationError, main, prepare, verify, write_evidence


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

    def test_evidence_uses_audit_outcome_without_including_payloads(self):
        pilot = Mock()
        pilot.audit.return_value = {
            name: {"id": name, "status": status, "value": "fixture message", "credentials": "private credential"}
            for name, status in {
                "reply": "succeeded", "add_label": "succeeded", "remove_label": "succeeded",
                "denied": "denied", "revoked": "pending", "expired": "pending",
            }.items()
        }
        pilot.audit.return_value["revoked"]["session_revoked_at"] = "2026-11-21T00:00:00Z"
        pilot.review.return_value = {"status": "revoked", "reviewed_at": "2026-11-21T00:00:01Z"}
        report = verify(pilot, {"changed_rejected": True, "repository": "fixtures/dedicated", "issue": 2}, "check-now")
        self.assertEqual(report["actions"]["revoked"]["status"], "revoked")
        self.assertEqual(report["actions"]["revoked"]["reviewed_at"], "2026-11-21T00:00:01Z")
        self.assertNotIn("expired", report["actions"])
        self.assertIn("exact_github_reply_and_labels", report["checks"])
        serialized = json.dumps(report)
        self.assertNotIn("private credential", serialized)
        self.assertNotIn("fixture message", serialized)

    def test_existing_evidence_survives_a_failed_publish(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.json"
            write_evidence(path, {"phase": "check-now"})
            with self.assertRaises(FileExistsError):
                write_evidence(path, {"phase": "check-expired"})
            self.assertEqual(json.loads(path.read_text()), {"phase": "check-now"})
            self.assertEqual(list(path.parent.iterdir()), [path])

    def test_failed_check_creates_no_evidence_file(self):
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "state.json"
            evidence_path = Path(directory) / "evidence.json"
            state_path.write_text(json.dumps({"repository": "fixtures/dedicated", "issue": 2, "drafts": dict.fromkeys(
                ("reply", "add_label", "remove_label", "denied", "expired", "revoked"),
            )}))
            args = ["verify_github_pilot.py", "check-now", "--test-repository", "fixtures/dedicated", "--issue", "2",
                    "--state", str(state_path), "--evidence", str(evidence_path)]
            env = {"MONOLITH_DASHBOARD_API_URL": "http://localhost:3000", "MONOLITH_VERIFY_GITHUB_TOKEN": "github",
                   "MONOLITH_OPERATOR_TOKEN": "operator"}
            with (
                patch.object(sys, "argv", args),
                patch.dict("os.environ", env, clear=True),
                patch("verify_github_pilot.verify", side_effect=VerificationError("unexpected duplicate")),
                patch("sys.stderr"),
            ):
                self.assertEqual(main(), 1)
                self.assertFalse(evidence_path.exists())
