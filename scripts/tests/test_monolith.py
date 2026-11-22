import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import call, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from generate_secrets import SECRET_NAMES
from monolith import main
from monolith_wrap import find_mcp_shield, load_dotenv


class MonolithCliTests(unittest.TestCase):
    def test_init_creates_private_config_and_preserves_it_on_retry(self):
        with tempfile.TemporaryDirectory() as directory, redirect_stdout(io.StringIO()) as output:
            root = Path(directory)
            with patch("monolith.REPO_ROOT", root):
                self.assertEqual(main(["init"]), 0)
                env_file = root / ".env"
                original = env_file.read_bytes()
                values = load_dotenv(env_file)
                self.assertTrue(all(values.get(name) for name in SECRET_NAMES))
                if os.name != "nt":
                    self.assertEqual(env_file.stat().st_mode & 0o777, 0o600)

                self.assertEqual(main(["init"]), 0)
                self.assertEqual(env_file.read_bytes(), original)
                self.assertIn("kept it in place", output.getvalue())
                for name in SECRET_NAMES:
                    self.assertNotIn(values[name], output.getvalue())

    def test_init_reports_an_occupied_path(self):
        with tempfile.TemporaryDirectory() as directory, redirect_stderr(io.StringIO()) as error:
            root = Path(directory)
            (root / ".env").mkdir()
            with patch("monolith.REPO_ROOT", root):
                self.assertEqual(main(["init"]), 1)
        self.assertIn("path is occupied", error.getvalue())

    @unittest.skipIf(os.name == "nt", "POSIX executable permission check")
    def test_configured_shield_must_be_executable(self):
        with tempfile.TemporaryDirectory() as directory:
            shield = Path(directory) / "mcp-shield"
            shield.touch(mode=0o600)
            with patch.dict(os.environ, {"MONOLITH_MCP_SHIELD_BIN": str(shield)}):
                self.assertIsNone(find_mcp_shield())
                shield.chmod(0o700)
                self.assertEqual(find_mcp_shield(), shield.resolve())

    def test_doctor_uses_launcher_settings_and_checks_every_service(self):
        dotenv = {
            "MONOLITH_DASHBOARD_API_URL": "https://dashboard.example.test/",
            "MONOLITH_VECTOR_ANCHOR_URL": "https://vector.example.test",
            "MONOLITH_EVENT_TOKEN_MCP_SHIELD": "sample-token-for-test-only",
        }
        with (
            patch.dict(os.environ, {"MONOLITH_VECTOR_ANCHOR_URL": "http://localhost:8101"}, clear=True),
            patch("monolith.load_dotenv", return_value=dotenv),
            patch("monolith.find_mcp_shield", return_value=Path("mcp-shield")),
            patch("monolith_wrap.service_healthy", return_value=True) as service_healthy,
            redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(main(["doctor"]), 0)

        self.assertEqual(service_healthy.call_args_list, [
            call("https://dashboard.example.test/api/ingest"),
            call("http://localhost:8101/health"),
            call("http://127.0.0.1:8002/health"),
        ])
        self.assertIn("Gateway preflight passed", output.getvalue())
        self.assertNotIn(dotenv["MONOLITH_EVENT_TOKEN_MCP_SHIELD"], output.getvalue())

    def test_doctor_reports_failures_without_revealing_url_credentials(self):
        with (
            patch.dict(os.environ, {
                "MONOLITH_DASHBOARD_API_URL": "https://user:url-secret@dashboard.example.test/path-secret",
                "https_proxy": "http://user:proxy-secret@proxy.example.test",
            }, clear=True),
            patch("monolith.load_dotenv", return_value={}),
            patch("monolith.find_mcp_shield", return_value=None) as find_shield,
            patch("monolith_wrap.service_healthy", side_effect=[False, True, True]),
            redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(main(["doctor", "--no-mcp"]), 2)
            find_shield.assert_not_called()

        report = output.getvalue()
        self.assertIn("[FAIL] Dashboard ingest", report)
        self.assertIn("https://dashboard.example.test", report)
        self.assertIn("http://proxy.example.test", report)
        self.assertIn("[OK]   TraceAudit", report)
        self.assertIn("[FAIL] MCP-Shield event token", report)
        self.assertNotIn("MCP-Shield binary", report)
        self.assertNotIn("secret", report)

    def test_wrap_passes_through_args_and_exit_code(self):
        args = ["--claude", "--", "-p", "Summarize the project"]
        with patch("monolith.wrap", return_value=7) as wrap:
            self.assertEqual(main(["wrap", *args]), 7)
        wrap.assert_called_once_with(args)
