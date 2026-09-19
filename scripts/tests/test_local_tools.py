import json
import os
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from generate_secrets import SECRET_NAMES, generate
from run_local_demo import Runner, check_ports, configure, load_env, wait_health


class LocalToolsTests(unittest.TestCase):
    def test_secrets_are_unique_and_existing_file_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            generate(path)
            original = path.read_bytes()
            values = load_env(path, {})
            self.assertEqual(len({values[name] for name in SECRET_NAMES}), 8)
            for name in SECRET_NAMES:
                self.assertRegex(values[name], r"^[0-9a-f]{48}$")
            with self.assertRaises(FileExistsError):
                generate(path)
            self.assertEqual(path.read_bytes(), original)
            generate(path, force=True)
            self.assertNotEqual(path.read_bytes(), original)

    def test_dotenv_is_literal_and_environment_wins(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            path.write_text(
                "\ufeff# comment\nexport A='hello world'\nB=$(touch nope)\nC=x=y\n",
                encoding="utf-8",
            )
            self.assertEqual(
                load_env(path, {"A": "override"}),
                {"A": "override", "B": "$(touch nope)", "C": "x=y"},
            )
            path.write_text("broken line\n")
            with self.assertRaises(ValueError):
                load_env(path, {})

    def test_configuration_encodes_password_and_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            generate(path)
            env = load_env(path, {})
            env["MONOLITH_POSTGRES_PASSWORD"] = "a@b:/?#"
            env["MONOLITH_TENANT_ID"] = 'tenant"quoted'
            result = configure(env, [3000, 8001, 8002])
            self.assertIn("a%40b%3A%2F%3F%23", result["DATABASE_ADMIN_URL"])
            self.assertIn('tenant"quoted', json.loads(result["EVENT_INGEST_TOKENS_JSON"]))
            env["DATABASE_ADMIN_URL"] = "postgresql://custom/db"
            self.assertEqual(
                configure(env, [3000, 8001, 8002])["DATABASE_ADMIN_URL"], env["DATABASE_ADMIN_URL"]
            )
            del env["MONOLITH_ADMIN_TOKEN"]
            with self.assertRaises(ValueError):
                configure(env, [3000, 8001, 8002])

    def test_occupied_port_is_rejected_without_touching_listener(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            port = listener.getsockname()[1]
            with self.assertRaises(RuntimeError):
                check_ports([port])
            self.assertEqual(listener.getsockname()[1], port)
        for ports in ([1234, 1234], [0], [65536]):
            with self.assertRaises(ValueError):
                check_ports(ports)

    def test_process_failure_is_reported_and_log_preserved(self):
        with tempfile.TemporaryDirectory(prefix="monolith space ") as directory:
            runner = Runner(Path(directory))
            try:
                with self.assertRaises(RuntimeError):
                    runner.run(
                        "failure",
                        [sys.executable, "-c", "print('diagnostic'); raise SystemExit(7)"],
                        Path(directory),
                        dict(os.environ),
                    )
                self.assertIn("diagnostic", (Path(directory) / "failure.log").read_text())
            finally:
                runner.close()

    def test_cleanup_stops_child_and_preserves_unrelated_process(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = Runner(Path(directory))
            unrelated = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
            child = runner.start(
                "service",
                [sys.executable, "-c", "import time; time.sleep(60)"],
                Path(directory),
                dict(os.environ),
            )
            try:
                runner.close()
                self.assertIsNotNone(child.poll())
                self.assertIsNone(unrelated.poll())
            finally:
                unrelated.terminate()
                unrelated.wait(timeout=5)

    def test_health_check_fails_immediately_for_dead_child(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = Runner(Path(directory))
            child = runner.start(
                "dead", [sys.executable, "-c", "pass"], Path(directory), dict(os.environ)
            )
            child.wait(timeout=5)
            try:
                with self.assertRaises(RuntimeError):
                    wait_health("http://127.0.0.1:1/health", child)
            finally:
                runner.close()

    def test_timeout_cleanup_stops_running_child(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = Runner(Path(directory))
            try:
                with self.assertRaises(subprocess.TimeoutExpired):
                    runner.run(
                        "slow",
                        [sys.executable, "-c", "import time; time.sleep(60)"],
                        Path(directory),
                        dict(os.environ),
                        timeout=0.1,
                    )
            finally:
                runner.close()
            self.assertIsNotNone(runner.children[0].poll())


if __name__ == "__main__":
    unittest.main()
