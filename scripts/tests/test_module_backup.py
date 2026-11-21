"""Exercise the Linux backup helper across Docker failures and publication races."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

HELPER = Path(__file__).resolve().parents[1] / "pilot_module_volumes.sh"
DOCKER = """#!/bin/sh
case "$1" in
  volume) printf '%s\\n' "${7##*=}" ;;
  ps) exit 0 ;;
  run)
    case "$*" in
      *src=trace-audit-outbox,*)
        case "$SCENARIO" in
          failure) printf partial; exit 42 ;;
          race) mkdir "$DEST"; echo winner > "$DEST/marker" ;;
        esac ;;
    esac
    printf 'fixture bytes'
    ;;
  *) exit 1 ;;
esac
"""


class ModuleBackupTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.destination = self.root / "module backup"
        docker = self.root / "docker"
        docker.write_text(DOCKER)
        docker.chmod(0o700)

    def backup(self, scenario):
        return subprocess.run(
            ["bash", HELPER, "backup", "pilot", self.destination],
            env={**os.environ, "PATH": f"{self.root}:{os.environ['PATH']}",
                 "SCENARIO": scenario, "DEST": str(self.destination)},
            capture_output=True, text=True,
        )

    def test_failure_then_retry(self):
        self.assertEqual(self.backup("failure").returncode, 42)
        self.assertFalse(self.destination.exists())
        self.assertEqual(list(self.root.glob(".monolith-backup.*")), [])
        success = self.backup("success")
        self.assertEqual(success.returncode, 0, success.stderr)
        verified = subprocess.run(["sha256sum", "--check", "SHA256SUMS"],
                                  cwd=self.destination, capture_output=True, text=True)
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.assertEqual(verified.stdout.count(": OK"), 4)

    def test_concurrent_destination_survives(self):
        self.assertNotEqual(self.backup("race").returncode, 0)
        self.assertEqual([p.name for p in self.destination.iterdir()], ["marker"])
        self.assertEqual((self.destination / "marker").read_text(), "winner\n")
        self.assertEqual(list(self.root.glob(".monolith-backup.*")), [])
