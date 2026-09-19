"""CI-only disposable PostgreSQL + native three-layer integration smoke test."""

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import uuid
from contextlib import contextmanager
from pathlib import Path

from generate_secrets import generate
from run_local_demo import ROOT


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def postgres_bin():
    candidates = [Path(os.environ["PG_BIN"])] if os.environ.get("PG_BIN") else []
    if shutil.which("initdb"):
        candidates.append(Path(shutil.which("initdb")).parent)
    for base in (Path("/usr/lib/postgresql"), Path("C:/Program Files/PostgreSQL")):
        if base.exists():
            candidates += sorted(base.glob("*/bin"), reverse=True)
    candidates += [
        Path("/opt/homebrew/opt/postgresql@17/bin"),
        Path("/usr/local/opt/postgresql@17/bin"),
    ]
    suffix = ".exe" if os.name == "nt" else ""
    for path in candidates:
        if (path / ("initdb" + suffix)).is_file():
            return path, suffix
    raise RuntimeError("Install PostgreSQL or set PG_BIN to its bin directory")


@contextmanager
def postgres_state():
    # Python's Windows 0700 temporary directory ACL blocks initdb's restricted
    # child token. Inherit the CI workspace ACL, which that token can access.
    state = ROOT / (".native-pg-" + uuid.uuid4().hex)
    state.mkdir(mode=0o755)
    try:
        yield state
    finally:
        shutil.rmtree(state)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--backend", choices=("mock", "ollama"), default="mock")
    args = parser.parse_args()
    directory, suffix = postgres_bin()
    with postgres_state() as state:
        data = state / "database"
        env = dict(os.environ)
        env["PATH"] = str(directory) + os.pathsep + env["PATH"]
        pg_port = free_port()
        env["DATABASE_ADMIN_URL"] = f"postgresql://postgres@127.0.0.1:{pg_port}/postgres"
        generate(ROOT / ".env")
        # Read only the generated runtime password; never print it.
        from run_local_demo import load_env

        config = load_env(ROOT / ".env", env)
        env["DATABASE_URL"] = (
            f"postgresql://monolith_runtime:{config['MONOLITH_DATABASE_RUNTIME_PASSWORD']}@127.0.0.1:{pg_port}/postgres"
        )
        subprocess.run(
            [
                str(directory / ("initdb" + suffix)),
                "-D",
                str(data),
                "-U",
                "postgres",
                "-A",
                "trust",
                "--no-locale",
                "-E",
                "UTF8",
            ],
            check=True,
            env=env,
        )
        # Use TCP only: distro builds may default their Unix socket directory
        # to /var/run/postgresql, which is owned by the system database account.
        with (data / "postgresql.conf").open("a", encoding="utf-8") as config_file:
            config_file.write("\nunix_socket_directories = ''\n")
        ctl = str(directory / ("pg_ctl" + suffix))
        started = False
        try:
            subprocess.run(
                [
                    ctl,
                    "-D",
                    str(data),
                    "-l",
                    str(state / "postgres.log"),
                    "-o",
                    f"-h 127.0.0.1 -p {pg_port}",
                    "-w",
                    "start",
                ],
                check=True,
                env=env,
            )
            started = True
            ports = set()
            while len(ports) < 3:
                ports.add(free_port())
            dash, vector, trace = sorted(ports)
            command = [
                sys.executable,
                str(ROOT / "scripts/run_local_demo.py"),
                "--no-hold",
                "--skip-build",
                "--dash-port",
                str(dash),
                "--va-port",
                str(vector),
                "--ta-port",
                str(trace),
            ]
            if args.backend == "ollama":
                command += ["--backend", "ollama", "--skip-attacks", "--agent-demo"]
            result = subprocess.run(
                command, cwd=ROOT, env=env, text=True, capture_output=True, timeout=900
            )
            print(result.stdout)
            print(result.stderr, file=sys.stderr)
            if result.returncode:
                for line in result.stdout.splitlines():
                    if line.startswith("Demo logs and state: "):
                        logs = Path(line.split(": ", 1)[1])
                        for log in logs.glob("*.log"):
                            tail = log.read_text(encoding="utf-8", errors="replace")[-5000:]
                            for key, value in config.items():
                                if value and any(
                                    word in key
                                    for word in ("TOKEN", "PASSWORD", "SECRET", "KEY", "DATABASE")
                                ):
                                    tail = tail.replace(value, "<redacted>")
                            print(log.name, tail)
                raise RuntimeError("Native full-stack smoke failed; see retained demo directory")
            if args.backend == "ollama":
                for line in result.stdout.splitlines():
                    if line.startswith("Demo logs and state: "):
                        report = Path(line.split(": ", 1)[1]) / "protected-agent/session-report.json"
                        target = ROOT / "evaluation/results/agent-real.json"
                        target.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(report, target)
                        print(target.read_text(encoding="utf-8"))
            # The compatibility roles must stay inert on a plain database.
            roles = subprocess.run(
                [str(directory / ("psql" + suffix)), env["DATABASE_ADMIN_URL"],
                 "-XAt", "-v", "ON_ERROR_STOP=1", "-c",
                 "SELECT count(*) FROM pg_roles WHERE rolname IN ('anon', 'authenticated') "
                 "AND NOT (rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole "
                 "OR rolreplication OR rolbypassrls)"],
                check=True, env=env, capture_output=True, text=True,
            )
            if roles.stdout.strip() != "2":
                raise RuntimeError("Plain PostgreSQL compatibility roles are not inert")
            for port in (dash, vector, trace):
                with socket.socket() as sock:
                    if sock.connect_ex(("127.0.0.1", port)) == 0:
                        raise RuntimeError(f"Service on {port} survived launcher cleanup")
            print(json.dumps({"native_stack": "passed", "cleanup": "passed"}))
        except Exception:
            log = state / "postgres.log"
            if log.exists():
                print(log.read_text(encoding="utf-8", errors="replace")[-5000:])
            raise
        finally:
            if started:
                subprocess.run(
                    [ctl, "-D", str(data), "-m", "immediate", "-w", "stop"], check=True, env=env
                )


if __name__ == "__main__":
    main()
