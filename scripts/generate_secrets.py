"""Generate local development credentials on Windows, macOS, or Linux."""

import argparse
import os
import secrets
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SECRET_NAMES = (
    "MONOLITH_POSTGRES_PASSWORD",
    "MONOLITH_DATABASE_RUNTIME_PASSWORD",
    "MONOLITH_EVENT_TOKEN_MCP_SHIELD",
    "MONOLITH_EVENT_TOKEN_VECTOR_ANCHOR",
    "MONOLITH_EVENT_TOKEN_TRACE_AUDIT",
    "MCP_SHIELD_KEY",
    "MONOLITH_ADMIN_TOKEN",
    "MONOLITH_OPERATOR_TOKEN",
)


def generate(path: Path, force: bool = False) -> None:
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if force else os.O_EXCL)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as output:
        output.write("# Local development credentials. Never commit this file.\n")
        for name in SECRET_NAMES:
            output.write(f"{name}={secrets.token_hex(24)}\n")
        output.write("MONOLITH_TENANT_ID=default\nMONOLITH_OPERATOR_NAME=operator\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true", help="replace existing credentials")
    args = parser.parse_args()
    try:
        generate(ROOT / ".env", args.force)
    except FileExistsError:
        parser.exit(1, "Refusing to overwrite .env; use --force to regenerate.\n")
    print("Wrote .env with 8 random secrets (values not printed).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
