"""Set up and run the Project Black Monolith local gateway."""

import argparse
import sys

from generate_secrets import generate
from monolith_wrap import (
    REPO_ROOT,
    check_gateway_readiness,
    find_mcp_shield,
    load_dotenv,
    resolve_setting,
    service_urls,
)
from monolith_wrap import main as wrap


def init() -> int:
    env_file = REPO_ROOT / ".env"
    try:
        generate(env_file)
    except FileExistsError:
        if not env_file.is_file():
            print("Could not create .env because the path is occupied.", file=sys.stderr)
            return 1
        print("Found an existing .env and kept it in place.")
    except OSError as error:
        print(f"Could not create .env ({error.strerror}).", file=sys.stderr)
        return 1
    else:
        print("Created .env with local development credentials.")
    print("Start the stack with `docker compose up -d --build --wait`.")
    return 0


def doctor(no_mcp: bool) -> int:
    dotenv = load_dotenv(REPO_ROOT / ".env")
    checks = check_gateway_readiness(
        *service_urls(dotenv),
        shield=None if no_mcp else find_mcp_shield(),
        event_token=resolve_setting("MONOLITH_EVENT_TOKEN_MCP_SHIELD", dotenv),
        require_shield=not no_mcp,
    )
    for name, problem in checks:
        if problem:
            print(f"[FAIL] {name}. {problem}")
        else:
            print(f"[OK]   {name}")
    if any(problem for _, problem in checks):
        return 2
    print("Gateway preflight passed.")
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "wrap":
        return wrap(argv[1:])

    parser = argparse.ArgumentParser(prog="monolith", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init", help="create local development credentials")
    doctor_parser = commands.add_parser("doctor", help="check gateway readiness")
    doctor_parser.add_argument(
        "--no-mcp", action="store_true", help="skip the MCP-Shield binary check"
    )
    commands.add_parser("wrap", help="launch an agent through the gateway")
    args = parser.parse_args(argv)
    if args.command == "init":
        return init()
    return doctor(args.no_mcp)


if __name__ == "__main__":
    raise SystemExit(main())
