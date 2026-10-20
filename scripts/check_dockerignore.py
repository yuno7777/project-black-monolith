"""Keep .dockerignore in step with .gitignore.

Every image builds from the repository root (the `context: .` lines in
docker-compose.yml), so the root .dockerignore is the only file that decides
what enters an image. .gitignore already says what must not be committed; a
pattern that is missing from .dockerignore is a file that is absent from the
repository but present in the build context and, from there, in the image.

The check is derived from .gitignore rather than from a list written here, so
adding a pattern to .gitignore is enough to make it fail here until
.dockerignore catches up.

Usage: python scripts/check_dockerignore.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
GITIGNORE = ROOT / ".gitignore"
DOCKERIGNORE = ROOT / ".dockerignore"


def read_patterns(path: Path) -> list[tuple[str, bool]]:
    """Return the (pattern, is_negation) pairs of a gitignore-style file."""
    out: list[tuple[str, bool]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        negated = line.startswith("!")
        if negated:
            line = line[1:].strip()
        out.append((line, negated))
    return out


def to_regex(pattern: str) -> re.Pattern[str]:
    """Compile one .dockerignore pattern into a full-path matcher.

    Docker's semantics: `*` does not cross a path separator, `**` does, and a
    pattern with no separator matches a basename at any depth.
    """
    body = pattern.rstrip("/")
    out: list[str] = []
    index = 0
    while index < len(body):
        char = body[index]
        if char == "*":
            if body[index : index + 3] == "**/":
                out.append("(?:.*/)?")
                index += 3
                continue
            if body[index : index + 2] == "**":
                out.append(".*")
                index += 2
                continue
            out.append("[^/]*")
            index += 1
            continue
        if char == "?":
            out.append("[^/]")
            index += 1
            continue
        if char == "[":
            close = body.find("]", index + 1)
            if close == -1:
                out.append(re.escape(char))
                index += 1
                continue
            out.append(body[index : close + 1])
            index = close + 1
            continue
        out.append(re.escape(char))
        index += 1
    joined = "".join(out)
    if "/" not in body:
        # No separator: the pattern names a basename and matches at any depth.
        return re.compile(r"(?:.*/)?" + joined + r"(?:/.*)?$")
    return re.compile(r"^" + joined + r"(?:/.*)?$")


def sample_path(pattern: str) -> str:
    """Build a representative path that the pattern would match.

    A pattern like `**/detector_state.json*` becomes
    `a/b/detector_state.jsonx` — a path that exists nowhere, which is the
    point: it is what a real file of that shape would be called.
    """
    text = pattern.rstrip("/")
    text = re.sub(r"\*\*/", "a/b/", text)
    text = text.replace("**", "a/b")
    # A character class stands for one of its members, so the sample has to
    # name one of them — `*.py[cod]` means `x.pyc`, not `x.py[cod]`.
    text = re.sub(
        r"\[([!]?)([^\]])[^\]]*\]",
        lambda match: match.group(2) if match.group(1) else match.group(2),
        text,
    )
    text = text.replace("*", "x")
    text = text.replace("?", "x")
    return text.lstrip("/")


def excluded(path: str, patterns: list[tuple[str, bool]]) -> bool:
    """Apply an ordered .dockerignore rule set to a path."""
    result = False
    for pattern, negated in patterns:
        if to_regex(pattern).match(path):
            result = not negated
    return result


def validate() -> None:
    git_patterns = read_patterns(GITIGNORE)
    docker_patterns = read_patterns(DOCKERIGNORE)

    failures: list[str] = []

    for pattern, negated in git_patterns:
        sample = sample_path(pattern)
        if negated:
            # A negation in .gitignore means the file is meant to be present.
            # The image must make the same exception, or the file is silently
            # dropped from the context.
            if not any(
                not other_negated and excluded(sample, [(other, False)])
                for other, other_negated in docker_patterns
            ) and not any(
                other_negated and to_regex(other).match(sample)
                for other, other_negated in docker_patterns
            ):
                failures.append(
                    f"  .gitignore keeps {pattern!r} but .dockerignore excludes "
                    f"the sample path {sample!r}"
                )
            continue
        if not excluded(sample, docker_patterns):
            failures.append(
                f"  .gitignore excludes {pattern!r} but .dockerignore still "
                f"ships the sample path {sample!r}"
            )

    # A per-module .dockerignore is inert: Docker reads the one at the root
    # of the build context, and every context here is the repository root.
    # A file that looks protective but protects nothing is worse than none.
    inert = sorted(
        str(path.relative_to(ROOT)).replace("\\", "/")
        for path in ROOT.glob("*/.dockerignore")
    )
    if inert:
        failures.append(
            "  per-module .dockerignore files are inert because every build "
            f"context is the repository root: {', '.join(inert)}"
        )

    if failures:
        raise AssertionError(
            ".dockerignore is out of step with .gitignore:\n"
            + "\n".join(failures)
            + "\n\nAdd the missing patterns to .dockerignore (the root one), "
            "or remove the .gitignore rule if it should not apply to an image."
        )


if __name__ == "__main__":
    try:
        validate()
    except AssertionError as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
    print("dockerignore parity: ok")
