"""Build a deterministic platform bundle with native MCP-Shield and SPDX SBOM."""

import argparse
import hashlib
import json
import os
import re
import subprocess
import tomllib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EPOCH = (2020, 1, 1, 0, 0, 0)


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT)


def blob(commit, path):
    return git("show", f"{commit}:{path}")


def component(ref, name, version, ecosystem, checksum=None, license_name=None):
    item = {
        "SPDXID": ref,
        "name": name,
        "versionInfo": version,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": license_name or "NOASSERTION",
        "licenseDeclared": license_name or "NOASSERTION",
        "copyrightText": "NOASSERTION",
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": f"pkg:{ecosystem}/{name}@{version}",
            }
        ],
    }
    if checksum:
        item["checksums"] = [{"algorithm": "SHA256", "checksumValue": checksum}]
    return item


def make_sbom(commit, version):
    packages = [component("SPDXRef-Root", "project-black-monolith", version, "generic")]
    seen = set()
    for lock_path in ("vector-anchor/requirements.lock", "trace-audit/requirements.lock"):
        for line in blob(commit, lock_path).decode().splitlines():
            match = re.match(r"([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+!-]+)", line)
            if match and ("pypi", *match.groups()) not in seen:
                name, package_version = match.groups()
                seen.add(("pypi", name, package_version))
                packages.append(
                    component(f"SPDXRef-PyPI-{len(packages)}", name, package_version, "pypi")
                )
    cargo = tomllib.loads(blob(commit, "mcp-shield/Cargo.lock").decode())
    for package in cargo["package"]:
        key = ("cargo", package["name"], package["version"])
        if key in seen:
            continue
        seen.add(key)
        packages.append(
            component(
                f"SPDXRef-Cargo-{len(packages)}",
                package["name"],
                package["version"],
                "cargo",
                package.get("checksum"),
            )
        )
    npm = json.loads(blob(commit, "dashboard/package-lock.json"))
    for path, package in npm["packages"].items():
        if not path or "version" not in package:
            continue
        name = path.rsplit("node_modules/", 1)[-1]
        key = ("npm", name, package["version"])
        if key in seen:
            continue
        seen.add(key)
        packages.append(
            component(
                f"SPDXRef-NPM-{len(packages)}",
                name,
                package["version"],
                "npm",
                license_name=package.get("license"),
            )
        )
    namespace_hash = hashlib.sha256((commit + version).encode()).hexdigest()
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"black-monolith-{version}",
        "documentNamespace": f"https://github.com/yuno7777/project-black-monolith/spdx/{namespace_hash}",
        "creationInfo": {
            "created": "2020-01-01T00:00:00Z",
            "creators": ["Tool: scripts/build_platform_bundle.py"],
        },
        "packages": packages,
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": "SPDXRef-Root",
            }
        ],
    }


def add(archive, name, content, mode=0o100644):
    info = zipfile.ZipInfo(name, EPOCH)
    info.create_system = 3
    info.external_attr = mode << 16
    archive.writestr(info, content)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--platform",
        required=True,
        choices=("windows-x86_64", "linux-x86_64", "macos-x86_64", "macos-arm64"),
    )
    parser.add_argument("--version", default="0.3.0-rc.1")
    parser.add_argument("--revision", default="HEAD")
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--output", type=Path, default=ROOT / "dist")
    args = parser.parse_args()
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:-[a-z0-9.]+)?", args.version):
        raise ValueError("Invalid semantic version")
    commit = git("rev-parse", "--verify", args.revision + "^{commit}").decode().strip()
    suffix = ".exe" if args.platform.startswith("windows") else ""
    binary = args.binary or ROOT / "mcp-shield/target/release" / ("mcp-shield" + suffix)
    binary_bytes = binary.read_bytes()
    if not binary_bytes:
        raise ValueError("MCP-Shield binary is empty")
    sbom = json.dumps(make_sbom(commit, args.version), indent=2, sort_keys=True).encode() + b"\n"
    prefix = f"black-monolith-{args.version}-{args.platform}/"
    entries = git("ls-tree", "-rz", "--full-tree", commit).split(b"\0")
    args.output.mkdir(parents=True, exist_ok=True)
    destination = args.output / f"black-monolith-{args.version}-{args.platform}.zip"
    with zipfile.ZipFile(
        destination, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:
        for entry in sorted(item for item in entries if item):
            metadata, raw_name = entry.split(b"\t", 1)
            mode, kind, sha = metadata.decode().split()
            name = raw_name.decode()
            if kind != "blob" or mode not in ("100644", "100755"):
                raise ValueError(f"Unsupported release entry: {name}")
            if Path(name).name == ".env" or name.startswith(("evaluation/results/", "dist/")):
                raise ValueError(f"Sensitive/generated tracked file: {name}")
            add(archive, prefix + name, git("cat-file", "blob", sha), int(mode, 8))
        bundled_binary = prefix + "mcp-shield/target/debug/mcp-shield" + suffix
        add(archive, bundled_binary, binary_bytes, 0o100755)
        add(archive, prefix + "SBOM.spdx.json", sbom)
    digest = hashlib.sha256(destination.read_bytes()).hexdigest()
    destination.with_suffix(".zip.sha256").write_text(f"{digest}  {destination.name}\n")
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": destination.name, "digest": {"sha256": digest}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://github.com/yuno7777/project-black-monolith/actions/workflows/package.yml@v1",
                "externalParameters": {"platform": args.platform, "version": args.version},
                "resolvedDependencies": [
                    {
                        "uri": "git+https://github.com/yuno7777/project-black-monolith",
                        "digest": {"gitCommit": commit},
                    }
                ],
            },
            "runDetails": {
                "builder": {
                    "id": "https://github.com/actions/runner"
                    if os.getenv("GITHUB_ACTIONS")
                    else "local:build_platform_bundle.py"
                },
                "metadata": {"invocationId": os.getenv("GITHUB_RUN_ID", "local")},
            },
        },
    }
    destination.with_suffix(".intoto.jsonl").write_text(
        json.dumps(statement, sort_keys=True) + "\n"
    )
    print(
        json.dumps(
            {
                "bundle": str(destination),
                "sha256": digest,
                "packages": len(json.loads(sbom)["packages"]),
            }
        )
    )


if __name__ == "__main__":
    main()
