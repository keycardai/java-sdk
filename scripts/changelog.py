#!/usr/bin/env python3
"""Release plumbing for the Java SDK.

Usage:
  python3 scripts/changelog.py validate [base_branch]
  python3 scripts/changelog.py check-drift
  python3 scripts/changelog.py changes [--output-format json|github]
  python3 scripts/changelog.py package <tag> [--output-format json|github]

Commands:
  validate      Check commit messages against the conventional commit format
  check-drift   Fail if .cz.toml's version disagrees with gradle.properties
  changes       List the package if it has unreleased changes ([] otherwise)
  package       Resolve a v<version> release tag to the package and version

Every module releases together under one lockstep version, so there is one
package, ``java-sdk``, rooted at the repository root. The list shape of
``changes`` matches the other SDK repos, so main.yml can feed it to a matrix.
Commitizen is a Python tool, so the release scripts are Python.
"""

import argparse
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = {"package_name": "java-sdk", "package_dir": "."}
TAG = re.compile(r"^v(\d+\.\d+\.\d+)$")


def run_command(cmd: list[str], cwd: str | Path | None = None) -> tuple[int, str, str]:
    """Run a command and return exit code, stdout, stderr."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd, check=False)
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except Exception as e:  # noqa: BLE001 - surfaced to the caller as a failure
        return 1, "", str(e)


def read_cz_version(root: Path = ROOT) -> str | None:
    with open(root / ".cz.toml", "rb") as f:
        return tomllib.load(f).get("tool", {}).get("commitizen", {}).get("version")


def read_gradle_version(root: Path = ROOT) -> str | None:
    """Return the ``version=`` value from gradle.properties, or ``None``."""
    path = root / "gradle.properties"
    if not path.exists():
        return None
    for line in path.read_text().splitlines():
        match = re.match(r"^\s*version\s*=\s*(\S+)\s*$", line)
        if match:
            return match.group(1)
    return None


def check_version_drift(root: Path = ROOT) -> dict | None:
    """Return a drift record when .cz.toml and gradle.properties disagree.

    Commitizen treats ``[tool.commitizen].version`` as the current version and
    rewrites gradle.properties from it. Hand-edit gradle.properties without
    ``cz bump`` and the two drift apart, after which the next automated bump
    tries to create a tag that already exists.
    """
    cz_version = read_cz_version(root)
    gradle_version = read_gradle_version(root)
    if cz_version and gradle_version == cz_version:
        return None
    return {"file": "gradle.properties", "cz_version": cz_version, "file_version": gradle_version}


def get_merge_base(base_branch: str) -> str:
    exit_code, stdout, stderr = run_command(["git", "merge-base", base_branch, "HEAD"])
    if exit_code != 0:
        raise Exception(f"Failed to get merge base: {stderr}")
    return stdout


def validate_commits_with_cz(base_branch: str) -> bool:
    rev_range = f"{get_merge_base(base_branch)}..HEAD"
    exit_code, stdout, _ = run_command(["git", "rev-list", rev_range])
    if exit_code != 0 or not stdout.strip():
        return True  # No commits to validate
    exit_code, stdout, stderr = run_command(["cz", "check", "--rev-range", rev_range])
    if exit_code != 0:
        print(stdout or stderr)
    return exit_code == 0


def has_unreleased_changes(root: Path = ROOT) -> bool:
    """True when ``cz changelog --dry-run`` reports entries under Unreleased."""
    exit_code, stdout, _ = run_command(["cz", "changelog", "--dry-run"], cwd=root)
    if exit_code != 0 or not stdout.strip():
        return False
    lines = stdout.split("\n")
    if not lines[0].strip().startswith("## Unreleased"):
        return False
    for line in lines[1:]:
        line = line.strip()
        if line.startswith("## "):
            break  # the next release; "### Feat" style group headings stay inside Unreleased
        if line and not line.startswith("#"):
            return True
    return False


def detect_changes() -> list[dict]:
    return [PACKAGE] if has_unreleased_changes() else []


def extract_package_from_tag(tag: str) -> dict:
    """Resolve a ``v<version>`` release tag to the package and version."""
    if tag.startswith("refs/tags/"):
        tag = tag[len("refs/tags/") :]
    match = TAG.match(tag)
    if not match:
        raise Exception(f"'{tag}' is not a release tag. Expected v<major>.<minor>.<patch>")
    return {"tag": tag, "version": match.group(1), **PACKAGE}


def _print(value, output_format: str) -> None:
    print(json.dumps(value, separators=(",", ":")) if output_format == "github" else json.dumps(value, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(description="Release plumbing for the Java SDK.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate_p = subparsers.add_parser("validate", help="Validate commit messages")
    validate_p.add_argument("base_branch", nargs="?", default="origin/main")
    subparsers.add_parser("check-drift", help="Compare .cz.toml with gradle.properties")
    changes_p = subparsers.add_parser("changes", help="List the package if it has unreleased changes")
    changes_p.add_argument("--output-format", choices=["json", "github"], default="json")
    package_p = subparsers.add_parser("package", help="Resolve a release tag")
    package_p.add_argument("tag")
    package_p.add_argument("--output-format", choices=["json", "github"], default="json")
    args = parser.parse_args()

    if args.command == "validate":
        if not validate_commits_with_cz(args.base_branch):
            sys.exit(1)
        print("All commit messages are valid.")
    elif args.command == "check-drift":
        drift = check_version_drift()
        if drift:
            print(
                f"Version drift: .cz.toml says {drift['cz_version']}, {drift['file']} says "
                f"{drift['file_version']}. Let cz bump own both; don't hand-edit either."
            )
            sys.exit(1)
        print("No version drift.")
    elif args.command == "changes":
        _print(detect_changes(), args.output_format)
    else:
        try:
            _print(extract_package_from_tag(args.tag), args.output_format)
        except Exception as e:  # noqa: BLE001 - reported as a CLI error
            print(str(e), file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
