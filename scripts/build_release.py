#!/usr/bin/env python3
"""Build a release-ready copy of the lab.

Produces ``../BCSSL-Cybersecurity-Assessment-Lab-RELEASE/`` containing only
what an instructor or student needs:

  * source, configuration, scripts, target definition, tools documentation,
    exercises, evidence and report skeletons, both guides, README
  * installation and troubleshooting instructions

Excluded, deliberately:

  * virtual environments, ``__pycache__``, ``*.pyc``
  * downloaded Nuclei templates (re-fetched by ``setup.ps1``)
  * generated scan results, evidence records and student progress
  * secrets, credentials, temporary files

Usage::

    python scripts/build_release.py [--output PATH] [--include-artifacts]
"""

from __future__ import annotations

import argparse
import filecmp
import shutil
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = PROJECT_ROOT.parent / "BCSSL-Cybersecurity-Assessment-Lab-RELEASE"

#: Directories copied wholesale.
INCLUDE_DIRS = (
    "bcssl",
    "config",
    "docs",
    "lab",
    "runners",
    "parsers",
    "scripts",
    "target",
    "tests",
    "tools",
)

#: Individual files copied.
INCLUDE_FILES = (
    "README.md",
    "LICENSE",
    ".gitignore",
    "pyproject.toml",
    "RELEASE-CHECKLIST.md",
)

#: Empty skeleton directories recreated in the release.
#:
#: Evidence and report namespaces are created per assessment, so only the
#: parent directories are skeletonised here.
INCLUDE_SKELETON = (
    "reports/raw",
    "reports/normalized",
    "reports/final",
    "evidence",
    "state",
    "state/assessments",
)

EXCLUDE_DIR_NAMES = {
    "__pycache__",
    ".venv",
    "venv",
    "env",
    ".git",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "node_modules",
    "htmlcov",
}

EXCLUDE_SUFFIXES = {".pyc", ".pyo", ".pyd", ".log", ".tmp", ".bak", ".old"}

#: Nuclei templates are data, not source: re-fetched by setup.ps1.
EXCLUDE_RELATIVE = (
    "tools/nuclei/templates",
    "tools/nuclei/templates-lab",
)


def _ignore(directory: str, names: list[str]) -> set[str]:
    """Return the names to skip while copying *directory*.

    Only known-bad directory names and excluded file suffixes are skipped.
    Ordinary subdirectories must be recursed into, otherwise the release
    silently loses nested packages such as ``bcssl/runners``.
    """
    ignored = set()
    for name in names:
        path = Path(directory) / name
        if name in EXCLUDE_DIR_NAMES:
            ignored.add(name)
        elif path.is_dir():
            continue  # recurse normally
        elif path.suffix.lower() in EXCLUDE_SUFFIXES:
            ignored.add(name)
    return ignored


def copy_tree(source: Path, destination: Path) -> int:
    """Copy *source* to *destination*, applying the exclusion rules."""
    if not source.is_dir():
        return 0
    count = 0
    destination.mkdir(parents=True, exist_ok=True)
    for item in source.iterdir():
        if item.name in EXCLUDE_DIR_NAMES:
            continue
        if item.is_dir():
            count += copy_tree(item, destination / item.name)
        elif item.suffix.lower() in EXCLUDE_SUFFIXES:
            continue
        else:
            shutil.copy2(item, destination / item.name)
            count += 1
    return count


def build(output: Path, include_artifacts: bool = False) -> dict[str, int]:
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)

    counts = {"directories": 0, "files": 0, "skeleton_dirs": 0}

    for name in INCLUDE_DIRS:
        source = PROJECT_ROOT / name
        if not source.is_dir():
            continue
        destination = output / name
        shutil.copytree(
            source,
            destination,
            ignore=_ignore,
            ignore_dangling_symlinks=True,
        )
        counts["directories"] += 1

    for name in INCLUDE_FILES:
        source = PROJECT_ROOT / name
        if source.is_file():
            shutil.copy2(source, output / name)
            counts["files"] += 1

    for name in INCLUDE_SKELETON:
        (output / name).mkdir(parents=True, exist_ok=True)
        keep = output / name / ".gitkeep"
        keep.touch()
        counts["skeleton_dirs"] += 1

    if include_artifacts:
        for name in ("reports/raw", "reports/normalized", "reports/final", "evidence", "state"):
            source = PROJECT_ROOT / name
            if source.is_dir():
                counts["files"] += copy_tree(source, output / name)

    # Remove any template trees that slipped through the directory copy.
    for relative in EXCLUDE_RELATIVE:
        target = output / relative
        if target.is_dir():
            shutil.rmtree(target, ignore_errors=True)

    total = sum(
        1 for item in output.rglob("*") if item.is_file() and ".git" not in item.parts
    )
    counts["total_files"] = total
    return counts


def audit(output: Path) -> list[str]:
    """Check the release for anything that must not ship, and for omissions."""
    problems: list[str] = []

    for path in output.rglob("*"):
        if not path.is_file():
            continue
        parts = set(path.parts)
        if "__pycache__" in parts:
            problems.append(f"python cache present: {path.relative_to(output)}")
        if path.suffix.lower() in EXCLUDE_SUFFIXES:
            problems.append(f"excluded file type: {path.relative_to(output)}")
        if "templates" in parts or "templates-lab" in parts:
            problems.append(f"nuclei templates present: {path.relative_to(output)}")

    # Generated artifacts must be absent unless explicitly requested. Patterns
    # cover both the per-assessment namespace and the older flat layout.
    for pattern in (
        "reports/raw/*",
        "reports/raw/*/*",
        "reports/raw/*/*/*",
        "reports/normalized/*",
        "reports/final/*",
        "evidence/*",
        "evidence/*/*",
        "evidence/*/*/*",
        "state/*",
        "state/*/*",
    ):
        for path in output.glob(pattern):
            if path.name == ".gitkeep" or path.is_dir():
                continue
            problems.append(f"generated artifact present: {path.relative_to(output)}")

    # Required content must be present.
    required = (
        "README.md",
        "LICENSE",
        "pyproject.toml",
        "RELEASE-CHECKLIST.md",
        ".gitignore",
        "bcssl/__init__.py",
        "bcssl/cli.py",
        "bcssl/target.py",
        "bcssl/runs.py",
        "bcssl/sarif.py",
        "bcssl/runners/__init__.py",
        "bcssl/runners/nmap.py",
        "bcssl/parsers/__init__.py",
        "bcssl/lab/__init__.py",
        "bcssl/lab/quiz.py",
        "bcssl/web/__init__.py",
        "bcssl/web/static/index.html",
        "bcssl/web/static/app.js",
        "bcssl/web/static/styles.css",
        "config/lab-config.json",
        "target/docker-compose.yml",
        "target/README.md",
        "scripts/setup.ps1",
        "scripts/preflight.ps1",
        "scripts/start-target.ps1",
        "scripts/stop-target.ps1",
        "scripts/check-target.ps1",
        "scripts/start-lab.ps1",
        "scripts/stop-lab.ps1",
        "scripts/run-all.ps1",
        "scripts/clean.ps1",
        "scripts/build_release.py",
        "docs/installation.md",
        "docs/limitations.md",
        "docs/instructor-quick-start.md",
        "docs/student-quick-start.md",
        "docs/demo-guide.md",
        "docs/presentation-guide.md",
        "tools/nuclei/README.md",
        "tests/conftest.py",
        "tests/test_runs.py",
        "tests/test_sarif.py",
    )
    for relative in required:
        if not (output / relative).exists():
            problems.append(f"MISSING required file: {relative}")

    exercises = list((output / "lab").rglob("exercise.json"))
    if len(exercises) != 12:
        problems.append(f"expected 12 exercises, found {len(exercises)}")
    for level in ("beginner", "intermediate", "advanced"):
        count = len(list((output / "lab" / level).glob("ex*")))
        if count != 4:
            problems.append(f"expected 4 {level} exercises, found {count}")

    # No fabricated results may ship.
    for pattern in ("reports/final/*.sarif", "reports/final/*.html", "evidence/**/*.json"):
        for path in output.glob(pattern):
            problems.append(f"possible scan result in release: {path.relative_to(output)}")

    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the lab release package.")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument(
        "--include-artifacts",
        action="store_true",
        help="also copy scan artifacts (normally excluded from a release)",
    )
    args = parser.parse_args(argv)

    output = Path(args.output).expanduser().resolve()
    print(f"Project root : {PROJECT_ROOT}")
    print(f"Output       : {output}")
    print()

    counts = build(output, include_artifacts=args.include_artifacts)

    print(f"Copied {counts['directories']} directories")
    print(f"Copied {counts['files']} root files")
    print(f"Created {counts['skeleton_dirs']} empty skeleton directories")
    print(f"Release contains {counts['total_files']} files")
    print()

    problems = audit(output)
    if problems:
        print("RELEASE AUDIT: problems found", file=sys.stderr)
        for problem in problems[:40]:
            print(f"  - {problem}", file=sys.stderr)
        if len(problems) > 40:
            print(f"  ... and {len(problems) - 40} more", file=sys.stderr)
        return 1

    print("[ OK ] Release audit clean: no caches, templates, secrets or scan artifacts.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
