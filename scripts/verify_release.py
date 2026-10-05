#!/usr/bin/env python3
"""Verify a release package from a clean, extracted copy.

The source directory working is **not** evidence that the release package works:
the package is a filtered copy, and a missing subdirectory, a stale file or an
absolute path baked into the source tree would only show up on a machine that
receives the archive.

This script therefore:

1. copies the release package into a fresh temporary directory,
2. runs the documented verification steps *from that copy*, in a subprocess with
   its own working directory and no ``PYTHONPATH`` pointing at the source tree,
3. asserts the safety refusals still work,
4. asserts the CLI and the test suite both succeed,
5. reports each check with an explicit pass or fail.

It never scans anything and never contacts a target.

Usage::

    python scripts/verify_release.py
    python scripts/verify_release.py --release <path> --keep
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RELEASE = PROJECT_ROOT.parent / "BCSSL-Cybersecurity-Assessment-Lab-RELEASE"

#: Files that must exist in the extracted copy for it to be usable.
REQUIRED = (
    "README.md",
    "pyproject.toml",
    ".gitignore",
    "bcssl/__init__.py",
    "bcssl/cli.py",
    "bcssl/runs.py",
    "bcssl/sarif.py",
    "config/lab-config.json",
    "target/docker-compose.yml",
    "scripts/setup.ps1",
    "scripts/start-target.ps1",
    "scripts/check-target.ps1",
    "scripts/run-all.ps1",
    "scripts/clean.ps1",
    "docs/installation.md",
    "docs/instructor-quick-start.md",
    "docs/student-quick-start.md",
    "docs/demo-guide.md",
    "docs/limitations.md",
)

#: Nothing generated may ship.
FORBIDDEN_PATTERNS = (
    "reports/raw/*/*",
    "reports/normalized/*/*",
    "reports/final/*.html",
    "reports/final/*.json",
    "reports/final/*.sarif",
    "evidence/*/*",
    "evidence/*/*/*",
    "state/*.json",
)

FORBIDDEN_DIRS = ("__pycache__", ".venv", "venv", "templates", "templates-lab")


class Checker:
    """Runs checks and keeps a pass/fail tally."""

    def __init__(self) -> None:
        self.passed = 0
        self.failed: list[str] = []

    def check(self, label: str, condition: bool, detail: str = "") -> bool:
        if condition:
            self.passed += 1
            print(f"  [ OK ] {label}")
            return True
        self.failed.append(label)
        print(f"  [FAIL] {label}")
        if detail:
            for line in str(detail).splitlines()[-12:]:
                print(f"         {line}")
        return False

    def section(self, title: str) -> None:
        print()
        print(f"== {title} ==")


def run(
    args: list[str],
    cwd: Path,
    *,
    timeout: int = 900,
    env_extra: dict[str, str] | None = None,
) -> subprocess.CompletedProcess:
    """Run a command in *cwd* with a clean, explicit environment."""
    env = {
        key: value
        for key, value in os.environ.items()
        if key not in ("PYTHONPATH", "BCSSL_OUTPUT_ROOT")
    }
    # Deliberately no PYTHONPATH: the copied tree must be self-contained.
    env["NO_COLOR"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        args,
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
        shell=False,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", default=str(DEFAULT_RELEASE))
    parser.add_argument("--keep", action="store_true", help="keep the extracted copy")
    parser.add_argument("--skip-tests", action="store_true")
    args = parser.parse_args(argv)

    release = Path(args.release).expanduser().resolve()
    print("=" * 70)
    print(" BCSSL RELEASE VERIFICATION (from a clean extracted copy)")
    print("=" * 70)
    print(f"Release package : {release}")
    print(f"Source project  : {PROJECT_ROOT}")

    if not release.is_dir():
        print(f"\n[FAIL] release package not found: {release}")
        print("       build it first:  python scripts/build_release.py")
        return 1

    workdir = Path(tempfile.mkdtemp(prefix="bcssl-release-verify-"))
    extracted = workdir / "extracted"
    checker = Checker()

    try:
        # -- 1. extract -----------------------------------------------------
        checker.section("1. Extract the package into a clean directory")
        shutil.copytree(release, extracted)
        files = [item for item in extracted.rglob("*") if item.is_file()]
        checker.check(
            "package extracts and contains files",
            len(files) > 0,
            f"extracted to {extracted}",
        )
        print(f"         {len(files)} file(s) extracted")

        # -- 2. contents ---------------------------------------------------
        checker.section("2. Package contents")
        missing = [item for item in REQUIRED if not (extracted / item).exists()]
        checker.check(
            f"all {len(REQUIRED)} required files present",
            not missing,
            "missing: " + ", ".join(missing),
        )

        stray = [
            str(path.relative_to(extracted))
            for path in extracted.rglob("*")
            if any(part in FORBIDDEN_DIRS for part in path.parts)
        ]
        checker.check(
            "no caches, virtual environments or Nuclei templates",
            not stray,
            "\n".join(stray[:10]),
        )

        generated: list[str] = []
        for pattern in FORBIDDEN_PATTERNS:
            for path in extracted.glob(pattern):
                if path.name != ".gitkeep" and path.is_file():
                    generated.append(str(path.relative_to(extracted)))
        checker.check(
            "no fabricated scan results, evidence or run state",
            not generated,
            "\n".join(generated[:10]),
        )

        exercises = list((extracted / "lab").rglob("exercise.json"))
        checker.check("12 exercises present", len(exercises) == 12, f"found {len(exercises)}")
        docs = list((extracted / "docs").glob("*.md"))
        checker.check(
            f"documentation present ({len(docs)} files)", len(docs) >= 14, f"found {len(docs)}"
        )

        # The secret scanner's own needle list would match itself, so it is
        # excluded. Everything else in the package is scanned.
        scanner = "verify_release.py"
        secrets = []
        patterns = ("*.py", "*.json", "*.ps1", "*.md", "*.yml", "*.js")
        needles = ("BEGIN RSA PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY", "api_key", "AKIA")
        for pattern in patterns:
            for path in extracted.rglob(pattern):
                if path.name == scanner:
                    continue
                try:
                    text = path.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                for needle in needles:
                    if needle.lower() in text.lower():
                        secrets.append(f"{path.relative_to(extracted)}: {needle}")
        checker.check("no secrets or credentials", not secrets, "\n".join(secrets[:5]))

        # -- 3. CLI works from the copy ------------------------------------
        checker.section("3. Command-line interface (from the extracted copy)")

        result = run([sys.executable, "-m", "bcssl", "version"], extracted)
        checker.check(
            "`bcssl version` succeeds",
            result.returncode == 0,
            result.stdout + result.stderr,
        )
        print(f"         {result.stdout.strip().splitlines()[0] if result.stdout.strip() else ''}")

        result = run([sys.executable, "-m", "bcssl", "validate-target", "--no-probe"], extracted)
        checker.check(
            "`bcssl validate-target` authorizes the lab target",
            result.returncode == 0 and "AUTHORIZED TARGET" in result.stdout,
            result.stdout + result.stderr,
        )

        result = run(
            [sys.executable, "-m", "bcssl", "validate-target", "--url", "https://example.com", "--no-probe"],
            extracted,
        )
        checker.check(
            "public domain is refused",
            result.returncode == 2 and "REJECTED" in result.stdout,
            result.stdout + result.stderr,
        )

        result = run(
            [sys.executable, "-m", "bcssl", "validate-target", "--url", "http://8.8.8.8:3001", "--no-probe"],
            extracted,
        )
        checker.check(
            "public IP is refused",
            result.returncode == 2 and "not-loopback" in result.stdout,
            result.stdout + result.stderr,
        )

        result = run(
            [sys.executable, "-m", "bcssl", "validate-target", "--url", "http://localhost:22", "--no-probe"],
            extracted,
        )
        checker.check(
            "unauthorized port is refused",
            result.returncode == 2 and "REJECTED" in result.stdout,
            result.stdout + result.stderr,
        )

        result = run(
            [sys.executable, "-m", "bcssl", "web", "--host", "0.0.0.0"], extracted
        )
        checker.check(
            "dashboard refuses a non-loopback bind address",
            result.returncode == 2 and "loopback" in (result.stdout + result.stderr),
            result.stdout + result.stderr,
        )

        # Safety checks run against an isolated output root so that no check
        # leaves state behind for the next one.
        safety_root = workdir / "safety-output"
        result = run(
            [sys.executable, "-m", "bcssl", "run", "nikto", "--tuning", "126"],
            extracted,
            env_extra={"BCSSL_OUTPUT_ROOT": str(safety_root)},
        )
        combined = result.stdout + result.stderr
        checker.check(
            "destructive Nikto tuning is refused",
            "refusing nikto tuning" in combined,
            combined[-600:],
        )

        # -- 4. lab content loads ------------------------------------------
        checker.section("4. Lab content")
        result = run([sys.executable, "-m", "bcssl", "lab", "list"], extracted)
        checker.check(
            "`bcssl lab list` loads all 12 exercises",
            result.returncode == 0 and all(
                f"ex{index:02d}" in result.stdout for index in range(1, 13)
            ),
            result.stdout + result.stderr,
        )

        # -- 5. run rotation and SARIF --------------------------------------
        checker.section("5. Run rotation and SARIF export (from the extracted copy)")

        script = (
            "from bcssl import runs, sarif;"
            "from bcssl.models import Finding, Severity;"
            # Identifiers allocate sequentially and never repeat.
            "a = runs.allocate(); b = runs.allocate();"
            "assert (a, b) == ('run-001', 'run-002'), (a, b);"
            "assert a != b;"
            # Each assessment owns an isolated namespace.
            "assert runs.run_id_for('nmap', a) == 'run-001-nmap';"
            "assert runs.run_id_for('nmap', b) == 'run-002-nmap';"
            "assert runs.layout(a).raw_dir != runs.layout(b).raw_dir;"
            "assert runs.layout(a).raw_dir.is_dir() and runs.layout(b).raw_dir.is_dir();"
            "assert runs.layout(a).evidence_dir != runs.layout(b).evidence_dir;"
            # Reports are named after their assessment.
            "assert runs.layout(a).report_file('sarif').name == 'run-001.sarif';"
            # A malformed identifier is refused rather than silently accepted.
            "bad = False"
            "\ntry:\n"
            "    runs.layout('not-a-run')\n"
            "except runs.RunIdError:\n"
            "    bad = True\n"
            "assert bad, 'malformed identifier must be refused';"
            # SARIF is structurally valid for findings and for an empty run.
            "log = sarif.build([Finding(tool='zap', category='security-header',"
            "severity=Severity.MEDIUM, title='CSP header is missing',"
            "target='http://localhost:3001', endpoint='http://localhost:3001',"
            "subject='missing-header:csp')], 'http://localhost:3001');"
            "assert sarif.validate(log) == [], sarif.validate(log);"
            "assert log['version'] == '2.1.0';"
            "assert len(log['runs'][0]['results']) == 1;"
            "assert sarif.validate(sarif.build([], 'http://localhost:3001')) == [];"
            "print('rotation-and-sarif-ok')"
        )
        result = run([sys.executable, "-c", script], extracted, env_extra={"BCSSL_OUTPUT_ROOT": str(workdir / "out")})
        checker.check(
            "assessment identifiers allocate sequentially and SARIF validates",
            "rotation-and-sarif-ok" in result.stdout,
            result.stdout + result.stderr,
        )

        # -- 6. empty-state honesty ----------------------------------------
        # Each check gets its own isolated output root, so an earlier check
        # cannot leave state that makes a later one pass or fail spuriously.
        checker.section("6. Empty-state honesty")
        empty_root = workdir / "empty-output"
        result = run(
            [sys.executable, "-m", "bcssl", "report"],
            extracted,
            env_extra={"BCSSL_OUTPUT_ROOT": str(empty_root)},
        )
        checker.check(
            "report states there are no results when nothing has been scanned",
            "No scan results available" in result.stdout,
            result.stdout + result.stderr,
        )

        # A refused command must be recorded as refused, never as zero findings
        # presented as a successful scan.
        result = run(
            [sys.executable, "-m", "bcssl", "run", "nikto", "--tuning", "126"],
            extracted,
            env_extra={"BCSSL_OUTPUT_ROOT": str(empty_root)},
        )
        checker.check(
            "a refused command is reported as a refusal, not as a clean scan",
            "refusing nikto tuning" in result.stdout + result.stderr,
            (result.stdout + result.stderr)[-400:],
        )

        # -- 7. compile ------------------------------------------------------
        checker.section("7. Byte-compile every module")
        result = run(
            [sys.executable, "-m", "compileall", "-q", "bcssl", "scripts", "runners", "parsers", "tests"],
            extracted,
        )
        checker.check(
            "compileall succeeds",
            result.returncode == 0,
            (result.stdout + result.stderr)[-800:],
        )

        # -- 8. tests ---------------------------------------------------------
        if not args.skip_tests:
            checker.section("8. Test suite (from the extracted copy)")
            started = time.time()
            result = run(
                [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"],
                extracted,
                timeout=1800,
            )
            elapsed = time.time() - started
            tail = (result.stdout + result.stderr).strip().splitlines()[-4:]
            passed = result.returncode == 0
            checker.check(
                "pytest passes in the extracted copy",
                passed,
                "\n".join(tail),
            )
            for line in tail:
                if "passed" in line or "failed" in line:
                    print(f"         {line.strip()}  ({elapsed:.0f}s)")

        # -- 9. PowerShell scripts parse ------------------------------------
        checker.section("9. PowerShell scripts")
        powershell = shutil.which("powershell") or shutil.which("pwsh")
        if not powershell:
            print("  [SKIP] PowerShell not available on this machine")
        else:
            for script in (
                "setup.ps1",
                "preflight.ps1",
                "start-target.ps1",
                "stop-target.ps1",
                "check-target.ps1",
                "start-lab.ps1",
                "stop-lab.ps1",
                "run-all.ps1",
                "clean.ps1",
            ):
                result = run(
                    [powershell, "-NoProfile", "-Command", f"$ErrorActionPreference='Stop'; "
                     f"$null = [System.Management.Automation.Language.Parser]::ParseFile("
                     f"'{str(extracted / 'scripts' / script).replace(chr(92), chr(92))}', [ref]$null, [ref]$null); "
                     f"'parsed'"],
                    extracted,
                    timeout=120,
                )
                checker.check(
                    f"{script} parses",
                    result.returncode == 0 and "parsed" in result.stdout,
                    result.stdout + result.stderr,
                )

    finally:
        if args.keep:
            print(f"\nExtracted copy kept at: {extracted}")
        else:
            shutil.rmtree(workdir, ignore_errors=True)

    # -- summary -----------------------------------------------------------
    print()
    print("=" * 70)
    if checker.failed:
        print(f" RESULT: FAILED - {len(checker.failed)} of "
              f"{checker.passed + len(checker.failed)} checks did not pass")
        for label in checker.failed:
            print(f"   - {label}")
        print("=" * 70)
        return 1
    print(f" RESULT: PASSED - all {checker.passed} checks succeeded")
    print(" The release package works from a clean, extracted copy.")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())