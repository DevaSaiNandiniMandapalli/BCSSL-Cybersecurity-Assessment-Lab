"""Custom scanner integration: the external Project #08 web security scanner.

This runner treats Project #08 as an external application-security component.
It is **never** modified, copied or reimplemented here: the runner launches it
as a subprocess with its own interpreter, from its own project directory, and
parses the HTML report it writes.

Contract with Project #08 (observed from its CLI, not changed by this lab):

* ``--url``      required, target to scan
* ``--modules``  comma-separated subset of ``headers``, ``paths``, ``injection``
* ``--html-output PATH``  writes a self-contained HTML report
* ``--quiet``    print only the summary
* ``--no-color`` disable ANSI codes so captured output stays clean
* exit codes: ``0`` completed, ``1`` usage error, ``2`` completed with errors
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any, ClassVar

from ..executor import CommandSpec, ExecutionResult
from ..parsers import custom as custom_parser
from ..parsers.base import ParseResult
from ..runner import BaseRunner
from ..target import TargetValidation

VALID_MODULES = ("headers", "paths", "injection")


class CustomScannerRunner(BaseRunner):
    name: ClassVar[str] = "custom-scanner"
    purpose: ClassVar[str] = "Custom application-security scanner (external Project #08)"
    report_filename: ClassVar[str] = "custom-scanner-report.html"
    requires_reachable_target: ClassVar[bool] = True

    # -- location of the external project --------------------------------
    def project_root(self) -> Path:
        return Path(str(self.settings.get("project_root") or "")).expanduser()

    def interpreter(self) -> str:
        """Resolve the interpreter used to run Project #08.

        Prefers the project's own virtual environment so its dependencies are
        used, and never installs anything.
        """
        configured_raw = str(self.settings.get("python") or "auto")
        # Compare case-insensitively, but keep the configured value verbatim:
        # lower-casing a filesystem path would break on case-sensitive systems.
        if configured_raw.strip().lower() != "auto":
            candidate = Path(configured_raw.strip()).expanduser()
            if candidate.is_file():
                return str(candidate)
            raise ValueError(
                f"configured python interpreter '{configured_raw}' does not exist"
            )

        root = self.project_root()
        for candidate in (
            root / ".venv" / "Scripts" / "python.exe",
            root / ".venv" / "bin" / "python",
        ):
            if candidate.is_file():
                return str(candidate)
        system = shutil.which("python") or shutil.which("python3")
        if system:
            return system
        raise ValueError(
            "no Python interpreter found to run the custom scanner; expected "
            f"{root / '.venv'} or python on PATH"
        )

    def modules(self, options: dict[str, Any]) -> list[str]:
        raw = options.get("modules") or self.settings.get("modules") or list(VALID_MODULES)
        if isinstance(raw, str):
            raw = [part.strip() for part in raw.split(",") if part.strip()]
        values = [str(item).strip().lower() for item in raw if str(item).strip()]
        invalid = [value for value in values if value not in VALID_MODULES]
        if invalid:
            raise ValueError(
                f"unknown custom scanner module(s): {', '.join(invalid)}. "
                f"Available: {', '.join(VALID_MODULES)}"
            )
        if not values:
            raise ValueError("at least one module must be selected")
        return values

    def build_command(
        self,
        validation: TargetValidation,
        options: dict[str, Any],
    ) -> CommandSpec:
        root = self.project_root()
        entry = root / "scanner.py"
        if not entry.is_file():
            raise ValueError(
                f"custom scanner project not found at {root}; set "
                "tools.custom-scanner.project_root in config/lab-config.json"
            )

        report_path = (self.context.run_dir / self.report_filename).resolve()
        argv: list[str] = [
            self.interpreter(),
            "-m",
            "scanner",
            "--url",
            validation.url,
            "--modules",
            ",".join(self.modules(options)),
            "--no-color",
            "--quiet",
            "--html-output",
            str(report_path),
        ]

        timeout_value = options.get("timeout", self.settings.get("request_timeout_seconds"))
        if timeout_value:
            argv.extend(["--timeout", str(timeout_value)])

        return CommandSpec(
            argv=argv,
            timeout=self.timeout(options),
            # Project #08 must run from its own root so `scanner` is importable.
            cwd=str(root),
        )

    def parse_output(
        self,
        execution: ExecutionResult,
        validation: TargetValidation,
    ) -> ParseResult:
        html = self.read_report()
        if not html.strip():
            result = ParseResult()
            result.errors.append(
                "The custom scanner produced no HTML report. Check "
                "stdout/stderr in reports/raw/custom-scanner/ for the reason."
            )
            if execution.exit_code == 1:
                result.errors.append(
                    "Exit code 1 indicates a usage error in the scanner arguments."
                )
            elif execution.exit_code == 2:
                result.warnings.append(
                    "Exit code 2 indicates the scanner completed with operational "
                    "errors (coverage gaps, not security findings)."
                )
            return result

        parsed = custom_parser.parse(html, target=validation.url)
        parsed.artifacts.append(self.report_filename)
        if execution.exit_code == 2:
            parsed.warnings.append(
                "The custom scanner reported operational errors during the scan; "
                "these are coverage gaps rather than security findings."
            )
        elif execution.exit_code not in (0, None):
            parsed.warnings.append(
                f"The custom scanner exited with code {execution.exit_code}."
            )
        return parsed
