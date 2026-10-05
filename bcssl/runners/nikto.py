"""Nikto integration: local web server configuration and security assessment.

Only ``localhost:3001`` is ever targeted. The default tuning string selects
informational, configuration, information-disclosure, server-information and
software-identification plugin groups. The plugin groups that perform uploads,
injection, remote file retrieval, denial of service, command execution, SQL
injection, authentication bypass or remote source inclusion are deliberately
left out of the default and are listed here so an instructor can see exactly
what is excluded.

Nikto reports its version on stderr on some builds, and writes a JSON stream
when ``-Format json`` is used. Both are captured.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar

from ..executor import CommandSpec, ExecutionResult
from ..parsers import nikto as nikto_parser
from ..parsers.base import ParseResult
from ..runner import BaseRunner
from ..target import TargetValidation

#: Plugin groups intentionally excluded from the lab's default tuning.
EXCLUDED_PLUGIN_GROUPS: dict[str, str] = {
    "0": "file upload",
    "4": "injection",
    "5": "remote file retrieval",
    "6": "denial of service",
    "8": "command execution",
    "9": "SQL injection",
    "a": "authentication bypass",
    "c": "remote source inclusion",
}

_TUNING = re.compile(r"^[0-9a-z]+$")


class NiktoRunner(BaseRunner):
    name: ClassVar[str] = "nikto"
    purpose: ClassVar[str] = "Local web server configuration and security assessment"
    report_filename: ClassVar[str] = "nikto-report.json"
    requires_reachable_target: ClassVar[bool] = True

    def tuning(self, options: dict[str, Any]) -> str:
        tuning = str(options.get("tuning") or self.settings.get("tuning") or "1237bd")
        tuning = tuning.strip().lower()
        if not _TUNING.match(tuning):
            raise ValueError(
                f"invalid nikto tuning '{tuning}'; use nikto plugin-group "
                "characters only (digits and letters)"
            )
        included = set(tuning)
        # Remove any excluded group that a caller may have passed explicitly.
        forbidden = included & set(EXCLUDED_PLUGIN_GROUPS)
        if forbidden:
            names = ", ".join(
                f"{key} ({EXCLUDED_PLUGIN_GROUPS[key]})" for key in sorted(forbidden)
            )
            raise ValueError(
                f"refusing nikto tuning '{tuning}': this lab does not run "
                f"destructive or active-exploitation plugin groups - {names}"
            )
        return tuning

    def build_command(
        self,
        validation: TargetValidation,
        options: dict[str, Any],
    ) -> CommandSpec:
        settings = dict(self.settings)
        timeout = self.timeout(options)
        timeout_secs = int(settings.get("request_timeout_seconds", 10))
        max_time = max(1, int(timeout // 60))

        argv: list[str] = [
            str(settings.get("executable") or "nikto"),
            "-h",
            validation.url,
            "-Tuning",
            self.tuning(options),
            "-Format",
            "json",
            "-output",
            self.report_filename,
            "-timeout",
            str(timeout_secs),
            "-maxtime",
            f"{max_time}m",
            "-nointeractive",
        ]

        return CommandSpec(argv=argv, timeout=timeout, cwd=str(self.context.run_dir))

    def parse_output(
        self,
        execution: ExecutionResult,
        validation: TargetValidation,
    ) -> ParseResult:
        payload = self.read_report()
        result = nikto_parser.parse(payload, target=validation.url)
        version = nikto_parser.version_from_report(payload)
        if version:
            result.notes.append(f"Nikto version: {version}")
        if not payload.strip():
            result.errors.append(
                "Nikto wrote no JSON report. Check stdout/stderr in "
                "reports/raw/nikto/ for the reason."
            )
        return result
