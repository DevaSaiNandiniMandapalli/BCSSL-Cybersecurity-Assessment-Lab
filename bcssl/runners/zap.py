"""OWASP ZAP integration: authorized application assessment of the local target.

ZAP's baseline scan is used by default. It runs ZAP's passive scan rules plus a
small, curated set of low-impact active rules - the safe mode for an assessment
lab. ``passive`` mode additionally switches the spider to passive-only so no
active rules run at all.

Only flags that are stable across ZAP releases are used: ``-t`` (target), ``-m``
(maximum minutes), ``-r``/``-J`` (HTML/JSON reports) and ``-config`` for
behaviour changes. ZAP is not currently installed on the lab machine, so this
command has not been executed end-to-end here; it is verified structurally by
the test-suite and must be confirmed on the first machine where ZAP is present.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, ClassVar

from ..executor import CommandSpec, ExecutionResult
from ..parsers import zap as zap_parser
from ..parsers import zap_html as zap_html_parser
from ..parsers.base import ParseResult
from ..runner import BaseRunner
from ..target import TargetValidation

VALID_MODES = ("baseline", "passive")


class ZapRunner(BaseRunner):
    name: ClassVar[str] = "zap"
    purpose: ClassVar[str] = "Authorized web application assessment (passive + controlled active)"
    report_filename: ClassVar[str] = "zap-report.json"
    requires_reachable_target: ClassVar[bool] = True
    #: Verified against zap-baseline.py: 0 means no alerts, 2 means the scan
    #: completed and alerts were raised, 3 means the script itself failed.
    success_exit_codes: ClassVar[tuple[int, ...]] = (0, 2)

    def mode(self, options: dict[str, Any]) -> str:
        mode = str(options.get("mode") or self.settings.get("mode") or "baseline").lower()
        if mode not in VALID_MODES:
            raise ValueError(
                f"unknown ZAP mode '{mode}'. This lab supports: "
                f"{', '.join(VALID_MODES)}"
            )
        return mode

    def build_command(
        self,
        validation: TargetValidation,
        options: dict[str, Any],
    ) -> CommandSpec:
        settings = dict(self.settings)
        mode = self.mode(options)
        timeout = self.timeout(options)
        minutes = max(1, int(timeout // 60))

        executable = str(settings.get("executable") or "zap-baseline.py")
        argv = [
            executable,
            "-t",
            validation.url,
            "-m",
            str(minutes),
            "-r",
            "zap-report.html",
            "-J",
            self.report_filename,
        ]

        env: dict[str, str] = {}
        daemon_port = settings.get("daemon_port")
        if daemon_port:
            env["ZAP_PORT"] = str(daemon_port)

        core = self._core_config(mode, settings, options)
        if core:
            # Verified against ZAP stable: zap-baseline.py passes core settings
            # through its own -z option as a single quoted argument. Its -c is a
            # logging config file and zap.sh's -cmd expects an automation plan
            # file, so neither of those can carry these settings.
            argv.extend(["-z", " ".join(core)])

        return CommandSpec(
            argv=argv,
            timeout=timeout,
            cwd=str(self.context.run_dir),
            env_overrides=env,
        )

    def _core_config(
        self, mode: str, settings: dict[str, Any], options: dict[str, Any]
    ) -> list[str]:
        """Build the ``-config key=value`` pairs bounding this lab's scan."""
        pairs: list[tuple[str, str]] = [
            (
                "connection.timeoutInSecs",
                str(int(settings.get("request_timeout_seconds", 20))),
            ),
            ("spider.maxDepth", str(int(settings.get("spider_max_depth", 5)))),
            ("spider.maxDuration", str(int(settings.get("spider_max_seconds", 300)))),
            ("scanner.threadPerHost", str(int(settings.get("threads_per_host", 2)))),
        ]
        if mode == "passive":
            pairs.append(("spider.active", "false"))

        threshold = options.get("alert_threshold", settings.get("alert_threshold"))
        if threshold is not None:
            try:
                value = int(threshold)
            except (TypeError, ValueError):
                raise ValueError(
                    f"alert_threshold must be an integer 0-2, got {threshold!r}"
                ) from None
            if value not in (0, 1, 2):
                raise ValueError(
                    "alert_threshold must be 0 (Low), 1 (Medium) or 2 (High)"
                )
            pairs.append(("scanner.alertThreshold", str(value)))

        argv: list[str] = []
        for key, value in pairs:
            argv.extend(["-config", f"{key}={value}"])
        return argv

    def parse_output(
        self,
        execution: ExecutionResult,
        validation: TargetValidation,
    ) -> ParseResult:
        payload = self.read_report()
        result = zap_parser.parse(payload, target=validation.url)

        version = zap_parser.version_from_report(payload)
        if version:
            result.notes.append(f"ZAP version reported in the report: {version}")

        # Current ZAP releases omit the classic 'alerts' array from the JSON
        # report, but write the alerts into the HTML report. Falling back keeps
        # a successful scan from being reported as zero findings.
        if not result.findings:
            html = self.context.run_dir / "zap-report.html"
            if html.is_file():
                html_result = zap_html_parser.parse(
                    html.read_text(encoding="utf-8", errors="replace"),
                    target=validation.url,
                )
                if html_result.findings:
                    html_result.notes.extend(result.notes)
                    result = html_result
                    result.notes.append(
                        "Alerts were read from the ZAP HTML report: this ZAP "
                        "release does not include the classic alerts array in "
                        "its JSON report."
                    )

        if not payload.strip():
            result.errors.append(
                "ZAP wrote no JSON report. The scan may not have completed; "
                "check stdout/stderr in reports/raw/zap/ for the reason."
            )
        return result

    def tool_version(self) -> str:
        return super().tool_version()
