"""Nuclei integration: controlled template-based vulnerability assessment.

Three safety properties are enforced here rather than merely documented:

1. The target is the authorized loopback URL and nothing else (enforced by the
   base runner's target validation).
2. Destructive template families are excluded. The exclusion list is merged
   from configuration and the tool's own ``-etags`` flag is always applied, so a
   configuration edit that removes them cannot make the runner run DoS or
   intrusive templates silently.
3. Template updates are not performed automatically, so a lab run does not
   reach out to the internet.
"""

from __future__ import annotations

from typing import Any, ClassVar

from ..executor import CommandSpec, ExecutionResult
from ..parsers import nuclei as nuclei_parser
from ..parsers.base import ParseResult
from ..runner import BaseRunner
from ..target import TargetValidation

VALID_SEVERITIES = ("info", "low", "medium", "high", "critical")

#: Always excluded, regardless of configuration.
MANDATORY_EXCLUDE_TAGS = (
    "dos",
    "fuzz",
    "intrusion",
    "headless",
    "bruteforce",
    "brutespray",
    "code",
    "workflow",
    "headless",
)


class NucleiRunner(BaseRunner):
    name: ClassVar[str] = "nuclei"
    purpose: ClassVar[str] = "Controlled template-based vulnerability assessment"
    report_filename: ClassVar[str] = "nuclei-report.jsonl"
    requires_reachable_target: ClassVar[bool] = True

    def severities(self, options: dict[str, Any]) -> list[str]:
        raw = options.get("severities") or self.settings.get("severities") or list(
            VALID_SEVERITIES
        )
        if isinstance(raw, str):
            raw = [part.strip() for part in raw.split(",") if part.strip()]
        values = [str(item).strip().lower() for item in raw if str(item).strip()]
        invalid = [value for value in values if value not in VALID_SEVERITIES]
        if invalid:
            raise ValueError(
                f"invalid nuclei severity/severities: {', '.join(invalid)}. "
                f"Valid values: {', '.join(VALID_SEVERITIES)}"
            )
        if not values:
            raise ValueError("at least one severity must be selected")
        return values

    def exclude_tags(self, options: dict[str, Any]) -> list[str]:
        configured = options.get("exclude_tags") or self.settings.get("exclude_tags") or []
        if isinstance(configured, str):
            configured = [part.strip() for part in configured.split(",") if part.strip()]
        merged = {str(tag).strip().lower() for tag in configured if str(tag).strip()}
        merged.update(MANDATORY_EXCLUDE_TAGS)
        return sorted(merged)

    def build_command(
        self,
        validation: TargetValidation,
        options: dict[str, Any],
    ) -> CommandSpec:
        settings = dict(self.settings)
        timeout = self.timeout(options)

        argv: list[str] = [
            str(settings.get("executable") or "nuclei"),
            "-u",
            validation.url,
            "-severity",
            ",".join(self.severities(options)),
            "-etags",
            ",".join(self.exclude_tags(options)),
            "-rate-limit",
            str(settings.get("rate_limit", 5)),
            "-c",
            str(settings.get("concurrency", 5)),
            "-timeout",
            str(settings.get("request_timeout_seconds", 10)),
            # Never phone home during a lab run.
            "-duc",
            "-silent",
        ]

        # Nuclei 3.x requires -json for machine output; 2.x derives it from the
        # .jsonl output extension. Both are supported via configuration so the
        # lab works with whichever version is installed.
        json_flag = settings.get("json_flag")
        if json_flag:
            argv.append(str(json_flag))

        # Nuclei 3.x also refuses to run without an explicit "no update" flag;
        # 2.x has none. Left empty unless configured.
        update_flag = settings.get("no_update_templates_flag")
        if update_flag:
            argv.append(str(update_flag))

        extra = settings.get("extra_flags") or []
        if isinstance(extra, str):
            extra = [part for part in extra.split() if part]
        argv.extend(str(item) for item in extra)

        argv.extend(["-o", self.report_filename])

        # Optional explicit template directory. Required when the image ships
        # without templates; the directory is mounted read-only from the host.
        templates_dir = settings.get("templates_dir")
        if templates_dir:
            argv.extend(["-t", str(templates_dir)])

        return CommandSpec(argv=argv, timeout=timeout, cwd=str(self.context.run_dir))

    def parse_output(
        self,
        execution: ExecutionResult,
        validation: TargetValidation,
    ) -> ParseResult:
        payload = self.read_report()
        if not payload.strip():
            # Fall back to stdout in case -o was redirected elsewhere.
            payload = execution.stdout
            if not payload.strip():
                result = ParseResult()
                result.errors.append(
                    "Nuclei produced no output. Confirm templates are installed "
                    "and that the severity filter is not excluding everything."
                )
                return result
        return nuclei_parser.parse(payload, target=validation.url)
