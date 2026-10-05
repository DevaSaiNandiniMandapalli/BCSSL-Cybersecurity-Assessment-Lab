"""Base class implementing the fixed runner contract.

Every tool integration performs the same ten steps, in this order, and records
the outcome whether or not the tool is usable:

1. Verify tool availability.
2. Verify the target is authorized.
3. Build a safe command (argument list, never a shell string).
4. Execute it.
5. Capture stdout/stderr.
6. Capture the exit code.
7. Store the raw output verbatim.
8. Parse the output.
9. Normalize the findings.
10. Generate evidence metadata.

Nothing is hidden: a missing executable yields ``TOOL NOT INSTALLED``, an
unauthorized target is refused before any command is built, a timeout is
reported as a timeout, and a non-zero exit code is surfaced as a failure.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, ClassVar

from . import paths, preflight, runs
from .config import LabConfig
from .executor import CommandSpec, ExecutionResult, run_command
from .models import EvidenceRecord, Finding, RunStatus, ToolRunResult, sha256_file, utc_now_iso
from .parsers.base import ParseResult
from .target import (
    TargetRejectedError,
    TargetValidation,
    check_reachability,
    validate_target,
)


class RunnerError(RuntimeError):
    """Raised when a runner cannot proceed (used by orchestration)."""


def slugify(value: str, limit: int = 60) -> str:
    """Filesystem-safe fragment derived from arbitrary text."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", value or "").strip("-")
    return (cleaned[:limit] or "item").lower()


def new_run_id(tool: str, assessment: str | None = None, when: datetime | None = None) -> str:
    """Per-tool run identifier scoped to an assessment.

    With *assessment* the identifier is ``{assessment}-{tool}`` (for example
    ``run-003-nmap``), which guarantees two runs of the same tool never collide
    even inside the same second. Without it the identifier falls back to a
    timestamp for backward compatibility.
    """
    if assessment:
        return runs.run_id_for(tool, assessment)
    stamp = (when or datetime.now(timezone.utc)).strftime("%Y%m%dT%H%M%SZ")
    return f"{tool}-{stamp}"


@dataclass
class RunnerContext:
    """Resolved output locations for a single run."""

    run_id: str
    run_dir: Path
    stdout_path: Path
    stderr_path: Path
    assessment: str = ""

    @classmethod
    def create(
        cls,
        tool: str,
        run_id: str | None = None,
        assessment: str | None = None,
    ) -> "RunnerContext":
        identifier = run_id or new_run_id(tool, assessment)
        resolved = assessment or runs.assessment_of(
            "-".join(identifier.split("-")[:2])
        )
        if resolved:
            # Isolated per assessment: reports/raw/run-003/run-003-nmap/
            run_dir = runs.layout(resolved).tool_raw_dir(tool)
        else:
            run_dir = paths.raw_dir() / tool / identifier
        run_dir.mkdir(parents=True, exist_ok=True)
        return cls(
            run_id=identifier,
            run_dir=run_dir,
            stdout_path=run_dir / "stdout.txt",
            stderr_path=run_dir / "stderr.txt",
            assessment=resolved or "",
        )


class BaseRunner:
    """Template for a single tool integration."""

    #: Tool identifier used across config, evidence and reports.
    name: ClassVar[str] = ""
    #: Human-facing purpose shown on the dashboard.
    purpose: ClassVar[str] = ""
    #: Filename (relative to the run directory) of the tool's native report.
    report_filename: ClassVar[str] = ""
    #: Web tools cannot produce findings against a service that is not listening.
    requires_reachable_target: ClassVar[bool] = True

    #: Exit codes that still represent a completed scan.
    #:
    #: Most tools use 0. OWASP ZAP's baseline script returns 2 when the scan
    #: completed and raised alerts, which is a *successful* scan with findings,
    #: not a failure. Treating that as an error would throw away a real scan.
    success_exit_codes: ClassVar[tuple[int, ...]] = (0,)

    def __init__(
        self,
        config: LabConfig,
        run_id: str | None = None,
        assessment: str | None = None,
    ) -> None:
        self.config = config
        self.settings = config.tool(self.name)
        self.context = RunnerContext.create(self.name, run_id, assessment)

    @property
    def assessment_id(self) -> str:
        """Assessment this run belongs to, or an empty string when unassigned."""
        return self.context.assessment

    # -- step 1 ------------------------------------------------------------
    def availability(self) -> preflight.ToolStatus:
        return preflight.detect(self.name, self.config)

    # -- step 3 ------------------------------------------------------------
    def build_command(
        self,
        validation: TargetValidation,
        options: dict[str, Any],
    ) -> CommandSpec:
        """Build the tool command. Subclasses implement this."""
        raise NotImplementedError

    def timeout(self, options: dict[str, Any]) -> float:
        try:
            return float(options.get("timeout") or self.settings.get("timeout_seconds", 300))
        except (TypeError, ValueError):
            return 300.0

    def wrap_with_docker(self, spec: CommandSpec) -> CommandSpec:
        """Prefix *spec* with a ``docker run`` invocation.

        The run directory is mounted at a fixed path and used as the working
        directory, so tool-relative output filenames work identically whether the
        tool runs locally or inside a container.

        If the image already declares the tool as its ENTRYPOINT, the leading
        executable name is dropped: otherwise the tool would receive it as a
        positional argument and could treat it as an extra scan target.
        """
        image = str(self.settings.get("docker_image") or "").strip()
        if not image:
            raise RunnerError(f"no docker_image configured for tool '{self.name}'")

        tool_argv = list(spec.argv)
        entrypoint = self.availability().docker_entrypoint
        if entrypoint and tool_argv:
            import os as _os

            def _stem(path: str) -> str:
                """Basename without its interpreter-style extension.

                Lets ``nikto`` match an entrypoint of ``nikto.pl`` and
                ``nuclei`` match ``nuclei``.
                """
                base = _os.path.basename(path)
                return _os.path.splitext(base)[0] or base

            if _stem(entrypoint[-1]) and _stem(entrypoint[-1]) == _stem(tool_argv[0]):
                tool_argv = tool_argv[1:]

        # Some tool images insist on their own work directory (ZAP requires
        # /zap/wrk to be mounted), so the mount point is configurable.
        container_dir = str(self.settings.get("docker_mount_path") or "/bcssl-out")

        argv: list[str] = ["docker", "run", "--rm", "--network", "host"]
        argv.extend(["-v", f"{self.context.run_dir}:{container_dir}"])

        extra = self.settings.get("docker_extra_mounts") or []
        if isinstance(extra, str):
            extra = [part.strip() for part in extra.split(",") if part.strip()]
        for mount in extra:
            source, _, destination = str(mount).partition(":")
            # Placeholders keep the committed configuration machine-independent.
            source = source.replace("{project_root}", str(paths.project_root()))
            source = source.replace("{output_root}", str(paths.output_root()))
            source_path = Path(source).expanduser()
            if not source_path.exists():
                # A missing auxiliary mount must not silently alter the scan; it
                # is reported instead.
                raise RunnerError(
                    f"configured docker_extra_mounts entry '{mount}' does not exist "
                    f"on this machine: {source_path}"
                )
            argv.extend(["-v", f"{source_path}:{destination}"])

        argv.extend(["-w", container_dir, image, *tool_argv])

        env_overrides = dict(spec.env_overrides)
        env = self.settings.get("docker_env")
        if isinstance(env, dict):
            for key, value in env.items():
                argv.extend(["-e", f"{key}={value}"])
        for key, value in env_overrides.items():
            argv.extend(["-e", f"{key}={value}"])

        return CommandSpec(
            argv=argv,
            timeout=spec.timeout,
            cwd=str(self.context.run_dir),
            env_overrides=env_overrides,
        )

    # -- step 8 ------------------------------------------------------------
    def parse_output(
        self,
        execution: ExecutionResult,
        validation: TargetValidation,
    ) -> ParseResult:
        """Parse captured output. Subclasses implement this."""
        raise NotImplementedError

    def tool_version(self) -> str:
        return self.availability().version

    # -- orchestration -----------------------------------------------------
    def run(
        self,
        url: str | None = None,
        *,
        options: dict[str, Any] | None = None,
        skip_reachability: bool = False,
    ) -> ToolRunResult:
        """Execute the full contract and return an honest result object."""
        options = dict(options or {})
        target_url = url or self.config.authorized_url
        started = utc_now_iso()
        started_dt = datetime.now(timezone.utc)

        result = ToolRunResult(
            tool=self.name,
            status=RunStatus.OK,
            target=target_url,
            started_at=started,
            run_id=self.context.run_id,
            assessment=self.context.assessment,
        )

        # 1 - tool availability
        status = self.availability()
        result.tool_available = status.available
        result.tool_version = status.version
        result.install_hint = status.install_hint
        if not status.available:
            result.status = (
                RunStatus.DISABLED
                if "DISABLED" in status.message
                else RunStatus.TOOL_NOT_INSTALLED
            )
            result.errors.append(status.message)
            result.finished_at = utc_now_iso()
            result.duration_seconds = (
                datetime.now(timezone.utc) - started_dt
            ).total_seconds()
            return result
        if status.transport == preflight.TRANSPORT_DOCKER:
            result.notes.append(
                f"Tool executed through Docker image "
                f"{self.settings.get('docker_image')} (local executable absent)."
            )

        # 2 - target authorization
        validation = validate_target(target_url, self.config)
        result.target = validation.url or target_url
        if not validation.ok:
            result.status = RunStatus.TARGET_REJECTED
            result.errors.append(f"TARGET REJECTED - NOT AUTHORIZED: {validation.reason}")
            result.finished_at = utc_now_iso()
            result.duration_seconds = (
                datetime.now(timezone.utc) - started_dt
            ).total_seconds()
            return result

        # Optional reachability gate for web tools.
        if self.requires_reachable_target and not skip_reachability:
            probe = check_reachability(
                validation, timeout=float(self.config.http.get("timeout_seconds", 15))
            )
            result.target_reachable = probe.reachable
            if not probe.reachable:
                result.status = RunStatus.TARGET_UNREACHABLE
                result.errors.append(
                    f"TARGET UNREACHABLE: no HTTP response from {validation.url} "
                    f"({probe.error}). Start the training target before scanning."
                )
                result.finished_at = utc_now_iso()
                result.duration_seconds = (
                    datetime.now(timezone.utc) - started_dt
                ).total_seconds()
                return result
            result.notes.append(
                f"Target reachable (HTTP {probe.status_code}) before the scan started."
            )

        # 3 - command construction
        try:
            spec = self.build_command(validation, options)
            if status.transport == preflight.TRANSPORT_DOCKER:
                spec = self.wrap_with_docker(spec)
        except Exception as exc:  # noqa: BLE001 - surfaced, never hidden
            result.status = RunStatus.FAILED
            result.errors.append(f"Could not build a safe command: {exc}")
            result.finished_at = utc_now_iso()
            return result

        result.command = list(spec.argv)
        result.notes.append(f"Command: {spec.display()}")

        # 4-6 - execute and capture
        execution = run_command(spec)

        # 7 - store raw output verbatim
        result.stdout = execution.stdout
        result.stderr = execution.stderr
        result.exit_code = execution.exit_code
        result.duration_seconds = execution.duration_seconds
        self.context.stdout_path.write_text(execution.stdout, encoding="utf-8")
        self.context.stderr_path.write_text(execution.stderr, encoding="utf-8")
        result.stdout_path = paths.relative_to_root(self.context.stdout_path)
        result.stderr_path = paths.relative_to_root(self.context.stderr_path)
        result.raw_artifacts.append(result.stdout_path)
        if execution.stderr.strip():
            result.raw_artifacts.append(result.stderr_path)

        report_path = self.context.run_dir / self.report_filename if self.report_filename else None
        if report_path is not None and report_path.is_file():
            result.raw_artifacts.append(paths.relative_to_root(report_path))

        if execution.timed_out:
            # Checked before launch_error: a timeout also carries a message, and
            # reporting it as a generic failure would hide the real cause.
            result.status = RunStatus.TIMEOUT
            result.errors.append(
                f"TIMEOUT: {self.name} exceeded its "
                f"{execution.duration_seconds:.0f}s limit and was terminated."
            )
        elif execution.launch_error:
            result.status = RunStatus.FAILED
            result.errors.append(f"TOOL FAILED: {execution.launch_error}")

        # 8-9 - parse and normalize
        parsed = ParseResult()
        if execution.stdout.strip() or execution.stderr.strip():
            try:
                parsed = self.parse_output(execution, validation)
            except Exception as exc:  # noqa: BLE001 - parser bugs are reported
                result.errors.append(f"Parser failure: {exc}")

        result.findings = self._apply_floor(parsed.findings)
        result.warnings.extend(parsed.warnings)
        result.notes.extend(parsed.notes)
        result.errors.extend(parsed.errors)
        for artifact in parsed.artifacts:
            resolved = self.context.run_dir / artifact
            if resolved.is_file():
                relative = paths.relative_to_root(resolved)
                if relative not in result.raw_artifacts:
                    result.raw_artifacts.append(relative)

        if result.status is RunStatus.OK:
            accepted = self.success_exit_codes
            if execution.exit_code is not None and execution.exit_code not in accepted:
                result.status = RunStatus.FAILED
                result.errors.append(
                    f"{self.name} exited with code {execution.exit_code}."
                )
                tail = (execution.stderr or execution.stdout or "").strip().splitlines()
                if tail:
                    result.errors.append(f"Last output line: {tail[-1][:300]}")
            elif execution.exit_code not in accepted:
                result.status = RunStatus.FAILED
                result.errors.append(
                    f"{self.name} did not report an exit code."
                )
            elif parsed.errors:
                result.status = RunStatus.PARSE_ERROR
            elif parsed.warnings:
                result.status = RunStatus.PARTIAL

        # 10 - evidence metadata
        result.evidence = self._build_evidence(result, parsed, validation)
        result.finished_at = utc_now_iso()
        return result

    # -- helpers -----------------------------------------------------------
    def _apply_floor(self, findings: list[Finding]) -> list[Finding]:
        """Drop findings below the configured severity floor."""
        from .severity import Severity, at_or_above

        floor = Severity.from_string(self.config.severity_floor)
        kept = [f for f in findings if at_or_above(f.severity, floor)]
        return kept

    def _build_evidence(
        self,
        result: ToolRunResult,
        parsed: ParseResult,
        validation: TargetValidation,
    ) -> list[EvidenceRecord]:
        """Write one evidence record per finding, with raw-output integrity hash."""
        if not result.findings:
            return []

        primary = None
        for artifact in result.raw_artifacts:
            # Stored artifact paths are relative to the output root, which may
            # differ from the project root (tests redirect it).
            candidate = paths.output_root() / artifact
            if candidate.is_file():
                primary = candidate
                break
        digest = sha256_file(primary) if primary else ""

        # Evidence is namespaced by assessment, so a later run can never
        # overwrite an earlier run's records.
        if self.context.assessment:
            evidence_dir = runs.layout(self.context.assessment).tool_evidence_dir(self.name)
        else:
            evidence_dir = paths.evidence_dir(self.name)
        evidence_dir.mkdir(parents=True, exist_ok=True)

        limit = self.config.evidence_excerpt_chars
        records: list[EvidenceRecord] = []
        # Several findings can share a title (for example one template reporting
        # eight missing headers). Filenames must therefore be unique per record,
        # or records would silently overwrite each other and the evidence count
        # would understate what was found.
        used: set[str] = set()
        for index, finding in enumerate(result.findings, start=1):
            excerpt = parsed.excerpts.get(finding.title) or finding.evidence or finding.description
            if len(excerpt) > limit:
                excerpt = excerpt[:limit] + "\n[...]"
            record = EvidenceRecord(
                tool=self.name,
                finding_title=finding.title,
                target=validation.url or result.target,
                endpoint=finding.endpoint,
                excerpt=excerpt,
                raw_artifact=result.raw_artifacts[0] if result.raw_artifacts else "",
                raw_sha256=digest,
                reference=finding.reference,
            )
            base = (
                f"{self.context.run_id}--"
                f"{slugify(finding.title)}--{digest[:8] or 'nohash'}"
            )
            filename = f"{base}.json"
            if filename in used:
                filename = f"{base}--{index:03d}.json"
            attempt = 2
            while filename in used:
                filename = f"{base}--{index:03d}-{attempt}.json"
                attempt += 1
            used.add(filename)

            destination = evidence_dir / filename
            record.path = paths.relative_to_root(destination)
            from .models import write_json

            write_json(destination, record.to_dict())
            records.append(record)

        return records

    def read_report(self) -> str:
        """Read the tool's native report from the run directory."""
        if not self.report_filename:
            return ""
        path = self.context.run_dir / self.report_filename
        if not path.is_file():
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
