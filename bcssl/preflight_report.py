"""Environment preflight.

Answers one question honestly: **can this lab run right now, and if not, what
exactly is missing?**

Every component is probed for real. Nothing is assumed, and a component that
cannot be used is reported with the reason and an install hint rather than being
quietly skipped.
"""

from __future__ import annotations

import platform
import shutil
import sys
from dataclasses import dataclass, field
from typing import Any

from . import paths, preflight
from .config import LabConfig
from .target import check_reachability, validate_target

# Component states used in the report table.
READY = "READY"
READY_WITH_WARNING = "READY WITH WARNING"
NOT_INSTALLED = "NOT INSTALLED"
NOT_RUNNING = "NOT RUNNING"
UNAVAILABLE = "UNAVAILABLE"
ERROR = "ERROR"

#: Components that must be usable for a full assessment.
REQUIRED_FOR_ASSESSMENT = ("python", "docker", "target")


@dataclass
class Component:
    """One preflight row."""

    name: str
    status: str
    version: str = ""
    detail: str = ""
    required: bool = False
    remedy: str = ""

    @property
    def ok(self) -> bool:
        return self.status in (READY, READY_WITH_WARNING)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "version": self.version,
            "detail": self.detail,
            "required": self.required,
            "remedy": self.remedy,
            "ok": self.ok,
        }


@dataclass
class PreflightReport:
    components: list[Component] = field(default_factory=list)

    @property
    def blocking(self) -> list[Component]:
        return [c for c in self.components if c.required and not c.ok]

    @property
    def ready(self) -> bool:
        return not self.blocking

    @property
    def ready_tools(self) -> list[str]:
        return [
            c.name
            for c in self.components
            if c.ok and c.name in ("nmap", "zap", "nikto", "nuclei", "custom-scanner")
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ready": self.ready,
            "components": [c.to_dict() for c in self.components],
            "blocking": [c.name for c in self.blocking],
            "ready_tools": self.ready_tools,
            "tools_ready": len(self.ready_tools),
            "tools_total": 5,
        }


def _python_version() -> str:
    return f"{platform.python_version()} ({sys.executable})"


def check_python() -> Component:
    version = platform.python_version()
    if sys.version_info < (3, 10):
        return Component(
            name="python",
            status=ERROR,
            version=version,
            detail=f"Python {version} is older than the required 3.10",
            required=True,
            remedy="Install Python 3.10 or newer from https://python.org",
        )
    return Component(
        name="python",
        status=READY,
        version=_python_version(),
        detail="standard library only, no third-party packages required",
        required=True,
    )


def check_docker_cli() -> Component:
    path = shutil.which("docker")
    if not path:
        return Component(
            name="docker-cli",
            status=NOT_INSTALLED,
            detail="docker command not found on PATH",
            remedy="Install Docker Desktop from https://docker.com/desktop",
        )
    return Component(
        name="docker-cli", status=READY, version=path, detail="docker CLI found"
    )


def check_docker_daemon() -> Component:
    if not shutil.which("docker"):
        return Component(
            name="docker-daemon",
            status=UNAVAILABLE,
            detail="docker CLI is not installed",
            required=True,
            remedy="Install Docker Desktop, then start it",
        )
    available, detail = preflight.docker_available()
    if available:
        return Component(
            name="docker-daemon",
            status=READY,
            version=detail,
            detail="engine reachable; container fallbacks are possible",
            required=True,
        )
    return Component(
        name="docker-daemon",
        status=NOT_RUNNING,
        detail=detail,
        required=True,
        remedy="Start Docker Desktop and wait for the engine to report ready",
    )


def check_juice_shop() -> Component:
    """Report whether a container is serving the lab target."""
    if not shutil.which("docker"):
        return Component(
            name="juice-shop-container",
            status=UNAVAILABLE,
            detail="docker CLI not installed; cannot inspect containers",
            remedy="Install and start Docker Desktop, then use scripts/start-target.ps1",
        )
    from .executor import CommandSpec, run_command

    result = run_command(
        CommandSpec(
            argv=[
                "docker",
                "ps",
                "--filter",
                "name=bcssl-juiceshop",
                "--format",
                "{{.Names}}|{{.Status}}|{{.Ports}}",
            ],
            timeout=40.0,
        )
    )
    line = (result.stdout or "").strip()
    if result.launch_error or result.exit_code != 0:
        return Component(
            name="juice-shop-container",
            status=ERROR,
            detail=result.launch_error or "could not query docker ps",
            remedy="Start Docker Desktop, then run scripts/start-target.ps1",
        )
    if not line:
        return Component(
            name="juice-shop-container",
            status=NOT_RUNNING,
            detail="no container named bcssl-juiceshop is running",
            remedy="Run scripts/start-target.ps1 (docker compose up -d)",
        )
    parts = line.split("|")
    ports = parts[2] if len(parts) > 2 else ""
    detail = f"{parts[0]} ports={ports}"

    # A deliberately vulnerable training application must never be reachable
    # from the local network. Flag any binding that is not loopback-only.
    if ports and "127.0.0.1:3001" not in ports:
        return Component(
            name="juice-shop-container",
            status=READY_WITH_WARNING,
            version=parts[1] if len(parts) > 1 else "",
            detail=(
                f"{detail} - NOT bound to loopback only. The target is reachable "
                "from other machines on the network."
            ),
            remedy=(
                "Recreate the container from target/docker-compose.yml, which "
                "binds 127.0.0.1:3001:3000. A container started with "
                "'-p 3001:3000' binds every interface."
            ),
        )
    return Component(
        name="juice-shop-container",
        status=READY,
        version=parts[1] if len(parts) > 1 else "",
        detail=detail,
        remedy="",
    )


def check_target(config: LabConfig) -> Component:
    validation = validate_target(config.authorized_url, config)
    if not validation.ok:
        return Component(
            name="target",
            status=ERROR,
            detail=f"configured target rejected by the validator: {validation.reason}",
            required=True,
            remedy="Fix target.authorized_url in config/lab-config.json",
        )
    probe = check_reachability(validation, timeout=float(config.http.get("timeout_seconds", 10)))
    if probe.reachable:
        return Component(
            name="target",
            status=READY,
            version=f"HTTP {probe.status_code}",
            detail=f"{validation.url} responded in {probe.elapsed_seconds:.2f}s",
            required=True,
        )
    return Component(
        name="target",
        status=NOT_RUNNING,
        detail=f"no HTTP response from {validation.url}: {probe.error}",
        required=True,
        remedy="Start the lab target: scripts/start-target.ps1",
    )


def check_directories() -> Component:
    required = (
        paths.raw_dir(),
        paths.normalized_dir(),
        paths.final_dir(),
        paths.state_dir(),
    )
    missing: list[str] = []
    for directory in required:
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            missing.append(f"{paths.relative_to_root(directory)} ({exc.strerror})")
    if missing:
        return Component(
            name="directories",
            status=ERROR,
            detail="; ".join(missing),
            remedy="Check write permissions for the project directory",
        )
    return Component(
        name="directories",
        status=READY,
        detail="reports/, evidence/ and state/ are writable",
    )


def check_configuration(config: LabConfig) -> Component:
    source = config.source
    warnings: list[str] = []
    if source is None:
        warnings.append("config/lab-config.json not found; using built-in defaults")
    if not paths.project_root().samefile(source.parent.parent) if source else False:
        warnings.append("configuration is outside the project directory")
    if config.allowed_ports != (3001,):
        warnings.append(
            f"non-default ports authorized: {', '.join(str(p) for p in config.allowed_ports)}"
        )
    if warnings:
        return Component(
            name="configuration",
            status=READY_WITH_WARNING,
            version=str(source) if source else "built-in defaults",
            detail="; ".join(warnings),
        )
    return Component(
        name="configuration",
        status=READY,
        version=str(source) if source else "built-in defaults",
        detail=f"authorized target {config.authorized_url}",
    )


def check_custom_scanner_project() -> Component:
    root = paths.project_root().parent / "Web-Security-Scanner"
    if not (root / "scanner.py").is_file():
        return Component(
            name="project08",
            status=NOT_INSTALLED,
            detail=f"custom scanner project not found at {root}",
            remedy=(
                "Set tools.custom-scanner.project_root in config/lab-config.json "
                "to the completed Project #08 directory"
            ),
        )
    return Component(
        name="project08",
        status=READY,
        version="read-only external integration",
        detail=f"found at {root}; invoked as a subprocess, never modified",
    )


def check_tools(config: LabConfig) -> list[Component]:
    components: list[Component] = []
    for tool, status in preflight.detect_all(config).items():
        if status.available:
            components.append(
                Component(
                    name=tool,
                    status=READY,
                    version=status.version,
                    detail=f"{status.message} via {status.transport}",
                    remedy="",
                )
            )
        elif "DISABLED" in status.message:
            components.append(
                Component(
                    name=tool,
                    status=UNAVAILABLE,
                    detail=status.message,
                    remedy=f"set tools.{tool}.enabled to true in config/lab-config.json",
                )
            )
        else:
            components.append(
                Component(
                    name=tool,
                    status=NOT_INSTALLED,
                    detail=status.message,
                    remedy=status.install_hint or "see docs/installation.md",
                )
            )
    return components


def run(config: LabConfig, *, include_tools: bool = True) -> PreflightReport:
    """Probe every component and return the full report."""
    report = PreflightReport()
    report.components.append(check_python())
    report.components.append(check_docker_cli())
    report.components.append(check_docker_daemon())
    report.components.append(check_juice_shop())
    report.components.append(check_target(config))
    report.components.append(check_configuration(config))
    report.components.append(check_directories())
    report.components.append(check_custom_scanner_project())
    if include_tools:
        report.components.extend(check_tools(config))
    return report


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------
STATUS_ICON = {
    READY: "[ OK ]",
    READY_WITH_WARNING: "[WARN]",
    NOT_INSTALLED: "[MISS]",
    NOT_RUNNING: "[DOWN]",
    UNAVAILABLE: "[N/A ]",
    ERROR: "[FAIL]",
}


def render_table(report: PreflightReport) -> str:
    """Render the professional Component | Status | Version | Details table."""
    rows = [("Component", "Status", "Version", "Details")]
    for component in report.components:
        icon = STATUS_ICON.get(component.status, "[????]")
        rows.append(
            (
                component.name,
                f"{icon} {component.status}",
                (component.version or "-")[:46],
                (component.detail or "-")[:78],
            )
        )

    widths = [
        max(len(row[index]) for row in rows) for index in range(4)
    ]
    widths[0] = max(widths[0], 20)

    def line(values: tuple[str, ...]) -> str:
        return "  ".join(
            value.ljust(widths[index])[:widths[index]] for index, value in enumerate(values)
        )

    out = [line(rows[0]), "  ".join("-" * width for width in widths)]
    out.extend(line(row) for row in rows[1:])
    return "\n".join(out)


def render_remedies(report: PreflightReport) -> str:
    """Render actionable setup instructions for anything not ready."""
    problems = [c for c in report.components if not c.ok and c.remedy]
    if not problems:
        return ""
    out = ["", "SETUP REQUIRED", "-" * 62]
    for component in problems:
        out.append(f"  {component.name}: {component.detail}")
        out.append(f"    -> {component.remedy}")
    return "\n".join(out)
