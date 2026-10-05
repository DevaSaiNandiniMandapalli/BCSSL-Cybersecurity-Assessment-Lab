"""Tool availability detection.

The lab must never pretend a scan happened. This module answers one question
honestly: can this tool actually be executed here, and how do we know?

Detection covers two transports:

* ``local``  - the executable must be resolvable on ``PATH``.
* ``docker`` - the Docker CLI must exist *and* the engine must be reachable.

Version strings come from a real ``--version`` probe, so the value written into
a report is one the tool actually printed.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import paths
from .config import LabConfig
from .executor import probe_version, run_command, CommandSpec, which
from .models import ToolStatus

#: Version probe arguments per tool. Anything not listed uses ``--version``.
VERSION_ARGS: dict[str, list[str]] = {
    "nmap": ["--version"],
    "zap": ["-version"],
    "nikto": ["-Version"],
    "nuclei": ["-version"],
    "custom-scanner": ["--version"],
}

TRANSPORT_LOCAL = "local"
TRANSPORT_DOCKER = "docker"


def tool_manifest(tool: str) -> dict[str, Any]:
    """Load ``tools/<tool>/tool.json`` if present, else an empty manifest."""
    path = paths.tool_config_file(tool)
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def install_hint(tool: str) -> str:
    """Return the platform-appropriate install hint recorded in the manifest."""
    manifest = tool_manifest(tool)
    hint = manifest.get("install", {})
    if not isinstance(hint, dict):
        return ""
    system = "windows"
    import sys

    if sys.platform.startswith("linux"):
        system = "linux"
    elif sys.platform == "darwin":
        system = "macos"
    value = hint.get(system) or hint.get("generic") or ""
    return str(value)


def docker_available() -> tuple[bool, str]:
    """Check whether the Docker engine is actually usable."""
    if not which("docker"):
        return False, "docker CLI not found on PATH"
    result = run_command(
        CommandSpec(argv=["docker", "info", "--format", "{{.ServerVersion}}"], timeout=25.0)
    )
    if result.launch_error:
        return False, result.launch_error
    if result.exit_code != 0:
        detail = (result.stderr or result.stdout or "").strip().splitlines()
        message = detail[-1] if detail else "docker daemon is not reachable"
        return False, f"docker CLI present but daemon unreachable: {message}"
    version = (result.stdout or "").strip()
    return True, version or "engine reachable"


def docker_image_entrypoint(image: str) -> list[str]:
    """Return an image's declared ENTRYPOINT as a list.

    Many tool images declare the tool itself as the entrypoint. Knowing this
    lets the runner avoid passing the executable name twice - otherwise the
    duplicated token is parsed by the tool as an extra target argument, which
    would silently widen the scan.
    """
    if not image or not which("docker"):
        return []
    result = run_command(
        CommandSpec(
            argv=["docker", "inspect", image, "--format", "{{json .Config.Entrypoint}}"],
            timeout=60.0,
        )
    )
    if result.launch_error or result.exit_code != 0:
        return []
    text = (result.stdout or "").strip()
    if not text or text in ("null", "[]"):
        return []
    try:
        parsed = json.loads(text)
    except ValueError:
        return []
    if isinstance(parsed, list):
        return [str(item) for item in parsed]
    return []


def resolve_transport(tool: str, settings: dict[str, Any]) -> tuple[str, str]:
    """Decide which transport to use for *tool*.

    Returns ``(transport, executable)``. ``transport`` is ``"local"``,
    ``"docker"`` or ``"none"`` when neither option can work.
    """
    configured = str(settings.get("transport", "auto")).lower()
    executable = str(settings.get("executable") or tool)

    if tool == "custom-scanner":
        # Never containerised: it is an external local project.
        return TRANSPORT_LOCAL, executable

    if configured == TRANSPORT_LOCAL:
        return (TRANSPORT_LOCAL if which(executable) else "none"), executable

    if configured == TRANSPORT_DOCKER:
        ok, _ = docker_available()
        return (TRANSPORT_DOCKER if ok else "none"), executable

    # auto
    if which(executable):
        return TRANSPORT_LOCAL, executable
    ok, _ = docker_available()
    if ok and settings.get("docker_image"):
        return TRANSPORT_DOCKER, executable
    return "none", executable


def detect(tool: str, config: LabConfig) -> ToolStatus:
    """Probe *tool* and report availability without running a scan."""
    settings = config.tool(tool)
    manifest = tool_manifest(tool)
    executable = str(settings.get("executable") or tool)
    hint = install_hint(tool)

    if not settings.get("enabled", True):
        return ToolStatus(
            tool=tool,
            available=False,
            executable=executable,
            transport="none",
            message="TOOL DISABLED IN CONFIGURATION",
            install_hint=hint,
        )

    if tool == "custom-scanner":
        return _detect_custom_scanner(settings, manifest, hint)

    transport, _ = resolve_transport(tool, settings)

    if transport == TRANSPORT_LOCAL:
        version_args = VERSION_ARGS.get(tool, manifest.get("version_args", ["--version"]))
        available, version = probe_version(executable, version_args)
        if available:
            return ToolStatus(
                tool=tool,
                available=True,
                executable=executable,
                resolved_path=which(executable),
                version=version,
                transport=TRANSPORT_LOCAL,
                message="TOOL AVAILABLE",
            )
        return ToolStatus(
            tool=tool,
            available=False,
            executable=executable,
            transport=TRANSPORT_LOCAL,
            message="TOOL NOT INSTALLED",
            install_hint=hint,
        )

    if transport == TRANSPORT_DOCKER:
        ok, detail = docker_available()
        if ok:
            image = str(settings.get("docker_image") or "")
            entrypoint = docker_image_entrypoint(image)
            return ToolStatus(
                tool=tool,
                available=True,
                executable=executable,
                version=f"docker engine {detail}; image {image}",
                transport=TRANSPORT_DOCKER,
                message="TOOL AVAILABLE VIA DOCKER",
                docker_entrypoint=entrypoint,
            )
        return ToolStatus(
            tool=tool,
            available=False,
            executable=executable,
            transport="none",
            message=f"TOOL NOT INSTALLED - {detail}",
            install_hint=hint,
        )

    message = "TOOL NOT INSTALLED"
    if not which(executable):
        ok, detail = docker_available()
        if not ok:
            message = f"TOOL NOT INSTALLED - {executable} not on PATH; {detail}"
    return ToolStatus(
        tool=tool,
        available=False,
        executable=executable,
        transport="none",
        message=message,
        install_hint=hint,
    )


def _detect_custom_scanner(
    settings: dict[str, Any],
    manifest: dict[str, Any],
    hint: str,
) -> ToolStatus:
    """Locate the external Project #08 scanner without modifying it."""
    root = Path(str(settings.get("project_root") or "")).expanduser()
    entry = root / "scanner.py"

    if not entry.is_file():
        return ToolStatus(
            tool="custom-scanner",
            available=False,
            executable="scanner.py",
            transport=TRANSPORT_LOCAL,
            message=(
                "TOOL NOT INSTALLED - custom scanner project not found at "
                f"{root}. Set tools.custom-scanner.project_root in "
                "config/lab-config.json to the Web-Security-Scanner directory."
            ),
            install_hint=hint,
        )

    interpreter_setting = str(settings.get("python") or "auto").lower()
    candidates: list[Path] = []
    if interpreter_setting != "auto":
        candidates.append(Path(interpreter_setting).expanduser())
    else:
        candidates.extend(
            [root / ".venv" / "Scripts" / "python.exe", root / ".venv" / "bin" / "python"]
        )
        import shutil

        system_python = shutil.which("python")
        if system_python:
            candidates.append(Path(system_python))

    for candidate in candidates:
        if candidate.is_file():
            available, version = probe_version(str(candidate), ["--version"])
            if version.lower().startswith("python "):
                version = version[len("python "):]
            return ToolStatus(
                tool="custom-scanner",
                available=True,
                executable="scanner.py",
                resolved_path=str(candidate),
                version=f"Python {version}" if version else "Python interpreter detected",
                transport=TRANSPORT_LOCAL,
                message="TOOL AVAILABLE",
            )

    return ToolStatus(
        tool="custom-scanner",
        available=False,
        executable="scanner.py",
        transport=TRANSPORT_LOCAL,
        message=(
            "TOOL NOT INSTALLED - custom scanner found but no usable Python "
            "interpreter was located. Expected a project virtual environment "
            f"at {root / '.venv'}."
        ),
        install_hint=hint,
    )


def detect_all(config: LabConfig) -> dict[str, ToolStatus]:
    """Probe every configured tool."""
    return {tool: detect(tool, config) for tool in config.tool_names()}
