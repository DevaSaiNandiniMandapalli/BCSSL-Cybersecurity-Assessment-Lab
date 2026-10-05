"""Subprocess execution with full capture.

Every external tool is launched through :func:`run_command` with an argument
list (never a shell string), so a target string can never be reinterpreted as
shell syntax. stdout, stderr, the exit code and the wall-clock duration are
always captured, including on timeout.
"""

from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence


@dataclass
class ExecutionResult:
    """Raw outcome of one external command."""

    command: list[str]
    exit_code: int | None
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False
    launch_error: str = ""
    cwd: str = ""

    @property
    def succeeded(self) -> bool:
        return (
            self.exit_code == 0
            and not self.timed_out
            and not self.launch_error
        )

    def to_dict(self, include_output: bool = False) -> dict[str, Any]:
        data: dict[str, Any] = {
            "command": self.command,
            "exit_code": self.exit_code,
            "duration_seconds": round(self.duration_seconds, 3),
            "timed_out": self.timed_out,
            "launch_error": self.launch_error,
        }
        if include_output:
            data["stdout"] = self.stdout
            data["stderr"] = self.stderr
        return data


@dataclass
class CommandSpec:
    """A command to execute, plus the environment it needs.

    ``env_overrides`` is applied on top of the inherited environment; it is used
    for non-interactive behaviour (for example ZAP's ``-config``/API settings
    or Nikto's no-prompt flags).
    """

    argv: list[str]
    timeout: float = 300.0
    cwd: str | None = None
    env_overrides: Mapping[str, str] = field(default_factory=dict)

    def display(self) -> str:
        """Render the command for logs and reports.

        Uses :func:`~shlex.join`-style quoting so what the student reads is an
        accurate, copy-pasteable representation.
        """
        import shlex

        return " ".join(shlex.quote(part) for part in self.argv)


def run_command(spec: CommandSpec) -> ExecutionResult:
    """Execute *spec* and capture everything it produced.

    Never raises for tool-level failures: a missing executable, a non-zero exit
    and a timeout are all reported through the returned object so the caller can
    surface them instead of hiding them.
    """
    environment = dict(os.environ)
    environment.update(spec.env_overrides)
    # Keep tool output line-buffered and non-interactive so captured text is
    # complete when the process exits.
    environment.setdefault("PYTHONUNBUFFERED", "1")

    started = time.monotonic()
    try:
        completed = subprocess.run(  # noqa: S603 - argv list, never shell=True
            spec.argv,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=spec.timeout,
            cwd=spec.cwd,
            env=environment,
            shell=False,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return ExecutionResult(
            command=list(spec.argv),
            exit_code=None,
            stdout=_decode(exc.stdout),
            stderr=_decode(exc.stderr),
            duration_seconds=time.monotonic() - started,
            timed_out=True,
            launch_error=f"exceeded timeout of {spec.timeout:g}s and was terminated",
            cwd=spec.cwd or "",
        )
    except FileNotFoundError as exc:
        return ExecutionResult(
            command=list(spec.argv),
            exit_code=None,
            stdout="",
            stderr="",
            duration_seconds=time.monotonic() - started,
            launch_error=f"executable not found: {exc}",
            cwd=spec.cwd or "",
        )
    except OSError as exc:
        return ExecutionResult(
            command=list(spec.argv),
            exit_code=None,
            stdout="",
            stderr="",
            duration_seconds=time.monotonic() - started,
            launch_error=f"could not start process: {exc}",
            cwd=spec.cwd or "",
        )

    return ExecutionResult(
        command=list(spec.argv),
        exit_code=completed.returncode,
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
        duration_seconds=time.monotonic() - started,
        timed_out=False,
        cwd=spec.cwd or "",
    )


def _decode(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def which(executable: str) -> str:
    """Return the resolved path of *executable* on PATH, or an empty string."""
    import shutil

    return shutil.which(executable) or ""


def probe_version(
    executable: str,
    version_args: Sequence[str] = ("--version",),
    *,
    timeout: float = 20.0,
) -> tuple[bool, str]:
    """Run a ``--version`` style probe.

    Returns ``(available, version_text)``. A tool that prints its banner to
    stderr (common for ZAP and Nikto) is still treated as available.
    """
    resolved = which(executable)
    if not resolved:
        return False, ""
    result = run_command(
        CommandSpec(argv=[resolved, *version_args], timeout=timeout)
    )
    if result.launch_error:
        return False, ""
    text = (result.stdout or result.stderr or "").strip()
    first_line = text.splitlines()[0].strip() if text else ""
    if not first_line:
        # Some tools exit non-zero on --version but still prove they exist.
        return result.exit_code is not None, ""
    return True, first_line


def save_stream(
    directory: Path,
    stem: str,
    content: str,
) -> Path:
    """Write *content* to ``<directory>/<stem>`` and return the path."""
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / stem
    destination.write_text(content, encoding="utf-8")
    return destination
