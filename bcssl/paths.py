"""Canonical filesystem layout for the assessment lab.

Every component resolves paths through this module so that the on-disk layout
matches the documented structure regardless of the current working directory.

Layout::

    <root>/config/lab-config.json
    <root>/tools/<tool>/tool.json
    <root>/bcssl/...                     engine package
    <root>/runners/<tool>-runner/        thin entry points
    <root>/parsers/<tool>-parser/        standalone parser CLIs
    <root>/reports/raw/                  verbatim tool output
    <root>/reports/normalized/           normalized findings
    <root>/reports/final/                consolidated reports
    <root>/evidence/<tool>/              per-finding evidence records
    <root>/state/                        run index + student progress
    <root>/lab/<level>/exNN/             exercises
"""

from __future__ import annotations

import os
from pathlib import Path

#: Environment variable that relocates *writable output* only (reports,
#: evidence and state). Content - configuration, tool manifests and lab
#: exercises - always comes from the project the code is installed in, so
#: redirecting output can never hide the lab material.
OUTPUT_ROOT_ENV_VAR = "BCSSL_OUTPUT_ROOT"

_PACKAGE_DIR = Path(__file__).resolve().parent


def project_root() -> Path:
    """Return the project root that ships the lab content.

    This is derived from the installed package location and is not affected by
    the output override.
    """
    return _PACKAGE_DIR.parent


def output_root() -> Path:
    """Return the root under which generated artifacts are written.

    Defaults to :func:`project_root`. ``$BCSSL_OUTPUT_ROOT`` overrides it, which
    is how the test-suite runs without touching the real artifact directories.
    """
    override = os.environ.get(OUTPUT_ROOT_ENV_VAR)
    if override:
        return Path(override).expanduser().resolve()
    return project_root()


def config_dir() -> Path:
    return project_root() / "config"


def lab_config_file() -> Path:
    return config_dir() / "lab-config.json"


def tools_dir() -> Path:
    return project_root() / "tools"


def tool_config_file(tool: str) -> Path:
    return tools_dir() / tool / "tool.json"


def reports_dir() -> Path:
    return output_root() / "reports"


def raw_dir() -> Path:
    return reports_dir() / "raw"


def normalized_dir() -> Path:
    return reports_dir() / "normalized"


def final_dir() -> Path:
    return reports_dir() / "final"


def evidence_dir(tool: str | None = None) -> Path:
    base = output_root() / "evidence"
    return base if tool is None else base / tool


def state_dir() -> Path:
    return output_root() / "state"


def run_index_file() -> Path:
    """Index of every tool run performed in this lab."""
    return state_dir() / "run-index.json"


def progress_file() -> Path:
    """Student exercise acknowledgements."""
    return state_dir() / "progress.json"


def lab_dir(level: str | None = None) -> Path:
    base = project_root() / "lab"
    return base if level is None else base / level


def exercise_dir(level: str, exercise_id: str) -> Path:
    return lab_dir(level) / exercise_id


def ensure_layout() -> None:
    """Create the writable output directories if they do not exist yet.

    Per-assessment namespaces (``raw/run-NNN/``, ``normalized/run-NNN/``,
    ``evidence/run-NNN/<tool>/``) are created when an assessment is allocated,
    not here.
    """
    for directory in (
        raw_dir(),
        normalized_dir(),
        final_dir(),
        state_dir(),
        evidence_dir(),
    ):
        directory.mkdir(parents=True, exist_ok=True)
    # Legacy flat evidence directories are kept so records written by an older
    # build stay discoverable.
    for tool in ("nmap", "zap", "nikto", "nuclei", "custom-scanner"):
        evidence_dir(tool).mkdir(parents=True, exist_ok=True)


def relative_to_root(path: Path | str) -> str:
    """Render *path* relative to the output root (or project root) when possible.

    Used in reports and artifacts so absolute local paths do not leak into
    every file.
    """
    candidate = Path(path)
    resolved = candidate.resolve() if candidate.is_absolute() else candidate
    for base in (output_root(), project_root()):
        try:
            return resolved.relative_to(base).as_posix()
        except (ValueError, OSError):
            continue
    return candidate.as_posix()
