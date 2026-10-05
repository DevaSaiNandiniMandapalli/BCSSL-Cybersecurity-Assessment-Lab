"""Nuclei template management.

Nuclei ships without templates, and the complete set is large. These helpers let
an instructor fetch templates once and build the curated lab profile referenced
by ``tools/nuclei/README.md``.

Both operations only manage *template definition files*. Neither runs a scan and
neither contacts the assessment target.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path

from . import paths
from .config import LabConfig
from .executor import CommandSpec, run_command, which

#: Families copied into the lab profile. Documented in
#: ``tools/nuclei/README.md`` with the reasoning for each exclusion.
LAB_PROFILE_DIRS: tuple[str, ...] = (
    "technologies",
    "misconfiguration",
    "exposures",
    "miscellaneous",
)

FULL_DIR_NAME = "templates"
PROFILE_DIR_NAME = "templates-lab"
CONTAINER_TEMPLATES_DIR = "/bcssl-templates"


@dataclass
class TemplateResult:
    ok: bool
    message: str
    downloaded: int = 0
    copied: int = 0
    details: list[str] = field(default_factory=list)


def templates_dir() -> Path:
    return paths.project_root() / "tools" / "nuclei" / FULL_DIR_NAME


def profile_dir() -> Path:
    return paths.project_root() / "tools" / "nuclei" / PROFILE_DIR_NAME


def count_templates(directory: Path) -> int:
    if not directory.is_dir():
        return 0
    return sum(1 for item in directory.rglob("*.yaml"))


def update_templates(config: LabConfig, *, timeout: float = 1800.0) -> TemplateResult:
    """Download the full nuclei template set into ``tools/nuclei/templates``.

    Uses the configured image (or a local ``nuclei`` executable) and
    ``-update-template-dir`` so nothing is written inside a throwaway container.
    """
    settings = config.tool("nuclei")
    destination = templates_dir()
    destination.mkdir(parents=True, exist_ok=True)

    image = str(settings.get("docker_image") or "")
    if which("nuclei"):
        argv = [
            "nuclei",
            "-ut",
            "-ud",
            str(destination),
        ]
    elif which("docker") and image:
        argv = [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{destination}:{CONTAINER_TEMPLATES_DIR}",
            image,
            "-ut",
            "-duc",
            "-ud",
            CONTAINER_TEMPLATES_DIR,
        ]
    else:
        return TemplateResult(
            ok=False,
            message=(
                "Neither a local nuclei executable nor a usable Docker engine "
                "was found. Install nuclei or start Docker Desktop, then retry."
            ),
        )

    result = run_command(CommandSpec(argv=argv, timeout=timeout))
    if result.launch_error or result.exit_code != 0:
        tail = (result.stderr or result.stdout or "").strip().splitlines()
        return TemplateResult(
            ok=False,
            message=tail[-1] if tail else (result.launch_error or "template update failed"),
        )

    return TemplateResult(
        ok=True,
        message=f"templates updated in {paths.relative_to_root(destination)}",
        downloaded=count_templates(destination),
    )


def build_template_profile(
    *, overwrite: bool = False
) -> TemplateResult:
    """Copy the curated families from the full set into the lab profile."""
    source_root = templates_dir() / "http"
    target_root = profile_dir()

    if not source_root.is_dir():
        return TemplateResult(
            ok=False,
            message=(
                f"no downloaded templates found at "
                f"{paths.relative_to_root(source_root)}. Run "
                "'python -m bcssl update-templates' first."
            ),
        )

    copied = 0
    details: list[str] = []
    for name in LAB_PROFILE_DIRS:
        source = source_root / name
        if not source.is_dir():
            details.append(f"{name}: not present in the downloaded set")
            continue
        target = target_root / name
        if target.exists():
            if not overwrite:
                details.append(f"{name}: already present, skipped")
                continue
            shutil.rmtree(target)
        shutil.copytree(source, target)
        count = count_templates(target)
        copied += count
        details.append(f"{name}: {count} templates")

    existing = count_templates(target_root)
    return TemplateResult(
        # Rebuilding an already-complete profile is a success, not a failure:
        # nothing was copied, but the profile is in place.
        ok=bool(copied or existing),
        message=(
            f"lab profile contains {count_templates(target_root)} templates in "
            f"{paths.relative_to_root(target_root)}"
        ),
        copied=copied,
        details=details,
    )


def template_status() -> dict[str, int | str]:
    """Report how many templates are available in each location."""
    return {
        "full": count_templates(templates_dir()),
        "profile": count_templates(profile_dir()),
        "profile_path": paths.relative_to_root(profile_dir()),
        "full_path": paths.relative_to_root(templates_dir()),
    }
