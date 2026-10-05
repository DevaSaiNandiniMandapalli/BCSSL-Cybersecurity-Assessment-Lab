"""Artifact cleanup.

Removes generated scan output, evidence and student progress so a lab can be
handed on or re-run from a known state. Source, configuration, exercises and
documentation are never touched, and ``.gitkeep`` placeholders are preserved so
the directory skeleton survives.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path

from . import paths


@dataclass
class CleanResult:
    removed_files: int = 0
    removed_dirs: int = 0
    freed_bytes: int = 0
    skipped: list[str] = field(default_factory=list)
    areas: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "removed_files": self.removed_files,
            "removed_dirs": self.removed_dirs,
            "freed_bytes": self.freed_bytes,
            "skipped": self.skipped,
            "areas": self.areas,
        }


def _purge(root: Path, result: CleanResult, *, dry_run: bool = False) -> None:
    """Remove everything under *root* except ``.gitkeep`` placeholders."""
    if not root.is_dir():
        return
    result.areas.append(paths.relative_to_root(root))

    entries = sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True)
    for entry in entries:
        try:
            if entry.is_file() or entry.is_symlink():
                if entry.name == ".gitkeep":
                    continue
                size = entry.stat().st_size if entry.is_file() else 0
                if not dry_run:
                    entry.unlink()
                result.removed_files += 1
                result.freed_bytes += size
            elif entry.is_dir():
                # Only remove directories that are now empty.
                try:
                    next(entry.iterdir())
                except StopIteration:
                    if not dry_run:
                        entry.rmdir()
                    result.removed_dirs += 1
                except OSError:
                    pass
        except OSError as exc:
            result.skipped.append(f"{paths.relative_to_root(entry)}: {exc}")


def clean(
    *,
    keep_evidence: bool = False,
    keep_progress: bool = False,
    include_caches: bool = True,
    dry_run: bool = False,
) -> CleanResult:
    """Remove generated artifacts.

    Args:
        keep_evidence: keep ``evidence/`` records.
        keep_progress: keep ``state/`` (run index and student acknowledgements).
        include_caches: also remove ``__pycache__`` directories.
        dry_run: report what would be removed without deleting anything.

    Returns:
        A :class:`CleanResult` describing exactly what was (or would be) removed.
    """
    result = CleanResult()
    result.dry_run = dry_run
    targets = [
        paths.raw_dir(),
        paths.normalized_dir(),
        paths.final_dir(),
    ]
    if not keep_evidence:
        targets.append(paths.evidence_dir())
    if not keep_progress:
        targets.append(paths.state_dir())

    for target in targets:
        _purge(Path(target), result, dry_run=dry_run)

    if include_caches:
        for cache in sorted(paths.project_root().rglob("__pycache__")):
            if cache.is_dir():
                if not dry_run:
                    shutil.rmtree(cache, ignore_errors=True)
                result.removed_dirs += 1

    return result
