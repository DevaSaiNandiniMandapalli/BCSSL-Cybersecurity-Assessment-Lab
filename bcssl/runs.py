"""Assessment run identifiers and per-run directory isolation.

Every assessment receives a unique, monotonically increasing identifier::

    run-001
    run-002
    run-003

The identifier is reserved *before* any tool runs and is used as a namespace
for everything that run produces, so a later assessment can never overwrite an
earlier one's output:

.. code-block:: text

    reports/raw/{run_id}/{run_id}-{tool}/     verbatim tool output
    reports/normalized/{run_id}/              normalized findings
    evidence/{run_id}/{tool}/                 evidence records
    reports/final/{run_id}.{html,json,md,sarif}
    state/assessments/{run_id}.json           run metadata manifest

The counter lives in ``state/sequence.json``. It is reconciled with the
filesystem and the run index on every allocation, so deleting a directory or a
state file can never cause an identifier to be reused and an earlier assessment
to be overwritten.
"""

from __future__ import annotations

import json
import re
import shutil
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from . import paths
from .models import utc_now_iso

#: Canonical identifier shape: ``run-`` followed by a zero-padded counter.
ID_PATTERN = re.compile(r"^run-(\d{3,})$")

SEQUENCE_NAME = "sequence.json"
ASSESSMENT_DIR_NAME = "assessments"


class RunIdError(RuntimeError):
    """Raised when a run identifier is malformed or cannot be allocated."""


# ---------------------------------------------------------------------------
# Allocation
# ---------------------------------------------------------------------------
def _sequence_path() -> Path:
    return paths.state_dir() / SEQUENCE_NAME


def _read_sequence() -> int:
    path = _sequence_path()
    if not path.is_file():
        return 0
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return 0
    try:
        return max(0, int(data.get("highest_allocated", 0)))
    except (TypeError, ValueError):
        return 0


def _write_sequence(value: int) -> None:
    """Persist the counter atomically so a crash cannot corrupt it."""
    path = _sequence_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "highest_allocated": value,
        "updated_at": utc_now_iso(),
        "note": (
            "Monotonic assessment counter. Reconciled with the filesystem and "
            "run index on every allocation; never decreased."
        ),
    }
    handle = tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=str(path.parent),
        prefix=".sequence-",
        suffix=".tmp",
        delete=False,
    )
    try:
        with handle as stream:
            json.dump(payload, stream, indent=2)
            stream.write("\n")
        Path(handle.name).replace(path)
    except OSError:
        Path(handle.name).unlink(missing_ok=True)
        raise


def _highest_seen() -> int:
    """Highest counter visible on disk or in the run index."""
    highest = 0

    def bump(identifier: str) -> None:
        nonlocal highest
        match = ID_PATTERN.match(identifier or "")
        if match:
            highest = max(highest, int(match.group(1)))

    def bump_assessment(value: str) -> None:
        """Accept either ``run-003`` or ``run-003-nmap``."""
        bump("-".join((value or "").split("-")[:2]))

    raw = paths.raw_dir()
    if raw.is_dir():
        for entry in raw.iterdir():
            bump(entry.name)
            if entry.is_dir():
                for run_dir in entry.iterdir():
                    bump_assessment(run_dir.name)

    index = paths.run_index_file()
    if index.is_file():
        try:
            data = json.loads(index.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        for run_id in data.get("runs") or {}:
            bump_assessment(run_id)
        for assessment in data.get("assessments") or {}:
            bump_assessment(assessment)

    manifests = manifests_dir()
    if manifests.is_dir():
        for entry in manifests.glob("*.json"):
            bump(entry.stem)

    return highest


def allocate(when: datetime | None = None) -> str:
    """Reserve and return the next assessment identifier.

    Args:
        when: optional timestamp, used only for the manifest's start time.

    Returns:
        The reserved identifier, for example ``run-004``.

    Raises:
        RunIdError: if the identifier cannot be persisted, in which case no
            identifier is consumed.
    """
    paths.ensure_layout()
    next_value = max(_read_sequence(), _highest_seen()) + 1
    identifier = f"run-{next_value:03d}"
    _write_sequence(next_value)

    # Guarantee uniqueness even if the reserved directory name already exists.
    while layout_exists(identifier):
        next_value += 1
        identifier = f"run-{next_value:03d}"
        _write_sequence(next_value)

    layout(identifier).raw_dir.mkdir(parents=True, exist_ok=True)
    layout(identifier).normalized_dir.mkdir(parents=True, exist_ok=True)
    layout(identifier).evidence_dir.mkdir(parents=True, exist_ok=True)
    layout(identifier).final_dir.mkdir(parents=True, exist_ok=True)
    write_manifest(identifier, {"started_at": utc_now_iso()})
    return identifier


def layout_exists(identifier: str) -> bool:
    """True when any output already exists for *identifier*."""
    if not ID_PATTERN.match(identifier or ""):
        return False
    spots = layout(identifier)
    return any(
        path.exists()
        for path in (spots.raw_dir, spots.normalized_dir, spots.evidence_dir, spots.metadata_file)
    )


# ---------------------------------------------------------------------------
# Layout
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class RunLayout:
    """Every directory and file belonging to one assessment."""

    run_id: str
    raw_dir: Path
    normalized_dir: Path
    evidence_dir: Path
    final_dir: Path
    metadata_file: Path
    report_stem: str

    def tool_raw_dir(self, tool: str) -> Path:
        return self.raw_dir / f"{self.run_id}-{tool}"

    def tool_evidence_dir(self, tool: str) -> Path:
        return self.evidence_dir / tool

    def normalized_file(self, tool: str) -> Path:
        return self.normalized_dir / f"findings-{self.run_id}-{tool}.json"

    def report_file(self, extension: str) -> Path:
        suffix = extension[1:] if extension.startswith(".") else extension
        return self.final_dir / f"{self.run_id}.{suffix}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "raw_dir": paths.relative_to_root(self.raw_dir),
            "normalized_dir": paths.relative_to_root(self.normalized_dir),
            "evidence_dir": paths.relative_to_root(self.evidence_dir),
            "final_dir": paths.relative_to_root(self.final_dir),
            "metadata_file": paths.relative_to_root(self.metadata_file),
            "report_stem": self.report_stem,
        }


def layout(run_id: str) -> RunLayout:
    """Resolve the directory layout for *run_id*.

    Raises:
        RunIdError: when *run_id* does not match ``run-NNN``.
    """
    if not ID_PATTERN.match(run_id or ""):
        raise RunIdError(
            f"invalid assessment identifier {run_id!r}; expected 'run-NNN' "
            "(for example run-001)"
        )
    return RunLayout(
        run_id=run_id,
        raw_dir=paths.raw_dir() / run_id,
        normalized_dir=paths.normalized_dir() / run_id,
        evidence_dir=paths.evidence_dir() / run_id,
        final_dir=paths.final_dir(),
        metadata_file=manifests_dir() / f"{run_id}.json",
        report_stem=run_id,
    )


def run_id_for(tool: str, assessment: str) -> str:
    """Per-tool run identifier inside an assessment namespace."""
    return f"{assessment}-{tool}"


def assessment_of(run_id: str) -> str | None:
    """Extract the assessment identifier from an identifier or run id.

    Accepts both ``run-003`` and ``run-003-nmap`` and returns ``run-003``, or
    ``None`` when the value carries no assessment.
    """
    candidate = "-".join((run_id or "").split("-")[:2])
    return candidate if ID_PATTERN.match(candidate) else None


def manifests_dir() -> Path:
    return paths.state_dir() / ASSESSMENT_DIR_NAME


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------
def list_runs(include_empty: bool = True) -> list[str]:
    """Every assessment identifier known to the lab, oldest first."""
    found: set[str] = set()

    raw = paths.raw_dir()
    if raw.is_dir():
        for entry in raw.iterdir():
            if entry.is_dir() and ID_PATTERN.match(entry.name):
                found.add(entry.name)

    manifests = manifests_dir()
    if manifests.is_dir():
        for entry in manifests.glob("run-*.json"):
            found.add(entry.stem)

    index_file = paths.run_index_file()
    if index_file.is_file():
        try:
            data = json.loads(index_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        for identifier in data.get("assessments") or {}:
            if ID_PATTERN.match(identifier):
                found.add(identifier)
        for run_id in data.get("runs") or {}:
            assessment = assessment_of(run_id)
            if assessment:
                found.add(assessment)

    if not include_empty:
        return [item for item in sorted(found) if layout_exists(item)]
    return sorted(found)


def latest() -> str | None:
    """Most recently allocated assessment identifier."""
    runs = list_runs()
    return runs[-1] if runs else None


def resolve(identifier: str | None) -> str:
    """Resolve a requested assessment, falling back to the latest one.

    Raises:
        RunIdError: when nothing has been allocated yet, or the requested
            identifier is unknown.
    """
    if identifier:
        if not ID_PATTERN.match(identifier):
            raise RunIdError(
                f"invalid assessment identifier {identifier!r}; expected 'run-NNN'"
            )
        if identifier not in list_runs():
            raise RunIdError(
                f"assessment {identifier} does not exist; known assessments: "
                + (", ".join(list_runs()) or "none")
            )
        return identifier
    current = latest()
    if not current:
        raise RunIdError(
            "no assessment has been run yet; run 'python -m bcssl run-all' first"
        )
    return current


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------
def write_manifest(run_id: str, payload: dict[str, Any]) -> Path:
    """Merge *payload* into the assessment manifest and persist it."""
    spots = layout(run_id)
    existing: dict[str, Any] = {}
    if spots.metadata_file.is_file():
        try:
            loaded = json.loads(spots.metadata_file.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                existing = loaded
        except (OSError, ValueError):
            existing = {}

    merged = {**existing, **payload, "run_id": run_id, "updated_at": utc_now_iso()}
    merged.setdefault("started_at", utc_now_iso())
    merged.setdefault("layout", spots.to_dict())
    merged.setdefault("tools", [])
    merged.setdefault("status", "in-progress")

    spots.metadata_file.parent.mkdir(parents=True, exist_ok=True)
    spots.metadata_file.write_text(
        json.dumps(merged, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return spots.metadata_file


def read_manifest(run_id: str) -> dict[str, Any]:
    """Load the assessment manifest, or an empty mapping when absent."""
    manifest = layout(run_id).metadata_file
    if not manifest.is_file():
        return {}
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def record_tool(
    run_id: str,
    tool: str,
    *,
    status: str = "",
    finding_count: int = 0,
    run_id_for_tool: str = "",
    started_at: str = "",
    finished_at: str = "",
    errors: Iterable[str] = (),
    warnings: Iterable[str] = (),
) -> Path:
    """Add or replace one tool's entry in the assessment manifest."""
    manifest = read_manifest(run_id)
    tools: list[dict[str, Any]] = [
        item for item in manifest.get("tools", []) if item.get("tool") != tool
    ]
    tools.append(
        {
            "tool": tool,
            "run_id": run_id_for_tool or run_id_for(tool, run_id),
            "status": status,
            "finding_count": finding_count,
            "started_at": started_at,
            "finished_at": finished_at,
            "errors": list(errors),
            "warnings": list(warnings),
        }
    )
    tools.sort(key=lambda item: str(item.get("tool", "")))
    payload: dict[str, Any] = {"tools": tools}
    if any(item.get("status") not in ("ok", "", "partial") for item in tools):
        payload["status"] = "completed-with-errors"
    return write_manifest(run_id, payload)


def mark_complete(run_id: str, **payload: Any) -> Path:
    """Mark the assessment finished."""
    return write_manifest(run_id, {"status": "completed", "finished_at": utc_now_iso(), **payload})


def summarise(run_ids: Iterable[str] | None = None) -> list[dict[str, Any]]:
    """Compact per-assessment summary for the CLI and dashboard."""
    rows: list[dict[str, Any]] = []
    for run_id in run_ids if run_ids is not None else list_runs():
        manifest = read_manifest(run_id)
        tools = manifest.get("tools", []) if manifest else []
        rows.append(
            {
                "run_id": run_id,
                "status": manifest.get("status", "unknown") if manifest else "no-manifest",
                "started_at": manifest.get("started_at", ""),
                "finished_at": manifest.get("finished_at", ""),
                "tool_count": len(tools),
                "finding_count": sum(
                    int(item.get("finding_count", 0) or 0) for item in tools
                ),
                "tools": [
                    {
                        "tool": item.get("tool", ""),
                        "status": item.get("status", ""),
                        "finding_count": item.get("finding_count", 0),
                    }
                    for item in tools
                ],
                "reports": sorted(
                    paths.relative_to_root(item)
                    for item in layout(run_id).final_dir.glob(f"{run_id}.*")
                ),
            }
        )
    return rows


# ---------------------------------------------------------------------------
# Retention
# ---------------------------------------------------------------------------
#: Assessments are never pruned automatically. Evidence hashes are only
#: meaningful while the artifact they cover still exists, so a run is kept until
#: an operator removes it deliberately.
RETENTION_POLICY = "manual"


def retention_policy() -> dict[str, Any]:
    """Describe how long assessment artifacts are kept, and how to remove them."""
    return {
        "policy": RETENTION_POLICY,
        "automatic_pruning": False,
        "description": (
            "Every assessment is retained in full, including its raw tool "
            "output and evidence records. Evidence hashes are only meaningful "
            "while the referenced artifact exists, so nothing is removed "
            "automatically. Remove a run deliberately with "
            "'python -m bcssl clean' (all runs) or by archiving an assessment "
            "and deleting its directory."
        ),
        "remove_all": "python -m bcssl clean --yes",
        "archive_first": (
            "Copy reports/, evidence/ and state/ elsewhere before deleting an "
            "assessment; the run index is what allows reports to be rebuilt."
        ),
        "verify_after": "python -m bcssl runs --verify",
    }


def prune(keep: int = 5, *, dry_run: bool = False) -> dict[str, Any]:
    """Delete the oldest assessments, keeping the newest *keep*.

    This is opt-in and defaults to a dry run. Evidence for a removed assessment
    disappears with it, so archive first if the artifacts matter.
    """
    identifiers = list_runs()
    if keep < 0 or keep >= len(identifiers):
        return {"removed": [], "kept": identifiers, "dry_run": dry_run}

    doomed = identifiers[:-keep] if keep else list(identifiers)
    survivors = [item for item in identifiers if item not in doomed]

    removed: list[str] = []
    for run_id in doomed:
        if dry_run:
            removed.append(run_id)
            continue
        spots = layout(run_id)
        for directory in (spots.raw_dir, spots.normalized_dir, spots.evidence_dir):
            if directory.is_dir():
                shutil.rmtree(directory, ignore_errors=True)
        if spots.metadata_file.is_file():
            spots.metadata_file.unlink(missing_ok=True)
        removed.append(run_id)

    if removed and not dry_run:
        _rebuild_index(survivors)
    return {"removed": removed, "kept": list_runs(), "dry_run": dry_run}


def _rebuild_index(surviving: list[str]) -> None:
    """Drop index entries for assessments that no longer exist on disk."""
    index_path = paths.run_index_file()
    if not index_path.is_file():
        return
    try:
        data = json.loads(index_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return
    keep = set(surviving)
    data["runs"] = {
        key: value
        for key, value in (data.get("runs") or {}).items()
        if assessment_of(key) in keep
    }
    index_path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def now_stamp() -> str:
    """UTC stamp used inside manifests."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")