"""Evidence collection and integrity verification.

Raw tool output is stored verbatim and never edited. Every normalized finding
gets an evidence record naming the artifact it came from plus the sha256 of
that artifact, so a reviewer can prove a finding was derived from the stored
output rather than written by hand.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from . import paths
from .models import EvidenceRecord, Finding, ToolRunResult, read_json, sha256_file, write_json

#: Filename of the generated evidence index.
INDEX_NAME = "evidence-index.json"


@dataclass
class EvidenceVerification:
    """Outcome of re-hashing stored artifacts."""

    checked: int = 0
    intact: int = 0
    modified: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.modified and not self.missing

    def to_dict(self) -> dict[str, Any]:
        return {
            "checked": self.checked,
            "intact": self.intact,
            "modified": self.modified,
            "missing": self.missing,
            "ok": self.ok,
        }


def evidence_dir(tool: str) -> Path:
    """Records for *tool* across every assessment.

    Records are stored under ``evidence/{assessment}/{tool}/``. This returns the
    legacy per-tool directory when it exists, and otherwise the assessment
    namespaces holding that tool's records, so callers see all of them.
    """
    return paths.evidence_dir(tool)


def _record_files(tool: str) -> list[Path]:
    """Every evidence-record file belonging to *tool*, across assessments."""
    root = paths.evidence_dir()
    if not root.is_dir():
        return []

    files: list[Path] = []

    # Namespaced layout: evidence/run-NNN/<tool>/*.json
    for candidate in sorted(root.glob(f"*/{tool}/*.json")):
        files.append(candidate)

    # Legacy flat layout: evidence/<tool>/*.json
    flat = root / tool
    if flat.is_dir() and flat.parent == root:
        files.extend(sorted(flat.glob("*.json")))

    # Deduplicate while preserving order.
    seen: set[Path] = set()
    unique: list[Path] = []
    for item in files:
        resolved = item.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        unique.append(item)
    return unique


def write_record(record: EvidenceRecord) -> Path:
    """Persist an evidence record, returning its path."""
    if not record.path:
        raise ValueError("evidence record has no path assigned")
    destination = paths.output_root() / record.path
    write_json(destination, record.to_dict())
    return destination


def records_for(tool: str) -> list[EvidenceRecord]:
    """Load every evidence record stored for *tool*, from every assessment."""
    loaded: list[EvidenceRecord] = []
    for file in _record_files(tool):
        data = read_json(file)
        if not isinstance(data, dict) or "finding_title" not in data:
            continue
        loaded.append(
            EvidenceRecord(
                tool=data.get("tool", tool),
                finding_title=data.get("finding_title", ""),
                target=data.get("target", ""),
                endpoint=data.get("endpoint", ""),
                excerpt=data.get("excerpt", ""),
                raw_artifact=data.get("raw_artifact", ""),
                raw_sha256=data.get("raw_sha256", ""),
                recorded_at=data.get("recorded_at", ""),
                path=paths.relative_to_root(file),
                reference=data.get("reference", ""),
            )
        )
    return loaded


def records_for_assessment(run_id: str, tools: Iterable[str] | None = None) -> list[EvidenceRecord]:
    """Records belonging to one assessment only."""
    from . import runs as runs_module

    try:
        spots = runs_module.layout(run_id)
    except runs_module.RunIdError:
        return []
    if not spots.evidence_dir.is_dir():
        return []
    selected = list(tools) if tools else [
        item.name for item in sorted(spots.evidence_dir.iterdir()) if item.is_dir()
    ]
    records: list[EvidenceRecord] = []
    for tool in selected:
        for file in sorted((spots.evidence_dir / tool).glob("*.json")):
            data = read_json(file)
            if isinstance(data, dict) and "finding_title" in data:
                records.append(
                    EvidenceRecord(
                        tool=data.get("tool", tool),
                        finding_title=data.get("finding_title", ""),
                        target=data.get("target", ""),
                        endpoint=data.get("endpoint", ""),
                        excerpt=data.get("excerpt", ""),
                        raw_artifact=data.get("raw_artifact", ""),
                        raw_sha256=data.get("raw_sha256", ""),
                        recorded_at=data.get("recorded_at", ""),
                        path=paths.relative_to_root(file),
                        reference=data.get("reference", ""),
                    )
                )
    return records


def verify_assessment(run_id: str, tools: Iterable[str] | None = None) -> EvidenceVerification:
    """Re-hash only the artifacts belonging to one assessment."""
    return _verify(records_for_assessment(run_id, tools))


def all_records(tools: Iterable[str]) -> list[EvidenceRecord]:
    records: list[EvidenceRecord] = []
    for tool in tools:
        records.extend(records_for(tool))
    return records


def build_index(results: Iterable[ToolRunResult]) -> dict[str, Any]:
    """Build a machine-readable index of every evidence record produced."""
    entries: list[dict[str, Any]] = []
    for result in results:
        for record in result.evidence:
            entries.append(record.to_dict())
    index = {
        "generated_at": _now(),
        "record_count": len(entries),
        "records": entries,
    }
    write_json(paths.state_dir() / INDEX_NAME, index)
    return index


def verify(tools: Iterable[str]) -> EvidenceVerification:
    """Re-hash every referenced raw artifact and report drift."""
    return _verify(all_records(tools))


def _verify(records: Iterable[EvidenceRecord]) -> EvidenceVerification:
    verification = EvidenceVerification()
    for record in records:
        if not record.raw_artifact or not record.raw_sha256:
            continue
        verification.checked += 1
        artifact = paths.output_root() / record.raw_artifact
        if not artifact.is_file():
            verification.missing.append(record.raw_artifact)
            continue
        if sha256_file(artifact) == record.raw_sha256:
            verification.intact += 1
        else:
            verification.modified.append(record.raw_artifact)
    return verification


def coverage(
    results: Iterable[ToolRunResult],
    correlation_groups: Iterable[Any] = (),
) -> dict[str, Any]:
    """Summarize which findings have evidence attached."""
    total_findings = 0
    with_evidence = 0
    missing: list[str] = []
    for result in results:
        if not result.status.is_success:
            continue
        for finding in result.findings:
            total_findings += 1
            titles = {record.finding_title for record in result.evidence}
            if finding.title in titles:
                with_evidence += 1
            else:
                missing.append(f"{result.tool}: {finding.title}")
    return {
        "findings_total": total_findings,
        "findings_with_evidence": with_evidence,
        "findings_without_evidence": missing,
        "coverage_percent": (
            round(with_evidence / total_findings * 100, 1) if total_findings else 0.0
        ),
        "correlation_groups": len(list(correlation_groups)),
    }


def _now() -> str:
    from .models import utc_now_iso

    return utc_now_iso()


def render_evidence_index(records: Iterable[EvidenceRecord]) -> str:
    """Markdown table of evidence records, used by the text reports."""
    rows = [
        "| Tool | Finding | Endpoint | Raw artifact | SHA-256 (first 16) |",
        "| --- | --- | --- | --- | --- |",
    ]
    for record in records:
        rows.append(
            "| {tool} | {title} | {endpoint} | `{artifact}` | `{digest}` |".format(
                tool=record.tool,
                title=_cell(record.finding_title),
                endpoint=_cell(record.endpoint),
                artifact=_cell(record.raw_artifact),
                digest=record.raw_sha256[:16] or "n/a",
            )
        )
    return "\n".join(rows)


def _cell(value: str) -> str:
    return str(value or "-").replace("|", "\\|").replace("\n", " ")
