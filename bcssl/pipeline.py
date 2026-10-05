"""Pipeline orchestration: run tools, collect results, build the assessment.

This module is the bridge between the individual runners and the reporting
layer. It persists every run to ``state/run-index.json`` so that a report can be
regenerated later without re-running any tool, which is what makes
``collect-results`` meaningful.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from . import evidence as evidence_module
from . import paths, runs
from .config import LabConfig
from .correlation import CorrelationReport, correlate
from .models import (
    EvidenceRecord,
    Finding,
    RunStatus,
    ToolRunResult,
    read_json,
    utc_now_iso,
    write_json,
)
from .runners import resolve_runner
from .target import TargetValidation, describe_scope, validate_target


# ---------------------------------------------------------------------------
# Running
# ---------------------------------------------------------------------------
def run_tool(
    name: str,
    config: LabConfig,
    *,
    url: str | None = None,
    options: dict[str, Any] | None = None,
    skip_reachability: bool = False,
    run_id: str | None = None,
    assessment: str | None = None,
) -> ToolRunResult:
    """Run one tool through the full runner contract.

    Args:
        assessment: existing assessment to join. When omitted, a new unique
            assessment identifier is allocated so the run cannot overwrite
            earlier output.
    """
    runner_class = resolve_runner(name)
    if assessment is None and run_id is None:
        assessment = runs.allocate()
    runner = runner_class(config, run_id=run_id, assessment=assessment)
    result = runner.run(
        url=url, options=options or {}, skip_reachability=skip_reachability
    )
    result.assessment = runner.assessment_id
    return result


def run_all(
    config: LabConfig,
    *,
    tools: Iterable[str] | None = None,
    url: str | None = None,
    options: dict[str, Any] | None = None,
    skip_reachability: bool = False,
    assessment: str | None = None,
) -> list[ToolRunResult]:
    """Run several tools in the configured order.

    Every tool shares one freshly allocated assessment identifier, so a full
    assessment is a single addressable unit with isolated output.

    Each tool is independent: one failing or missing tool never prevents the
    others from running, and every outcome is recorded.
    """
    selected = list(tools) if tools else list(config.tool_names())
    current = assessment or runs.allocate()
    results: list[ToolRunResult] = []
    for name in selected:
        results.append(
            run_tool(
                name,
                config,
                url=url,
                options=options or {},
                skip_reachability=skip_reachability,
                assessment=current,
            )
        )
    return results


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------
def _normalized_path(tool: str, run_id: str) -> Path:
    """Normalized findings file, namespaced by assessment when known."""
    assessment = runs.assessment_of("-".join(run_id.split("-")[:2]))
    if assessment:
        return runs.layout(assessment).normalized_file(tool)
    return paths.normalized_dir() / f"findings-{tool}-{run_id}.json"


def persist_result(result: ToolRunResult) -> Path:
    """Store a run's metadata, normalized findings and evidence index entry."""
    paths.ensure_layout()

    run_id = _run_id_for(result)
    assessment = result.assessment or runs.assessment_of("-".join(run_id.split("-")[:2]))

    # 1. Normalized findings in the documented eleven-key schema, isolated
    #    per assessment so a later run never overwrites an earlier one.
    write_json(
        _normalized_path(result.tool, run_id),
        {
            "tool": result.tool,
            "target": result.target,
            "status": result.status.value,
            "run_id": run_id,
            "assessment": assessment,
            "generated_at": utc_now_iso(),
            "finding_count": result.finding_count,
            "severity_counts": result.severity_counts(),
            "findings": [finding.to_dict() for finding in result.findings],
        },
    )

    # 2. Run index entry (includes correlation metadata for offline rebuilds).
    index = load_run_index()
    index["runs"][run_id] = {
        "tool": result.tool,
        "run_id": run_id,
        "assessment": assessment,
        "recorded_at": utc_now_iso(),
        **result.to_dict(),
    }
    index["updated_at"] = utc_now_iso()
    index.setdefault("created_at", index["updated_at"])
    write_json(paths.run_index_file(), index)

    # 3. Evidence index.
    evidence_module.build_index([result])

    # 4. Assessment manifest: the per-run record of what this assessment did.
    if assessment:
        runs.record_tool(
            assessment,
            result.tool,
            status=result.status.value,
            finding_count=result.finding_count,
            run_id_for_tool=run_id,
            started_at=result.started_at,
            finished_at=result.finished_at,
            errors=result.errors,
            warnings=result.warnings,
        )
    return paths.run_index_file()


def _run_id_for(result: ToolRunResult) -> str:
    """The run's own identifier.

    Taken from the result when the runner recorded it, and otherwise derived
    from the stored stdout path so results rebuilt from older state still work.
    """
    if result.run_id:
        return result.run_id
    if result.stdout_path:
        parts = Path(result.stdout_path).parts
        if len(parts) >= 2:
            return parts[-2]
    return f"{result.tool}-unknown"


def load_run_index() -> dict[str, Any]:
    data = read_json(paths.run_index_file(), default=None)
    if not isinstance(data, dict):
        return {"created_at": utc_now_iso(), "updated_at": utc_now_iso(), "runs": {}}
    data.setdefault("runs", {})
    data.setdefault("assessments", {})
    return data


def _assessment_of_entry(run_id: str, entry: dict[str, Any]) -> str:
    """The assessment an index entry belongs to.

    Prefers the recorded ``assessment`` field and falls back to the identifier
    itself, so entries written before the field existed are still scoped
    correctly instead of leaking into every report.
    """
    recorded = str(entry.get("assessment", "") or "")
    return recorded or runs.assessment_of(run_id) or ""


def results_from_index(assessment: str | None = None) -> list[ToolRunResult]:
    """Rebuild :class:`ToolRunResult` objects from the stored run index.

    Args:
        assessment: when given, only the tool runs belonging to that assessment
            (``run-003``) are returned. This is what keeps one assessment's
            report from absorbing another assessment's findings. When omitted,
            every stored run is returned, which is what the lab-wide overview
            views want.
    """
    index = load_run_index()
    rebuilt: list[ToolRunResult] = []
    for run_id, entry in index.get("runs", {}).items():
        if not isinstance(entry, dict):
            continue
        if assessment and _assessment_of_entry(run_id, entry) != assessment:
            continue
        status_value = str(entry.get("status", RunStatus.OK.value))
        try:
            status = RunStatus(status_value)
        except ValueError:
            status = RunStatus.FAILED
        findings = [
            Finding.from_dict(item)
            for item in entry.get("findings", [])
            if isinstance(item, dict)
        ]
        records = [
            EvidenceRecord(
                tool=item.get("tool", entry.get("tool", "")),
                finding_title=item.get("finding_title", ""),
                target=item.get("target", ""),
                endpoint=item.get("endpoint", ""),
                excerpt=item.get("excerpt", ""),
                raw_artifact=item.get("raw_artifact", ""),
                raw_sha256=item.get("raw_sha256", ""),
                recorded_at=item.get("recorded_at", ""),
                path=item.get("path", ""),
                reference=item.get("reference", ""),
            )
            for item in entry.get("evidence", [])
            if isinstance(item, dict)
        ]
        rebuilt.append(
            ToolRunResult(
                tool=entry.get("tool", ""),
                status=status,
                target=entry.get("target", ""),
                run_id=run_id,
                assessment=_assessment_of_entry(run_id, entry),
                command=list(entry.get("command", [])),
                tool_version=entry.get("tool_version", ""),
                exit_code=entry.get("exit_code"),
                started_at=entry.get("started_at", ""),
                finished_at=entry.get("finished_at", ""),
                duration_seconds=float(entry.get("duration_seconds", 0.0) or 0.0),
                raw_artifacts=list(entry.get("raw_artifacts", [])),
                stdout_path=entry.get("stdout_path", ""),
                stderr_path=entry.get("stderr_path", ""),
                findings=findings,
                evidence=records,
                errors=list(entry.get("errors", [])),
                warnings=list(entry.get("warnings", [])),
                notes=list(entry.get("notes", [])),
                install_hint=entry.get("install_hint", ""),
                tool_available=entry.get("tool_available"),
                target_reachable=entry.get("target_reachable"),
            )
        )
    return rebuilt


def clear_index() -> None:
    """Remove the stored run index (used by ``lab reset``)."""
    path = paths.run_index_file()
    if path.is_file():
        path.unlink()


# ---------------------------------------------------------------------------
# Collected assessment
# ---------------------------------------------------------------------------
@dataclass
class CollectedAssessment:
    """Everything the reporting layer needs."""

    target: TargetValidation | None
    config: LabConfig
    results: list[ToolRunResult] = field(default_factory=list)
    correlation: CorrelationReport = field(default_factory=CorrelationReport)
    evidence_records: list[EvidenceRecord] = field(default_factory=list)
    generated_at: str = field(default_factory=utc_now_iso)
    scope_text: str = ""
    warnings: list[str] = field(default_factory=list)
    #: Result of the lab's own re-checks against the authorized target.
    verification: Any = None
    verification_counts: dict[str, int] = field(default_factory=dict)
    #: Assessment this object describes (``run-003``). Empty means the object
    #: spans every stored assessment, which is only valid for lab-wide views.
    assessment: str = ""

    @property
    def scoped(self) -> bool:
        """True when the results belong to exactly one assessment."""
        return bool(self.assessment)

    @property
    def successful_runs(self) -> list[ToolRunResult]:
        return [result for result in self.results if result.status.is_success]

    @property
    def all_findings(self) -> list[Finding]:
        return [finding for result in self.results for finding in result.findings]

    def tool_summary(self) -> list[dict[str, Any]]:
        return [
            {
                "tool": result.tool,
                "run_id": result.run_id,
                "assessment": result.assessment,
                "status": result.status.value,
                "status_label": result.status.label,
                "tool_available": result.tool_available,
                "tool_version": result.tool_version,
                "exit_code": result.exit_code,
                "duration_seconds": round(result.duration_seconds, 2),
                "finding_count": result.finding_count,
                "severity_counts": result.severity_counts(),
                "errors": list(result.errors),
                "warnings": list(result.warnings),
                "raw_artifacts": list(result.raw_artifacts),
            }
            for result in self.results
        ]


def collect(
    config: LabConfig,
    *,
    url: str | None = None,
    verify_findings: bool = True,
    assessment: str | None = None,
) -> CollectedAssessment:
    """Collect stored runs, correlate findings, verify and index evidence.

    Args:
        config: active lab configuration.
        url: optional target override (still validated).
        verify_findings: when true, re-check the conditions tools reported
            against the authorized target so findings can be marked DETECTED.
            Skipped automatically when the target is unreachable.
        assessment: restrict the collected data to one assessment (``run-003``).
            Every finding, tool record, raw artifact path, correlation group,
            verification result and evidence record then comes from that
            assessment alone, so a report can never absorb an earlier run's
            output. When omitted, every stored run is collected, which is only
            appropriate for a lab-wide overview.
    """
    paths.ensure_layout()
    if assessment:
        # Refuse a malformed or unknown identifier rather than silently
        # falling back to a lab-wide collection.
        assessment = runs.resolve(assessment)
    results = results_from_index(assessment)
    findings = [finding for result in results for finding in result.findings]
    correlation = correlate(findings)

    records = [
        record for result in results for record in result.evidence
    ]
    if not records:
        if assessment:
            records = evidence_module.records_for_assessment(
                assessment, config.tool_names()
            )
        else:
            records = evidence_module.all_records(config.tool_names())

    target_url = url or config.authorized_url
    validation = validate_target(target_url, config)

    assessment_obj = CollectedAssessment(
        target=validation,
        config=config,
        results=results,
        correlation=correlation,
        evidence_records=records,
        scope_text=describe_scope(config),
        assessment=assessment or "",
    )

    # Independent verification of what the tools claimed. Only upgrades
    # statuses; it never creates or removes a finding.
    if verify_findings and findings and validation.ok:
        from .verify import apply_verification, verify

        result = verify(findings, config, url=validation.url)
        assessment_obj.verification = result
        if result.reachable:
            assessment_obj.verification_counts = apply_verification(findings, result)
        else:
            assessment_obj.warnings.append(
                "Findings could not be independently verified because the "
                f"target did not respond ({result.error}). Findings are left at "
                "their correlated status."
            )
    elif findings:
        assessment_obj.verification_counts = {
            status: sum(
                1 for f in findings if f.verification_status == status
            )
            for status in (
                "CORROBORATED",
                "SINGLE-TOOL OBSERVATION",
                "DETECTED",
                "NOT VERIFIED",
            )
        }

    if not results:
        assessment_obj.warnings.append(
            "No scan results are available. Run a tool with "
            "'python -m bcssl run <tool>' before generating a report."
        )
    else:
        skipped = [
            result.tool
            for result in results
            if result.status is not RunStatus.OK
        ]
        if skipped:
            assessment_obj.warnings.append(
                "The following tools did not produce a normal result and are "
                f"excluded from the severity summary: {', '.join(skipped)}."
            )
    return assessment_obj


__all__ = [
    "CollectedAssessment",
    "clear_index",
    "collect",
    "describe_scope",
    "load_run_index",
    "persist_result",
    "results_from_index",
    "run_all",
    "run_tool",
]
