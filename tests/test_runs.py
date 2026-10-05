"""Assessment run rotation and output isolation.

These tests prove the two properties that matter: consecutive runs never
overwrite each other, and every recorded artifact stays addressable with a
valid SHA-256 afterwards.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bcssl import evidence as evidence_module, paths, pipeline, reporting, runs
from bcssl.models import (
    EvidenceRecord,
    Finding,
    RunStatus,
    ToolRunResult,
    sha256_file,
)
from bcssl.severity import Severity


# ---------------------------------------------------------------------------
# Helpers: fabricate a completed run without invoking a real tool
# ---------------------------------------------------------------------------
def make_result(
    tool: str,
    assessment: str,
    *,
    titles: tuple[str, ...] = ("Header missing",),
    severity: Severity = Severity.MEDIUM,
    started: str = "2026-01-01T00:00:00Z",
    finished: str = "2026-01-01T00:00:05Z",
) -> ToolRunResult:
    """A stored run with raw output, findings and hashed evidence."""
    run_id = runs.run_id_for(tool, assessment)
    run_dir = runs.layout(assessment).tool_raw_dir(tool)
    run_dir.mkdir(parents=True, exist_ok=True)

    stdout = run_dir / "stdout.txt"
    stdout.write_text(f"verbatim {tool} output for {assessment}\n", encoding="utf-8")
    stderr = run_dir / "stderr.txt"
    stderr.write_text("", encoding="utf-8")

    digest = sha256_file(stdout)
    findings = [
        Finding(
            tool=tool,
            category="security-header",
            severity=severity,
            title=title,
            description="A finding.",
            target="http://localhost:3001",
            endpoint="http://localhost:3001",
            evidence="header absent",
            recommendation="Set the header.",
            timestamp=finished,
            subject="missing-header:csp",
        )
        for title in titles
    ]

    evidence_dir = runs.layout(assessment).tool_evidence_dir(tool)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    records: list[EvidenceRecord] = []
    for finding in findings:
        record = EvidenceRecord(
            tool=tool,
            finding_title=finding.title,
            target=finding.target,
            endpoint=finding.endpoint,
            excerpt="header absent",
            raw_artifact=paths.relative_to_root(stdout),
            raw_sha256=digest,
            recorded_at=finished,
            reference=finding.subject,
        )
        destination = evidence_dir / f"{abs(hash(finding.title)):012x}.json"
        record.path = paths.relative_to_root(destination)
        evidence_module.write_record(record)
        records.append(record)

    return ToolRunResult(
        tool=tool,
        status=RunStatus.OK,
        target="http://localhost:3001",
        command=[tool, "-t", "http://localhost:3001"],
        tool_version=f"{tool} 1.0",
        exit_code=0,
        started_at=started,
        finished_at=finished,
        duration_seconds=5.0,
        raw_artifacts=[paths.relative_to_root(stdout), paths.relative_to_root(stderr)],
        stdout_path=paths.relative_to_root(stdout),
        stderr_path=paths.relative_to_root(stderr),
        findings=findings,
        evidence=records,
        assessment=assessment,
        target_reachable=True,
        tool_available=True,
    )


# ---------------------------------------------------------------------------
# Identifier allocation
# ---------------------------------------------------------------------------
def test_first_allocation_is_run_001(config):
    assert runs.allocate() == "run-001"


def test_allocations_are_sequential(config):
    first = runs.allocate()
    second = runs.allocate()
    assert first == "run-001"
    assert second == "run-002"


def test_allocation_never_reuses_an_identifier(config):
    seen = [runs.allocate() for _ in range(5)]
    assert seen == ["run-001", "run-002", "run-003", "run-004", "run-005"]
    assert len(set(seen)) == len(seen)


def test_allocation_creates_isolated_directories(config):
    run_id = runs.allocate()
    layout = runs.layout(run_id)
    assert layout.raw_dir.is_dir()
    assert layout.normalized_dir.is_dir()
    assert layout.evidence_dir.is_dir()
    assert layout.metadata_file.is_file()


def test_sequence_survives_a_lost_state_directory(config):
    """A deleted sequence file must not cause an identifier to be reused."""
    first = runs.allocate()
    runs.layout(first).raw_dir.mkdir(parents=True, exist_ok=True)
    paths.state_dir().joinpath(runs.SEQUENCE_NAME).unlink()

    # The filesystem still shows run-001, so the next allocation must not
    # collide with it.
    second = runs.allocate()
    assert second != first


def test_allocation_respects_the_run_index(config):
    first = runs.allocate()
    make_result("nmap", first)
    paths.state_dir().joinpath(runs.SEQUENCE_NAME).unlink()
    paths.raw_dir().joinpath(first).rename(paths.raw_dir() / "moved-away")

    assert runs.allocate() != first


def test_layout_rejects_a_malformed_identifier(config):
    with pytest.raises(runs.RunIdError):
        runs.layout("not-a-run")
    with pytest.raises(runs.RunIdError):
        runs.layout("run-1")


def test_tool_run_id_is_scoped_to_the_assessment(config):
    assert runs.run_id_for("nmap", "run-007") == "run-007-nmap"


def test_assessment_of_accepts_both_forms(config):
    assert runs.assessment_of("run-003") == "run-003"
    assert runs.assessment_of("run-003-nmap") == "run-003"
    assert runs.assessment_of("nmap-20260101T000000Z") is None


def test_report_file_is_named_after_the_assessment(config):
    layout = runs.layout("run-004")
    assert layout.report_file("sarif").name == "run-004.sarif"
    assert layout.report_file(".json").name == "run-004.json"


# ---------------------------------------------------------------------------
# Isolation between consecutive runs
# ---------------------------------------------------------------------------
def test_two_consecutive_runs_do_not_overwrite_each_other(config):
    first = runs.allocate()
    second = runs.allocate()
    assert first != second

    a = make_result("nmap", first, titles=("Port 3001 open",))
    b = make_result("nmap", second, titles=("Port 3001 open (second run)",))

    assert a.assessment != b.assessment
    assert a.stdout_path != b.stdout_path
    assert Path(paths.output_root() / a.stdout_path).is_file()
    assert Path(paths.output_root() / b.stdout_path).is_file()

    # Each run's stored output still describes its own assessment.
    assert first in (paths.output_root() / a.stdout_path).read_text(encoding="utf-8")
    assert second in (paths.output_root() / b.stdout_path).read_text(encoding="utf-8")


def test_raw_output_is_namespaced_per_assessment(config):
    first = runs.allocate()
    second = runs.allocate()
    make_result("nikto", first)
    make_result("nikto", second)

    first_dir = paths.raw_dir() / first / f"{first}-nikto"
    second_dir = paths.raw_dir() / second / f"{second}-nikto"
    assert first_dir.is_dir()
    assert second_dir.is_dir()
    assert first_dir != second_dir


def test_normalized_output_is_namespaced_per_assessment(config):
    first = runs.allocate()
    second = runs.allocate()
    a = make_result("zap", first, titles=("CSP header not set",))
    b = make_result("zap", second, titles=("HSTS header not set",))

    pipeline.persist_result(a)
    pipeline.persist_result(b)

    first_file = runs.layout(first).normalized_file("zap")
    second_file = runs.layout(second).normalized_file("zap")
    assert first_file != second_file
    assert first_file.is_file() and second_file.is_file()

    first_titles = json.loads(first_file.read_text(encoding="utf-8"))["findings"]
    second_titles = json.loads(second_file.read_text(encoding="utf-8"))["findings"]
    assert [item["title"] for item in first_titles] == ["CSP header not set"]
    assert [item["title"] for item in second_titles] == ["HSTS header not set"]


def test_evidence_is_namespaced_per_assessment(config):
    first = runs.allocate()
    second = runs.allocate()
    make_result("nuclei", first, titles=("Missing HSTS",))
    make_result("nuclei", second, titles=("Missing CSP",))

    first_records = evidence_module.records_for_assessment(first)
    second_records = evidence_module.records_for_assessment(second)

    assert [record.finding_title for record in first_records] == ["Missing HSTS"]
    assert [record.finding_title for record in second_records] == ["Missing CSP"]

    # Every record is still reachable through the tool-wide view.
    combined = evidence_module.records_for("nuclei")
    assert len(combined) == 2


def test_evidence_records_do_not_overwrite(config):
    first = runs.allocate()
    second = runs.allocate()
    make_result("nmap", first, titles=("Open port",))
    make_result("nmap", second, titles=("Open port",))

    first_files = sorted((paths.evidence_dir() / first).rglob("*.json"))
    second_files = sorted((paths.evidence_dir() / second).rglob("*.json"))
    assert first_files and second_files
    assert set(first_files).isdisjoint(second_files)


def test_hash_collision_in_filenames_does_not_lose_records(config):
    """Two findings with the same title in different runs must both survive."""
    first = runs.allocate()
    second = runs.allocate()
    a = make_result("nmap", first, titles=("Same title",))
    b = make_result("nmap", second, titles=("Same title",))
    assert a.findings[0].title == b.findings[0].title
    assert len(evidence_module.records_for_assessment(first)) == 1
    assert len(evidence_module.records_for_assessment(second)) == 1


# ---------------------------------------------------------------------------
# Integrity across runs
# ---------------------------------------------------------------------------
def test_sha256_hashes_remain_valid_after_both_runs(config):
    first = runs.allocate()
    second = runs.allocate()
    make_result("nmap", first)
    make_result("nmap", second)

    for run_id in (first, second):
        check = evidence_module.verify_assessment(run_id)
        assert check.checked > 0, run_id
        assert check.ok, f"{run_id}: modified={check.modified} missing={check.missing}"


def test_a_second_run_does_not_invalidate_the_first_runs_hash(config):
    first = runs.allocate()
    make_result("nmap", first)
    before = evidence_module.verify_assessment(first)
    assert before.ok

    make_result("nmap", runs.allocate())

    after = evidence_module.verify_assessment(first)
    assert after.ok
    assert after.intact == before.intact


def test_modified_artifact_is_detected_within_its_run(config):
    run_id = runs.allocate()
    result = make_result("nmap", run_id)
    artifact = paths.output_root() / result.raw_artifacts[0]
    artifact.write_text("tampered", encoding="utf-8")

    check = evidence_module.verify_assessment(run_id)
    assert check.ok is False
    assert check.modified


# ---------------------------------------------------------------------------
# Manifests and report references
# ---------------------------------------------------------------------------
def test_manifest_records_each_tool(config):
    run_id = runs.allocate()
    pipeline.persist_result(make_result("nmap", run_id, started="s", finished="f"))
    pipeline.persist_result(make_result("zap", run_id, started="s", finished="f"))

    manifest = runs.read_manifest(run_id)
    assert manifest["run_id"] == run_id
    tools = {item["tool"]: item for item in manifest["tools"]}
    assert set(tools) == {"nmap", "zap"}
    assert tools["nmap"]["run_id"] == f"{run_id}-nmap"
    assert tools["zap"]["run_id"] == f"{run_id}-zap"


def test_manifest_records_failure_without_hiding_success(config):
    run_id = runs.allocate()
    pipeline.persist_result(make_result("nmap", run_id))
    failed = make_result("zap", run_id)
    failed.status = RunStatus.FAILED
    failed.errors = ["zap exited with code 3"]
    pipeline.persist_result(failed)

    manifest = runs.read_manifest(run_id)
    tools = {item["tool"]: item for item in manifest["tools"]}
    assert tools["nmap"]["status"] == "ok"
    assert tools["zap"]["status"] == "failed"
    assert "zap exited with code 3" in tools["zap"]["errors"]
    assert manifest["status"] == "completed-with-errors"


def test_reports_are_named_after_their_assessment(config):
    first = runs.allocate()
    second = runs.allocate()
    make_result("nmap", first)
    make_result("nmap", second)

    assessment = pipeline.collect(config)
    first_written = reporting.write_reports(assessment, formats=("html", "json"), run_id=first)
    second_written = reporting.write_reports(assessment, formats=("html", "json"), run_id=second)

    assert first_written["html"].name == "run-001.html"
    assert second_written["html"].name == "run-002.html"
    assert first_written["html"] != second_written["html"]
    assert first_written["html"].is_file() and second_written["html"].is_file()


def test_manifest_lists_generated_reports(config):
    run_id = runs.allocate()
    make_result("nmap", run_id)
    assessment = pipeline.collect(config)
    reporting.write_reports(assessment, formats=("html", "sarif"), run_id=run_id)

    manifest = runs.read_manifest(run_id)
    assert manifest["status"] == "completed"
    assert any(report.endswith(".sarif") for report in manifest["reports"])


def test_summarise_reports_per_run_totals(config):
    first = runs.allocate()
    second = runs.allocate()
    pipeline.persist_result(make_result("nmap", first))
    pipeline.persist_result(make_result("nmap", first))
    pipeline.persist_result(make_result("nmap", second))

    rows = {row["run_id"]: row for row in runs.summarise()}
    assert rows["run-001"]["tool_count"] == 1, "the same tool replaces its own entry"
    assert rows["run-002"]["finding_count"] == 1


def test_list_runs_is_ordered_and_complete(config):
    allocated = [runs.allocate() for _ in range(3)]
    assert runs.list_runs() == allocated
    assert runs.latest() == allocated[-1]


def test_resolve_rejects_an_unknown_assessment(config):
    runs.allocate()
    with pytest.raises(runs.RunIdError):
        runs.resolve("run-099")


def test_resolve_falls_back_to_the_latest(config):
    first = runs.allocate()
    last = runs.allocate()
    assert runs.resolve(None) == last
    assert runs.resolve(first) == first


def test_clean_removes_every_assessment_namespace(config):
    first = runs.allocate()
    second = runs.allocate()
    make_result("nmap", first)
    make_result("nmap", second)
    pipeline.persist_result(make_result("nmap", first))

    from bcssl import clean as clean_module

    clean_module.clean()

    leftovers = [
        item
        for item in paths.raw_dir().rglob("*")
        if item.is_file() and item.name != ".gitkeep"
    ]
    assert not leftovers