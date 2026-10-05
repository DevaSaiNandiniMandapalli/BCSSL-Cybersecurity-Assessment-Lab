"""Report isolation: one assessment's report describes only that assessment.

Regression tests for the bug where ``report --run run-002`` wrote a lab-wide
aggregate into ``reports/final/run-002.json``. A report named after an
assessment must contain that assessment's findings, tool records and raw
artifact paths and nothing else, while the earlier assessment stays intact as
historical evidence.

The tests fabricate completed runs through the normal persistence path
(``persist_result``) instead of invoking real tools, so they are offline and
deterministic.
"""

from __future__ import annotations

import json

import pytest

from bcssl import evidence as evidence_module, paths, pipeline, reporting, runs
from bcssl.models import RunStatus, sha256_file
from bcssl.severity import Severity

#: The real tool mix and per-tool finding counts observed in the lab's
#: run-002 against http://localhost:3001. Reproducing them keeps the
#: regression honest: an aggregate would show 278, not 139.
TOOL_PLAN: dict[str, tuple[str, ...]] = {
    "nmap": ("Open port 3001/tcp (nessus)",),
    "zap": (
        "Content Security Policy (CSP) Header Not Set",
        "Cross-Domain Misconfiguration",
        "Cross-Origin-Embedder-Policy Header Missing or Invalid",
        "Cross-Origin-Opener-Policy Header Missing or Invalid",
        "Dangerous JS Functions",
        "Deprecated Feature-Policy Header Set",
        "Timestamp Disclosure - Unix",
        "User Agent Disclosure",
        "Modern Web Application",
        "Non-Storable Content",
        "Storable and Cacheable Content",
    ),
    "nikto": tuple(
        f"Potentially interesting backup/cert file found (/backup-{n:03d}.tar.gz)"
        for n in range(104)
    ),
    "nuclei": tuple(
        f"Template match nuclei-{n:03d}" for n in range(19)
    ),
    "custom-scanner": (
        "Content-Security-Policy header is missing",
        "Strict-Transport-Security header is missing",
        "Discovered accessible resource: /ftp/",
        "Discovered accessible resource: /robots.txt",
    ),
}

EXPECTED_TOOL_COUNTS = {
    "nmap": 1,
    "zap": 11,
    "nikto": 104,
    "nuclei": 19,
    "custom-scanner": 4,
}
EXPECTED_TOTAL = 139  # sum(EXPECTED_TOOL_COUNTS.values())


# ---------------------------------------------------------------------------
# Helpers: fabricate a completed assessment without invoking a real tool
# ---------------------------------------------------------------------------
def build_tool_result(
    tool: str,
    assessment: str,
    titles: tuple[str, ...],
    *,
    status: RunStatus = RunStatus.OK,
    started: str = "2026-10-05T04:16:29Z",
    finished: str = "2026-10-05T04:37:13Z",
    exit_code: int | None = 0,
    errors: tuple[str, ...] = (),
    distinct_subjects: bool = True,
):
    """Create raw output, findings and hashed evidence for one tool run."""
    from bcssl.models import EvidenceRecord, Finding, ToolRunResult

    run_id = runs.run_id_for(tool, assessment)
    raw_dir = runs.layout(assessment).tool_raw_dir(tool)
    raw_dir.mkdir(parents=True, exist_ok=True)

    stdout = raw_dir / "stdout.txt"
    stdout.write_text(
        f"verbatim {tool} output for {assessment}\n" + "x" * 64 + "\n",
        encoding="utf-8",
    )
    stderr = raw_dir / "stderr.txt"
    stderr.write_text("\n".join(errors), encoding="utf-8")

    digest = sha256_file(stdout)
    findings = [
        Finding(
            tool=tool,
            category="security-header",
            severity=Severity.INFO if position >= 3 else Severity.MEDIUM,
            title=title,
            description=f"{tool} finding {position}.",
            target="http://localhost:3001",
            endpoint="http://localhost:3001",
            evidence="verbatim excerpt",
            recommendation="Remediate.",
            timestamp=finished,
            # A shared subject across tools is what correlation needs to
            # corroborate; distinct subjects keep the 104 nikto rows separate.
            subject=(
                f"missing-header:h{position}" if distinct_subjects else title[:40]
            ),
        )
        for position, title in enumerate(titles, start=1)
    ]

    evidence_dir = runs.layout(assessment).tool_evidence_dir(tool)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    records = []
    used: set[str] = set()
    for position, finding in enumerate(findings, start=1):
        record = EvidenceRecord(
            tool=tool,
            finding_title=finding.title,
            target=finding.target,
            endpoint=finding.endpoint,
            excerpt="verbatim excerpt",
            raw_artifact=paths.relative_to_root(stdout),
            raw_sha256=digest,
            recorded_at=finished,
            reference=finding.subject,
        )
        base = f"{run_id}--{_slug(finding.title)}--{digest[:8]}"
        name = f"{base}.json"
        if name in used:
            name = f"{base}--{position:03d}.json"
        used.add(name)
        record.path = paths.relative_to_root(evidence_dir / name)
        evidence_module.write_record(record)
        records.append(record)

    return ToolRunResult(
        tool=tool,
        status=status,
        target="http://localhost:3001",
        command=[tool, "-t", "http://localhost:3001"],
        tool_version=f"{tool} 1.0",
        exit_code=exit_code,
        started_at=started,
        finished_at=finished,
        duration_seconds=5.0,
        raw_artifacts=[paths.relative_to_root(stdout), paths.relative_to_root(stderr)],
        stdout_path=paths.relative_to_root(stdout),
        stderr_path=paths.relative_to_root(stderr),
        findings=findings,
        evidence=records,
        assessment=assessment,
        run_id=run_id,
        target_reachable=True,
        tool_available=status is not RunStatus.TOOL_NOT_INSTALLED,
        errors=list(errors),
    )


def _slug(text: str) -> str:
    from bcssl.runner import slugify

    return slugify(text)


def build_assessment(identifier: str, *, plan: dict | None = None):
    """Persist a full five-tool assessment under *identifier*."""
    selected = TOOL_PLAN if plan is None else plan
    results = []
    for tool, titles in selected.items():
        result = build_tool_result(tool, identifier, titles)
        pipeline.persist_result(result)
        results.append(result)
    return results


def tool_counts(document: dict) -> dict[str, int]:
    """Finding count per tool, read from a rendered report document."""
    counts: dict[str, int] = {}
    for entry in document["tools"]:
        counts[entry["tool"]] = counts.get(entry["tool"], 0) + entry["finding_count"]
    return counts


def all_strings(document: dict) -> list[str]:
    """Every string value in a report document, for leak assertions."""
    found: list[str] = []
    stack: list[object] = [document]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
        elif isinstance(item, str):
            found.append(item)
    return found


@pytest.fixture()
def two_assessments(config):
    """run-001 with a failed nmap, run-002 complete. Mirrors the real lab."""
    first = runs.allocate()
    second = runs.allocate()
    assert (first, second) == ("run-001", "run-002")

    # run-001: nmap never installed, the other four completed. The two runs
    # share finding titles on purpose so leakage is detectable.
    build_assessment(
        first,
        plan={
            "zap": TOOL_PLAN["zap"],
            "nikto": TOOL_PLAN["nikto"],
            "nuclei": TOOL_PLAN["nuclei"],
            "custom-scanner": TOOL_PLAN["custom-scanner"],
        },
    )
    failed = build_tool_result(
        "nmap",
        first,
        (),
        status=RunStatus.TOOL_NOT_INSTALLED,
        exit_code=None,
        errors=("TOOL NOT INSTALLED - nmap not on PATH; docker daemon unreachable",),
    )
    pipeline.persist_result(failed)

    build_assessment(second)
    return first, second


# ---------------------------------------------------------------------------
# A) run-001 findings cannot appear in a run-002 report
# ---------------------------------------------------------------------------
def test_run_001_findings_are_absent_from_a_run_002_report(config, two_assessments):
    first, second = two_assessments
    collected = pipeline.collect(config, assessment=second, verify_findings=False)
    payload = reporting.build_payload(collected)

    assert payload["report"]["assessment"] == second
    assert collected.scoped is True

    # Nothing from the earlier assessment may appear anywhere in the document.
    document = reporting.render_json(collected)
    assert first not in all_strings(reporting.build_payload(collected))
    assert f"reports/raw/{first}/" not in document
    assert f"reports/raw/{first}/" not in reporting.render_html(collected)
    assert f"reports/raw/{first}/" not in reporting.render_markdown(collected)


def test_raw_artifact_paths_in_a_run_002_report_are_run_002_only(
    config, two_assessments
):
    first, second = two_assessments
    collected = pipeline.collect(config, assessment=second, verify_findings=False)
    payload = reporting.build_payload(collected)

    artifacts: list[str] = []
    for entry in payload["tools"]:
        artifacts.extend(entry["raw_artifacts"])
    for record in payload["evidence"]:
        artifacts.append(record["raw_artifact"])

    assert artifacts, "the report must reference the raw artifacts it came from"
    assert all(f"reports/raw/{second}/" in item for item in artifacts)
    assert not any(f"reports/raw/{first}/" in item for item in artifacts)
    assert all((paths.output_root() / item).is_file() for item in artifacts)


def test_evidence_records_in_a_run_002_report_are_run_002_only(
    config, two_assessments
):
    first, second = two_assessments
    collected = pipeline.collect(config, assessment=second, verify_findings=False)

    assert collected.evidence_records
    for record in collected.evidence_records:
        assert second in record.path
        assert first not in record.path


# ---------------------------------------------------------------------------
# B) run-002 report contains exactly its own 139 findings
# ---------------------------------------------------------------------------
def test_run_002_report_holds_exactly_its_own_findings(config, two_assessments):
    _, second = two_assessments
    collected = pipeline.collect(config, assessment=second, verify_findings=False)
    payload = reporting.build_payload(collected)

    assert payload["executive_summary"]["total_findings"] == EXPECTED_TOTAL
    assert len(payload["findings"]) == EXPECTED_TOTAL
    assert len(collected.all_findings) == EXPECTED_TOTAL

    # The aggregate would be 277 (138 + 139); assert we are not seeing it.
    assert payload["executive_summary"]["total_findings"] != 277


def test_run_002_tool_counts_are_exactly_1_11_104_19_4(config, two_assessments):
    _, second = two_assessments
    collected = pipeline.collect(config, assessment=second, verify_findings=False)
    payload = reporting.build_payload(collected)

    assert tool_counts(payload) == EXPECTED_TOOL_COUNTS
    assert sum(EXPECTED_TOOL_COUNTS.values()) == EXPECTED_TOTAL

    # One tool record per tool, not one per (assessment, tool) pair.
    assert [entry["tool"] for entry in payload["tools"]] == list(TOOL_PLAN)


def test_normalized_finding_count_is_still_139_after_reporting(
    config, two_assessments
):
    """Report generation must not alter what was normalized for run-002."""
    _, second = two_assessments

    def normalized_total():
        total = 0
        for tool in TOOL_PLAN:
            document = json.loads(
                runs.layout(second).normalized_file(tool).read_text(encoding="utf-8")
            )
            assert document["assessment"] == second
            assert document["run_id"] == runs.run_id_for(tool, second)
            assert document["finding_count"] == len(document["findings"])
            total += document["finding_count"]
        return total

    assert normalized_total() == EXPECTED_TOTAL

    collected = pipeline.collect(config, assessment=second, verify_findings=False)
    reporting.write_reports(collected, formats=("json", "html", "md", "sarif"), run_id=second)

    assert normalized_total() == EXPECTED_TOTAL


# ---------------------------------------------------------------------------
# C) tool summaries are run-scoped
# ---------------------------------------------------------------------------
def test_tool_summary_entries_carry_only_their_own_run(config, two_assessments):
    first, second = two_assessments
    collected = pipeline.collect(config, assessment=second, verify_findings=False)

    summary = collected.tool_summary()
    assert len(summary) == len(TOOL_PLAN)
    for entry in summary:
        assert entry["assessment"] == second
        assert entry["run_id"] == runs.run_id_for(entry["tool"], second)
        assert first not in entry["run_id"]


def test_collecting_one_assessment_never_returns_another_tools_records(
    config, two_assessments
):
    _, second = two_assessments
    collected = pipeline.collect(config, assessment=second, verify_findings=False)

    assert {result.tool for result in collected.results} == set(TOOL_PLAN)
    assert len(collected.results) == len(TOOL_PLAN)
    assert all(result.assessment == second for result in collected.results)


def test_scan_metadata_is_scoped_to_the_selected_assessment(config, two_assessments):
    _, second = two_assessments
    collected = pipeline.collect(config, assessment=second, verify_findings=False)
    metadata = reporting.build_payload(collected)["scan_metadata"]

    assert set(metadata["tool_versions"]) == set(TOOL_PLAN)
    assert set(metadata["durations"]) == set(TOOL_PLAN)


# ---------------------------------------------------------------------------
# D) historical failed-tool state cannot contaminate a later run
# ---------------------------------------------------------------------------
def test_a_failed_historical_tool_is_absent_from_the_later_report(
    config, two_assessments
):
    first, second = two_assessments
    collected = pipeline.collect(config, assessment=second, verify_findings=False)
    payload = reporting.build_payload(collected)

    # run-001's nmap never ran; run-002's nmap did. Only the latter belongs here.
    nmap = [entry for entry in payload["tools"] if entry["tool"] == "nmap"]
    assert len(nmap) == 1
    assert nmap[0]["assessment"] == second
    assert nmap[0]["status"] == "ok"
    assert nmap[0]["exit_code"] == 0
    assert nmap[0]["finding_count"] == 1

    assert payload["executive_summary"]["tools_not_completed"] == []
    assert payload["executive_summary"]["tools_completed"] == len(TOOL_PLAN)
    assert not any(
        "docker daemon unreachable" in message for message in payload["errors"]
    )


def test_failed_run_is_still_reported_honestly_when_selected_alone(
    config, two_assessments
):
    """Scoping must not hide a real failure from its own report."""
    first, _ = two_assessments
    collected = pipeline.collect(config, assessment=first, verify_findings=False)
    payload = reporting.build_payload(collected)

    nmap = [entry for entry in payload["tools"] if entry["tool"] == "nmap"]
    assert len(nmap) == 1
    assert nmap[0]["status"] == "tool-not-installed"
    assert nmap[0]["finding_count"] == 0
    assert payload["report"]["assessment"] == first

    missing = payload["executive_summary"]["tools_not_completed"]
    assert [entry["tool"] for entry in missing] == ["nmap"]


def test_runs_command_keeps_both_assessments_separate(config, two_assessments):
    first, second = two_assessments
    # Generate run-002's report, which is what marks it complete.
    collected = pipeline.collect(config, assessment=second, verify_findings=False)
    reporting.write_reports(collected, formats=("json",), run_id=second)

    rows = {row["run_id"]: row for row in runs.summarise(runs.list_runs())}

    assert set(rows) == {first, second}
    # run-001: 4 tools ok + 1 failed, so 138 findings.
    assert rows[first]["tool_count"] == 5
    assert rows[first]["finding_count"] == 138
    assert rows[first]["status"] == "completed-with-errors"
    # run-002: all five tools completed with 139 findings.
    assert rows[second]["tool_count"] == 5
    assert rows[second]["finding_count"] == EXPECTED_TOTAL
    assert rows[second]["status"] == "completed"

    per_tool = {item["tool"]: item["finding_count"] for item in rows[second]["tools"]}
    assert per_tool == EXPECTED_TOOL_COUNTS


def test_a_later_run_cannot_overwrite_an_earlier_runs_state(
    config, two_assessments
):
    """run-002 must not rewrite run-001's manifest or normalized output."""
    first, second = two_assessments
    manifest_before = runs.read_manifest(first)
    normalized_before = {
        tool: runs.layout(first).normalized_file(tool).read_text(encoding="utf-8")
        for tool in ("zap", "custom-scanner")
    }

    collected = pipeline.collect(config, assessment=second, verify_findings=False)
    reporting.write_reports(collected, formats=("json",), run_id=second)

    assert runs.read_manifest(first) == manifest_before
    for tool, text in normalized_before.items():
        assert runs.layout(first).normalized_file(tool).read_text(encoding="utf-8") == text


def test_unknown_assessment_is_refused_rather_than_silently_widened(config):
    runs.allocate()
    with pytest.raises(runs.RunIdError):
        pipeline.collect(config, assessment="run-099")


# ---------------------------------------------------------------------------
# E) all four report formats use the same isolated dataset
# ---------------------------------------------------------------------------
def test_all_four_formats_describe_only_run_002(config, two_assessments):
    first, second = two_assessments
    collected = pipeline.collect(config, assessment=second, verify_findings=False)
    written = reporting.write_reports(
        collected, formats=("html", "json", "md", "sarif"), run_id=second
    )

    assert set(written) == {"html", "json", "md", "sarif"}
    for path in written.values():
        assert path.is_file()
        assert path.name == f"{second}{path.suffix}"

    html = written["html"].read_text(encoding="utf-8")
    markdown = written["md"].read_text(encoding="utf-8")
    document = json.loads(written["json"].read_text(encoding="utf-8"))
    sarif_log = json.loads(written["sarif"].read_text(encoding="utf-8"))

    # JSON is the reference dataset.
    assert document["report"]["assessment"] == second
    assert document["executive_summary"]["total_findings"] == EXPECTED_TOTAL
    assert tool_counts(document) == EXPECTED_TOOL_COUNTS

    # The other three must agree with it.
    for text in (html, markdown):
        assert f"reports/raw/{first}/" not in text
        assert f"reports/raw/{second}/" in text

    # SARIF: one run object per tool, and the totals must match the JSON report.
    sarif_counts = {
        entry["tool"]["driver"]["name"]: entry["properties"]["findingCount"]
        for entry in sarif_log["runs"]
    }
    assert sarif_counts == EXPECTED_TOOL_COUNTS
    assert sum(sarif_counts.values()) == EXPECTED_TOTAL
    assert len(sarif_log["version"]) and sarif_log["version"] == "2.1.0"
    assert sarif_log["$schema"].endswith("sarif-schema-2.1.0.json")

    # SARIF locates results by endpoint, not by raw artifact path, so the
    # check is that the document carries no other assessment's paths and that
    # every result belongs to the authorized target.
    serialized = json.dumps(sarif_log)
    assert f"reports/raw/{first}/" not in serialized
    for entry in sarif_log["runs"]:
        for result in entry["results"]:
            for location in result.get("locations", []):
                uri = location["physicalLocation"]["artifactLocation"]["uri"]
                assert uri.startswith("http://localhost:3001")


def test_evidence_integrity_in_a_scoped_report_checks_only_that_assessment(
    config, two_assessments
):
    first, second = two_assessments
    collected = pipeline.collect(config, assessment=second, verify_findings=False)
    integrity = reporting.build_payload(collected)["scan_metadata"]["evidence_integrity"]

    # Every record carried by the report is re-hashed, not just the distinct
    # artifacts behind them.
    expected = sum(
        1 for record in collected.evidence_records if record.raw_artifact and record.raw_sha256
    )
    assert expected == EXPECTED_TOTAL
    assert integrity["checked"] == expected
    assert integrity["intact"] == expected
    assert integrity["ok"] is True
    assert integrity["modified"] == []
    assert integrity["missing"] == []


def test_drift_in_an_earlier_run_is_not_attributed_to_a_later_report(
    config, two_assessments
):
    """run-001 tampering must not make run-002's integrity block fail."""
    first, second = two_assessments
    stale_artifact = runs.layout(first).tool_raw_dir("zap") / "stdout.txt"
    stale_artifact.write_text("tampered in an earlier run\n", encoding="utf-8")

    assert evidence_module.verify_assessment(first).ok is False

    collected = pipeline.collect(config, assessment=second, verify_findings=False)
    integrity = reporting.build_payload(collected)["scan_metadata"]["evidence_integrity"]

    assert integrity["ok"] is True
    assert integrity["modified"] == []
    assert all(first not in item for item in integrity["modified"])
    assert evidence_module.verify_assessment(second).ok is True


def test_evidence_hashes_stay_valid_in_both_assessments(config, two_assessments):
    first, second = two_assessments
    for identifier in (first, second):
        check = evidence_module.verify_assessment(identifier)
        assert check.checked > 0, identifier
        assert check.ok, f"{identifier}: {check.modified} {check.missing}"


def test_reports_for_both_assessments_can_be_generated_side_by_side(
    config, two_assessments
):
    first, second = two_assessments
    for identifier in (first, second):
        collected = pipeline.collect(
            config, assessment=identifier, verify_findings=False
        )
        written = reporting.write_reports(
            collected, formats=("json", "sarif"), run_id=identifier
        )
        assert written["json"].name == f"{identifier}.json"
        assert written["sarif"].name == f"{identifier}.sarif"

    first_document = json.loads(
        runs.layout(first).report_file("json").read_text(encoding="utf-8")
    )
    second_document = json.loads(
        runs.layout(second).report_file("json").read_text(encoding="utf-8")
    )

    assert first_document["report"]["assessment"] == first
    assert second_document["report"]["assessment"] == second
    assert first_document["executive_summary"]["total_findings"] == 138
    assert second_document["executive_summary"]["total_findings"] == EXPECTED_TOTAL


# ---------------------------------------------------------------------------
# Unscoped collection is still available for lab-wide views
# ---------------------------------------------------------------------------
def test_collect_without_an_assessment_still_spans_every_run(config, two_assessments):
    collected = pipeline.collect(config, verify_findings=False)

    assert collected.scoped is False
    assert collected.assessment == ""
    # 138 from run-001 plus 139 from run-002.
    assert len(collected.all_findings) == 138 + EXPECTED_TOTAL