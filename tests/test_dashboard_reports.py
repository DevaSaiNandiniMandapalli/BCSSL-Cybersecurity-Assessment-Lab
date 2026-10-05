"""Dashboard Reports page: reading the report that already exists.

Regression tests for the Reports page showing "not found" even though the
run-002 reports were on disk.

The cause was routing, not data: ``/api/report`` was registered only for GET
while the page's "Generate consolidated report" button issued a POST, so the
POST router fell through to its generic 404 and the client rendered the error
string next to the button. Separately, the page had no read-only route at all,
so an existing report could only ever be seen by regenerating it.

These tests exercise the real handler over HTTP against fabricated, persisted
assessments. No scan is started and no target is contacted.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import pytest

from bcssl import evidence as evidence_module, paths, pipeline, reporting, runs
from bcssl.config import LabConfig
from bcssl.models import EvidenceRecord, Finding, RunStatus, ToolRunResult, sha256_file
from bcssl.runner import slugify
from bcssl.severity import Severity
from bcssl.web.server import DashboardHandler

#: Per-tool finding counts from the real run-002 against localhost:3001.
TOOL_TITLES: dict[str, tuple[str, ...]] = {
    "nmap": ("Open port 3001/tcp (nessus)",),
    "zap": tuple(f"ZAP alert {n:02d}" for n in range(1, 12)),
    "nikto": tuple(f"Potentially interesting backup file (/b-{n:03d}.tar.gz)" for n in range(104)),
    "nuclei": tuple(f"Nuclei template match {n:02d}" for n in range(1, 20)),
    "custom-scanner": (
        "Content-Security-Policy header is missing",
        "Strict-Transport-Security header is missing",
        "Discovered accessible resource: /ftp/",
        "Discovered accessible resource: /robots.txt",
    ),
}
EXPECTED_TOOL_COUNTS = {"nmap": 1, "zap": 11, "nikto": 104, "nuclei": 19, "custom-scanner": 4}
EXPECTED_TOTAL = 139
RUN_ONE_TOTAL = 138


# ---------------------------------------------------------------------------
# Fixtures: fabricate persisted assessments, then serve the dashboard over them
# ---------------------------------------------------------------------------
def _store_tool_run(tool: str, assessment: str, titles: tuple[str, ...], **kwargs):
    """Persist one tool run with raw output, findings and hashed evidence."""
    run_id = runs.run_id_for(tool, assessment)
    raw_dir = runs.layout(assessment).tool_raw_dir(tool)
    raw_dir.mkdir(parents=True, exist_ok=True)

    stdout = raw_dir / "stdout.txt"
    stdout.write_text(f"verbatim {tool} output for {assessment}\n", encoding="utf-8")
    stderr = raw_dir / "stderr.txt"
    stderr.write_text("", encoding="utf-8")
    digest = sha256_file(stdout)

    findings = [
        Finding(
            tool=tool,
            category="security-header",
            severity=Severity.INFO,
            title=title,
            description=f"{tool} finding {position}.",
            target="http://localhost:3001",
            endpoint="http://localhost:3001",
            evidence="excerpt",
            recommendation="Remediate.",
            timestamp="2026-10-05T08:00:00Z",
            subject=f"{tool}-{position}",
        )
        for position, title in enumerate(titles, start=1)
    ]

    evidence_dir = runs.layout(assessment).tool_evidence_dir(tool)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    records: list[EvidenceRecord] = []
    used: set[str] = set()
    for position, finding in enumerate(findings, start=1):
        record = EvidenceRecord(
            tool=tool,
            finding_title=finding.title,
            target=finding.target,
            endpoint=finding.endpoint,
            excerpt="excerpt",
            raw_artifact=paths.relative_to_root(stdout),
            raw_sha256=digest,
            recorded_at=finding.timestamp,
            reference=finding.subject,
        )
        name = f"{run_id}--{slugify(finding.title)}--{digest[:8]}"
        if name in used:
            name = f"{name}--{position:03d}"
        used.add(name)
        record.path = paths.relative_to_root(evidence_dir / f"{name}.json")
        evidence_module.write_record(record)
        records.append(record)

    result = ToolRunResult(
        tool=tool,
        status=kwargs.get("status", RunStatus.OK),
        target="http://localhost:3001",
        command=[tool, "-t", "http://localhost:3001"],
        tool_version=f"{tool} 1.0",
        exit_code=kwargs.get("exit_code", 0),
        started_at="2026-10-05T07:07:58Z",
        finished_at="2026-10-05T08:43:27Z",
        duration_seconds=5.0,
        raw_artifacts=[paths.relative_to_root(stdout), paths.relative_to_root(stderr)],
        stdout_path=paths.relative_to_root(stdout),
        stderr_path=paths.relative_to_root(stderr),
        findings=findings,
        evidence=records,
        assessment=assessment,
        run_id=run_id,
        target_reachable=True,
        tool_available=kwargs.get("exit_code", 0) == 0,
        errors=list(kwargs.get("errors", ())),
    )
    pipeline.persist_result(result)
    return result


@pytest.fixture(scope="module")
def seeded_runs():
    """run-001 with a failed nmap, run-002 complete, both reports written."""
    output_root = tempfile.mkdtemp(prefix="bcssl-reports-test-")
    previous = os.environ.get("BCSSL_OUTPUT_ROOT")
    os.environ["BCSSL_OUTPUT_ROOT"] = output_root
    try:
        paths.ensure_layout()

        first = runs.allocate()
        second = runs.allocate()
        assert (first, second) == ("run-001", "run-002")

        # run-001: four tools completed, nmap never ran.
        for tool in ("zap", "nikto", "nuclei", "custom-scanner"):
            _store_tool_run(tool, first, TOOL_TITLES[tool])
        _store_tool_run(
            "nmap",
            first,
            (),
            status=RunStatus.TOOL_NOT_INSTALLED,
            exit_code=None,
            errors=("TOOL NOT INSTALLED - nmap not on PATH",),
        )

        # run-002: all five tools completed.
        for tool, titles in TOOL_TITLES.items():
            _store_tool_run(tool, second, titles)

        # The reports a reviewer would open.
        config = LabConfig.load()
        for identifier in (first, second):
            collected = pipeline.collect(config, assessment=identifier, verify_findings=False)
            reporting.write_reports(
                collected,
                formats=("html", "json", "md", "sarif"),
                run_id=identifier,
            )

        yield first, second, output_root
    finally:
        if previous is None:
            os.environ.pop("BCSSL_OUTPUT_ROOT", None)
        else:
            os.environ["BCSSL_OUTPUT_ROOT"] = previous


@pytest.fixture(autouse=True)
def _use_seeded_output(seeded_runs, monkeypatch):
    """Point the lab at the seeded output root for the duration of each test.

    The shared ``isolated_output`` fixture in ``conftest.py`` redirects
    ``$BCSSL_OUTPUT_ROOT`` per test; this module-scoped fixture is defined
    closer to the test, so it runs afterwards and wins, which is what lets the
    live handler see the fabricated assessments.
    """
    monkeypatch.setenv("BCSSL_OUTPUT_ROOT", seeded_runs[2])


@pytest.fixture(scope="module")
def server(seeded_runs):
    """The dashboard served on loopback over the seeded, isolated output root."""
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), DashboardHandler)
    httpd.lab_config = LabConfig.load()
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()

    port = httpd.server_address[1]
    deadline = time.time() + 15
    while time.time() < deadline:
        try:
            conn = HTTPConnection("127.0.0.1", port, timeout=2)
            conn.request("GET", "/healthz")
            conn.getresponse().read()
            conn.close()
            break
        except OSError:
            time.sleep(0.05)

    yield port

    httpd.shutdown()
    httpd.server_close()


def get(port: int, path: str) -> tuple[int, object]:
    conn = HTTPConnection("127.0.0.1", port, timeout=90)
    conn.request("GET", path)
    response = conn.getresponse()
    body = response.read().decode("utf-8")
    status = response.status
    conn.close()
    try:
        return status, json.loads(body)
    except ValueError:
        return status, body


def post(port: int, path: str, payload: dict) -> tuple[int, object]:
    request = Request(
        f"http://127.0.0.1:{port}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=90) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        body = exc.read().decode("utf-8")
        try:
            return exc.code, json.loads(body)
        except ValueError:
            return exc.code, body


# ---------------------------------------------------------------------------
# The reported symptom
# ---------------------------------------------------------------------------
def test_report_post_is_routed_and_not_404(server):
    """The button's POST must not fall through to the generic 404."""
    status, payload = post(server, "/api/report", {})
    assert status == 200, payload
    assert "error" not in payload


def test_report_get_is_routed_and_not_404(server):
    status, payload = get(server, "/api/report")
    assert status == 200, payload
    assert "error" not in payload


# ---------------------------------------------------------------------------
# The page exposes the existing latest assessment report
# ---------------------------------------------------------------------------
def test_reports_page_exposes_the_existing_run_002_report(server, seeded_runs):
    _, second, _ = seeded_runs
    status, payload = get(server, "/api/report")

    assert status == 200
    assert payload["assessment"] == second
    assert payload["latest_run"] == second
    assert payload["has_results"] is True

    # The four files that already existed are listed, not regenerated.
    assert payload["files"] == {
        "html": f"reports/final/{second}.html",
        "json": f"reports/final/{second}.json",
        "md": f"reports/final/{second}.md",
        "sarif": f"reports/final/{second}.sarif",
    }

    summary = payload["report"]
    assert summary["available"] is True
    assert summary["assessment"] == second
    assert summary["findings"] == EXPECTED_TOTAL
    assert summary["tool_counts"] == EXPECTED_TOOL_COUNTS
    assert summary["severity_counts"]["MEDIUM"] >= 0
    assert summary["evidence"]["ok"] is True


def test_reports_page_lists_every_assessment_separately(server, seeded_runs):
    first, second, _ = seeded_runs
    _, payload = get(server, "/api/report")

    rows = {row["run_id"]: row for row in payload["runs"]}
    assert set(rows) == {first, second}
    # Lab-wide totals stay separate here; the Overview page shows their sum.
    assert rows[first]["finding_count"] == RUN_ONE_TOTAL
    assert rows[second]["finding_count"] == EXPECTED_TOTAL
    assert rows[second]["latest"] is True
    assert rows[first]["latest"] is False

    # Each row reports its own tools, including the one that failed.
    first_tools = {item["tool"]: item for item in rows[first]["tools"]}
    second_tools = {item["tool"]: item for item in rows[second]["tools"]}
    assert first_tools["nmap"]["status"] == "tool-not-installed"
    assert first_tools["nmap"]["finding_count"] == 0
    assert second_tools["nmap"]["status"] == "ok"
    assert second_tools["nmap"]["finding_count"] == 1


def test_overview_remains_lab_wide_while_reports_page_is_scoped(server, seeded_runs):
    """The intentional distinction must survive the fix."""
    first, second, _ = seeded_runs
    _, reports = get(server, "/api/report")
    _, state = get(server, "/api/state")

    assert state["total_findings"] == RUN_ONE_TOTAL + EXPECTED_TOTAL
    assert reports["report"]["findings"] == EXPECTED_TOTAL
    assert reports["report"]["findings"] < state["total_findings"]


# ---------------------------------------------------------------------------
# Selection
# ---------------------------------------------------------------------------
def test_run_query_parameter_selects_a_specific_assessment(server, seeded_runs):
    first, _, _ = seeded_runs
    status, payload = get(server, f"/api/report?{urlencode({'run': first})}")

    assert status == 200
    assert payload["assessment"] == first
    assert payload["report"]["assessment"] == first
    assert payload["report"]["findings"] == RUN_ONE_TOTAL
    assert payload["report"]["tool_counts"]["nmap"] == 0


def test_unknown_run_is_rejected_rather_than_silently_widened(server):
    status, payload = get(server, "/api/report?run=run-099")
    assert status == 400
    assert "error" in payload
    assert payload["has_results"] is False


def test_malformed_run_is_rejected(server):
    status, payload = get(server, "/api/report?run=not-a-run")
    assert status == 400
    assert "error" in payload


# ---------------------------------------------------------------------------
# Isolation: no earlier run leaks into the run-002 response
# ---------------------------------------------------------------------------
def test_run_002_response_does_not_leak_run_001_data(server, seeded_runs):
    first, second, _ = seeded_runs
    status, payload = get(server, "/api/report")

    assert status == 200
    assert payload["assessment"] == second

    # The selected assessment's own view is entirely run-002.
    assert f"reports/raw/{first}/" not in json.dumps(payload)
    assert all(f"reports/final/{first}." not in item for item in payload["files"].values())
    assert all(f"reports/final/{second}." in item for item in payload["files"].values())
    assert first not in json.dumps(payload["report"])

    # The per-assessment listing is a separate, labelled overview and may name
    # each run's own files; what it must not do is merge one run's data into
    # another run's report view.
    listing = {row["run_id"]: row for row in payload["runs"]}
    assert listing[second]["reports"] and all(
        second in item for item in listing[second]["reports"]
    )
    assert listing[first]["reports"] and all(
        first in item for item in listing[first]["reports"]
    )
    assert payload["report"]["source"] == f"reports/final/{second}.json"


def test_run_002_report_summary_counts_only_run_002_tools(server, seeded_runs):
    _, second, _ = seeded_runs
    _, payload = get(server, "/api/report")

    assert payload["report"]["tool_counts"] == EXPECTED_TOOL_COUNTS
    assert sum(payload["report"]["tool_counts"].values()) == EXPECTED_TOTAL
    assert payload["report"]["findings"] != RUN_ONE_TOTAL + EXPECTED_TOTAL


def test_stored_summary_reads_the_file_it_names(server, seeded_runs):
    """The numbers shown must be the numbers written to disk."""
    _, second, output_root = seeded_runs
    _, payload = get(server, "/api/report")

    source = payload["report"]["source"]
    assert source == f"reports/final/{second}.json"
    on_disk = json.loads((Path(output_root) / source).read_text(encoding="utf-8"))

    assert payload["report"]["findings"] == on_disk["executive_summary"]["total_findings"]
    assert payload["report"]["assessment"] == on_disk["report"]["assessment"]
    assert payload["report"]["tool_counts"] == {
        entry["tool"]: entry["finding_count"] for entry in on_disk["tools"]
    }


# ---------------------------------------------------------------------------
# GET must not write
# ---------------------------------------------------------------------------
def test_get_does_not_rewrite_any_file(server, seeded_runs):
    _, second, output_root = seeded_runs
    root = Path(output_root)
    watched = [
        root / "reports" / "final" / f"{second}.{ext}"
        for ext in ("html", "json", "md", "sarif")
    ]
    watched += sorted((root / "state" / "assessments").glob("*.json"))
    before = {item: (item.stat().st_mtime_ns, item.stat().st_size) for item in watched}
    assert before, "expected stored reports and manifests to exist"

    for _ in range(3):
        status, _ = get(server, "/api/report")
        assert status == 200

    after = {item: (item.stat().st_mtime_ns, item.stat().st_size) for item in watched}
    assert after == before, "GET /api/report must not rewrite stored artifacts"


# ---------------------------------------------------------------------------
# POST stays scoped to the latest assessment
# ---------------------------------------------------------------------------
def test_post_regenerates_only_the_latest_assessment(server, seeded_runs):
    first, second, _ = seeded_runs
    status, payload = post(server, "/api/report", {})

    assert status == 200
    assert payload["assessment"] == second
    assert payload["findings"] == EXPECTED_TOTAL
    assert set(payload["files"].values()) == {
        f"reports/final/{second}.{ext}" for ext in ("html", "json", "md")
    }
    assert all(f"reports/final/{first}." not in item for item in payload["files"].values())


def test_post_honours_an_explicit_run_and_does_not_contaminate(server, seeded_runs):
    first, second, _ = seeded_runs
    status, payload = post(server, "/api/report", {"run": first})

    assert status == 200
    assert payload["assessment"] == first
    assert payload["findings"] == RUN_ONE_TOTAL
    assert all(f"reports/final/{second}." not in item for item in payload["files"].values())

    # The later assessment is untouched by generating the earlier one.
    _, after = get(server, "/api/report")
    assert after["assessment"] == second
    assert after["report"]["findings"] == EXPECTED_TOTAL


def test_post_rejects_an_unknown_run(server):
    status, payload = post(server, "/api/report", {"run": "run-099"})
    assert status == 400
    assert "error" in payload


# ---------------------------------------------------------------------------
# Missing stored report is reported honestly
# ---------------------------------------------------------------------------
def test_summary_reports_no_stored_report_instead_of_inventing_one():
    """With no stored file the summary must be empty, not recomputed."""
    from bcssl.web.server import _stored_report_summary

    layout = runs.layout("run-404")
    summary = _stored_report_summary(layout, "run-404")

    assert summary["available"] is False
    assert summary["findings"] == 0
    assert summary["tool_counts"] == {}
    assert summary["assessment"] == "run-404"


# ---------------------------------------------------------------------------
# Frontend contract
# ---------------------------------------------------------------------------
def test_index_declares_the_reports_page(server):
    status, body = get(server, "/")
    page = str(body)

    assert status == 200
    assert 'id="tab-reports"' in page
    assert 'id="report-files"' in page
    assert 'id="make-report"' in page


def test_client_loads_reports_when_the_tab_opens(server):
    """The page must read the stored report, not only react to the button."""
    status, body = get(server, "/static/app.js")
    script = str(body)

    assert status == 200
    assert '"/api/report"' in script
    assert "loadReports" in script
    assert 'name === "reports"' in script
    # The generate button stays a POST; reading is a GET.
    assert 'api("/api/report", { method: "POST" })' in script


def test_report_endpoint_is_in_both_route_tables():
    """Guards the exact defect: GET registered, POST missing."""
    source = Path("bcssl/web/server.py")
    if not source.is_file():
        source = Path(__file__).resolve().parent.parent / "bcssl" / "web" / "server.py"
    text = source.read_text(encoding="utf-8")

    get_block = text.split("def do_GET")[1].split("def do_HEAD")[0]
    post_block = text.split("def do_POST")[1].split("# -- endpoints")[0]

    assert '"/api/report": self._api_reports' in get_block
    assert '"/api/report"' in post_block
    assert "self._api_report()" in post_block