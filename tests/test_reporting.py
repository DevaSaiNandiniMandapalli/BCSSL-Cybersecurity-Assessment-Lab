"""Reporting: payload shape, honesty guarantees and HTML safety."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from bcssl import paths, reporting
from bcssl.config import LabConfig
from bcssl.models import (
    EvidenceRecord,
    Finding,
    RunStatus,
    ToolRunResult,
    utc_now_iso,
)
from bcssl.pipeline import CollectedAssessment
from bcssl.reporting import NO_RESULTS_MESSAGE
from bcssl.severity import Severity


def make_result(tool="zap", findings=None, status=RunStatus.OK, **kwargs) -> ToolRunResult:
    return ToolRunResult(
        tool=tool,
        status=status,
        target="http://localhost:3001",
        started_at=utc_now_iso(),
        finished_at=utc_now_iso(),
        duration_seconds=1.5,
        tool_version=kwargs.get("tool_version", "2.14.0"),
        exit_code=kwargs.get("exit_code", 0),
        findings=list(findings or []),
        errors=list(kwargs.get("errors", [])),
        warnings=list(kwargs.get("warnings", [])),
        evidence=list(kwargs.get("evidence", [])),
    )


def passing_answers(exercise) -> dict[str, str]:
    """Build one answer per question that satisfies its grading specification.

    Used by completion tests: they verify completion rules, not grading, so the
    answers must be valid without hard-coding content per exercise.
    """
    from bcssl.lab import quiz

    answers: dict[str, str] = {}
    for question in exercise.questions:
        kind = quiz.question_type(question)
        qid = str(question.get("id"))
        if kind == quiz.YES_NO:
            answers[qid] = "Yes, because the value is authorised by the configuration."
        elif kind == quiz.NUMBER:
            exact = question.get("exact")
            if exact is None:
                low = question.get("min_number", 0)
                answers[qid] = str(int(low) + 1)
            else:
                answers[qid] = str(exact)
        elif kind == quiz.LIST:
            answers[qid] = "\n".join(f"item {i}" for i in range(1, 5))
        else:
            keywords = [str(k) for k in question.get("expected_keywords", [])]
            if not keywords:
                keywords = ["answer"]
            answers[qid] = "My answer covers: " + ", ".join(keywords) + "."
    return answers


def make_finding(tool="zap", title="CSP Header Not Set", severity=Severity.MEDIUM, **kw) -> Finding:
    return Finding(
        tool=tool,
        category=kw.pop("category", "security-header"),
        severity=severity,
        title=title,
        description=kw.pop("description", "A description."),
        target="http://localhost:3001",
        endpoint=kw.pop("endpoint", "http://localhost:3001/"),
        evidence=kw.pop("evidence", "HTTP/1.1 200 OK"),
        recommendation=kw.pop("recommendation", "Add the header."),
        subject=kw.pop("subject", "missing-header:csp"),
    )


@pytest.fixture()
def empty_assessment(config: LabConfig) -> CollectedAssessment:
    from bcssl.target import validate_target

    return CollectedAssessment(
        target=validate_target(config.authorized_url, config),
        config=config,
        results=[],
        generated_at=utc_now_iso(),
    )


@pytest.fixture()
def populated_assessment(config: LabConfig) -> CollectedAssessment:
    from bcssl.correlation import correlate

    zap_findings = [
        make_finding("zap", "Content Security Policy (CSP) Header Not Set"),
        make_finding("zap", "X-Frame-Options Header Not Set", subject="missing-header:frame-options", endpoint="http://localhost:3001/admin"),
    ]
    custom_findings = [
        make_finding("custom-scanner", "Content-Security-Policy header is missing"),
    ]
    evidence = [
        EvidenceRecord(
            tool="zap",
            finding_title="Content Security Policy (CSP) Header Not Set",
            target="http://localhost:3001",
            endpoint="http://localhost:3001/",
            excerpt="HTTP/1.1 200 OK",
            raw_artifact="reports/raw/zap/zap-test/stdout.txt",
            raw_sha256="a" * 64,
        )
    ]
    results = [
        make_result("zap", zap_findings, evidence=evidence),
        make_result("custom-scanner", custom_findings),
        make_result(
            "nuclei",
            status=RunStatus.TOOL_NOT_INSTALLED,
            tool_version="",
            errors=["TOOL NOT INSTALLED - nuclei not on PATH"],
        ),
    ]
    findings = [f for result in results for f in result.findings]
    from bcssl.target import validate_target

    return CollectedAssessment(
        target=validate_target(config.authorized_url, config),
        config=config,
        results=results,
        correlation=correlate(findings),
        evidence_records=evidence,
        generated_at=utc_now_iso(),
    )


# ---------------------------------------------------------------------------
# Empty state
# ---------------------------------------------------------------------------
def test_empty_assessment_says_no_results_available(empty_assessment):
    payload = reporting.build_payload(empty_assessment)
    assert payload["report"]["has_results"] is False
    assert payload["executive_summary"]["message"] == NO_RESULTS_MESSAGE
    assert payload["findings"] == []
    assert NO_RESULTS_MESSAGE in reporting.render_html(empty_assessment)
    assert NO_RESULTS_MESSAGE in reporting.render_markdown(empty_assessment)


def test_empty_assessment_reports_zero_counts_not_fake_ones(empty_assessment):
    summary = reporting.build_payload(empty_assessment)["executive_summary"]
    assert summary["total_findings"] == 0
    assert summary["highest_severity"] is None
    assert summary["severity_counts"] == {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0,
    }


# ---------------------------------------------------------------------------
# Payload
# ---------------------------------------------------------------------------
def test_payload_top_level_sections(populated_assessment):
    payload = reporting.build_payload(populated_assessment)
    for key in (
        "report",
        "executive_summary",
        "scan_metadata",
        "tools",
        "findings",
        "correlation",
        "evidence",
        "limitations",
        "errors",
        "recommendations",
    ):
        assert key in payload, f"report must include '{key}'"


def test_payload_records_target_and_authorization(populated_assessment):
    report = reporting.build_payload(populated_assessment)["report"]
    assert report["target"] == "http://localhost:3001"
    assert "Authorized educational use only" in report["authorization_statement"]


def test_findings_use_exact_schema(populated_assessment):
    findings = reporting.build_payload(populated_assessment)["findings"]
    assert findings
    for finding in findings:
        assert set(finding) == {
            "tool", "category", "severity", "title", "description",
            "target", "endpoint", "evidence", "recommendation", "timestamp",
            "verification_status",
        }


def test_findings_carry_a_verification_status(populated_assessment):
    findings = reporting.build_payload(populated_assessment)["findings"]
    for finding in findings:
        assert finding["verification_status"] in {
            "DETECTED",
            "CORROBORATED",
            "SINGLE-TOOL OBSERVATION",
            "NOT VERIFIED",
            "TOOL UNAVAILABLE",
        }


def test_report_includes_verification_breakdown(populated_assessment):
    payload = reporting.build_payload(populated_assessment)
    assert "verification" in payload
    assert "status_counts" in payload["verification"]


def test_missing_tool_is_listed_and_explained(populated_assessment):
    payload = reporting.build_payload(populated_assessment)
    not_completed = payload["executive_summary"]["tools_not_completed"]
    assert any(entry["tool"] == "nuclei" for entry in not_completed)
    nuclei_entry = next(e for e in not_completed if e["tool"] == "nuclei")
    assert nuclei_entry["status_label"] == "TOOL NOT INSTALLED"
    assert "not on PATH" in nuclei_entry["reason"]


def test_missing_tool_produces_a_scan_limitation(populated_assessment):
    limitations = reporting.build_payload(populated_assessment)["limitations"]
    assert any("nuclei" in limit and "no scan was performed" in limit for limit in limitations)


def test_limitations_always_state_manual_verification(populated_assessment):
    limitations = reporting.build_payload(populated_assessment)["limitations"]
    assert any("manual verification" in limit for limit in limitations)


def test_correlation_counts_are_honest(populated_assessment):
    summary = reporting.build_payload(populated_assessment)["correlation"]["summary"]
    # CSP is seen by zap and custom-scanner; X-Frame-Options only by zap.
    assert summary["confirmed_by_multiple_tools"] == 1
    assert summary["single_tool_observations"] >= 1
    assert summary["contributing_tools"] == ["custom-scanner", "zap"]


def test_tool_versions_recorded_including_unavailable(populated_assessment):
    versions = reporting.build_payload(populated_assessment)["scan_metadata"]["tool_versions"]
    assert versions["zap"] == "2.14.0"
    assert "nuclei" in versions


def test_errors_and_warnings_are_surfaced(populated_assessment):
    errors = reporting.build_payload(populated_assessment)["errors"]
    assert any(entry["tool"] == "nuclei" and entry["level"] == "error" for entry in errors)


def test_recommendations_are_deduplicated(populated_assessment):
    recommendations = reporting.build_payload(populated_assessment)["recommendations"]
    texts = [item["recommendation"] for item in recommendations]
    assert len(texts) == len(set(texts))
    assert texts


# ---------------------------------------------------------------------------
# Output formats
# ---------------------------------------------------------------------------
def test_json_report_is_valid_json(populated_assessment):
    payload = json.loads(reporting.render_json(populated_assessment))
    assert payload["report"]["target"] == "http://localhost:3001"


def test_markdown_report_has_required_sections(populated_assessment):
    text = reporting.render_markdown(populated_assessment)
    for heading in (
        "# ",
        "## Executive summary",
        "## Tool-by-tool results",
        "## Cross-tool correlation",
        "## Detailed findings",
        "## Recommendations",
        "## Evidence references",
        "## Scan limitations",
        "## Scan metadata",
    ):
        assert heading in text, f"missing section: {heading}"


def test_markdown_report_labels_confirmation(populated_assessment):
    text = reporting.render_markdown(populated_assessment)
    assert "Confirmed by multiple tools" in text
    assert "Single-tool observation" in text


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------
def test_html_is_self_contained(populated_assessment):
    html = reporting.render_html(populated_assessment)
    assert html.startswith("<!DOCTYPE html>")
    assert "<style>" in html
    # No external stylesheet, font or script requests.
    assert not re.search(r'<link[^>]+href="https?://', html)
    assert not re.search(r'src="https?://', html)


def test_html_supports_light_and_dark(populated_assessment):
    html = reporting.render_html(populated_assessment)
    assert 'data-theme="light"' in html
    assert 'html[data-theme="dark"]' in html
    assert "prefers-color-scheme: dark" in html
    assert "theme-toggle" in html
    assert "viewport" in html, "report must be responsive"


def test_html_shows_authorization_banner(populated_assessment):
    html = reporting.render_html(populated_assessment)
    assert "AUTHORIZED TARGET" in html
    assert "http://localhost:3001" in html


def test_html_flags_a_rejected_target(config: LabConfig):
    """A report built from an unauthorized target must say so, not hide it."""
    from bcssl.target import validate_target

    rejected = validate_target("http://example.com:3001", config)
    assert not rejected.ok
    assessment = CollectedAssessment(
        target=rejected,
        config=config,
        results=[],
        generated_at=utc_now_iso(),
    )
    payload = reporting.build_payload(assessment)
    assert payload["report"]["target_authorized"] is False
    html = reporting.render_html(assessment)
    assert "TARGET REJECTED" in html
    assert "AUTHORIZED TARGET" not in html


def test_html_escapes_untrusted_finding_text(config: LabConfig):
    """Tool-supplied text must never become live markup."""
    hostile = make_finding(
        "zap",
        title="<script>alert('xss')</script>",
        description="<img src=x onerror=alert(1)>",
        evidence="</pre><script>alert(2)</script>",
    )
    from bcssl.correlation import correlate

    assessment = CollectedAssessment(
        target=None,
        config=config,
        results=[make_result("zap", [hostile])],
        correlation=correlate([hostile]),
        generated_at=utc_now_iso(),
    )
    html = reporting.render_html(assessment)
    assert "<script>alert(" not in html
    assert "<img src=x" not in html
    assert "&lt;script&gt;" in html


def test_html_contains_all_severity_classes(populated_assessment):
    html = reporting.render_html(populated_assessment)
    for level in ("critical", "high", "medium", "low", "info"):
        assert f"sev-{level}" in html


def test_html_lists_evidence_with_hash(populated_assessment):
    html = reporting.render_html(populated_assessment)
    assert "Evidence references" in html
    assert "a" * 16 in html
    assert "Integrity check" in html


def test_html_shows_limitations_and_metadata(populated_assessment):
    html = reporting.render_html(populated_assessment)
    assert "Scan limitations" in html
    assert "Scan metadata" in html
    assert "Errors and warnings" in html


# ---------------------------------------------------------------------------
# Output files
# ---------------------------------------------------------------------------
def test_write_reports_creates_files(populated_assessment, config):
    written = reporting.write_reports(
        populated_assessment, formats=("html", "json", "md")
    )
    assert set(written) == {"html", "json", "md"}
    for path in written.values():
        assert path.is_file()
        assert path.stat().st_size > 0
        assert path.parent == paths.final_dir()


def test_write_reports_rejects_unknown_format(populated_assessment):
    with pytest.raises(ValueError):
        reporting.write_reports(populated_assessment, formats=("pdf",))


def test_latest_report_path_finds_generated_file(populated_assessment):
    reporting.write_reports(populated_assessment, formats=("html",))
    assert reporting.latest_report_path("html") is not None
