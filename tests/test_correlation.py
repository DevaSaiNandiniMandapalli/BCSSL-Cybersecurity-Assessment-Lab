"""Cross-tool correlation.

The critical property under test: a finding seen by one tool is never presented
as multi-tool confirmation.
"""

from __future__ import annotations

from pathlib import Path

from bcssl.correlation import CONFIRMED, SINGLE, correlate
from bcssl.models import Finding
from bcssl.parsers import custom, nuclei, zap
from bcssl.severity import Severity

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def finding(tool: str, subject: str, severity=Severity.MEDIUM, **kwargs) -> Finding:
    return Finding(
        tool=tool,
        category=kwargs.pop("category", "security-header"),
        severity=severity,
        title=kwargs.pop("title", subject),
        subject=subject,
        **kwargs,
    )


# ---------------------------------------------------------------------------
# Labels
# ---------------------------------------------------------------------------
def test_two_tools_on_the_same_fingerprint_are_confirmed():
    report = correlate(
        [
            finding("zap", "missing-header:csp", title="CSP Header Not Set"),
            finding("custom-scanner", "missing-header:csp", title="CSP header is missing"),
        ]
    )
    assert len(report.confirmed) == 1
    group = report.confirmed[0]
    assert group.label == CONFIRMED
    assert group.tools == ["custom-scanner", "zap"]
    assert group.is_confirmed


def test_one_tool_alone_is_a_single_tool_observation():
    report = correlate([finding("nuclei", "missing-header:csp")])
    assert report.confirmed == []
    assert len(report.single) == 1
    assert report.single[0].label == SINGLE
    assert report.single[0].is_confirmed is False


def test_same_tool_twice_is_not_confirmation():
    """Repetition by one tool is still a single-tool observation."""
    report = correlate(
        [
            finding("nikto", "missing-header:csp", endpoint="http://localhost:3001/"),
            finding("nikto", "missing-header:csp", endpoint="http://localhost:3001/admin"),
        ]
    )
    assert report.confirmed == []
    assert report.single[0].tools == ["nikto"]


def test_three_tools_confirming_one_issue():
    report = correlate(
        [
            finding("zap", "missing-header:frame-options"),
            finding("custom-scanner", "missing-header:frame-options"),
            finding("nuclei", "missing-header:frame-options"),
        ]
    )
    group = report.confirmed[0]
    assert group.tool_count == 3
    assert len(group.tools) == 3


# ---------------------------------------------------------------------------
# Different fingerprints are never merged
# ---------------------------------------------------------------------------
def test_different_subjects_stay_separate():
    report = correlate(
        [
            finding("zap", "missing-header:csp"),
            finding("zap", "missing-header:hsts"),
            finding("custom-scanner", "missing-header:csp"),
        ]
    )
    subjects = {group.subject for group in report.groups}
    assert subjects == {"missing-header:csp", "missing-header:hsts"}
    assert len(report.confirmed) == 1


def test_wording_similarity_alone_is_not_enough():
    """Two different issues with similar wording must not be merged."""
    report = correlate(
        [
            finding("zap", "missing-header:csp", title="Content-Security-Policy is absent"),
            finding("custom-scanner", "missing-header:permissions-policy", title="Content-Security-Policy is absent"),
        ]
    )
    assert report.confirmed == []
    assert len(report.groups) == 2


def test_title_slug_fingerprints_never_count_as_confirmed():
    """Wording-derived subjects are excluded from multi-tool confirmation."""
    report = correlate(
        [
            Finding(
                tool="zap",
                category="vulnerability",
                severity=Severity.HIGH,
                title="Some obscure issue",
                subject="",
            ),
            Finding(
                tool="nuclei",
                category="vulnerability",
                severity=Severity.HIGH,
                title="Some obscure issue",
                subject="",
            ),
        ]
    )
    # Identical wording produces the same slug, but a slug is not proof.
    assert len(report.groups) == 1
    assert report.groups[0].is_confirmed is False
    assert report.groups[0].label == SINGLE
    assert any("wording-derived" in note for note in report.notes)


# ---------------------------------------------------------------------------
# Deduplication and metadata
# ---------------------------------------------------------------------------
def test_identical_duplicates_from_one_tool_are_collapsed_and_counted():
    duplicate = finding("zap", "missing-header:csp", endpoint="http://localhost:3001/")
    report = correlate([duplicate, finding(
        "zap", "missing-header:csp", endpoint="http://localhost:3001/"
    )])
    assert len(report.groups[0].findings) == 1
    assert report.duplicate_count == 1
    assert any("duplicate" in note for note in report.notes)


def test_group_takes_the_most_severe_rating():
    report = correlate(
        [
            finding("zap", "missing-header:csp", severity=Severity.LOW, title="CSP low"),
            finding("nikto", "missing-header:csp", severity=Severity.HIGH, title="CSP high"),
        ]
    )
    group = report.groups[0]
    assert group.severity is Severity.HIGH
    assert group.title == "CSP high", "representative title should be the most severe"


def test_group_collects_endpoints_and_severity_counts():
    report = correlate(
        [
            finding("zap", "missing-header:csp", endpoint="http://localhost:3001/"),
            finding("custom-scanner", "missing-header:csp", endpoint="http://localhost:3001/admin"),
        ]
    )
    group = report.groups[0]
    assert group.endpoints == ["http://localhost:3001/", "http://localhost:3001/admin"]
    assert group.severity_counts["MEDIUM"] == 2


def test_empty_input_produces_empty_report():
    report = correlate([])
    assert report.groups == []
    assert report.confirmed == []
    assert report.summary()["total_groups"] == 0


# ---------------------------------------------------------------------------
# Real parser output
# ---------------------------------------------------------------------------
def test_real_zap_and_custom_output_correlates():
    """The shipped fixtures genuinely share three fingerprint subjects."""
    zap_findings = zap.parse(_fixture("zap-sample.json"), target="http://localhost:3001").findings
    custom_findings = custom.parse(
        _fixture("custom-scanner-sample.html"), target="http://localhost:3001"
    ).findings

    report = correlate(zap_findings + custom_findings)
    shared = {group.subject for group in report.confirmed}

    assert "missing-header:csp" in shared
    assert "missing-header:frame-options" in shared
    assert report.summary()["confirmed_by_multiple_tools"] >= 2
    # ZAP-only subjects must remain single-tool observations.
    assert "missing-header:hsts" not in shared
    assert any(
        group.subject == "missing-header:hsts" and not group.is_confirmed
        for group in report.groups
    )


def test_nuclei_fixture_does_not_falsely_confirm():
    nuclei_findings = nuclei.parse(_fixture("nuclei-sample.jsonl")).findings
    report = correlate(nuclei_findings)
    assert report.confirmed == [], "a single tool cannot confirm anything"
    assert len(report.single) == 3


def test_report_dict_exposes_label_and_tools():
    report = correlate(
        [
            finding("zap", "missing-header:csp"),
            finding("custom-scanner", "missing-header:csp"),
        ]
    )
    payload = report.to_dict()["groups"][0]
    assert payload["label"] == CONFIRMED
    assert payload["confirmed_by_multiple_tools"] is True
    assert payload["tool_count"] == 2
    assert len(payload["findings"]) == 2
