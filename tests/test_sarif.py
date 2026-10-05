"""SARIF 2.1.0 export: structure, severity mapping, isolation and honesty.

Every assertion here checks that the export faithfully represents stored
findings - it never checks that the exporter invents anything.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bcssl import sarif
from bcssl.models import Finding, utc_now_iso
from bcssl.severity import Severity

TARGET = "http://localhost:3001"


def make_finding(
    tool: str = "zap",
    title: str = "Content-Security-Policy header is missing",
    severity: Severity = Severity.MEDIUM,
    subject: str = "missing-header:csp",
    *,
    description: str = "No CSP header was returned.",
    endpoint: str = TARGET,
    recommendation: str = "Send a Content-Security-Policy header.",
    evidence: str = "header absent",
    status: str = "CORROBORATED",
) -> Finding:
    return Finding(
        tool=tool,
        category="security-header",
        severity=severity,
        title=title,
        description=description,
        target=TARGET,
        endpoint=endpoint,
        evidence=evidence,
        recommendation=recommendation,
        timestamp=utc_now_iso(),
        verification_status=status,
        subject=subject,
        reference="pluginId 10038",
    )


def results_of(log: dict) -> list[dict]:
    return [result for run in log["runs"] for result in run["results"]]


def make_assessment(findings: list[Finding], config) -> object:
    """A minimal CollectedAssessment wrapping *findings*."""
    from bcssl.models import RunStatus, ToolRunResult
    from bcssl.pipeline import CollectedAssessment
    from bcssl.target import validate_target

    result = ToolRunResult(
        tool=findings[0].tool if findings else "zap",
        status=RunStatus.OK,
        target=TARGET,
        findings=list(findings),
    )
    assessment = CollectedAssessment(
        target=validate_target(config.authorized_url, config),
        config=config,
        results=[result],
    )
    from bcssl.correlation import correlate

    assessment.correlation = correlate(assessment.all_findings)
    return assessment


# ---------------------------------------------------------------------------
# Structure
# ---------------------------------------------------------------------------
def test_document_declares_sarif_2_1_0():
    log = sarif.build([make_finding()], TARGET)
    assert log["version"] == "2.1.0"
    assert log["$schema"].startswith("https://")
    assert "sarif-schema-2.1.0" in log["$schema"]


def test_document_has_at_least_one_run():
    log = sarif.build([make_finding()], TARGET)
    assert isinstance(log["runs"], list) and log["runs"]
    assert log["runs"][0]["tool"]["driver"]["name"] == "zap"


def test_document_is_json_serialisable():
    log = sarif.build([make_finding()], TARGET)
    assert json.loads(json.dumps(log)) == log


def test_validate_accepts_a_generated_document():
    log = sarif.build([make_finding(), make_finding(tool="nmap", subject="service:http")], TARGET)
    assert sarif.validate(log) == []


def test_validate_rejects_a_bad_version():
    log = sarif.build([make_finding()], TARGET)
    log["version"] = "1.0.0"
    assert any("version" in problem for problem in sarif.validate(log))


def test_validate_rejects_missing_runs():
    assert sarif.validate({"version": "2.1.0", "$schema": "x", "runs": []})


def test_validate_rejects_a_result_without_a_rule():
    log = sarif.build([make_finding()], TARGET)
    log["runs"][0]["results"][0]["ruleId"] = "not-declared"
    assert any("matching rule" in problem for problem in sarif.validate(log))


def test_validate_rejects_an_invalid_level():
    log = sarif.build([make_finding()], TARGET)
    log["runs"][0]["results"][0]["level"] = "critical"
    assert any("not a SARIF level" in problem for problem in sarif.validate(log))


def test_validate_rejects_a_missing_message():
    log = sarif.build([make_finding()], TARGET)
    del log["runs"][0]["results"][0]["message"]
    assert any("message.text" in problem for problem in sarif.validate(log))


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "severity,expected_level",
    [
        (Severity.CRITICAL, sarif.SARIF_ERROR),
        (Severity.HIGH, sarif.SARIF_ERROR),
        (Severity.MEDIUM, sarif.SARIF_WARNING),
        (Severity.LOW, sarif.SARIF_WARNING),
        (Severity.INFO, sarif.SARIF_NOTE),
    ],
)
def test_severity_maps_to_a_sarif_level(severity, expected_level):
    assert sarif.severity_to_level(severity.value) == expected_level


def test_only_three_sarif_levels_are_used():
    findings = [make_finding(severity=level) for level in Severity]
    log = sarif.build(findings, TARGET)
    levels = {result["level"] for result in results_of(log)}
    assert levels <= {sarif.SARIF_ERROR, sarif.SARIF_WARNING, sarif.SARIF_NOTE}


def test_unknown_severity_falls_back_to_the_lowest_level():
    assert sarif.severity_to_level("WEIRD") == sarif.SARIF_NOTE


def test_lab_severity_is_preserved_alongside_the_sarif_level():
    log = sarif.build([make_finding(severity=Severity.MEDIUM)], TARGET)
    result = results_of(log)[0]
    assert result["level"] == sarif.SARIF_WARNING
    assert result["properties"]["severity"] == "MEDIUM"


def test_security_severity_is_lab_based_not_cvss():
    log = sarif.build([make_finding(severity=Severity.HIGH)], TARGET)
    properties = results_of(log)[0]["properties"]
    assert properties["security-severity"] == "7.5"
    assert "not a CVSS" in properties["security-severity-basis"]


# ---------------------------------------------------------------------------
# One run per tool
# ---------------------------------------------------------------------------
def test_each_tool_gets_its_own_run():
    findings = [
        make_finding(tool="zap", subject="missing-header:csp"),
        make_finding(tool="custom-scanner", subject="missing-header:csp"),
        make_finding(tool="nuclei", subject="exposure:robots-txt"),
    ]
    log = sarif.build(findings, TARGET)
    names = sorted(run["tool"]["driver"]["name"] for run in log["runs"])
    assert names == ["custom-scanner", "nuclei", "zap"]


def test_same_finding_from_two_tools_stays_two_results():
    findings = [
        make_finding(tool="zap", subject="missing-header:csp"),
        make_finding(tool="custom-scanner", subject="missing-header:csp"),
    ]
    log = sarif.build(findings, TARGET)
    assert len(results_of(log)) == 2
    assert all(result["ruleId"] == "missing-header:csp" for result in results_of(log))


def test_result_count_equals_finding_count():
    findings = [make_finding(title=f"Finding {index}") for index in range(7)]
    log = sarif.build(findings, TARGET)
    assert len(results_of(log)) == 7


def test_nothing_is_deduplicated_or_merged():
    """Correlation groups findings; SARIF must not collapse anything."""
    findings = [
        make_finding(tool="zap", subject="missing-header:csp", endpoint=f"{TARGET}/a"),
        make_finding(tool="zap", subject="missing-header:csp", endpoint=f"{TARGET}/b"),
    ]
    log = sarif.build(findings, TARGET)
    assert len(results_of(log)) == 2
    assert len({result["partialFingerprints"]["bcsslFingerprint/v1"] for result in results_of(log)}) == 2


# ---------------------------------------------------------------------------
# Correlated findings
# ---------------------------------------------------------------------------
def test_corroborated_status_is_carried_through():
    findings = [
        make_finding(tool="zap", subject="missing-header:csp", status="CORROBORATED"),
        make_finding(tool="custom-scanner", subject="missing-header:csp", status="CORROBORATED"),
    ]
    log = sarif.build(findings, TARGET)
    assert {result["properties"]["verificationStatus"] for result in results_of(log)} == {
        "CORROBORATED"
    }


def test_corroborated_finding_shares_one_rule():
    findings = [
        make_finding(tool="zap", subject="missing-header:csp"),
        make_finding(tool="custom-scanner", subject="missing-header:csp"),
    ]
    log = sarif.build(findings, TARGET)
    for run in log["runs"]:
        assert [rule["id"] for rule in run["tool"]["driver"]["rules"]] == ["missing-header:csp"]


def test_single_tool_observation_status_is_carried_through():
    log = sarif.build([make_finding(status="SINGLE-TOOL OBSERVATION")], TARGET)
    assert results_of(log)[0]["properties"]["verificationStatus"] == "SINGLE-TOOL OBSERVATION"


def test_distinct_subjects_produce_distinct_rules():
    findings = [
        make_finding(subject="missing-header:csp"),
        make_finding(subject="missing-header:hsts"),
        make_finding(subject="missing-header:nosniff"),
    ]
    log = sarif.build(findings, TARGET)
    rule_ids = {rule["id"] for rule in log["runs"][0]["tool"]["driver"]["rules"]}
    assert rule_ids == {"missing-header:csp", "missing-header:hsts", "missing-header:nosniff"}


# ---------------------------------------------------------------------------
# Field mapping
# ---------------------------------------------------------------------------
def test_target_and_endpoint_map_to_a_physical_location():
    log = sarif.build([make_finding(endpoint=f"{TARGET}/ftp/")], TARGET)
    location = results_of(log)[0]["locations"][0]
    assert location["physicalLocation"]["artifactLocation"]["uri"] == f"{TARGET}/ftp/"


def test_endpoint_falls_back_to_the_target():
    log = sarif.build([make_finding(endpoint="")], TARGET)
    location = results_of(log)[0]["locations"][0]
    assert location["physicalLocation"]["artifactLocation"]["uri"] == TARGET


def test_description_is_included_in_the_message():
    log = sarif.build([make_finding(description="The header was absent.")], TARGET)
    message = results_of(log)[0]["message"]["text"]
    assert "The header was absent." in message


def test_recommendation_maps_to_a_fix():
    log = sarif.build([make_finding(recommendation="Set the header.")], TARGET)
    fix = results_of(log)[0]["fixes"][0]
    assert fix["description"]["text"] == "Set the header."


def test_evidence_is_carried_as_a_property():
    log = sarif.build([make_finding(evidence="pluginId 10038")], TARGET)
    assert results_of(log)[0]["properties"]["evidenceExcerpt"] == "pluginId 10038"


def test_evidence_property_is_truncated():
    log = sarif.build([make_finding(evidence="x" * 5000)], TARGET)
    assert len(results_of(log)[0]["properties"]["evidenceExcerpt"]) <= 2000


def test_tool_reference_is_preserved():
    log = sarif.build([make_finding()], TARGET)
    assert results_of(log)[0]["properties"]["toolReference"] == "pluginId 10038"


def test_invocation_records_the_authorization_statement(config):
    config.data["target"]["authorization_statement"] = "Authorized lab target only."
    log = sarif.build([make_finding()], TARGET, config=config)
    invocation = log["runs"][0]["invocations"][0]
    assert invocation["properties"]["authorization"] == "Authorized lab target only."
    assert invocation["executionSuccessful"] is True


def test_run_properties_carry_the_lab_and_target(config):
    log = sarif.build([make_finding()], TARGET, config=config)
    properties = log["runs"][0]["properties"]
    assert properties["target"] == TARGET
    assert properties["findingCount"] == 1


# ---------------------------------------------------------------------------
# Empty results
# ---------------------------------------------------------------------------
def test_no_findings_still_produces_a_valid_document():
    log = sarif.build([], TARGET)
    assert log["version"] == "2.1.0"
    assert len(log["runs"]) == 1
    assert log["runs"][0]["results"] == []
    assert sarif.validate(log) == []


def test_empty_document_states_that_nothing_was_found():
    log = sarif.build([], TARGET)
    assert "No findings" in log["runs"][0]["properties"]["note"]


def test_empty_document_invents_no_rules():
    log = sarif.build([], TARGET)
    assert "rules" not in log["runs"][0]["tool"]["driver"]


def test_empty_document_invents_no_results():
    log = sarif.build([], TARGET)
    assert results_of(log) == []


# ---------------------------------------------------------------------------
# Special characters
# ---------------------------------------------------------------------------
def test_special_characters_survive_a_json_round_trip():
    nasty = 'Title with "quotes", <angle> & ampersand, \\backslash\\, \u2028 line sep, \u00e9\u00df'
    log = sarif.build([make_finding(title=nasty, description=nasty, evidence=nasty)], TARGET)
    text = json.dumps(log, indent=2, ensure_ascii=False)
    restored = json.loads(text)
    assert results_of(restored)[0]["message"]["text"].count(nasty) >= 1
    assert sarif.validate(restored) == []


def test_special_characters_do_not_leak_raw_into_the_file(tmp_path):
    log = sarif.build([make_finding(title="<script>alert(1)</script>")], TARGET)
    destination = sarif.write(log, tmp_path / "out.sarif")
    text = destination.read_text(encoding="utf-8")
    # SARIF is JSON, not HTML: the payload stays data and is never rendered.
    assert "<script>" in text
    assert json.loads(text)["runs"][0]["results"][0]["message"]["text"].startswith("<script>")


def test_newlines_in_evidence_are_preserved():
    log = sarif.build([make_finding(evidence="line one\nline two\r\nline three")], TARGET)
    restored = json.loads(json.dumps(log))
    assert "line one\nline two" in results_of(restored)[0]["properties"]["evidenceExcerpt"]


def test_tab_and_control_characters_do_not_break_the_document():
    log = sarif.build([make_finding(evidence="a\tb\x07c")], TARGET)
    assert sarif.validate(json.loads(json.dumps(log))) == []


def test_unicode_rules_and_fingerprints_are_encoded():
    log = sarif.build([make_finding(subject="exposure:r\u00f6bots-txt", title="Caf\u00e9")], TARGET)
    restored = json.loads(json.dumps(log, ensure_ascii=False))
    assert sarif.validate(restored) == []
    assert results_of(restored)[0]["partialFingerprints"]["bcsslFingerprint/v1"]


# ---------------------------------------------------------------------------
# Ordering and file output
# ---------------------------------------------------------------------------
def test_results_are_ordered_most_severe_first():
    findings = [
        make_finding(title="info one", severity=Severity.INFO),
        make_finding(title="high one", severity=Severity.HIGH),
        make_finding(title="medium one", severity=Severity.MEDIUM),
    ]
    log = sarif.build(findings, TARGET)
    levels = [result["level"] for result in results_of(log)]
    assert levels == [sarif.SARIF_ERROR, sarif.SARIF_WARNING, sarif.SARIF_NOTE]


def test_write_produces_readable_utf8(tmp_path):
    log = sarif.build([make_finding(title="Caf\u00e9")], TARGET)
    destination = sarif.write(log, tmp_path / "nested" / "run-001.sarif")
    assert destination.name == "run-001.sarif"
    assert "Caf\u00e9" in destination.read_text(encoding="utf-8")
    assert json.loads(destination.read_text(encoding="utf-8"))["version"] == "2.1.0"


def test_write_ends_with_a_newline(tmp_path):
    destination = sarif.write(sarif.build([], TARGET), tmp_path / "run-001.sarif")
    assert destination.read_text(encoding="utf-8").endswith("}\n")


def test_render_uses_the_assessment_target(config):
    assessment = make_assessment([make_finding()], config)
    log = sarif.render(assessment)
    assert log["runs"][0]["properties"]["target"] == "http://localhost:3001"
    assert sarif.validate(log) == []
    assert len(results_of(log)) == len(assessment.all_findings)


def test_report_writes_a_sarif_file(config):
    from bcssl import paths as paths_module, reporting

    assessment = make_assessment([make_finding()], config)
    written = reporting.write_reports(assessment, formats=("sarif",))
    destination = written["sarif"]
    assert destination.suffix == ".sarif"
    assert destination.parent == paths_module.final_dir()
    log = json.loads(destination.read_text(encoding="utf-8"))
    assert log["version"] == "2.1.0"
    assert sarif.validate(log) == []


def test_sarif_of_an_empty_assessment_is_valid(config):
    from bcssl import pipeline

    log = sarif.render(pipeline.collect(config))
    assert sarif.validate(log) == []
    assert results_of(log) == []