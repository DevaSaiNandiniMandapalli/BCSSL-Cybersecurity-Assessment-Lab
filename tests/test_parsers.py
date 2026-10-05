"""Parser behaviour for all five tools, including malformed input.

No test here contacts a target: every parser consumes a fixture file that
represents the tool's documented output format.
"""

from __future__ import annotations

import pytest

from bcssl.parsers import custom, nikto, nmap, nuclei, zap
from bcssl.severity import Severity

NORMALIZED_KEYS = {
    "tool",
    "category",
    "severity",
    "title",
    "description",
    "target",
    "endpoint",
    "evidence",
    "recommendation",
    "timestamp",
    "verification_status",
}


def assert_normalized(finding) -> None:
    assert set(finding.to_dict().keys()) == NORMALIZED_KEYS
    assert isinstance(finding.severity, Severity)
    assert finding.title
    assert finding.tool


# ---------------------------------------------------------------------------
# Nmap
# ---------------------------------------------------------------------------
def test_nmap_xml_parses_open_port_and_banner(fixture_text):
    result = nmap.parse(fixture_text("nmap-sample.xml"), target="http://localhost:3001")
    assert result.errors == []
    assert result.count == 2, "one open-port finding and one banner-disclosure finding"

    port_finding = result.findings[0]
    assert port_finding.tool == "nmap"
    assert port_finding.category == "open-port"
    assert port_finding.severity is Severity.INFO
    assert "3001/tcp" in port_finding.endpoint
    assert "http" in port_finding.title

    banner = result.findings[1]
    assert banner.category == "technology-disclosure"
    assert "Node.js" in banner.evidence


def test_nmap_findings_are_never_inflated(fixture_text):
    """Port discovery is not vulnerability assessment."""
    result = nmap.parse(fixture_text("nmap-sample.xml"))
    assert all(f.severity is Severity.INFO for f in result.findings)
    assert all(f.severity is not Severity.CRITICAL for f in result.findings)


def test_nmap_malformed_xml_reports_error_not_exception():
    result = nmap.parse("<nmaprun><host>", target="http://localhost:3001")
    assert result.findings == []
    assert result.errors and "could not be parsed" in result.errors[0]


def test_nmap_empty_output_reports_error():
    result = nmap.parse("", target="http://localhost:3001")
    assert result.findings == []
    assert result.errors


def test_nmap_handles_banner_noise_before_declaration(fixture_text):
    xml = f"Nmap scan report for localhost\n{fixture_text('nmap-sample.xml')}"
    result = nmap.parse(xml)
    assert result.count == 2


def test_nmap_no_open_ports_is_a_valid_result():
    xml = """<?xml version="1.0"?><nmaprun><host><status state="up"/>
    <ports><port protocol="tcp" portid="3001">
    <state state="closed" reason="conn-refused"/></port></ports></host></nmaprun>"""
    result = nmap.parse(xml, target="http://localhost:3001")
    assert result.findings == [], "a closed port is not a finding"
    assert result.errors == []
    assert any("no open ports" in note.lower() for note in result.notes)


# ---------------------------------------------------------------------------
# ZAP
# ---------------------------------------------------------------------------
def test_zap_parses_alerts_with_riskcode_mapping(fixture_text):
    result = zap.parse(fixture_text("zap-sample.json"), target="http://localhost:3001")
    assert result.errors == []
    assert result.count == 4

    severities = sorted(f.severity.value for f in result.findings)
    assert severities == ["LOW", "LOW", "MEDIUM", "MEDIUM"]

    csp = next(f for f in result.findings if "Content Security Policy" in f.title)
    assert csp.severity is Severity.MEDIUM
    assert csp.category == "security-header"
    assert csp.endpoint == "http://localhost:3001/"
    assert csp.subject == "missing-header:csp"
    assert csp.recommendation
    assert "pluginId 10038" in csp.reference

    clickjacking = next(f for f in result.findings if "clickjacking" in f.title.lower())
    assert clickjacking.subject == "missing-header:frame-options"


def test_zap_riskcode_is_not_invented_as_critical(fixture_text):
    result = zap.parse(fixture_text("zap-sample.json"))
    assert all(f.severity is not Severity.CRITICAL for f in result.findings)


def test_zap_subjects_align_with_other_tools(fixture_text):
    """A CSP alert must share a subject with the custom scanner's CSP finding."""
    result = zap.parse(fixture_text("zap-sample.json"))
    subjects = {f.subject for f in result.findings}
    assert "missing-header:csp" in subjects
    assert "missing-header:hsts" in subjects


def test_zap_empty_alerts_is_a_valid_result():
    result = zap.parse('{"@version":"2.14.0","alerts":[]}', target="http://localhost:3001")
    assert result.findings == []
    assert result.errors == []
    assert result.notes and "no alerts" in result.notes[0].lower()


def test_zap_invalid_json_reports_error():
    result = zap.parse("{not json", target="http://localhost:3001")
    assert result.findings == []
    assert result.errors


def test_zap_missing_alerts_array_reports_error():
    result = zap.parse('{"site":[]}', target="http://localhost:3001")
    assert result.findings == []
    assert result.errors


def test_zap_version_extracted_from_report(fixture_text):
    assert zap.version_from_report(fixture_text("zap-sample.json")) == "2.14.0"


# ---------------------------------------------------------------------------
# Nikto
# ---------------------------------------------------------------------------
def test_nikto_parses_items_and_osvdb(fixture_text):
    result = nikto.parse(fixture_text("nikto-sample.json"), target="http://localhost:3001")
    assert result.count >= 4
    for finding in result.findings:
        assert_normalized(finding)
        assert finding.tool == "nikto"


def test_nikto_uses_severity_marker_when_present(fixture_text):
    result = nikto.parse(fixture_text("nikto-sample.json"))
    by_reference = {f.reference: f for f in result.findings if f.reference}
    high = by_reference["OSVDB-12345"]
    assert high.severity is Severity.HIGH
    assert "Test issue description" in high.title

    # A "Severity: medium" marker is honoured even though OSVDB 0 means the
    # plugin has no OSVDB reference, so no reference string is emitted.
    medium = next(f for f in result.findings if "Cookie(s) without HttpOnly" in f.title)
    assert medium.severity is Severity.MEDIUM
    assert medium.reference == ""


def test_nikto_zero_osvdb_is_not_treated_as_a_reference(fixture_text):
    """OSVDB 0 means 'no reference', not 'issue 0'."""
    result = nikto.parse(fixture_text("nikto-sample.json"))
    for finding in result.findings:
        assert "OSVDB-0" not in finding.reference


def test_nikto_context_lines_are_not_findings(fixture_text):
    """Banner/context lines must not become findings."""
    result = nikto.parse(fixture_text("nikto-sample.json"))
    for finding in result.findings:
        assert not finding.title.lower().startswith("server:")
        assert not finding.title.lower().startswith("target ip")
        assert not finding.title.lower().startswith("nikto v")


def test_nikto_legacy_21x_object_format(fixture_text):
    """The 2.1.x JSON shape is an object with a 'vulnerabilities' array."""
    result = nikto.parse(fixture_text("nikto-2.1.6-real.json"), target="http://localhost:3001")
    assert result.errors == []
    assert result.count > 0
    titles = " ".join(f.title for f in result.findings)
    assert "X-XSS-Protection" in titles
    assert "/archive.sql" in titles
    assert "robots.txt" in titles


def test_nikto_legacy_records_carry_method_and_endpoint(fixture_text):
    result = nikto.parse(fixture_text("nikto-2.1.6-real.json"), target="http://localhost:3001")
    backup = [f for f in result.findings if "archive.sql" in f.title]
    assert backup, "the backup-file finding should be present"
    assert backup[0].endpoint == "http://localhost:3001/archive.sql"
    assert "HEAD" in backup[0].evidence


def test_nikto_legacy_subjects_align_with_other_tools(fixture_text):
    """robots.txt must correlate with the custom scanner's robots.txt finding."""
    subjects = {f.subject for f in nikto.parse(fixture_text("nikto-2.1.6-real.json")).findings}
    assert "exposure:robots-txt" in subjects
    assert "missing-header:xss-protection" in subjects
    assert "exposure:backup-file" in subjects


def test_nikto_found_items_are_informational(fixture_text):
    result = nikto.parse(fixture_text("nikto-sample.json"))
    found = [f for f in result.findings if f.subject.startswith("exposure:")]
    assert found
    assert all(f.severity is Severity.INFO for f in found)


def test_nikto_empty_report_is_valid():
    result = nikto.parse("[]", target="http://localhost:3001")
    assert result.findings == []
    assert result.errors == []


def test_nikto_invalid_json_reports_error():
    result = nikto.parse("[[[", target="http://localhost:3001")
    assert result.findings == []
    assert result.errors


# ---------------------------------------------------------------------------
# Nuclei
# ---------------------------------------------------------------------------
def test_nuclei_parses_jsonl(fixture_text):
    result = nuclei.parse(fixture_text("nuclei-sample.jsonl"), target="http://localhost:3001")
    assert result.errors == []
    assert result.count == 3
    for finding in result.findings:
        assert_normalized(finding)
        assert finding.tool == "nuclei"


def test_nuclei_severity_and_reference_fields(fixture_text):
    result = nuclei.parse(fixture_text("nuclei-sample.jsonl"))
    by_id = {f.reference.split(";")[0]: f for f in result.findings}
    assert by_id["technologies-detect"].severity is Severity.INFO
    assert by_id["CVE-2021-1234"].severity is Severity.HIGH
    assert by_id["CVE-2021-1234"].endpoint == "http://localhost:3001/admin"


def test_nuclei_accepts_both_template_id_spellings(fixture_text):
    """Older nuclei used templateID; the parser must accept both."""
    result = nuclei.parse(fixture_text("nuclei-sample.jsonl"))
    references = " ".join(f.reference for f in result.findings)
    assert "template-id style" not in references
    assert "technologies-detect" in references
    assert "CVE-2021-1234" in references


def test_nuclei_empty_output_is_valid():
    result = nuclei.parse("", target="http://localhost:3001")
    assert result.findings == []
    assert result.errors == []
    assert result.notes


def test_nuclei_unparseable_lines_warn_but_keep_good_ones(fixture_text):
    payload = "{bad json\n" + fixture_text("nuclei-sample.jsonl")
    result = nuclei.parse(payload)
    assert result.count == 3
    assert result.warnings and "could not be interpreted" in result.warnings[0]


def test_nuclei_matched_at_is_recorded(fixture_text):
    result = nuclei.parse(fixture_text("nuclei-sample.jsonl"))
    assert any(f.endpoint.startswith("http://localhost:3001") for f in result.findings)


# ---------------------------------------------------------------------------
# Custom scanner (Project #08 HTML report)
# ---------------------------------------------------------------------------
def test_custom_parser_reads_real_report_markup(fixture_text):
    result = custom.parse(
        fixture_text("custom-scanner-sample.html"), target="http://localhost:3001"
    )
    assert result.errors == []
    assert result.count == 3
    for finding in result.findings:
        assert_normalized(finding)
        assert finding.tool == "custom-scanner"


def test_custom_parser_preserves_severity(fixture_text):
    result = custom.parse(fixture_text("custom-scanner-sample.html"))
    titles = {f.title: f.severity for f in result.findings}
    assert titles["Missing X-Frame-Options header"] is Severity.MEDIUM
    assert titles["Missing Content-Security-Policy header"] is Severity.LOW
    assert titles["Discoverable path: /robots.txt"] is Severity.INFO


def test_custom_parser_extracts_evidence_and_remediation(fixture_text):
    result = custom.parse(fixture_text("custom-scanner-sample.html"))
    finding = next(
        f for f in result.findings if "X-Frame-Options" in f.title
    )
    assert "X-Powered-By" in finding.evidence
    assert "X-Frame-Options: SAMEORIGIN" in finding.recommendation
    assert finding.endpoint == "http://localhost:3001/"


def test_custom_parser_derives_endpoint_from_url(fixture_text):
    result = custom.parse(fixture_text("custom-scanner-sample.html"))
    finding = next(f for f in result.findings if "robots.txt" in f.title)
    assert finding.endpoint == "http://localhost:3001/robots.txt"


def test_custom_parser_surfaces_scanner_errors_as_warnings(fixture_text):
    result = custom.parse(fixture_text("custom-scanner-sample.html"))
    assert any("operational error" in warning for warning in result.warnings)


def test_custom_parser_subjects_align_with_zap(fixture_text):
    """Cross-tool correlation depends on shared subjects.

    The two headers present in both fixtures must resolve to the same subject;
    headers only one tool reported must not be considered shared.
    """
    custom_subjects = {
        f.subject for f in custom.parse(fixture_text("custom-scanner-sample.html")).findings
    }
    zap_subjects = {f.subject for f in zap.parse(fixture_text("zap-sample.json")).findings}
    shared = custom_subjects & zap_subjects

    assert "missing-header:csp" in shared
    assert "missing-header:frame-options" in shared
    # ZAP also reports HSTS and Permissions Policy; the custom-scanner fixture
    # does not, so those must not appear as shared.
    assert "missing-header:hsts" in zap_subjects
    assert "missing-header:hsts" not in custom_subjects
    assert "missing-header:permissions-policy" not in shared


def test_custom_parser_empty_html_reports_error():
    result = custom.parse("", target="http://localhost:3001")
    assert result.findings == []
    assert result.errors


def test_custom_parser_survives_malformed_markup():
    result = custom.parse("<div class='finding'><h3>Broken", target="http://localhost:3001")
    assert result.findings == []


def test_custom_parser_reports_layout_change_instead_of_guessing():
    """A summary table promising findings but no extractable blocks is an error."""
    html = """
    <h2>Summary by severity</h2>
    <table><tr><th>Severity</th><th>Label</th><th>Count</th></tr>
    <tr><td>Medium</td><td>medium</td><td>7</td></tr></table>
    """
    result = custom.parse(html, target="http://localhost:3001")
    assert result.findings == []
    assert result.errors
    assert "no findings were inferred" in result.errors[0]
