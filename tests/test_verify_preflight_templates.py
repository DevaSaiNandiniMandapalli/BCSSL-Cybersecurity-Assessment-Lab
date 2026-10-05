"""Independent verification, preflight reporting and template management."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bcssl import preflight_report, templates as templates_module, verify
from bcssl.models import Finding
from bcssl.severity import Severity

AUTHORIZED = "http://localhost:3001"


def finding(subject: str, tool: str = "zap", status: str = "NOT VERIFIED") -> Finding:
    return Finding(
        tool=tool,
        category="security-header",
        severity=Severity.MEDIUM,
        title=subject,
        subject=subject,
        verification_status=status,
    )


# ---------------------------------------------------------------------------
# Verification vocabulary
# ---------------------------------------------------------------------------
def test_status_vocabulary_matches_the_documented_set():
    assert set(verify.ALL_STATUSES) == {
        "NOT VERIFIED",
        "SINGLE-TOOL OBSERVATION",
        "CORROBORATED",
        "DETECTED",
        "TOOL UNAVAILABLE",
    }


def test_verify_refuses_an_unauthorized_target(config):
    result = verify.verify([finding("missing-header:csp")], config, url="http://example.com:3001")
    assert result.error.startswith("verification refused")
    assert result.confirmed == {}


def test_verify_of_no_findings_is_a_no_op(config):
    result = verify.verify([], config)
    assert result.confirmed == {}
    assert result.reachable is False or result.error == ""


def test_verify_reports_unreachable_target_honestly(config):
    """A closed loopback port must be reported, never assumed."""
    import socket

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        free = probe.getsockname()[1]
    config.data["target"]["allowed_ports"] = [free]
    result = verify.verify([finding("missing-header:csp")], config, url=f"http://127.0.0.1:{free}")
    assert result.reachable is False
    assert result.error


# ---------------------------------------------------------------------------
# Status application
# ---------------------------------------------------------------------------
def test_apply_verification_upgrades_confirmed_findings():
    findings = [finding("missing-header:csp")]
    result = verify.VerificationResult(confirmed={"missing-header:csp": True})
    counters = verify.apply_verification(findings, result)
    assert findings[0].verification_status == verify.DETECTED
    assert counters[verify.DETECTED] == 1


def test_apply_verification_never_downgrades_corroborated():
    findings = [finding("missing-header:csp", status=verify.CORROBORATED)]
    result = verify.VerificationResult(confirmed={"missing-header:csp": True})
    verify.apply_verification(findings, result)
    assert findings[0].verification_status == verify.CORROBORATED


def test_apply_verification_leaves_unconfirmed_findings_alone():
    findings = [finding("missing-header:csp", status=verify.SINGLE_TOOL_OBSERVATION)]
    result = verify.VerificationResult(confirmed={"missing-header:csp": False})
    verify.apply_verification(findings, result)
    assert findings[0].verification_status == verify.SINGLE_TOOL_OBSERVATION


def test_apply_verification_does_not_invent_findings():
    findings = [finding("title:some-unrelated-issue")]
    result = verify.VerificationResult(confirmed={"missing-header:csp": True})
    before = len(findings)
    verify.apply_verification(findings, result)
    assert len(findings) == before


def test_apply_verification_ignores_unknown_subjects():
    findings = [finding("title:unknown")]
    result = verify.VerificationResult(confirmed={"something-else": True})
    counters = verify.apply_verification(findings, result)
    assert sum(counters.values()) == 1


# ---------------------------------------------------------------------------
# Preflight report structure
# ---------------------------------------------------------------------------
def test_preflight_report_has_all_required_components(config):
    report = preflight_report.run(config)
    names = {component.name for component in report.components}
    for required in (
        "python",
        "docker-cli",
        "docker-daemon",
        "juice-shop-container",
        "target",
        "configuration",
        "directories",
        "project08",
        "nmap",
        "zap",
        "nikto",
        "nuclei",
        "custom-scanner",
    ):
        assert required in names, f"preflight must report {required}"


def test_preflight_component_statuses_are_from_the_documented_set(config):
    report = preflight_report.run(config)
    allowed = {
        preflight_report.READY,
        preflight_report.READY_WITH_WARNING,
        preflight_report.NOT_INSTALLED,
        preflight_report.NOT_RUNNING,
        preflight_report.UNAVAILABLE,
        preflight_report.ERROR,
    }
    for component in report.components:
        assert component.status in allowed, component.name


def test_preflight_table_renders_every_component(config):
    report = preflight_report.run(config)
    table = preflight_report.render_table(report)
    assert "Component" in table and "Status" in table and "Details" in table
    for component in report.components:
        assert component.name in table


def test_preflight_remedies_name_missing_dependencies(config, monkeypatch):
    monkeypatch.setattr(
        preflight_report.shutil, "which", lambda name: None
    )
    report = preflight_report.run(config)
    remedies = preflight_report.render_remedies(report)
    assert "SETUP REQUIRED" in remedies
    assert "->" in remedies


def test_preflight_json_payload_is_serialisable(config):
    report = preflight_report.run(config)
    text = json.dumps(report.to_dict())
    payload = json.loads(text)
    assert payload["tools_total"] == 5
    assert isinstance(payload["ready"], bool)


def test_preflight_flags_non_loopback_container_binding(config, monkeypatch):
    """A deliberately vulnerable app must never be exposed to the network."""
    from bcssl.executor import ExecutionResult

    fake = ExecutionResult(
        command=["docker", "ps"],
        exit_code=0,
        stdout="bcssl-juiceshop|Up 1 minute|0.0.0.0:3001->3000/tcp, [::]:3001->3000/tcp",
        stderr="",
        duration_seconds=0.1,
    )
    monkeypatch.setattr(preflight_report, "run", None, raising=False)
    monkeypatch.setattr(
        "bcssl.executor.run_command", lambda spec, **kwargs: fake
    )
    component = preflight_report.check_juice_shop()
    assert component.status == preflight_report.READY_WITH_WARNING
    assert "loopback" in component.detail
    assert component.remedy


def test_preflight_accepts_loopback_binding(config, monkeypatch):
    from bcssl.executor import ExecutionResult

    fake = ExecutionResult(
        command=["docker", "ps"],
        exit_code=0,
        stdout="bcssl-juiceshop|Up 1 minute|127.0.0.1:3001->3000/tcp",
        stderr="",
        duration_seconds=0.1,
    )
    monkeypatch.setattr("bcssl.executor.run_command", lambda spec, **kwargs: fake)
    component = preflight_report.check_juice_shop()
    assert component.status == preflight_report.READY


def test_python_check_rejects_old_versions(config, monkeypatch):
    import sys as sys_module

    monkeypatch.setattr(sys_module, "version_info", (3, 8, 0))
    component = preflight_report.check_python()
    assert component.status == preflight_report.ERROR
    assert component.required


# ---------------------------------------------------------------------------
# Template management
# ---------------------------------------------------------------------------
def test_template_status_reports_both_locations():
    status = templates_module.template_status()
    assert "full" in status and "profile" in status
    assert "profile_path" in status


def test_build_profile_without_downloaded_templates_fails_honestly(config, monkeypatch, tmp_path):
    monkeypatch.setattr(
        templates_module.paths, "project_root", lambda: tmp_path
    )
    result = templates_module.build_template_profile()
    assert result.ok is False
    assert "update-templates" in result.message


def test_build_profile_copies_curated_families(config, monkeypatch, tmp_path):
    root = tmp_path / "lab"
    http = root / "tools" / "nuclei" / "templates" / "http"
    for family in ("technologies", "misconfiguration", "fuzzing"):
        (http / family).mkdir(parents=True)
        (http / family / "t.yaml").write_text("id: t\n", encoding="utf-8")
    monkeypatch.setattr(templates_module.paths, "project_root", lambda: root)

    result = templates_module.build_template_profile()
    assert result.ok is True
    profile = root / "tools" / "nuclei" / "templates-lab"
    assert (profile / "technologies" / "t.yaml").is_file()
    # Fuzzing must never be copied into the lab profile.
    assert not (profile / "fuzzing").exists()


def test_build_profile_is_idempotent(config, monkeypatch, tmp_path):
    root = tmp_path / "lab"
    (root / "tools" / "nuclei" / "templates" / "http" / "technologies").mkdir(parents=True)
    (root / "tools" / "nuclei" / "templates" / "http" / "technologies" / "t.yaml").write_text(
        "id: t\n", encoding="utf-8"
    )
    monkeypatch.setattr(templates_module.paths, "project_root", lambda: root)

    first = templates_module.build_template_profile()
    second = templates_module.build_template_profile()
    assert first.ok and second.ok
    assert any("already present" in detail for detail in second.details)


def test_shipped_lab_profile_excludes_destructive_families():
    """The committed profile must not contain fuzzing or credential templates."""
    profile = Path(__file__).resolve().parents[1] / "tools" / "nuclei" / "templates-lab"
    if not profile.is_dir():
        pytest.skip("lab profile has not been built in this checkout")
    for forbidden in ("fuzzing", "credential-stuffing", "default-logins", "token-spray"):
        assert not (profile / forbidden).exists(), forbidden
