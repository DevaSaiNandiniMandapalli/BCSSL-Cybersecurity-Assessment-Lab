"""CLI surface: exit codes, honesty of output, and machine-readable modes."""

from __future__ import annotations

import json

import pytest

from bcssl.cli import main


def run(capsys, *args):
    """Invoke the CLI and return (exit_code, stdout, stderr)."""
    code = main(list(args))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def run_json(capsys, *args):
    code, out, _ = run(capsys, *args)
    return code, json.loads(out)


# ---------------------------------------------------------------------------
# version / help
# ---------------------------------------------------------------------------
def test_version(capsys):
    code, out, _ = run(capsys, "version")
    assert code == 0
    assert "BCSSL Cybersecurity Assessment Lab" in out
    assert "http://localhost:3001" in out


def test_version_json(capsys):
    code, payload = run_json(capsys, "version", "--json")
    assert code == 0
    assert payload["authorized_target"] == "http://localhost:3001"


def test_help_lists_all_commands(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["--help"])
    assert excinfo.value.code == 0
    out = capsys.readouterr().out
    for command in (
        "validate-target",
        "preflight",
        "run",
        "run-all",
        "collect",
        "report",
        "status",
        "lab",
        "web",
        "version",
    ):
        assert command in out


# ---------------------------------------------------------------------------
# validate-target
# ---------------------------------------------------------------------------
def test_validate_target_accepts_authorized(capsys):
    code, out, _ = run(capsys, "validate-target", "--url", "http://localhost:3001", "--no-probe")
    assert code == 0
    assert "AUTHORIZED TARGET" in out
    assert "http://localhost:3001" in out


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:3000",
        "https://example.com",
        "http://8.8.8.8:3001",
        "ftp://localhost:3001",
    ],
)
def test_validate_target_rejects_unauthorized_with_exit_code_2(capsys, url):
    code, out, _ = run(capsys, "validate-target", "--url", url, "--no-probe")
    assert code == 2
    assert "TARGET REJECTED" in out


def test_validate_target_json(capsys):
    code, payload = run_json(
        capsys, "validate-target", "--url", "http://localhost:3001", "--no-probe", "--json"
    )
    assert code == 0
    assert payload["ok"] is True
    assert payload["port"] == 3001

    code, payload = run_json(
        capsys, "validate-target", "--url", "http://evil.example:3001", "--no-probe", "--json"
    )
    assert code == 2
    assert payload["ok"] is False
    assert payload["code"] == "host-not-authorized"


def test_validate_target_without_url_prints_scope(capsys):
    code, out, _ = run(capsys, "validate-target", "--no-probe")
    assert code == 0
    assert "AUTHORIZED SCOPE" in out
    assert "All other hosts, domains, IPs and ports are refused" in out


# ---------------------------------------------------------------------------
# preflight
# ---------------------------------------------------------------------------
def test_preflight_reports_every_tool(capsys):
    """Preflight reports every tool, and exits non-zero if the target is down.

    Exit code is deliberately non-zero when a required component (Python,
    Docker, target) is unavailable, so the command can gate a lesson or a CI
    step.
    """
    code, out, _ = run(capsys, "preflight")
    assert code in (0, 1)
    for tool in ("nmap", "zap", "nikto", "nuclei", "custom-scanner"):
        assert tool in out
    assert "AUTHORIZED TARGET" in out
    assert "http://localhost:3001" in out
    if "NOT RUNNING" in out or "UNAVAILABLE" in out or "ERROR" in out:
        assert code == 1, "a blocking component must produce a non-zero exit code"


def test_preflight_json_marks_unavailable_tools(capsys):
    code, payload = run_json(capsys, "preflight", "--json")
    assert code in (0, 1)
    components = {entry["name"]: entry for entry in payload["components"]}
    assert len(components) == 13, "preflight must report every component"
    assert payload["tools_total"] == 5
    for entry in components.values():
        assert entry["status"] in {
            "READY",
            "READY WITH WARNING",
            "NOT INSTALLED",
            "NOT RUNNING",
            "UNAVAILABLE",
            "ERROR",
        }
        if not entry["ok"] and entry["required"]:
            assert entry["name"] in payload["blocking"]


def test_preflight_renders_a_component_table(capsys):
    code, out, _ = run(capsys, "preflight")
    assert code in (0, 1)
    assert "Component" in out and "Status" in out and "Details" in out
    for name in ("python", "docker-daemon", "target", "project08"):
        assert name in out


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------
def test_run_rejects_unauthorized_target_before_running(capsys):
    code, out, _ = run(capsys, "run", "nmap", "--url", "http://example.com:3001")
    assert code == 2
    assert "TARGET REJECTED" in out


def test_run_unknown_tool_is_reported(capsys):
    code, _, err = run(capsys, "run", "metasploit")
    assert code != 0


def test_run_missing_tool_reports_not_installed(capsys, monkeypatch, tmp_path):
    """A tool that is not installed must say so and produce no findings."""
    from bcssl.config import LabConfig

    config_path = tmp_path / "lab-config.json"
    config_path.write_text(
        json.dumps(
            {
                "tools": {
                    "nmap": {
                        "enabled": True,
                        "executable": "definitely-not-a-real-binary-xyz",
                        "transport": "local",
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    code, out, _ = run(capsys, "--config", str(config_path), "run", "nmap")
    assert code == 1
    assert "TOOL NOT INSTALLED" in out


# ---------------------------------------------------------------------------
# report / collect / status
# ---------------------------------------------------------------------------
def test_report_with_no_results_says_so(capsys):
    code, out, _ = run(capsys, "report", "--format", "html,json,md")
    assert code == 0
    assert "No scan results available." in out


def test_collect_reports_no_runs(capsys):
    code, out, _ = run(capsys, "collect")
    assert code == 0
    assert "stored runs" in out


def test_status_includes_target_and_tools(capsys):
    code, payload = run_json(capsys, "status", "--json")
    assert code == 0
    assert payload["target"]["host"] == "localhost"
    assert payload["target"]["ok"] is True
    assert len(payload["tools"]) == 5
    assert "progress" in payload


def test_report_json_payload_is_valid(capsys):
    code, payload = run_json(capsys, "report", "--json")
    assert code == 0
    assert "executive_summary" in payload
    assert "correlation" in payload


# ---------------------------------------------------------------------------
# lab
# ---------------------------------------------------------------------------
def test_lab_list_shows_all_twelve(capsys):
    code, out, _ = run(capsys, "lab", "list")
    assert code == 0
    for index in range(1, 13):
        assert f"ex{index:02d}" in out
    assert "BEGINNER" in out and "INTERMEDIATE" in out and "ADVANCED" in out
    assert "running a tool never marks an exercise complete" in out


def test_lab_list_json(capsys):
    code, payload = run_json(capsys, "lab", "list", "--json")
    assert code == 0
    assert len(payload) == 12
    assert all("progress" in item for item in payload)


def test_lab_show_prints_full_exercise(capsys):
    code, out, _ = run(capsys, "lab", "show", "ex05")
    assert code == 0
    assert "Objective" in out
    assert "Exact command" in out
    assert "Safety note" in out
    assert "python -m bcssl run zap" in out


def test_lab_show_unknown_exercise(capsys):
    code, _, err = run(capsys, "lab", "show", "ex99")
    assert code == 2


def test_lab_ack_flow(capsys):
    code, out, _ = run(
        capsys, "lab", "ack", "ex01",
        "--check", "c1",
        "--evidence", "reports/raw/lab-cli/preflight.txt",
    )
    assert code == 0
    assert "incomplete" in out.lower() or "still required" in out.lower()

    code, payload = run_json(capsys, "lab", "progress", "--json")
    assert code == 0
    ex01 = next(item for item in payload["exercises"] if item["id"] == "ex01")
    assert ex01["started"] is True
    assert ex01["checks_done"] == 1
    assert ex01["complete"] is False, "partial acknowledgement must not complete"


def test_lab_ack_rejects_unknown_check(capsys):
    code, out, _ = run(capsys, "lab", "ack", "ex01", "--check", "c99")
    assert code == 2
    assert "unknown checklist item" in out


def test_lab_progress_json(capsys):
    code, payload = run_json(capsys, "lab", "progress", "--json")
    assert code == 0
    assert payload["summary"]["total"] == 12


# ---------------------------------------------------------------------------
# web safety
# ---------------------------------------------------------------------------
def test_web_refuses_non_loopback_bind(capsys):
    code, out, _ = run(capsys, "web", "--host", "0.0.0.0")
    assert code == 2
    assert "loopback only" in out
