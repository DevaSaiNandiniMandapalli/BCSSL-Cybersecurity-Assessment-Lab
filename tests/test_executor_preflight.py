"""Executor behaviour and tool availability detection.

Availability is asserted structurally: a tool is "available" only when the lab
can actually execute it and obtain a version string from it.
"""

from __future__ import annotations

import sys

import pytest

from bcssl import preflight
from bcssl.executor import CommandSpec, probe_version, run_command, which


# ---------------------------------------------------------------------------
# Executor
# ---------------------------------------------------------------------------
def test_captures_stdout_exit_code_and_duration():
    result = run_command(
        CommandSpec(argv=[sys.executable, "-c", "print('hello')"], timeout=30)
    )
    assert result.exit_code == 0
    assert result.stdout.strip() == "hello"
    assert result.succeeded
    assert result.duration_seconds >= 0
    assert result.timed_out is False


def test_captures_stderr_and_non_zero_exit():
    result = run_command(
        CommandSpec(
            argv=[sys.executable, "-c", "import sys; sys.stderr.write('bad'); sys.exit(7)"],
            timeout=30,
        )
    )
    assert result.exit_code == 7
    assert result.stderr.strip() == "bad"
    assert not result.succeeded


def test_missing_executable_is_reported_not_raised():
    result = run_command(CommandSpec(argv=["definitely-not-a-real-binary-xyz"], timeout=10))
    assert result.launch_error
    assert "not found" in result.launch_error.lower()
    assert result.exit_code is None


def test_timeout_is_reported():
    result = run_command(
        CommandSpec(argv=[sys.executable, "-c", "import time; time.sleep(20)"], timeout=2)
    )
    assert result.timed_out is True
    assert "timeout" in result.launch_error.lower()
    assert not result.succeeded


def test_output_is_decoded_despite_invalid_bytes():
    result = run_command(
        CommandSpec(
            argv=[
                sys.executable,
                "-c",
                "import sys; sys.stdout.buffer.write(b'\\xff\\xfe ok')",
            ],
            timeout=30,
        )
    )
    assert "ok" in result.stdout


def test_command_display_is_copy_pasteable():
    spec = CommandSpec(argv=["nikto", "-h", "http://localhost:3001", "-Tuning", "1237bd"])
    displayed = spec.display()
    assert displayed.startswith("nikto -h ")
    assert "-Tuning 1237bd" in displayed


def test_no_shell_interpretation():
    """A metacharacter in an argument stays literal."""
    payload = "http://localhost:3001; echo pwned"
    result = run_command(
        CommandSpec(argv=[sys.executable, "-c", "import sys; print(sys.argv[1])", payload], timeout=30)
    )
    assert result.stdout.strip() == payload
    assert "pwned" in result.stdout.strip()
    assert result.stdout.strip().count("pwned") == 1


def test_which_finds_python():
    assert which("python") or which("python3")


def test_which_returns_empty_for_unknown():
    assert which("definitely-not-a-real-binary-xyz") == ""


def test_probe_version_detects_real_interpreter():
    available, version = probe_version(sys.executable, ["--version"])
    assert available
    assert "Python" in version


def test_probe_version_reports_missing_tool():
    available, version = probe_version("definitely-not-a-real-binary-xyz")
    assert available is False
    assert version == ""


# ---------------------------------------------------------------------------
# Availability detection
# ---------------------------------------------------------------------------
def test_detect_returns_status_for_every_tool(config):
    statuses = preflight.detect_all(config)
    assert set(statuses) == set(config.tool_names())
    for status in statuses.values():
        assert isinstance(status.available, bool)
        assert status.message


def test_missing_tool_message_is_explicit(config):
    config.data["tools"]["nikto"]["executable"] = "definitely-not-a-real-binary-xyz"
    config.data["tools"]["nikto"]["transport"] = "local"
    status = preflight.detect("nikto", config)
    assert status.available is False
    assert "TOOL NOT INSTALLED" in status.message


def test_present_tool_is_detected(config):
    config.data["tools"]["nikto"]["executable"] = sys.executable
    config.data["tools"]["nikto"]["transport"] = "local"
    config.data["tools"]["nikto"]["version_args"] = ["--version"]
    status = preflight.detect("nikto", config)
    assert status.available is True
    assert status.version


def test_disabled_tool_is_not_available(config):
    config.data["tools"]["zap"]["enabled"] = False
    status = preflight.detect("zap", config)
    assert status.available is False
    assert "DISABLED" in status.message


def test_custom_scanner_missing_project_is_reported(config, tmp_path):
    config.data["tools"]["custom-scanner"]["project_root"] = str(tmp_path / "absent")
    status = preflight.detect("custom-scanner", config)
    assert status.available is False
    assert "not found" in status.message


def test_custom_scanner_present_project_is_detected(config, tmp_path):
    project = tmp_path / "proj08"
    project.mkdir()
    (project / "scanner.py").write_text("# stub", encoding="utf-8")
    config.data["tools"]["custom-scanner"]["project_root"] = str(project)
    config.data["tools"]["custom-scanner"]["python"] = sys.executable

    status = preflight.detect("custom-scanner", config)
    assert status.available is True
    # shutil.which applies os.path.normcase, which lower-cases on Windows.
    import os

    assert os.path.normcase(status.resolved_path) == os.path.normcase(sys.executable)
    assert status.version


def test_transport_auto_prefers_local_when_present(config):
    config.data["tools"]["nuclei"]["executable"] = sys.executable
    transport, _ = preflight.resolve_transport("nuclei", config.tool("nuclei"))
    assert transport == "local"


def test_transport_local_never_falls_back_to_docker(config):
    config.data["tools"]["nuclei"]["executable"] = "definitely-not-a-real-binary-xyz"
    config.data["tools"]["nuclei"]["transport"] = "local"
    transport, _ = preflight.resolve_transport("nuclei", config.tool("nuclei"))
    assert transport == "none"


def test_tool_manifest_is_optional():
    assert isinstance(preflight.tool_manifest("nmap"), dict)
    assert isinstance(preflight.install_hint("nmap"), str)
