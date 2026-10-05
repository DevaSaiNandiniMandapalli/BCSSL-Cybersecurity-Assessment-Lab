"""Runner contract: availability, authorization, command construction, failure.

Command-construction tests never execute a scan. Failure-handling tests use a
stub executable created in a temporary directory, so no real security tool runs
and no target other than loopback is contacted.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from bcssl import preflight
from bcssl.models import RunStatus
from bcssl.runners import ALIASES, RUNNERS, resolve_runner
from bcssl.runners.nikto import EXCLUDED_PLUGIN_GROUPS
from bcssl.runners.nuclei import MANDATORY_EXCLUDE_TAGS
from bcssl.target import validate_target

AUTHORIZED = "http://localhost:3001"


def authorized(config):
    result = validate_target(AUTHORIZED, config)
    assert result.ok
    return result


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------
def test_registry_contains_all_five_components():
    assert set(RUNNERS) == {"nmap", "zap", "nikto", "nuclei", "custom-scanner"}


def test_resolve_runner_accepts_aliases():
    assert resolve_runner("custom") is RUNNERS["custom-scanner"]
    assert resolve_runner("zaproxy") is RUNNERS["zap"]
    assert ALIASES["scanner"] == "custom-scanner"


def test_resolve_runner_rejects_unknown_tool():
    with pytest.raises(ValueError) as excinfo:
        resolve_runner("metasploit")
    assert "unknown tool" in str(excinfo.value)


def test_resolve_runner_rejects_empty_name():
    with pytest.raises(ValueError):
        resolve_runner("")


# ---------------------------------------------------------------------------
# Command construction - nmap
# ---------------------------------------------------------------------------
def test_nmap_command_is_loopback_only_and_scoped_to_authorized_ports(config):
    runner = RUNNERS["nmap"](config)
    spec = runner.build_command(authorized(config), {})
    argv = spec.argv

    assert argv[0].endswith("nmap")
    assert "-sT" in argv, "TCP connect scan only"
    assert "-Pn" in argv
    assert argv[argv.index("-p") + 1] == "3001"
    assert argv[-1] == "localhost"
    assert "-oX" in argv
    assert not any(flag in argv for flag in ("-sS", "-O", "-A", "-sU"))
    assert spec.cwd is not None


def test_nmap_service_detection_toggle(config):
    runner = RUNNERS["nmap"](config)
    spec = runner.build_command(authorized(config), {"service_detection": False})
    assert "-sV" not in spec.argv


def test_nmap_refuses_syn_scan(config):
    runner = RUNNERS["nmap"](config)
    with pytest.raises(ValueError) as excinfo:
        runner.build_command(authorized(config), {"scan_type": "-sS"})
    assert "not permitted" in str(excinfo.value)


@pytest.mark.parametrize("ports", ["3001; rm -rf /", "abc", "3001 4000", "--script=x", "-p22"])
def test_nmap_refuses_malicious_port_specs(config, ports):
    runner = RUNNERS["nmap"](config)
    with pytest.raises(ValueError):
        runner.build_command(authorized(config), {"ports": ports})


def test_nmap_empty_port_option_falls_back_to_configured_default(config):
    """An empty value is treated as unset, never as 'scan everything'."""
    runner = RUNNERS["nmap"](config)
    assert runner.ports({"ports": ""}) == "3001"


def test_nmap_port_range_must_be_configured_by_instructor(config):
    """A wider range is possible but only through configuration."""
    runner = RUNNERS["nmap"](config)
    assert runner.ports({}) == "3001"
    runner.settings["ports"] = "1-1024,3001"
    assert runner.ports({}) == "1-1024,3001"


# ---------------------------------------------------------------------------
# Command construction - zap
# ---------------------------------------------------------------------------
def test_zap_command_targets_only_the_authorized_url(config):
    runner = RUNNERS["zap"](config)
    spec = runner.build_command(authorized(config), {})
    argv = spec.argv
    assert argv[argv.index("-t") + 1] == AUTHORIZED
    assert "-J" in argv and "-r" in argv
    assert argv[argv.index("-J") + 1] == "zap-report.json"


def test_zap_passive_mode_disables_the_active_spider(config):
    """Passive mode is expressed in ZAP core options passed via -z."""
    runner = RUNNERS["zap"](config)
    spec = runner.build_command(authorized(config), {"mode": "passive"})
    core = spec.argv[spec.argv.index("-z") + 1]
    assert "spider.active=false" in core

    baseline = runner.build_command(authorized(config), {"mode": "baseline"})
    baseline_core = baseline.argv[baseline.argv.index("-z") + 1]
    assert "spider.active" not in baseline_core


def test_zap_rejects_unknown_mode(config):
    runner = RUNNERS["zap"](config)
    with pytest.raises(ValueError) as excinfo:
        runner.build_command(authorized(config), {"mode": "aggressive"})
    assert "unknown ZAP mode" in str(excinfo.value)


def test_zap_alert_threshold_only_applied_when_configured(config):
    runner = RUNNERS["zap"](config)
    spec = runner.build_command(authorized(config), {})
    core = spec.argv[spec.argv.index("-z") + 1]
    assert "scanner.alertThreshold" not in core

    configured = runner.build_command(authorized(config), {"alert_threshold": 0})
    configured_core = configured.argv[configured.argv.index("-z") + 1]
    assert "scanner.alertThreshold=0" in configured_core


def test_zap_core_options_are_bounded(config):
    """The lab must never hand ZAP an unbounded crawl."""
    runner = RUNNERS["zap"](config)
    spec = runner.build_command(authorized(config), {})
    core = spec.argv[spec.argv.index("-z") + 1]
    assert "spider.maxDepth=" in core
    assert "spider.maxDuration=" in core
    assert "connection.timeoutInSecs=" in core


def test_zap_rejects_invalid_alert_threshold(config):
    runner = RUNNERS["zap"](config)
    with pytest.raises(ValueError):
        runner.build_command(authorized(config), {"alert_threshold": 9})


def test_zap_max_minutes_derived_from_timeout(config):
    runner = RUNNERS["zap"](config)
    spec = runner.build_command(authorized(config), {"timeout": 300})
    assert spec.argv[spec.argv.index("-m") + 1] == "5"


# ---------------------------------------------------------------------------
# Command construction - nikto
# ---------------------------------------------------------------------------
def test_nikto_command_shape(config):
    runner = RUNNERS["nikto"](config)
    spec = runner.build_command(authorized(config), {})
    argv = spec.argv
    assert argv[argv.index("-h") + 1] == AUTHORIZED
    assert argv[argv.index("-Tuning") + 1] == "1237bd"
    assert argv[argv.index("-Format") + 1] == "json"
    assert "-nointeractive" in argv
    assert "-output" in argv


@pytest.mark.parametrize("tuning", sorted(EXCLUDED_PLUGIN_GROUPS))
def test_nikto_refuses_destructive_tuning_groups(config, tuning):
    """File upload, DoS, command execution, SQLi and friends are refused."""
    runner = RUNNERS["nikto"](config)
    with pytest.raises(ValueError) as excinfo:
        runner.build_command(authorized(config), {"tuning": f"12{tuning}"})
    message = str(excinfo.value)
    assert "refusing nikto tuning" in message
    assert EXCLUDED_PLUGIN_GROUPS[tuning] in message


def test_nikto_default_tuning_excludes_no_destructive_groups(config):
    runner = RUNNERS["nikto"](config)
    tuning = runner.tuning({})
    assert not (set(tuning) & set(EXCLUDED_PLUGIN_GROUPS))


def test_nikto_rejects_non_alphanumeric_tuning(config):
    runner = RUNNERS["nikto"](config)
    with pytest.raises(ValueError):
        runner.build_command(authorized(config), {"tuning": "12;rm -rf /"})


# ---------------------------------------------------------------------------
# Command construction - nuclei
# ---------------------------------------------------------------------------
def test_nuclei_command_scope_and_limits(config):
    runner = RUNNERS["nuclei"](config)
    spec = runner.build_command(authorized(config), {})
    argv = spec.argv
    assert argv[argv.index("-u") + 1] == AUTHORIZED
    assert argv[argv.index("-severity") + 1] == "info,low,medium,high,critical"
    assert argv[argv.index("-c") + 1] == "5"
    assert argv[argv.index("-rate-limit") + 1] == "5"
    # Verified against nuclei v3: the automatic update check is disabled with
    # -duc; there is no -no-update-templates flag in current releases.
    assert "-duc" in argv
    assert "-no-update-templates" not in argv


def test_nuclei_always_excludes_destructive_tags(config):
    runner = RUNNERS["nuclei"](config)
    for options in ({}, {"exclude_tags": []}, {"exclude_tags": ["fuzz"]}):
        spec = runner.build_command(authorized(config), options)
        excluded = spec.argv[spec.argv.index("-etags") + 1].split(",")
        for tag in MANDATORY_EXCLUDE_TAGS:
            assert tag in excluded


def test_nuclei_rejects_invalid_severity(config):
    runner = RUNNERS["nuclei"](config)
    with pytest.raises(ValueError) as excinfo:
        runner.build_command(authorized(config), {"severities": ["critical", "apocalyptic"]})
    assert "apocalyptic" in str(excinfo.value)


def test_nuclei_severity_list_accepted_as_string(config):
    runner = RUNNERS["nuclei"](config)
    spec = runner.build_command(authorized(config), {"severities": "low,high"})
    assert spec.argv[spec.argv.index("-severity") + 1] == "low,high"


# ---------------------------------------------------------------------------
# Command construction - custom scanner
# ---------------------------------------------------------------------------
def test_custom_scanner_command_uses_external_project(config, tmp_path):
    project = tmp_path / "proj08"
    (project / "scanner").mkdir(parents=True)
    (project / "scanner.py").write_text("# stub", encoding="utf-8")
    config.data["tools"]["custom-scanner"]["project_root"] = str(project)
    config.data["tools"]["custom-scanner"]["python"] = sys.executable

    runner = RUNNERS["custom-scanner"](config)
    spec = runner.build_command(authorized(config), {})
    argv = spec.argv

    assert argv[0] == sys.executable
    assert argv[1:3] == ["-m", "scanner"]
    assert argv[argv.index("--url") + 1] == AUTHORIZED
    assert argv[argv.index("--modules") + 1] == "headers,paths,injection"
    assert "--html-output" in argv
    assert "--no-color" in argv
    assert spec.cwd == str(project), "must run from the external project root"


def test_custom_scanner_rejects_unknown_module(config, tmp_path):
    project = tmp_path / "proj08"
    project.mkdir()
    (project / "scanner.py").write_text("# stub", encoding="utf-8")
    config.data["tools"]["custom-scanner"]["project_root"] = str(project)
    config.data["tools"]["custom-scanner"]["python"] = sys.executable

    runner = RUNNERS["custom-scanner"](config)
    with pytest.raises(ValueError) as excinfo:
        runner.build_command(authorized(config), {"modules": "headers,exfiltrate"})
    assert "exfiltrate" in str(excinfo.value)


def test_custom_scanner_missing_project_is_reported(config, tmp_path):
    config.data["tools"]["custom-scanner"]["project_root"] = str(tmp_path / "nope")
    runner = RUNNERS["custom-scanner"](config)
    with pytest.raises(ValueError) as excinfo:
        runner.build_command(authorized(config), {})
    assert "not found" in str(excinfo.value)


def test_custom_scanner_is_never_containerised(config):
    config.data["tools"]["custom-scanner"]["transport"] = "docker"
    transport, _ = preflight.resolve_transport("custom-scanner", config.tool("custom-scanner"))
    assert transport == "local"


# ---------------------------------------------------------------------------
# Docker transport
# ---------------------------------------------------------------------------
def test_docker_wrapper_mounts_run_directory(config):
    runner = RUNNERS["nmap"](config)
    spec = runner.wrap_with_docker(runner.build_command(authorized(config), {}))
    assert spec.argv[0] == "docker"
    assert "--rm" in spec.argv
    assert "-v" in spec.argv
    assert any(arg.endswith(":/bcssl-out") for arg in spec.argv)
    assert "/bcssl-out" in spec.argv


# ---------------------------------------------------------------------------
# Availability and failure handling
# ---------------------------------------------------------------------------
def test_missing_tool_reports_tool_not_installed(config):
    config.data["tools"]["nmap"]["executable"] = "definitely-not-installed-nmap-xyz"
    config.data["tools"]["nmap"]["transport"] = "local"
    result = RUNNERS["nmap"](config).run(skip_reachability=True)
    assert result.status is RunStatus.TOOL_NOT_INSTALLED
    assert result.status.label == "TOOL NOT INSTALLED"
    assert result.findings == [], "a tool that did not run produces no findings"
    assert result.command == [], "no command is built for a missing tool"


def test_disabled_tool_reports_disabled(config):
    config.data["tools"]["nmap"]["enabled"] = False
    result = RUNNERS["nmap"](config).run()
    assert result.status is RunStatus.DISABLED
    assert result.findings == []


def test_unauthorized_target_is_refused_before_any_command(config):
    config.data["tools"]["nmap"]["executable"] = sys.executable
    result = RUNNERS["nmap"](config).run(url="http://example.com:3001")
    assert result.status is RunStatus.TARGET_REJECTED
    assert result.command == []
    assert result.findings == []
    assert any("NOT AUTHORIZED" in error for error in result.errors)


@pytest.mark.skipif(sys.platform != "win32", reason="uses a .cmd wrapper")
def test_tool_failure_is_surfaced_not_hidden(config, tmp_path):
    """A stub executable that exits non-zero must produce FAILED, not success."""
    stub = tmp_path / "failing-tool.py"
    stub.write_text("import sys; sys.stderr.write('stub failure\\n'); sys.exit(3)", encoding="utf-8")
    wrapper = tmp_path / "failing-tool.cmd"
    wrapper.write_text(
        f'@echo off\r\n"{sys.executable}" "{stub}" %*\r\n', encoding="utf-8"
    )

    config.data["tools"]["nmap"]["executable"] = str(wrapper)
    config.data["tools"]["nmap"]["transport"] = "local"
    config.data["tools"]["nmap"]["service_detection"] = False

    result = RUNNERS["nmap"](config).run(skip_reachability=True)
    assert result.status is RunStatus.FAILED
    assert result.exit_code == 3
    assert result.findings == []
    assert any("exited with code 3" in error for error in result.errors)


@pytest.mark.skipif(sys.platform != "win32", reason="uses a .cmd wrapper")
def test_tool_timeout_is_reported(config, tmp_path):
    # Answers --version immediately so preflight succeeds, then hangs on a real run.
    stub = tmp_path / "slow-tool.py"
    stub.write_text(
        "import sys, time\n"
        "if '--version' in sys.argv:\n"
        "    print('slow-tool 1.0')\n"
        "    sys.exit(0)\n"
        "time.sleep(30)\n",
        encoding="utf-8",
    )
    wrapper = tmp_path / "slow-tool.cmd"
    wrapper.write_text(f'@echo off\r\n"{sys.executable}" "{stub}" %*\r\n', encoding="utf-8")

    config.data["tools"]["nmap"]["executable"] = str(wrapper)
    config.data["tools"]["nmap"]["transport"] = "local"

    result = RUNNERS["nmap"](config).run(options={"timeout": 3}, skip_reachability=True)
    assert result.status is RunStatus.TIMEOUT, result.errors
    assert result.findings == []
    assert any("timeout" in error.lower() for error in result.errors)


@pytest.mark.skipif(sys.platform != "win32", reason="uses a .cmd wrapper")
def test_successful_tool_output_is_parsed_and_evidenced(config, tmp_path):
    """End-to-end: stub writes an nmap XML report, which must be parsed."""
    fixture = Path(__file__).resolve().parent / "fixtures" / "nmap-sample.xml"
    xml = fixture.read_text(encoding="utf-8")

    stub = tmp_path / "good-tool.py"
    stub.write_text(
        "import sys\n"
        "out = None\n"
        "args = sys.argv[1:]\n"
        f"xml = open({str(fixture)!r}, encoding='utf-8').read()\n"
        "for i, a in enumerate(args):\n"
        "    if a == '-oX':\n"
        "        out = args[i+1]\n"
        "open(out, 'w', encoding='utf-8').write(xml)\n"
        "print('scan complete')\n",
        encoding="utf-8",
    )
    wrapper = tmp_path / "good-tool.cmd"
    wrapper.write_text(f'@echo off\r\n"{sys.executable}" "{stub}" %*\r\n', encoding="utf-8")

    config.data["tools"]["nmap"]["executable"] = str(wrapper)
    config.data["tools"]["nmap"]["transport"] = "local"

    result = RUNNERS["nmap"](config).run(skip_reachability=True)

    assert result.status is RunStatus.OK, result.errors
    assert result.exit_code == 0
    assert result.finding_count == 2
    assert result.stdout_path.endswith("stdout.txt")

    from bcssl import paths as lab_paths

    stdout_file = lab_paths.output_root() / result.stdout_path
    assert stdout_file.read_text(encoding="utf-8").strip() == "scan complete"

    assert len(result.evidence) == 2
    for record in result.evidence:
        assert record.raw_sha256, "evidence must carry an integrity hash"
        evidence_file = lab_paths.output_root() / record.path
        assert evidence_file.is_file()
