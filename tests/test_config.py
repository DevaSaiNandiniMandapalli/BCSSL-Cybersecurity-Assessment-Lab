"""Configuration loading: precedence, defaults and safety-relevant scope.

The critical property tested here is that a missing or partial configuration can
never widen the authorized scope beyond the single documented target.
"""

from __future__ import annotations

import copy
import json

import pytest

from bcssl.config import DEFAULT_AUTHORIZED_URL, DEFAULT_CONFIG, ConfigError, LabConfig


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
def test_defaults_authorize_only_the_documented_target():
    config = LabConfig(data=copy.deepcopy(DEFAULT_CONFIG), source=None)
    assert config.authorized_url == DEFAULT_AUTHORIZED_URL
    assert config.allowed_hosts == ("localhost", "127.0.0.1", "::1")
    assert config.allowed_ports == (3001,)
    assert config.require_loopback is True


def test_missing_config_file_falls_back_to_conservative_defaults(tmp_path):
    config = LabConfig.load(tmp_path / "does-not-exist.json")
    assert config.source is None
    assert config.authorized_url == DEFAULT_AUTHORIZED_URL
    assert config.allowed_ports == (3001,), "a missing config must not widen the scope"


def test_malformed_config_is_reported(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(ConfigError):
        LabConfig.load(bad)


def test_non_object_config_is_reported(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("[1, 2, 3]", encoding="utf-8")
    with pytest.raises(ConfigError):
        LabConfig.load(bad)


def test_project_config_loads(tmp_path):
    good = tmp_path / "lab-config.json"
    good.write_text(json.dumps({"lab": {"instructor": "Someone"}}), encoding="utf-8")
    config = LabConfig.load(good)
    assert config.source == good
    assert config.lab["instructor"] == "Someone"
    assert config.authorized_url == DEFAULT_AUTHORIZED_URL


# ---------------------------------------------------------------------------
# Merging
# ---------------------------------------------------------------------------
def test_partial_override_keeps_other_defaults(tmp_path):
    partial = tmp_path / "lab-config.json"
    partial.write_text(
        json.dumps({"tools": {"nmap": {"ports": "3001,8080"}}}), encoding="utf-8"
    )
    config = LabConfig.load(partial)
    assert config.tool("nmap")["ports"] == "3001,8080"
    assert config.tool("nmap")["scan_type"] == "-sT", "other defaults must survive"
    assert config.authorized_url == DEFAULT_AUTHORIZED_URL


def test_all_five_tools_have_settings():
    config = LabConfig(data=copy.deepcopy(DEFAULT_CONFIG), source=None)
    for name in ("nmap", "zap", "nikto", "nuclei", "custom-scanner"):
        settings = config.tool(name)
        assert settings["enabled"] is True
        assert settings.get("executable")


def test_unknown_tool_returns_name_only():
    config = LabConfig(data=copy.deepcopy(DEFAULT_CONFIG), source=None)
    assert config.tool("metasploit")["name"] == "metasploit"


# ---------------------------------------------------------------------------
# Key aliases
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "alias,canonical,value",
    [
        ("timeout", "timeout_seconds", 1234),
        ("default_tuning", "tuning", "7b"),
        ("port_spec", "ports", "3001,8080"),
        ("alert_level", "alert_threshold", 1),
        ("minimum_severities", "severities", ["low"]),
        ("excluded_tags", "exclude_tags", ["dos"]),
    ],
)
def test_alias_spellings_are_folded_into_canonical_keys(alias, canonical, value):
    config = LabConfig(data=copy.deepcopy(DEFAULT_CONFIG), source=None)
    config.data["tools"]["nmap"][alias] = value
    settings = config.tool("nmap")
    assert settings[canonical] == value


def test_canonical_key_wins_over_alias():
    config = LabConfig(data=copy.deepcopy(DEFAULT_CONFIG), source=None)
    config.data["tools"]["nmap"]["timeout"] = 1
    config.data["tools"]["nmap"]["timeout_seconds"] = 2
    assert config.tool("nmap")["timeout_seconds"] == 2


# ---------------------------------------------------------------------------
# Safety-relevant parsing
# ---------------------------------------------------------------------------
def test_allowed_ports_are_coerced_and_deduplicated():
    config = LabConfig(data=copy.deepcopy(DEFAULT_CONFIG), source=None)
    config.data["target"]["allowed_ports"] = [3001, "3001", 8080, "bad", None]
    assert config.allowed_ports == (3001, 8080)


def test_allowed_hosts_are_normalized():
    config = LabConfig(data=copy.deepcopy(DEFAULT_CONFIG), source=None)
    config.data["target"]["allowed_hosts"] = [" LocalHost ", "127.0.0.1", ""]
    assert config.allowed_hosts == ("localhost", "127.0.0.1")


def test_severity_floor_is_uppercased():
    config = LabConfig(data=copy.deepcopy(DEFAULT_CONFIG), source=None)
    config.data["pipeline"]["severity_floor"] = "medium"
    assert config.severity_floor == "MEDIUM"


def test_correlation_is_on_by_default():
    config = LabConfig(data=copy.deepcopy(DEFAULT_CONFIG), source=None)
    assert config.pipeline["correlation"] is True


def test_authorization_statement_is_present():
    config = LabConfig(data=copy.deepcopy(DEFAULT_CONFIG), source=None)
    assert "Authorized educational use only" in config.authorization_statement


def test_to_dict_round_trips_through_load(tmp_path):
    config = LabConfig(data=copy.deepcopy(DEFAULT_CONFIG), source=None)
    config.data["target"]["allowed_ports"] = [3001, 8080]
    path = tmp_path / "lab-config.json"
    path.write_text(json.dumps(config.to_dict()), encoding="utf-8")
    assert LabConfig.load(path).allowed_ports == (3001, 8080)
