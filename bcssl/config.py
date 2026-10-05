"""Configuration loading for the assessment lab.

``config/lab-config.json`` is the single source of truth for the authorized
target and for per-tool settings. An instructor may layer an override file on
top (for example to enable additional loopback ports) with::

    python -m bcssl run nmap --config config/instructor-config.json

Missing keys fall back to conservative defaults. The defaults never widen the
authorized scope beyond the single documented target.
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import paths

#: The one target this lab exists to assess.
DEFAULT_AUTHORIZED_URL = "http://localhost:3001"

#: Loopback names/addresses accepted by the target validator.
DEFAULT_ALLOWED_HOSTS = ("localhost", "127.0.0.1", "::1")

DEFAULT_CONFIG: dict[str, Any] = {
    "lab": {
        "name": "BCSSL Cybersecurity Assessment Lab",
        "version": "1.0.0",
        "instructor": "",
        "authorization_statement": (
            "Authorized educational use only. Assessment is restricted to the "
            "locally hosted training target declared in this configuration. "
            "No public, third-party, or arbitrary host may be scanned."
        ),
    },
    "target": {
        "authorized_url": DEFAULT_AUTHORIZED_URL,
        "allowed_hosts": list(DEFAULT_ALLOWED_HOSTS),
        "allowed_ports": [3001],
        "require_loopback": True,
        "allow_ipv4_mapped": True,
    },
    "http": {
        "timeout_seconds": 15,
        "user_agent": "BCSSL-Assessment-Lab/1.0 (authorized local lab)",
        "max_body_bytes": 262144,
    },
    "tools": {
        "nmap": {
            "enabled": True,
            "executable": "nmap",
            "transport": "auto",
            "ports": "3001",
            "scan_type": "-sT",
            "service_detection": True,
            "skip_host_discovery": True,
            "timeout_seconds": 300,
            "docker_image": "instrumentisto/nmap:latest",
        },
        "zap": {
            "enabled": True,
            "executable": "zap-baseline.py",
            "transport": "auto",
            "mode": "baseline",
            "level": "MEDIUM",
            "timeout_seconds": 900,
            "docker_image": "ghcr.io/zaproxy/zaproxy:stable",
            # ZAP's packaged scripts refuse to run unless /zap/wrk is mounted.
            "docker_mount_path": "/zap/wrk",
        },
        "nikto": {
            "enabled": True,
            "executable": "nikto",
            "transport": "auto",
            "tuning": "1237bd",
            "timeout_seconds": 600,
            "docker_image": "alpine/nikto:latest",
        },
        "nuclei": {
            "enabled": True,
            "executable": "nuclei",
            "transport": "auto",
            "severities": ["info", "low", "medium", "high", "critical"],
            "exclude_tags": [
                "dos",
                "fuzz",
                "intrusion",
                "headless",
                "bruteforce",
                "brutespray",
                "code",
                "workflow",
            ],
            "rate_limit": 5,
            "concurrency": 5,
            "timeout_seconds": 900,
            "docker_image": "projectdiscovery/nuclei:latest",
            # Nuclei ships no templates. Fetch them once with
            # `python -m bcssl update-templates`, then mount them read-only.
            "templates_dir": "/bcssl-templates",
            "docker_extra_mounts": [
                "{project_root}/tools/nuclei/templates:/bcssl-templates:ro"
            ],
        },
        "custom-scanner": {
            "enabled": True,
            "transport": "local",
            "executable": "scanner.py",
            "project_root": r"C:\Users\devas\Documents\Cybersecurity\Web-Security-Scanner",
            "python": "auto",
            "modules": ["headers", "paths", "injection"],
            "timeout_seconds": 900,
        },
    },
    "pipeline": {
        "severity_floor": "INFO",
        "correlation": True,
        "evidence_excerpt_chars": 1200,
    },
    "web": {
        "host": "127.0.0.1",
        "port": 8765,
        "open_browser": False,
    },
}


#: Alternative spellings accepted for tool settings, mapped to the canonical
#: key. Documentation and instructor configurations use a few natural variants;
#: accepting them means a config written from the docs cannot silently do
#: nothing. Canonical names always win when both are present.
TOOL_KEY_ALIASES: dict[str, str] = {
    "timeout": "timeout_seconds",
    "default_tuning": "tuning",
    "executable_name": "executable",
    "port_spec": "ports",
    "alert_level": "alert_threshold",
    "minimum_severities": "severities",
    "excluded_tags": "exclude_tags",
    "project_path": "project_root",
}


def _normalize_tool_keys(
    settings: dict[str, Any], defaults: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Fold accepted alias spellings into their canonical keys.

    An alias is honoured when the canonical key is either absent or still holds
    its default value - that is the case where the alias *is* the user's
    explicit setting. When both spellings are present with the canonical one
    deliberately changed, the canonical key wins.
    """
    if not isinstance(settings, dict):
        return {}
    defaults = defaults or {}
    result = dict(settings)
    for alias, canonical in TOOL_KEY_ALIASES.items():
        if alias not in result:
            continue
        canonical_is_default = (
            canonical not in result or result.get(canonical) == defaults.get(canonical)
        )
        if canonical_is_default:
            result[canonical] = result.pop(alias)
    return result


class ConfigError(RuntimeError):
    """Raised when the configuration file cannot be used."""


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


@dataclass
class LabConfig:
    """Parsed lab configuration."""

    data: dict[str, Any] = field(default_factory=dict)
    source: Path | None = None

    # -- construction ------------------------------------------------------
    @classmethod
    def load(cls, path: Path | str | None = None) -> "LabConfig":
        config_path = Path(path) if path else paths.lab_config_file()
        if not config_path.is_file():
            # A missing config must not silently widen scope: fall back to
            # defaults, which authorize only the single documented target.
            return cls(data=copy.deepcopy(DEFAULT_CONFIG), source=None)
        try:
            raw = json.loads(config_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ConfigError(f"cannot read configuration {config_path}: {exc}") from exc
        if not isinstance(raw, dict):
            raise ConfigError(f"configuration {config_path} must contain a JSON object")
        return cls(data=_deep_merge(DEFAULT_CONFIG, raw), source=config_path)

    # -- sections ----------------------------------------------------------
    @property
    def lab(self) -> dict[str, Any]:
        return self.data["lab"]

    @property
    def target(self) -> dict[str, Any]:
        return self.data["target"]

    @property
    def http(self) -> dict[str, Any]:
        return self.data["http"]

    @property
    def pipeline(self) -> dict[str, Any]:
        return self.data["pipeline"]

    @property
    def web(self) -> dict[str, Any]:
        return self.data["web"]

    @property
    def lab_name(self) -> str:
        return str(self.lab.get("name") or DEFAULT_CONFIG["lab"]["name"])

    @property
    def authorization_statement(self) -> str:
        return str(self.lab.get("authorization_statement") or "")

    @property
    def authorized_url(self) -> str:
        return str(self.target.get("authorized_url") or DEFAULT_AUTHORIZED_URL)

    @property
    def allowed_hosts(self) -> tuple[str, ...]:
        hosts = self.target.get("allowed_hosts") or list(DEFAULT_ALLOWED_HOSTS)
        return tuple(str(h).strip().lower() for h in hosts if str(h).strip())

    @property
    def allowed_ports(self) -> tuple[int, ...]:
        ports: list[int] = []
        for value in self.target.get("allowed_ports") or [3001]:
            try:
                ports.append(int(value))
            except (TypeError, ValueError):
                continue
        return tuple(sorted(set(ports)))

    @property
    def require_loopback(self) -> bool:
        return bool(self.target.get("require_loopback", True))

    # -- tools -------------------------------------------------------------
    @property
    def tools(self) -> dict[str, Any]:
        return self.data["tools"]

    def tool(self, name: str) -> dict[str, Any]:
        """Return settings for *name*, merged over the built-in defaults.

        Alias spellings are folded into their canonical keys first, so a
        configuration written from the documentation behaves as documented.
        """
        base = copy.deepcopy(DEFAULT_CONFIG["tools"].get(name, {}))
        configured = _normalize_tool_keys(self.tools.get(name), base)
        if configured:
            base = _deep_merge(base, configured)
        base.setdefault("name", name)
        return base

    def tool_names(self) -> list[str]:
        return list(DEFAULT_CONFIG["tools"].keys())

    @property
    def severity_floor(self) -> str:
        return str(self.pipeline.get("severity_floor") or "INFO").upper()

    @property
    def evidence_excerpt_chars(self) -> int:
        try:
            return int(self.pipeline.get("evidence_excerpt_chars", 1200))
        except (TypeError, ValueError):
            return 1200

    def to_dict(self) -> dict[str, Any]:
        return copy.deepcopy(self.data)
