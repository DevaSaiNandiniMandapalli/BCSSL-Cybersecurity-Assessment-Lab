"""Per-tool runner implementations.

Each module owns exactly one integration: how to build a safe command for the
authorized target and how to turn that tool's output into normalized findings.
"""

from __future__ import annotations

from .custom import CustomScannerRunner
from .nikto import NiktoRunner
from .nmap import NmapRunner
from .nuclei import NucleiRunner
from .zap import ZapRunner

#: Canonical tool name -> runner class.
RUNNERS: dict[str, type] = {
    "nmap": NmapRunner,
    "zap": ZapRunner,
    "nikto": NiktoRunner,
    "nuclei": NucleiRunner,
    "custom-scanner": CustomScannerRunner,
}

#: Friendly aliases accepted on the command line.
ALIASES: dict[str, str] = {
    "custom": "custom-scanner",
    "scanner": "custom-scanner",
    "web-scanner": "custom-scanner",
    "zaproxy": "zap",
}

__all__ = [
    "ALIASES",
    "RUNNERS",
    "CustomScannerRunner",
    "NiktoRunner",
    "NmapRunner",
    "NucleiRunner",
    "ZapRunner",
    "resolve_runner",
]


def resolve_runner(name: str):
    """Return the runner class for *name*, accepting documented aliases.

    Raises:
        ValueError: when *name* is not a known tool. The caller must not fall
            back to a default tool.
    """
    key = (name or "").strip().lower()
    key = ALIASES.get(key, key)
    if key not in RUNNERS:
        raise ValueError(
            f"unknown tool '{name}'. Known tools: {', '.join(sorted(RUNNERS))}"
        )
    return RUNNERS[key]
