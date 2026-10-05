"""BCSSL Cybersecurity Assessment Lab - engine package.

An authorized, local-only assessment laboratory that runs a single training
target through several security tools, normalizes their output into one
finding schema, correlates overlapping findings, records evidence and produces
a consolidated report.

Safety invariants enforced by this package:

* Every tool invocation is preceded by :func:`bcssl.target.validate_target`.
* Only the configured loopback target (by default ``http://localhost:3001``)
  is ever contacted.
* A tool that is not installed is reported as ``TOOL NOT INSTALLED``; no
  findings are ever invented.
"""

from __future__ import annotations

__version__ = "1.0.0"
__all__ = [
    "__version__",
    "config",
    "correlation",
    "evidence",
    "executor",
    "lab",
    "models",
    "parsers",
    "paths",
    "preflight",
    "reporting",
    "runners",
    "severity",
    "target",
]
