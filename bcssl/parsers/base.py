"""Shared parser plumbing.

A parser converts one tool's captured output into :class:`Finding` objects. It
must never invent findings: an empty parse result with a clear warning is the
correct outcome for output the parser does not recognise.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..models import Finding


@dataclass
class ParseResult:
    """Findings plus everything the parser wants the user to know."""

    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    #: Extra files produced by the tool that belong to the evidence trail.
    artifacts: list[str] = field(default_factory=list)
    #: Raw excerpts keyed by finding title, used to build evidence records.
    excerpts: dict[str, str] = field(default_factory=dict)

    def extend(self, other: "ParseResult") -> "ParseResult":
        self.findings.extend(other.findings)
        self.warnings.extend(other.warnings)
        self.errors.extend(other.errors)
        self.notes.extend(other.notes)
        self.artifacts.extend(other.artifacts)
        self.excerpts.update(other.excerpts)
        return self

    @property
    def count(self) -> int:
        return len(self.findings)


def truncate(text: str | None, limit: int = 1200) -> str:
    """Collapse and clip *text* for storage in a finding or evidence file."""
    if not text:
        return ""
    collapsed = " ".join(str(text).split())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[:limit].rstrip() + " [...]"


def multiline(text: str | None, limit: int = 1200) -> str:
    """Trim a multi-line block (HTTP responses, headers) without reflowing it."""
    if not text:
        return ""
    lines = str(text).replace("\r\n", "\n").split("\n")
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    clipped = lines[:60]
    body = "\n".join(clipped)
    if len(body) > limit:
        body = body[:limit].rstrip() + "\n[...]"
    return body


__all__ = ["ParseResult", "Finding", "truncate", "multiline", "Any"]
