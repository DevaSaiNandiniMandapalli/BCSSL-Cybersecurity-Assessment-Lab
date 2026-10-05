"""Cross-tool finding correlation.

Two findings are treated as the same issue only when they share an **exact**
normalized fingerprint (``category::subject``). Similar wording alone is never
enough. This is deliberate: the report's credibility depends on not claiming
that two tools confirmed something when only one of them looked for it.

Outcome labels:

* ``Confirmed by multiple tools`` - two or more *distinct* tools reported the
  same fingerprint.
* ``Single-tool observation``      - only one tool reported it, however many
  endpoints it appeared on.

A group produced twice by the same tool is still a single-tool observation.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Iterable

from .models import Finding
from .severity import Severity, worst

CONFIRMED = "Confirmed by multiple tools"
SINGLE = "Single-tool observation"

#: Verification statuses applied to findings by this module. Imported lazily to
#: avoid a circular import with :mod:`bcssl.verify`.
STATUS_CORROBORATED = "CORROBORATED"
STATUS_SINGLE = "SINGLE-TOOL OBSERVATION"

#: Findings whose subject is a free-text title slug are excluded from
#: confirmation, because two tools would rarely produce the identical wording
#: and an accidental match would be meaningless.
_SLUG_PREFIX = "title:"


@dataclass
class CorrelationGroup:
    """All findings sharing one fingerprint."""

    fingerprint: str
    category: str
    subject: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def tools(self) -> list[str]:
        return sorted({finding.tool for finding in self.findings})

    @property
    def tool_count(self) -> int:
        """Number of distinct tools that reported this fingerprint."""
        return len(self.tools)

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def endpoints(self) -> list[str]:
        return sorted({f.endpoint for f in self.findings if f.endpoint})

    @property
    def severity(self) -> Severity:
        return worst(finding.severity for finding in self.findings)

    @property
    def severity_counts(self) -> dict[str, int]:
        counts = {level.value: 0 for level in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    @property
    def is_confirmed(self) -> bool:
        """True only when two or more distinct tools reported the fingerprint.

        The check is on :attr:`subject`, not on the full fingerprint: a
        fingerprint is ``"<category>::<subject>"``, so testing it for the slug
        prefix would never match and wording-derived matches would wrongly be
        presented as multi-tool confirmation.
        """
        if self.subject.startswith(_SLUG_PREFIX):
            return False
        return len(self.tools) >= 2

    @property
    def label(self) -> str:
        return CONFIRMED if self.is_confirmed else SINGLE

    @property
    def title(self) -> str:
        """Representative title: the most severe finding's title."""
        ordered = sorted(
            self.findings, key=lambda f: (-f.severity.rank, f.tool, f.title)
        )
        return ordered[0].title if ordered else self.fingerprint

    @property
    def description(self) -> str:
        ordered = sorted(self.findings, key=lambda f: -f.severity.rank)
        for finding in ordered:
            if finding.description:
                return finding.description
        return ""

    @property
    def recommendation(self) -> str:
        for finding in sorted(self.findings, key=lambda f: -f.severity.rank):
            if finding.recommendation:
                return finding.recommendation
        return ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "category": self.category,
            "subject": self.subject,
            "label": self.label,
            "confirmed_by_multiple_tools": self.is_confirmed,
            "severity": self.severity.value,
            "severity_counts": self.severity_counts,
            "title": self.title,
            "description": self.description,
            "recommendation": self.recommendation,
            "tools": self.tools,
            "tool_count": len(self.tools),
            "endpoints": self.endpoints,
            "finding_count": len(self.findings),
            "findings": [finding.to_internal_dict() for finding in self.findings],
        }


@dataclass
class CorrelationReport:
    """Result of correlating one or more tool runs."""

    groups: list[CorrelationGroup] = field(default_factory=list)
    duplicate_count: int = 0
    notes: list[str] = field(default_factory=list)

    @property
    def confirmed(self) -> list[CorrelationGroup]:
        return [group for group in self.groups if group.is_confirmed]

    @property
    def single(self) -> list[CorrelationGroup]:
        return [group for group in self.groups if not group.is_confirmed]

    @property
    def contributing_tools(self) -> list[str]:
        tools: set[str] = set()
        for group in self.groups:
            tools.update(group.tools)
        return sorted(tools)

    def summary(self) -> dict[str, Any]:
        return {
            "total_groups": len(self.groups),
            "confirmed_by_multiple_tools": len(self.confirmed),
            "single_tool_observations": len(self.single),
            "duplicates_within_a_tool": self.duplicate_count,
            "contributing_tools": self.contributing_tools,
            "notes": list(self.notes),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary(),
            "groups": [group.to_dict() for group in self.groups],
        }


def _dedupe_key(finding: Finding) -> tuple[str, str, str]:
    return (finding.tool, finding.fingerprint, finding.endpoint or finding.title)


def correlate(findings: Iterable[Finding]) -> CorrelationReport:
    """Group *findings* by fingerprint and label each group honestly.

    Identical repeats from a single tool (same tool, fingerprint and endpoint)
    are collapsed and counted so the report can state that duplicates were
    removed rather than hiding them.
    """
    report = CorrelationReport()
    groups: "OrderedDict[str, CorrelationGroup]" = OrderedDict()
    seen: set[tuple[str, str, str]] = set()

    for finding in findings:
        key = _dedupe_key(finding)
        if key in seen:
            report.duplicate_count += 1
            continue
        seen.add(key)

        group = groups.get(finding.fingerprint)
        if group is None:
            group = CorrelationGroup(
                fingerprint=finding.fingerprint,
                category=finding.category,
                subject=finding.subject,
            )
            groups[finding.fingerprint] = group
        group.findings.append(finding)

    if report.duplicate_count:
        report.notes.append(
            f"{report.duplicate_count} duplicate finding record(s) from the same "
            "tool and endpoint were collapsed during correlation."
        )

    report.groups = sorted(
        groups.values(),
        key=lambda group: (
            -group.severity.rank,
            not group.is_confirmed,
            -len(group.tools),
            group.fingerprint,
        ),
    )

    # Stamp each finding with how much weight correlation gives it. This runs
    # before any independent verification, which may only upgrade a status.
    for group in report.groups:
        status = STATUS_CORROBORATED if group.is_confirmed else STATUS_SINGLE
        for finding in group.findings:
            finding.verification_status = status

    multi_tool_groups = [group for group in report.groups if len(group.tools) >= 2]
    slug_only = [
        group
        for group in multi_tool_groups
        if group.subject.startswith(_SLUG_PREFIX)
    ]
    if slug_only:
        report.notes.append(
            "Some findings matched on wording-derived fingerprints; because two "
            "tools rarely word an issue identically, those groups are reported as "
            "single-tool observations rather than confirmed findings."
        )
    return report
