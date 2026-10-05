"""SARIF 2.1.0 export of normalized findings.

SARIF (Static Analysis Results Interchange Format) is the interchange format
under OASIS governance. It lets the lab's results be loaded into code-scanning
and dashboard tooling without a bespoke importer.

What this module emits comes **only** from stored normalized findings. It does
not classify, score, deduplicate or invent anything. Every SARIF result
corresponds to exactly one stored finding, and an assessment with no findings
produces a valid, empty SARIF log rather than a fabricated one.

Relevant documents:

* SARIF 2.1.0 specification - https://docs.oasis-open.org/sarif/sarif/v2.1.0/
* ``version`` and ``$schema`` are required; ``runs`` must contain at least one
  run object.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from .models import Finding, utc_now_iso

#: Official SARIF 2.1.0 schema location.
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/"
    "sarif-schema-2.1.0.json"
)
SARIF_VERSION = "2.1.0"

#: Informational URI for the lab tool driver.
TOOL_INFORMATION_URI = "https://example.invalid/bcssl-cybersecurity-assessment-lab"

#: SARIF levels. SARIF has exactly three: error, warning and note. The lab's
#: five severities are mapped conservatively - a finding is only called an
#: "error" when the lab itself rated it CRITICAL or HIGH.
SARIF_ERROR = "error"
SARIF_WARNING = "warning"
SARIF_NOTE = "note"

#: Severity -> SARIF level. ``CRITICAL`` is mapped to error because it is the
#: lab's most severe band; it is documented rather than silently merged.
SEVERITY_TO_LEVEL: dict[str, str] = {
    "CRITICAL": SARIF_ERROR,
    "HIGH": SARIF_ERROR,
    "MEDIUM": SARIF_WARNING,
    "LOW": SARIF_WARNING,
    "INFO": SARIF_NOTE,
}

#: Severity -> SARIF ``security-severity`` (a numeric score in a 0.0-10.0
#: band). These are the lab's own severity bands expressed numerically; they
#: are NOT CVSS scores and the documentation says so.
SEVERITY_TO_SCORE: dict[str, str] = {
    "CRITICAL": "9.5",
    "HIGH": "7.5",
    "MEDIUM": "5.0",
    "LOW": "2.5",
    "INFO": "0.0",
}

#: SARIF result ``kind`` values. The lab only reports reported results.
KIND = "fail"


def severity_to_level(severity: str) -> str:
    """Map a lab severity onto one of SARIF's three levels."""
    return SEVERITY_TO_LEVEL.get(str(severity or "").upper(), SARIF_NOTE)


def _level_rank(level: str) -> int:
    return {SARIF_ERROR: 3, SARIF_WARNING: 2, SARIF_NOTE: 1}.get(level, 0)


def _properties(finding: Finding, tool_run: dict[str, Any]) -> dict[str, Any]:
    """Lab-specific facts carried in ``properties``.

    Everything here is derived from fields the lab already records, so the
    export adds no new claims.
    """
    return {
        "severity": finding.severity.value,
        "verificationStatus": finding.verification_status,
        "category": finding.category,
        "correlationSubject": finding.subject,
        "toolReference": finding.reference or tool_run.get("tool", ""),
        "rawArtifact": finding.source_artifact,
    }


def _region(target: str, endpoint: str) -> dict[str, Any]:
    """A SARIF physical location for the assessed target."""
    uri = endpoint or target
    if not uri:
        return {}
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": uri},
        }
    }


def _result(finding: Finding, target: str, index: int) -> dict[str, Any]:
    severity = finding.severity.value
    level = severity_to_level(severity)
    title = finding.title or f"{finding.tool} finding {index}"

    message_parts = [title]
    if finding.description and finding.description.strip() != title.strip():
        message_parts.append(finding.description.strip())

    result: dict[str, Any] = {
        "ruleId": finding.subject or finding.reference or f"{finding.tool}-finding",
        "level": level,
        "kind": KIND,
        "message": {"text": "\n\n".join(part for part in message_parts if part)},
        "properties": {
            **_properties(finding, {"tool": finding.tool}),
            "precision": "high",
            "security-severity": SEVERITY_TO_SCORE.get(severity, "0.0"),
            "security-severity-basis": (
                "lab severity band, not a CVSS score"
            ),
        },
        "partialFingerprints": {
            # Stable within an assessment: tool + subject + endpoint.
            "bcsslFingerprint/v1": f"{finding.tool}:{finding.subject}:{finding.endpoint}".lower()
        },
    }

    location = _region(target, finding.endpoint)
    if location:
        result["locations"] = [location]

    if finding.recommendation:
        result["fixes"] = [
            {
                "description": {"text": finding.recommendation},
            }
        ]

    # Evidence is carried as a property rather than a snippet: the verbatim
    # artifact stays the authoritative record, referenced by path.
    if finding.evidence:
        result["properties"]["evidenceExcerpt"] = finding.evidence[:2000]

    return result


def build(findings: Iterable[Finding], target: str = "", *, config: Any = None) -> dict[str, Any]:
    """Build a SARIF 2.1.0 log from *findings*.

    Args:
        findings: normalized findings, in any order.
        target: the authorized target the findings refer to.
        config: optional :class:`~bcssl.config.LabConfig`, used only for the
            tool version and the authorization statement.

    Returns:
        A SARIF 2.1.0 document as a plain dictionary. Findings with no tool are
        grouped into a single fallback run so the document always satisfies the
        requirement of at least one run.
    """
    items = list(findings)

    version = ""
    lab_name = "BCSSL Cybersecurity Assessment Lab"
    authorization = ""
    if config is not None:
        settings = getattr(config, "lab", {}) or {}
        version = str(settings.get("version", "") or "")
        lab_name = str(settings.get("name", lab_name) or lab_name)
        authorization = str(
            (getattr(config, "target", {}) or {}).get("authorization_statement", "")
            or getattr(config, "authorization_statement", "")
            or ""
        )

    # One SARIF run per tool, so results stay attributable to their source.
    by_tool: dict[str, list[Finding]] = {}
    for finding in items:
        by_tool.setdefault(finding.tool or "unknown", []).append(finding)

    sarif_runs: list[dict[str, Any]] = []
    for tool in sorted(by_tool):
        subset = sorted(
            by_tool[tool],
            key=lambda f: (
                -_level_rank(severity_to_level(f.severity.value)),
                f.subject,
                f.title,
            ),
        )
        rules = _rules(subset, tool)
        sarif_runs.append(
            {
                "tool": {
                    "driver": {
                        "name": tool,
                        "informationUri": TOOL_INFORMATION_URI,
                        "rules": rules,
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": utc_now_iso(),
                        **(
                            {"properties": {"authorization": authorization}}
                            if authorization
                            else {}
                        ),
                    }
                ],
                "properties": {
                    "target": target,
                    "lab": lab_name,
                    "labVersion": version,
                    "findingCount": len(subset),
                },
                "results": [_result(item, target, index) for index, item in enumerate(subset, 1)],
            }
        )

    if not sarif_runs:
        # A valid SARIF log needs at least one run object, even when nothing was
        # found. An empty result set is reported as an empty result set.
        sarif_runs.append(
            {
                "tool": {"driver": {"name": "bcssl", "informationUri": TOOL_INFORMATION_URI}},
                "invocations": [{"executionSuccessful": True, "endTimeUtc": utc_now_iso()}],
                "properties": {
                    "target": target,
                    "lab": lab_name,
                    "labVersion": version,
                    "findingCount": 0,
                    "note": "No findings were produced by this assessment.",
                },
                "results": [],
            }
        )

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": sarif_runs,
    }


def _rules(subset: list[Finding], tool: str) -> list[dict[str, Any]]:
    """One rule per distinct subject, with short descriptions from the lab."""
    seen: dict[str, dict[str, Any]] = {}
    for finding in subset:
        rule_id = finding.subject or finding.reference or f"{tool}-finding"
        if rule_id in seen:
            continue
        seen[rule_id] = {
            "id": rule_id,
            "name": rule_id.replace("-", " ").replace(":", " ").title()[:80],
            "shortDescription": {"text": finding.title[:200] or rule_id},
            "defaultConfiguration": {
                "level": severity_to_level(finding.severity.value)
            },
            "properties": {"category": finding.category, "tool": finding.tool},
        }
    return [seen[key] for key in sorted(seen)]


def write(log: dict[str, Any], destination: Path) -> Path:
    """Write a SARIF log to *destination* as UTF-8 JSON."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(log, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return destination


def render(assessment: Any) -> dict[str, Any]:
    """Build a SARIF log from a :class:`~bcssl.pipeline.CollectedAssessment`."""
    findings = assessment.all_findings
    target = ""
    if assessment.target is not None:
        target = assessment.target.url
    return build(findings, target, config=assessment.config)


def validate(log: dict[str, Any]) -> list[str]:
    """Check the structural requirements SARIF 2.1.0 imposes.

    Returns:
        A list of problems; empty means the document is structurally valid for
        the subset SARIF the lab emits.
    """
    problems: list[str] = []

    if log.get("version") != SARIF_VERSION:
        problems.append(f"version must be {SARIF_VERSION!r}")
    if "$schema" not in log:
        problems.append("$schema is required")

    runs = log.get("runs")
    if not isinstance(runs, list) or not runs:
        problems.append("runs must be a non-empty array")
        return problems

    for position, run in enumerate(runs):
        label = f"runs[{position}]"
        if not isinstance(run, dict):
            problems.append(f"{label} must be an object")
            continue
        driver = (run.get("tool") or {}).get("driver")
        if not isinstance(driver, dict) or not driver.get("name"):
            problems.append(f"{label}.tool.driver.name is required")
        results = run.get("results")
        if not isinstance(results, list):
            problems.append(f"{label}.results must be an array")
            continue

        rule_ids = {
            rule.get("id")
            for rule in (driver or {}).get("rules", [])
            if isinstance(rule, dict)
        }
        for index, result in enumerate(results):
            where = f"{label}.results[{index}]"
            if not isinstance(result, dict):
                problems.append(f"{where} must be an object")
                continue
            if not result.get("ruleId"):
                problems.append(f"{where}.ruleId is required")
            elif rule_ids and result["ruleId"] not in rule_ids:
                problems.append(
                    f"{where}.ruleId {result['ruleId']!r} has no matching rule"
                )
            level = result.get("level")
            if level is not None and level not in (SARIF_ERROR, SARIF_WARNING, SARIF_NOTE):
                problems.append(f"{where}.level {level!r} is not a SARIF level")
            if not (result.get("message") or {}).get("text"):
                problems.append(f"{where}.message.text is required")

    return problems