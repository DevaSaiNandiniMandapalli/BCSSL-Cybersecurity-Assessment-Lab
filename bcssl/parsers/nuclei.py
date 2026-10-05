"""Parse Nuclei JSONL output (``-json -o file``).

Nuclei emits one JSON object per line. Field names differ slightly between
releases (``template-id`` vs ``templateID``, ``matcher-name`` vs
``matched-at``), so both spellings are accepted.
"""

from __future__ import annotations

import json
from typing import Any, Iterable

from ..models import Finding, utc_now_iso
from ..severity import Severity
from .base import ParseResult, truncate

TOOL = "nuclei"


def parse(payload: str | bytes, target: str = "") -> ParseResult:
    """Parse Nuclei JSONL output into normalized findings."""
    result = ParseResult()
    if payload is None:
        result.errors.append("Nuclei produced no output to parse.")
        return result
    if isinstance(payload, bytes):
        payload = payload.decode("utf-8", errors="replace")

    lines = [line for line in (payload or "").splitlines() if line.strip()]
    if not lines:
        result.notes.append(
            "Nuclei produced no results. With no-update-templates and the "
            "configured severity filter this can legitimately mean no template "
            "matched the target."
        )
        return result

    timestamp = utc_now_iso()
    unparsed = 0
    json_lines = 0
    non_json_samples: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped.startswith("{"):
            # Banner/statistics/console output. Remembered for diagnostics: a
            # console stream in the results file means the output format flag
            # was missing, which must not be reported as "no findings".
            if stripped and len(non_json_samples) < 5:
                non_json_samples.append(_strip_ansi(stripped)[:160])
            continue
        json_lines += 1
        try:
            record = json.loads(stripped)
        except ValueError:
            unparsed += 1
            continue
        if not isinstance(record, dict):
            unparsed += 1
            continue
        finding = _parse_record(record, target=target, timestamp=timestamp)
        if finding is not None:
            result.findings.append(finding)
            result.excerpts[finding.title] = finding.evidence
        else:
            unparsed += 1

    if non_json_samples and json_lines == 0:
        # Every line was console output: this is a format mismatch, not an
        # empty result. Reporting zero findings here would be dishonest.
        result.errors.append(
            "Nuclei wrote console output instead of JSONL results, so no "
            "findings could be parsed. Nuclei needs the JSONL output flag "
            "(nuclei 3: -j / -jsonl; set tools.nuclei.json_flag). "
            "First output line was: " + non_json_samples[0]
        )
    elif non_json_samples:
        result.warnings.append(
            f"{len(lines) - json_lines} non-JSON line(s) ignored alongside "
            f"{json_lines} result line(s)."
        )

    if unparsed:
        result.warnings.append(
            f"{unparsed} Nuclei output line(s) could not be interpreted as results."
        )
    if not result.findings and not unparsed and not result.errors:
        result.notes.append("Nuclei ran to completion and matched no templates.")
    return result


def _strip_ansi(text: str) -> str:
    """Remove ANSI colour escapes from captured tool output."""
    import re

    return re.sub(r"\x1b\[[0-9;]*m", "", text or "")


def _first(record: dict[str, Any], *keys: str, default: str = "") -> str:
    for key in keys:
        value = record.get(key)
        if value not in (None, ""):
            return str(value)
    return default


def _parse_record(
    record: dict[str, Any],
    *,
    target: str,
    timestamp: str,
) -> Finding | None:
    info = record.get("info")
    info = info if isinstance(info, dict) else {}

    template_id = _first(record, "template-id", "templateID", "template_id")
    name = _first(info, "name", default=template_id)
    if not name:
        return None

    severity = Severity.from_string(_first(info, "severity", default="info"))
    matched_at = _first(record, "matched-at", "matched_at", "matched")
    host = _first(record, "host", "matched_at")
    endpoint = matched_at or host or target

    matcher = _first(record, "matcher-name", "matcher_name", "type")
    description = _first(info, "description")
    remediation = _first(info, "remediation")
    reference = info.get("reference")
    tags = info.get("tags")

    evidence_parts: list[str] = []
    if matcher:
        evidence_parts.append(f"Matcher: {matcher}")
    if endpoint:
        evidence_parts.append(f"Matched at: {endpoint}")
    extracted = record.get("extracted-results") or record.get("extracted_results")
    if extracted:
        joined = ", ".join(str(item) for item in extracted) if isinstance(extracted, list) else str(extracted)
        evidence_parts.append(f"Extracted: {truncate(joined, 300)}")
    if description:
        evidence_parts.append(description)
    evidence = truncate("\n".join(evidence_parts), 1200)

    title = name if not template_id or template_id in name else f"{name} ({template_id})"

    reference_bits: list[str] = []
    if template_id:
        reference_bits.append(template_id)
    if isinstance(reference, list) and reference:
        reference_bits.append(truncate(", ".join(str(r) for r in reference), 300))
    elif reference:
        reference_bits.append(str(reference))
    if isinstance(tags, list) and tags:
        reference_bits.append(f"tags: {', '.join(str(t) for t in tags)}")

    if not remediation:
        remediation = (
            "Review this template's reference material and remediate if the "
            "condition applies to this application."
        )

    return Finding(
        tool=TOOL,
        category=_category_for(str(name)),
        severity=severity,
        title=title,
        description=truncate(description or f"Nuclei template matched: {title}", 1000),
        target=target or host,
        endpoint=endpoint,
        evidence=evidence,
        recommendation=truncate(str(remediation), 800),
        timestamp=timestamp,
        subject=_subject_for(str(name)),
        reference="; ".join(reference_bits),
    )


def _category_for(name: str) -> str:
    lowered = name.lower()
    if "header" in lowered or "clickjacking" in lowered:
        return "security-header"
    if "cookie" in lowered:
        return "cookie"
    if any(token in lowered for token in ("technology", "tech-detect", "fingerprint")):
        return "technology-disclosure"
    if "disclosure" in lowered or "exposure" in lowered:
        return "information-disclosure"
    if any(token in lowered for token in ("tls", "ssl", "https", "certificate")):
        return "tls"
    if any(token in lowered for token in ("xss", "injection", "sqli", "sql injection")):
        return "injection"
    return "vulnerability"


def _subject_for(name: str) -> str:
    lowered = name.lower()
    # Align subjects with the shared correlation vocabulary where the template
    # clearly describes the same condition another tool reports.
    if "clickjacking" in lowered or "x-frame-options" in lowered:
        return "missing-header:frame-options"
    if "content security policy" in lowered or "csp" in lowered:
        return "missing-header:csp"
    if "x-content-type-options" in lowered or "nosniff" in lowered:
        return "missing-header:nosniff"
    if "strict-transport-security" in lowered or "hsts" in lowered:
        return "missing-header:hsts"
    if "referrer-policy" in lowered:
        return "missing-header:referrer-policy"
    if "missing security header" in lowered or "security headers" in lowered:
        return "missing-header:generic"
    return ""


def template_ids(findings: Iterable[Any]) -> list[str]:
    """Extract template ids from already-parsed findings (report helper)."""
    ids: list[str] = []
    for finding in findings:
        for part in str(getattr(finding, "reference", "")).split(";"):
            candidate = part.strip()
            if candidate and " " not in candidate and candidate not in ids:
                ids.append(candidate)
    return ids
