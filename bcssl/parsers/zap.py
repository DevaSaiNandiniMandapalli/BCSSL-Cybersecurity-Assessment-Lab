"""Parse an OWASP ZAP baseline-scan report.

The runner asks ZAP for its JSON report and this module reads the ``alerts``
array. Severity comes from ZAP's ``riskcode`` (3=High, 2=Medium, 1=Low,
0=Informational). ZAP has no CRITICAL level, so the lab never manufactures one
from a ZAP alert.
"""

from __future__ import annotations

import json
from typing import Any

from ..models import Finding, utc_now_iso
from ..severity import Severity, zap_riskcode
from .base import ParseResult, multiline, truncate

TOOL = "zap"


def parse(payload: str | bytes, target: str = "") -> ParseResult:
    """Parse a ZAP JSON report into normalized findings.

    Args:
        payload: contents of the ``-J`` report written by ``zap-baseline.py``.
        target: authorized target URL.

    Returns:
        A :class:`ParseResult`. When the report contains no alerts the result
        is empty with a note explaining that the scan ran and found nothing.
    """
    result = ParseResult()
    if payload is None:
        result.errors.append("ZAP produced no report to parse.")
        return result
    if isinstance(payload, bytes):
        payload = payload.decode("utf-8", errors="replace")

    text = payload.strip()
    if not text:
        result.errors.append("ZAP report was empty; nothing could be parsed.")
        return result

    try:
        data = json.loads(text)
    except ValueError as exc:
        result.errors.append(f"ZAP JSON report could not be parsed: {exc}")
        return result

    if not isinstance(data, dict):
        result.errors.append("ZAP report did not contain a JSON object.")
        return result

    alerts = data.get("alerts")

    if alerts is None:
        # Current ZAP releases replaced the top-level 'alerts' array with an
        # 'insights' model in the JSON report. That is a *valid* report, not a
        # broken one: record the crawl statistics and report zero findings
        # honestly instead of claiming a parse failure.
        statistics = _collect_statistics(data)
        if statistics is not None:
            result.notes.extend(statistics)
            result.notes.append(
                "ZAP produced a modern-format report which contains no classic "
                "alert entries. Zero findings is the genuine result for this "
                "scan at the configured alert threshold; lower "
                "tools.zap.alert_threshold to surface Low risk passive alerts."
            )
            return result
        result.errors.append(
            "ZAP report contained neither an 'alerts' array nor an 'insights' "
            "model; this is not a recognised ZAP report."
        )
        return result

    if not isinstance(alerts, list):
        result.errors.append("ZAP report 'alerts' field was not a list.")
        return result

    timestamp = utc_now_iso()
    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        finding = _parse_alert(alert, target=target, timestamp=timestamp)
        if finding is not None:
            result.findings.append(finding)
            result.excerpts[finding.title] = finding.evidence

    result.notes.extend(_collect_statistics(data) or [])

    if not alerts:
        result.notes.append(
            "ZAP completed the scan and reported no alerts at the configured "
            "alert threshold. No findings is a valid result."
        )
    return result


def _collect_statistics(data: dict[str, Any]) -> list[str] | None:
    """Extract crawl statistics from a ZAP report, if the model has them.

    Returns ``None`` when the report carries no statistics at all, which means
    it is not a ZAP report this parser understands.
    """
    insights = data.get("insights")
    if not isinstance(insights, list):
        return None

    wanted = {
        "insight.endpoint.total": "endpoints discovered",
        "insight.code.2xx": "responses with 2xx",
        "insight.code.3xx": "responses with 3xx",
        "insight.code.4xx": "responses with 4xx",
        "insight.code.5xx": "responses with 5xx",
        "insight.response.slow": "slow responses",
        "insight.log.warn": "ZAP warnings logged",
    }
    notes: list[str] = []
    for insight in insights:
        if not isinstance(insight, dict):
            continue
        key = str(insight.get("key") or "")
        label = wanted.get(key)
        if not label:
            continue
        statistic = insight.get("statistic")
        if isinstance(statistic, dict):
            value = statistic.get("value", statistic.get("count"))
        else:
            value = statistic
        notes.append(f"ZAP scan statistic: {label} = {value}")

    version = data.get("@version")
    if version:
        notes.insert(0, f"ZAP version reported in the report: {version}")
    return notes


def _parse_alert(
    alert: dict[str, Any],
    *,
    target: str,
    timestamp: str,
) -> Finding | None:
    title = str(
        alert.get("alert") or alert.get("name") or alert.get("pluginId") or ""
    ).strip()
    if not title:
        return None

    severity = zap_riskcode(alert.get("riskcode"))
    plugin_id = str(alert.get("pluginId", "")).strip()
    risk_desc = str(alert.get("riskdesc", "")).strip()
    confidence = str(alert.get("confidence", "")).strip()
    url = str(alert.get("url", "")).strip()
    method = str(alert.get("method", "")).strip()
    param = str(alert.get("param", "")).strip()
    desc = str(alert.get("desc", "")).strip()
    solution = str(alert.get("solution", "")).strip()
    evidence_raw = str(alert.get("evidence", "")).strip()
    reference = str(alert.get("reference", "")).strip()
    cwe = str(alert.get("cweid", "")).strip()
    wasc = str(alert.get("wasc", "")).strip()

    endpoint = url or (f"{method} {target}".strip() if target else "")
    if method and param:
        endpoint = f"{url}{url + '?' if url and '?' not in url else ''}{param}={param}"

    evidence_parts: list[str] = []
    if risk_desc:
        evidence_parts.append(f"ZAP risk: {risk_desc}")
    if confidence:
        evidence_parts.append(f"ZAP confidence: {confidence}")
    if desc:
        evidence_parts.append(desc)
    if evidence_raw:
        evidence_parts.append(f"Evidence:\n{multiline(evidence_raw, 800)}")
    evidence = truncate("\n".join(evidence_parts), 1200)

    description = desc or f"ZAP alert {title}."
    if risk_desc:
        description = f"{description} (ZAP risk: {risk_desc})"

    if not solution:
        solution = (
            "Review this alert against the ZAP alert reference and remediate "
            "accordingly if the condition applies to this application."
        )

    reference_bits = [bit for bit in (f"pluginId {plugin_id}" if plugin_id else "",) if bit]
    if cwe:
        reference_bits.append(f"CWE {cwe}")
    if wasc:
        reference_bits.append(f"WASC {wasc}")

    return Finding(
        tool=TOOL,
        category=_category_for(title),
        severity=severity,
        title=title,
        description=truncate(description, 1200),
        target=target,
        endpoint=endpoint,
        evidence=evidence,
        recommendation=truncate(solution, 800),
        timestamp=timestamp,
        reference="; ".join(reference_bits),
    )


def _category_for(title: str) -> str:
    """Assign a lab category from the ZAP alert name."""
    lowered = title.lower()
    if any(
        token in lowered
        for token in ("header", "clickjacking", "csp", "content security policy")
    ):
        return "security-header"
    if "cookie" in lowered:
        return "cookie"
    if any(token in lowered for token in ("information disclosure", "version disclosure")):
        return "information-disclosure"
    if "redirect" in lowered:
        return "misconfiguration"
    if "https" in lowered or "tls" in lowered or "ssl" in lowered:
        return "tls"
    if "injection" in lowered or "xss" in lowered or "sql" in lowered:
        return "injection"
    return "vulnerability"


def version_from_report(payload: str | bytes) -> str:
    """Extract ZAP's own version string from the report, when present."""
    try:
        text = payload.decode("utf-8", errors="replace") if isinstance(payload, bytes) else payload
        data = json.loads(text)
    except (ValueError, AttributeError):
        return ""
    if isinstance(data, dict):
        for key in ("@version", "version"):
            value = data.get(key)
            if value:
                return str(value)
    return ""
