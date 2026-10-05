"""Parse Nikto JSON output (``-Format json``).

Two output generations exist in the wild and both are supported:

**Legacy (Nikto 2.1.x, e.g. the ``alpine/nikto`` image):**

.. code-block:: json

    {"host": "localhost", "ip": "127.0.0.1", "port": "3001",
     "vulnerabilities": [{"id": "999102", "OSVDB": "0",
                          "method": "GET", "url": "/", "msg": "..."}]}

**Current (Nikto 2.5.x):**

.. code-block:: json

    [{"msg": "+ Nikto v2.5.0", "nikto": "2.5.0"},
     {"msg": "+ OSVDB-12345: ... - Severity: high", "osvdbid": "12345"}]

Nikto does not assign a reliable severity, so severity is taken from an explicit
``Severity: x`` marker when present. A matched OSVDB reference is recorded at
LOW; everything else stays informational. Nothing is inflated.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urljoin

from ..models import Finding, utc_now_iso
from ..severity import Severity, nikto_rating
from .base import ParseResult, truncate

TOOL = "nikto"

_SEVERITY_MARKER = re.compile(r"\bSeverity:\s*(\w+)", re.I)
_OSVDB_ID = re.compile(r"OSVDB-(\d+)", re.I)
_FOUND_MARKER = re.compile(r"\(found\b", re.I)

#: Message fragments that are context, not findings.
_CONTEXT_PREFIXES = (
    "target ip:",
    "target hostname:",
    "target port:",
    "start time:",
    "end time:",
    "server:",
)

#: Retrieval-only messages: the header was read, nothing was judged.
_RETRIEVAL_ONLY = re.compile(
    r"^retrieved\s+\S+\s+header", re.I
)


def parse(payload: str | bytes, target: str = "") -> ParseResult:
    """Parse a Nikto JSON report into normalized findings.

    Args:
        payload: contents of the ``-Format json`` report.
        target: authorized target URL.

    Returns:
        A :class:`ParseResult`. An empty result with a note means Nikto ran and
        reported nothing; an error means the report could not be understood.
    """
    result = ParseResult()
    if payload is None:
        result.errors.append("Nikto produced no report to parse.")
        return result
    if isinstance(payload, bytes):
        payload = payload.decode("utf-8", errors="replace")

    text = (payload or "").strip()
    if not text:
        result.errors.append("Nikto report was empty; nothing could be parsed.")
        return result

    try:
        data = json.loads(text)
    except ValueError as exc:
        result.errors.append(f"Nikto JSON report could not be parsed: {exc}")
        return result

    timestamp = utc_now_iso()

    if isinstance(data, dict):
        # Legacy 2.1.x object shape.
        items = data.get("vulnerabilities")
        if items is None:
            result.errors.append(
                "Nikto report contained no 'vulnerabilities' array; this is not "
                "a recognised Nikto JSON report."
            )
            return result
        if not isinstance(items, list):
            result.errors.append("Nikto report 'vulnerabilities' field was not a list.")
            return result
        version = ""
        banner = str(data.get("banner") or "").strip()
        if banner:
            result.notes.append(f"Nikto reported a server banner: {truncate(banner, 200)}")
        for record in items:
            if isinstance(record, dict):
                _emit_legacy(record, data, target, timestamp, result)
    elif isinstance(data, list):
        # Current flat record stream.
        version = ""
        for record in data:
            if isinstance(record, str):
                record = {"msg": record}
            if not isinstance(record, dict):
                continue
            message = str(record.get("msg") or "").strip()
            if not message:
                continue
            if record.get("nikto"):
                version = f"{message} ({record['nikto']})"
                continue
            _emit_stream_record(record, message, target, timestamp, result)
    else:
        result.errors.append("Nikto report was neither an object nor a list of records.")
        return result

    if version:
        result.notes.append(f"Nikto version: {version}")
    if not result.findings:
        result.notes.append(
            "Nikto completed with the configured safe tuning and reported no "
            "items. No findings is a valid result for this tuning selection."
        )
    return result


# ---------------------------------------------------------------------------
# Legacy 2.1.x records
# ---------------------------------------------------------------------------
def _emit_legacy(
    record: dict[str, Any],
    envelope: dict[str, Any],
    target: str,
    timestamp: str,
    result: ParseResult,
) -> None:
    message = str(record.get("msg") or "").strip()
    if not message or _is_context(message):
        return

    raw_url = str(record.get("url") or "").strip()
    method = str(record.get("method") or "").strip()
    plugin_id = str(record.get("id") or "").strip()
    osvdb = str(record.get("OSVDB") or record.get("osvdbid") or "").strip()

    endpoint = _absolute(raw_url, target)
    title = _legacy_title(message, raw_url)
    severity = _legacy_severity(message, osvdb)

    finding = Finding(
        tool=TOOL,
        category=_category_for(message, title),
        severity=severity,
        title=title,
        description=truncate(message, 1000),
        target=target,
        endpoint=endpoint,
        evidence=truncate(_evidence_text(message, method, raw_url), 1000),
        recommendation=_recommendation_for(message),
        timestamp=timestamp,
        reference=_reference_for(plugin_id, osvdb),
    )
    result.findings.append(finding)
    result.excerpts[title] = finding.evidence


def _legacy_title(message: str, raw_url: str) -> str:
    cleaned = re.sub(r"^\+\s*", "", message).strip().rstrip()
    # Generic per-path messages are far clearer when the path is named.
    if raw_url and raw_url not in cleaned and len(cleaned) < 70:
        cleaned = f"{cleaned.rstrip('.')} ({raw_url})"
    return truncate(cleaned, 140)


def _legacy_severity(message: str, osvdb: str) -> Severity:
    explicit = nikto_rating(message, default=Severity.INFO)
    if explicit is not Severity.INFO:
        return explicit
    if osvdb and osvdb not in ("0", "-1"):
        return Severity.LOW
    return Severity.INFO


def _reference_for(plugin_id: str, osvdb: str) -> str:
    parts: list[str] = []
    if plugin_id and plugin_id not in ("0", "999999"):
        parts.append(f"pluginId {plugin_id}")
    if osvdb and osvdb not in ("0", "-1"):
        parts.append(f"OSVDB-{osvdb}")
    return "; ".join(parts)


def _evidence_text(message: str, method: str, raw_url: str) -> str:
    parts = [message]
    if method and raw_url:
        parts.append(f"Requested: {method} {raw_url}")
    return " | ".join(parts)


# ---------------------------------------------------------------------------
# Current (2.5.x) stream records
# ---------------------------------------------------------------------------
def _emit_stream_record(
    record: dict[str, Any],
    message: str,
    target: str,
    timestamp: str,
    result: ParseResult,
) -> None:
    if _is_context(message) or _RETRIEVAL_ONLY.match(message):
        return

    osvdb = str(record.get("osvdbid") or record.get("osvdb") or "").strip()
    match = _OSVDB_ID.search(message)
    if match and not osvdb:
        osvdb = match.group(1)

    severity = nikto_rating(message)
    if severity is Severity.INFO and osvdb and osvdb not in ("0", "-1"):
        severity = Severity.LOW

    is_found = bool(_FOUND_MARKER.search(message))
    title = _stream_title(message, record, is_found)

    finding = Finding(
        tool=TOOL,
        category=_category_for(message, title),
        severity=severity,
        title=title,
        description=truncate(message, 1000),
        target=target,
        endpoint=_absolute(_stream_url(message, record), target),
        evidence=truncate(message, 1000),
        recommendation=_recommendation_for(message),
        timestamp=timestamp,
        reference=_reference_for("", osvdb),
    )
    result.findings.append(finding)
    result.excerpts[finding.title] = finding.evidence


def _stream_title(message: str, record: dict[str, Any], is_found: bool) -> str:
    cleaned = re.sub(r"^\+\s*", "", message).strip()
    if is_found:
        cleaned = re.sub(r"\s*\(found.*?\)\s*$", "", cleaned, flags=re.I).strip()
        cleaned = cleaned or "Nikto reported an accessible resource"
    match = _OSVDB_ID.search(cleaned)
    if match:
        prefix = cleaned[: match.start()].strip(" +-:")
        if prefix:
            cleaned = prefix
    url = str(record.get("url") or "").strip()
    if url and url not in cleaned and len(cleaned) < 70:
        cleaned = f"{cleaned.rstrip('.')} ({url})"
    return truncate(cleaned, 140)


def _stream_url(message: str, record: dict[str, Any]) -> str:
    url = str(record.get("url") or "").strip()
    if url:
        return url
    match = re.search(r"(/[^\s'\"]+)", message)
    return match.group(1) if match else ""


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------
def _is_context(message: str) -> bool:
    lowered = message.strip().lower()
    # Nikto prefixes most lines with "+ ", so strip it before matching.
    if lowered.startswith("+ "):
        lowered = lowered[2:].lstrip()
    return lowered.startswith(_CONTEXT_PREFIXES)


def _absolute(path: str, target: str) -> str:
    if not path:
        return target
    if path.startswith(("http://", "https://")):
        return path
    if not target:
        return path
    return urljoin(target if target.endswith("/") else target + "/", path.lstrip("/"))


def _category_for(message: str, title: str) -> str:
    lowered = f"{message} {title}".lower()
    if any(token in lowered for token in ("not defined", "header is not", "uncommon header")):
        if "uncommon header" in lowered:
            return "information-disclosure"
        return "security-header"
    if "cookie" in lowered:
        return "cookie"
    if "backup" in lowered or "potentially interesting" in lowered:
        return "path-discovery"
    if "robots.txt" in lowered:
        return "path-discovery"
    if any(token in lowered for token in ("server", "banner", "software", "powered")):
        return "technology-disclosure"
    if any(token in lowered for token in ("outdated", "vulnerable", "cve", "osvdb")):
        return "web-server-config"
    if any(token in lowered for token in ("admin", "login", "restricted")):
        return "path-discovery"
    return "path-discovery"


def _recommendation_for(message: str) -> str:
    lowered = message.lower()
    if "not defined" in lowered and "header" in lowered:
        return (
            "Review whether this header should be set; absent headers reduce "
            "the browser's defensive behaviour and should be configured "
            "deliberately."
        )
    if "uncommon header" in lowered:
        return (
            "Review whether this header is required; unusual headers disclose "
            "implementation detail and can assist reconnaissance."
        )
    if "backup" in lowered or "potentially interesting" in lowered:
        return (
            "Confirm this resource should be publicly reachable on the lab "
            "target; backup or archive files should not be served."
        )
    if "robots.txt" in lowered:
        return (
            "Review robots.txt so it does not disclose paths that should not "
            "be discoverable."
        )
    return (
        "Review this item against the local lab target and remediate if the "
        "condition applies to this deployment."
    )


def version_from_report(payload: str | bytes) -> str:
    """Return Nikto's version string from either output generation."""
    try:
        text = payload.decode("utf-8", errors="replace") if isinstance(payload, bytes) else payload
        data = json.loads(text)
    except (ValueError, AttributeError):
        return ""
    if isinstance(data, list):
        for record in data:
            if isinstance(record, dict) and record.get("nikto"):
                return str(record.get("msg", "")).strip()
    return ""
