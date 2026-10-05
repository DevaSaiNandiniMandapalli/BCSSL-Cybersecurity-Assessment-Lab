"""Parse Nmap XML output (``-oX``).

The runner requests XML because it is stable and machine-readable. Findings
produced here are *observations about the service*, never vulnerabilities:
Nmap does not assess application security, so every finding is emitted at INFO
and categorised as discovery. Inflating a port scan into a HIGH finding would be
a fabricated result.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from ..models import Finding, utc_now_iso
from ..severity import Severity
from .base import ParseResult, truncate

TOOL = "nmap"


def parse(xml_text: str, target: str = "") -> ParseResult:
    """Parse Nmap XML into normalized findings.

    Args:
        xml_text: verbatim content of the ``-oX`` report file.
        target: authorized target URL, recorded on every finding.

    Returns:
        A :class:`ParseResult`. Malformed or empty input yields warnings rather
        than exceptions so the pipeline can report the problem honestly.
    """
    result = ParseResult()
    text = (xml_text or "").strip()
    if not text:
        result.errors.append("Nmap XML output was empty; nothing could be parsed.")
        return result

    # Tolerate leading banner noise before the XML declaration.
    start = text.find("<?xml")
    if start == -1:
        start = text.find("<nmaprun")
    if start > 0:
        text = text[start:]

    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        result.errors.append(f"Nmap XML could not be parsed: {exc}")
        return result

    timestamp = utc_now_iso()
    hosts = root.findall("host")
    if not hosts:
        result.warnings.append("Nmap reported no hosts in its XML output.")

    open_ports = 0
    for host in hosts:
        host_status = host.find("status")
        state = host_status.get("state", "unknown") if host_status is not None else "unknown"

        addresses = [
            address.get("addr", "")
            for address in host.findall("address")
            if address.get("addr")
        ]
        hostnames = [
            node.get("name", "")
            for node in host.findall("./hostnames/hostname")
            if node.get("name")
        ]
        endpoint = addresses[0] if addresses else (hostnames[0] if hostnames else "localhost")

        if state != "up":
            result.notes.append(f"Host {endpoint} reported state '{state}' and was not scanned further.")
            continue

        for port in host.findall("./ports/port"):
            if (port.find("state") is not None) and (
                port.find("state").get("state") == "open"
            ):
                open_ports += 1
            result.findings.extend(
                _parse_port(port, target=target, host=endpoint, timestamp=timestamp, result=result)
            )

    if open_ports == 0:
        result.notes.append(
            "Nmap found no open ports in the authorized range. This is a genuine "
            "observation, not a parse failure."
        )

    return result


def _parse_port(
    port: ET.Element,
    *,
    target: str,
    host: str,
    timestamp: str,
    result: ParseResult,
) -> list[Finding]:
    findings: list[Finding] = []
    protocol = port.get("protocol", "tcp")
    port_id = port.get("portid", "0")

    state_node = port.find("state")
    state = state_node.get("state", "unknown") if state_node is not None else "unknown"
    reason = state_node.get("reason", "") if state_node is not None else ""

    if state != "open":
        # A closed or filtered port is a legitimate observation but is not a
        # finding: reporting it would overstate the scan result.
        result.notes.append(f"Port {port_id}/{protocol} on {host} is {state}.")
        return []

    service_node = port.find("service")
    service_name = service_node.get("name", "") if service_node is not None else ""
    product = service_node.get("product", "") if service_node is not None else ""
    version = service_node.get("version", "") if service_node is not None else ""
    extrainfo = service_node.get("extrainfo", "") if service_node is not None else ""
    confidence = service_node.get("conf", "") if service_node is not None else ""

    banner = " ".join(part for part in (product, version, extrainfo) if part).strip()

    endpoint = f"{host}:{port_id}/{protocol}"
    description_parts = [
        f"Port {port_id}/{protocol} is {state} on the local lab host.",
    ]
    if reason:
        description_parts.append(f"Nmap reason: {reason}.")
    if service_name:
        description_parts.append(f"Service: {service_name}.")
    if banner:
        description_parts.append(f"Service banner: {banner}.")

    evidence_text = truncate(" ".join(description_parts), 800)

    findings.append(
        Finding(
            tool=TOOL,
            category="open-port",
            severity=Severity.INFO,
            title=f"Open port {port_id}/{protocol} ({service_name or 'unknown service'})",
            description=" ".join(description_parts),
            target=target,
            endpoint=endpoint,
            evidence=evidence_text,
            recommendation=(
                "Confirm this service is intended to be reachable from the local "
                "lab network and is required for the exercise."
            ),
            timestamp=timestamp,
            subject=f"open-port:{port_id}/{protocol}",
            reference=f"nmap:{port_id}/{protocol}",
        )
    )
    result.excerpts[f"Open port {port_id}/{protocol} ({service_name or 'unknown service'})"] = evidence_text

    if banner:
        confidence_note = f" (confidence {confidence})" if confidence else ""
        disclosure = truncate(
            f"Service version banner detected on {endpoint}: {banner}{confidence_note}",
            800,
        )
        title = f"Service version banner disclosed on port {port_id}"
        findings.append(
            Finding(
                tool=TOOL,
                category="technology-disclosure",
                severity=Severity.INFO,
                title=title,
                description=(
                    "Nmap service detection identified software and version "
                    "information from the service banner. Version disclosure "
                    "gives an attacker useful targeting information; it is not "
                    "itself a vulnerability."
                ),
                target=target,
                endpoint=endpoint,
                evidence=disclosure,
                recommendation=(
                    "Suppress or normalise the Server and technology version "
                    "headers in the application configuration."
                ),
                timestamp=timestamp,
                subject="technology-disclosure:service-banner",
                reference=f"nmap:{port_id}",
            )
        )
        result.excerpts[title] = disclosure

    return findings


def parse_text_output(text: str, target: str = "") -> ParseResult:
    """Best-effort parse of plain Nmap console output.

    Used only when XML output was not produced. Findings are informational and
    this path is clearly weaker than the XML parser.
    """
    result = ParseResult()
    if not text.strip():
        result.errors.append("Nmap produced no output to parse.")
        return result

    timestamp = utc_now_iso()
    host_seen = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("Nmap scan report for"):
            host_seen = True
            continue
        if "/" in stripped and ("open" in stripped or "closed" in stripped or "filtered" in stripped):
            port_part = stripped.split()[0]
            state_match = stripped.split(" ", 1)[-1]
            if "open" not in state_match:
                continue
            title = f"Open port {port_part}"
            evidence_text = truncate(stripped, 800)
            result.findings.append(
                Finding(
                    tool=TOOL,
                    category="open-port",
                    severity=Severity.INFO,
                    title=title,
                    description=stripped,
                    target=target,
                    endpoint=port_part,
                    evidence=evidence_text,
                    recommendation="Confirm the service is intended to be locally reachable.",
                    timestamp=timestamp,
                    subject=f"open-port:{port_part}",
                )
            )
            result.excerpts[title] = evidence_text

    if not result.findings and not host_seen:
        result.warnings.append(
            "Nmap console output did not contain a recognisable scan report; "
            "the XML parser is authoritative for this tool."
        )
    return result


def summarize(data: dict[str, Any]) -> dict[str, Any]:
    """Return a short summary dict for run metadata."""
    return {"parser": "nmap-xml", "hosts": len(data.get("hosts", []))}
