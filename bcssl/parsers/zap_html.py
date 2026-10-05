"""Parse an OWASP ZAP HTML report.

Current ZAP releases do **not** include the classic ``alerts`` array in the JSON
report produced by ``-J``; the alerts live in the HTML report instead. This
module reads that HTML so the lab does not silently under-report a successful
ZAP scan.

Two structures are used:

1. ``<table class="alerts">`` - the summary table, one row per alert, with the
   plugin id in an ``<a href="#10038">`` anchor and the risk in ``class="risk-N"``.
2. The per-alert detail blocks that follow, each introduced by
   ``<a id="10038">``, containing Description, Solution and a repeated set of
   URL / Method / Evidence rows.

Only the report's own text is read. Nothing is executed and no request is made.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Any

from ..models import Finding, utc_now_iso
from ..severity import Severity
from .base import ParseResult, multiline, truncate

TOOL = "zap"

_ANCHOR_ID = re.compile(r"^#?(\d{3,6})$")
_RISK_CLASS = re.compile(r"risk-(\d)")
_RISK_BY_NAME = {
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFO,
    "info": Severity.INFO,
}


class _ZapHtmlParser(HTMLParser):
    """Collect alert summaries and their detail blocks."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.summaries: list[dict[str, Any]] = []
        self.details: dict[str, dict[str, Any]] = {}

        self._in_alerts_table = False
        self._table_depth = 0
        self._row: dict[str, Any] | None = None
        self._cell: str | None = None
        self._buffer: list[str] = []

        # Per-alert detail capture
        self._detail_id: str | None = None
        self._d_cells: list[str] = []
        self._d_index: int = 0

    # -- helpers -----------------------------------------------------------
    def _flush_cell(self) -> None:
        if self._row is None or self._cell is None:
            self._buffer = []
            return
        value = " ".join("".join(self._buffer).split())
        self._row[self._cell] = value
        self._buffer = []
        self._cell = None

    def _flush_row(self) -> None:
        row = self._row
        self._row = None
        if not row:
            return
        name = str(row.get("name", "")).strip()
        risk = str(row.get("risk", "")).strip()
        plugin_id = str(row.get("plugin_id", "")).strip()

        # The table starts with a header row ("Name | Risk Level | Number of
        # Instances"). Accepting it would create a fictitious finding, so a row
        # must carry a real alert name and a recognised risk level.
        if not name or not risk:
            return
        if risk.lower() not in _RISK_BY_NAME:
            return
        if risk.lower() in ("risk level",):
            return
        self.summaries.append(
            {"plugin_id": plugin_id, "name": name, "risk": risk}
        )

    def _detail(self) -> dict[str, Any]:
        if self._detail_id is None:
            return {}
        return self.details.setdefault(
            self._detail_id,
            {
                "plugin_id": self._detail_id,
                "name": "",
                "risk": "",
                "description": "",
                "solution": "",
                "instances": [],
                "evidence": "",
            },
        )

    # -- HTMLParser API ----------------------------------------------------
    def handle_data(self, data: str) -> None:
        """Buffer text for the cell currently being read.

        Without this the parser sees the table structure but not the alert
        names, which silently yields zero findings.
        """
        if self._cell is not None:
            self._buffer.append(data)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        classes = set()
        for key, value in attrs:
            if key == "class" and value:
                classes = set(value.split())
            if key == "id" and value:
                self._maybe_start_detail(value)
            if key == "href" and value and tag == "a":
                match = _ANCHOR_ID.match(value)
                if match:
                    self._row = self._row or {}
                    self._row["plugin_id"] = match.group(1)

        if tag == "table":
            self._table_depth += 1
            if "alerts" in classes and self._table_depth == 1:
                self._in_alerts_table = True
            return

        if tag == "tr":
            self._flush_row()
            self._row = {}
            if self._detail_id and not self._in_alerts_table:
                self._d_cells = []
                self._d_index = 0
            return

        if tag in ("td", "th"):
            if self._in_alerts_table and self._row is not None:
                # Summary table: name, risk, instances.
                if self._cell is None:
                    self._cell = self._next_summary_column()
                    self._buffer = []
            elif self._detail_id:
                self._cell = "detail"
                self._buffer = []
            return

        if self._detail_id and tag in ("div", "p"):
            self._buffer = []
            self._cell = self._cell or "detail"

    def _next_summary_column(self) -> str:
        filled = [key for key in self._row if self._row[key]]
        for column in ("name", "risk", "instances"):
            if column not in filled:
                return column
        return "extra"

    def _flush_detail_row(self) -> None:
        """Pair the label/value cells of one detail row and store them."""
        cells = self._d_cells
        self._d_cells = []
        self._d_index = 0
        if len(cells) < 2:
            return
        label = cells[0].strip().lower()
        value = cells[1].strip()
        if not label or not value:
            return
        detail = self._detail()
        if label == "description" and not detail["description"]:
            detail["description"] = value
        elif label == "solution" and not detail["solution"]:
            detail["solution"] = value
        elif label == "url":
            detail["instances"].append({"url": value})
        elif label == "method" and detail["instances"]:
            detail["instances"][-1]["method"] = value
        elif label == "evidence" and not detail["evidence"]:
            detail["evidence"] = value
        elif label == "risk level" and not detail["risk"]:
            detail["risk"] = value
        elif label == "name" and not detail["name"]:
            detail["name"] = value

    def handle_endtag(self, tag: str) -> None:
        if tag in ("td", "th"):
            if self._in_alerts_table and self._row is not None:
                self._flush_cell()
            elif self._detail_id:
                self._store_detail_cell()
            return

        if tag == "tr":
            if self._in_alerts_table:
                self._flush_row()
            elif self._detail_id:
                self._flush_detail_row()
            return

        if tag == "table":
            self._table_depth = max(0, self._table_depth - 1)
            if self._table_depth == 0:
                self._in_alerts_table = False
            return

    def _store_detail_cell(self) -> None:
        value = " ".join("".join(self._buffer).split())
        self._buffer = []
        self._cell = None
        if self._d_index < 2:
            self._d_cells.append(value)
        self._d_index += 1

    def _maybe_start_detail(self, element_id: str) -> None:
        if not _ANCHOR_ID.match(element_id):
            return
        # Only start a detail block after the summary table has been read.
        self._detail_id = element_id
        self._d_cells = []
        self._d_index = 0
        self._buffer = []
        self._cell = None

    def _store_detail_value(self) -> None:
        value = " ".join("".join(self._buffer).split())
        self._buffer = []
        self._cell = None
        label = (self._label or "").strip()
        if not label or not value:
            return
        detail = self._detail()
        lowered = label.lower()

        if lowered == "description" and not detail["description"]:
            detail["description"] = value
        elif lowered == "solution" and not detail["solution"]:
            detail["solution"] = value
        elif lowered == "url":
            detail["instances"].append({"url": value})
        elif lowered == "method" and detail["instances"]:
            detail["instances"][-1]["method"] = value
        elif lowered == "evidence" and value and not detail["evidence"]:
            detail["evidence"] = value
        elif lowered == "risk level" and not detail["risk"]:
            detail["risk"] = value
        elif lowered == "name" and not detail["name"]:
            detail["name"] = value


def _severity_from(summary: dict[str, Any], detail: dict[str, Any]) -> Severity:
    """Prefer the numeric risk class, fall back to the risk name."""
    for source in (summary.get("risk", ""), detail.get("risk", "")):
        text = str(source).strip().lower()
        if text in _RISK_BY_NAME:
            return _RISK_BY_NAME[text]
    return Severity.INFO


def parse(html_text: str, target: str = "") -> ParseResult:
    """Parse a ZAP HTML report into normalized findings.

    Args:
        html_text: contents of the ``-r`` HTML report.
        target: authorized target URL.

    Returns:
        A :class:`ParseResult`. An HTML report with an empty alert table is a
        genuine zero-finding result, not a parse failure.
    """
    result = ParseResult()
    if not html_text or not html_text.strip():
        result.errors.append("ZAP produced no HTML report to parse.")
        return result

    parser = _ZapHtmlParser()
    try:
        parser.feed(html_text)
        parser.close()
    except Exception as exc:  # noqa: BLE001 - a parser must not crash a run
        result.errors.append(f"ZAP HTML report could not be parsed: {exc}")
        return result

    if not parser.summaries:
        result.notes.append(
            "ZAP HTML report contains an empty alert table: the scan completed "
            "and raised no alerts. Zero findings is the genuine result."
        )
        return result

    timestamp = utc_now_iso()
    for summary in parser.summaries:
        plugin_id = str(summary.get("plugin_id", ""))
        detail = parser.details.get(plugin_id, {})
        name = str(detail.get("name") or summary.get("name") or "").strip()
        if not name:
            continue
        severity = _severity_from(summary, detail)

        instances = detail.get("instances") or []
        urls = [str(item.get("url", "")) for item in instances if item.get("url")]
        methods = sorted({str(item.get("method", "")) for item in instances if item.get("method")})
        endpoint = urls[0] if urls else target

        evidence_parts = [f"ZAP plugin {plugin_id}"]
        if summary.get("risk"):
            evidence_parts.append(f"ZAP risk: {summary['risk']}")
        if methods:
            evidence_parts.append(f"Methods: {', '.join(methods)}")
        if urls:
            evidence_parts.append(
                f"URLs ({len(urls)}): " + ", ".join(urls[:6])
            )
        if detail.get("evidence"):
            evidence_parts.append(f"Evidence:\n{multiline(detail['evidence'], 600)}")

        reference_bits = [f"pluginId {plugin_id}"] if plugin_id else []

        result.findings.append(
            Finding(
                tool=TOOL,
                category=_category_for(name),
                severity=severity,
                title=name,
                description=truncate(
                    detail.get("description") or f"ZAP alert {name}.", 1200
                ),
                target=target,
                endpoint=endpoint,
                evidence=truncate("\n".join(evidence_parts), 1400),
                recommendation=truncate(
                    detail.get("solution")
                    or "Review this ZAP alert and remediate if it applies to this application.",
                    800,
                ),
                timestamp=timestamp,
                reference="; ".join(reference_bits),
            )
        )

    if not result.findings:
        result.notes.append("ZAP HTML alert table was present but produced no usable rows.")
    return result


def _category_for(name: str) -> str:
    lowered = name.lower()
    if any(token in lowered for token in ("header", "clickjacking", "csp")):
        return "security-header"
    if "cookie" in lowered:
        return "cookie"
    if any(token in lowered for token in ("disclosure", "timestamp", "version")):
        return "information-disclosure"
    if "cross-domain" in lowered or "cross-origin" in lowered:
        return "misconfiguration"
    if any(token in lowered for token in ("https", "tls", "ssl")):
        return "tls"
    if any(token in lowered for token in ("xss", "injection", "sql")):
        return "injection"
    return "vulnerability"
