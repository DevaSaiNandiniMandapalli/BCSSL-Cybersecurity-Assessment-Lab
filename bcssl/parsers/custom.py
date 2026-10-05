"""Parse the HTML report produced by the external Project #08 scanner.

The custom scanner is a separate, completed project. This lab never modifies it;
it invokes it as a subprocess with ``--html-output`` and parses the report that
comes back. The HTML is the machine-readable artifact it offers (its console
table is width-dependent and therefore unsuitable for reliable parsing).

Markup consumed (from the scanner's own Jinja template)::

    <div class="finding">
      <div class="finding-head">
        <span class="sev sev-medium">Medium</span>
        <h3>Title</h3>
        <span class="module">headers</span>
      </div>
      <p>description</p>
      <dl>
        <dt>URL</dt>        <dd>...</dd>
        <dt>Severity</dt>   <dd>...</dd>
        <dt>Evidence</dt>   <dd><pre>...</pre></dd>
        <dt>Remediation</dt><dd>...</dd>
      </dl>
    </div>
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Any

from ..models import Finding, utc_now_iso
from ..severity import Severity
from .base import ParseResult, multiline, truncate

TOOL = "custom-scanner"

_MODULE_CATEGORIES = {
    "headers": "security-header",
    "paths": "path-discovery",
    "injection": "injection",
}


class _ReportParser(HTMLParser):
    """Extract finding records and scan errors from the scanner HTML report."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.findings: list[dict[str, Any]] = []
        self.errors: list[str] = []
        self.severity_summary: dict[str, int] = {}
        self.module_summary: dict[str, int] = {}
        self.target = ""

        # Stack of (tag, classes)
        self._stack: list[tuple[str, set[str]]] = []
        # Active finding record state
        self._depth = 0
        self._current: dict[str, Any] | None = None
        self._buffer: list[str] = []
        self._capture: str | None = None
        self._dl_key: str | None = None
        # Fallback table capture
        self._row: list[str] | None = None
        self._in_error_list = False

    # -- helpers -----------------------------------------------------------
    def _classes(self, attrs: list[tuple[str, str | None]]) -> set[str]:
        for name, value in attrs:
            if name == "class" and value:
                return set(value.split())
        return set()

    def _start_capture(self, name: str) -> None:
        """Begin buffering text for field *name*."""
        self._flush()
        self._buffer = []
        self._capture = name

    def _flush(self) -> None:
        """Store the buffered text under the active capture, then reset."""
        text = "".join(self._buffer)
        self._buffer = []
        capture, self._capture = self._capture, None
        if not capture or self._current is None:
            return
        if capture == "title":
            cleaned = re.sub(r"\s+", " ", text).strip()
            if cleaned:
                self._current["title"] = cleaned
        elif capture == "module":
            cleaned = re.sub(r"\s+", " ", text).strip()
            if cleaned:
                self._current["module"] = cleaned
        elif capture == "description":
            cleaned = " ".join(text.split())
            if cleaned:
                self._current["description"] = cleaned
        elif capture == "dl":
            label = self._dl_key or "detail"
            value = text.strip()
            if value:
                self._current.setdefault("details", {})[label] = value

    def _maybe_store_row(self) -> None:
        if self._row is None:
            return
        cells = [cell.strip() for cell in self._row]
        self._row = None
        if len(cells) == 3 and re.fullmatch(r"[a-z]+", cells[1] or "x"):
            # Summary-by-severity row: label, level, count
            try:
                self.severity_summary[cells[1]] = int(re.sub(r"\D", "", cells[2]) or 0)
            except ValueError:
                pass
        elif len(cells) == 2 and cells[1].isdigit():
            self.module_summary[cells[0]] = int(cells[1])
        elif len(cells) == 5:
            # Findings table row fallback.
            self.findings.append(
                {
                    "severity": cells[0],
                    "module": cells[1],
                    "title": cells[2],
                    "url": cells[3],
                    "details": {},
                }
            )

    # -- HTMLParser API ----------------------------------------------------
    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        classes = self._classes(attrs)

        if tag == "div" and "finding" in classes and self._current is None:
            self._current = {"details": {}}
            self._depth = 1
            self._stack.append((tag, classes))
            return

        if self._current is not None and tag == "div":
            self._depth += 1
            self._stack.append((tag, classes))
            return

        if self._current is not None:
            if tag == "span":
                sev_class = next(
                    (c for c in classes if c.startswith("sev-")), ""
                )
                if sev_class:
                    # Severity lives in the CSS class, not in the label text.
                    level = sev_class[len("sev-"):]
                    if self._current.get("severity") in (None, "", "info"):
                        self._current["severity"] = level
                    self._flush()
                elif "module" in classes:
                    self._start_capture("module")
            elif tag == "h3":
                self._start_capture("title")
            elif tag == "p":
                self._start_capture("description")
            elif tag == "dt":
                self._start_capture("dt")
            elif tag == "dd":
                self._start_capture("dl")
            return

        # Outside a finding block: tables and error lists.
        if tag == "tr":
            self._row = []
        elif tag in ("td", "th") and self._row is not None:
            self._start_capture("cell")
        elif tag == "ul" and "errors" in classes:
            self._in_error_list = True
        elif tag == "li" and self._in_error_list:
            self._start_capture("error")

    def handle_endtag(self, tag: str) -> None:
        if self._capture == "cell" and self._row is not None:
            self._row.append("".join(self._buffer))
            self._buffer = []
            self._capture = None
        elif self._capture == "error":
            message = "".join(self._buffer).strip()
            if message:
                self.errors.append(" ".join(message.split()))
            self._buffer = []
            self._capture = None
            self._in_error_list = False
        elif tag == "dt":
            self._dl_key = "".join(self._buffer).strip().lower()
            self._buffer = []
            self._capture = None
        elif tag in ("dd", "h3", "p", "li"):
            self._flush()

        if self._current is not None and tag == "div":
            self._depth -= 1
            if self._stack:
                self._stack.pop()
            if self._depth <= 0:
                self._flush()
                if self._current.get("title"):
                    self.findings.append(self._current)
                self._current = None
                self._depth = 0
        elif self._stack and tag == self._stack[-1][0]:
            self._stack.pop()

        if tag == "tr" and self._row is not None:
            self._maybe_store_row()

    def handle_data(self, data: str) -> None:
        if self._capture:
            self._buffer.append(data)
            return
        # Capture the target line from the report header when present.
        if not self.target and "Target:" in data:
            match = re.search(r"Target:\s*(\S+)", data)
            if match:
                self.target = match.group(1)

    def close(self) -> None:  # pragma: no cover - defensive
        super().close()
        if self._current and self._current.get("title"):
            self.findings.append(self._current)
            self._current = None


def parse(html_text: str, target: str = "") -> ParseResult:
    """Parse the custom scanner HTML report into normalized findings.

    Args:
        html_text: verbatim contents of the ``--html-output`` file.
        target: authorized target URL.

    Returns:
        A :class:`ParseResult`. Scanner-reported operational errors are
        surfaced as warnings because they are coverage gaps, not vulnerabilities.
    """
    result = ParseResult()
    if html_text is None or not html_text.strip():
        result.errors.append("Custom scanner produced no HTML report to parse.")
        return result

    parser = _ReportParser()
    try:
        parser.feed(html_text)
        parser.close()
    except Exception as exc:  # noqa: BLE001 - parser must never crash the run
        result.errors.append(f"Custom scanner HTML could not be parsed: {exc}")
        return result

    effective_target = target or parser.target
    timestamp = utc_now_iso()

    for message in parser.errors:
        result.warnings.append(f"custom scanner operational error: {message}")

    for record in parser.findings:
        finding = _to_finding(record, effective_target, timestamp)
        if finding is not None:
            result.findings.append(finding)
            result.excerpts[finding.title] = finding.evidence

    expected = sum(parser.severity_summary.values())
    if expected and not result.findings:
        result.errors.append(
            "The custom scanner report lists "
            f"{expected} finding(s) in its summary table, but none could be "
            "extracted from the finding blocks. The report layout may have "
            "changed; no findings were inferred."
        )
    elif not result.findings:
        result.notes.append(
            "Custom scanner completed and reported no findings for the "
            "selected modules."
        )

    return result


def _to_finding(record: dict[str, Any], target: str, timestamp: str) -> Finding | None:
    title = str(record.get("title") or "").strip()
    if not title:
        return None

    severity = Severity.from_string(record.get("severity", "info"))
    module = str(record.get("module") or "").strip()
    details = record.get("details") or {}
    url = str(details.get("url") or record.get("url") or "").strip()
    if url.lower() in ("not recorded", "-", "none"):
        url = ""

    evidence = multiline(str(details.get("evidence") or ""), 1200)
    if evidence.lower() in ("none recorded", ""):
        evidence = ""

    remediation = str(details.get("remediation") or "").strip()
    if remediation.lower() in ("no recommendation recorded", ""):
        remediation = ""

    description = str(record.get("description") or "").strip()

    return Finding(
        tool=TOOL,
        category=_category_for(module, title),
        severity=severity,
        title=title,
        description=truncate(description or title, 1000),
        target=target,
        endpoint=url or target,
        evidence=truncate(evidence, 1200),
        recommendation=truncate(remediation, 800),
        timestamp=timestamp,
        reference=module,
        subject="",
    )


def _category_for(module: str, title: str) -> str:
    lowered_title = title.lower()
    if "cookie" in lowered_title:
        return "cookie"
    if any(
        token in lowered_title
        for token in ("x-powered-by", "server header", "version disclosure", "technology")
    ):
        return "technology-disclosure"
    base = _MODULE_CATEGORIES.get(module)
    if base:
        return base
    return "information-disclosure"


def version_from_html(html_text: str) -> str:
    """Return a version string if the report happens to embed one."""
    match = re.search(r"scanner\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)", html_text or "", re.I)
    return match.group(1) if match else ""
