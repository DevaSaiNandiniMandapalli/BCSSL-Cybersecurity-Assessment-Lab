"""Consolidated reporting: JSON, Markdown and a self-contained HTML report.

The HTML report is standalone (no external stylesheet, font or script) so it can
be archived as evidence and opened offline. All tool-supplied text is HTML
escaped: findings contain response fragments from the target and must never be
injected into the report as markup.

When no scan has been run the report says so explicitly rather than rendering an
empty-looking assessment.
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from . import evidence as evidence_module
from . import paths
from . import sarif as sarif_module
from .correlation import CorrelationGroup
from .models import RunStatus, ToolRunResult, utc_now_iso
from .pipeline import CollectedAssessment
from .severity import ORDERED_SEVERITIES, Severity, tally, worst

NO_RESULTS_MESSAGE = "No scan results available."


# ---------------------------------------------------------------------------
# Shared payload
# ---------------------------------------------------------------------------
def build_payload(assessment: CollectedAssessment) -> dict[str, Any]:
    """Build the canonical report payload used by every output format."""
    config = assessment.config
    findings = assessment.all_findings
    successful = assessment.successful_runs

    severity_counts = tally(f.severity for f in findings)
    confirmed = assessment.correlation.confirmed
    single = assessment.correlation.single

    limitations = _limitations(assessment)

    return {
        "report": {
            "title": f"{config.lab_name} - Security Assessment Report",
            "generated_at": assessment.generated_at,
            "lab": config.lab_name,
            "target": assessment.target.url if assessment.target else config.authorized_url,
            "target_authorized": bool(assessment.target and assessment.target.ok),
            "authorization_statement": config.authorization_statement,
            "tools_used": [result.tool for result in successful],
            "tools_attempted": [result.tool for result in assessment.results],
            "has_results": bool(assessment.results),
        },
        "executive_summary": {
            "message": NO_RESULTS_MESSAGE if not assessment.results else _executive_text(
                assessment, severity_counts
            ),
            "total_findings": len(findings),
            "severity_counts": severity_counts,
            "highest_severity": (
                worst(f.severity for f in findings).value if findings else None
            ),
            "confirmed_by_multiple_tools": len(confirmed),
            "single_tool_observations": len(single),
            "tools_completed": len(successful),
            "tools_not_completed": [
                {
                    "tool": result.tool,
                    "status": result.status.value,
                    "status_label": result.status.label,
                    "reason": "; ".join(result.errors) or result.status.label,
                }
                for result in assessment.results
                if not result.status.is_success
            ],
        },
        "scan_metadata": {
            "target": assessment.target.url if assessment.target else config.authorized_url,
            "started_at": min(
                (r.started_at for r in assessment.results if r.started_at),
                default="",
            ),
            "finished_at": max(
                (r.finished_at for r in assessment.results if r.finished_at),
                default="",
            ),
            "generated_at": assessment.generated_at,
            "tool_versions": {
                result.tool: result.tool_version for result in assessment.results
            },
            "durations": {
                result.tool: round(result.duration_seconds, 2)
                for result in assessment.results
            },
            "evidence_integrity": evidence_module.verify(
                [result.tool for result in assessment.results]
            ).to_dict()
            if assessment.results
            else {"checked": 0, "intact": 0, "modified": [], "missing": [], "ok": True},
        },
        "tools": assessment.tool_summary(),
        "findings": [finding.to_dict() for finding in findings],
        "correlation": assessment.correlation.to_dict(),
        "verification": _verification_section(assessment, findings),
        "evidence": [record.to_dict() for record in assessment.evidence_records],
        "limitations": limitations,
        "errors": _collect_errors(assessment),
        "recommendations": _recommendations(assessment),
    }


def _verification_section(
    assessment: CollectedAssessment, findings: list[Any]
) -> dict[str, Any]:
    """Summarize how much weight each finding carries."""
    from .verify import ALL_STATUSES, DETECTED, NOT_VERIFIED, SINGLE_TOOL_OBSERVATION, CORROBORATED

    counts = {status: 0 for status in ALL_STATUSES}
    for finding in findings:
        counts[finding.verification_status] = (
            counts.get(finding.verification_status, 0) + 1
        )

    result = assessment.verification
    return {
        "status_counts": counts,
        "definitions": {
            DETECTED: "the lab independently reproduced the condition against the authorized target",
            CORROBORATED: "two or more distinct tools reported the same finding fingerprint",
            SINGLE_TOOL_OBSERVATION: "exactly one tool reported it after correlation",
            NOT_VERIFIED: "reported by a tool but not independently confirmed",
            "TOOL UNAVAILABLE": "the component could not run, so it contributed no findings",
        },
        "independent_check": result.to_dict() if result is not None else None,
        "counts": assessment.verification_counts,
    }


def _executive_text(
    assessment: CollectedAssessment, severity_counts: dict[str, int]
) -> str:
    total = sum(severity_counts.values())
    successful = len(assessment.successful_runs)
    confirmed = len(assessment.correlation.confirmed)
    parts = [
        f"{total} finding(s) were reported by {successful} of "
        f"{len(assessment.results)} attempted tool(s)."
    ]
    if severity_counts.get("CRITICAL"):
        parts.append(f"{severity_counts['CRITICAL']} rated CRITICAL.")
    elif severity_counts.get("HIGH"):
        parts.append(f"{severity_counts['HIGH']} rated HIGH.")
    if confirmed:
        parts.append(
            f"{confirmed} issue(s) were reported by more than one tool and are "
            "labelled as confirmed by multiple tools."
        )
    else:
        parts.append(
            "No issue was reported by more than one tool, so every observation "
            "is labelled as a single-tool observation."
        )
    return " ".join(parts)


def _limitations(assessment: CollectedAssessment) -> list[str]:
    limits: list[str] = []
    for result in assessment.results:
        if result.status is RunStatus.TOOL_NOT_INSTALLED:
            limits.append(
                f"{result.tool}: no scan was performed because the tool is not "
                "installed, so this assessment has no coverage from it."
            )
        elif result.status is RunStatus.TARGET_UNREACHABLE:
            limits.append(
                f"{result.tool}: no scan was performed because the target did "
                "not answer."
            )
        elif result.status is RunStatus.TARGET_REJECTED:
            limits.append(
                f"{result.tool}: the requested target was rejected by the "
                "authorized-target validator."
            )
        elif result.status is RunStatus.TIMEOUT:
            limits.append(
                f"{result.tool}: the run exceeded its timeout, so results may be "
                "incomplete."
            )
        elif result.status is RunStatus.FAILED:
            limits.append(
                f"{result.tool}: the tool exited with a non-zero status, so its "
                "output may be incomplete."
            )
        elif result.status is RunStatus.PARSE_ERROR:
            limits.append(
                f"{result.tool}: output was captured but could not be parsed, so "
                "its findings are not represented here."
            )
    if assessment.warnings:
        limits.extend(assessment.warnings)
    limits.append(
        "Automated findings are indicators that require manual verification. "
        "Absence of a finding is not proof that the application is secure."
    )
    limits.append(
        "Assessment is limited to the authorized local target and to the tool "
        "settings configured in config/lab-config.json."
    )
    return limits


def _collect_errors(assessment: CollectedAssessment) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for result in assessment.results:
        for message in result.errors:
            entries.append({"tool": result.tool, "level": "error", "message": message})
        for message in result.warnings:
            entries.append({"tool": result.tool, "level": "warning", "message": message})
    return entries


def _recommendations(assessment: CollectedAssessment) -> list[dict[str, Any]]:
    """Deduplicated recommendations, most severe first."""
    seen: dict[str, dict[str, Any]] = {}
    for group in assessment.correlation.groups:
        recommendation = group.recommendation
        if not recommendation:
            continue
        key = recommendation.strip().lower()[:120]
        if key not in seen:
            seen[key] = {
                "severity": group.severity.value,
                "title": group.title,
                "recommendation": recommendation,
                "tools": group.tools,
                "label": group.label,
                "endpoints": group.endpoints,
            }
    return sorted(
        seen.values(), key=lambda item: -Severity[item["severity"]].rank
    )


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------
def render_json(assessment: CollectedAssessment) -> str:
    return json.dumps(build_payload(assessment), indent=2, ensure_ascii=False, default=str)


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------
def render_markdown(assessment: CollectedAssessment) -> str:
    payload = build_payload(assessment)
    meta = payload["report"]
    summary = payload["executive_summary"]

    lines: list[str] = [
        f"# {meta['title']}",
        "",
        f"**Target:** {meta['target']}",
        f"**Generated:** {meta['generated_at']}",
        f"**Authorization:** {meta['authorization_statement']}",
        "",
        "## Executive summary",
        "",
    ]
    if not payload["report"]["has_results"]:
        lines.append(NO_RESULTS_MESSAGE)
        lines.append("")
    else:
        lines.append(summary["message"])
        lines.append("")
        counts = summary["severity_counts"]
        lines.append("| Severity | Count |")
        lines.append("| --- | --- |")
        for level in ORDERED_SEVERITIES:
            lines.append(f"| {level.value} | {counts[level.value]} |")
        lines.append("")
        lines.append(
            f"- Confirmed by multiple tools: {summary['confirmed_by_multiple_tools']}"
        )
        lines.append(
            f"- Single-tool observations: {summary['single_tool_observations']}"
        )
        lines.append("")

    lines += ["## Tool-by-tool results", "", "| Tool | Status | Version | Findings |", "| --- | --- | --- | --- |"]
    for entry in payload["tools"]:
        lines.append(
            f"| {entry['tool']} | {entry['status_label']} | "
            f"{entry['tool_version'] or '-'} | {entry['finding_count']} |"
        )
    lines.append("")

    if assessment.correlation.groups:
        lines += ["## Cross-tool correlation", ""]
        for group in assessment.correlation.groups:
            lines.append(
                f"### [{group.label}] {group.severity.value} - {group.title}"
            )
            lines.append(f"- Tools: {', '.join(group.tools)}")
            if group.endpoints:
                lines.append(f"- Endpoints: {', '.join(group.endpoints[:8])}")
            lines.append("")

    findings = payload["findings"]
    if findings:
        lines += ["## Detailed findings", ""]
        for level in ORDERED_SEVERITIES:
            subset = [f for f in findings if f["severity"] == level.value]
            if not subset:
                continue
            lines.append(f"### {level.value} ({len(subset)})")
            lines.append("")
            for finding in subset:
                lines.append(f"#### {finding['title']}")
                lines.append(f"- Tool: {finding['tool']}")
                lines.append(f"- Category: {finding['category']}")
                lines.append(f"- Endpoint: {finding['endpoint'] or '-'}")
                if finding["description"]:
                    lines.append(f"- Description: {finding['description']}")
                if finding["evidence"]:
                    lines.append(
                        "- Evidence: `" + finding["evidence"].replace("`", "'")[:300] + "`"
                    )
                if finding["recommendation"]:
                    lines.append(f"- Recommendation: {finding['recommendation']}")
                lines.append("")

    if payload["recommendations"]:
        lines += ["## Recommendations", ""]
        for index, item in enumerate(payload["recommendations"], start=1):
            lines.append(
                f"{index}. [{item['severity']}] {item['recommendation']} "
                f"({item['label']}; tools: {', '.join(item['tools'])})"
            )
        lines.append("")

    if payload["evidence"]:
        lines += ["## Evidence references", ""]
        lines.append(evidence_module.render_evidence_index(assessment.evidence_records))
        lines.append("")

    if payload["limitations"]:
        lines += ["## Scan limitations", ""]
        for limitation in payload["limitations"]:
            lines.append(f"- {limitation}")
        lines.append("")

    errors = payload["errors"]
    if errors:
        lines += ["## Errors and warnings", ""]
        for entry in errors:
            lines.append(f"- **{entry['tool']}** ({entry['level']}): {entry['message']}")
        lines.append("")

    lines += [
        "## Scan metadata",
        "",
        f"- Target: {payload['scan_metadata']['target']}",
        f"- Started: {payload['scan_metadata']['started_at'] or '-'}",
        f"- Finished: {payload['scan_metadata']['finished_at'] or '-'}",
        f"- Tools used: {', '.join(meta['tools_used']) or '-'}",
        "",
        "Findings are automated indicators requiring manual verification.",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------
_CSS = """
:root {
  --bg:#f5f7fa; --panel:#ffffff; --panel-2:#eef2f7; --border:#d5dce6;
  --text:#16202c; --muted:#5b6b7f; --accent:#1f6feb; --accent-2:#0b4ea2;
  --critical:#8b0000; --critical-bg:#ffd9d9;
  --high:#b23b00; --high-bg:#ffe4cc;
  --medium:#8a6100; --medium-bg:#fff3c4;
  --low:#1f6f8b; --low-bg:#d6f0fb;
  --info:#3d4f60; --info-bg:#e2e8ef;
  --ok:#1a6b3c; --ok-bg:#d8f3e2;
  --shadow:0 1px 2px rgba(16,24,40,.06),0 1px 3px rgba(16,24,40,.10);
}
html[data-theme="dark"] {
  --bg:#0d1117; --panel:#161b22; --panel-2:#1c2430; --border:#2d3644;
  --text:#e6edf3; --muted:#9aa8b8; --accent:#58a6ff; --accent-2:#1f6feb;
  --critical:#ff8080; --critical-bg:#4a1a1a;
  --high:#ffa657; --high-bg:#4a2a12;
  --medium:#e3b341; --medium-bg:#463a12;
  --low:#79c0ff; --low-bg:#12324a;
  --info:#b6c2cf; --info-bg:#242c37;
  --ok:#56d364; --ok-bg:#12331c;
  --shadow:0 1px 2px rgba(0,0,0,.4);
}
@media (prefers-color-scheme: dark) {
  html:not([data-theme="light"]) {
    --bg:#0d1117; --panel:#161b22; --panel-2:#1c2430; --border:#2d3644;
    --text:#e6edf3; --muted:#9aa8b8; --accent:#58a6ff; --accent-2:#1f6feb;
    --critical:#ff8080; --critical-bg:#4a1a1a;
    --high:#ffa657; --high-bg:#4a2a12;
    --medium:#e3b341; --medium-bg:#463a12;
    --low:#79c0ff; --low-bg:#12324a;
    --info:#b6c2cf; --info-bg:#242c37;
    --ok:#56d364; --ok-bg:#12331c;
    --shadow:0 1px 2px rgba(0,0,0,.4);
  }
}
* { box-sizing:border-box; }
body {
  margin:0; padding:0 0 4rem; background:var(--bg); color:var(--text);
  font-family:"Segoe UI",system-ui,-apple-system,Roboto,Helvetica,Arial,sans-serif;
  font-size:15px; line-height:1.55;
}
a { color:var(--accent); }
.wrap { max-width:1180px; margin:0 auto; padding:0 1.25rem; }
header.top {
  background:linear-gradient(135deg,var(--accent-2),var(--accent));
  color:#fff; padding:1.75rem 0; border-bottom:1px solid var(--border);
}
header.top h1 { margin:0 0 .25rem; font-size:1.5rem; letter-spacing:.2px; }
header.top .sub { opacity:.92; font-size:.92rem; }
.banner {
  margin:1.25rem 0; padding:.9rem 1rem; border-radius:8px;
  background:var(--ok-bg); border:1px solid var(--ok); color:var(--text);
  font-weight:600;
}
.banner.reject { background:var(--critical-bg); border-color:var(--critical); }
.banner small { display:block; font-weight:400; color:var(--muted); margin-top:.3rem; }
section { margin:1.75rem 0; }
h2 { font-size:1.15rem; margin:0 0 .75rem; padding-bottom:.4rem; border-bottom:1px solid var(--border); }
h3 { font-size:1rem; margin:1.25rem 0 .5rem; }
.card {
  background:var(--panel); border:1px solid var(--border); border-radius:10px;
  padding:1rem 1.1rem; margin:.75rem 0; box-shadow:var(--shadow);
}
.grid { display:grid; gap:.9rem; grid-template-columns:repeat(auto-fit,minmax(210px,1fr)); }
.stat { background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:.85rem 1rem; box-shadow:var(--shadow); }
.stat .n { font-size:1.7rem; font-weight:700; line-height:1.1; }
.stat .l { color:var(--muted); font-size:.82rem; text-transform:uppercase; letter-spacing:.04em; }
table { width:100%; border-collapse:collapse; background:var(--panel); border:1px solid var(--border); border-radius:10px; overflow:hidden; }
th, td { text-align:left; padding:.55rem .7rem; border-bottom:1px solid var(--border); vertical-align:top; font-size:.9rem; }
th { background:var(--panel-2); font-weight:600; }
tr:last-child td { border-bottom:none; }
.badge {
  display:inline-block; padding:.12rem .5rem; border-radius:999px;
  font-size:.72rem; font-weight:700; letter-spacing:.03em; border:1px solid;
}
.sev-critical { color:var(--critical); background:var(--critical-bg); border-color:var(--critical); }
.sev-high { color:var(--high); background:var(--high-bg); border-color:var(--high); }
.sev-medium { color:var(--medium); background:var(--medium-bg); border-color:var(--medium); }
.sev-low { color:var(--low); background:var(--low-bg); border-color:var(--low); }
.sev-info { color:var(--info); background:var(--info-bg); border-color:var(--info); }
.status-ok { color:var(--ok); font-weight:600; }
.status-bad { color:var(--critical); font-weight:600; }
.verify { display:inline-block; padding:.05rem .4rem; border-radius:999px; border:1px solid var(--border); font-size:.68rem; font-weight:700; letter-spacing:.03em; }
.verify-detected { color:var(--ok); border-color:var(--ok); background:var(--ok-bg); }
.verify-corroborated { color:var(--accent); border-color:var(--accent); }
.verify-single-tool-observation { color:var(--muted); }
.verify-not-verified { color:var(--medium); border-color:var(--medium); }
.confirmed { color:var(--ok); font-weight:600; }
.single { color:var(--muted); }
pre {
  background:var(--panel-2); border:1px solid var(--border); border-radius:6px;
  padding:.6rem .7rem; overflow-x:auto; font-size:.8rem; margin:.4rem 0 0;
  white-space:pre-wrap; word-break:break-word;
}
code { background:var(--panel-2); padding:.1rem .3rem; border-radius:4px; font-size:.85em; }
.muted { color:var(--muted); }
.empty { padding:1.5rem; text-align:center; color:var(--muted); border:1px dashed var(--border); border-radius:10px; background:var(--panel); }
.toolname { font-weight:700; }
.theme-toggle {
  position:fixed; top:.75rem; right:.75rem; z-index:50; cursor:pointer;
  background:var(--panel); color:var(--text); border:1px solid var(--border);
  border-radius:999px; padding:.35rem .8rem; font-size:.82rem; box-shadow:var(--shadow);
}
footer.bottom { color:var(--muted); font-size:.85rem; border-top:1px solid var(--border); margin-top:2.5rem; padding-top:1rem; }
ul.tight { margin:.3rem 0; padding-left:1.1rem; }
@media (max-width:640px) { .grid { grid-template-columns:1fr; } header.top h1 { font-size:1.2rem; } }
"""


def render_html(assessment: CollectedAssessment) -> str:
    payload = build_payload(assessment)
    meta = payload["report"]
    summary = payload["executive_summary"]

    def esc(value: Any) -> str:
        """HTML-escape any value, coercing non-strings first.

        Counters are integers; ``html.escape`` requires a string, so coercion
        happens here rather than being repeated at every call site.
        """
        return html.escape("" if value is None else str(value))

    parts: list[str] = []
    parts.append("<!DOCTYPE html>")
    parts.append('<html lang="en" data-theme="light">')
    parts.append("<head>")
    parts.append('<meta charset="utf-8">')
    parts.append('<meta name="viewport" content="width=device-width, initial-scale=1">')
    parts.append(f"<title>{esc(meta['title'])}</title>")
    parts.append(f"<style>{_CSS}</style>")
    parts.append("</head><body>")
    parts.append(
        '<button class="theme-toggle" type="button" '
        "onclick=\"(function(t){var r=document.documentElement;"
        "var n=(t.getAttribute('data-theme')==='dark')?'light':'dark';"
        "t.setAttribute('data-theme',n);try{localStorage.setItem('bcssl-theme',n)}catch(e){}})"
        "(document.documentElement)\">Theme</button>"
    )

    # Header
    parts.append('<header class="top"><div class="wrap">')
    parts.append(f"<h1>{esc(meta['title'])}</h1>")
    parts.append(
        f'<div class="sub">Authorized target: {esc(meta["target"])} &middot; '
        f'Generated {esc(meta["generated_at"])}</div>'
    )
    parts.append("</div></header>")
    parts.append('<div class="wrap">')

    # Authorization banner
    reject = not meta["target_authorized"]
    parts.append(
        f'<div class="banner{" reject" if reject else ""}">'
        f'{"TARGET REJECTED - NOT AUTHORIZED" if reject else "AUTHORIZED TARGET"}'
        f"<small>{esc(meta['authorization_statement'])}</small></div>"
    )

    if not meta["has_results"]:
        parts.append(f"<section><div class=\"empty\">{esc(NO_RESULTS_MESSAGE)}</div></section>")

    # Executive summary
    parts.append("<section><h2>Executive summary</h2>")
    if meta["has_results"]:
        counts = summary["severity_counts"]
        parts.append(f"<p>{esc(summary['message'])}</p>")
        parts.append('<div class="grid">')
        for level in ORDERED_SEVERITIES:
            parts.append(
                f'<div class="stat"><div class="n">{counts[level.value]}</div>'
                f'<div class="l">{level.value}</div></div>'
            )
        parts.append(
            f'<div class="stat"><div class="n">{summary["confirmed_by_multiple_tools"]}</div>'
            '<div class="l">Confirmed by 2+ tools</div></div>'
        )
        parts.append(
            f'<div class="stat"><div class="n">{summary["single_tool_observations"]}</div>'
            '<div class="l">Single-tool observations</div></div>'
        )
        parts.append(
            f'<div class="stat"><div class="n">{summary["tools_completed"]}/'
            f'{len(meta["tools_attempted"])}</div><div class="l">Tools completed</div></div>'
        )
        parts.append("</div>")
    parts.append("</section>")

    # Tools not completed
    if summary["tools_not_completed"]:
        parts.append("<section><h2>Tools that did not produce results</h2>")
        parts.append("<table><tr><th>Tool</th><th>Status</th><th>Reason</th></tr>")
        for entry in summary["tools_not_completed"]:
            parts.append(
                f'<tr><td class="toolname">{esc(entry["tool"])}</td>'
                f'<td class="status-bad">{esc(entry["status_label"])}</td>'
                f'<td>{esc(entry["reason"])}</td></tr>'
            )
        parts.append("</table></section>")

    # Tool-by-tool
    parts.append("<section><h2>Tool-by-tool results</h2>")
    if payload["tools"]:
        parts.append(
            "<table><tr><th>Tool</th><th>Status</th><th>Version</th><th>Exit</th>"
            "<th>Duration</th><th>Findings</th></tr>"
        )
        for entry in payload["tools"]:
            ok = entry["status"] in ("ok", "partial")
            cls = "status-ok" if ok else "status-bad"
            parts.append(
                f'<tr><td class="toolname">{esc(entry["tool"])}</td>'
                f'<td class="{cls}">{esc(entry["status_label"])}</td>'
                f'<td class="muted">{esc(entry["tool_version"] or "-")}</td>'
                f'<td>{esc(str(entry["exit_code"]))}</td>'
                f'<td>{entry["duration_seconds"]}s</td>'
                f'<td>{entry["finding_count"]}</td></tr>'
            )
        parts.append("</table>")
    else:
        parts.append(f'<div class="empty">{esc(NO_RESULTS_MESSAGE)}</div>')
    parts.append("</section>")

    # Correlation
    if assessment.correlation.groups:
        parts.append("<section><h2>Cross-tool correlation</h2>")
        confirmed = assessment.correlation.confirmed
        if confirmed:
            parts.append(
                f"<p>{len(confirmed)} issue(s) were reported by more than one "
                "tool and are labelled as confirmed by multiple tools.</p>"
            )
        else:
            parts.append(
                "<p>No issue was reported by more than one tool. Every "
                "observation below is a single-tool observation.</p>"
            )
        parts.append("<table><tr><th>Label</th><th>Severity</th><th>Issue</th>"
                     "<th>Tools</th><th>Endpoints</th></tr>")
        for group in assessment.correlation.groups:
            cls = "confirmed" if group.is_confirmed else "single"
            endpoints = ", ".join(group.endpoints[:4]) or "-"
            parts.append(
                f'<tr><td class="{cls}">{esc(group.label)}</td>'
                f'<td><span class="badge sev-{group.severity.value.lower()}">'
                f"{group.severity.value}</span></td>"
                f'<td>{esc(group.title)}</td>'
                f'<td>{esc(", ".join(group.tools))}</td>'
                f'<td class="muted">{esc(endpoints)}</td></tr>'
            )
        parts.append("</table></section>")

    # Verification status
    verification = payload["verification"]
    findings = payload["findings"]
    if findings:
        parts.append("<section><h2>Verification status</h2>")
        parts.append('<div class="grid">')
        for status in ("DETECTED", "CORROBORATED", "SINGLE-TOOL OBSERVATION", "NOT VERIFIED"):
            parts.append(
                f'<div class="stat"><div class="n">'
                f'{esc(verification["status_counts"].get(status, 0))}</div>'
                f'<div class="l">{esc(status.replace("-", " ").title())}</div></div>'
            )
        parts.append("</div>")
        parts.append('<div class="card"><ul class="tight">')
        for status, meaning in verification["definitions"].items():
            parts.append(
                f"<li><strong>{esc(status)}</strong>: {esc(meaning)}</li>"
            )
        parts.append("</ul>")
        check = verification.get("independent_check")
        if check:
            if check.get("reachable"):
                parts.append(
                    f'<p class="muted">Independent re-check of the authorized target at '
                    f'{esc(check["checked_at"])} (HTTP {esc(check["status_code"])}): '
                    f'{len(check["confirmed_subjects"])} condition(s) reproduced, '
                    f'{len(check["refuted_subjects"])} not reproduced.</p>'
                )
            elif check.get("error"):
                parts.append(
                    f'<p class="muted">Independent re-check could not run: '
                    f'{esc(check["error"])}</p>'
                )
        parts.append("</div></section>")

    # Findings by severity
    findings = payload["findings"]
    if findings:
        parts.append("<section><h2>Detailed findings</h2>")
        for level in ORDERED_SEVERITIES:
            subset = [f for f in findings if f["severity"] == level.value]
            if not subset:
                continue
            parts.append(
                f'<h3><span class="badge sev-{level.value.lower()}">{level.value}</span> '
                f"{len(subset)} finding(s)</h3>"
            )
            for finding in subset:
                status = str(finding.get("verification_status", "")).lower()
                parts.append('<div class="card">')
                parts.append(
                    f'<div><span class="badge sev-{level.value.lower()}">'
                    f'{level.value}</span> <strong>{esc(finding["title"])}</strong></div>'
                )
                parts.append(
                    f'<div class="muted">Tool: {esc(finding["tool"])} &middot; '
                    f'Category: {esc(finding["category"])} &middot; '
                    f'<span class="verify verify-{esc(status)}">'
                    f'{esc(finding.get("verification_status", ""))}</span></div>'
                )
                if finding["endpoint"]:
                    parts.append(
                        f'<div class="muted">Endpoint: <code>{esc(finding["endpoint"])}</code></div>'
                    )
                if finding["description"]:
                    parts.append(f"<p>{esc(finding['description'])}</p>")
                if finding["evidence"]:
                    parts.append(
                        f"<pre>{esc(finding['evidence'][:1200])}</pre>"
                    )
                if finding["recommendation"]:
                    parts.append(
                        f'<p><strong>Recommendation:</strong> '
                        f'{esc(finding["recommendation"])}</p>'
                    )
                parts.append("</div>")
        parts.append("</section>")

    # Recommendations
    if payload["recommendations"]:
        parts.append("<section><h2>Recommendations</h2><div class='card'><ol>")
        for item in payload["recommendations"]:
            parts.append(
                f'<li><span class="badge sev-{item["severity"].lower()}">{item["severity"]}</span> '
                f'{esc(item["recommendation"])} <span class="muted">({esc(item["label"])}; '
                f'tools: {esc(", ".join(item["tools"]))})</span></li>'
            )
        parts.append("</ol></div></section>")

    # Evidence
    parts.append("<section><h2>Evidence references</h2>")
    if assessment.evidence_records:
        parts.append("<table><tr><th>Tool</th><th>Finding</th><th>Endpoint</th>"
                     "<th>Raw artifact</th><th>SHA-256</th></tr>")
        for record in assessment.evidence_records:
            parts.append(
                f'<tr><td>{esc(record.tool)}</td><td>{esc(record.finding_title)}</td>'
                f'<td class="muted">{esc(record.endpoint or "-")}</td>'
                f'<td><code>{esc(record.raw_artifact or "-")}</code></td>'
                f'<td class="muted"><code>{esc(record.raw_sha256[:16] or "-")}</code></td></tr>'
            )
        parts.append("</table>")
    else:
        parts.append('<div class="empty">No evidence records yet. Run a tool to collect evidence.</div>')
    integrity = payload["scan_metadata"]["evidence_integrity"]
    parts.append(
        f'<p class="muted">Integrity check: {integrity["intact"]} of '
        f'{integrity["checked"]} raw artifact(s) match their recorded sha256.</p>'
    )
    parts.append("</section>")

    # Metadata and limitations
    scan = payload["scan_metadata"]
    parts.append("<section><h2>Scan metadata</h2><table>")
    for label, value in (
        ("Target", scan["target"]),
        ("Started", scan["started_at"] or "-"),
        ("Finished", scan["finished_at"] or "-"),
        ("Tools used", ", ".join(meta["tools_used"]) or "-"),
    ):
        parts.append(f"<tr><th>{esc(label)}</th><td>{esc(value)}</td></tr>")
    for tool, version in scan["tool_versions"].items():
        parts.append(
            f'<tr><th>{esc(tool)} version</th><td>{esc(version or "not detected")}</td></tr>'
        )
    parts.append("</table></section>")

    parts.append("<section><h2>Scan limitations</h2><div class='card'><ul class='tight'>")
    for limitation in payload["limitations"]:
        parts.append(f"<li>{esc(limitation)}</li>")
    parts.append("</ul></div></section>")

    errors = payload["errors"]
    if errors:
        parts.append("<section><h2>Errors and warnings</h2><table>"
                     "<tr><th>Tool</th><th>Level</th><th>Message</th></tr>")
        for entry in errors:
            parts.append(
                f'<tr><td>{esc(entry["tool"])}</td><td>{esc(entry["level"])}</td>'
                f'<td>{esc(entry["message"])}</td></tr>'
            )
        parts.append("</table></section>")

    parts.append(
        '<footer class="bottom">Findings are automated indicators produced by the '
        "listed tools and require manual verification. This report is a record of "
        "an authorized, local-only assessment.</footer>"
    )
    parts.append("</div>")
    parts.append(
        "<script>try{var t=localStorage.getItem('bcssl-theme');"
        "if(t)document.documentElement.setAttribute('data-theme',t);}catch(e){}</script>"
    )
    parts.append("</body></html>")
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def write_reports(
    assessment: CollectedAssessment,
    formats: Iterable[str] = ("html", "json", "md"),
    basename: str | None = None,
    run_id: str | None = None,
) -> dict[str, Path]:
    """Render and write the requested report formats.

    Args:
        assessment: the collected assessment to report.
        formats: any of ``html``, ``json``, ``md``, ``sarif``.
        basename: explicit output stem, overriding the assessment identifier.
        run_id: assessment identifier whose outputs these reports belong to.
            When given, reports are written as ``{run_id}.{ext}`` so each
            assessment owns its own report set.
    """
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    stem = basename or run_id or f"assessment-{stamp}"
    written: dict[str, Path] = {}

    paths.ensure_layout()
    for fmt in formats:
        fmt = fmt.lower()
        if fmt == "html":
            destination = paths.final_dir() / f"{stem}.html"
            destination.write_text(render_html(assessment), encoding="utf-8")
        elif fmt == "json":
            destination = paths.final_dir() / f"{stem}.json"
            destination.write_text(render_json(assessment), encoding="utf-8")
        elif fmt in ("md", "markdown"):
            destination = paths.final_dir() / f"{stem}.md"
            destination.write_text(render_markdown(assessment), encoding="utf-8")
        elif fmt == "sarif":
            destination = paths.final_dir() / f"{stem}.sarif"
            sarif_module.write(sarif_module.render(assessment), destination)
        else:
            raise ValueError(f"unknown report format '{fmt}'")
        written[fmt] = destination

    if run_id:
        _mark_assessment_complete(
            run_id, reports=sorted(paths.relative_to_root(p) for p in written.values())
        )
    return written


def _mark_assessment_complete(run_id: str, **payload: Any) -> None:
    """Record report generation in the assessment manifest (best effort)."""
    try:
        from . import runs as runs_module

        runs_module.mark_complete(run_id, **payload)
    except Exception:  # noqa: BLE001 - reporting must not fail on bookkeeping
        pass


def latest_report_path(fmt: str = "html") -> Path | None:
    """Return the most recently written report of *fmt*, if any."""
    directory = paths.final_dir()
    if not directory.is_dir():
        return None
    suffix = ".html" if fmt == "html" else f".{fmt}"
    candidates = sorted(
        (item for item in directory.glob(f"*{suffix}") if item.is_file()),
        key=lambda item: item.stat().st_mtime,
    )
    return candidates[-1] if candidates else None
