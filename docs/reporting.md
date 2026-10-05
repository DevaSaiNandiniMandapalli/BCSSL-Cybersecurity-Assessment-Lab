# Reporting

The lab produces five kinds of report from one collected assessment, all built
from the same data so they cannot disagree with each other.

| Output | Produced by | Location |
| --- | --- | --- |
| Console summary | `python -m bcssl report` | terminal |
| Consolidated JSON | `python -m bcssl report --format json` | `reports/final/<run-id>.json` |
| Consolidated Markdown | `python -m bcssl report --format md` | `reports/final/<run-id>.md` |
| HTML report | `python -m bcssl report --format html` | `reports/final/<run-id>.html` |
| SARIF 2.1.0 | `python -m bcssl report --format sarif` | `reports/final/<run-id>.sarif` |
| Per-tool normalized JSON | every run | `reports/normalized/<run-id>/` |
| Raw tool output | every run | `reports/raw/<run-id>/` |

Reports are named after the assessment they describe (`run-001.html`,
`run-002.html`, ...), so each assessment keeps its own report set and a later
report never overwrites an earlier one. Attach a report to a specific
assessment with `--run`:

```bash
python -m bcssl report --run run-001 --format html,json,md,sarif
```

Reports are regenerated from `state/run-index.json`, so a report can be rebuilt
**without re-running any scan**:

```bash
python -m bcssl collect     # re-normalize, correlate and index evidence
python -m bcssl report
```

---

## SARIF 2.1.0 export

SARIF is the OASIS interchange format for static-analysis results, so findings
can be loaded into code-scanning and dashboard tooling without a bespoke
importer.

```bash
python -m bcssl report --format sarif
```

What the exporter guarantees:

- **Nothing is invented.** Every SARIF result corresponds to exactly one stored
  normalized finding. Nothing is classified, scored, deduplicated or merged.
- **One run per tool**, so results stay attributable to their source.
- **An empty assessment produces a valid, empty log** rather than being omitted
  or padded.
- Mapping is explicit: `tool`, `ruleId` (the correlation subject), `level`,
  `title`/`description` into `message.text`, `target`/`endpoint` into
  `physicalLocation`, `evidence` into `properties.evidenceExcerpt`,
  `recommendation` into `fixes`, and the lab's own `severity` and
  `verification_status` preserved in `properties`.

### Severity mapping

SARIF has exactly three levels, so the lab's five severities map onto them:

| Lab severity | SARIF `level` | `security-severity` |
| --- | --- | --- |
| CRITICAL | `error` | 9.5 |
| HIGH | `error` | 7.5 |
| MEDIUM | `warning` | 5.0 |
| LOW | `warning` | 2.5 |
| INFO | `note` | 0.0 |

The lab's original severity is preserved in `properties.severity`, so nothing is
lost. `security-severity` is the lab's own severity band expressed numerically -
it is **not** a CVSS score, and `properties["security-severity-basis"]` says so
in the file itself.

Structure is checked in the test suite (`tests/test_sarif.py`), including the
requirement that SARIF imposes of at least one `runs` entry even when there are
no findings.

---

## With no results

If no scan has been run, the report says so explicitly rather than rendering an
empty-looking assessment:

```text
--------------------------- REPORT ---------------------------
  No scan results available.
  Run 'python -m bcssl run <tool>' first.
```

The HTML report renders the same message, and the dashboard shows it too.

---

## The normalized finding schema

Every tool's output is reduced to these eleven fields. Nothing else is emitted.

```json
{
  "tool": "zap",
  "category": "security-header",
  "severity": "MEDIUM",
  "title": "Content Security Policy (CSP) Header Not Set",
  "description": "No Content Security Policy (CSP) header was found...",
  "target": "http://localhost:3001",
  "endpoint": "http://localhost:3001",
  "evidence": "ZAP plugin 10038\nZAP risk: Medium\nMethods: GET\nURLs (5): ...",
  "recommendation": "Ensure that your web server ... is configured to set the header",
  "timestamp": "2026-10-04T21:24:57Z",
  "verification_status": "CORROBORATED"
}
```

### Severity

`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`.

Each tool's native scale is folded in conservatively:

| Tool | Native scale | Mapping |
| --- | --- | --- |
| ZAP | `riskcode` 3/2/1/0 | HIGH / MEDIUM / LOW / INFO |
| Nuclei | `info.severity` | identity |
| Custom scanner | info/low/medium/high/critical | identity |
| Nikto | `Severity: x` marker, else OSVDB reference | explicit marker, else LOW / INFO |
| Nmap | port and service observations | INFO only |

Two rules are enforced:

- **ZAP never produces CRITICAL.** It has no such level, so the lab never
  manufactures one.
- **Unrecognised input is never inflated.** `from_string` defaults to INFO, and
  opaque identifiers such as `0xDEADBEEF` or `12345` resolve to INFO rather than
  having their digits read as a rating.

### Verification status

| Value | Meaning |
| --- | --- |
| `NOT VERIFIED` | A tool reported it; nothing has confirmed it. |
| `SINGLE-TOOL OBSERVATION` | Exactly one tool reported it, after correlation. |
| `CORROBORATED` | Two or more distinct tools reported the same fingerprint. |
| `DETECTED` | The lab reproduced the condition itself against the target. |
| `TOOL UNAVAILABLE` | The component could not run, so it contributed nothing. |

`DETECTED` is assigned by `bcssl/verify.py`, which performs its own minimal HTTP
checks (headers present or absent, path reachability). It can only *upgrade* an
existing finding; it never creates or removes one. Corroboration outranks
independent reproduction.

```bash
python -m bcssl verify     # show what the lab could re-check, and what it reproduced
```

---

## Cross-tool correlation

Correlation is deliberately conservative.

Two findings are linked only when they share an **exact** fingerprint of
`category::subject`. Subjects come from a shared vocabulary
(`bcssl/models.py:_SUBJECT_PATTERNS`), for example:

```text
missing-header:csp                 missing-header:csp
missing-header:hsts                missing-header:hsts
missing-header:frame-options       missing-header:frame-options
missing-header:nosniff             missing-header:nosniff
exposure:robots-txt                exposure:robots-txt
technology-disclosure:x-powered-by technology-disclosure:x-powered-by
```

Header names are matched tolerantly, because tools word them differently: ZAP
says "Anti-clickjacking Header", the custom scanner says "X-Frame-Options header
is missing", Nuclei says "Missing Security Headers". All three map to
`missing-header:frame-options`.

Rules:

- Two or more **distinct tools** on one fingerprint → **Confirmed by multiple tools**.
- One tool, however many endpoints → **Single-tool observation**.
- The same tool twice is never corroboration.
- Wording-derived fingerprints (a slug of the title) are **excluded** from
  confirmation, because identical wording is not independent agreement.

The report and the dashboard both show the reasoning, the contributing tools and
the endpoints for every group.

```bash
python -m bcssl report --correlation-view
```

---

## HTML report contents

Self-contained: no external stylesheet, font or script, so it can be archived as
evidence and opened offline. Light and dark themes, responsive layout.

1. Authorization banner and scope statement
2. Executive summary with severity totals
3. Tools that did not produce results, with the reason
4. Tool-by-tool results: status, version, exit code, duration, finding count
5. Cross-tool correlation table with labels and contributing tools
6. Verification status breakdown with definitions
7. Detailed findings grouped by severity, each with evidence and recommendation
8. Recommendations, deduplicated across tools
9. Evidence references with sha256 and an integrity check line
10. Scan metadata: target, start/finish, tool versions, durations
11. Scan limitations
12. Errors and warnings

All tool-supplied text is HTML-escaped. Tool output contains response fragments
from the target and must never be injected into the report as markup.

---

## Evidence

Each normalized finding gets a JSON record under `evidence/<tool>/`:

```json
{
  "tool": "nuclei",
  "finding_title": "Missing Security Headers: strict-transport-security",
  "target": "http://localhost:3001",
  "endpoint": "http://localhost:3001",
  "excerpt": "...",
  "raw_artifact": "reports/raw/nuclei/nuclei-20261004T211557Z/stdout.txt",
  "raw_sha256": "0f2c…",
  "recorded_at": "2026-10-04T21:15:57Z",
  "reference": "http-missing-security-headers"
}
```

`raw_sha256` is computed over the verbatim tool output, so a reviewer can prove
a finding came from the stored artifact rather than from someone's notes.

Integrity is re-checked on every report:

```text
Integrity check: 118 of 118 raw artifact(s) match their recorded sha256.
```

---

## Limitations

The report always states its own limits, including:

- a tool that is not installed contributed **no coverage**;
- a tool that timed out may be incomplete;
- output captured but not parsed is excluded from the severity summary;
- automated findings are indicators requiring manual verification;
- absence of a finding is not proof that the application is secure.

This section is never omitted. A report that hides its gaps is worse than no
report.

---

## Machine-readable output

```bash
python -m bcssl report --json     # the full payload
python -m bcssl collect --json    # run counts, correlation summary, evidence count
python -m bcssl status --json     # target, tools, runs, progress
python -m bcssl preflight --json  # component table
```

Exit codes: `0` success, `1` a tool or step failed, `2` configuration or target
rejected.

---

## The run index

`state/run-index.json` holds every run: command, exit code, duration, versions,
raw artifact paths, normalized findings (with the internal `subject` used for
correlation), evidence records, errors and warnings.

It is what makes `collect` and `report` reproducible without re-scanning. Delete
it with `scripts/clean.ps1`.
