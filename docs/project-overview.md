# Project overview

**BCSSL Cybersecurity Assessment Lab** — an authorized, local-only security
assessment platform with an educational practical environment.

| | |
| --- | --- |
| Authorized target | `http://localhost:3001` (OWASP Juice Shop, loopback only) |
| Assessment components | 5 |
| Latest run | `run-001`, all five components completed |
| Findings | 139 |
| Automated tests | 474 across 16 modules |
| Documentation | 22 documents |
| Student practicals | 12 exercises across 3 levels |

---

## 1. Problem statement

Practical security assessment is usually taught in one of two unsatisfactory
ways. Either students run scanners against real websites, which is unsafe and
legally fraught, or they read about tools without ever seeing how their output
is interpreted, corroborated and defended.

Running five scanners side by side does not solve this. Each produces a
different output format, uses a different severity scale, and disagrees with the
others about what counts as a problem. A student who runs Nmap, ZAP, Nikto,
Nuclei and a custom scanner sees 139 lines of output and no defensible
conclusion. There is no normalization, no way to tell which findings are
independently confirmed, no way to prove a finding came from real captured
output, and no way to present the result professionally.

## 2. Objective

Build a single platform that performs the complete assessment workflow against
one authorized local target, and refuses to overstate what it found.

The platform must:

- integrate five independent assessment tools behind one interface;
- reduce their incompatible outputs to one normalized finding schema;
- distinguish a scanner observation from a corroborated conclusion;
- preserve verifiable evidence with cryptographic hashes;
- produce professional reports and an interactive dashboard;
- provide graded, answer-key-protected student practicals;
- refuse any target other than the authorized local one;
- never fabricate a result when a tool cannot run.

## 3. Scope

**In scope.** One deliberately vulnerable training application on loopback:
port and service discovery, web application assessment, web server configuration
review, template-driven checks, and a custom scanner. Then normalization,
correlation, evidence, reporting, a dashboard and a student lab.

**Out of scope, by design.** Any network, subnet, domain, cloud or remote host.
Any credential testing, denial of service, fuzzing, exploitation, file upload or
bulk data extraction. See section 15.

## 4. Authorized target

```text
AUTHORIZED TARGET
http://localhost:3001
```

OWASP Juice Shop — a deliberately vulnerable training application from the OWASP
foundation. The container is published on `127.0.0.1:3001` only, so it is
unreachable from the local network. The lab's preflight raises a warning if it
ever observes any other binding.

## 5. Tools used

| Tool | Role in the pipeline | Latest result |
| --- | --- | --- |
| **Nmap** 7.98 | Port and service discovery | exit 0, 1 finding |
| **OWASP ZAP** stable | Web application assessment, baseline mode | exit 2, 11 findings |
| **Nikto** 2.1.6 | Web server configuration and information disclosure | exit 0, 104 findings |
| **Nuclei** 3.11.1 | Template-driven checks, curated safe profile | exit 0, 19 findings |
| **Custom Project #08 scanner** | Application security scanner | exit 0, 4 findings |

The four external tools run through the Docker transport, which is a supported
configuration rather than a workaround: each tool executes inside its own
official image, so no student machine needs a global install.

## 6. The custom scanner

A separate, completed project — *Web Security Scanner* (Project #08) — is
integrated **read-only**. The lab never modifies it. It is invoked as a
subprocess using that project's own virtual environment interpreter, and its
HTML report is parsed because its console table is width-dependent and therefore
not reliably machine-readable.

Only three modules are selectable: `headers`, `paths` and `injection`. Anything
else is refused. In the latest run it reported two `MEDIUM` findings — a missing
`Content-Security-Policy` header and a missing `Strict-Transport-Security`
header — plus two `INFO` observations.

The custom scanner is what makes the pipeline genuinely educational rather than
five off-the-shelf tools. It is the component whose finding the project can
independently verify.

## 7. Architecture

```text
                 Student / Instructor
                          |
                          v
              Web Dashboard (13 pages) / CLI (18 commands)
                          |
                          v
                  Assessment Controller
                          |
        +-----------------+------------------+
        |                 |                  |
        v                 v                  v
   Preflight      Target Validator     Configuration
                          |
                          v
    +---------+---------+---------+---------+
    |         |         |         |         |
  Nmap       ZAP       Nikto     Nuclei   Custom Scanner
    |         |         |         |         |
    +---------+---------+---------+---------+
                          |
                          v
              Tool Output / Raw Evidence
                          |
                          v
            Parsers + Normalization (11 fields)
                          |
                          v
                   Correlation Engine
                          |
                          v
                Evidence + SHA-256
                          |
                          v
                   Reporting Engine
                   /      |       \
                  v       v        v
                HTML    JSON    Markdown
                         +
                       SARIF 2.1.0
                          |
                          v
                   Student Practicals
```

Every layer is explained in `docs/architecture.md` against the actual modules.

## 8. Assessment workflow

Each assessment receives a unique identifier from a monotonic counter —
`run-001`, `run-002` — allocated before any tool runs. The counter is
reconciled against the filesystem and the run index on every allocation, so an
identifier can never be reused and an earlier assessment can never be
overwritten. One assessment owns an isolated namespace:

| Artifact | Location |
| --- | --- |
| Raw tool output | `reports/raw/run-001/run-001-<tool>/` |
| Normalized findings | `reports/normalized/run-001/` |
| Evidence records | `evidence/run-001/<tool>/` |
| Reports | `reports/final/run-001.{html,json,md,sarif}` |
| Run metadata | `state/assessments/run-001.json` |

Each tool then passes through a fixed ten-step runner contract: availability
check, version probe, target validation, safety validation, command
construction, execution with timeout, stdout/stderr capture, exit-code
interpretation, parsing, and evidence generation. A tool that fails is recorded
as failed; the batch continues and the report states exactly which tools
succeeded.

## 9. Finding normalization

Five tools emit five incompatible formats across five severity scales. The lab
reduces every finding to one eleven-field schema:

```json
{
  "tool": "zap",
  "category": "security-header",
  "severity": "MEDIUM",
  "title": "Content Security Policy (CSP) Header Not Set",
  "description": "...",
  "target": "http://localhost:3001",
  "endpoint": "http://localhost:3001",
  "evidence": "...",
  "recommendation": "...",
  "timestamp": "2026-10-05T04:16:29Z",
  "verification_status": "CORROBORATED"
}
```

Severity is folded in conservatively. ZAP's `riskcode` maps to the lab's bands
without ever producing `CRITICAL`, because ZAP has no such level. An
unrecognised value becomes `INFO` rather than being read as a rating. Nothing is
inflated.

Latest run severity distribution: `INFO` 129, `LOW` 5, `MEDIUM` 5, `HIGH` 0,
`CRITICAL` 0.

## 10. Correlation

Correlation links findings only when they share an **exact canonical
fingerprint** — a category and subject pair such as `missing-header:csp` or
`exposure:robots-txt`. Similar wording alone is never treated as agreement, and
the same tool twice is never corroboration.

Header names are matched tolerantly, because tools word them differently: ZAP
says "Anti-clickjacking Header", the custom scanner says "X-Frame-Options header
is missing", Nuclei says "Missing Security Headers". All three map to
`missing-header:frame-options`.

Latest run: 31 correlation groups, of which **2 are confirmed by two or more
tools**:

| Finding | Severity | Tools |
| --- | --- | --- |
| Content-Security-Policy header is missing | MEDIUM | custom-scanner, zap |
| Discovered accessible resource: `/robots.txt` | INFO | custom-scanner, nikto |

The remaining 29 groups are single-tool observations and are labelled as such.
Under-correlating is preferred over over-correlating.

## 11. Verification status

This is the mechanism that stops the lab from overstating its results.

| Status | Count in latest run | Meaning |
| --- | --- | --- |
| `SINGLE-TOOL OBSERVATION` | 122 | Exactly one tool reported it |
| `NOT VERIFIED` | 7 | Reported by a tool, not independently confirmed |
| `CORROBORATED` | 5 | Two or more tools reported the same fingerprint |
| `DETECTED` | 5 | The lab reproduced the condition itself |
| `TOOL UNAVAILABLE` | 0 | The component could not run |

`DETECTED` is assigned by `bcssl/verify.py`, which makes its own minimal HTTP
checks against the authorized target — whether specific headers are present or
absent, and whether a path returns a non-error status. In the latest run it
reproduced 5 conditions and refuted none. It can only *upgrade* a finding's
status, never create, remove or downgrade one.

**A finding is not a vulnerability.** A `DETECTED` missing-header finding means
the header was absent in a real response, not that an attack succeeded.

## 12. Evidence integrity

Every normalized finding gets a JSON evidence record naming the verbatim raw
artifact it was derived from, plus that artifact's SHA-256. A reviewer can
therefore prove a finding came from captured output rather than from anyone's
notes.

Latest run: **124 evidence records, 124 checked, 124 intact.** Integrity is
re-verified on every report generation and per assessment by
`python -m bcssl runs --verify`.

Filenames are unique per record. This matters in practice: nuclei reported
"HTTP Missing Security Headers" eight times for eight different headers. Without
collision-safe filenames those eight findings would have overwritten each other
and the evidence count would have understated the result. There is a regression
test for exactly this.

## 13. Reporting

Four formats from one collected assessment, so they cannot disagree:

| Format | File | Purpose |
| --- | --- | --- |
| HTML | `reports/final/run-001.html` | Self-contained, presentation-ready |
| JSON | `reports/final/run-001.json` | Machine-readable, full payload |
| Markdown | `reports/final/run-001.md` | Diff-friendly, reviewable |
| SARIF 2.1.0 | `reports/final/run-001.sarif` | Interchange with code-scanning tools |

The HTML report contains the authorization banner, executive summary,
tool-by-tool results, correlation with reasoning, verification-status breakdown,
detailed findings with evidence and recommendations, evidence hashes with an
integrity line, scan metadata, limitations and errors. All tool-supplied text is
HTML-escaped.

SARIF contains 139 results across 5 runs, one per tool, with no structural
problems. Because SARIF has three levels and the lab has five severities, the
mapping merges bands — but the original severity is preserved in
`properties.severity`, and `security-severity` is explicitly labelled as a lab
band rather than a CVSS score.

The report always states its own limits. A report that hides its gaps teaches
the wrong lesson.

## 14. Dashboard and student practicals

The dashboard runs on loopback only — the `web` command refuses any other bind
address — and serves thirteen pages from sixteen JSON endpoints using only the
Python standard library. It shows real state read from disk, and reads
"No scan results available" before anything has been scanned.

Twelve exercises run across three levels: four beginner, four intermediate, four
advanced. Each carries an objective, theory, prerequisites, the authorized
target, the tool, an exact safe command, the expected observation, a practical
task, an evidence requirement, three graded questions, a safety note and a
completion checklist.

All 36 questions carry a grading specification. Answer keys are stripped from
every student-facing response by `bcssl/lab/quiz.py`, so a key cannot leak
through the CLI, the dashboard API or a report. An exercise completes only when
every checklist item is ticked, **every question is answered and gradable ones
pass**, and at least one evidence reference is recorded. Running a scanner
advances nothing on its own.

## 15. Safety controls

The single most important property of the platform is that it cannot be pointed
at a system it should not touch.

| Control | Implementation |
| --- | --- |
| Target allowlist | Host and port allowlist; resolution must remain on loopback |
| Public address rejection | IPv4, IPv6 and IPv4-mapped public addresses refused |
| Credential URL rejection | URLs containing userinfo refused |
| Argument smuggling rejection | Control characters and whitespace refused |
| Scheme restriction | `http` and `https` only |
| Validation before every tool | Enforced in `BaseRunner.run`, before any command is built |
| Nmap scope | `-sT` only; `-sS`, `-O`, `-A`, `-sU` refused; port spec validated |
| Nikto scope | 8 destructive plugin groups refused by name |
| Nuclei scope | Intrusive tags excluded, plus a mandatory list merged at build time |
| ZAP scope | Bounded spider depth, duration and threads |
| Target binding | Compose publishes `127.0.0.1`; preflight flags any other binding |
| Dashboard binding | Loopback enforced |
| No fabrication | Missing tool yields `TOOL NOT INSTALLED` and zero findings |

Deliberately excluded everywhere: fuzzing, denial of service, credential
testing and brute force, exploitation templates, remote code execution, file
upload, remote file retrieval, SQL injection and authentication bypass. The
refusals are enforced in the runners, not merely omitted from configuration.

## 16. Limitations

Stated plainly, because a lab that hides its gaps teaches the wrong lesson.

**Scope.** One target, loopback only, one port. The lab assesses no network, no
subnet, no domain and no remote host.

**Coverage.** Not every finding can be independently verified. The lab's
verifier checks a small set of observable conditions; CVE-style, path-discovery
and version-banner findings keep their correlated status. `DETECTED` is not
"proven exploitable" — the lab never attempts exploitation.

**Severity.** The lab's severity bands are not CVSS scores and must not be
presented as such. Nikto provides no reliable severity, so severity is derived
conservatively.

**Correlation.** Fingerprint-based, not semantic. Two tools describing the same
condition with different wording will appear as two single-tool observations.
This under-correlates by design.

**Environment.** The four external tools run through Docker and were not
verified natively on this host. Nuclei buffers output, so a timeout loses the
whole run rather than partial results. Tool images are pinned to `:latest`, so a
future image may change output format again. Nuclei templates are downloaded
rather than committed, so findings can differ between cohorts.

**Automation.** The report reflects only stored runs. One scan point in time;
nothing is continuously monitored. An empty result is not proof that an
application is secure.

Full detail in `docs/limitations.md`.

## 17. Where to go next

| Purpose | Document |
| --- | --- |
| Architecture, layer by layer | `docs/architecture.md` |
| 10-15 minute demonstration | `docs/demo-guide.md`, `docs/live-demo-script.md` |
| Three-slide presentation | `docs/presentation-guide.md`, `docs/presentation-content.md` |
| Viva preparation | `docs/viva-questions.md` |
| Instructor commands | `docs/instructor-quick-start.md` |
| Student orientation | `docs/student-quick-start.md` |
| Installation | `docs/installation.md` |
| Report and correlation semantics | `docs/reporting.md` |
| Evidence model | `docs/evidence-guide.md` |
| Known limitations | `docs/limitations.md` |
| Verification evidence | `docs/final-verification.md` |
| Completion status | `docs/project-status.md` |