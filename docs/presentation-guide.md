# Presentation guide

A three-slide presentation of the lab. Each slide states what to show, what to
say, the command to run, and the result to expect.

**Total talk time: about 8 minutes.** The live demonstration is slide 3, where
the full sequence is in `docs/demo-guide.md`.

Before you present, put these in place so nothing is improvised live:

```powershell
cd C:\Users\devas\Documents\Cybersecurity\BCSSL-Cybersecurity-Assessment-Lab
$env:PYTHONPATH = (Get-Location).Path
powershell -ExecutionPolicy Bypass -File scripts\start-target.ps1
python -m bcssl preflight
```

Have open in three tabs: this document, the terminal, and
<http://127.0.0.1:8765> (start the dashboard in a fourth terminal with
`python -m bcssl web --port 8765`).

---

## Slide 1 - Problem and objective

### What to show

The title slide:

```text
BCSSL Cybersecurity Assessment Lab
Authorized local security assessment of http://localhost:3001
```

### What to explain

- Practical security assessment is usually taught on real public targets, which
  is unsafe and legally fraught for students.
- This lab gives the full assessment workflow - five scanners, normalization,
  cross-tool correlation, evidence with cryptographic hashes, professional
  reporting and a graded student lab - against **one deliberately vulnerable
  application on loopback only**.
- The design constraint that shapes everything: **never fabricate results**. If a
  tool cannot run, the lab says so and produces nothing.
- The second constraint: **never call something a vulnerability because a scanner
  printed a line.** Every finding carries a verification status.

### Command to perform

```powershell
python -m bcssl validate-target --url https://example.com --no-probe
```

### Expected result

```text
TARGET REJECTED - NOT AUTHORIZED
  code: host-not-authorized
  Only the configured target may be assessed.
```

### Say

"Before I show you the system, here is the safety property it is built around.
The lab's target validator refuses a public domain. The same validator runs
before every tool, so there is no code path in which a tool can be pointed at
anything except the configured loopback target."

---

## Slide 2 - Architecture and the five security tools

### What to show

The pipeline diagram. Either render it from `docs/architecture.md`, or write it
on a whiteboard - it is easier to explain by hand.

```text
                    BCSSL CYBERSECURITY LAB
                              |
                              v
                    AUTHORIZED TARGET
                    http://localhost:3001
                              |
        +---------------------+---------------------+
        |          |          |          |           |
        v          v          v          v           v
      Nmap       ZAP        Nikto      Nuclei    Custom Scanner
   (project 8, integrated read-only)
        |          |          |          |           |
        +----------+----------+----------+-----------+
                              |
                              v
                   RESULT NORMALIZATION
                              |
                              v
                    CORRELATION ENGINE
                              |
                              v
                    EVIDENCE MANAGEMENT
                              |
                              v
                     REPORTING ENGINE
                              |
             +----------------+----------------+
             v                                 v
        CLI REPORTS                       WEB DASHBOARD
             |                                 |
             +----------------+----------------+
                              |
                              v
                       STUDENT LAB
```

Then the role of each tool, in one line each:

| Tool | Role |
| --- | --- |
| Nmap | Which port is open, and what service is on it |
| OWASP ZAP | Application-level alerts with risk and confidence |
| Nikto | Web server configuration and information disclosure |
| Nuclei | Template-driven checks from a curated, non-destructive profile |
| Custom Project #08 | A completed scanner project, integrated read-only |

### What to explain

- **One normalized schema.** Five tools emit five completely different formats.
  All output is reduced to the same eleven fields, so correlation and reporting
  have one shape to work with.
- **Conservative severity mapping.** Five native scales folded in without
  inflation. ZAP cannot produce CRITICAL because ZAP has no such level, and an
  unrecognised value becomes INFO rather than being read as a rating.
- **Corroboration is fingerprint-based.** Two tools reporting the same canonical
  fingerprint (category plus subject) corroborate. Similar wording does not.
- **Evidence is hashed.** Each finding names the verbatim artifact it came from
  and its SHA-256.
- **Transport independence.** Each tool runs locally or in its official
  container image, chosen automatically.

### Command to perform

```powershell
python -m bcssl preflight
```

### Expected result

A `Component | Status | Version | Details` table with 13 rows, ending:

```text
  Lab is ready. 5/5 assessment tools usable.
```

### Say

"Preflight probes every component for real. It distinguishes the Docker CLI from
the Docker engine, and it never reports a tool as available because a file
exists on disk. If a required component is missing it exits non-zero, so it can
gate a lesson or a CI job."

---

## Slide 3 - Live practical demonstration

### What to show

The dashboard at <http://127.0.0.1:8765>, then the terminal.

### Sequence

**a. Launch the assessment** (it runs in the background for several minutes):

```powershell
python -m bcssl run-all
```

**b. Show tool availability and refusals** on the **Tools** page, then:

```powershell
python -m bcssl run nikto --tuning 126
```

Expected:

```text
  error: Could not build a safe command: refusing nikto tuning '126':
  this lab does not run destructive or active-exploitation plugin groups -
  6 (denial of service)
```

Nikto's plugin group 6 is a denial-of-service group. The runner refuses it by
name, before anything executes. The same mechanism blocks aggressive Nmap scan
types, intrusive Nuclei tags and out-of-scope scanner modules.

**c. Show findings** on the **Findings** page. Point at the verification-status
badge.

**d. Show correlation** on the **Correlation** page, including the reasoning
line under each group.

**e. Show evidence** on the **Evidence** page: raw artifact path plus SHA-256.

**f. Show the report:**

```powershell
python -m bcssl report --format html,json,md,sarif --correlation-view --open
```

**g. Show the student lab** on the **Exercises** page, then:

```powershell
python -m bcssl lab progress
```

### Expected results

Tool execution:

```text
  nmap            SCAN COMPLETED  exit 0   1 finding
  zap             SCAN COMPLETED  exit 2   11 findings
  nikto           SCAN COMPLETED  exit 0   104 findings
  nuclei          SCAN COMPLETED  exit 0   19 findings
  custom-scanner  SCAN COMPLETED  exit 0   4 findings
```

Note ZAP's exit code 2: the baseline script returns 2 when the scan completes
*and* alerts were raised. That is a successful scan, and the lab treats it as
one rather than discarding real findings.

Correlation:

```text
  [CONFIRMED] MEDIUM  Content-Security-Policy header is missing
             tools: custom-scanner, zap
  [CONFIRMED] MEDIUM  Discovered accessible resource: /robots.txt
             tools: custom-scanner, nikto
```

Report:

```text
  assessment     : run-001
  findings        : 139
  confirmed (2+)  : 2
  single-tool     : 29
  html  : reports/final/run-001.html
  json  : reports/final/run-001.json
  md    : reports/final/run-001.md
  sarif : reports/final/run-001.sarif
```

### Say

Three sentences worth landing:

1. "Five independent tools, one schema, and a report that names exactly which
   tools ran, which did not, and why."
2. "Two findings are corroborated by genuinely different tools. Everything else
   is labelled as a single-tool observation, because that is what it is."
3. "Each finding's evidence names the verbatim artifact and its SHA-256. A
   reviewer can prove where each finding came from - and the report re-verifies
   those hashes every time it is generated."

### If you are asked "what is missing?"

Point at the report's Limitations section and answer plainly. The lab states
what it could not do: tools that were unavailable, coverage that was not
achieved, and that automated findings are indicators requiring manual
verification. A lab that hides its gaps teaches the wrong lesson.

---

## Backup answers

**"What if a tool is not installed on the student's machine?"**
Preflight shows `[MISS]` with exact install instructions, and the tool reports
`TOOL NOT INSTALLED` with zero findings. There is no simulation path in the
codebase.

**"How do you prevent an accidental scan of a real system?"**
An allowlist of hosts and ports, a requirement that resolution stays on loopback,
rejection of credential-bearing URLs and of argument smuggling, and validation
that runs before every tool invocation. There are more than twenty rejection
tests covering IPv4, IPv6 and IPv4-mapped public addresses.

**"Does it exploit the target?"**
No. Fuzzing, denial of service, credential testing, exploitation templates,
uploads and data extraction are all excluded, and the exclusions are enforced in
the runners rather than merely omitted from configuration.

**"How is this graded?"**
Automatically. Answers are checked against a specification, the keys never reach
the student, and an exercise completes only when the checklist is ticked, the
questions pass and evidence is recorded. Running a tool never advances
progress.

**"Is it reproducible for the next cohort?"**
Each assessment gets its own identifier - run-001, run-002 - with isolated raw
output, findings, evidence, reports and metadata, so nothing is overwritten and
each run can be independently verified.