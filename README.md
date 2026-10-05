# BCSSL Cybersecurity Assessment Lab

An authorized, local-only security assessment laboratory. It runs a single
training target through several security tools, normalizes their very different
outputs into one finding schema, correlates overlapping findings, records
evidence, and produces a consolidated report a student can defend.

**The only target this lab will ever assess is `http://localhost:3001`** (OWASP
Juice Shop, running locally). The target validator enforces this before every
tool invocation, and refuses public IPs, external domains, arbitrary URLs and
unauthorized ports.

> **No fabricated results.** A tool that is not installed is reported as
> `TOOL NOT INSTALLED` and produces zero findings. A target that is not running
> is reported as `TARGET UNREACHABLE`. An empty finding list is only ever
> reported when a tool actually ran and returned nothing.

---

## Table of contents

- [Purpose](#purpose)
- [Architecture](#architecture)
- [Authorized scope](#authorized-scope)
- [Installation](#installation)
- [Tool prerequisites](#tool-prerequisites)
- [Configuration](#configuration)
- [Running individual tools](#running-individual-tools)
- [Running all tools](#running-all-tools)
- [Reports](#reports)
- [Evidence](#evidence)
- [Student workflow](#student-workflow)
- [Instructor workflow](#instructor-workflow)
- [Troubleshooting](#troubleshooting)
- [Ethical and legal scope](#ethical-and-legal-scope)
- [Project layout](#project-layout)
- [Documentation index](#documentation-index)

---

## Purpose

Comparing the output of several tools is how a student learns what each tool is
actually good at. This lab makes that comparison reproducible and auditable:

| Component | Role in the assessment |
|---|---|
| **Nmap** | Local host/port/service discovery. Informational observations only. |
| **OWASP ZAP** | Application assessment (baseline = passive + low-impact active). |
| **Nikto** | Web server configuration and disclosure checks. |
| **Nuclei** | Template-based checks, destructive template families excluded. |
| **Custom scanner** | The in-house Project #08 application scanner, invoked as an external process. |

Each tool has a different output format and a different severity vocabulary.
The lab's job is to make them comparable without overstating what any of them
found.

---

## Architecture

```mermaid
flowchart TD
    S[Student / Instructor] --> D[Lab Dashboard or CLI]
    D --> V[Authorized Target Validation<br/>bcssl/target.py]

    V -->|rejected| R[TARGET REJECTED<br/>no command is built]
    V -->|authorized| P[Tool Availability Check<br/>bcssl/preflight.py]
    P -->|not installed| N[TOOL NOT INSTALLED<br/>zero findings]
    P -->|available| NM[Nmap<br/>discovery]
    P --> ZP[OWASP ZAP<br/>app assessment]
    P --> NK[Nikto<br/>server config]
    P --> NU[Nuclei<br/>template checks]
    P --> CS[Custom Scanner<br/>external Project #08]

    NM --> X[Raw Output Stored Verbatim<br/>reports/raw/]
    ZP --> X
    NK --> X
    NU --> X
    CS --> X

    X --> NRM[Parsing + Normalization<br/>bcssl/parsers/]
    NRM --> F[Normalized Findings<br/>10-key schema]
    F --> COR[Cross-Tool Correlation<br/>bcssl/correlation.py]
    COR --> EV[Evidence Collection<br/>bcssl/evidence.py]
    EV --> REP[Consolidated Report<br/>HTML + JSON + Markdown]
```

Two invariants shape the middle of this pipeline:

1. **Correlation is conservative.** Two findings are linked only when they
   share an exact normalized fingerprint. Two or more *distinct* tools on one
   fingerprint is labelled **Confirmed by multiple tools**; anything else is
   **Single-tool observation**. Wording similarity alone never counts.
2. **Findings are never invented.** Parsers emit only what a tool actually
   reported. Unparseable output produces a `PARSE_ERROR` and an explanation,
   not an empty-but-successful-looking scan.

Every tool integration follows the same ten-step runner contract:

```mermaid
flowchart LR
    A[1 Verify tool<br/>availability] --> B[2 Verify target<br/>authorization]
    B --> C[3 Build safe<br/>command]
    C --> D[4 Execute]
    D --> E[5 Capture<br/>stdout/stderr]
    E --> F[6 Capture<br/>exit code]
    F --> G[7 Store raw<br/>output verbatim]
    G --> H[8 Parse output]
    H --> I[9 Normalize<br/>findings]
    I --> J[10 Generate evidence<br/>metadata]
```

---

## Authorized scope

```text
AUTHORIZED TARGET
http://localhost:3001
Allowed hosts : localhost, 127.0.0.1, ::1
Allowed ports : 3001
```

The validator in `bcssl/target.py` is **allowlist-based**, not blocklist-based.
A target is accepted only when all of the following hold:

- the scheme is `http` or `https`;
- the host appears in `target.allowed_hosts`;
- every address the host resolves to is a **loopback** address;
- the port appears in `target.allowed_ports`;
- the string contains no control characters or whitespace (which would allow
  argument smuggling into an external tool's command line);
- no credentials are embedded in the URL.

Everything else is rejected with a machine-readable code, for example:

| Input | Result |
|---|---|
| `http://localhost:3001` | accepted |
| `http://[::1]:3001` | accepted |
| `http://localhost:3000` | `port-not-authorized` |
| `https://example.com:3001` | `host-not-authorized` |
| `http://8.8.8.8:3001` | `not-loopback` |
| `http://[::ffff:8.8.8.8]:3001` | `not-loopback` |
| `http://localhost:3001@evil.example` | `credentials-in-url` |
| `http://localhost:3001 -oX /tmp/x` | `forbidden-character` |
| `ftp://localhost:3001` | `scheme-not-allowed` |
| `not-a-url` | `missing-scheme` |

Try it yourself:

```bash
python -m bcssl validate-target --url https://example.com
```

### Starting the target

The lab needs the Juice Shop running. With Docker Desktop started:

```bash
docker run --rm -p 3001:3001 bkimminich/juice-shop
```

Confirm it answers before scanning:

```bash
python -m bcssl validate-target
```

If the target is not listening you will see `TARGET UNREACHABLE`, which is a
real result, not an error to hide.

---

## Installation

The engine is **dependency-free**: it uses only the Python standard library.

```bash
# Python 3.10 or newer
python --version

# From the project root, no install step is required
python -m bcssl version
python -m bcssl preflight
```

Optionally install it as a package to get the shorter `bcssl` command:

```bash
pip install -e .
bcssl version
```

Run the test suite (240 tests, no network access, no scans):

```bash
python -m pytest
```

---

## Tool prerequisites

`python -m bcssl preflight` reports exactly what is available on your machine.

| Tool | Required for | Notes |
|---|---|---|
| Python 3.10+ | the lab itself | standard library only |
| Nmap | Exercise 02 | TCP connect scan, no admin rights needed |
| OWASP ZAP | Exercise 05 | **requires a Java runtime** |
| Nikto | Exercise 04, 06 | requires Perl |
| Nuclei | Exercise 09 | install templates ahead of class if offline |
| Project #08 scanner | Exercises 03, 07, 10, 12 | set `tools.custom-scanner.project_root` |

Install hints (never applied automatically):

```bash
# Windows
winget install Insecure.Nmap
winget install zaproxy.zaproxy.stable
winget install nuclei

# macOS
brew install nmap nikto nuclei

# Linux
sudo apt-get install nmap nikto
```

If a local executable is missing but Docker Desktop is running, the lab can use
the configured image instead (`ghcr.io/zaproxy/zaproxy:stable`,
`projectdiscovery/nuclei`, `ediblehobo/nikto`, `instrumentisto/nmap`).

> **Status of this checkout.** All five components were verified by **real
> execution** against a live Juice Shop: Nmap 7.98, OWASP ZAP stable, Nikto 2.1.6
> and Nuclei 3.11.1 run through the Docker transport, and the Project #08 scanner
> runs natively. See `docs/final-verification.md` for the recorded evidence and
> `docs/limitations.md` for what is deliberately out of scope.

---

## Configuration

`config/lab-config.json` is the single source of truth.

| Key | Meaning |
|---|---|
| `target.authorized_url` | the one permitted target |
| `target.allowed_hosts` | loopback names/addresses accepted |
| `target.allowed_ports` | loopback ports accepted |
| `target.require_loopback` | refuse anything that resolves off-loopback |
| `tools.<tool>.enabled` | turn a component off entirely |
| `tools.<tool>.executable` | executable name or absolute path |
| `tools.<tool>.transport` | `auto`, `local` or `docker` |
| `tools.<tool>.timeout_seconds` | per-tool timeout |
| `tools.nmap.ports` | port specification (default `3001`) |
| `tools.zap.mode` / `alert_threshold` | `baseline`/`passive`, ZAP alert threshold |
| `tools.nikto.tuning` | plugin groups (destructive groups are rejected) |
| `tools.nuclei.exclude_tags` | merged with a mandatory exclusion list |
| `tools.custom-scanner.project_root` | location of the external Project #08 |
| `pipeline.severity_floor` | drop findings below this severity |
| `web.host` / `web.port` | dashboard bind address (loopback only) |

Layer an instructor override on top without editing the shipped file:

```bash
python -m bcssl --config config/instructor-config.json status
```

See `config/instructor-config.example.json` and
[docs/instructor-guide.md](docs/instructor-guide.md).

---

## Running individual tools

```bash
python -m bcssl run nmap
python -m bcssl run zap --mode baseline
python -m bcssl run zap --mode passive
python -m bcssl run nikto
python -m bcssl run nikto --tuning 7b
python -m bcssl run nuclei --severities low,medium,high
python -m bcssl run custom-scanner --modules headers
python -m bcssl run custom-scanner --modules paths
python -m bcssl run nmap --ports 3001,8080      # ports must be instructor-enabled
```

Every run prints the authorized target first, then the exact command, the tool
version, the exit code, the duration, and either the findings or the reason it
could not run.

Equivalently, the thin wrappers in `runners/`:

```bash
python runners/nmap-runner/main.py
python runners/custom-scanner-runner/main.py --modules headers
```

---

## Running all tools

```bash
python -m bcssl run-all
python -m bcssl run-all --tools zap,nikto,custom-scanner
python scripts/run-all.py            # same thing
```

Each tool runs independently: a missing or failing tool never stops the others,
and a tool that did not run contributes no findings.

---

## Reports

```bash
python -m bcssl report                                   # HTML
python -m bcssl report --format html,json,md            # all three
python -m bcssl report --correlation-view                # print the correlation table
python scripts/generate-report.py
```

Output lands in `reports/final/`. The HTML report is self-contained (no external
assets), supports light and dark themes, is responsive, and includes:

1. Executive summary with severity totals
2. Detailed findings grouped by severity
3. Tool-by-tool results with versions, exit codes and durations
4. Cross-tool correlation with confirmation labels
5. Evidence references with sha256 integrity hashes
6. Recommendations, deduplicated
7. Scan metadata, limitations, and errors
8. The authorization statement

With no prior scan it states **"No scan results available."** instead of
rendering an empty report.

Machine-readable form:

```bash
python -m bcssl report --json
python -m bcssl collect --json
python -m bcssl status --json
```

---

## Evidence

| Location | Contents |
|---|---|
| `reports/raw/<tool>/<run-id>/` | verbatim stdout, stderr and the tool's native report |
| `reports/normalized/` | findings in the documented ten-key schema |
| `reports/final/` | consolidated reports |
| `evidence/<tool>/` | one JSON record per finding |
| `state/` | run index, evidence index, student progress |

Each evidence record names the raw artifact it was derived from and its
`sha256`, so a finding can be traced back to unmodified tool output:

```json
{
  "tool": "custom-scanner",
  "finding_title": "Content-Security-Policy header is missing",
  "endpoint": "http://localhost:3001/",
  "raw_artifact": "reports/raw/custom-scanner/custom-scanner-20261004T131759Z/stdout.txt",
  "raw_sha256": "…"
}
```

Verify integrity at any time:

```bash
python -m bcssl collect        # reports how many artifacts still match their hash
```

---

## Student workflow

1. Start the target and confirm it answers.
2. `python -m bcssl preflight` — record which tools are available.
3. Work the exercises in order:

   ```bash
   python -m bcssl lab list
   python -m bcssl lab show ex03
   ```

4. Run the exercise's tool and save the output as evidence under
   `evidence/<tool>/`.
5. Answer the questions and tick the checklist **yourself**:

   ```bash
   python -m bcssl lab ack ex03 \
       --check c1 --check c2 --check c3 --check c4 \
       --answer "q1=Your answer in your own words" \
       --answer "q2=..." --answer "q3=..." \
       --evidence "reports/raw/custom-scanner/ex03-headers-report.html"
   ```

6. Build the final report:

   ```bash
   python -m bcssl run-all
   python -m bcssl report --correlation-view --open
   ```

> **Progress is never awarded for running a tool.** An exercise completes only
> when you have acknowledged the evidence, answered every question and ticked
> every checklist item. The lab does not infer completion from a scan.

The optional dashboard shows the same data:

```bash
python -m bcssl web --open        # http://127.0.0.1:8765
```

---

## Instructor workflow

1. Review and adjust `config/lab-config.json`, or layer an instructor config.
2. Preflight the classroom machines; install what is missing.
3. Verify the target and the validator before class.
4. Teach exercises 01-04 (beginner), 05-08 (intermediate), 09-12 (advanced).
5. Grade on **evidence + answers**, not on finding counts. Different tool
   versions legitimately produce different results.
6. Reset a student's progress with:

   ```bash
   python -m bcssl lab reset ex05     # one exercise
   python -m bcssl lab reset          # everything
   ```

Details and grading guidance: [docs/instructor-guide.md](docs/instructor-guide.md).

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `TOOL NOT INSTALLED` | executable not on PATH | install it, or start Docker Desktop for container fallback |
| `TARGET UNREACHABLE` | target not running | start Juice Shop on port 3001 |
| `TARGET REJECTED` | outside authorized scope | use `http://localhost:3001`; ask the instructor to widen the allowlist |
| `TOOL FAILED` (exit code) | tool crashed | read `reports/raw/<tool>/<run-id>/stderr.txt` |
| `TIMEOUT` | exceeded the configured limit | raise `timeout_seconds`, or investigate the target |
| `OUTPUT COULD NOT BE PARSED` | tool output format changed | read the raw output; do not hand-write findings |
| ZAP will not start | no Java runtime | install a JRE, or use the Docker image |
| Dashboard port in use | 8765 taken | `python -m bcssl web --port 8766` |

More: [docs/troubleshooting.md](docs/troubleshooting.md).

---

## Ethical and legal scope

This project is an **authorized educational laboratory**. It is built to assess
one deliberately vulnerable training application on the loopback interface of
the machine it runs on.

- The lab refuses to scan any host outside the configured loopback allowlist.
  This is enforced in code, not by convention.
- Do not point this lab at any system you do not own or have written
  authorization to test. In many jurisdictions, unauthorized access to computer
  systems is a criminal offence regardless of intent.
- Do not use the knowledge gained here against systems you are not authorized
  to test.
- Excluded on purpose: uploads, injection, remote file retrieval, denial of
  service, command execution, SQL injection, authentication bypass, remote
  source inclusion, brute force and fuzzing templates. The runners reject these
  configurations rather than merely documenting them.
- Findings are automated indicators. They require manual verification, and an
  empty result is not proof that an application is secure.

---

## Project layout

```text
BCSSL-Cybersecurity-Assessment-Lab/
├── README.md, LICENSE, .gitignore, pyproject.toml
├── config/
│   ├── lab-config.json                 single source of truth
│   └── instructor-config.example.json  override template
├── bcssl/                             engine
│   ├── target.py                       authorized-target validator
│   ├── preflight.py                    tool availability
│   ├── executor.py                     subprocess capture
│   ├── runner.py                       10-step runner contract
│   ├── parsers/                        nmap, zap, nikto, nuclei, custom
│   ├── runners/                        nmap, zap, nikto, nuclei, custom
│   ├── correlation.py                  cross-tool correlation
│   ├── evidence.py                     evidence + integrity
│   ├── reporting.py                    HTML/JSON/Markdown
│   ├── pipeline.py                     run, collect, persist
│   ├── lab/                            exercises + progress
│   ├── web/                            stdlib dashboard
│   └── cli.py                          command-line interface
├── runners/<tool>-runner/              thin entry points
├── parsers/<tool>-parser/              standalone parser CLIs
├── tools/<tool>/tool.json              executable, image, install hints
├── reports/{raw,normalized,final}/     artifacts
├── evidence/<tool>/                    per-finding evidence
├── state/                              run index + progress (gitignored)
├── lab/<level>/exNN/                   exercise.json + exercise.md
├── scripts/                            preflight, validate-target, run-all,
│                                        collect-results, generate-report
├── docs/                               architecture, tool-guide, student-guide,
│                                        instructor-guide, evidence-guide,
│                                        troubleshooting
└── tests/                              240 tests
```

### Normalized finding schema

Every tool's output is reduced to these ten fields:

```json
{
  "tool": "",
  "category": "",
  "severity": "",
  "title": "",
  "description": "",
  "target": "",
  "endpoint": "",
  "evidence": "",
  "recommendation": "",
  "timestamp": ""
}
```

Severities: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`.

Tool-specific mapping:

| Tool | Native scale | Mapped |
|---|---|---|
| ZAP | `riskcode` 3/2/1/0 | HIGH/MEDIUM/LOW/INFO (never CRITICAL) |
| Nuclei | `info.severity` | identity |
| Custom scanner | info/low/medium/high/critical | identity |
| Nikto | `Severity: x` marker, else conservative LOW/INFO | nearest level |
| Nmap | service/port observations | INFO only |

---

## Documentation index

| Document | Contents |
|---|---|
| [docs/project-overview.md](docs/project-overview.md) | project summary: problem, objective, architecture, results |
| [docs/architecture.md](docs/architecture.md) | layer flow, per-layer implementation, module map |
| [docs/tool-guide.md](docs/tool-guide.md) | per-tool reference and install hints |
| [docs/student-guide.md](docs/student-guide.md) | the twelve exercises, step by step |
| [docs/instructor-guide.md](docs/instructor-guide.md) | configuration, preflight, grading |
| [docs/evidence-guide.md](docs/evidence-guide.md) | evidence model and submission template |
| [docs/installation.md](docs/installation.md) | step-by-step setup from a clean machine |
| [docs/instructor-quick-start.md](docs/instructor-quick-start.md) | the minimum commands to run a session |
| [docs/student-quick-start.md](docs/student-quick-start.md) | beginner-facing lab orientation |
| [docs/demo-guide.md](docs/demo-guide.md) | scripted 10-15 minute demonstration |
| [docs/live-demo-script.md](docs/live-demo-script.md) | exact 14-step live demo with real expected output |
| [docs/presentation-guide.md](docs/presentation-guide.md) | three-slide faculty presentation |
| [docs/presentation-content.md](docs/presentation-content.md) | slide-ready content with verified figures |
| [docs/demo-screenshot-checklist.md](docs/demo-screenshot-checklist.md) | the 15 screenshots to capture, and how |
| [docs/viva-questions.md](docs/viva-questions.md) | 30 viva questions with answers |
| [docs/daily-work-summary.md](docs/daily-work-summary.md) | work-sheet summary line with evidence |
| [docs/reporting.md](docs/reporting.md) | report formats, correlation, verification status |
| [docs/limitations.md](docs/limitations.md) | what the lab does *not* do, and why |
| [docs/troubleshooting.md](docs/troubleshooting.md) | symptom/cause/fix |
| [docs/project-status.md](docs/project-status.md) | component-by-component completion status |
| [docs/final-verification.md](docs/final-verification.md) | recorded verification evidence |
| [docs/final-project-scorecard.md](docs/final-project-scorecard.md) | honest completion percentages |
| [RELEASE-CHECKLIST.md](RELEASE-CHECKLIST.md) | pre-handover verification list |

---

## License

MIT — see [LICENSE](LICENSE), including the educational scope notice.
