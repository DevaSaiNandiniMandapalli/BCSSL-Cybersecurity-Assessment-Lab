# Presentation content

Three slides. Every figure is taken from the latest real run (`run-001`) against
the authorized local target `http://localhost:3001`.

---

# SLIDE 1 — PROJECT OBJECTIVE

## BCSSL Cybersecurity Assessment Lab

**An authorized local cybersecurity lab for automated multi-tool assessment and
educational practicals**

### Problem

Practical security assessment is taught in two unsatisfactory ways: students
scan real websites, which is unsafe and unlawful, or they read about tools
without ever seeing how to interpret, corroborate and defend the output.

Running five scanners side by side does not solve it. Five tools produce five
formats and disagree with each other. A student sees 139 lines of output and no
defensible conclusion — no normalization, no way to know which findings are
independently confirmed, no way to prove a finding came from real captured
output.

### Objective

Build one platform that performs the complete assessment workflow against a
single authorized local target, and **refuses to overstate what it found**.

### Key features

| | |
| --- | --- |
| **Authorized local cybersecurity lab** | Only `http://localhost:3001`. Validator refuses every other host, port and scheme before any tool runs |
| **Automated multi-tool assessment** | Nmap, OWASP ZAP, Nikto, Nuclei and a custom scanner behind one command |
| **Educational practical environment** | 12 graded exercises, 3 levels, 36 auto-graded questions, answer keys never exposed to students |

### The principle the project is built on

> Never fabricate a result, and never call a scanner observation a vulnerability
> without evidence supporting that conclusion.

---

# SLIDE 2 — ARCHITECTURE & TOOLS

```text
                    Target
        OWASP Juice Shop @ localhost:3001
        (loopback only - the only authorized target)
                       |
                       v
      +--------+--------+--------+--------+--------+
      |        |        |        |        |        |
    Nmap     ZAP     Nikto   Nuclei   Custom          <- 5 assessment
      |        |        |        |        |             components
      +--------+--------+--------+--------+--------+
                       |
                       v
              Normalization
        one 11-field finding schema,
        5 severity scales folded conservatively
                       |
                       v
               Correlation Engine
        exact fingerprint match only:
        category::subject
                       |
                       v
          Evidence + SHA-256
        one record per finding,
        names verbatim artifact + digest
                       |
                       v
        Reports + Dashboard
                       |
                       v
              Student Exercises
```

## The five components

| Tool | One-line purpose |
| --- | --- |
| **Nmap** | Discovers which ports are open and what service is listening |
| **OWASP ZAP** | Assesses the web application and reports risk, URL and remediation |
| **Nikto** | Reviews web server configuration and information disclosure |
| **Nuclei** | Runs specific, reproducible template-driven checks |
| **Custom scanner** | Our own scanner: headers, path discovery, safe injection indicators |

## What each layer contributes

| Layer | Contribution |
| --- | --- |
| **Normalization** | Makes five incompatible outputs comparable — without it, correlation is impossible |
| **Correlation** | Separates "one tool said so" from "two independent tools agree" |
| **Evidence + SHA-256** | Proves each finding came from captured output, not from notes |
| **Reports** | HTML, JSON, Markdown and SARIF 2.1.0 from one assessment, so they cannot disagree |
| **Dashboard** | 13 pages of live state; loopback-only; never shows fake findings |
| **Exercises** | Graded practicals where progress requires evidence and understanding, not activity |

## Safety — enforced in code, not just configured

- Only `localhost:3001`; validator runs **before** every tool invocation
- Public IPv4/IPv6/IPv4-mapped addresses, wrong ports, credential URLs, argument smuggling — all refused
- Nikto's 8 destructive plugin groups, Nuclei's intrusive tags, Nmap's aggressive flags — refused by name
- A missing tool reports `TOOL NOT INSTALLED` and zero findings — never simulated

---

# SLIDE 3 — PRACTICAL DEMONSTRATION

## Real results, real run

```text
Local OWASP Juice Shop  @  http://localhost:3001
Assessment              run-001  (all 5 components completed)
```

## Preflight

```text
python -m bcssl preflight
```

13 components probed for real: Python, Docker CLI, Docker **engine**, target
container, target reachability, configuration, directories, Project #08, and all
five tools. Exact remediation for anything not ready; non-zero exit when a
required component is unavailable.

## Five assessment components

| Component | Exit | Findings | Severity |
| --- | --- | --- | --- |
| Nmap 7.98 | 0 | 1 | INFO |
| OWASP ZAP stable | **2** | 11 | MEDIUM 2, LOW 5, INFO 4 |
| Nikto 2.1.6 | 0 | 104 | INFO |
| Nuclei 3.11.1 | 0 | 19 | MEDIUM 1, INFO 18 |
| Custom scanner | 0 | 4 | MEDIUM 2, INFO 2 |
| **Total** | | **139** | INFO 129, LOW 5, MEDIUM 5 |

**ZAP's exit code 2 is correct.** Its baseline script returns 2 when the scan
completed *and* alerts were raised. A naive wrapper would discard 11 real
findings. The project declares accepted exit codes per tool.

## Real findings, honestly weighted

| Verification status | Count | Meaning |
| --- | --- | --- |
| Single-tool observation | 122 | Exactly one tool reported it |
| Not verified | 7 | Reported, not independently confirmed |
| **Corroborated** | **5** | Two or more tools reported the same fingerprint |
| **Detected** | **5** | The project reproduced the condition itself |
| Tool unavailable | 0 | — |

**Zero HIGH. Zero CRITICAL.** Because that is what the evidence supported. ZAP
cannot produce CRITICAL — it has no such level — and the project does not
manufacture one.

## Cross-tool correlation — genuine overlap

| Finding | Severity | Reported by |
| --- | --- | --- |
| Content-Security-Policy header is missing | MEDIUM | **custom scanner + ZAP** |
| Discovered accessible resource: `/robots.txt` | INFO | **custom scanner + Nikto** |

31 correlation groups · 2 confirmed by 2+ tools · 29 single-tool.
Matched only on an exact fingerprint (`category::subject`), never on similar
wording. Under-correlating is preferred over over-correlating.

## Evidence verification

```text
run-001:  124 evidence records  |  124/124 SHA-256 hashes intact
```

Every finding names the verbatim raw artifact it came from, plus its digest.
Reports re-verify on every generation. Tampering is reported as
`DRIFT DETECTED`.

Each assessment gets its own id — `run-001`, `run-002` — with isolated raw
output, findings, evidence, reports and metadata, so nothing is ever overwritten.

## Reports

| Format | Purpose |
| --- | --- |
| HTML | Self-contained, presentation-ready, opens offline |
| JSON | Full machine-readable payload |
| Markdown | Diff-friendly, reviewable |
| **SARIF 2.1.0** | OASIS interchange format — 139 results across 5 tool runs |

## Dashboard

13 pages · 16 JSON endpoints · standard library only · loopback-only bind.
Shows live state read from disk. Reads *"No scan results available"* before any
scan — it never shows fake findings.

## 12 practical exercises

4 beginner · 4 intermediate · 4 advanced · 36 auto-graded questions.

Completion requires **every checklist item ticked, every question answered
correctly, and evidence recorded**. Running a scanner advances nothing.

> A student can run all five tools and still be at 0%.

---

## Closing statement

> All testing was performed against the authorized local Juice Shop environment
> at `http://localhost:3001`. The project refuses any other target, never
> fabricates a result, and never calls a scanner observation a vulnerability
> without evidence supporting that conclusion.