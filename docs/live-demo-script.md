# Live demo script

An exact 10-15 minute demonstration. Every command here was executed on the
build machine and the expected output is taken from the latest real run
(`run-001`).

```text
AUTHORIZED TARGET
http://localhost:3001
```

**Before the demo.** In three terminals, with the project folder as the working
directory:

```powershell
# Terminal 1 - the demo terminal
cd C:\Users\devas\Documents\Cybersecurity\BCSSL-Cybersecurity-Assessment-Lab
$env:PYTHONPATH = (Get-Location).Path
```

```powershell
# Terminal 2 - target
powershell -ExecutionPolicy Bypass -File scripts\start-target.ps1
```

```powershell
# Terminal 3 - dashboard
python -m bcssl web --port 8765
```

Total timed sequence below: about 13 minutes.

---

## STEP 1 — Project directory and purpose (30 s)

Show the folder:

```powershell
Get-ChildItem -Name
```

**Say:**

"This is the BCSSL Cybersecurity Assessment Lab. It is an end-to-end security
assessment platform for a single authorized local target, and it includes a
graded student practical lab.

The problem it solves: five scanners produce five incompatible formats and
disagree with each other. Running them side by side gives a student 139 lines of
output and no defensible conclusion. This platform normalizes them, tells you
which findings are independently confirmed, and gives you evidence you can
prove."

Point at the directory names: `bcssl/` engine, `runners/` and `parsers/` thin
wrappers, `tools/` tool manifests, `lab/` exercises, `docs/`, `scripts/`,
`tests/`.

---

## STEP 2 — The authorized target (45 s)

```powershell
python -m bcssl validate-target
```

**Actual output:**

```text
AUTHORIZED TARGET
  http://localhost:3001
  host=localhost port=3001 scheme=http
  resolved to: ::1, 127.0.0.1
  target matches the authorized lab scope
  TARGET REACHABLE (HTTP 200)
```

**Say:**

"The one and only target is OWASP Juice Shop on localhost port 3001 — a
deliberately vulnerable training application. Testing is restricted to this
local lab.

The validator resolved the hostname and confirmed it stays on loopback. Now the
important demonstration — every one of these is refused:"

```powershell
python -m bcssl validate-target --url https://example.com --no-probe
python -m bcssl validate-target --url http://8.8.8.8:3001 --no-probe
python -m bcssl validate-target --url http://localhost:22 --no-probe
python -m bcssl validate-target --url http://user:pass@localhost:3001 --no-probe
```

**Actual results:** `host-not-authorized`, `not-loopback`, `port-not-authorized`,
and the credential URL refused — each with exit code 2.

**Say:**

"This same validator runs before every single tool. There is no code path in
which a scanner can be pointed at anything except this loopback target."

---

## STEP 3 — Preflight (1 min)

```powershell
python -m bcssl preflight
```

**Actual output:**

```text
Component             Status        Version      Details
--------------------  ------------  -----------  ---------------------------
python                [ OK ] READY  3.12.10     standard library only
docker-cli            [ OK ] READY  ...          docker CLI found
docker-daemon         [ OK ] READY  29.8.0      engine reachable
juice-shop-container  [ OK ] READY  Up ...       127.0.0.1:3001->3000/tcp
target                [ OK ] READY  HTTP 200     responded in 0.09s
configuration         [ OK ] READY  ...          authorized target http://localhost:3001
directories           [ OK ] READY  -            reports/ writable
project08             [ OK ] READY  read-only    external integration
nmap                  [ OK ] READY  docker ...   image instrumentisto/nmap
zap                   [ OK ] READY  docker ...   image ghcr.io/zaproxy/zaproxy
nikto                 [ OK ] READY  docker ...   image alpine/nikto
nuclei                [ OK ] READY  docker ...   image projectdiscovery/nuclei
custom-scanner        [ OK ] READY  Python 3.12.10

  Lab is ready. 5/5 assessment tools usable.
```

**Say:**

"Preflight answers one question honestly: can this lab run right now, and if
not, exactly what is missing? Thirteen components are probed for real.

Notice it distinguishes the Docker CLI from the Docker engine — they are
different things, and a missing engine means the container transport cannot
work. It also verified the container is bound to `127.0.0.1:3001` and not
`0.0.0.0`. If a required component were missing, this command would exit
non-zero and print the exact fix."

---

## STEP 4 — Nmap (1 min)

```powershell
python -m bcssl run nmap
```

**Actual output:**

```text
  SCAN COMPLETED
  exit code: 0
  findings: 1
  severities: INFO=1
```

**Say:**

"Nmap gives us the discovery layer: which port is open and what service is
listening. One finding — port 3001 open, TCP.

It is INFO severity, and that is deliberate. An open port on a target we were
told to assess is an observation, not a vulnerability.

What Nmap is *not* doing here is visible in the command it built. It uses TCP
connect scanning only. SYN scanning, OS fingerprinting, aggressive scanning and
UDP probing are all refused by the runner, and the port specification is
validated so it cannot be used to widen scope."

Optionally show the exact argv:

```powershell
python -m bcssl run nmap --json
```

---

## STEP 5 — OWASP ZAP (2 min)

```powershell
python -m bcssl run zap
```

**Actual output:**

```text
  SCAN COMPLETED
  exit code: 2
  findings: 11
  severities: MEDIUM=2, LOW=5, INFO=4
```

**Say, and this is the key point:**

"ZAP completed its passive web application assessment and raised 11 alerts.
Two are MEDIUM, five LOW, four INFO.

Notice the exit code is 2, not 0. ZAP's baseline script returns 2 when the scan
completed *and* found alerts. A naive wrapper would mark this run as FAILED and
throw away 11 real findings. This project declares the accepted exit codes per
tool, so ZAP's `(0, 2)` are both treated as success.

Two MEDIUM alerts: Content-Security-Policy header not set, and Cross-Domain
Misconfiguration."

Now show the safety refusals:

```powershell
python -m bcssl run nikto --tuning 126
```

**Actual output:**

```text
  error: Could not build a safe command: refusing nikto tuning '126':
  this lab does not run destructive or active-exploitation plugin groups -
  6 (denial of service)
```

**Say:**

"Nikto's plugin group 6 is a denial-of-service group. The runner refuses it by
name before anything executes. The same mechanism blocks aggressive Nmap flags,
intrusive Nuclei tags and out-of-scope scanner modules."

---

## STEP 6 — Nikto (1 min)

```powershell
python -m bcssl run nikto
```

**Actual output:**

```text
  SCAN COMPLETED
  exit code: 0
  findings: 104
  severities: INFO=104
```

**Say:**

"Nikto reviews web server configuration and reports information disclosure. 104
observations — all INFO.

That is honest. Nikto does not assign reliable severity, so the lab does not
invent one. Where Nikto embeds an explicit `Severity:` marker the lab honours
it; otherwise it stays INFO. Notice this creates a case the correlation engine
must not get wrong — Nikto and the custom scanner both found `/robots.txt`, and
they agreed because they matched a canonical fingerprint, not because the words
looked similar."

---

## STEP 7 — Nuclei (1 min)

```powershell
python -m bcssl run nuclei
```

**Actual output:**

```text
  SCAN COMPLETED
  exit code: 0
  findings: 19
  severities: MEDIUM=1, INFO=18
```

**Say:**

"Nuclei runs template-driven checks. 19 findings, one MEDIUM.

The important detail is the template scope. The complete nuclei template set is
over 14,000 templates and a large part of it is destructive or irrelevant to a
training app. The project ships a curated profile of about 2,600 templates —
technologies, misconfiguration, exposures, miscellaneous — and the excluded
families are documented with reasons in `tools/nuclei/README.md`.

Fuzzing, credential stuffing, default logins, token spray and exploitation
templates are excluded, and excluded twice: from configuration *and* from a
mandatory tag list merged at command-build time, so removing the configured
list does not re-enable them."

Then show the failure path honestly:

**Say:**

"Two things worth demonstrating because they are how this project refuses to
lie. First, Nuclei ships without templates. Without them the run fails with
`no templates provided for scan` — it does not produce invented findings.
Second, earlier in development Nuclei wrote console output where JSONL was
expected. The parser reported that as an *error*, because treating a format
mismatch as 'zero findings' would have been a lie."

---

## STEP 8 — Custom Project #08 scanner (1 min)

```powershell
python -m bcssl run custom-scanner
```

**Actual output:**

```text
  SCAN COMPLETED
  exit code: 0
  findings: 4
  severities: MEDIUM=2, INFO=2
```

**Say:**

"This is a separate, completed project integrated read-only. The lab never
modifies it — it invokes it as a subprocess with that project's own
interpreter. Only three modules are selectable: headers, paths and injection.

Two MEDIUM findings: a missing Content-Security-Policy header and a missing
Strict-Transport-Security header. Plus path discovery for `/robots.txt` and
`/ftp/`.

This component is what makes the platform educational rather than five
off-the-shelf tools: it is the one whose findings the lab can independently
verify, because it is ours."

---

## STEP 9 — Normalized findings (1 min)

```powershell
python -m bcssl status
```

**Say:**

"Why is normalization necessary? Look at what the five tools produced:

- Nmap produced XML.
- ZAP produced HTML alerts with a numeric riskcode.
- Nikto produced JSON with plugin ids and no reliable severity.
- Nuclei produced JSONL with template ids.
- The custom scanner produced HTML.

Five formats, five severity vocabularies, five output shapes. Without a common
schema, correlation, evidence and reporting are impossible.

Every finding is reduced to eleven fields: tool, category, severity, title,
description, target, endpoint, evidence, recommendation, timestamp, and
verification status.

Look at the severity breakdown: 129 INFO, 5 LOW, 5 MEDIUM. No HIGH, no
CRITICAL. Two rules made that honest. ZAP can never produce CRITICAL because
ZAP has no such level — the lab does not manufacture one. And an unrecognised
severity value becomes INFO rather than being read as a rating."

Show one raw normalized artifact:

```powershell
Get-Content reports\normalized\run-001\findings-run-001-zap.json -TotalCount 24
```

---

## STEP 10 — Correlation, real overlap (1.5 min)

```powershell
python -m bcssl report --correlation-view
```

**Actual output:**

```text
---------------------- CORRELATION VIEW ----------------------
  [CONFIRMED] MEDIUM   Content-Security-Policy header is missing
              tools: custom-scanner, zap
              endpoints: http://localhost:3001
  [CONFIRMED] INFO     Discovered accessible resource: /robots.txt
              tools: custom-scanner, nikto
              endpoints: http://localhost:3001/ftp/, http://localhost:3001/robots.txt
  [SINGLE]    MEDIUM   Strict-Transport-Security header is missing
              tools: custom-scanner
  ...
```

Totals: **31 groups, 2 confirmed by two or more tools, 29 single-tool.**

**Say:**

"This is the core of the project. Two findings were reported by two genuinely
different tools.

The first: Content-Security-Policy header is missing. The custom scanner found
it, and ZAP's passive rules found it independently. Those are two different
engines with two different detection logic agreeing.

The second: `/robots.txt` is accessible. The custom scanner's path discovery
module found it, and Nikto's content checks found it.

How is that decided? Only on an exact canonical fingerprint — a category and
subject pair like `missing-header:csp` or `exposure:robots-txt`. Two rules make
it trustworthy. Similar wording alone is never treated as agreement, and the
same tool twice is never corroboration.

Header names are matched tolerantly though, because tools word them
differently: ZAP says 'Anti-clickjacking Header', the custom scanner says
'X-Frame-Options header is missing', Nuclei says 'Missing Security Headers'.
All three map to `missing-header:frame-options`.

Everything else — 29 groups — is labelled a single-tool observation. We
deliberately under-correlate rather than over-correlate."

Now the distinction that matters most:

**Say:**

"And notice what ZAP's content-security-policy finding from STEP 5 is now. It
is not called a vulnerability. Its verification status is CORROBORATED — two
tools agree it is *reported*. Five findings are DETECTED, meaning this project
independently re-checked the condition against the live target itself. Seven
are NOT VERIFIED."

```powershell
python -m bcssl verify
```

---

## STEP 11 — Evidence and SHA-256 (1 min)

```powershell
python -m bcssl runs --verify
```

**Actual output:**

```text
  run-001  completed                tools=5  findings=139
      ok   custom-scanner   findings=4
      ok   nikto            findings=104
      ok   nmap             findings=1
      ok   nuclei           findings=19
      ok   zap              findings=11
      evidence: 124/124 intact
```

**Say:**

"Every normalized finding has an evidence record naming the verbatim raw
artifact it came from, plus that artifact's SHA-256.

124 records, 124 checked, 124 intact. Every report re-verifies these hashes, so
a reviewer can prove a finding was derived from captured output rather than
typed by hand.

Two design points worth noting.

First, every assessment gets a unique identifier — run-001, run-002 — with
isolated raw output, normalized findings, evidence, reports and metadata. A later
run can never overwrite an earlier one's evidence. That counter is reconciled
against the filesystem on every allocation, so even deleting a directory cannot
cause an identifier to be reused.

Second, evidence filenames are collision-safe. This is not theoretical: nuclei
reported 'HTTP Missing Security Headers' eight times for eight different
headers. Without unique filenames those eight records would have overwritten
each other and the evidence count would have understated the result. There is a
regression test for exactly that case."

Prove tampering is detected:

```powershell
(Get-Content reports\raw\run-001\run-001-nmap\stdout.txt)[0]
# edit that file by hand, then re-run:
python -m bcssl runs --verify
```

**Say:**

"It now reports DRIFT DETECTED. The hash no longer matches."

---

## STEP 12 — The dashboard (1.5 min)

```powershell
python -m bcssl web --port 8765 --open
```

Open <http://127.0.0.1:8765> and click through.

**Say:**

"Thirteen pages, sixteen JSON endpoints, and only the Python standard library —
no build step, no npm install."

| Page | Show |
| --- | --- |
| Dashboard | Live totals: 139 findings, 2 corroborated, tool status, verification breakdown |
| Target | Authorized scope, and a box to paste any URL and watch the validator refuse it |
| Preflight | The same thirteen-component table, with remedies |
| Tools | Availability, version, transport and install hint per tool |
| Run | Launch one tool or the full assessment |
| Findings | Filter by severity, tool and verification status |
| Correlation | Each group with its reasoning spelled out in words |
| Evidence | Artifact path and SHA-256 per record |
| Reports | Generate HTML, JSON, Markdown, SARIF |
| Exercises | The 12 practicals with checklists, questions and progress |
| Progress | Percentage, per-exercise status, achievement badges |
| Documentation | Read the shipped docs without leaving the browser |
| About | Scope, excluded testing, and the CLI equivalent of every action |

**Say two things:**

"It binds loopback only — the web command refuses any other address, because a
security lab dashboard should not be exposed.

And it never shows fake findings. Before a scan it reads 'No scan results
available'. Everything on screen is read from disk."

Show the answer-key protection on the Exercises page:

**Say:**

"When I open an exercise, the questions come back without any grading key. The
key fields are stripped server-side, so they never reach the browser."

---

## STEP 13 — Student practical workflow (1 min)

```powershell
python -m bcssl lab list
python -m bcssl lab show ex01
```

**Say:**

"Twelve practicals — four beginner, four intermediate, four advanced. Each has
an objective, the real safe command, the expected observation, a practical task,
an evidence requirement, three graded questions, a safety note and a completion
checklist.

Now the part that matters for teaching. Completion requires three things:
every checklist item ticked, every question answered and gradable ones correct,
and at least one evidence file recorded.

Running a scanner advances nothing. A student can run every tool in this lab and
still be at 0% — because progress requires evidence and understanding, not
activity.

And answers are graded automatically against a specification the student never
sees."

```powershell
python -m bcssl lab progress
```

---

## STEP 14 — Final report (1 min)

```powershell
python -m bcssl report --format html,json,md,sarif --correlation-view --open
```

**Actual output:**

```text
--------------------------- REPORT ---------------------------
  assessment     : run-001
  findings        : 139
  confirmed (2+)  : 2
  single-tool     : 29
  html           : reports/final/run-001.html
  json           : reports/final/run-001.json
  md             : reports/final/run-001.md
  sarif          : reports/final/run-001.sarif
```

The HTML report opens. Walk the sections: authorization banner, executive
summary, tools that produced no results and why, tool-by-tool results with
versions and exit codes, correlation with reasoning, verification breakdown,
detailed findings with evidence and recommendations, evidence hashes with the
integrity line, scan metadata, limitations, errors.

**Say, on the last two sections:**

"The report always states what it could not do. A tool that was unavailable, a
finding that could not be independently verified, coverage that was not
achieved. A lab that hides its gaps teaches the wrong lesson."

Confirm the interchange format:

```powershell
python -c "import json;d=json.load(open('reports/final/run-001.sarif',encoding='utf-8'));print('SARIF',d['version'],'-',sum(len(r['results']) for r in d['runs']),'results across',len(d['runs']),'tools')"
```

**Actual output:**

```text
SARIF 2.1.0 - 139 results across 5 tools
```

**Say:**

"SARIF 2.1.0 is the OASIS interchange format, so these results load into
code-scanning and dashboard tools without a bespoke importer. One run object
per tool keeps attribution intact. Because SARIF has three severity levels and
this project has five, the original severity is preserved in the file's own
properties, and the numeric band is explicitly labelled as a lab band rather
than a CVSS score."

Close with:

---

## Closing statement

> All testing was performed against the authorized local Juice Shop environment
> at `http://localhost:3001`. The project refuses any other target, never
> fabricates a result, and never calls a scanner observation a vulnerability
> without evidence supporting that conclusion.

---

## If you are asked about limitations

Answer from `docs/limitations.md`. The honest summary: one target on loopback;
not every finding can be independently verified; severity is not CVSS;
correlation is fingerprint-based and deliberately under-correlates; the four
external tools were verified through Docker rather than natively on this host;
Nuclei buffers output so a timeout loses the whole run; tool images are pinned
to `:latest`, so a future image could change output format again.