# Demo guide

A complete, reliable demonstration of the lab in **10-15 minutes**, using only
the authorized target.

```text
AUTHORIZED TARGET
http://localhost:3001
```

Every command below was run on the build machine and is reproduced exactly as
written. Timings are realistic for a laptop with Docker Desktop.

> **Before you present.** Run steps 0a-0c at least once on the demo machine.
> The first assessment run pulls container images and needs roughly 10 minutes;
> every run after that takes about 6-8 minutes. A full assessment has already
> been executed on the build machine and its results are documented in
> `docs/final-verification.md`.

---

## Timing at a glance

| Step | What you show | Time |
| --- | --- | --- |
| 0 | Prepare the machine | 1 min |
| 1 | Start Docker | 1 min |
| 2 | Start Juice Shop | 1 min |
| 3 | Preflight | 1 min |
| 4 | Open the dashboard | 30 s |
| 5 | Target validation, including refusals | 1 min |
| 6 | Run the assessment | 30 s to launch |
| 7 | Watch tool execution | 3 min |
| 8 | Show findings | 1 min |
| 9 | Show correlation | 1 min |
| 10 | Show evidence with hashes | 1 min |
| 11 | Show the final report | 1 min |
| 12 | Show the student exercises | 1 min |
| 13 | Shut down cleanly | 30 s |

---

## 0. Prepare (before the audience arrives)

Open a terminal in the project folder:

```powershell
cd C:\Users\devas\Documents\Cybersecurity\BCSSL-Cybersecurity-Assessment-Lab
```

Set the module path once per terminal. Every command in this guide assumes it:

```powershell
$env:PYTHONPATH = (Get-Location).Path
```

Two optional one-time steps. Skip them if `python -m bcssl preflight` already
reports all five tools as available.

```powershell
powershell -ExecutionPolicy Bypass -File scripts\setup.ps1
```

This pulls the five container images and builds the Nuclei template profile. It
installs no software.

---

## 1. Start Docker

```powershell
docker info --format '{{.ServerVersion}}'
```

**Say:** "Docker Desktop is the lab's portability layer. Nmap, ZAP, Nikto and
Nuclei run inside their official images; the custom Project #08 scanner runs
natively. Nothing is installed on the student's machine."

**Expected:** a version number such as `29.8.0`.

If Docker Desktop is not running, start it and wait until this command prints a
version. Every tool check below depends on it.

---

## 2. Start Juice Shop

```powershell
powershell -ExecutionPolicy Bypass -File scripts\start-target.ps1
```

**Say:** "OWASP Juice Shop is a deliberately vulnerable training application.
The lab's job is to find real problems in it, safely, on loopback only."

**Expected:**

```text
==> Container state: Up 3 seconds (health: starting) 127.0.0.1:3001->3000/tcp
==> Waiting for http://localhost:3001 to answer (timeout 180s)

[ OK ] Target is up.
       AUTHORIZED TARGET: http://localhost:3001
```

**Point out:** the binding is `127.0.0.1:3001`, not `0.0.0.0:3001`. A
deliberately vulnerable application must never be reachable from the network.
This is enforced in `target/docker-compose.yml` and the lab's preflight raises
a warning if it ever sees any other binding.

Optional confirmation:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\check-target.ps1
```

---

## 3. Preflight

```powershell
python -m bcssl preflight
```

**Say:** "Preflight answers one question honestly: can this lab run right now,
and if not, what exactly is missing? Nothing is assumed."

**Expected** on a prepared machine:

```text
Component             Status        Version      Details
--------------------  ------------  -----------  ---------------------------
python                [ OK ] READY  3.12.10     standard library only
docker-cli            [ OK ] READY  ...          docker CLI found
docker-daemon         [ OK ] READY  29.8.0      engine reachable
juice-shop-container  [ OK ] READY  Up 2 minutes 127.0.0.1:3001->3000/tcp
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

**To make the honesty point**, show what happens when something is missing.
Disable one tool and re-run:

```powershell
python -c "import json,pathlib;p=pathlib.Path('config/lab-config.json');d=json.loads(p.read_text(encoding='utf-8'));d['tools']['nikto']['enabled']=False;p.write_text(json.dumps(d,indent=2)+chr(10),encoding='utf-8')"
python -m bcssl preflight
```

**Say:** "Nikto now shows UNAVAILABLE with the exact instruction to re-enable it.
The lab will not fabricate Nikto findings."

Restore it immediately:

```powershell
python -c "import json,pathlib;p=pathlib.Path('config/lab-config.json');d=json.loads(p.read_text(encoding='utf-8'));d['tools']['nikto']['enabled']=True;p.write_text(json.dumps(d,indent=2)+chr(10),encoding='utf-8')"
```

---

## 4. Open the dashboard

```powershell
python -m bcssl web --port 8765 --open
```

Leave this running in its own terminal for the rest of the demo. If you closed
it earlier, navigate to <http://127.0.0.1:8765>.

**Say:** "Thirteen pages, sixteen JSON endpoints, standard library only, no
build step. It binds loopback only - the `web` command refuses any other bind
address."

Click through **Dashboard**, **Tools** and **Preflight**. Each shows live state
read from disk.

**If no scan has been run yet**, the dashboard says:

```text
No scan results available.
```

That is the point: the lab never shows fake findings to make itself look
impressive.

---

## 5. Show target validation, including the refusals

Accept the authorized target:

```powershell
python -m bcssl validate-target
```

**Expected:**

```text
AUTHORIZED TARGET
  http://localhost:3001
  host=localhost port=3001 scheme=http
  TARGET REACHABLE (HTTP 200)
```

Now the refusals. Run each of these:

```powershell
python -m bcssl validate-target --url https://example.com --no-probe
python -m bcssl validate-target --url http://8.8.8.8:3001 --no-probe
python -m bcssl validate-target --url http://localhost:22 --no-probe
python -m bcssl validate-target --url http://user:pass@localhost:3001 --no-probe
python -m bcssl validate-target --url http://localhost:3001/ -oX /tmp/x --no-probe
```

**Say, once:** "This validator runs before every single tool. A public domain, a
public IP, the wrong port, a credential-bearing URL and an argument-smuggling
attempt are each refused with a distinct reason code. The lab fails safe."

**Expected** for each: `TARGET REJECTED` with a code such as
`host-not-authorized`, `not-loopback`, `port-not-authorized`,
`credentials-not-allowed` or `invalid-characters`, and a non-zero exit code.

Show it in the dashboard too: **Target** page, paste a URL, press **Validate**.

---

## 6. Run the assessment

```powershell
python -m bcssl run-all
```

**Say:** "One click, five tools, and the run continues when a tool fails. The
report will state exactly which tools succeeded and which did not."

Note the assessment identifier printed at the start, for example `run-001`.
Everything this run produces is namespaced under it.

The command takes roughly 6-8 minutes. Start it, then move to step 7 and watch
the dashboard's **Run** page, or watch the terminal output.

**If you need a fast demo**, run one tool instead:

```powershell
python -m bcssl run nmap
```

---

## 7. Show tool execution

In the dashboard, **Run** shows per-tool status. Or in the terminal, each tool
prints its status, exit code, duration and finding count:

```text
  SCAN COMPLETED
  exit code: 0
  findings: 1
  severities: INFO=1
```

**Say:** "Notice what is *not* here: no aggressive Nmap flags, no Nikto
destructive plugin groups, no Nuclei exploitation or fuzzing templates. The
refusals are in code, not just in configuration."

Prove it. Nikto's plugin group `6` is a denial-of-service group; the runner
refuses it by name:

```powershell
python -m bcssl run nikto --tuning 126
```

**Expected:**

```text
  error: Could not build a safe command: refusing nikto tuning '126':
  this lab does not run destructive or active-exploitation plugin groups -
  6 (denial of service)
```

Two more worth showing:

```powershell
python -m bcssl run custom-scanner --modules exploit
```

```text
  error: Could not build a safe command: unknown custom scanner module(s):
  exploit. Available: headers, paths, injection
```

```powershell
python -m bcssl web --host 0.0.0.0
```

```text
  The web dashboard binds to loopback only. Start Docker Desktop to reach it
  from another machine, or use an SSH tunnel.
```

All three abort **before** anything runs.

---

## 8. Show findings

Dashboard **Findings** page, filterable by severity, tool and verification
status. Or:

```powershell
python -m bcssl status
```

**Say:** "Every tool's output is reduced to the same eleven-field schema:
tool, category, severity, title, description, target, endpoint, evidence,
recommendation, timestamp and verification status. Severity is folded in
conservatively from five different native scales, and ZAP can never produce
CRITICAL because ZAP has no such level."

Point at the verification-status badge on a finding and explain the vocabulary:
`DETECTED`, `CORROBORATED`, `SINGLE-TOOL OBSERVATION`, `NOT VERIFIED`.

**Say clearly:** "A finding is an indicator that requires verification. The lab
never calls something a vulnerability because a scanner printed a line."

---

## 9. Show correlation

```powershell
python -m bcssl report --correlation-view
```

Or the dashboard **Correlation** page, which shows the reasoning for each group.

**Expected** from a real run:

```text
---------------------- CORRELATION VIEW ----------------------
  [CONFIRMED] MEDIUM   Content-Security-Policy header is missing
              tools: custom-scanner, zap
              endpoints: http://localhost:3001
  [CONFIRMED] MEDIUM   Discovered accessible resource: /robots.txt
              tools: custom-scanner, nikto
              endpoints: http://localhost:3001
  [SINGLE]    MEDIUM   Strict-Transport-Security header is missing
              tools: custom-scanner
```

**Say:** "Corroboration is fingerprint-based, never string similarity. The two
confirmed groups were reported by two genuinely different tools. Where only one
tool spoke, the lab says single-tool observation rather than inflating it to a
finding."

---

## 10. Show evidence with hashes

Dashboard **Evidence** page, or:

```powershell
python -m bcssl collect
```

This re-hashes every referenced raw artifact:

```text
Integrity check: 139 of 139 raw artifact(s) match their recorded sha256.
```

Then prove no run overwrites another:

```powershell
python -m bcssl runs --verify
```

**Expected:**

```text
  run-001  completed                  tools=5  findings=139
      ok    nmap                findings=1
      ok    zap                 findings=11
      ok    nikto               findings=104
      ok    nuclei              findings=19
      ok    custom-scanner      findings=4
      report: reports/final/run-001.html
      evidence: 139/139 intact
```

**Say:** "Every assessment gets a unique identifier: run-001, run-002. Raw
output, normalized findings, evidence, reports and metadata are all isolated per
run, so nothing is ever overwritten. Each evidence record names the verbatim
artifact it came from and its SHA-256, so a reviewer can prove a finding was
derived from stored output rather than typed by hand."

---

## 11. Show the final report

```powershell
python -m bcssl report --format html,json,md,sarif --correlation-view --open
```

**Expected:**

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

The HTML report opens in a browser and is self-contained: no external
stylesheet, font or script, so it can be archived as evidence and opened
offline.

Walk through the sections in this order:

1. Authorization banner and scope statement
2. Executive summary with severity totals
3. Tools that produced no results, with the reason
4. Tool-by-tool results: status, version, exit code, duration
5. Cross-tool correlation with contributing tools
6. Verification status breakdown with definitions
7. Detailed findings with evidence and recommendations
8. Recommendations, deduplicated
9. Evidence references with hashes and the integrity line
10. Scan metadata
11. Limitations
12. Errors and warnings

**Say, on the last two sections:** "The report always states what it could not
do. A lab that hides its gaps teaches the wrong lesson."

Point out the SARIF file too:

```powershell
python -c "import json;d=json.load(open('reports/final/run-001.sarif',encoding='utf-8'));print('SARIF',d['version'],'-',sum(len(r['results']) for r in d['runs']),'results across',len(d['runs']),'tools')"
```

---

## 12. Show the student exercises

```powershell
python -m bcssl lab list
python -m bcssl lab show ex01
```

Or the dashboard **Exercises** page.

**Say:** "Twelve exercises, four per level. Each has an objective, a real safe
command, an expected observation, a practical task, an evidence requirement,
three graded questions, a safety note and a completion checklist."

Then make the grading point:

```powershell
python -m bcssl lab ack ex01
```

**Say:** "Answer keys are never sent to the client. The CLI and the dashboard
strip every grading field before returning a question. And completion requires
the checklist, correctly answered questions *and* recorded evidence - running a
tool never advances progress."

Show progress:

```powershell
python -m bcssl lab progress
```

---

## 13. Shut down cleanly

```powershell
powershell -ExecutionPolicy Bypass -File scripts\stop-lab.ps1
```

**Expected:**

```text
  stopping dashboard PID 12345
Stopping the authorized lab target...
[ OK ] Target stopped. http://localhost:3001 is no longer served.
[ OK ] Lab stopped.
```

Optional, to reset for the next cohort:

```powershell
python -m bcssl clean --yes
```

---

## Questions you will be asked

**"Is this really only localhost?"**
`python -m bcssl validate-target --url https://example.com --no-probe` is
refused, and the same validator gates every tool. The target container is
published on `127.0.0.1` only, and preflight warns if that ever changes.

**"What happens if a tool isn't installed?"**
Preflight shows `[MISS]` with exact install instructions. The run reports
`TOOL NOT INSTALLED` and contributes zero findings. It is never simulated.

**"How do you know a finding is real?"**
Each finding carries a verification status. `DETECTED` means the lab
reproduced the condition itself with its own HTTP check; `CORROBORATED` means
two different tools reported the same fingerprint; anything else is labelled
honestly as a single-tool observation or unverified.

**"Does it exploit anything?"**
No. No fuzzing, no denial of service, no credential testing, no exploitation
templates, no uploads, no data extraction. The refusals are enforced in the
runners, and the excluded template families are documented in
`tools/nuclei/README.md`.

**"Can I show it on another machine?"**
Yes. Clone or copy the folder, run `scripts\setup.ps1`, then
`scripts\start-target.ps1`. The release package is self-contained and its test
suite was verified from a clean extracted copy.