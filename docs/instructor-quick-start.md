# Instructor quick start

The minimum commands to run a session. Nothing else is required.

```text
AUTHORIZED TARGET
http://localhost:3001
```

---

## 1. One-time setup per machine

```powershell
cd C:\Users\devas\Documents\Cybersecurity\BCSSL-Cybersecurity-Assessment-Lab
powershell -ExecutionPolicy Bypass -File scripts\setup.ps1
```

Installs no software. Pulls the five container images and builds the Nuclei
template profile.

Requirements: Python 3.10+ and Docker Desktop. The lab itself uses only the
Python standard library.

---

## 2. Start the lab

```powershell
powershell -ExecutionPolicy Bypass -File scripts\start-lab.ps1
```

That starts the target and the dashboard. To do it in two separate terminals
instead:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\start-target.ps1
```

```powershell
python -m bcssl web --port 8765
```

Dashboard: <http://127.0.0.1:8765>

> If you use these commands directly, set `$env:PYTHONPATH` to the project
> folder first. The PowerShell scripts do it for you.

---

## 3. Check the target

```powershell
powershell -ExecutionPolicy Bypass -File scripts\check-target.ps1
```

```powershell
python -m bcssl validate-target
```

Both must succeed before a scan:

```text
[ OK ] Target is authorized and reachable.
```

```text
TARGET REACHABLE (HTTP 200)
```

---

## 4. Run preflight

```powershell
powershell -ExecutionPolicy Bypass -File scripts\preflight.ps1
```

Exit code 0 means the lab is ready. Exit code 1 means a required component -
Python, Docker, or the target - is unavailable, and the table names the remedy
for each problem.

---

## 5. Run all tools

```powershell
powershell -ExecutionPolicy Bypass -File scripts\run-all.ps1
```

Or, for a subset:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\run-all.ps1 -Tools nmap,nikto
```

Takes roughly 6-8 minutes on a prepared machine. A tool that fails is recorded
as failed; the run continues and the report states which tools succeeded.

To run one tool while teaching:

```powershell
python -m bcssl run zap
```

Show the safety refusals - all three abort before anything executes:

```powershell
python -m bcssl run nikto --tuning 126
python -m bcssl run custom-scanner --modules exploit
python -m bcssl web --host 0.0.0.0
```

---

## 6. Generate reports

```powershell
python -m bcssl report --format html,json,md,sarif --correlation-view
```

Files appear in `reports/final/`, named after the assessment:

```text
run-001.html
run-001.json
run-001.md
run-001.sarif
```

Open the HTML report:

```powershell
python -m bcssl report --format html --open
```

---

## 7. Stop the lab

```powershell
powershell -ExecutionPolicy Bypass -File scripts\stop-lab.ps1
```

Optional reset for the next cohort - removes scan artifacts, evidence and
student progress:

```powershell
python -m bcssl clean --yes
```

Keep evidence or progress if you need it:

```powershell
python -m bcssl clean --yes --keep-evidence --keep-progress
```

---

## One-line version

```powershell
powershell -ExecutionPolicy Bypass -File scripts\setup.ps1
powershell -ExecutionPolicy Bypass -File scripts\start-lab.ps1
powershell -ExecutionPolicy Bypass -File scripts\check-target.ps1
powershell -ExecutionPolicy Bypass -File scripts\preflight.ps1
powershell -ExecutionPolicy Bypass -File scripts\run-all.ps1
powershell -ExecutionPolicy Bypass -File scripts\stop-lab.ps1
```

---

## Session checklist

| Check | Command | Pass condition |
| --- | --- | --- |
| Docker engine up | `docker info --format '{{.ServerVersion}}'` | prints a version |
| Target running | `scripts\check-target.ps1` | `[ OK ]` |
| Target reachable | `python -m bcssl validate-target` | `TARGET REACHABLE (HTTP 200)` |
| Tools available | `scripts\preflight.ps1` | `5/5 assessment tools usable` |
| Assessment run | `scripts\run-all.ps1` | five `SCAN COMPLETED` lines |
| Corroboration exists | `python -m bcssl report --correlation-view` | at least one `[CONFIRMED]` group |
| Evidence intact | `python -m bcssl collect` | all artifacts match their SHA-256 |
| Runs isolated | `python -m bcssl runs --verify` | each run lists its own outputs |
| SARIF written | `python -c "import json;d=json.load(open('reports/final/run-001.sarif',encoding='utf-8'));print(d['version'])"` | `2.1.0` |

---

## Adjusting the session

**Shorter session (one tool).** Run only Nmap, then walk the exercises that
concern discovery. `python -m bcssl run nmap` takes under a minute.

**Longer session (add analysis).** After the assessment:

```powershell
python -m bcssl verify
```

Re-checks the conditions the tools reported against the live target and shows
which findings the lab could reproduce itself.

**Difficult cohort.** Disable a tool so students see the unavailable-tool path:

```json
"tools": { "nikto": { "enabled": false } }
```

Preflight then reports `UNAVAILABLE` with the instruction to re-enable it, and
the run contributes zero Nikto findings. Restore it after the session.

**Reset between cohorts.** `python -m bcssl clean --yes` leaves the lab with no
scan results; the dashboard then reads "No scan results available."

---

## Related documents

| Document | Use it for |
| --- | --- |
| `docs/installation.md` | Full setup, including native tool installs |
| `docs/demo-guide.md` | A scripted 10-15 minute demonstration |
| `docs/presentation-guide.md` | Three-slide faculty presentation |
| `docs/instructor-guide.md` | Grading, configuration, extending exercises |
| `docs/tool-guide.md` | Per-tool reference and safety restrictions |
| `docs/limitations.md` | What the lab does not do, and why |
| `docs/troubleshooting.md` | Symptom, cause, fix |
| `RELEASE-CHECKLIST.md` | Pre-handover verification list |