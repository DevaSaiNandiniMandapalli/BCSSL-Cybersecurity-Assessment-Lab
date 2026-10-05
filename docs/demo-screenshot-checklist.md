# Demo screenshot checklist

Fifteen screenshots for a presentation. **Capture every one from a real run of
this project.** Do not edit output, stage a sample, or reuse a screenshot from a
different machine — a screenshot that does not match the live system is worse
than no screenshot.

## Before capturing

```powershell
cd C:\Users\devas\Documents\Cybersecurity\BCSSL-Cybersecurity-Assessment-Lab
$env:PYTHONPATH = (Get-Location).Path
powershell -ExecutionPolicy Bypass -File scripts\start-target.ps1
```

Take screenshots on a **clean run** so every figure matches. Then:

```powershell
python -m bcssl clean --yes
powershell -ExecutionPolicy Bypass -File scripts\run-all.ps1
powershell -ExecutionPolicy Bypass -File scripts\preflight.ps1
python -m bcssl report --format html,json,md,sarif --correlation-view
python -m bcssl runs --verify
```

Use a terminal with a readable font size. Suggested filenames are given; keep
them so the slide order is obvious.

| # | Filename | What to capture | Command |
| --- | --- | --- | --- |
| 01 | `01-project-folder.png` | Project root in the file explorer or `Get-ChildItem` | `Get-ChildItem -Name` |
| 02 | `02-target-running.png` | Juice Shop in a browser at `http://localhost:3001` | browse to the target |
| 03 | `03-preflight.png` | The full preflight table, all rows visible | `python -m bcssl preflight` |
| 04 | `04-nmap.png` | Nmap `SCAN COMPLETED`, exit code, finding count | `python -m bcssl run nmap` |
| 05 | `05-zap.png` | ZAP result — include the **exit code 2** line | `python -m bcssl run zap` |
| 06 | `06-nikto.png` | Nikto result with 104 findings | `python -m bcssl run nikto` |
| 07 | `07-nuclei.png` | Nuclei result with 19 findings | `python -m bcssl run nuclei` |
| 08 | `08-custom-scanner.png` | Custom scanner result with 4 findings | `python -m bcssl run custom-scanner` |
| 09 | `09-normalized-findings.png` | The normalized JSON artifact | `Get-Content reports\normalized\run-001\findings-run-001-zap.json -TotalCount 24` |
| 10 | `10-correlation.png` | Correlation view showing both `[CONFIRMED]` groups | `python -m bcssl report --correlation-view` |
| 11 | `11-evidence-sha256.png` | `runs --verify` output showing the intact count | `python -m bcssl runs --verify` |
| 12 | `12-final-report.png` | The HTML report — executive summary or verification breakdown | `python -m bcssl report --format html --open` |
| 13 | `13-dashboard.png` | Dashboard with real findings, plus Correlation page | `python -m bcssl web --port 8765` |
| 14 | `14-exercises.png` | Exercises page with progress state | `python -m bcssl lab list` or the dashboard |
| 15 | `15-release-package.png` | The release folder contents | `Get-ChildItem ..\BCSSL-Cybersecurity-Assessment-Lab-RELEASE -Name` |

## Details that matter

**02 — target running.** The address bar must show `localhost:3001`. Capture the
Juice Shop welcome page so it is obvious this is the training app.

**03 — preflight.** All thirteen rows must be visible. This is the slide that
proves the environment is genuinely probed rather than assumed. If any row shows
`NOT INSTALLED` or `NOT RUNNING`, either fix it or the screenshot is
misleading.

**05 — ZAP.** Include the `exit code: 2` line. It is the most interesting detail
in the whole demonstration: a successful scan that returns a non-zero exit code,
which a naive wrapper would have discarded as a failure.

**09 — normalized findings.** The eleven keys must all be visible. This is the
slide that shows five incompatible formats reduced to one schema.

**10 — correlation.** Both `[CONFIRMED]` lines must be visible:

```text
[CONFIRMED] MEDIUM   Content-Security-Policy header is missing
            tools: custom-scanner, zap
[CONFIRMED] INFO     Discovered accessible resource: /robots.txt
            tools: custom-scanner, nikto
```

Also capture a `[SINGLE]` line so the contrast is visible.

**11 — evidence.** The `evidence: 124/124 intact` line is the point. Do not
screenshot a redacted version.

**12 — report.** Prefer the executive summary and the verification-status
breakdown over the detailed findings list; they read better at slide size.

**13 — dashboard.** Capture at least two pages — Dashboard for the totals,
Correlation for the reasoning text. Show real finding counts, not zero.

**14 — exercises.** Show a checklist with some items unticked so it is obvious
that running a scanner does not complete an exercise.

**15 — release package.** Include `README.md`, `docs/`, `lab/`, `scripts/` and
`bcssl/` in the listing.

## Optional supporting captures

| Filename | Command |
| --- | --- |
| `16-target-refused.png` | `python -m bcssl validate-target --url https://example.com --no-probe` |
| `17-safety-refusal.png` | `python -m bcssl run nikto --tuning 126` |
| `18-empty-state.png` | `python -m bcssl clean --yes` then `python -m bcssl report` |
| `19-sarif.png` | `python -c "import json;d=json.load(open('reports/final/run-001.sarif',encoding='utf-8'));print(d['version'],sum(len(r['results']) for r in d['runs']))"` |
| `20-retention.png` | `python -m bcssl runs --retention` |

Screenshots 16-19 are strong viva material: they show refusal behaviour and an
honest empty state, which is where this project differs from a plain scanner
wrapper.

## Rules

- Every screenshot must come from the run you actually performed.
- Do not crop out an error, a warning or a `NOT RUNNING` row.
- Do not retype output into a mock terminal window.
- Do not fabricate a finding count. If a tool failed, show the failure.
- Match every number to `python -m bcssl runs --verify` and
  `python -m bcssl report --correlation-view` on the day you present.