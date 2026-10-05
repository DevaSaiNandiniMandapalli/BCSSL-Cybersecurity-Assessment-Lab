# Exercise 10 — Custom Scanner Comparison

## Objective

Run the full external custom-scanner with all of its modules enabled and position its output against the other tools already used, so you can defend where a home-grown scanner adds value and where it does not.

## Authorized Target

```
http://localhost:3001
```

## Prerequisites

- Exercises 03, 05, 06, 07, 08 and 09 completed, with all four tools' raw reports saved under `evidence/`.
- The standalone custom-scanner project (Project #08 Web Security Scanner) is installed and callable as an external subprocess. **This lab does not modify or rewrite it.**
- You have read the scanner's own severity vocabulary: `info`, `low`, `medium`, `high`, `critical`.
- OWASP Juice Shop is running on `http://localhost:3001` and you have created the folder `evidence/custom-scanner/`.

## Tool Used

`custom-scanner` (Project #08) — invoked externally as a subprocess by the lab, with its full default module set: `headers`, `paths`, `injection`. Output is an HTML report that the lab parses.

| Tool | Severity vocabulary used in this lab |
|------|---------------------------------------|
| custom-scanner | info / low / medium / high / critical |
| ZAP | 0 Informational, 1 Low, 2 Medium, 3 High (**no critical**) |
| nikto | item id + HTTP response code (no severity scale) |
| nuclei | info.severity from the template (info … critical) |

## Exact Command

```bash
python -m bcssl run custom-scanner
```

## Expected Observation

With no `--modules` flag, the lab runs the external scanner with its full default module set, which includes `headers`, `paths` and `injection`, and the lab parses the resulting HTML report into `reports/raw/`. The console should show the subprocess being launched, the report path, and a consolidated summary.

Against Juice Shop you should typically see header findings, discovered paths, and injection-module output; the injection module issues probes, so record its results as **tool-reported indicators only**.

Use the scanner's own severity vocabulary (`info`/`low`/`medium`/`high`/`critical`) and do not translate it into ZAP's 0-3 scale or a CVSS score without saying that you did. Never assume the finding count, and never edit the HTML report.

## Student Task

1. Run the exact command above from the lab project root and keep the complete console log.
2. Save the scanner's unmodified HTML report to `evidence/custom-scanner/ex10-full-report.html`.
3. From the report, list the findings grouped by module (`headers`, `paths`, `injection`), with each finding's scanner-assigned severity and, where present, the request or URL it refers to.
4. Build a coverage comparison in `evidence/custom-scanner/ex10-coverage-notes.md` with columns for finding theme, custom-scanner, ZAP, nikto, nuclei — using the saved evidence from exercises 05 to 09 — and mark which themes only the custom-scanner surfaced.
5. Write one short paragraph on the single biggest limitation of the custom-scanner compared with the other three tools, backed by something you actually observed in the output.

## Evidence Requirement

- File `evidence/custom-scanner/ex10-full-report.html` containing the unmodified HTML report from the full-module run.
- File `evidence/custom-scanner/ex10-coverage-notes.md` containing your module-grouped findings list and your four-tool coverage comparison.
- A written statement identifying at least one theme that only the custom-scanner surfaced, plus one concrete limitation you observed.
- These filenames must be referenced in the evidence index of your final report (Exercise 12).

## Questions

**q1. What does the custom-scanner's full run add on top of the headers-only and paths-only runs you did earlier?**

> Compare the modules actually executed and the resulting sections of the report. Explain that module composition changes request volume and the breadth of coverage, and that running all modules together makes it harder to attribute a finding to a specific check, which is one argument for module-scoped runs in an assessment.

**q2. Where does the custom-scanner outperform or underperform ZAP, nikto and nuclei on this target, based on your evidence?**

> Use your coverage notes. Reasonable observations: a purpose-built scanner can produce cleaner, more opinionated header findings or try its own wordlist that crawler-driven tools miss, while typically lacking the maintained template library of nuclei, the per-product test catalog of nikto, and the crawling and rule depth of ZAP. Base every claim on output you actually saw, and say "not observed" rather than inventing a gap.

**q3. Why must severity labels from different tools not be merged into one number without a stated mapping?**

> Explain that the scanner's `info`/`low`/`medium`/`high`/`critical` labels, ZAP's 0-3 Informational-to-High scale, nikto's item output and nuclei template severities are each defined differently and none is a CVSS base score. Converting between them invents precision; the defensible approach is to report each tool's label, group findings by root cause, and justify any overall severity with an impact argument.

## Safety Note

Authorized local-only use against `http://localhost:3001`. The custom-scanner is an existing separate project that must be invoked only through the lab; never edit its source, never extend it with new intrusive checks, and never point it at an external host, public domain, or arbitrary IP address. The `injection` module issues probe payloads against the local vulnerable app by design, so do not point those probes anywhere else, do not chain them into exploitation, and do not use any result to access data, credentials, or functionality beyond what the lab already exposes.

## Completion Checklist

- [ ] **c1** — I ran `python -m bcssl run custom-scanner` from the lab project root with no module restriction and kept the console log.
- [ ] **c2** — I saved the unmodified HTML report to `evidence/custom-scanner/ex10-full-report.html` and grouped its findings by module with the scanner's own severity labels.
- [ ] **c3** — I completed the four-tool coverage comparison in `evidence/custom-scanner/ex10-coverage-notes.md` using evidence from exercises 05 to 09.
- [ ] **c4** — I wrote my own limitation paragraph with a cited observation, explained why severities must not be merged silently, and answered q1, q2 and q3.

> Progress in this lab is never auto-completed by running a tool. An exercise is done only when you have saved the evidence, answered the questions, and ticked the checklist.