# Exercise 12 — Final Security Assessment and Report

## Objective

Execute the full authorized toolset in one reproducible pass and produce a defensible written security assessment of `http://localhost:3001` that traces every claim back to a saved evidence artifact.

## Authorized Target

```
http://localhost:3001
```

## Prerequisites

- Exercises 01 through 11 completed, with evidence saved in `evidence/lab-cli/`, `evidence/nmap/`, `evidence/custom-scanner/`, `evidence/nikto/`, `evidence/zap/` and `evidence/nuclei/`.
- ZAP, nikto, nuclei, nmap and the external custom-scanner (Project #08) are all installed and individually verified.
- OWASP Juice Shop is running on `http://localhost:3001` and you have created the folder `evidence/report/`.
- You have read the four severity vocabularies used in this lab:

| Tool | Severity vocabulary |
|------|---------------------|
| ZAP | 0 Informational, 1 Low, 2 Medium, 3 High — **no critical** |
| nikto | item id + HTTP response code (no severity scale) |
| nuclei | `info.severity` from the template |
| custom-scanner | info / low / medium / high / critical |

## Tool Used

All tools, orchestrated by the lab CLI in their pinned safe profiles:

- **nmap** — TCP connect scan, service detection, port 3001 only
- **zap** — baseline mode (passive + low-impact active)
- **nikto** — tuning `1237bd`, intrusive categories excluded
- **custom-scanner** — Project #08, invoked externally, unmodified
- **nuclei** — destructive tag families excluded, rate limited, JSONL output

## Exact Command

```bash
python -m bcssl run-all
```

## Expected Observation

The lab runs the complete configured toolset in sequence against `http://localhost:3001`, then regenerates the consolidated correlation report. The console shows one clearly labelled block per tool followed by the correlation summary, and raw artifacts land under `reports/raw/`.

Expect a longer run than any single exercise, and a consolidated view in which some themes are labelled **"Confirmed by multiple tools"** and others **"Single-tool observation"**.

The exact set of findings depends on the tools' versions and templates and on the Juice Shop build, so record what you actually observed. Do not state a finding count you cannot cite, and do not edit any report.

## Student Task

1. Run the exact command above from the lab project root and allow every tool to finish; note the start and end time of the pass in your report.
2. Copy every raw artifact the run produced from `reports/raw/` into the correct `evidence/<tool>/` folder with an `ex12-` prefix, without editing them.
3. Write `evidence/report/ex12-final-report.md` containing:
   - scope and authorization statement
   - methodology and the exact commands run
   - tool inventory with versions
   - consolidated findings grouped by root cause, each with severity shown in the originating tool's own vocabulary
   - the confidence label for each finding
   - remediation advice you wrote yourself
   - residual risk and limitations
   - a numbered evidence index listing every `evidence/` file you referenced
4. Add an executive summary of at most ten lines that a non-technical reader could understand.
5. Re-open each raw artifact once to confirm the finding you wrote about it is genuinely in that file, and mark any claim you could not verify as "unverified" rather than deleting it silently.

## Evidence Requirement

- Unmodified `ex12-` copies of every raw artifact from the full run, filed under `evidence/nmap/`, `evidence/zap/`, `evidence/nikto/`, `evidence/nuclei/` and `evidence/custom-scanner/`.
- File `evidence/report/ex12-final-report.md` containing all eight required sections plus the executive summary.
- A numbered evidence index inside that report mapping each finding to at least one `evidence/` filename.
- An explicit limitations section naming the tools or checks that were out of scope, including any tool that returned no findings.

## Questions

**q1. How do you justify a severity rating in the final report when four tools use four different severity vocabularies?**

> Explain that you report each tool's native label as evidence, group findings by root cause so one weakness is not counted four times, and then justify any overall severity with an impact argument in your own words. State explicitly that no CVSS vector was calculated, so no numeric score is implied.

**q2. What belongs in the limitations section of an assessment report, and why is it the section most often missing?**

> List concrete items: tools that returned nothing, templates or tuning categories that were deliberately excluded (the destructive nuclei tags, the excluded nikto tuning letters), the fact that no authentication was used, no fuzzing or injection exploitation was performed, no denial-of-service testing, and that only loopback port 3001 was assessed. Explain that omitting limitations makes the report overstate its own certainty.

**q3. How would you defend this report's evidence chain if a reviewer asked you to prove a specific finding?**

> Walk the chain: finding in the final report, numbered evidence index entry, the `evidence/` file, the raw artifact under `reports/raw/`, and the exact command plus timestamp that produced it. Explain that an untraceable claim must be labelled unverified, and that hand-edited or fabricated artifacts break the chain permanently.

## Safety Note

Authorized local-only use against `http://localhost:3001`. This run-all pass is the widest activity in the lab and still stays inside the safe profiles the lab pins: ZAP baseline only, nikto under the reduced tuning profile, nuclei with destructive tag families excluded and rate limited, nmap limited to a connect scan on port 3001, and the external custom-scanner used as-is. Never broaden any of those constraints, never add a target, and never point any tool at a public website, external domain, or arbitrary IP address. Reporting is documentation work: do not use the findings to exploit the application, access data, attempt credential attacks, establish persistence, escalate privileges, or degrade service availability.

## Completion Checklist

- [ ] **c1** — I ran `python -m bcssl run-all` from the lab project root, let every tool finish, and recorded the start and end time of the pass.
- [ ] **c2** — I filed unmodified `ex12-` copies of every raw artifact into `evidence/nmap/`, `evidence/zap/`, `evidence/nikto/`, `evidence/nuclei/` and `evidence/custom-scanner/`.
- [ ] **c3** — I wrote `evidence/report/ex12-final-report.md` with scope, methodology, tool inventory, root-cause-grouped findings in native tool vocabularies, confidence labels, my own remediation advice, residual risk, limitations and a numbered evidence index.
- [ ] **c4** — I added the ten-line executive summary, re-verified each finding against its raw artifact, marked anything unverifiable as "unverified", and answered q1, q2 and q3.

> Progress in this lab is never auto-completed by running a tool. An exercise is done only when you have saved the evidence, answered the questions, and ticked the checklist.