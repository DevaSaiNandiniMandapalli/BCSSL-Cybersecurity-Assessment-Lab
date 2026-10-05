# Exercise 11 — Finding Correlation

## Objective

Use the lab's correlation engine to combine every saved raw result into one deduplicated, confidence-annotated view, and learn why confirmed and single-tool observations must be presented differently.

## Authorized Target

```
http://localhost:3001
```

## Prerequisites

- Exercises 02 through 10 completed, with each tool's raw output saved under `reports/raw/` and copied into the matching `evidence/` subdirectory.
- At least two tools have produced results, otherwise the correlation view has nothing to compare and the exercise teaches nothing.
- You have created the folder `evidence/report/` for correlation notes.
- OWASP Juice Shop is running on `http://localhost:3001`.

## Tool Used

The lab's correlation engine, invoked through `python -m bcssl report`. It reads the raw artifacts already collected and normalizes them into common themes:

| Input artifact | Source tool |
|-----------------|-------------|
| `*.xml` under `reports/raw/` | nmap |
| ZAP HTML + JSON | zap |
| nikto JSON | nikto |
| custom-scanner HTML | custom-scanner |
| nuclei JSONL | nuclei |

Each output theme is labelled by how many tools saw it: **"Confirmed by multiple tools"** (2 or more) or **"Single-tool observation"** (exactly 1).

## Exact Command

```bash
python -m bcssl report
```

## Expected Observation

The lab reads the raw artifacts under `reports/raw/`, normalizes each finding into a common theme, deduplicates near-identical entries, and prints a consolidated correlation view plus a consolidated report artifact.

You should typically see missing security headers as a multi-tool theme, and some single-tool themes depending on which runs actually produced results. If a tool produced no results, that is reported as a **gap**, not as a clean bill of health. The engine never fabricates findings to fill the view.

## Student Task

1. Run the exact command above from the lab project root and capture the full console output.
2. Save the console output unmodified to `evidence/report/ex11-correlation-view.txt`.
3. Build a table in `evidence/report/ex11-correlation-table.md` listing every theme the engine produced, with columns for:
   - theme
   - tools that reported it
   - the label the engine assigned (`Confirmed by multiple tools` / `Single-tool observation`)
   - the source artifact filename for each contributing tool
4. Write a short interpretation paragraph explaining which theme you consider the strongest in the whole assessment and why, quoting at least two independent tool artifacts.
5. Note any tool that contributed zero findings and state plainly what a gap means for the confidence of the report.

## Evidence Requirement

- File `evidence/report/ex11-correlation-view.txt` containing the unmodified correlation console output.
- File `evidence/report/ex11-correlation-table.md` containing your theme table with the engine's own labels and per-tool source artifact filenames.
- A written interpretation naming your strongest theme with citations to at least two independent tool artifacts.
- A statement naming any tool with zero findings and what that gap implies for confidence.
- These filenames must be referenced in the evidence index of your final report (Exercise 12).

## Questions

**q1. What does the engine mean by "Confirmed by multiple tools", and why is that different from "found by one tool"?**

> Explain that the label reflects independent corroboration: at least two tools, with different rule catalogs and request patterns, reached the same conclusion. Explain that single-tool observations are still worth reporting but carry a higher chance of being a tool-specific artefact or a false positive, and therefore need different wording and usually a second look.

**q2. Why does deduplication matter, and what mistakes can normalization introduce?**

> Explain that without deduplication, one weakness seen by three tools looks like three weaknesses and inflates counts and perceived risk. Then explain the failure modes of normalization: mapping two different severity vocabularies onto one label, merging findings that only look similar, or dropping a distinct instance because its path differs. Normalization is an editorial decision and must be documented.

**q3. A theme appears in the correlation view but one contributing tool shows no evidence file. How should you handle that in the report?**

> Explain that the correlation view is derived from raw artifacts, so a missing artifact means the claim is not traceable and the finding must be downgraded to unconfirmed or excluded until the artifact is produced. Describe checking `reports/raw/` for the file, re-running that single tool through the lab if needed, and never fabricating or hand-writing a missing evidence file to make the view look complete.

## Safety Note

Authorized local-only use against `http://localhost:3001`. The correlation step is an offline analysis of results already collected from the authorized local target; it issues no new attack traffic and must not be turned into a re-scan against anything. Never add or hand-craft raw result files to make the correlation view look more complete, never point the report or any tool at an external host, public domain, or arbitrary IP address, and never use correlated findings to drive exploitation, credential testing, data extraction, or denial-of-service activity.

## Completion Checklist

- [ ] **c1** — I ran `python -m bcssl report` from the lab project root after completing at least two prior tool exercises.
- [ ] **c2** — I saved the unmodified correlation console output to `evidence/report/ex11-correlation-view.txt`.
- [ ] **c3** — I built the theme table at `evidence/report/ex11-correlation-table.md` using the engine's own labels and citing the source artifact filename for every contributing tool.
- [ ] **c4** — I wrote my strongest-theme interpretation with at least two independent citations, named any zero-finding tool and its effect on confidence, and answered q1, q2 and q3.

> Progress in this lab is never auto-completed by running a tool. An exercise is done only when you have saved the evidence, answered the questions, and ticked the checklist.