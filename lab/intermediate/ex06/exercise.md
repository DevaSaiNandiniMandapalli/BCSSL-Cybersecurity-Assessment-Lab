# Exercise 06 — Nikto Web Server Assessment

## Objective

Run the lab's standard nikto profile (`-Tuning 1237bd`), learn which intrusive test categories have been deliberately removed, and convert raw nikto output into a defensible finding list.

## Authorized Target

```
http://localhost:3001
```

## Prerequisites

- Exercise 04 completed and its tuned nikto evidence saved to `evidence/nikto/`.
- Nikto is installed and on your PATH, and you already recorded its version.
- OWASP Juice Shop is running on `http://localhost:3001`.
- You have created the folder `evidence/nikto/` for this exercise's outputs.

## Tool Used

`nikto` — web server scanner, run under the lab's standard profile.

The effective command the lab builds:

```
nikto -h http://localhost:3001 -Tuning 1237bd -Format json -output <out>.json -nointeractive
```

### Tuning letters: enabled vs deliberately excluded

| Letter | Category | In this lab? |
|--------|----------|--------------|
| `1` | interesting files / sites | enabled |
| `2` | misconfiguration / information disclosure | enabled |
| `3` | information disclosure | enabled |
| `7` | server info retrieval | enabled |
| `b` | software identification | enabled |
| `d` | XSS-oriented checks | enabled |
| `0` | file upload | **excluded** |
| `4` | injection | **excluded** |
| `5` | remote file retrieval | **excluded** |
| `6` | denial of service | **excluded** |
| `8` | remote command execution | **excluded** |
| `9` | SQL / code injection | **excluded** |
| `a` | authentication bypass | **excluded** |
| `c` | remote source inclusion | **excluded** |

## Exact Command

```bash
python -m bcssl run nikto
```

## Expected Observation

The output should report the target, the server header, items found with their HTTP codes, and a count of items tested. You should typically see disclosure or misconfiguration items against Juice Shop.

You should also be able to prove, from the echoed command line, that the intrusive categories are absent from the tuning string: `0` file upload, `4` injection, `5` remote file retrieval, `6` denial of service, `8` command execution, `9` SQL injection, `a` authentication bypass, and `c` remote source inclusion are all missing.

Treat the specific item list as an observation to record rather than an expected answer.

## Student Task

1. Run the exact command above from the lab project root.
2. Copy the exact nikto invocation that the lab printed, highlight the `-Tuning` value, and mark which of the letters `a`, `4`, `5`, `6`, `8`, `9` and `c` are missing.
3. Read the JSON output under `reports/raw/` and list every finding that returned a `200` response code, with the item identifier, the path or URL, and a plain-English description.
4. For each `200` item, decide and record whether it is a genuine unauthenticated information disclosure, a benign known file, or a false positive, and justify the decision in one line.
5. Save the unmodified JSON to `evidence/nikto/ex06-nikto-report.json` and your classified findings table to `evidence/nikto/ex06-nikto-findings.md`.

## Evidence Requirement

- File `evidence/nikto/ex06-nikto-report.json` containing the unmodified JSON output of this nikto run.
- File `evidence/nikto/ex06-nikto-findings.md` containing your findings table: item id, path or URL, HTTP code, classification, and one-line justification.
- A pasted copy of the exact nikto command line, with an annotated note listing which tuning letters were deliberately excluded and why.
- These filenames must be referenced in the evidence index of your final report (Exercise 12).

## Questions

**q1. Which test categories does the tuning value 1237bd enable, and what is the practical effect of that choice on request volume and impact?**

> Enumerate `1` interesting files and sites, `2` misconfiguration and information disclosure, `3` information disclosure, `7` server and software information retrieval, `b` software identification, and the XSS-oriented entry. Explain that this keeps the assessment read-mostly and moderate in volume compared with a default run.

**q2. Why does this lab exclude tuning letters 4 (injection), 9 (SQL injection), 6 (denial of service), 8 (command execution), 5 (remote file retrieval), 0 (file upload), a (authentication bypass) and c (remote source inclusion)?**

> Explain that these categories move from observation into active attack behaviour: injection and command execution attempts are exploitation, remote file retrieval and file upload can change server state, and denial of service deliberately degrades the target. Excluding them keeps the engagement non-destructive, keeps evidence interpretable for a learning context, and respects the authorized-testing rules of the lab.

**q3. How do you decide whether a nikto item with HTTP 200 is a real information-disclosure finding or noise?**

> Walk through the decision: does the path expose something not intended for public access, does it contain version or configuration detail that narrows an attacker's options, is it a generic well-known file that adds nothing, and would the same item appear on any site of this product. Record the classification and the reason, and treat "benign known file" as a legitimate conclusion rather than a failure.

## Safety Note

Authorized local-only use against `http://localhost:3001`. The tuning profile used here excludes intrusive categories on purpose; do not add tuning letters back, do not switch nikto out of `-nointeractive` batch mode into interactive probing, and never retarget it at any host you do not own. Do not follow a discovery lead into exploitation, upload, injection, credential testing, or denial-of-service testing, and do not point nikto at a public website, external domain, or arbitrary IP address.

## Completion Checklist

- [ ] **c1** — I ran `python -m bcssl run nikto` from the lab project root and kept the lab's console output.
- [ ] **c2** — I pasted the exact nikto command line into my notes and annotated which tuning letters (`a`, `4`, `5`, `6`, `8`, `9`, `c`) were excluded and why.
- [ ] **c3** — I saved the unmodified JSON to `evidence/nikto/ex06-nikto-report.json` and my classified findings table to `evidence/nikto/ex06-nikto-findings.md`.
- [ ] **c4** — I classified every `200` item as disclosure, benign or false positive with a written reason, and answered q1, q2 and q3.

> Progress in this lab is never auto-completed by running a tool. An exercise is done only when you have saved the evidence, answered the questions, and ticked the checklist.