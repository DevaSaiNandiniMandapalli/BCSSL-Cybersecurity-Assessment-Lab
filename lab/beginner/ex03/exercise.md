# Exercise 03 — Security Headers and HTTP Analysis

## Objective

Run the pre-existing Project #08 Web Security Scanner from outside the lab with only its `headers` module enabled, and read the resulting HTTP security header findings using the scanner's own severity vocabulary.

## Authorized Target

```
http://localhost:3001
```

## Prerequisites

- Exercise 01 completed and its preflight evidence saved.
- The standalone custom-scanner project (Project #08 Web Security Scanner) is installed and reachable as an external executable or module. The lab invokes it as a subprocess and never modifies or rewrites it.
- OWASP Juice Shop is running on `http://localhost:3001`.
- You have created the folder `evidence/custom-scanner/`.

## Tool Used

`custom-scanner` — an existing, separate Python web security scanner (Project #08) that this lab calls externally. Its modules are `headers`, `paths` and `injection`, and its severity vocabulary is `info`, `low`, `medium`, `high`, `critical`. This exercise enables **only** the `headers` module.

## Exact Command

```bash
python -m bcssl run custom-scanner --modules headers
```

## Expected Observation

The lab calls the external scanner with only the headers module selected, so no path enumeration or injection testing happens. You should see the lab log the subprocess it started, then the scanner's HTML report path, and finally a summary of header-related findings written under `reports/raw/`.

Against Juice Shop you should typically see findings about response headers that are missing or misconfigured, such as a missing `Content-Security-Policy`, missing `X-Content-Type-Options`, missing `X-Frame-Options` or an anti-clickjacking header, and cookie attributes such as the absence of `HttpOnly` or `Secure`.

Treat the exact list and counts as observations to record, never as a fixed answer; different versions of the scanner and of Juice Shop will legitimately differ, and a run that reports nothing on a header is a finding in itself that you must report honestly.

## Student Task

1. Run the exact command above from the lab project root.
2. Open the generated HTML report in your browser and locate the section covering HTTP security headers.
3. Write a table in your notes with one row per header finding: header name, what was observed, the severity the scanner assigned (`info`/`low`/`medium`/`high`/`critical`), and a short remediation note in your own words.
4. Save a copy of the scanner's HTML report to `evidence/custom-scanner/ex03-headers-report.html` and save your table as `evidence/custom-scanner/ex03-header-notes.md`.
5. Confirm in your notes that only the `headers` module ran, and note which other modules were deliberately not executed.

## Evidence Requirement

- File `evidence/custom-scanner/ex03-headers-report.html` containing the scanner's HTML report for the headers module run.
- File `evidence/custom-scanner/ex03-header-notes.md` containing your per-header table with the scanner's severity values quoted from the report.
- A statement naming which scanner modules were excluded from this run and why.
- These filenames must be referenced in the evidence index of your final report (Exercise 12).

## Questions

**q1. Which HTTP security headers did the scanner flag, and what is the practical risk of each one being absent or wrong?**

> For each flagged header, describe the browser behaviour it controls: `Content-Security-Policy` limits script and frame sources, `X-Content-Type-Options` stops MIME sniffing, `X-Frame-Options` or a `frame-ancestors` directive stops clickjacking. If a header was present and correct, record that too; a positive confirmation is evidence.

**q2. The scanner grades with info, low, medium, high and critical. How does that vocabulary compare with a CVSS-style severity scale, and what should a report author avoid doing with it?**

> Explain that the scanner's severity is a heuristic label, not a calculated CVSS base score, and that it does not carry exploitability context. The author must avoid inflating a missing-header finding into "critical", and must not treat a low label as proof the issue is harmless.

**q3. Why did the lab run only the headers module instead of the scanner's full default set?**

> Explain module scoping: it keeps the first exercise focused so the student learns to read one class of finding properly, keeps the request volume low against the local app, and avoids running the injection module before the student understands scope and evidence discipline. Name the other available modules (`paths`, `injection`) and when they are used in this lab.

## Safety Note

Authorized local-only use against `http://localhost:3001`. Header analysis is read-only: the lab only issues normal GET requests to the lab application and never modifies, exploits, or extracts data from it. The custom-scanner is an existing separate project and must be invoked only through the lab; do not edit its source, and never redirect its target to any external host, public domain, or IP address. No brute forcing, exploitation, or denial-of-service activity is permitted.

## Completion Checklist

- [ ] **c1** — I ran `python -m bcssl run custom-scanner --modules headers` and kept the lab's console log.
- [ ] **c2** — I opened the scanner's HTML report in a browser and read the header section end to end.
- [ ] **c3** — I saved the report to `evidence/custom-scanner/ex03-headers-report.html` and wrote my per-header table with the scanner's own severity values to `evidence/custom-scanner/ex03-header-notes.md`.
- [ ] **c4** — I noted which modules were excluded, wrote a remediation sentence for each flagged header, and answered q1, q2 and q3 in my own words.

> Progress in this lab is never auto-completed by running a tool. An exercise is done only when you have saved the evidence, answered the questions, and ticked the checklist.