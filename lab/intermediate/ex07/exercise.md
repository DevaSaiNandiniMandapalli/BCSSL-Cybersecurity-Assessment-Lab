# Exercise 07 — Content and Path Discovery

## Objective

Run the external custom-scanner's `paths` module to enumerate content on the authorized target, and separate genuine unauthenticated exposures from scanner noise using evidence-based triage rules.

## Authorized Target

```
http://localhost:3001
```

## Prerequisites

- Exercise 03 completed and its headers-module evidence saved.
- The standalone custom-scanner project (Project #08 Web Security Scanner) is installed and callable as an external subprocess. The lab does not modify it.
- OWASP Juice Shop is running on `http://localhost:3001`.
- You have created the folder `evidence/custom-scanner/` for this exercise's outputs.

## Tool Used

`custom-scanner` — the existing Project #08 scanner, invoked externally as a subprocess with only the `paths` module enabled. Severity vocabulary: `info`, `low`, `medium`, `high`, `critical`. Output: an HTML report that the lab parses.

## Exact Command

```bash
python -m bcssl run custom-scanner --modules paths
```

## Expected Observation

The lab calls the external scanner with only the `paths` module enabled. You should see the lab log the subprocess, the scanner's report path, and a summary of path-related results written under `reports/raw/`.

Against Juice Shop you should typically see a set of existing paths returned with a success status, and among them paths that expose application surface such as administrative, account, product, search or API-style locations.

Do not assume a specific number of discovered paths, and do not copy in paths from the internet or from another target; only report what this run actually returned.

## Student Task

1. Run the exact command above from the lab project root.
2. Open the generated HTML report and copy out every discovered path exactly as the scanner recorded it, including the status or severity the scanner assigned.
3. Triage each path into one of three buckets in a table:
   - **(a)** content that should require authentication or is not meant to be public
   - **(b)** ordinary public application surface
   - **(c)** probable scanner noise or a generic well-known path

   Give a one-line reason for each bucket assignment.
4. For every path you placed in bucket (a), write one remediation sentence, and mark it as **your own assessment**.
5. Save the scanner's HTML report to `evidence/custom-scanner/ex07-paths-report.html` and your triage table to `evidence/custom-scanner/ex07-path-triage.md`.

## Evidence Requirement

- File `evidence/custom-scanner/ex07-paths-report.html` containing the scanner's unmodified HTML report for the paths run.
- File `evidence/custom-scanner/ex07-path-triage.md` containing your triage table with the scanner's status or severity quoted for each path and a written justification for the bucket.
- A statement confirming that the `headers` and `injection` modules were not run in this invocation.
- These filenames must be referenced in the evidence index of your final report (Exercise 12).

## Questions

**q1. Which paths did the paths module discover, and what evidence does the report give for each one?**

> Quote the path, the HTTP status or the scanner's own status field, and the severity label. Explain that the evidence is "this URL responded", which is weaker than "this URL leaks something important".

**q2. Why is a discovered path not automatically a vulnerability, and what triage evidence upgrades a path into a finding?**

> Describe the upgrade criteria: the path should not be reachable without authentication, or the response body should expose data, versions, stack traces or configuration that is not intended for public access. If a discovered path returns an ordinary public page, the correct conclusion is exposure surface rather than a vulnerability.

**q3. How does path discovery overlap with what nikto and ZAP do, and why is running a dedicated path module still worthwhile?**

> Explain that nikto has a curated per-product interesting-file list while ZAP's spider finds links it can reach through navigation, and the custom-scanner applies its own wordlist and status logic. The overlap means corroboration is common, and the dedicated module gives you breadth that crawler-dependent tools miss, such as paths not linked from any page.

## Safety Note

Authorized local-only use against `http://localhost:3001`. Path discovery here is read-only enumeration against the local lab application. Do not authenticate with real or reused credentials, do not attempt to create, delete, or modify any record, do not upload or download files, and do not follow discovered paths onto any external host, public domain, or IP address. Discovery is not exploitation; no injection, credential attack, persistence, privilege escalation, or denial-of-service testing is permitted.

## Completion Checklist

- [ ] **c1** — I ran `python -m bcssl run custom-scanner --modules paths` from the lab project root and kept the lab's console log.
- [ ] **c2** — I opened the scanner's HTML report and transcribed every discovered path with its recorded status and severity.
- [ ] **c3** — I saved the report to `evidence/custom-scanner/ex07-paths-report.html` and my three-bucket triage table to `evidence/custom-scanner/ex07-path-triage.md`.
- [ ] **c4** — I confirmed which modules were not run, wrote remediation sentences for the paths I judged as real exposures, and answered q1, q2 and q3.

> Progress in this lab is never auto-completed by running a tool. An exercise is done only when you have saved the evidence, answered the questions, and ticked the checklist.