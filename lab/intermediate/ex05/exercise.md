# Exercise 05 — OWASP ZAP Controlled Scanning

## Objective

Run an OWASP ZAP baseline scan against the authorized local target, and interpret ZAP's four-level risk scale correctly instead of misreporting High as critical.

## Authorized Target

```
http://localhost:3001
```

## Prerequisites

- Exercise 01 completed and its preflight evidence saved.
- OWASP ZAP is installed (packaged or docker distribution) with the passive scan and the standard baseline scan alert rules available.
- Java is available and `JAVA_HOME` or the ZAP launcher resolves correctly.
- OWASP Juice Shop is running on `http://localhost:3001` and you have created the folder `evidence/zap/`.

## Tool Used

`zap` — OWASP ZAP in **baseline mode**: passive analysis plus a limited set of low-impact active checks, writing HTML and JSON reports.

ZAP risk scale — there is no Critical level:

| Numeric | Name |
|---------|------|
| 0 | Informational |
| 1 | Low |
| 2 | Medium |
| 3 | High |

## Exact Command

```bash
python -m bcssl run zap --mode baseline
```

## Expected Observation

The lab drives ZAP in baseline mode against `http://localhost:3001` and writes an HTML report and a JSON report into `reports/raw/`. In the console you should see ZAP start, crawl/spider progress, then the alert summary.

Against Juice Shop you should typically see alerts about missing or weak security headers, for example `Content-Security-Policy`, `X-Content-Type-Options` and `X-Frame-Options`, a missing anti-clickjacking header, and cookie flag issues such as a session cookie without `HttpOnly` or `Secure`.

**Important:** ZAP has no Critical risk level. Its scale is Informational(0), Low(1), Medium(2), High(3). Any report that says "critical" for a ZAP alert is a reporting error. Record the alerts actually returned; do not expect a fixed count.

## Student Task

1. Run the exact command above from the lab project root and let the baseline scan finish completely before touching the reports.
2. Open the HTML report and, in the Alerts table, record each alert name, the URL or parameter it applies to, and the numeric risk shown.
3. Convert each numeric risk to its correct name using ZAP's scale and write a table of your own in `evidence/zap/ex05-alert-notes.md`.
4. For each alert, write one sentence describing the impact on this specific application and one remediation sentence, clearly labelled as **your assessment**, not ZAP's output.
5. Save ZAP's HTML and JSON reports unmodified to `evidence/zap/ex05-baseline-report.html` and `evidence/zap/ex05-baseline-report.json`.

## Evidence Requirement

- Files `evidence/zap/ex05-baseline-report.html` and `evidence/zap/ex05-baseline-report.json`, both unmodified copies of ZAP's own reports.
- File `evidence/zap/ex05-alert-notes.md` containing your alert table with alert name, affected URL, numeric risk and correct risk name.
- An explicit statement that no ZAP alert was labelled "critical", with the reason why that word is invalid in ZAP's scale.
- These filenames must be referenced in the evidence index of your final report (Exercise 12).

## Questions

**q1. Which alerts did ZAP raise, and how do you translate their numeric risk values into names?**

> Quote the alert name and risk number from the report, then map 0 Informational, 1 Low, 2 Medium, 3 High. State plainly that ZAP does not have a Critical value, so a missing-header alert at risk 2 is Medium, not critical.

**q2. Why is a baseline scan considered a lower-risk activity than an active attack scan, and what residual risk does it still carry?**

> Explain that baseline mode leans on passive analysis and a small, curated set of active checks that do not attempt exploitation, injection, fuzzing or denial-of-service. Residual risk still includes added request volume, spidered URLs, and state changes such as session or cookie creation in the target, so it still needs an authorized, rate-conscious environment like this local lab.

**q3. Two ZAP alerts describe the same underlying weakness from different angles. How should you present that in a written report without inflating the count?**

> Explain the practice of grouping by root cause: a missing anti-clickjacking header and a missing `X-Frame-Options` header are one weakness with two detections. Report it as one finding with two supporting pieces of evidence, keep both alert names visible for traceability, and let the severity come from impact rather than from how many rules fired.

## Safety Note

Authorized local-only use against `http://localhost:3001`. Baseline mode is used precisely so that the scan stays non-destructive; do not switch to an aggressive or attack mode, do not enable fuzzing, and do not raise concurrency to stress the target. Never point ZAP at any external host, public domain, or IP address, and do not use spider or scanner scope settings to wander outside `localhost:3001`. No exploitation, credential attack, persistence, or denial-of-service testing is permitted in this lab.

## Completion Checklist

- [ ] **c1** — I ran `python -m bcssl run zap --mode baseline` and allowed the scan to finish before reading anything.
- [ ] **c2** — I opened the ZAP HTML report and recorded each alert's name, affected URL and numeric risk value.
- [ ] **c3** — I saved both unmodified ZAP reports to `evidence/zap/` and wrote my own risk-name mapping and impact/remediation sentences to `evidence/zap/ex05-alert-notes.md`.
- [ ] **c4** — I confirmed in writing that ZAP has no critical level, grouped any duplicate alerts by root cause, and answered q1, q2 and q3.

> Progress in this lab is never auto-completed by running a tool. An exercise is done only when you have saved the evidence, answered the questions, and ticked the checklist.