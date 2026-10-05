# Viva questions and answers

Thirty questions with concise answers, reflecting the actual implementation.
Where a number is given it comes from the latest real run (`run-001`).

---

## 1. Why cybersecurity assessment?

Because software is deployed with defects that attackers find faster than
defenders. Assessment turns an assumption — "this is probably fine" — into
evidence: a defensible statement of what was checked, what was found, what was
independently confirmed, and what was not covered. Without it there is no basis
for remediation priorities, no proof of due diligence, and no way to show that a
fix worked.

## 2. Why OWASP Juice Shop?

Because it is a deliberately vulnerable training application maintained by the
OWASP foundation. It contains realistic, well-known vulnerability classes, so
students practise against meaningful findings rather than contrived ones, and it
is legally safe to attack because that is its purpose. It is also freely
available as a container, so every student gets an identical target and results
are comparable between machines.

## 3. Why localhost rather than a real website?

Three reasons. **Safety** — no third party is affected. **Legality** — testing a
system without authorisation is a criminal offence in most jurisdictions.
**Reproducibility** — a local target cannot change mid-session, so findings are
comparable across a cohort. The project enforces this: the validator allowlists
host and port, resolves the name, and requires the result to stay on loopback.

## 4. Why Nmap?

For the discovery layer. Before assessing an application you must know what is
listening and on which ports — you cannot assess what you have not found. It
answers "what is exposed?". In this project it produced one finding: port 3001
open. It is scoped to TCP connect scanning on the single authorized port;
SYN scanning, OS fingerprinting, aggressive scanning and UDP probing are refused
by the runner.

## 5. Why OWASP ZAP?

For application-level assessment. ZAP crawls the application and applies
passive and active rules, reporting risk level, confidence, URL, evidence and a
recommendation per alert — the kind of finding a port scanner cannot produce. In
this project it raised 11 alerts: 2 MEDIUM, 5 LOW, 4 INFO.

## 6. Why Nikto?

For web server configuration and information disclosure — the things that sit
between "the port is open" and "the application is vulnerable". It found 104
observations in this project: backup and archive files, robots.txt, header
absences, uncommon headers. It provides no reliable severity, so the project
does not invent one.

## 7. Why Nuclei?

For template-driven, specific, reproducible checks. Each template encodes one
known issue, so a match is precise and repeatable rather than heuristic. In this
project it produced 19 findings including a MEDIUM. It matters that templates
are scoped: the project ships a curated profile of about 2,600 safe templates
and documents every excluded family.

## 8. Why build a custom scanner?

Three reasons. **Ownership** — it demonstrates the full scanner lifecycle rather
than tool orchestration alone. **Control** — its modules map directly onto the
lab curriculum (headers, paths, injection). **Corroboration value** — it is a
genuinely different implementation, which is what makes cross-tool agreement
meaningful. It is integrated read-only as an external subprocess and is never
modified.

## 9. What is normalization?

Reducing five incompatible tool outputs to one schema. Five tools produce five
formats — XML, ZAP's alert structure, Nikto JSON, nuclei JSONL, the custom
scanner's HTML — across five severity vocabularies. Normalization maps each
into an eleven-field finding record so correlation, evidence, reporting and SARIF
export can operate on one shape.

## 10. What is correlation?

Deciding which findings from different tools describe the same underlying issue.
The project links findings only when they share an exact canonical fingerprint —
a category and subject pair such as `missing-header:csp` or `exposure:robots-txt`.
Two or more distinct tools on one fingerprint is a confirmation; one tool is a
single-tool observation; the same tool twice is never corroboration.

## 11. Difference between a finding and a vulnerability?

A finding is a tool's observation: "this condition was detected". A
vulnerability is a demonstrated weakness with an understood impact. The project
never converts the first into the second without evidence. In the latest run,
129 of 139 findings were INFO, and the highest severity present was MEDIUM —
because that is what the evidence supported.

## 12. Difference between DETECTED and CORROBORATED?

`CORROBORATED` means two or more distinct tools reported the same fingerprint.
`DETECTED` means the project itself re-checked the condition against the live
target with its own HTTP request — for example confirming a header really is
absent. In this run: 5 CORROBORATED, 5 DETECTED, 122 single-tool, 7 not
verified. Corroboration outranks independent reproduction.

## 13. What is evidence?

The verbatim raw tool output a finding was derived from, plus a record linking
the finding to that artifact. It answers "where did this claim come from?".
Without it, a report is only assertions.

## 14. Why SHA-256?

To make the link verifiable. The hash is computed over the stored raw artifact,
so a reviewer can re-hash the file and prove it was not altered after capture.
It is a cryptographic digest: any modification changes it. In this run all 124
records verified intact, and reports re-check them every time they are
generated. Tampering is detected as `DRIFT DETECTED`.

## 15. What is preflight?

A real probe of every dependency before any scan. It answers "can this lab run
right now, and if not, what exactly is missing?" It produces a
`Component | Status | Version | Details` table over thirteen components with
statuses READY, READY WITH WARNING, NOT INSTALLED, NOT RUNNING, UNAVAILABLE and
ERROR, an exact remediation for anything not ready, and a non-zero exit code when
a required component is unavailable. It also detects a target container bound to
anything other than loopback.

## 16. What is target validation?

The mandatory check before every tool invocation. It restricts the scheme, checks
host and port against an allowlist, rejects credential-bearing URLs and argument
smuggling, resolves the name and requires the result to stay on loopback. It
returns a structured reason code — `host-not-authorized`, `not-loopback`,
`port-not-authorized` — and runs from `BaseRunner.run` *before* any command is
built, so no code path can construct a command against an unauthorized target.

## 17. Why a Docker transport?

So a student machine needs no global install of four security tools, which on a
managed or locked-down machine is often impossible. Each tool runs inside its own
official image. It is a supported configuration, not a workaround: the run
directory is mounted at a fixed path and used as the working directory, so
tool-relative output filenames behave identically whether the tool runs locally
or in a container. A local install is still preferred automatically when
present.

## 18. Why store raw evidence?

Because a finding is only trustworthy if it can be traced to captured output.
Raw stdout, stderr and the tool's native report are stored verbatim and never
edited, so parsing can be re-derived and audited. Without them, a reviewer cannot
distinguish a real detection from a parsing bug — and in this project's
development, real tool output did expose exactly such bugs.

## 19. Why HTML, JSON and Markdown?

Three audiences, one source. HTML is self-contained and presentation-ready, so it
can be archived as evidence and opened offline. JSON is the full machine-readable
payload for tooling and dashboards. Markdown is diff-friendly and reviewable in
pull requests. All three are rendered from one collected assessment, so they
cannot disagree with each other.

## 20. Why SARIF?

Interoperability. SARIF 2.1.0 is the OASIS interchange format for
static-analysis results, so findings load into code-scanning and dashboard tools
without a bespoke importer. This project emits one SARIF run object per tool so
attribution is preserved, keeps the original severity in `properties` because
SARIF has only three levels, and labels its numeric band as a lab band rather
than a CVSS score. It emits a valid document even when there are zero findings.

## 21. What are false positives?

When a tool reports a condition that is not actually a problem. Common causes:
a rule keyed on a generic header name that the application uses legitimately, a
version fingerprint matched by fingerprinting rather than proof, or a
config-check template that assumes a deployment convention the target does not
follow. This is exactly why the project labels findings by verification status
and never calls an observation a vulnerability on a scanner's authority alone.

## 22. Why should findings not automatically be called vulnerabilities?

Because a scanner detects patterns, not impact. A missing header is a
misconfiguration whose real-world consequence depends entirely on context — it
may be mitigated by other controls, or irrelevant for an application that serves
no user input. Calling such output "vulnerabilities" teaches students to
over-report and destroys the report's credibility. This project reports what was
observed, states how much weight it carries, and leaves the impact judgement
explicit.

## 23. How is the project safe?

By refusing by default. Only `http://localhost:3001` is authorized, validated
before every tool. Public IPv4, IPv6 and IPv4-mapped addresses are rejected, as
are wrong ports, credential URLs, non-HTTP schemes and argument-smuggling
attempts. The target container publishes loopback only, and preflight flags any
other binding. The dashboard binds loopback and refuses any other address. Each
tool's dangerous flags are refused in code: Nikto's eight destructive plugin
groups, Nuclei's intrusive tags, Nmap's aggressive scan types, ZAP's unbounded
crawl. There are more than 39 rejection tests.

## 24. What testing is deliberately excluded?

Fuzzing, denial of service and load testing, credential testing, brute force,
default-login and token-spray attacks, exploitation templates, remote code
execution, file upload, remote file retrieval, SQL injection, authentication
bypass and cross-site request forgery payloads. Excluded twice for Nuclei: from
configuration and from a mandatory tag list merged at command-build time, so
removing the configured list does not re-enable them. The curated template
profile documents every excluded family and the reason.

## 25. What are the project's limitations?

Honest summary. **One target, loopback only.** **Coverage** — the independent
verifier checks only observable conditions (header presence, path reachability),
so CVE-style and version-banner findings keep their correlated status; `DETECTED`
never means proven exploitable. **Severity is not CVSS** and must not be
presented as such. **Correlation is fingerprint-based**, so differently worded
findings are not merged — it under-correlates deliberately. **Environment** — the
four external tools were verified through Docker, not natively; Nuclei buffers
output so a timeout loses the whole run; images are pinned to `:latest`; Nuclei
templates are downloaded rather than committed, so findings can differ between
cohorts. **One scan point in time**, nothing is continuously monitored.

## 26. How does the dashboard work?

`bcssl/web/server.py` serves thirteen pages and sixteen JSON endpoints using only
the Python standard library — no framework, no build step, no npm. It reads live
state from disk on each request. It binds loopback only. With no stored runs it
displays "No scan results available" rather than sample data; nothing is ever
simulated. It is a reader plus a launch pad: it can start a scan and record
exercise acknowledgements, but it never writes results itself.

## 27. How are student exercises protected from answer-key exposure?

Each question carries grading fields — expected keywords, accepted answers,
numeric bounds. `bcssl/lab/quiz.py` defines `student_view()`, which strips every
such field, and both the CLI and the dashboard API apply it before returning a
question. Keys stay inside the lab for grading only. This was a real defect found
during development: the exercise-list endpoint initially returned raw question
objects. It is now covered by tests on both the CLI and the API.

## 28. What happens when a tool returns a non-zero exit code because findings were detected?

Exit codes are interpreted per tool. Most tools use 0. ZAP's baseline script
returns 2 when the scan completed and alerts were raised — a *successful* scan
with findings. `BaseRunner.success_exit_codes` declares `(0, 2)` for ZAP, so
those eleven real findings are kept. This is not cosmetic: before the fix, ZAP's
entire result set was reported as `TOOL FAILED`. A genuinely failed tool is still
recorded as failed, with the reason, and the run continues.

## 29. How does the system prevent external target testing?

In four independent ways. **By construction** — the authorized target is an
allowlist, and there is no code path that accepts an arbitrary host.
**By validation before execution** — `BaseRunner.run` validates before building
any command. **By resolution** — the hostname is resolved and the result must be
loopback, so a name resolving to a public address is refused. **By transport** —
the runners build an argument list with no shell interpolation, so a target
string cannot smuggle additional arguments. Tests cover IPv4, IPv6, IPv4-mapped
addresses, wrong ports, credential URLs, non-HTTP schemes and whitespace and
control characters.

## 30. What makes this different from simply running five scanners?

Running five scanners gives five incompatible outputs and no defensible
conclusion. This project adds the four things a professional assessment actually
requires:

1. **A common finding model**, so results from different engines can be compared
   at all.
2. **Honest weighting** — 139 findings labelled by verification status, with
   exactly 2 corroborated and 5 independently reproduced, instead of 139
   undifferentiated "vulnerabilities".
3. **Verifiable evidence** — 124 records, each naming its verbatim artifact and
   its SHA-256, all re-checked on every report.
4. **Fail-safe operation** — a refused target, an unavailable tool or an
   unparseable format is reported as such. The project never manufactures a
   result to look successful, and a report that states its own limitations is
   more valuable than one that hides them.

The student lab is the same principle applied to teaching: progress requires
evidence and understanding, never activity.

---

## Numbers you can quote

From the latest real run, `run-001`, against Juice Shop at
`http://localhost:3001`:

| Metric | Value |
| --- | --- |
| Assessment components executed | 5 of 5, all completed |
| Findings | 139 |
| Severity | INFO 129, LOW 5, MEDIUM 5, HIGH 0, CRITICAL 0 |
| Verification status | single-tool 122, not verified 7, corroborated 5, detected 5 |
| Correlation groups | 31 |
| Confirmed by two or more tools | 2 |
| Evidence records | 124, all hashes verified intact |
| Report formats | HTML, JSON, Markdown, SARIF 2.1.0 |
| SARIF results | 139 across 5 tool runs |
| Dashboard | 13 pages, 16 endpoints, loopback only |
| Practical exercises | 12 across 3 levels, 36 graded questions |
| Automated tests | 474 across 16 modules |
| Documentation | 22 documents |