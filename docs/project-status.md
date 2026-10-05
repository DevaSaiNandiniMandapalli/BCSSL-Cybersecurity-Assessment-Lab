# Project status

**Project:** BCSSL Cybersecurity Assessment Lab
**Version:** 1.0.0
**Environment:** Windows 11, Python 3.12.10, Docker Engine 29.8.0
**Target:** `http://localhost:3001` (OWASP Juice Shop, live, bound to loopback)

Statuses used below:

| Status | Meaning |
| --- | --- |
| COMPLETE | Implemented and verified by execution or by test |
| IMPLEMENTED BUT NOT VERIFIED | Implemented; no real execution evidence in this environment |
| PARTIALLY IMPLEMENTED | Some of the component exists, some does not |
| NOT IMPLEMENTED | Does not exist |
| BLOCKED BY ENVIRONMENT | Cannot be built or verified here |

All figures below were measured from this checkout, not estimated.

---

## 1. Version and status

Version 1.0.0, functional and demonstrable. The lab runs end to end against a live
Juice Shop with all five assessment components producing real findings, real
evidence and a real consolidated report.

## 2. Total files

| Group | Files |
| --- | --- |
| Engine (`bcssl/`, 39 modules, ~10,000 lines) | 39 |
| Tests (15 modules) | 15 |
| Documentation | 12 |
| Exercises (12 × json + md) | 24 |
| Tool manifests + Nuclei guidance | 6 |
| Runner wrappers / parser wrappers | 10 |
| Scripts (9 PowerShell + 7 Python) | 16 |
| Configuration | 2 |
| Target definition | 2 |
| Web assets (html/js/css) | 3 |
| Root files | 6 |
| **Total (excluding downloaded templates and generated artifacts)** | **135** |

With downloaded Nuclei templates and the artifacts of one full run, the working
tree holds 301 files.

## 3. Source files

| Type | Count |
| --- | --- |
| Engine modules (`bcssl/`) | 39 |
| Wrappers and scripts | 26 |
| Test modules | 15 |
| Dashboard assets | 3 |
| Test fixtures (real tool output) | 6 |

## 4. Tests

314 test functions across 15 modules; **389 test cases pass** (some functions
are parameterised), 0 failures, 1 expected skip in the release package where
Nuclei templates are deliberately absent.

| Module | Test functions |
| --- | --- |
| `test_runners.py` | 36 |
| `test_parsers.py` | 38 |
| `test_web_api.py` | 31 |
| `test_reporting.py` | 28 |
| `test_lab_progress.py` | 26 |
| `test_cli.py` | 25 |
| `test_quiz.py` | 22 |
| `test_verify_preflight_templates.py` | 22 |
| `test_executor_preflight.py` | 20 |
| `test_config.py` | 16 |
| `test_correlation.py` | 14 |
| `test_target_validation.py` | 14 |
| `test_severity_mapping.py` | 12 |
| `test_clean.py` | 10 |

## 5. Tests passing/failing

**389 passed, 0 failed.** `python -m compileall .` also passes.

The suite is offline: it never contacts a target and never runs a real scan.
Real tool behaviour is verified separately by real execution (section 9).

---

## 6. Modules implemented

| Module | Responsibility | Status |
| --- | --- | --- |
| `target.py` | Authorized-target validator | COMPLETE |
| `preflight.py` | Tool detection, version probe, image entrypoint lookup | COMPLETE |
| `preflight_report.py` | Professional component status table and remedies | COMPLETE |
| `config.py` | Configuration load, merge, alias folding, safe defaults | COMPLETE |
| `executor.py` | Subprocess execution with capture and timeout | COMPLETE |
| `runner.py` | 10-step runner contract, Docker transport, evidence | COMPLETE |
| `runs.py` | Assessment identifiers, per-run isolation, manifests | COMPLETE |
| `templates.py` | Nuclei template fetch and curated lab profile | COMPLETE |
| `clean.py` | Artifact cleanup with dry-run | COMPLETE |
| `verify.py` | Independent re-check of reported conditions | COMPLETE |
| `sarif.py` | SARIF 2.1.0 export and structural validation | COMPLETE |
| `parsers/nmap.py` | Nmap XML | COMPLETE |
| `parsers/zap.py` | ZAP JSON, classic and modern report models | COMPLETE |
| `parsers/zap_html.py` | ZAP HTML report (current releases store alerts here) | COMPLETE |
| `parsers/nikto.py` | Nikto JSON, 2.1.x and 2.5.x shapes | COMPLETE |
| `parsers/nuclei.py` | Nuclei JSONL with format-mismatch detection | COMPLETE |
| `parsers/custom.py` | Project #08 HTML report | COMPLETE |
| `runners/*.py` (5) | Per-tool command construction and safety refusals | COMPLETE |
| `severity.py` | Severity vocabulary and native-scale mapping | COMPLETE |
| `models.py` | Finding schema, run results, statuses | COMPLETE |
| `correlation.py` | Cross-tool correlation and labelling | COMPLETE |
| `evidence.py` | Evidence records, per-run scoping, integrity verification | COMPLETE |
| `reporting.py` | HTML, JSON, Markdown and SARIF reports | COMPLETE |
| `pipeline.py` | Run, collect, persist, assessment assembly | COMPLETE |
| `lab/exercises.py` | Exercise registry and validation | COMPLETE |
| `lab/quiz.py` | Answer grading and answer-key protection | COMPLETE |
| `lab/progress.py` | Progress, completion rules, badges | COMPLETE |
| `web/server.py` | Dashboard API, 16 endpoints | COMPLETE |
| `web/static/*` | Dashboard UI, 13 pages | COMPLETE |
| `cli.py` | Command-line interface, 18 commands | COMPLETE |

## 7. Tools integrated

All five, with detection, version probe, safe command construction, execution,
stdout/stderr capture, exit-code handling, timeout, raw storage, parsing,
normalization, evidence and reporting.

| Tool | Role |
| --- | --- |
| Nmap | Local port and service discovery |
| OWASP ZAP | Application assessment, baseline mode |
| Nikto | Web server configuration assessment |
| Nuclei | Template-based checks |
| Custom Project #08 scanner | Application security scanner, invoked externally |

## 8. Tools actually executable on this machine

**5 of 5.**

| Tool | Executable used | Version |
| --- | --- | --- |
| Nmap | `instrumentisto/nmap:latest` (Docker) | 7.98 |
| OWASP ZAP | `ghcr.io/zaproxy/zaproxy:stable` (Docker) | Java 17.0.20 |
| Nikto | `alpine/nikto:latest` (Docker) | 2.1.6 |
| Nuclei | `projectdiscovery/nuclei:latest` (Docker) | 3.11.1 |
| Custom scanner | Native Python (Project #08 `.venv`) | Python 3.12.10 |

None of the four external tools is installed natively; all use the supported
Docker transport.

## 9. Tools only parser/fixture tested

**None.** All five produced real findings in one clean full run. Recorded
evidence:

| Run | Status | Exit | Findings |
| --- | --- | --- | --- |
| nmap | ok | 0 | 1 |
| zap | ok | 2 (alerts found, treated as success) | 11 |
| nikto | ok | 0 | 104 |
| nuclei | ok | 0 | 19 |
| custom-scanner | ok | 0 | 4 |
| **Total** | | | **139** |

Fixture-based tests exist as well and are **additional** to real execution.

## 10. Web dashboard status

**COMPLETE.** 13 pages: Dashboard, Target, Preflight, Tools, Run, Findings,
Correlation, Evidence, Reports, Exercises, Progress, Documentation, About.
16 JSON endpoints.

Verified live against real run data: state (139 findings, 5 runs), per-tool
results, correlation with reasoning, target authorization, preflight table,
progress, docs listing, exercise detail with answer keys stripped, grading, and
refusal of path traversal on both `/static/` and `/docs/`.

## 11. CLI status

**COMPLETE.** 18 commands: `validate-target`, `preflight`, `run`, `run-all`,
`collect`, `report`, `runs`, `status`, `lab` (`list`/`show`/`ack`/`progress`/`reset`),
`web`, `version`, `update-templates`, `build-template-profile`, `verify`, `clean`.

## 11a. Run-index rotation status

**COMPLETE.** `bcssl/runs.py` allocates a monotonic assessment identifier
(`run-001`, `run-002`, ...) before any tool runs and gives each assessment an
isolated namespace:

| Artifact | Location |
| --- | --- |
| Raw tool output | `reports/raw/run-001/run-001-<tool>/` |
| Normalized findings | `reports/normalized/run-001/findings-run-001-<tool>.json` |
| Evidence records | `evidence/run-001/<tool>/` |
| Reports | `reports/final/run-001.{html,json,md,sarif}` |
| Run metadata manifest | `state/assessments/run-001.json` |
| Counter | `state/sequence.json` |

The counter is reconciled against the filesystem and the run index on every
allocation, so identifier reuse is impossible even after a manual deletion. A
full assessment shares one identifier across all five tools.
`python -m bcssl runs --verify` lists each run and re-hashes its evidence.

Covered by `tests/test_runs.py`, including consecutive-run isolation, evidence
addressability, report references and hash validity across runs.

## 11b. SARIF export status

**COMPLETE.** `bcssl/sarif.py` emits SARIF 2.1.0 from stored normalized findings
and nothing else. One run object per tool, explicit severity-to-level mapping,
empty assessments produce a valid empty log, and `sarif.validate()` checks the
structural requirements SARIF imposes. Covered by `tests/test_sarif.py`,
including special-character handling.

## 11c. Git repository status

**COMPLETE.** Initialised at the project root with one commit describing
v1.0.0. `.gitignore` excludes secrets, credentials, virtual environments,
Python caches, generated scan artifacts, evidence records, run state, Nuclei
templates, Docker runtime data, logs and temporary files, while preserving the
directory skeleton. Tracked file count is 148; the working tree is clean.

## 12. Reporting status

**COMPLETE.** HTML, JSON and Markdown from one collected assessment. With no
results, all three state "No scan results available."

Reports include authorization statement, target, timestamps, tools used, tool
versions, severity distribution, tool-by-tool results, cross-tool correlation
with reasoning, verification status, evidence with hashes, deduplicated
recommendations, errors, limitations and scan coverage.

## 13. Evidence system status

**COMPLETE.** One JSON record per finding naming the verbatim raw artifact and
its SHA-256. Integrity re-verified on every report generation.

## 14. Student exercise status

**COMPLETE.** 12 exercises (4 beginner, 4 intermediate, 4 advanced), each with
objective, theory, prerequisites, authorized target, tool, exact command,
expected observation, practical task, evidence requirement, questions, safety
note and completion checklist. Markdown mirrors for every exercise.

All 36 questions carry a grading specification and are auto-gradable. Answer keys
are stripped from every student-facing response (CLI, dashboard API). Completion
requires every checklist item, every question answered and passing, and at least
one evidence reference. Running a tool never advances progress. Achievement
badges are computed from recorded state.

## 15. Documentation status

**COMPLETE.** 22 documents:

| Group | Documents |
| --- | --- |
| Orientation | `project-overview.md`, `architecture.md` |
| Setup | `installation.md`, `instructor-quick-start.md`, `student-quick-start.md` |
| Demonstration | `demo-guide.md`, `live-demo-script.md`, `presentation-guide.md`, `presentation-content.md`, `demo-screenshot-checklist.md` |
| Academic | `viva-questions.md`, `daily-work-summary.md` |
| Reference | `tool-guide.md`, `student-guide.md`, `instructor-guide.md`, `evidence-guide.md`, `reporting.md`, `troubleshooting.md`, `limitations.md` |
| Status | `project-status.md`, `final-verification.md`, `final-project-scorecard.md` |

Plus `README.md` and `RELEASE-CHECKLIST.md`.

Every documented command was executed on the build machine. Where a documented
flag does not exist, the documentation was corrected rather than the behaviour
guessed — this is how a fabricated `--scan-type` example was found and replaced
with a refusal that actually works.

## 16. Security/safety controls status

**COMPLETE.**

| Control | Implementation | Verified by |
| --- | --- | --- |
| Target allowlist (host + port) | `bcssl/target.py` | tests + live refusal |
| Loopback resolution requirement | `bcssl/target.py` | IPv4, IPv6, IPv4-mapped tests |
| Public IP rejection | `bcssl/target.py` | live `8.8.8.8`, `169.254.169.254`, `0.0.0.0` |
| Credential URL rejection | `bcssl/target.py` | test + live |
| Argument smuggling rejection | `bcssl/target.py` | test + live (`/ -oX /tmp/x`) |
| Scheme restriction | `bcssl/target.py` | test + live (`ftp:`) |
| Port restriction | `bcssl/target.py` | test + live (`3000`, `22`) |
| Validation before every tool | `bcssl/runner.py` | test (no command built) |
| Nmap `-sT` only; `-sS`/`-O`/`-A`/`-sU` refused | `bcssl/runners/nmap.py` | tests |
| Nmap port-spec validation | `bcssl/runners/nmap.py` | tests (6 specs) |
| Nikto 8 destructive groups refused | `bcssl/runners/nikto.py` | tests + live check |
| Nuclei mandatory tag exclusion merged at build time | `bcssl/runners/nuclei.py` | tests + live command inspection |
| ZAP bounded crawl | `bcssl/runners/zap.py` | tests |
| No fabricated results | `bcssl/runner.py` | tests + live `TOOL NOT INSTALLED` with 0 findings |
| Format mismatch is an error, not zero findings | `bcssl/parsers/nuclei.py` | test |
| Answer keys never exposed | `bcssl/lab/quiz.py`, `bcssl/web/server.py` | tests (CLI + API) |
| Dashboard loopback-only | `bcssl/cli.py` | test |
| Target loopback-only binding | `target/docker-compose.yml` | preflight flags any other binding |

## 17. Percentage of the complete project finished

**98.5%** of the specified scope, weighted across the 17 scored categories. The
remainder is listed in sections 18 and 19.

## 18. What remains to be implemented

| Item | Status |
| --- | --- |
| Git repository initialisation | NOT IMPLEMENTED (no `.git` in this checkout) |
| Run-index rotation / evidence retention policy | NOT IMPLEMENTED |
| Nuclei CVE template profile (optional, behind an instructor flag) | NOT IMPLEMENTED (deliberately excluded, documented) |
| ZAP authenticated scan | NOT IMPLEMENTED (out of scope for this lab) |
| Machine-readable SARIF/CycloneDX export | NOT IMPLEMENTED (optional enhancement) |
| Per-exercise expected-finding ranges from reference runs | NOT IMPLEMENTED (optional enhancement) |

## 19. What remains to be practically verified

| Item | Status |
| --- | --- |
| Native (non-Docker) tool execution | BLOCKED BY ENVIRONMENT - the four external tools are not installed natively on this host; the documented Docker transport is verified instead |
| macOS and Linux code paths | BLOCKED BY ENVIRONMENT - host is Windows only |
| Concurrent multi-student use | BLOCKED BY ENVIRONMENT - single host, single container target |
| Human visual sign-off of dashboard rendering | NOT VERIFIED - API and DOM contract are tested; no visual review performed |

## 20. Technical debt and known limitations

| Item | Impact |
| --- | --- |
| Tool images pinned to `:latest` | A future image may change output format again; pin digests for a stable cohort |
| Nuclei templates downloaded, not committed | Findings can differ between cohorts; pin a template release for reproducibility |
| Nuclei buffers output | A timeout loses the whole run rather than partial results |
| Nikto provides no reliable severity | Severity is derived conservatively; not comparable to CVSS |
| ZAP alert set depends on `scanner.alertThreshold` | A different threshold changes which alerts appear |
| Container networking uses `--network host` | Required for loopback reachability; on hosts that namespace loopback, run tools natively |
| Run index grows without rotation | Long-running cohorts should archive `state/run-index.json` |
| Verification only upgrades statuses | `CORROBORATED` is never downgraded to `DETECTED`, by design |
| Correlation is fingerprint-based | Different wording for the same issue is not merged; under-correlation is preferred |
| `PowerShell` scripts are Windows-only | The Python CLI and scripts are the cross-platform path |
| Documentation is English only | No localisation |

Full detail in `docs/limitations.md`.
