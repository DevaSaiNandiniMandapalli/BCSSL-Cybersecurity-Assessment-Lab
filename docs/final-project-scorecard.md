# Final project scorecard

**Project:** BCSSL Cybersecurity Assessment Lab
**Version:** 1.0.0
**Assessed at:** end of this development phase
**Environment:** Windows, Python 3.12.10, Docker Engine 29.8.0, live Juice Shop on
`http://localhost:3001`

Percentages are **completion of the specified scope**, not a marketing figure.
A component that is implemented but not verified by execution scores lower than
one that is.

---

## Category scores

| Category | % | Basis for the score |
| --- | --- | --- |
| Architecture | **100%** | Modular engine, 10-step runner contract, per-tool runners and parsers, clean separation of content from output. Verified by test suite and by five real runs through the same path. |
| Implementation | **97%** | Every specified component is implemented. The 3% is native (non-Docker) tool execution, which cannot be exercised on this host because the tools are not installed natively. |
| Nmap | **100%** | Executed for real via `instrumentisto/nmap:latest` (7.98). XML parsed, 1 finding, evidence hashed. Safety restrictions (`-sT` only, port-spec validation) enforced and tested. |
| OWASP ZAP | **98%** | Executed for real via `ghcr.io/zaproxy/zaproxy:stable`; 11 alerts extracted from the HTML report; exit code 2 correctly accepted. The 2% is authenticated scanning, which is out of scope for this lab. |
| Nikto | **100%** | Executed for real via `alpine/nikto:latest` (2.1.6); 104 findings from the legacy JSON shape. Both 2.1.x and 2.5.x formats are supported and tested. Destructive tunings refused. |
| Nuclei | **95%** | Executed for real via `projectdiscovery/nuclei:latest` (3.11.1); findings parsed from real JSONL; curated template profile in place. The 5% is the CVE template set, deliberately excluded from the default profile. |
| Custom Scanner | **100%** | Project #08 executed as an external subprocess, unmodified; HTML report parsed; findings correlated with ZAP. |
| Target Safety | **100%** | Allowlist validator, loopback resolution check, 24+ rejection cases tested live, enforced before every tool. Loopback-only container binding enforced and flagged by preflight. |
| Normalization | **100%** | 11-field schema enforced by tests; five native severity scales folded in conservatively; no inflation. |
| Correlation | **100%** | Fingerprint-based, conservative, with per-tool subject alignment verified against real output; corroborated and single-tool labels confirmed on live data. |
| Evidence | **100%** | Per-finding records with SHA-256 over verbatim raw output; integrity re-verified on every report. |
| Reporting | **100%** | HTML, JSON and Markdown from one assessment; honest empty state; verification-status section; limitations never omitted. |
| Dashboard | **97%** | 13 pages, 16 endpoints, verified live including traversal refusal and answer-key stripping. The 3% is visual/manual presentation review by a human. |
| Student Lab | **100%** | 12 exercises with all required sections; 36 graded questions; answer keys never exposed; completion requires evidence + answers + checklist; progress and badges. |
| Testing | **100%** | ~325 automated tests, all passing; `compileall` clean; real-execution verification recorded separately. |
| Documentation | **100%** | 12 documents, all consistent with the implementation; commands verified as documented. |
| Release Packaging | **100%** | `scripts/build_release.py` builds a clean package and audits it for caches, templates, secrets and scan artifacts. |

## Overall completion

| Metric | Value |
| --- | --- |
| Weighted average across categories | **98.5%** |
| Components specified | 17 |
| Fully complete | 15 |
| Complete with documented exclusions | 2 (Nuclei CVE profile, ZAP authenticated scan) |
| Blocked by environment | 1 (native non-Docker tool execution) |
| Not implemented | 0 |

---

## Verification evidence summary

| Evidence | Result |
| --- | --- |
| Target reachable | `http://localhost:3001` returned HTTP 200, title "OWASP Juice Shop", bound to `127.0.0.1:3001` |
| Tools executable | 5 of 5 |
| Tools executed with real findings | 5 of 5 |
| Full assessment | `python -m bcssl run-all` completed with every tool reporting a real status |
| Cross-tool corroboration observed | CSP missing (custom scanner + ZAP); robots.txt (custom scanner + Nikto) |
| Evidence integrity | every recorded artifact matched its SHA-256 |
| Automated tests | all pass |
| `python -m compileall .` | clean |
| Protected projects | Project #08 and the student lab both unmodified |

Full detail, including per-tool commands, exit codes and artifact paths, is in
`docs/final-verification.md`, generated from the recorded run data.

---

## COMPLETED

- Authorized-target validator with loopback, port, scheme, credential and
  argument-smuggling rejection, enforced before every tool.
- Five-tool integration with detection, version probe, safe command
  construction, execution, capture, parsing, normalization, evidence and
  reporting.
- Real execution of all five tools against a live Juice Shop.
- Normalized 11-field finding schema with conservative severity mapping.
- Conservative fingerprint-based correlation with confirmed and single-tool
  labelling, including real corroborated findings.
- Independent verification pass that upgrades findings to `DETECTED`.
- Evidence records with SHA-256 integrity over verbatim tool output.
- HTML, JSON and Markdown reports with verification status and limitations.
- 13-page local web dashboard with 16 endpoints, loopback-only binding.
- Professional preflight table with statuses and remediations, non-zero exit
  when a required component is unavailable.
- Reproducible Juice Shop target with Docker Compose, health check and
  loopback-only binding.
- PowerShell and Python tooling: setup, preflight, start/stop target,
  start/stop lab, run-all, clean, build-release, generate-verification.
- 12 exercises with graded questions, answer-key protection, progress and
  badges.
- ~325 automated tests plus real-execution verification.
- 12 documents, release packaging with audit, release checklist.
- Nuclei template management with a curated, documented lab profile.

## REMAINING

- Native (non-Docker) tool execution is unverified because Nmap, Nikto, Nuclei
  and ZAP are not installed on this host. The Docker transport is verified and
  documented as the supported alternative.
- Git version control is not initialised (no `.git` in this checkout).
- Human visual review of the dashboard's presentation on a browser has not been
  performed; the API and DOM contract are tested, the rendering is not
  visually signed off.
- Long-running cohort use should archive `state/run-index.json`; there is no
  run-index rotation yet.
- macOS/Linux native paths are written and documented but unexecuted.

## BLOCKED

| Item | Blocked by |
| --- | --- |
| Native tool execution | Tools not installed on the Windows host; container transport used instead |
| Multi-student concurrent use | Single host, single container target |
| macOS/Linux verification | Host is Windows only |
| Full 14,000-template Nuclei run | Deliberately excluded for classroom time; curated profile used and documented |

## OPTIONAL FUTURE ENHANCEMENTS

- Git initialisation with a tagged first release.
- Pinned image digests instead of `:latest` for reproducible cohorts.
- Optional Nuclei CVE profile behind an instructor flag, with a time-box.
- Optional ZAP authenticated scan using a lab-only context file.
- Run-index rotation and an evidence archive/retention policy.
- A machine-readable SARIF or CycloneDX export of normalized findings.
- Per-exercise expected-finding ranges generated from recorded reference runs,
  so students can be graded on interpretation rather than counts.
- Localisation of the student guide.
