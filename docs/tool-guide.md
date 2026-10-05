# BCSSL Cybersecurity Assessment Lab - Tool Guide

## 1. Honest status of tools on the lab machine

At the time of writing, **nmap, Nikto, Nuclei, and OWASP ZAP are not installed on the lab
machine.** The lab reports `TOOL NOT INSTALLED` for each of them. It does not simulate,
sample, or fabricate their output.

What this means in practice:

- `python -m bcssl preflight` will list each tool with its availability state.
- `python -m bcssl run <tool>` for a missing tool stops at step 1 of the runner contract,
  writes no raw output, produces no findings, and creates no evidence records.
- The consolidated report states which tools contributed and which did not. A report with
  zero tool output is a valid, honest report; it is not a failure of the lab.

The custom scanner is a special case. It is not a packaged tool; it is an external
subprocess (see section 6). Its availability depends on the local state of Project #08.

## 2. Authorized scope

Every tool in this lab targets **only** `http://localhost:3001` (OWASP Juice Shop running
locally) and, for nmap, only the authorized port(s) configured in `config/lab-config.json`,
which default to `3001` alone.

| Tool | Target | Port scope | Notes |
| --- | --- | --- | --- |
| nmap | `localhost` | 3001 (default, instructor-configurable) | TCP connect scan |
| OWASP ZAP | `http://localhost:3001` | HTTP only | Baseline scan; requires a JRE |
| Nikto | `http://localhost:3001` | HTTP only | Restricted tuning set; requires Perl |
| Nuclei | `http://localhost:3001` | HTTP only | Restricted severities and excluded tags |
| Custom scanner | `http://localhost:3001` | HTTP only | External subprocess (Project #08) |

## 3. nmap

**Purpose.** Local host/port/service discovery. Establishes what is listening on the
authorized port and what service version the host reports. This is the lab's baseline
reachability check.

**Authorized scope.** Loopback host only. Port range is instructor-configurable in
`lab-config.json`; the default is **only** the authorized port 3001. Nothing outside
`allowed_ports` can be scanned, and nothing outside loopback can be scanned.

**Prerequisites.** nmap on `PATH`. On Windows, `winget install nmap.nmap` or
`choco install nmap`. A container image `instrumentisto/nmap` is available as an alternative
(requires a running Docker daemon).

**Command shape.**

```
nmap -sT -sV -Pn -p 3001 --reason -oX <out>.xml localhost
```

| Flag | Meaning | Why it is in scope |
| --- | --- | --- |
| `-sT` | TCP connect scan | Unprivileged; no raw sockets, no root, no privilege escalation |
| `-sV` | Version/service detection | Read-only banner probing |
| `-Pn` | Treat host as up | Loopback is always up; avoids a host-discovery probe |
| `-p 3001` | Port range | Instructor-configurable, loopback-only |
| `--reason` | Annotate why a port is shown | Makes the raw XML self-explaining |
| `-oX <out>.xml` | XML output | Machine-parseable; stored verbatim in `reports/raw/` |

Explicitly **not** used: `-sS`, `-sU`, `-O`, `--script`, `--traceroute`, `-A`. No root
requirement, no OS fingerprinting, no NSE scripts, no UDP scanning.

**Output produced.** An nmap XML file plus stdout/stderr, both stored verbatim under
`reports/raw/nmap/`.

**Parser.** `bcssl/parsers/nmap.py`, reading the `-oX` XML. Ports, states, service names,
versions, and `--reason` text are lifted into normalized findings.

**Severity mapping.** nmap does not assign severities. The lab's mapping is:

| nmap condition | Lab severity |
| --- | --- |
| Open port, version detected | INFO |
| Open port, service identified, no version | LOW |
| Filtered port | INFO |
| Closed port | not emitted as a finding (recorded as context only) |

**Normalization.** Category is `open-port`, `service-version`, or `filtered-port`. The
endpoint is `host:port`. The evidence field holds the exact `<portstate>` / `<service>` XML
excerpt.

**Override.** `--ports X` narrows or widens within the instructor-configured allowlist. A
value outside the allowlist is rejected by the target validator before nmap runs.

## 4. OWASP ZAP

**Purpose.** Application-level assessment of the Juice Shop instance. Baseline mode
enumerates passive indicators plus a small set of low-impact active checks, producing
alert records that map well onto a student report.

**Authorized scope.** `http://localhost:3001` only. Baseline mode only.

**Prerequisites.** A Java runtime (JRE or JDK 11+). ZAP is a Java application; without a
runtime the lab reports `TOOL NOT INSTALLED` and the reason `java not found`. Docker is an
alternative: `ghcr.io/zaproxy/zaproxy:stable` (requires a running Docker daemon).

**Mode.** `--mode baseline|passive`.

- `baseline` (default): passive spider/crawler plus low-impact active checks. This is what
  the lab intends students to use.
- `passive`: crawler only, no active verification at all. Useful on a slow machine, and
  useful for showing a student why a passive scan produces fewer findings.

ZAP does not use "scan" modes that attack the application. The lab never invokes the
fuzzer, the sequencer, or the requester with attack payloads.

**Output produced.** An HTML report and a JSON report, both written under `reports/raw/zap/`.

**Parser.** `bcssl/parsers/zap.py`, reading the JSON report's `alerts` array. Fields used:
`pluginId`, `alert`, `riskcode`, `riskdesc`, `url`, `evidence`, `solution`, plus occurrences
for the affected URL list.

**Severity mapping.**

| ZAP `riskcode` | ZAP `riskdesc` | Lab severity |
| --- | --- | --- |
| 3 | High | HIGH |
| 2 | Medium | MEDIUM |
| 1 | Low | LOW |
| 0 | Informational | INFO |

ZAP does not emit CRITICAL. The lab does not promote a ZAP alert above HIGH.

**Normalization.** Category is `zap-<pluginId>`, so correlation against another tool's
`missing-security-header` will not match - ZAP alerts stay single-tool observations unless
another tool uses the identical fingerprint. Title is `alert`. Description is the
`riskdesc` text. Evidence is the tool's `evidence` field verbatim. Recommendation is
`solution`.

## 5. Nikto

**Purpose.** Web server configuration and hardening assessment. Checks for missing security
headers, cookie flags, server banner leakage, and similar configuration weaknesses.

**Authorized scope.** `http://localhost:3001` only.

**Prerequisites.** **Perl.** Nikto is a Perl script; it will not run without a Perl
interpreter. Docker is an alternative (`docker.io/snikd/...` community images exist but are
not vendored by this lab; use the interpreter route or a vetted internal image).
On Windows, install Perl (Strawberry Perl) and ensure `perl` and `nikto.pl` are on `PATH`.

**Command shape.**

```
nikto -h http://localhost:3001 -Tuning 1237bd -Format json -output <out>.json -nointeractive
```

`-nointeractive` is important: it prevents Nikto from pausing for input, which would hang
the executor until the timeout.

**Tuning set `1237bd` and what it excludes.** The tuning value is pinned deliberately. The
lab's stated intent is that this configuration covers software identification, header and
cookie analysis, and debug-message observation, while leaving out every plugin family that
sends an attack payload or stresses the service.

Nikto's tuning letters map to plugin categories, and that mapping is published by Nikto
itself rather than by this lab. The categories the lab requires to be **excluded**:

| Excluded category | Why it is excluded |
| --- | --- |
| File upload (including upload via PUT/DELETE) | Uploads content to the server |
| Injection and command execution | Sends injection or command payloads |
| Remote file retrieval | Reads server-side files |
| Denial of service | Impacts availability |
| SQL injection | Sends injection payloads |
| Authentication bypass | Attempts to bypass authentication |
| Remote source inclusion | Triggers inclusion behaviour |

The categories the lab requires to be **in scope**: software and technology identification,
response header analysis, cookie flag analysis, and debug/error message analysis. These are
read-only observations of configuration state.

**Instructor verification step - do this before class.** The lab pins `1237bd` and records the
value in every run record and in the report, but it does not ship Nikto's tuning table and it
cannot verify which plugins a given letter resolves to on your machine. Tuning letters also
differ between Nikto versions and distributions. Before teaching from this document:

1. On the lab machine, run `nikto -Tuning help` and read the category list Nikto prints for
   itself.
2. Confirm that the pinned value resolves only to software identification, header, cookie, and
   debug-message plugins, and does not resolve to any category in the excluded table above.
   If it does resolve to an excluded category, stop and set `default_tuning` in
   `config/lab-config.json` to a value that does not.
3. Record the verified value and tell students which value you used, so their write-ups match
   your configuration.

Do not assume the pinned value behaves identically across versions. This is a configuration
check the instructor owns; the lab deliberately does not paper over it.

If an instructor needs a narrower configuration, change `default_tuning` in `lab-config.json`
or pass `--tuning X`; the lab records the tuning value used in the run record and prints it in
the report so a reader can see exactly which configuration was in play for a given result.

**Output produced.** Nikto JSON at the path given to `-output`, plus stdout/stderr, stored
verbatim under `reports/raw/nikto/`.

**Parser.** `bcssl/parsers/nikto.py`, reading the Nikto JSON host record.

**Severity mapping.** Nikto's `OSVDB`/severity hints are inconsistent across plugin
versions, so the lab maps conservatively:

| Nikto severity hint | Lab severity |
| --- | --- |
| Critical / High | HIGH |
| Medium | MEDIUM |
| Low | LOW |
| None / informational | INFO |

The parser never promotes a Nikto item above HIGH, even if an upstream mapping suggests
CRITICAL, because Nikto does not emit a meaningful criticality signal.

**Normalization.** Category is `nikto-<pluginId or osvdb>`. The endpoint is the URL Nikto
tested. Evidence is the verbatim finding message.

## 6. Nuclei

**Purpose.** Template-driven assessment. Nuclei's value here is breadth of known-issue
checks against a specific URL.

**Authorized scope.** `http://localhost:3001` only, safe severities only, rate limited.

**Prerequisites.** Nuclei binary on `PATH`, or Docker image `instrumentisto/nuclei`
(requires a running Docker daemon). Templates must be present locally; the lab passes
`-no-update-templates` so Nuclei never reaches out to the network to fetch templates or
prompt for an update. If templates are missing, Nuclei reports that condition itself and
the lab surfaces it rather than treating it as "no findings".

**Command shape.**

```
nuclei -u http://localhost:3001 \
  -severity info,low,medium,high,critical \
  -etags dos,fuzz,intrusion,headless,bruteforce,brutespray,code \
  -rate-limit 5 -c 5 \
  -no-update-templates -silent -json -o <out>.jsonl
```

| Flag | Meaning | Safety rationale |
| --- | --- | --- |
| `-severity info,low,medium,high,critical` | Severity filter | Includes CRITICAL so that a genuinely critical finding is not hidden |
| `-etags dos,fuzz,intrusion,headless,bruteforce,brutespray,code` | Excluded template tags | Removes denial-of-service, fuzzing, exploitation, headless-browser, and credential-attack template families |
| `-rate-limit 5` | Max 5 requests/second | Keeps load on the local app negligible |
| `-c 5` | Max 5 concurrent templates | Bounds parallelism |
| `-no-update-templates` | No template auto-update | No network fetch, no interactive prompt |
| `-silent` | Findings only on stdout | Cleaner raw capture |
| `-json -o <out>.jsonl` | JSON Lines output | One JSON object per line, parsed line by line |

**Excluded tags, itemised.**

| Tag | Why excluded |
| --- | --- |
| `dos` | Availability-impacting templates |
| `fuzz` | Random input generation, unpredictable load |
| `intrusion` | Templates that attempt exploitation |
| `headless` | Spawns a browser / runtime, unnecessary here |
| `bruteforce` | Credential attack templates |
| `brutespray` | Credential spraying templates |
| `code` | Templates that execute code on the target |

**Override.** `--severities a,b` narrows or widens the severity list. Widen it only to
informational levels; the lab records the exact severity list used in the run record.

**Output produced.** A `.jsonl` file plus stdout/stderr, stored verbatim under
`reports/raw/nuclei/`.

**Parser.** `bcssl/parsers/nuclei.py`, reading JSONL line by line. Uses
`info.severity`, `info.name`, `info.tags`, `type`, `matched-at`, `host`, and
`matcher-name`.

**Severity mapping.**

| Nuclei severity | Lab severity |
| --- | --- |
| critical | CRITICAL |
| high | HIGH |
| medium | MEDIUM |
| low | LOW |
| info | INFO |
| unknown | INFO, with the uncertainty noted in the description |

**Normalization.** Category is `nuclei-<template-id>`, or `nuclei-<primary-tag>` when the
template id is not stable. Endpoint is `matched-at`. Evidence is the matcher's matched
string verbatim.

## 7. Custom scanner (Project #08)

**Purpose.** The lab's own contribution: a Python web security scanner built as a separate,
already-completed project, reused here as an external dependency.

**Location.** `C:\Users\devas\Documents\Cybersecurity\Web-Security-Scanner`

**Hard rules.**

- It is invoked **externally as a subprocess**, using its own interpreter.
- It is **never modified, copied, patched, or rewritten** by this lab. The lab holds no
  write access to that project tree.
- It produces an HTML report, which `bcssl/parsers/custom.py` parses.

**Modules.** `headers`, `paths`, `injection`. Select with `--modules M`. The default set is
all three.

| Module | What it checks | Typical severity ceiling it produces |
| --- | --- | --- |
| `headers` | Presence and correctness of security response headers | medium |
| `paths` | Presence of common exposed paths and sensitive files | medium |
| `injection` | Response-level checks for reflected/suspicious input handling | high |

The `injection` module is a passive reflection and response-behaviour check. It does not
perform extraction, and the lab does not configure it to retrieve data.

**Severity vocabulary.** `info`, `low`, `medium`, `high`, `critical`. The parser lower-cases
the source severity and maps it to the lab vocabulary:

| Custom scanner severity | Lab severity |
| --- | --- |
| critical | CRITICAL |
| high | HIGH |
| medium | MEDIUM |
| low | LOW |
| info | INFO |

**Prerequisites.** The external project must exist at the configured `project_root`, and its
own virtual environment must be present with its dependencies installed. The lab invokes the
interpreter it finds there (falling back to `python` on `PATH` only if configured to do so)
and passes the target URL plus the selected modules. If the project root is missing, the lab
reports `TOOL NOT INSTALLED` with the reason `custom scanner project root not found` and the
configured path. It does not create the project, clone it, or substitute a different
scanner.

**Output produced.** An HTML report from the external project, written to a path the lab
passes in and then stored verbatim under `reports/raw/custom-scanner/`.

**Parser.** `bcssl/parsers/custom.py`, reading the external scanner's HTML report. It extracts
the finding rows (severity, title, endpoint/URL, description, evidence) and discards the
report's styling and navigation.

**Normalization.** Category is `custom-<module>`. Severity comes from the scanner's own
vocabulary. Endpoint is the URL the finding refers to. Evidence is the scanner's verbatim
detail text.

## 8. Safe and unsafe settings reference

The lab exists to make the difference between a safe, authorized configuration and an unsafe
one explicit. This table is the reference for both students and instructors. The **unsafe**
column is documentation of what the lab deliberately does not do.

| Tool | Setting | SAFE - used by this lab | UNSAFE - never used |
| --- | --- | --- | --- |
| nmap | Scan type | `-sT` (unprivileged TCP connect) | `-sS`, `-sU`, `-O` (requires root, fingerprinting) |
| nmap | Scripts | none | `--script` / NSE (arbitrary script execution against target) |
| nmap | Ports | `-p 3001` from `allowed_ports` | `-p-`, `-p 1-65535` |
| nmap | Target | `localhost` | any routable host or IP |
| ZAP | Mode | `baseline`, `passive` | any attack/fuzzer/sequencer mode |
| Nikto | Tuning | `1237bd` | a tuning set including `0`, `2`, `4`, `6`, `7`, `8`, `9` |
| Nikto | Interaction | `-nointeractive` | interactive prompting (hangs the executor) |
| Nikto | Target | `http://localhost:3001` | any external host |
| Nuclei | Severities | `info,low,medium,high,critical` | severity list outside the documented five |
| Nuclei | Tags | `-etags dos,fuzz,intrusion,headless,bruteforce,brutespray,code` | enabling `dos`, `fuzz`, `bruteforce`, `intrusion`, `headless`, `code` |
| Nuclei | Rate | `-rate-limit 5 -c 5` | unlimited concurrency |
| Nuclei | Templates | `-no-update-templates` | network template fetch during a lab run |
| Custom scanner | Modules | `headers`, `paths`, `injection` | any module that extracts or exfiltrates data |
| Custom scanner | Project tree | read-only, external | modifying Project #08 from inside the lab |
| Any | Shell | `shell=False`, argv list | shell string concatenation of user input |
| Any | Target | loopback allowlist only | public websites, external domains, arbitrary IPs |

## 9. Installation hints

### 9.1 nmap

| Platform | Command |
| --- | --- |
| Windows (winget) | `winget install nmap.nmap` |
| Windows (choco) | `choco install nmap -y` |
| macOS (Homebrew) | `brew install nmap` |
| Debian/Ubuntu | `sudo apt install nmap` |
| Docker alternative | `docker pull instrumentisto/nmap` |
| Verify | `nmap --version` |

After a Windows install, open a new terminal so `PATH` picks up the change, then re-run
`python -m bcssl preflight`.

### 9.2 OWASP ZAP

| Platform | Command / note |
| --- | --- |
| Prerequisite | Java runtime: `java -version` must succeed (JRE or JDK 11 or newer) |
| Windows (winget) | `winget install zaproxy.zap` |
| Windows (choco) | `choco install zaproxy -y` |
| macOS (Homebrew) | `brew install --cask zaproxy` |
| Linux (apt) | `sudo apt install zaproxy` |
| Docker alternative | `docker pull ghcr.io/zaproxy/zaproxy:stable` |
| Verify | `zap.sh -version` on Linux/macOS, `zap.bat -version` on Windows, or `java -jar zap.jar -version` |

If ZAP is installed but `java` is not on `PATH`, the lab reports `TOOL NOT INSTALLED` with
reason `java not found`. Fixing `PATH` is the remedy; the lab does not work around it.

### 9.3 Nikto

| Platform | Command / note |
| --- | --- |
| Prerequisite | **Perl**: `perl -v` must succeed. Windows: install Strawberry Perl |
| Source | Nikto is a Perl script (`nikto.pl`); place it on `PATH` or point the lab at it |
| macOS | `brew install nikto` |
| Debian/Ubuntu | `sudo apt install nikto` |
| Verify | `nikto -Version` |
| Docker alternative | community images exist but are not vendored by this lab; prefer the interpreter route |

On Windows, add the directory containing `nikto.pl` to `PATH`, and make sure `perl` is
resolvable from the same shell that runs `python -m bcssl`.

### 9.4 Nuclei

| Platform | Command / note |
| --- | --- |
| Windows (winget) | `winget install nuclei` if a package exists in your sources; otherwise `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| macOS | `brew install nuclei` |
| Linux (apt) | `sudo apt install nuclei` |
| Docker alternative | `docker pull instrumentisto/nuclei` |
| Verify | `nuclei -version` |
| Templates | run `nuclei -update-templates` **once, as a setup step, with network access**. During lab runs the lab passes `-no-update-templates`, so no update prompt or network fetch occurs |

### 9.5 Docker prerequisites

Any of the four tools can be supplied through Docker instead of a native install. That path
requires a **running Docker daemon**. If Docker is installed but not started, the lab reports
`TOOL NOT INSTALLED` with reason `docker daemon not reachable`. Start Docker Desktop (or
`systemctl start docker` on Linux) and re-run `python -m bcssl preflight`.

## 10. Verifying the install

```
python -m bcssl preflight
python -m bcssl preflight --json
```

Expected healthy output lists each tool with a state and, for available tools, the version
string captured from the `--version` probe. A tool reported `TOOL NOT INSTALLED` is a normal,
honest state and does not block the rest of the lab. See `docs/troubleshooting.md` for
symptom-by-symptom remedies.