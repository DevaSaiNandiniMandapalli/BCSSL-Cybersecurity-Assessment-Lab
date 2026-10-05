# BCSSL Cybersecurity Assessment Lab - Instructor Guide

## 1. What this document covers

How to configure the lab for a classroom, verify the machines before students start, grade
submissions, safely widen the scope for a specific exercise, and reset progress.

## 2. `config/lab-config.json` is the single source of truth

Every scope and tool setting the lab uses comes from `config/lab-config.json`. The lab reads
it at start-up and never writes to it. Do not fork the code to change scope; change the
config.

A representative shape (illustrative structure - your file may nest keys differently, so
check the shipped file before editing):

```json
{
  "lab": {
    "name": "BCSSL Cybersecurity Assessment Lab",
    "target": {
      "url": "http://localhost:3001",
      "allowed_hosts": ["localhost", "127.0.0.1", "::1"],
      "allowed_ports": [3001],
      "allowed_schemes": ["http", "https"],
      "require_loopback_resolution": true
    }
  },
  "tools": {
    "nmap":      { "enabled": true, "timeout": 300, "default_ports": "3001" },
    "zap":       { "enabled": true, "timeout": 900, "default_mode": "baseline" },
    "nikto":     { "enabled": true, "timeout": 600, "default_tuning": "1237bd" },
    "nuclei":    { "enabled": true, "timeout": 600, "severities": ["info","low","medium","high","critical"],
                   "excluded_tags": ["dos","fuzz","intrusion","headless","bruteforce","brutespray","code"],
                   "rate_limit": 5, "concurrency": 5 },
    "custom-scanner": {
      "enabled": true,
      "timeout": 300,
      "project_root": "C:\\Users\\devas\\Documents\\Cybersecurity\\Web-Security-Scanner",
      "default_modules": ["headers", "paths", "injection"]
    }
  }
}
```

### 2.1 Target keys

| Key | Meaning | Instructor guidance |
| --- | --- | --- |
| `target.url` | Default target when `--url` is omitted | Keep as `http://localhost:3001`. |
| `allowed_hosts` | Names accepted before resolution | Default `localhost`, `127.0.0.1`, `::1`. Adding a name here still requires it to resolve to loopback. |
| `allowed_ports` | Ports accepted | Default `[3001]`. See section 5 before changing. |
| `allowed_schemes` | URL schemes | Keep `["http", "https"]`. Do not add `file`, `ftp`, `gopher`, or `data`. |
| `require_loopback_resolution` | Enforce post-resolution loopback check | Leave `true`. Setting it to `false` disables the lab's most important safety property. |

### 2.2 Per-tool keys

| Tool | Key | Effect |
| --- | --- | --- |
| nmap | `timeout` | Seconds before the executor kills the process. Default is generous because version detection can be slow. |
| nmap | `default_ports` | Port argument used when `--ports` is absent. Must be a subset of `allowed_ports`. |
| zap | `timeout` | Baseline scanning of a SPA takes a while. Raise this rather than letting baseline runs time out. |
| zap | `default_mode` | `baseline` or `passive`. |
| nikto | `timeout` | Nikto is slow. |
| nikto | `default_tuning` | Do not ship this unchanged without verifying it. See the check below. |
| nuclei | `severities` | The severity list passed to `-severity`. |
| nuclei | `excluded_tags` | Passed to `-etags`. Do not remove any of the seven default tags. |
| nuclei | `rate_limit` / `concurrency` | Passed to `-rate-limit` / `-c`. |
| custom-scanner | `project_root` | Absolute path to Project #08. The lab never writes here. |
| custom-scanner | `default_modules` | `headers`, `paths`, `injection`. |

### 2.3 Verify the Nikto tuning value before class

Nikto's tuning letters map to plugin categories, and that mapping comes from Nikto itself. It
also varies between Nikto versions and distributions. The lab pins `default_tuning` and records
the value in every run record, but it does not ship Nikto's tuning table and cannot verify
which plugins a letter resolves to on your machine.

Before you teach from this lab, on the lab machine:

1. Run `nikto -Tuning help` and read the category list Nikto prints for itself.
2. Confirm the configured value resolves only to software identification, header, cookie, and
   debug-message plugins.
3. Confirm it does **not** resolve to file upload, injection or command execution, remote file
   retrieval, denial of service, SQL injection, authentication bypass, or remote source
   inclusion.
4. If it does resolve to an excluded category, stop. Set `default_tuning` to a value that does
   not, then re-run the check.
5. Record the verified value and tell students which value you used.

This check is yours to perform. The lab deliberately reports the tuning value it used rather
than asserting that a given value is safe on every Nikto build.

### 2.4 Per-tool metadata

`tools/<tool>/tool.json` holds the executable name, the Docker image name, the version probe
arguments, and the install hints surfaced in `preflight` output. Edit these when you install a
tool under a different name or path, so students get accurate guidance rather than a bare
"not installed".

## 3. Preflighting a classroom

Do this on **every** machine before students start. It converts a mid-lab mystery into a
two-minute fix.

```
python -m bcssl preflight
python -m bcssl validate-target --url http://localhost:3001
```

Checklist per machine:

1. `python -m bcssl version` succeeds.
2. `validate-target` reports `ok` for `http://localhost:3001`.
3. `validate-target` **refuses** a non-loopback target. Confirm the refusal happens, so
   students can see the boundary working. A machine that does not refuse is a lab fault.
4. `preflight` output is captured to a file and distributed to students, so nobody spends the
   first hour discovering what is missing.
5. Juice Shop is reachable in a browser on `http://localhost:3001`.
6. If you are using Docker-supplied tools, the Docker daemon is running.
7. If you are using the custom scanner, its project root exists and its virtual environment is
   usable.

Record preflight output per machine in `state/` or wherever your course keeps setup records,
and include it in the distribution. Students are explicitly graded on reporting
`TOOL NOT INSTALLED` honestly, so knowing the baseline in advance is part of the exercise.

## 4. Grading

### 4.1 Graded artifacts

| Artifact | Where | What it demonstrates |
| --- | --- | --- |
| Preflight record | `state/` or the student's written record | Honest tool-availability reporting |
| Raw tool output | `reports/raw/` | The tool actually ran; unmodified |
| Normalized findings | `reports/normalized/` | Understanding of the ten-key schema |
| Evidence records | `evidence/<tool>/` | Evidence discipline and integrity awareness |
| Correlation result | Consolidated report | Correct multi-tool versus single-tool reasoning |
| Final report | `reports/final/` | Written analysis, severity justification, stated limitations |
| Exercise progress | `state/` | Acknowledged evidence, answered questions, ticked checklist |

### 4.2 Grade the reasoning, not the tool count

A student with zero tools installed who correctly records `TOOL NOT INSTALLED`, explains what
evidence each missing tool would have produced, and writes a defensible scope statement has
done more of this lab than a student who installed everything and copied raw output without
interpretation.

In particular:

- **Do not reward a larger finding count.** The lab must never fabricate results, and neither
  should a report.
- **Reward correct severity mapping.** ZAP 3 is HIGH, not CRITICAL. Nikto does not produce
  CRITICAL. If a student promotes a ZAP High to Critical, that is an error worth marking.
- **Reward honest correlation.** A student who says "only Nikto reported this, so it is a
  single-tool observation" has understood something important. A student who claims
  multi-tool confirmation on a fingerprint only one tool reported has not, regardless of how
  many findings they list.
- **Reward stated limitations.** A report with a limitations section is stronger than one
  without, even if shorter.
- **Mark evidence acknowledgement.** If a student's progress shows an acknowledged evidence
  file that does not exist, treat it as an integrity problem, not a clerical one.

### 4.3 Common student errors to look for

| Error | How to spot | Weight |
| --- | --- | --- |
| Over-claiming correlation | Multi-tool confirmation on a one-tool fingerprint | High |
| Invented findings | A finding with no matching raw excerpt or evidence record | High |
| Ignoring `TOOL NOT INSTALLED` | A report implying a tool ran when it did not | High |
| Severity inflation | ZAP High presented as Critical | Medium |
| Missing evidence citations | Findings quoted with no `evidence/<tool>/` path or hash | Medium |
| No limitations section | Report reads as a complete assessment | Medium |
| Misreading zero findings | "No issues found" when the run actually failed | Medium |

### 4.4 Red flags for academic integrity

- Evidence hashes that do not match the raw files.
- Answers whose wording matches a search engine verbatim rather than the student's own.
- A report covering a tool that preflight said was not installed.
- Timestamps on evidence older than the run index entry for that run.

## 5. Expanding the allowlist safely

Sometimes an exercise needs a second local service - for example, a student-hosted app on
`http://localhost:8000` instead of Juice Shop on 3001. That is a legitimate reason to widen the
allowlist. These are the rules.

**Permitted:**

- Adding **loopback** ports to `allowed_ports`, e.g. `[3001, 8000]`.
- Adding `127.0.0.1` or `::1` to `allowed_hosts` (they are already there by default).
- Pointing `target.url` at a different loopback port for a specific exercise.

**Never permitted, in any configuration:**

- Adding a routable host name or IP address to `allowed_hosts`.
- Setting `require_loopback_resolution` to `false`.
- Adding a scheme other than `http` or `https`.
- Adding ports to nmap's `default_ports` that are outside `allowed_ports`.

Why the resolution check matters: a hostname is just a string. If a name is allowed and it
resolves to a routable address, the lab would scan a machine that is not the student. The
post-resolution loopback check is what makes the allowlist meaningful. Leave it on.

Recommended workflow for a widened exercise:

1. Change `config/lab-config.json` and save the previous version.
2. Run `python -m bcssl validate-target --url http://localhost:<newport>` and confirm `ok`.
3. Run it again against a non-loopback URL and confirm the refusal.
4. Announce the widened scope in writing before students run anything.
5. Restore the previous config afterwards.

## 6. Resetting student progress

Student progress and the run index live under `state/`, which is gitignored.

Reset all progress for all students:

```
# stop any running web dashboard first, then remove the state directory
rmdir /s /q state
```

PowerShell equivalent:

```powershell
Remove-Item -Recurse -Force state
```

The lab recreates `state/` on the next command that needs it.

Reset a single student: remove their entry from the progress store in `state/` rather than
deleting the whole directory, so the run index survives.

Reset derived artifacts while keeping progress and raw evidence:

```
# reports/normalized and reports/final are fully derived and can be rebuilt
rmdir /s /q reports\normalized
rmdir /s /q reports\final
```

`reports/raw/` and `evidence/` should **not** be deleted casually - they are the chain of
custody. If you must reset them, say so explicitly and have students re-run their tools,
because acknowledged evidence references will no longer resolve.

## 7. Running the lab as an instructor

The same CLI is available to you. Useful differences:

- `--json` on every command, for scripting across a classroom.
- `report --format html --open` to display results during a walkthrough.
- `web --port <n>` if `8765` collides with something on the classroom machine.
- `run-all --tools a,b,c` to demo a subset, so students watching do not have to wait for the
  slow tool.

When demonstrating, it is worth showing the refusal path on purpose. Refusing a non-loopback
target in front of the class is the fastest way to make the point that scope is enforced by
the tool, not by good intentions.

## 8. Timing guidance

Observed behaviour rather than fixed guarantees:

| Stage | Typical expectation |
| --- | --- |
| `preflight` | Seconds. |
| `validate-target` | Sub-second, plus one name resolution. |
| nmap on one port with `-sV` | Fast; version detection can add seconds. |
| Nikto | The slowest of the four. Minutes, not seconds. |
| ZAP baseline against a SPA | The longest single step. Size the timeout accordingly. |
| Nuclei with the lab's severity list | Bounded by `-rate-limit 5`; can be minutes. |
| Custom scanner | Depends entirely on Project #08's own timing. |

If your session is short, prefer passive ZAP (`--mode passive`), a narrowed Nuclei severity
list, and running Nikto as a demonstration rather than a hands-on step. Record the change in
configuration when you do, so students know what they did and did not run.

## 9. Acceptance checks before a session

- [ ] `python -m bcssl version` works on every machine.
- [ ] `validate-target` accepts `http://localhost:3001`.
- [ ] `validate-target` refuses a non-loopback target, with a reason and a code.
- [ ] `preflight` output captured and distributed.
- [ ] Nikto `default_tuning` verified against `nikto -Tuning help` on the installed version.
- [ ] Juice Shop reachable on `http://localhost:3001`.
- [ ] Custom scanner project root and interpreter confirmed, if in use.
- [ ] Timeouts in `lab-config.json` sized for your session.
- [ ] Student code of conduct issued in writing, and signed if your course requires it.
- [ ] Submission format and deadline stated.
- [ ] `state/` reset so students start from zero.