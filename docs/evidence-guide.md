# BCSSL Cybersecurity Assessment Lab - Evidence Guide

## 1. Principle

Evidence in this lab is anything a third party could not have produced without access to the
machine the scan ran on. That means: the raw tool output, the verbatim excerpt inside each
evidence record, and the integrity hash of the raw file. Everything else - normalized
findings, correlation results, the consolidated report - is **derived** and is labelled as
such.

Raw is never edited. Derived can be rebuilt at any time.

## 2. Directory layout

```
BCSSL-Cybersecurity-Assessment-Lab/
  reports/
    raw/
      nmap/            <- nmap -oX XML + captured stdout/stderr, verbatim
      zap/             <- ZAP HTML report + ZAP JSON report + stdout/stderr
      nikto/           <- Nikto JSON (-output) + stdout/stderr
      nuclei/          <- Nuclei JSONL (-o) + stdout/stderr
      custom-scanner/  <- Project #08 HTML report + stdout/stderr
    normalized/
      findings-nmap.json
      findings-zap.json
      findings-nikto.json
      findings-nuclei.json
      findings-custom-scanner.json
    final/
      assessment.html
      assessment.json
      assessment.md
  evidence/
    nmap/              <- one record per finding, plus the run's hash manifest
    zap/
    nikto/
    nuclei/
    custom-scanner/
  state/
    progress.json      <- student acknowledgements, answers, checklist ticks
    runs.json          <- run index: tool, start/end, duration, exit code, status
```

### 2.1 `reports/raw/`

- Written by `bcssl/executor.py` from captured stdout/stderr and by the tool itself
  (`-oX`, `-o`, `-output`).
- **Append-only.** Each run writes new timestamped artifacts; it does not overwrite.
- Never hand-edited. If a tool produces garbage output, the garbage is preserved as-is and
  the parser's failure is recorded separately. A human fixing a parse bug fixes the parser,
  not the raw file.
- Deleting `reports/raw/` destroys chain of custody. If you clear it, acknowledged evidence
  references stop resolving and prior submissions become unverifiable.

### 2.2 `reports/normalized/`

- `findings-<tool>.json`: the ten-key normalized schema, one array per tool.
- Fully derived from `reports/raw/`. Safe to delete and regenerate.
- Regenerate with `python -m bcssl collect`.

Ten keys, always all of them:

```json
{
  "tool": "nikto",
  "category": "nikto-9996",
  "severity": "LOW",
  "title": "...",
  "description": "...",
  "target": "http://localhost:3001",
  "endpoint": "http://localhost:3001/",
  "evidence": "exact excerpt copied from the raw tool output",
  "recommendation": "...",
  "timestamp": "2026-01-01T00:00:00Z"
}
```

Severity vocabulary: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`.

### 2.3 `reports/final/`

- The consolidated report in HTML, JSON, and Markdown.
- Fully derived. Delete freely; `python -m bcssl report --format html` rebuilds it.
- Must state which tools contributed findings and which did not run, and must mark
  multi-tool versus single-tool status per finding.

### 2.4 `evidence/<tool>/`

One record per finding, produced by `bcssl/evidence.py`. Contains:

| Field | Meaning |
| --- | --- |
| `tool` | Which tool produced the underlying raw output |
| `timestamp` | When the finding was normalized |
| `target` | Authorized target for the run |
| `endpoint` | The specific endpoint the finding refers to |
| `raw_excerpt` | The exact text lifted from the raw output, unmodified |
| `raw_file` | Path to the raw output file the excerpt came from |
| `sha256` | SHA-256 of that raw output file, for integrity |
| `finding` | The full normalized finding object |

Plus a per-run hash manifest listing every raw file from that run with its sha256, so a run
can be verified as a unit rather than file by file.

### 2.5 `state/`

- `progress.json`: student acknowledgements, answers, checklist ticks.
- `runs.json`: run index - tool, start and end time, duration, exit code, status
  (`ok`, `TOOL NOT INSTALLED`, `TARGET REFUSED`, `TIMEOUT`, `PARSE FAILURE`).
- Gitignored, because it is per-student rather than part of the deliverable.
- **Not evidence.** State files record what a student claimed; evidence files record what a
  tool observed. Never cite `state/` as evidence of a finding.

## 3. What counts as acceptable evidence

| Artifact | Acceptable? | Why |
| --- | --- | --- |
| Raw tool output captured by the executor | Yes | Verbatim, hashable, produced by the tool itself |
| A native tool report (`-oX`, `-o`, `-output`, ZAP HTML/JSON) | Yes | Written by the tool, stored unmodified |
| An evidence record with a matching sha256 | Yes | It points back to raw output that can be verified |
| A raw excerpt that can be located in the raw file | Yes | Traceable end to end |
| A normalized finding with no evidence record | No | Unverifiable |
| A finding copied from a blog post | No | No provenance |
| A screenshot with no raw output behind it | No | Not verifiable, not hashable |
| Output from a different target than the authorized one | No | Out of scope |
| A file the student hand-wrote into `evidence/` | No | Fabricated |
| `state/progress.json` | No | Records a claim, not an observation |
| "No findings" with no raw output file | No | Cannot distinguish clean result from failed run |

The test: **could someone else, given only your submission and the lab, trace each finding
back to untouched tool output?** If not, the evidence is incomplete.

## 4. The sha256 integrity field

Every evidence record carries the SHA-256 of the raw output file it was drawn from.

What it establishes:

- The raw file has not been altered since the run. Any edit changes the hash.
- The evidence record and the raw file refer to the same content.
- Two submissions of the same run can be compared hash to hash.

What it does not establish:

- That the raw output is truthful about the target. It proves the bytes are unaltered since
  capture, nothing about the target's actual state. Only the tool establishes that.
- Which tool produced the bytes. That comes from `raw_file` and the run index.
- Anything at all about a file that was never hashed. A record with no `sha256` field is
  incomplete evidence.

Verify a record:

```
# Windows PowerShell
Get-FileHash -Algorithm SHA256 reports\raw\nikto\<raw-file>.json
```

```
# Linux / macOS
sha256sum reports/raw/nikto/<raw-file>.json
```

Compare against the `sha256` value in the evidence record. A mismatch means the raw file
changed after the run and the submission is not verifiable.

## 5. Naming and timestamps

- Raw artifacts are written under `reports/raw/<tool>/` with a timestamped filename so that
  successive runs do not collide and ordering is obvious from the name.
- Timestamps in evidence records and the run index are ISO 8601, UTC, so records from
  different machines sort correctly.
- The `timestamp` on a normalized finding is when the finding was normalized, not when the
  tool observed it. Use the run index `runs.json` for start and end times, and say which one
  you are citing.
- Timestamps are part of the record, not decoration. A raw output file that is newer than its
  evidence record, or older than the run that supposedly produced it, is an integrity problem
  and should be raised with the student rather than quietly corrected.

## 6. Citing evidence in a report

Every finding in a written report should carry a citation a reviewer can follow without
asking you a question. The minimum is the evidence path plus the hash.

```
[Finding] Missing Strict-Transport-Security response header
  Severity : MEDIUM
  Endpoint : http://localhost:3001/
  Evidence : evidence/nikto/2026-01-01T09-14-22Z-0007-absence-of-hsts.json
  Raw file : reports/raw/nikto/nikto-2026-01-01T09-14-22Z.json
  SHA-256  : <value copied from the evidence record>
  Status   : Single-tool observation (reported only by Nikto)
```

Three things a citation must convey:

1. **Where the raw output is.** The `evidence/` path and the `reports/raw/` path.
2. **That it is unaltered.** The sha256, and ideally a note that it was recomputed and
   matched.
3. **Corroboration status.** Whether one tool or several reported this fingerprint. Do not
   claim multi-tool confirmation for a finding only one tool reported.

## 7. Chain of custody for a student submission

A submission is a package: the evidence directories, the normalized findings, the report, and
a manifest. Build it in this order so custody is never ambiguous.

1. **Freeze the run.** Do not re-run tools after you start assembling the submission.
   Re-running produces new timestamps and new hashes, which invalidates hashes you already
   wrote into your report.
2. **Collect.** `python -m bcssl collect` regenerates `reports/normalized/` from
   `reports/raw/`. It changes nothing in `reports/raw/`.
3. **Report.** `python -m bcssl report --format html` (and `md`, `json`) writes
   `reports/final/`.
4. **Verify.** Recompute the sha256 of every raw file referenced in your evidence records and
   confirm each matches. Do this before packaging, not after.
5. **Package.** Include `reports/raw/`, `reports/normalized/`, `reports/final/`, and
   `evidence/`. Include `state/progress.json` if your instructor wants your acknowledgements,
   but do not present it as finding evidence.
6. **Manifest.** List every file in the submission with its sha256 and size, and state how
   many evidence records exist. A manifest lets a reviewer verify the package without
   trusting the submitter's word.
7. **Declare.** State in the submission which tools ran, which were not installed, and which
   findings are single-tool versus multi-tool. An undeclared gap in coverage is the most
   common reason a submission gets returned.

Expectations in short: raw output unedited, hashes recomputed and matching, every finding
traceable to a raw excerpt, progress acknowledged by you rather than inferred from a run, and
coverage gaps declared rather than filled with guesses.

## 8. Evidence request template

Use this when asking a student for a specific piece of evidence. It forces the request to be
answerable and forces the answer to be verifiable.

```
EVIDENCE REQUEST
----------------
Request ID     : <your reference>
Exercise       : <exercise id, e.g. ex09>
Raised by      : <name>
Date raised    : <YYYY-MM-DD>
Due            : <YYYY-MM-DD>

WHAT IS REQUESTED
  <Exactly one finding, or one specific behaviour. Not "more evidence".>

WHY IT IS REQUESTED
  <The specific gap: a finding with no evidence record, a severity you could not
   justify from the raw output, a correlation claim not supported by the contributing
   tools, or a tool availability state you did not report.>

WHERE TO LOOK
  Tool        : <nmap | zap | nikto | nuclei | custom-scanner>
  Raw output  : <path under reports/raw/, or "not present - explain why">
  Evidence    : <expected path under evidence/<tool>/>

WHAT AN ACCEPTABLE RESPONSE LOOKS LIKE
  - The evidence record exists and its sha256 matches a recomputed hash of the raw file.
  - The raw_excerpt is locatable in the named raw file, byte for byte.
  - If the tool did not run, a written explanation of why (TOOL NOT INSTALLED, target
    refused, timeout) with the lab output that proves it. A missing tool is an acceptable
    answer; an invented record is not.
  - If the claim cannot be supported, a correction withdrawing it.

STUDENT RESPONSE
  Finding / claim : <what they are submitting>
  Evidence path   : <path>
  SHA-256         : <hash, recomputed>
  Tool status     : <ran / TOOL NOT INSTALLED / TARGET REFUSED / TIMEOUT>
  Note            : <one line on anything the evidence does not show>

VERDICT
  Accepted / Rejected - <reason>            Reviewer: <name>   Date: <YYYY-MM-DD>
```

## 9. Integrity failures and what to do about them

| Observation | Likely cause | Action |
| --- | --- | --- |
| Evidence record's sha256 does not match the raw file | Raw file edited after the run | Treat as an integrity failure. Do not repair the record to match. |
| Evidence record exists with no raw file | Raw output deleted, or record fabricated | Ask which. A fabricated record ends the submission. |
| A finding's `evidence` text is absent from the raw file | Excerpt paraphrased or invented | Reject the finding. |
| Raw output is newer than the evidence record | Re-run after assembling | Re-freeze and re-verify. |
| Findings exist for a tool preflight reported as missing | Fabricated results | Escalate. This is the most serious failure mode in the lab. |
| `state/progress.json` acknowledges evidence that does not exist | Progress recorded against nothing | Escalate as an integrity problem, not a clerical one. |

Never correct an integrity problem silently. Record it, raise it, and let the process handle
it. A report that quietly patches a hash is worse than an incomplete report.