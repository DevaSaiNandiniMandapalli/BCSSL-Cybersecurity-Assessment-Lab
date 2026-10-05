# BCSSL Cybersecurity Assessment Lab - Student Guide

## 1. What this lab is

You will assess one web application running on your own machine: **OWASP Juice Shop** at
`http://localhost:3001`. You will use several industry-standard security tools against it,
normalize what they report into one schema, correlate their findings, gather evidence, and
produce a defensible report.

What this lab will never do is test anything else. The lab is configured to refuse any target
that is not loopback, and it will tell you that it refused. That refusal is a designed
feature, not a bug - part of your assessment is understanding why scoping matters.

## 2. Code of conduct

Read this before you run anything.

1. **Authorized target only.** The only permitted target is `http://localhost:3001`. This
   applies to the lab's tools and to anything you run by hand.
2. **No external targets.** Do not point the lab, or any tool in the lab, at a public website,
   an external domain, or an arbitrary IP address. Not as a test, not as a comparison, not as
   a "quick check".
3. **No destructive activity.** No denial-of-service testing, no exploitation, no data
   extraction, no credential theft, no persistence, no privilege escalation. The lab's tool
   configurations already exclude these categories; do not work around that configuration.
4. **No credential attacks.** No brute force, no credential spraying, no password guessing -
   including against Juice Shop's default accounts.
5. **The data is training data.** Anything Juice Shop returns is synthetic and intentionally
   broken. Do not reuse, publish, or redistribute it.
6. **Leave the machine clean.** Do not install software or change firewall settings without
   asking your instructor.

Violating these rules ends your participation in the lab, regardless of your technical
result.

## 3. Setting up

You need:

- Python 3.10 or newer, with the lab's dependencies installed (`pip install -e .` in the
  project root, or `pip install -r requirements.txt` if your instructor provided one).
- OWASP Juice Shop running locally, listening on port 3001.

Confirm both before you start.

```
python -m bcssl version
python -m bcssl validate-target --url http://localhost:3001
```

`validate-target` should report `ok`. If it reports a refusal, stop and read
`docs/troubleshooting.md`.

Then check which tools you actually have:

```
python -m bcssl preflight
```

Some tools may report `TOOL NOT INSTALLED`. That is expected and honest. It means the tool
is not on your machine, so the lab will not run it and will not invent results for it. You
can still complete every exercise; a missing tool is something you record, not something you
work around by guessing.

## 4. Running the tools

Run one tool at a time so you can read its output and understand what it did.

```
python -m bcssl run nmap
python -m bcssl run zap --mode baseline
python -m bcssl run nikto
python -m bcssl run nuclei --severities info,low,medium,high,critical
python -m bcssl run custom-scanner --modules headers,paths,injection
```

Useful flags:

| Flag | Applies to | Meaning |
| --- | --- | --- |
| `--url URL` | all | Override the target. Only loopback targets are accepted. |
| `--timeout N` | all | Per-tool timeout in seconds. |
| `--json` | all | Machine-readable output. |
| `--ports X` | nmap | Port list within the instructor allowlist. |
| `--mode baseline\|passive` | zap | Baseline (passive + low-impact active) or passive only. |
| `--tuning X` | nikto | Nikto tuning set. |
| `--severities a,b` | nuclei | Severity list. |
| `--modules M` | custom-scanner | `headers`, `paths`, `injection`. |

Run everything at once, if you prefer:

```
python -m bcssl run-all
python -m bcssl run-all --tools nmap,nikto --json
```

Then see what you have:

```
python -m bcssl collect
python -m bcssl status
```

Finally build the report:

```
python -m bcssl report --format md
python -m bcssl report --format html --output reports/final/assessment.html --open
python -m bcssl report --format json --output reports/final/assessment.json
```

An optional local dashboard shows the same data in a browser:

```
python -m bcssl web --open
```

It serves on `http://127.0.0.1:8765` by default and is bound to loopback.

## 5. How progress actually works

**Read this carefully, because it is the most misunderstood part of the lab.**

Running a tool does **not** complete an exercise. Ever. Your progress is recorded only when
you, as the student, do three things:

1. **Acknowledge evidence.** You point at a specific evidence file that the run produced and
   you say you have read it and understood it.
2. **Answer the questions.** Every exercise has questions. Short answers are fine. Copying an
   answer you did not reason out is not.
3. **Tick the checklist item.** The exercise has a completion checklist. Each item is ticked
   by you, not by the tool.

Each exercise defines three questions (`q1`, `q2`, `q3`) and four checklist items (`c1` to
`c4`). The commands:

```
python -m bcssl lab list
python -m bcssl lab show ex01
python -m bcssl lab ack ex01 --check c1 --answer q1="validate-target confirmed scheme http, host localhost, port 3001 ..."
python -m bcssl lab ack ex01 --check c2 --answer q2="It returned 200 ..."
python -m bcssl lab ack ex01 --check c3 --check c4 --answer q3="I would start Juice Shop and keep both outputs ..."
python -m bcssl lab progress
```

`ack` takes the exercise id, one or more `--check` checklist item ids, and one or more
`--answer qid=text` pairs. It is the only command that changes your progress.

If your tool was not installed and therefore produced no evidence, you cannot acknowledge
evidence that does not exist. Record that fact in your report and ask your instructor whether
the exercise is to be completed differently. Do not create an evidence file yourself.

## 6. The twelve exercises

Exercises are ordered. Each builds on the last, and each has an `exercise.json` (metadata,
questions, checklist) and an `exercise.md` (the brief) under `lab/<level>/exNN/`.

Each exercise has three questions (`q1` to `q3`), four checklist items (`c1` to `c4`), and an
evidence requirement. `python -m bcssl lab show <id>` prints the full brief for any exercise,
so that command is always the authority - this section is only the map.

### Beginner

**ex01 - HTTP and Target Validation** (tool: lab-cli)
- Command: `python -m bcssl validate-target --url http://localhost:3001`
- Confirm in a browser that Juice Shop actually answers, then record the scheme, resolved
  host, port and HTTP status code from the tool's own output.
- q1: which URL components did the report confirm, and why is the port checked separately?
- q2: what status code came back, and what does that single value tell you about the target?
- q3: if the target is unreachable, what is the correct response, and why record the failure
  rather than retry until it succeeds?

**ex02 - Nmap Local Service Discovery** (tool: nmap)
- Command: `python -m bcssl run nmap`
- Read the raw `-oX` XML yourself; do not only read the normalized summary.
- q1: what state did 3001/tcp report, which service was identified, and what banner evidence
  supports it?
- q2: why `-sT` with `-Pn` instead of a SYN scan with host discovery?
- q3: how would your findings change if 3001/tcp had been closed or filtered?

**ex03 - Security Headers and HTTP Analysis** (tool: custom-scanner, headers module)
- Command: `python -m bcssl run custom-scanner --modules headers`
- q1: which HTTP security headers were flagged, and what is the practical risk of each being
  absent or wrong?
- q2: the scanner grades `info` to `critical` - how does that compare with a CVSS-style scale,
  and what should a report author avoid doing with it?
- q3: why did the lab run only the `headers` module instead of the scanner's full set?

**ex04 - Technology Identification** (tool: nikto, software-identification tuning)
- Command: `python -m bcssl run nikto` (this exercise uses a narrower tuning value than the
  lab default; run it with the tuning the exercise brief specifies)
- q1: what technology stack did Nikto help identify, and what evidence supports each
  conclusion?
- q2: what does the tuning value used here restrict, and what did it leave out compared with a
  default Nikto run?
- q3: how should a report author treat a Nikto item that returned HTTP 200?

### Intermediate

**ex05 - OWASP ZAP Controlled Scanning** (tool: zap, baseline mode)
- Command: `python -m bcssl run zap --mode baseline`
- If ZAP is not installed, record `TOOL NOT INSTALLED` and explain what evidence it would have
  produced. That is an acceptable answer; inventing findings is not.
- q1: which alerts did ZAP raise, and how do you translate numeric risk values into names?
- q2: why is a baseline scan lower-risk than an active attack scan, and what residual risk
  does it still carry?
- q3: two ZAP alerts describe the same weakness from different angles - how do you present
  that without inflating the count?

**ex06 - Nikto Web Server Assessment** (tool: nikto)
- Command: `python -m bcssl run nikto --tuning 1237bd`
- q1: which test categories does `1237bd` enable, and what is the practical effect on request
  volume and impact?
- q2: why does the lab exclude the injection, SQL injection, denial-of-service, command
  execution, remote file retrieval, file upload, authentication bypass and remote source
  inclusion categories?
- q3: how do you decide whether a Nikto item returning HTTP 200 is a real
  information-disclosure finding or noise?

**ex07 - Content and Path Discovery** (tool: custom-scanner, paths module)
- Command: `python -m bcssl run custom-scanner --modules paths`
- q1: which paths were discovered, and what evidence does the report give for each?
- q2: why is a discovered path not automatically a vulnerability, and what triage evidence
  upgrades a path into a finding?
- q3: how does path discovery overlap with Nikto and ZAP, and why is a dedicated path module
  still worth running?

**ex08 - Cross-Tool Finding Comparison** (tool: zap, nikto, custom-scanner)
- Commands: run zap, nikto and the custom scanner, then compare.
- q1: which finding themes did all three tools report, and what makes that agreement
  meaningful?
- q2: why did each tool see a different set of findings against the same application at the
  same time?
- q3: how should a report author treat a theme only one tool reported?

### Advanced

**ex09 - Nuclei Controlled Assessment** (tool: nuclei)
- Command: `python -m bcssl run nuclei --severities info,low,medium,high,critical`
- q1: which templates matched, and how do you read a Nuclei JSONL finding line?
- q2: why were the `dos`, `fuzz`, `intrusion`, `headless`, `bruteforce`, `brutespray` and
  `code` tags excluded, and what risk would including them introduce?
- q3: how does rate limiting change the meaning of a Nuclei run, and what happens to coverage
  when you lower the rate?

**ex10 - Custom Scanner Comparison** (tool: custom-scanner, versus zap, nikto, nuclei)
- Command: `python -m bcssl run custom-scanner --modules headers,paths,injection`
- q1: what does the full run add on top of the headers-only and paths-only runs?
- q2: where does the custom scanner outperform or underperform ZAP, Nikto and Nuclei on this
  target, based on your evidence?
- q3: why must severity labels from different tools not be merged into one number without a
  stated mapping?

**ex11 - Finding Correlation** (tool: the correlation engine via `report`)
- Command: `python -m bcssl report --format md`
- q1: what does the engine mean by `Confirmed by multiple tools`, and why is that different
  from `found by one tool`?
- q2: why does deduplication matter, and what mistakes can normalization introduce?
- q3: a theme appears in the correlation view but one contributing tool has no evidence file -
  how do you handle that in the report?

**ex12 - Final Security Assessment and Report** (tool: all tools via `run-all`)
- Commands: `python -m bcssl run-all`, then `python -m bcssl report --format html --open`
- Build the evidence index that every earlier exercise pointed at.
- q1: how do you justify a severity rating when four tools use four different vocabularies?
- q2: what belongs in the limitations section, and why is it the section most often missing?
- q3: how would you defend this report's evidence chain if a reviewer asked you to prove a
  specific finding?

## 7. Saving and citing evidence

Findings you keep come from three places:

- `reports/raw/<tool>/` - verbatim tool stdout/stderr and the tool's native report. Never
  edited.
- `reports/normalized/findings-<tool>.json` - the lab's normalized ten-key schema.
- `evidence/<tool>/` - one record per finding, with the exact raw excerpt and the sha256 of
  the raw output file.

Each exercise brief also names a specific evidence file it expects you to save. For ex01 that
is `evidence/lab-cli/ex01-validate-target.txt` - the complete, unmodified output of the
command. Save the output **exactly as printed**: do not trim it, tidy it, retype it, or
correct spelling in a header. The filename each brief specifies is the one you must cite,
and those citations belong in the evidence index of your final report at ex12.

When you write about a finding in your report, cite its evidence file by path and include the
sha256 from the record. Full conventions are in `docs/evidence-guide.md`.

## 8. The completion checklist

Your lab is complete when all twelve exercises show as complete in `python -m bcssl lab
progress`. That means, for every exercise:

- the checklist items are ticked by you,
- the questions have your answers recorded,
- and the evidence you acknowledged actually exists under `evidence/`.

A run count is not a completion criterion. If your instructor asked for a written
submission, the checklist and your answers are what will be read.

## 9. When something looks wrong

- **A tool reports `TOOL NOT INSTALLED`.** Expected on some machines. Record it. Do not
  substitute results from anywhere else.
- **A target is refused.** Expected for anything that is not loopback. The refusal message
  includes a reason and a code; put both in your report.
- **Zero findings from a tool that ran.** Distinguish this from a parser failure before you
  claim "no issues". `docs/troubleshooting.md` explains how to tell the two apart, and it is
  a graded skill - see ex11.
- **A run times out.** Raise `--timeout` within your instructor's limits, or reduce scope
  (fewer severities, passive mode). Record that you changed the configuration.

`docs/troubleshooting.md` covers the rest.