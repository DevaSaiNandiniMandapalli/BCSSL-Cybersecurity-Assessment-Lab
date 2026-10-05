# Exercise 09 — Nuclei Controlled Assessment

## Objective

Run a template-driven nuclei assessment with the destructive tag families excluded and rate limiting applied, and read JSONL findings by `templateID`, `matched-at` URL and `info.severity`.

## Authorized Target

```
http://localhost:3001
```

## Prerequisites

- Exercises 05 through 08 completed, so you already know what ZAP, nikto and the custom-scanner each detect.
- Nuclei is installed and templates are updated for the local lab environment. Run `nuclei -version` and record it.
- You understand the tag exclusion list in this exercise: `dos`, `fuzz`, `intrusion`, `headless`, `bruteforce`, `brutespray` and `code` are excluded, and the run is rate limited.
- OWASP Juice Shop is running on `http://localhost:3001` and you have created the folder `evidence/nuclei/`.

## Tool Used

`nuclei` — template-driven scanner. Effectively invoked by the lab as:

```
nuclei -u http://localhost:3001 -severity info,low,medium,high,critical   (destructive tags excluded, rate limited, JSONL output)
```

## Exact Command

```bash
python -m bcssl run nuclei
```

## Expected Observation

Each finding is one JSON object per line carrying a `templateID`, the `matched-at` URL, and an `info.severity` value. Against Juice Shop you should typically see template matches relating to technology detection, exposed files or directories, missing security headers, or misconfiguration, with severities spread across the informational-to-critical vocabulary.

Because the destructive template families are excluded you should **not** see denial-of-service, fuzzing, brute-force, code-execution or intrusion-style results.

Record what actually matched; template availability and application version both change, so never quote a finding count you did not observe.

## Student Task

1. Run the exact command above from the lab project root and let nuclei finish.
2. Open the JSONL output line by line and, for every line, record the `templateID`, the `matched-at` URL, the `info.severity`, and the `info.name`.
3. Build a table in `evidence/nuclei/ex09-finding-notes.md` sorted from the highest severity you actually observed to the lowest, and count how many distinct `templateID`s fired.
4. Identify the templates whose IDs suggest a behaviour that could change application state, and write one line each on why that category is excluded in this lab.
5. Save the unmodified JSONL output to `evidence/nuclei/ex09-nuclei-findings.jsonl`.

## Evidence Requirement

- File `evidence/nuclei/ex09-nuclei-findings.jsonl` containing the unmodified nuclei JSONL output.
- File `evidence/nuclei/ex09-finding-notes.md` containing your sorted table: `templateID`, matched-at URL, `info.severity`, `info.name`, plus your distinct-`templateID` count.
- A written statement naming the excluded tag families (`dos`, `fuzz`, `intrusion`, `headless`, `bruteforce`, `brutespray`, `code`) and the rate-limiting behaviour in effect.
- These filenames must be referenced in the evidence index of your final report (Exercise 12).

## Questions

**q1. Which templates matched, and how do you read a nuclei JSONL finding line?**

> Explain the fields you used: `templateID` identifies the check, `info.name` is the human label, `info.severity` is the vendor-assigned severity, and `matched-at` is the exact URL that satisfied the matchers. Note that `matched-at` is also a source of false positives if a template matches too broadly.

**q2. Why were the dos, fuzz, intrusion, headless, bruteforce, brutespray and code tags excluded, and what risk would including them have introduced?**

> Explain each briefly: `dos` degrades or stops the target, `fuzz` is unbounded input generation that can corrupt state, `headless` launches real browsers, `bruteforce` and `brutespray` attempt credential guessing, `code` executes commands, and `intrusion` families attempt unauthorised access. Including any of them would push a template scanner from assessment into active attack.

**q3. How does rate limiting change the meaning of a nuclei run, and what happens to detection coverage when you lower the rate?**

> Explain that a low rate keeps the load gentle on the local application and avoids tripping app-level protections or producing errors that look like findings, but it makes the run slower and can time out on long crawls. Coverage itself depends on the template set and matcher logic, not the rate, but aggressive rates can cause dropped connections and missed or misleading results.

## Safety Note

Authorized local-only use against `http://localhost:3001`. This run is deliberately constrained: destructive tag families are excluded and rate limiting is in force. Do not remove the exclusions, do not run with `-include-tags` for intrusive categories, and never pass a different `-u` value pointing at a public website, external domain, or arbitrary IP address. Template scanning must stay non-destructive here: no denial-of-service, no fuzzing, no brute-force credential testing, no command execution, and no attempts to access data you were not given.

## Completion Checklist

- [ ] **c1** — I ran `python -m bcssl run nuclei` from the lab project root and kept the lab's console log.
- [ ] **c2** — I opened the JSONL output and transcribed `templateID`, matched-at URL, `info.severity` and `info.name` for every finding line.
- [ ] **c3** — I saved the unmodified JSONL to `evidence/nuclei/ex09-nuclei-findings.jsonl` and wrote my severity-sorted table with a distinct-`templateID` count to `evidence/nuclei/ex09-finding-notes.md`.
- [ ] **c4** — I wrote the excluded-tag rationale and the rate-limiting note, and answered q1, q2 and q3 in my own words.

> Progress in this lab is never auto-completed by running a tool. An exercise is done only when you have saved the evidence, answered the questions, and ticked the checklist.