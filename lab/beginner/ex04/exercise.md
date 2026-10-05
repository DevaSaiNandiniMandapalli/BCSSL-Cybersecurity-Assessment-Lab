# Exercise 04 — Technology Identification

## Objective

Run nikto with a narrowed tuning set that reduces the scan to information disclosure and software identification, and build an accurate technology stack picture of the local application from the evidence.

## Authorized Target

```
http://localhost:3001
```

## Prerequisites

- Exercise 01 completed and its preflight evidence saved.
- Nikto is installed and on your PATH. Run `nikto -Version` and record the version.
- OWASP Juice Shop is running on `http://localhost:3001`.
- You have created the folder `evidence/nikto/`.

## Tool Used

`nikto` — web server scanner, invoked with a narrowed tuning set. Nikto tuning letters select categories of test; this exercise uses only:

- `7` — retrieve server and software information
- `b` — software identification

## Exact Command

```bash
python -m bcssl run nikto --tuning 7b
```

## Expected Observation

The lab maps `--tuning 7b` to nikto's tuning options `7` and `b`. The output should be far shorter than a default nikto run, and it should focus on things like the server header, the technology stack, known-interesting files for the detected product, and any information disclosure items.

Against Juice Shop you should typically see disclosure of the underlying server/framework (for example an Express/Node.js style stack) and possibly items about files or endpoints that reveal the application type. Nothing here is a guaranteed vulnerability; nikto items are leads to investigate.

Record exactly what you saw; do not assume a specific item count, and do not record an item you did not actually see.

## Student Task

1. Run the exact command above from the lab project root.
2. Read the whole nikto output and, for every line that ends with a `200` response code, write down what was retrieved.
3. Build a short technology stack list in your notes: product name, version if shown, and the evidence line that supports each entry.
4. Note the `Target IP`, `Target Hostname` and `Server` header lines that nikto reports and check them against your authorized scope.
5. Save the unmodified JSON output the lab produced to `evidence/nikto/ex04-nikto-software.json` and save your stack list to `evidence/nikto/ex04-tech-stack.md`.

## Evidence Requirement

- File `evidence/nikto/ex04-nikto-software.json` containing the unmodified JSON output from this tuned run.
- File `evidence/nikto/ex04-tech-stack.md` containing your technology stack list, each entry citing the nikto line that supports it.
- A quoted `Server` header value and a statement confirming the reported target host and IP are localhost/loopback.
- These filenames must be referenced in the evidence index of your final report (Exercise 12).

## Questions

**q1. What technology stack did nikto help you identify, and which specific pieces of evidence support each conclusion?**

> Cite the exact header values or retrieved items, for example a `Server` or `X-Powered-By` style header, and the product-specific items nikto listed. Explain that fingerprinting narrows which advisories and misconfigurations are even plausible for this application.

**q2. What does the tuning value 7b actually restrict, and what did it deliberately leave out compared with a default nikto run?**

> Explain that `7` = server and software information retrieval and `b` = software identification, so this run is limited to fingerprinting and disclosure. Note that a default run would additionally attempt file upload checks, injection probes, remote file retrieval, denial-of-service style tests and similar categories, which this lab excludes on purpose because they are intrusive or unsafe.

**q3. How should a report author treat a nikto item that returned HTTP 200?**

> Explain that a 200 means the resource exists and is reachable, not that it is exploitable; the item is an unauthenticated-disclosure lead whose severity must be justified by what the resource actually contains. Remind yourself never to fetch or browse anything outside the authorized target while chasing the lead.

## Safety Note

Authorized local-only use against `http://localhost:3001`. The tuned run in this exercise is limited to information retrieval and software identification so that no intrusive probe category is enabled. Do not remove the tuning restriction, do not re-point nikto at any external host, public domain, or IP address, and do not add `-h` values for systems you do not own. Discovery must never be followed by exploitation, credential testing, data extraction, or denial-of-service activity.

## Completion Checklist

- [ ] **c1** — I ran `python -m bcssl run nikto --tuning 7b` from the lab project root and kept the full console output.
- [ ] **c2** — I recorded the `Target IP`, `Target Hostname` and `Server` header lines nikto reported and verified they are the local authorized target.
- [ ] **c3** — I saved the unmodified JSON to `evidence/nikto/ex04-nikto-software.json` and wrote my evidence-cited stack list to `evidence/nikto/ex04-tech-stack.md`.
- [ ] **c4** — I explained what the `7b` tuning restricts, classified every `200` item as a lead rather than a proven vulnerability, and answered q1, q2 and q3.

> Progress in this lab is never auto-completed by running a tool. An exercise is done only when you have saved the evidence, answered the questions, and ticked the checklist.