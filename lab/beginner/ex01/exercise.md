# Exercise 01 — HTTP and Target Validation

## Objective

Confirm that http://localhost:3001 is the only authorized target, verify it is reachable over HTTP, and capture a preflight baseline that every later exercise in this track depends on.

## Authorized Target

```
http://localhost:3001
```

This is a locally hosted OWASP Juice Shop instance on your own machine. It is the only host and the only port you may touch in this lab.

## Prerequisites

- OWASP Juice Shop is running locally. Open http://localhost:3001 in a browser and confirm the welcome page loads.
- You are working from the lab project root: `C:\Users\devas\Documents\Cybersecurity\BCSSL-Cybersecurity-Assessment-Lab`
- The lab CLI is importable. Run `python -m bcssl --help` and confirm it prints usage.
- You have created the folders `reports/raw/` and `evidence/lab-cli/`.

## Tool Used

`lab-cli` — the exercise driver that wraps every tool in this lab and enforces the authorized target.

## Exact Command

```bash
python -m bcssl validate-target --url http://localhost:3001
```

## Expected Observation

A short preflight report that breaks the URL into its components (scheme `http`, host `localhost`, port `3001`), confirms the host resolves to the local loopback address, performs an HTTP reachability check and prints a response status code (a healthy Juice Shop normally answers `200` on `/`), and then prints an explicit scope confirmation naming `http://localhost:3001` as the permitted target.

If Juice Shop is not running, the same command should instead report the target as unreachable and stop before any scan work. Either outcome is a valid observation as long as you record what actually happened; do not fabricate a successful preflight.

## Student Task

1. Open `http://localhost:3001` in a browser, confirm the Juice Shop welcome page renders, and close the tab.
2. Run the exact command above from the lab project root and read the entire output before doing anything else.
3. Record the scheme, resolved host address, port, and HTTP status code printed by the tool, plus the exact authorization or scope line.
4. Save the complete, unmodified preflight output to `evidence/lab-cli/ex01-validate-target.txt`.
5. Write a short note stating whether the target was reachable. If it was not, write what you did about it (for example, starting the local container) and record that the first preflight failed.

## Evidence Requirement

- File `evidence/lab-cli/ex01-validate-target.txt` containing the complete preflight output from the command, unmodified.
- A quoted HTTP status code and resolved host/port from that same output in your notes.
- A one-line statement confirming you verified the target yourself in a browser at `http://localhost:3001`.
- This filename must be referenced in the evidence index of your final report (Exercise 12).

## Questions

**q1. Which URL components did the preflight report confirm, and why does the lab check the port separately instead of trusting the host alone?**

> Look for lines naming the scheme, the host, and the port. Explain that `localhost:3001` is the only authorized endpoint on this machine: the same host name can serve other ports, and any port other than 3001 is outside the scope of this engagement, so host-only validation would silently widen the blast radius.

**q2. What HTTP status code did the target return, and what does that single value tell you about whether Juice Shop was actually serving during your preflight?**

> A `200` response on `/` indicates the application was up and answering. A connection error, timeout, or refused connection means nothing was listening on 3001. Explain the difference between "the tool ran" and "the target answered".

**q3. Suppose validate-target reports the target unreachable. What is the correct response, and why must that failure be recorded rather than quietly retried until it succeeds?**

> The correct response is to start the local Juice Shop, then re-run the preflight and keep both outputs. Explain that an audit trail is the deliverable: a hidden failed attempt destroys the timeline, and later findings cannot be trusted if you cannot say when the target was first confirmed reachable.

## Safety Note

This exercise contacts `http://localhost:3001` and nothing else. It is authorized educational use against a deliberately vulnerable application running on your own machine. Do not substitute any other host, port, IP address, or domain; do not point this command at a public website, a colleague's machine, or a shared service. Preflight validation is a scope-control step, not a scanning step, and it performs no exploitation, data extraction, or credential testing.

## Completion Checklist

- [ ] **c1** — I opened `http://localhost:3001` in a browser myself and confirmed the Juice Shop welcome page renders.
- [ ] **c2** — I ran `python -m bcssl validate-target --url http://localhost:3001` from the lab project root and read the whole output.
- [ ] **c3** — I saved the unmodified preflight output to `evidence/lab-cli/ex01-validate-target.txt`.
- [ ] **c4** — I recorded the status code and the authorization line in my notes, and I understand this exercise is not complete just because the command ran; completion needs my saved evidence and my written answers to q1, q2 and q3.

> Progress in this lab is never auto-completed by running a tool. An exercise is done only when you have saved the evidence, answered the questions, and ticked the checklist.