# Student quick start

Welcome. This page is everything you need to begin.

---

## 1. The one rule

```text
AUTHORIZED TARGET
http://localhost:3001
```

**Only** `http://localhost:3001` may be assessed. Not any website, not any IP
address, not any other program on this or any other machine.

The lab enforces this for you. Every scanner refuses a target that is not the
authorized one, so you cannot accidentally scan something you should not. If a
command of yours fails with `TARGET REJECTED`, that is the safety system
working, not a mistake in your command.

### What is in scope

- The Juice Shop application running on your own machine at port 3001.

### What is out of scope, always

- Any website or web address
- Any IP address that is not your own machine
- Any other port or program
- Any system on your school or work network

### What the lab will not do, even on the authorized target

- Brute-force or password testing
- Denial-of-service or load testing
- Fuzzing
- Uploading files
- Exploiting or running commands on the target
- Downloading data in bulk

The scanners are configured to exclude all of these, and the runners refuse
dangerous flags even if you ask for them.

---

## 2. What the tools are for

| Tool | What it tells you |
| --- | --- |
| **Nmap** | Which port is open on the target, and what service is listening |
| **OWASP ZAP** | Application-level problems such as missing security headers |
| **Nikto** | Web server configuration issues and information disclosure |
| **Nuclei** | Specific known issues, checked with safe templates |
| **Custom scanner** | A separate completed project, used to compare results |

They overlap on purpose. When two different tools report the same problem, that
is stronger evidence than one tool alone - the lab marks those findings
`CORROBORATED`.

---

## 3. Getting started

Open a terminal in the project folder:

```powershell
cd C:\Users\devas\Documents\Cybersecurity\BCSSL-Cybersecurity-Assessment-Lab
$env:PYTHONPATH = (Get-Location).Path
```

Check the lab is ready:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\preflight.ps1
```

You want to see:

```text
  Lab is ready. 5/5 assessment tools usable.
```

If it does not, ask your instructor. The table tells you exactly what is
missing.

Check the target is up:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\check-target.ps1
```

You want:

```text
[ OK ] Target is authorized and reachable.
```

---

## 4. Beginning Exercise 01

List the exercises:

```powershell
python -m bcssl lab list
```

Read Exercise 01 in full:

```powershell
python -m bcssl lab show ex01
```

Or open it in the dashboard: <http://127.0.0.1:8765>

Exercise 01 asks you to confirm the authorized target and understand why the
lab checks the port and not just the host name. You will run:

```powershell
python -m bcssl validate-target
```

then try to make the validator refuse something, for example:

```powershell
python -m bcssl validate-target --url https://example.com --no-probe
```

Read the reason it gives. That reasoning is the practical task.

---

## 5. How to collect evidence

Evidence is proof you actually did the work. Every exercise requires at least
one.

1. Run the command the exercise gives you.
2. Save the output somewhere in the project folder.
3. Write down the path to that file.

For example:

```powershell
python -m bcssl run nmap
```

Your evidence is the file the runner wrote for you:

```text
reports/raw/run-001/run-001-nmap/stdout.txt
```

`python -m bcssl runs --verify` lists every run and shows that its output is
still exactly what was captured.

**Rule:** evidence is a real file you can point to. Not a description of what
you remember happening.

---

## 6. How to complete an exercise

An exercise is complete only when all three of these are true:

1. **Every checklist item is ticked.**
2. **Every question is answered, and gradable ones are correct.**
3. **At least one evidence file is recorded.**

Running a scanner does **not** complete anything by itself.

Record your work:

```powershell
python -m bcssl lab ack ex01 --check c1 --check c2 --evidence reports/raw/run-001/run-001-nmap/stdout.txt
```

Answer the questions and let the lab grade them:

```powershell
python -m bcssl lab ack ex01 --answer "q1=http scheme, localhost host, port 3001" --answer "q2=host-only validation would widen the blast radius" --answer "q3=3001"
```

Use `--check` once per checklist item and `--answer QID=TEXT` once per question.
The lab tells you which questions did not pass and what was missing. It will
never show you the answer key.

In the dashboard, tick the checkboxes, type your answers and evidence paths, and
press **Save acknowledgements**.

Check your progress at any time:

```powershell
python -m bcssl lab progress
```

---

## 7. Seeing results

Console summary:

```powershell
python -m bcssl status
```

Full report, opened in a browser:

```powershell
python -m bcssl report --format html --open
```

Which tools agreed on what:

```powershell
python -m bcssl report --correlation-view
```

Dashboard, which shows the same data interactively:

```powershell
python -m bcssl web --port 8765
```

Then <http://127.0.0.1:8765>.

---

## 8. Understanding what you are reading

Each finding carries a **verification status**. This is the most important thing
to understand:

| Status | Meaning |
| --- | --- |
| `CORROBORATED` | Two or more different tools reported the same problem |
| `DETECTED` | The lab checked the condition itself and reproduced it |
| `SINGLE-TOOL OBSERVATION` | Exactly one tool reported it |
| `NOT VERIFIED` | A tool reported it; nothing has confirmed it |
| `TOOL UNAVAILABLE` | That tool could not run, so it found nothing |

**A finding is an indicator, not a verdict.** If three tools flag something, it
deserves attention. It is not proof that the application is exploitable, and you
should never present it as though it is.

Severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`) comes from each tool's
own scale, mapped conservatively. It is **not** a CVSS score, and you should not
report it as one.

---

## 9. The twelve exercises

| Level | Exercise | Focus |
| --- | --- | --- |
| Beginner | 01 | Target and HTTP fundamentals |
| Beginner | 02 | Nmap discovery |
| Beginner | 03 | HTTP security headers |
| Beginner | 04 | Technology identification |
| Intermediate | 05 | OWASP ZAP |
| Intermediate | 06 | Nikto |
| Intermediate | 07 | Content and path discovery |
| Intermediate | 08 | Cross-tool comparison |
| Advanced | 09 | Nuclei |
| Advanced | 10 | Custom scanner comparison |
| Advanced | 11 | Finding correlation |
| Advanced | 12 | Final security assessment |

Full instructions for each: `docs/student-guide.md`.

---

## 10. When you are finished

```powershell
powershell -ExecutionPolicy Bypass -File scripts\stop-lab.ps1
```

Your progress is stored in `state/progress.json`. Do not delete it, and do not run
`python -m bcssl clean` unless your instructor tells you to - that removes your
recorded evidence.

---

## If something goes wrong

| What you see | What to do |
| --- | --- |
| `TARGET REACHABLE` fails | Ask your instructor to start the target |
| `TOOL NOT INSTALLED` | Tell your instructor. The lab will not make up results |
| `Docker engine is not reachable` | Docker Desktop is not running |
| A command says `TARGET REJECTED` | You used a URL other than the authorized one. Use `http://localhost:3001` |
| An exercise will not complete | Check all three requirements in section 6 |
| The dashboard says no results | No scan has been run yet |

More: `docs/troubleshooting.md`.