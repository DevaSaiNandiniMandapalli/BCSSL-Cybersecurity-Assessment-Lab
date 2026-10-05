# BCSSL Cybersecurity Assessment Lab - Troubleshooting

## 1. Symptom / cause / fix

| Symptom | Cause | Fix |
| --- | --- | --- |
| `TOOL NOT INSTALLED: nmap` | `nmap` is not on the `PATH` visible to the lab's process | Install it (`winget install nmap.nmap`, `choco install nmap -y`, `brew install nmap`, `sudo apt install nmap`, or `docker pull instrumentisto/nmap`). Open a **new** terminal so `PATH` is refreshed, then `nmap --version`, then `python -m bcssl preflight`. |
| `TOOL NOT INSTALLED: zap` | ZAP is not installed, or `zap.sh` / `zap.bat` / `zap.jar` is not on `PATH` | Install ZAP (`winget install zaproxy.zap`, `choco install zaproxy -y`, `brew install --cask zaproxy`, `sudo apt install zaproxy`, or `docker pull ghcr.io/zaproxy/zaproxy:stable`). Verify `zap.sh -version` (Linux/macOS) or `zap.bat -version` (Windows). |
| `TOOL NOT INSTALLED: nikto` | Nikto's Perl script is not on `PATH`, or `nikto.pl` is not installed | Install Nikto and ensure `nikto.pl` is on `PATH`. `nikto -Version` must succeed. On Linux, `sudo apt install nikto`; on macOS, `brew install nikto`. |
| `TOOL NOT INSTALLED: nuclei` | `nuclei` binary not on `PATH`, or only supplied via Docker image | Install (`brew install nuclei`, `sudo apt install nuclei`, `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`, or `docker pull instrumentisto/nuclei`). Verify `nuclei -version`. |
| `TOOL NOT INSTALLED: custom-scanner` with reason `custom scanner project root not found` | `custom-scanner.project_root` in `config/lab-config.json` does not point at the existing Project #08 tree | Correct the path. It should be `C:\Users\devas\Documents\Cybersecurity\Web-Security-Scanner` (adjust the separator style if the config uses forward slashes). Do not create a substitute project; the lab must not fabricate a scanner. |
| `TOOL NOT INSTALLED: custom-scanner` with reason `interpreter not usable` | The project's `.venv` is missing or its dependencies are not installed | Activate the project's environment, install its dependencies with its own installer, and confirm it runs. The lab invokes the external project with **its own** interpreter and never installs into it for you. |
| Reason `java not found` while ZAP is installed | ZAP is present but no JRE is on `PATH` | Install a Java runtime (JRE or JDK 11+). Verify `java -version`. The lab does not bundle or work around a missing JVM. |
| Reason `docker daemon not reachable` | Docker is installed but not running, or the daemon is failing | Start Docker Desktop, or `systemctl start docker`. Verify with `docker info`. If you are not using Docker, install the tool natively instead. |
| `TARGET REFUSED` for `http://localhost:3001` | The URL does not match the configured allowlist, most often because `allowed_ports` no longer contains 3001, or `target.url` is set differently | Check `config/lab-config.json`. `validate-target` prints the reason and a code. Do not "fix" this by widening the host list - the target is loopback, so the port is what is wrong. |
| `TARGET REFUSED: host not in allowlist` | A host name other than `localhost`, `127.0.0.1`, `::1` was requested | Use `http://localhost:3001`. This refusal is intentional. Do not add external hosts to the allowlist. |
| `TARGET REFUSED: resolves to non-loopback address` | The allowed hostname resolved to a routable address | Keep `require_loopback_resolution` at `true` and fix your DNS/hosts state, or use `127.0.0.1` directly. Never disable the resolution check. |
| `TARGET REFUSED: malformed URL` | The URL is missing a scheme, has a bad port, or is not a URL at all | Use a full URL including scheme, for example `http://localhost:3001`. |
| Connection refused / target unreachable on `localhost:3001` | Juice Shop is not running or is bound to a different port | Confirm in a browser at `http://localhost:3001`. If it is down, start it. If it runs on another port, either start it on 3001 or have your instructor add that loopback port to `allowed_ports`. |
| ZAP baseline times out | Baseline scanning of a SPA is slow; the configured timeout is too short for the machine | Raise `tools.zap.timeout` in `lab-config.json`, or pass `--timeout N`. If time is short for a class, use `--mode passive` instead and note the change in your write-up. |
| Nikto is slow | Nikto issues many requests by design | Raise `tools.nikto.timeout`. If you must narrow it, narrow the tuning set (documenting the change) rather than pointing it elsewhere. |
| Nikto appears to hang | Interactive prompt waiting on stdin | The lab passes `-nointeractive`; if you invoke `nikto` directly, add it. Interactive invocation will block until timeout. |
| Nikto writes nothing to the `-output` path | Wrong working directory, or a path that does not exist | Run it from the project root and confirm the output directory exists. The lab writes under `reports/raw/nikto/`, which it creates. |
| Nuclei prompts for a template update | Templates are missing and Nuclei wants to fetch them | Run `nuclei -update-templates` **once, as a setup step, with network access**, before the session. Lab runs pass `-no-update-templates`, so during a run there should be no prompt. If you see one, the flag did not apply - report it rather than answering the prompt. |
| Nuclei reports no templates / template errors | Templates directory missing or unreadable | Populate templates with the setup step above. If templates are unavailable, record that as a coverage limitation; do not report it as "no findings". |
| Nuclei JSONL is empty but the run "succeeded" | Genuinely no matching templates fired, or templates were missing, or the target was never crawled | Distinguish using section 2 below. Check the raw stderr for template-loading errors before concluding anything. |
| Permission denied writing to `reports/` or `evidence/` | Directory owned by another account, read-only checkout, or file locked by another process | Close any program holding the file, check folder permissions, or run as the account that owns the project tree. Do not run the lab from a read-only location. |
| `Address already in use` when starting the web dashboard | Port 8765 is occupied | Change the port: `python -m bcssl web --port 8766`. Also set `--host 127.0.0.1` explicitly if a firewall prompts. |
| `python -m bcssl` reports the package cannot be found | Not installed, or wrong working directory | Run from the project root, or install with `pip install -e .` so `bcssl` is importable. Confirm `python -m bcssl version` works. |
| The web dashboard is reachable from another machine | Dashboard bound to a non-loopback interface | Restart with `--host 127.0.0.1`. The dashboard is a local-only surface. |
| Progress not advancing after running tools | Expecting a run to complete an exercise | Runs never complete exercises. Use `python -m bcssl lab ack <id> --check <cid> --answer <qid>=<text>`. See `docs/student-guide.md`. |
| Findings disappear after deleting a directory | `reports/normalized/` or `reports/final/` was cleared | Both are derived. Rebuild with `python -m bcssl collect` and `python -m bcssl report`. If `reports/raw/` was also deleted, the evidence is gone - re-run the tools. |

## 2. Empty findings, or a parser failure - telling them apart

This distinction matters for grading and for honesty, so learn to make it deliberately.

### 2.1 Three distinct states

| State | What the lab reports | Meaning |
| --- | --- | --- |
| **Tool not installed** | `TOOL NOT INSTALLED` with a reason | Nothing ran. No raw output, no findings, no evidence. |
| **Target refused** | `TARGET REFUSED` with reason and code | Nothing ran. The refusal is a feature. |
| **Run produced no findings** | exit code recorded, raw output present and parseable, findings array empty | The tool ran and reported nothing matching. This is a real result. |
| **Parse failure** | `PARSE FAILURE` recorded, raw output present, parser raised or produced malformed input | The tool ran but the lab could not read the output. **Not** the same as zero findings. |

### 2.2 How to tell them apart

1. **Check the run status.** `python -m bcssl status` shows the status per run. A status of
   `PARSE FAILURE` is decisive.
2. **Check for raw output.** `reports/raw/<tool>/` should contain a file from that run. No raw
   file means the tool never ran (`TOOL NOT INSTALLED` or `TARGET REFUSED`).
3. **Read the raw output.** Open it. Genuine zero findings means a parseable file with no
   finding entries: a nmap XML with only a host element, a ZAP JSON with an empty `alerts`
   array, a Nikto JSON with no findings, a Nuclei `.jsonl` with zero lines, a custom scanner
   HTML report with no finding rows.
4. **Look at stderr.** Template-loading errors, missing-module tracebacks, Java exceptions,
   and Perl errors all land here. Their presence means the run was not a clean result.
5. **Re-run the parser in isolation** using the standalone parser CLI under
   `parsers/<tool>-parser/`, pointing at the preserved raw file. If it also fails, the parser
   has a genuine defect against this tool's output format.

### 2.3 What to write in your report

- Genuinely zero findings: state that the tool ran, state the exit code, state that the raw
  output is empty of findings, and cite the raw file. Do not write "no issues found" - write
  "this tool reported no findings within its configured scope".
- Parse failure: state it as a limitation. Say the tool ran, say the lab could not parse the
  output, include the raw file as evidence, and exclude those findings from your conclusions
  rather than guessing at them.

Never present a parse failure, a missing tool, or a timeout as a clean result.

## 3. Confirming the lab is not fabricating results

The lab's central promise is that it reports what happened and nothing else. Verify that
promise rather than trusting it.

1. **A missing tool must produce no findings.** Run a tool that is not installed:
   `python -m bcssl run nuclei` on a machine without nuclei. Expect `TOOL NOT INSTALLED`,
   **no** file in `reports/raw/nuclei/`, **no** `reports/normalized/findings-nuclei.json`, and
   **no** directory under `evidence/nuclei/`. If findings appear, stop and report it.
2. **A refused target must produce no findings.** Run nmap with a `--url` whose host is
   outside the allowlist - any host other than `localhost`, `127.0.0.1`, or `::1` will do.
   Expect `TARGET REFUSED` with a reason and a code, and no new raw output. Nothing should be
   scanned, and no command should have been built.
3. **Every finding must be locatable in raw output.** Take any finding from
   `reports/normalized/findings-<tool>.json`, take its `evidence` string, and find that exact
   text in the raw file under `reports/raw/<tool>/`. If you cannot, the finding is not backed
   by the tool.
4. **Hashes must match.** Recompute the sha256 of a raw file and compare it to the `sha256`
   in its evidence record. A mismatch means the raw file changed after the run.
5. **Counts must be consistent.** The number of findings in `reports/normalized/` must match
   what the consolidated report claims. A report that inflates counts, or claims
   multi-tool confirmation for a fingerprint only one tool reported, is fabricating.
6. **Empty must look like empty.** With no tools installed and Juice Shop unreachable, a full
   `run-all` followed by `report` must produce a report that says no tool contributed
   findings - not a report full of plausible entries.

If any of these checks fail, treat the result as untrustworthy, preserve `reports/raw/`, and
report it to whoever maintains the lab before drawing conclusions from anything it produced.

## 4. Quick diagnostic sequence

When something is wrong, work down this list; it goes from cheapest check to most involved.

```
python -m bcssl version
python -m bcssl validate-target --url http://localhost:3001
python -m bcssl preflight
python -m bcssl status
```

Then, in order: is Python working, is the target in scope, is the tool installed, and what
does the run index say actually happened. Most problems are answered by the first three
commands.