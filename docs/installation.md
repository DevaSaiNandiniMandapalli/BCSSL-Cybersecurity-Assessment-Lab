# Installation and setup

Everything the lab needs, in the order you should do it. Every command in this
document has been run on the machine the project was built on; where a step is
blocked by the environment, that is stated explicitly.

Target for the whole lab:

```text
AUTHORIZED TARGET
http://localhost:3001
```

---

## 1. Requirements

| Component | Required | Notes |
| --- | --- | --- |
| Python | **Yes**, 3.10 or newer | Standard library only. No `pip install` needed. |
| Docker Desktop | **Recommended** | Provides the target and the container fallback for all four external tools. |
| OWASP Juice Shop image | **Yes** for scanning | `bkimminich/juice-shop` |
| Nmap / Nikto / Nuclei / ZAP | Optional locally | If absent, the lab uses the documented container images instead. |

The lab has **no third-party Python dependencies**. `pip install` is only
needed for the test runner.

---

## 2. Install Python

Verify:

```powershell
python --version
```

If the command is missing, install Python 3.10+ from
<https://python.org> and enable "Add python.exe to PATH".

---

## 3. Install and start Docker Desktop

Verify the CLI *and* the engine - they are different things:

```powershell
docker --version
docker info --format '{{.ServerVersion}}'
```

If `docker info` fails, Docker Desktop is installed but not running. Start it
and wait until the engine reports a version.

The lab reports these separately:

| Component | Meaning |
| --- | --- |
| `docker-cli` | The command exists |
| `docker-daemon` | The engine is actually reachable |

---

## 4. Run the one-time setup

```powershell
powershell -ExecutionPolicy Bypass -File scripts/setup.ps1
```

What it does, and what it deliberately does **not** do:

- verifies Python, Docker, the engine and the target;
- pulls the five documented container images;
- downloads the Nuclei template set and builds the curated lab profile;
- verifies each step and prints `[ OK ]` or `[ FAIL ]` accordingly.

It installs **no software**. Tools are either already installed, or run from
their documented container image.

Useful variants:

```powershell
scripts/setup.ps1 -SkipImages        # do not pull images
scripts/setup.ps1 -SkipTemplates     # do not download Nuclei templates
scripts/setup.ps1 -Force             # re-verify and rebuild
```

---

## 5. Start the authorized target

```powershell
powershell -ExecutionPolicy Bypass -File scripts/start-target.ps1
```

This brings up `target/docker-compose.yml`, which publishes the container's
port 3000 as **127.0.0.1:3001** and waits until the application actually
answers. Juice Shop needs 30-90 seconds to initialise its database on first
start, so the script polls rather than assuming.

Verify:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/check-target.ps1
python -m bcssl validate-target
```

> **Port mapping.** The container listens on 3000 internally. The host mapping
> is `127.0.0.1:3001:3000`. Using `3001:3001` fails silently: the container is
> not listening on 3001. The lab's preflight flags any binding that is not
> loopback-only, because a deliberately vulnerable application must never be
> reachable from the network.

Stop it again with:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/stop-target.ps1
```

---

## 6. Install the assessment tools

You have three options per tool. The lab picks the first that works.

### Option A - use the container image (no install)

This is what happens by default on a machine with a working Docker engine. The
lab runs the tool in its documented image and mounts the run directory so the
output lands in `reports/raw/`.

| Tool | Image | Notes |
| --- | --- | --- |
| Nmap | `instrumentisto/nmap:latest` | |
| Nikto | `alpine/nikto:latest` | Alpine-published image; the project is Perl |
| Nuclei | `projectdiscovery/nuclei:latest` | Ships **no** templates, see below |
| ZAP | `ghcr.io/zaproxy/zaproxy:stable` | Bundles its own JRE |

### Option B - install natively

```powershell
winget install Insecure.Nmap      # Nmap
winget install nuclei             # Nuclei
winget install zaproxy.zaproxy.stable
```

- **ZAP** additionally needs a Java runtime. The Docker image bundles one; a
  native install does not.
- **Nikto** needs Perl. On Windows install Strawberry Perl, then
  `cpan Nikto`, or clone <https://github.com/sullo/nikto>.

### Option C - disable a tool

```json
{ "tools": { "nikto": { "enabled": false } } }
```

The tool then reports `UNAVAILABLE` and contributes no findings.

---

## 7. Nuclei templates

Nuclei ships without templates. Fetch them once, then build the lab profile:

```bash
python -m bcssl update-templates
python -m bcssl build-template-profile
```

This downloads template *definitions* only - it never scans anything.

The complete set is over 14,000 templates, which is too slow and too noisy for a
classroom. The lab therefore uses a curated profile
(`tools/nuclei/templates-lab/`, about 2,600 templates: technologies,
misconfiguration, exposures, miscellaneous). See
`tools/nuclei/README.md` for the full inclusion and exclusion rationale.

If you skip this step, the nuclei run fails honestly with:

```text
TOOL FAILED
error: Nuclei produced no output. Confirm templates are installed ...
```

That is intentional: a missing template set must not be papered over with
fabricated findings.

---

## 8. Verify the installation

```powershell
powershell -ExecutionPolicy Bypass -File scripts/preflight.ps1
```

Expected on a fully prepared machine:

```text
Component             Status        Version
--------------------  ------------  ------------------------------
python                [ OK ] READY  3.12.10
docker-cli            [ OK ] READY  ...
docker-daemon         [ OK ] READY  29.8.0
juice-shop-container  [ OK ] READY  Up 2 minutes
target                [ OK ] READY  HTTP 200
configuration         [ OK ] READY  .../config/lab-config.json
directories           [ OK ] READY  -
project08             [ OK ] READY  read-only external integration
nmap                  [ OK ] READY  docker engine ...; image instrumentisto/nmap
zap                   [ OK ] READY  ...
nikto                 [ OK ] READY  ...
nuclei                [ OK ] READY  ...
custom-scanner        [ OK ] READY  Python 3.12.10
```

Anything `[MISS]`, `[DOWN]` or `[FAIL]` is followed by an exact remediation.

The exit code is non-zero when a required component (Python, Docker, target) is
unavailable, so it can gate a lesson or a CI step.

---

## 9. Install the external Project #08 scanner

The custom scanner is a **separate, completed project**. This lab never modifies
it; it invokes it as a subprocess.

Default path in `config/lab-config.json`:

```json
"custom-scanner": {
  "project_root": "C:\\Users\\devas\\Documents\\Cybersecurity\\Web-Security-Scanner",
  "python": "auto"
}
```

`"python": "auto"` resolves in this order:

1. `<project_root>/.venv/Scripts/python.exe` (Windows) or `<project_root>/.venv/bin/python`
2. `python` on `PATH`

Point `project_root` at your copy if it lives elsewhere. If the project is
missing, preflight reports `project08 NOT INSTALLED` and the custom scanner
reports `TOOL NOT INSTALLED` rather than producing findings.

---

## 10. Run the tests

```bash
python -m pytest
```

The suite is offline: it never contacts a target and never runs a real scan.
Tool-specific behaviour is verified with fixtures and, separately, by real
execution - see `docs/final-verification.md`.

---

## 11. Everyday commands

```powershell
powershell -ExecutionPolicy Bypass -File scripts/start-lab.ps1     # target + dashboard
powershell -ExecutionPolicy Bypass -File scripts/run-all.ps1       # safe full assessment
powershell -ExecutionPolicy Bypass -File scripts/stop-lab.ps1      # stop everything
powershell -ExecutionPolicy Bypass -File scripts/clean.ps1        # remove artifacts
```

Or drive the CLI directly:

```bash
python -m bcssl preflight
python -m bcssl validate-target
python -m bcssl run nmap
python -m bcssl run-all
python -m bcssl report --correlation-view --open
python -m bcssl web --open
```

---

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `python` not found | Python not on PATH | Reinstall with "Add to PATH" |
| `docker info` fails | Docker Desktop not running | Start it, wait for the engine |
| Target never answers | Juice Shop still initialising | Wait; `start-target.ps1` already polls |
| Container healthy but connection refused | Wrong port mapping | Use `127.0.0.1:3001:3000` |
| `project08 NOT INSTALLED` | Wrong `project_root` | Fix `tools.custom-scanner.project_root` |
| Nuclei: "no templates provided" | Templates not downloaded | `python -m bcssl update-templates` |
| Nuclei: "console output instead of JSONL" | Missing JSONL flag | Set `tools.nuclei.json_flag` to `-j` |
| Nikto finds 0 items | Tuning too narrow or old Nikto | Check the tuning; `nikto -Tuning help` |
| ZAP `TOOL FAILED`, exit 3 | ZAP could not start | Check the container logs; usually the work directory |
| Dashboard will not bind | Port in use | `python -m bcssl web --port 8766` |

Full symptom table: `docs/troubleshooting.md`.
