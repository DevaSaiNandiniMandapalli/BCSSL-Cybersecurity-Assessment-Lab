# Release checklist

Everything that must be true before this lab is handed to an instructor or a
student. Run the checks; do not assume them.

Build the package:

```powershell
python scripts\build_release.py
```

Output: `../BCSSL-Cybersecurity-Assessment-Lab-RELEASE/`. The script exits
non-zero if the audit finds anything that must not ship.

---

## 1. Included in the release

| Item | Path | Check |
| --- | --- | --- |
| Engine source | `bcssl/` | 40+ Python modules present |
| Configuration | `config/lab-config.json` | Valid JSON; target is `http://localhost:3001` |
| Instructor override example | `config/instructor-config.example.json` | Present |
| Target definition | `target/docker-compose.yml`, `target/README.md` | Binds `127.0.0.1:3001:3000` |
| Scripts | `scripts/*.ps1`, `scripts/*.py` | 8 PowerShell + 6 Python |
| Tool manifests | `tools/*/tool.json` | 5 manifests with install hints |
| Nuclei guidance | `tools/nuclei/README.md` | Profile rationale documented |
| Runner wrappers | `runners/*-runner/main.py` | 5 |
| Parser wrappers | `parsers/*-parser/main.py` | 5 |
| Exercises | `lab/<level>/exNN/` | 12 × (`exercise.json` + `exercise.md`) |
| Documentation | `docs/*.md` | 12 documents |
| Tests | `tests/` | Test modules and fixtures |
| Empty skeletons | `reports/{raw,normalized,final}/`, `evidence/<tool>/`, `state/` | Contain only `.gitkeep` |
| Project files | `README.md`, `LICENSE`, `.gitignore`, `pyproject.toml` | Present |

## 2. Excluded from the release

| Item | Why |
| --- | --- |
| `.venv`, `venv`, `env` | Machine-specific |
| `__pycache__`, `*.pyc` | Build artifacts |
| `.pytest_cache`, `.mypy_cache`, `.ruff_cache` | Tooling caches |
| `tools/nuclei/templates`, `tools/nuclei/templates-lab` | Re-fetched by `scripts/setup.ps1`; not source |
| `reports/raw/**` | Generated scan output |
| `reports/normalized/**` | Generated findings |
| `reports/final/**` | Generated reports |
| `evidence/**/*.json` | Generated evidence records |
| `state/*.json` | Run index, evidence index, student progress |
| `*.log`, `*.tmp`, `*.bak` | Temporary files |
| Any `.env`, credential or key file | Secrets |

## 3. Safety verification before release

| Check | Command | Expected |
| --- | --- | --- |
| Authorized target only | `python -m bcssl validate-target` | `AUTHORIZED TARGET http://localhost:3001` |
| Public domain refused | `python -m bcssl validate-target --url https://example.com` | `TARGET REJECTED`, exit 2 |
| Public IP refused | `python -m bcssl validate-target --url http://8.8.8.8:3001` | `TARGET REJECTED`, exit 2 |
| Wrong port refused | `python -m bcssl validate-target --url http://localhost:3000` | `TARGET REJECTED`, exit 2 |
| Nmap refuses SYN scan | `python -m bcssl run nmap --scan-type -sS` | Error: not permitted |
| Nikto refuses DoS tuning | `python -m bcssl run nikto --tuning 126` | Error: refusing nikto tuning |
| Nuclei refuses intrusive tags | inspect `bcssl/runners/nuclei.py` | `MANDATORY_EXCLUDE_TAGS` merged at build time |
| Dashboard binds loopback only | `python -m bcssl web --host 0.0.0.0` | Refused, exit 2 |
| Target bound to loopback | `scripts/check-target.ps1` | `127.0.0.1:3001` |
| No public host is executable | `Select-String` over `bcssl/` for non-loopback URLs | Only rejection tests and docs |

## 4. Functional verification before release

| Check | Command | Expected |
| --- | --- | --- |
| Engine imports | `python -m compileall -q bcssl` | No errors |
| Test suite | `python -m pytest` | All pass |
| Preflight | `python -m bcssl preflight` | Component table; ready or blocking listed |
| Target reachable | `python -m bcssl validate-target` | `TARGET REACHABLE (HTTP 200)` |
| Tool detection | `python -m bcssl preflight` | 5/5 available, or explicit `[MISS]` with hints |
| Missing tool honest | point a tool at a bogus executable | `TOOL NOT INSTALLED`, 0 findings |
| Individual run | `python -m bcssl run nmap` | Command, exit code, findings |
| Full assessment | `python -m bcssl run-all` | Per-tool status; failures recorded, never faked |
| Report generation | `python -m bcssl report --format html,json,md` | Three files in `reports/final/` |
| Correlation | `python -m bcssl report --correlation-view` | Confirmed vs single-tool split |
| Evidence integrity | `python -m bcssl collect` | Hashes match |
| Empty-state honesty | `python -m bcssl clean --yes` then `report` | `No scan results available.` |
| Dashboard | `python -m bcssl web --open` | 13 pages, real state only |
| Exercises | `python -m bcssl lab list` | 12 exercises, progress tracking |
| Answer grading | `python -m bcssl lab ack ex01 --answer "q1=..."` | Graded; keys never printed |
| Cleanup | `python -m bcssl clean --yes` | Artifacts removed |

## 5. Documentation verification before release

| Check | Expected |
| --- | --- |
| Every documented command exists | Cross-check `docs/` against `python -m bcssl --help` |
| Target in every document | Only `http://localhost:3001` |
| Tool names match the registry | nmap, zap, nikto, nuclei, custom-scanner |
| Config keys match the code | `config/lab-config.json` vs `bcssl/config.py` defaults |
| Exercises reference real commands | Each `command` runs or explains why the tool is missing |
| Limitations documented | `docs/limitations.md` covers scope, tools, verification, environment |
| Status honest | `docs/project-status.md` and `docs/final-verification.md` match reality |

## 6. Do-not-modify check

| Project | Check |
| --- | --- |
| `Web-Security-Scanner` (Project #08) | Source file timestamps unchanged; read-only import/subprocess only |
| `BCSSL-Student-Web-Security-Lab` | No files added, changed or removed |

## 7. Final sign-off

| Item | State |
| --- | --- |
| All automated tests pass | ☐ |
| All five tools verified by real execution | ☐ |
| No fabricated results or evidence in the package | ☐ |
| No secrets or credentials | ☐ |
| No public target reachable from the package | ☐ |
| Release audit clean (`build_release.py` exit 0) | ☐ |
| Documentation matches the implementation | ☐ |
| Protected projects untouched | ☐ |

A release is only valid when every row above is checked. `docs/final-verification.md`
records the verification evidence for the current build.
