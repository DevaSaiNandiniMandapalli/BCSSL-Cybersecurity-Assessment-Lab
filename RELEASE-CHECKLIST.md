# Release checklist

Everything that must be true before this lab is handed to an instructor or a
student. Run the checks; do not assume them.

Build and verify the package:

```powershell
python scripts\build_release.py
python scripts\verify_release.py
```

`verify_release.py` is the important one. It copies the package into a **fresh
temporary directory** and runs the documented checks from that copy, in a
subprocess with no `PYTHONPATH` pointing at the source tree. A release package
that only works in the development directory has not been verified.

Output: `../BCSSL-Cybersecurity-Assessment-Lab-RELEASE/`. `build_release.py`
exits non-zero if the audit finds anything that must not ship.

---

## 1. Included in the release

| Item | Path | Check |
| --- | --- | --- |
| Engine source | `bcssl/` | 40+ Python modules present, including `runs.py` and `sarif.py` |
| Configuration | `config/lab-config.json` | Valid JSON; target is `http://localhost:3001` |
| Instructor override example | `config/instructor-config.example.json` | Present |
| Target definition | `target/docker-compose.yml`, `target/README.md` | Binds `127.0.0.1:3001:3000` |
| Scripts | `scripts/*.ps1`, `scripts/*.py` | 9 PowerShell + 8 Python |
| Tool manifests | `tools/*/tool.json` | 5 manifests with install hints |
| Nuclei guidance | `tools/nuclei/README.md` | Profile rationale documented |
| Runner wrappers | `runners/*-runner/main.py` | 5 |
| Parser wrappers | `parsers/*-parser/main.py` | 5 |
| Exercises | `lab/<level>/exNN/` | 12 × (`exercise.json` + `exercise.md`) |
| Documentation | `docs/*.md` | 16 documents |
| Tests | `tests/` | Test modules and fixtures |
| Git exclusions | `.gitignore` | Present; documents what must not be committed |
| Empty skeletons | `reports/{raw,normalized,final}/`, `evidence/`, `state/` | Contain only `.gitkeep` |
| Project files | `README.md`, `LICENSE`, `pyproject.toml` | Present |

## 2. Excluded from the release

| Item | Why |
| --- | --- |
| `.git/` | Version history comes from cloning the repository, not from a copy |
| `.venv`, `venv`, `env` | Machine-specific |
| `__pycache__`, `*.pyc` | Build artifacts |
| `.pytest_cache`, `.mypy_cache`, `.ruff_cache` | Tooling caches |
| `tools/nuclei/templates`, `tools/nuclei/templates-lab` | Re-fetched by `scripts/setup.ps1`; not source |
| `reports/raw/**` | Generated scan output |
| `reports/normalized/**` | Generated findings |
| `reports/final/**` | Generated reports and SARIF |
| `evidence/**/*.json` | Generated evidence records |
| `state/*.json`, `state/assessments/**` | Run index, assessment manifests, student progress |
| `*.log`, `*.tmp`, `*.bak` | Temporary files |
| Any `.env`, credential or key file | Secrets |

## 3. Git repository state

| Check | Command | Expected |
| --- | --- | --- |
| Repository initialised | `git rev-parse --git-dir` | `.git` exists |
| Working tree clean | `git status --porcelain` | no output |
| Initial commit present | `git log --oneline` | one commit describing v1.0.0 |
| Nothing generated tracked | `git ls-files` | no `reports/raw/*`, `evidence/*`, `state/*`, `templates*` |
| Nothing cached tracked | `git ls-files` | no `__pycache__`, `*.pyc`, `*.log`, `.env` |
| Exclusions documented | `.gitignore` | present and current |

## 4. Run-index rotation

| Check | Command | Expected |
| --- | --- | --- |
| Identifiers allocate sequentially | `python -m bcssl runs` | `run-001`, then `run-002` |
| Output is isolated per run | inspect `reports/raw/` | `reports/raw/run-001/run-001-nmap/` |
| Evidence namespaced | inspect `evidence/` | `evidence/run-001/<tool>/` |
| Reports named after the run | `python -m bcssl report` | `reports/final/run-001.{html,json,md,sarif}` |
| Consecutive runs do not overwrite | `pytest tests/test_runs.py` | all pass |
| Hashes stay valid across runs | `python -m bcssl runs --verify` | every run `intact` |
| Tampering is detected | modify a stored artifact, re-run `--verify` | `DRIFT DETECTED` |

## 5. SARIF export

| Check | Command | Expected |
| --- | --- | --- |
| SARIF written | `python -m bcssl report --format sarif` | `reports/final/run-001.sarif` |
| Version declared | inspect the file | `"version": "2.1.0"` |
| Schema declared | inspect the file | `$schema` points at `sarif-schema-2.1.0` |
| Result count matches findings | compare with the JSON report | equal |
| Severity mapped | inspect `level` | only `error`, `warning`, `note` |
| Empty assessment is valid | `python -m bcssl report --format sarif` with no results | valid document, zero results |
| Structure verified | `pytest tests/test_sarif.py` | all pass |

## 6. Safety verification before release

| Check | Command | Expected |
| --- | --- | --- |
| Authorized target only | `python -m bcssl validate-target` | `AUTHORIZED TARGET http://localhost:3001` |
| Public domain refused | `python -m bcssl validate-target --url https://example.com` | `TARGET REJECTED`, exit 2 |
| Public IP refused | `python -m bcssl validate-target --url http://8.8.8.8:3001` | `TARGET REJECTED`, exit 2 |
| Wrong port refused | `python -m bcssl validate-target --url http://localhost:3000` | `TARGET REJECTED`, exit 2 |
| Credential URL refused | `python -m bcssl validate-target --url http://user:pass@localhost:3001` | `TARGET REJECTED`, exit 2 |
| Argument smuggling refused | `python -m bcssl validate-target --url "http://localhost:3001/ -oX /tmp/x"` | `TARGET REJECTED`, exit 2 |
| Destructive Nikto tuning refused | `python -m bcssl run nikto --tuning 126` | `refusing nikto tuning` |
| Out-of-scope module refused | `python -m bcssl run custom-scanner --modules exploit` | `unknown custom scanner module` |
| Intrusive Nuclei tags excluded | inspect `bcssl/runners/nuclei.py` | `MANDATORY_EXCLUDE_TAGS` merged at build time |
| Dashboard binds loopback only | `python -m bcssl web --host 0.0.0.0` | Refused, exit 2 |
| Target bound to loopback | `scripts/check-target.ps1` | `127.0.0.1:3001` |
| No public host is executable | `Select-String` over `bcssl/` for non-loopback URLs | Only rejection tests and install-documentation links |

## 7. Functional verification before release

| Check | Command | Expected |
| --- | --- | --- |
| Engine imports | `python -m compileall -q bcssl` | No errors |
| Test suite | `python -m pytest` | All pass |
| Preflight | `python -m bcssl preflight` | Component table; ready or blocking listed |
| Target reachable | `python -m bcssl validate-target` | `TARGET REACHABLE (HTTP 200)` |
| Tool detection | `python -m bcssl preflight` | 5/5 available, or explicit `[MISS]` with hints |
| Missing tool honest | point a tool at a bogus executable | `TOOL NOT INSTALLED`, 0 findings |
| Individual run | `python -m bcssl run nmap` | Command, exit code, findings |
| Full assessment | `python -m bcssl run-all` | One shared assessment id; per-tool status |
| Report generation | `python -m bcssl report --format html,json,md,sarif` | Four files in `reports/final/` |
| Correlation | `python -m bcssl report --correlation-view` | Confirmed vs single-tool split |
| Evidence integrity | `python -m bcssl collect` | Hashes match |
| Empty-state honesty | `python -m bcssl clean --yes` then `report` | `No scan results available.` |
| Dashboard | `python -m bcssl web --open` | 13 pages, real state only |
| Exercises | `python -m bcssl lab list` | 12 exercises, progress tracking |
| Answer grading | `python -m bcssl lab ack ex01 --answer "q1=..."` | Graded; keys never printed |
| Cleanup | `python -m bcssl clean --yes` | Artifacts removed |

## 8. Extracted-copy verification

Run by `python scripts/verify_release.py`. This is the only check that
demonstrates the **package** works rather than the working directory.

| Check | Expected |
| --- | --- |
| Package extracts to a clean directory | files present |
| Required files present | no missing entries |
| No caches, venvs or Nuclei templates | none found |
| No fabricated results, evidence or run state | none found |
| 12 exercises and 16 documents present | counts match |
| No secrets or credentials | none found |
| `bcssl version` works from the copy | exit 0 |
| `bcssl validate-target` authorizes the target | exit 0 |
| Public domain, public IP and wrong port refused | exit 2 each |
| Dashboard refuses a non-loopback bind | exit 2 |
| Destructive Nikto tuning refused | refusal message |
| `bcssl lab list` loads 12 exercises | exit 0 |
| Run rotation allocates sequentially | `run-001`, `run-002` |
| SARIF builds and validates | valid 2.1.0 |
| Empty-state report is honest | "No scan results available." |
| `compileall` succeeds | exit 0 |
| `pytest` passes | all pass |
| Every PowerShell script parses | 9 scripts |

## 9. Documentation verification before release

| Check | Expected |
| --- | --- |
| Every documented command exists | Cross-check `docs/` against `python -m bcssl --help` |
| Every documented script exists | `scripts/` reference check |
| Every documented document exists | `docs/` link check |
| Target in every document | Only `http://localhost:3001` |
| Tool names match the registry | nmap, zap, nikto, nuclei, custom-scanner |
| Config keys match the code | `config/lab-config.json` vs `bcssl/config.py` defaults |
| Exercises reference real commands | Each `command` runs or explains why the tool is missing |
| Limitations documented | `docs/limitations.md` covers scope, tools, verification, environment |
| Demo commands verified | `docs/demo-guide.md` commands were executed |
| Status honest | `docs/project-status.md` and `docs/final-verification.md` match reality |
| No stale markers | no `TODO`, `FIXME`, `TBD` in code, docs or tests |

## 10. Do-not-modify check

| Project | Check |
| --- | --- |
| `Web-Security-Scanner` (Project #08) | Source file timestamps unchanged; read-only subprocess invocation only |
| `BCSSL-Student-Web-Security-Lab` | No files added, changed or removed |

## 11. Final sign-off

| Item | State |
| --- | --- |
| All automated tests pass | ☐ |
| All five tools verified by real execution | ☐ |
| Run-index rotation verified | ☐ |
| SARIF export verified | ☐ |
| No fabricated results or evidence in the package | ☐ |
| No secrets or credentials | ☐ |
| No public target reachable from the package | ☐ |
| Git repository initialised and clean | ☐ |
| Release audit clean (`build_release.py` exit 0) | ☐ |
| **Extracted-copy verification passed (`verify_release.py` exit 0)** | ☐ |
| Documentation matches the implementation | ☐ |
| Protected projects untouched | ☐ |

A release is only valid when every row above is checked, including the
extracted-copy verification. `docs/final-verification.md` records the evidence
for the current build.
