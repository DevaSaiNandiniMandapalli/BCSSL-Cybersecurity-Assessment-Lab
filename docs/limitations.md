# Limitations and known issues

This document records what the lab does **not** do, what is not verified, and
where results can legitimately differ. It is deliberately blunt: a lab that
overstates its coverage teaches the wrong lesson.

---

## 1. Scope limitations

**One target, loopback only.** The validator authorizes `http://localhost:3001`
(plus `127.0.0.1:3001` and `[::1]:3001` representations of the same service).
Nothing else can be assessed. This is a feature, not a limitation to work
around.

**Loopback only means single-host.** The lab does not assess a network, a
subnet, a domain, a cloud environment or any remote host. Adding one would
require a deliberate change to `target.allowed_hosts`, and `require_loopback`
would still refuse a non-loopback address.

**Authorized ports only.** By default only 3001. Nmap's port list comes from
`tools.nmap.ports`, default `3001`. Widening it is an instructor decision
recorded in `config/lab-config.json`, and preflight flags non-default ports.

---

## 2. Tool coverage limitations

### Nmap

Port and service discovery only. It does not assess application security, so
**every Nmap finding is INFO**. A closed or filtered port is recorded as a note,
never as a finding. The default scan type is `-sT` (TCP connect); SYN scanning,
OS fingerprinting (`-O`), aggressive script scanning (`-A`) and UDP probing are
refused by the runner.

### OWASP ZAP

Baseline mode only, bounded by `spider.maxDepth`, `spider.maxDuration` and
`scanner.threadPerHost`. Authenticated scanning is not configured.

ZAP's alert *set* depends on `scanner.alertThreshold`. The lab sets it to `0`
(Low) so passive header checks appear. A threshold of `2` would report almost
nothing on this target, which is a configuration difference, not a lab defect.

Current ZAP releases do **not** put the classic `alerts` array in the JSON
report; the lab reads the HTML report instead. Both paths are implemented and
the report records which was used.

### Nikto

Nikto does not assign reliable severity. The lab uses an explicit
`Severity: x` marker when present, otherwise LOW for a matched OSVDB reference
and INFO for everything else. Nothing is inflated.

Nikto's plugin *categories* are version specific. The lab refuses the eight
destructive groups (`0`, `4`, `5`, `6`, `8`, `9`, `a`, `c`) by character, which
is enforced in code - but an instructor who changes `tools.nikto.tuning` should
verify with `nikto -Tuning help` that the resulting selection is still safe.

The `alpine/nikto` image currently ships Nikto 2.1.6, whose JSON format is an
object with a `vulnerabilities` array. Newer 2.5.x releases emit a flat record
stream. **Both are supported and both are covered by tests.**

### Nuclei

Nuclei ships without templates. Without `python -m bcssl update-templates` the
run fails honestly with `no templates provided for scan` - it does not produce
invented findings.

The lab uses a curated profile of roughly 2,600 templates
(`tools/nuclei/templates-lab/`) rather than all 14,000+. Excluded families are
listed with reasons in `tools/nuclei/README.md`. Excluded templates simply do
not run, so **a vulnerability a template would have found is not reported as
absent**.

Destructive tag families are excluded twice over: from configuration *and* from
a mandatory list merged at command-build time, so removing the configured list
does not re-enable them.

Nuclei versions differ in output flags. Nuclei 3.x requires `-j`/`-jsonl` for
JSONL; 2.x derives it from the `.jsonl` output extension. Both are supported
through `tools.nuclei.json_flag`. If Nuclei writes console output instead of
JSONL, the parser reports that as an **error**, not as zero findings.

### Custom Project #08 scanner

Invoked as a subprocess with its own interpreter, from its own directory, and
never modified. Its HTML report is parsed because its console table is
width-dependent and therefore not reliably machine-readable.

Only the modules `headers`, `paths` and `injection` are selectable; anything
else is refused.

---

## 3. Verification limitations

**`DETECTED` is not `PROVEN EXPLOITABLE`.** The lab's independent verifier
(`bcssl/verify.py`) checks a small set of observable conditions: whether specific
headers are present or absent, and whether a path returns a non-error status.
It does **not** attempt exploitation. A `DETECTED` missing-header finding means
the header was absent in a real response, not that an attack succeeded.

**Verification covers a subset of findings.** Only findings whose subject the
verifier understands are re-checked. CVE-style, path-discovery and
version-banner findings cannot be reproduced cheaply and keep their correlated
status.

**Correlation is fingerprint-based, not semantic.** Two tools reporting the same
underlying condition under different wording will appear as two single-tool
observations. This under-correlates rather than over-correlates, by design.

**One scan point in time.** Findings describe the target as it was when scanned.
Nothing is continuously monitored.

---

## 4. Environment limitations

**Container networking.** Tools run with `--network host`. On Docker Desktop
this resolves to the host network, which is required for a tool inside a
container to reach `localhost:3001` on the host. On some hardened hosts,
loopback inside a container is namespaced and the tool will report the target
as unreachable; run it natively in that case.

**Container resource limits.** ZAP needs roughly 1 GB of memory. On a constrained
host, raise Docker Desktop's memory allocation rather than removing the spider
bounds.

**Image drift.** `image:latest` tags move. A future image may change output
formats again. Pin exact tags in `config/lab-config.json` for a stable cohort.

**Nuclei template drift.** Templates are fetched from the internet and change
often. Findings can therefore differ between cohorts even against an unchanged
target. Pin a template release for reproducibility.

**Target initialisation.** Juice Shop needs 30-90 seconds on first start. A scan
started too early reports `TARGET UNREACHABLE`, which is correct behaviour.

---

## 5. Reporting limitations

- The report reflects **only** stored runs. Deleting `state/run-index.json`
  removes all history; the HTML report then says "No scan results available."
- Findings below `pipeline.severity_floor` are dropped after parsing. Raising the
  floor hides them from the report but the raw output still contains them.
- Duplicate findings from one tool and endpoint are collapsed during
  correlation, and the count of collapsed records is reported.
- Severity is not a CVSS score. Nothing here should be presented as one.

---

## 6. Deliberate non-goals

The lab does not, and will not:

- scan anything other than the authorized loopback target;
- perform authentication or credential testing;
- run fuzzing, denial-of-service or load tests;
- execute payloads, upload files, or attempt remote code execution;
- extract data beyond HTTP response headers, status codes and short response
  snippets already collected by the target tools;
- establish persistence or modify the target beyond the requests the tools make;
- provide an exploitation framework.

These are excluded in configuration **and** enforced in code. Nikto's destructive
plugin groups and Nuclei's intrusive tags are refused by the runners rather than
merely omitted from the default settings.

---

## 7. Testing limitations

The automated suite is offline. It never contacts a target and never runs a real
security scan. It covers target validation, command construction, tool
detection, parsers, severity mapping, correlation, evidence hashing, reporting,
the web API and exercise validation.

Real tool behaviour is verified separately by real execution, recorded in
`docs/final-verification.md`. Where a tool could not be executed in the build
environment, this document says so rather than substituting a fixture result.
