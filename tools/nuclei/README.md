# Nuclei lab template profile

`templates-lab/` is a curated subset of the full nuclei template set, chosen so
that a classroom scan finishes in minutes instead of hours while still covering
the check families that matter for a web application lab.

## Why a profile exists

The complete nuclei template set is over 14,000 templates. Running all of it
against one local application is slow, and a large part of it is irrelevant to a
deliberately vulnerable training app. This profile keeps the families that are
both **relevant** and **non-destructive**.

## Included families

| Directory | Templates | What it checks |
| --- | --- | --- |
| `technologies/` | 918 | Framework, product and library fingerprinting (technology disclosure) |
| `misconfiguration/` | 981 | Missing headers, permissive CORS, debug modes, exposed configuration |
| `exposures/` | 707 | Exposed files, directories, backups, `.git`, logs and similar |
| `miscellaneous/` | 55 | Assorted low-risk HTTP checks |

## Deliberately excluded families

These are not copied into the profile. Some are destructive or intrusive, and
others simply cannot apply to a single loopback target.

| Excluded | Reason |
| --- | --- |
| `fuzzing/` | Fuzzing is destructive and explicitly out of scope |
| `credential-stuffing/`, `default-logins/`, `token-spray/` | Credential testing is out of scope |
| `workflows/`, `code/`, `dast/` | Multi-step or code-executing templates |
| `headless/` | Requires a browser engine |
| `network/`, `dns/` | Target non-HTTP services |
| `ssl/` | The lab target is plain HTTP |
| `cves/` | 4,320 templates, almost all irrelevant to Juice Shop; enable deliberately if wanted |
| `exposed-panels/` | Large, slow, and rarely actionable for a training app |
| `takeovers/` | Subdomain takeover checks need external DNS |
| `file/` | Local file access, not applicable to a remote HTTP target |
| `osint/`, `cnvd/`, `iot/` | Require external services or non-HTTP targets |

The runner additionally applies a mandatory tag exclusion list
(`bcssl/runners/nuclei.py:MANDATORY_EXCLUDE_TAGS`) that is merged with the
configured list at command-build time. Removing a tag from configuration does
**not** re-enable destructive templates.

## Refreshing the profile

Templates are not committed. Fetch the full set once, then rebuild the profile:

```bash
python -m bcssl update-templates
python -m bcssl build-template-profile
```

Both commands are safe: they download template definitions only, and never run a
scan.

## Using a different template set

Point the runner at any directory of templates:

```json
"tools": {
  "nuclei": {
    "templates_dir": "/bcssl-templates",
    "docker_extra_mounts": [
      "{project_root}/tools/nuclei/templates:/bcssl-templates:ro"
    ]
  }
}
```

`{project_root}` is expanded at run time, so the committed configuration stays
machine independent.

## Reference

Template selection guidance: `docs/tool-guide.md`. Nuclei project:
<https://docs.projectdiscovery.io/templates/introduction>
