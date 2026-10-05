"""Command-line interface for the BCSSL Cybersecurity Assessment Lab.

Commands::

    validate-target   Check a target against the authorized scope
    preflight         Report which tools are actually installed
    run <tool>        Run one tool through the full runner contract
    run-all           Run several tools and store the results
    collect           Normalize, correlate and index evidence from stored runs
    report            Render the consolidated report
    status            Dashboard summary: target, tools, runs, progress
    lab               List, show and acknowledge exercises
    web               Start the optional local web dashboard
    version           Print the lab version

Nothing here fabricates a result. A tool that is not installed reports
``TOOL NOT INSTALLED``; a target that is not authorized is refused before any
command is constructed.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import webbrowser
from typing import Any, Sequence

from . import (
    __version__,
    evidence as evidence_module,
    paths,
    pipeline,
    preflight,
    reporting,
    runs,
)
from .config import ConfigError, LabConfig
from .lab import exercises as exercise_module
from .lab import progress as progress_module
from .models import RunStatus
from .severity import ORDERED_SEVERITIES
from .target import (
    TargetRejectedError,
    check_reachability,
    describe_scope,
    validate_target,
)

# ---------------------------------------------------------------------------
# Console helpers
# ---------------------------------------------------------------------------
_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _paint(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _COLOR else text


def bold(text: str) -> str:
    return _paint(text, "1")


def dim(text: str) -> str:
    return _paint(text, "2")


def red(text: str) -> str:
    return _paint(text, "31")


def green(text: str) -> str:
    return _paint(text, "32")


def yellow(text: str) -> str:
    return _paint(text, "33")


def cyan(text: str) -> str:
    return _paint(text, "36")


def rule(title: str = "") -> None:
    width = 62
    if title:
        text = f" {title} ".center(width, "-")
    else:
        text = "-" * width
    print(text)


def emit_json(payload: Any) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=False, default=str))


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
def cmd_validate_target(args: argparse.Namespace, config: LabConfig) -> int:
    if args.url is None:
        print(describe_scope(config))
        print()
    candidate = args.url or config.authorized_url
    validation = validate_target(candidate, config)

    if args.json:
        emit_json(validation.to_dict())
        return 0 if validation.ok else 2

    if validation.ok:
        print()
        print(green("AUTHORIZED TARGET"))
        print(f"  {validation.url}")
        print(f"  host={validation.host} port={validation.port} scheme={validation.scheme}")
        if validation.addresses:
            print(f"  resolved to: {', '.join(validation.addresses)}")
        print(f"  {dim(validation.reason)}")
        if not args.no_probe:
            probe = check_reachability(
                validation, timeout=float(config.http.get("timeout_seconds", 15))
            )
            if probe.reachable:
                print(f"  {green('TARGET REACHABLE')} (HTTP {probe.status_code})")
            else:
                print(f"  {yellow('TARGET UNREACHABLE')}: {probe.error}")
        print()
        return 0

    print()
    print(red("TARGET REJECTED - NOT AUTHORIZED"))
    print(f"  requested: {candidate}")
    print(f"  reason:    {validation.reason}")
    print(f"  code:      {validation.code}")
    print(f"  {dim('Only the configured loopback target may be assessed.')}")
    print()
    return 2


def cmd_preflight(args: argparse.Namespace, config: LabConfig) -> int:
    """Professional environment preflight table."""
    from . import preflight_report

    report = preflight_report.run(config, include_tools=not getattr(args, "no_tools", False))

    if args.json:
        emit_json(report.to_dict())
        return 0 if report.ready else 1

    print()
    print(green("AUTHORIZED TARGET"))
    print(f"  {config.authorized_url}")
    print(f"  {dim('All other hosts, domains, IPs and ports are refused.')}")
    print()
    print(preflight_report.render_table(report))

    remedies = preflight_report.render_remedies(report)
    if remedies:
        print(remedies)

    print()
    if report.ready:
        print(green(f"  Lab is ready. {len(report.ready_tools)}/5 assessment tools usable."))
        print(dim("  Start the authorized target with: scripts/start-target.ps1"))
        print(dim("  Run the full assessment with:     scripts/run-all.ps1"))
        print()
        return 0

    print(yellow("  Blocking problems: " + ", ".join(c.name for c in report.blocking)))
    print(dim("  Fix them, or run a scan anyway; unavailable tools are reported, not faked."))
    print()
    return 1


def cmd_update_templates(args: argparse.Namespace, config: LabConfig) -> int:
    """Download the nuclei template set (setup only, never a scan)."""
    from . import templates as templates_module

    result = templates_module.update_templates(config)
    print()
    if args.json:
        emit_json({"ok": result.ok, "message": result.message, "templates": result.downloaded})
    else:
        if result.ok:
            print(green(f"[ OK ] {result.message}"))
            print(dim(f"       {result.downloaded} template file(s) available"))
        else:
            print(red(f"[FAIL] {result.message}"))
    return 0 if result.ok else 1


def cmd_build_template_profile(args: argparse.Namespace, config: LabConfig) -> int:
    """Build the curated nuclei lab profile."""
    from . import templates as templates_module

    result = templates_module.build_template_profile(overwrite=args.force)
    print()
    if args.json:
        emit_json({"ok": result.ok, "message": result.message, "details": result.details})
    else:
        if result.ok:
            print(green(f"[ OK ] {result.message}"))
            for detail in result.details:
                print(dim(f"       {detail}"))
        else:
            print(red(f"[FAIL] {result.message}"))
    return 0 if result.ok else 1


def cmd_clean(args: argparse.Namespace, config: LabConfig) -> int:
    """Remove generated scan artifacts, evidence and student progress."""
    from . import clean as clean_module

    if args.json:
        # Only report; never delete under --json, which is a read-only mode.
        print(json.dumps(clean_module.clean().__class__().__dict__, indent=2))
        return 0

    if not args.yes:
        answer = input(
            "This removes generated scan artifacts, evidence and progress. "
            "Type 'yes' to continue: "
        )
        if answer.strip().lower() != "yes":
            print("Cancelled. Nothing was removed.")
            return 0

    result = clean_module.clean(
        keep_evidence=args.keep_evidence, keep_progress=args.keep_progress
    )
    print()
    for area in result.areas:
        print(f"  cleaned {area}")
    print()
    print(
        f"[ OK ] Removed {result.removed_files} file(s) and "
        f"{result.removed_dirs} director(ies), "
        f"{result.freed_bytes / 1024:.0f} KB freed."
    )
    print("      The lab now has no scan results.")
    for item in result.skipped:
        print(f"      skipped: {item}")
    print()
    return 0


def cmd_verify(args: argparse.Namespace, config: LabConfig) -> int:
    """Independently re-check what the tools reported."""
    from .verify import apply_verification, verify

    assessment = pipeline.collect(config, verify_findings=False)
    findings = assessment.all_findings
    print()
    rule("INDEPENDENT VERIFICATION")
    if not findings:
        print(f"  {yellow(reporting.NO_RESULTS_MESSAGE)}")
        print(dim("  Run a tool first: python -m bcssl run <tool>"))
        return 0

    result = verify(findings, config)
    print(f"  target   : {result.target}")
    if not result.reachable:
        print(f"  {red('TARGET UNREACHABLE')}: {result.error}")
        return 1
    print(f"  HTTP     : {result.status_code}")
    print(f"  headers  : {len(result.response_headers)} captured")
    print()
    if not result.confirmed:
        print("  No finding in this run was of a condition the lab can re-check.")
        print(dim("  (path discovery, CVE checks and version banners need the tool's own evidence)"))
        return 0
    for subject in sorted(result.confirmed):
        mark = green("confirmed") if result.confirmed[subject] else dim("not reproduced")
        print(f"  {mark:<15} {subject}: {result.notes.get(subject, '')}")
    counters = apply_verification(findings, result)
    print()
    print(f"  DETECTED: {counters.get('DETECTED', 0)} finding(s) reproduced independently")
    print()
    return 0


def _print_run_result(result: Any) -> None:
    """Render one tool run honestly, including failures."""
    status_line = result.status.label
    if result.status.is_success:
        print(f"  {green(status_line)}")
    else:
        print(f"  {red(status_line)}")

    if result.command:
        print(f"  {dim('command: ' + ' '.join(result.command))}")
    if result.tool_version:
        print(f"  {dim('version: ' + result.tool_version)}")
    if result.exit_code is not None:
        print(f"  {dim(f'exit code: {result.exit_code}')}")
    if result.duration_seconds:
        print(f"  {dim(f'duration: {result.duration_seconds:.1f}s')}")

    for message in result.errors:
        print(f"  {red('error:')} {message}")
    for message in result.warnings:
        print(f"  {yellow('warning:')} {message}")
    if result.install_hint and result.status is RunStatus.TOOL_NOT_INSTALLED:
        print(f"  {dim('install: ' + result.install_hint)}")

    if result.status.is_success:
        counts = result.severity_counts()
        total = result.finding_count
        print(f"  findings: {total}")
        if total:
            summary = ", ".join(
                f"{level.value}={counts[level.value]}"
                for level in ORDERED_SEVERITIES
                if counts[level.value]
            )
            print(f"  {dim('severities: ' + summary)}")
        else:
            print(f"  {dim('no findings were reported by this tool for this run.')}")
        if result.stdout_path:
            print(f"  {dim('raw output: ' + result.stdout_path)}")
        if result.evidence:
            print(f"  {dim(f'evidence records: {len(result.evidence)}')}")
    print()


def _tool_options(args: argparse.Namespace) -> dict[str, Any]:
    options: dict[str, Any] = {}
    if getattr(args, "modules", None):
        options["modules"] = args.modules
    if getattr(args, "mode", None):
        options["mode"] = args.mode
    if getattr(args, "tuning", None):
        options["tuning"] = args.tuning
    if getattr(args, "severities", None):
        options["severities"] = args.severities
    if getattr(args, "ports", None):
        options["ports"] = args.ports
    if getattr(args, "timeout", None):
        options["timeout"] = args.timeout
    return options


def cmd_run(args: argparse.Namespace, config: LabConfig) -> int:
    validation = validate_target(args.url or config.authorized_url, config)
    if not validation.ok and not args.json:
        print(red("TARGET REJECTED - NOT AUTHORIZED"))
        print(f"  {validation.reason}")
        return 2

    options = _tool_options(args)
    print()
    rule(f"RUN {args.tool.upper()}")
    if not args.json:
        print(green("AUTHORIZED TARGET"))
        print(f"  {validation.url or config.authorized_url}")
        print()

    result = pipeline.run_tool(
        args.tool,
        config,
        url=args.url,
        options=options,
        skip_reachability=args.skip_reachability,
    )
    pipeline.persist_result(result)

    if args.json:
        emit_json(result.to_dict())
    else:
        _print_run_result(result)

    if not args.no_report:
        assessment = pipeline.collect(config)
        written = reporting.write_reports(assessment, formats=("json",))
        if not args.json:
            print(f"  {dim('normalized findings: ' + str(written['json'].name))}")
    return 0 if result.status.is_success else 1


def cmd_run_all(args: argparse.Namespace, config: LabConfig) -> int:
    validation = validate_target(args.url or config.authorized_url, config)
    if not validation.ok:
        if args.json:
            emit_json({"ok": False, "reason": validation.reason, "code": validation.code})
        else:
            print(red("TARGET REJECTED - NOT AUTHORIZED"))
            print(f"  {validation.reason}")
        return 2

    tools = (
        [part.strip() for part in args.tools.split(",") if part.strip()]
        if args.tools
        else list(config.tool_names())
    )

    if not args.json:
        print()
        print(green("AUTHORIZED TARGET"))
        print(f"  {validation.url}")
        print(f"  {dim('tools: ' + ', '.join(tools))}")
        print()

    results = []
    for tool in tools:
        if not args.json:
            rule(tool.upper())
        try:
            result = pipeline.run_tool(
                tool,
                config,
                url=args.url,
                options=_tool_options(args),
                skip_reachability=args.skip_reachability,
            )
        except ValueError as exc:
            print(red(f"  {exc}"))
            continue
        pipeline.persist_result(result)
        results.append(result)
        if not args.json:
            _print_run_result(result)

    if args.json:
        emit_json([result.to_dict() for result in results])
    else:
        assessment = pipeline.collect(config)
        written = reporting.write_reports(assessment, formats=("json",))
        print(f"  {dim('normalized report: ' + written['json'].name)}")
        print(dim("  Run 'python -m bcssl report' for the consolidated report."))
    return 0 if all(r.status.is_success for r in results) else 1


def cmd_collect(args: argparse.Namespace, config: LabConfig) -> int:
    assessment = pipeline.collect(config)
    payload = {
        "target": assessment.target.to_dict() if assessment.target else {},
        "runs": len(assessment.results),
        "findings": len(assessment.all_findings),
        "correlation": assessment.correlation.summary(),
        "evidence_records": len(assessment.evidence_records),
    }
    if args.json:
        emit_json(payload)
        return 0

    print()
    rule("COLLECT")
    print(f"  target          : {assessment.target.url if assessment.target else '-'}")
    print(f"  stored runs     : {len(assessment.results)}")
    print(f"  findings        : {len(assessment.all_findings)}")
    summary = payload["correlation"]
    print(f"  confirmed (2+)  : {summary['confirmed_by_multiple_tools']}")
    print(f"  single-tool     : {summary['single_tool_observations']}")
    print(f"  evidence records: {len(assessment.evidence_records)}")
    for note in summary["notes"]:
        print(f"  {dim('note: ' + note)}")
    for warning in assessment.warnings:
        print(f"  {yellow(warning)}")
    print()
    return 0


def cmd_report(args: argparse.Namespace, config: LabConfig) -> int:
    assessment = pipeline.collect(config)
    formats = [fmt.strip().lower() for fmt in args.format.split(",") if fmt.strip()]

    # Attach reports to the assessment they describe, so each assessment owns
    # an isolated report set.
    run_id = ""
    try:
        run_id = runs.resolve(getattr(args, "run", None))
    except runs.RunIdError as exc:
        # --json output must stay machine-readable, so this note is only
        # printed in human mode.
        if not args.json:
            print(dim(f"  {exc}"))

    try:
        written = reporting.write_reports(assessment, formats=formats, run_id=run_id or None)
    except ValueError as exc:
        print(red(str(exc)))
        return 2

    if args.json:
        emit_json(reporting.build_payload(assessment))
        return 0

    print()
    rule("REPORT")
    if not assessment.results:
        print(f"  {yellow(reporting.NO_RESULTS_MESSAGE)}")
        print(dim("  Run 'python -m bcssl run <tool>' first."))
    else:
        summary = assessment.correlation.summary()
        print(f"  assessment     : {run_id or dim('(none recorded)')}")
        print(f"  findings        : {len(assessment.all_findings)}")
        print(f"  confirmed (2+)  : {summary['confirmed_by_multiple_tools']}")
        print(f"  single-tool     : {summary['single_tool_observations']}")
    for fmt, path in written.items():
        print(f"  {fmt:<15}: {paths.relative_to_root(path)}")

    if args.correlation_view and assessment.correlation.groups:
        print()
        rule("CORRELATION VIEW")
        for group in assessment.correlation.groups:
            marker = green("[CONFIRMED]") if group.is_confirmed else dim("[SINGLE]   ")
            print(f"  {marker} {group.severity.value:<8} {group.title}")
            print(f"              tools: {', '.join(group.tools)}")
            if group.endpoints:
                print(f"              endpoints: {', '.join(group.endpoints[:4])}")
    print()

    if args.open:
        target = written.get("html") or written.get("json")
        if target is not None:
            webbrowser.open(target.resolve().as_uri())
    return 0


def cmd_runs(args: argparse.Namespace, config: LabConfig) -> int:
    """List assessment runs, their isolated outputs and evidence integrity."""
    identifiers = runs.list_runs()
    rows = runs.summarise(identifiers)

    integrity: dict[str, Any] = {}
    if args.verify:
        for run_id in identifiers:
            result = evidence_module.verify_assessment(run_id, config.tool_names())
            integrity[run_id] = result.to_dict()

    if args.json:
        emit_json({"runs": rows, "evidence_integrity": integrity})
        return 0

    print()
    rule("ASSESSMENT RUNS")
    if not rows:
        print(f"  {yellow(reporting.NO_RESULTS_MESSAGE)}")
        print(dim("  Run 'python -m bcssl run-all' to create the first assessment."))
        print()
        return 0

    for row in rows:
        print(f"  {row['run_id']}  {row['status']:<24} tools={row['tool_count']}  findings={row['finding_count']}")
        if row["started_at"]:
            print(dim(f"      started {row['started_at']}"))
        for tool in row["tools"]:
            marker = green("ok  ") if tool["status"] in ("ok", "partial") else red("FAIL")
            print(f"      {marker} {tool['tool']:<16} findings={tool['finding_count']}")
        for report in row["reports"]:
            print(dim(f"      report: {report}"))
        check = integrity.get(row["run_id"])
        if check:
            verdict = green("intact") if check["ok"] else red("DRIFT DETECTED")
            print(f"      evidence: {check['intact']}/{check['checked']} {verdict}")
            for item in check["modified"] + check["missing"]:
                print(red(f"        {item}"))
        print()
    return 0


def cmd_status(args: argparse.Namespace, config: LabConfig) -> int:
    validation = validate_target(config.authorized_url, config)
    probe = check_reachability(
        validation, timeout=float(config.http.get("timeout_seconds", 15))
    )
    statuses = preflight.detect_all(config)
    results = pipeline.results_from_index()
    try:
        exercises = exercise_module.load_all()
        progress = progress_module.load_progress()
        progress_summary = progress.summary(exercises)
        progress_error = ""
    except exercise_module.ExerciseError as exc:
        exercises, progress_summary = [], {}
        progress_error = str(exc)

    payload = {
        "lab": config.lab_name,
        "version": __version__,
        "target": {
            **validation.to_dict(),
            "reachable": probe.reachable,
            "status_code": probe.status_code,
            "reachability_error": probe.error,
        },
        "tools": [status.to_dict() for status in statuses.values()],
        "runs": [
            {
                "tool": result.tool,
                "status": result.status.value,
                "status_label": result.status.label,
                "finding_count": result.finding_count,
                "finished_at": result.finished_at,
            }
            for result in results
        ],
        "progress": progress_summary,
        "progress_error": progress_error,
    }

    if args.json:
        emit_json(payload)
        return 0

    print()
    rule("LAB STATUS")
    print(f"  Lab         : {config.lab_name} v{__version__}")
    print()
    print(green("AUTHORIZED TARGET"))
    print(f"  {validation.url}")
    if probe.reachable:
        print(f"  {green('reachable')} (HTTP {probe.status_code})")
    else:
        print(f"  {yellow('unreachable')}: {probe.error}")
    print()
    rule("TOOLS")
    for tool, status in statuses.items():
        marker = green("available    ") if status.available else red("not installed")
        print(f"  {tool:<16} {marker}")
    print()
    rule("RECENT RUNS")
    if results:
        for result in sorted(results, key=lambda r: r.finished_at)[-8:]:
            marker = green("ok        ") if result.status.is_success else red("failed    ")
            print(
                f"  {result.finished_at or '-':<22} {result.tool:<16} "
                f"{marker} {result.finding_count} finding(s)"
            )
    else:
        print(f"  {dim('No scan results available.')}")
    print()
    rule("LAB PROGRESS")
    if progress_error:
        print(f"  {red(progress_error)}")
    elif progress_summary:
        print(
            f"  {progress_summary['complete']}/{progress_summary['total']} exercises complete "
            f"({progress_summary['percent']}%)"
        )
        for level, stats in progress_summary["by_level"].items():
            print(
                f"    {level:<14} {stats['complete']}/{stats['total']} complete"
            )
    print()
    return 0


def _student_exercise(exercise: Any) -> dict[str, Any]:
    """Exercise payload with every grading key removed.

    Answer keys must never reach a student, through the CLI, the dashboard or
    a report.
    """
    from .lab.quiz import student_view

    data = exercise.to_dict()
    data["questions"] = [student_view(question) for question in exercise.questions]
    return data


def cmd_lab(args: argparse.Namespace, config: LabConfig) -> int:
    if args.lab_command == "list":
        exercises = exercise_module.load_all()
        progress = progress_module.load_progress()
        if args.json:
            emit_json(
                [
                    {
                        **_student_exercise(exercise),                        "progress": progress.status_for(exercise),
                    }
                    for exercise in exercises
                ]
            )
            return 0
        print()
        rule("LAB EXERCISES")
        for level in exercise_module.LEVELS:
            items = [ex for ex in exercises if ex.level == level]
            if not items:
                continue
            print(f"\n  {bold(level.upper())}")
            for exercise in items:
                status = progress.status_for(exercise)
                mark = green("[x]") if status["complete"] else (
                    yellow("[~]") if status["started"] else "[ ]"
                )
                percent = f"{status['percent']:.0f}%"
                print(
                    f"    {mark} {exercise.id}  {exercise.title}"
                    f"  {dim('(' + percent + ')')}"
                )
        summary = progress.summary(exercises)
        print()
        print(
            f"  {summary['complete']}/{summary['total']} complete "
            f"({summary['percent']}%)"
        )
        print(dim("  Progress requires evidence, answers and checklist ticks - "
                  "running a tool never marks an exercise complete."))
        print()
        return 0

    if args.lab_command == "show":
        try:
            exercise = _find_exercise(args.exercise_id)
        except exercise_module.ExerciseError as exc:
            print(red(str(exc)))
            return 2
        progress = progress_module.load_progress()
        status = progress.status_for(exercise)
        if args.json:
            emit_json({**_student_exercise(exercise), "progress": status})
            return 0
        print()
        print(bold(f"Exercise {exercise.step}: {exercise.title}"))
        rule()
        print(f"  Level             : {exercise.level}")
        print(f"  Tool              : {exercise.tool}")
        print(f"  Authorized target : {exercise.authorized_target}")
        print()
        print(bold("Objective"))
        print(f"  {exercise.objective}")
        print()
        print(bold("Prerequisites"))
        for item in exercise.prerequisites:
            print(f"  - {item}")
        print()
        print(bold("Exact command"))
        print(f"  {cyan(exercise.command)}")
        print()
        print(bold("Expected observation"))
        print(f"  {exercise.expected_observation}")
        print()
        print(bold("Student task"))
        for index, item in enumerate(exercise.student_task, start=1):
            print(f"  {index}. {item}")
        print()
        print(bold("Evidence requirement"))
        for item in exercise.evidence_requirement:
            print(f"  - {item}")
        print()
        print(bold("Questions"))
        for question in exercise.questions:
            print(f"  {question.get('id')}. {question.get('question')}")
        print()
        print(bold("Completion checklist"))
        ticked = set(progress.entries[exercise.id].checks) if exercise.id in progress.entries else set()
        for item in exercise.checklist:
            mark = green("[x]") if item["id"] in ticked else "[ ]"
            print(f"  {mark} {item['id']}: {item['label']}")
        print()
        print(bold("Safety note"))
        print(f"  {yellow(exercise.safety_note)}")
        print()
        print(bold("Progress"))
        print(f"  checklist   : {status['checks_done']}/{status['checks_total']}")
        print(f"  questions   : {status['questions_answered']}/{status['questions_total']}")
        print(f"  evidence    : {'recorded' if status['evidence_recorded'] else 'not recorded'}")
        print(
            f"  completion  : "
            f"{green('COMPLETE') if status['complete'] else dim('incomplete')}"
        )
        print()
        return 0

    if args.lab_command == "ack":
        progress = progress_module.load_progress()
        answers = {}
        for item in args.answer or []:
            if "=" not in item:
                print(red(f"  answer must look like q1=your answer, got '{item}'"))
                return 2
            key, _, value = item.partition("=")
            answers[key.strip()] = value.strip()
        try:
            status = progress_module.ack_exercise(
                progress,
                args.exercise_id,
                checks=args.check or [],
                answers=answers,
                evidence=args.evidence or [],
            )
        except (exercise_module.ExerciseError, ValueError) as exc:
            print(red(f"  {exc}"))
            return 2
        if args.json:
            emit_json(status)
            return 0
        print()
        print(f"  {args.exercise_id}: checklist {status['checks_done']}/{status['checks_total']}, "
              f"questions {status['questions_answered']}/{status['questions_total']}, "
              f"evidence {'recorded' if status['evidence_recorded'] else 'missing'}")
        if status["complete"]:
            print(f"  {green('Exercise complete.')}")
        else:
            missing = []
            if status["missing_checks"]:
                missing.append(f"checklist {', '.join(status['missing_checks'])}")
            if status["missing_answers"]:
                missing.append(f"questions {', '.join(status['missing_answers'])}")
            if not status["evidence_recorded"]:
                missing.append("an evidence reference")
            print(dim("  Still required: " + "; ".join(missing)))
        print()
        return 0

    if args.lab_command == "progress":
        exercises = exercise_module.load_all()
        progress = progress_module.load_progress()
        summary = progress.summary(exercises)
        if args.json:
            emit_json(
                {
                    "summary": summary,
                    "exercises": [
                        progress.status_for(exercise) for exercise in exercises
                    ],
                }
            )
            return 0
        print()
        rule("PROGRESS")
        print(f"  {summary['complete']}/{summary['total']} exercises complete ({summary['percent']}%)")
        print()
        for level, stats in summary["by_level"].items():
            print(f"  {bold(level)}: {stats['complete']}/{stats['total']} complete ({stats['percent']}%)")
        print()
        for exercise in exercises:
            status = progress.status_for(exercise)
            mark = green("[x]") if status["complete"] else (
                yellow("[~]") if status["started"] else "[ ]"
            )
            print(f"    {mark} {exercise.id} {status['percent']:>5.1f}%  {exercise.title}")
        print()
        return 0

    if args.lab_command == "reset":
        if args.exercise_id:
            progress = progress_module.load_progress()
            done = progress_module.reset_exercise(progress, args.exercise_id)
            print(f"  {'reset' if done else 'nothing to reset for'} {args.exercise_id}")
        else:
            progress_module.reset_progress()
            print("  all recorded progress cleared")
        return 0

    print(red("  unknown lab command"))
    return 2


def _find_exercise(exercise_id: str) -> exercise_module.Exercise:
    errors: list[str] = []
    for level in exercise_module.LEVELS:
        try:
            return exercise_module.load_exercise(level, exercise_id)
        except exercise_module.ExerciseError as exc:
            errors.append(str(exc))
    raise exercise_module.ExerciseError(
        f"exercise '{exercise_id}' not found. Known exercises: "
        f"{', '.join(ex.id for ex in exercise_module.load_all())}"
    )


def cmd_web(args: argparse.Namespace, config: LabConfig) -> int:
    from .web.server import serve

    host = args.host or str(config.web.get("host", "127.0.0.1"))
    port = int(args.port or config.web.get("port", 8765))

    # The dashboard is a local tool; refuse to expose it beyond loopback.
    if host not in ("127.0.0.1", "localhost", "::1"):
        print(
            red(
                "  The web dashboard binds to loopback only. Start Docker "
                "Desktop to reach it from another machine, or use an SSH tunnel."
            )
        )
        return 2

    url = f"http://{host}:{port}"
    print()
    print(green("AUTHORIZED TARGET"))
    print(f"  {config.authorized_url}")
    print()
    print(f"  dashboard : {url}")
    print(dim("  press Ctrl+C to stop"))
    if args.open:
        webbrowser.open(url)
    try:
        serve(host, port, config)
    except KeyboardInterrupt:
        print()
        print("  dashboard stopped")
    return 0


def cmd_version(args: argparse.Namespace, config: LabConfig) -> int:
    payload = {
        "lab": config.lab_name,
        "version": __version__,
        "authorized_target": config.authorized_url,
        "config_source": str(config.source) if config.source else "built-in defaults",
    }
    if args.json:
        emit_json(payload)
    else:
        print(f"{payload['lab']} v{payload['version']}")
        print(f"authorized target: {payload['authorized_target']}")
        print(f"configuration    : {payload['config_source']}")
    return 0


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bcssl",
        description=(
            "BCSSL Cybersecurity Assessment Lab - authorized local assessment "
            f"of {LabConfig.load().authorized_url}"
        ),
        epilog=(
            "Only the authorized loopback target may be scanned. Tools that are "
            "not installed are reported as TOOL NOT INSTALLED."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--config",
        metavar="PATH",
        help="alternate lab configuration file",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # validate-target
    p = sub.add_parser(
        "validate-target", help="check a target against the authorized scope"
    )
    p.add_argument("--url", help="URL to validate (default: the authorized target)")
    p.add_argument("--no-probe", action="store_true", help="skip the reachability probe")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.set_defaults(func=cmd_validate_target)

    # preflight
    p = sub.add_parser(
        "preflight", help="professional environment preflight table"
    )
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument(
        "--no-tools", action="store_true", help="skip per-tool detection"
    )
    p.set_defaults(func=cmd_preflight)

    # update-templates
    p = sub.add_parser(
        "update-templates",
        help="download the nuclei template set (setup only, never scans)",
    )
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_update_templates)

    # build-template-profile
    p = sub.add_parser(
        "build-template-profile",
        help="build the curated nuclei lab template profile",
    )
    p.add_argument("--force", action="store_true", help="rebuild existing directories")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_build_template_profile)

    # verify
    p = sub.add_parser(
        "verify",
        help="independently re-check what the tools reported",
    )
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_verify)

    # clean
    p = sub.add_parser(
        "clean",
        help="remove generated scan artifacts, evidence and student progress",
    )
    p.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    p.add_argument("--keep-evidence", action="store_true", help="keep evidence records")
    p.add_argument("--keep-progress", action="store_true", help="keep acknowledgements")
    p.add_argument(
        "--json",
        action="store_true",
        help="dry run: report what would be removed and delete nothing",
    )
    p.set_defaults(func=cmd_clean)

    # run
    p = sub.add_parser("run", help="run one tool against the authorized target")
    p.add_argument("tool", help="nmap, zap, nikto, nuclei or custom-scanner")
    p.add_argument("--url", help="target override (validated; rejected if not authorized)")
    p.add_argument("--timeout", type=float, help="override the tool timeout in seconds")
    p.add_argument("--modules", help="custom-scanner modules (headers,paths,injection)")
    p.add_argument("--mode", choices=("baseline", "passive"), help="ZAP scan mode")
    p.add_argument("--tuning", help="nikto plugin-group tuning string")
    p.add_argument("--severities", help="comma-separated nuclei severities")
    p.add_argument("--ports", help="nmap port specification (authorized ports only)")
    p.add_argument(
        "--skip-reachability",
        action="store_true",
        help="do not probe the target before scanning",
    )
    p.add_argument("--no-report", action="store_true", help="do not write a JSON summary")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.set_defaults(func=cmd_run)

    # run-all
    p = sub.add_parser("run-all", help="run several tools and store the results")
    p.add_argument("--tools", help="comma-separated tool list (default: all)")
    p.add_argument("--url", help="target override (validated)")
    p.add_argument("--timeout", type=float, help="override the tool timeout")
    p.add_argument("--skip-reachability", action="store_true")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_run_all)

    # collect
    p = sub.add_parser("collect", help="normalize, correlate and index stored results")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_collect)

    # report
    p = sub.add_parser("report", help="render the consolidated report")
    p.add_argument(
        "--format",
        default="html",
        help="comma-separated: html, json, md, sarif (default html)",
    )
    p.add_argument(
        "--run",
        default=None,
        metavar="RUN-NNN",
        help="attach the report to a specific assessment (default: the latest)",
    )
    p.add_argument("--correlation-view", action="store_true", help="print the correlation view")
    p.add_argument("--open", action="store_true", help="open the report when finished")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_report)

    # runs
    p = sub.add_parser(
        "runs",
        help="list assessment runs and their isolated outputs",
    )
    p.add_argument("--json", action="store_true")
    p.add_argument(
        "--verify",
        action="store_true",
        help="re-hash each run's evidence artifacts",
    )
    p.set_defaults(func=cmd_runs)

    # status
    p = sub.add_parser("status", help="target, tool, run and progress summary")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_status)

    # lab
    p = sub.add_parser("lab", help="exercise list, detail, acknowledgement and progress")
    sub_lab = p.add_subparsers(dest="lab_command", required=True)

    lp = sub_lab.add_parser("list", help="list exercises with progress")
    lp.add_argument("--json", action="store_true")

    lp = sub_lab.add_parser("show", help="show one exercise in full")
    lp.add_argument("exercise_id")
    lp.add_argument("--json", action="store_true")

    lp = sub_lab.add_parser("ack", help="record your own acknowledgements")
    lp.add_argument("exercise_id")
    lp.add_argument(
        "--check", action="append", metavar="ID", help="acknowledge a checklist item"
    )
    lp.add_argument(
        "--answer", action="append", metavar="QID=TEXT", help="answer a question"
    )
    lp.add_argument(
        "--evidence", action="append", metavar="PATH", help="reference saved evidence"
    )
    lp.add_argument("--json", action="store_true")

    lp = sub_lab.add_parser("progress", help="overall progress")
    lp.add_argument("--json", action="store_true")

    lp = sub_lab.add_parser("reset", help="clear progress for one exercise or all")
    lp.add_argument("exercise_id", nargs="?", help="omit to clear all progress")

    p.set_defaults(func=cmd_lab)

    # web
    p = sub.add_parser("web", help="start the optional local web dashboard")
    p.add_argument("--host", help="bind address (loopback only)")
    p.add_argument("--port", type=int, help="bind port (default 8765)")
    p.add_argument("--open", action="store_true", help="open a browser window")
    p.set_defaults(func=cmd_web)

    # version
    p = sub.add_parser("version", help="print the lab version")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_version)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    paths.ensure_layout()

    try:
        config = LabConfig.load(args.config)
    except ConfigError as exc:
        print(red(f"configuration error: {exc}"))
        return 2

    try:
        return int(args.func(args, config))
    except TargetRejectedError as exc:
        print(red(f"target rejected: {exc.validation.reason}"))
        return 2
    except ValueError as exc:
        # Unknown tool names and invalid option values arrive here. Report them
        # as a clean user error rather than an unhandled traceback.
        print(red(f"  {exc}"))
        return 2
    except KeyboardInterrupt:
        print()
        print("interrupted")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
