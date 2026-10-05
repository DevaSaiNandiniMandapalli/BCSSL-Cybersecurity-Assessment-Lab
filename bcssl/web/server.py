"""Optional local web dashboard (Python standard library only).

No third-party web framework is used. The server binds to loopback only and
exposes a small JSON API plus one static page.

Safety properties:

* Read-only endpoints never start a scan. A scan is started only by an explicit
  POST to ``/api/run``.
* Every run goes through the same runner contract, so the authorized-target
  validator still applies and a missing tool is still reported as
  ``TOOL NOT INSTALLED``.
* An exercise is never marked complete by running a tool; completion requires
  an explicit acknowledgement POST that the student makes.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

from .. import paths, pipeline, preflight, reporting
from ..config import LabConfig
from ..lab import exercises as exercise_module
from ..lab import progress as progress_module
from ..models import RunStatus
from ..target import check_reachability, validate_target

STATIC_DIR = Path(__file__).resolve().parent / "static"

#: Serialises scan execution so two clicks cannot launch overlapping scans.
_RUN_LOCK = threading.Lock()
_RUN_STATE: dict[str, Any] = {"running": False, "tool": "", "started_at": "", "log": []}


def _json_bytes(payload: Any) -> bytes:
    return json.dumps(payload, indent=2, ensure_ascii=False, default=str).encode("utf-8")


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "BCSSL-Lab/1.0"
    protocol_version = "HTTP/1.1"

    # -- plumbing ----------------------------------------------------------
    @property
    def config(self) -> LabConfig:
        return self.server.lab_config  # type: ignore[attr-defined]

    def log_message(self, *args) -> None:  # keep the console clean
        return

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_json(self, payload: Any, status: int = 200) -> None:
        self._send(status, _json_bytes(payload), "application/json; charset=utf-8")

    def _send_text(self, text: str, status: int = 200) -> None:
        self._send(status, text.encode("utf-8"), "text/plain; charset=utf-8")

    def _read_body(self) -> dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return {}
        if length <= 0 or length > 1_000_000:
            return {}
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return {}
        return data if isinstance(data, dict) else {}

    # -- routing -----------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        route = self.path.split("?", 1)[0]
        handlers: dict[str, Callable[[], None]] = {
            "/": self._index,
            "/api/state": self._api_state,
            "/api/status": self._api_status,
            "/api/tools": self._api_tools,
            "/api/exercises": self._api_exercises,
            "/api/exercise": self._api_exercise,
            "/api/findings": self._api_findings,
            "/api/report": self._api_report,
            "/api/evidence": self._api_evidence,
            "/api/correlation": self._api_correlation,
            "/api/preflight": self._api_preflight,
            "/api/target": self._api_target,
            "/api/grade": self._api_grade,
            "/api/progress": self._api_progress,
            "/api/docs": self._api_docs,
        }
        if route in handlers:
            handlers[route]()
            return
        if route.startswith("/static/"):
            self._static(route)
            return
        if route.startswith("/docs/"):
            self._doc_file(route)
            return
        if route == "/healthz":
            self._send_json({"status": "ok"})
            return
        self._send_json({"error": "not found", "path": route}, status=404)

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_POST(self) -> None:  # noqa: N802
        route = self.path.split("?", 1)[0]
        if route == "/api/run":
            self._api_run()
            return
        if route == "/api/run-all":
            self._api_run_all()
            return
        if route == "/api/ack":
            self._api_ack()
            return
        if route == "/api/validate-target":
            self._api_validate()
            return
        if route == "/api/preflight":
            self._api_preflight()
            return
        if route == "/api/grade":
            self._api_grade()
            return
        self._send_json({"error": "not found", "path": route}, status=404)

    # -- endpoints ---------------------------------------------------------
    def _index(self) -> None:
        path = STATIC_DIR / "index.html"
        if not path.is_file():
            self._send_text("dashboard assets are missing", status=500)
            return
        self._send(200, path.read_bytes(), "text/html; charset=utf-8")

    def _static(self, route: str) -> None:
        name = route[len("/static/"):]
        # Contain the request to the static directory.
        target = (STATIC_DIR / name).resolve()
        try:
            target.relative_to(STATIC_DIR.resolve())
        except ValueError:
            self._send_text("forbidden", status=403)
            return
        if not target.is_file():
            self._send_text("not found", status=404)
            return
        types = {
            ".html": "text/html; charset=utf-8",
            ".js": "text/javascript; charset=utf-8",
            ".css": "text/css; charset=utf-8",
            ".json": "application/json; charset=utf-8",
        }
        self._send(
            200,
            target.read_bytes(),
            types.get(target.suffix, "application/octet-stream"),
        )

    def _api_state(self) -> None:
        """Everything the dashboard needs for one render."""
        config = self.config
        validation = validate_target(config.authorized_url, config)
        probe = check_reachability(
            validation, timeout=float(config.http.get("timeout_seconds", 10))
        )
        tools = preflight.detect_all(config)
        results = pipeline.results_from_index()
        findings = [f for result in results for f in result.findings]
        from ..correlation import correlate

        correlation = correlate(findings)
        try:
            exercises = exercise_module.load_all()
            progress = progress_module.load_progress()
            progress_payload = progress.summary(exercises)
            progress_error = ""
        except exercise_module.ExerciseError as exc:
            progress_payload, progress_error = {}, str(exc)

        self._send_json(
            {
                "lab": config.lab_name,
                "authorization_statement": config.authorization_statement,
                "target": {
                    "url": config.authorized_url,
                    "authorized": validation.ok,
                    "reason": validation.reason,
                    "reachable": probe.reachable,
                    "status_code": probe.status_code,
                    "reachability_error": probe.error,
                },
                "tools": [status.to_dict() for status in tools.values()],
                "runs": [
                    {
                        "tool": result.tool,
                        "status": result.status.value,
                        "status_label": result.status.label,
                        "tool_version": result.tool_version,
                        "finding_count": result.finding_count,
                        "severity_counts": result.severity_counts(),
                        "errors": result.errors,
                        "warnings": result.warnings,
                        "finished_at": result.finished_at,
                        "raw_artifacts": result.raw_artifacts,
                    }
                    for result in results
                ],
                "total_findings": len(findings),
                "correlation": correlation.summary(),
                "progress": progress_payload,
                "progress_error": progress_error,
                "run_state": dict(_RUN_STATE),
                "has_results": bool(results),
            }
        )

    def _api_status(self) -> None:
        self._api_state()

    def _api_tools(self) -> None:
        statuses = preflight.detect_all(self.config)
        self._send_json([status.to_dict() for status in statuses.values()])

    def _api_exercises(self) -> None:
        try:
            exercises = exercise_module.load_all()
        except exercise_module.ExerciseError as exc:
            self._send_json({"error": str(exc)}, status=500)
            return
        progress = progress_module.load_progress()
        from ..lab.quiz import student_view

        payload = []
        for exercise in exercises:
            data = exercise.to_dict()
            # Never ship the grading keys to a client.
            data["questions"] = [student_view(question) for question in exercise.questions]
            data["progress"] = progress.status_for(exercise)
            payload.append(data)
        self._send_json(payload)

    def _api_findings(self) -> None:
        results = pipeline.results_from_index()
        self._send_json(
            {
                "has_results": bool(results),
                "findings": [
                    finding.to_internal_dict()
                    for result in results
                    for finding in result.findings
                ],
            }
        )

    def _api_evidence(self) -> None:
        from .. import evidence as evidence_module

        records = evidence_module.all_records(self.config.tool_names())
        self._send_json([record.to_dict() for record in records])

    def _api_target(self) -> None:
        """Target authorization and reachability, as shown on the Target page."""
        config = self.config
        validation = validate_target(config.authorized_url, config)
        probe = check_reachability(
            validation, timeout=float(config.http.get("timeout_seconds", 10))
        )
        self._send_json(
            {
                **validation.to_dict(),
                "reachable": probe.reachable,
                "status_code": probe.status_code,
                "reachability_error": probe.error,
                "server": probe.server,
                "allowed_hosts": list(config.allowed_hosts),
                "allowed_ports": list(config.allowed_ports),
                "authorization_statement": config.authorization_statement,
            }
        )

    def _api_preflight(self) -> None:
        """Component | Status | Version | Details table."""
        from .. import preflight_report

        report = preflight_report.run(self.config)
        payload = report.to_dict()
        payload["table"] = preflight_report.render_table(report)
        payload["remedies"] = preflight_report.render_remedies(report)
        self._send_json(payload)

    def _api_correlation(self) -> None:
        """Correlated findings with the reasoning for each match."""
        assessment = pipeline.collect(self.config, verify_findings=False)
        if not assessment.results:
            self._send_json({"has_results": False, "message": reporting.NO_RESULTS_MESSAGE})
            return
        self._send_json(
            {
                "has_results": True,
                "summary": assessment.correlation.summary(),
                "groups": [
                    {
                        **group.to_dict(),
                        "reasoning": _correlation_reason(group),
                    }
                    for group in assessment.correlation.groups
                ],
            }
        )

    def _api_progress(self) -> None:
        try:
            exercises = exercise_module.load_all()
        except exercise_module.ExerciseError as exc:
            self._send_json({"error": str(exc)}, status=500)
            return
        progress = progress_module.load_progress()
        self._send_json(
            {
                "summary": progress.summary(exercises),
                "badges": progress.badges(exercises),
                "exercises": [progress.status_for(exercise) for exercise in exercises],
            }
        )

    def _api_docs(self) -> None:
        """List the shipped documentation so the dashboard can link to it."""
        documents = []
        for name in (
            "architecture.md",
            "installation.md",
            "tool-guide.md",
            "student-guide.md",
            "instructor-guide.md",
            "evidence-guide.md",
            "reporting.md",
            "troubleshooting.md",
            "limitations.md",
            "project-status.md",
            "final-verification.md",
        ):
            path = paths.project_root() / "docs" / name
            if path.is_file():
                title = ""
                for line in path.read_text(encoding="utf-8").splitlines():
                    if line.startswith("# "):
                        title = line[2:].strip()
                        break
                documents.append(
                    {
                        "name": name,
                        "title": title or name,
                        "path": f"docs/{name}",
                        "bytes": path.stat().st_size,
                    }
                )
        readme = paths.project_root() / "README.md"
        if readme.is_file():
            documents.insert(
                0,
                {
                    "name": "README.md",
                    "title": "README",
                    "path": "docs/README.md",
                    "bytes": readme.stat().st_size,
                },
            )
        self._send_json(documents)

    def _doc_file(self, route: str) -> None:
        """Serve a documentation file as plain text, contained to the repo."""
        name = route[len("/docs/"):]
        if not name or "/" in name or "\\" in name or ".." in name:
            self._send_text("forbidden", status=403)
            return
        candidates = [paths.project_root() / "docs" / name]
        if name == "README.md":
            candidates.append(paths.project_root() / "README.md")
        for candidate in candidates:
            resolved = candidate.resolve()
            try:
                resolved.relative_to(paths.project_root().resolve())
            except ValueError:
                self._send_text("forbidden", status=403)
                return
            if resolved.is_file():
                self._send(200, resolved.read_bytes(), "text/markdown; charset=utf-8")
                return
        self._send_text("not found", status=404)

    def _api_exercise(self) -> None:
        """One exercise, with every answer-key field stripped."""
        query = self.path.split("?", 1)[1] if "?" in self.path else ""
        params = dict(
            part.split("=", 1) for part in query.split("&") if "=" in part
        )
        exercise_id = params.get("id", "")
        if not exercise_id:
            self._send_json({"error": "id query parameter is required"}, status=400)
            return
        from ..lab.quiz import student_view

        try:
            exercise = _find_exercise(exercise_id)
        except exercise_module.ExerciseError as exc:
            self._send_json({"error": str(exc)}, status=404)
            return
        progress = progress_module.load_progress()
        payload = exercise.to_dict()
        payload["questions"] = [student_view(question) for question in exercise.questions]
        payload["progress"] = progress.status_for(exercise)
        self._send_json(payload)

    def _api_grade(self) -> None:
        """Grade submitted answers without ever returning the key."""
        body = self._read_body()
        exercise_id = str(body.get("exercise_id", "")).strip()
        answers = body.get("answers") or {}
        if not exercise_id or not isinstance(answers, dict):
            self._send_json({"error": "exercise_id and answers are required"}, status=400)
            return
        from ..lab.quiz import grade_all

        try:
            exercise = _find_exercise(exercise_id)
        except exercise_module.ExerciseError as exc:
            self._send_json({"error": str(exc)}, status=404)
            return
        results = grade_all(exercise.questions, {str(k): str(v) for k, v in answers.items()})
        self._send_json(
            {
                "exercise_id": exercise_id,
                "passed": sum(1 for item in results if item.passed),
                "total": len(results),
                "results": [item.to_dict() for item in results],
            }
        )

    def _api_run_all(self) -> None:
        """Run the safe full assessment, tool by tool, in the background."""
        body = self._read_body()
        requested = body.get("tools")
        selected = (
            [str(item).strip() for item in requested if str(item).strip()]
            if isinstance(requested, list)
            else None
        )

        with _RUN_LOCK:
            if _RUN_STATE["running"]:
                self._send_json(
                    {"error": f"a {_RUN_STATE['tool']} run is already in progress"},
                    status=409,
                )
                return
            _RUN_STATE.update(
                {"running": True, "tool": "full assessment", "started_at": "", "log": []}
            )

        from ..models import utc_now_iso

        def worker() -> None:
            _RUN_STATE["started_at"] = utc_now_iso()
            log: list[str] = []
            try:
                names = selected or list(self.config.tool_names())
                for name in names:
                    log.append(f"running {name} ...")
                    _RUN_STATE["log"] = list(log)
                    try:
                        result = pipeline.run_tool(name, self.config)
                        pipeline.persist_result(result)
                        log.append(
                            f"{name}: {result.status.label} "
                            f"({result.finding_count} finding(s))"
                        )
                    except Exception as exc:  # noqa: BLE001
                        log.append(f"{name}: ERROR {type(exc).__name__}: {exc}")
                    _RUN_STATE["log"] = list(log)
            finally:
                with _RUN_LOCK:
                    _RUN_STATE["running"] = False
                try:
                    assessment = pipeline.collect(self.config)
                    reporting.write_reports(assessment, formats=("html", "json", "md"))
                except Exception as exc:  # noqa: BLE001
                    log.append(f"report: ERROR {type(exc).__name__}: {exc}")

        threading.Thread(target=worker, daemon=True).start()
        self._send_json({"started": True, "tools": selected or "all"}, status=202)

    def _api_report(self) -> None:
        """Render a report on demand and return the written paths."""
        assessment = pipeline.collect(self.config)
        try:
            written = reporting.write_reports(assessment, formats=("html", "json", "md"))
        except ValueError as exc:
            self._send_json({"error": str(exc)}, status=400)
            return
        self._send_json(
            {
                "has_results": bool(assessment.results),
                "message": reporting.NO_RESULTS_MESSAGE
                if not assessment.results
                else None,
                "files": {
                    fmt: paths.relative_to_root(path) for fmt, path in written.items()
                },
                "findings": len(assessment.all_findings),
                "correlation": assessment.correlation.summary(),
            }
        )

    def _api_validate(self) -> None:
        body = self._read_body()
        candidate = body.get("url") or self.config.authorized_url
        self._send_json(validate_target(candidate, self.config).to_dict())

    def _api_run(self) -> None:
        """Start one tool run through the normal runner contract."""
        body = self._read_body()
        tool = str(body.get("tool", "")).strip()
        url = body.get("url") or self.config.authorized_url
        options = body.get("options") if isinstance(body.get("options"), dict) else {}

        if not tool:
            self._send_json({"error": "a tool name is required"}, status=400)
            return

        with _RUN_LOCK:
            if _RUN_STATE["running"]:
                self._send_json(
                    {"error": f"a {_RUN_STATE['tool']} run is already in progress"},
                    status=409,
                )
                return
            _RUN_STATE.update(
                {"running": True, "tool": tool, "started_at": "", "log": []}
            )

        def worker() -> None:
            from ..models import utc_now_iso

            started = utc_now_iso()
            _RUN_STATE["started_at"] = started
            try:
                result = pipeline.run_tool(tool, self.config, url=url, options=options)
                pipeline.persist_result(result)
                _RUN_STATE["log"] = [
                    f"{result.status.label}",
                    f"findings: {result.finding_count}",
                    *result.errors,
                ]
            except Exception as exc:  # noqa: BLE001 - reported to the dashboard
                _RUN_STATE["log"] = [f"ERROR: {type(exc).__name__}: {exc}"]
            finally:
                with _RUN_LOCK:
                    _RUN_STATE["running"] = False

        threading.Thread(target=worker, daemon=True).start()
        self._send_json(
            {
                "started": True,
                "tool": tool,
                "status": "scan started; poll /api/state for the result",
            },
            status=202,
        )

    def _api_ack(self) -> None:
        """Record student acknowledgements (never triggered by a scan)."""
        body = self._read_body()
        exercise_id = str(body.get("exercise_id", "")).strip()
        if not exercise_id:
            self._send_json({"error": "exercise_id is required"}, status=400)
            return

        checks = body.get("checks") or []
        answers = body.get("answers") or {}
        evidence = body.get("evidence") or []
        if not isinstance(checks, list) or not isinstance(answers, dict) or not isinstance(
            evidence, list
        ):
            self._send_json({"error": "invalid acknowledgement payload"}, status=400)
            return

        progress = progress_module.load_progress()
        try:
            status = progress_module.ack_exercise(
                progress,
                exercise_id,
                checks=[str(item) for item in checks],
                answers={str(k): str(v) for k, v in answers.items()},
                evidence=[str(item) for item in evidence],
            )
        except (exercise_module.ExerciseError, ValueError) as exc:
            self._send_json({"error": str(exc)}, status=400)
            return
        self._send_json({"exercise_id": exercise_id, "progress": status})


def serve(host: str, port: int, config: LabConfig) -> None:
    """Run the dashboard until interrupted."""
    paths.ensure_layout()
    httpd = ThreadingHTTPServer((host, port), DashboardHandler)
    httpd.lab_config = config  # type: ignore[attr-defined]
    try:
        httpd.serve_forever()
    finally:
        httpd.server_close()


def _find_exercise(exercise_id: str) -> exercise_module.Exercise:
    """Locate an exercise across all levels."""
    errors: list[str] = []
    for level in exercise_module.LEVELS:
        try:
            return exercise_module.load_exercise(level, exercise_id)
        except exercise_module.ExerciseError as exc:
            errors.append(str(exc))
    raise exercise_module.ExerciseError(
        f"exercise '{exercise_id}' not found in the lab"
    )


def _correlation_reason(group: Any) -> str:
    """Explain in plain words why a group is (or is not) corroborated."""
    tools = ", ".join(group.tools)
    if group.is_confirmed:
        return (
            f"{len(group.tools)} distinct tools reported the same finding "
            f"fingerprint (category '{group.category}', subject "
            f"'{group.subject}'): {tools}."
        )
    if len(group.tools) == 1:
        return (
            f"Only {group.tools[0]} reported this fingerprint, so it is a "
            "single-tool observation, not a corroborated finding."
        )
    return (
        "The tools reported matching wording but not a canonical fingerprint, "
        "so the lab does not treat this as corroboration."
    )
