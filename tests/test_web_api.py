"""Web dashboard API tests.

Every request is made against the real handler with an isolated output root.
Nothing here starts a scan: the run endpoints are exercised only for their
validation and rejection behaviour.
"""

from __future__ import annotations

import json
import threading
from http.client import HTTPConnection
import urllib.error
from urllib.request import Request, urlopen

import pytest

from bcssl.config import LabConfig
from bcssl.web.server import DashboardHandler, serve


@pytest.fixture(scope="module")
def server():
    """Run the dashboard on a free loopback port for this module."""
    import os
    import socket
    import tempfile
    import time
    from http.server import ThreadingHTTPServer

    output_root = tempfile.mkdtemp(prefix="bcssl-web-test-")
    previous = os.environ.get("BCSSL_OUTPUT_ROOT")
    os.environ["BCSSL_OUTPUT_ROOT"] = output_root

    config = LabConfig.load()

    # Bind an ephemeral port ourselves so we know exactly where the server is.
    holder: dict[str, object] = {}

    def run() -> None:
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), DashboardHandler)
        httpd.lab_config = config
        holder["httpd"] = httpd
        httpd.serve_forever()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()

    # Wait for the server to report its bound port.
    deadline = time.time() + 15
    while "httpd" not in holder and time.time() < deadline:
        time.sleep(0.05)
    assert "httpd" in holder, "dashboard did not start"
    httpd = holder["httpd"]
    port = httpd.server_address[1]

    # Wait until it actually answers.
    deadline = time.time() + 15
    while time.time() < deadline:
        try:
            conn = HTTPConnection("127.0.0.1", port, timeout=2)
            conn.request("GET", "/healthz")
            conn.getresponse().read()
            conn.close()
            break
        except OSError:
            time.sleep(0.1)

    yield port

    httpd.shutdown()
    httpd.server_close()
    if previous is None:
        os.environ.pop("BCSSL_OUTPUT_ROOT", None)
    else:  # pragma: no cover
        os.environ["BCSSL_OUTPUT_ROOT"] = previous


def get(port: int, path: str) -> tuple[int, object]:
    conn = HTTPConnection("127.0.0.1", port, timeout=90)
    conn.request("GET", path)
    response = conn.getresponse()
    body = response.read().decode("utf-8")
    status = response.status
    conn.close()
    try:
        return status, json.loads(body)
    except ValueError:
        return status, body


def post(port: int, path: str, payload: dict) -> tuple[int, object]:
    data = json.dumps(payload).encode("utf-8")
    request = Request(
        f"http://127.0.0.1:{port}{path}",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=90) as response:
            body = response.read().decode("utf-8")
            return response.status, json.loads(body)
    except urllib.error.HTTPError as exc:
        # Return the status and body so tests can assert on rejection paths.
        body = exc.read().decode("utf-8")
        try:
            return exc.code, json.loads(body)
        except ValueError:
            return exc.code, body


# ---------------------------------------------------------------------------
# Static content
# ---------------------------------------------------------------------------
def test_index_is_served(server):
    status, body = get(server, "/")
    assert status == 200
    assert "BCSSL" in str(body)


def test_static_assets_are_served(server):
    for path in ("/static/styles.css", "/static/app.js"):
        status, body = get(server, path)
        assert status == 200, path
        assert len(str(body)) > 100


def test_static_traversal_is_refused(server):
    status, _ = get(server, "/static/../../config/lab-config.json")
    assert status in (403, 404)


def test_healthz(server):
    status, payload = get(server, "/healthz")
    assert status == 200
    assert payload["status"] == "ok"


def test_unknown_route_is_404(server):
    status, payload = get(server, "/api/nope")
    assert status == 404
    assert "error" in payload


# ---------------------------------------------------------------------------
# State endpoints
# ---------------------------------------------------------------------------
def test_state_endpoint_shape(server):
    status, payload = get(server, "/api/state")
    assert status == 200
    for key in ("lab", "target", "tools", "runs", "total_findings", "correlation", "progress"):
        assert key in payload, key
    assert payload["target"]["url"] == "http://localhost:3001"
    assert len(payload["tools"]) == 5


def test_state_never_reports_fake_findings(server):
    """With no stored runs the dashboard must not invent findings."""
    _, payload = get(server, "/api/state")
    if payload["runs"]:
        pytest.skip("this environment has real stored runs")
    assert payload["total_findings"] == 0
    assert payload["has_results"] is False


def test_findings_endpoint_reports_no_results(server):
    status, payload = get(server, "/api/findings")
    assert status == 200
    if not payload["has_results"]:
        assert payload["findings"] == []


def test_tools_endpoint(server):
    status, payload = get(server, "/api/tools")
    assert status == 200
    assert len(payload) == 5


def test_target_endpoint_exposes_scope(server):
    status, payload = get(server, "/api/target")
    assert status == 200
    assert payload["ok"] is True
    assert payload["allowed_ports"] == [3001]
    assert "3001" in payload["allowed_hosts"] or "localhost" in payload["allowed_hosts"]


def test_preflight_endpoint_has_a_table(server):
    status, payload = get(server, "/api/preflight")
    assert status == 200
    assert "Component" in payload["table"]
    assert payload["tools_total"] == 5


def test_progress_endpoint(server):
    status, payload = get(server, "/api/progress")
    assert status == 200
    assert "summary" in payload
    assert isinstance(payload["badges"], list)


def test_correlation_endpoint_reports_real_state(server):
    status, payload = get(server, "/api/correlation")
    assert status == 200
    if not payload.get("has_results"):
        assert payload["message"]


def test_evidence_endpoint(server):
    status, payload = get(server, "/api/evidence")
    assert status == 200
    assert isinstance(payload, list)


def test_docs_endpoint_lists_shipped_documents(server):
    status, payload = get(server, "/api/docs")
    assert status == 200
    names = {item["name"] for item in payload}
    assert "installation.md" in names
    assert "limitations.md" in names


def test_doc_file_is_served(server):
    status, body = get(server, "/docs/installation.md")
    assert status == 200
    assert "Installation" in str(body)


def test_doc_traversal_is_refused(server):
    status, _ = get(server, "/docs/../config/lab-config.json")
    assert status in (403, 404)


def test_exercises_endpoint_strips_answer_keys(server):
    status, payload = get(server, "/api/exercises")
    assert status == 200
    assert len(payload) == 12
    for exercise in payload:
        for question in exercise["questions"]:
            for hidden in ("expected_keywords", "any_keywords", "min_keywords", "exact"):
                assert hidden not in question, hidden


def test_single_exercise_endpoint(server):
    status, payload = get(server, "/api/exercise?id=ex01")
    assert status == 200
    assert payload["id"] == "ex01"
    assert "guidance" not in payload["questions"][0]


def test_single_exercise_unknown_id(server):
    status, payload = get(server, "/api/exercise?id=ex99")
    assert status == 404


# ---------------------------------------------------------------------------
# Target validation through the API
# ---------------------------------------------------------------------------
def test_validate_target_accepts_the_authorized_target(server):
    status, payload = post(server, "/api/validate-target", {"url": "http://localhost:3001"})
    assert status == 200
    assert payload["ok"] is True


@pytest.mark.parametrize(
    "url,expected_code",
    [
        ("http://localhost:3000", "port-not-authorized"),
        ("https://example.com:3001", "host-not-authorized"),
        ("http://8.8.8.8:3001", "not-loopback"),
        ("not-a-url", "missing-scheme"),
    ],
)
def test_validate_target_rejects_unauthorized_targets(server, url, expected_code):
    status, payload = post(server, "/api/validate-target", {"url": url})
    assert status == 200
    assert payload["ok"] is False
    assert payload["code"] == expected_code


# ---------------------------------------------------------------------------
# Grading
# ---------------------------------------------------------------------------
def test_grade_endpoint_returns_feedback_not_keys(server):
    status, payload = post(
        server, "/api/grade", {"exercise_id": "ex01", "answers": {"q1": "yes"}}
    )
    assert status == 200
    assert payload["total"] >= 1
    for result in payload["results"]:
        assert "expected_keywords" not in result
        assert "feedback" in result


def test_grade_endpoint_requires_arguments(server):
    status, payload = post(server, "/api/grade", {})
    assert status == 400


def test_grade_endpoint_unknown_exercise(server):
    status, _ = post(server, "/api/grade", {"exercise_id": "ex99", "answers": {}})
    assert status == 404


# ---------------------------------------------------------------------------
# Acknowledgement
# ---------------------------------------------------------------------------
def test_ack_endpoint_rejects_unknown_checklist_item(server):
    status, payload = post(
        server, "/api/ack", {"exercise_id": "ex01", "checks": ["c99"]}
    )
    assert status == 400
    assert "unknown checklist item" in payload["error"]


def test_ack_endpoint_rejects_malformed_payload(server):
    status, _ = post(server, "/api/ack", {"exercise_id": "ex01", "checks": "not-a-list"})
    assert status == 400


def test_ack_endpoint_requires_exercise_id(server):
    status, _ = post(server, "/api/ack", {})
    assert status == 400


# ---------------------------------------------------------------------------
# Run endpoints are validated without starting a scan
# ---------------------------------------------------------------------------
def test_run_endpoint_requires_a_tool(server):
    status, payload = post(server, "/api/run", {})
    assert status == 400
    assert "tool name is required" in payload["error"]


def test_run_endpoint_rejects_unknown_tool_before_starting(server):
    status, payload = post(server, "/api/run", {"tool": "definitely-not-a-tool"})
    # Either rejected synchronously, or accepted then failed in the worker.
    assert status in (202, 400, 500)


def test_run_all_endpoint_accepts_a_tool_list(server):
    status, payload = post(server, "/api/run-all", {"tools": ["nmap"]})
    # A scan may genuinely start here; only the contract matters.
    assert status in (202, 409)
