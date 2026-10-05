"""Independent verification of findings against the authorized target.

A tool reporting a missing header is a *claim*. This module performs its own
minimal HTTP checks against the authorized target and records whether the
condition is actually observable, which is what separates:

``NOT VERIFIED``            the tool reported it; nothing has confirmed it
``SINGLE-TOOL OBSERVATION`` exactly one tool reported it after correlation
``DETECTED``                the lab independently reproduced the condition
``CORROBORATED``            two or more tools reported the same fingerprint

The verifier never invents findings: it can only upgrade the status of a finding
that already exists, and it only inspects headers and status codes. It does not
attempt exploitation, and it is always run against the validated target.
"""

from __future__ import annotations

import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable

from .config import LabConfig
from .models import Finding, utc_now_iso
from .target import TargetValidation, validate_target

# Verification status vocabulary (mirrors the documented schema).
NOT_VERIFIED = "NOT VERIFIED"
SINGLE_TOOL_OBSERVATION = "SINGLE-TOOL OBSERVATION"
CORROBORATED = "CORROBORATED"
DETECTED = "DETECTED"
TOOL_UNAVAILABLE = "TOOL UNAVAILABLE"

ALL_STATUSES = (
    NOT_VERIFIED,
    SINGLE_TOOL_OBSERVATION,
    CORROBORATED,
    DETECTED,
    TOOL_UNAVAILABLE,
)


@dataclass
class VerificationResult:
    """Outcome of the independent checks."""

    checked_at: str = field(default_factory=utc_now_iso)
    target: str = ""
    reachable: bool = False
    status_code: int | None = None
    response_headers: dict[str, str] = field(default_factory=dict)
    #: subject -> confirmed
    confirmed: dict[str, bool] = field(default_factory=dict)
    #: Human-readable note per subject.
    notes: dict[str, str] = field(default_factory=dict)
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "checked_at": self.checked_at,
            "target": self.target,
            "reachable": self.reachable,
            "status_code": self.status_code,
            "confirmed_subjects": sorted(k for k, v in self.confirmed.items() if v),
            "refuted_subjects": sorted(k for k, v in self.confirmed.items() if not v),
            "notes": self.notes,
            "error": self.error,
        }


def _headers_of(response) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in response.headers.items()}


def _fetch(url: str, config: LabConfig, timeout: float) -> tuple[int | None, dict[str, str], str]:
    request = urllib.request.Request(
        url,
        method="GET",
        headers={"User-Agent": str(config.http.get("user_agent", "BCSSL-Assessment-Lab/1.0"))},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            response.read(2048)
            return response.status, _headers_of(response), ""
    except urllib.error.HTTPError as exc:
        # An error status still proves the resource exists and is reachable.
        return exc.code, _headers_of(exc) if exc.headers else {}, ""
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return None, {}, f"{type(exc).__name__}: {getattr(exc, 'reason', exc)}"


def verify(
    findings: list[Finding],
    config: LabConfig,
    *,
    url: str | None = None,
) -> VerificationResult:
    """Independently check the conditions described by *findings*.

    Only conditions this module knows how to observe are checked; anything else
    is left untouched. The target is re-validated before any request is made.
    """
    result = VerificationResult()
    candidate = url or config.authorized_url
    validation: TargetValidation = validate_target(candidate, config)
    if not validation.ok:
        result.error = f"verification refused: {validation.reason}"
        return result
    result.target = validation.url

    subjects = {finding.subject for finding in findings}
    if not subjects:
        return result

    timeout = float(config.http.get("timeout_seconds", 15))

    status, headers, error = _fetch(validation.url, config, timeout)
    if status is None:
        result.error = error or "target did not respond"
        return result

    result.reachable = True
    result.status_code = status
    result.response_headers = headers

    # --- security header conditions ------------------------------------
    for subject, header in (
        ("missing-header:csp", "content-security-policy"),
        ("missing-header:hsts", "strict-transport-security"),
        ("missing-header:frame-options", "x-frame-options"),
        ("missing-header:nosniff", "x-content-type-options"),
        ("missing-header:referrer-policy", "referrer-policy"),
        ("missing-header:permissions-policy", "permissions-policy"),
        ("missing-header:xss-protection", "x-xss-protection"),
    ):
        if subject in subjects:
            present = header in headers
            result.confirmed[subject] = not present
            result.notes[subject] = (
                f"header '{header}' {'is present' if present else 'is absent'}"
            )

    # --- technology / banner disclosure --------------------------------
    for subject, header in (
        ("technology-disclosure:x-powered-by", "x-powered-by"),
        ("server-banner-disclosure", "server"),
    ):
        if subject in subjects:
            present = header in headers
            result.confirmed[subject] = present
            result.notes[subject] = (
                f"header '{header}' {'is present: ' + headers[header][:80] if present else 'is absent'}"
            )

    # --- path reachability ---------------------------------------------
    for subject, path in (
        ("exposure:robots-txt", "/robots.txt"),
        ("title:discovered-accessible-resource-ftp", "/ftp/"),
        ("title:discovered-accessible-resource-favicon", "/favicon.ico"),
    ):
        if subject not in subjects:
            continue
        if subject == "exposure:robots-txt":
            for finding in findings:
                if finding.subject == subject and finding.endpoint:
                    path = _path_of(finding.endpoint) or path
                    break
        code, _, _ = _fetch(validation.url.rstrip("/") + path, config, timeout)
        reachable = code is not None and code < 400
        result.confirmed[subject] = reachable
        result.notes[subject] = f"GET {path} -> {code if code is not None else 'no response'}"

    return result


def _path_of(endpoint: str) -> str:
    import re

    match = re.match(r"https?://[^/]+(/[^?#]*)", endpoint or "")
    return match.group(1) if match else ""


def apply_verification(
    findings: list[Finding], result: VerificationResult
) -> dict[str, int]:
    """Upgrade finding statuses using *result*.

    Only findings whose subject the verifier actually checked are touched, and
    only forward transitions are allowed: a corroborated finding is never
    downgraded to merely detected, and a detected finding is never downgraded to
    unverified.

    Returns:
        Counters per status for reporting.
    """
    counters = {status: 0 for status in ALL_STATUSES}
    for finding in findings:
        if result.confirmed.get(finding.subject):
            # Corroboration outranks independent reproduction.
            if finding.verification_status == CORROBORATED:
                counters[CORROBORATED] += 1
            else:
                finding.verification_status = DETECTED
                counters[DETECTED] += 1
        else:
            counters[finding.verification_status] += 1
    return counters
