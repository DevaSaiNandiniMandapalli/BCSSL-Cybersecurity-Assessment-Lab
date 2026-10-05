"""Data structures shared by every stage of the lab pipeline.

The normalized :class:`Finding` is the contract between parsers, correlation,
evidence and reporting. :meth:`Finding.to_dict` emits exactly the ten keys
required by the lab schema and nothing else, so a normalized JSON artifact is
stable regardless of which tool produced it.
"""

from __future__ import annotations

import dataclasses
import enum
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .severity import Severity, tally, worst


def utc_now_iso() -> str:
    """Current UTC time as an ISO-8601 string with a ``Z`` suffix."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


class RunStatus(enum.Enum):
    """Outcome of a single tool run.

    Every non-``OK`` state is surfaced to the user. The lab never reports a
    scan that did not happen.
    """

    OK = "ok"
    #: Executable not found on PATH (or Docker image not available).
    TOOL_NOT_INSTALLED = "tool-not-installed"
    #: Target failed authorization validation.
    TARGET_REJECTED = "target-rejected"
    #: Target authorized but not accepting connections.
    TARGET_UNREACHABLE = "target-unreachable"
    #: Tool ran but exited non-zero.
    FAILED = "failed"
    #: Tool exceeded its configured timeout and was terminated.
    TIMEOUT = "timeout"
    #: Output captured but nothing could be parsed out of it.
    PARSE_ERROR = "parse-error"
    #: Findings were produced but some inputs could not be handled.
    PARTIAL = "partial"
    #: Tool was disabled in the configuration.
    DISABLED = "disabled"

    @property
    def is_success(self) -> bool:
        return self in (RunStatus.OK, RunStatus.PARTIAL)

    @property
    def label(self) -> str:
        return {
            RunStatus.OK: "SCAN COMPLETED",
            RunStatus.PARTIAL: "SCAN COMPLETED WITH WARNINGS",
            RunStatus.TOOL_NOT_INSTALLED: "TOOL NOT INSTALLED",
            RunStatus.TARGET_REJECTED: "TARGET REJECTED - NOT AUTHORIZED",
            RunStatus.TARGET_UNREACHABLE: "TARGET UNREACHABLE",
            RunStatus.FAILED: "TOOL FAILED",
            RunStatus.TIMEOUT: "TIMEOUT",
            RunStatus.PARSE_ERROR: "OUTPUT COULD NOT BE PARSED",
            RunStatus.DISABLED: "TOOL DISABLED IN CONFIGURATION",
        }[self]


@dataclass
class EvidenceRecord:
    """Provenance for a single finding.

    ``raw_sha256`` is computed over the verbatim tool output file so a reviewer
    can prove the finding was derived from the stored artifact and not edited
    afterwards.
    """

    tool: str
    finding_title: str
    target: str
    endpoint: str
    excerpt: str
    raw_artifact: str
    raw_sha256: str
    recorded_at: str = field(default_factory=utc_now_iso)
    path: str | None = None
    reference: str = ""

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class Finding:
    """A single normalized security finding.

    The documented normalized schema plus ``verification_status``, which records
    how much weight the finding carries: a raw tool claim, an observation from a
    single tool, an independently reproduced condition, or a corroborated one.

    The remaining fields are internal correlation/provenance hints and are
    excluded from :meth:`to_dict`.
    """

    tool: str
    category: str
    severity: Severity
    title: str
    description: str = ""
    target: str = ""
    endpoint: str = ""
    evidence: str = ""
    recommendation: str = ""
    timestamp: str = field(default_factory=utc_now_iso)
    #: NOT VERIFIED / SINGLE-TOOL OBSERVATION / DETECTED / CORROBORATED
    verification_status: str = "NOT VERIFIED"
    # -- internal only (not part of the normalized schema) -------------------
    #: Canonical subject used for cross-tool correlation, e.g. ``missing-header``.
    subject: str = ""
    #: Tool-native identifier: ZAP pluginId, nuclei templateID, osvdb, ...
    reference: str = ""
    #: Path (relative to project root) of the verbatim tool output.
    source_artifact: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.severity, Severity):
            self.severity = Severity.from_string(self.severity)
        if not self.subject:
            self.subject = derive_subject(self.category, self.title)

    def to_dict(self) -> dict[str, Any]:
        """Return the normalized schema."""
        return {
            "tool": self.tool,
            "category": self.category,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "target": self.target,
            "endpoint": self.endpoint,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "timestamp": self.timestamp,
            "verification_status": self.verification_status,
        }

    def to_internal_dict(self) -> dict[str, Any]:
        """Normalized schema plus internal correlation metadata."""
        data = self.to_dict()
        data.update(
            {
                "subject": self.subject,
                "reference": self.reference,
                "source_artifact": self.source_artifact,
            }
        )
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        return cls(
            tool=data.get("tool", ""),
            category=data.get("category", ""),
            severity=Severity.from_string(data.get("severity")),
            title=data.get("title", ""),
            description=data.get("description", ""),
            target=data.get("target", ""),
            endpoint=data.get("endpoint", ""),
            evidence=data.get("evidence", ""),
            recommendation=data.get("recommendation", ""),
            timestamp=data.get("timestamp") or utc_now_iso(),
            verification_status=data.get("verification_status", "NOT VERIFIED"),
            subject=data.get("subject", ""),
            reference=data.get("reference", ""),
            source_artifact=data.get("source_artifact", ""),
        )

    @property
    def fingerprint(self) -> str:
        """Stable correlation key: category + subject."""
        return f"{self.category}::{self.subject}"


# Categories used across the lab. Keeping them in one place is what makes
# cross-tool correlation meaningful.
CATEGORIES: dict[str, str] = {
    "security-header": "Missing or misconfigured HTTP security header",
    "cookie": "Cookie attribute or handling weakness",
    "technology-disclosure": "Technology or version disclosure",
    "information-disclosure": "Information disclosure",
    "path-discovery": "Discoverable content or path",
    "tls": "Transport layer configuration",
    "injection": "Potential injection vector (unconfirmed indicator)",
    "web-server-config": "Web server configuration weakness",
    "open-port": "Open network service",
    "misconfiguration": "Application or server misconfiguration",
    "vulnerability": "Template- or plugin-identified weakness",
    "methodology": "Assessment methodology observation",
}

_SUBJECT_PATTERNS: tuple[tuple[str, str], ...] = (
    # Header names are written differently by each tool ("X-Frame-Options
    # header is missing" vs "Anti-clickjacking Header" vs "frame-ancestors"), so
    # every pattern tolerates hyphen/space variations.
    (r"clickjack|x[- ]frame[- ]options|frame-?ancestors", "missing-header:frame-options"),
    (r"content[- ]security[- ]policy|\bcsp\b", "missing-header:csp"),
    (r"x[- ]content[- ]type[- ]options|nosniff", "missing-header:nosniff"),
    (r"x[- ]xss[- ]protection", "missing-header:xss-protection"),
    (r"strict[- ]transport[- ]security|\bhsts\b", "missing-header:hsts"),
    (r"referrer[- ]policy", "missing-header:referrer-policy"),
    (r"permissions[- ]policy", "missing-header:permissions-policy"),
    (r"server.{0,20}header|hide.{0,20}server|version disclosure", "server-banner-disclosure"),
    (r"x[- ]powered[- ]by", "technology-disclosure:x-powered-by"),
    (r"missing.{0,20}cookie|httponly|secure.{0,20}cookie|samesite", "cookie-flags"),
    (r"directory listing|autoindex|index listing", "directory-listing"),
    (r"robots\.txt", "exposure:robots-txt"),
    (r"sitemap", "exposure:sitemap"),
    (r"admin (page|panel|interface|folder|file)", "exposure:admin-interface"),
    (r"login page|sign-?in", "exposure:login-interface"),
    (r"backup|\.bak|\.old|\.swp", "exposure:backup-file"),
    (r"git|svn|\.hg", "exposure:vcs-metadata"),
    (r"error page|stack trace|debug", "information-disclosure:error-detail"),
    (r"comment", "information-disclosure:html-comment"),
    (r"session", "session-management"),
    (r"open redirect", "open-redirect"),
)


def derive_subject(category: str, title: str) -> str:
    """Derive a canonical correlation subject from a category and title.

    Correlation must be conservative: two findings are only linked when their
    subject matches exactly. The patterns below are deliberately narrow so an
    over-broad match can never invent multi-tool confirmation.
    """
    import re

    text = f"{category} {title}".lower()
    for pattern, subject in _SUBJECT_PATTERNS:
        if re.search(pattern, text):
            return subject
    import re as _re

    slug = _re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
    return f"title:{slug}" if slug else "title:unknown"


@dataclass
class ToolRunResult:
    """Everything known about one tool invocation.

    This object is the single source of truth for the console output, the
    run index, the evidence directory and the consolidated report. If a tool
    did not run, ``status`` says so and ``findings`` stays empty.
    """

    tool: str
    status: RunStatus
    target: str = ""
    command: list[str] = field(default_factory=list)
    tool_version: str = ""
    exit_code: int | None = None
    started_at: str = ""
    finished_at: str = ""
    duration_seconds: float = 0.0
    stdout: str = ""
    stderr: str = ""
    raw_artifacts: list[str] = field(default_factory=list)
    stdout_path: str = ""
    stderr_path: str = ""
    findings: list[Finding] = field(default_factory=list)
    evidence: list[EvidenceRecord] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    install_hint: str = ""
    target_reachable: bool | None = None
    tool_available: bool | None = None
    #: Assessment namespace this run belongs to (``run-003``), when assigned.
    assessment: str = ""

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    def severity_counts(self) -> dict[str, int]:
        return tally(f.severity for f in self.findings)

    @property
    def max_severity(self) -> Severity:
        return worst(f.severity for f in self.findings)

    def to_dict(self, include_output: bool = False) -> dict[str, Any]:
        data: dict[str, Any] = {
            "tool": self.tool,
            "status": self.status.value,
            "status_label": self.status.label,
            "target": self.target,
            "command": self.command,
            "tool_version": self.tool_version,
            "exit_code": self.exit_code,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": round(self.duration_seconds, 3),
            "raw_artifacts": self.raw_artifacts,
            "stdout_path": self.stdout_path,
            "stderr_path": self.stderr_path,
            "finding_count": self.finding_count,
            "severity_counts": self.severity_counts(),
            "findings": [f.to_internal_dict() for f in self.findings],
            "evidence": [e.to_dict() for e in self.evidence],
            "errors": self.errors,
            "warnings": self.warnings,
            "notes": self.notes,
            "tool_available": self.tool_available,
            "target_reachable": self.target_reachable,
        }
        if include_output:
            data["stdout"] = self.stdout
            data["stderr"] = self.stderr
        return data


@dataclass
class ToolStatus:
    """Result of probing whether a tool can be used."""

    tool: str
    available: bool
    executable: str
    resolved_path: str = ""
    version: str = ""
    transport: str = "local"
    message: str = ""
    install_hint: str = ""
    #: Image ENTRYPOINT when the tool runs from Docker, used to avoid passing
    #: the executable name twice (which the tool would read as a target).
    docker_entrypoint: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


def sha256_file(path: Path) -> str:
    """Return the hex sha256 of a file, or an empty string when unreadable."""
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
    except OSError:
        return ""
    return digest.hexdigest()


def write_json(path: Path, payload: Any) -> Path:
    """Write *payload* as pretty UTF-8 JSON, creating parent directories."""
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(payload, indent=2, ensure_ascii=False, default=str)
    path.write_text(text + "\n", encoding="utf-8")
    return path


def read_json(path: Path, default: Any = None) -> Any:
    """Read JSON from *path*, returning *default* on any failure."""
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def iter_findings(groups: Iterable[list[Finding]]) -> list[Finding]:
    return [finding for group in groups for finding in group]
