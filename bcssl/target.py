"""Authorized-target validation.

This module is the lab's security boundary. :func:`validate_target` runs before
*every* tool invocation and refuses anything that is not the configured
authorized target.

The policy is allowlist-based rather than blocklist-based: a target is accepted
only when its host appears in ``target.allowed_hosts`` **and** its port appears
in ``target.allowed_ports`` **and** every address the host resolves to is a
loopback address. Adding a new public host to the allowlist is therefore a
deliberate, visible act rather than an omission.

Rejected: public IP addresses, external domains, arbitrary URLs, loopback ports
other than those the instructor enabled, IPv4-mapped loopback abuse, embedded
credentials, and malformed input (including characters that could break out of
a command line).
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from typing import Any, Iterable
from urllib.parse import urlsplit

from .config import LabConfig

ALLOWED_SCHEMES = ("http", "https")

#: Characters that must never appear in a target string: NUL, every other
#: control character, and whitespace. A newline or space inside a target can
#: smuggle an extra argument into an external tool's command line or corrupt a
#: log line, so they are refused outright.
#:
#: URL-legal punctuation (``[ ]`` for IPv6 literals, ``( ) !`` and so on) is
#: deliberately permitted: the host/port allowlist, not a blocklist, is what
#: keeps the lab in scope. Blocking them would reject the allowlisted IPv6
#: loopback form ``http://[::1]:3001``.
_FORBIDDEN_CHARS = re.compile(r"[\x00-\x20\x7f]")

#: Rejection codes, stable identifiers for tests and machine consumers.
CODE_OK = "ok"
CODE_EMPTY = "empty-target"
CODE_TOO_LONG = "target-too-long"
CODE_FORBIDDEN_CHAR = "forbidden-character"
CODE_MISSING_SCHEME = "missing-scheme"
CODE_SCHEME_NOT_ALLOWED = "scheme-not-allowed"
CODE_MISSING_HOST = "missing-host"
CODE_CREDENTIALS_IN_URL = "credentials-in-url"
CODE_HOST_NOT_ALLOWED = "host-not-authorized"
CODE_UNRESOLVABLE = "host-unresolvable"
CODE_NON_LOOPBACK = "not-loopback"
CODE_PORT_NOT_ALLOWED = "port-not-authorized"
CODE_MALFORMED = "malformed-target"


@dataclass
class TargetValidation:
    """Result of validating a candidate target."""

    ok: bool
    code: str
    reason: str
    url: str = ""
    scheme: str = ""
    host: str = ""
    port: int = 0
    addresses: list[str] = field(default_factory=list)
    input_value: str = ""

    @property
    def rejected(self) -> bool:
        return not self.ok

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "code": self.code,
            "reason": self.reason,
            "url": self.url,
            "scheme": self.scheme,
            "host": self.host,
            "port": self.port,
            "addresses": self.addresses,
            "input": self.input_value,
        }

    def banner(self) -> str:
        """Human-facing authorization banner."""
        if self.ok:
            return f"AUTHORIZED TARGET\n{self.url}"
        return f"TARGET REJECTED - NOT AUTHORIZED\n{self.reason}"


def _is_loopback(address: str, allow_ipv4_mapped: bool = True) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    if ip.is_loopback:
        return True
    # ::ffff:127.0.0.1 reaches loopback but is not itself flagged loopback.
    if allow_ipv4_mapped and isinstance(ip, ipaddress.IPv6Address):
        mapped = ip.ipv4_mapped
        if mapped is not None and mapped.is_loopback:
            return True
    return False


def _resolve(host: str, port: int) -> tuple[list[str], str | None]:
    """Resolve *host*, returning addresses and an error message if any."""
    literal = host
    if host.startswith("[") and host.endswith("]"):
        literal = host[1:-1]
    try:
        ipaddress.ip_address(literal)
        return [literal], None
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError, OSError) as exc:
        return [], str(exc)
    addresses: list[str] = []
    for info in infos:
        sockaddr = info[4]
        if sockaddr and sockaddr[0] not in addresses:
            addresses.append(str(sockaddr[0]))
    if not addresses:
        return [], "no addresses returned"
    return addresses, None


def _reject(code: str, reason: str, raw: str) -> TargetValidation:
    return TargetValidation(ok=False, code=code, reason=reason, input_value=raw)


def validate_target(
    candidate: str | None,
    config: LabConfig,
    *,
    check_dns: bool = True,
) -> TargetValidation:
    """Validate *candidate* against the lab's authorized scope.

    Args:
        candidate: the URL a tool is about to be pointed at.
        config: active lab configuration supplying the allowlists.
        check_dns: when true, resolve the host and require every address to be
            loopback. Disabled only by tests that want a deterministic result
            without touching the resolver.

    Returns:
        A :class:`TargetValidation`. Callers must check ``ok`` and refuse to run
        when it is false.
    """
    if candidate is None:
        return _reject(CODE_EMPTY, "no target was supplied", "")

    raw = str(candidate).strip()
    if not raw:
        return _reject(CODE_EMPTY, "no target was supplied", raw)
    if len(raw) > 2048:
        return _reject(CODE_TOO_LONG, "target string is implausibly long", raw[:64])

    if _FORBIDDEN_CHARS.search(raw):
        return _reject(
            CODE_FORBIDDEN_CHAR,
            "target contains characters that are not permitted in a lab URL",
            raw,
        )

    if "://" not in raw:
        return _reject(
            CODE_MISSING_SCHEME,
            "target must include an explicit http:// or https:// scheme",
            raw,
        )

    try:
        parts = urlsplit(raw)
    except ValueError as exc:
        return _reject(CODE_MALFORMED, f"target could not be parsed: {exc}", raw)

    scheme = (parts.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        return _reject(
            CODE_SCHEME_NOT_ALLOWED,
            f"scheme '{scheme}' is not permitted; use http or https",
            raw,
        )

    try:
        port = parts.port  # type: ignore[assignment]
    except ValueError as exc:
        return _reject(CODE_MALFORMED, f"invalid port in target: {exc}", raw)

    netloc = parts.netloc
    if not netloc:
        return _reject(CODE_MISSING_HOST, "target does not contain a host", raw)
    if "@" in netloc:
        return _reject(
            CODE_CREDENTIALS_IN_URL,
            "credentials embedded in the target URL are not accepted",
            raw,
        )

    host = (parts.hostname or "").strip().lower()
    if not host:
        return _reject(CODE_MISSING_HOST, "target does not contain a host", raw)

    if port is None:
        port = 443 if scheme == "https" else 80

    allow_ipv4_mapped = bool(config.target.get("allow_ipv4_mapped", True))
    addresses: list[str] = []

    literal = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    try:
        parsed_ip = ipaddress.ip_address(literal)
    except ValueError:
        parsed_ip = None

    if parsed_ip is not None:
        # An IP literal is accepted only when loopback and explicitly allowed.
        if not _is_loopback(literal, allow_ipv4_mapped):
            return _reject(
                CODE_NON_LOOPBACK,
                f"{literal} is not a loopback address; this lab only assesses "
                "the local training target",
                raw,
            )
        addresses = [literal]
    else:
        if host not in config.allowed_hosts:
            return _reject(
                CODE_HOST_NOT_ALLOWED,
                f"host '{host}' is not in the authorized host allowlist "
                f"({', '.join(config.allowed_hosts)})",
                raw,
            )
        if check_dns:
            resolved, error = _resolve(host, port)
            if error:
                # A name that is explicitly allowlisted but temporarily cannot
                # be resolved is still not a bypass: treat as rejected so no
                # tool runs against an unknown address.
                return _reject(
                    CODE_UNRESOLVABLE,
                    f"authorized host '{host}' could not be resolved: {error}",
                    raw,
                )
            addresses = resolved
            if config.require_loopback:
                offenders = [
                    addr
                    for addr in addresses
                    if not _is_loopback(addr, allow_ipv4_mapped)
                ]
                if offenders:
                    return _reject(
                        CODE_NON_LOOPBACK,
                        f"host '{host}' resolves to non-loopback address(es): "
                        f"{', '.join(offenders)}",
                        raw,
                    )

    if parsed_ip is not None and literal not in config.allowed_hosts:
        # Loopback literal that the instructor has not enabled explicitly.
        return _reject(
            CODE_HOST_NOT_ALLOWED,
            f"host '{literal}' is loopback but is not in the authorized host "
            f"allowlist ({', '.join(config.allowed_hosts)})",
            raw,
        )

    if port not in config.allowed_ports:
        return _reject(
            CODE_PORT_NOT_ALLOWED,
            f"port {port} is not authorized; the permitted port(s) are "
            f"{', '.join(str(p) for p in config.allowed_ports)}",
            raw,
        )

    # Rebuild a canonical URL: no credentials, no fragment, no query.
    display_host = f"[{host}]" if ":" in host else host
    normalized = f"{scheme}://{display_host}:{port}"

    return TargetValidation(
        ok=True,
        code=CODE_OK,
        reason="target matches the authorized lab scope",
        url=normalized,
        scheme=scheme,
        host=host,
        port=port,
        addresses=addresses,
        input_value=raw,
    )


def validate_or_raise(candidate: str | None, config: LabConfig) -> TargetValidation:
    """Validate and raise :class:`TargetRejectedError` when not authorized."""
    result = validate_target(candidate, config)
    if not result.ok:
        raise TargetRejectedError(result)
    return result


class TargetRejectedError(RuntimeError):
    """Raised when a requested target is outside the authorized scope."""

    def __init__(self, validation: TargetValidation) -> None:
        super().__init__(validation.reason)
        self.validation = validation


# ---------------------------------------------------------------------------
# Reachability (distinct from authorization)
# ---------------------------------------------------------------------------
@dataclass
class Reachability:
    reachable: bool
    status_code: int | None = None
    error: str = ""
    server: str = ""
    elapsed_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "reachable": self.reachable,
            "status_code": self.status_code,
            "error": self.error,
            "server": self.server,
            "elapsed_seconds": round(self.elapsed_seconds, 3),
        }


def check_reachability(
    validation: TargetValidation,
    *,
    timeout: float = 5.0,
) -> Reachability:
    """Check that the *authorized* target actually answers HTTP.

    This is intentionally separate from authorization: a target can be fully
    authorized yet not running, and the lab must say so rather than reporting a
    scan that never happened.
    """
    import time
    import urllib.error
    import urllib.request

    if not validation.ok:
        return Reachability(reachable=False, error="target was not authorized")

    started = time.monotonic()
    request = urllib.request.Request(
        validation.url,
        method="GET",
        headers={"User-Agent": "BCSSL-Assessment-Lab/1.0 (reachability check)"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            # Read a small amount only; nothing is stored or extracted.
            response.read(1024)
            return Reachability(
                reachable=True,
                status_code=response.status,
                server=str(response.headers.get("Server", "")),
                elapsed_seconds=time.monotonic() - started,
            )
    except urllib.error.HTTPError as exc:
        # An HTTP error status still proves the service is listening.
        return Reachability(
            reachable=True,
            status_code=exc.code,
            server=str(exc.headers.get("Server", "") if exc.headers else ""),
            elapsed_seconds=time.monotonic() - started,
        )
    except (urllib.error.URLError, OSError, ValueError) as exc:
        reason = getattr(exc, "reason", exc)
        return Reachability(
            reachable=False,
            error=f"{type(exc).__name__}: {reason}",
            elapsed_seconds=time.monotonic() - started,
        )


def describe_scope(config: LabConfig, candidates: Iterable[str] | None = None) -> str:
    """Render the authorization banner shown before tools run."""
    lines = ["=" * 62, "AUTHORIZED SCOPE - BCSSL CYBERSECURITY ASSESSMENT LAB", "=" * 62]
    lines.append(f"AUTHORIZED TARGET\n{config.authorized_url}")
    lines.append(
        f"Allowed hosts : {', '.join(config.allowed_hosts)}"
    )
    lines.append(
        f"Allowed ports : {', '.join(str(p) for p in config.allowed_ports)}"
    )
    lines.append(f"Lab           : {config.lab_name}")
    if config.authorization_statement:
        lines.append(f"Authorization : {config.authorization_statement}")
    lines.append("All other hosts, domains, IPs and ports are refused by the validator.")
    lines.append("=" * 62)
    return "\n".join(lines)
