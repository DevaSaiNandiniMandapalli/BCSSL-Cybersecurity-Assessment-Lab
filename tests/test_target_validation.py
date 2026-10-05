"""Target validation: the lab's primary safety boundary.

These tests encode the rule that only the authorized loopback target may be
assessed. Every rejection path is asserted with its machine-readable code.
"""

from __future__ import annotations

import pytest

from bcssl import target as target_module
from bcssl.config import LabConfig
from bcssl.target import (
    TargetRejectedError,
    check_reachability,
    describe_scope,
    validate_or_raise,
    validate_target,
)

AUTHORIZED = "http://localhost:3001"


@pytest.fixture()
def lab_config():
    from bcssl.config import DEFAULT_CONFIG
    import copy

    return LabConfig(data=copy.deepcopy(DEFAULT_CONFIG), source=None)


# ---------------------------------------------------------------------------
# Accepted targets
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "url,host",
    [
        ("http://localhost:3001", "localhost"),
        ("http://127.0.0.1:3001", "127.0.0.1"),
        ("http://[::1]:3001", "::1"),
        ("HTTP://LOCALHOST:3001", "localhost"),
        ("  http://localhost:3001  ", "localhost"),
        ("http://localhost:3001/some/path?q=1", "localhost"),
    ],
)
def test_authorized_targets_are_accepted(lab_config, url, host):
    result = validate_target(url, lab_config)
    assert result.ok, result.reason
    assert result.host == host
    assert result.port == 3001
    assert result.code == target_module.CODE_OK


def test_normalized_url_drops_query_and_fragment(lab_config):
    result = validate_target("http://localhost:3001/admin?x=1#frag", lab_config)
    assert result.ok
    assert result.url == AUTHORIZED


def test_dns_resolution_is_loopback(lab_config):
    result = validate_target(AUTHORIZED, lab_config)
    assert result.ok
    assert result.addresses, "localhost should resolve"
    import ipaddress

    for address in result.addresses:
        assert ipaddress.ip_address(address).is_loopback


# ---------------------------------------------------------------------------
# Rejected targets
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "url,expected_code",
    [
        ("http://localhost:3000", target_module.CODE_PORT_NOT_ALLOWED),
        ("http://127.0.0.1:22", target_module.CODE_PORT_NOT_ALLOWED),
        ("http://localhost:80", target_module.CODE_PORT_NOT_ALLOWED),
        ("https://example.com:3001", target_module.CODE_HOST_NOT_ALLOWED),
        ("http://scanme.example.org:3001", target_module.CODE_HOST_NOT_ALLOWED),
        ("http://8.8.8.8:3001", target_module.CODE_NON_LOOPBACK),
        ("http://169.254.169.254:3001", target_module.CODE_NON_LOOPBACK),
        ("http://0.0.0.0:3001", target_module.CODE_NON_LOOPBACK),
        ("http://[::ffff:8.8.8.8]:3001", target_module.CODE_NON_LOOPBACK),
        ("not-a-url", target_module.CODE_MISSING_SCHEME),
        ("localhost:3001", target_module.CODE_MISSING_SCHEME),
        ("ftp://localhost:3001", target_module.CODE_SCHEME_NOT_ALLOWED),
        ("file:///etc/passwd", target_module.CODE_SCHEME_NOT_ALLOWED),
        ("http://localhost:3001@evil.example", target_module.CODE_CREDENTIALS_IN_URL),
        ("http:///path", target_module.CODE_MISSING_HOST),
        ("", target_module.CODE_EMPTY),
        ("   ", target_module.CODE_EMPTY),
        (None, target_module.CODE_EMPTY),
        ("http://localhost:3001 -oX /tmp/x", target_module.CODE_FORBIDDEN_CHAR),
        ("http://localhost:3001\n-oX /tmp/x", target_module.CODE_FORBIDDEN_CHAR),
        ("http://local host:3001", target_module.CODE_FORBIDDEN_CHAR),
    ],
)
def test_unauthorized_targets_are_rejected(lab_config, url, expected_code):
    result = validate_target(url, lab_config)
    assert not result.ok, f"{url!r} must be rejected"
    assert result.code == expected_code, result.reason
    assert result.reason, "a rejection must always carry a human-readable reason"


def test_public_hostname_that_looks_local_is_rejected(lab_config):
    """A hostname ending in loopback is not an allowlist entry."""
    for url in (
        "http://localhost.evil.example:3001",
        "http://127.0.0.1.nip.io:3001",
    ):
        result = validate_target(url, lab_config)
        assert not result.ok
        assert result.code in (
            target_module.CODE_HOST_NOT_ALLOWED,
            target_module.CODE_UNRESOLVABLE,
            target_module.CODE_NON_LOOPBACK,
        )


def test_overlong_target_rejected(lab_config):
    result = validate_target("http://localhost:3001/" + "a" * 4000, lab_config)
    assert not result.ok
    assert result.code == target_module.CODE_TOO_LONG


# ---------------------------------------------------------------------------
# Configuration-driven scope changes
# ---------------------------------------------------------------------------
def test_instructor_can_enable_an_extra_loopback_port(lab_config):
    lab_config.data["target"]["allowed_ports"] = [3001, 8080]
    assert validate_target("http://localhost:8080", lab_config).ok
    assert not validate_target("http://localhost:9090", lab_config).ok


def test_loopback_literal_requires_explicit_allowlist_entry(lab_config):
    """A loopback IP that is not allowlisted is still refused."""
    lab_config.data["target"]["allowed_hosts"] = ["localhost"]
    result = validate_target("http://127.0.0.1:3001", lab_config)
    assert not result.ok
    assert result.code == target_module.CODE_HOST_NOT_ALLOWED


def test_validate_or_raise_raises_on_rejection(lab_config):
    with pytest.raises(TargetRejectedError) as excinfo:
        validate_or_raise("http://example.com:3001", lab_config)
    assert excinfo.value.validation.code == target_module.CODE_HOST_NOT_ALLOWED


def test_validate_or_raise_returns_validation_when_ok(lab_config):
    result = validate_or_raise(AUTHORIZED, lab_config)
    assert result.ok and result.url == AUTHORIZED


# ---------------------------------------------------------------------------
# Banner and reachability
# ---------------------------------------------------------------------------
def test_scope_banner_names_the_authorized_target(lab_config):
    text = describe_scope(lab_config)
    assert "AUTHORIZED TARGET" in text
    assert AUTHORIZED in text
    assert "3001" in text


def test_banner_rejection_text_differs(lab_config):
    result = validate_target("http://example.com", lab_config)
    assert "TARGET REJECTED" in result.banner()
    assert "AUTHORIZED TARGET" not in result.banner()


def test_reachability_of_rejected_target_is_false(lab_config):
    rejected = validate_target("http://example.com", lab_config)
    assert check_reachability(rejected).reachable is False


def test_reachability_of_closed_loopback_port_is_false(lab_config):
    """A closed loopback port must report unreachable, not a scan."""
    import socket

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        free_port = probe.getsockname()[1]
    lab_config.data["target"]["allowed_ports"] = [free_port]
    result = validate_target(f"http://127.0.0.1:{free_port}", lab_config)
    assert result.ok
    assert check_reachability(result, timeout=2.0).reachable is False
