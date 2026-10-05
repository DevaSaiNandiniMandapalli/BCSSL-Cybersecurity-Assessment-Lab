"""Severity mapping from each tool's native scale onto the lab's five levels."""

from __future__ import annotations

import pytest

from bcssl.severity import (
    ORDERED_SEVERITIES,
    Severity,
    at_or_above,
    from_string,
    nikto_rating,
    tally,
    worst,
    zap_riskcode,
)


def test_exactly_five_severities():
    assert [level.value for level in ORDERED_SEVERITIES] == [
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
        "INFO",
    ]


@pytest.mark.parametrize(
    "value,expected",
    [
        ("critical", Severity.CRITICAL),
        ("CRITICAL", Severity.CRITICAL),
        ("Critical", Severity.CRITICAL),
        ("high", Severity.HIGH),
        ("HIGH", Severity.HIGH),
        ("medium", Severity.MEDIUM),
        ("moderate", Severity.MEDIUM),
        ("low", Severity.LOW),
        ("info", Severity.INFO),
        ("informational", Severity.INFO),
        ("unknown", Severity.INFO),
        ("", Severity.INFO),
        (None, Severity.INFO),
        (12345, Severity.INFO),
    ],
)
def test_from_string_maps_native_tokens(value, expected):
    assert from_string(value) is expected


def test_from_string_is_conservative_for_unknown_text():
    """An unrecognised rating must never be inflated upward."""
    assert from_string("catastrophic doom", default=Severity.INFO) is Severity.INFO
    # Arbitrary identifiers resolve to the informational default, not a rating.
    for opaque in ("0xDEADBEEF", "12345", "CVE-2021-1234", "OSVDB-99999"):
        mapped = from_string(opaque)
        assert mapped not in (Severity.HIGH, Severity.CRITICAL), opaque
        assert mapped is Severity.INFO, opaque


def test_severity_classmethod_available():
    assert Severity.from_string("high") is Severity.HIGH
    assert Severity.from_string("nonsense") is Severity.INFO


# ---------------------------------------------------------------------------
# ZAP risk codes
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "riskcode,expected",
    [
        (3, Severity.HIGH),
        ("3", Severity.HIGH),
        (2, Severity.MEDIUM),
        (1, Severity.LOW),
        (0, Severity.INFO),
    ],
)
def test_zap_riskcode_mapping(riskcode, expected):
    assert zap_riskcode(riskcode) is expected


def test_zap_never_yields_critical():
    """ZAP has no CRITICAL level; the mapping must not invent one."""
    for code in range(0, 5):
        assert zap_riskcode(code) is not Severity.CRITICAL


def test_zap_riskcode_invalid_input_is_info():
    assert zap_riskcode("high") is Severity.INFO
    assert zap_riskcode(None) is Severity.INFO


# ---------------------------------------------------------------------------
# Nikto ratings
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "text,expected",
    [
        ("Severity: high", Severity.HIGH),
        ("Severity: medium", Severity.MEDIUM),
        ("Severity: low", Severity.LOW),
        ("OSVDB-0: Informational", Severity.INFO),
        (None, Severity.INFO),
        ("no rating here", Severity.INFO),
    ],
)
def test_nikto_rating_mapping(text, expected):
    assert nikto_rating(text) is expected


# ---------------------------------------------------------------------------
# Ordering helpers
# ---------------------------------------------------------------------------
def test_ordering_is_severity_ascending():
    assert sorted([Severity.HIGH, Severity.INFO, Severity.MEDIUM]) == [
        Severity.INFO,
        Severity.MEDIUM,
        Severity.HIGH,
    ]
    assert Severity.CRITICAL > Severity.HIGH > Severity.LOW > Severity.INFO


def test_worst_and_tally():
    values = [Severity.LOW, Severity.CRITICAL, Severity.INFO, Severity.INFO]
    assert worst(values) is Severity.CRITICAL
    assert worst([]) is Severity.INFO
    counts = tally(values)
    assert counts == {
        "CRITICAL": 1,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 1,
        "INFO": 2,
    }


def test_tally_always_returns_all_five_keys():
    assert sorted(tally([]).keys()) == ["CRITICAL", "HIGH", "INFO", "LOW", "MEDIUM"]


def test_at_or_above_floor():
    assert at_or_above(Severity.HIGH, Severity.MEDIUM)
    assert not at_or_above(Severity.LOW, Severity.MEDIUM)
