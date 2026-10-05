"""Severity vocabulary and the mappings each tool's scale is folded into.

The lab exposes exactly five severities. Every parser translates its tool's
native risk scale into one of these values; nothing else is ever emitted.

Native scales that get folded in:

===========  =====================================================
Tool         Native scale
===========  =====================================================
ZAP          riskcode 3/2/1/0 -> HIGH/MEDIUM/LOW/INFO
Nikto        OSVDB-derived rating text -> nearest lab severity
Nuclei       info.severity -> identity
Custom scan  info/low/medium/high/critical -> identity
Nmap         service/state observations -> INFO (never inflated)
===========  =====================================================
"""

from __future__ import annotations

import enum
import re
from typing import Iterable


class Severity(enum.Enum):
    """The five severities supported by the normalized finding schema."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        """Ascending rank; higher means more severe."""
        return _RANKS[self]

    @property
    def css_class(self) -> str:
        return f"sev-{self.value.lower()}"

    def __lt__(self, other: object) -> bool:  # type: ignore[override]
        if isinstance(other, Severity):
            return self.rank < other.rank
        return NotImplemented

    def __le__(self, other: object) -> bool:  # type: ignore[override]
        if isinstance(other, Severity):
            return self.rank <= other.rank
        return NotImplemented

    def __gt__(self, other: object) -> bool:  # type: ignore[override]
        if isinstance(other, Severity):
            return self.rank > other.rank
        return NotImplemented

    def __ge__(self, other: object) -> bool:  # type: ignore[override]
        if isinstance(other, Severity):
            return self.rank >= other.rank
        return NotImplemented

    @classmethod
    def from_string(cls, value: object, default: "Severity | None" = None) -> "Severity":
        """Class-level alias for :func:`from_string`.

        Accepts a native tool severity token (``"High"``, ``"3"``, ``"risk: 2"``)
        and returns the corresponding lab severity, falling back to *default*
        (INFO when omitted).
        """
        return from_string(value, default if default is not None else cls.INFO)


_RANKS: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

#: Ordered most severe first - used for report section ordering.
ORDERED_SEVERITIES: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)

_ALIASES: dict[str, Severity] = {}


def _register(names: Iterable[str], severity: Severity) -> None:
    for name in names:
        _ALIASES[name] = severity


_register(["critical", "crit", "severe", "4", "5"], Severity.CRITICAL)
_register(["high", "3", "important", "significant"], Severity.HIGH)
_register(["medium", "moderate", "med", "2"], Severity.MEDIUM)
_register(["low", "minor", "1"], Severity.LOW)
_register(
    [
        "info",
        "informational",
        "information",
        "note",
        "notice",
        "none",
        "0",
        "unknown",
        "false positive",
        "not a security issue",
    ],
    Severity.INFO,
)


def from_string(value: object, default: Severity = Severity.INFO) -> Severity:
    """Map an arbitrary native severity token onto a lab severity.

    Unrecognised input falls back to *default* (INFO by default) rather than
    guessing upward. Inflating an unknown rating into HIGH or CRITICAL would be
    a fabricated result, so the mapping is deliberately conservative.
    """
    if isinstance(value, Severity):
        return value
    if value is None:
        return default
    text = str(value).strip().lower()
    if not text:
        return default
    if text in _ALIASES:
        return _ALIASES[text]
    # Collapse separators so "high severity" or "risk: high" still matches.
    collapsed = re.sub(r"[^a-z0-9]+", " ", text).strip()
    if collapsed in _ALIASES:
        return _ALIASES[collapsed]
    # Fall back to whole-word matching. Multi-digit numbers are skipped: they
    # are identifiers (osvdb ids, hex values, ports), not severity ratings, and
    # matching their individual digits would map arbitrary input to a level.
    for token in re.findall(r"[a-z]+|\d+", collapsed):
        if token.isdigit() and len(token) > 1:
            continue
        if token in _ALIASES:
            return _ALIASES[token]
    return default


def zap_riskcode(riskcode: object, default: Severity = Severity.INFO) -> Severity:
    """Map a ZAP ``riskcode`` to a lab severity.

    ZAP has no CRITICAL level: 3=High, 2=Medium, 1=Low, 0=Informational.
    """
    try:
        code = int(str(riskcode).strip())
    except (TypeError, ValueError):
        return default
    return {
        3: Severity.HIGH,
        2: Severity.MEDIUM,
        1: Severity.LOW,
        0: Severity.INFO,
    }.get(code, default)


def nikto_rating(text: object, default: Severity = Severity.INFO) -> Severity:
    """Map a Nikto ``severity``/``rating`` string to a lab severity.

    Nikto plugins carry free-text ratings such as ``"high"`` or
    ``"OSVDB-0: Informational"``. Anything unrecognised stays INFO.
    """
    if text is None:
        return default
    raw = str(text)
    # Keep an explicit leading level if present, otherwise use the whole text.
    match = re.search(r"\b(critical|high|medium|low|informational|info)\b", raw, re.I)
    if match:
        return from_string(match.group(1), default)
    return default


def worst(severities: Iterable[Severity]) -> Severity:
    """Return the most severe value, or INFO when empty."""
    items = list(severities)
    if not items:
        return Severity.INFO
    return max(items, key=lambda s: s.rank)


def tally(severities: Iterable[Severity]) -> dict[str, int]:
    """Count severities, always returning all five keys (zero-filled)."""
    counts = {level.value: 0 for level in ORDERED_SEVERITIES}
    for severity in severities:
        counts[severity.value] += 1
    return counts


def at_or_above(severity: Severity, floor: Severity) -> bool:
    return severity.rank >= floor.rank
