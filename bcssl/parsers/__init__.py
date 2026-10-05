"""Parser package for the assessment lab.

Each module parses one tool's native output into the normalized finding schema.
"""

from __future__ import annotations

from .base import ParseResult

__all__ = ["ParseResult"]
