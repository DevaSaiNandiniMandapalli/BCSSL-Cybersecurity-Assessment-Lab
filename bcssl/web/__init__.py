"""Optional local web dashboard for the assessment lab."""

from __future__ import annotations

from .server import DashboardHandler, serve

__all__ = ["DashboardHandler", "serve"]
