#!/usr/bin/env python3
"""Render the consolidated HTML, JSON and Markdown assessment report."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bcssl.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main(["report", *sys.argv[1:]]))
