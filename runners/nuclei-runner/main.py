#!/usr/bin/env python3
"""Nuclei controlled assessment runner.

Thin entry point. All behaviour lives in ``bcssl.runners.nuclei`` so the CLI,
this script and the web dashboard share one implementation.

Usage::

    python runners/nuclei-runner/main.py --url http://localhost:3001
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from bcssl.cli import main  # noqa: E402

if __name__ == "__main__":
    # Reuse the documented CLI so options and safety behaviour cannot drift.
    raise SystemExit(main(["run", "nuclei", *sys.argv[1:]]))
