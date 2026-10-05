#!/usr/bin/env python3
"""Report which assessment tools are actually installed.

The lab never fabricates a scan: a tool that cannot be executed is reported as
TOOL NOT INSTALLED. Run this before class.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bcssl.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main(["preflight", *sys.argv[1:]]))
