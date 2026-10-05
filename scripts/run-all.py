#!/usr/bin/env python3
"""Run every configured tool against the authorized target.

Missing or failing tools are reported individually; one failure never stops the
others, and no tool that did not run produces findings.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bcssl.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main(["run-all", *sys.argv[1:]]))
