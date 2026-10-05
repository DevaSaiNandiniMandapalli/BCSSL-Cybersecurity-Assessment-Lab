#!/usr/bin/env python3
"""Check a target against the lab's authorized scope.

The same validator runs before every tool. This script exposes it on its own so
a student can prove the boundary works before scanning anything.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bcssl.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main(["validate-target", *sys.argv[1:]]))
