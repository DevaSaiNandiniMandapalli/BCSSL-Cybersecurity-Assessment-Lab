#!/usr/bin/env python3
"""Project #08 HTML report (--html-output)

Standalone parser CLI: reads a stored custom-scanner report and prints normalized
findings as JSON. It never contacts a target and never runs a scan.

Usage::

    python parsers/custom-parser/main.py <path-to-custom-scanner-report.html>
    python parsers/custom-parser/main.py <path> --target http://localhost:3001
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from bcssl.parsers import custom as parser  # noqa: E402
from bcssl.severity import ORDERED_SEVERITIES  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("report", help="path to the stored custom-scanner report")
    ap.add_argument(
        "--target",
        default="http://localhost:3001",
        help="authorized target recorded on each finding",
    )
    args = ap.parse_args(argv)

    path = Path(args.report)
    if not path.is_file():
        print(f"report not found: {path}", file=sys.stderr)
        return 2

    payload = path.read_text(encoding="utf-8", errors="replace")
    result = parser.parse(payload, target=args.target)

    counts = {level.value: 0 for level in ORDERED_SEVERITIES}
    for finding in result.findings:
        counts[finding.severity.value] += 1

    print(
        json.dumps(
            {
                "tool": "custom-scanner",
                "report": str(path),
                "finding_count": len(result.findings),
                "severity_counts": counts,
                "errors": result.errors,
                "warnings": result.warnings,
                "notes": result.notes,
                "findings": [finding.to_dict() for finding in result.findings],
            },
            indent=2,
            ensure_ascii=False,
        )
    )
    return 1 if result.errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
