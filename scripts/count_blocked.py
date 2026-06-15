#!/usr/bin/env python3
"""Helper script that reads report.json and prints the blocked connection count."""

import json
import sys


def count_blocked(report_path: str) -> int:
    """Read report.json and return the blocked connection count."""
    with open(report_path, "r") as f:
        report = json.load(f)
    return report.get("blocked_connections", 0)


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <path-to-report.json>", file=sys.stderr)
        sys.exit(1)

    print(count_blocked(sys.argv[1]))


if __name__ == "__main__":
    main()
