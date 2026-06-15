#!/usr/bin/env python3
"""Syslog log parser for iptables NFW-CONN entries.

Parses syslog/kern.log entries produced by iptables LOG rules with
the ``NFW-CONN: `` prefix and converts them into structured connection
metadata. Pure functions with minimal I/O — file reading is the only
side effect.
"""

import os
import re
from typing import Optional

# Pattern matches syslog lines containing NFW-CONN log entries, e.g.:
# Jun 10 12:00:00 runner kernel: [12345.678] NFW-CONN: IN= OUT=eth0
#   SRC=10.0.0.1 DST=93.184.216.34 ... PROTO=TCP ... DPT=443 ... UID=1001
NFW_LOG_PATTERN = re.compile(
    r"NFW-CONN: .*?"
    r"SRC=(?P<src_ip>\S+).*?"
    r"DST=(?P<dst_ip>\S+).*?"
    r"PROTO=(?P<protocol>\S+).*?"
    r"DPT=(?P<dst_port>\d+).*?"
    r"UID=(?P<uid>\d+)"
)

# Syslog timestamp at the start of a line, e.g. "Jun 10 12:00:00"
_SYSLOG_TS_PATTERN = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
)


def parse_nfw_log_line(line: str) -> Optional[dict]:
    """Parse a single syslog line with NFW-CONN prefix.

    Args:
        line: A raw syslog line string.

    Returns:
        Dictionary with keys ``dst_ip``, ``dst_port`` (int),
        ``protocol``, ``uid`` (int), ``src_ip``, and ``timestamp``
        (string, may be empty if not present). Returns ``None`` if
        the line does not contain a valid NFW-CONN entry.
    """
    match = NFW_LOG_PATTERN.search(line)
    if match is None:
        return None

    ts_match = _SYSLOG_TS_PATTERN.search(line)
    timestamp = ts_match.group("timestamp") if ts_match else ""

    return {
        "dst_ip": match.group("dst_ip"),
        "dst_port": int(match.group("dst_port")),
        "protocol": match.group("protocol"),
        "uid": int(match.group("uid")),
        "src_ip": match.group("src_ip"),
        "timestamp": timestamp,
    }


def parse_nfw_log_file(path: str) -> list[dict]:
    """Read a syslog file and return all parsed NFW-CONN entries.

    Args:
        path: Absolute or relative path to the syslog file.

    Returns:
        List of parsed entry dictionaries. Returns an empty list if
        the file does not exist, cannot be read, or contains no
        matching entries.
    """
    if not os.path.isfile(path):
        return []

    entries: list[dict] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parsed = parse_nfw_log_line(line)
                if parsed is not None:
                    entries.append(parsed)
    except OSError:
        return []

    return entries


def merge_iptables_entries(
    iptables_entries: list[dict],
    existing_entries: list[dict],
) -> list[dict]:
    """Merge iptables log entries with existing JSONL entries.

    Deduplicates by ``(dst_ip, dst_port)`` — if an existing entry
    already covers that destination (matching ``host`` or ``server_ip``
    and ``port``), the iptables entry is skipped.

    All original *existing_entries* are always preserved in the result.

    Args:
        iptables_entries: Parsed entries from :func:`parse_nfw_log_file`.
            Each dict must have ``dst_ip`` and ``dst_port`` keys.
        existing_entries: Entries from the addon.py JSONL log. Each dict
            uses ``host`` (and optionally ``server_ip``) for the
            destination and ``port`` for the port.

    Returns:
        A new list containing all *existing_entries* followed by any
        non-duplicate *iptables_entries*.
    """
    # Build a set of (ip, port) pairs from existing entries for fast lookup.
    existing_keys: set[tuple[str, int]] = set()
    for entry in existing_entries:
        port = entry.get("port")
        host = entry.get("host")
        server_ip = entry.get("server_ip")
        if host is not None and port is not None:
            existing_keys.add((host, int(port)))
        if server_ip is not None and port is not None:
            existing_keys.add((server_ip, int(port)))

    merged: list[dict] = list(existing_entries)
    for ipt_entry in iptables_entries:
        key = (ipt_entry["dst_ip"], int(ipt_entry["dst_port"]))
        if key not in existing_keys:
            merged.append(ipt_entry)

    return merged
