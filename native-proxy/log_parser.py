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


def _transport_of(protocol: str | None) -> str:
    """Reduce a protocol label to the transport it runs over.

    The two sources name things differently — the proxy records application
    protocols ("https", "dns"), iptables records "TCP"/"UDP" — so they have to
    be reduced to a common axis before entries can be compared. Anything
    unrecognised falls back to TCP, matching the proxy's own default.
    """
    name = (protocol or "").lower()
    if name in ("udp", "quic"):
        return "udp"
    if name == "dns":
        # DNS is asked over UDP in practice; a TCP fallback would be recorded
        # separately by the proxy anyway.
        return "udp"
    return "tcp"


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
    # Keyed on transport as well as (ip, port). Without it, a UDP entry is
    # discarded as a duplicate of a TCP one to the same destination — which
    # hides essentially all QUIC, since an HTTP/3 client contacts a host over
    # TCP/443 first and every subsequent UDP/443 datagram then looks like a
    # repeat. Found by the bypass suite, which asserted UDP 443 was visible and
    # it was not.
    existing_keys: set[tuple[str, int, str]] = set()
    for entry in existing_entries:
        port = entry.get("port")
        if port is None:
            continue
        transport = _transport_of(entry.get("protocol"))
        for addr in (entry.get("host"), entry.get("server_ip")):
            if addr is not None:
                existing_keys.add((addr, int(port), transport))

    merged: list[dict] = list(existing_entries)
    for ipt_entry in iptables_entries:
        key = (
            ipt_entry["dst_ip"],
            int(ipt_entry["dst_port"]),
            _transport_of(ipt_entry.get("protocol")),
        )
        if key not in existing_keys:
            merged.append(ipt_entry)

    return merged
