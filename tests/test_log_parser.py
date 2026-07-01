"""Property-based tests for native-proxy/log_parser.py — syslog log parsing.

Feature: native-transparent-proxy
"""

import os
import sys
import tempfile

# Ensure native-proxy is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "native-proxy"))

from hypothesis import assume, given, settings
from hypothesis import strategies as st
from log_parser import merge_iptables_entries, parse_nfw_log_file, parse_nfw_log_line

# ------------------------------------------------------------------
# Generators
# ------------------------------------------------------------------

@st.composite
def nfw_log_lines(draw):
    """Generate realistic NFW-CONN syslog lines with known field values."""
    month = draw(st.sampled_from([
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ]))
    day = draw(st.integers(1, 28))
    hour = draw(st.integers(0, 23))
    minute = draw(st.integers(0, 59))
    second = draw(st.integers(0, 59))
    src_ip = draw(st.from_regex(
        r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", fullmatch=True
    ))
    dst_ip = draw(st.from_regex(
        r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", fullmatch=True
    ))
    proto = draw(st.sampled_from(["TCP", "UDP"]))
    dpt = draw(st.integers(1, 65535))
    uid = draw(st.integers(0, 65535))
    ts = f"{month} {day:2d} {hour:02d}:{minute:02d}:{second:02d}"
    line = (
        f"{ts} runner kernel: [12345.678] NFW-CONN: IN= OUT=eth0 "
        f"SRC={src_ip} DST={dst_ip} LEN=60 TOS=0x00 PREC=0x00 TTL=64 "
        f"ID=12345 DF PROTO={proto} SPT=54321 DPT={dpt} "
        f"WINDOW=65535 RES=0x00 SYN URGP=0 UID={uid} GID=1000"
    )
    return line, src_ip, dst_ip, proto, dpt, uid


@st.composite
def non_nfw_lines(draw):
    """Generate strings that do NOT contain 'NFW-CONN: '."""
    line = draw(st.text())
    assume("NFW-CONN: " not in line)
    return line


@st.composite
def iptables_entry(draw):
    """Generate a parsed iptables entry dict."""
    dst_ip = draw(st.from_regex(
        r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", fullmatch=True
    ))
    dst_port = draw(st.integers(1, 65535))
    proto = draw(st.sampled_from(["TCP", "UDP"]))
    uid = draw(st.integers(0, 65535))
    return {
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "protocol": proto,
        "uid": uid,
        "src_ip": "10.0.0.1",
        "timestamp": "Jun  1 00:00:00",
    }


@st.composite
def existing_jsonl_entry(draw):
    """Generate an existing JSONL connection entry (as written by addon.py)."""
    host = draw(st.from_regex(
        r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", fullmatch=True
    ))
    port = draw(st.integers(1, 65535))
    return {
        "host": host,
        "port": port,
        "timestamp": "2025-06-10T12:00:00",
        "protocol": "tcp",
        "status": "allowed",
    }


# ------------------------------------------------------------------
# Property 2: Log line parsing extracts all required fields
# ------------------------------------------------------------------
# Validates: Requirements 5.2, 11.1
#
# For any syslog line containing NFW-CONN: prefix with valid SRC=,
# DST=, PROTO=, DPT=, UID= fields, parse_nfw_log_line returns a dict
# with all five keys matching the input.
# ------------------------------------------------------------------


@given(data=nfw_log_lines())
@settings(max_examples=100)
def test_p2_log_line_parsing(data):
    """Feature: native-transparent-proxy, Property 2: Log line parsing extracts all required fields

    **Validates: Requirements 5.2, 11.1**
    """
    line, src_ip, dst_ip, proto, dpt, uid = data
    result = parse_nfw_log_line(line)

    assert result is not None, "Expected a parsed dict, got None"
    assert result["src_ip"] == src_ip
    assert result["dst_ip"] == dst_ip
    assert result["protocol"] == proto
    assert result["dst_port"] == dpt
    assert result["uid"] == uid


# ------------------------------------------------------------------
# Property 3: Non-matching lines return None
# ------------------------------------------------------------------
# Validates: Requirements 11.2
#
# For any string that does NOT contain NFW-CONN: , parse_nfw_log_line
# returns None.
# ------------------------------------------------------------------


@given(line=non_nfw_lines())
@settings(max_examples=100)
def test_p3_non_matching_lines(line):
    """Feature: native-transparent-proxy, Property 3: Non-matching lines return None

    **Validates: Requirements 11.2**
    """
    result = parse_nfw_log_line(line)
    assert result is None, f"Expected None for non-NFW line, got {result}"


# ------------------------------------------------------------------
# Property 4: File parsing returns correct entry count
# ------------------------------------------------------------------
# Validates: Requirements 5.1, 11.3
#
# For any file with N valid NFW-CONN lines and M non-matching lines,
# parse_nfw_log_file returns exactly N entries.
# ------------------------------------------------------------------


@given(
    valid_lines=st.lists(nfw_log_lines(), min_size=0, max_size=20),
    invalid_lines=st.lists(non_nfw_lines(), min_size=0, max_size=20),
    data=st.data(),
)
@settings(max_examples=100)
def test_p4_file_parsing_count(valid_lines, invalid_lines, data):
    """Feature: native-transparent-proxy, Property 4: File parsing returns correct entry count

    **Validates: Requirements 5.1, 11.3**
    """
    # Build a file with interleaved valid and invalid lines
    all_lines = [(line, True) for line, *_ in valid_lines] + \
                [(line, False) for line in invalid_lines]
    # Shuffle using Hypothesis data strategy for reproducibility
    shuffled = data.draw(st.permutations(all_lines))

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".log", delete=False, encoding="utf-8"
    ) as f:
        for line, _ in shuffled:
            f.write(line + "\n")
        file_path = f.name

    try:
        result = parse_nfw_log_file(file_path)
        expected_count = len(valid_lines)
        assert len(result) == expected_count, (
            f"Expected {expected_count} entries, got {len(result)}"
        )
    finally:
        os.unlink(file_path)


# ------------------------------------------------------------------
# Property 5: Merge deduplication preserves non-duplicates and removes
#             duplicates
# ------------------------------------------------------------------
# Validates: Requirements 5.4, 11.4, 11.5
#
# For any list of iptables entries and existing JSONL entries,
# merge_iptables_entries returns a list where:
# (a) duplicates by (dst_ip, dst_port) matching (host/server_ip, port)
#     are excluded
# (b) non-duplicates are included
# (c) all existing entries are preserved
# ------------------------------------------------------------------


@given(
    ipt_entries=st.lists(iptables_entry(), min_size=0, max_size=15),
    existing=st.lists(existing_jsonl_entry(), min_size=0, max_size=15),
)
@settings(max_examples=100)
def test_p5_merge_deduplication(ipt_entries, existing):
    """Feature: native-transparent-proxy, Property 5: Merge deduplication preserves non-duplicates and removes duplicates

    **Validates: Requirements 5.4, 11.4, 11.5**
    """
    result = merge_iptables_entries(ipt_entries, existing)

    # Build the set of existing keys for dedup checking
    existing_keys = set()
    for entry in existing:
        host = entry.get("host")
        port = entry.get("port")
        server_ip = entry.get("server_ip")
        if host is not None and port is not None:
            existing_keys.add((host, int(port)))
        if server_ip is not None and port is not None:
            existing_keys.add((server_ip, int(port)))

    # (c) All existing entries are preserved at the start
    assert result[:len(existing)] == existing, "Existing entries must be preserved"

    # Partition iptables entries into duplicates and non-duplicates
    non_dup = []
    for entry in ipt_entries:
        key = (entry["dst_ip"], int(entry["dst_port"]))
        if key not in existing_keys:
            non_dup.append(entry)

    # (a) + (b): The appended portion should be exactly the non-duplicates
    appended = result[len(existing):]
    assert appended == non_dup, (
        f"Expected {len(non_dup)} non-duplicate entries appended, got {len(appended)}"
    )


# ==================================================================
# Unit Tests — Task 2.3: Log parser edge cases
# ==================================================================
# Validates: Requirements 5.5, 11.2


class TestParseNfwLogLine:
    """Unit tests for parse_nfw_log_line."""

    def test_valid_line(self):
        """Known syslog line parses correctly."""
        line = (
            "Jun 10 12:00:00 runner kernel: [12345.678] NFW-CONN: IN= OUT=eth0 "
            "SRC=10.0.0.1 DST=93.184.216.34 LEN=60 TOS=0x00 PREC=0x00 TTL=64 "
            "ID=12345 DF PROTO=TCP SPT=54321 DPT=443 "
            "WINDOW=65535 RES=0x00 SYN URGP=0 UID=1001 GID=1000"
        )
        result = parse_nfw_log_line(line)
        assert result is not None
        assert result["dst_ip"] == "93.184.216.34"
        assert result["dst_port"] == 443
        assert result["protocol"] == "TCP"
        assert result["uid"] == 1001
        assert result["src_ip"] == "10.0.0.1"
        assert result["timestamp"] == "Jun 10 12:00:00"

    def test_no_nfw_prefix(self):
        """Line without NFW-CONN prefix returns None."""
        line = "Jun 10 12:00:00 runner kernel: some other log message"
        assert parse_nfw_log_line(line) is None

    def test_empty_string(self):
        """Empty string returns None."""
        assert parse_nfw_log_line("") is None


class TestParseNfwLogFile:
    """Unit tests for parse_nfw_log_file."""

    def test_empty_file(self, tmp_path):
        """Empty file returns empty list."""
        f = tmp_path / "empty.log"
        f.write_text("")
        assert parse_nfw_log_file(str(f)) == []

    def test_nonexistent_file(self):
        """Nonexistent file returns empty list."""
        assert parse_nfw_log_file("/tmp/does_not_exist_nfw_test.log") == []

    def test_file_with_mixed_lines(self, tmp_path):
        """Only NFW-CONN lines are parsed; other lines are skipped."""
        nfw_line = (
            "Jun 10 12:00:00 runner kernel: [12345.678] NFW-CONN: IN= OUT=eth0 "
            "SRC=10.0.0.1 DST=1.2.3.4 LEN=60 TOS=0x00 PREC=0x00 TTL=64 "
            "ID=12345 DF PROTO=UDP SPT=54321 DPT=53 "
            "WINDOW=65535 RES=0x00 SYN URGP=0 UID=1000 GID=1000"
        )
        content = "some random log line\n" + nfw_line + "\nanother random line\n"
        f = tmp_path / "mixed.log"
        f.write_text(content)
        result = parse_nfw_log_file(str(f))
        assert len(result) == 1
        assert result[0]["dst_ip"] == "1.2.3.4"
        assert result[0]["dst_port"] == 53
        assert result[0]["protocol"] == "UDP"


class TestMergeIptablesEntries:
    """Unit tests for merge_iptables_entries."""

    def test_no_duplicates(self):
        """All iptables entries preserved when no overlap with existing."""
        ipt = [
            {"dst_ip": "1.1.1.1", "dst_port": 443, "protocol": "TCP", "uid": 1000,
             "src_ip": "10.0.0.1", "timestamp": "Jun  1 00:00:00"},
        ]
        existing = [
            {"host": "2.2.2.2", "port": 80, "timestamp": "t", "protocol": "tcp", "status": "allowed"},
        ]
        result = merge_iptables_entries(ipt, existing)
        assert len(result) == 2
        assert result[0] == existing[0]
        assert result[1] == ipt[0]

    def test_exact_duplicates_removed(self):
        """Iptables entry matching existing (host, port) is excluded."""
        ipt = [
            {"dst_ip": "93.184.216.34", "dst_port": 443, "protocol": "TCP", "uid": 1000,
             "src_ip": "10.0.0.1", "timestamp": "Jun  1 00:00:00"},
        ]
        existing = [
            {"host": "93.184.216.34", "port": 443, "timestamp": "t", "protocol": "tcp", "status": "allowed"},
        ]
        result = merge_iptables_entries(ipt, existing)
        assert len(result) == 1
        assert result[0] == existing[0]

    def test_empty_inputs(self):
        """Both empty lists returns empty list."""
        assert merge_iptables_entries([], []) == []

    def test_existing_preserved(self):
        """All existing entries appear in result regardless of iptables input."""
        existing = [
            {"host": "5.5.5.5", "port": 22, "timestamp": "t", "protocol": "tcp", "status": "allowed"},
            {"host": "6.6.6.6", "port": 8080, "timestamp": "t", "protocol": "tcp", "status": "allowed"},
        ]
        result = merge_iptables_entries([], existing)
        assert result == existing
