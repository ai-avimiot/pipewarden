"""Unit and property-based tests for the report generator."""

import json
import os

from hypothesis import given, settings
from hypothesis import strategies as st

from scripts.count_blocked import count_blocked
from scripts.generate_report import (
    build_report,
    format_markdown_summary,
    format_summary,
    generate_complete_policy_yaml,
    generate_report,
    read_jsonl,
)

# ---------------------------------------------------------------------------
# Strategies for property-based tests
# ---------------------------------------------------------------------------

PROTOCOLS = st.sampled_from(["http", "https", "tcp"])
STATUSES = st.sampled_from(["allowed", "blocked", "would_block"])
HOST_CHARS = st.characters(whitelist_categories=("L", "N"), whitelist_characters=".-")

connection_entry_strategy = st.fixed_dictionaries(
    {
        "timestamp": st.text(min_size=1, max_size=30),
        "protocol": PROTOCOLS,
        "host": st.text(min_size=1, max_size=50, alphabet=HOST_CHARS),
        "port": st.integers(min_value=1, max_value=65535),
        "status": STATUSES,
        "bytes_transferred": st.integers(min_value=0, max_value=10**9),
    },
    optional={
        "path": st.text(max_size=100),
        "method": st.sampled_from(["GET", "POST", "PUT", "DELETE", "PATCH"]),
    },
)


def _http_entry_strategy():
    """Strategy for HTTP/HTTPS connection entries that always include path."""
    return st.fixed_dictionaries({
        "timestamp": st.text(min_size=1, max_size=30),
        "protocol": st.sampled_from(["http", "https"]),
        "host": st.text(min_size=1, max_size=50, alphabet=HOST_CHARS),
        "port": st.integers(min_value=1, max_value=65535),
        "path": st.text(min_size=0, max_size=100),
        "method": st.sampled_from(["GET", "POST", "PUT", "DELETE", "PATCH"]),
        "status": STATUSES,
        "bytes_transferred": st.integers(min_value=0, max_value=10**9),
    })


def _tcp_entry_strategy():
    """Strategy for TCP connection entries (no path/method)."""
    return st.fixed_dictionaries({
        "timestamp": st.text(min_size=1, max_size=30),
        "protocol": st.just("tcp"),
        "host": st.text(min_size=1, max_size=50, alphabet=HOST_CHARS),
        "port": st.integers(min_value=1, max_value=65535),
        "status": STATUSES,
        "bytes_transferred": st.integers(min_value=0, max_value=10**9),
    })


# Mixed list of HTTP/S and TCP entries
connection_list_strategy = st.lists(
    st.one_of(_http_entry_strategy(), _tcp_entry_strategy()),
    min_size=0,
    max_size=20,
)


# ---------------------------------------------------------------------------
# Helper to write a JSONL file
# ---------------------------------------------------------------------------

def _write_jsonl(path: str, entries: list[dict]):
    with open(path, "w") as f:
        for entry in entries:
            f.write(json.dumps(entry) + "\n")


# ---------------------------------------------------------------------------
# Unit tests — read_jsonl
# ---------------------------------------------------------------------------

class TestReadJsonl:
    def test_empty_file(self, tmp_path):
        p = tmp_path / "empty.jsonl"
        p.write_text("")
        assert read_jsonl(str(p)) == []

    def test_single_entry(self, tmp_path):
        entry = {"timestamp": "t1", "protocol": "http", "host": "a.com", "port": 80, "status": "allowed", "bytes_transferred": 0}
        p = tmp_path / "one.jsonl"
        p.write_text(json.dumps(entry) + "\n")
        result = read_jsonl(str(p))
        assert len(result) == 1
        assert result[0] == entry

    def test_multiple_entries(self, tmp_path):
        entries = [
            {"timestamp": "t1", "protocol": "http", "host": "a.com", "port": 80, "status": "allowed", "bytes_transferred": 0},
            {"timestamp": "t2", "protocol": "tcp", "host": "b.com", "port": 443, "status": "blocked", "bytes_transferred": 100},
        ]
        p = tmp_path / "multi.jsonl"
        _write_jsonl(str(p), entries)
        assert read_jsonl(str(p)) == entries


# ---------------------------------------------------------------------------
# Unit tests — build_report
# ---------------------------------------------------------------------------

class TestBuildReport:
    def test_empty_connections(self):
        report = build_report([])
        assert report["total_connections"] == 0
        assert report["allowed_connections"] == 0
        assert report["blocked_connections"] == 0
        assert report["connections"] == []
        assert "generated_at" in report

    def test_counts(self):
        connections = [
            {"status": "allowed"},
            {"status": "allowed"},
            {"status": "blocked"},
            {"status": "would_block"},
        ]
        report = build_report(connections)
        assert report["total_connections"] == 4
        assert report["allowed_connections"] == 2
        assert report["blocked_connections"] == 2

    def test_connections_preserved(self):
        connections = [{"status": "allowed", "host": "x.com"}]
        report = build_report(connections)
        assert report["connections"] == connections

    def test_access_summary_present(self):
        connections = [
            {"status": "allowed", "host": "a.com", "port": 443, "protocol": "https"},
            {"status": "allowed", "host": "a.com", "port": 443, "protocol": "https"},
            {"status": "blocked", "host": "b.com", "port": 443, "protocol": "https"},
        ]
        report = build_report(connections)
        summary = report["access_summary"]
        assert summary["unique_destinations"] == 2
        assert len(summary["destinations"]) == 2

    def test_access_summary_counts_per_destination(self):
        connections = [
            {"status": "allowed", "host": "a.com", "port": 443, "protocol": "https"},
            {"status": "allowed", "host": "a.com", "port": 443, "protocol": "https"},
            {"status": "blocked", "host": "a.com", "port": 443, "protocol": "https"},
        ]
        report = build_report(connections)
        dest = report["access_summary"]["destinations"][0]
        assert dest["host"] == "a.com"
        assert dest["count"] == 3
        assert dest["statuses"] == {"allowed": 2, "blocked": 1}

    def test_access_summary_tls_fields(self):
        connections = [
            {
                "status": "allowed", "host": "a.com", "port": 443,
                "protocol": "https", "tls_sni": "a.com",
                "tls_cert_issuer": "DigiCert Inc",
            },
        ]
        report = build_report(connections)
        dest = report["access_summary"]["destinations"][0]
        assert dest["tls_sni"] == "a.com"
        assert dest["tls_cert_issuer"] == "DigiCert Inc"

    def test_access_summary_cert_warnings(self):
        connections = [
            {
                "status": "allowed", "host": "evil.com", "port": 443,
                "protocol": "https", "tls_cert_valid": False,
                "tls_cert_error": "self-signed certificate",
            },
        ]
        report = build_report(connections)
        warnings = report["access_summary"]["tls_cert_warnings"]
        assert len(warnings) == 1
        assert warnings[0]["host"] == "evil.com"

    def test_access_summary_empty(self):
        report = build_report([])
        summary = report["access_summary"]
        assert summary["unique_destinations"] == 0
        assert summary["total_bytes"] == 0
        assert summary["destinations"] == []
        assert summary["tls_cert_warnings"] == []

    def test_access_summary_bytes_per_destination(self):
        connections = [
            {"status": "allowed", "host": "a.com", "port": 443, "protocol": "https", "bytes_transferred": 1024},
            {"status": "allowed", "host": "a.com", "port": 443, "protocol": "https", "bytes_transferred": 2048},
            {"status": "blocked", "host": "b.com", "port": 80, "protocol": "http", "bytes_transferred": 512},
        ]
        report = build_report(connections)
        summary = report["access_summary"]
        assert summary["total_bytes"] == 1024 + 2048 + 512
        dests = {d["host"]: d for d in summary["destinations"]}
        assert dests["a.com"]["bytes_transferred"] == 3072
        assert dests["b.com"]["bytes_transferred"] == 512


# ---------------------------------------------------------------------------
# Unit tests — format_summary
# ---------------------------------------------------------------------------

class TestFormatSummary:
    def test_summary_contains_counts(self):
        report = build_report([
            {"status": "allowed", "host": "ok.com", "port": 443, "protocol": "https"},
            {"status": "blocked", "host": "evil.com", "port": 443, "protocol": "https"},
        ])
        summary = format_summary(report)
        assert "Total connections:   2" in summary
        assert "Allowed connections: 1" in summary
        assert "Blocked connections: 1" in summary

    def test_summary_highlights_blocked(self):
        report = build_report([
            {"status": "blocked", "host": "evil.com", "port": 443, "protocol": "https"},
        ])
        summary = format_summary(report)
        assert "evil.com:443" in summary
        assert "blocked" in summary.lower()

    def test_summary_no_blocked_section_when_none(self):
        report = build_report([{"status": "allowed", "host": "ok.com", "port": 80, "protocol": "http"}])
        summary = format_summary(report)
        # The detail section starts with "Blocked connections ("
        assert "Blocked connections (" not in summary

    def test_summary_shows_unique_destinations(self):
        report = build_report([
            {"status": "allowed", "host": "a.com", "port": 443, "protocol": "https", "bytes_transferred": 5120},
            {"status": "allowed", "host": "a.com", "port": 443, "protocol": "https", "bytes_transferred": 1024},
            {"status": "blocked", "host": "b.com", "port": 80, "protocol": "http", "bytes_transferred": 256},
        ])
        summary = format_summary(report)
        assert "Unique destinations: 2" in summary
        assert "Total data transferred:" in summary
        assert "a.com:443 (2x, 6.0 KB)" in summary
        assert "b.com:80 (1x, 256 B)" in summary

    def test_summary_shows_cert_issuer(self):
        report = build_report([
            {
                "status": "allowed", "host": "a.com", "port": 443,
                "protocol": "https", "tls_cert_issuer": "DigiCert Inc",
            },
        ])
        summary = format_summary(report)
        assert "CA: DigiCert Inc" in summary

    def test_summary_shows_cert_warning(self):
        report = build_report([
            {
                "status": "allowed", "host": "evil.com", "port": 443,
                "protocol": "https", "tls_cert_valid": False,
                "tls_cert_error": "self-signed certificate",
            },
        ])
        summary = format_summary(report)
        assert "TLS Certificate Warnings" in summary
        assert "self-signed certificate" in summary


# ---------------------------------------------------------------------------
# Unit tests — format_markdown_summary
# ---------------------------------------------------------------------------

class TestFormatMarkdownSummary:
    def test_contains_header(self):
        report = build_report([])
        md = format_markdown_summary(report)
        assert "## 🔒 PipeWarden Report" in md

    def test_contains_metrics_table(self):
        report = build_report([
            {"status": "allowed", "host": "a.com", "port": 443, "protocol": "https"},
            {"status": "blocked", "host": "b.com", "port": 80, "protocol": "http"},
        ])
        md = format_markdown_summary(report)
        assert "| Total connections | 2 |" in md
        assert "| ✅ Allowed | 1 |" in md
        assert "| 🚫 Blocked / would-block | 1 |" in md

    def test_contains_destinations_table(self):
        report = build_report([
            {"status": "allowed", "host": "a.com", "port": 443, "protocol": "https",
             "bytes_transferred": 1024, "tls_cert_issuer": "DigiCert Inc"},
        ])
        md = format_markdown_summary(report)
        assert "`a.com:443`" in md
        assert "DigiCert Inc" in md
        assert "1.0 KB" in md

    def test_cert_warning_section(self):
        report = build_report([
            {"status": "allowed", "host": "evil.com", "port": 443, "protocol": "https",
             "tls_cert_valid": False, "tls_cert_error": "self-signed certificate"},
        ])
        md = format_markdown_summary(report)
        assert "### ⚠️ TLS Certificate Warnings" in md
        assert "self-signed certificate" in md

    def test_blocked_section(self):
        report = build_report([
            {"status": "blocked", "host": "bad.com", "port": 443, "protocol": "https",
             "timestamp": "2026-01-01T12:00:00Z"},
        ])
        md = format_markdown_summary(report)
        assert "🚫 Blocked connections" in md
        assert "`bad.com:443`" in md

    def test_collapsible_sections(self):
        report = build_report([
            {"status": "allowed", "host": "a.com", "port": 443, "protocol": "https"},
        ])
        md = format_markdown_summary(report)
        assert "<details>" in md
        assert "</details>" in md


# ---------------------------------------------------------------------------
# Unit tests — generate_report (end-to-end file I/O)
# ---------------------------------------------------------------------------

class TestGenerateReport:
    def test_creates_report_json(self, tmp_path):
        log_path = tmp_path / "conn.jsonl"
        _write_jsonl(str(log_path), [
            {"timestamp": "t1", "protocol": "https", "host": "a.com", "port": 443,
             "path": "/api", "method": "GET", "status": "allowed", "bytes_transferred": 512},
        ])
        out_dir = str(tmp_path / "output")
        generate_report(str(log_path), out_dir)

        report_file = os.path.join(out_dir, "report.json")
        assert os.path.exists(report_file)
        with open(report_file) as f:
            saved = json.load(f)
        assert saved["total_connections"] == 1

    def test_creates_summary_txt(self, tmp_path):
        log_path = tmp_path / "conn.jsonl"
        _write_jsonl(str(log_path), [
            {"timestamp": "t1", "protocol": "tcp", "host": "db.internal", "port": 5432,
             "status": "blocked", "bytes_transferred": 0},
        ])
        out_dir = str(tmp_path / "output")
        generate_report(str(log_path), out_dir)

        summary_file = os.path.join(out_dir, "summary.txt")
        assert os.path.exists(summary_file)
        with open(summary_file) as f:
            text = f.read()
        assert "db.internal:5432" in text

    def test_creates_summary_md(self, tmp_path):
        log_path = tmp_path / "conn.jsonl"
        _write_jsonl(str(log_path), [
            {"timestamp": "t1", "protocol": "https", "host": "a.com", "port": 443,
             "path": "/", "method": "GET", "status": "allowed", "bytes_transferred": 0},
        ])
        out_dir = str(tmp_path / "output")
        generate_report(str(log_path), out_dir)

        md_file = os.path.join(out_dir, "summary.md")
        assert os.path.exists(md_file)
        with open(md_file) as f:
            text = f.read()
        assert "PipeWarden Report" in text
        assert "`a.com:443`" in text

    def test_empty_log(self, tmp_path):
        log_path = tmp_path / "empty.jsonl"
        log_path.write_text("")
        out_dir = str(tmp_path / "output")
        report = generate_report(str(log_path), out_dir)
        assert report["total_connections"] == 0

    def test_discovery_mode_writes_policy_file(self, tmp_path):
        """In discovery mode (no policy_path), generate_report writes network-policy.yml."""
        log_path = tmp_path / "conn.jsonl"
        _write_jsonl(str(log_path), [
            {"timestamp": "t1", "protocol": "https", "host": "a.com", "port": 443,
             "path": "/", "method": "GET", "status": "would_block", "bytes_transferred": 0},
        ])
        out_dir = str(tmp_path / "output")
        generate_report(str(log_path), out_dir)

        policy_file = os.path.join(out_dir, "network-policy.yml")
        assert os.path.exists(policy_file)
        with open(policy_file) as f:
            content = f.read()
        assert 'version: "1"' in content
        assert "mode: monitor" in content
        assert "a.com" in content

    def test_policy_mode_does_not_write_policy_file(self, tmp_path):
        """When policy_path is provided, generate_report does NOT write network-policy.yml."""
        log_path = tmp_path / "conn.jsonl"
        _write_jsonl(str(log_path), [
            {"timestamp": "t1", "protocol": "https", "host": "a.com", "port": 443,
             "path": "/", "method": "GET", "status": "allowed", "bytes_transferred": 0},
        ])
        policy_path = tmp_path / "policy.yml"
        policy_path.write_text(
            'version: "1"\nmode: monitor\nrules:\n'
            '  - name: "test"\n    allow:\n      domains: ["a.com"]\n'
            '      ports: [443]\n      protocols: [https]\n'
        )
        out_dir = str(tmp_path / "output")
        generate_report(str(log_path), out_dir, policy_path=str(policy_path))

        assert not os.path.exists(os.path.join(out_dir, "network-policy.yml"))


# ---------------------------------------------------------------------------
# Unit tests — generate_complete_policy_yaml
# ---------------------------------------------------------------------------

class TestGenerateCompletePolicyYaml:
    def _make_report(self, destinations: list[dict]) -> dict:
        """Build a minimal report dict with the given destinations."""
        return {
            "access_summary": {
                "destinations": destinations,
            },
            "dns_summary": {"queries": []},
        }

    def test_empty_report_produces_valid_yaml(self):
        report = self._make_report([])
        yaml = generate_complete_policy_yaml(report)
        assert 'version: "1"' in yaml
        assert "mode: monitor" in yaml
        assert "rules:" in yaml

    def test_includes_all_destinations(self):
        report = self._make_report([
            {"host": "api.example.com", "port": 443, "protocol": "https"},
            {"host": "cdn.example.com", "port": 80, "protocol": "http"},
        ])
        yaml = generate_complete_policy_yaml(report)
        assert "api.example.com" in yaml
        assert "cdn.example.com" in yaml
        assert "443" in yaml
        assert "80" in yaml

    def test_skips_dns_protocol(self):
        report = self._make_report([
            {"host": "example.com", "port": 53, "protocol": "dns"},
            {"host": "api.example.com", "port": 443, "protocol": "https"},
        ])
        yaml = generate_complete_policy_yaml(report)
        assert "53" not in yaml
        assert "api.example.com" in yaml

    def test_sorted_output(self):
        report = self._make_report([
            {"host": "z.com", "port": 443, "protocol": "https"},
            {"host": "a.com", "port": 443, "protocol": "https"},
        ])
        yaml = generate_complete_policy_yaml(report)
        a_pos = yaml.index("a.com")
        z_pos = yaml.index("z.com")
        assert a_pos < z_pos

    def test_includes_owner_comment_when_available(self):
        report = self._make_report([
            {
                "host": "api.example.com", "port": 443, "protocol": "https",
                "ip_info": {"owner": "Example Corp", "country": "US"},
            },
        ])
        yaml = generate_complete_policy_yaml(report)
        assert "Example Corp" in yaml

    def test_no_owner_no_comment(self):
        report = self._make_report([
            {"host": "api.example.com", "port": 443, "protocol": "https"},
        ])
        yaml = generate_complete_policy_yaml(report)
        # Should not crash and should contain the host
        assert "api.example.com" in yaml

    def test_wildcard_host_rule_name(self):
        report = self._make_report([
            {"host": "*.github.com", "port": 443, "protocol": "https"},
        ])
        yaml = generate_complete_policy_yaml(report)
        assert "*.github.com" in yaml

    def test_generated_yaml_has_discovery_header(self):
        report = self._make_report([])
        yaml = generate_complete_policy_yaml(report)
        assert "Auto-generated by PipeWarden" in yaml
        assert "discovery run" in yaml


# ---------------------------------------------------------------------------
# Unit tests — count_blocked
# ---------------------------------------------------------------------------

class TestCountBlocked:
    def test_returns_blocked_count(self, tmp_path):
        report = {"blocked_connections": 5}
        p = tmp_path / "report.json"
        p.write_text(json.dumps(report))
        assert count_blocked(str(p)) == 5

    def test_returns_zero_when_missing(self, tmp_path):
        report = {"total_connections": 3}
        p = tmp_path / "report.json"
        p.write_text(json.dumps(report))
        assert count_blocked(str(p)) == 0


# ---------------------------------------------------------------------------
# Property test P9: Report Field Completeness
# **Validates: Requirements 4.2**
# ---------------------------------------------------------------------------

REQUIRED_FIELDS = {"timestamp", "protocol", "host", "port", "status", "bytes_transferred"}


@given(connections=connection_list_strategy)
@settings(max_examples=200)
def test_p9_report_field_completeness(connections):
    """P9: For any list of connection entries, the report contains all required
    fields: timestamp, protocol, host, port, status, bytes_transferred.
    For HTTP/S entries, path is also present.

    **Validates: Requirements 4.2**
    """
    report = build_report(connections)

    # Top-level report fields
    assert "total_connections" in report
    assert "allowed_connections" in report
    assert "blocked_connections" in report
    assert "connections" in report
    assert "generated_at" in report
    assert "access_summary" in report

    # Access summary structure
    access = report["access_summary"]
    assert "unique_destinations" in access
    assert "total_bytes" in access
    assert "destinations" in access
    assert "tls_cert_warnings" in access
    assert isinstance(access["destinations"], list)
    assert isinstance(access["tls_cert_warnings"], list)

    # Each connection entry has all required fields
    for conn in report["connections"]:
        for field in REQUIRED_FIELDS:
            assert field in conn, f"Missing required field '{field}' in connection entry"

        # HTTP/S entries must also have path
        if conn["protocol"] in ("http", "https"):
            assert "path" in conn, "HTTP/S entry missing 'path' field"
