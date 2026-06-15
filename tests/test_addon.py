"""Unit tests for the proxy addon (NetworkMonitorAddon)."""

import json
import os

import pytest

from tests.conftest import (
    MockHTTPFlow,
    MockRequest,
    MockResponse,
    MockClientConn,
    MockCert,
    MockServerConn,
    MockServerConnWithCert,
    MockTCPFlow,
    MockTCPMessage,
)
from proxy.addon import NetworkMonitorAddon


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _read_log_entries(log_path: str) -> list[dict]:
    """Read all JSONL entries from the log file."""
    entries = []
    with open(log_path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


def _make_addon(policy_file, mode="enforce", log_path="/tmp/test.jsonl"):
    """Create a NetworkMonitorAddon with explicit arguments."""
    return NetworkMonitorAddon(
        policy_file=policy_file,
        mode=mode,
        log_path=log_path,
    )


# ------------------------------------------------------------------
# HTTP/HTTPS request interception tests
# ------------------------------------------------------------------

class TestHTTPRequestInterception:
    """Tests for the request() handler."""

    def test_allowed_https_request_logs_allowed(self, sample_policy_file, log_file):
        addon = _make_addon(sample_policy_file, mode="enforce", log_path=log_file)
        flow = MockHTTPFlow(MockRequest(
            scheme="https", host="api.github.com", port=443, path="/repos", method="GET",
        ))

        addon.request(flow)

        entries = _read_log_entries(log_file)
        assert len(entries) == 1
        assert entries[0]["host"] == "api.github.com"
        assert entries[0]["port"] == 443
        assert entries[0]["protocol"] == "https"
        assert entries[0]["path"] == "/repos"
        assert entries[0]["method"] == "GET"
        assert entries[0]["status"] == "allowed"
        # Allowed request should NOT have a response set
        assert flow.response is None

    def test_blocked_request_in_enforce_mode(self, sample_policy_file, log_file):
        addon = _make_addon(sample_policy_file, mode="enforce", log_path=log_file)
        flow = MockHTTPFlow(MockRequest(
            scheme="https", host="evil.example.com", port=443, path="/steal", method="POST",
        ))

        addon.request(flow)

        entries = _read_log_entries(log_file)
        assert len(entries) == 1
        assert entries[0]["status"] == "blocked"
        # Response should be set to 403
        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_would_block_in_monitor_mode(self, sample_policy_file, log_file):
        addon = _make_addon(sample_policy_file, mode="monitor", log_path=log_file)
        flow = MockHTTPFlow(MockRequest(
            scheme="https", host="evil.example.com", port=443, path="/steal", method="POST",
        ))

        addon.request(flow)

        entries = _read_log_entries(log_file)
        assert len(entries) == 1
        assert entries[0]["status"] == "would_block"
        # Monitor mode should NOT block — no response set
        assert flow.response is None

    def test_http_request_logged_as_http(self, sample_policy_file, log_file):
        addon = _make_addon(sample_policy_file, mode="monitor", log_path=log_file)
        flow = MockHTTPFlow(MockRequest(
            scheme="http", host="example.com", port=80, path="/page", method="GET",
        ))

        addon.request(flow)

        entries = _read_log_entries(log_file)
        assert entries[0]["protocol"] == "http"

    def test_multiple_requests_appended_to_log(self, sample_policy_file, log_file):
        addon = _make_addon(sample_policy_file, mode="monitor", log_path=log_file)

        for i in range(3):
            flow = MockHTTPFlow(MockRequest(
                scheme="https", host=f"host{i}.github.com", port=443,
                path=f"/path{i}", method="GET",
            ))
            addon.request(flow)

        entries = _read_log_entries(log_file)
        assert len(entries) == 3
        assert [e["host"] for e in entries] == [
            "host0.github.com", "host1.github.com", "host2.github.com",
        ]


# ------------------------------------------------------------------
# TCP connection logging tests
# ------------------------------------------------------------------

class TestTCPConnectionLogging:
    """Tests for the tcp_message() handler."""

    def test_tcp_message_logged(self, sample_policy_file, log_file):
        addon = _make_addon(sample_policy_file, mode="monitor", log_path=log_file)
        flow = MockTCPFlow(
            server_conn=MockServerConn(host="10.0.0.1", port=5432),
            messages=[MockTCPMessage(content=b"SELECT 1")],
        )

        addon.tcp_message(flow)

        entries = _read_log_entries(log_file)
        assert len(entries) == 1
        assert entries[0]["protocol"] == "tcp"
        assert entries[0]["host"] == "10.0.0.1"
        assert entries[0]["port"] == 5432
        assert entries[0]["bytes_transferred"] == len(b"SELECT 1")

    def test_tcp_message_status_evaluated(self, sample_policy_file, log_file):
        addon = _make_addon(sample_policy_file, mode="enforce", log_path=log_file)
        # Port 5432 is not in the policy — should be blocked
        flow = MockTCPFlow(
            server_conn=MockServerConn(host="10.0.0.1", port=5432),
            messages=[MockTCPMessage(content=b"data")],
        )

        addon.tcp_message(flow)

        entries = _read_log_entries(log_file)
        assert entries[0]["status"] == "blocked"

    def test_tcp_dns_allowed(self, sample_policy_file, log_file):
        addon = _make_addon(sample_policy_file, mode="enforce", log_path=log_file)
        # DNS on port 53 with tcp protocol should be allowed
        flow = MockTCPFlow(
            server_conn=MockServerConn(host="8.8.8.8", port=53),
            messages=[MockTCPMessage(content=b"\x00\x01")],
        )

        addon.tcp_message(flow)

        entries = _read_log_entries(log_file)
        assert entries[0]["status"] == "allowed"


# ------------------------------------------------------------------
# Policy enforcement mode tests
# ------------------------------------------------------------------

class TestPolicyEnforcement:
    """Tests verifying enforce vs monitor mode behaviour."""

    def test_enforce_blocks_non_matching(self, sample_policy_file, log_file):
        addon = _make_addon(sample_policy_file, mode="enforce", log_path=log_file)
        flow = MockHTTPFlow(MockRequest(
            scheme="https", host="malicious.io", port=443, path="/", method="GET",
        ))

        addon.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_monitor_never_blocks(self, sample_policy_file, log_file):
        addon = _make_addon(sample_policy_file, mode="monitor", log_path=log_file)
        flow = MockHTTPFlow(MockRequest(
            scheme="https", host="malicious.io", port=443, path="/", method="GET",
        ))

        addon.request(flow)

        assert flow.response is None
        entries = _read_log_entries(log_file)
        assert entries[0]["status"] == "would_block"

    def test_enforce_allows_matching(self, sample_policy_file, log_file):
        addon = _make_addon(sample_policy_file, mode="enforce", log_path=log_file)
        flow = MockHTTPFlow(MockRequest(
            scheme="https", host="registry.npmjs.org", port=443,
            path="/package", method="GET",
        ))

        addon.request(flow)

        assert flow.response is None
        entries = _read_log_entries(log_file)
        assert entries[0]["status"] == "allowed"


# ------------------------------------------------------------------
# JSONL log file tests
# ------------------------------------------------------------------

class TestJSONLLogging:
    """Tests for JSONL log file writing."""

    def test_log_entries_are_valid_json(self, sample_policy_file, log_file):
        addon = _make_addon(sample_policy_file, mode="monitor", log_path=log_file)
        flow = MockHTTPFlow(MockRequest(
            scheme="https", host="api.github.com", port=443, path="/", method="GET",
        ))

        addon.request(flow)

        with open(log_file, "r") as fh:
            for line in fh:
                entry = json.loads(line.strip())
                assert "timestamp" in entry
                assert "protocol" in entry
                assert "host" in entry
                assert "port" in entry
                assert "status" in entry

    def test_log_creates_parent_directories(self, tmp_path):
        """Log file in a nested directory that doesn't exist yet."""
        nested_log = str(tmp_path / "deep" / "nested" / "connections.jsonl")
        # Need a policy file
        policy_path = tmp_path / "policy.yml"
        policy_path.write_text(
            'version: "1"\nmode: monitor\nrules:\n'
            '  - name: all\n    allow:\n      domains: ["*"]\n      ports: []\n      protocols: [http, https, tcp]\n'
        )
        addon = _make_addon(str(policy_path), mode="monitor", log_path=nested_log)
        flow = MockHTTPFlow(MockRequest())

        addon.request(flow)

        assert os.path.exists(nested_log)
        entries = _read_log_entries(nested_log)
        assert len(entries) == 1

    def test_log_entry_has_timestamp(self, sample_policy_file, log_file):
        addon = _make_addon(sample_policy_file, mode="monitor", log_path=log_file)
        flow = MockHTTPFlow(MockRequest())

        addon.request(flow)

        entries = _read_log_entries(log_file)
        ts = entries[0]["timestamp"]
        # Should be an ISO-format timestamp
        assert "T" in ts


# ------------------------------------------------------------------
# TLS / SNI domain reporting tests
# ------------------------------------------------------------------

class TestTLSDomainReporting:
    """Tests for HTTPS domain extraction from TLS SNI."""

    def test_sni_used_as_host_when_ip(self, sample_policy_file, log_file):
        """When host is an IP but SNI is available, use SNI as the host."""
        addon = _make_addon(sample_policy_file, mode="monitor", log_path=log_file)
        flow = MockHTTPFlow(
            request=MockRequest(
                scheme="https", host="140.82.121.4", port=443,
                path="/repos", method="GET",
            ),
            client_conn=MockClientConn(sni="api.github.com"),
        )

        addon.request(flow)

        entries = _read_log_entries(log_file)
        assert entries[0]["host"] == "api.github.com"
        assert entries[0]["tls_sni"] == "api.github.com"

    def test_sni_logged_for_https(self, sample_policy_file, log_file):
        """SNI should be logged in the tls_sni field for HTTPS."""
        addon = _make_addon(sample_policy_file, mode="monitor", log_path=log_file)
        flow = MockHTTPFlow(
            request=MockRequest(
                scheme="https", host="registry.npmjs.org", port=443,
                path="/", method="GET",
            ),
            client_conn=MockClientConn(sni="registry.npmjs.org"),
        )

        addon.request(flow)

        entries = _read_log_entries(log_file)
        assert entries[0]["tls_sni"] == "registry.npmjs.org"

    def test_no_sni_for_http(self, sample_policy_file, log_file):
        """HTTP connections should not have tls_sni."""
        addon = _make_addon(sample_policy_file, mode="monitor", log_path=log_file)
        flow = MockHTTPFlow(
            request=MockRequest(
                scheme="http", host="example.com", port=80,
                path="/", method="GET",
            ),
        )

        addon.request(flow)

        entries = _read_log_entries(log_file)
        assert "tls_sni" not in entries[0]

    def test_domain_host_not_replaced_by_sni(self, sample_policy_file, log_file):
        """When host is already a domain, keep it even if SNI differs."""
        addon = _make_addon(sample_policy_file, mode="monitor", log_path=log_file)
        flow = MockHTTPFlow(
            request=MockRequest(
                scheme="https", host="api.github.com", port=443,
                path="/", method="GET",
            ),
            client_conn=MockClientConn(sni="api.github.com"),
        )

        addon.request(flow)

        entries = _read_log_entries(log_file)
        assert entries[0]["host"] == "api.github.com"


# ------------------------------------------------------------------
# Server certificate verification tests
# ------------------------------------------------------------------

class TestCertificateVerification:
    """Tests for upstream server certificate validation."""

    def test_cert_issuer_logged(self, sample_policy_file, log_file):
        """Server cert issuer CN should be logged."""
        addon = _make_addon(sample_policy_file, mode="monitor", log_path=log_file)
        cert = MockCert(cn="api.github.com", issuer_cn="DigiCert SHA2 Extended Validation Server CA")
        flow = MockHTTPFlow(
            request=MockRequest(
                scheme="https", host="api.github.com", port=443,
                path="/", method="GET",
            ),
            client_conn=MockClientConn(sni="api.github.com"),
            server_conn=MockServerConnWithCert(cert=cert),
        )

        addon.request(flow)

        entries = _read_log_entries(log_file)
        assert entries[0].get("tls_cert_issuer") == "DigiCert SHA2 Extended Validation Server CA"

    def test_no_cert_fields_for_http(self, sample_policy_file, log_file):
        """HTTP connections should not have cert fields."""
        addon = _make_addon(sample_policy_file, mode="monitor", log_path=log_file)
        flow = MockHTTPFlow(
            request=MockRequest(
                scheme="http", host="example.com", port=80,
                path="/", method="GET",
            ),
        )

        addon.request(flow)

        entries = _read_log_entries(log_file)
        assert "tls_cert_issuer" not in entries[0]
        assert "tls_cert_valid" not in entries[0]

    def test_no_cert_no_crash(self, sample_policy_file, log_file):
        """If server has no cert, don't crash."""
        addon = _make_addon(sample_policy_file, mode="monitor", log_path=log_file)
        flow = MockHTTPFlow(
            request=MockRequest(
                scheme="https", host="api.github.com", port=443,
                path="/", method="GET",
            ),
            server_conn=MockServerConnWithCert(cert=None),
        )

        addon.request(flow)

        entries = _read_log_entries(log_file)
        assert len(entries) == 1  # Should not crash


# ------------------------------------------------------------------
# Response data tracking tests
# ------------------------------------------------------------------

class TestResponseDataTracking:
    """Tests for the response() handler that captures transfer sizes."""

    def test_response_logs_data_entry(self, sample_policy_file, log_file):
        """Response hook should log a 'data' entry with bytes_transferred."""
        addon = _make_addon(sample_policy_file, mode="monitor", log_path=log_file)
        flow = MockHTTPFlow(
            request=MockRequest(
                scheme="https", host="api.github.com", port=443,
                path="/repos", method="GET", raw_content=b"request-body",
            ),
        )
        flow.response = MockResponse(status_code=200, raw_content=b"x" * 4096)

        addon.response(flow)

        entries = _read_log_entries(log_file)
        assert len(entries) == 1
        assert entries[0]["status"] == "data"
        assert entries[0]["bytes_transferred"] == len(b"request-body") + 4096

    def test_response_no_log_when_empty(self, sample_policy_file, log_file):
        """No data entry when both request and response are empty."""
        addon = _make_addon(sample_policy_file, mode="monitor", log_path=log_file)
        flow = MockHTTPFlow(
            request=MockRequest(
                scheme="https", host="api.github.com", port=443,
                path="/", method="GET", raw_content=b"",
            ),
        )
        flow.response = MockResponse(status_code=200, raw_content=b"")

        addon.response(flow)

        assert not os.path.exists(log_file) or _read_log_entries(log_file) == []

    def test_response_no_log_when_no_response(self, sample_policy_file, log_file):
        """No data entry when response is None."""
        addon = _make_addon(sample_policy_file, mode="monitor", log_path=log_file)
        flow = MockHTTPFlow(
            request=MockRequest(
                scheme="https", host="api.github.com", port=443,
                path="/", method="GET",
            ),
        )
        # flow.response is None by default

        addon.response(flow)

        assert not os.path.exists(log_file) or _read_log_entries(log_file) == []
