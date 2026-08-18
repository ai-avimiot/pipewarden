"""Unit tests for the proxy addon (NetworkMonitorAddon)."""

import json
import os
import socket
import ssl
import sys
import time
from datetime import datetime, timedelta, timezone

import pytest

from proxy.addon import (
    NetworkMonitorAddon,
    _cert_dns_names,
    _hostname_matches_cert_names,
    verify_server_cert,
)
from tests.conftest import (
    MockCert,
    MockClientConn,
    MockHTTPFlow,
    MockRequest,
    MockResponse,
    MockServerConn,
    MockServerConnWithCert,
    MockTCPFlow,
    MockTCPMessage,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _self_signed_pem(cn: str = "evil.test", sans: list[str] | None = None) -> bytes:
    """Build a self-signed certificate PEM for tests (no CA, so it's untrusted)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
    )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]),
            critical=False,
        )
    cert = builder.sign(key, hashes.SHA256())
    return cert.public_bytes(Encoding.PEM)

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

class TestQueryStringRedaction:
    """The query string must never reach the log (it can carry credentials)."""

    def test_helper_strips_query_keeps_path(self):
        from proxy.addon import _redact_path
        assert _redact_path("/download?X-Amz-Signature=abc&e=1") == "/download?<redacted>"
        assert _redact_path("/api/v1") == "/api/v1"
        assert _redact_path("/p?a=1#frag") == "/p?<redacted>"
        assert _redact_path("/p#frag") == "/p"
        assert _redact_path("") == ""

    def test_https_request_query_is_redacted(self, sample_policy_file, log_file):
        addon = _make_addon(sample_policy_file, mode="monitor", log_path=log_file)
        secret = "/objects?X-Amz-Signature=DEADBEEF&X-Amz-Credential=AKIA"
        flow = MockHTTPFlow(MockRequest(
            scheme="https", host="api.github.com", port=443, path=secret, method="GET",
        ))

        addon.request(flow)

        entries = _read_log_entries(log_file)
        assert entries[0]["path"] == "/objects?<redacted>"
        # The secret must appear nowhere in the serialized log line.
        raw = open(log_file, encoding="utf-8").read()
        assert "DEADBEEF" not in raw
        assert "AKIA" not in raw


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
# Hostname ↔ certificate name matching (RFC 6125)
# ------------------------------------------------------------------

class TestHostnameMatching:
    """Tests for _hostname_matches_cert_names."""

    def test_exact_match(self):
        assert _hostname_matches_cert_names("api.github.com", ["api.github.com"])

    def test_case_insensitive(self):
        assert _hostname_matches_cert_names("API.GitHub.COM", ["api.github.com"])

    def test_trailing_dot_ignored(self):
        assert _hostname_matches_cert_names("api.github.com.", ["api.github.com"])

    def test_wildcard_matches_one_label(self):
        assert _hostname_matches_cert_names("cdn.example.com", ["*.example.com"])

    def test_wildcard_does_not_match_bare_domain(self):
        assert not _hostname_matches_cert_names("example.com", ["*.example.com"])

    def test_wildcard_matches_only_leftmost_label(self):
        assert not _hostname_matches_cert_names("a.b.example.com", ["*.example.com"])

    def test_no_match_against_other_names(self):
        assert not _hostname_matches_cert_names(
            "evil.com", ["api.github.com", "*.github.com"]
        )

    def test_empty_hostname_never_matches(self):
        assert not _hostname_matches_cert_names("", ["api.github.com"])


# ------------------------------------------------------------------
# verify_server_cert return contract
# ------------------------------------------------------------------

class TestVerifyServerCert:
    """Tests for the tri-state verify_server_cert contract."""

    def test_none_when_trust_store_missing(self):
        status, err = verify_server_cert(b"anything", "example.com", None)
        assert status is None
        assert "trust store" in err.lower()

    def test_none_when_unparseable(self):
        ctx = ssl.create_default_context()
        status, err = verify_server_cert(
            b"-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n",
            "example.com", ctx,
        )
        assert status is None

    def test_false_for_self_signed(self):
        pem = _self_signed_pem(cn="evil.test", sans=["evil.test"])
        ctx = ssl.create_default_context()
        status, err = verify_server_cert(pem, "evil.test", ctx)
        assert status is False
        assert "self-signed" in err.lower()

    def test_cert_dns_names_reads_san(self):
        from cryptography import x509
        pem = _self_signed_pem(cn="cn.test", sans=["a.test", "b.test"])
        cert = x509.load_pem_x509_certificate(pem)
        assert _cert_dns_names(cert) == ["a.test", "b.test"]

    def test_cert_dns_names_falls_back_to_cn(self):
        from cryptography import x509
        pem = _self_signed_pem(cn="only-cn.test", sans=None)
        cert = x509.load_pem_x509_certificate(pem)
        assert _cert_dns_names(cert) == ["only-cn.test"]


# ------------------------------------------------------------------
# Enforce-mode certificate gate (anti spoofed-SNI / MITM)
# ------------------------------------------------------------------

class TestEnforceCertGate:
    """An allowlisted HTTPS host with a definitively invalid upstream cert
    must be blocked in enforce mode and only recorded in monitor mode."""

    _ALLOW_ALL_HTTPS = (
        'version: "1"\n'
        "mode: enforce\n"
        "rules:\n"
        "  - name: all\n"
        "    allow:\n"
        '      domains: ["*"]\n'
        "      ports: [443]\n"
        "      protocols: [https]\n"
    )

    def _policy(self, tmp_path):
        p = tmp_path / "allow-all.yml"
        p.write_text(self._ALLOW_ALL_HTTPS)
        return str(p)

    def _flow_with_bad_cert(self, host="api.github.com"):
        pem = _self_signed_pem(cn=host, sans=[host])
        cert = MockCert(cn=host, issuer_cn=host, pem=pem)
        return MockHTTPFlow(
            request=MockRequest(
                scheme="https", host=host, port=443, path="/", method="GET",
            ),
            client_conn=MockClientConn(sni=host),
            server_conn=MockServerConnWithCert(cert=cert),
        )

    def test_enforce_blocks_allowed_host_with_invalid_cert(self, tmp_path, log_file):
        addon = _make_addon(self._policy(tmp_path), mode="enforce", log_path=log_file)
        flow = self._flow_with_bad_cert()

        addon.request(flow)

        entries = _read_log_entries(log_file)
        assert entries[0]["status"] == "blocked"
        assert entries[0]["tls_cert_valid"] is False
        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_monitor_records_invalid_cert_but_does_not_block(self, tmp_path, log_file):
        addon = _make_addon(self._policy(tmp_path), mode="monitor", log_path=log_file)
        flow = self._flow_with_bad_cert()

        addon.request(flow)

        entries = _read_log_entries(log_file)
        assert entries[0]["status"] == "allowed"
        assert entries[0]["tls_cert_valid"] is False
        assert flow.response is None

    def test_enforce_does_not_block_when_cert_absent(self, tmp_path, log_file):
        """No presented cert => can't verify => must not block a policy-allowed host."""
        addon = _make_addon(self._policy(tmp_path), mode="enforce", log_path=log_file)
        flow = MockHTTPFlow(
            request=MockRequest(
                scheme="https", host="api.github.com", port=443, path="/", method="GET",
            ),
            client_conn=MockClientConn(sni="api.github.com"),
            server_conn=MockServerConnWithCert(cert=None),
        )

        addon.request(flow)

        entries = _read_log_entries(log_file)
        assert entries[0]["status"] == "allowed"
        assert flow.response is None


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


# ------------------------------------------------------------------
# Policy loading: fail-closed and mode precedence
# ------------------------------------------------------------------

class TestPolicyLoadFailure:
    """An invalid policy file must fail closed, never silently allow."""

    def test_invalid_policy_sets_init_error(self, tmp_path, log_file):
        bad = tmp_path / "bad-policy.yml"
        bad.write_text("version: '1'\nmode: bogus\nrules: []\n")
        addon = NetworkMonitorAddon(
            policy_file=str(bad), mode="enforce", log_path=log_file,
        )
        assert addon.init_error is not None
        assert "bad-policy.yml" in addon.init_error

    def test_invalid_policy_blocks_everything_in_enforce(self, tmp_path, log_file):
        bad = tmp_path / "bad-policy.yml"
        bad.write_text("rules: [")  # unparseable YAML
        addon = NetworkMonitorAddon(
            policy_file=str(bad), mode="enforce", log_path=log_file,
        )
        flow = MockHTTPFlow(MockRequest(
            scheme="https", host="api.github.com", port=443, path="/", method="GET",
        ))

        addon.request(flow)

        entries = _read_log_entries(log_file)
        assert entries[0]["status"] == "blocked"
        assert flow.response is not None

    def test_running_hook_is_safe_outside_mitmproxy(self, tmp_path, log_file):
        bad = tmp_path / "bad-policy.yml"
        bad.write_text("rules: [")
        addon = NetworkMonitorAddon(
            policy_file=str(bad), mode="enforce", log_path=log_file,
        )
        # Outside mitmproxy there is no master to shut down; must not raise.
        addon.running()

    def test_valid_policy_has_no_init_error(self, sample_policy_file, log_file):
        addon = _make_addon(sample_policy_file, log_path=log_file)
        assert addon.init_error is None
        addon.running()  # no-op


class TestModePrecedence:
    """Mode: constructor arg > MODE env > policy file mode > monitor."""

    def test_policy_file_mode_used_when_no_arg_or_env(
        self, sample_policy_file, log_file, monkeypatch,
    ):
        monkeypatch.delenv("MODE", raising=False)
        addon = NetworkMonitorAddon(
            policy_file=sample_policy_file, log_path=log_file,
        )
        # The sample policy declares mode: enforce
        assert addon.mode == "enforce"
        assert addon.engine.mode == "enforce"

    def test_env_mode_overrides_policy_file(
        self, sample_policy_file, log_file, monkeypatch,
    ):
        monkeypatch.setenv("MODE", "monitor")
        addon = NetworkMonitorAddon(
            policy_file=sample_policy_file, log_path=log_file,
        )
        assert addon.mode == "monitor"

    def test_arg_overrides_env_and_policy_file(
        self, sample_policy_file, log_file, monkeypatch,
    ):
        monkeypatch.setenv("MODE", "monitor")
        addon = NetworkMonitorAddon(
            policy_file=sample_policy_file, mode="enforce", log_path=log_file,
        )
        assert addon.mode == "enforce"

    def test_defaults_to_monitor_without_policy_or_env(
        self, tmp_path, log_file, monkeypatch,
    ):
        monkeypatch.delenv("MODE", raising=False)
        addon = NetworkMonitorAddon(
            policy_file=str(tmp_path / "missing.yml"), log_path=log_file,
        )
        assert addon.mode == "monitor"
        assert addon.init_error is None  # missing file is discovery, not error


class TestCertVerifyCache:
    """Definitive verification verdicts are cached per cert+hostname."""

    def test_repeat_cert_verified_once(self, sample_policy_file, log_file, monkeypatch):
        import proxy.addon as addon_mod

        calls = {"n": 0}

        def fake_verify(cert_pem, hostname, trust_ctx, chain_pems=None):
            calls["n"] += 1
            return False, "untrusted"

        monkeypatch.setattr(addon_mod, "verify_server_cert", fake_verify)
        addon = _make_addon(sample_policy_file, mode="monitor", log_path=log_file)
        cert = MockCert(issuer_cn="Evil CA")
        conn = MockServerConnWithCert(cert=cert)

        for _ in range(3):
            entry = addon_mod.ConnectionEntry(
                timestamp="t", protocol="https", host="api.github.com", port=443,
            )
            addon._check_server_cert(conn, "api.github.com", entry)
            assert entry.tls_cert_valid is False

        assert calls["n"] == 1

    def test_unverifiable_result_not_cached(self, sample_policy_file, log_file, monkeypatch):
        import proxy.addon as addon_mod

        calls = {"n": 0}

        def fake_verify(cert_pem, hostname, trust_ctx, chain_pems=None):
            calls["n"] += 1
            return None, "transient error"

        monkeypatch.setattr(addon_mod, "verify_server_cert", fake_verify)
        addon = _make_addon(sample_policy_file, mode="monitor", log_path=log_file)
        conn = MockServerConnWithCert(cert=MockCert())

        for _ in range(2):
            entry = addon_mod.ConnectionEntry(
                timestamp="t", protocol="https", host="api.github.com", port=443,
            )
            addon._check_server_cert(conn, "api.github.com", entry)

        assert calls["n"] == 2


class TestPolicyFileResolution:
    """Discovery mode used to kill the addon before it recorded anything.

    setup.sh exports POLICY_FILE="" when no policy is committed. A two-arg
    os.environ.get returns "" for a set-but-empty key rather than the default,
    and Path("") is Path("."), so the parser read_text()'d a directory and
    raised IsADirectoryError past the FileNotFoundError guard.
    """

    def test_empty_policy_file_env_falls_back_to_discovery(
        self, tmp_path, log_file, monkeypatch,
    ):
        monkeypatch.setenv("POLICY_FILE", "")
        monkeypatch.delenv("MODE", raising=False)
        monkeypatch.chdir(tmp_path)

        addon = NetworkMonitorAddon(log_path=log_file)

        assert addon.init_error is None, "discovery mode is not an error"
        assert addon.mode == "monitor"

    def test_unset_policy_file_env_falls_back_to_discovery(
        self, tmp_path, log_file, monkeypatch,
    ):
        monkeypatch.delenv("POLICY_FILE", raising=False)
        monkeypatch.delenv("MODE", raising=False)
        monkeypatch.chdir(tmp_path)

        addon = NetworkMonitorAddon(log_path=log_file)

        assert addon.init_error is None
        assert addon.mode == "monitor"

    def test_directory_as_policy_path_fails_closed(self, tmp_path, log_file):
        """A path that resolves but cannot be read is not "no policy" — the
        caller asked for one, so degrading to discovery would drop enforcement.
        """
        addon = _make_addon(str(tmp_path), log_path=log_file)

        assert addon.init_error is not None
        assert addon.engine.rules == []


class TestExfiltrationDetection:
    """Payload scanning wired into the request path.

    The case that matters is an allowlisted destination: destination-based
    enforcement has already said yes, so if a secret leaves here, only reading
    the payload can catch it.
    """

    SECRET = "supersecretvalue123456"

    def _policy(self, tmp_path, mode="block", extra_rule="", scan_headers=False):
        content = f"""
version: "2"
mode: enforce
exfiltration:
  mode: {mode}
  detectors: [env-secrets, patterns]
  watch_env: [MY_TOKEN]
  scan_headers: {str(scan_headers).lower()}
rules:
  - name: "Allowed host"
    allow:
      domains: ["allowed.example.com"]
      ports: [443]
      protocols: [https]
{extra_rule}
"""
        path = tmp_path / "policy.yml"
        path.write_text(content, encoding="utf-8")
        return str(path)

    def _addon(self, tmp_path, log_file, monkeypatch, **kw):
        monkeypatch.setenv("MY_TOKEN", self.SECRET)
        return NetworkMonitorAddon(
            policy_file=self._policy(tmp_path, **kw),
            mode="enforce",
            log_path=log_file,
        )

    def _post(self, body: bytes, host="allowed.example.com"):
        return MockHTTPFlow(
            request=MockRequest(
                scheme="https", host=host, port=443,
                path="/upload", method="POST", raw_content=body,
            )
        )

    def test_secret_to_allowlisted_host_is_blocked(
        self, tmp_path, log_file, monkeypatch,
    ):
        addon = self._addon(tmp_path, log_file, monkeypatch)
        flow = self._post(f'{{"data":"{self.SECRET}"}}'.encode())

        addon.request(flow)

        assert flow.response is not None, "expected the request to be blocked"
        entry = _read_log_entries(log_file)[0]
        assert entry["status"] == "blocked"
        assert entry["exfil_findings"][0]["label"] == "MY_TOKEN"

    def test_clean_request_to_same_host_passes(
        self, tmp_path, log_file, monkeypatch,
    ):
        addon = self._addon(tmp_path, log_file, monkeypatch)
        flow = self._post(b'{"data":"nothing interesting"}')

        addon.request(flow)

        assert flow.response is None
        entry = _read_log_entries(log_file)[0]
        assert entry["status"] == "allowed"
        assert "exfil_findings" not in entry

    def test_warn_mode_records_but_does_not_block(
        self, tmp_path, log_file, monkeypatch,
    ):
        addon = self._addon(tmp_path, log_file, monkeypatch, mode="warn")
        flow = self._post(f'{{"data":"{self.SECRET}"}}'.encode())

        addon.request(flow)

        assert flow.response is None, "warn mode must not block"
        entry = _read_log_entries(log_file)[0]
        assert entry["status"] == "allowed"
        assert entry["exfil_findings"][0]["label"] == "MY_TOKEN"

    def test_off_by_default_for_v1_policies(self, tmp_path, log_file, monkeypatch):
        monkeypatch.setenv("MY_TOKEN", self.SECRET)
        path = tmp_path / "v1.yml"
        path.write_text(
            'version: "1"\nmode: enforce\nrules:\n'
            '  - name: "Allowed host"\n    allow:\n'
            '      domains: ["allowed.example.com"]\n'
            "      ports: [443]\n      protocols: [https]\n",
            encoding="utf-8",
        )
        addon = NetworkMonitorAddon(
            policy_file=str(path), mode="enforce", log_path=log_file
        )
        flow = self._post(f'{{"data":"{self.SECRET}"}}'.encode())

        addon.request(flow)

        assert flow.response is None
        assert "exfil_findings" not in _read_log_entries(log_file)[0]

    def test_per_rule_opt_out_skips_scanning(
        self, tmp_path, log_file, monkeypatch,
    ):
        extra = """  - name: "Secrets manager"
    allow_request_body: true
    allow:
      domains: ["vault.example.com"]
      ports: [443]
      protocols: [https]
"""
        addon = self._addon(tmp_path, log_file, monkeypatch, extra_rule=extra)
        flow = self._post(
            f'{{"data":"{self.SECRET}"}}'.encode(), host="vault.example.com"
        )

        addon.request(flow)

        assert flow.response is None
        assert "exfil_findings" not in _read_log_entries(log_file)[0]

    def test_secret_in_query_string_is_caught(
        self, tmp_path, log_file, monkeypatch,
    ):
        """_redact_path strips the query before logging, so this is the only
        place it can still be examined."""
        addon = self._addon(tmp_path, log_file, monkeypatch)
        flow = MockHTTPFlow(
            request=MockRequest(
                scheme="https", host="allowed.example.com", port=443,
                path=f"/x?token={self.SECRET}", method="GET",
            )
        )

        addon.request(flow)

        entry = _read_log_entries(log_file)[0]
        assert entry["status"] == "blocked"
        assert entry["exfil_findings"][0]["label"] == "MY_TOKEN"

    def test_secret_in_header_is_caught_when_opted_in(
        self, tmp_path, log_file, monkeypatch,
    ):
        addon = self._addon(tmp_path, log_file, monkeypatch, scan_headers=True)
        flow = MockHTTPFlow(
            request=MockRequest(
                scheme="https", host="allowed.example.com", port=443,
                path="/x", method="GET",
                headers={"X-Custom-Auth": self.SECRET},
            )
        )

        addon.request(flow)

        assert _read_log_entries(log_file)[0]["status"] == "blocked"

    def test_known_token_shape_caught_without_env_watch(
        self, tmp_path, log_file, monkeypatch,
    ):
        addon = self._addon(tmp_path, log_file, monkeypatch)
        pat = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
        flow = self._post(f'{{"t":"{pat}"}}'.encode())

        addon.request(flow)

        entry = _read_log_entries(log_file)[0]
        assert entry["status"] == "blocked"
        assert entry["exfil_findings"][0]["label"] == "github-pat"

    def test_log_never_contains_the_secret(
        self, tmp_path, log_file, monkeypatch,
    ):
        """connections.jsonl is uploaded as a build artifact. A detector that
        recorded its match would publish the credential more conveniently than
        the exfiltration attempt it caught."""
        addon = self._addon(tmp_path, log_file, monkeypatch)
        addon.request(self._post(f'{{"data":"{self.SECRET}"}}'.encode()))

        raw = open(log_file, encoding="utf-8").read()
        assert self.SECRET not in raw
        assert "MY_TOKEN" in raw  # the label names the source, not the value

    def test_monitor_mode_never_blocks_on_findings(
        self, tmp_path, log_file, monkeypatch,
    ):
        """Monitor mode is a promise not to interfere; a finding must not
        become the one thing that breaks the build."""
        monkeypatch.setenv("MY_TOKEN", self.SECRET)
        addon = NetworkMonitorAddon(
            policy_file=self._policy(tmp_path),
            mode="monitor",
            log_path=log_file,
        )
        flow = self._post(f'{{"data":"{self.SECRET}"}}'.encode())

        addon.request(flow)

        assert flow.response is None

    def test_auth_header_to_allowlisted_host_passes_by_default(
        self, tmp_path, log_file, monkeypatch,
    ):
        """A credential sent to the service it belongs to is authentication,
        not exfiltration. Scanning headers by default 403'd every
        `Authorization: Bearer` to an allowlisted host — plain gh/git/upload
        traffic — under the documented recommended config."""
        addon = self._addon(tmp_path, log_file, monkeypatch)
        flow = MockHTTPFlow(
            request=MockRequest(
                scheme="https", host="allowed.example.com", port=443,
                path="/repos", method="GET",
                headers={"Authorization": f"Bearer {self.SECRET}"},
            )
        )

        addon.request(flow)

        assert flow.response is None
        entry = _read_log_entries(log_file)[0]
        assert entry["status"] == "allowed"
        assert "exfil_findings" not in entry

    def test_pattern_shaped_auth_header_also_passes_by_default(
        self, tmp_path, log_file, monkeypatch,
    ):
        addon = self._addon(tmp_path, log_file, monkeypatch)
        ghs = "ghs_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
        flow = MockHTTPFlow(
            request=MockRequest(
                scheme="https", host="allowed.example.com", port=443,
                path="/", method="GET",
                headers={"Authorization": f"Bearer {ghs}"},
            )
        )

        addon.request(flow)

        assert flow.response is None

    def test_body_is_still_scanned_with_headers_off(
        self, tmp_path, log_file, monkeypatch,
    ):
        """Turning headers off must not soften the body path — the body is
        the exfiltration carrier that matters."""
        addon = self._addon(tmp_path, log_file, monkeypatch)
        flow = self._post(f'{{"data":"{self.SECRET}"}}'.encode())

        addon.request(flow)

        assert _read_log_entries(log_file)[0]["status"] == "blocked"

    def test_opt_out_survives_a_broader_rule_listed_first(
        self, tmp_path, log_file, monkeypatch,
    ):
        """Policies routinely put a wildcard rule ahead of the specific one.
        First-match semantics made allow_request_body silently inert in
        exactly that ordinary layout."""
        extra = """  - name: "Everything on example.com"
    allow:
      domains: ["*.example.com"]
      ports: [443]
      protocols: [https]
  - name: "Secrets manager"
    allow_request_body: true
    allow:
      domains: ["vault.example.com"]
      ports: [443]
      protocols: [https]
"""
        addon = self._addon(tmp_path, log_file, monkeypatch, extra_rule=extra)
        flow = self._post(
            f'{{"data":"{self.SECRET}"}}'.encode(), host="vault.example.com"
        )

        addon.request(flow)

        assert flow.response is None, (
            "allow_request_body must hold whichever matching rule carries it"
        )
        assert "exfil_findings" not in _read_log_entries(log_file)[0]

    def test_v1_policy_with_exfiltration_block_fails_closed(
        self, tmp_path, log_file, monkeypatch,
    ):
        """The author wrote the block expecting payload scanning; running
        green without it is the outcome the refusal exists to prevent."""
        monkeypatch.setenv("MY_TOKEN", self.SECRET)
        path = tmp_path / "v1-exfil.yml"
        path.write_text(
            'version: "1"\nmode: enforce\nexfiltration:\n  mode: block\n'
            "rules: []\n",
            encoding="utf-8",
        )
        addon = NetworkMonitorAddon(
            policy_file=str(path), mode="enforce", log_path=log_file
        )
        assert addon.init_error is not None
        assert "version 2" in addon.init_error


# ------------------------------------------------------------------
# Client / process attribution
# ------------------------------------------------------------------

class TestAttribution:
    """Who made the connection — see policy/attribution.py.

    The User-Agent tier is readable only because PipeWarden terminates TLS, so
    these assertions cover a capability a passive network monitor cannot have.
    """

    def test_user_agent_is_recorded(self, sample_policy_file, log_file):
        addon = _make_addon(sample_policy_file, log_path=log_file)
        flow = MockHTTPFlow(MockRequest(
            scheme="https", host="api.github.com", port=443, path="/repos",
            headers={"User-Agent": "npm/10.2.4 node/v20.11.0 linux x64"},
        ))

        addon.request(flow)

        entry = _read_log_entries(log_file)[0]
        assert entry["attribution"]["client"] == "npm/10.2.4"
        assert entry["attribution"]["source"] == "user-agent"

    def test_absent_user_agent_leaves_no_key(self, sample_policy_file, log_file):
        """An empty attribution must not cost a key on every connection."""
        addon = _make_addon(sample_policy_file, log_path=log_file)
        addon.request(MockHTTPFlow(MockRequest(
            scheme="https", host="api.github.com", port=443, path="/repos",
        )))
        assert "attribution" not in _read_log_entries(log_file)[0]

    def test_blocked_request_is_still_attributed(self, sample_policy_file, log_file):
        """The blocked connection is the one whose author matters most."""
        addon = _make_addon(sample_policy_file, mode="enforce", log_path=log_file)
        addon.request(MockHTTPFlow(MockRequest(
            scheme="https", host="evil.example.com", port=443, path="/",
            headers={"User-Agent": "curl/8.5.0"},
        )))
        entry = _read_log_entries(log_file)[0]
        assert entry["status"] == "blocked"
        assert entry["attribution"]["client"] == "curl/8.5.0"

    def test_header_lookup_is_case_insensitive_when_headers_are(
        self, sample_policy_file, log_file,
    ):
        addon = _make_addon(sample_policy_file, log_path=log_file)
        addon.request(MockHTTPFlow(MockRequest(
            scheme="https", host="api.github.com", port=443, path="/repos",
            headers={"user-agent": "pip/24.0"},
        )))
        entry = _read_log_entries(log_file)[0]
        assert entry.get("attribution", {}).get("client") == "pip/24.0"

    def test_hostile_user_agent_cannot_break_out_of_a_report_cell(
        self, sample_policy_file, log_file,
    ):
        """A User-Agent is whatever the client typed, and it reaches Markdown."""
        addon = _make_addon(sample_policy_file, log_path=log_file)
        addon.request(MockHTTPFlow(MockRequest(
            scheme="https", host="api.github.com", port=443, path="/repos",
            headers={"User-Agent": "evil|`<script>`|x [link](http://x)"},
        )))
        client = _read_log_entries(log_file)[0].get("attribution", {}).get("client", "")
        for char in "<>|`[]()":
            assert char not in client

    def test_mode_off_records_nothing(self, sample_policy_file, log_file, monkeypatch):
        monkeypatch.setenv("ATTRIBUTION_MODE", "off")
        addon = _make_addon(sample_policy_file, log_path=log_file)
        addon.request(MockHTTPFlow(MockRequest(
            scheme="https", host="api.github.com", port=443, path="/repos",
            headers={"User-Agent": "npm/10.2.4"},
        )))
        assert "attribution" not in _read_log_entries(log_file)[0]

    def test_process_mode_without_a_socket_falls_back_to_client(
        self, sample_policy_file, log_file, monkeypatch,
    ):
        """Losing process detail must not lose the free tier with it."""
        monkeypatch.setenv("ATTRIBUTION_MODE", "process")
        monkeypatch.delenv("ATTRIBUTION_SOCKET", raising=False)
        addon = _make_addon(sample_policy_file, log_path=log_file)
        assert addon.attribution_cfg.mode == "client"

        addon.request(MockHTTPFlow(MockRequest(
            scheme="https", host="api.github.com", port=443, path="/repos",
            headers={"User-Agent": "npm/10.2.4"},
        )))
        assert _read_log_entries(log_file)[0]["attribution"]["client"] == "npm/10.2.4"

    def test_unreachable_helper_does_not_break_the_request(
        self, sample_policy_file, log_file, monkeypatch, tmp_path,
    ):
        """Attribution is diagnostics; egress control must survive its loss."""
        monkeypatch.setenv("ATTRIBUTION_MODE", "process")
        monkeypatch.setenv("ATTRIBUTION_SOCKET", str(tmp_path / "absent.sock"))
        addon = _make_addon(sample_policy_file, log_path=log_file)

        for _ in range(3):
            addon.request(MockHTTPFlow(MockRequest(
                scheme="https", host="api.github.com", port=443, path="/repos",
                headers={"User-Agent": "npm/10.2.4"},
            )))

        entries = _read_log_entries(log_file)
        assert len(entries) == 3
        assert all(e["status"] == "allowed" for e in entries)
        assert all(e["attribution"]["client"] == "npm/10.2.4" for e in entries)

    def test_tcp_flow_is_attributed(self, sample_policy_file, log_file):
        """Raw TCP is where process attribution earns its keep: nothing else
        in the entry says what made the connection."""
        addon = _make_addon(sample_policy_file, log_path=log_file)
        addon.tcp_message(MockTCPFlow())
        # No User-Agent exists for raw TCP, so this stays absent without a helper.
        assert "attribution" not in _read_log_entries(log_file)[0]

class TestAttributionAgainstALiveHelper:
    """The addon and the helper, running together over a real unix socket.

    Every other test stops at one side of this seam: the helper is exercised
    against its own sockets and the addon against the ``User-Agent`` header. The
    one bug that made process attribution return nothing at all lived precisely
    here — in what the addon asks for versus what the helper is willing to
    answer — and neither side's tests could see it.

    Linux only: the lookup reads the kernel socket table through ``/proc``.
    """

    @staticmethod
    def _start_helper(tmp_path):
        import subprocess
        import time

        sock = str(tmp_path / "helper.sock")
        proc = subprocess.Popen(
            [sys.executable,
             os.path.join(REPO_ROOT, "scripts", "attribution_helper.py"),
             "--socket", sock, "--no-audit"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            if os.path.exists(sock):
                return proc, sock
            time.sleep(0.05)
        proc.terminate()
        pytest.skip("helper did not come up")

    @pytest.fixture
    def live_helper(self, tmp_path, monkeypatch):
        if not os.path.exists("/proc/net/tcp"):
            pytest.skip("needs a real /proc socket table")
        proc, sock = self._start_helper(tmp_path)
        monkeypatch.setenv("ATTRIBUTION_MODE", "process")
        monkeypatch.setenv("ATTRIBUTION_SOCKET", sock)
        try:
            yield sock
        finally:
            proc.terminate()
            proc.wait(timeout=10)

    @staticmethod
    def _connected_port():
        """A live client socket, so the helper has a row in /proc to find."""
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        cli = socket.socket()
        cli.connect(srv.getsockname())
        return cli, srv, cli.getsockname()[1]

    def test_the_helper_names_the_process_behind_a_request(
            self, live_helper, sample_policy_file, log_file):
        addon = _make_addon(sample_policy_file, mode="monitor", log_path=log_file)
        assert addon.attribution_cfg.mode == "process"
        cli, srv, port = self._connected_port()
        try:
            addon.request(MockHTTPFlow(
                MockRequest(scheme="https", host="api.github.com", port=443,
                            path="/repos", headers={"User-Agent": "curl/8.5.0"}),
                client_conn=MockClientConn(peername=("127.0.0.1", port)),
            ))
        finally:
            cli.close()
            srv.close()
        att = _read_log_entries(log_file)[0]["attribution"]
        assert att["source"] == "proc"
        assert att["pid"] == os.getpid()
        # The kernel answer joins the self-reported one rather than replacing
        # it: which tool it claims to be is worth keeping next to what it is.
        assert att["client"] == "curl/8.5.0"

    def test_raw_tcp_is_named_when_nothing_else_can_name_it(
            self, live_helper, sample_policy_file, log_file):
        """No User-Agent exists here, so this is the privileged tier alone."""
        addon = _make_addon(sample_policy_file, mode="monitor", log_path=log_file)
        cli, srv, port = self._connected_port()
        flow = MockTCPFlow()
        flow.client_conn = MockClientConn(peername=("127.0.0.1", port))
        try:
            addon.tcp_message(flow)
        finally:
            cli.close()
            srv.close()
        att = _read_log_entries(log_file)[0]["attribution"]
        assert att["pid"] == os.getpid()
        assert att["source"] == "proc"

    def test_a_port_nobody_owns_falls_back_instead_of_failing(
            self, live_helper, sample_policy_file, log_file):
        """A client that exited before the lookup is routine, not a failure.

        Counting it as one would make the addon give up on a helper that is
        working perfectly, on nothing worse than a short-lived curl.
        """
        addon = _make_addon(sample_policy_file, mode="monitor", log_path=log_file)
        addon.request(MockHTTPFlow(
            MockRequest(scheme="https", host="api.github.com", port=443,
                        path="/x", headers={"User-Agent": "npm/10.2.4"}),
            client_conn=MockClientConn(peername=("127.0.0.1", 1)),
        ))
        att = _read_log_entries(log_file)[0]["attribution"]
        assert att["client"] == "npm/10.2.4"
        assert att["source"] == "user-agent"
        assert addon._attribution_failures == 0

    def test_a_helper_that_dies_degrades_instead_of_stalling_the_job(
            self, tmp_path, monkeypatch, sample_policy_file, log_file):
        """Attribution is reporting; losing it must not cost traffic or time."""
        if not os.path.exists("/proc/net/tcp"):
            pytest.skip("needs a real /proc socket table")
        proc, sock = self._start_helper(tmp_path)
        proc.terminate()
        proc.wait(timeout=10)
        monkeypatch.setenv("ATTRIBUTION_MODE", "process")
        monkeypatch.setenv("ATTRIBUTION_SOCKET", sock)

        addon = _make_addon(sample_policy_file, mode="monitor", log_path=log_file)
        started = time.monotonic()
        for i in range(12):
            addon.request(MockHTTPFlow(
                MockRequest(scheme="https", host="api.github.com", port=443,
                            path=f"/{i}", headers={"User-Agent": "curl/8.5.0"}),
                # Distinct ports: an unanswered port is cached like any other,
                # so repeating one would never reach the give-up threshold.
                client_conn=MockClientConn(peername=("127.0.0.1", 40000 + i)),
            ))
        assert time.monotonic() - started < 10
        assert addon._attribution_failures >= 5

        entries = _read_log_entries(log_file)
        assert len(entries) == 12
        assert all(e["status"] == "allowed" for e in entries)
        assert all(e["attribution"]["client"] == "curl/8.5.0" for e in entries)
