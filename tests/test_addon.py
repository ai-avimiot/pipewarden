"""Unit tests for the proxy addon (NetworkMonitorAddon)."""

import json
import os
import ssl
from datetime import datetime, timedelta, timezone

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
