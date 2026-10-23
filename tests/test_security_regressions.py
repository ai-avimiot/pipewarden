"""Regression tests for the v2.2.0 security audit findings.

Each test pins one bypass that was reproduced against v2.1.2: if it fails, the
corresponding hole is open again.
"""

import base64
import json
import ssl
import struct
from datetime import datetime, timedelta, timezone

import pytest

from policy.exfil import ExfilConfig, WatchedSecret, _encodings, scan
from policy.matcher import PolicyEngine
from policy.models import ConnectionEntry, PolicyRule
from proxy.addon import verify_server_cert
from proxy.dns_server import handle_query
from scripts.generate_report import generate_complete_policy_yaml, read_jsonl_counted
from scripts.policy_analysis import _generate_yaml
from tests.conftest import (
    MockClientConn,
    MockHeaders,
    MockHTTPFlow,
    MockRequest,
    MockServerConn,
    MockTCPFlow,
    MockTCPMessage,
)
from tests.test_addon import _make_addon, _read_log_entries

# ------------------------------------------------------------------
# Raw TCP on an intercepted port
# ------------------------------------------------------------------

class _KillableTCPFlow(MockTCPFlow):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.killed = False

    def kill(self):
        self.killed = True


class TestRawTcpIsKilledInEnforce:
    def test_blocked_flow_killed_before_first_byte(self, sample_policy_file, log_file):
        addon = _make_addon(sample_policy_file, mode="enforce", log_path=log_file)
        flow = _KillableTCPFlow(server_conn=MockServerConn("203.0.113.9", 443))
        addon.tcp_start(flow)
        assert flow.killed

    def test_blocked_message_is_blanked(self, sample_policy_file, log_file):
        addon = _make_addon(sample_policy_file, mode="enforce", log_path=log_file)
        msg = MockTCPMessage(b"SECRET_TOKEN=ghp_exfil")
        flow = _KillableTCPFlow(server_conn=MockServerConn("203.0.113.9", 443), messages=[msg])
        addon.tcp_message(flow)
        assert msg.content == b""
        assert _read_log_entries(log_file)[0]["status"] == "blocked"

    def test_monitor_mode_relays(self, sample_policy_file, log_file):
        addon = _make_addon(sample_policy_file, mode="monitor", log_path=log_file)
        flow = _KillableTCPFlow(server_conn=MockServerConn("203.0.113.9", 443))
        addon.tcp_start(flow)
        assert not flow.killed


# ------------------------------------------------------------------
# Upstream certificate checks
# ------------------------------------------------------------------

def _ca_and_leaf(sans=None, ip_sans=None, eku=None):
    """A throwaway CA plus a leaf it signed, with the CA as the only trust root."""
    import ipaddress

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID

    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Root")])
    ca = (
        x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
        .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    key = ec.generate_private_key(ec.SECP256R1())
    builder = (
        x509.CertificateBuilder().subject_name(x509.Name([])).issuer_name(ca_name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
    )
    names = [x509.DNSName(s) for s in sans or []]
    names += [x509.IPAddress(ipaddress.ip_address(i)) for i in ip_sans or []]
    if names:
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
    if eku is not None:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    leaf = builder.sign(ca_key, hashes.SHA256())
    return leaf.public_bytes(Encoding.PEM), ca.public_bytes(Encoding.PEM)


class TestCertIdentity:
    @pytest.fixture(autouse=True)
    def trust_only(self, monkeypatch):
        """Make *ca_pem* the sole trust root for verify_server_cert."""
        from OpenSSL import crypto

        import proxy.addon as addon_mod

        def install(ca_pem):
            store = crypto.X509Store()
            store.add_cert(crypto.load_certificate(crypto.FILETYPE_PEM, ca_pem))
            monkeypatch.setattr(addon_mod, "_x509_store", store)
            return ssl.create_default_context()

        self.trust = install

    def test_ip_only_cert_cannot_vouch_for_a_hostname(self):
        pem, ca = _ca_and_leaf(ip_sans=["198.51.100.7"])
        ctx = self.trust(ca)
        ok, err = verify_server_cert(pem, "github.com", ctx)
        assert ok is False
        assert "github.com" in err

    def test_client_auth_only_cert_rejected(self):
        from cryptography.x509.oid import ExtendedKeyUsageOID

        pem, ca = _ca_and_leaf(sans=["github.com"], eku=[ExtendedKeyUsageOID.CLIENT_AUTH])
        ctx = self.trust(ca)
        ok, _ = verify_server_cert(pem, "github.com", ctx)
        assert ok is False

    def test_matching_server_cert_still_passes(self):
        from cryptography.x509.oid import ExtendedKeyUsageOID

        pem, ca = _ca_and_leaf(sans=["github.com"], eku=[ExtendedKeyUsageOID.SERVER_AUTH])
        ctx = self.trust(ca)
        assert verify_server_cert(pem, "github.com", ctx) == (True, "")


# ------------------------------------------------------------------
# Domain fronting
# ------------------------------------------------------------------

class TestHostHeaderFronting:
    def _flow(self, host_header):
        req = MockRequest(scheme="https", host="registry.npmjs.org", port=443,
                          headers=MockHeaders({"Host": host_header}))
        return MockHTTPFlow(req, client_conn=MockClientConn(sni="registry.npmjs.org"))

    def test_disallowed_host_header_blocked(self, sample_policy_file, log_file):
        addon = _make_addon(sample_policy_file, mode="enforce", log_path=log_file)
        flow = self._flow("attacker.example")
        addon.request(flow)
        assert flow.response is not None and flow.response.status_code == 403
        assert "attacker.example" in _read_log_entries(log_file)[0]["block_reason"]

    def test_matching_host_header_with_port_allowed(self, sample_policy_file, log_file):
        addon = _make_addon(sample_policy_file, mode="enforce", log_path=log_file)
        flow = self._flow("registry.npmjs.org:443")
        addon.request(flow)
        assert flow.response is None


# ------------------------------------------------------------------
# Payload scanning evasions
# ------------------------------------------------------------------

SECRET = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"


def _found(payload: bytes) -> bool:
    watch = [WatchedSecret(label="GH_TOKEN", variants=_encodings(SECRET))]
    return bool(scan(payload, watch, ExfilConfig(), b"salt"))


class TestExfilEncodings:
    @pytest.mark.parametrize("prefix", [b"", b"x", b"xy", b"HOME=/root\nPATH=/usr/bin\n"])
    def test_secret_inside_larger_base64_blob(self, prefix):
        blob = base64.b64encode(prefix + b"GH_TOKEN=" + SECRET.encode() + b"\nEND=1\n")
        assert _found(b"data=" + blob)

    def test_uppercase_hex(self):
        assert _found(SECRET.encode().hex().upper().encode())

    def test_json_unicode_escape(self):
        escaped = SECRET.replace("_", "\\u005f").encode()
        assert _found(json.dumps({"t": "x"}).encode() + escaped)


# ------------------------------------------------------------------
# Path rules
# ------------------------------------------------------------------

class TestPathTraversal:
    @pytest.fixture
    def engine(self):
        rule = PolicyRule(name="org", domains=["github.com"], ports=[443],
                          protocols=["https"], paths=["/myorg/*"])
        return PolicyEngine([rule], mode="enforce")

    @pytest.mark.parametrize("path", [
        "/myorg/../attacker/repo",
        "/myorg/%2e%2e/attacker/repo",
        "/myorg/..%2fattacker",
        "/myorg\\..\\attacker",
    ])
    def test_escape_is_not_matched(self, engine, path):
        entry = ConnectionEntry(timestamp="", protocol="https", host="github.com",
                                port=443, path=path, method="GET")
        assert engine.evaluate(entry) == "blocked"

    def test_plain_path_still_matches(self, engine):
        entry = ConnectionEntry(timestamp="", protocol="https", host="github.com",
                                port=443, path="/myorg/repo", method="GET")
        assert engine.evaluate(entry) == "allowed"


# ------------------------------------------------------------------
# Report integrity
# ------------------------------------------------------------------

class TestReportIntegrity:
    def test_malformed_lines_are_counted_not_fatal(self, tmp_path):
        log = tmp_path / "connections.jsonl"
        log.write_text(
            json.dumps({"host": "evil.test", "port": 443, "status": "blocked"}) + "\n"
            "not json\n"
            + json.dumps({"host": ["x"], "port": "443"}) + "\n"
        )
        conns, malformed = read_jsonl_counted(str(log))
        assert len(conns) == 1
        assert malformed == 2

    def test_generated_policy_drops_injected_host(self):
        injected = 'x.test"]\n  - name: "telemetry"\n    allow:\n      domains: ["*'
        report = {"access_summary": {"destinations": [
            {"host": injected, "port": 443, "protocol": "https"},
            {"host": "registry.npmjs.org", "port": 443, "protocol": "https",
             "ip_info": {"owner": "Fastly\n  - name: evil"}},
        ]}}
        import yaml

        doc = yaml.safe_load(generate_complete_policy_yaml(report))
        domains = [d for r in doc["rules"] for d in r["allow"]["domains"]]
        assert domains == ["registry.npmjs.org"]

    def test_suggested_yaml_drops_injected_host(self):
        out = _generate_yaml([
            {"host": 'a.test"\n- "*', "port": 443},
            {"host": "ok.test", "port": 443, "reverse_dns": "r\nips:\n  - \"0.0.0.0/0"},
        ])
        assert '"*' not in out
        assert "0.0.0.0/0" not in out.split("#")[0]
        assert out.count("\n  - ") == 1


# ------------------------------------------------------------------
# DNS parser robustness
# ------------------------------------------------------------------

class _Sock:
    def __init__(self):
        self.sent = []

    def sendto(self, data, addr):
        self.sent.append(data)


def test_truncated_compression_pointer_gets_formerr():
    header = struct.pack("!HHHHHH", 0xBEEF, 0x0100, 1, 0, 0, 0)
    sock = _Sock()
    handle_query(header + b"\xc0", ("127.0.0.1", 5353), sock)
    assert sock.sent and sock.sent[0][:2] == b"\xbe\xef"
    assert sock.sent[0][3] & 0x0F == 1
