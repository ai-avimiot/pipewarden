"""Unit tests for policy data models."""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from policy.models import ConnectionEntry, PolicyRule

# --- ConnectionEntry unit tests ---


class TestConnectionEntry:
    def test_to_dict_full(self):
        entry = ConnectionEntry(
            timestamp="2024-01-01T00:00:00Z",
            protocol="https",
            host="example.com",
            port=443,
            path="/api/v1",
            method="GET",
            status="allowed",
            bytes_transferred=1024,
        )
        d = entry.to_dict()
        assert d == {
            "timestamp": "2024-01-01T00:00:00Z",
            "protocol": "https",
            "host": "example.com",
            "port": 443,
            "path": "/api/v1",
            "method": "GET",
            "status": "allowed",
            "bytes_transferred": 1024,
        }

    def test_to_dict_with_tls_fields(self):
        entry = ConnectionEntry(
            timestamp="2024-01-01T00:00:00Z",
            protocol="https",
            host="example.com",
            port=443,
            tls_sni="example.com",
            tls_cert_issuer="DigiCert Inc",
            tls_cert_valid=False,
            tls_cert_error="self-signed certificate",
        )
        d = entry.to_dict()
        assert d["tls_sni"] == "example.com"
        assert d["tls_cert_issuer"] == "DigiCert Inc"
        assert d["tls_cert_valid"] is False
        assert d["tls_cert_error"] == "self-signed certificate"

    def test_to_dict_omits_empty_tls_fields(self):
        """Empty TLS fields should be omitted from the dict."""
        entry = ConnectionEntry(
            timestamp="2024-01-01T00:00:00Z",
            protocol="http",
            host="example.com",
            port=80,
        )
        d = entry.to_dict()
        assert "tls_sni" not in d
        assert "tls_cert_issuer" not in d
        assert "tls_cert_valid" not in d  # True is omitted
        assert "tls_cert_error" not in d

    def test_from_dict_full(self):
        data = {
            "timestamp": "2024-01-01T00:00:00Z",
            "protocol": "tcp",
            "host": "db.internal",
            "port": 5432,
            "path": "",
            "method": "",
            "status": "blocked",
            "bytes_transferred": 256,
        }
        entry = ConnectionEntry.from_dict(data)
        assert entry.timestamp == "2024-01-01T00:00:00Z"
        assert entry.protocol == "tcp"
        assert entry.host == "db.internal"
        assert entry.port == 5432
        assert entry.status == "blocked"
        assert entry.bytes_transferred == 256

    def test_from_dict_defaults(self):
        """Optional fields should default when missing from dict."""
        data = {
            "timestamp": "2024-01-01T00:00:00Z",
            "protocol": "http",
            "host": "example.com",
            "port": 80,
        }
        entry = ConnectionEntry.from_dict(data)
        assert entry.path == ""
        assert entry.method == ""
        assert entry.status == ""
        assert entry.bytes_transferred == 0

    def test_roundtrip(self):
        """to_dict -> from_dict produces an equal object."""
        entry = ConnectionEntry(
            timestamp="2024-06-15T12:30:00Z",
            protocol="https",
            host="registry.npmjs.org",
            port=443,
            path="/package",
            method="GET",
            status="allowed",
            bytes_transferred=2048,
        )
        assert ConnectionEntry.from_dict(entry.to_dict()) == entry

    def test_from_dict_missing_required_raises(self):
        with pytest.raises(KeyError):
            ConnectionEntry.from_dict({"protocol": "http"})


# --- PolicyRule unit tests ---


class TestPolicyRule:
    def test_to_dict(self):
        rule = PolicyRule(
            name="npm registry",
            domains=["registry.npmjs.org", "*.npmjs.org"],
            ports=[443],
            protocols=["https"],
        )
        d = rule.to_dict()
        assert d == {
            "name": "npm registry",
            "domains": ["registry.npmjs.org", "*.npmjs.org"],
            "ports": [443],
            "protocols": ["https"],
            "paths": [],
            "appears": "always",
        }

    def test_from_dict(self):
        data = {
            "name": "GitHub",
            "domains": ["*.github.com"],
            "ports": [443, 80],
            "protocols": ["https", "http"],
        }
        rule = PolicyRule.from_dict(data)
        assert rule.name == "GitHub"
        assert rule.domains == ["*.github.com"]
        assert rule.ports == [443, 80]
        assert rule.protocols == ["https", "http"]

    def test_from_dict_defaults(self):
        """Optional list fields default to empty lists."""
        data = {"name": "minimal"}
        rule = PolicyRule.from_dict(data)
        assert rule.domains == []
        assert rule.ports == []
        assert rule.protocols == []

    def test_roundtrip(self):
        """to_dict -> from_dict produces an equal object."""
        rule = PolicyRule(
            name="DNS",
            domains=["*"],
            ports=[53],
            protocols=["tcp", "udp"],
        )
        assert PolicyRule.from_dict(rule.to_dict()) == rule

    def test_from_dict_missing_name_raises(self):
        with pytest.raises(KeyError):
            PolicyRule.from_dict({"domains": ["example.com"]})


# --- Property-based tests for roundtrip serialization ---


@given(
    timestamp=st.text(min_size=1),
    protocol=st.sampled_from(["http", "https", "tcp"]),
    host=st.text(min_size=1, alphabet=st.characters(whitelist_categories=("L", "N"), whitelist_characters=".-")),
    port=st.integers(min_value=1, max_value=65535),
    path=st.text(),
    method=st.sampled_from(["", "GET", "POST", "PUT", "DELETE", "PATCH"]),
    status=st.sampled_from(["", "allowed", "blocked", "would_block"]),
    bytes_transferred=st.integers(min_value=0, max_value=10**9),
)
def test_connection_entry_roundtrip_property(
    timestamp, protocol, host, port, path, method, status, bytes_transferred
):
    """For any valid ConnectionEntry, to_dict -> from_dict produces an equal object."""
    entry = ConnectionEntry(
        timestamp=timestamp,
        protocol=protocol,
        host=host,
        port=port,
        path=path,
        method=method,
        status=status,
        bytes_transferred=bytes_transferred,
    )
    assert ConnectionEntry.from_dict(entry.to_dict()) == entry


@given(
    name=st.text(min_size=1),
    domains=st.lists(st.text(min_size=1, alphabet=st.characters(whitelist_categories=("L", "N"), whitelist_characters="*.-")), max_size=10),
    ports=st.lists(st.integers(min_value=1, max_value=65535), max_size=10),
    protocols=st.lists(st.sampled_from(["http", "https", "tcp"]), max_size=5),
)
def test_policy_rule_roundtrip_property(name, domains, ports, protocols):
    """For any valid PolicyRule, to_dict -> from_dict produces an equal object."""
    rule = PolicyRule(name=name, domains=domains, ports=ports, protocols=protocols)
    assert PolicyRule.from_dict(rule.to_dict()) == rule
