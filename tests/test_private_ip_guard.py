"""Tests for the private / metadata destination guard and ``allow.allowed_ips``."""

import asyncio
import json
import os
import struct
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "proxy"))

import dns_server  # noqa: E402

from policy.matcher import PolicyEngine, internal_ip_category  # noqa: E402
from policy.models import ConnectionEntry, PolicyRule  # noqa: E402
from policy.parser import parse_policy_string  # noqa: E402
from proxy import addon as addon_module  # noqa: E402
from proxy.addon import NetworkMonitorAddon  # noqa: E402
from scripts.resolve_policy import merge_policies  # noqa: E402
from tests.conftest import (  # noqa: E402
    MockHTTPFlow,
    MockRequest,
    MockServerConn,
    MockServerConnWithCert,
    MockTCPFlow,
    MockTCPMessage,
)

POLICY_V2 = """\
version: "2"
mode: enforce
rules:
  - name: "internal registry"
    allow:
      domains: ["registry.corp.example"]
      ports: [443]
      protocols: [https]
      allowed_ips: ["10.20.0.0/16"]
  - name: "public api"
    allow:
      domains: ["api.example.com"]
      ports: [443]
      protocols: [https]
  - name: "postgres"
    allow:
      domains: ["db.corp.example"]
      ports: [5432]
      protocols: [tcp]
  - name: "DNS"
    allow:
      domains: ["*"]
      ports: [53]
      protocols: [udp]
"""


def _entry(host, protocol="https", port=443):
    return ConnectionEntry(timestamp="t", protocol=protocol, host=host, port=port)


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


class TestInternalIpCategory:
    @pytest.mark.parametrize("ip,label", [
        ("169.254.169.254", "cloud metadata"),
        ("fd00:ec2::254", "cloud metadata"),
        ("127.0.0.1", "loopback"),
        ("::1", "loopback"),
        ("169.254.1.1", "link-local"),
        ("fe80::1", "link-local"),
        ("fe80::1%eth0", "link-local"),
        ("10.1.2.3", "private"),
        ("172.16.0.1", "private"),
        ("172.31.255.255", "private"),
        ("192.168.1.1", "private"),
        ("100.64.0.1", "CGNAT"),
        ("fd12:3456::1", "unique-local"),
        ("::ffff:10.0.0.1", "private"),
        ("::ffff:169.254.169.254", "cloud metadata"),
        ("0.0.0.0", "unspecified"),
        ("168.63.129.16", "cloud metadata"),
        ("192.0.0.192", "cloud metadata"),
        ("192.0.0.8", "reserved"),
        ("198.18.0.1", "reserved"),
        ("198.19.255.255", "reserved"),
        ("240.0.0.1", "reserved"),
        ("255.255.255.255", "reserved"),
    ])
    def test_internal(self, ip, label):
        assert internal_ip_category(ip) == label

    @pytest.mark.parametrize("ip", [
        "8.8.8.8", "172.32.0.1", "100.128.0.1", "2606:4700::1111",
        "198.20.0.1", "registry.npmjs.org", "",
    ])
    def test_not_internal(self, ip):
        assert internal_ip_category(ip) == ""


class TestCompatibility:
    """Version 1 policies keep their behaviour; a literally named internal host is explicit."""

    LITERALS = """\
version: "{v}"
mode: enforce
rules:
  - name: "local service"
    allow:
      domains: ["localhost", "10.0.0.5"]
      ports: [80]
      protocols: [http]
  - name: "mirror"
    allow:
      domains: ["mirror.corp.example"]
      ports: [443]
      protocols: [https]
"""

    def _engine(self, version):
        _, rules = parse_policy_string(self.LITERALS.format(v=version))
        return PolicyEngine(rules, mode="enforce")

    def test_v1_policy_is_not_guarded(self):
        engine = self._engine("1")
        assert engine.internal_ip_violation(_entry("mirror.corp.example"), "10.9.9.9") == ""
        assert engine.internal_ip_violation(_entry("localhost", "http", 80), "127.0.0.1") == ""
        assert engine.dns_allows_internal_ip("mirror.corp.example", "169.254.169.254")

    @pytest.mark.parametrize("host,ip", [
        ("localhost", "127.0.0.1"),
        ("localhost", "::1"),
        ("10.0.0.5", "10.0.0.5"),
    ])
    def test_v2_literal_internal_name_is_exempt(self, host, ip):
        assert self._engine("2").internal_ip_violation(_entry(host, "http", 80), ip) == ""

    def test_v2_literal_exemption_is_exact(self):
        engine = self._engine("2")
        assert engine.internal_ip_violation(_entry("10.0.0.5", "http", 80), "10.0.0.6")
        assert engine.internal_ip_violation(_entry("localhost", "http", 80), "10.0.0.7")
        assert engine.internal_ip_violation(_entry("mirror.corp.example"), "10.9.9.9")


class TestEngineViolation:
    def setup_method(self):
        _, rules = parse_policy_string(POLICY_V2)
        self.engine = PolicyEngine(rules, mode="enforce")

    def test_public_ip_is_fine(self):
        assert self.engine.internal_ip_violation(_entry("api.example.com"), "93.184.216.34") == ""

    def test_private_ip_without_allowed_ips_is_flagged(self):
        reason = self.engine.internal_ip_violation(_entry("api.example.com"), "10.0.0.5")
        assert "private" in reason and "10.0.0.5" in reason

    def test_metadata_ip_is_flagged(self):
        reason = self.engine.internal_ip_violation(_entry("api.example.com"), "169.254.169.254")
        assert "cloud metadata" in reason

    def test_listed_ip_on_matching_rule_is_exempt(self):
        assert self.engine.internal_ip_violation(_entry("registry.corp.example"), "10.20.3.4") == ""

    def test_listed_ip_outside_cidr_is_flagged(self):
        assert self.engine.internal_ip_violation(_entry("registry.corp.example"), "10.21.0.1")

    def test_exemption_does_not_leak_to_other_rules(self):
        assert self.engine.internal_ip_violation(_entry("api.example.com"), "10.20.3.4")

    def test_exemption_needs_whole_rule_match(self):
        entry = _entry("registry.corp.example", protocol="https", port=8443)
        assert self.engine.internal_ip_violation(entry, "10.20.3.4")

    def test_dns_exemption_is_by_domain(self):
        assert self.engine.dns_allows_internal_ip("registry.corp.example.", "10.20.0.9")
        assert not self.engine.dns_allows_internal_ip("api.example.com", "10.20.0.9")


class TestParser:
    def test_v2_parses_and_canonicalises(self):
        _, rules = parse_policy_string(POLICY_V2.replace('"10.20.0.0/16"', '"10.20.0.0/16", "127.0.0.1"'))
        assert rules[0].allowed_ips == ["10.20.0.0/16", "127.0.0.1/32"]
        assert rules[1].allowed_ips == []

    def test_v1_rejects_allowed_ips(self):
        with pytest.raises(ValueError, match="'allowed_ips' requires policy version 2"):
            parse_policy_string(POLICY_V2.replace('version: "2"', 'version: "1"'))

    @pytest.mark.parametrize("value,match", [
        ('"10.0.0.0/8"', "must be a list"),
        ("[42]", "entries must be IP addresses or CIDRs"),
        ('[""]', "entries must be IP addresses or CIDRs"),
        ('["not-an-ip"]', "invalid IP/CIDR"),
        ('["10.0.0.1/8"]', "invalid IP/CIDR"),
        ('["8.8.8.8"]', "not inside a private"),
        ('["0.0.0.0/0"]', "not inside a private"),
        ('["172.0.0.0/8"]', "not inside a private"),
    ])
    def test_invalid_values(self, value, match):
        bad = POLICY_V2.replace('["10.20.0.0/16"]', value)
        with pytest.raises(ValueError, match=match):
            parse_policy_string(bad)

    def test_resolve_policy_keeps_field_and_bumps_version(self, tmp_path):
        p = tmp_path / "p.yml"
        p.write_text(POLICY_V2)
        merged = merge_policies([str(p)], "enforce")
        assert merged["version"] == "2"
        assert merged["rules"][0]["allow"]["allowed_ips"] == ["10.20.0.0/16"]

    def test_resolve_policy_version_follows_sources(self, tmp_path):
        plain = 'version: "{v}"\nmode: enforce\nrules:\n  - name: a\n    allow:\n      domains: ["a.example"]\n'
        v1, v2 = tmp_path / "v1.yml", tmp_path / "v2.yml"
        v1.write_text(plain.format(v="1"))
        v2.write_text(plain.format(v="2").replace("name: a", "name: b"))
        assert merge_policies([str(v1)], "enforce")["version"] == "1"
        assert merge_policies([str(v2)], "enforce")["version"] == "2"
        # Upgrading would silently guard the v1 rules.
        with pytest.raises(ValueError, match="different versions"):
            merge_policies([str(v1), str(v2)], "enforce")


@pytest.fixture
def policy_v2(tmp_path):
    p = tmp_path / "network-policy.yml"
    p.write_text(POLICY_V2)
    return str(p)


def _https_flow(host, ip):
    return MockHTTPFlow(
        MockRequest(scheme="https", host=host, port=443, path="/", method="GET"),
        server_conn=MockServerConnWithCert(host=ip),
    )


class TestAddonHttp:
    def test_enforce_blocks_allowed_name_on_private_ip(self, policy_v2, log_file):
        addon = NetworkMonitorAddon(policy_file=policy_v2, mode="enforce", log_path=log_file)
        flow = _https_flow("api.example.com", "10.0.0.5")
        addon.request(flow)
        entry = _read(log_file)[0]
        assert entry["status"] == "blocked"
        assert "private" in entry["block_reason"]
        assert flow.response is not None

    def test_enforce_blocks_metadata(self, policy_v2, log_file):
        addon = NetworkMonitorAddon(policy_file=policy_v2, mode="enforce", log_path=log_file)
        addon.request(_https_flow("api.example.com", "169.254.169.254"))
        assert "cloud metadata" in _read(log_file)[0]["block_reason"]

    def test_monitor_flags_would_block_and_passes(self, policy_v2, log_file):
        addon = NetworkMonitorAddon(policy_file=policy_v2, mode="monitor", log_path=log_file)
        flow = _https_flow("api.example.com", "127.0.0.1")
        addon.request(flow)
        entry = _read(log_file)[0]
        assert entry["status"] == "would_block"
        assert "loopback" in entry["block_reason"]
        assert flow.response is None

    def test_allowed_ips_exempts(self, policy_v2, log_file):
        addon = NetworkMonitorAddon(policy_file=policy_v2, mode="enforce", log_path=log_file)
        flow = _https_flow("registry.corp.example", "10.20.1.1")
        addon.request(flow)
        entry = _read(log_file)[0]
        assert entry["status"] == "allowed"
        assert "block_reason" not in entry

    def test_public_ip_unaffected(self, policy_v2, log_file):
        addon = NetworkMonitorAddon(policy_file=policy_v2, mode="enforce", log_path=log_file)
        addon.request(_https_flow("api.example.com", "93.184.216.34"))
        assert _read(log_file)[0]["status"] == "allowed"

    def test_peername_wins_over_hostname_address(self, policy_v2, log_file):
        """Regular mode: address is the hostname; the connected peer is the real destination."""
        addon = NetworkMonitorAddon(policy_file=policy_v2, mode="enforce", log_path=log_file)
        server = MockServerConnWithCert(host="api.example.com")
        server.peername = ("192.168.0.10", 443)
        flow = MockHTTPFlow(
            MockRequest(scheme="https", host="api.example.com", port=443, path="/", method="GET"),
            server_conn=server,
        )
        addon.request(flow)
        assert _read(log_file)[0]["status"] == "blocked"

    def test_unresolved_hostname_is_left_to_policy(self, policy_v2, log_file):
        addon = NetworkMonitorAddon(policy_file=policy_v2, mode="enforce", log_path=log_file)
        addon.request(_https_flow("api.example.com", "api.example.com"))
        assert _read(log_file)[0]["status"] == "allowed"

    def test_disallowed_keeps_its_original_reason(self, policy_v2, log_file):
        addon = NetworkMonitorAddon(policy_file=policy_v2, mode="enforce", log_path=log_file)
        addon.request(_https_flow("evil.example", "10.0.0.5"))
        entry = _read(log_file)[0]
        assert entry["status"] == "blocked"
        assert "block_reason" not in entry


POLICY_V2_HTTP = POLICY_V2 + """\
  - name: "plain http api"
    allow:
      domains: ["plain.example.com"]
      ports: [80]
      protocols: [http]
"""


class _Upstream:
    """A regular-mode upstream before connect: no peername, address set later."""

    def __init__(self, address=None):
        self.address = address
        self.peername = None
        self.error = None


class TestAddonRegularModePlainHttp:
    """Regular mode: the request hook fires before mitmproxy picks an upstream."""

    @pytest.fixture
    def policy(self, tmp_path):
        p = tmp_path / "network-policy.yml"
        p.write_text(POLICY_V2_HTTP)
        return str(p)

    def _run(self, policy, log_file, mode, monkeypatch, ips):
        addon = NetworkMonitorAddon(policy_file=policy, mode=mode, log_path=log_file)

        async def fake_resolve(host, port):
            return list(ips)

        monkeypatch.setattr(addon_module, "_resolve", fake_resolve)
        flow = MockHTTPFlow(
            MockRequest(scheme="http", host="plain.example.com", port=80, path="/", method="GET"),
            server_conn=_Upstream(),
        )
        killed = []
        flow.kill = lambda: killed.append(True)
        addon.request(flow)
        assert _read_or_empty(log_file) == []
        server = _Upstream(address=("plain.example.com", 80))
        asyncio.run(addon.server_connect(SimpleNamespace(server=server, client=flow.client_conn)))
        return addon, flow, server, killed

    def test_enforce_kills_on_private_upstream(self, policy, log_file, monkeypatch):
        _, flow, server, killed = self._run(policy, log_file, "enforce", monkeypatch, ["10.0.0.5"])
        entries = _read(log_file)
        assert len(entries) == 1
        assert entries[0]["status"] == "blocked"
        assert entries[0]["server_ip"] == "10.0.0.5"
        assert "private" in entries[0]["block_reason"]
        assert server.error and killed

    def test_enforce_blocks_when_any_answer_is_metadata(self, policy, log_file, monkeypatch):
        _, _, server, _ = self._run(policy, log_file, "enforce", monkeypatch,
                                    ["93.184.216.34", "169.254.169.254"])
        assert "cloud metadata" in _read(log_file)[0]["block_reason"]
        assert server.error

    def test_monitor_logs_would_block_once_and_passes(self, policy, log_file, monkeypatch):
        addon, flow, server, killed = self._run(policy, log_file, "monitor", monkeypatch, ["127.0.0.1"])
        entries = _read(log_file)
        assert [e["status"] for e in entries] == ["would_block"]
        assert server.error is None and not killed
        addon.response(flow)
        assert len(_read(log_file)) == 1

    def test_public_upstream_is_allowed_and_pinned(self, policy, log_file, monkeypatch):
        _, _, server, killed = self._run(policy, log_file, "enforce", monkeypatch,
                                         ["2606:4700::1", "93.184.216.34"])
        entry = _read(log_file)[0]
        assert entry["status"] == "allowed"
        assert entry["server_ip"] == "93.184.216.34"
        assert server.address == ("93.184.216.34", 80)
        assert server.error is None and not killed

    def test_unresolvable_name_is_left_to_mitmproxy(self, policy, log_file, monkeypatch):
        _, _, server, _ = self._run(policy, log_file, "enforce", monkeypatch, [])
        assert _read(log_file)[0]["status"] == "allowed"
        assert server.address == ("plain.example.com", 80)

    def test_request_hook_block_is_not_logged_again(self, policy, log_file, monkeypatch):
        addon = NetworkMonitorAddon(policy_file=policy, mode="enforce", log_path=log_file)
        flow = MockHTTPFlow(
            MockRequest(scheme="http", host="plain.example.com", port=80, path="/", method="GET"),
            server_conn=_Upstream(address=("10.0.0.5", 80)),
        )
        addon.request(flow)
        server = _Upstream(address=("plain.example.com", 80))
        asyncio.run(addon.server_connect(SimpleNamespace(server=server, client=flow.client_conn)))
        assert [e["status"] for e in _read(log_file)] == ["blocked"]
        assert server.error is None

    def test_deferred_entry_is_logged_on_error(self, policy, log_file):
        addon = NetworkMonitorAddon(policy_file=policy, mode="enforce", log_path=log_file)
        flow = MockHTTPFlow(
            MockRequest(scheme="http", host="plain.example.com", port=80, path="/", method="GET"),
            server_conn=_Upstream(),
        )
        addon.request(flow)
        addon.error(flow)
        assert [e["status"] for e in _read(log_file)] == ["allowed"]

    def test_v1_policy_is_not_deferred(self, tmp_path, log_file):
        p = tmp_path / "v1.yml"
        p.write_text(TestCompatibility.LITERALS.format(v="1"))
        addon = NetworkMonitorAddon(policy_file=str(p), mode="enforce", log_path=log_file)
        flow = MockHTTPFlow(
            MockRequest(scheme="http", host="localhost", port=80, path="/", method="GET"),
            server_conn=_Upstream(),
        )
        addon.request(flow)
        assert [e["status"] for e in _read(log_file)] == ["allowed"]


def _read_or_empty(path):
    return _read(path) if os.path.exists(path) else []


class TestAddonTcp:
    def _flow(self, ip):
        return MockTCPFlow(
            server_conn=MockServerConn(host=ip, port=5432),
            messages=[MockTCPMessage(content=b"SELECT 1")],
        )

    def _addon(self, policy_v2, log_file, mode, monkeypatch, ip):
        addon = NetworkMonitorAddon(policy_file=policy_v2, mode=mode, log_path=log_file)
        monkeypatch.setattr(addon, "_resolve_host_from_dns", lambda _ip: "db.corp.example")
        return addon

    def test_enforce_kills_and_blanks(self, policy_v2, log_file, monkeypatch):
        addon = self._addon(policy_v2, log_file, "enforce", monkeypatch, "10.9.9.9")
        flow = self._flow("10.9.9.9")
        killed = []
        flow.kill = lambda: killed.append(True)
        addon.tcp_start(flow)
        assert killed
        addon.tcp_message(flow)
        entry = _read(log_file)[0]
        assert entry["status"] == "blocked"
        assert entry["server_ip"] == "10.9.9.9"
        assert "private" in entry["block_reason"]
        assert flow.messages[-1].content == b""

    def test_monitor_would_block(self, policy_v2, log_file, monkeypatch):
        addon = self._addon(policy_v2, log_file, "monitor", monkeypatch, "10.9.9.9")
        flow = self._flow("10.9.9.9")
        addon.tcp_message(flow)
        entry = _read(log_file)[0]
        assert entry["status"] == "would_block"
        assert flow.messages[-1].content == b"SELECT 1"

    def test_public_tcp_allowed(self, policy_v2, log_file, monkeypatch):
        addon = self._addon(policy_v2, log_file, "enforce", monkeypatch, "203.0.113.7")
        addon.tcp_message(self._flow("203.0.113.7"))
        assert _read(log_file)[0]["status"] == "allowed"


def _query(name, qtype=1, txn=0x1234):
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", txn, 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", qtype, 1)


def _response(name, a=(), aaaa=(), txn=0x1234):
    import socket
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    out = struct.pack("!HHHHHH", txn, 0x8180, 1, len(a) + len(aaaa), 0, 0)
    out += q + struct.pack("!HH", 1, 1)
    for ip in a:
        out += struct.pack("!HHHIH", 0xC00C, 1, 1, 300, 4) + socket.inet_aton(ip)
    for ip in aaaa:
        out += struct.pack("!HHHIH", 0xC00C, 28, 1, 300, 16) + socket.inet_pton(socket.AF_INET6, ip)
    return out


class _Sock:
    def __init__(self):
        self.sent = []

    def sendto(self, data, addr):
        self.sent.append(data)


class TestDns:
    @pytest.fixture(autouse=True)
    def _isolate(self, monkeypatch):
        self.logged = []
        monkeypatch.setattr(dns_server, "log_dns_query",
                            lambda *a, **k: self.logged.append(a))
        monkeypatch.setattr(dns_server, "ip_to_domain", {})
        monkeypatch.setattr(dns_server, "_map_dirty", type("E", (), {"set": lambda self: None})())

    def _run(self, mode, name, response):
        _, rules = parse_policy_string(POLICY_V2)
        engine = PolicyEngine(rules + [PolicyRule(
            name="any", domains=["*.example.com"], ports=[443], protocols=["https"],
        )], mode=mode)
        sock = _Sock()
        original = dns_server.forward_query
        dns_server.forward_query = lambda data, timeout=3.0: response
        try:
            dns_server.handle_query(_query(name), ("127.0.0.1", 5353), sock, engine)
        finally:
            dns_server.forward_query = original
        return sock.sent[0]

    def test_enforce_refuses_private_answer(self):
        sent = self._run("enforce", "api.example.com", _response("api.example.com", a=["10.0.0.5"]))
        assert sent[3] & 0x0F == 3
        assert self.logged[-1][3] == "blocked"
        assert "private" in self.logged[-1][4]
        assert "10.0.0.5" not in dns_server.ip_to_domain

    def test_enforce_refuses_metadata_aaaa(self):
        resp = _response("api.example.com", a=["93.184.216.34"], aaaa=["fd00:ec2::254"])
        sent = self._run("enforce", "api.example.com", resp)
        assert sent[3] & 0x0F == 3

    def test_enforce_passes_listed_answer(self):
        resp = _response("registry.corp.example", a=["10.20.0.9"])
        sent = self._run("enforce", "registry.corp.example", resp)
        assert sent == resp
        assert self.logged[-1][3] == "allowed"

    def test_enforce_passes_public_answer(self):
        resp = _response("api.example.com", a=["93.184.216.34"])
        assert self._run("enforce", "api.example.com", resp) == resp

    def test_monitor_forwards_and_flags(self):
        resp = _response("api.example.com", a=["169.254.169.254"])
        assert self._run("monitor", "api.example.com", resp) == resp
        assert self.logged[-1][3] == "would_block"
        assert "cloud metadata" in self.logged[-1][4]

    def test_parse_response_aaaa_opt_in(self):
        resp = _response("x.example.com", a=["1.2.3.4"], aaaa=["2606:4700::1111"])
        assert dns_server.parse_dns_response(resp) == ["1.2.3.4"]
        assert dns_server.parse_dns_response(resp, include_aaaa=True) == ["1.2.3.4", "2606:4700::1111"]
