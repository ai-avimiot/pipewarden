"""Per-rule ``tls: passthrough``: parsing, matching, and the addon's relay decision."""

import json
import os
import ssl
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from policy.matcher import PolicyEngine  # noqa: E402
from policy.models import ConnectionEntry  # noqa: E402
from policy.parser import parse_policy_string  # noqa: E402
from proxy import addon as addon_module  # noqa: E402
from proxy.addon import NetworkMonitorAddon  # noqa: E402
from scripts.policy_boundary import dimension_gaps  # noqa: E402
from scripts.resolve_policy import _rule_to_yaml  # noqa: E402
from tests.conftest import MockServerConn, MockTCPMessage  # noqa: E402

pytest.importorskip("mitmproxy")

AGENT = "hosted-compute-request-orchestrator-gccus02-01.githubapp.com"
AGENT_IP = "140.82.113.21"

POLICY = """
version: "2"
mode: enforce
rules:
  - name: runner-agent
    tls: passthrough
    allow:
      domains: ["hosted-compute-*.githubapp.com"]
      ports: [443]
      protocols: [https]
  - name: github
    allow:
      domains: ["api.github.com"]
      ports: [443]
      protocols: [https]
"""


def _rules(extra: str, version: str = "2"):
    return parse_policy_string(
        f'version: "{version}"\nmode: enforce\nrules:\n  - name: r\n{extra}'
    )[1]


class TestParser:
    def test_default_is_intercept(self):
        assert _rules("    allow: {domains: [a.example], protocols: [https]}\n")[0].tls == "intercept"

    def test_passthrough(self):
        rules = parse_policy_string(POLICY)[1]
        assert [r.tls for r in rules] == ["passthrough", "intercept"]

    @pytest.mark.parametrize("extra, message", [
        ("    tls: decrypt\n    allow: {domains: [a.example], protocols: [https]}\n", "must be one of"),
        ("    tls: passthrough\n    allow: {domains: [a.example], protocols: [tcp]}\n", "'https'"),
        ("    tls: passthrough\n    allow: {domains: ['*'], protocols: [https]}\n", "bare wildcard"),
        ("    tls: passthrough\n    allow: {domains: [], protocols: [https]}\n", "named domains"),
        ("    tls: passthrough\n    allow: {domains: [a.example], protocols: [https], paths: [/x]}\n", "'paths'"),
        ("    tls: passthrough\n    allow: {domains: [a.example], protocols: [https], methods: [GET]}\n", "'methods'"),
        ("    tls: passthrough\n    allow_request_body: true\n    allow: {domains: [a.example], protocols: [https]}\n",
         "'allow_request_body'"),
    ])
    def test_rejected(self, extra, message):
        with pytest.raises(ValueError, match=message):
            _rules(extra)

    def test_needs_version_2(self):
        with pytest.raises(ValueError, match="version 2"):
            _rules("    tls: passthrough\n    allow: {domains: [a.example], protocols: [https]}\n", "1")

    def test_survives_policy_merge(self):
        assert _rule_to_yaml(parse_policy_string(POLICY)[1][0])["tls"] == "passthrough"
        assert "tls" not in _rule_to_yaml(parse_policy_string(POLICY)[1][1])

    def test_boundary_reports_passthrough_as_broader(self):
        passthrough, intercept = parse_policy_string(POLICY)[1]
        intercept.domains = passthrough.domains
        assert any("tls: passthrough" in g for g in dimension_gaps(passthrough, intercept))
        assert not any("tls" in g for g in dimension_gaps(intercept, passthrough))


class TestEngine:
    def test_passthrough_rule(self):
        engine = PolicyEngine(parse_policy_string(POLICY)[1])
        hit = ConnectionEntry(timestamp="", protocol="https", host=AGENT, port=443)
        assert engine.passthrough_rule(hit).name == "runner-agent"
        for host, port in (("api.github.com", 443), (AGENT, 8443)):
            entry = ConnectionEntry(timestamp="", protocol="https", host=host, port=port)
            assert engine.passthrough_rule(entry) is None


def _client_hello(sni: str) -> bytes:
    ctx = ssl.create_default_context()
    out = ssl.MemoryBIO()
    tls = ctx.wrap_bio(ssl.MemoryBIO(), out, server_hostname=sni)
    with pytest.raises(ssl.SSLWantReadError):
        tls.do_handshake()
    return out.read()


def _nextlayer(sni, dest, client_id="c1"):
    context = SimpleNamespace(
        client=SimpleNamespace(transport_protocol="tcp", tls_established=False, id=client_id),
        server=SimpleNamespace(address=(dest, 443)),
        layers=[],
        options=SimpleNamespace(),
    )
    hello = _client_hello(sni)
    return SimpleNamespace(layer=None, context=context, data_client=lambda: hello)


@pytest.fixture
def addon(tmp_path, log_file):
    path = tmp_path / "policy.yml"
    path.write_text(POLICY)
    a = NetworkMonitorAddon(policy_file=str(path), mode="enforce", log_path=log_file)
    a._resolve_host_from_dns = lambda ip: AGENT if ip == AGENT_IP else ""
    return a


def _read(path):
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


class TestAddon:
    def test_allowed_sni_becomes_raw_tcp(self, addon):
        from mitmproxy.proxy.layers import TCPLayer
        nl = _nextlayer(AGENT, AGENT_IP)
        addon.next_layer(nl)
        assert isinstance(nl.layer, TCPLayer)

    @pytest.mark.parametrize("sni", ["api.github.com", "evil.example"])
    def test_other_hosts_stay_intercepted(self, addon, sni):
        nl = _nextlayer(sni, AGENT_IP)
        addon.next_layer(nl)
        assert nl.layer is None

    def test_connect_host_must_equal_sni(self, addon):
        nl = _nextlayer(AGENT, "evil.example")
        addon.next_layer(nl)
        assert nl.layer is None

    def test_existing_layer_untouched(self, addon):
        nl = _nextlayer(AGENT, AGENT_IP)
        nl.layer = sentinel = object()
        addon.next_layer(nl)
        assert nl.layer is sentinel

    def test_relayed_bytes_are_logged_as_passthrough(self, addon, log_file):
        nl = _nextlayer(AGENT, AGENT_IP)
        addon.next_layer(nl)
        flow = SimpleNamespace(
            client_conn=nl.context.client,
            server_conn=MockServerConn(host=AGENT_IP, port=443),
            messages=[MockTCPMessage(content=b"x" * 517)],
            kill=lambda: pytest.fail("passthrough flow was killed"),
        )
        addon.tcp_start(flow)
        addon.tcp_message(flow)
        [entry] = _read(log_file)
        assert entry["status"] == "passthrough"
        assert entry["host"] == AGENT and entry["tls_sni"] == AGENT
        assert entry["server_ip"] == AGENT_IP and entry["bytes_transferred"] == 517
        addon.tcp_end(flow)
        assert not addon._passthrough

    def test_borrowed_sni_to_another_address_is_intercepted(self, addon):
        nl = _nextlayer(AGENT, "203.0.113.9")
        addon.next_layer(nl)
        assert nl.layer is None and not addon._passthrough

    def test_shared_ip_binds_any_name_it_was_resolved_for(self, tmp_path, monkeypatch):
        from mitmproxy.proxy.layers import TCPLayer
        map_path = tmp_path / "dns_ip_map.json"
        map_path.write_text(json.dumps({AGENT_IP: "api.githubapp.com"}))
        (tmp_path / "dns_ip_map.json.names").write_text(
            json.dumps({AGENT_IP: [AGENT, "api.githubapp.com"]}))
        monkeypatch.setattr(addon_module, "DNS_IP_MAP_PATH", str(map_path))
        policy = tmp_path / "policy.yml"
        policy.write_text(POLICY)
        a = NetworkMonitorAddon(policy_file=str(policy), mode="enforce",
                                log_path=str(tmp_path / "c.jsonl"))
        nl = _nextlayer(AGENT, AGENT_IP)
        a.next_layer(nl)
        assert isinstance(nl.layer, TCPLayer)

    def test_no_passthrough_rules_never_touches_layers(self, tmp_path, log_file):
        path = tmp_path / "policy.yml"
        path.write_text(POLICY.replace("    tls: passthrough\n", ""))
        a = NetworkMonitorAddon(policy_file=str(path), mode="enforce", log_path=log_file)
        nl = _nextlayer(AGENT, AGENT_IP)
        a.next_layer(nl)
        assert nl.layer is None
