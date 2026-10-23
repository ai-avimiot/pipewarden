"""Tests for the actionable 403 body and X-PipeWarden-Block-Reason header."""

import pytest
import yaml

from policy.models import ConnectionEntry
from policy.parser import parse_policy_string
from proxy.addon import NetworkMonitorAddon, _denial
from tests.conftest import (
    MockClientConn,
    MockHeaders,
    MockHTTPFlow,
    MockRequest,
    MockServerConnWithCert,
)
from tests.test_addon import TestEnforceCertGate

SECRET = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"

POLICY = """\
version: "2"
mode: enforce
exfiltration:
  mode: block
  detectors: [env-secrets, patterns]
  watch_env: [MY_TOKEN]
rules:
  - name: "npm"
    allow:
      domains: ["registry.npmjs.org"]
      ports: [443]
      protocols: [https]
"""


def _addon(tmp_path, log_file, mode="enforce"):
    p = tmp_path / "policy.yml"
    p.write_text(POLICY)
    return NetworkMonitorAddon(policy_file=str(p), mode=mode, log_path=log_file)


def _flow(host="evil.example.com", path="/steal", method="POST", **req):
    return MockHTTPFlow(
        MockRequest(scheme="https", host=host, port=443, path=path, method=method, **req),
        client_conn=MockClientConn(sni=host),
    )


def _body(flow) -> str:
    assert flow.response is not None and flow.response.status_code == 403
    return flow.response.content.decode()


def _reason(flow) -> str:
    return flow.response.headers["X-PipeWarden-Block-Reason"]


def _snippet(body: str) -> str:
    return "\n".join(line for line in body.splitlines() if line.startswith("  "))


class TestPolicyMiss:
    def test_body_names_destination_and_reason(self, tmp_path, log_file):
        flow = _flow()
        _addon(tmp_path, log_file).request(flow)
        body = _body(flow)
        assert _reason(flow) == "policy-miss"
        for want in ("evil.example.com", "443", "https", "/steal", "POST", "policy-miss"):
            assert want in body
        assert flow.response.headers["Content-Type"].startswith("text/plain")

    def test_snippet_is_a_valid_rule_allowing_exactly_this_request(self, tmp_path, log_file):
        flow = _flow(path="/a/b?token=hunter2")
        _addon(tmp_path, log_file).request(flow)
        body = _body(flow)
        assert "hunter2" not in body
        policy = 'version: "1"\nmode: enforce\nrules:\n' + _snippet(body) + "\n"
        rule = yaml.safe_load(policy)["rules"][0]["allow"]
        assert rule == {
            "domains": ["evil.example.com"], "ports": [443],
            "protocols": ["https"], "paths": ["/a/b"],
        }
        _, rules = parse_policy_string(policy)
        assert len(rules) == 1

    def test_root_path_and_glob_paths_omit_paths(self, tmp_path, log_file):
        for path in ("/", "/x*y"):
            flow = _flow(path=path)
            _addon(tmp_path, log_file).request(flow)
            assert "paths:" not in _snippet(_body(flow))

    def test_monitor_never_sets_response(self, tmp_path, log_file):
        flow = _flow()
        _addon(tmp_path, log_file, mode="monitor").request(flow)
        assert flow.response is None

    def test_long_path_is_clipped(self, tmp_path, log_file):
        flow = _flow(path="/" + "a" * 5000)
        _addon(tmp_path, log_file).request(flow)
        assert len(flow.response.content) < 2048


class TestSecurityBlocksNeverSuggestWidening:
    def _assert_no_rule(self, flow, kind):
        body = _body(flow)
        assert _reason(flow) == kind
        assert "domains:" not in body
        assert "Do not widen" in body

    def test_exfil(self, tmp_path, log_file, monkeypatch):
        monkeypatch.setenv("MY_TOKEN", SECRET)
        flow = _flow(host="registry.npmjs.org", raw_content=f'{{"t":"{SECRET}"}}'.encode())
        _addon(tmp_path, log_file).request(flow)
        self._assert_no_rule(flow, "exfil")
        assert SECRET not in _body(flow)
        assert "MY_TOKEN" in _body(flow)

    def test_domain_fronting_does_not_echo_host_header(self, tmp_path, log_file):
        flow = _flow(host="registry.npmjs.org",
                     headers=MockHeaders({"Host": "attacker.example"}))
        _addon(tmp_path, log_file).request(flow)
        self._assert_no_rule(flow, "domain-fronting")
        assert "attacker.example" not in _body(flow)

    def test_private_ip(self, tmp_path, log_file):
        flow = MockHTTPFlow(
            MockRequest(scheme="https", host="registry.npmjs.org", port=443,
                        path="/", method="GET"),
            server_conn=MockServerConnWithCert(host="169.254.169.254"),
        )
        _addon(tmp_path, log_file).request(flow)
        self._assert_no_rule(flow, "private-ip")
        assert "cloud metadata" in _body(flow)

    def test_cert_identity(self, tmp_path, log_file):
        gate = TestEnforceCertGate()
        addon = NetworkMonitorAddon(policy_file=gate._policy(tmp_path), mode="enforce",
                                    log_path=log_file)
        flow = gate._flow_with_bad_cert()
        addon.request(flow)
        self._assert_no_rule(flow, "cert-identity")


class TestNoWideningSuggestion:
    def test_method_miss_names_rule_and_suggests_no_rule(self, tmp_path, log_file):
        p = tmp_path / "policy.yml"
        p.write_text(
            'version: "2"\nmode: enforce\nrules:\n'
            '  - name: "npm"\n    allow:\n      domains: ["registry.npmjs.org"]\n'
            '      ports: [443]\n      protocols: [https]\n      access: read-only\n'
        )
        addon = NetworkMonitorAddon(policy_file=str(p), mode="enforce", log_path=log_file)
        flow = _flow(host="registry.npmjs.org", path="/pkg", method="PUT")
        addon.request(flow)
        body = _body(flow)
        assert _reason(flow) == "method"
        assert "method PUT not in methods [GET, HEAD, OPTIONS] of rule 'npm'" in body
        assert _snippet(body) == ""

    @pytest.mark.parametrize("host", ["*", "*.com", "a?.example", "[ab].example"])
    def test_glob_host_gets_no_rule(self, host):
        entry = ConnectionEntry(timestamp="t", protocol="https", host=host, port=443, path="/")
        body = _denial(entry, "policy-miss", "no rule")[0].decode()
        assert "domains:" not in body
        assert "No rule suggested" in body
