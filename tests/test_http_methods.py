"""HTTP method rules: allow.methods and the access: read-only shorthand."""

import json

import pytest
import yaml

from policy.matcher import PolicyEngine
from policy.models import READ_ONLY_METHODS, ConnectionEntry, PolicyRule
from policy.parser import parse_policy_string
from proxy.addon import NetworkMonitorAddon
from scripts.generate_report import build_report, generate_complete_policy_yaml
from scripts.policy_analysis import _rule_matches
from scripts.resolve_policy import merge_policies
from tests.conftest import MockHTTPFlow, MockRequest


def _policy(allow: str, version: str = "2", mode: str = "enforce") -> str:
    return (
        f'version: "{version}"\nmode: {mode}\nrules:\n'
        f'  - name: "api"\n    allow:\n'
        f'      domains: ["api.example.com"]\n'
        f"{allow}"
    )


def _conn(method="GET", protocol="https", host="api.example.com", port=443):
    return ConnectionEntry(
        timestamp="t", protocol=protocol, host=host, port=port, path="/", method=method,
    )


class TestParser:
    def test_methods_parsed(self):
        _, rules = parse_policy_string(_policy(
            "      protocols: [https]\n      methods: [GET, POST]\n"))
        assert rules[0].methods == ["GET", "POST"]

    def test_access_read_only_expands(self):
        _, rules = parse_policy_string(_policy(
            "      protocols: [https]\n      access: read-only\n"))
        assert rules[0].methods == list(READ_ONLY_METHODS)

    def test_no_methods_means_any(self):
        _, rules = parse_policy_string(_policy("      protocols: [https]\n"))
        assert rules[0].methods == []

    def test_duplicates_collapsed(self):
        _, rules = parse_policy_string(_policy(
            "      protocols: [https]\n      methods: [GET, GET, HEAD]\n"))
        assert rules[0].methods == ["GET", "HEAD"]

    @pytest.mark.parametrize("field", [
        "methods: [GET]", "access: read-only",
    ])
    def test_v1_rejected(self, field):
        with pytest.raises(ValueError, match="requires policy version 2"):
            parse_policy_string(_policy(
                f"      protocols: [https]\n      {field}\n", version="1"))

    def test_methods_and_access_conflict(self):
        with pytest.raises(ValueError, match="either 'methods' or 'access'"):
            parse_policy_string(_policy(
                "      protocols: [https]\n      methods: [GET]\n      access: read-only\n"))

    def test_lowercase_rejected_with_hint(self):
        with pytest.raises(ValueError, match="uppercase"):
            parse_policy_string(_policy("      protocols: [https]\n      methods: [get]\n"))

    def test_unknown_method_rejected(self):
        with pytest.raises(ValueError, match="invalid method 'FETCH'"):
            parse_policy_string(_policy("      protocols: [https]\n      methods: [FETCH]\n"))

    @pytest.mark.parametrize("value", ["[]", "GET", "[1]"])
    def test_malformed_methods_rejected(self, value):
        with pytest.raises(ValueError, match="'methods' must be a non-empty list|strings"):
            parse_policy_string(_policy(
                f"      protocols: [https]\n      methods: {value}\n"))

    def test_unknown_access_rejected(self):
        with pytest.raises(ValueError, match="invalid access 'read-write'"):
            parse_policy_string(_policy(
                "      protocols: [https]\n      access: read-write\n"))

    def test_methods_on_non_http_rule_rejected(self):
        with pytest.raises(ValueError, match="only apply to http/https"):
            parse_policy_string(_policy(
                "      protocols: [tcp]\n      methods: [GET]\n"))


class TestMatcher:
    def _engine(self, methods, protocols=("https",)):
        rule = PolicyRule(name="api", domains=["api.example.com"],
                          protocols=list(protocols), methods=methods)
        return PolicyEngine([rule], mode="enforce")

    def test_listed_method_allowed(self):
        assert self._engine(["GET"]).evaluate(_conn("GET")) == "allowed"

    def test_unlisted_method_blocked(self):
        assert self._engine(["GET"]).evaluate(_conn("POST")) == "blocked"

    def test_method_comparison_is_case_sensitive(self):
        assert self._engine(["GET"]).evaluate(_conn("get")) == "blocked"

    def test_empty_methods_allows_any(self):
        assert self._engine([]).evaluate(_conn("DELETE")) == "allowed"

    def test_tcp_unaffected(self):
        engine = self._engine(["GET"], protocols=("https", "tcp"))
        assert engine.evaluate(_conn("", protocol="tcp")) == "allowed"

    def test_dns_unaffected(self):
        assert self._engine(["GET"]).evaluate(_conn("", protocol="dns", port=53)) == "allowed"

    def test_another_rule_can_allow_the_method(self):
        rules = [
            PolicyRule(name="ro", domains=["api.example.com"], protocols=["https"],
                       methods=["GET"]),
            PolicyRule(name="upload", domains=["api.example.com"], protocols=["https"],
                       methods=["POST"]),
        ]
        engine = PolicyEngine(rules, mode="enforce")
        assert engine.evaluate(_conn("POST")) == "allowed"
        assert engine.evaluate(_conn("PUT")) == "blocked"

    def test_monitor_never_blocks(self):
        rule = PolicyRule(name="api", domains=["api.example.com"], protocols=["https"],
                          methods=["GET"])
        engine = PolicyEngine([rule], mode="monitor")
        assert engine.evaluate(_conn("POST")) == "would_block"

    def test_request_body_opt_out_scoped_to_methods(self):
        rule = PolicyRule(name="api", domains=["api.example.com"], protocols=["https"],
                          methods=["PUT"], allow_request_body=True)
        engine = PolicyEngine([rule], mode="enforce")
        assert engine.allows_request_body(_conn("PUT"))
        assert not engine.allows_request_body(_conn("POST"))

    def test_policy_analysis_matches_by_method(self):
        rule = PolicyRule(name="api", domains=["api.example.com"], protocols=["https"],
                          methods=["GET"])
        assert _rule_matches(rule, _conn("GET"))
        assert not _rule_matches(rule, _conn("POST"))


class TestAddon:
    def _addon(self, tmp_path, mode):
        policy = tmp_path / "policy.yml"
        policy.write_text(_policy(
            "      protocols: [https]\n      access: read-only\n", mode=mode))
        log = tmp_path / "log.jsonl"
        return NetworkMonitorAddon(policy_file=str(policy), mode=mode,
                                   log_path=str(log)), log

    def _send(self, addon, method):
        flow = MockHTTPFlow(MockRequest(
            scheme="https", host="api.example.com", port=443, path="/x", method=method,
        ))
        addon.request(flow)
        return flow

    def test_enforce_blocks_write_method(self, tmp_path):
        addon, log = self._addon(tmp_path, "enforce")
        assert self._send(addon, "GET").response is None
        blocked = self._send(addon, "POST")
        assert blocked.response is not None and blocked.response.status_code == 403
        statuses = [json.loads(line)["status"] for line in log.read_text().splitlines()]
        assert statuses == ["allowed", "blocked"]

    def test_monitor_records_without_blocking(self, tmp_path):
        addon, log = self._addon(tmp_path, "monitor")
        assert self._send(addon, "POST").response is None
        assert json.loads(log.read_text().splitlines()[-1])["status"] == "would_block"


class TestMerge:
    def test_methods_survive_merge_and_force_v2(self, tmp_path):
        common = tmp_path / "common.yml"
        common.write_text(_policy("      protocols: [https]\n      methods: [GET]\n"))
        merged = merge_policies([str(common)], "enforce")
        assert merged["version"] == "2"
        assert merged["rules"][0]["allow"]["methods"] == ["GET"]
        _, rules = parse_policy_string(yaml.safe_dump(merged))
        assert rules[0].methods == ["GET"]


def _log(*entries):
    return [
        {"timestamp": "t", "host": h, "port": p, "protocol": proto, "method": m,
         "path": "/", "status": "allowed"}
        for h, p, proto, m in entries
    ]


class TestGenerator:
    def test_read_only_destination_gets_commented_hint_only(self):
        report = build_report(_log(
            ("ro.example.com", 443, "https", "HEAD"),
            ("ro.example.com", 443, "https", "GET"),
            ("rw.example.com", 443, "https", "GET"),
            ("rw.example.com", 443, "https", "POST"),
        ))
        content = generate_complete_policy_yaml(report)
        doc = yaml.safe_load(content)
        assert doc["version"] == "1"
        assert all("methods" not in r["allow"] and "access" not in r["allow"] for r in doc["rules"])
        ro_block = content.split('name: "ro.example.com"')[1].split("- name:")[0]
        assert "# access: read-only" in ro_block
        rw_block = content.split('name: "rw.example.com"')[1]
        assert "access" not in rw_block

    def test_generated_policy_does_not_block_unseen_writes(self):
        # A cache hit during discovery must not break the cache save that follows a miss.
        log = _log(("ro.example.com", 443, "https", "GET"))
        content = generate_complete_policy_yaml(build_report(log))
        _, rules = parse_policy_string(content)
        engine = PolicyEngine(rules, mode="enforce")
        assert engine.evaluate(_conn("GET", host="ro.example.com")) == "allowed"
        assert engine.evaluate(_conn("PUT", host="ro.example.com")) == "allowed"
        assert engine.evaluate(_conn("HEAD", host="ro.example.com")) == "allowed"

    def test_no_read_only_destination_stays_v1(self):
        report = build_report(_log(
            ("rw.example.com", 443, "https", "POST"),
            ("db.example.com", 5432, "tcp", ""),
        ))
        content = generate_complete_policy_yaml(report)
        assert 'version: "1"' in content
        assert "methods" not in content
        parse_policy_string(content)

    def test_unknown_method_disables_restriction(self):
        report = build_report(_log(
            ("ro.example.com", 443, "https", "GET"),
            ("ro.example.com", 443, "https", ""),
        ))
        assert "methods" not in generate_complete_policy_yaml(report)

    def test_mixed_tcp_and_http_on_same_destination(self):
        report = build_report(_log(
            ("mix.example.com", 443, "tcp", ""),
            ("mix.example.com", 443, "https", "GET"),
        ))
        content = generate_complete_policy_yaml(report)
        assert "methods" not in content
        parse_policy_string(content)
