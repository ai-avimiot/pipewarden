"""DNS hardening: enforce-mode AAAA NODATA, tunnel heuristics, no wildcard DNS rule."""

import os
import random
import struct
import sys

import pytest
import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "proxy"))

import dns_server  # noqa: E402

from policy.matcher import PolicyEngine  # noqa: E402
from policy.models import ConnectionEntry  # noqa: E402
from policy.parser import parse_policy_file  # noqa: E402
from scripts.generate_report import (  # noqa: E402
    build_report,
    dns_tunnel_reason,
    format_markdown_summary,
    format_summary,
)

REPO = os.path.join(os.path.dirname(__file__), "..")


def _query(domain: str, qtype: int, txn_id: int = 0xBEEF, edns: bool = False) -> bytes:
    header = struct.pack("!HHHHHH", txn_id, 0x0100, 1, 0, 0, 1 if edns else 0)
    qname = b"".join(bytes([len(x)]) + x.encode() for x in domain.split(".")) + b"\x00"
    opt = b"\x00" + struct.pack("!HHIH", 41, 1232, 0, 0) if edns else b""
    return header + qname + struct.pack("!HH", qtype, 1) + opt


class _Sock:
    def __init__(self):
        self.sent = []

    def sendto(self, data, addr):
        self.sent.append(data)


class _Engine:
    def __init__(self, mode, verdict="allowed"):
        self.mode = mode
        self.verdict = verdict

    def evaluate(self, entry):
        return self.verdict

    def internal_ip_violation(self, entry, ip):
        return ""


def _run(monkeypatch, data, engine, upstream=b"UPSTREAM"):
    forwarded = []
    logged = []

    def fake_forward(d, timeout=3.0):
        forwarded.append(d)
        return upstream

    monkeypatch.setattr(dns_server, "forward_query", fake_forward)
    monkeypatch.setattr(dns_server, "log_dns_query", lambda *a, **k: logged.append(a))
    sock = _Sock()
    dns_server.handle_query(data, ("127.0.0.1", 5300), sock, engine)
    return sock.sent, forwarded, logged


class TestAaaaNodata:
    def test_enforce_allowed_aaaa_gets_nodata_without_forwarding(self, monkeypatch):
        q = _query("registry.npmjs.org", 28)
        sent, forwarded, logged = _run(monkeypatch, q, _Engine("enforce"))

        assert forwarded == []
        assert len(sent) == 1
        resp = sent[0]
        assert resp[:2] == q[:2]
        assert resp[2] & 0x80, "QR must be set"
        assert resp[3] & 0x0F == 0, "NOERROR, not NXDOMAIN"
        qd, an, ns, ar = struct.unpack("!HHHH", resp[4:12])
        assert (qd, an, ns, ar) == (1, 0, 0, 0)
        assert dns_server.parse_dns_query(resp)[1:] == ("registry.npmjs.org", 28)
        assert logged and logged[0][0] == "registry.npmjs.org"
        assert logged[0][3] == "allowed"

    def test_nodata_drops_edns_additional_record(self, monkeypatch):
        q = _query("api.github.com", 28, edns=True)
        sent, _, _ = _run(monkeypatch, q, _Engine("enforce"))
        assert len(sent[0]) == len(q) - 11, "OPT record must not trail a zero ARCOUNT"

    def test_enforce_a_query_still_forwarded(self, monkeypatch):
        q = _query("registry.npmjs.org", 1)
        sent, forwarded, _ = _run(monkeypatch, q, _Engine("enforce"))
        assert forwarded == [q]
        assert sent == [b"UPSTREAM"]

    def test_enforce_blocked_aaaa_still_nxdomain(self, monkeypatch):
        q = _query("evil.example", 28)
        sent, forwarded, _ = _run(monkeypatch, q, _Engine("enforce", "blocked"))
        assert forwarded == []
        assert sent[0][3] & 0x0F == 3

    def test_monitor_aaaa_forwarded_unchanged(self, monkeypatch):
        q = _query("registry.npmjs.org", 28)
        sent, forwarded, _ = _run(monkeypatch, q, _Engine("monitor"))
        assert forwarded == [q]
        assert sent == [b"UPSTREAM"]

    def test_no_policy_aaaa_forwarded(self, monkeypatch):
        q = _query("registry.npmjs.org", 28)
        _, forwarded, _ = _run(monkeypatch, q, None)
        assert forwarded == [q]


class TestTunnelHeuristic:
    def test_ordinary_ci_hosts_not_flagged(self):
        for host in (
            "registry.npmjs.org",
            "github-production-release-asset-2e65be.s3.amazonaws.com",
            "productionresultssa0.blob.core.windows.net",
            "pipelinesghubeus21.actions.githubusercontent.com",
            "objects.githubusercontent.com",
            "_http._tcp.deb.debian.org",
            "a1b2c3d4e5f60718293a4b5c6d7e8f90-1234567890.us-east-1.elb.amazonaws.com",
            "internal-k8s-default-myservice-0123456789abcdef-1234567890.us-east-1.elb.amazonaws.com",
            "my-company-terraform-state-production-eu-west-1.s3.amazonaws.com",
            "3f1b2c4d5e6f7a8b9c0d1e2f3a4b5c6d.dkr.ecr.us-east-1.amazonaws.com",
            "123456789012.dkr.ecr.eu-west-1.amazonaws.com",
            "ec2-54-123-45-67.compute-1.amazonaws.com",
        ):
            assert dns_tunnel_reason(host) == "", host

    def test_long_word_label_not_flagged(self):
        assert dns_tunnel_reason("a" * 60 + ".attacker.example") == ""

    def test_base32_label_flagged(self):
        host = "mzxw6ytboi4dkmrsgezdgnbvgy3tqojq.attacker.example"
        assert "encoded-looking" in dns_tunnel_reason(host)

    @pytest.mark.parametrize("label_len,labels", [(40, 1), (40, 5), (20, 3), (16, 6)])
    def test_hex_tunnel_flagged(self, label_len, labels):
        rng = random.Random(label_len * 10 + labels)
        name = ".".join(
            "".join(rng.choice("0123456789abcdef") for _ in range(label_len))
            for _ in range(labels)
        )
        assert dns_tunnel_reason(name + ".t.evil.example"), name

    def test_base32_in_short_labels_flagged(self):
        rng = random.Random(7)
        name = ".".join(
            "".join(rng.choice("abcdefghijklmnopqrstuvwxyz234567") for _ in range(23))
            for _ in range(3)
        )
        assert dns_tunnel_reason(name + ".t.evil.example")

    def test_short_random_label_not_flagged(self):
        assert dns_tunnel_reason("k3j9x2qv7w.cloudfront.net") == ""


def _dns(host, status="allowed"):
    return {"timestamp": "t", "protocol": "dns", "host": host, "port": 53,
            "method": "A", "status": status}


class TestTunnelReport:
    def test_suspects_counted_and_rendered(self):
        suspect = "mzxw6ytboi4dkmrsgezdgnbvgy3tqojq.attacker.example"
        report = build_report([
            _dns("registry.npmjs.org"),
            _dns(suspect, "would_block"),
            _dns(suspect, "would_block"),
        ])
        dns = report["dns_summary"]
        assert dns["tunnel_suspect_queries"] == 2
        assert [s["host"] for s in dns["tunnel_suspects"]] == [suspect]

        text = format_summary(report)
        assert "Possible DNS tunnelling" in text and suspect in text
        md = format_markdown_summary(report)
        assert "Possible DNS tunnelling" in md and suspect in md
        assert "never blocks" in md

    def test_clean_run_has_no_section(self):
        report = build_report([_dns("registry.npmjs.org")])
        assert report["dns_summary"]["tunnel_suspects"] == []
        assert "tunnelling" not in format_summary(report)
        assert "tunnelling" not in format_markdown_summary(report)

    def test_many_short_chunks_under_one_zone_flagged(self):
        rng = random.Random(3)
        names = [
            "".join(rng.choice("0123456789abcdef") for _ in range(24)) + ".t.evil.example"
            for _ in range(15)
        ]
        assert not any(dns_tunnel_reason(n) for n in names)
        suspects = build_report([_dns(n) for n in names])["dns_summary"]["tunnel_suspects"]
        assert [s["host"] for s in suspects] == ["*.t.evil.example"]
        assert suspects[0]["count"] >= 10

    def test_few_hashed_names_under_one_zone_not_flagged(self):
        rng = random.Random(4)
        names = [
            "".join(rng.choice("0123456789abcdef") for _ in range(32)) + "-1.us-east-1.elb.amazonaws.com"
            for _ in range(3)
        ]
        assert build_report([_dns(n) for n in names])["dns_summary"]["tunnel_suspects"] == []

    def test_heuristic_never_changes_status(self):
        suspect = "mzxw6ytboi4dkmrsgezdgnbvgy3tqojqmzxw6ytb.github.com"
        report = build_report([_dns(suspect)])
        assert report["total_blocked"] == 0
        assert report["dns_summary"]["tunnel_suspects"][0]["status"] == "allowed"


class TestNoWildcardDnsRule:
    def test_example_policy_has_no_catch_all_dns_rule(self):
        with open(os.path.join(REPO, "examples", "network-policy.yml")) as f:
            doc = yaml.safe_load(f)
        for rule in doc["rules"]:
            allow = rule["allow"]
            assert not ("*" in allow.get("domains", []) and 53 in allow.get("ports", [])), rule

    def test_allowed_names_resolve_without_a_dns_rule(self):
        _, rules = parse_policy_file(os.path.join(REPO, "examples", "network-policy.yml"))
        engine = PolicyEngine(rules, mode="enforce")

        def dns(host):
            return engine.evaluate(ConnectionEntry(
                timestamp="t", protocol="dns", host=host, port=53))

        assert dns("registry.npmjs.org") == "allowed"
        assert dns("api.github.com") == "allowed"
        assert dns("stolen-data.attacker.example") == "blocked"
