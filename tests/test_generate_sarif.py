"""Tests for SARIF report generation."""

import json
import os

from scripts.generate_sarif import generate_sarif, write_sarif


class TestGenerateSarif:
    def test_empty_report_produces_valid_sarif(self):
        report = {
            "access_summary": {"destinations": [], "tls_cert_warnings": []},
            "dns_summary": {"queries": []},
        }
        sarif = generate_sarif(report)
        assert sarif["version"] == "2.1.0"
        assert sarif["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
        assert len(sarif["runs"]) == 1
        assert sarif["runs"][0]["results"] == []
        assert sarif["runs"][0]["tool"]["driver"]["name"] == "pipewarden"
        assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) == 2

    def test_blocked_connection_creates_result(self):
        report = {
            "access_summary": {
                "destinations": [
                    {
                        "host": "evil.com",
                        "port": 443,
                        "protocol": "https",
                        "statuses": {"blocked": 3},
                    },
                ],
                "tls_cert_warnings": [],
            },
            "dns_summary": {"queries": []},
        }
        sarif = generate_sarif(report)
        results = sarif["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["ruleId"] == "NFW-001"
        assert results[0]["level"] == "error"
        assert "evil.com:443" in results[0]["message"]["text"]
        assert "3x blocked" in results[0]["message"]["text"]

    def test_would_block_connection_creates_result(self):
        report = {
            "access_summary": {
                "destinations": [
                    {
                        "host": "suspicious.io",
                        "port": 8080,
                        "protocol": "http",
                        "statuses": {"would_block": 1},
                    },
                ],
                "tls_cert_warnings": [],
            },
            "dns_summary": {"queries": []},
        }
        sarif = generate_sarif(report)
        results = sarif["runs"][0]["results"]
        assert len(results) == 1
        assert "suspicious.io:8080" in results[0]["message"]["text"]
        assert "would be blocked" in results[0]["message"]["text"]

    def test_allowed_connections_no_results(self):
        report = {
            "access_summary": {
                "destinations": [
                    {
                        "host": "registry.npmjs.org",
                        "port": 443,
                        "protocol": "https",
                        "statuses": {"allowed": 10},
                    },
                ],
                "tls_cert_warnings": [],
            },
            "dns_summary": {"queries": []},
        }
        sarif = generate_sarif(report)
        assert sarif["runs"][0]["results"] == []

    def test_cert_warning_creates_result(self):
        report = {
            "access_summary": {
                "destinations": [],
                "tls_cert_warnings": [
                    {
                        "host": "internal.corp",
                        "port": 443,
                        "tls_cert_error": "self-signed certificate",
                    },
                ],
            },
            "dns_summary": {"queries": []},
        }
        sarif = generate_sarif(report)
        results = sarif["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["ruleId"] == "NFW-002"
        assert results[0]["level"] == "warning"
        assert "self-signed" in results[0]["message"]["text"]

    def test_blocked_dns_creates_result(self):
        report = {
            "access_summary": {"destinations": [], "tls_cert_warnings": []},
            "dns_summary": {
                "queries": [
                    {
                        "host": "malware-c2.example",
                        "count": 2,
                        "status": "blocked",
                    },
                ],
            },
        }
        sarif = generate_sarif(report)
        results = sarif["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["ruleId"] == "NFW-001"
        assert "malware-c2.example" in results[0]["message"]["text"]
        assert "[dns]" in results[0]["message"]["text"]

    def test_allowed_dns_no_result(self):
        report = {
            "access_summary": {"destinations": [], "tls_cert_warnings": []},
            "dns_summary": {
                "queries": [
                    {"host": "ok.com", "count": 5, "status": "allowed"},
                ],
            },
        }
        sarif = generate_sarif(report)
        assert sarif["runs"][0]["results"] == []

    def test_mixed_findings(self):
        report = {
            "access_summary": {
                "destinations": [
                    {"host": "ok.com", "port": 443, "protocol": "https",
                     "statuses": {"allowed": 5}},
                    {"host": "bad.com", "port": 443, "protocol": "https",
                     "statuses": {"blocked": 2}},
                    {"host": "sus.io", "port": 80, "protocol": "http",
                     "statuses": {"would_block": 1, "allowed": 3}},
                ],
                "tls_cert_warnings": [
                    {"host": "self-signed.dev", "port": 443,
                     "tls_cert_error": "untrusted CA"},
                ],
            },
            "dns_summary": {
                "queries": [
                    {"host": "blocked.dns", "count": 1, "status": "would_block"},
                ],
            },
        }
        sarif = generate_sarif(report)
        results = sarif["runs"][0]["results"]
        # bad.com blocked + sus.io would_block + cert warning + dns blocked
        assert len(results) == 4
        rule_ids = [r["ruleId"] for r in results]
        assert rule_ids.count("NFW-001") == 3
        assert rule_ids.count("NFW-002") == 1

    def test_ip_info_included_in_message(self):
        report = {
            "access_summary": {
                "destinations": [
                    {
                        "host": "45.33.32.156",
                        "port": 443,
                        "protocol": "https",
                        "statuses": {"blocked": 1},
                        "ip_info": {"owner": "Linode LLC"},
                    },
                ],
                "tls_cert_warnings": [],
            },
            "dns_summary": {"queries": []},
        }
        sarif = generate_sarif(report)
        msg = sarif["runs"][0]["results"][0]["message"]["text"]
        assert "Linode LLC" in msg

    def test_custom_policy_file(self):
        report = {
            "access_summary": {
                "destinations": [
                    {"host": "x.com", "port": 443, "protocol": "https",
                     "statuses": {"blocked": 1}},
                ],
                "tls_cert_warnings": [],
            },
            "dns_summary": {"queries": []},
        }
        sarif = generate_sarif(report, policy_file="custom-policy.yml")
        loc = sarif["runs"][0]["results"][0]["locations"][0]
        assert loc["physicalLocation"]["artifactLocation"]["uri"] == "custom-policy.yml"

    def test_partial_fingerprints_unique(self):
        report = {
            "access_summary": {
                "destinations": [
                    {"host": "a.com", "port": 443, "protocol": "https",
                     "statuses": {"blocked": 1}},
                    {"host": "b.com", "port": 80, "protocol": "http",
                     "statuses": {"blocked": 1}},
                ],
                "tls_cert_warnings": [],
            },
            "dns_summary": {"queries": []},
        }
        sarif = generate_sarif(report)
        fps = [r["partialFingerprints"]["primaryLocationLineHash"]
               for r in sarif["runs"][0]["results"]]
        assert len(fps) == len(set(fps))


class TestWriteSarif:
    def test_writes_valid_json(self, tmp_path):
        report = {
            "access_summary": {
                "destinations": [
                    {"host": "blocked.com", "port": 443, "protocol": "https",
                     "statuses": {"blocked": 1}},
                ],
                "tls_cert_warnings": [],
            },
            "dns_summary": {"queries": []},
        }
        out = str(tmp_path / "pipewarden.sarif")
        write_sarif(report, out)

        assert os.path.exists(out)
        with open(out) as f:
            sarif = json.load(f)
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"][0]["results"]) == 1

    def test_creates_parent_dirs(self, tmp_path):
        report = {
            "access_summary": {"destinations": [], "tls_cert_warnings": []},
            "dns_summary": {"queries": []},
        }
        out = str(tmp_path / "sub" / "dir" / "pipewarden.sarif")
        write_sarif(report, out)
        assert os.path.exists(out)

    def test_returns_path(self, tmp_path):
        report = {
            "access_summary": {"destinations": [], "tls_cert_warnings": []},
            "dns_summary": {"queries": []},
        }
        out = str(tmp_path / "pipewarden.sarif")
        result = write_sarif(report, out)
        assert result == out
