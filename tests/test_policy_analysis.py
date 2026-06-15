"""Tests for policy analysis module."""

from policy.models import PolicyRule
from scripts.policy_analysis import analyze_policy, _generate_yaml


class TestAnalyzePolicy:
    def _make_rules(self):
        return [
            PolicyRule(name="npm registry", domains=["registry.npmjs.org", "*.npmjs.org"],
                       ports=[443], protocols=["https"]),
            PolicyRule(name="GitHub", domains=["github.com", "*.github.com"],
                       ports=[443], protocols=["https"]),
            PolicyRule(name="DNS", domains=["*"], ports=[53], protocols=["tcp"]),
        ]

    def test_rule_usage_counts(self):
        rules = self._make_rules()
        connections = [
            {"host": "registry.npmjs.org", "port": 443, "protocol": "https", "status": "allowed"},
            {"host": "registry.npmjs.org", "port": 443, "protocol": "https", "status": "allowed"},
            {"host": "evil.com", "port": 443, "protocol": "https", "status": "would_block"},
        ]
        result = analyze_policy(rules, connections, [])
        usage = {r["name"]: r for r in result["rule_usage"]}
        assert usage["npm registry"]["match_count"] == 2
        assert usage["GitHub"]["match_count"] == 0
        assert usage["DNS"]["match_count"] == 0

    def test_unused_rules(self):
        rules = self._make_rules()
        connections = [
            {"host": "registry.npmjs.org", "port": 443, "protocol": "https", "status": "allowed"},
        ]
        result = analyze_policy(rules, connections, [])
        assert "GitHub" in result["unused_rules"]
        assert "DNS" in result["unused_rules"]
        assert "npm registry" not in result["unused_rules"]

    def test_suggested_rules_for_blocked(self):
        rules = self._make_rules()
        connections = [
            {"host": "evil.com", "port": 443, "protocol": "https", "status": "would_block"},
        ]
        destinations = [
            {"host": "evil.com", "port": 443, "protocol": "https",
             "statuses": {"would_block": 1}, "ip_info": {"owner": "EVIL-AS", "country": "XX"}},
        ]
        result = analyze_policy(rules, connections, destinations)
        assert len(result["suggested_rules"]) == 1
        assert result["suggested_rules"][0]["host"] == "evil.com"
        assert result["suggested_rules"][0]["owner"] == "EVIL-AS"

    def test_suggested_yaml_not_empty_for_blocked(self):
        rules = self._make_rules()
        connections = [
            {"host": "evil.com", "port": 443, "protocol": "https", "status": "would_block"},
        ]
        destinations = [
            {"host": "evil.com", "port": 443, "protocol": "https",
             "statuses": {"would_block": 3}},
        ]
        result = analyze_policy(rules, connections, destinations)
        yaml_str = result["suggested_yaml"]
        assert "evil.com:443" in yaml_str
        assert "domains:" in yaml_str

    def test_no_suggestions_when_all_allowed(self):
        rules = self._make_rules()
        connections = [
            {"host": "registry.npmjs.org", "port": 443, "protocol": "https", "status": "allowed"},
        ]
        destinations = [
            {"host": "registry.npmjs.org", "port": 443, "protocol": "https",
             "statuses": {"allowed": 1}},
        ]
        result = analyze_policy(rules, connections, destinations)
        assert len(result["suggested_rules"]) == 0
        assert result["suggested_yaml"] == ""

    def test_data_entries_skipped_in_rule_matching(self):
        rules = self._make_rules()
        connections = [
            {"host": "registry.npmjs.org", "port": 443, "protocol": "https", "status": "data"},
        ]
        result = analyze_policy(rules, connections, [])
        for ru in result["rule_usage"]:
            assert ru["match_count"] == 0

    def test_matched_hosts_tracked(self):
        rules = self._make_rules()
        connections = [
            {"host": "registry.npmjs.org", "port": 443, "protocol": "https", "status": "allowed"},
            {"host": "www.npmjs.org", "port": 443, "protocol": "https", "status": "allowed"},
        ]
        result = analyze_policy(rules, connections, [])
        usage = {r["name"]: r for r in result["rule_usage"]}
        assert sorted(usage["npm registry"]["matched_hosts"]) == ["registry.npmjs.org", "www.npmjs.org"]

    def test_reverse_dns_in_suggested_rules(self):
        rules = self._make_rules()
        connections = [
            {"host": "185.125.190.81", "port": 80, "protocol": "http", "status": "would_block"},
        ]
        destinations = [
            {"host": "185.125.190.81", "port": 80, "protocol": "http",
             "statuses": {"would_block": 5},
             "reverse_dns": "archive.ubuntu.com",
             "ip_info": {"owner": "CANONICAL-AS", "country": "GB",
                         "prefix": "185.125.188.0/22", "reverse_dns": "archive.ubuntu.com"}},
        ]
        result = analyze_policy(rules, connections, destinations)
        assert result["suggested_rules"][0]["reverse_dns"] == "archive.ubuntu.com"
        assert result["suggested_rules"][0]["prefix"] == "185.125.188.0/22"
        yaml_str = result["suggested_yaml"]
        assert "185.125.188.0/22:80" in yaml_str
        assert "archive.ubuntu.com" in yaml_str


class TestGenerateYaml:
    def test_includes_comments_with_owner_and_date(self):
        suggested = [
            {"host": "cdn.example.com", "port": 443, "protocol": "https",
             "owner": "CLOUDFLARE", "country": "US", "blocked_count": 5},
        ]
        yaml_str = _generate_yaml(suggested)
        assert "CLOUDFLARE, US" in yaml_str
        assert "5x blocked" in yaml_str
        assert "cdn.example.com:443" in yaml_str
        # Date should be present (YYYY-MM-DD format)
        import re
        assert re.search(r"\d{4}-\d{2}-\d{2}", yaml_str)

    def test_domains_and_ips_separate_lists(self):
        suggested = [
            {"host": "a.com", "port": 443, "protocol": "https",
             "owner": "", "country": "", "blocked_count": 2},
            {"host": "1.2.3.4", "port": 80, "protocol": "http",
             "owner": "SOME-AS", "country": "US", "prefix": "1.2.3.0/24",
             "blocked_count": 3},
        ]
        yaml_str = _generate_yaml(suggested)
        assert "domains:" in yaml_str
        assert '"a.com:443"' in yaml_str
        assert "ips:" in yaml_str
        assert '"1.2.3.0/24:80"' in yaml_str

    def test_ip_uses_prefix_with_port(self):
        suggested = [
            {"host": "10.0.0.1", "port": 80, "protocol": "http",
             "owner": "TEST", "country": "US", "prefix": "10.0.0.0/8",
             "blocked_count": 1},
        ]
        yaml_str = _generate_yaml(suggested)
        assert '"10.0.0.0/8:80"' in yaml_str

    def test_ip_falls_back_to_host_with_port(self):
        suggested = [
            {"host": "10.0.0.1", "port": 8080, "protocol": "http",
             "owner": "", "country": "", "blocked_count": 1},
        ]
        yaml_str = _generate_yaml(suggested)
        assert '"10.0.0.1:8080"' in yaml_str

    def test_reverse_dns_in_comment(self):
        suggested = [
            {"host": "185.125.190.81", "port": 80, "protocol": "http",
             "owner": "CANONICAL-AS", "country": "GB",
             "prefix": "185.125.188.0/22",
             "reverse_dns": "archive.ubuntu.com",
             "blocked_count": 9},
        ]
        yaml_str = _generate_yaml(suggested)
        assert "archive.ubuntu.com" in yaml_str
        assert "CANONICAL-AS, GB" in yaml_str
        assert "9x blocked" in yaml_str
        assert "185.125.188.0/22:80" in yaml_str

    def test_empty_input(self):
        assert _generate_yaml([]) == ""

    def test_needed_allowlist_label(self):
        suggested = [
            {"host": "test.com", "port": 80, "protocol": "http",
             "owner": "", "country": "", "blocked_count": 1},
        ]
        yaml_str = _generate_yaml(suggested)
        assert "Needed allowlist" in yaml_str
        assert "domains:" in yaml_str
        assert '"test.com:80"' in yaml_str
