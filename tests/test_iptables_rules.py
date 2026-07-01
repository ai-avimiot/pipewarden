"""Property-based tests for native-proxy/iptables_rules.py — iptables rule generation.

Feature: native-transparent-proxy
"""

import os
import sys

# Ensure native-proxy is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "native-proxy"))

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from iptables_rules import generate_flush_commands, generate_log_rules, generate_nat_rules

# ------------------------------------------------------------------
# Property 1: NAT rule generation correctness
# ------------------------------------------------------------------
# Validates: Requirements 3.1, 3.2, 10.1, 10.2
#
# For any valid proxy port (1–65535) and any non-empty username string,
# generate_nat_rules(port, username) shall return exactly 2 rules
# (one for port 443, one for port 80), where each rule contains
# -m owner ! --uid-owner <username>, --dport matching the target port
# (80 or 443), and -j REDIRECT --to-port <proxy_port>.
# ------------------------------------------------------------------


@given(
    proxy_port=st.integers(min_value=1, max_value=65535),
    username=st.text(min_size=1, alphabet=st.characters(whitelist_categories=("L", "N"))),
)
@settings(max_examples=100)
def test_p1_nat_rule_generation(proxy_port: int, username: str):
    """Feature: native-transparent-proxy, Property 1: NAT rule generation correctness

    **Validates: Requirements 3.1, 3.2, 10.1, 10.2**
    """
    rules = generate_nat_rules(proxy_port, username)

    # Exactly 2 rules
    assert len(rules) == 2, f"Expected 2 rules, got {len(rules)}"

    # Collect the --dport values from each rule
    dports = set()
    for rule in rules:
        # Each rule contains the uid-owner exclusion
        assert "-m" in rule
        assert "owner" in rule
        assert "!" in rule
        assert "--uid-owner" in rule
        uid_idx = rule.index("--uid-owner")
        assert rule[uid_idx + 1] == username, (
            f"Expected --uid-owner {username}, got {rule[uid_idx + 1]}"
        )

        # Each rule has --dport with 80 or 443
        assert "--dport" in rule
        dport_idx = rule.index("--dport")
        dport_val = rule[dport_idx + 1]
        dports.add(dport_val)

        # Each rule redirects to the proxy port
        assert "-j" in rule
        assert "REDIRECT" in rule
        assert "--to-port" in rule
        to_port_idx = rule.index("--to-port")
        assert rule[to_port_idx + 1] == str(proxy_port), (
            f"Expected --to-port {proxy_port}, got {rule[to_port_idx + 1]}"
        )

    # One rule for port 443, one for port 80
    assert dports == {"443", "80"}, f"Expected dports {{443, 80}}, got {dports}"


# ------------------------------------------------------------------
# Unit Tests for iptables rule generation
# Requirements: 3.3, 4.1, 4.2, 10.3, 10.4
# ------------------------------------------------------------------


class TestGenerateNatRules:
    """Unit tests for generate_nat_rules."""

    def test_default_port(self):
        rules = generate_nat_rules(8080, "mitmproxyuser")
        assert len(rules) == 2
        # First rule: port 443
        assert "--dport" in rules[0]
        assert rules[0][rules[0].index("--dport") + 1] == "443"
        assert "--to-port" in rules[0]
        assert rules[0][rules[0].index("--to-port") + 1] == "8080"
        assert rules[0][rules[0].index("--uid-owner") + 1] == "mitmproxyuser"
        # Second rule: port 80
        assert rules[1][rules[1].index("--dport") + 1] == "80"
        assert rules[1][rules[1].index("--to-port") + 1] == "8080"

    def test_edge_port_1(self):
        rules = generate_nat_rules(1, "proxyuser")
        for rule in rules:
            assert rule[rule.index("--to-port") + 1] == "1"

    def test_edge_port_65535(self):
        rules = generate_nat_rules(65535, "proxyuser")
        for rule in rules:
            assert rule[rule.index("--to-port") + 1] == "65535"

    def test_invalid_port_zero(self):
        with pytest.raises(ValueError):
            generate_nat_rules(0, "user")

    def test_invalid_port_negative(self):
        with pytest.raises(ValueError):
            generate_nat_rules(-1, "user")

    def test_invalid_port_too_high(self):
        with pytest.raises(ValueError):
            generate_nat_rules(65536, "user")

    def test_empty_username(self):
        with pytest.raises(ValueError):
            generate_nat_rules(8080, "")


class TestGenerateLogRules:
    """Unit tests for generate_log_rules."""

    def test_returns_one_rule(self):
        rules = generate_log_rules()
        assert len(rules) == 1

    def test_contains_nfw_prefix(self):
        rules = generate_log_rules()
        rule = rules[0]
        assert "--log-prefix" in rule
        prefix_idx = rule.index("--log-prefix")
        assert rule[prefix_idx + 1] == "NFW-CONN: "

    def test_contains_log_uid(self):
        rules = generate_log_rules()
        assert "--log-uid" in rules[0]

    def test_contains_conntrack_new(self):
        rules = generate_log_rules()
        rule = rules[0]
        assert "-m" in rule
        assert "conntrack" in rule
        assert "--ctstate" in rule
        ctstate_idx = rule.index("--ctstate")
        assert rule[ctstate_idx + 1] == "NEW"


class TestGenerateFlushCommands:
    """Unit tests for generate_flush_commands."""

    def test_returns_three_commands(self):
        cmds = generate_flush_commands(8080, "mitmproxyuser")
        # Two NAT redirect deletions (ports 443 and 80) + one LOG deletion
        assert len(cmds) == 3

    def test_deletes_nat_rule_port_443(self):
        cmds = generate_flush_commands(8080, "mitmproxyuser")
        first = cmds[0]
        assert "-t" in first
        assert "nat" in first
        assert "-D" in first
        assert "OUTPUT" in first
        assert "--dport" in first
        dport_idx = first.index("--dport")
        assert first[dport_idx + 1] == "443"
        assert "--to-port" in first
        to_port_idx = first.index("--to-port")
        assert first[to_port_idx + 1] == "8080"

    def test_deletes_nat_rule_port_80(self):
        cmds = generate_flush_commands(8080, "mitmproxyuser")
        second = cmds[1]
        assert "-t" in second
        assert "nat" in second
        assert "-D" in second
        assert "OUTPUT" in second
        assert "--dport" in second
        dport_idx = second.index("--dport")
        assert second[dport_idx + 1] == "80"

    def test_deletes_log_rule(self):
        cmds = generate_flush_commands(8080, "mitmproxyuser")
        last = cmds[-1]
        assert "-D" in last
        assert "OUTPUT" in last
        assert "--log-prefix" in last
        assert "NFW-CONN: " in last

    def test_does_not_flush_entire_chain(self):
        cmds = generate_flush_commands(8080, "mitmproxyuser")
        for cmd in cmds:
            assert "-F" not in cmd, "flush-all flag must not be used"

    def test_raises_on_invalid_proxy_port(self):
        with pytest.raises(ValueError):
            generate_flush_commands(0, "mitmproxyuser")
        with pytest.raises(ValueError):
            generate_flush_commands(99999, "mitmproxyuser")

    def test_raises_on_empty_username(self):
        with pytest.raises(ValueError):
            generate_flush_commands(8080, "")
