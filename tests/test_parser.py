"""Unit and property tests for policy parser."""


import pytest
import yaml
from hypothesis import given, settings, strategies as st

from policy.models import PolicyRule
from policy.parser import parse_policy_file, parse_policy_string


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

VALID_POLICY_YAML = """\
version: "1"
mode: enforce
rules:
  - name: "npm registry"
    allow:
      domains:
        - "registry.npmjs.org"
        - "*.npmjs.org"
      ports: [443]
      protocols: [https]
  - name: "GitHub"
    allow:
      domains:
        - "*.github.com"
      ports: [443, 80]
      protocols: [https, http]
"""

MONITOR_POLICY_YAML = """\
version: "1"
mode: monitor
rules:
  - name: "DNS"
    allow:
      domains: ["*"]
      ports: [53]
      protocols: [tcp, udp]
"""


# ---------------------------------------------------------------------------
# Unit tests — parse_policy_string
# ---------------------------------------------------------------------------


class TestParsePolicyString:
    def test_valid_enforce_policy(self):
        mode, rules = parse_policy_string(VALID_POLICY_YAML)
        assert mode == "enforce"
        assert len(rules) == 2
        assert rules[0].name == "npm registry"
        assert rules[0].domains == ["registry.npmjs.org", "*.npmjs.org"]
        assert rules[0].ports == [443]
        assert rules[0].protocols == ["https"]
        assert rules[1].name == "GitHub"

    def test_valid_monitor_policy(self):
        mode, rules = parse_policy_string(MONITOR_POLICY_YAML)
        assert mode == "monitor"
        assert len(rules) == 1
        assert rules[0].name == "DNS"
        assert rules[0].protocols == ["tcp", "udp"]

    def test_empty_rules_list(self):
        content = 'version: "1"\nmode: monitor\nrules: []\n'
        mode, rules = parse_policy_string(content)
        assert mode == "monitor"
        assert rules == []

    def test_rule_with_defaults(self):
        content = 'version: "1"\nmode: monitor\nrules:\n  - name: "minimal"\n'
        mode, rules = parse_policy_string(content)
        assert rules[0].domains == []
        assert rules[0].ports == []
        assert rules[0].protocols == []

    # --- Validation errors ---

    def test_missing_version(self):
        with pytest.raises(ValueError, match="Missing required field: 'version'"):
            parse_policy_string("mode: monitor\nrules: []\n")

    def test_unsupported_version(self):
        with pytest.raises(ValueError, match="Unsupported policy version"):
            parse_policy_string('version: "2"\nmode: monitor\nrules: []\n')

    def test_missing_mode(self):
        with pytest.raises(ValueError, match="Missing required field: 'mode'"):
            parse_policy_string('version: "1"\nrules: []\n')

    def test_invalid_mode(self):
        with pytest.raises(ValueError, match="Invalid mode"):
            parse_policy_string('version: "1"\nmode: block\nrules: []\n')

    def test_missing_rules(self):
        with pytest.raises(ValueError, match="Missing required field: 'rules'"):
            parse_policy_string('version: "1"\nmode: monitor\n')

    def test_rules_not_a_list(self):
        with pytest.raises(ValueError, match="'rules' must be a list"):
            parse_policy_string('version: "1"\nmode: monitor\nrules: "bad"\n')

    def test_rule_missing_name(self):
        content = 'version: "1"\nmode: monitor\nrules:\n  - allow:\n      domains: ["x"]\n'
        with pytest.raises(ValueError, match="missing required field 'name'"):
            parse_policy_string(content)

    def test_invalid_port(self):
        content = (
            'version: "1"\nmode: monitor\nrules:\n'
            '  - name: "bad"\n    allow:\n      ports: [99999]\n'
        )
        with pytest.raises(ValueError, match="invalid port"):
            parse_policy_string(content)

    def test_invalid_protocol(self):
        content = (
            'version: "1"\nmode: monitor\nrules:\n'
            '  - name: "bad"\n    allow:\n      protocols: [ftp]\n'
        )
        with pytest.raises(ValueError, match="invalid protocol"):
            parse_policy_string(content)

    def test_non_string_domain_rejected(self):
        content = (
            'version: "1"\nmode: monitor\nrules:\n'
            '  - name: "bad"\n    allow:\n      domains: [123]\n'
        )
        with pytest.raises(ValueError, match="domain patterns must be non-empty"):
            parse_policy_string(content)

    def test_empty_string_domain_rejected(self):
        content = (
            'version: "1"\nmode: monitor\nrules:\n'
            '  - name: "bad"\n    allow:\n      domains: [""]\n'
        )
        with pytest.raises(ValueError, match="domain patterns must be non-empty"):
            parse_policy_string(content)

    def test_non_string_name_rejected(self):
        content = 'version: "1"\nmode: monitor\nrules:\n  - name: 123\n    allow: {}\n'
        with pytest.raises(ValueError, match="'name' must be a string"):
            parse_policy_string(content)

    def test_duplicate_rule_name_rejected(self):
        content = (
            'version: "1"\nmode: monitor\nrules:\n'
            '  - name: "dup"\n    allow:\n      domains: ["a.com"]\n'
            '  - name: "dup"\n    allow:\n      domains: ["b.com"]\n'
        )
        with pytest.raises(ValueError, match="duplicate rule name"):
            parse_policy_string(content)

    def test_invalid_yaml(self):
        with pytest.raises(ValueError, match="Invalid YAML"):
            parse_policy_string(":\n  :\n  - [invalid")

    def test_non_mapping_top_level(self):
        with pytest.raises(ValueError, match="YAML mapping"):
            parse_policy_string("- item1\n- item2\n")

    def test_returns_policy_rule_instances(self):
        _, rules = parse_policy_string(VALID_POLICY_YAML)
        for rule in rules:
            assert isinstance(rule, PolicyRule)


# ---------------------------------------------------------------------------
# Unit tests — parse_policy_file
# ---------------------------------------------------------------------------


class TestParsePolicyFile:
    def test_reads_file(self, tmp_path):
        policy_file = tmp_path / "network-policy.yml"
        policy_file.write_text(VALID_POLICY_YAML)
        mode, rules = parse_policy_file(str(policy_file))
        assert mode == "enforce"
        assert len(rules) == 2

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError, match="Policy file not found"):
            parse_policy_file("/nonexistent/path/policy.yml")

    def test_invalid_content_in_file(self, tmp_path):
        policy_file = tmp_path / "bad.yml"
        policy_file.write_text("not_valid: true\n")
        with pytest.raises(ValueError):
            parse_policy_file(str(policy_file))


# ---------------------------------------------------------------------------
# Property test P4 — Policy Parsing Roundtrip
# **Validates: Requirements 3.1**
# ---------------------------------------------------------------------------

# Strategies for generating valid policy components
_domain_char = st.characters(whitelist_categories=("L", "N"), whitelist_characters=".-")
_domain_st = st.text(min_size=1, max_size=30, alphabet=_domain_char)
_wildcard_domain_st = st.one_of(
    _domain_st,
    _domain_st.map(lambda d: f"*.{d}"),
    st.just("*"),
)
_port_st = st.integers(min_value=1, max_value=65535)
_protocol_st = st.sampled_from(["http", "https", "tcp", "udp", "dns"])
_mode_st = st.sampled_from(["monitor", "enforce"])

_rule_st = st.fixed_dictionaries(
    {
        "name": st.text(min_size=1, max_size=50, alphabet=st.characters(whitelist_categories=("L", "N", "Z"), whitelist_characters="-_ ")),
        "allow": st.fixed_dictionaries(
            {
                "domains": st.lists(_wildcard_domain_st, min_size=0, max_size=5),
                "ports": st.lists(_port_st, min_size=0, max_size=5),
                "protocols": st.lists(_protocol_st, min_size=0, max_size=4, unique=True),
            }
        ),
    }
)

_policy_st = st.fixed_dictionaries(
    {
        "version": st.just("1"),
        "mode": _mode_st,
        # Rule names must be unique within a policy (enforced by the parser).
        "rules": st.lists(
            _rule_st, min_size=0, max_size=5, unique_by=lambda r: r["name"]
        ),
    }
)


@given(policy=_policy_st)
@settings(max_examples=200)
def test_policy_parsing_roundtrip_p4(policy):
    """P4: For any valid policy config, parsing YAML and converting back
    produces an equivalent structure.

    **Validates: Requirements 3.1**
    """
    yaml_str = yaml.dump(policy, default_flow_style=False)
    mode, rules = parse_policy_string(yaml_str)

    # Mode must match
    assert mode == policy["mode"]

    # Number of rules must match
    assert len(rules) == len(policy["rules"])

    # Each rule must match the original dict
    for rule, raw in zip(rules, policy["rules"]):
        assert rule.name == raw["name"]
        assert rule.domains == raw["allow"]["domains"]
        assert rule.ports == raw["allow"]["ports"]
        assert rule.protocols == raw["allow"]["protocols"]

        # Roundtrip through to_dict should also be equivalent
        rule_dict = rule.to_dict()
        assert rule_dict["name"] == raw["name"]
        assert rule_dict["domains"] == raw["allow"]["domains"]
        assert rule_dict["ports"] == raw["allow"]["ports"]
        assert rule_dict["protocols"] == raw["allow"]["protocols"]


# ---------------------------------------------------------------------------
# `appears` marker
# ---------------------------------------------------------------------------

def test_appears_defaults_to_always():
    _, rules = parse_policy_string(VALID_POLICY_YAML)
    assert all(r.appears == "always" for r in rules)


def test_appears_sometimes_parsed():
    yaml_str = """\
version: "1"
mode: monitor
rules:
  - name: "pip cache mirror"
    appears: sometimes
    allow:
      domains: ["*.pythonhosted.org"]
      ports: [443]
      protocols: [https]
"""
    _, rules = parse_policy_string(yaml_str)
    assert rules[0].appears == "sometimes"


def test_appears_invalid_value_rejected():
    yaml_str = """\
version: "1"
mode: monitor
rules:
  - name: "bad"
    appears: maybe
    allow:
      domains: ["example.com"]
      ports: [443]
      protocols: [https]
"""
    with pytest.raises(ValueError, match="appears"):
        parse_policy_string(yaml_str)

