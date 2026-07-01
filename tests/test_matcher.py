"""Unit and property-based tests for PolicyEngine."""

import pytest
from hypothesis import given, settings, assume
from hypothesis import strategies as st

from policy.models import ConnectionEntry, PolicyRule
from policy.matcher import PolicyEngine


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _conn(host="example.com", port=443, protocol="https", **kw) -> ConnectionEntry:
    """Shorthand to build a ConnectionEntry for tests."""
    return ConnectionEntry(
        timestamp="2024-01-01T00:00:00Z",
        protocol=protocol,
        host=host,
        port=port,
        **kw,
    )


def _rule(name="r", domains=None, ports=None, protocols=None) -> PolicyRule:
    """Shorthand to build a PolicyRule for tests."""
    return PolicyRule(
        name=name,
        domains=domains or ["*"],
        ports=ports or [],
        protocols=protocols or ["https"],
    )


# ---------------------------------------------------------------------------
# Unit tests — 3.4
# ---------------------------------------------------------------------------

class TestPolicyEngineAllows:
    """Unit tests for PolicyEngine.allows()."""

    def test_exact_domain_match(self):
        engine = PolicyEngine([_rule(domains=["example.com"], protocols=["https"])])
        assert engine.allows(_conn(host="example.com")) is True

    def test_exact_domain_no_match(self):
        engine = PolicyEngine([_rule(domains=["example.com"], protocols=["https"])])
        assert engine.allows(_conn(host="other.com")) is False

    def test_wildcard_domain_match(self):
        engine = PolicyEngine([_rule(domains=["*.example.com"], protocols=["https"])])
        assert engine.allows(_conn(host="sub.example.com")) is True

    def test_wildcard_domain_no_match_bare(self):
        engine = PolicyEngine([_rule(domains=["*.example.com"], protocols=["https"])])
        assert engine.allows(_conn(host="example.com")) is False

    def test_star_matches_everything(self):
        engine = PolicyEngine([_rule(domains=["*"], protocols=["https"])])
        assert engine.allows(_conn(host="anything.test")) is True

    def test_port_match(self):
        engine = PolicyEngine([_rule(ports=[443], protocols=["https"])])
        assert engine.allows(_conn(port=443)) is True

    def test_port_no_match(self):
        engine = PolicyEngine([_rule(ports=[443], protocols=["https"])])
        assert engine.allows(_conn(port=80)) is False

    def test_empty_ports_allows_any(self):
        engine = PolicyEngine([_rule(ports=[], protocols=["https"])])
        assert engine.allows(_conn(port=9999)) is True

    def test_protocol_match(self):
        engine = PolicyEngine([_rule(protocols=["http"])])
        assert engine.allows(_conn(protocol="http")) is True

    def test_protocol_no_match(self):
        engine = PolicyEngine([_rule(protocols=["http"])])
        assert engine.allows(_conn(protocol="tcp")) is False

    def test_multiple_rules_first_matches(self):
        rules = [
            _rule(name="a", domains=["a.com"], protocols=["https"]),
            _rule(name="b", domains=["b.com"], protocols=["https"]),
        ]
        engine = PolicyEngine(rules)
        assert engine.allows(_conn(host="a.com")) is True

    def test_multiple_rules_second_matches(self):
        rules = [
            _rule(name="a", domains=["a.com"], protocols=["https"]),
            _rule(name="b", domains=["b.com"], protocols=["https"]),
        ]
        engine = PolicyEngine(rules)
        assert engine.allows(_conn(host="b.com")) is True

    def test_no_rules_blocks_everything(self):
        engine = PolicyEngine([])
        assert engine.allows(_conn()) is False

    def test_all_three_criteria_must_match(self):
        engine = PolicyEngine([_rule(domains=["x.com"], ports=[80], protocols=["http"])])
        # domain matches, port matches, protocol wrong
        assert engine.allows(_conn(host="x.com", port=80, protocol="tcp")) is False
        # domain matches, protocol matches, port wrong
        assert engine.allows(_conn(host="x.com", port=443, protocol="http")) is False
        # port matches, protocol matches, domain wrong
        assert engine.allows(_conn(host="y.com", port=80, protocol="http")) is False
        # all match
        assert engine.allows(_conn(host="x.com", port=80, protocol="http")) is True


class TestPolicyEngineCaseInsensitivity:
    """Domain matching must be case-insensitive and OS-independent.

    Hostnames are case-insensitive per RFC 4343, and a client fully controls
    the casing of the SNI/Host it sends. ``fnmatch`` (as opposed to
    ``fnmatchcase``) is case-sensitive on Linux, so these cases regress-guard
    against mixed-case hosts silently failing to match on the Linux CI runners
    this tool targets.
    """

    def test_uppercase_host_matches_lowercase_pattern(self):
        engine = PolicyEngine([_rule(domains=["example.com"], protocols=["https"])])
        assert engine.allows(_conn(host="EXAMPLE.COM")) is True

    def test_mixed_case_host_matches_wildcard(self):
        engine = PolicyEngine([_rule(domains=["*.example.com"], protocols=["https"])])
        assert engine.allows(_conn(host="CDN.Example.COM")) is True

    def test_uppercase_pattern_matches_lowercase_host(self):
        engine = PolicyEngine([_rule(domains=["*.EXAMPLE.COM"], protocols=["https"])])
        assert engine.allows(_conn(host="cdn.example.com")) is True

    def test_dns_matching_is_case_insensitive(self):
        engine = PolicyEngine([_rule(domains=["example.com"], protocols=["dns"])])
        assert engine.allows(_conn(host="Example.Com", protocol="dns")) is True

    @given(host=st.sampled_from(["a.example.com", "sub.example.com", "example.com"]))
    @settings(max_examples=25)
    def test_case_folding_is_symmetric(self, host):
        """Matching a host must not depend on the casing of that host."""
        engine = PolicyEngine([_rule(domains=["*.example.com"], protocols=["https"])])
        assert engine.allows(_conn(host=host)) is engine.allows(
            _conn(host=host.upper())
        )


class TestPolicyEngineEvaluate:
    """Unit tests for PolicyEngine.evaluate()."""

    def test_allowed(self):
        engine = PolicyEngine([_rule()], mode="enforce")
        assert engine.evaluate(_conn()) == "allowed"

    def test_blocked_in_enforce(self):
        engine = PolicyEngine([], mode="enforce")
        assert engine.evaluate(_conn()) == "blocked"

    def test_would_block_in_monitor(self):
        engine = PolicyEngine([], mode="monitor")
        assert engine.evaluate(_conn()) == "would_block"

    def test_allowed_in_monitor(self):
        engine = PolicyEngine([_rule()], mode="monitor")
        assert engine.evaluate(_conn()) == "allowed"


    class TestDnsPolicyFiltering:
        """Unit tests for DNS query filtering via _allows_dns()."""

        def test_dns_allowed_when_domain_in_rule(self):
            """DNS query for a domain that appears in a rule's domains → allowed."""
            engine = PolicyEngine([
                _rule(domains=["registry.npmjs.org"], protocols=["https"]),
            ])
            conn = _conn(host="registry.npmjs.org", port=53, protocol="dns")
            assert engine.allows(conn) is True

        def test_dns_blocked_when_domain_not_in_any_rule(self):
            """DNS query for a domain NOT in any rule → blocked."""
            engine = PolicyEngine([
                _rule(domains=["registry.npmjs.org"], protocols=["https"]),
            ])
            conn = _conn(host="evil-exfil.example.com", port=53, protocol="dns")
            assert engine.allows(conn) is False

        def test_dns_with_service_prefix_allowed(self):
            """DNS query with _http._tcp. prefix for an allowed domain → allowed."""
            engine = PolicyEngine([
                _rule(domains=["registry.npmjs.org"], protocols=["https"]),
            ])
            conn = _conn(host="_http._tcp.registry.npmjs.org", port=53, protocol="dns")
            assert engine.allows(conn) is True

        def test_dns_with_service_prefix_blocked(self):
            """DNS query with _http._tcp. prefix for unknown domain → blocked."""
            engine = PolicyEngine([
                _rule(domains=["registry.npmjs.org"], protocols=["https"]),
            ])
            conn = _conn(host="_http._tcp.evil.com", port=53, protocol="dns")
            assert engine.allows(conn) is False

        def test_dns_wildcard_domain_match(self):
            """Wildcard domain pattern (*.npmjs.org) allows DNS for sub.npmjs.org."""
            engine = PolicyEngine([
                _rule(domains=["*.npmjs.org"], protocols=["https"]),
            ])
            conn = _conn(host="registry.npmjs.org", port=53, protocol="dns")
            assert engine.allows(conn) is True

        def test_dns_wildcard_no_match_bare(self):
            """Wildcard *.npmjs.org does NOT match bare npmjs.org for DNS."""
            engine = PolicyEngine([
                _rule(domains=["*.npmjs.org"], protocols=["https"]),
            ])
            conn = _conn(host="npmjs.org", port=53, protocol="dns")
            assert engine.allows(conn) is False

        def test_dns_star_matches_everything(self):
            """Star (*) domain pattern allows DNS for any domain."""
            engine = PolicyEngine([
                _rule(domains=["*"], protocols=["https"]),
            ])
            conn = _conn(host="anything.example.com", port=53, protocol="dns")
            assert engine.allows(conn) is True

        def test_dns_no_rules_blocks_all(self):
            """Empty rules → all DNS queries blocked."""
            engine = PolicyEngine([])
            conn = _conn(host="example.com", port=53, protocol="dns")
            assert engine.allows(conn) is False

        def test_dns_ignores_protocol_and_port_of_rules(self):
            """DNS matching checks only domain patterns, ignoring rule protocol/port."""
            engine = PolicyEngine([
                _rule(domains=["example.com"], ports=[443], protocols=["https"]),
            ])
            # DNS query on port 53 with protocol "dns" should still match
            conn = _conn(host="example.com", port=53, protocol="dns")
            assert engine.allows(conn) is True

        def test_dns_multiple_rules_any_domain_matches(self):
            """DNS allowed if domain appears in ANY rule's domain list."""
            engine = PolicyEngine([
                _rule(name="npm", domains=["registry.npmjs.org"], protocols=["https"]),
                _rule(name="github", domains=["github.com", "*.github.com"], protocols=["https"]),
            ])
            assert engine.allows(_conn(host="github.com", port=53, protocol="dns")) is True
            assert engine.allows(_conn(host="api.github.com", port=53, protocol="dns")) is True
            assert engine.allows(_conn(host="registry.npmjs.org", port=53, protocol="dns")) is True
            assert engine.allows(_conn(host="unknown.com", port=53, protocol="dns")) is False

        def test_dns_evaluate_blocked_in_enforce(self):
            """In enforce mode, unknown DNS query → 'blocked'."""
            engine = PolicyEngine([
                _rule(domains=["example.com"], protocols=["https"]),
            ], mode="enforce")
            conn = _conn(host="evil.com", port=53, protocol="dns")
            assert engine.evaluate(conn) == "blocked"

        def test_dns_evaluate_would_block_in_monitor(self):
            """In monitor mode, unknown DNS query → 'would_block'."""
            engine = PolicyEngine([
                _rule(domains=["example.com"], protocols=["https"]),
            ], mode="monitor")
            conn = _conn(host="evil.com", port=53, protocol="dns")
            assert engine.evaluate(conn) == "would_block"

        def test_dns_evaluate_allowed(self):
            """Known DNS query → 'allowed' in any mode."""
            engine = PolicyEngine([
                _rule(domains=["example.com"], protocols=["https"]),
            ], mode="enforce")
            conn = _conn(host="example.com", port=53, protocol="dns")
            assert engine.evaluate(conn) == "allowed"

        def test_dns_nested_service_prefix(self):
            """Multiple underscore prefixes like _srv._tcp.example.com are stripped."""
            engine = PolicyEngine([
                _rule(domains=["example.com"], protocols=["https"]),
            ])
            conn = _conn(host="_srv._tcp.example.com", port=53, protocol="dns")
            assert engine.allows(conn) is True



# ---------------------------------------------------------------------------
# Hypothesis strategies
# ---------------------------------------------------------------------------

PROTOCOLS = ["http", "https", "tcp"]

# Strategy for a valid domain label (simplified)
_domain_label = st.from_regex(r"[a-z][a-z0-9]{0,10}", fullmatch=True)

_domain = st.builds(
    lambda parts: ".".join(parts),
    st.lists(_domain_label, min_size=2, max_size=4),
)

_port = st.integers(min_value=1, max_value=65535)
_protocol = st.sampled_from(PROTOCOLS)


def _st_connection(
    host=None, port=None, protocol=None
) -> st.SearchStrategy[ConnectionEntry]:
    """Strategy that builds a ConnectionEntry."""
    return st.builds(
        ConnectionEntry,
        timestamp=st.just("2024-01-01T00:00:00Z"),
        protocol=protocol if protocol is not None else _protocol,
        host=host if host is not None else _domain,
        port=port if port is not None else _port,
        path=st.just(""),
        method=st.just(""),
        status=st.just(""),
        bytes_transferred=st.just(0),
    )


def _st_rule(
    domains=None, ports=None, protocols=None
) -> st.SearchStrategy[PolicyRule]:
    """Strategy that builds a PolicyRule."""
    return st.builds(
        PolicyRule,
        name=st.text(min_size=1, max_size=10, alphabet="abcdefghijklmnopqrstuvwxyz"),
        domains=domains or st.lists(_domain, min_size=1, max_size=3),
        ports=ports or st.lists(_port, min_size=0, max_size=5),
        protocols=protocols or st.lists(_protocol, min_size=1, max_size=3),
    )


# ---------------------------------------------------------------------------
# P5: Allowlist Correctness — Allow
# **Validates: Requirements 3.2**
# ---------------------------------------------------------------------------

@given(data=st.data())
@settings(max_examples=200)
def test_property_p5_allowlist_allow(data):
    """P5: For any connection matching at least one rule, allows() returns True.

    **Validates: Requirements 3.2**

    Strategy: generate a rule, then derive a connection that is guaranteed to
    match that rule (pick a domain from the rule's list, a port from the rule's
    list, and a protocol from the rule's list).
    """
    rule = data.draw(_st_rule())

    # Pick values that definitely match the rule
    domain = data.draw(st.sampled_from(rule.domains))
    protocol = data.draw(st.sampled_from(rule.protocols))

    if rule.ports:
        port = data.draw(st.sampled_from(rule.ports))
    else:
        port = data.draw(_port)  # empty ports means any port is allowed

    conn = ConnectionEntry(
        timestamp="2024-01-01T00:00:00Z",
        protocol=protocol,
        host=domain,
        port=port,
    )

    engine = PolicyEngine([rule])
    assert engine.allows(conn) is True


# ---------------------------------------------------------------------------
# P6: Allowlist Correctness — Block
# **Validates: Requirements 3.3**
# ---------------------------------------------------------------------------

@given(data=st.data())
@settings(max_examples=200)
def test_property_p6_allowlist_block(data):
    """P6: For any connection NOT matching any rule, allows() returns False.

    **Validates: Requirements 3.3**

    Strategy: generate rules, then generate a connection whose protocol is NOT
    in any rule's protocol list — guaranteeing no rule can match.
    """
    rules = data.draw(st.lists(_st_rule(), min_size=1, max_size=3))

    # Collect all protocols used across all rules
    all_rule_protocols = set()
    for r in rules:
        all_rule_protocols.update(r.protocols)

    # Pick a protocol NOT in any rule
    remaining = [p for p in PROTOCOLS if p not in all_rule_protocols]
    assume(len(remaining) > 0)

    bad_protocol = data.draw(st.sampled_from(remaining))
    conn = data.draw(_st_connection(protocol=st.just(bad_protocol)))

    engine = PolicyEngine(rules)
    assert engine.allows(conn) is False


# ---------------------------------------------------------------------------
# P7: Wildcard Domain Matching
# **Validates: Requirements 3.4**
# ---------------------------------------------------------------------------

@given(subdomain=_domain_label, base=_domain)
@settings(max_examples=200)
def test_property_p7_wildcard_domain_matching(subdomain, base):
    """P7: Wildcard patterns match correctly for any domain.

    **Validates: Requirements 3.4**

    Checks:
    - *.base matches subdomain.base
    - *.base does NOT match base itself
    - * matches everything
    - literal matches only itself
    """
    pattern = f"*.{base}"
    full_domain = f"{subdomain}.{base}"

    rule_wildcard = _rule(domains=[pattern], protocols=["https"])
    rule_star = _rule(domains=["*"], protocols=["https"])
    rule_literal = _rule(domains=[base], protocols=["https"])

    engine_wildcard = PolicyEngine([rule_wildcard])
    engine_star = PolicyEngine([rule_star])
    engine_literal = PolicyEngine([rule_literal])

    conn_full = _conn(host=full_domain)
    conn_base = _conn(host=base)

    # *.base matches subdomain.base
    assert engine_wildcard.allows(conn_full) is True
    # *.base does NOT match base itself
    assert engine_wildcard.allows(conn_base) is False
    # * matches everything
    assert engine_star.allows(conn_full) is True
    assert engine_star.allows(conn_base) is True
    # literal matches only itself
    assert engine_literal.allows(conn_base) is True
    assert engine_literal.allows(conn_full) is False


# ---------------------------------------------------------------------------
# P8: Monitor Mode Never Blocks
# **Validates: Requirements 3.6**
# ---------------------------------------------------------------------------

@given(
    rules=st.lists(_st_rule(), min_size=0, max_size=5),
    conn=_st_connection(),
)
@settings(max_examples=200)
def test_property_p8_monitor_mode_never_blocks(rules, conn):
    """P8: In monitor mode, evaluate() never returns 'blocked'.

    **Validates: Requirements 3.6**
    """
    engine = PolicyEngine(rules, mode="monitor")
    result = engine.evaluate(conn)
    assert result in ("allowed", "would_block")
    assert result != "blocked"
