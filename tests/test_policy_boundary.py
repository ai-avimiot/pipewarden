"""Tests for scripts/policy_boundary.py (offline org boundary check)."""

import fnmatch
import itertools
import random
import textwrap

import pytest

from policy.models import PolicyRule
from scripts.policy_boundary import (
    check_rule,
    dimension_gaps,
    domain_subsumes,
    glob_subsumes,
    main,
)


def rule(name="r", domains=None, ports=None, protocols=None, paths=None, **kw):
    return PolicyRule(
        name=name,
        domains=domains if domains is not None else ["a.com"],
        ports=ports if ports is not None else [443],
        protocols=protocols if protocols is not None else ["https"],
        paths=paths or [],
        **kw,
    )


class TestDomainSubsumes:
    @pytest.mark.parametrize(
        "boundary, candidate, expected",
        [
            ("a.com", "a.com", True),
            ("A.COM", "a.com", True),
            ("*.a.com", "x.a.com", True),
            ("*.a.com", "x.y.a.com", True),
            # The apex is not a subdomain: fnmatch needs the leading dot.
            ("*.a.com", "a.com", False),
            ("a.com", "*.a.com", False),
            ("*.a.com", "*.b.a.com", True),
            ("*.b.a.com", "*.a.com", False),
            ("*.a.com", "*.a.com", True),
            ("*.a.com", "*a.com", False),
            ("*a.com", "*.a.com", True),
            ("*.a.com", "*.evila.com", False),
            ("*.a.com", "x.a.com.evil.net", False),
            ("*", "anything.example", True),
            ("*", "*", True),
            ("*.com", "*", False),
            ("registry-?.npmjs.org", "registry-1.npmjs.org", True),
            ("registry-?.npmjs.org", "registry-??.npmjs.org", False),
            ("registry-*.npmjs.org", "registry-?.npmjs.org", True),
            ("?.a.com", "*.a.com", False),
            ("[ab].a.com", "a.a.com", True),
            ("[ab].a.com", "c.a.com", False),
            ("?.a.com", "[ab].a.com", True),
            ("[ab].a.com", "[ab].a.com", True),
            # Not provable by token comparison, so conservatively refused.
            ("[abc].a.com", "[ab].a.com", False),
            ("a.com", "[a].com", False),
        ],
    )
    def test_cases(self, boundary, candidate, expected):
        assert domain_subsumes(boundary, candidate) is expected

    def test_paths_are_case_sensitive(self):
        assert glob_subsumes("/api/*", "/api/v1/*")
        assert not glob_subsumes("/api/*", "/API/v1")
        assert not glob_subsumes("/api/*", "/api")
        assert glob_subsumes("/api*", "/api")

    def test_never_claims_a_wider_pattern_is_covered(self):
        alphabet = "ab.*?"
        strings = ["".join(t) for n in range(5) for t in itertools.product("ab.", repeat=n)]
        rnd = random.Random(1234)
        patterns = {"".join(rnd.choice(alphabet) for _ in range(rnd.randint(0, 5)))
                    for _ in range(400)}
        for b, p in itertools.product(sorted(patterns), repeat=2):
            if not glob_subsumes(b, p):
                continue
            for s in strings:
                if fnmatch.fnmatchcase(s, p):
                    assert fnmatch.fnmatchcase(s, b), (b, p, s)


class TestDimensions:
    def test_empty_ports_only_within_empty_boundary_ports(self):
        assert dimension_gaps(rule(ports=[]), rule(ports=[443]))
        assert not dimension_gaps(rule(ports=[]), rule(ports=[]))
        assert not dimension_gaps(rule(ports=[443]), rule(ports=[]))

    def test_ports_subset(self):
        assert not dimension_gaps(rule(ports=[443]), rule(ports=[80, 443]))
        gaps = dimension_gaps(rule(ports=[443, 8443]), rule(ports=[443]))
        assert gaps and "8443" in gaps[0]

    def test_protocols_subset(self):
        assert not dimension_gaps(rule(protocols=["https"]), rule(protocols=["http", "https"]))
        assert dimension_gaps(rule(protocols=["https", "tcp"]), rule(protocols=["https"]))

    def test_rule_without_protocols_needs_only_domain_cover(self):
        assert not dimension_gaps(rule(protocols=[], ports=[]), rule(ports=[443]))

    def test_paths(self):
        assert dimension_gaps(rule(paths=[]), rule(paths=["/simple/*"]))
        assert not dimension_gaps(rule(paths=["/simple/foo/*"]), rule(paths=["/simple/*"]))
        assert dimension_gaps(rule(paths=["/upload/*"]), rule(paths=["/simple/*"]))
        assert not dimension_gaps(rule(paths=["/anything"]), rule(paths=[]))

    def test_methods(self):
        assert dimension_gaps(rule(), rule(methods=["GET", "HEAD"]))
        assert dimension_gaps(rule(methods=["GET", "PUT"]), rule(methods=["GET", "HEAD"]))
        assert not dimension_gaps(rule(methods=["GET"]), rule(methods=["GET", "HEAD"]))
        assert not dimension_gaps(rule(methods=["PUT"]), rule())

    def test_methods_ignored_for_non_http_candidate(self):
        tcp = rule(protocols=["tcp"])
        assert not dimension_gaps(tcp, rule(protocols=["tcp", "https"], methods=["GET"]))

    def test_allowed_ips_cidr_subset(self):
        assert not dimension_gaps(
            rule(allowed_ips=["10.20.1.0/24"]), rule(allowed_ips=["10.20.0.0/16"])
        )
        assert dimension_gaps(rule(allowed_ips=["10.0.0.0/8"]), rule(allowed_ips=["10.20.0.0/16"]))
        assert dimension_gaps(rule(allowed_ips=["10.20.1.0/24"]), rule())
        assert dimension_gaps(rule(allowed_ips=["fd00::/64"]), rule(allowed_ips=["10.0.0.0/8"]))
        assert not dimension_gaps(rule(), rule(allowed_ips=["10.0.0.0/8"]))

    def test_v1_rule_is_unguarded(self):
        v1 = rule(internal_ip_guard=False)
        assert any("version 1" in g for g in dimension_gaps(v1, rule()))
        assert not dimension_gaps(v1, rule(internal_ip_guard=False))
        assert not dimension_gaps(rule(allowed_ips=["10.0.0.0/8"]), rule(internal_ip_guard=False))

    def test_literal_internal_domain_needs_boundary_exemption(self):
        for name in ("10.0.0.5", "localhost"):
            assert dimension_gaps(rule(domains=[name]), rule(domains=["*"]))
        assert not dimension_gaps(rule(domains=["10.0.0.5"]), rule(domains=["*"], allowed_ips=["10.0.0.0/8"]))
        assert not dimension_gaps(rule(domains=["localhost"]), rule(domains=["localhost"]))
        assert not dimension_gaps(rule(domains=["93.184.216.34"]), rule(domains=["*"]))

    def test_allowed_ips_checked_on_rule_without_protocols(self):
        # The DNS interceptor honours allowed_ips whatever the rule's protocols.
        dns_only = rule(protocols=[], ports=[], allowed_ips=["169.254.169.254/32", "10.0.0.0/8"])
        gaps = dimension_gaps(dns_only, rule(ports=[443]))
        assert gaps and "allowed_ips" in gaps[0]
        assert not dimension_gaps(dns_only, rule(ports=[443], allowed_ips=["169.254.0.0/16", "10.0.0.0/8"]))

    def test_allow_request_body_needs_boundary_opt_out(self):
        assert dimension_gaps(rule(allow_request_body=True), rule())
        assert not dimension_gaps(rule(allow_request_body=True), rule(allow_request_body=True))


class TestCheckRule:
    def test_domains_may_be_covered_by_different_boundary_rules(self):
        boundary = [rule("gh", domains=["*.github.com"]), rule("npm", domains=["*.npmjs.org"])]
        candidate = rule(domains=["api.github.com", "registry.npmjs.org"])
        assert check_rule(candidate, boundary) == []

    def test_domain_must_be_covered_together_with_its_dimensions(self):
        boundary = [rule("web", domains=["*.a.com"], ports=[443]),
                    rule("any", domains=["*.b.com"], ports=[])]
        reasons = check_rule(rule(domains=["x.a.com"], ports=[]), boundary)
        assert len(reasons) == 1
        assert "'web'" in reasons[0] and "all ports" in reasons[0]

    def test_uncovered_domain_explained(self):
        reasons = check_rule(rule(domains=["a.com"]), [rule(domains=["*.a.com"])])
        assert reasons == ["domain 'a.com': not provably matched by any boundary domain"]

    def test_empty_domains_matches_nothing(self):
        assert check_rule(rule(domains=[]), []) == []


BOUNDARY = """\
version: "2"
mode: enforce
rules:
  - name: github
    allow:
      domains: ["github.com", "*.github.com", "*.githubusercontent.com"]
      ports: [443]
      protocols: [https]
  - name: npm read-only
    allow:
      domains: ["registry.npmjs.org"]
      ports: [443]
      protocols: [https]
      access: read-only
"""

GOOD = """\
version: "2"
mode: enforce
rules:
  - name: gh
    allow:
      domains: ["api.github.com", "objects.githubusercontent.com"]
      ports: [443]
      protocols: [https]
  - name: npm
    allow:
      domains: ["registry.npmjs.org"]
      ports: [443]
      protocols: [https]
      methods: [GET]
"""

BAD = """\
version: "2"
mode: enforce
rules:
  - name: gh
    allow:
      domains: ["*.github.com"]
      ports: [443]
      protocols: [https]
  - name: "npm publish"
    allow:
      domains: ["registry.npmjs.org"]
      protocols: [https]
"""


@pytest.fixture
def files(tmp_path):
    def write(name, content):
        p = tmp_path / name
        p.write_text(textwrap.dedent(content), encoding="utf-8")
        return str(p)
    return write


class TestCli:
    def test_all_subsumed_exits_zero(self, files, capsys, monkeypatch):
        monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
        assert main(["--boundary", files("b.yml", BOUNDARY), files("ok.yml", GOOD)]) == 0
        assert "all rules within boundary" in capsys.readouterr().out

    def test_violation_exits_one_with_explanation(self, files, capsys, monkeypatch):
        monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
        bad = files("bad.yml", BAD)
        assert main(["--boundary", files("b.yml", BOUNDARY), files("ok.yml", GOOD), bad]) == 1
        out = capsys.readouterr().out
        assert "'npm publish'" in out
        assert "all ports" in out and "all methods" in out
        assert "rule 'gh'" not in out
        assert "::error" not in out

    def test_github_actions_annotations(self, files, capsys, monkeypatch):
        monkeypatch.setenv("GITHUB_ACTIONS", "true")
        bad = files("bad.yml", BAD)
        assert main(["--boundary", files("b.yml", BOUNDARY), bad]) == 1
        errors = [ln for ln in capsys.readouterr().out.splitlines() if ln.startswith("::error ")]
        assert len(errors) == 1
        assert f"file={bad.replace(':', '%3A')},line=9," in errors[0]
        assert "title=PipeWarden boundary violation::" in errors[0]
        assert "%0A" not in errors[0].split("::", 2)[1]

    def test_invalid_policy_exits_two(self, files, capsys, monkeypatch):
        monkeypatch.setenv("GITHUB_ACTIONS", "true")
        broken = files("broken.yml", "version: '1'\nmode: enforce\nrules: nope\n")
        assert main(["--boundary", files("b.yml", BOUNDARY), broken]) == 2
        assert "PipeWarden policy invalid" in capsys.readouterr().out

    def test_missing_boundary_exits_two(self, files, monkeypatch):
        monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
        assert main(["--boundary", "/nonexistent/b.yml", files("ok.yml", GOOD)]) == 2
