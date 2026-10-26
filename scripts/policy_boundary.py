#!/usr/bin/env python3
"""Check that policy files never allow more than an org-wide boundary policy.

    python3 scripts/policy_boundary.py --boundary org-boundary.yml policy.yml [...]

Every rule of every policy must be subsumed by the boundary: each of its
domain patterns must be covered by one boundary rule whose ports, protocols,
paths, methods, allowed_ips and allow_request_body are at least as broad.
The check is conservative and offline — anything it cannot prove is reported
as a violation. Exit 0 when everything is subsumed, 1 on any violation, 2 when
a file cannot be read or parsed.
"""

import argparse
import fnmatch
import functools
import ipaddress
import os
import re
import sys
from dataclasses import dataclass, field

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from policy.matcher import internal_ip_category, rule_exempts_ip  # noqa: E402
from policy.models import PolicyRule  # noqa: E402
from policy.parser import parse_policy_file  # noqa: E402

HTTP_PROTOCOLS = ("http", "https")

# Glob tokens: ("lit", c), ("one", ""), ("star", ""), ("class", raw "[...]").
Token = tuple[str, str]


def _tokenize(pattern: str) -> tuple[Token, ...]:
    """Split an fnmatch pattern into tokens, mirroring fnmatch.translate."""
    tokens: list[Token] = []
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        i += 1
        if c == "*":
            if not tokens or tokens[-1][0] != "star":
                tokens.append(("star", ""))
        elif c == "?":
            tokens.append(("one", ""))
        elif c == "[":
            j = i
            if j < n and pattern[j] == "!":
                j += 1
            if j < n and pattern[j] == "]":
                j += 1
            while j < n and pattern[j] != "]":
                j += 1
            if j >= n:
                tokens.append(("lit", "["))
            else:
                tokens.append(("class", pattern[i - 1:j + 1]))
                i = j + 1
        else:
            tokens.append(("lit", c))
    return tuple(tokens)


def _class_matches(raw: str, char: str) -> bool:
    return fnmatch.fnmatchcase(char, raw)


@functools.lru_cache(maxsize=4096)
def glob_subsumes(boundary: str, candidate: str) -> bool:
    """True only if every string fnmatch-matching *candidate* also matches *boundary*.

    Sound but not complete: a False answer means "not proven", never "proven wider".
    """
    b = _tokenize(boundary)
    p = _tokenize(candidate)

    @functools.lru_cache(maxsize=None)
    def covers(i: int, j: int) -> bool:
        if j == len(b):
            return i == len(p)
        kind, val = b[j]
        if kind == "star":
            return covers(i, j + 1) or (i < len(p) and covers(i + 1, j))
        if i == len(p):
            return False
        pkind, pval = p[i]
        if pkind == "star":
            return False
        if kind == "one":
            ok = True
        elif kind == "lit":
            ok = pkind == "lit" and pval == val
        elif pkind == "lit":
            ok = _class_matches(val, pval)
        else:
            ok = pkind == "class" and pval == val
        return ok and covers(i + 1, j + 1)

    return covers(0, 0)


def domain_subsumes(boundary: str, candidate: str) -> bool:
    """Domain variant of :func:`glob_subsumes`; hostnames match case-insensitively."""
    return glob_subsumes(boundary.lower(), candidate.lower())


def _uses_http(rule: PolicyRule) -> bool:
    return any(p in HTTP_PROTOCOLS for p in rule.protocols)


def _network(cidr: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    return ipaddress.ip_network(cidr, strict=False)


def _cidr_subsumed(candidate: str, boundary: list[str]) -> bool:
    net = _network(candidate)
    for b in boundary:
        outer = _network(b)
        if (
            net.version == outer.version
            and net.network_address in outer
            and net.broadcast_address in outer
        ):
            return True
    return False


def _fmt(values: list, empty: str) -> str:
    return "[" + ", ".join(str(v) for v in values) + "]" if values else empty


_LOOPBACK = ["127.0.0.0/8", "::1/128"]


def _boundary_exempts_name(boundary: PolicyRule, domain: str) -> bool:
    """False if *domain* literally names an internal host the boundary does not exempt."""
    if domain.lower() == "localhost":
        return (
            not boundary.internal_ip_guard
            or "localhost" in (d.lower() for d in boundary.domains)
            or all(_cidr_subsumed(c, boundary.allowed_ips) for c in _LOOPBACK)
        )
    if not internal_ip_category(domain):
        return True
    return rule_exempts_ip(boundary, domain)


def dimension_gaps(candidate: PolicyRule, boundary: PolicyRule) -> list[str]:
    """Reasons *boundary* is narrower than *candidate* outside the domains dimension."""
    gaps: list[str] = []
    # DNS-layer exemptions apply even to a rule with no protocols.
    extra_ips = [c for c in candidate.allowed_ips if not _cidr_subsumed(c, boundary.allowed_ips)]
    if extra_ips and boundary.internal_ip_guard:
        gaps.append(
            f"allowed_ips: {_fmt(extra_ips, '')} not inside boundary "
            f"{_fmt(boundary.allowed_ips, '[]')}"
        )

    if not candidate.internal_ip_guard and boundary.internal_ip_guard:
        gaps.append("internal IPs: a version 1 rule may reach any internal address")
    elif candidate.internal_ip_guard:
        named = [d for d in candidate.domains if not _boundary_exempts_name(boundary, d)]
        if named:
            gaps.append(f"internal IPs: {_fmt(named, '')} named literally, not exempt in boundary")

    # A rule with no protocols matches no connection; it only lets its names resolve.
    if not candidate.protocols:
        return gaps

    if boundary.ports:
        if not candidate.ports:
            gaps.append(f"ports: all ports, boundary allows only {_fmt(boundary.ports, '')}")
        else:
            extra = sorted(set(candidate.ports) - set(boundary.ports))
            if extra:
                gaps.append(f"ports: {_fmt(extra, '')} not in boundary {_fmt(boundary.ports, '')}")

    extra_protos = [p for p in candidate.protocols if p not in boundary.protocols]
    if extra_protos:
        gaps.append(
            f"protocols: {_fmt(extra_protos, '')} not in boundary "
            f"{_fmt(boundary.protocols, '[]')}"
        )

    if boundary.paths:
        if not candidate.paths:
            gaps.append(f"paths: all paths, boundary allows only {_fmt(boundary.paths, '')}")
        else:
            extra_paths = [
                p for p in candidate.paths
                if not any(glob_subsumes(b, p) for b in boundary.paths)
            ]
            if extra_paths:
                gaps.append(
                    f"paths: {_fmt(extra_paths, '')} not provably within boundary "
                    f"{_fmt(boundary.paths, '')}"
                )

    if boundary.methods and _uses_http(candidate):
        if not candidate.methods:
            gaps.append(f"methods: all methods, boundary allows only {_fmt(boundary.methods, '')}")
        else:
            extra_methods = [m for m in candidate.methods if m not in boundary.methods]
            if extra_methods:
                gaps.append(
                    f"methods: {_fmt(extra_methods, '')} not in boundary "
                    f"{_fmt(boundary.methods, '')}"
                )

    if candidate.allow_request_body and not boundary.allow_request_body:
        gaps.append("allow_request_body: true, boundary rule keeps payload scanning on")

    return gaps


@dataclass
class Violation:
    """One rule of a checked policy that the boundary does not provably cover."""

    file: str
    rule: str
    reasons: list[str] = field(default_factory=list)


def check_rule(candidate: PolicyRule, boundary: list[PolicyRule]) -> list[str]:
    """Per-domain explanations of why *candidate* is not subsumed; empty when it is."""
    reasons: list[str] = []
    for domain in candidate.domains:
        domain_rules = [
            b for b in boundary if any(domain_subsumes(bd, domain) for bd in b.domains)
        ]
        if not domain_rules:
            reasons.append(f"domain {domain!r}: not provably matched by any boundary domain")
            continue
        near_misses: list[str] = []
        for b in domain_rules:
            gaps = dimension_gaps(candidate, b)
            if not gaps:
                break
            near_misses.append(f"boundary rule {b.name!r}: " + "; ".join(gaps))
        else:
            reasons.append(f"domain {domain!r}: " + " | ".join(near_misses))
    return reasons


def check_policy(path: str, boundary: list[PolicyRule]) -> list[Violation]:
    _mode, rules = parse_policy_file(path)
    violations = []
    for rule in rules:
        reasons = check_rule(rule, boundary)
        if reasons:
            violations.append(Violation(file=path, rule=rule.name, reasons=reasons))
    return violations


def _rule_line(path: str, rule_name: str) -> int | None:
    pattern = re.compile(
        r"^\s*(?:-\s*)?name:\s*[\"']?" + re.escape(rule_name) + r"[\"']?\s*(?:#.*)?$"
    )
    try:
        with open(path, encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, start=1):
                if pattern.match(line):
                    return lineno
    except OSError:
        return None
    return None


def _escape_annotation(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_property(text: str) -> str:
    return _escape_annotation(text).replace(":", "%3A").replace(",", "%2C")


def _annotate(path: str, message: str, title: str, line: int | None = None) -> None:
    props = f"file={_escape_property(path)}"
    if line:
        props += f",line={line}"
    props += f",title={_escape_property(title)}"
    print(f"::error {props}::{_escape_annotation(message)}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Fail if any policy rule allows more than the org boundary policy."
    )
    parser.add_argument("--boundary", required=True, help="boundary policy YAML")
    parser.add_argument("policies", nargs="+", help="policy YAML files to check")
    args = parser.parse_args(argv)
    in_actions = os.environ.get("GITHUB_ACTIONS") == "true"

    try:
        _mode, boundary = parse_policy_file(args.boundary)
    except (OSError, ValueError) as exc:
        print(f"boundary {args.boundary}: {exc}", file=sys.stderr)
        if in_actions:
            _annotate(args.boundary, str(exc), "PipeWarden boundary invalid")
        return 2

    status = 0
    for path in args.policies:
        try:
            violations = check_policy(path, boundary)
        except (OSError, ValueError) as exc:
            print(f"{path}: {exc}", file=sys.stderr)
            if in_actions:
                _annotate(path, str(exc), "PipeWarden policy invalid")
            status = 2
            continue
        if not violations:
            print(f"{path}: all rules within boundary {args.boundary}")
            continue
        status = max(status, 1)
        for v in violations:
            print(f"{path}: rule {v.rule!r} exceeds boundary {args.boundary}:")
            for reason in v.reasons:
                print(f"  - {reason}")
            if in_actions:
                _annotate(
                    path,
                    f"Rule {v.rule!r} exceeds boundary {args.boundary}: " + "\n".join(v.reasons),
                    "PipeWarden boundary violation",
                    _rule_line(path, v.rule),
                )
    return status


if __name__ == "__main__":
    sys.exit(main())
