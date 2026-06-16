"""Policy analysis: compare actual traffic against allowlist rules.

Produces:
- Suggested YAML rules for blocked destinations (copy-paste ready)
- List of unused allowlist rules (candidates for removal)
- Per-rule match counts
"""

import fnmatch

from policy.models import ConnectionEntry, PolicyRule


def analyze_policy(rules: list[PolicyRule],
                   connections: list[dict],
                   destinations: list[dict]) -> dict:
    """Compare observed traffic against policy rules.

    Args:
        rules: Parsed policy rules from the YAML file.
        connections: Raw connection dicts from the JSONL log.
        destinations: Aggregated destination dicts from access_summary.

    Returns a dict with:
        rule_usage: list of {name, domains, matched_hosts, match_count, appears}
        unused_rules: rule names with zero matches and appears="always"
            (candidates for removal)
        sometimes_unmatched: rule names with zero matches and appears="sometimes"
            (expected — not flagged as unused)
        suggested_rules: list of dicts for blocked destinations
        suggested_yaml: ready-to-paste YAML string
    """
    # Count matches per rule
    rule_usage = []
    for rule in rules:
        matched_hosts: set[str] = set()
        match_count = 0
        for c in connections:
            if c.get("status") == "data":
                continue
            entry = _to_entry(c)
            if _rule_matches(rule, entry):
                matched_hosts.add(entry.host)
                match_count += 1
        rule_usage.append({
            "name": rule.name,
            "domains": rule.domains,
            "matched_hosts": sorted(matched_hosts),
            "match_count": match_count,
            "appears": rule.appears,
        })

    # An "always" rule with no matches is a real candidate for removal. A
    # "sometimes" rule with no matches is expected (cache hit, conditional step)
    # and is reported separately, not as unused.
    unused_rules = [
        r["name"] for r in rule_usage
        if r["match_count"] == 0 and r.get("appears", "always") != "sometimes"
    ]
    sometimes_unmatched = [
        r["name"] for r in rule_usage
        if r["match_count"] == 0 and r.get("appears", "always") == "sometimes"
    ]

    # Build suggested rules for blocked destinations
    blocked_dests = [
        d for d in destinations
        if any(s in ("blocked", "would_block")
               for s in d.get("statuses", {}))
    ]

    suggested_rules = []
    for dest in blocked_dests:
        host = dest["host"]
        port = dest["port"]
        proto = dest.get("protocol", "https")
        ip_info = dest.get("ip_info", {})
        owner = ip_info.get("owner", "")
        country = ip_info.get("country", "")
        prefix = ip_info.get("prefix", "")
        rdns = dest.get("reverse_dns", "") or ip_info.get("reverse_dns", "")
        count = sum(
            n for s, n in dest.get("statuses", {}).items()
            if s in ("blocked", "would_block")
        )
        suggested_rules.append({
            "host": host,
            "port": port,
            "protocol": proto,
            "owner": owner,
            "country": country,
            "prefix": prefix,
            "reverse_dns": rdns,
            "blocked_count": count,
        })

    suggested_yaml = _generate_yaml(suggested_rules)

    return {
        "rule_usage": rule_usage,
        "unused_rules": unused_rules,
        "sometimes_unmatched": sometimes_unmatched,
        "suggested_rules": suggested_rules,
        "suggested_yaml": suggested_yaml,
    }


def _to_entry(c: dict) -> ConnectionEntry:
    """Convert a raw connection dict to a ConnectionEntry for matching."""
    return ConnectionEntry(
        timestamp=c.get("timestamp", ""),
        protocol=c.get("protocol", ""),
        host=c.get("host", ""),
        port=c.get("port", 0),
        path=c.get("path", ""),
        method=c.get("method", ""),
    )


def _rule_matches(rule: PolicyRule, conn: ConnectionEntry) -> bool:
    """Check if a rule matches a connection.

    DNS queries match by domain only (ignoring protocol/port) — same
    logic as PolicyEngine._allows_dns.  This ensures that DNS lookups
    for allowed domains count as rule matches in the analysis.
    """
    domain_ok = any(
        fnmatch.fnmatch(conn.host, pat) for pat in rule.domains
    )
    if conn.protocol == "dns":
        # Also try stripping DNS-SD prefixes
        clean = conn.host
        while clean.startswith("_"):
            dot = clean.find(".")
            if dot < 0:
                break
            clean = clean[dot + 1:]
        if clean != conn.host:
            domain_ok = domain_ok or any(
                fnmatch.fnmatch(clean, pat) for pat in rule.domains
            )
        return domain_ok
    port_ok = not rule.ports or conn.port in rule.ports
    proto_ok = conn.protocol in rule.protocols
    return domain_ok and port_ok and proto_ok


def _generate_yaml(suggested_rules: list[dict]) -> str:
    """Generate a needed allowlist for blocked destinations.

    Format: flat list with port per target (host:port or cidr:port).
    Each entry has a # comment with owner/reverse-DNS info and date.
    """
    if not suggested_rules:
        return ""

    from datetime import date

    today = date.today().isoformat()

    domains: list[tuple[str, str]] = []   # (host:port, comment)
    ips: list[tuple[str, str]] = []       # (cidr:port or ip:port, comment)

    for sr in sorted(suggested_rules, key=lambda x: x["host"]):
        host = sr["host"]
        port = sr.get("port", 443)
        comment_parts = []
        rdns = sr.get("reverse_dns", "")
        owner = sr.get("owner", "")
        country = sr.get("country", "")
        blocked = sr.get("blocked_count", 0)

        if rdns:
            comment_parts.append(rdns)
        if owner:
            tag = owner
            if country:
                tag += f", {country}"
            comment_parts.append(tag)
        if blocked:
            comment_parts.append(f"{blocked}x blocked")
        comment_parts.append(today)

        comment = "  # " + " | ".join(comment_parts)

        if _is_ip_str(host):
            prefix = sr.get("prefix", "")
            value = prefix if prefix else host
            ips.append((f"{value}:{port}", comment))
        else:
            domains.append((f"{host}:{port}", comment))

    lines = [f"# --- Needed allowlist from dry-run ({today}) ---"]

    if domains:
        lines.append("")
        lines.append("domains:")
        for value, comment in domains:
            lines.append(f"  - \"{value}\"{comment}")

    if ips:
        lines.append("")
        lines.append("ips:")
        for value, comment in ips:
            lines.append(f"  - \"{value}\"{comment}")

    return "\n".join(lines)


def _is_ip_str(host: str) -> bool:
    """Check if host looks like an IP address."""
    import ipaddress
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False
